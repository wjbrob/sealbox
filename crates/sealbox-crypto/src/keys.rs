//! Key material: [`Identity`] (one of *our* secret keys, held unlocked in memory) and
//! [`PublicKey`] (anybody's OpenPGP certificate).
//!
//! # Key profiles
//!
//! * [`KeyProfile::Classical`] (default): Ed25519 primary (certify + sign) and one X25519
//!   encryption subkey — v4 with the legacy algorithm ids (22/18) so that gpg 2.x, Thunderbird,
//!   Proton and OpenPGP.js all accept it, or RFC 9580 v6 (27/25) on request.
//! * [`KeyProfile::HybridPqc`] (needs the `pqc` cargo feature): the same primary and X25519
//!   subkey **plus a second encryption subkey, ML-KEM-768+X25519** (RFC 9980 composite KEM,
//!   algorithm id 35). The X25519 subkey stays so that every classical peer can keep
//!   encrypting to the key; the composite subkey gives post-quantum confidentiality between
//!   peers that implement RFC 9980. Signatures stay Ed25519 (ML-DSA/SLH-DSA are not offered —
//!   a quantum adversary recorded today can break tomorrow's *confidentiality*, not yesterday's
//!   signatures, so the KEM is what matters for mail at rest). The key version follows
//!   [`KeyGenOptions::version`] exactly as for classical keys — v4 by default. RFC 9980 allows
//!   ML-KEM-768+X25519 on v4 keys precisely for this migration case (ML-KEM-1024+X448 and the
//!   PQ signature algorithms are v6-only, which is another reason not to use them here).
//!
//! # Which subkey a message is encrypted to
//!
//! [`PublicKey::encryption_target`] picks the **post-quantum subkey whenever the certificate
//! carries a live one** (and this build can use it), otherwise the newest live classical
//! encryption subkey, otherwise an encryption-capable primary key. A hybrid recipient therefore
//! always gets an ML-KEM-768+X25519 PKESK from a `pqc` build, a classical recipient gets X25519
//! as before, and a build without the `pqc` feature treats algorithm 35 as unknown and falls
//! back to the X25519 subkey of a hybrid key — so classical and hybrid builds of Sealbox always
//! interoperate. The Autocrypt minimal key deliberately exports only the classical subkey
//! (see `autocrypt::minimal_public_key`).
//!
//! # Interop status (2026-10)
//!
//! RFC 9980 is implemented by rPGP (this crate's engine), OpenPGP.js and Proton; GnuPG 2.4 and
//! Thunderbird do not speak it yet (gpg 2.4.7 lists the composite subkey as "unknown
//! algorithm 35" and skips it; it still encrypts to the X25519 subkey). The `pqc` feature is
//! therefore **off** in the product build; gate G14 (`tests/gate_g14.rs`) turns it on and
//! proves the round-trip plus the RFC 9980 sample vectors.

use std::fmt;

use chrono::{DateTime, Utc};
use pgp::composed::{
    ArmorOptions, Deserializable, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey,
    SignedPublicSubKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::aead::AeadAlgorithm;
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{self, Signature, SignatureType};
use pgp::ser::Serialize;
use pgp::types::{
    CompressionAlgorithm, Fingerprint, KeyDetails as _, KeyId, KeyVersion as PgpKeyVersion,
    Password, SigningKey, VerifyingKey,
};
use smallvec::smallvec;

use crate::error::{Error, Result};
use crate::util::{email_of_user_id, hex_upper, timestamp_to_datetime};

/// OpenPGP key version to generate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum KeyVersion {
    /// RFC 4880 v4 keys with Ed25519Legacy / Curve25519Legacy. Interoperates with everything
    /// (gpg 2.x, Thunderbird, Proton, OpenPGP.js, Delta Chat). **Default.**
    #[default]
    V4,
    /// RFC 9580 v6 keys (Ed25519 / X25519 new formats). Not readable by GnuPG 2.4.
    V6,
}

/// Which algorithms an identity is generated with (see the module docs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum KeyProfile {
    /// Ed25519 primary + one X25519 encryption subkey. Understood by every OpenPGP peer.
    /// **Default.**
    #[default]
    Classical,
    /// Ed25519 primary + X25519 encryption subkey **+ ML-KEM-768+X25519 encryption subkey**
    /// (RFC 9980). Needs the `pqc` cargo feature: without it [`Identity::generate_with`] fails
    /// with [`Error::Unsupported`] (check [`crate::capabilities::PQC`] first).
    HybridPqc,
}

/// Options for [`Identity::generate_with`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyGenOptions {
    /// Key version (default v4).
    pub version: KeyVersion,
    /// Algorithm profile (default classical; see [`KeyProfile`]).
    pub profile: KeyProfile,
    /// Advertise SEIPDv2 (AEAD) support in the key's Features subpacket. Senders that honour
    /// it will encrypt with AES-256/OCB SEIPDv2, which gpg 2.4 cannot read — so only set this
    /// when the key is used exclusively between RFC 9580 capable clients. v6 keys always
    /// advertise it.
    pub advertise_seipd_v2: bool,
}

/// One of the user's own keys: Ed25519 primary (certify + sign) and a Curve25519/X25519
/// encryption subkey — plus an ML-KEM-768+X25519 encryption subkey for
/// [`KeyProfile::HybridPqc`]. Held **unlocked** in memory; passphrase protection is applied
/// only on export (`to_armored_secret`). The plain secret scalars inside rPGP's packets are
/// zeroized on drop by rPGP itself.
#[derive(Clone)]
pub struct Identity {
    secret: SignedSecretKey,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint())
            .field("user_ids", &self.user_ids())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Generate a v4 identity: Ed25519 primary (certify + sign) and Curve25519 encryption subkey.
    pub fn generate(name: &str, email: &str) -> Result<Self> {
        Self::generate_with(name, email, KeyGenOptions::default())
    }

    /// Generate a v4 **post-quantum hybrid** identity ([`KeyProfile::HybridPqc`]): Ed25519
    /// primary, X25519 encryption subkey and ML-KEM-768+X25519 encryption subkey. Fails with
    /// [`Error::Unsupported`] when the crate is built without the `pqc` feature.
    pub fn generate_hybrid(name: &str, email: &str) -> Result<Self> {
        Self::generate_with(
            name,
            email,
            KeyGenOptions {
                profile: KeyProfile::HybridPqc,
                ..KeyGenOptions::default()
            },
        )
    }

    /// Generate with explicit options (key version, algorithm profile, SEIPDv2 advertisement).
    pub fn generate_with(name: &str, email: &str, opts: KeyGenOptions) -> Result<Self> {
        let email = email.trim();
        if email.is_empty() || !email.contains('@') {
            return Err(Error::InvalidInput(format!(
                "`{email}` is not an email address"
            )));
        }
        let uid = format_user_id(name, email);
        let (version, primary_type, subkey_type, aead) = match opts.version {
            KeyVersion::V4 => (
                PgpKeyVersion::V4,
                KeyType::Ed25519Legacy,
                KeyType::ECDH(ECCCurve::Curve25519Legacy),
                opts.advertise_seipd_v2,
            ),
            KeyVersion::V6 => (PgpKeyVersion::V6, KeyType::Ed25519, KeyType::X25519, true),
        };

        let subkey = SubkeyParamsBuilder::default()
            .version(version)
            .key_type(subkey_type)
            .can_encrypt(EncryptionCaps::All)
            .build()
            .map_err(|e| Error::KeyGeneration(e.to_string()))?;
        // Classical subkey first: an implementation that drops unknown-algorithm subkeys (gpg)
        // keeps the one it understands, and `encryption_target` ranks by algorithm anyway.
        let mut subkeys = vec![subkey];
        if opts.profile == KeyProfile::HybridPqc {
            subkeys.push(pqc_subkey_params(version)?);
        }

        let mut params = SecretKeyParamsBuilder::default();
        params
            .version(version)
            .key_type(primary_type)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id(uid)
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha224,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
                CompressionAlgorithm::Uncompressed,
            ])
            .feature_seipd_v1(true)
            .feature_seipd_v2(aead)
            .subkeys(subkeys);
        if aead {
            params.preferred_aead_algorithms(smallvec![
                (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb),
                (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Ocb),
                (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Gcm),
            ]);
        }
        let params = params
            .build()
            .map_err(|e| Error::KeyGeneration(e.to_string()))?;
        let secret = params
            .generate(rand::thread_rng())
            .map_err(|e| Error::KeyGeneration(e.to_string()))?;
        Ok(Self { secret })
    }

    /// Import an ASCII-armored transferable secret key (optionally passphrase protected).
    pub fn from_armored_secret(armored: &str, passphrase: Option<&str>) -> Result<Self> {
        Self::from_secret_bytes(armored.as_bytes(), passphrase)
    }

    /// Import a transferable secret key from armored *or* binary bytes.
    pub fn from_secret_bytes(data: &[u8], passphrase: Option<&str>) -> Result<Self> {
        let (mut secret, _headers) = SignedSecretKey::from_reader_single(data)
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        unlock_all(&mut secret, passphrase)?;
        secret
            .verify_bindings()
            .map_err(|e| Error::InvalidKey(format!("self-signatures do not verify: {e}")))?;
        Ok(Self { secret })
    }

    /// Export the secret key, ASCII armored. With `Some(passphrase)` every secret packet is
    /// locked with AES-256 CFB + iterated/salted S2K (v4) or AEAD + Argon2 (v6) — the formats
    /// gpg and other OpenPGP implementations understand.
    pub fn to_armored_secret(&self, passphrase: Option<&str>) -> Result<String> {
        let mut key = self.secret.clone();
        if let Some(pw) = passphrase {
            if pw.is_empty() {
                return Err(Error::InvalidInput("empty passphrase".into()));
            }
            let pw = Password::from(pw);
            let mut rng = rand::thread_rng();
            key.primary_key.set_password(&mut rng, &pw)?;
            for sub in key.secret_subkeys.iter_mut() {
                sub.key.set_password(&mut rng, &pw)?;
            }
        }
        Ok(key.to_armored_string(ArmorOptions::default())?)
    }

    /// Export the (unprotected) secret key as binary OpenPGP packets.
    pub fn to_secret_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.secret.to_writer(&mut out)?;
        Ok(out)
    }

    /// Upper-case hex fingerprint of the primary key (40 hex chars for v4, 64 for v6).
    pub fn fingerprint(&self) -> String {
        format!("{:X}", self.secret.fingerprint())
    }

    /// Upper-case hex 64-bit key id of the primary key.
    pub fn key_id(&self) -> String {
        hex_upper(self.secret.legacy_key_id().as_ref())
    }

    /// The matching certificate (public key).
    pub fn public(&self) -> PublicKey {
        PublicKey {
            cert: self.secret.to_public_key(),
        }
    }

    /// All User IDs (`Name <addr>`).
    pub fn user_ids(&self) -> Vec<String> {
        self.secret
            .details
            .users
            .iter()
            .map(|u| user_id_string(&u.id))
            .collect()
    }

    /// The e-mail addresses found in the User IDs, primary first.
    pub fn emails(&self) -> Vec<String> {
        emails_of(&self.secret.details.users)
    }

    /// The primary e-mail address, if any User ID carries one.
    pub fn primary_email(&self) -> Option<String> {
        self.emails().into_iter().next()
    }

    /// Key version.
    pub fn version(&self) -> KeyVersion {
        key_version_of(self.secret.version())
    }

    /// Creation time of the primary key.
    pub fn created_at(&self) -> DateTime<Utc> {
        timestamp_to_datetime(self.secret.created_at())
    }

    pub(crate) fn secret(&self) -> &SignedSecretKey {
        &self.secret
    }

    /// The component to produce data signatures with: the primary key when it carries the
    /// sign flag (our generated keys), else the newest signing-capable subkey.
    pub(crate) fn signing_key(&self) -> Result<SigningRef<'_>> {
        let cert = self.secret.to_public_key();
        let primary_caps = primary_caps(&cert);
        if primary_caps.sign || primary_caps.flags_unknown {
            return Ok(SigningRef::Primary(&self.secret.primary_key));
        }
        let mut best: Option<(u32, &packet::SecretSubkey)> = None;
        for sub in &self.secret.secret_subkeys {
            let info = subkey_caps(&sub.signatures);
            if !sub.key.algorithm().can_sign() || !info.sign || info.revoked {
                continue;
            }
            let created = sub.key.created_at().as_secs();
            if best.map(|(c, _)| created > c).unwrap_or(true) {
                best = Some((created, &sub.key));
            }
        }
        best.map(|(_, k)| SigningRef::Subkey(k))
            .ok_or(Error::NoSigningKey)
    }
}

/// Which secret component signs.
pub(crate) enum SigningRef<'a> {
    Primary(&'a packet::SecretKey),
    Subkey(&'a packet::SecretSubkey),
}

impl<'a> SigningRef<'a> {
    pub(crate) fn as_dyn(&self) -> &'a dyn SigningKey {
        match self {
            SigningRef::Primary(k) => *k,
            SigningRef::Subkey(k) => *k,
        }
    }
}

/// Somebody's OpenPGP certificate (transferable public key). Import verifies all
/// self-signatures; a key whose bindings do not verify is rejected.
#[derive(Clone)]
pub struct PublicKey {
    cert: SignedPublicKey,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("fingerprint", &self.fingerprint())
            .field("user_ids", &self.user_ids())
            .field("encryption_capable", &self.encryption_capable())
            .finish()
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.cert.fingerprint() == other.cert.fingerprint()
    }
}

impl PublicKey {
    /// Parse an ASCII-armored public key block.
    pub fn from_armored(armored: &str) -> Result<Self> {
        Self::from_bytes(armored.as_bytes())
    }

    /// Parse a public key from armored *or* binary bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let (cert, _headers) = SignedPublicKey::from_reader_single(data)
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::from_cert(cert)
    }

    pub(crate) fn from_cert(cert: SignedPublicKey) -> Result<Self> {
        cert.verify_bindings()
            .map_err(|e| Error::InvalidKey(format!("self-signatures do not verify: {e}")))?;
        if cert.details.users.is_empty() && cert.version() == PgpKeyVersion::V4 {
            return Err(Error::InvalidKey("v4 key without a User ID".into()));
        }
        Ok(Self { cert })
    }

    /// ASCII armored export.
    pub fn to_armored(&self) -> Result<String> {
        Ok(self.cert.to_armored_string(ArmorOptions::default())?)
    }

    /// Binary OpenPGP export.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.cert.to_writer(&mut out)?;
        Ok(out)
    }

    /// Upper-case hex fingerprint of the primary key.
    pub fn fingerprint(&self) -> String {
        format!("{:X}", self.cert.fingerprint())
    }

    /// Upper-case hex 64-bit key id of the primary key.
    pub fn key_id(&self) -> String {
        hex_upper(self.cert.legacy_key_id().as_ref())
    }

    /// All User IDs.
    pub fn user_ids(&self) -> Vec<String> {
        self.cert
            .details
            .users
            .iter()
            .map(|u| user_id_string(&u.id))
            .collect()
    }

    /// E-mail addresses in the User IDs, primary first.
    pub fn emails(&self) -> Vec<String> {
        emails_of(&self.cert.details.users)
    }

    /// Primary e-mail address.
    pub fn primary_email(&self) -> Option<String> {
        self.emails().into_iter().next()
    }

    /// True if we could encrypt to this key *right now*: not revoked, not expired, and it has a
    /// live encryption-capable (sub)key.
    pub fn encryption_capable(&self) -> bool {
        self.encryption_capable_at(Utc::now())
    }

    /// [`Self::encryption_capable`] evaluated at a given instant.
    pub fn encryption_capable_at(&self, now: DateTime<Utc>) -> bool {
        self.encryption_target(now).is_some()
    }

    /// True if the certificate carries a live post-quantum (ML-KEM-768+X25519) encryption
    /// subkey **that this build can encrypt to** — always false without the `pqc` feature,
    /// where algorithm 35 is unknown and the X25519 subkey is used instead.
    pub fn pqc_capable(&self) -> bool {
        matches!(
            self.encryption_target(Utc::now()),
            Some(EncryptionTarget::Subkey(s)) if s.key.algorithm().is_pqc()
        )
    }

    /// True if the key holder advertises SEIPDv2 (RFC 9580 AEAD) support.
    pub fn supports_seipd_v2(&self) -> bool {
        self.cert
            .details
            .users
            .iter()
            .flat_map(|u| u.signatures.iter())
            .chain(self.cert.details.direct_signatures.iter())
            .any(|s| s.features().map(|f| f.seipd_v2()).unwrap_or(false))
    }

    /// Primary key revoked?
    pub fn is_revoked(&self) -> bool {
        !self.cert.details.revocation_signatures.is_empty()
    }

    /// Expiry of the primary key, if it has one.
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        primary_caps(&self.cert).expires.map(|s| {
            chrono::DateTime::<Utc>::from_timestamp(i64::from(s), 0)
                .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
        })
    }

    /// Key version.
    pub fn version(&self) -> KeyVersion {
        key_version_of(self.cert.version())
    }

    /// Creation time of the primary key.
    pub fn created_at(&self) -> DateTime<Utc> {
        timestamp_to_datetime(self.cert.created_at())
    }

    pub(crate) fn cert(&self) -> &SignedPublicKey {
        &self.cert
    }

    /// The component we encrypt to: the live post-quantum encryption subkey if there is one
    /// (strongest available — see the module docs), else the newest live classical encryption
    /// subkey, else the primary key if it is itself encryption capable and flagged so (RSA keys
    /// without subkeys).
    pub(crate) fn encryption_target(&self, now: DateTime<Utc>) -> Option<EncryptionTarget<'_>> {
        self.select_encryption_target(now, true)
    }

    /// Like [`Self::encryption_target`] but never a post-quantum subkey: the component every
    /// classical OpenPGP implementation can encrypt to (used for the Autocrypt minimal key).
    pub(crate) fn classical_encryption_target(
        &self,
        now: DateTime<Utc>,
    ) -> Option<EncryptionTarget<'_>> {
        self.select_encryption_target(now, false)
    }

    fn select_encryption_target(
        &self,
        now: DateTime<Utc>,
        allow_pqc: bool,
    ) -> Option<EncryptionTarget<'_>> {
        let now = u64::try_from(now.timestamp()).unwrap_or(0);
        let primary = primary_caps(&self.cert);
        if primary.revoked || primary.expired_at(now) {
            return None;
        }
        // Rank: post-quantum first, then creation time (newest wins). Without the `pqc`
        // feature `is_pqc()` is always false and algorithm 35 fails `can_encrypt()`, so this
        // reduces to "newest classical subkey".
        let mut best: Option<((bool, u32), &SignedPublicSubKey)> = None;
        for sub in &self.cert.public_subkeys {
            let alg = sub.key.algorithm();
            if !alg.can_encrypt() || (alg.is_pqc() && !allow_pqc) {
                continue;
            }
            let caps = subkey_caps(&sub.signatures);
            if !caps.encrypt || caps.revoked {
                continue;
            }
            let created = sub.key.created_at().as_secs();
            if let Some(exp) = caps.expiry_secs(created) {
                if exp <= now {
                    continue;
                }
            }
            let rank = (alg.is_pqc(), created);
            if best.map(|(r, _)| rank > r).unwrap_or(true) {
                best = Some((rank, sub));
            }
        }
        if let Some((_, sub)) = best {
            return Some(EncryptionTarget::Subkey(sub));
        }
        if self.cert.primary_key.algorithm().can_encrypt() && primary.encrypt {
            return Some(EncryptionTarget::Primary(&self.cert.primary_key));
        }
        None
    }

    /// Find the component (primary or subkey) matching any of the given issuer fingerprints /
    /// key ids, for signature verification.
    pub(crate) fn component_for(
        &self,
        fingerprints: &[&Fingerprint],
        key_ids: &[&KeyId],
    ) -> Option<Component<'_>> {
        let matches = |fp: Fingerprint, id: KeyId| {
            fingerprints.iter().any(|f| **f == fp) || key_ids.iter().any(|k| **k == id)
        };
        if matches(
            self.cert.primary_key.fingerprint(),
            self.cert.primary_key.legacy_key_id(),
        ) {
            return Some(Component::Primary(&self.cert.primary_key));
        }
        self.cert
            .public_subkeys
            .iter()
            .find(|s| matches(s.key.fingerprint(), s.key.legacy_key_id()))
            .map(|s| Component::Subkey(&s.key))
    }
}

/// The public component a message is encrypted to.
pub(crate) enum EncryptionTarget<'a> {
    Primary(&'a packet::PublicKey),
    Subkey(&'a SignedPublicSubKey),
}

/// The public component that made a signature.
pub(crate) enum Component<'a> {
    Primary(&'a packet::PublicKey),
    Subkey(&'a packet::PublicSubkey),
}

impl<'a> Component<'a> {
    pub(crate) fn as_verifying(&self) -> &'a dyn VerifyingKey {
        match self {
            Component::Primary(k) => *k,
            Component::Subkey(k) => *k,
        }
    }

    /// Verify a detached data signature with this component.
    pub(crate) fn verify_detached(
        &self,
        sig: &pgp::composed::DetachedSignature,
        data: &[u8],
    ) -> pgp::errors::Result<()> {
        match self {
            Component::Primary(k) => sig.verify(*k, data),
            Component::Subkey(k) => sig.verify(*k, data),
        }
    }
}

/// Resolve a signature's issuer against a set of known certificates.
pub(crate) fn find_signer<'a>(
    known: &[&'a PublicKey],
    sig: &Signature,
) -> Option<(&'a PublicKey, Component<'a>)> {
    let fps = sig.issuer_fingerprint();
    let ids = sig.issuer_key_id();
    known
        .iter()
        .find_map(|k| k.component_for(&fps, &ids).map(|c| (*k, c)))
}

/// Hex key id / fingerprint of a signature's issuer, for `UnknownKey` reporting.
pub(crate) fn issuer_hex(sig: &Signature) -> String {
    if let Some(id) = sig.issuer_key_id().first() {
        return hex_upper(id.as_ref());
    }
    if let Some(fp) = sig.issuer_fingerprint().first() {
        return hex_upper(fp.as_bytes());
    }
    String::from("unknown")
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Caps {
    pub(crate) sign: bool,
    pub(crate) encrypt: bool,
    pub(crate) revoked: bool,
    /// Lifetime in seconds after creation, if the binding signature sets one.
    pub(crate) lifetime: Option<u32>,
    /// Absolute expiry (primary keys only).
    pub(crate) expires: Option<u32>,
    /// No binding signature with flags found (treat permissively for signing).
    pub(crate) flags_unknown: bool,
}

impl Caps {
    fn expiry_secs(&self, created: u32) -> Option<u64> {
        self.lifetime
            .map(|l| u64::from(created).saturating_add(u64::from(l)))
    }
    fn expired_at(&self, now: u64) -> bool {
        self.expires.map(|e| u64::from(e) <= now).unwrap_or(false)
    }
}

fn newest<'a>(sigs: impl Iterator<Item = &'a Signature>) -> Option<&'a Signature> {
    sigs.max_by_key(|s| s.created().map(|t| t.as_secs()).unwrap_or(0))
}

/// Capabilities of a subkey from its binding signatures.
pub(crate) fn subkey_caps(sigs: &[Signature]) -> Caps {
    let revoked = sigs
        .iter()
        .any(|s| s.typ() == Some(SignatureType::SubkeyRevocation));
    let binding = newest(
        sigs.iter()
            .filter(|s| s.typ() == Some(SignatureType::SubkeyBinding)),
    );
    match binding {
        Some(b) => {
            let flags = b.key_flags();
            Caps {
                sign: flags.sign(),
                encrypt: flags.encrypt_comms() || flags.encrypt_storage(),
                revoked,
                lifetime: b.key_expiration_time().map(|d| d.as_secs()),
                expires: None,
                flags_unknown: false,
            }
        }
        None => Caps {
            revoked,
            flags_unknown: true,
            ..Caps::default()
        },
    }
}

/// Capabilities of the primary key from its newest self-certification (v4) or direct-key
/// signature (v6).
pub(crate) fn primary_caps(cert: &SignedPublicKey) -> Caps {
    let revoked = !cert.details.revocation_signatures.is_empty();
    let is_cert = |t: Option<SignatureType>| {
        matches!(
            t,
            Some(
                SignatureType::CertGeneric
                    | SignatureType::CertPersona
                    | SignatureType::CertCasual
                    | SignatureType::CertPositive
            )
        )
    };
    let direct = newest(
        cert.details
            .direct_signatures
            .iter()
            .filter(|s| s.typ() == Some(SignatureType::Key)),
    );
    let self_cert = newest(
        cert.details
            .users
            .iter()
            .flat_map(|u| u.signatures.iter())
            .filter(|s| is_cert(s.typ())),
    );
    let source = match (direct, self_cert) {
        (Some(d), Some(c)) => {
            // Prefer whichever carries key flags; v6 keys put them on the direct signature.
            if cert.version() == PgpKeyVersion::V6 {
                Some(d)
            } else {
                Some(c)
            }
        }
        (Some(d), None) => Some(d),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    };
    let created = cert.primary_key.created_at().as_secs();
    match source {
        Some(s) => {
            let flags = s.key_flags();
            let lifetime = s.key_expiration_time().map(|d| d.as_secs());
            Caps {
                sign: flags.sign(),
                encrypt: flags.encrypt_comms() || flags.encrypt_storage(),
                revoked,
                lifetime,
                expires: lifetime.map(|l| created.saturating_add(l)),
                flags_unknown: false,
            }
        }
        None => Caps {
            revoked,
            flags_unknown: true,
            ..Caps::default()
        },
    }
}

pub(crate) fn key_version_of(v: PgpKeyVersion) -> KeyVersion {
    match v {
        PgpKeyVersion::V6 => KeyVersion::V6,
        _ => KeyVersion::V4,
    }
}

pub(crate) fn user_id_string(id: &packet::UserId) -> String {
    match id.as_str() {
        Some(s) => s.to_string(),
        None => String::from_utf8_lossy(id.id()).into_owned(),
    }
}

pub(crate) fn emails_of(users: &[pgp::types::SignedUser]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |u: &pgp::types::SignedUser| {
        if let Some(e) = email_of_user_id(&user_id_string(&u.id)) {
            if !out.iter().any(|x| x.eq_ignore_ascii_case(&e)) {
                out.push(e);
            }
        }
    };
    for u in users.iter().filter(|u| u.is_primary()) {
        push(u);
    }
    for u in users.iter().filter(|u| !u.is_primary()) {
        push(u);
    }
    out
}

fn format_user_id(name: &str, email: &str) -> String {
    let name = name.trim();
    if name.is_empty() {
        format!("<{email}>")
    } else {
        let name: String = name
            .chars()
            .filter(|c| !matches!(c, '<' | '>' | '(' | ')'))
            .collect();
        format!("{} <{email}>", name.trim())
    }
}

/// Parameters of the ML-KEM-768+X25519 encryption subkey of a hybrid identity. RFC 9980 allows
/// this composite on both v4 and v6 keys, so it follows the version of the rest of the key.
#[cfg(feature = "pqc")]
fn pqc_subkey_params(version: PgpKeyVersion) -> Result<pgp::composed::SubkeyParams> {
    SubkeyParamsBuilder::default()
        .version(version)
        .key_type(KeyType::MlKem768X25519)
        .can_encrypt(EncryptionCaps::All)
        .build()
        .map_err(|e| Error::KeyGeneration(e.to_string()))
}

#[cfg(not(feature = "pqc"))]
fn pqc_subkey_params(_version: PgpKeyVersion) -> Result<pgp::composed::SubkeyParams> {
    Err(Error::Unsupported(
        "post-quantum hybrid keys need the `pqc` cargo feature".into(),
    ))
}

/// Remove passphrase protection from every secret packet (in memory only).
fn unlock_all(secret: &mut SignedSecretKey, passphrase: Option<&str>) -> Result<()> {
    let locked = secret.primary_key.secret_params().is_encrypted()
        || secret
            .secret_subkeys
            .iter()
            .any(|s| s.key.secret_params().is_encrypted());
    if !locked {
        return Ok(());
    }
    let Some(pw) = passphrase else {
        return Err(Error::KeyLocked);
    };
    let pw = Password::from(pw);
    if secret.primary_key.secret_params().is_encrypted() {
        secret
            .primary_key
            .remove_password(&pw)
            .map_err(|_| Error::KeyLocked)?;
    }
    for sub in secret.secret_subkeys.iter_mut() {
        if sub.key.secret_params().is_encrypted() {
            sub.key.remove_password(&pw).map_err(|_| Error::KeyLocked)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_v4_shape() {
        let id = Identity::generate("Alice Example", "alice@example.org").unwrap();
        assert_eq!(id.fingerprint().len(), 40);
        assert_eq!(id.user_ids(), vec!["Alice Example <alice@example.org>"]);
        assert_eq!(id.primary_email().as_deref(), Some("alice@example.org"));
        assert_eq!(id.version(), KeyVersion::V4);
        let pk = id.public();
        assert!(pk.encryption_capable());
        assert!(!pk.supports_seipd_v2());
        assert_eq!(pk.fingerprint(), id.fingerprint());
        assert!(matches!(
            pk.encryption_target(Utc::now()),
            Some(EncryptionTarget::Subkey(_))
        ));
    }

    #[test]
    fn generate_v6_shape() {
        let id = Identity::generate_with(
            "V6",
            "v6@example.org",
            KeyGenOptions {
                version: KeyVersion::V6,
                advertise_seipd_v2: true,
                ..KeyGenOptions::default()
            },
        )
        .unwrap();
        assert_eq!(id.fingerprint().len(), 64);
        assert_eq!(id.version(), KeyVersion::V6);
        let pk = id.public();
        assert!(pk.encryption_capable());
        assert!(pk.supports_seipd_v2());
        // v6 keys survive an armored round trip
        let again = PublicKey::from_armored(&pk.to_armored().unwrap()).unwrap();
        assert_eq!(again.fingerprint(), pk.fingerprint());
    }

    #[test]
    fn secret_export_import_roundtrip_plain_and_locked() {
        let id = Identity::generate("Bob", "bob@example.org").unwrap();
        let plain = id.to_armored_secret(None).unwrap();
        assert!(plain.starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        let back = Identity::from_armored_secret(&plain, None).unwrap();
        assert_eq!(back.fingerprint(), id.fingerprint());

        let locked = id.to_armored_secret(Some("correct horse")).unwrap();
        assert!(matches!(
            Identity::from_armored_secret(&locked, None),
            Err(Error::KeyLocked)
        ));
        assert!(matches!(
            Identity::from_armored_secret(&locked, Some("wrong")),
            Err(Error::KeyLocked)
        ));
        let unlocked = Identity::from_armored_secret(&locked, Some("correct horse")).unwrap();
        assert_eq!(unlocked.fingerprint(), id.fingerprint());
        // binary export is accepted too
        let bin = id.to_secret_bytes().unwrap();
        assert_eq!(
            Identity::from_secret_bytes(&bin, None)
                .unwrap()
                .fingerprint(),
            id.fingerprint()
        );
    }

    #[test]
    fn public_key_roundtrip_and_rejects_garbage() {
        let id = Identity::generate("Carol", "carol@example.org").unwrap();
        let armored = id.public().to_armored().unwrap();
        let pk = PublicKey::from_armored(&armored).unwrap();
        assert_eq!(pk.emails(), vec!["carol@example.org"]);
        assert_eq!(pk.key_id().len(), 16);
        let bin = pk.to_bytes().unwrap();
        assert_eq!(PublicKey::from_bytes(&bin).unwrap(), pk);
        assert!(PublicKey::from_armored("not a key").is_err());
        assert!(PublicKey::from_bytes(&bin[..bin.len() / 2]).is_err());
    }

    #[test]
    fn user_id_formatting() {
        assert_eq!(format_user_id("", "a@b.c"), "<a@b.c>");
        assert_eq!(format_user_id(" Ann <x> ", "a@b.c"), "Ann x <a@b.c>");
    }

    /// RFC 9980 sample: v4 Ed25519 primary with a single ML-KEM-768+X25519 subkey (no
    /// classical subkey). Parses in every build; only a `pqc` build can encrypt to it.
    const RFC9980_V4_SAMPLE_PK: &str = include_str!("../tests/fixtures/pqc/v4-eddsa-sample-pk.asc");

    #[test]
    fn classical_profile_never_has_a_pqc_subkey() {
        let id = Identity::generate("Plain", "plain@example.org").unwrap();
        assert_eq!(id.secret().secret_subkeys.len(), 1);
        assert!(!id.public().pqc_capable());
        assert_eq!(KeyGenOptions::default().profile, KeyProfile::Classical);
    }

    #[cfg(not(feature = "pqc"))]
    #[test]
    fn hybrid_profile_needs_the_pqc_feature() {
        // Checked at compile time: this build reports no PQC support.
        const { assert!(!crate::capabilities::PQC) };
        let err = Identity::generate_hybrid("H", "h@example.org").unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
        // A certificate with an algorithm-35 subkey still imports; the subkey is simply not an
        // encryption target for this build (the sample has no classical subkey at all).
        let pk = PublicKey::from_armored(RFC9980_V4_SAMPLE_PK).unwrap();
        assert_eq!(pk.fingerprint(), "342E5DB2DE345215CB2C944F7102FFED3B9CF12D");
        assert!(!pk.pqc_capable());
        assert!(!pk.encryption_capable());
        assert!(pk.classical_encryption_target(Utc::now()).is_none());
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn hybrid_profile_shape() {
        use pgp::crypto::public_key::PublicKeyAlgorithm;
        assert!(crate::capabilities::PQC);
        let id = Identity::generate_hybrid("Hybrid", "hybrid@example.org").unwrap();
        assert_eq!(id.version(), KeyVersion::V4);
        let algs: Vec<PublicKeyAlgorithm> = id
            .secret()
            .secret_subkeys
            .iter()
            .map(|s| s.key.algorithm())
            .collect();
        assert_eq!(
            algs,
            vec![PublicKeyAlgorithm::ECDH, PublicKeyAlgorithm::MlKem768X25519]
        );
        let pk = id.public();
        assert!(pk.encryption_capable());
        assert!(pk.pqc_capable());
        // the PQC subkey is preferred although both subkeys share a creation time …
        assert!(matches!(
            pk.encryption_target(Utc::now()),
            Some(EncryptionTarget::Subkey(s)) if s.key.algorithm() == PublicKeyAlgorithm::MlKem768X25519
        ));
        // … and the classical view still finds X25519
        assert!(matches!(
            pk.classical_encryption_target(Utc::now()),
            Some(EncryptionTarget::Subkey(s)) if s.key.algorithm() == PublicKeyAlgorithm::ECDH
        ));
        // v6 hybrid
        let v6 = Identity::generate_with(
            "H6",
            "h6@example.org",
            KeyGenOptions {
                version: KeyVersion::V6,
                profile: KeyProfile::HybridPqc,
                advertise_seipd_v2: true,
            },
        )
        .unwrap();
        assert_eq!(v6.version(), KeyVersion::V6);
        assert!(v6.public().pqc_capable());
        // RFC 9980 sample certificate: PQC-only, so it is an encryption target here
        let pk = PublicKey::from_armored(RFC9980_V4_SAMPLE_PK).unwrap();
        assert!(pk.pqc_capable());
        assert!(pk.classical_encryption_target(Utc::now()).is_none());
    }
}
