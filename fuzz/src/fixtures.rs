//! The fuzz fixtures and the containers the *wrapped* harness modes build around fuzz input.
//! Shared, through `#[path]`, by the harness library (`fuzz/src/lib.rs`, keys compiled in) and
//! the seed generator's `--check` mode (`fuzz/seedgen`, keys read at run time), so the check
//! exercises exactly the code the fuzz targets run.

use std::io::Cursor;

use pgp::composed::{Deserializable, RawSessionKey, SignedPublicKey};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{
    PacketTrait, PublicKeyEncryptedSessionKey, SymEncryptedProtectedData, SymKeyEncryptedSessionKey,
};
use pgp::types::{Password, StringToKey};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sealbox_crypto::{Identity, PublicKey};

use crate::params::{GUEST_PASSPHRASE, WRAP_S2K_COUNT, WRAP_S2K_SALT};

/// Everything the harnesses share, built once per process.
pub struct Fixtures {
    /// v4 fuzz identity (Ed25519 + X25519 legacy) — a decryptor.
    pub identity: Identity,
    /// v6 fuzz identity (RFC 9580, advertises SEIPDv2) — a decryptor.
    pub identity_v6: Identity,
    /// The fuzz peer's certificate — the sender of the seeds, a known signer.
    pub peer: PublicKey,
    identity_public: PublicKey,
    identity_v6_public: PublicKey,
    /// AES-256 session key of every wrapped container.
    session_key: RawSessionKey,
    /// Serialized PKESK v3 (to the v4 identity's X25519 subkey) for `session_key`.
    pkesk_v3: Vec<u8>,
    /// Serialized PKESK v6 (to the v6 identity's X25519 subkey) for `session_key`.
    pkesk_v6: Vec<u8>,
    /// Serialized SKESK v4 (cheap iterated S2K, [`GUEST_PASSPHRASE`]) for `session_key`.
    skesk_v4: Vec<u8>,
    /// Serialized SKESK v6 (cheap iterated S2K, OCB, [`GUEST_PASSPHRASE`]) for `session_key`.
    skesk_v6: Vec<u8>,
}

impl Fixtures {
    /// Build the fixtures from the armored fuzz keys (`fuzz/seeds/keys/`).
    pub fn from_armored(
        identity_secret: &str,
        identity_v6_secret: &str,
        peer_public: &str,
    ) -> Result<Self, String> {
        let err = |what: &str, e: &dyn std::fmt::Display| format!("{what}: {e}");
        let identity = Identity::from_armored_secret(identity_secret, None)
            .map_err(|e| err("fuzz identity", &e))?;
        let identity_v6 = Identity::from_armored_secret(identity_v6_secret, None)
            .map_err(|e| err("fuzz identity v6", &e))?;
        let peer = PublicKey::from_armored(peer_public).map_err(|e| err("fuzz peer", &e))?;
        let identity_public = identity.public();
        let identity_v6_public = identity_v6.public();

        let session_key = SymmetricKeyAlgorithm::AES256.new_session_key(rng());
        let cert = |id: &Identity| -> Result<SignedPublicKey, String> {
            let armored = id.public().to_armored().map_err(|e| err("export", &e))?;
            Ok(SignedPublicKey::from_armor_single(Cursor::new(armored))
                .map_err(|e| err("re-read", &e))?
                .0)
        };
        let v4 = cert(&identity)?;
        let v6 = cert(&identity_v6)?;
        let subkey = |c: &SignedPublicKey| c.public_subkeys.first().map(|s| s.key.clone());
        let v4_sub = subkey(&v4).ok_or("fuzz identity has no subkey")?;
        let v6_sub = subkey(&v6).ok_or("fuzz identity v6 has no subkey")?;

        let mut pkesk_v3 = Vec::new();
        PublicKeyEncryptedSessionKey::from_session_key_v3(
            rng(),
            &session_key,
            SymmetricKeyAlgorithm::AES256,
            &v4_sub,
        )
        .and_then(|p| p.to_writer_with_header(&mut pkesk_v3))
        .map_err(|e| err("PKESK v3", &e))?;
        let mut pkesk_v6 = Vec::new();
        PublicKeyEncryptedSessionKey::from_session_key_v6(rng(), &session_key, &v6_sub)
            .and_then(|p| p.to_writer_with_header(&mut pkesk_v6))
            .map_err(|e| err("PKESK v6", &e))?;

        let pw = Password::from(GUEST_PASSPHRASE);
        let s2k = || StringToKey::IteratedAndSalted {
            hash_alg: HashAlgorithm::Sha256,
            salt: WRAP_S2K_SALT,
            count: WRAP_S2K_COUNT,
        };
        let mut skesk_v4 = Vec::new();
        SymKeyEncryptedSessionKey::encrypt_v4(
            &pw,
            &session_key,
            s2k(),
            SymmetricKeyAlgorithm::AES256,
        )
        .and_then(|p| p.to_writer_with_header(&mut skesk_v4))
        .map_err(|e| err("SKESK v4", &e))?;
        let mut skesk_v6 = Vec::new();
        SymKeyEncryptedSessionKey::encrypt_v6(
            rng(),
            &pw,
            &session_key,
            s2k(),
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
        )
        .and_then(|p| p.to_writer_with_header(&mut skesk_v6))
        .map_err(|e| err("SKESK v6", &e))?;

        Ok(Fixtures {
            identity,
            identity_v6,
            peer,
            identity_public,
            identity_v6_public,
            session_key,
            pkesk_v3,
            pkesk_v6,
            skesk_v4,
            skesk_v6,
        })
    }

    /// Decryption keys handed to `decrypt_and_verify`.
    pub fn decryptors(&self) -> [&Identity; 2] {
        [&self.identity, &self.identity_v6]
    }

    /// Known signers handed to every verification call.
    pub fn known_signers(&self) -> [&PublicKey; 3] {
        [&self.peer, &self.identity_public, &self.identity_v6_public]
    }

    /// PKESK v3 → v4 identity + SEIPDv1(AES-256, MDC) around `packets`.
    pub fn wrap_pkesk_seipd_v1(&self, packets: &[u8]) -> Option<Vec<u8>> {
        seipd_v1(&self.pkesk_v3, self.session_key.as_ref(), packets)
    }

    /// PKESK v6 → v6 identity + SEIPDv2(AES-256/OCB) around `packets`.
    pub fn wrap_pkesk_seipd_v2(&self, packets: &[u8]) -> Option<Vec<u8>> {
        seipd_v2(&self.pkesk_v6, self.session_key.as_ref(), packets)
    }

    /// SKESK v4 ([`GUEST_PASSPHRASE`]) + SEIPDv1 around `packets`.
    pub fn wrap_skesk_seipd_v1(&self, packets: &[u8]) -> Option<Vec<u8>> {
        seipd_v1(&self.skesk_v4, self.session_key.as_ref(), packets)
    }

    /// SKESK v6 ([`GUEST_PASSPHRASE`]) + SEIPDv2/OCB around `packets`.
    pub fn wrap_skesk_seipd_v2(&self, packets: &[u8]) -> Option<Vec<u8>> {
        seipd_v2(&self.skesk_v6, self.session_key.as_ref(), packets)
    }
}

/// Split a moded input into (mode, payload); empty input → mode 0, empty payload.
pub fn split_mode(data: &[u8], modes: u8) -> (u8, &[u8]) {
    match data.split_first() {
        Some((m, rest)) => (m % modes, rest),
        None => (0, data),
    }
}

/// Deterministic RNG: libFuzzer expects one input to always take the same path.
fn rng() -> StdRng {
    StdRng::seed_from_u64(0x5ea1_b0c5_f022_0013)
}

fn seipd_v1(esk: &[u8], key: &[u8], packets: &[u8]) -> Option<Vec<u8>> {
    let edata = SymEncryptedProtectedData::encrypt_seipdv1(
        rng(),
        SymmetricKeyAlgorithm::AES256,
        key,
        packets,
    )
    .ok()?;
    let mut out = esk.to_vec();
    edata.to_writer_with_header(&mut out).ok()?;
    Some(out)
}

fn seipd_v2(esk: &[u8], key: &[u8], packets: &[u8]) -> Option<Vec<u8>> {
    let edata = SymEncryptedProtectedData::encrypt_seipdv2(
        rng(),
        SymmetricKeyAlgorithm::AES256,
        AeadAlgorithm::Ocb,
        ChunkSize::default(),
        key,
        packets,
    )
    .ok()?;
    let mut out = esk.to_vec();
    edata.to_writer_with_header(&mut out).ok()?;
    Some(out)
}
