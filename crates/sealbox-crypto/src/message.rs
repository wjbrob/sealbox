//! Encrypt (+sign) and decrypt (+verify) OpenPGP messages.
//!
//! * Output is SEIPDv1 (AES-256 + MDC) unless every recipient advertises SEIPDv2, in which case
//!   AES-256/OCB SEIPDv2 (RFC 9580) is used.
//! * Each recipient's session-key packet (PKESK) goes to the component chosen by
//!   `PublicKey::encryption_target`: the ML-KEM-768+X25519 subkey when the certificate has a
//!   live one and this build has the `pqc` feature, else the newest X25519/ECDH/RSA subkey. A
//!   message to a hybrid recipient and a classical one therefore carries one algorithm-35 PKESK
//!   and one algorithm-18 PKESK over the same AES-256 session key.
//! * Signatures are one-pass, SHA-256, made inside the encryption layer.
//! * Decryption refuses legacy SED packets (no integrity protection) and SEIPDv2 containers
//!   with an AEAD mode rPGP does not implement before touching any key material, and reports
//!   integrity failures distinctly from "no key".
//! * The plaintext is read with a hard limit ([`MAX_PLAINTEXT_BYTES`]), so a compressed
//!   literal packet cannot expand into an out-of-memory abort.

use std::io::Read;

use chrono::Utc;
use pgp::composed::{
    ArmorOptions, DecryptionOptions, DummyReader, Edata, Encryption, Message, MessageBuilder,
    TheRing,
};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{ProtectedDataConfig, SymEncryptedProtectedDataConfig};
use pgp::types::{CompressionAlgorithm, Password, SigningKey};

use crate::error::{Error, Result};
use crate::keys::{find_signer, issuer_hex, EncryptionTarget, Identity, PublicKey};

/// Verification outcome for one signature found on a message.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Verified with one of the `known_signers`; `fingerprint` is that key's primary fingerprint.
    Good { fingerprint: String },
    /// The issuer is one of the `known_signers` but the signature does not verify.
    Bad { fingerprint: String },
    /// The issuer is not among the `known_signers` (hex key id or fingerprint of the issuer).
    UnknownKey { key_id: String },
}

/// Result of [`decrypt_and_verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decrypted {
    /// The literal data.
    pub plaintext: Vec<u8>,
    /// One entry per signature packet on the message (empty if unsigned).
    pub signatures: Vec<SignatureStatus>,
}

impl Decrypted {
    /// True if at least one signature is `Good` and none is `Bad`.
    pub fn signed_by_known_key(&self) -> bool {
        self.signatures
            .iter()
            .any(|s| matches!(s, SignatureStatus::Good { .. }))
            && !self
                .signatures
                .iter()
                .any(|s| matches!(s, SignatureStatus::Bad { .. }))
    }
}

/// Knobs for [`encrypt_and_sign_with`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptOptions {
    /// ZLIB-compress the literal data before encryption (off: compression leaks length info).
    pub compress: bool,
    /// Use SEIPDv2/AEAD when *all* recipients advertise it (on). Never used otherwise.
    pub prefer_seipd_v2: bool,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            compress: false,
            prefer_seipd_v2: true,
        }
    }
}

/// Encrypt `plaintext` to every recipient (and sign with `signer`, if given).
/// Returns a binary OpenPGP message. Include the sender's own [`PublicKey`] in `recipients`
/// if the sender must be able to read it back (Sent folder).
pub fn encrypt_and_sign(
    plaintext: &[u8],
    recipients: &[&PublicKey],
    signer: Option<&Identity>,
) -> Result<Vec<u8>> {
    encrypt_and_sign_with(
        plaintext,
        recipients,
        signer,
        EncryptOptions::default(),
        false,
    )
}

/// Like [`encrypt_and_sign`] but ASCII armored (`-----BEGIN PGP MESSAGE-----`).
pub fn encrypt_and_sign_armored(
    plaintext: &[u8],
    recipients: &[&PublicKey],
    signer: Option<&Identity>,
) -> Result<String> {
    let bytes = encrypt_and_sign_with(
        plaintext,
        recipients,
        signer,
        EncryptOptions::default(),
        true,
    )?;
    Ok(String::from_utf8(bytes)?)
}

/// Full-control variant: options + choice of armored (UTF-8 bytes) or binary output.
pub fn encrypt_and_sign_with(
    plaintext: &[u8],
    recipients: &[&PublicKey],
    signer: Option<&Identity>,
    opts: EncryptOptions,
    armor: bool,
) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err(Error::NoRecipients);
    }
    let now = Utc::now();
    let mut targets = Vec::with_capacity(recipients.len());
    for r in recipients {
        targets.push(
            r.encryption_target(now)
                .ok_or_else(|| Error::NoEncryptionKey {
                    fingerprint: r.fingerprint(),
                })?,
        );
    }
    let use_v2 = opts.prefer_seipd_v2 && recipients.iter().all(|r| r.supports_seipd_v2());
    let signing = match signer {
        Some(id) => Some(id.signing_key()?),
        None => None,
    };
    let signing_dyn: Option<&dyn SigningKey> = signing.as_ref().map(|s| s.as_dyn());

    let mut rng = rand::thread_rng();
    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec());
    if opts.compress {
        builder.compression(CompressionAlgorithm::ZLIB);
    }

    if use_v2 {
        let mut b = builder.seipd_v2(
            &mut rng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
        );
        for t in &targets {
            match t {
                EncryptionTarget::Primary(k) => b.encrypt_to_key(&mut rng, *k)?,
                EncryptionTarget::Subkey(s) => b.encrypt_to_key(&mut rng, &s.key)?,
            };
        }
        finish(b, signing_dyn, armor)
    } else {
        let mut b = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        for t in &targets {
            match t {
                EncryptionTarget::Primary(k) => b.encrypt_to_key(&mut rng, *k)?,
                EncryptionTarget::Subkey(s) => b.encrypt_to_key(&mut rng, &s.key)?,
            };
        }
        finish(b, signing_dyn, armor)
    }
}

fn finish<'a, E: Encryption>(
    mut b: MessageBuilder<'a, DummyReader, E>,
    signing: Option<&'a dyn SigningKey>,
    armor: bool,
) -> Result<Vec<u8>> {
    if let Some(key) = signing {
        b.sign(key, Password::empty(), HashAlgorithm::Sha256);
    }
    let mut rng = rand::thread_rng();
    if armor {
        Ok(b.to_armored_string(&mut rng, ArmorOptions::default())?
            .into_bytes())
    } else {
        Ok(b.to_vec(&mut rng)?)
    }
}

/// Decrypt an (armored or binary) OpenPGP message with any of `decryptors` and verify every
/// signature on it against `known_signers`.
///
/// Errors: [`Error::NotEncrypted`], [`Error::MissingIntegrityProtection`] (legacy SED packet —
/// never decrypted), [`Error::NoDecryptionKey`], [`Error::IntegrityFailure`] (MDC/AEAD
/// mismatch: tampered ciphertext), [`Error::Corrupt`] (also: a SEIPDv2 container with an AEAD
/// mode other than EAX/OCB/GCM), [`Error::TooLarge`] (plaintext over [`MAX_PLAINTEXT_BYTES`]).
pub fn decrypt_and_verify(
    message: &[u8],
    decryptors: &[&Identity],
    known_signers: &[&PublicKey],
) -> Result<Decrypted> {
    decrypt_and_verify_limited(message, decryptors, known_signers, MAX_PLAINTEXT_BYTES)
}

/// [`decrypt_and_verify`] with an explicit plaintext limit (tests use small ones).
pub(crate) fn decrypt_and_verify_limited(
    message: &[u8],
    decryptors: &[&Identity],
    known_signers: &[&PublicKey],
    limit: u64,
) -> Result<Decrypted> {
    if decryptors.is_empty() {
        return Err(Error::NoDecryptionKey);
    }
    let (msg, _headers) =
        Message::from_reader(message).map_err(|e| Error::Corrupt(e.to_string()))?;
    check_outer_layer(&msg)?;

    let empty = Password::empty();
    let ring = TheRing {
        secret_keys: decryptors.iter().map(|d| d.secret()).collect(),
        key_passwords: decryptors.iter().map(|_| &empty).collect(),
        decrypt_options: DecryptionOptions::new().enable_gnupg_aead(),
        ..Default::default()
    };
    let (msg, _ring_result) = msg
        .decrypt_the_ring(ring, true)
        .map_err(map_decrypt_error)?;
    read_and_verify(msg, known_signers, limit)
}

/// Upper bound on the plaintext materialised from one message, after decompression: 256 MiB.
///
/// Providers cap whole messages at 20–150 MB, and plaintext is about the size of the ciphertext
/// unless the sender compressed it, so real mail stays far below this. Without the bound one
/// small compressed literal packet (deflate alone expands ~1000:1, and compression layers nest)
/// would make rPGP's reader allocate until the process aborts — on every sync of that message.
pub const MAX_PLAINTEXT_BYTES: u64 = 256 * 1024 * 1024;

/// The outermost layer must be an integrity-protected encryption container that rPGP can
/// actually process. Checked before any key material is touched.
pub(crate) fn check_outer_layer(msg: &Message<'_>) -> Result<()> {
    match msg {
        Message::Encrypted { edata, .. } => match edata {
            Edata::SymEncryptedData { .. } => Err(Error::MissingIntegrityProtection),
            Edata::SymEncryptedProtectedData { reader } | Edata::GnupgAeadData { reader } => {
                check_container_config(reader.config())
            }
        },
        _ => Err(Error::NotEncrypted),
    }
}

/// rPGP 0.21 derives the SEIPDv2 nonce with `aead.nonce_size() - 8` *before* it checks that it
/// implements the AEAD mode, so an unknown mode octet panics (integer underflow with overflow
/// checks, an out-of-range slice without). That octet sits in the unauthenticated container
/// header: any sender, or anyone who can alter a stored or in-flight message, could crash the
/// receive pipeline. Found by the G13 fuzzer (`fuzz/`, target `guest_decrypt`). Only the modes
/// RFC 9580 defines get through; GnuPG's OCB packet already rejects anything but OCB when parsed.
fn check_container_config(config: &ProtectedDataConfig) -> Result<()> {
    if let ProtectedDataConfig::Seipd(SymEncryptedProtectedDataConfig::V2 { aead, .. }) = config {
        if !matches!(
            aead,
            AeadAlgorithm::Eax | AeadAlgorithm::Ocb | AeadAlgorithm::Gcm
        ) {
            return Err(Error::Corrupt(format!(
                "SEIPDv2 container uses an unsupported AEAD mode ({aead:?})"
            )));
        }
    }
    Ok(())
}

/// Read a message's (decompressed) literal data, refusing more than `limit` bytes. Reading to
/// the end is what makes rPGP check the MDC / final AEAD tag and reject trailing data, so the
/// data is returned only when the message was consumed completely and within the limit. A
/// failing read is mapped by `on_read_error` (`Corrupt` for messages, `BadPassphrase` for guest
/// envelopes); exceeding the limit is always [`Error::TooLarge`].
pub(crate) fn read_limited(
    msg: &mut Message<'_>,
    limit: u64,
    on_read_error: impl FnOnce(std::io::Error) -> Error,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    (&mut *msg)
        .take(limit.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(on_read_error)?;
    if out.len() as u64 > limit {
        return Err(Error::TooLarge { limit });
    }
    Ok(out)
}

pub(crate) fn map_decrypt_error(e: pgp::errors::Error) -> Error {
    match e {
        pgp::errors::Error::MissingKey => Error::NoDecryptionKey,
        pgp::errors::Error::MdcError => Error::IntegrityFailure,
        other => {
            let text = other.to_string();
            let lower = text.to_ascii_lowercase();
            if lower.contains("mdc")
                || lower.contains("aead")
                || lower.contains("tag mismatch")
                || lower.contains("modification detection")
            {
                Error::IntegrityFailure
            } else {
                Error::Pgp(other)
            }
        }
    }
}

/// Decompress, read the literal data (at most `limit` bytes) and evaluate every signature.
pub(crate) fn read_and_verify(
    mut msg: Message<'_>,
    known_signers: &[&PublicKey],
    limit: u64,
) -> Result<Decrypted> {
    let corrupt = |e: pgp::errors::Error| Error::Corrupt(e.to_string());
    for _ in 0..4 {
        if msg.is_compressed() {
            msg = msg.decompress().map_err(corrupt)?;
        } else {
            break;
        }
    }
    if msg.is_compressed() {
        return Err(Error::Corrupt("too many compression layers".into()));
    }
    if msg.is_signed() {
        // A signed message may wrap a compressed message; this is a no-op otherwise.
        msg = msg.decompress().map_err(corrupt)?;
    }
    let plaintext = read_limited(&mut msg, limit, |e| {
        Error::Corrupt(format!("reading literal data: {e}"))
    })?;

    let mut signatures = Vec::new();
    if let Message::Signed { reader, .. } = &msg {
        for i in 0..reader.num_signatures() {
            let Some(sig) = reader.signature(i) else {
                signatures.push(SignatureStatus::UnknownKey {
                    key_id: "unknown".into(),
                });
                continue;
            };
            let status = match find_signer(known_signers, sig) {
                Some((pk, component)) => {
                    match msg.verify_nested_explicit(i, component.as_verifying()) {
                        Ok(_) => SignatureStatus::Good {
                            fingerprint: pk.fingerprint(),
                        },
                        Err(_) => SignatureStatus::Bad {
                            fingerprint: pk.fingerprint(),
                        },
                    }
                }
                None => SignatureStatus::UnknownKey {
                    key_id: issuer_hex(sig),
                },
            };
            signatures.push(status);
        }
    }
    Ok(Decrypted {
        plaintext,
        signatures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyGenOptions, KeyVersion};
    use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};

    fn pair() -> (Identity, Identity) {
        (
            Identity::generate("Alice", "alice@example.org").unwrap(),
            Identity::generate("Bob", "bob@example.org").unwrap(),
        )
    }

    #[test]
    fn roundtrip_binary_and_armored_with_signature() {
        let (alice, bob) = pair();
        let msg = encrypt_and_sign(
            b"hello bob",
            &[&bob.public(), &alice.public()],
            Some(&alice),
        )
        .unwrap();
        let dec = decrypt_and_verify(&msg, &[&bob], &[&alice.public()]).unwrap();
        assert_eq!(dec.plaintext, b"hello bob");
        assert_eq!(
            dec.signatures,
            vec![SignatureStatus::Good {
                fingerprint: alice.fingerprint()
            }]
        );
        assert!(dec.signed_by_known_key());
        // the sender can read it back too
        let dec2 = decrypt_and_verify(&msg, &[&alice], &[]).unwrap();
        assert_eq!(dec2.plaintext, b"hello bob");
        assert!(matches!(
            dec2.signatures[0],
            SignatureStatus::UnknownKey { .. }
        ));

        let armored = encrypt_and_sign_armored(b"armored", &[&bob.public()], None).unwrap();
        assert!(armored.starts_with("-----BEGIN PGP MESSAGE-----"));
        let dec = decrypt_and_verify(armored.as_bytes(), &[&bob], &[]).unwrap();
        assert_eq!(dec.plaintext, b"armored");
        assert!(dec.signatures.is_empty());
    }

    #[test]
    fn wrong_key_and_tamper_are_errors() {
        let (alice, bob) = pair();
        let carol = Identity::generate("Carol", "carol@example.org").unwrap();
        let msg = encrypt_and_sign(b"secret", &[&bob.public()], Some(&alice)).unwrap();
        assert!(matches!(
            decrypt_and_verify(&msg, &[&carol], &[]),
            Err(Error::NoDecryptionKey)
        ));
        let mut tampered = msg.clone();
        let n = tampered.len();
        tampered[n - 8] ^= 0x55;
        let err = decrypt_and_verify(&tampered, &[&bob], &[]).unwrap_err();
        assert!(
            matches!(err, Error::IntegrityFailure | Error::Corrupt(_)),
            "unexpected error {err:?}"
        );
        assert!(matches!(
            decrypt_and_verify(b"garbage", &[&bob], &[]),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn seipd_v2_is_used_only_when_everyone_supports_it() {
        let aead = KeyGenOptions {
            version: KeyVersion::V4,
            advertise_seipd_v2: true,
            ..KeyGenOptions::default()
        };
        let a = Identity::generate_with("A", "a@example.org", aead).unwrap();
        let b = Identity::generate_with("B", "b@example.org", aead).unwrap();
        let legacy = Identity::generate("L", "l@example.org").unwrap();

        let msg = encrypt_and_sign(b"aead", &[&a.public(), &b.public()], Some(&a)).unwrap();
        // SEIPDv2 container: tag 18, version byte 2 right after the header in the last packet.
        assert!(is_seipd_v2(&msg), "expected a SEIPDv2 message");
        let dec = decrypt_and_verify(&msg, &[&b], &[&a.public()]).unwrap();
        assert_eq!(dec.plaintext, b"aead");
        assert!(dec.signed_by_known_key());

        let mixed = encrypt_and_sign(b"v1", &[&a.public(), &legacy.public()], None).unwrap();
        assert!(
            !is_seipd_v2(&mixed),
            "a legacy recipient must force SEIPDv1"
        );
        assert_eq!(
            decrypt_and_verify(&mixed, &[&legacy], &[])
                .unwrap()
                .plaintext,
            b"v1"
        );

        // v6 identities (RFC 9580) end to end
        let v6 = KeyGenOptions {
            version: KeyVersion::V6,
            advertise_seipd_v2: true,
            ..KeyGenOptions::default()
        };
        let x = Identity::generate_with("X", "x@example.org", v6).unwrap();
        let y = Identity::generate_with("Y", "y@example.org", v6).unwrap();
        let msg = encrypt_and_sign(b"v6", &[&y.public()], Some(&x)).unwrap();
        let dec = decrypt_and_verify(&msg, &[&y], &[&x.public()]).unwrap();
        assert_eq!(dec.plaintext, b"v6");
        assert!(dec.signed_by_known_key());
    }

    #[test]
    fn compressed_option_roundtrips() {
        let (alice, bob) = pair();
        let msg = encrypt_and_sign_with(
            b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            &[&bob.public()],
            Some(&alice),
            EncryptOptions {
                compress: true,
                prefer_seipd_v2: true,
            },
            false,
        )
        .unwrap();
        let dec = decrypt_and_verify(&msg, &[&bob], &[&alice.public()]).unwrap();
        assert!(dec.plaintext.starts_with(b"zzzz"));
        assert!(dec.signed_by_known_key());
    }

    /// Found while building the G13 harness (rPGP documents `as_data_vec` as unbounded): a
    /// compressed literal packet expands ~1000:1 per deflate layer, so one small encrypted mail
    /// could make the sync loop allocate until it aborts. The read is bounded now.
    #[test]
    fn plaintext_is_limited_so_compression_cannot_exhaust_memory() {
        let (alice, bob) = pair();
        let zeros = vec![0u8; 1 << 20];
        let msg = encrypt_and_sign_with(
            &zeros,
            &[&bob.public()],
            Some(&alice),
            EncryptOptions {
                compress: true,
                prefer_seipd_v2: false,
            },
            false,
        )
        .unwrap();
        assert!(
            msg.len() < 16 * 1024,
            "1 MiB of zeros compresses to {} bytes",
            msg.len()
        );
        assert!(matches!(
            decrypt_and_verify_limited(&msg, &[&bob], &[&alice.public()], (1 << 20) - 1),
            Err(Error::TooLarge { limit }) if limit == (1 << 20) - 1
        ));
        let dec = decrypt_and_verify_limited(&msg, &[&bob], &[&alice.public()], 1 << 20).unwrap();
        assert_eq!(dec.plaintext.len(), 1 << 20);
        assert!(
            dec.signed_by_known_key(),
            "a message read to the end still verifies"
        );
        assert_eq!(
            decrypt_and_verify(&msg, &[&bob], &[])
                .unwrap()
                .plaintext
                .len(),
            1 << 20
        );
    }

    /// PKESK v6 + SEIPDv2 (AES-256/OCB) around one literal packet, with the container's AEAD
    /// mode octet replaced by `aead_octet` (it is part of the unauthenticated header).
    fn seipd_v2_with_aead_octet(id: &Identity, aead_octet: u8) -> Vec<u8> {
        use pgp::composed::RawSessionKey;
        use pgp::packet::{
            LiteralData, PacketTrait, PublicKeyEncryptedSessionKey, SymEncryptedProtectedData,
        };
        let public = id.public();
        let subkey = &public.cert().public_subkeys[0].key;
        let mut rng = rand::thread_rng();
        let session_key: RawSessionKey = SymmetricKeyAlgorithm::AES256.new_session_key(&mut rng);
        let pkesk =
            PublicKeyEncryptedSessionKey::from_session_key_v6(&mut rng, &session_key, subkey)
                .unwrap();
        let mut inner = Vec::new();
        LiteralData::from_bytes("", pgp::bytes::Bytes::from_static(b"aead"))
            .unwrap()
            .to_writer_with_header(&mut inner)
            .unwrap();
        let seipd = SymEncryptedProtectedData::encrypt_seipdv2(
            &mut rng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
            session_key.as_ref(),
            &inner,
        )
        .unwrap();
        let mut container = Vec::new();
        seipd.to_writer_with_header(&mut container).unwrap();
        // new-format tag octet, one length octet (body < 192), then version 2, AES-256, OCB
        assert!(container[1] < 192, "test container unexpectedly large");
        assert_eq!(&container[2..5], &[2, 9, 2]);
        container[4] = aead_octet;
        let mut msg = Vec::new();
        pkesk.to_writer_with_header(&mut msg).unwrap();
        msg.extend_from_slice(&container);
        msg
    }

    /// Fuzz finding (G13, `fuzz/` target `guest_decrypt`, then reproduced here): rPGP 0.21
    /// derives the SEIPDv2 nonce with `aead.nonce_size() - 8` before checking that it knows
    /// the AEAD mode, so an unknown mode octet panicked (underflow, or an out-of-range slice in
    /// release builds). Any sender — or anyone who can alter a message in transit or in the
    /// mailbox — could crash the receive pipeline. It must be an error.
    #[test]
    fn seipd_v2_with_unknown_aead_mode_is_an_error_not_a_panic() {
        let v6 = KeyGenOptions {
            version: KeyVersion::V6,
            advertise_seipd_v2: true,
            ..KeyGenOptions::default()
        };
        // the product default (v4) and an RFC 9580 identity: a v6 PKESK can address either
        let ids = [
            Identity::generate("V4", "v4@example.org").unwrap(),
            Identity::generate_with("V6", "v6@example.org", v6).unwrap(),
        ];
        for id in &ids {
            for octet in [0u8, 4, 99, 100, 255] {
                let msg = seipd_v2_with_aead_octet(id, octet);
                assert!(
                    decrypt_and_verify(&msg, &[id], &[]).is_err(),
                    "AEAD mode {octet} accepted"
                );
            }
            // control: the untouched container (OCB) decrypts
            let msg = seipd_v2_with_aead_octet(id, 2);
            assert_eq!(
                decrypt_and_verify(&msg, &[id], &[]).unwrap().plaintext,
                b"aead"
            );
        }
    }

    /// Walk the top-level packets and report whether the encrypted container is SEIPDv2.
    fn is_seipd_v2(msg: &[u8]) -> bool {
        use pgp::packet::{Packet, PacketParser};
        let parser = PacketParser::new(msg);
        for p in parser {
            if let Ok(Packet::SymEncryptedProtectedData(d)) = p {
                return d.version() == 2;
            }
        }
        false
    }
}
