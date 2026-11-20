//! The guest envelope: OpenPGP *symmetric* encryption under a passphrase, for recipients who
//! have no key. The default profile is readable by `gpg --decrypt --passphrase` and OpenPGP.js;
//! the RFC 9580 profile uses Argon2id + AEAD for clients that support it (OpenPGP.js v6).

use pgp::composed::{ArmorOptions, DecryptionOptions, Esk, Message, MessageBuilder, TheRing};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{Password, StringToKey};
use rand::RngCore;

use crate::error::{Error, Result};
use crate::message::{check_outer_layer, read_limited, MAX_PLAINTEXT_BYTES};

/// Most password-encrypted session-key packets (SKESK) an envelope may carry. rPGP derives a
/// key from the passphrase for *every* one of them, so each costs a full S2K run.
pub(crate) const MAX_SKESK_PACKETS: usize = 4;

/// Most key-derivation work one envelope may demand, summed over its SKESK packets: octets
/// hashed by iterated+salted S2K, or KiB × passes filled by Argon2 (× 1024). 256 MiB admits both
/// product profiles (Interop: count 255 = 62 MiB; Rfc9580: Argon2 t=3 × 64 MiB = 192 MiB),
/// `gpg --symmetric --s2k-count 65011712` (even with SHA-1, which hashes it twice for AES-256)
/// and OpenPGP.js' defaults. rPGP on its own allows 2 GiB × 32 passes per packet and any number
/// of packets: one crafted guest envelope or Autocrypt Setup Message could pin a CPU for hours
/// or exhaust memory (found while building the G13 `guest_decrypt` fuzz target).
pub(crate) const MAX_S2K_WORK: u64 = 256 * 1024 * 1024;

/// Largest Argon2 memory an envelope may ask for: 2^18 KiB = 256 MiB.
pub(crate) const MAX_ARGON2_M_ENC: u8 = 18;

/// Which symmetric profile to produce.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GuestProfile {
    /// v4 SKESK, iterated+salted SHA-256 S2K at the maximum count code (255 ≈ 65 M octets),
    /// AES-256, SEIPDv1 (MDC). Decrypts with GnuPG 2.x, OpenPGP.js, Thunderbird. **Default.**
    #[default]
    Interop,
    /// RFC 9580: v6 SKESK with Argon2id (t=3, p=4, m=64 MiB), AES-256, SEIPDv2/OCB.
    /// GnuPG 2.4 cannot read this; OpenPGP.js v6 and rPGP can.
    Rfc9580,
}

/// Alphabet without the look-alikes 0/o/O and 1/l/I: exactly 32 symbols, 5 bits each.
const ALPHABET: &[u8; 32] = b"abcdefghijkmnpqrstuvwxyz23456789";

/// A fresh guest passphrase from OS randomness: five groups of four symbols
/// (`xxxx-xxxx-xxxx-xxxx-xxxx`), 100 bits of entropy, easy to read out over the phone.
pub fn generate_passphrase() -> String {
    let mut rng = rand::rngs::OsRng;
    let mut out = String::with_capacity(24);
    for group in 0..5 {
        if group > 0 {
            out.push('-');
        }
        for _ in 0..4 {
            let idx = (rng.next_u32() >> 27) as usize; // top 5 bits: uniform over 32
            out.push(ALPHABET[idx] as char);
        }
    }
    out
}

/// Encrypt `plaintext` under `passphrase` with the interop profile; returns an armored
/// `-----BEGIN PGP MESSAGE-----` block.
pub fn guest_encrypt(plaintext: &[u8], passphrase: &str) -> Result<String> {
    guest_encrypt_with(plaintext, passphrase, GuestProfile::Interop)
}

/// [`guest_encrypt`] with an explicit profile.
pub fn guest_encrypt_with(
    plaintext: &[u8],
    passphrase: &str,
    profile: GuestProfile,
) -> Result<String> {
    if passphrase.is_empty() {
        return Err(Error::InvalidInput("empty passphrase".into()));
    }
    let pw = Password::from(passphrase);
    let mut rng = rand::thread_rng();
    let builder = MessageBuilder::from_bytes("", plaintext.to_vec());
    let armored = match profile {
        GuestProfile::Interop => {
            let mut b = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
            let s2k = StringToKey::new_iterated(&mut rng, HashAlgorithm::Sha256, 255);
            b.encrypt_with_password(s2k, &pw)?;
            b.to_armored_string(&mut rng, ArmorOptions::default())?
        }
        GuestProfile::Rfc9580 => {
            let mut b = builder.seipd_v2(
                &mut rng,
                SymmetricKeyAlgorithm::AES256,
                AeadAlgorithm::Ocb,
                ChunkSize::default(),
            );
            let s2k = StringToKey::new_argon2(&mut rng, 3, 4, 16);
            b.encrypt_with_password(&mut rng, s2k, &pw)?;
            b.to_armored_string(&mut rng, ArmorOptions::default())?
        }
    };
    Ok(armored)
}

/// Decrypt an armored guest envelope (either profile, or anything `gpg --symmetric` made).
pub fn guest_decrypt(armored: &str, passphrase: &str) -> Result<Vec<u8>> {
    guest_decrypt_bytes(armored.as_bytes(), passphrase)
}

/// [`guest_decrypt`] for armored *or* binary input.
///
/// Before the passphrase is tried, the envelope's key-derivation demands are checked against
/// [`MAX_SKESK_PACKETS`], [`MAX_ARGON2_M_ENC`] and [`MAX_S2K_WORK`] ([`Error::InvalidInput`] if
/// exceeded); the plaintext is limited to [`MAX_PLAINTEXT_BYTES`] ([`Error::TooLarge`]).
pub fn guest_decrypt_bytes(message: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    guest_decrypt_limited(message, passphrase, MAX_PLAINTEXT_BYTES)
}

/// [`guest_decrypt_bytes`] with an explicit plaintext limit (tests use small ones).
pub(crate) fn guest_decrypt_limited(
    message: &[u8],
    passphrase: &str,
    limit: u64,
) -> Result<Vec<u8>> {
    let (msg, _headers) =
        Message::from_reader(message).map_err(|e| Error::Corrupt(e.to_string()))?;
    check_outer_layer(&msg)?;
    check_s2k_budget(&msg)?;
    let pw = Password::from(passphrase);
    let ring = TheRing {
        message_password: vec![&pw],
        decrypt_options: DecryptionOptions::new().enable_gnupg_aead(),
        ..Default::default()
    };
    let (mut msg, _) = msg
        .decrypt_the_ring(ring, true)
        .map_err(|_| Error::BadPassphrase)?;
    for _ in 0..4 {
        if msg.is_compressed() {
            msg = msg.decompress().map_err(|_| Error::BadPassphrase)?;
        } else {
            break;
        }
    }
    if msg.is_compressed() {
        return Err(Error::Corrupt("too many compression layers".into()));
    }
    if msg.is_signed() {
        msg = msg.decompress().map_err(|_| Error::BadPassphrase)?;
    }
    read_limited(&mut msg, limit, |_| Error::BadPassphrase)
}

/// Refuse an envelope whose SKESK packets would make the passphrase check unreasonably
/// expensive (see [`MAX_S2K_WORK`]). Runs before any key derivation.
fn check_s2k_budget(msg: &Message<'_>) -> Result<()> {
    let Message::Encrypted { esk, .. } = msg else {
        return Ok(());
    };
    let too_costly = |what: String| {
        Err(Error::InvalidInput(format!(
            "guest envelope refused: {what} (limit: {MAX_SKESK_PACKETS} password packets, \
             {} MiB of key derivation)",
            MAX_S2K_WORK >> 20
        )))
    };
    let mut packets = 0usize;
    let mut work = 0u64;
    for e in esk {
        let Esk::SymKeyEncryptedSessionKey(skesk) = e else {
            continue;
        };
        // Packets rPGP cannot use (unknown versions) are skipped without deriving anything.
        let (Some(s2k), Some(sym_alg)) = (skesk.s2k(), skesk.sym_algorithm()) else {
            continue;
        };
        packets += 1;
        if packets > MAX_SKESK_PACKETS {
            return too_costly(format!("more than {MAX_SKESK_PACKETS} password packets"));
        }
        work = work.saturating_add(match s2k {
            StringToKey::IteratedAndSalted {
                hash_alg, count, ..
            } => {
                // RFC 9580 §3.7.1.3; rPGP hashes the whole count once per digest-sized piece of key
                let octets = (16u64 + u64::from(count & 15)) << (u64::from(count >> 4) + 6);
                let digest = hash_alg.digest_size().unwrap_or(0) as u64;
                if digest == 0 {
                    0 // rPGP refuses unknown hashes before hashing anything
                } else {
                    octets.saturating_mul((sym_alg.key_size() as u64).div_ceil(digest).max(1))
                }
            }
            StringToKey::Argon2 { t, m_enc, .. } => {
                if *m_enc > MAX_ARGON2_M_ENC {
                    return too_costly(format!("Argon2 asks for 2^{m_enc} KiB of memory"));
                }
                u64::from(*t).saturating_mul(1024u64 << m_enc)
            }
            // Simple / Salted: a single hash; Reserved / Private / Other: rPGP refuses them.
            _ => 0,
        });
    }
    if work > MAX_S2K_WORK {
        return too_costly(format!("{} MiB of key derivation", work >> 20));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_shape() {
        let p = generate_passphrase();
        assert_eq!(p.len(), 24);
        let groups: Vec<&str> = p.split('-').collect();
        assert_eq!(groups.len(), 5);
        for g in groups {
            assert_eq!(g.len(), 4);
            assert!(g.bytes().all(|b| ALPHABET.contains(&b)));
        }
        assert_ne!(generate_passphrase(), generate_passphrase());
    }

    #[test]
    fn interop_profile_roundtrip() {
        let pw = generate_passphrase();
        let armored = guest_encrypt(b"guest body", &pw).unwrap();
        assert!(armored.starts_with("-----BEGIN PGP MESSAGE-----"));
        assert_eq!(guest_decrypt(&armored, &pw).unwrap(), b"guest body");
        assert!(matches!(
            guest_decrypt(&armored, "wrong-pass"),
            Err(Error::BadPassphrase)
        ));
        assert!(guest_encrypt(b"x", "").is_err());
    }

    #[test]
    fn rfc9580_profile_roundtrip() {
        let pw = "correct horse battery staple";
        let armored = guest_encrypt_with(b"argon", pw, GuestProfile::Rfc9580).unwrap();
        assert_eq!(guest_decrypt(&armored, pw).unwrap(), b"argon");
        assert!(matches!(
            guest_decrypt(&armored, "nope"),
            Err(Error::BadPassphrase)
        ));
    }

    /// Envelope built packet by packet: `n` SKESK packets (all for `GUEST_PW`, S2K `s2k`) and
    /// an AEAD (SEIPDv2/OCB) or MDC (SEIPDv1) container around the packets of a literal message
    /// holding `data`, optionally ZLIB-compressed. Returns the bytes and the offset of the
    /// container's AEAD mode octet (meaningful for SEIPDv2 only).
    fn envelope(n: usize, s2k: StringToKey, v2: bool, data: &[u8], zlib: bool) -> (Vec<u8>, usize) {
        use pgp::packet::{PacketTrait, SymEncryptedProtectedData, SymKeyEncryptedSessionKey};
        let mut rng = rand::thread_rng();
        let pw = Password::from(GUEST_PW);
        let session_key = SymmetricKeyAlgorithm::AES256.new_session_key(&mut rng);
        let mut out = Vec::new();
        for _ in 0..n {
            let skesk = if v2 {
                SymKeyEncryptedSessionKey::encrypt_v6(
                    &mut rng,
                    &pw,
                    &session_key,
                    s2k.clone(),
                    SymmetricKeyAlgorithm::AES256,
                    AeadAlgorithm::Ocb,
                )
            } else {
                SymKeyEncryptedSessionKey::encrypt_v4(
                    &pw,
                    &session_key,
                    s2k.clone(),
                    SymmetricKeyAlgorithm::AES256,
                )
            };
            skesk.unwrap().to_writer_with_header(&mut out).unwrap();
        }
        // the plaintext packet stream: rPGP's builder without encryption
        let mut inner = MessageBuilder::from_bytes("", data.to_vec());
        if zlib {
            inner.compression(pgp::types::CompressionAlgorithm::ZLIB);
        }
        let inner = inner.to_vec(&mut rng).unwrap();
        let seipd = if v2 {
            SymEncryptedProtectedData::encrypt_seipdv2(
                &mut rng,
                SymmetricKeyAlgorithm::AES256,
                AeadAlgorithm::Ocb,
                ChunkSize::default(),
                session_key.as_ref(),
                &inner,
            )
        } else {
            SymEncryptedProtectedData::encrypt_seipdv1(
                &mut rng,
                SymmetricKeyAlgorithm::AES256,
                session_key.as_ref(),
                &inner,
            )
        }
        .unwrap();
        let start = out.len();
        seipd.to_writer_with_header(&mut out).unwrap();
        // new-format tag octet, then a 1-, 2- or 5-octet length, then the body
        let len_octets = match out[start + 1] {
            0..=191 => 1,
            192..=223 => 2,
            _ => 5,
        };
        let body = start + 1 + len_octets;
        if v2 {
            assert_eq!(&out[body..body + 3], &[2, 9, 2], "v2, AES-256, OCB");
        }
        (out, body + 2)
    }

    const GUEST_PW: &str = "guest-test-passphrase";

    fn cheap() -> StringToKey {
        StringToKey::new_iterated(rand::thread_rng(), HashAlgorithm::Sha256, 0)
    }

    /// Fuzz finding (G13 `guest_decrypt`): an unknown AEAD mode octet in the SEIPDv2 header of
    /// a guest envelope / setup message panicked inside rPGP. It must be an error.
    #[test]
    fn unknown_aead_mode_in_envelope_is_an_error_not_a_panic() {
        for octet in [0u8, 4, 99, 255] {
            let (mut env, aead_at) = envelope(1, cheap(), true, b"aead", false);
            env[aead_at] = octet;
            assert!(guest_decrypt_bytes(&env, GUEST_PW).is_err(), "mode {octet}");
        }
        let (env, _) = envelope(1, cheap(), true, b"aead", false);
        assert_eq!(guest_decrypt_bytes(&env, GUEST_PW).unwrap(), b"aead");
    }

    #[test]
    fn envelopes_demanding_excessive_key_derivation_are_refused() {
        // one key derivation per SKESK packet: more than MAX_SKESK_PACKETS is refused up front
        let (ok, _) = envelope(MAX_SKESK_PACKETS, cheap(), false, b"four", false);
        assert_eq!(guest_decrypt_bytes(&ok, GUEST_PW).unwrap(), b"four");
        let (many, _) = envelope(MAX_SKESK_PACKETS + 1, cheap(), false, b"five", false);
        assert!(matches!(
            guest_decrypt_bytes(&many, GUEST_PW),
            Err(Error::InvalidInput(_))
        ));
        // Argon2 parameters are read from the (unauthenticated) S2K specifier; build a cheap one
        // and patch t / m_enc: the refusal must come before any derivation.
        let salt = [0x5a; 16];
        let argon = |t: u8, m_enc: u8| {
            let (mut env, _) = envelope(
                1,
                StringToKey::Argon2 {
                    salt,
                    t: 1,
                    p: 1,
                    m_enc: 3,
                },
                true,
                b"argon",
                false,
            );
            let at = env.windows(16).position(|w| w == salt).unwrap() + 16;
            env[at] = t;
            env[at + 2] = m_enc;
            env
        };
        let started = std::time::Instant::now();
        // 512 MiB of memory
        assert!(matches!(
            guest_decrypt_bytes(&argon(1, MAX_ARGON2_M_ENC + 1), GUEST_PW),
            Err(Error::InvalidInput(_))
        ));
        // within the memory ceiling, but 32 passes × 256 MiB of work
        assert!(matches!(
            guest_decrypt_bytes(&argon(32, MAX_ARGON2_M_ENC), GUEST_PW),
            Err(Error::InvalidInput(_))
        ));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "refusal must not run the KDF"
        );
        // the product's own profiles stay within the budget (see also the round-trip tests)
        let s2k_255 = StringToKey::new_iterated(rand::thread_rng(), HashAlgorithm::Sha256, 255);
        let (gpg_like, _) = envelope(1, s2k_255, false, b"gpg max count", false);
        assert_eq!(
            guest_decrypt_bytes(&gpg_like, GUEST_PW).unwrap(),
            b"gpg max count"
        );
    }

    #[test]
    fn envelope_plaintext_is_limited() {
        let zeros = vec![0u8; 64 * 1024];
        let (bomb, _) = envelope(1, cheap(), false, &zeros, true);
        assert!(bomb.len() < 1024, "64 KiB of zeros should compress well");
        assert!(matches!(
            guest_decrypt_limited(&bomb, GUEST_PW, 64 * 1024 - 1),
            Err(Error::TooLarge { .. })
        ));
        assert_eq!(
            guest_decrypt_limited(&bomb, GUEST_PW, 64 * 1024)
                .unwrap()
                .len(),
            64 * 1024
        );
    }

    #[test]
    fn tampered_envelope_fails() {
        let pw = "pw";
        let armored = guest_encrypt(b"0123456789abcdef", pw).unwrap();
        // flip a byte inside the base64 body (not the armor checksum/footer)
        let mut lines: Vec<String> = armored.lines().map(String::from).collect();
        let body_idx = lines
            .iter()
            .position(|l| !l.is_empty() && !l.starts_with("-----") && !l.contains(':'))
            .unwrap();
        let mut body: Vec<u8> = lines[body_idx].clone().into_bytes();
        let i = body.len() / 2;
        body[i] = if body[i] == b'A' { b'B' } else { b'A' };
        lines[body_idx] = String::from_utf8(body).unwrap();
        // drop the CRC line so the armor parser does not reject it before decryption
        lines.retain(|l| !l.starts_with('='));
        let tampered = lines.join("\n");
        assert!(guest_decrypt(&tampered, pw).is_err());
    }
}
