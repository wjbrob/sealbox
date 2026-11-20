//! Detached signatures for PGP/MIME `multipart/signed` (RFC 3156).

use pgp::composed::{ArmorOptions, Deserializable, DetachedSignature};
use pgp::crypto::hash::HashAlgorithm;
use pgp::ser::Serialize;
use pgp::types::Password;

use crate::error::{Error, Result};
use crate::keys::{find_signer, issuer_hex, Identity, SigningRef};
use crate::message::SignatureStatus;

/// The `micalg` parameter for `multipart/signed` bodies produced by [`sign_detached`].
pub const MICALG: &str = "pgp-sha256";

/// The hash algorithm used for detached signatures, as a `micalg` value.
pub fn micalg() -> &'static str {
    MICALG
}

/// Sign `data` (already in canonical CRLF MIME form, as RFC 3156 requires) and return an
/// armored `-----BEGIN PGP SIGNATURE-----` block, binary signature type, SHA-256.
pub fn sign_detached(data: &[u8], signer: &Identity) -> Result<String> {
    Ok(make(data, signer)?.to_armored_string(ArmorOptions::default())?)
}

/// Binary (unarmored) detached signature packet.
pub fn sign_detached_binary(data: &[u8], signer: &Identity) -> Result<Vec<u8>> {
    Ok(make(data, signer)?.to_bytes()?)
}

fn make(data: &[u8], signer: &Identity) -> Result<DetachedSignature> {
    let rng = rand::thread_rng();
    let pw = Password::empty();
    let sig = match signer.signing_key()? {
        SigningRef::Primary(k) => {
            DetachedSignature::sign_binary_data(rng, k, &pw, HashAlgorithm::Sha256, data)?
        }
        SigningRef::Subkey(k) => {
            DetachedSignature::sign_binary_data(rng, k, &pw, HashAlgorithm::Sha256, data)?
        }
    };
    Ok(sig)
}

/// Verify an armored or binary detached signature (possibly several signature packets) over
/// `data` against `known_signers`. One status per signature packet.
pub fn verify_detached(
    data: &[u8],
    signature: &[u8],
    known_signers: &[&crate::PublicKey],
) -> Result<Vec<SignatureStatus>> {
    let (iter, _headers) = DetachedSignature::from_reader_many(signature)
        .map_err(|e| Error::InvalidInput(format!("not a detached signature: {e}")))?;
    let mut out = Vec::new();
    for item in iter {
        let sig = item.map_err(|e| Error::InvalidInput(format!("bad signature packet: {e}")))?;
        let status = match find_signer(known_signers, &sig.signature) {
            Some((pk, component)) => match component.verify_detached(&sig, data) {
                Ok(()) => SignatureStatus::Good {
                    fingerprint: pk.fingerprint(),
                },
                Err(_) => SignatureStatus::Bad {
                    fingerprint: pk.fingerprint(),
                },
            },
            None => SignatureStatus::UnknownKey {
                key_id: issuer_hex(&sig.signature),
            },
        };
        out.push(status);
    }
    if out.is_empty() {
        return Err(Error::InvalidInput("no signature packets found".into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detached_roundtrip_good_bad_unknown() {
        let alice = Identity::generate("Alice", "alice@example.org").unwrap();
        let mallory = Identity::generate("Mallory", "m@example.org").unwrap();
        let data = b"Content-Type: text/plain\r\n\r\nhello\r\n";
        let sig = sign_detached(data, &alice).unwrap();
        assert!(sig.starts_with("-----BEGIN PGP SIGNATURE-----"));
        assert_eq!(
            verify_detached(data, sig.as_bytes(), &[&alice.public()]).unwrap(),
            vec![SignatureStatus::Good {
                fingerprint: alice.fingerprint()
            }]
        );
        assert_eq!(
            verify_detached(b"tampered", sig.as_bytes(), &[&alice.public()]).unwrap(),
            vec![SignatureStatus::Bad {
                fingerprint: alice.fingerprint()
            }]
        );
        let unknown = verify_detached(data, sig.as_bytes(), &[&mallory.public()]).unwrap();
        assert_eq!(
            unknown,
            vec![SignatureStatus::UnknownKey {
                key_id: alice.key_id()
            }]
        );
        let bin = sign_detached_binary(data, &alice).unwrap();
        assert!(matches!(
            verify_detached(data, &bin, &[&alice.public()]).unwrap()[0],
            SignatureStatus::Good { .. }
        ));
        assert!(verify_detached(data, b"nonsense", &[&alice.public()]).is_err());
        assert_eq!(micalg(), "pgp-sha256");
    }
}
