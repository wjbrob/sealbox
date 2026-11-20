//! The little OpenPGP the server needs, straight on rPGP (`pgp` 0.21):
//! parse + sanitize an uploaded certificate, reduce it to selected user IDs,
//! and verify a detached signature.
//!
//! Sanitizing means: keep only user IDs that carry a valid self-certification by the primary key
//! (and are not revoked), only subkeys whose binding verifies, only direct/revocation signatures
//! made by the primary key, and no user attributes or third-party certifications. This mirrors what
//! keys.openpgp.org serves and guarantees we only ever hand out data we verified.

use std::collections::HashSet;

use pgp::{
    composed::{
        ArmorOptions, Deserializable, DetachedSignature, SignedKeyDetails, SignedPublicKey,
    },
    packet::{Signature, SignatureType},
    ser::Serialize,
    types::{KeyDetails, SignedUser},
};

#[derive(Debug, thiserror::Error)]
pub enum PgpError {
    #[error("not a valid OpenPGP public key: {0}")]
    InvalidKey(String),
    #[error("key has no user ID with a valid self-signature")]
    NoValidUserId,
    #[error("key has no user ID with an e-mail address")]
    NoEmail,
    #[error("not a valid OpenPGP detached signature: {0}")]
    InvalidSignature(String),
    #[error("signature does not verify with this key")]
    BadSignature,
    #[error("could not serialize key: {0}")]
    Serialize(String),
}

/// A certificate that passed [`parse_and_sanitize`].
#[derive(Debug, Clone)]
pub struct VerifiedKey {
    /// The sanitized certificate.
    pub key: SignedPublicKey,
    /// Primary-key fingerprint, upper-case hex (40 chars for v4, 64 for v6).
    pub fingerprint: String,
    /// Lower-cased e-mail addresses of the valid user IDs, de-duplicated, in key order.
    pub emails: Vec<String>,
    /// The sanitized key, ASCII-armored.
    pub armored: String,
}

/// Parse an armored OpenPGP certificate and keep only cryptographically self-consistent parts.
pub fn parse_and_sanitize(armored: &str) -> Result<VerifiedKey, PgpError> {
    sanitize(parse_armored(armored)?)
}

/// Union of two certificates for the same primary key: nothing is dropped, duplicate packets
/// are kept once. Sanitize the result before storing or serving it. Uploads are merged this
/// way so that re-uploading a *stripped* copy of a public key can never remove user IDs
/// (or revocations) that the directory already holds.
pub fn merge(
    mut base: SignedPublicKey,
    other: SignedPublicKey,
) -> Result<SignedPublicKey, PgpError> {
    if base.primary_key.fingerprint() != other.primary_key.fingerprint() {
        return Err(PgpError::InvalidKey(
            "cannot merge certificates with different primary keys".into(),
        ));
    }
    fn sig_bytes(s: &Signature) -> Vec<u8> {
        s.to_bytes().unwrap_or_default()
    }
    fn union_sigs(dst: &mut Vec<Signature>, src: Vec<Signature>) {
        let mut seen: HashSet<Vec<u8>> = dst.iter().map(sig_bytes).collect();
        for s in src {
            if seen.insert(sig_bytes(&s)) {
                dst.push(s);
            }
        }
    }
    union_sigs(
        &mut base.details.revocation_signatures,
        other.details.revocation_signatures,
    );
    union_sigs(
        &mut base.details.direct_signatures,
        other.details.direct_signatures,
    );
    for user in other.details.users {
        match base
            .details
            .users
            .iter_mut()
            .find(|u| u.id.id() == user.id.id())
        {
            Some(existing) => union_sigs(&mut existing.signatures, user.signatures),
            None => base.details.users.push(user),
        }
    }
    for attr in other.details.user_attributes {
        match base
            .details
            .user_attributes
            .iter_mut()
            .find(|a| a.attr == attr.attr)
        {
            Some(existing) => union_sigs(&mut existing.signatures, attr.signatures),
            None => base.details.user_attributes.push(attr),
        }
    }
    for sub in other.public_subkeys {
        match base
            .public_subkeys
            .iter_mut()
            .find(|s| s.key.fingerprint() == sub.key.fingerprint())
        {
            Some(existing) => union_sigs(&mut existing.signatures, sub.signatures),
            None => base.public_subkeys.push(sub),
        }
    }
    Ok(base)
}

/// Keep only the cryptographically self-consistent parts of `key` (see the module docs).
pub fn sanitize(key: SignedPublicKey) -> Result<VerifiedKey, PgpError> {
    let SignedPublicKey {
        primary_key,
        details,
        public_subkeys,
    } = key;

    let mut users = Vec::new();
    for user in details.users {
        let SignedUser { id, signatures } = user;
        let valid: Vec<_> = signatures
            .into_iter()
            .filter(|sig| {
                sig.verify_certification(&primary_key, pgp::types::Tag::UserId, &id)
                    .is_ok()
            })
            .collect();
        let has_cert = valid
            .iter()
            .any(|s| s.typ() != Some(SignatureType::CertRevocation));
        // A valid certification revocation hides the user ID (we do not model re-certification
        // after revocation; it is rare and clients can still fetch by fingerprint elsewhere).
        let revoked = valid
            .iter()
            .any(|s| s.typ() == Some(SignatureType::CertRevocation));
        if has_cert && !revoked {
            users.push(SignedUser {
                id,
                signatures: valid,
            });
        }
    }
    if users.is_empty() {
        return Err(PgpError::NoValidUserId);
    }

    let public_subkeys = public_subkeys
        .into_iter()
        .filter(|sk| sk.verify_bindings(&primary_key).is_ok())
        .collect();
    let direct_signatures = details
        .direct_signatures
        .into_iter()
        .filter(|s| s.verify_key(&primary_key).is_ok())
        .collect();
    let revocation_signatures = details
        .revocation_signatures
        .into_iter()
        .filter(|s| s.verify_key(&primary_key).is_ok())
        .collect();

    let mut emails: Vec<String> = Vec::new();
    for u in &users {
        if let Some(email) = u.id.as_str().and_then(email_from_user_id) {
            if !emails.contains(&email) {
                emails.push(email);
            }
        }
    }
    if emails.is_empty() {
        return Err(PgpError::NoEmail);
    }

    let fingerprint = primary_key.fingerprint().to_string().to_uppercase();
    let key = SignedPublicKey {
        primary_key,
        details: SignedKeyDetails {
            revocation_signatures,
            direct_signatures,
            users,
            user_attributes: Vec::new(),
        },
        public_subkeys,
    };
    let armored = armor(&key)?;
    Ok(VerifiedKey {
        key,
        fingerprint,
        emails,
        armored,
    })
}

/// Parse a (previously sanitized) armored certificate without re-validating it.
pub fn parse_armored(armored: &str) -> Result<SignedPublicKey, PgpError> {
    SignedPublicKey::from_string(armored.trim())
        .map(|(k, _)| k)
        .map_err(|e| PgpError::InvalidKey(e.to_string()))
}

/// Re-armor `key` keeping only the user IDs whose e-mail address is in `emails` (lower-case).
pub fn armored_for_emails(key: &SignedPublicKey, emails: &[String]) -> Result<String, PgpError> {
    let mut reduced = key.clone();
    reduced.details.users.retain(|u| {
        u.id.as_str()
            .and_then(email_from_user_id)
            .is_some_and(|e| emails.contains(&e))
    });
    reduced.details.user_attributes.clear();
    if reduced.details.users.is_empty() {
        return Err(PgpError::NoValidUserId);
    }
    armor(&reduced)
}

fn armor(key: &SignedPublicKey) -> Result<String, PgpError> {
    key.to_armored_string(ArmorOptions::default())
        .map_err(|e| PgpError::Serialize(e.to_string()))
}

/// Parse a detached signature given either armored text or binary packet bytes.
pub fn parse_detached_signature(bytes: &[u8]) -> Result<DetachedSignature, PgpError> {
    let text = std::str::from_utf8(bytes).ok().map(str::trim_start);
    let parsed = match text {
        Some(t) if t.starts_with("-----BEGIN") => DetachedSignature::from_string(t).map(|(s, _)| s),
        _ => DetachedSignature::from_bytes(bytes),
    };
    parsed.map_err(|e| PgpError::InvalidSignature(e.to_string()))
}

/// Verify a detached signature over `data` with the primary key or any (bound) subkey of `key`.
pub fn verify_detached(key: &SignedPublicKey, sig: &[u8], data: &[u8]) -> Result<(), PgpError> {
    let sig = parse_detached_signature(sig)?;
    if sig.verify(&key.primary_key, data).is_ok() {
        return Ok(());
    }
    for sub in &key.public_subkeys {
        if sig.verify(&sub.key, data).is_ok() {
            return Ok(());
        }
    }
    Err(PgpError::BadSignature)
}

/// Extract the lower-cased e-mail address from a user ID like `Name <addr@example>`.
///
/// A user ID that is a bare address is accepted too. Returns `None` for comment-only IDs.
pub fn email_from_user_id(uid: &str) -> Option<String> {
    let candidate = match (uid.rfind('<'), uid.rfind('>')) {
        (Some(open), Some(close)) if close > open => &uid[open + 1..close],
        _ => uid,
    };
    normalize_email(candidate)
}

/// Trim, lower-case and sanity-check an e-mail address (local@domain, no whitespace, ≤254 chars).
pub fn normalize_email(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() || s.len() > 254 || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let (local, domain) = s.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() || !domain.contains('.') && domain != "localhost" {
        return None;
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return None;
    }
    Some(s.to_lowercase())
}

/// Normalize a fingerprint from a URL or header: strip spaces and `0x`, upper-case; must be
/// 40 (v4) or 64 (v6) hex digits.
pub fn normalize_fingerprint(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !(cleaned.len() == 40 || cleaned.len() == 64)
        || !cleaned.chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }
    Some(cleaned.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_extraction() {
        assert_eq!(
            email_from_user_id("Alice Test <Alice@Example.COM>").as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(
            email_from_user_id("bob@example.org").as_deref(),
            Some("bob@example.org")
        );
        assert_eq!(email_from_user_id("Just A Comment"), None);
        assert_eq!(email_from_user_id("Weird <not an email>"), None);
        assert_eq!(normalize_email(" X@Y.Z "), Some("x@y.z".to_owned()));
        assert_eq!(
            normalize_email("x@localhost"),
            Some("x@localhost".to_owned())
        );
        assert_eq!(normalize_email("x@.bad"), None);
        assert_eq!(normalize_email("@bad.com"), None);
    }

    #[test]
    fn fingerprint_normalization() {
        let v4 = "0123 4567 89ab cdef 0123  4567 89AB CDEF 0123 4567";
        assert_eq!(
            normalize_fingerprint(v4).as_deref(),
            Some("0123456789ABCDEF0123456789ABCDEF01234567")
        );
        assert_eq!(
            normalize_fingerprint("0x0123456789abcdef0123456789abcdef01234567").map(|s| s.len()),
            Some(40)
        );
        assert_eq!(normalize_fingerprint("0123456789abcdef"), None);
        assert_eq!(
            normalize_fingerprint("zz23456789abcdef0123456789abcdef01234567"),
            None
        );
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(matches!(
            parse_and_sanitize(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n"
            ),
            Err(PgpError::InvalidKey(_))
        ));
        assert!(matches!(
            parse_detached_signature(b"nonsense"),
            Err(PgpError::InvalidSignature(_))
        ));
    }
}
