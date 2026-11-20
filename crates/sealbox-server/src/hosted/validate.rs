//! Local-part rules for hosted addresses, the reserved-name list and password generation.
//!
//! A local part is normalised (trimmed, lower-cased) and then must be 3–32 characters of
//! `[a-z0-9._-]`, start and end with a letter or digit, contain no `..`, and must not be a
//! reserved mailbox name (RFC 2142 role addresses, obvious impersonation targets) or start
//! with `sealbox`.

use rand::{distributions::Alphanumeric, Rng};

/// Shortest local part accepted.
pub const MIN_LEN: usize = 3;
/// Longest local part accepted.
pub const MAX_LEN: usize = 32;
/// Human-readable shape, reported by `GET /v1/hosted/info`.
pub const PATTERN: &str = "^[a-z0-9]([a-z0-9._-]{1,30})[a-z0-9]$ without '..'";
/// Length of generated mailbox passwords (alphanumeric, ~143 bits of entropy).
pub const PASSWORD_LEN: usize = 24;

/// Names nobody may register (exact match after normalisation).
pub const RESERVED: &[&str] = &[
    "abuse",
    "admin",
    "administrator",
    "billing",
    "contact",
    "dkim",
    "dmarc",
    "ftp",
    "help",
    "hostmaster",
    "imap",
    "info",
    "legal",
    "mail",
    "mailer-daemon",
    "marketing",
    "news",
    "no-reply",
    "noc",
    "noreply",
    "owner",
    "postmaster",
    "privacy",
    "root",
    "sales",
    "sealbox",
    "security",
    "smtp",
    "spf",
    "staff",
    "support",
    "sysadmin",
    "team",
    "test",
    "webmaster",
    "www",
];

/// Prefixes nobody may register (`sealbox-team`, `sealboxsupport`, …).
pub const RESERVED_PREFIXES: &[&str] = &["sealbox"];

/// Why a local part was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rejection {
    TooShort,
    TooLong,
    InvalidCharacters,
    InvalidShape,
    Reserved,
}

impl Rejection {
    /// Message shown to the user.
    pub fn message(self) -> &'static str {
        match self {
            Rejection::TooShort => "name must be at least 3 characters",
            Rejection::TooLong => "name must be at most 32 characters",
            Rejection::InvalidCharacters => {
                "name may only contain lowercase letters, digits, '.', '_' and '-'"
            }
            Rejection::InvalidShape => {
                "name must start and end with a letter or digit and must not contain '..'"
            }
            Rejection::Reserved => "that name is reserved",
        }
    }

    /// Short machine-readable tag (`reason` field of the availability response).
    pub fn tag(self) -> &'static str {
        match self {
            Rejection::TooShort => "too_short",
            Rejection::TooLong => "too_long",
            Rejection::InvalidCharacters => "invalid_characters",
            Rejection::InvalidShape => "invalid_shape",
            Rejection::Reserved => "reserved",
        }
    }
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

/// Normalise and validate a requested local part; returns the canonical (lower-case) form.
pub fn normalize(local: &str) -> Result<String, Rejection> {
    let s = local.trim().to_ascii_lowercase();
    if s.chars().count() < MIN_LEN {
        return Err(Rejection::TooShort);
    }
    if s.len() > MAX_LEN {
        return Err(Rejection::TooLong);
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(Rejection::InvalidCharacters);
    }
    let first_ok = s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric());
    let last_ok = s.bytes().last().is_some_and(|b| b.is_ascii_alphanumeric());
    if !first_ok || !last_ok || s.contains("..") {
        return Err(Rejection::InvalidShape);
    }
    if is_reserved(&s) {
        return Err(Rejection::Reserved);
    }
    Ok(s)
}

/// Is this (already normalised) name reserved?
pub fn is_reserved(local: &str) -> bool {
    RESERVED.contains(&local) || RESERVED_PREFIXES.iter().any(|p| local.starts_with(p))
}

/// A fresh mailbox password: [`PASSWORD_LEN`] alphanumeric characters from the OS CSPRNG.
pub fn generate_password() -> String {
    rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(PASSWORD_LEN)
        .map(char::from)
        .collect()
}

/// Is `s` a plausible invite code (what we accept on the wire before comparing)?
pub fn invite_code_shaped(s: &str) -> bool {
    (4..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_names_and_lowercases() {
        assert_eq!(normalize("Alice").unwrap(), "alice");
        assert_eq!(normalize("  bob.smith-99_x ").unwrap(), "bob.smith-99_x");
        assert_eq!(normalize("a1b").unwrap(), "a1b");
        assert_eq!(normalize(&"x".repeat(32)).unwrap().len(), 32);
    }

    #[test]
    fn rejects_bad_shapes() {
        assert_eq!(normalize("ab"), Err(Rejection::TooShort));
        assert_eq!(normalize(&"x".repeat(33)), Err(Rejection::TooLong));
        assert_eq!(normalize("al ice"), Err(Rejection::InvalidCharacters));
        assert_eq!(normalize("ali+ce"), Err(Rejection::InvalidCharacters));
        assert_eq!(normalize("ümlaut"), Err(Rejection::InvalidCharacters));
        assert_eq!(normalize(".alice"), Err(Rejection::InvalidShape));
        assert_eq!(normalize("alice."), Err(Rejection::InvalidShape));
        assert_eq!(normalize("-alice"), Err(Rejection::InvalidShape));
        assert_eq!(normalize("al..ice"), Err(Rejection::InvalidShape));
    }

    #[test]
    fn rejects_reserved() {
        for n in [
            "admin",
            "Postmaster",
            "ABUSE",
            "root",
            "security",
            "noreply",
            "support",
        ] {
            assert_eq!(normalize(n), Err(Rejection::Reserved), "{n}");
        }
        assert_eq!(normalize("sealbox"), Err(Rejection::Reserved));
        assert_eq!(normalize("sealbox-team"), Err(Rejection::Reserved));
        assert_eq!(normalize("sealboxsupport"), Err(Rejection::Reserved));
        assert!(normalize("mysealbox").is_ok());
    }

    #[test]
    fn passwords_are_long_random_alnum() {
        let a = generate_password();
        let b = generate_password();
        assert_eq!(a.len(), PASSWORD_LEN);
        assert_ne!(a, b);
        assert!(a.bytes().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn invite_shape() {
        assert!(invite_code_shaped("beta-2026"));
        assert!(!invite_code_shaped("ab"));
        assert!(!invite_code_shaped("has space"));
    }
}
