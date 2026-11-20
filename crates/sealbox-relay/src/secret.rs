//! Credentials held in memory, with every accidental-disclosure path closed off.
//!
//! [`Secret`] has a redacting `Debug`/`Display` and deliberately **no** `Serialize`, so a
//! registration can never be echoed back through a JSON response by mistake. Error messages
//! that might carry server text are passed through [`scrub`] before they are stored.

use std::fmt;

use serde::Deserialize;

/// A password, OAuth access token or webhook bearer. Lives in memory only.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The raw value — the only way out. Call sites are the IMAP login and the webhook header.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// How the relay authenticates to the mailbox.
#[derive(Clone, PartialEq, Eq)]
pub enum Credentials {
    /// App password / plain password (SASL PLAIN or IMAP `LOGIN`).
    Password(Secret),
    /// OAuth2 access token (SASL XOAUTH2). Tokens expire; the client re-registers with a fresh
    /// one — the relay never holds a refresh token.
    OAuth(Secret),
}

impl Credentials {
    pub fn kind(&self) -> &'static str {
        match self {
            Credentials::Password(_) => "password",
            Credentials::OAuth(_) => "oauth",
        }
    }

    pub fn secret(&self) -> &Secret {
        match self {
            Credentials::Password(s) | Credentials::OAuth(s) => s,
        }
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credentials::{}([redacted])", self.kind())
    }
}

/// Replace every occurrence of each non-empty secret in `text` with `[redacted]`.
///
/// Server error strings are not supposed to contain credentials, but a relay that stores
/// `last_error` for `GET /status` must not rely on every IMAP server behaving. Secrets shorter
/// than four bytes are still scrubbed; the caller decides what counts as a secret.
pub fn scrub(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_owned();
    for s in secrets {
        if !s.is_empty() {
            out = out.replace(s, "[redacted]");
        }
    }
    out
}

/// ```compile_fail
/// // `Secret` must never gain a `Serialize` impl: a status/registration response could then
/// // echo a credential. If this starts compiling, somebody added one.
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<sealbox_relay::secret::Secret>();
/// ```
#[allow(dead_code)]
fn secret_has_no_serialize_impl() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_never_print_the_value() {
        let s = Secret::new("hunter2-very-secret");
        assert_eq!(format!("{s:?}"), "Secret([redacted])");
        assert_eq!(format!("{s}"), "[redacted]");
        let c = Credentials::OAuth(Secret::new("ya29.token"));
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("ya29"), "{dbg}");
        assert_eq!(dbg, "Credentials::oauth([redacted])");
        assert_eq!(s.expose(), "hunter2-very-secret");
    }

    #[test]
    fn scrub_replaces_every_secret() {
        let msg = "LOGIN u76 u76pw failed; token ya29.abc rejected (u76pw)";
        let out = scrub(msg, &["u76pw", "ya29.abc", ""]);
        assert_eq!(
            out,
            "LOGIN u76 [redacted] failed; token [redacted] rejected ([redacted])"
        );
        assert_eq!(scrub("clean", &["zzz"]), "clean");
    }
}
