//! sealbox-mail — MIME (PGP/MIME + protected headers), IMAP, SMTP, XOAUTH2,
//! provider autodiscovery and OAuth2 PKCE for Sealbox. See `docs/ARCHITECTURE.md`.
//!
//! This crate deliberately knows nothing about OpenPGP: the `mime` module takes
//! already-produced ciphertext / signature bytes and hands back the exact bytes
//! that must be signed, so `sealbox-crypto` can stay independent.

#![forbid(unsafe_code)]

#[cfg(feature = "net")]
pub mod autodiscover;
pub mod error;
#[cfg(feature = "html")]
pub mod html;
#[cfg(feature = "net")]
pub mod imap;
pub mod mime;
#[cfg(feature = "net")]
pub mod net_policy;
#[cfg(feature = "net")]
pub mod oauth;
#[cfg(feature = "net")]
pub mod smtp;
#[cfg(feature = "net")]
pub mod tls;

pub use error::MimeError;
#[cfg(feature = "net")]
pub use error::{DiscoverError, ImapError, MailError, OAuthError, SmtpError, TransportPolicyError};
#[cfg(feature = "net")]
pub use net_policy::{BearerScope, ConnectOptions};

/// Transport security for an IMAP or SMTP connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Security {
    /// Implicit TLS from the first byte (IMAPS 993, SMTPS 465).
    Tls,
    /// Plain TCP upgraded with STARTTLS (IMAP 143, submission 587).
    StartTls,
    /// No encryption at all. Only for local test servers: allowed towards loopback,
    /// private-network and special-use (`.test`, `.local`, …) hosts or hosts listed in
    /// `SEALBOX_ALLOW_PLAIN_HOSTS`, refused everywhere else (see the `net_policy` module).
    Plain,
}

/// How to authenticate against the mail server.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Auth {
    /// SASL PLAIN / LOGIN (or IMAP `LOGIN`).
    Password { user: String, pass: String },
    /// SASL XOAUTH2 with an OAuth2 bearer token.
    XOAuth2 { user: String, access_token: String },
}

impl Auth {
    /// The login name used for the connection.
    pub fn user(&self) -> &str {
        match self {
            Auth::Password { user, .. } | Auth::XOAuth2 { user, .. } => user,
        }
    }
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Auth::Password { user, .. } => f
                .debug_struct("Password")
                .field("user", user)
                .field("pass", &"<redacted>")
                .finish(),
            Auth::XOAuth2 { user, .. } => f
                .debug_struct("XOAuth2")
                .field("user", user)
                .field("access_token", &"<redacted>")
                .finish(),
        }
    }
}
