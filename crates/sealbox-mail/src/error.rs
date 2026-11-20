//! Error types for every module of `sealbox-mail`.

use thiserror::Error;

/// Umbrella error for callers that do not care which layer failed.
#[cfg(feature = "net")]
#[derive(Debug, Error)]
pub enum MailError {
    #[error("MIME: {0}")]
    Mime(#[from] MimeError),
    #[error("IMAP: {0}")]
    Imap(#[from] ImapError),
    #[error("SMTP: {0}")]
    Smtp(#[from] SmtpError),
    #[error("autodiscover: {0}")]
    Discover(#[from] DiscoverError),
    #[error("OAuth: {0}")]
    OAuth(#[from] OAuthError),
    #[error(transparent)]
    Policy(#[from] TransportPolicyError),
}

/// A connection refused by the transport policy (`crate::net_policy`) before any network
/// write: plaintext to a public host (docs/THREAT_MODEL.md R12) or an OAuth token for a host
/// outside its provider's domains (R14). Wrapped transparently by [`ImapError::Policy`],
/// [`SmtpError::Policy`], [`DiscoverError::Policy`] and [`MailError::Policy`], so the message
/// is the same whichever layer refused.
#[cfg(feature = "net")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportPolicyError {
    /// `Security::Plain` towards a host that is neither local/private nor listed in
    /// `SEALBOX_ALLOW_PLAIN_HOSTS`.
    InsecureTransportRefused { host: String, port: u16 },
    /// An XOAUTH2 bearer would be presented to a host outside the issuing provider's mail
    /// domains (`provider = None`: the provider is unknown and the host belongs to none).
    OAuthHostMismatch {
        provider: Option<crate::oauth::Provider>,
        host: String,
    },
}

#[cfg(feature = "net")]
impl std::fmt::Display for TransportPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportPolicyError::InsecureTransportRefused { host, port } => {
                let hp = if host.contains(':') {
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                };
                write!(
                    f,
                    "plaintext connection to {hp} refused: without TLS the password and the mail \
                     would cross the network unencrypted. `plain` is only allowed for loopback, \
                     private-network and .test/.local/.localhost/.internal/.lan/.home/.invalid \
                     hosts; use tls or starttls, or allow this exact host with \
                     {}={host}",
                    crate::net_policy::ENV_ALLOW_PLAIN_HOSTS
                )
            }
            TransportPolicyError::OAuthHostMismatch {
                provider: Some(p),
                host,
            } => write!(
                f,
                "OAuth token not sent to {host}: a {name} access token is only presented to \
                 {name}'s own mail servers (hosts under {domains}), and {host} is not one of \
                 them; check this account's IMAP/SMTP server, or sign in with a password instead",
                name = p.display_name(),
                domains = crate::net_policy::mail_domains(*p).join(", ")
            ),
            TransportPolicyError::OAuthHostMismatch {
                provider: None,
                host,
            } => write!(
                f,
                "OAuth token not sent to {host}: the token's identity provider is unknown, and \
                 {host} is not a Google or Microsoft mail server"
            ),
        }
    }
}

#[cfg(feature = "net")]
impl std::error::Error for TransportPolicyError {}

/// Errors from building or parsing RFC 5322 / PGP-MIME messages.
#[derive(Debug, Error)]
pub enum MimeError {
    #[error("invalid e-mail address: {0:?}")]
    InvalidAddress(String),
    #[error("invalid header {0:?}: {1}")]
    InvalidHeader(String, String),
    #[error("message could not be parsed")]
    Unparseable,
    #[error("malformed {0} structure: {1}")]
    Structure(&'static str, String),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from the IMAP client.
#[cfg(feature = "net")]
#[derive(Debug, Error)]
pub enum ImapError {
    #[error("connect to {host}:{port} failed: {source}")]
    Connect {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },
    #[error("TLS: {0}")]
    Tls(String),
    #[error("invalid server name {0:?}")]
    ServerName(String),
    #[error("server does not offer STARTTLS")]
    StartTlsUnsupported,
    /// No login could take place: the server greeted with `BYE` (busy, or refusing this client).
    /// A login the server answered is [`ImapError::LoginRejected`].
    #[error("authentication failed: {0}")]
    Auth(String),
    /// The server refused the login: a tagged `NO` or `BAD` in answer to `LOGIN` (password) or
    /// `AUTHENTICATE XOAUTH2` (token), including a server that first sent an XOAUTH2 error
    /// challenge. This is the server's answer to the credentials just presented, unlike a
    /// network error, a `BYE` greeting ([`ImapError::Auth`]) or
    /// [`ImapError::XOAuth2NotOffered`] (nothing was sent). `code` is the response code the
    /// server put in front of its text (RFC 5530); [`crate::imap::LoginCode::is_temporary`]
    /// tells a failure worth retrying with the same credentials (`[UNAVAILABLE]`) from a
    /// refusal. `reply` is the server's answer (`NO [AUTHENTICATIONFAILED] Invalid
    /// credentials`) with every form of the password or token replaced by `[redacted]` and
    /// control characters removed: the message never contains the credential.
    #[error("login to {host} rejected ({mechanism}): {reply}")]
    LoginRejected {
        host: String,
        /// [`crate::imap::AUTH_LOGIN`] or [`crate::imap::AUTH_XOAUTH2`].
        mechanism: &'static str,
        code: Option<crate::imap::LoginCode>,
        reply: String,
    },
    #[error("IMAP protocol: {0}")]
    Protocol(#[from] async_imap::error::Error),
    #[error("no IMAP session (not logged in or already logged out)")]
    NotConnected,
    #[error("no mailbox selected")]
    NoMailboxSelected,
    #[error("timed out after {0:?}")]
    Timeout(std::time::Duration),
    #[error("server does not advertise IDLE")]
    IdleUnsupported,
    /// The login uses an OAuth token but the server's pre-login capabilities have no
    /// `AUTH=XOAUTH2`. Sealbox never falls back to sending the token as a `LOGIN` password
    /// (docs/THREAT_MODEL.md R14); nothing was sent.
    #[error(
        "{host} does not offer OAuth sign-in over IMAP (no AUTH=XOAUTH2 in its capabilities), so \
         this account cannot sign in there with OAuth; Sealbox never sends an OAuth token as a \
         password. Sign in with a password or app password for this server instead"
    )]
    XOAuth2NotOffered { host: String },
    #[error(transparent)]
    Policy(#[from] TransportPolicyError),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(feature = "net")]
impl ImapError {
    /// A login the server refused for now rather than for good: an
    /// [`ImapError::LoginRejected`] whose response code is temporary
    /// ([`crate::imap::LoginCode::is_temporary`], RFC 5530 `[UNAVAILABLE]`). Retrying the same
    /// credentials after a pause may succeed; nothing should ask the user to sign in again
    /// because of it.
    pub fn is_transient_login(&self) -> bool {
        matches!(
            self,
            ImapError::LoginRejected { code: Some(code), .. } if code.is_temporary()
        )
    }

    /// Worth a *short, bounded* retry with the same credentials: a
    /// [`transient login refusal`](Self::is_transient_login), or a code-less refusal whose
    /// text is known to be sometimes temporary (Exchange Online's `User is authenticated but
    /// not connected`, which it also sends for failures that never clear, such as a `user=`
    /// that is not the token's mailbox or IMAP disabled for it). Unlike
    /// [`is_transient_login`](Self::is_transient_login) this says nothing about the
    /// credentials: a caller that decides whether credentials were rejected (the relay's
    /// parking) must not use it, and once the bounded retry is spent the refusal stands.
    pub fn may_clear_on_retry(&self) -> bool {
        self.is_transient_login()
            || matches!(
                self,
                ImapError::LoginRejected { code: None, reply, .. }
                    if crate::imap::is_codeless_maybe_transient_refusal(reply)
            )
    }

    /// The server refused `AUTHENTICATE XOAUTH2` for good, rather than for now: the shape of
    /// refusal an **alias** produces.
    ///
    /// Outlook/Exchange rejects XOAUTH2 when `user=` is an alias of a mailbox instead of its
    /// primary address — with a token that is perfectly good, against the right mailbox — and
    /// says only `[AUTHENTICATIONFAILED]`, or Exchange's code-less `User is authenticated but
    /// not connected`. That is indistinguishable on the wire from a genuinely wrong token, so
    /// this predicate is **grounds for a hint, never for a diagnosis**: it says the server
    /// refused the token *for this login identity* and will not change its mind on a retry
    /// ([`may_clear_on_retry`](Self::may_clear_on_retry) covers the ones that might).
    pub fn refused_xoauth2_identity(&self) -> bool {
        matches!(
            self,
            ImapError::LoginRejected { mechanism, code, .. }
                if *mechanism == crate::imap::AUTH_XOAUTH2
                    && !matches!(code, Some(c) if c.is_temporary())
        )
    }
}

/// Errors from the SMTP client.
#[cfg(feature = "net")]
#[derive(Debug, Error)]
pub enum SmtpError {
    #[error("invalid address {0:?}: {1}")]
    Address(String, String),
    #[error("TLS setup: {0}")]
    Tls(String),
    #[error("SMTP transport: {0}")]
    Transport(#[from] lettre::transport::smtp::Error),
    #[error("envelope: {0}")]
    Envelope(String),
    #[error(transparent)]
    Policy(#[from] TransportPolicyError),
}

/// Errors from provider autodiscovery.
#[cfg(feature = "net")]
#[derive(Debug, Error)]
pub enum DiscoverError {
    #[error("invalid e-mail address: {0:?}")]
    InvalidEmail(String),
    #[error("no mail server configuration found for {0:?}")]
    NotFound(String),
    #[error("HTTP: {0}")]
    Http(String),
    #[error("autoconfig XML: {0}")]
    Xml(String),
    #[error("DNS: {0}")]
    Dns(String),
    /// The discovered configuration would need plaintext towards a public host.
    #[error(transparent)]
    Policy(#[from] TransportPolicyError),
}

/// Errors from the OAuth2 / PKCE flow.
#[cfg(feature = "net")]
#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("invalid URL: {0}")]
    Url(String),
    #[error("configuration: {0}")]
    Config(String),
    #[error("token endpoint: {0}")]
    Token(String),
    #[error("loopback listener: {0}")]
    Listener(String),
    #[error("OAuth state parameter mismatch (possible CSRF)")]
    StateMismatch,
    #[error("authorization denied: {0}")]
    Denied(String),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}
