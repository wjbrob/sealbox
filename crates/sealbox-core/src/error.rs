//! Error type for sealbox-core.

/// Everything the engine can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("store: {0}")]
    Store(#[from] rusqlite::Error),

    #[error("crypto: {0}")]
    Crypto(#[from] sealbox_crypto::Error),

    #[error("MIME: {0}")]
    Mime(#[from] sealbox_mail::MimeError),

    #[error("IMAP: {0}")]
    Imap(#[from] sealbox_mail::ImapError),

    #[error("SMTP: {0}")]
    Smtp(#[from] sealbox_mail::SmtpError),

    #[error("autodiscover: {0}")]
    Discover(#[from] sealbox_mail::DiscoverError),

    /// A server configuration refused by the transport policy before anything was sent:
    /// plaintext towards a public host, or an OAuth token for a host outside its provider's
    /// domains (`sealbox_mail::net_policy`, docs/THREAT_MODEL.md R12/R14). The CLI exits 4.
    #[error("{0}")]
    TransportPolicy(#[from] sealbox_mail::TransportPolicyError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("account not found: {0}")]
    AccountNotFound(String),

    #[error("account already exists: {0}")]
    AccountExists(String),

    #[error("message not found: {0}")]
    MessageNotFound(i64),

    #[error("attachment {index} not found on message {message}")]
    AttachmentNotFound { message: i64, index: usize },

    #[error("account {0} has no identity (secret key)")]
    NoIdentity(String),

    /// The send policy refused to downgrade: these recipients have no usable key.
    #[error("encryption refused: no usable key for {}", missing.join(", "))]
    RecipientsWithoutKeys { missing: Vec<String> },

    #[error("policy: {0}")]
    Policy(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("key directory: {0}")]
    Directory(String),

    /// No Sealbox server / key directory is configured (`sealbox server set-url`,
    /// `SEALBOX_SERVER_URL` or `SEALBOX_DIRECTORY_URL`); nothing was contacted.
    #[error("no Sealbox server configured: {0}")]
    ServerNotConfigured(String),

    #[error("guest server: {0}")]
    Guest(String),

    /// A connection or authentication failure that is not already an IMAP/SMTP error.
    #[error("connection: {0}")]
    Connection(String),

    /// The profile is encrypted at rest and the key is missing or wrong (G27). Nothing was
    /// read; the CLI exits 5.
    #[error("profile locked: {0}")]
    ProfileLocked(String),

    /// The profile was written by a newer Sealbox: its store schema (`meta.schema_version`)
    /// is higher than this build's, whose writes could break it. Nothing was read or written;
    /// the CLI exits 5.
    #[error(
        "profile newer than this build: store schema {profile}, this build reads up to \
         {engine}; update Sealbox to open it (nothing was changed)"
    )]
    ProfileNewer { profile: i64, engine: i64 },

    /// A wrapped value failed authentication: tampered, moved to another row/column, or
    /// stored unwrapped in a keyed profile (G27).
    #[error("secret integrity: {0}")]
    SecretIntegrity(String),

    /// `send_draft` was called for a draft this engine is already sending. This call sent
    /// nothing; the send in flight decides whether the draft is kept.
    #[error("draft {0} is being sent")]
    DraftBeingSent(i64),
}

impl Error {
    /// True for policy refusals (the CLI exits 3).
    pub fn is_policy_refusal(&self) -> bool {
        matches!(self, Error::RecipientsWithoutKeys { .. } | Error::Policy(_))
    }

    /// True for authentication / connection failures, including connections the transport
    /// policy refused (the CLI exits 4).
    pub fn is_auth_or_connection(&self) -> bool {
        use sealbox_mail::ImapError;
        match self {
            Error::Imap(e) => matches!(
                e,
                ImapError::Connect { .. }
                    | ImapError::Tls(_)
                    | ImapError::ServerName(_)
                    | ImapError::StartTlsUnsupported
                    | ImapError::Auth(_)
                    | ImapError::LoginRejected { .. }
                    | ImapError::XOAuth2NotOffered { .. }
                    | ImapError::Policy(_)
                    | ImapError::Timeout(_)
                    | ImapError::Io(_)
            ),
            Error::Smtp(_)
            | Error::Connection(_)
            | Error::Discover(_)
            | Error::TransportPolicy(_) => true,
            _ => false,
        }
    }

    /// Suggested process exit code: 0 ok, 2 usage, 3 policy refusal, 4 auth/connection,
    /// 5 profile locked or newer than this build, 1 other.
    pub fn exit_code(&self) -> i32 {
        if matches!(self, Error::ProfileLocked(_) | Error::ProfileNewer { .. }) {
            5
        } else if self.is_policy_refusal() {
            3
        } else if self.is_auth_or_connection() {
            4
        } else if matches!(self, Error::InvalidInput(_) | Error::ServerNotConfigured(_)) {
            2
        } else {
            1
        }
    }
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
