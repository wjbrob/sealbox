//! Sealbox push relay (gate G16): a separate process that holds one IMAP IDLE session per
//! registered mailbox and, when the server reports new mail, sends a **content-free** push
//! ([`push::PushEvent`]: registration id, event kind, folder, timestamp — never a subject,
//! sender, UID or count) to the registration's transport (webhook today; FCM / APNs payload
//! shapes in [`push::mobile`]).
//!
//! The relay never stores credentials on disk: a registration lives in memory for the life of
//! the process and the client re-registers after a restart (or when an OAuth access token
//! expires). See `docs/PUSH_RELAY.md`.
//!
//! Modules: [`api`] (axum router: register / unregister / status / health), [`registry`]
//! (in-memory registrations with redacting `Debug` and a cancellation handle), [`worker`]
//! (the IDLE task: baseline at registration, re-`EXAMINE` on wake-up, never `FETCH`; parks a
//! registration whose credentials are rejected three times and evicts it after the parked
//! TTL), [`push`] (transports),
//! [`secret`] (credentials that cannot be serialised), [`error`].
//!
//! Exposure policies (threat-model R9): [`bind_policy`] (no open relay off loopback),
//! [`webhook_guard`] (SSRF guard for webhook URLs, at registration and at every delivery),
//! [`imap_guard`] (IMAP destinations: optional allow-list, public addresses only, checked at
//! registration and at every connect, which dials only the checked addresses), [`host_class`]
//! (address classes; plain IMAP only to local hosts), [`rate_limit`] (registrations per client
//! address). See `docs/PUSH_RELAY.md`.

pub mod api;
pub mod bind_policy;
pub mod error;
pub mod host_class;
pub mod imap_guard;
pub mod push;
pub mod rate_limit;
pub mod registry;
pub mod secret;
pub mod webhook_guard;
pub mod worker;

pub use api::{app, serve, AppState, Options};
pub use error::{ApiError, ApiResult, PushError, RelayError};
pub use imap_guard::{ImapAllowHosts, ImapGuard, ImapPolicy, ImapRefusal};
pub use push::{EventKind, LogTransport, PushEvent, PushTransport, WebhookTransport};
pub use registry::{
    MailboxSpec, NewRegistration, ParkReason, Registration, RegistrationState, RegistrationStatus,
    Registry,
};
pub use secret::{Credentials, Secret};
pub use webhook_guard::{AllowHosts, Refusal, WebhookPolicy};
pub use worker::{
    Watermark, WorkerConfig, CREDENTIALS_REJECTED, DEFAULT_PARKED_TTL, XOAUTH2_NOT_OFFERED,
};

/// RFC 3339 UTC with millisecond precision (`2026-10-28T20:00:00.000Z`), the timestamp format
/// of every push and status field.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    #[test]
    fn timestamp_is_rfc3339_utc_millis() {
        let t = super::now_rfc3339();
        assert!(t.ends_with('Z'), "{t}");
        assert_eq!(t.len(), "2026-10-28T20:00:00.000Z".len(), "{t}");
        assert!(chrono::DateTime::parse_from_rfc3339(&t).is_ok(), "{t}");
    }
}
