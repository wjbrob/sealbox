//! sealbox-core — the Sealbox engine: accounts, local SQLite store, the IMAP sync pipeline
//! (Autocrypt peer state, PGP/MIME decryption, protected headers, gossip) and the send
//! pipeline (recipient policy, PGP/MIME encrypt+sign, plaintext, guest links).
//! See `docs/ARCHITECTURE.md`.
//!
//! Every type crossing the API boundary is a plain `serde` struct ([`types`]), so a Flutter
//! bridge can mirror it. The engine is `Send + Sync`; share it behind an `Arc`.
//!
//! At-rest protection (G27, [`vault`]): secret keys, credentials, OAuth tokens, bodies and
//! attachments are wrapped in `sealbox.db` with a key from the OS keyring, a passphrase or
//! the app (mobile); see `docs/SECRETS_AT_REST.md`.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod autoreply;
mod directory;
pub mod drafts;
mod drafts_imap;
mod engine;
mod error;
pub mod filters;
mod guest;
pub mod hosted;
pub mod html;
pub mod identity;
pub mod oauth;
pub mod policy;
pub mod providers;
mod publish;
pub mod recovery;
pub mod search;
mod send;
pub mod settings;
pub mod signature;
pub mod spam;
mod store;
mod sync;
mod transport;
pub mod types;
pub mod vault;

pub use autoreply::{AutoReplyAction, AutoReplyOutcome, AutoReplyRunReport, SuppressReason};
pub use drafts::{DraftAttachment, DraftBlobInfo, DraftInput, DraftOrigin, SavedDraft};
pub use drafts_imap::{DraftServerInfo, DraftSyncReport};
pub use engine::{
    Engine, EngineConfig, DB_FILE, DEFAULT_BACKFILL_PER_SYNC, DEFAULT_FETCH_BATCH,
    DEFAULT_FETCH_BATCH_BYTES, DEFAULT_SYNC_WINDOW,
};
pub use error::{Error, Result};
pub use filters::{FilterApplied, FilterTestReport};
pub use html::HtmlBody;
pub use identity::{KtAuditOptions, KtAuditReport, KtEntriesPage, KtEntry};
pub use providers::MoveReport;
pub use recovery::{
    BackupOptions, BackupReport, BackupStatus, RecoveryPhrase, RestoreOptions, SetupExport,
};
pub use sealbox_spam::{
    EvalOptions, EvalReport, FilterAction, FilterField, FilterMatch, FilterOp, FilterOutcome,
    FilterRule, Reason, SpamLabel, Verdict,
};
pub use search::{SearchHit, SearchIndexStats, SearchQuery, MATCH_END, MATCH_START};
pub use settings::{
    AccountSettings, AutoReplyLogEntry, AutoReplySettings, SettingEntry, SettingsScope,
    SignatureIncludeOn, SignaturePlacement, SignatureSettings,
};
pub use signature::{ComposeKind, ComposeOptions, ComposePreview, SignaturePreview};
pub use spam::{
    SpamAccountStatus, SpamExplanation, SpamFeatureSummary, SpamHookAction, SpamLearnReport,
    SpamSettings, SpamStatus, StoredSpamInfo, DEFAULT_SPAM_FOLDER,
};
pub use types::*;
pub use vault::{ProfileKeySource, ProfileKeyStatus};

// Re-exported for callers that need the lower layers (tests, the CLI).
pub use sealbox_crypto;
pub use sealbox_mail;
pub use sealbox_spam;
