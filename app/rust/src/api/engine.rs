//! The Sealbox engine (`sealbox-core`) exposed to Dart through flutter_rust_bridge.
//!
//! * [`Engine`] is an opaque handle (an `Arc` around `sealbox_core::Engine`); Dart holds one
//!   per profile directory and calls its methods. `async fn`s run on FRB's tokio runtime,
//!   plain `fn`s (local SQLite reads) on FRB's worker pool, so the UI thread never blocks.
//! * Every type that crosses the bridge is a plain DTO mirroring `sealbox_core::types`
//!   one-to-one (same field names, same meaning), converted with `From`. No JSON strings.
//!   The only deviations: enums that carry data (`AuthHint`, `AuthSpec`, `WatchEvent`,
//!   `FilterField`, `FilterAction`) are flattened into `kind` + optional fields, because FRB
//!   would otherwise require `freezed` + `build_runner` on the Dart side; tuples and maps
//!   (`FilterOutcome.errors`, `FilterTestReport.rules`, `PublishReport.status`) become small
//!   structs; `usize` counts cross as `u32`.
//! * Errors surface in Dart as `AnyhowException(message)`; the message is the engine's
//!   `Display` text (policy refusals list the recipients without keys).
//! * [`Engine::watch`] turns the engine's IMAP IDLE callback into a Dart `Stream`; the loop
//!   ends on the first event after Dart cancels the subscription (bounded by the IDLE timeout).
//!   [`Engine::sync_account_with_progress`] and [`Engine::backfill_with_progress`] stream a
//!   sync's progress the same way and end with a `Done` event carrying the report. A stream
//!   function's own result never reaches Dart (the generated code does not await it), so these
//!   send their failure into the stream as its error and return `Ok`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use flutter_rust_bridge::frb;
use sealbox_core as sc;

use crate::frb_generated::StreamSink;

fn err(e: sc::Error) -> anyhow::Error {
    anyhow!("{e}")
}

// ----- server configuration (autodiscover) ------------------------------------------------

/// Transport security of an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// Implicit TLS from the first byte (IMAPS 993, SMTPS 465).
    Tls,
    /// Plain TCP upgraded with STARTTLS (IMAP 143, submission 587).
    StartTls,
    /// No encryption at all. Only for local test servers.
    Plain,
}

impl From<sc::Security> for Security {
    fn from(s: sc::Security) -> Self {
        match s {
            sc::Security::Tls => Security::Tls,
            sc::Security::StartTls => Security::StartTls,
            sc::Security::Plain => Security::Plain,
        }
    }
}

impl From<Security> for sc::Security {
    fn from(s: Security) -> Self {
        match s {
            Security::Tls => sc::Security::Tls,
            Security::StartTls => sc::Security::StartTls,
            Security::Plain => sc::Security::Plain,
        }
    }
}

/// One server endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub security: Security,
}

impl From<sc::Endpoint> for Endpoint {
    fn from(e: sc::Endpoint) -> Self {
        Self {
            host: e.host,
            port: e.port,
            security: e.security.into(),
        }
    }
}

impl From<Endpoint> for sc::Endpoint {
    fn from(e: Endpoint) -> Self {
        sc::Endpoint::new(e.host, e.port, e.security.into())
    }
}

/// OAuth2 identity providers Sealbox knows how to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthProvider {
    Google,
    Microsoft,
    Yahoo,
}

impl From<sc::OAuthProvider> for OAuthProvider {
    fn from(p: sc::OAuthProvider) -> Self {
        match p {
            sc::OAuthProvider::Google => OAuthProvider::Google,
            sc::OAuthProvider::Microsoft => OAuthProvider::Microsoft,
            sc::OAuthProvider::Yahoo => OAuthProvider::Yahoo,
        }
    }
}

impl From<OAuthProvider> for sc::OAuthProvider {
    fn from(p: OAuthProvider) -> Self {
        match p {
            OAuthProvider::Google => sc::OAuthProvider::Google,
            OAuthProvider::Microsoft => sc::OAuthProvider::Microsoft,
            OAuthProvider::Yahoo => sc::OAuthProvider::Yahoo,
        }
    }
}

/// What kind of credential the provider wants from a third-party client.
///
/// Flattened (kind + optional fields) instead of a Rust enum with data, so the Dart side
/// needs no `freezed`/`build_runner`; same for [`AuthSpec`] and [`WatchEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthHintKind {
    /// Sign in with the provider's OAuth2 flow (XOAUTH2 on the wire); `oauth_provider` set.
    OAuth2,
    /// The normal password will not work; the user must generate an app password
    /// (`help_url` set).
    AppPassword,
    /// The regular mailbox password works.
    Password,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthHint {
    pub kind: AuthHintKind,
    pub oauth_provider: Option<OAuthProvider>,
    pub help_url: Option<String>,
}

impl From<sc::AuthHint> for AuthHint {
    fn from(h: sc::AuthHint) -> Self {
        match h {
            sc::AuthHint::OAuth2(p) => AuthHint {
                kind: AuthHintKind::OAuth2,
                oauth_provider: Some(p.into()),
                help_url: None,
            },
            sc::AuthHint::AppPassword { help_url } => AuthHint {
                kind: AuthHintKind::AppPassword,
                oauth_provider: None,
                help_url: Some(help_url),
            },
            sc::AuthHint::Password => AuthHint {
                kind: AuthHintKind::Password,
                oauth_provider: None,
                help_url: None,
            },
        }
    }
}

impl From<AuthHint> for sc::AuthHint {
    fn from(h: AuthHint) -> Self {
        match h.kind {
            AuthHintKind::OAuth2 => {
                sc::AuthHint::OAuth2(h.oauth_provider.unwrap_or(OAuthProvider::Google).into())
            }
            AuthHintKind::AppPassword => sc::AuthHint::AppPassword {
                help_url: h.help_url.unwrap_or_default(),
            },
            AuthHintKind::Password => sc::AuthHint::Password,
        }
    }
}

/// Which login name the server expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsernameForm {
    FullAddress,
    LocalPart,
}

impl From<sc::UsernameForm> for UsernameForm {
    fn from(u: sc::UsernameForm) -> Self {
        match u {
            sc::UsernameForm::FullAddress => UsernameForm::FullAddress,
            sc::UsernameForm::LocalPart => UsernameForm::LocalPart,
        }
    }
}

impl From<UsernameForm> for sc::UsernameForm {
    fn from(u: UsernameForm) -> Self {
        match u {
            UsernameForm::FullAddress => sc::UsernameForm::FullAddress,
            UsernameForm::LocalPart => sc::UsernameForm::LocalPart,
        }
    }
}

/// Where a configuration came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    BuiltIn,
    Ispdb,
    DomainAutoconfig,
    Srv,
    Mx,
    Guess,
    /// Typed in by the user (manual server settings).
    Manual,
}

impl From<sc::ConfigSource> for ConfigSource {
    fn from(s: sc::ConfigSource) -> Self {
        match s {
            sc::ConfigSource::BuiltIn => ConfigSource::BuiltIn,
            sc::ConfigSource::Ispdb => ConfigSource::Ispdb,
            sc::ConfigSource::DomainAutoconfig => ConfigSource::DomainAutoconfig,
            sc::ConfigSource::Srv => ConfigSource::Srv,
            sc::ConfigSource::Mx => ConfigSource::Mx,
            sc::ConfigSource::Guess => ConfigSource::Guess,
            sc::ConfigSource::Manual => ConfigSource::Manual,
        }
    }
}

impl From<ConfigSource> for sc::ConfigSource {
    fn from(s: ConfigSource) -> Self {
        match s {
            ConfigSource::BuiltIn => sc::ConfigSource::BuiltIn,
            ConfigSource::Ispdb => sc::ConfigSource::Ispdb,
            ConfigSource::DomainAutoconfig => sc::ConfigSource::DomainAutoconfig,
            ConfigSource::Srv => sc::ConfigSource::Srv,
            ConfigSource::Mx => sc::ConfigSource::Mx,
            ConfigSource::Guess => sc::ConfigSource::Guess,
            ConfigSource::Manual => sc::ConfigSource::Manual,
        }
    }
}

/// Discovered (or typed) server configuration for an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub imap: Endpoint,
    pub smtp: Endpoint,
    pub auth_hint: AuthHint,
    pub display_name: String,
    pub source: ConfigSource,
    pub username: UsernameForm,
}

impl From<sc::ServerConfig> for ServerConfig {
    fn from(c: sc::ServerConfig) -> Self {
        Self {
            imap: c.imap.into(),
            smtp: c.smtp.into(),
            auth_hint: c.auth_hint.into(),
            display_name: c.display_name,
            source: c.source.into(),
            username: c.username.into(),
        }
    }
}

impl From<ServerConfig> for sc::ServerConfig {
    fn from(c: ServerConfig) -> Self {
        sc::ServerConfig {
            imap: c.imap.into(),
            smtp: c.smtp.into(),
            auth_hint: c.auth_hint.into(),
            display_name: c.display_name,
            source: c.source.into(),
            username: c.username.into(),
        }
    }
}

// ----- accounts -------------------------------------------------------------------------

/// Which kind of credential an account stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    Password,
    OAuth,
}

impl From<sc::AuthKind> for AuthKind {
    fn from(k: sc::AuthKind) -> Self {
        match k {
            sc::AuthKind::Password => AuthKind::Password,
            sc::AuthKind::OAuth => AuthKind::OAuth,
        }
    }
}

/// Credentials for a new account (flattened, see [`AuthHint`]). Never logged by the engine;
/// keep it out of Dart logs too (`Debug` redacts the secrets).
#[derive(Clone, PartialEq, Eq)]
pub struct AuthSpec {
    pub kind: AuthKind,
    /// Mailbox password or app password (`kind == Password`).
    pub password: Option<String>,
    /// OAuth2 bearer token and friends (`kind == OAuth`).
    pub oauth_provider: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    /// Unix seconds.
    pub expires_at: Option<i64>,
}

impl std::fmt::Debug for AuthSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSpec")
            .field("kind", &self.kind)
            .field("oauth_provider", &self.oauth_provider)
            .finish_non_exhaustive()
    }
}

impl From<AuthSpec> for sc::AuthSpec {
    fn from(a: AuthSpec) -> Self {
        match a.kind {
            AuthKind::Password => sc::AuthSpec::Password {
                password: a.password.unwrap_or_default(),
            },
            AuthKind::OAuth => sc::AuthSpec::OAuth {
                provider: a.oauth_provider,
                access_token: a.access_token.unwrap_or_default(),
                refresh_token: a.refresh_token,
                expires_at: a.expires_at,
            },
        }
    }
}

/// Input of [`Engine::add_account`].
#[derive(Debug, Clone)]
pub struct AddAccount {
    pub email: String,
    pub display_name: Option<String>,
    pub auth: AuthSpec,
    /// Manual server settings; `None` = autodiscover (built-in table, then network).
    pub servers: Option<ServerConfig>,
    /// Login name override (default: what the configuration says, usually the full
    /// address; on an authentication failure the bare local part is tried as well).
    pub login: Option<String>,
}

impl From<AddAccount> for sc::AddAccount {
    fn from(a: AddAccount) -> Self {
        sc::AddAccount {
            email: a.email,
            display_name: a.display_name,
            auth: a.auth.into(),
            servers: a.servers.map(Into::into),
            login: a.login,
        }
    }
}

/// A stored account (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    pub id: i64,
    pub email: String,
    pub display_name: String,
    pub imap: Endpoint,
    pub smtp: Endpoint,
    pub auth_kind: AuthKind,
    pub login: String,
    /// Fingerprint of the account's OpenPGP identity.
    pub fingerprint: Option<String>,
    /// Unix seconds.
    pub created_at: i64,
}

impl From<sc::AccountInfo> for AccountInfo {
    fn from(a: sc::AccountInfo) -> Self {
        Self {
            id: a.id,
            email: a.email,
            display_name: a.display_name,
            imap: a.imap.into(),
            smtp: a.smtp.into(),
            auth_kind: a.auth_kind.into(),
            login: a.login,
            fingerprint: a.fingerprint,
            created_at: a.created_at,
        }
    }
}

// ----- sending --------------------------------------------------------------------------

/// What to do when not every recipient has a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendPolicy {
    /// Encrypt + sign when every recipient has a usable key; otherwise refuse.
    Auto,
    /// Same as `Auto` today.
    RequireEncryption,
    /// Encrypt when everyone has a key; otherwise a passphrase-protected guest link.
    GuestLink,
    /// Send plaintext (still carrying our Autocrypt header).
    AllowPlaintext,
}

impl From<SendPolicy> for sc::SendPolicy {
    fn from(p: SendPolicy) -> Self {
        match p {
            SendPolicy::Auto => sc::SendPolicy::Auto,
            SendPolicy::RequireEncryption => sc::SendPolicy::RequireEncryption,
            SendPolicy::GuestLink => sc::SendPolicy::GuestLink,
            SendPolicy::AllowPlaintext => sc::SendPolicy::AllowPlaintext,
        }
    }
}

/// An attachment to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentData {
    pub filename: String,
    /// e.g. `application/pdf`; empty = `application/octet-stream`.
    pub content_type: String,
    pub data: Vec<u8>,
}

impl From<AttachmentData> for sc::AttachmentData {
    fn from(a: AttachmentData) -> Self {
        sc::AttachmentData {
            filename: a.filename,
            content_type: a.content_type,
            data: a.data,
        }
    }
}

/// At-rest protection of the profile (mirrors `sealbox_core::ProfileKeyStatus`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileKeyStatus {
    /// Effective source: `keyring`, `passphrase`, `raw` or `none`.
    pub source: String,
    pub wrapped_rows: u64,
    pub plaintext_rows: u64,
    pub kdf: Option<String>,
    /// Set when the requested source was not usable and another was taken, or the profile
    /// is plaintext.
    pub fallback: Option<String>,
}

impl From<sc::ProfileKeyStatus> for ProfileKeyStatus {
    fn from(s: sc::ProfileKeyStatus) -> Self {
        Self {
            source: s.source,
            wrapped_rows: s.wrapped_rows,
            plaintext_rows: s.plaintext_rows,
            kdf: s.kdf,
            fallback: s.fallback,
        }
    }
}

/// An outgoing message.
#[derive(Debug, Clone)]
pub struct Draft {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub text: String,
    pub html: Option<String>,
    pub attachments: Vec<AttachmentData>,
    /// Either a local message id (digits, from `list_messages`) or a raw `Message-ID`.
    pub in_reply_to: Option<String>,
    pub policy: SendPolicy,
    /// How a guest link is protected (G29). Passphrase = no secret in the link.
    pub guest_mode: GuestMode,
    /// The address that receives the one-time code in `EmailCode` mode (`None` = the only
    /// recipient).
    pub guest_recipient_hint: Option<String>,
}

/// Guest-link protection (mirrors `sealbox_core::GuestMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestMode {
    /// Default: the link carries no secret; the passphrase goes by another channel.
    Passphrase,
    /// The secret is in the link's fragment: anyone with the link can read the message.
    OneClick,
    /// Secret in the fragment, ciphertext released only after a mailed one-time code.
    EmailCode,
}

impl From<GuestMode> for sc::GuestMode {
    fn from(m: GuestMode) -> Self {
        match m {
            GuestMode::Passphrase => sc::GuestMode::Passphrase,
            GuestMode::OneClick => sc::GuestMode::OneClick,
            GuestMode::EmailCode => sc::GuestMode::EmailCode,
        }
    }
}

impl From<sc::GuestMode> for GuestMode {
    fn from(m: sc::GuestMode) -> Self {
        match m {
            sc::GuestMode::Passphrase => GuestMode::Passphrase,
            sc::GuestMode::OneClick => GuestMode::OneClick,
            sc::GuestMode::EmailCode => GuestMode::EmailCode,
        }
    }
}

impl From<Draft> for sc::Draft {
    fn from(d: Draft) -> Self {
        sc::Draft {
            to: d.to,
            cc: d.cc,
            bcc: d.bcc,
            subject: d.subject,
            text: d.text,
            html: d.html,
            attachments: d.attachments.into_iter().map(Into::into).collect(),
            in_reply_to: d.in_reply_to,
            policy: d.policy.into(),
            guest_mode: d.guest_mode.into(),
            guest_recipient_hint: d.guest_recipient_hint,
        }
    }
}

/// Where a recipient's key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Autocrypt,
    Gossip,
    Imported,
    Directory,
    Own,
    None,
}

impl From<sc::KeySource> for KeySource {
    fn from(s: sc::KeySource) -> Self {
        match s {
            sc::KeySource::Autocrypt => KeySource::Autocrypt,
            sc::KeySource::Gossip => KeySource::Gossip,
            sc::KeySource::Imported => KeySource::Imported,
            sc::KeySource::Directory => KeySource::Directory,
            sc::KeySource::Own => KeySource::Own,
            sc::KeySource::None => KeySource::None,
        }
    }
}

/// Autocrypt Level 1 UI recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recommendation {
    /// Encryption is not possible: hide the option.
    Disable,
    /// Possible but not advisable (gossip-only or stale key).
    Discourage,
    /// Possible: offer, do not default to it.
    Available,
    /// Default to encryption.
    Encrypt,
}

impl From<sc::Recommendation> for Recommendation {
    fn from(r: sc::Recommendation) -> Self {
        match r {
            sc::Recommendation::Disable => Recommendation::Disable,
            sc::Recommendation::Discourage => Recommendation::Discourage,
            sc::Recommendation::Available => Recommendation::Available,
            sc::Recommendation::Encrypt => Recommendation::Encrypt,
        }
    }
}

/// The peer's `prefer-encrypt` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferEncrypt {
    NoPreference,
    Mutual,
}

impl From<sc::PreferEncrypt> for PreferEncrypt {
    fn from(p: sc::PreferEncrypt) -> Self {
        match p {
            sc::PreferEncrypt::NoPreference => PreferEncrypt::NoPreference,
            sc::PreferEncrypt::Mutual => PreferEncrypt::Mutual,
        }
    }
}

/// Encryption status of one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientStatus {
    pub address: String,
    pub recommendation: Recommendation,
    pub fingerprint: Option<String>,
    pub source: KeySource,
    /// `fingerprint` is set and the recommendation is not `Disable`.
    pub has_key: bool,
}

impl From<sc::RecipientStatus> for RecipientStatus {
    fn from(r: sc::RecipientStatus) -> Self {
        let has_key = r.has_key();
        Self {
            address: r.address,
            recommendation: r.recommendation.into(),
            fingerprint: r.fingerprint,
            source: r.source.into(),
            has_key,
        }
    }
}

/// How a message went out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendMode {
    Encrypted,
    Plaintext,
    GuestLink,
}

impl From<sc::SendMode> for SendMode {
    fn from(m: sc::SendMode) -> Self {
        match m {
            sc::SendMode::Encrypted => SendMode::Encrypted,
            sc::SendMode::Plaintext => SendMode::Plaintext,
            sc::SendMode::GuestLink => SendMode::GuestLink,
        }
    }
}

/// Guest-link details (the passphrase is shared out of band).
#[derive(Clone, PartialEq, Eq)]
pub struct GuestLinkInfo {
    pub url: String,
    pub passphrase: String,
    pub mode: GuestMode,
    pub expires_at: i64,
    /// The URL itself can decrypt the message (one-click / email-code).
    pub secret_in_link: bool,
    /// The server gates the ciphertext behind a mailed one-time code.
    pub recipient_verification: bool,
}

impl std::fmt::Debug for GuestLinkInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestLinkInfo")
            .field("url", &self.url)
            .field("mode", &self.mode)
            .field("expires_at", &self.expires_at)
            .field("secret_in_link", &self.secret_in_link)
            .field("recipient_verification", &self.recipient_verification)
            .finish_non_exhaustive()
    }
}

impl From<sc::GuestLinkInfo> for GuestLinkInfo {
    fn from(g: sc::GuestLinkInfo) -> Self {
        Self {
            url: g.url,
            passphrase: g.passphrase,
            mode: g.mode.into(),
            expires_at: g.expires_at,
            secret_in_link: g.secret_in_link,
            recipient_verification: g.recipient_verification,
        }
    }
}

/// Result of [`Engine::send`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReport {
    pub message_id: String,
    pub mode: SendMode,
    pub encrypted: bool,
    pub recipients: Vec<RecipientStatus>,
    pub guest: Option<GuestLinkInfo>,
    pub sent_copy_appended: bool,
    pub sent_folder: Option<String>,
}

impl From<sc::SendReport> for SendReport {
    fn from(r: sc::SendReport) -> Self {
        Self {
            message_id: r.message_id,
            mode: r.mode.into(),
            encrypted: r.encrypted,
            recipients: r.recipients.into_iter().map(Into::into).collect(),
            guest: r.guest.map(Into::into),
            sent_copy_appended: r.sent_copy_appended,
            sent_folder: r.sent_folder,
        }
    }
}

// ----- sync -----------------------------------------------------------------------------

/// Per-folder part of a sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderSync {
    pub name: String,
    pub new: u32,
    pub uidvalidity_reset: bool,
    /// Older mail of the folder is not stored yet: its first sync fetched only the newest
    /// window (500 messages); later syncs and [`Engine::backfill_with_progress`] fetch the
    /// rest, newest first.
    pub more_to_backfill: bool,
    /// How many older messages are still to fetch, when this run counted them (a first sync
    /// and every backfill step do; 0 once nothing older is left); `None` when it did not look.
    pub older_pending: Option<u32>,
    /// Stored messages dropped because the server no longer lists their UID — deleted or moved
    /// away in webmail or on another device.
    pub removed: u32,
    /// Stored messages whose flags the server reports differently (read elsewhere, starred
    /// elsewhere) and which were brought into line.
    pub flags_changed: u32,
}

impl From<sc::FolderSync> for FolderSync {
    fn from(f: sc::FolderSync) -> Self {
        Self {
            name: f.name,
            new: f.new,
            uidvalidity_reset: f.uidvalidity_reset,
            more_to_backfill: f.more_to_backfill,
            older_pending: f.older_pending,
            removed: f.removed,
            flags_changed: f.flags_changed,
        }
    }
}

/// Result of [`Engine::sync`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub account: String,
    /// Messages stored for the first time.
    pub new: u32,
    /// Of those, encrypted messages we could decrypt.
    pub decrypted: u32,
    /// Encrypted or malformed messages we could not decrypt / parse.
    pub failed: u32,
    pub folders: Vec<FolderSync>,
    /// Local ids of the new messages, ascending: the order they were stored in (a first sync
    /// stores the newest mail first, so ids no longer follow the dates).
    pub new_ids: Vec<i64>,
}

impl From<sc::SyncReport> for SyncReport {
    fn from(r: sc::SyncReport) -> Self {
        Self {
            account: r.account,
            new: r.new,
            decrypted: r.decrypted,
            failed: r.failed,
            folders: r.folders.into_iter().map(Into::into).collect(),
            new_ids: r.new_ids,
        }
    }
}

/// Which part of a folder a sync step fetches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPhase {
    /// First sync of a folder: its newest window (500 messages), the newest batch first.
    Initial,
    /// Mail that arrived since the last sync (above everything stored), oldest first.
    Incremental,
    /// Older mail below the window, the newest batch first, down to the first message.
    Backfill,
}

impl From<sc::SyncPhase> for SyncPhase {
    fn from(p: sc::SyncPhase) -> Self {
        match p {
            sc::SyncPhase::Initial => SyncPhase::Initial,
            sc::SyncPhase::Incremental => SyncPhase::Incremental,
            sc::SyncPhase::Backfill => SyncPhase::Backfill,
        }
    }
}

/// One stored batch of a running sync or backfill, sent after the batch is committed: the
/// messages are listable when it arrives. Counts are per folder and phase of this run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncProgress {
    /// The account's address.
    pub account: String,
    pub folder: String,
    pub phase: SyncPhase,
    /// Messages fetched so far in this phase.
    pub fetched: u32,
    /// Of those, stored for the first time (one already stored is skipped).
    pub stored: u32,
    /// What this phase set out to fetch: the window, the new mail, or the backfill step.
    pub planned: u32,
    /// Messages in the folder on the server (`EXISTS` when the folder was selected).
    pub total_known: u32,
    /// Messages of the folder stored locally now.
    pub local: u32,
    /// Older mail is still waiting below the window after this batch.
    pub more_to_backfill: bool,
}

impl From<sc::SyncProgress> for SyncProgress {
    fn from(p: sc::SyncProgress) -> Self {
        Self {
            account: p.account,
            folder: p.folder,
            phase: p.phase.into(),
            fetched: p.fetched,
            stored: p.stored,
            planned: p.planned,
            total_known: p.total_known,
            local: p.local,
            more_to_backfill: p.more_to_backfill,
        }
    }
}

/// What a [`SyncEvent`] carries (flattened, see [`AuthHint`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncEventKind {
    /// A batch was stored (`progress` set).
    Progress,
    /// The run finished (`report` set); always the last event of the stream.
    Done,
}

/// An event of [`Engine::sync_account_with_progress`] / [`Engine::backfill_with_progress`]:
/// a `Progress` event after every stored batch, then exactly one `Done` event with the
/// report. A failed run sends no `Done`: its stream ends with the error instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncEvent {
    pub kind: SyncEventKind,
    pub progress: Option<SyncProgress>,
    pub report: Option<SyncReport>,
}

impl SyncEvent {
    fn progress(p: sc::SyncProgress) -> Self {
        Self {
            kind: SyncEventKind::Progress,
            progress: Some(p.into()),
            report: None,
        }
    }

    fn done(r: sc::SyncReport) -> Self {
        Self {
            kind: SyncEventKind::Done,
            progress: None,
            report: Some(r.into()),
        }
    }
}

/// What a sync run streams, before it reaches the Dart sink: an event, or the error that
/// ends the run (the engine's `Display` text).
type SyncItem = std::result::Result<SyncEvent, String>;

/// Hands one [`SyncItem`] to the Dart stream: an event as data, an error as the stream's
/// error (`AnyhowException(message)` in Dart), after which the stream closes. A send that
/// fails because Dart cancelled its subscription is ignored: the run goes on (see
/// [`Engine::sync_account_with_progress`]).
fn to_sink(sink: &StreamSink<SyncEvent>, item: SyncItem) {
    let _ = match item {
        Ok(event) => sink.add(event),
        Err(message) => sink.add_error(message),
    };
}

/// One account's outcome in [`Engine::sync_all`]: exactly one of `report` / `error` is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSyncResult {
    pub account: String,
    pub report: Option<SyncReport>,
    pub error: Option<String>,
}

/// Event from [`Engine::watch`] (flattened, see [`AuthHint`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchEventKind {
    /// IDLE is active (`folder` set).
    Idle,
    /// New mail was synced (`report` set; may be empty if the change was a flag update).
    NewMail,
    /// The IDLE timeout elapsed without server activity.
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    pub kind: WatchEventKind,
    pub folder: Option<String>,
    pub report: Option<SyncReport>,
}

impl From<sc::WatchEvent> for WatchEvent {
    fn from(e: sc::WatchEvent) -> Self {
        match e {
            sc::WatchEvent::Idle { folder } => WatchEvent {
                kind: WatchEventKind::Idle,
                folder: Some(folder),
                report: None,
            },
            sc::WatchEvent::NewMail { report } => WatchEvent {
                kind: WatchEventKind::NewMail,
                folder: None,
                report: Some(report.into()),
            },
            sc::WatchEvent::Timeout => WatchEvent {
                kind: WatchEventKind::Timeout,
                folder: None,
                report: None,
            },
        }
    }
}

// ----- messages -------------------------------------------------------------------------

/// An RFC 5322 address as shown to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub name: Option<String>,
    pub address: String,
}

impl From<sc::Address> for Address {
    fn from(a: sc::Address) -> Self {
        Self {
            name: a.name,
            address: a.address,
        }
    }
}

/// Signature verdict of a stored message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigState {
    /// No signature.
    None,
    /// Verified with a known key (`fingerprint` set).
    Good,
    /// Signed by a known key but the signature does not verify.
    Bad,
    /// Signed by a key we do not know (`fingerprint` holds the issuer key id).
    UnknownKey,
}

impl From<sc::SigState> for SigState {
    fn from(s: sc::SigState) -> Self {
        match s {
            sc::SigState::None => SigState::None,
            sc::SigState::Good => SigState::Good,
            sc::SigState::Bad => SigState::Bad,
            sc::SigState::UnknownKey => SigState::UnknownKey,
        }
    }
}

/// Signature summary of a stored message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureSummary {
    pub status: SigState,
    pub fingerprint: Option<String>,
    /// Address the signing key belongs to, when known.
    pub signer: Option<String>,
    /// G30: the sender's Autocrypt or signing key differs from the one seen before (kept
    /// on this message for good).
    pub key_changed: bool,
    /// G30: good signature by exactly the key the user verified for this sender.
    pub signer_verified: bool,
}

impl From<sc::SignatureSummary> for SignatureSummary {
    fn from(s: sc::SignatureSummary) -> Self {
        Self {
            status: s.status.into(),
            fingerprint: s.fingerprint,
            signer: s.signer,
            key_changed: s.key_changed,
            signer_verified: s.signer_verified,
        }
    }
}

/// Attachment metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentInfo {
    pub index: u32,
    pub filename: String,
    pub content_type: String,
    /// Bytes.
    pub size: i64,
    /// The part's `Content-ID` without angle brackets, when it has one: what a `cid:` image URL
    /// in the HTML body names (an inline image, `docs/HTML_MAIL.md`). `None` for a part without
    /// one and for messages stored before the store kept it.
    pub content_id: Option<String>,
}

impl From<sc::AttachmentInfo> for AttachmentInfo {
    fn from(a: sc::AttachmentInfo) -> Self {
        Self {
            index: u32::try_from(a.index).unwrap_or(u32::MAX),
            filename: a.filename,
            content_type: a.content_type,
            size: i64::try_from(a.size).unwrap_or(i64::MAX),
            content_id: a.content_id,
        }
    }
}

/// One row of the message list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSummary {
    /// Local id used by `get_message` / `get_attachment` / `set_flags` / `delete_message`.
    pub id: i64,
    pub account: String,
    pub folder: String,
    pub uid: u32,
    pub message_id: Option<String>,
    pub from: Address,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    /// The protected subject when the message carried one, else the outer subject.
    pub subject: Option<String>,
    /// `Date` header, unix seconds.
    pub date: Option<i64>,
    /// When we fetched it, unix seconds.
    pub received_at: i64,
    pub flags: Vec<String>,
    pub seen: bool,
    pub was_encrypted: bool,
    pub decrypted: bool,
    pub was_signed: bool,
    pub signature: SignatureSummary,
    pub protected_subject: bool,
    pub attachment_count: u32,
    pub raw_size: i64,
    pub decrypt_error: Option<String>,
    /// `In-Reply-To` header, angle brackets stripped.
    pub in_reply_to: Vec<String>,
    /// `References` header (oldest first), angle brackets stripped.
    pub references: Vec<String>,
    /// Conversation key computed by the store: the Message-ID of the earliest known ancestor
    /// in this account (walking `References` / `In-Reply-To` through the stored messages),
    /// else the message's own Message-ID, else `sbx-thread:<row id>`. A parent that arrives
    /// after its replies pulls them in. Scoped to the account: compare with `account`.
    pub thread_id: String,
    /// The start of the message for a list row: the first 160 characters of the text body,
    /// or of the HTML body reduced to text when there is no text (never markup), whitespace
    /// collapsed; sealed at rest like the bodies. `None` without a readable body (e.g. mail
    /// we could not decrypt): read the message for what to show instead.
    pub snippet: Option<String>,
}

impl From<sc::MessageSummary> for MessageSummary {
    fn from(m: sc::MessageSummary) -> Self {
        Self {
            id: m.id,
            account: m.account,
            folder: m.folder,
            uid: m.uid,
            message_id: m.message_id,
            from: m.from.into(),
            to: m.to.into_iter().map(Into::into).collect(),
            cc: m.cc.into_iter().map(Into::into).collect(),
            subject: m.subject,
            date: m.date,
            received_at: m.received_at,
            flags: m.flags,
            seen: m.seen,
            was_encrypted: m.was_encrypted,
            decrypted: m.decrypted,
            was_signed: m.was_signed,
            signature: m.signature.into(),
            protected_subject: m.protected_subject,
            attachment_count: u32::try_from(m.attachment_count).unwrap_or(u32::MAX),
            raw_size: i64::try_from(m.raw_size).unwrap_or(i64::MAX),
            decrypt_error: m.decrypt_error,
            in_reply_to: m.in_reply_to,
            references: m.references,
            thread_id: m.thread_id,
            snippet: m.snippet,
        }
    }
}

/// The summary plus decrypted bodies and attachment list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDetail {
    pub summary: MessageSummary,
    pub text: Option<String>,
    pub html: Option<String>,
    pub attachments: Vec<AttachmentInfo>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
}

impl From<sc::MessageDetail> for MessageDetail {
    fn from(d: sc::MessageDetail) -> Self {
        Self {
            summary: d.summary.into(),
            text: d.text,
            html: d.html,
            attachments: d.attachments.into_iter().map(Into::into).collect(),
            in_reply_to: d.in_reply_to,
            references: d.references,
        }
    }
}

/// The displayable HTML of one message ([`Engine::message_html`], `docs/HTML_MAIL.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtmlBody {
    /// Sanitized HTML: allow-listed tags only, no script, no CSS, links `http(s)`/`mailto`
    /// with `rel="noopener noreferrer nofollow"`, images `cid:`/`data:image/*` and — only when
    /// `allow_remote` was set — `http(s)`.
    pub html: String,
    /// Remote images in the message. While blocked each is a
    /// `<span class="sealbox-blocked-image" data-src="…"></span>` placeholder in `html`, so the
    /// UI can offer "N images blocked · Load images"; nothing is fetched until it does.
    pub remote_images: u32,
    /// The same content as plain text, for snippets, quoting and accessibility.
    pub text: String,
}

impl From<sc::HtmlBody> for HtmlBody {
    fn from(b: sc::HtmlBody) -> Self {
        Self {
            html: b.html,
            remote_images: b.remote_images,
            text: b.text,
        }
    }
}

/// Attachment bytes with their metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentBytes {
    pub info: AttachmentInfo,
    pub data: Vec<u8>,
}

/// Filter for [`Engine::list_messages`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListQuery {
    /// `None` = every account (unified inbox).
    pub account: Option<String>,
    /// `None` = INBOX; `"*"` = every folder.
    pub folder: Option<String>,
    /// Pick the folder by special-use role instead of by name: resolved per account to the
    /// folder the server's `LIST` mapped to that role (remembered on sync), else the
    /// provider's default name. Takes precedence over `folder`.
    pub folder_role: Option<FolderRole>,
    /// 0 = default (50).
    pub limit: u32,
}

impl From<ListQuery> for sc::ListQuery {
    fn from(q: ListQuery) -> Self {
        sc::ListQuery {
            account: q.account,
            folder: q.folder,
            folder_role: q.folder_role.map(Into::into),
            limit: q.limit as usize,
        }
    }
}

/// One known correspondent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub address: String,
    pub recommendation: Recommendation,
    pub fingerprint: Option<String>,
    pub source: KeySource,
    pub prefer_encrypt: PreferEncrypt,
    pub last_seen: Option<i64>,
    pub autocrypt_timestamp: Option<i64>,
    pub gossip_fingerprint: Option<String>,
    /// G30: the user verified the current key out of band.
    pub verified: bool,
    /// Unix seconds.
    pub verified_at: Option<i64>,
    /// G30: unix seconds when a message brought a different key; cleared by
    /// [`Engine::acknowledge_key_change`] / [`Engine::verify_contact`].
    pub key_changed_at: Option<i64>,
    /// The key trusted until the change.
    pub previous_fingerprint: Option<String>,
}

impl From<sc::Contact> for Contact {
    fn from(c: sc::Contact) -> Self {
        Self {
            address: c.address,
            recommendation: c.recommendation.into(),
            fingerprint: c.fingerprint,
            source: c.source.into(),
            prefer_encrypt: c.prefer_encrypt.into(),
            last_seen: c.last_seen,
            autocrypt_timestamp: c.autocrypt_timestamp,
            gossip_fingerprint: c.gossip_fingerprint,
            verified: c.verified,
            verified_at: c.verified_at.map(|t| t.timestamp()),
            key_changed_at: c.key_changed_at.map(|t| t.timestamp()),
            previous_fingerprint: c.previous_fingerprint,
        }
    }
}

/// Flag modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagOp {
    Add,
    Remove,
}

impl From<FlagOp> for sc::FlagOp {
    fn from(op: FlagOp) -> Self {
        match op {
            FlagOp::Add => sc::FlagOp::Add,
            FlagOp::Remove => sc::FlagOp::Remove,
        }
    }
}

// ----- per-account settings: signature (G23) and out-of-office auto-reply (G24) -----------

/// Where the signature goes in a reply or forward, relative to the quoted text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignaturePlacement {
    /// Below the new text, above the quote (Gmail/Outlook style).
    AboveQuote,
    /// At the very end, below the quoted text (Thunderbird/mutt style).
    BelowQuote,
}

impl From<sc::SignaturePlacement> for SignaturePlacement {
    fn from(p: sc::SignaturePlacement) -> Self {
        match p {
            sc::SignaturePlacement::AboveQuote => SignaturePlacement::AboveQuote,
            sc::SignaturePlacement::BelowQuote => SignaturePlacement::BelowQuote,
        }
    }
}

impl From<SignaturePlacement> for sc::SignaturePlacement {
    fn from(p: SignaturePlacement) -> Self {
        match p {
            SignaturePlacement::AboveQuote => sc::SignaturePlacement::AboveQuote,
            SignaturePlacement::BelowQuote => sc::SignaturePlacement::BelowQuote,
        }
    }
}

/// Which kinds of message get the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureIncludeOn {
    NewOnly,
    NewAndReplies,
    All,
}

impl From<sc::SignatureIncludeOn> for SignatureIncludeOn {
    fn from(i: sc::SignatureIncludeOn) -> Self {
        match i {
            sc::SignatureIncludeOn::NewOnly => SignatureIncludeOn::NewOnly,
            sc::SignatureIncludeOn::NewAndReplies => SignatureIncludeOn::NewAndReplies,
            sc::SignatureIncludeOn::All => SignatureIncludeOn::All,
        }
    }
}

impl From<SignatureIncludeOn> for sc::SignatureIncludeOn {
    fn from(i: SignatureIncludeOn) -> Self {
        match i {
            SignatureIncludeOn::NewOnly => sc::SignatureIncludeOn::NewOnly,
            SignatureIncludeOn::NewAndReplies => sc::SignatureIncludeOn::NewAndReplies,
            SignatureIncludeOn::All => sc::SignatureIncludeOn::All,
        }
    }
}

/// The per-account signature. `set_signature` validates and normalises (size limit, CRLF → LF,
/// HTML sanitised) and returns what was stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureSettings {
    pub enabled: bool,
    /// Plain-text signature; the engine appends it after the `-- ` separator line.
    pub text: String,
    /// Optional HTML signature (sanitised by the engine).
    pub html: Option<String>,
    pub placement: SignaturePlacement,
    pub include_on: SignatureIncludeOn,
}

impl From<sc::SignatureSettings> for SignatureSettings {
    fn from(s: sc::SignatureSettings) -> Self {
        Self {
            enabled: s.enabled,
            text: s.text,
            html: s.html,
            placement: s.placement.into(),
            include_on: s.include_on.into(),
        }
    }
}

impl From<SignatureSettings> for sc::SignatureSettings {
    fn from(s: SignatureSettings) -> Self {
        sc::SignatureSettings {
            enabled: s.enabled,
            text: s.text,
            html: s.html,
            placement: s.placement.into(),
            include_on: s.include_on.into(),
        }
    }
}

/// Holiday / out-of-office auto-reply (RFC 3834). Times are unix seconds (UTC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoReplySettings {
    pub enabled: bool,
    /// Start of the absence (inclusive); `None` = active as soon as enabled.
    pub start: Option<i64>,
    /// End of the absence (exclusive); `None` = until disabled.
    pub end: Option<i64>,
    /// `{subject}` is replaced by the original message's subject.
    pub subject_template: String,
    pub body: String,
    /// At most one reply per sender per this many days; `0` = once per absence.
    pub reply_once_per_sender_days: u32,
    /// Encrypt + sign when the sender has a usable key, else plaintext.
    pub encrypt_when_possible: bool,
    /// Only answer people this account wrote to before, or whose key was imported.
    pub only_to_known_contacts: bool,
}

fn secs_to_utc(secs: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .unwrap_or(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH)
}

impl From<sc::AutoReplySettings> for AutoReplySettings {
    fn from(a: sc::AutoReplySettings) -> Self {
        Self {
            enabled: a.enabled,
            start: a.start.map(|t| t.timestamp()),
            end: a.end.map(|t| t.timestamp()),
            subject_template: a.subject_template,
            body: a.body,
            reply_once_per_sender_days: a.reply_once_per_sender_days,
            encrypt_when_possible: a.encrypt_when_possible,
            only_to_known_contacts: a.only_to_known_contacts,
        }
    }
}

impl From<AutoReplySettings> for sc::AutoReplySettings {
    fn from(a: AutoReplySettings) -> Self {
        sc::AutoReplySettings {
            enabled: a.enabled,
            start: a.start.map(secs_to_utc),
            end: a.end.map(secs_to_utc),
            subject_template: a.subject_template,
            body: a.body,
            reply_once_per_sender_days: a.reply_once_per_sender_days,
            encrypt_when_possible: a.encrypt_when_possible,
            only_to_known_contacts: a.only_to_known_contacts,
        }
    }
}

/// One auto-reply the engine sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoReplyLogEntry {
    pub id: i64,
    pub account: String,
    pub sender: String,
    pub period_start: i64,
    pub sent_at: i64,
    pub message_id: String,
    pub in_reply_to: Option<String>,
    pub original_id: Option<i64>,
    pub encrypted: bool,
}

impl From<sc::AutoReplyLogEntry> for AutoReplyLogEntry {
    fn from(e: sc::AutoReplyLogEntry) -> Self {
        Self {
            id: e.id,
            account: e.account,
            sender: e.sender,
            period_start: e.period_start,
            sent_at: e.sent_at,
            message_id: e.message_id,
            in_reply_to: e.in_reply_to,
            original_id: e.original_id,
            encrypted: e.encrypted,
        }
    }
}

// ----- identity (G30) ---------------------------------------------------------------------

/// Result of [`Engine::kt_audit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtAuditReport {
    pub log_size: u64,
    pub sth_verified: bool,
    pub own_key_included: bool,
    pub consistency_ok: bool,
    pub alerts: Vec<String>,
}

impl From<sc::KtAuditReport> for KtAuditReport {
    fn from(r: sc::KtAuditReport) -> Self {
        Self {
            log_size: r.log_size,
            sth_verified: r.sth_verified,
            own_key_included: r.own_key_included,
            consistency_ok: r.consistency_ok,
            alerts: r.alerts,
        }
    }
}

/// One key-transparency log leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtEntry {
    /// `"publish"` or `"unpublish"`.
    pub action: String,
    pub email_hash: String,
    pub fingerprint: String,
    /// Unix seconds.
    pub time: i64,
}

impl From<sc::KtEntry> for KtEntry {
    fn from(e: sc::KtEntry) -> Self {
        Self {
            action: e.action,
            email_hash: e.email_hash,
            fingerprint: e.fingerprint,
            time: e.time,
        }
    }
}

/// One entry of [`KtEntriesPage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtIndexedEntry {
    pub index: u64,
    pub entry: KtEntry,
    pub leaf_hash: String,
}

/// One page of `GET /v1/kt/entries`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtEntriesPage {
    pub tree_size: u64,
    pub start: u64,
    pub entries: Vec<KtIndexedEntry>,
}

impl From<sc::KtEntriesPage> for KtEntriesPage {
    fn from(p: sc::KtEntriesPage) -> Self {
        Self {
            tree_size: p.tree_size,
            start: p.start,
            entries: p
                .entries
                .into_iter()
                .map(|e| KtIndexedEntry {
                    index: e.index,
                    entry: e.entry.into(),
                    leaf_hash: e.leaf_hash,
                })
                .collect(),
        }
    }
}

// ----- recovery (G15) ---------------------------------------------------------------------

/// A 12-word recovery phrase (shown once, stored nowhere).
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryPhrase {
    pub words: Vec<String>,
    pub checksum_ok: bool,
}

impl std::fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryPhrase")
            .field("words", &format_args!("<{} words>", self.words.len()))
            .field("checksum_ok", &self.checksum_ok)
            .finish()
    }
}

impl From<sc::RecoveryPhrase> for RecoveryPhrase {
    fn from(p: sc::RecoveryPhrase) -> Self {
        Self {
            words: p.words.clone(),
            checksum_ok: p.checksum_ok,
        }
    }
}

/// Result of [`Engine::backup_to_server`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReport {
    pub fingerprint: String,
    pub bytes: u64,
    pub server_url: String,
    /// Unix seconds.
    pub created_at: i64,
}

impl From<sc::BackupReport> for BackupReport {
    fn from(r: sc::BackupReport) -> Self {
        Self {
            fingerprint: r.fingerprint,
            bytes: r.bytes,
            server_url: r.server_url,
            created_at: r.created_at,
        }
    }
}

/// [`Engine::backup_status`] (local bookkeeping only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupStatus {
    pub email: String,
    pub last_backup: Option<BackupReport>,
    pub phrase_created_at: Option<i64>,
    pub reminder: Option<String>,
}

impl From<sc::BackupStatus> for BackupStatus {
    fn from(s: sc::BackupStatus) -> Self {
        Self {
            email: s.email,
            last_backup: s.last_backup.map(Into::into),
            phrase_created_at: s.phrase_created_at,
            reminder: s.reminder,
        }
    }
}

/// Options of [`Engine::backup_to_server_with`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupOptions {
    pub include_credentials: bool,
}

impl From<BackupOptions> for sc::BackupOptions {
    fn from(o: BackupOptions) -> Self {
        Self {
            include_credentials: o.include_credentials,
        }
    }
}

/// Options of [`Engine::restore_from_server_with`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOptions {
    pub fingerprint: Option<String>,
    pub credentials: Option<AuthSpec>,
    pub imap: Option<Endpoint>,
    pub smtp: Option<Endpoint>,
    pub login: Option<String>,
}

impl From<RestoreOptions> for sc::RestoreOptions {
    fn from(o: RestoreOptions) -> Self {
        Self {
            fingerprint: o.fingerprint,
            credentials: o.credentials.map(Into::into),
            imap: o.imap.map(Into::into),
            smtp: o.smtp.map(Into::into),
            login: o.login,
        }
    }
}

/// Result of [`Engine::setup_message_export`]. Show the code on this device only.
#[derive(Clone, PartialEq, Eq)]
pub struct SetupExport {
    pub setup_code: String,
    pub message_id: String,
}

impl std::fmt::Debug for SetupExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupExport")
            .field("setup_code", &"<redacted>")
            .field("message_id", &self.message_id)
            .finish()
    }
}

impl From<sc::SetupExport> for SetupExport {
    fn from(e: sc::SetupExport) -> Self {
        Self {
            setup_code: e.setup_code.clone(),
            message_id: e.message_id.clone(),
        }
    }
}

// ----- folders by special-use role ----------------------------------------------------------

/// Special-use folder roles (RFC 6154 plus Gmail's All Mail / Starred); mirrors
/// `sealbox_core::FolderRole`. The engine maps each role to the folder the server's `LIST`
/// gave it (learned on every sync) or else the provider's default name, per account, so one
/// role works across a Gmail, an Outlook and an IMAP account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderRole {
    Inbox,
    Sent,
    Drafts,
    Trash,
    /// Spam / junk mail (`\Junk`).
    Junk,
    Archive,
    /// Gmail "All Mail" (`\All`); elsewhere the archive folder.
    All,
    /// `\Flagged` / Gmail "Starred".
    Flagged,
}

impl From<sc::FolderRole> for FolderRole {
    fn from(r: sc::FolderRole) -> Self {
        match r {
            sc::FolderRole::Inbox => FolderRole::Inbox,
            sc::FolderRole::Sent => FolderRole::Sent,
            sc::FolderRole::Drafts => FolderRole::Drafts,
            sc::FolderRole::Trash => FolderRole::Trash,
            sc::FolderRole::Junk => FolderRole::Junk,
            sc::FolderRole::Archive => FolderRole::Archive,
            sc::FolderRole::All => FolderRole::All,
            sc::FolderRole::Flagged => FolderRole::Flagged,
        }
    }
}

impl From<FolderRole> for sc::FolderRole {
    fn from(r: FolderRole) -> Self {
        match r {
            FolderRole::Inbox => sc::FolderRole::Inbox,
            FolderRole::Sent => sc::FolderRole::Sent,
            FolderRole::Drafts => sc::FolderRole::Drafts,
            FolderRole::Trash => sc::FolderRole::Trash,
            FolderRole::Junk => sc::FolderRole::Junk,
            FolderRole::Archive => sc::FolderRole::Archive,
            FolderRole::All => sc::FolderRole::All,
            FolderRole::Flagged => sc::FolderRole::Flagged,
        }
    }
}

/// One role of an account and the folder it maps to (mirrors `sealbox_core::FolderRoleEntry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderRoleEntry {
    pub role: FolderRole,
    /// Folder name on the server.
    pub folder: String,
    /// `true` when the server's `LIST` said so on a sync; `false` when this is the provider
    /// profile's default, not confirmed yet.
    pub learned: bool,
}

impl From<sc::FolderRoleEntry> for FolderRoleEntry {
    fn from(e: sc::FolderRoleEntry) -> Self {
        Self {
            role: e.role.into(),
            folder: e.folder,
            learned: e.learned,
        }
    }
}

/// How a move was carried out on the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveMethod {
    /// `UID MOVE` (RFC 6851).
    Move,
    /// `UID COPY` + `\Deleted` + expunge (servers without MOVE).
    CopyExpunge,
}

impl From<sc::MoveMethod> for MoveMethod {
    fn from(m: sc::MoveMethod) -> Self {
        match m {
            sc::MoveMethod::Move => MoveMethod::Move,
            sc::MoveMethod::CopyExpunge => MoveMethod::CopyExpunge,
        }
    }
}

/// Result of [`Engine::move_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveReport {
    /// The local id that was moved. Its row is dropped: the message is stored again (under a
    /// new id) when the destination folder is synced ([`Engine::sync_folder_role`]).
    pub id: i64,
    pub from_folder: String,
    pub to_folder: String,
    /// `None` when the message already was in the destination (nothing happened, the row is
    /// kept).
    pub method: Option<MoveMethod>,
}

impl From<sc::MoveReport> for MoveReport {
    fn from(r: sc::MoveReport) -> Self {
        Self {
            id: r.id,
            from_folder: r.from_folder,
            to_folder: r.to_folder,
            method: r.method.map(Into::into),
        }
    }
}

// ----- compose: reply / forward quoting and the signature (G23) -----------------------------

/// How a draft came to be; drives signature inclusion (`SignatureSettings.include_on`) and
/// quoting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ComposeKind {
    #[default]
    New,
    /// `Draft.in_reply_to` names the message answered.
    Reply,
    /// `ComposeOptions.forward_of` names the message forwarded.
    Forward,
}

impl From<sc::ComposeKind> for ComposeKind {
    fn from(k: sc::ComposeKind) -> Self {
        match k {
            sc::ComposeKind::New => ComposeKind::New,
            sc::ComposeKind::Reply => ComposeKind::Reply,
            sc::ComposeKind::Forward => ComposeKind::Forward,
        }
    }
}

impl From<ComposeKind> for sc::ComposeKind {
    fn from(k: ComposeKind) -> Self {
        match k {
            ComposeKind::New => sc::ComposeKind::New,
            ComposeKind::Reply => sc::ComposeKind::Reply,
            ComposeKind::Forward => sc::ComposeKind::Forward,
        }
    }
}

/// Options of [`Engine::send_with`] and [`Engine::compose_preview`]. The default is exactly
/// what [`Engine::send`] does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComposeOptions {
    /// `New` with `Draft.in_reply_to` set is treated as `Reply`.
    pub kind: ComposeKind,
    /// Quote the replied-to message below the text (`On <date>, <from> wrote:` + `> `). Only
    /// stored messages can be quoted. Implied for forwards.
    pub quote: bool,
    /// For forwards: local id (digits) or Message-ID of the stored message; its text goes
    /// below a `-------- Forwarded Message --------` block and its attachments are carried
    /// along.
    pub forward_of: Option<String>,
    /// Never add the account signature.
    pub skip_signature: bool,
}

impl From<ComposeOptions> for sc::ComposeOptions {
    fn from(o: ComposeOptions) -> Self {
        sc::ComposeOptions {
            kind: o.kind.into(),
            quote: o.quote,
            forward_of: o.forward_of,
            skip_signature: o.skip_signature,
        }
    }
}

/// What [`Engine::send_with`] would send for a draft; nothing is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposePreview {
    /// The effective kind (`New` with `in_reply_to` set becomes `Reply`).
    pub kind: ComposeKind,
    /// Final text body: the draft text, then quote and signature per the settings.
    pub text: String,
    /// Final HTML body when the draft or the signature has one.
    pub html: Option<String>,
    /// The account signature was added.
    pub signature_applied: bool,
    /// File names of the forwarded message's attachments that `send_with` carries along.
    pub forwarded_attachments: Vec<String>,
}

impl From<sc::ComposePreview> for ComposePreview {
    fn from(p: sc::ComposePreview) -> Self {
        Self {
            kind: p.kind.into(),
            text: p.text,
            html: p.html,
            signature_applied: p.signature_applied,
            forwarded_attachments: p.forwarded_attachments,
        }
    }
}

/// The signature block alone, as [`Engine::send_with`] would append it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignaturePreview {
    /// Starts with the `-- ` separator line; empty when the signature is HTML-only.
    pub text: String,
    /// The sanitised HTML block, when an HTML variant is configured.
    pub html: Option<String>,
    pub placement: SignaturePlacement,
}

impl From<sc::SignaturePreview> for SignaturePreview {
    fn from(p: sc::SignaturePreview) -> Self {
        Self {
            text: p.text,
            html: p.html,
            placement: p.placement.into(),
        }
    }
}

// ----- spam (G25) -----------------------------------------------------------------------------

/// The classifier's label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpamLabel {
    Ham,
    Unsure,
    Spam,
}

impl From<sc::SpamLabel> for SpamLabel {
    fn from(l: sc::SpamLabel) -> Self {
        match l {
            sc::SpamLabel::Ham => SpamLabel::Ham,
            sc::SpamLabel::Unsure => SpamLabel::Unsure,
            sc::SpamLabel::Spam => SpamLabel::Spam,
        }
    }
}

/// One line of a spam explanation: a rule hit, a forced label (allowlist, blocklist, signed
/// by a contact) or the user's feedback.
#[derive(Debug, Clone, PartialEq)]
pub struct SpamReason {
    /// Stable code, e.g. `raw_ip_url`, `allowlist`, `signed_by_contact`, `user_feedback`.
    pub code: String,
    /// Log-odds contribution (0 for forced labels).
    pub weight: f64,
    pub detail: String,
}

impl From<sc::Reason> for SpamReason {
    fn from(r: sc::Reason) -> Self {
        Self {
            code: r.code,
            weight: r.weight,
            detail: r.detail,
        }
    }
}

/// The classifier's answer (mirrors `sealbox_core::Verdict`).
#[derive(Debug, Clone, PartialEq)]
pub struct SpamVerdict {
    pub spam_probability: f64,
    pub label: SpamLabel,
    pub reasons: Vec<SpamReason>,
    /// Raw Bayes log-odds before clamping / confidence scaling.
    pub bayes_log_odds: f64,
    /// 0..1 — how much the Bayes model was trusted.
    pub bayes_confidence: f64,
    /// Sum of the rule weights.
    pub rules_score: f64,
    /// Final log-odds the probability was derived from.
    pub log_odds: f64,
}

impl From<sc::Verdict> for SpamVerdict {
    fn from(v: sc::Verdict) -> Self {
        Self {
            spam_probability: v.spam_probability,
            label: v.label.into(),
            reasons: v.reasons.into_iter().map(Into::into).collect(),
            bayes_log_odds: v.bayes_log_odds,
            bayes_confidence: v.bayes_confidence,
            rules_score: v.rules_score,
            log_odds: v.log_odds,
        }
    }
}

/// Per-account spam settings. [`Engine::set_spam_settings`] validates and normalises them
/// (thresholds in 0..1 with unsure ≤ spam, a non-empty folder other than INBOX, lists
/// lower-cased and deduplicated) and returns what was stored.
#[derive(Debug, Clone, PartialEq)]
pub struct SpamSettings {
    /// Classify incoming mail at all.
    pub enabled: bool,
    /// Probability from which a message is shown as "unsure".
    pub unsure_threshold: f64,
    /// Probability from which a message is spam and moved to the junk folder.
    pub spam_threshold: f64,
    /// Query Spamhaus ZEN/DBL through DNS. Reveals sender IPs and link domains to the
    /// resolver, hence off by default.
    pub dnsbl_enabled: bool,
    /// Folder spam is moved to. The default `Spam` means "the server's junk folder, creating
    /// `Spam` when there is none".
    pub move_to_folder: String,
    /// Senders (addresses or domains) that are never spam.
    pub allowlist: Vec<String>,
    /// Senders (addresses or domains) that are always spam.
    pub blocklist: Vec<String>,
}

impl From<sc::SpamSettings> for SpamSettings {
    fn from(s: sc::SpamSettings) -> Self {
        Self {
            enabled: s.enabled,
            unsure_threshold: s.unsure_threshold,
            spam_threshold: s.spam_threshold,
            dnsbl_enabled: s.dnsbl_enabled,
            move_to_folder: s.move_to_folder,
            allowlist: s.allowlist,
            blocklist: s.blocklist,
        }
    }
}

impl From<SpamSettings> for sc::SpamSettings {
    fn from(s: SpamSettings) -> Self {
        sc::SpamSettings {
            enabled: s.enabled,
            unsure_threshold: s.unsure_threshold,
            spam_threshold: s.spam_threshold,
            dnsbl_enabled: s.dnsbl_enabled,
            move_to_folder: s.move_to_folder,
            allowlist: s.allowlist,
            blocklist: s.blocklist,
        }
    }
}

/// Spam bookkeeping of one account ([`SpamStatus::accounts`]).
#[derive(Debug, Clone, PartialEq)]
pub struct SpamAccountStatus {
    pub email: String,
    pub settings: SpamSettings,
    /// Where spam goes: the user's explicit folder, else what sync learned from the server,
    /// else the provider default.
    pub spam_folder: String,
    pub messages_spam: i64,
    pub messages_unsure: i64,
    pub messages_ham: i64,
    pub filter_rules: u32,
}

impl From<sc::SpamAccountStatus> for SpamAccountStatus {
    fn from(s: sc::SpamAccountStatus) -> Self {
        Self {
            email: s.email,
            settings: s.settings.into(),
            spam_folder: s.spam_folder,
            messages_spam: s.messages_spam,
            messages_unsure: s.messages_unsure,
            messages_ham: s.messages_ham,
            filter_rules: u32::try_from(s.filter_rules).unwrap_or(u32::MAX),
        }
    }
}

/// Model statistics and every account's settings ([`Engine::spam_status`]).
#[derive(Debug, Clone, PartialEq)]
pub struct SpamStatus {
    pub model_spam_messages: u32,
    pub model_ham_messages: u32,
    pub model_tokens: u32,
    /// 0..1 — how much the Bayes model is trusted right now (it needs some training first).
    pub model_confidence: f64,
    pub accounts: Vec<SpamAccountStatus>,
}

impl From<sc::SpamStatus> for SpamStatus {
    fn from(s: sc::SpamStatus) -> Self {
        Self {
            model_spam_messages: s.model_spam_messages,
            model_ham_messages: s.model_ham_messages,
            model_tokens: u32::try_from(s.model_tokens).unwrap_or(u32::MAX),
            model_confidence: s.model_confidence,
            accounts: s.accounts.into_iter().map(Into::into).collect(),
        }
    }
}

/// Result of one `Authentication-Results` method (SPF, DKIM, DMARC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpamAuthResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    /// temperror / permerror / policy / unknown.
    Other,
}

impl From<sc::sealbox_spam::features::AuthResult> for SpamAuthResult {
    fn from(r: sc::sealbox_spam::features::AuthResult) -> Self {
        use sc::sealbox_spam::features::AuthResult as A;
        match r {
            A::Pass => SpamAuthResult::Pass,
            A::Fail => SpamAuthResult::Fail,
            A::SoftFail => SpamAuthResult::SoftFail,
            A::Neutral => SpamAuthResult::Neutral,
            A::None => SpamAuthResult::None,
            A::Other => SpamAuthResult::Other,
        }
    }
}

/// The user's provider's `Authentication-Results` (the top-most header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpamAuthResults {
    /// An `Authentication-Results` header was present at all.
    pub present: bool,
    pub spf: Option<SpamAuthResult>,
    pub dkim: Option<SpamAuthResult>,
    pub dmarc: Option<SpamAuthResult>,
}

impl From<sc::sealbox_spam::features::AuthResults> for SpamAuthResults {
    fn from(a: sc::sealbox_spam::features::AuthResults) -> Self {
        Self {
            present: a.present,
            spf: a.spf.map(Into::into),
            dkim: a.dkim.map(Into::into),
            dmarc: a.dmarc.map(Into::into),
        }
    }
}

/// What the classifier extracted from a message (mirrors `sealbox_core::SpamFeatureSummary`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpamFeatureSummary {
    pub from_address: Option<String>,
    pub from_name: Option<String>,
    pub reply_to: Option<String>,
    /// Up to 20 links found in the body.
    pub urls: Vec<String>,
    /// `name (content/type)` per attachment.
    pub attachments: Vec<String>,
    /// Number of `Received:` headers.
    pub received_depth: u32,
    pub last_external_ip: Option<String>,
    pub auth: SpamAuthResults,
    pub html_only: bool,
    /// Distinct tokens the Bayes model saw.
    pub tokens: u32,
}

impl From<sc::SpamFeatureSummary> for SpamFeatureSummary {
    fn from(f: sc::SpamFeatureSummary) -> Self {
        Self {
            from_address: f.from_address,
            from_name: f.from_name,
            reply_to: f.reply_to,
            urls: f.urls,
            attachments: f.attachments,
            received_depth: u32::try_from(f.received_depth).unwrap_or(u32::MAX),
            last_external_ip: f.last_external_ip,
            auth: f.auth.into(),
            html_only: f.html_only,
            tokens: u32::try_from(f.tokens).unwrap_or(u32::MAX),
        }
    }
}

/// What the message row remembers from sync / learn time.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredSpamInfo {
    pub score: Option<f64>,
    pub label: Option<SpamLabel>,
    pub reasons: Vec<SpamReason>,
    /// The user's own feedback ([`Engine::spam_learn`]), if any.
    pub learned: Option<SpamLabel>,
}

impl From<sc::StoredSpamInfo> for StoredSpamInfo {
    fn from(s: sc::StoredSpamInfo) -> Self {
        Self {
            score: s.score,
            label: s.label.map(Into::into),
            reasons: s.reasons.into_iter().map(Into::into).collect(),
            learned: s.learned.map(Into::into),
        }
    }
}

/// A filter rule whose regex could not be evaluated (flattened from the core's `(id, error)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRuleError {
    pub rule_id: i64,
    pub error: String,
}

/// Combined effect of the matching filter rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterOutcome {
    /// Ids of the rules that matched, in evaluation order.
    pub matched: Vec<i64>,
    /// The first matching move wins (a message lives in one folder).
    pub move_to: Option<String>,
    pub add_flags: Vec<String>,
    pub mark_read: bool,
    pub star: bool,
    /// Rules skipped because their regex is invalid.
    pub errors: Vec<FilterRuleError>,
}

impl From<sc::FilterOutcome> for FilterOutcome {
    fn from(o: sc::FilterOutcome) -> Self {
        Self {
            matched: o.matched,
            move_to: o.move_to,
            add_flags: o.add_flags,
            mark_read: o.mark_read,
            star: o.star,
            errors: o
                .errors
                .into_iter()
                .map(|(rule_id, error)| FilterRuleError { rule_id, error })
                .collect(),
        }
    }
}

/// Result of [`Engine::spam_explain`]: the stored verdict and a fresh offline evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct SpamExplanation {
    pub id: i64,
    pub account: String,
    pub folder: String,
    /// `Name <address>` of the sender.
    pub from: String,
    pub subject: Option<String>,
    /// What was stored at sync / learn time.
    pub stored: StoredSpamInfo,
    /// Fresh verdict under the current model and settings (no DNSBL: offline).
    pub verdict: SpamVerdict,
    pub settings: SpamSettings,
    pub features: SpamFeatureSummary,
    /// What the account's filter rules would do with this message.
    pub filters: FilterOutcome,
}

impl From<sc::SpamExplanation> for SpamExplanation {
    fn from(e: sc::SpamExplanation) -> Self {
        Self {
            id: e.id,
            account: e.account,
            folder: e.folder,
            from: e.from,
            subject: e.subject,
            stored: e.stored.into(),
            verdict: e.verdict.into(),
            settings: e.settings.into(),
            features: e.features.into(),
            filters: e.filters.into(),
        }
    }
}

/// Result of [`Engine::spam_learn`].
#[derive(Debug, Clone, PartialEq)]
pub struct SpamLearnReport {
    pub id: i64,
    pub learned: SpamLabel,
    pub previously_learned: Option<SpamLabel>,
    /// Where the message was moved (the junk folder for spam, `INBOX` for "not spam"), when
    /// it was moved. The local row normally keeps its id; it is dropped (and stored again by
    /// the next sync of that folder) only when the server cannot tell the new UID.
    pub moved_to: Option<String>,
    pub model_spam_messages: u32,
    pub model_ham_messages: u32,
    /// Fresh verdict under the updated model; its label is the user's.
    pub verdict: SpamVerdict,
}

impl From<sc::SpamLearnReport> for SpamLearnReport {
    fn from(r: sc::SpamLearnReport) -> Self {
        Self {
            id: r.id,
            learned: r.learned.into(),
            previously_learned: r.previously_learned.map(Into::into),
            moved_to: r.moved_to,
            model_spam_messages: r.model_spam_messages,
            model_ham_messages: r.model_ham_messages,
            verdict: r.verdict.into(),
        }
    }
}

// ----- filter rules (G25) ------------------------------------------------------------------

/// Which part of the message a rule looks at (flattened, see [`AuthHint`]: `Header` carries
/// its name in [`FilterField::header`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterFieldKind {
    From,
    To,
    Cc,
    Subject,
    ListId,
    /// Any header by name, e.g. `X-Mailer` (case-insensitive).
    Header,
    Body,
}

/// A rule's field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterField {
    pub kind: FilterFieldKind,
    /// The header name for `kind == Header` (required there, ignored otherwise).
    pub header: Option<String>,
}

impl From<sc::FilterField> for FilterField {
    fn from(f: sc::FilterField) -> Self {
        let kind = match &f {
            sc::FilterField::From => FilterFieldKind::From,
            sc::FilterField::To => FilterFieldKind::To,
            sc::FilterField::Cc => FilterFieldKind::Cc,
            sc::FilterField::Subject => FilterFieldKind::Subject,
            sc::FilterField::ListId => FilterFieldKind::ListId,
            sc::FilterField::AnyHeader(_) => FilterFieldKind::Header,
            sc::FilterField::Body => FilterFieldKind::Body,
        };
        let header = match f {
            sc::FilterField::AnyHeader(h) => Some(h),
            _ => None,
        };
        Self { kind, header }
    }
}

impl From<FilterField> for sc::FilterField {
    /// A `Header` field without a name becomes an empty header name, which the engine
    /// refuses when the rule is stored ("header: needs a header name").
    fn from(f: FilterField) -> Self {
        match f.kind {
            FilterFieldKind::From => sc::FilterField::From,
            FilterFieldKind::To => sc::FilterField::To,
            FilterFieldKind::Cc => sc::FilterField::Cc,
            FilterFieldKind::Subject => sc::FilterField::Subject,
            FilterFieldKind::ListId => sc::FilterField::ListId,
            FilterFieldKind::Header => sc::FilterField::AnyHeader(f.header.unwrap_or_default()),
            FilterFieldKind::Body => sc::FilterField::Body,
        }
    }
}

/// How a rule compares its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOp {
    Contains,
    Equals,
    Regex,
    /// Address fields: the domain equals the value or is a sub-domain of it.
    Domain,
}

impl From<sc::FilterOp> for FilterOp {
    fn from(o: sc::FilterOp) -> Self {
        match o {
            sc::FilterOp::Contains => FilterOp::Contains,
            sc::FilterOp::Equals => FilterOp::Equals,
            sc::FilterOp::Regex => FilterOp::Regex,
            sc::FilterOp::Domain => FilterOp::Domain,
        }
    }
}

impl From<FilterOp> for sc::FilterOp {
    fn from(o: FilterOp) -> Self {
        match o {
            FilterOp::Contains => sc::FilterOp::Contains,
            FilterOp::Equals => sc::FilterOp::Equals,
            FilterOp::Regex => sc::FilterOp::Regex,
            FilterOp::Domain => sc::FilterOp::Domain,
        }
    }
}

/// A rule's condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterMatch {
    pub field: FilterField,
    pub op: FilterOp,
    pub value: String,
    pub case_insensitive: bool,
}

impl From<sc::FilterMatch> for FilterMatch {
    fn from(m: sc::FilterMatch) -> Self {
        Self {
            field: m.field.into(),
            op: m.op.into(),
            value: m.value,
            case_insensitive: m.case_insensitive,
        }
    }
}

impl From<FilterMatch> for sc::FilterMatch {
    fn from(m: FilterMatch) -> Self {
        sc::FilterMatch {
            field: m.field.into(),
            op: m.op.into(),
            value: m.value,
            case_insensitive: m.case_insensitive,
        }
    }
}

/// What a rule does (flattened). There is deliberately no delete: "delete" is a move to
/// Trash, so a filter can never destroy mail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterActionKind {
    /// Move to [`FilterAction::folder`] (created when missing); the first matching move wins.
    MoveTo,
    /// Add the IMAP flag [`FilterAction::flag`], e.g. `$Newsletter`.
    AddFlag,
    MarkRead,
    Star,
}

/// A rule's action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterAction {
    pub kind: FilterActionKind,
    /// Destination folder for `MoveTo`.
    pub folder: Option<String>,
    /// IMAP flag for `AddFlag` (no spaces, parentheses, quotes or wildcards).
    pub flag: Option<String>,
}

impl From<sc::FilterAction> for FilterAction {
    fn from(a: sc::FilterAction) -> Self {
        match a {
            sc::FilterAction::MoveTo { folder } => FilterAction {
                kind: FilterActionKind::MoveTo,
                folder: Some(folder),
                flag: None,
            },
            sc::FilterAction::AddFlag { flag } => FilterAction {
                kind: FilterActionKind::AddFlag,
                folder: None,
                flag: Some(flag),
            },
            sc::FilterAction::MarkRead => FilterAction {
                kind: FilterActionKind::MarkRead,
                folder: None,
                flag: None,
            },
            sc::FilterAction::Star => FilterAction {
                kind: FilterActionKind::Star,
                folder: None,
                flag: None,
            },
        }
    }
}

impl From<FilterAction> for sc::FilterAction {
    /// A missing folder / flag becomes empty, which the engine refuses when the rule is stored.
    fn from(a: FilterAction) -> Self {
        match a.kind {
            FilterActionKind::MoveTo => sc::FilterAction::MoveTo {
                folder: a.folder.unwrap_or_default(),
            },
            FilterActionKind::AddFlag => sc::FilterAction::AddFlag {
                flag: a.flag.unwrap_or_default(),
            },
            FilterActionKind::MarkRead => sc::FilterAction::MarkRead,
            FilterActionKind::Star => sc::FilterAction::Star,
        }
    }
}

/// One filter rule of an account. Rules run in `order` (then id) after spam classification;
/// every enabled matching rule contributes its action and `stop` ends the evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRule {
    /// Store id (0 before it is saved).
    pub id: i64,
    /// Position; 0 in [`Engine::add_filter_rule`] appends after the existing rules.
    pub order: i32,
    pub enabled: bool,
    /// Optional label shown in lists.
    pub name: String,
    pub matcher: FilterMatch,
    pub action: FilterAction,
    /// Stop evaluating further rules when this one matches.
    pub stop: bool,
}

impl From<sc::FilterRule> for FilterRule {
    fn from(r: sc::FilterRule) -> Self {
        Self {
            id: r.id,
            order: r.order,
            enabled: r.enabled,
            name: r.name,
            matcher: r.matcher.into(),
            action: r.action.into(),
            stop: r.stop,
        }
    }
}

impl From<FilterRule> for sc::FilterRule {
    fn from(r: FilterRule) -> Self {
        sc::FilterRule {
            id: r.id,
            order: r.order,
            enabled: r.enabled,
            name: r.name,
            matcher: r.matcher.into(),
            action: r.action.into(),
            stop: r.stop,
        }
    }
}

/// One enabled rule in a dry run (flattened from the core's `(id, description, matched)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRuleResult {
    pub id: i64,
    /// e.g. `subject contains "[newsletter]" → move:Newsletters`
    pub description: String,
    pub matched: bool,
}

/// Result of [`Engine::test_filter_rules`]; nothing is changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterTestReport {
    pub message_id: i64,
    pub outcome: FilterOutcome,
    /// Every enabled rule in evaluation order.
    pub rules: Vec<FilterRuleResult>,
}

impl From<sc::FilterTestReport> for FilterTestReport {
    fn from(r: sc::FilterTestReport) -> Self {
        Self {
            message_id: r.message_id,
            outcome: r.outcome.into(),
            rules: r
                .rules
                .into_iter()
                .map(|(id, description, matched)| FilterRuleResult {
                    id,
                    description,
                    matched,
                })
                .collect(),
        }
    }
}

// ----- key directory: publishing the account key ------------------------------------------------

/// One address of an uploaded key and what the directory says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryAddressState {
    pub address: String,
    /// `unpublished` · `pending` · `published`.
    pub state: String,
}

/// Result of [`Engine::publish_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishReport {
    /// Fingerprint of the uploaded key.
    pub fingerprint: String,
    /// Base URL of the directory the key went to.
    pub server_url: String,
    /// The directory's state per address after the upload (flattened from a map, sorted by
    /// address).
    pub status: Vec<DirectoryAddressState>,
    /// A verification mail was requested for the account address; once it arrived,
    /// [`Engine::complete_directory_verification`] follows its link. `false` when the address
    /// already was published.
    pub token_issued: bool,
}

impl From<sc::PublishReport> for PublishReport {
    fn from(r: sc::PublishReport) -> Self {
        Self {
            fingerprint: r.fingerprint,
            server_url: r.server_url,
            status: r
                .status
                .into_iter()
                .map(|(address, state)| DirectoryAddressState { address, state })
                .collect(),
            token_issued: r.token_issued,
        }
    }
}

/// What the key directory holds for one of our addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryStatus {
    pub server_url: String,
    /// A key is published for the address.
    pub published: bool,
    /// `Some(true)` = our current key, `Some(false)` = another key, `None` = nothing.
    pub fingerprint_matches: Option<bool>,
    /// `published` · `other_key` · `unpublished` · `awaiting_verification` (no challenge mail
    /// in INBOX or the junk folder yet) · `verification_failed` (the challenge link was
    /// refused: expired or used — publish again for a fresh one).
    pub state: String,
}

impl From<sc::DirectoryStatus> for DirectoryStatus {
    fn from(s: sc::DirectoryStatus) -> Self {
        Self {
            server_url: s.server_url,
            published: s.published,
            fingerprint_matches: s.fingerprint_matches,
            state: s.state,
        }
    }
}

// ----- search and saved drafts (local) ---------------------------------------------------------

/// Input of [`Engine::search`] (mirrors `sealbox_core::SearchQuery`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchQuery {
    /// Account address; `None` = every account.
    pub account: Option<String>,
    /// What the user typed. Every word must match (subject, sender and recipient names and
    /// addresses, decrypted body), case- and accent-insensitive; the last word also matches
    /// as a prefix once it has 3 characters. Text without a letter or digit finds nothing.
    pub text: String,
    /// Folder name (case-insensitive); `None` or `"*"` = every folder.
    pub folder: Option<String>,
    /// 0 = default (50); at most 500.
    pub limit: u32,
}

impl From<SearchQuery> for sc::SearchQuery {
    fn from(q: SearchQuery) -> Self {
        sc::SearchQuery {
            account: q.account,
            text: q.text,
            folder: q.folder,
            limit: q.limit as usize,
        }
    }
}

/// One result of [`Engine::search`]; results come best first.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchHit {
    pub summary: MessageSummary,
    /// About 16 words of the body around the best match, whitespace collapsed, every matched
    /// term between U+E000 and U+E001 (`sealbox_core::MATCH_START` / `MATCH_END`); the start
    /// of the body when only the subject or an address matched; empty without a readable body.
    pub snippet: String,
    /// Relevance, higher is better (the negated FTS5 bm25 score); comparable only within one
    /// result list.
    pub rank: f64,
}

impl From<sc::SearchHit> for SearchHit {
    fn from(h: sc::SearchHit) -> Self {
        Self {
            summary: h.summary.into(),
            snippet: h.snippet,
            rank: h.rank,
        }
    }
}

/// The in-memory search index after [`Engine::rebuild_search_index`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SearchIndexStats {
    /// Messages in the index.
    pub documents: u64,
    /// Size of the in-memory index database (page count × page size).
    pub memory_bytes: u64,
}

impl From<sc::SearchIndexStats> for SearchIndexStats {
    fn from(s: sc::SearchIndexStats) -> Self {
        Self {
            documents: s.documents,
            memory_bytes: s.memory_bytes,
        }
    }
}

impl From<sc::SendPolicy> for SendPolicy {
    fn from(p: sc::SendPolicy) -> Self {
        match p {
            sc::SendPolicy::Auto => SendPolicy::Auto,
            sc::SendPolicy::RequireEncryption => SendPolicy::RequireEncryption,
            sc::SendPolicy::GuestLink => SendPolicy::GuestLink,
            sc::SendPolicy::AllowPlaintext => SendPolicy::AllowPlaintext,
        }
    }
}

/// A file attached to a saved draft (mirrors `sealbox_core::DraftAttachment`): a sealed copy
/// kept in the store (`blob_id`, from [`Engine::put_draft_blob`]) or a reference to a file
/// (`path`, read when the draft is sent; nothing of it is copied). Exactly one is set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DraftAttachment {
    /// Path of the file. [`Engine::save_draft`] stores it canonicalised (absolute) and
    /// refuses a path that is not an existing file. Empty for a stored blob.
    pub path: String,
    /// The stored blob holding the file, sealed at rest like a received attachment; only
    /// drafts of the account that stored it may reference it.
    pub blob_id: Option<i64>,
    /// File name the recipient sees; empty = the file name of `path` / the blob's name.
    pub name: String,
    /// MIME type; empty = the blob's type, else `application/octet-stream`.
    pub content_type: String,
}

impl From<DraftAttachment> for sc::DraftAttachment {
    fn from(a: DraftAttachment) -> Self {
        sc::DraftAttachment {
            path: a.path,
            blob_id: a.blob_id,
            name: a.name,
            content_type: a.content_type,
        }
    }
}

impl From<sc::DraftAttachment> for DraftAttachment {
    fn from(a: sc::DraftAttachment) -> Self {
        Self {
            path: a.path,
            blob_id: a.blob_id,
            name: a.name,
            content_type: a.content_type,
        }
    }
}

/// A file stored for an account's drafts (mirrors `sealbox_core::DraftBlobInfo`); metadata
/// only, nothing unsealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftBlobInfo {
    pub id: i64,
    /// The account (address) whose drafts may reference it.
    pub account: String,
    /// Name it was stored under (an attachment's default name).
    pub filename: String,
    /// MIME type it was stored with; may be empty.
    pub content_type: String,
    /// Bytes.
    pub size: i64,
    /// Unix seconds.
    pub created_at: i64,
}

impl From<sc::DraftBlobInfo> for DraftBlobInfo {
    fn from(b: sc::DraftBlobInfo) -> Self {
        Self {
            id: b.id,
            account: b.account,
            filename: b.filename,
            content_type: b.content_type,
            size: i64::try_from(b.size).unwrap_or(i64::MAX),
            created_at: b.created_at,
        }
    }
}

/// A stored draft blob with its bytes ([`Engine::get_draft_blob`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftBlob {
    pub info: DraftBlobInfo,
    pub data: Vec<u8>,
}

/// Input of [`Engine::save_draft`] (mirrors `sealbox_core::DraftInput`): the whole draft —
/// saving replaces every field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftInput {
    /// `Some` = update that draft (re-created under that id if it is gone); `None` = new.
    pub id: Option<i64>,
    /// Sending account (address).
    pub account: String,
    /// `New` with `in_reply_to` set is stored as `Reply`, with `forward_of` as `Forward`.
    pub kind: ComposeKind,
    /// Reply: local id (digits) or Message-ID of the message answered.
    pub in_reply_to: Option<String>,
    /// Forward: local id or Message-ID of the stored message forwarded.
    pub forward_of: Option<String>,
    /// Quote the answered message below the text when sending (it must be stored locally).
    pub quote: bool,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body_text: String,
    pub attachments: Vec<DraftAttachment>,
    pub policy: SendPolicy,
    pub guest_mode: GuestMode,
    pub guest_recipient_hint: Option<String>,
    /// Do not add the account signature when sending.
    pub no_signature: bool,
}

impl From<DraftInput> for sc::DraftInput {
    fn from(d: DraftInput) -> Self {
        sc::DraftInput {
            id: d.id,
            account: d.account,
            kind: d.kind.into(),
            in_reply_to: d.in_reply_to,
            forward_of: d.forward_of,
            quote: d.quote,
            to: d.to,
            cc: d.cc,
            bcc: d.bcc,
            subject: d.subject,
            body_text: d.body_text,
            attachments: d.attachments.into_iter().map(Into::into).collect(),
            policy: d.policy.into(),
            guest_mode: d.guest_mode.into(),
            guest_recipient_hint: d.guest_recipient_hint,
            no_signature: d.no_signature,
        }
    }
}

/// A saved draft (mirrors `sealbox_core::SavedDraft`). Subject and body are sealed at rest
/// like message bodies; recipients and attachment references are not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedDraft {
    pub id: i64,
    /// Sending account (address).
    pub account: String,
    pub kind: ComposeKind,
    /// Message-ID (no angle brackets) of the message answered, or its local id when it has
    /// none.
    pub in_reply_to: Option<String>,
    /// Message-ID (or local id) of the message forwarded.
    pub forward_of: Option<String>,
    pub quote: bool,
    /// The answered message's `References` plus its Message-ID, oldest first (informational).
    pub references: Vec<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body_text: String,
    pub attachments: Vec<DraftAttachment>,
    pub policy: SendPolicy,
    pub guest_mode: GuestMode,
    pub guest_recipient_hint: Option<String>,
    pub no_signature: bool,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds; lists are newest first by this.
    pub updated_at: i64,
    /// Saved here first, or imported from the account's Drafts folder ([`Engine::sync_drafts`]).
    pub origin: DraftOrigin,
    /// File references the device that saved it kept there: not in its server copy, so not
    /// here (`X-Sealbox-Draft-Files`).
    pub remote_files: u32,
}

/// Where a saved draft was first saved (mirrors `sealbox_core::DraftOrigin`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DraftOrigin {
    /// Saved on this device.
    #[default]
    Local,
    /// Imported from the server: saved on another device with the same key.
    Server,
}

impl From<sc::DraftOrigin> for DraftOrigin {
    fn from(o: sc::DraftOrigin) -> Self {
        match o {
            sc::DraftOrigin::Local => DraftOrigin::Local,
            sc::DraftOrigin::Server => DraftOrigin::Server,
        }
    }
}

/// What [`Engine::sync_drafts`] did (mirrors `sealbox_core::DraftSyncReport`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DraftSyncReport {
    pub account: String,
    /// The Drafts role folder.
    pub folder: String,
    /// Local drafts written to the server.
    pub uploaded: u32,
    /// Server drafts this device did not have.
    pub imported: u32,
    /// Local drafts replaced by a newer server copy.
    pub updated: u32,
    /// Local drafts deleted because their server copy went (sent or discarded elsewhere).
    pub removed_locally: u32,
    /// Server copies deleted (drafts deleted or sent here, older duplicates).
    pub removed_on_server: u32,
    /// Sealbox drafts on the server this device cannot open (another key, or not signed by
    /// this account's key): never imported, never deleted.
    pub unreadable: u32,
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

impl From<sc::DraftSyncReport> for DraftSyncReport {
    fn from(r: sc::DraftSyncReport) -> Self {
        Self {
            account: r.account,
            folder: r.folder,
            uploaded: count(r.uploaded),
            imported: count(r.imported),
            updated: count(r.updated),
            removed_locally: count(r.removed_locally),
            removed_on_server: count(r.removed_on_server),
            unreadable: count(r.unreadable),
        }
    }
}

/// The server state of one draft (mirrors `sealbox_core::DraftServerInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftServerInfo {
    pub uuid: String,
    pub origin: DraftOrigin,
    /// A copy has been written to or read from the server.
    pub on_server: bool,
    /// Edited here since the server copy was written or read.
    pub pending: bool,
    /// File references the saving device kept local.
    pub remote_files: u32,
}

impl From<sc::DraftServerInfo> for DraftServerInfo {
    fn from(i: sc::DraftServerInfo) -> Self {
        Self {
            uuid: i.uuid,
            origin: if i.origin == "server" {
                DraftOrigin::Server
            } else {
                DraftOrigin::Local
            },
            on_server: i.on_server,
            pending: i.pending,
            remote_files: count(i.remote_files),
        }
    }
}

impl From<sc::SavedDraft> for SavedDraft {
    fn from(d: sc::SavedDraft) -> Self {
        Self {
            id: d.id,
            account: d.account,
            kind: d.kind.into(),
            in_reply_to: d.in_reply_to,
            forward_of: d.forward_of,
            quote: d.quote,
            references: d.references,
            to: d.to,
            cc: d.cc,
            bcc: d.bcc,
            subject: d.subject,
            body_text: d.body_text,
            attachments: d.attachments.into_iter().map(Into::into).collect(),
            policy: d.policy.into(),
            guest_mode: d.guest_mode.into(),
            guest_recipient_hint: d.guest_recipient_hint,
            no_signature: d.no_signature,
            created_at: d.created_at,
            updated_at: d.updated_at,
            origin: d.origin.into(),
            remote_files: d.remote_files,
        }
    }
}

// ----- the engine -----------------------------------------------------------------------

/// Built-in provider table only (no network, instant). `None` for unknown domains.
#[frb(sync)]
pub fn detect_servers_offline(email: String) -> Option<ServerConfig> {
    sc::Engine::detect_servers_offline(&email).map(Into::into)
}

/// A fresh guest-link passphrase from OS randomness (`xxxx-xxxx-xxxx-xxxx-xxxx`, 100 bits).
#[frb(sync)]
pub fn generate_guest_passphrase() -> String {
    sc::sealbox_crypto::generate_passphrase()
}

/// The Sealbox engine for one profile directory. Cheap to clone on the Dart side (it is an
/// `Arc`); all methods are safe to call concurrently.
#[frb(opaque)]
pub struct Engine {
    inner: Arc<sc::Engine>,
}

impl Engine {
    /// Open (creating if needed) the profile at `profile_dir`. Configuration comes from the
    /// environment (`SEALBOX_DIRECTORY_URL`, `SEALBOX_SERVER_URL`,
    /// `SEALBOX_NETWORK_TIMEOUT_SECS`), exactly like the CLI; a server URL stored with
    /// [`Engine::set_server_url`] wins over the environment.
    pub fn open(profile_dir: String) -> Result<Engine> {
        let inner = sc::Engine::open(&profile_dir).map_err(err)?;
        tracing::info!(profile = %profile_dir, "engine opened");
        Ok(Engine {
            inner: Arc::new(inner),
        })
    }

    /// Open the profile with a raw 32-byte master key (`ProfileKeySource::Raw`, G27): the app
    /// lock's key from Android Keystore / iOS Keychain / libsecret. Everything else comes from
    /// the environment like [`Engine::open`]. A profile keyed by another source (or with
    /// another key) fails with `profile locked: …` before any sensitive row is read; a legacy
    /// plaintext profile is wrapped with this key on first open.
    pub fn open_with_key(profile_dir: String, profile_key: Vec<u8>) -> Result<Engine> {
        if profile_key.len() != 32 {
            return Err(anyhow!("profile key must be 32 bytes"));
        }
        let cfg = sc::EngineConfig {
            profile_key: sc::ProfileKeySource::Raw(profile_key),
            ..sc::EngineConfig::from_env()
        };
        let inner = sc::Engine::open_with(&profile_dir, cfg).map_err(err)?;
        tracing::info!(profile = %profile_dir, "engine opened (raw profile key)");
        Ok(Engine {
            inner: Arc::new(inner),
        })
    }

    /// How the profile's secrets are protected at rest (G27).
    pub fn profile_key_status(&self) -> Result<ProfileKeyStatus> {
        self.inner.profile_key_status().map(Into::into).map_err(err)
    }

    /// Re-key the profile with a raw 32-byte master key (one-time migration of a desktop
    /// profile that was keyed by the OS keyring before the app lock existed).
    pub fn rewrap_profile_raw(&self, profile_key: Vec<u8>) -> Result<ProfileKeyStatus> {
        if profile_key.len() != 32 {
            return Err(anyhow!("profile key must be 32 bytes"));
        }
        self.inner
            .rewrap_profile(sc::ProfileKeySource::Raw(profile_key))
            .map(Into::into)
            .map_err(err)
    }

    /// The profile directory this engine was opened on.
    #[frb(sync)]
    pub fn profile_dir(&self) -> String {
        self.inner.profile_dir().display().to_string()
    }

    /// A Sealbox server URL is configured ([`Engine::set_server_url`] or
    /// `SEALBOX_SERVER_URL`), so guest-link sends can work.
    #[frb(sync)]
    pub fn guest_links_available(&self) -> bool {
        self.inner.server_url().is_some()
    }

    /// A key directory is configured (`SEALBOX_DIRECTORY_URL`, else the Sealbox server) for
    /// recipient lookups and publishing.
    #[frb(sync)]
    pub fn key_directory_available(&self) -> bool {
        self.inner.directory_url().is_some()
    }

    // ----- accounts --------------------------------------------------------------------

    /// Full autodiscovery: built-in table, then ISPDB / autoconfig / SRV / MX / guesses.
    pub async fn detect_servers(&self, email: String) -> Result<ServerConfig> {
        self.inner
            .detect_servers(&email)
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// Add an account: autodiscover unless servers are given, test IMAP and SMTP, generate an
    /// OpenPGP identity for the address if none exists, persist everything.
    pub async fn add_account(&self, req: AddAccount) -> Result<AccountInfo> {
        self.inner
            .add_account(req.into())
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// Every account (no secrets).
    pub fn list_accounts(&self) -> Result<Vec<AccountInfo>> {
        Ok(self
            .inner
            .list_accounts()
            .map_err(err)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Remove an account and everything stored for it (messages, identity, sync state).
    pub fn remove_account(&self, email: String) -> Result<()> {
        self.inner.remove_account(&email).map_err(err)
    }

    // ----- sync ------------------------------------------------------------------------

    /// Sync INBOX (and the Sent folder when the server has one) for one account.
    pub async fn sync(&self, email: String) -> Result<SyncReport> {
        self.inner.sync(&email).await.map(Into::into).map_err(err)
    }

    /// [`Engine::sync`] as a Dart `Stream` that says how far it got: a `Progress` event after
    /// every batch the engine stored (committed, so the list can show it at once), then one
    /// `Done` event with the report, and the stream closes. A failed sync ends the stream
    /// with the error (`AnyhowException`) instead of `Done`. A folder's first sync stores its
    /// newest 500 messages only (`FolderSync.more_to_backfill`; see
    /// [`Engine::backfill_with_progress`]). Cancelling the subscription does not stop the
    /// sync: the engine finishes the run (it cannot stop between batches) and keeps what it
    /// stored; the remaining events are dropped. Takes the account's mailbox lock, so it waits
    /// for a watcher's sync or a backfill of the same account that is running.
    pub async fn sync_account_with_progress(
        &self,
        email: String,
        sink: StreamSink<SyncEvent>,
    ) -> Result<()> {
        self.sync_items(&email, |item| to_sink(&sink, item)).await;
        Ok(())
    }

    /// Older mail as a Dart `Stream` ([`Engine::sync_account_with_progress`]'s events):
    /// up to `max_messages` messages (`None`: all of them) below the newest window of every
    /// folder that has some, INBOX first, newest first, with the spam / filter / auto-reply
    /// passes a sync runs. Nothing left: just `Done` (no network). `Done`'s
    /// `FolderSync.more_to_backfill` says whether older mail remains for another call; every
    /// batch is saved, so a later call (or sync) continues where this one stopped. Takes the
    /// account's mailbox lock for the whole call: keep `max_messages` small enough (the app
    /// asks for 1,000 at a time) that new mail and manual syncs do not wait long.
    pub async fn backfill_with_progress(
        &self,
        email: String,
        max_messages: Option<u32>,
        sink: StreamSink<SyncEvent>,
    ) -> Result<()> {
        self.backfill_items(&email, max_messages, |item| to_sink(&sink, item))
            .await;
        Ok(())
    }

    /// The sync behind [`Engine::sync_account_with_progress`], reporting to `emit` (a Dart
    /// sink in the app, a `Vec` in tests): every stored batch, then the report or the error.
    async fn sync_items(&self, email: &str, mut emit: impl FnMut(SyncItem) + Send) {
        let outcome = self
            .inner
            .sync_with_progress(email, |p| emit(Ok(SyncEvent::progress(p))))
            .await;
        emit(outcome.map(SyncEvent::done).map_err(|e| e.to_string()));
    }

    /// The backfill behind [`Engine::backfill_with_progress`] (see [`Engine::sync_items`]).
    async fn backfill_items(
        &self,
        email: &str,
        max_messages: Option<u32>,
        mut emit: impl FnMut(SyncItem) + Send,
    ) {
        let max = max_messages.map(|n| usize::try_from(n).unwrap_or(usize::MAX));
        let outcome = self
            .inner
            .backfill_with_progress(email, max, |p| emit(Ok(SyncEvent::progress(p))))
            .await;
        emit(outcome.map(SyncEvent::done).map_err(|e| e.to_string()));
    }

    /// Sync every account; failures are reported per account, never thrown.
    pub async fn sync_all(&self) -> Vec<AccountSyncResult> {
        self.inner
            .sync_all()
            .await
            .into_iter()
            .map(|(account, r)| match r {
                Ok(report) => AccountSyncResult {
                    account,
                    report: Some(report.into()),
                    error: None,
                },
                Err(e) => AccountSyncResult {
                    account,
                    report: None,
                    error: Some(e.to_string()),
                },
            })
            .collect()
    }

    /// Watch INBOX with IMAP IDLE as a Dart `Stream`. After an initial catch-up sync every
    /// server notification triggers a sync and a `NewMail` event. Cancelling the Dart
    /// subscription closes the sink; the loop notices on its next event, so it ends within
    /// `idle_timeout_secs` (clamped to 5 s … 29 min) of the cancel. A watcher that fails
    /// (connection lost, login rejected, no IDLE) ends the stream with the error
    /// (`AnyhowException`), so the app can tell a rejected login from a dropped connection.
    pub async fn watch(
        &self,
        email: String,
        idle_timeout_secs: u32,
        sink: StreamSink<WatchEvent>,
    ) -> Result<()> {
        let timeout = Duration::from_secs(u64::from(idle_timeout_secs.clamp(5, 29 * 60)));
        self.watch_items(&email, timeout, |item| match item {
            Ok(event) => sink.add(event).is_ok(),
            Err(message) => {
                let _ = sink.add_error(message);
                false
            }
        })
        .await;
        // The failure went into the stream: this function's own result never reaches Dart
        // (a stream function's is not awaited), so an `Err` here would only be lost.
        Ok(())
    }

    /// The watcher behind [`Engine::watch`]: every event to `emit` until it returns `false`,
    /// then — if the watcher failed — the error (the engine's `Display` text).
    async fn watch_items(
        &self,
        email: &str,
        timeout: Duration,
        mut emit: impl FnMut(std::result::Result<WatchEvent, String>) -> bool + Send,
    ) {
        let outcome = self
            .inner
            .watch(email, timeout, |event| emit(Ok(event.into())))
            .await;
        if let Err(e) = outcome {
            emit(Err(e.to_string()));
        }
    }

    // ----- sending ---------------------------------------------------------------------

    /// Send `draft` from `account_email` according to `draft.policy`.
    pub async fn send(&self, account_email: String, draft: Draft) -> Result<SendReport> {
        self.inner
            .send(&account_email, draft.into())
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// Mail a fresh notification for a guest message sent earlier (same link id and
    /// ciphertext; G29). `message_id` is the `SendReport.message_id` of that send.
    pub async fn resend_guest_link(&self, message_id: String) -> Result<SendReport> {
        self.inner
            .resend_guest_link(&message_id)
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// Resolve one address the way `send` would (own accounts → Autocrypt → imported keys).
    pub fn resolve_recipient(
        &self,
        address: String,
        reply_to_encrypted: bool,
    ) -> Result<RecipientStatus> {
        self.inner
            .resolve_recipient(&address, reply_to_encrypted)
            .map(Into::into)
            .map_err(err)
    }

    // ----- reading (local, no network) ------------------------------------------------

    /// Stored messages, newest first.
    pub fn list_messages(&self, query: ListQuery) -> Result<Vec<MessageSummary>> {
        Ok(self
            .inner
            .list_messages(query.into())
            .map_err(err)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// One message with its decrypted bodies and attachment list.
    ///
    /// [`MessageDetail::html`] is the HTML as it arrived and must never be rendered: use
    /// [`Engine::message_html`].
    pub fn get_message(&self, id: i64) -> Result<MessageDetail> {
        self.inner.get_message(id).map(Into::into).map_err(err)
    }

    /// The displayable HTML body of a message, or `None` when it has none (or nothing is left
    /// to show). The only HTML a UI may render — see `docs/HTML_MAIL.md`.
    ///
    /// Pass `allow_remote = true` only after the user asked for remote images on *this*
    /// message: it is what lets the sender's server see that the mail was opened.
    pub fn message_html(&self, id: i64, allow_remote: bool) -> Result<Option<HtmlBody>> {
        self.inner
            .message_html(id, allow_remote)
            .map(|b| b.map(Into::into))
            .map_err(err)
    }

    /// Attachment bytes.
    pub fn get_attachment(&self, id: i64, index: u32) -> Result<AttachmentBytes> {
        let (info, data) = self.inner.get_attachment(id, index as usize).map_err(err)?;
        Ok(AttachmentBytes {
            info: info.into(),
            data,
        })
    }

    /// Add or remove IMAP flags on the server and locally; returns the new flag set.
    pub async fn set_flags(&self, id: i64, op: FlagOp, flags: Vec<String>) -> Result<Vec<String>> {
        self.inner
            .set_flags(id, op.into(), &flags)
            .await
            .map_err(err)
    }

    /// Delete a message on the server (`\Deleted` + `EXPUNGE`) and locally.
    pub async fn delete_message(&self, id: i64) -> Result<()> {
        self.inner.delete_message(id).await.map_err(err)
    }

    // ----- keys ------------------------------------------------------------------------

    /// Everyone we know a key or Autocrypt state for (own accounts excluded).
    pub fn contacts(&self) -> Result<Vec<Contact>> {
        Ok(self
            .inner
            .contacts()
            .map_err(err)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// ASCII-armored public key of the account.
    pub fn export_public_key(&self, email: String) -> Result<String> {
        self.inner.export_public_key(&email).map_err(err)
    }

    /// Import somebody's public key for `address` (received out of band).
    pub fn import_peer_key(&self, address: String, armored: String) -> Result<Contact> {
        self.inner
            .import_peer_key(&address, &armored)
            .map(Into::into)
            .map_err(err)
    }

    /// Fingerprint of the account's OpenPGP key.
    pub fn my_fingerprint(&self, email: String) -> Result<String> {
        self.inner.my_fingerprint(&email).map_err(err)
    }
    // ----- per-account settings ---------------------------------------------------------

    /// The account's signature settings (defaults when never set).
    pub fn get_signature(&self, account: String) -> Result<SignatureSettings> {
        self.inner
            .get_signature(&account)
            .map(Into::into)
            .map_err(err)
    }

    /// Store the signature (validated + normalised by the engine); returns what was stored.
    pub fn set_signature(
        &self,
        account: String,
        settings: SignatureSettings,
    ) -> Result<SignatureSettings> {
        self.inner
            .set_signature(&account, settings.into())
            .map(Into::into)
            .map_err(err)
    }

    /// The account's out-of-office settings (defaults when never set).
    pub fn get_auto_reply(&self, account: String) -> Result<AutoReplySettings> {
        self.inner
            .get_autoreply(&account)
            .map(Into::into)
            .map_err(err)
    }

    /// Store the out-of-office settings; enabling starts a new absence period.
    pub fn set_auto_reply(
        &self,
        account: String,
        settings: AutoReplySettings,
    ) -> Result<AutoReplySettings> {
        self.inner
            .set_autoreply(&account, settings.into())
            .map(Into::into)
            .map_err(err)
    }

    /// Auto-replies sent for the account, newest first.
    pub fn auto_reply_log(&self, account: String, limit: u32) -> Result<Vec<AutoReplyLogEntry>> {
        Ok(self
            .inner
            .autoreply_log(&account, limit as usize)
            .map_err(err)?
            .into_iter()
            .map(Into::into)
            .collect())
    }
    // ----- identity (G30) ----------------------------------------------------------------

    /// Mark `address` as verified with `fingerprint` (hex, spaces/colons allowed, or the
    /// `OPENPGP4FPR:` payload). Fails with "fingerprint mismatch …" unless it is the current key.
    pub fn verify_contact(&self, address: String, fingerprint: String) -> Result<Contact> {
        self.inner
            .verify_contact(&address, &fingerprint)
            .map(Into::into)
            .map_err(err)
    }

    /// Remove the verified mark.
    pub fn unverify_contact(&self, address: String) -> Result<Contact> {
        self.inner
            .unverify_contact(&address)
            .map(Into::into)
            .map_err(err)
    }

    /// Accept a changed key without checking it (clears the key-change alert).
    pub fn acknowledge_key_change(&self, address: String) -> Result<Contact> {
        self.inner
            .acknowledge_key_change(&address)
            .map(Into::into)
            .map_err(err)
    }

    /// `OPENPGP4FPR:<hex>` for one of our own accounts (show it as a QR code).
    pub fn fingerprint_qr_payload(&self, email: String) -> Result<String> {
        self.inner.fingerprint_qr_payload(&email).map_err(err)
    }

    /// Parse a scanned `OPENPGP4FPR:` payload into the upper-case fingerprint.
    #[frb(sync)]
    pub fn parse_fingerprint_qr(payload: String) -> Result<String> {
        sc::Engine::parse_fingerprint_qr(&payload).map_err(err)
    }

    /// Audit the key-transparency log for one of our accounts (configured server, TOFU pin).
    pub async fn kt_audit(&self, email: String) -> Result<KtAuditReport> {
        self.inner
            .kt_audit(&email)
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// One page of raw key-transparency log entries.
    pub async fn kt_entries(
        &self,
        server: Option<String>,
        start: u64,
        limit: u64,
    ) -> Result<KtEntriesPage> {
        self.inner
            .kt_entries(server.as_deref(), start, limit)
            .await
            .map(Into::into)
            .map_err(err)
    }

    // ----- recovery (G15) ----------------------------------------------------------------

    /// The effective Sealbox server URL, the default backup target: the runtime setting
    /// ([`Engine::set_server_url`]), else `SEALBOX_SERVER_URL`. Reads one settings row.
    #[frb(sync)]
    pub fn server_url(&self) -> Option<String> {
        self.inner.server_url()
    }

    /// A new 12-word recovery phrase for `email` (stored nowhere; show it once).
    pub fn recovery_phrase_create(&self, email: String) -> Result<RecoveryPhrase> {
        self.inner
            .recovery_phrase_create(&email)
            .map(Into::into)
            .map_err(err)
    }

    /// Check a typed phrase: wrong count / unknown word → error naming it; otherwise the
    /// normalised words and whether the checksum matches. No network.
    #[frb(sync)]
    pub fn recovery_phrase_validate(words: String) -> Result<RecoveryPhrase> {
        sc::Engine::recovery_phrase_validate(&words)
            .map(Into::into)
            .map_err(err)
    }

    /// Encrypt keys, contacts and settings with the phrase and upload them.
    pub async fn backup_to_server(
        &self,
        email: String,
        server_url: String,
        phrase: String,
    ) -> Result<BackupReport> {
        self.inner
            .backup_to_server(&email, &server_url, &phrase)
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// [`Engine::backup_to_server`] with options (e.g. include the mail credential).
    pub async fn backup_to_server_with(
        &self,
        email: String,
        server_url: String,
        phrase: String,
        opts: BackupOptions,
    ) -> Result<BackupReport> {
        self.inner
            .backup_to_server_with(&email, &server_url, &phrase, &opts.into())
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// Last backup from this device and the reminder text (no network).
    pub fn backup_status(&self, email: String) -> Result<BackupStatus> {
        self.inner
            .backup_status(&email)
            .map(Into::into)
            .map_err(err)
    }

    /// Restore an account from the server backup (slot found via the key directory).
    pub async fn restore_from_server(
        &self,
        server_url: String,
        email: String,
        phrase: String,
    ) -> Result<AccountInfo> {
        self.inner
            .restore_from_server(&server_url, &email, &phrase)
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// [`Engine::restore_from_server`] with a fingerprint, credential or server overrides.
    pub async fn restore_from_server_with(
        &self,
        server_url: String,
        email: String,
        phrase: String,
        opts: RestoreOptions,
    ) -> Result<AccountInfo> {
        self.inner
            .restore_from_server_with(&server_url, &email, &phrase, &opts.into())
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// Store (or replace) the mail credential of an account, e.g. after a restore.
    pub fn set_account_credential(&self, email: String, auth: AuthSpec) -> Result<AccountInfo> {
        self.inner
            .set_account_credential(&email, &auth.into())
            .map(Into::into)
            .map_err(err)
    }

    /// Mail an Autocrypt Setup Message to ourselves; returns the 36-digit code.
    pub async fn setup_message_export(&self, email: String) -> Result<SetupExport> {
        self.inner
            .setup_message_export(&email)
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// Import an Autocrypt Setup Message (local message id, Message-ID or file path).
    pub fn setup_message_import(&self, source: String, setup_code: String) -> Result<AccountInfo> {
        self.inner
            .setup_message_import(&source, &setup_code)
            .map(Into::into)
            .map_err(err)
    }

    // ----- folders by special-use role ---------------------------------------------------

    /// The roles the server's `LIST` mapped for the account, as remembered from the last sync
    /// (empty before the first sync); every entry has `learned == true`. No network.
    pub fn folder_roles(&self, email: String) -> Result<Vec<FolderRoleEntry>> {
        Ok(self
            .inner
            .folder_roles(&email)
            .map_err(err)?
            .into_iter()
            .map(|(role, folder)| FolderRoleEntry {
                role: role.into(),
                folder,
                learned: true,
            })
            .collect())
    }

    /// Every role with the folder it maps to: learned from the server, else the provider
    /// default (`learned == false`). No network; enough to draw folder chips.
    pub fn folder_role_entries(&self, email: String) -> Result<Vec<FolderRoleEntry>> {
        Ok(self
            .inner
            .folder_role_entries(&email)
            .map_err(err)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Sync the folder playing `role` for one account (the Trash / Spam / Archive chips). An
    /// INBOX sync runs the spam / filter / auto-reply passes like [`Engine::sync`]; the Sent
    /// folder is not touched. A role the server has no folder for yields an empty report
    /// (`folders` empty). Serialised with every other sync of the account.
    pub async fn sync_folder_role(&self, email: String, role: FolderRole) -> Result<SyncReport> {
        self.inner
            .sync_folder_role(&email, role.into())
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// Move a stored message to the folder playing `role` (Trash, Junk, Archive, Inbox, …),
    /// creating the folder when the server has none. The local row is dropped; the message
    /// is stored again (under a new id) when the destination folder is synced. Serialised
    /// with the account's syncs.
    pub async fn move_message(&self, id: i64, role: FolderRole) -> Result<MoveReport> {
        self.inner
            .move_message(id, role.into())
            .await
            .map(Into::into)
            .map_err(err)
    }

    // ----- compose: quoting and the signature (G23) ----------------------------------------

    /// [`Engine::send`] with compose options: reply / forward quoting and signature control.
    /// The account signature is added per its settings (`include_on`, `placement`) unless
    /// `opts.skip_signature`. `send` is `send_with` with `ComposeOptions::default()`.
    pub async fn send_with(
        &self,
        account_email: String,
        draft: Draft,
        opts: ComposeOptions,
    ) -> Result<SendReport> {
        self.inner
            .send_with(&account_email, draft.into(), opts.into())
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// Exactly the bodies [`Engine::send_with`] would send for `draft` + `opts`, without
    /// sending anything (a compose screen showing quote and signature). Fails where
    /// `send_with` would before the network: unknown account, or a reply to quote / a forward
    /// that is not stored locally.
    pub fn compose_preview(
        &self,
        account_email: String,
        draft: Draft,
        opts: ComposeOptions,
    ) -> Result<ComposePreview> {
        self.inner
            .compose_preview(&account_email, draft.into(), opts.into())
            .map(Into::into)
            .map_err(err)
    }

    /// The signature block [`Engine::send_with`] would append to a message of `kind`, or
    /// `None` when the signature is off, empty or does not apply to that kind.
    pub fn signature_preview(
        &self,
        account_email: String,
        kind: ComposeKind,
    ) -> Result<Option<SignaturePreview>> {
        self.inner
            .signature_preview(&account_email, kind.into())
            .map(|p| p.map(Into::into))
            .map_err(err)
    }

    // ----- spam (G25) ----------------------------------------------------------------------

    /// The account's spam settings (defaults when never set).
    pub fn spam_settings(&self, email: String) -> Result<SpamSettings> {
        self.inner
            .spam_settings(&email)
            .map(Into::into)
            .map_err(err)
    }

    /// Replace the account's spam settings (validated and normalised); returns what was
    /// stored. Invalid values fail with `invalid input: …` and change nothing.
    pub fn set_spam_settings(&self, email: String, settings: SpamSettings) -> Result<SpamSettings> {
        self.inner
            .set_spam_settings(&email, settings.into())
            .map(Into::into)
            .map_err(err)
    }

    /// Add (`add == true`) or remove an allowlist entry (an address or a domain; a leading
    /// `@` is dropped). Adding also removes it from the blocklist. Returns the new settings.
    pub fn spam_allow(&self, email: String, entry: String, add: bool) -> Result<SpamSettings> {
        self.inner
            .spam_allow(&email, &entry, add)
            .map(Into::into)
            .map_err(err)
    }

    /// Add or remove a blocklist entry; adding also removes it from the allowlist.
    pub fn spam_block(&self, email: String, entry: String, add: bool) -> Result<SpamSettings> {
        self.inner
            .spam_block(&email, &entry, add)
            .map(Into::into)
            .map_err(err)
    }

    /// Model statistics plus every account's settings and label counts (local).
    pub fn spam_status(&self) -> Result<SpamStatus> {
        self.inner.spam_status().map(Into::into).map_err(err)
    }

    /// Why a stored message got its label: the stored verdict, a fresh offline evaluation,
    /// the extracted features and what the filter rules would do (no network).
    pub fn spam_explain(&self, id: i64) -> Result<SpamExplanation> {
        self.inner.spam_explain(id).map(Into::into).map_err(err)
    }

    /// The user's feedback: (un)learn the message, store the label and move it to the junk
    /// folder (`is_spam`) or back to INBOX (`!is_spam`). Serialised with the account's syncs.
    pub async fn spam_learn(&self, id: i64, is_spam: bool) -> Result<SpamLearnReport> {
        self.inner
            .spam_learn(id, is_spam)
            .await
            .map(Into::into)
            .map_err(err)
    }

    // ----- filter rules (G25) ------------------------------------------------------------

    /// The account's filter rules in evaluation order.
    pub fn filter_rules(&self, email: String) -> Result<Vec<FilterRule>> {
        Ok(self
            .inner
            .filter_rules(&email)
            .map_err(err)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Validate and store a new rule (`id` is ignored; `order == 0` appends it). Returns the
    /// stored rule with its id and order. Invalid rules (empty value, bad regex, no folder,
    /// a header field without a name, a malformed flag) fail with `invalid input: …`.
    pub fn add_filter_rule(&self, email: String, rule: FilterRule) -> Result<FilterRule> {
        self.inner
            .add_filter_rule(&email, rule.into())
            .map(Into::into)
            .map_err(err)
    }

    /// Replace a stored rule (same `id`), validated like [`Engine::add_filter_rule`].
    pub fn update_filter_rule(&self, email: String, rule: FilterRule) -> Result<FilterRule> {
        self.inner
            .update_filter_rule(&email, rule.into())
            .map(Into::into)
            .map_err(err)
    }

    /// Delete a rule; `false` when there was none with that id.
    pub fn remove_filter_rule(&self, email: String, id: i64) -> Result<bool> {
        self.inner.remove_filter_rule(&email, id).map_err(err)
    }

    /// Enable or disable a rule; returns it.
    pub fn set_filter_rule_enabled(
        &self,
        email: String,
        id: i64,
        enabled: bool,
    ) -> Result<FilterRule> {
        self.inner
            .set_filter_rule_enabled(&email, id, enabled)
            .map(Into::into)
            .map_err(err)
    }

    /// Replace every rule of the account with `rules`, in the order given (a rules editor
    /// saving its whole list). All rules are validated first, nothing changes when one is
    /// invalid; ids are reassigned and `order` becomes 10, 20, … by position.
    pub fn set_filter_rules(
        &self,
        email: String,
        rules: Vec<FilterRule>,
    ) -> Result<Vec<FilterRule>> {
        Ok(self
            .inner
            .set_filter_rules(&email, rules.into_iter().map(Into::into).collect())
            .map_err(err)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Dry run of the account's rules against one of its stored messages (nothing changes).
    pub fn test_filter_rules(&self, email: String, message_id: i64) -> Result<FilterTestReport> {
        self.inner
            .test_filter_rules(&email, message_id)
            .map(Into::into)
            .map_err(err)
    }

    // ----- key directory: publishing the account key -----------------------------------------

    /// Upload the account's public key to the key directory and, unless the address already
    /// is published, request the verification mail (`token_issued`). Without a server URL it
    /// fails with "no Sealbox server configured: … `sealbox server set-url` …" and contacts
    /// nothing.
    pub async fn publish_key(&self, email: String) -> Result<PublishReport> {
        self.inner
            .publish_key(&email)
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// What the directory holds for the account's address (one lookup).
    pub async fn directory_status(&self, email: String) -> Result<DirectoryStatus> {
        self.inner
            .directory_status(&email)
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// Finish publishing: sync INBOX (and the junk folder), find the directory's challenge
    /// mail and follow its link — only links of the configured directory — then report the
    /// state. `awaiting_verification` = the mail has not arrived yet (call again later).
    pub async fn complete_directory_verification(&self, email: String) -> Result<DirectoryStatus> {
        self.inner
            .complete_directory_verification(&email)
            .await
            .map(Into::into)
            .map_err(err)
    }

    // ----- the Sealbox server URL (runtime setting) -----------------------------------------

    /// Set (or with `None` / an empty string clear) the Sealbox server used for the key
    /// directory, guest links, backups and the key-transparency log. Persisted in the
    /// profile; wins over `SEALBOX_SERVER_URL`. Must be `http(s)://host[:port]` (a trailing
    /// slash is dropped), anything else fails with `invalid input: …`. Returns the effective
    /// URL afterwards: clearing falls back to the environment, if it has one.
    pub fn set_server_url(&self, url: Option<String>) -> Result<Option<String>> {
        self.inner.set_server_url(url).map_err(err)
    }

    /// Where [`Engine::server_url`] comes from: `settings`, `environment` or `none`.
    #[frb(sync)]
    pub fn server_url_source(&self) -> String {
        self.inner.server_url_source().to_string()
    }

    /// Base URL of the key directory: `SEALBOX_DIRECTORY_URL`, else the Sealbox server.
    #[frb(sync)]
    pub fn directory_url(&self) -> Option<String> {
        self.inner.directory_url()
    }

    // ----- search and saved drafts (local; only `send_draft` uses the network) ----------------

    /// Search the stored mail: subject, sender and recipient names and addresses, and the
    /// decrypted body. Every word must match, the last one also as a prefix; best match
    /// first. The first search of a process builds the in-memory index (bodies are sealed at
    /// rest, so the index never touches the disk; about 0.13 s per 10,000 messages in a
    /// release build). An unknown `query.account` fails with `account not found`.
    pub fn search(&self, query: SearchQuery) -> Result<Vec<SearchHit>> {
        Ok(self
            .inner
            .search(query.into())
            .map_err(err)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Build (or rebuild) the in-memory search index now, so the first search is fast.
    /// Never needed for correctness: the index follows every change to the stored mail.
    pub fn rebuild_search_index(&self) -> Result<SearchIndexStats> {
        self.inner
            .rebuild_search_index()
            .map(Into::into)
            .map_err(err)
    }

    /// Save a draft: `input.id = None` creates one, `Some(id)` replaces that draft (or
    /// re-creates it under that id when it is gone; ids are never reused). Recipients may be
    /// empty; attachment paths must name existing files. Nothing is sent.
    pub fn save_draft(&self, input: DraftInput) -> Result<SavedDraft> {
        self.inner
            .save_draft(input.into())
            .map(Into::into)
            .map_err(err)
    }

    /// Saved drafts, most recently updated first; `account` = only that account's.
    pub fn list_drafts(&self, account: Option<String>) -> Result<Vec<SavedDraft>> {
        Ok(self
            .inner
            .list_drafts(account.as_deref())
            .map_err(err)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// One saved draft; an unknown id fails with `invalid input: no draft <id>`.
    pub fn get_draft(&self, id: i64) -> Result<SavedDraft> {
        self.inner.get_draft(id).map(Into::into).map_err(err)
    }

    /// Delete a draft; `false` when there was none with that id.
    pub fn delete_draft(&self, id: i64) -> Result<bool> {
        self.inner.delete_draft(id).map_err(err)
    }

    /// Send a saved draft with its own policy through `send_with` (signature, quoting,
    /// forwarding, Sent copy) and delete it, with its stored blobs, once the message is out;
    /// a failure keeps both. A second call for a draft being sent fails at once with
    /// `draft <id> is being sent` and sends nothing.
    pub async fn send_draft(&self, id: i64) -> Result<SendReport> {
        self.inner.send_draft(id).await.map(Into::into).map_err(err)
    }

    /// Put draft `id`'s current version on the server (its account's Drafts folder,
    /// encrypted and signed to the account's own key), replacing the earlier copy: APPEND the
    /// new one, then delete the old. What the app runs after a save, in the background.
    pub async fn push_draft(&self, id: i64) -> Result<()> {
        self.inner.push_draft(id).await.map_err(err)
    }

    /// Two-way sync of `account_email`'s drafts with its Drafts folder: import what other
    /// devices with the same key saved, take newer server copies, upload local changes,
    /// remove what was sent or deleted elsewhere.
    pub async fn sync_drafts(&self, account_email: String) -> Result<DraftSyncReport> {
        self.inner
            .sync_drafts(&account_email)
            .await
            .map(Into::into)
            .map_err(err)
    }

    /// The server state of draft `id` (`None` for an unknown id).
    pub fn draft_server_info(&self, id: i64) -> Result<Option<DraftServerInfo>> {
        self.inner
            .draft_server_info(id)
            .map(|i| i.map(Into::into))
            .map_err(err)
    }

    /// Store a sealed copy of a file for `account_email`'s drafts and return its id (what a
    /// [`DraftAttachment`] names in `blob_id`). Sealed at rest like a received attachment;
    /// deleted with the draft that references it, or by [`Engine::sweep_draft_blobs`] once
    /// no draft does.
    pub fn put_draft_blob(
        &self,
        account_email: String,
        filename: String,
        content_type: String,
        data: Vec<u8>,
    ) -> Result<i64> {
        self.inner
            .put_draft_blob(&account_email, &filename, &content_type, &data)
            .map_err(err)
    }

    /// A stored draft blob with its bytes; an unknown id fails with
    /// `invalid input: no draft blob <id>`.
    pub fn get_draft_blob(&self, id: i64) -> Result<DraftBlob> {
        let (info, data) = self.inner.get_draft_blob(id).map_err(err)?;
        Ok(DraftBlob {
            info: info.into(),
            data,
        })
    }

    /// Delete a stored draft blob; `false` when there was none.
    pub fn delete_draft_blob(&self, id: i64) -> Result<bool> {
        self.inner.delete_draft_blob(id).map_err(err)
    }

    /// `account_email`'s stored draft blobs, oldest first (metadata only).
    pub fn list_draft_blobs(&self, account_email: String) -> Result<Vec<DraftBlobInfo>> {
        self.inner
            .list_draft_blobs(&account_email)
            .map(|v| v.into_iter().map(Into::into).collect())
            .map_err(err)
    }

    /// Delete `account_email`'s stored draft blobs that no saved draft references and that
    /// are more than ten minutes old; returns how many (the app runs it at start-up).
    pub fn sweep_draft_blobs(&self, account_email: String) -> Result<u32> {
        self.inner
            .sweep_draft_blobs(&account_email)
            .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
            .map_err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bridge engine on a fresh profile that does not depend on the environment: a raw
    /// profile key (never the OS keyring) and no server / directory URL.
    fn bare_engine(dir: &tempfile::TempDir) -> Engine {
        let cfg = sc::EngineConfig {
            profile_key: sc::ProfileKeySource::Raw(vec![0x5b; 32]),
            ..sc::EngineConfig::default()
        };
        Engine {
            inner: Arc::new(sc::Engine::open_with(dir.path(), cfg).unwrap()),
        }
    }

    #[test]
    fn attachment_info_carries_the_content_id() {
        let core = |content_id: Option<&str>| sc::AttachmentInfo {
            index: 2,
            filename: "logo.png".into(),
            content_type: "image/png".into(),
            size: 68,
            content_id: content_id.map(str::to_owned),
        };
        assert_eq!(
            AttachmentInfo::from(core(Some("logo@x"))),
            AttachmentInfo {
                index: 2,
                filename: "logo.png".into(),
                content_type: "image/png".into(),
                size: 68,
                content_id: Some("logo@x".into()),
            }
        );
        assert_eq!(AttachmentInfo::from(core(None)).content_id, None);
    }

    #[test]
    fn folder_role_compose_and_directory_dtos_round_trip() {
        for r in sc::FolderRole::ALL {
            assert_eq!(sc::FolderRole::from(FolderRole::from(r)), r);
        }
        for k in [
            sc::ComposeKind::New,
            sc::ComposeKind::Reply,
            sc::ComposeKind::Forward,
        ] {
            assert_eq!(sc::ComposeKind::from(ComposeKind::from(k)), k);
        }
        // The default options are exactly what `send` uses.
        assert_eq!(
            sc::ComposeOptions::from(ComposeOptions::default()),
            sc::ComposeOptions::default()
        );
        let core: sc::ComposeOptions = ComposeOptions {
            kind: ComposeKind::Forward,
            quote: true,
            forward_of: Some("12".into()),
            skip_signature: true,
        }
        .into();
        assert_eq!(
            core,
            sc::ComposeOptions {
                kind: sc::ComposeKind::Forward,
                quote: true,
                forward_of: Some("12".into()),
                skip_signature: true,
            }
        );
        let q: sc::ListQuery = ListQuery {
            folder_role: Some(FolderRole::Junk),
            limit: 5,
            ..ListQuery::default()
        }
        .into();
        assert_eq!(q.folder_role, Some(sc::FolderRole::Junk));
        assert_eq!(q.limit, 5);
        let mv: MoveReport = sc::MoveReport {
            id: 7,
            from_folder: "INBOX".into(),
            to_folder: "Trash".into(),
            method: Some(sc::MoveMethod::CopyExpunge),
        }
        .into();
        assert_eq!(mv.method, Some(MoveMethod::CopyExpunge));
        let pr: PublishReport = sc::PublishReport {
            fingerprint: "ABCD".into(),
            server_url: "https://keys.example".into(),
            status: [
                ("b@example.org".to_string(), "pending".to_string()),
                ("a@example.org".to_string(), "published".to_string()),
            ]
            .into_iter()
            .collect(),
            token_issued: true,
        }
        .into();
        assert_eq!(
            pr.status,
            vec![
                DirectoryAddressState {
                    address: "a@example.org".into(),
                    state: "published".into()
                },
                DirectoryAddressState {
                    address: "b@example.org".into(),
                    state: "pending".into()
                },
            ],
            "flattened map, sorted by address"
        );
        assert!(pr.token_issued);
    }

    #[test]
    fn filter_rules_and_spam_settings_round_trip() {
        let rule = |field: sc::FilterField, action: sc::FilterAction| sc::FilterRule {
            id: 3,
            order: 20,
            enabled: false,
            name: "n".into(),
            matcher: sc::FilterMatch {
                field,
                op: sc::FilterOp::Domain,
                value: "example.org".into(),
                case_insensitive: false,
            },
            action,
            stop: true,
        };
        let fields = [
            sc::FilterField::From,
            sc::FilterField::To,
            sc::FilterField::Cc,
            sc::FilterField::Subject,
            sc::FilterField::ListId,
            sc::FilterField::AnyHeader("x-mailer".into()),
            sc::FilterField::Body,
        ];
        let actions = [
            sc::FilterAction::MoveTo {
                folder: "Lists".into(),
            },
            sc::FilterAction::AddFlag {
                flag: "$Bulk".into(),
            },
            sc::FilterAction::MarkRead,
            sc::FilterAction::Star,
        ];
        for f in &fields {
            for a in &actions {
                let core = rule(f.clone(), a.clone());
                assert_eq!(sc::FilterRule::from(FilterRule::from(core.clone())), core);
            }
        }
        for op in [
            sc::FilterOp::Contains,
            sc::FilterOp::Equals,
            sc::FilterOp::Regex,
            sc::FilterOp::Domain,
        ] {
            assert_eq!(sc::FilterOp::from(FilterOp::from(op)), op);
        }
        // The flattened shape Dart sees.
        let b = FilterRule::from(rule(
            sc::FilterField::AnyHeader("x-mailer".into()),
            sc::FilterAction::AddFlag {
                flag: "$Bulk".into(),
            },
        ));
        assert_eq!(
            b.matcher.field,
            FilterField {
                kind: FilterFieldKind::Header,
                header: Some("x-mailer".into())
            }
        );
        assert_eq!(
            b.action,
            FilterAction {
                kind: FilterActionKind::AddFlag,
                folder: None,
                flag: Some("$Bulk".into())
            }
        );
        let s = sc::SpamSettings {
            unsure_threshold: 0.4,
            allowlist: vec!["friend.example".into()],
            blocklist: vec!["spam@bad.example".into()],
            ..sc::SpamSettings::default()
        };
        assert_eq!(sc::SpamSettings::from(SpamSettings::from(s.clone())), s);
        let o: FilterOutcome = sc::FilterOutcome {
            matched: vec![1, 2],
            move_to: Some("Lists".into()),
            errors: vec![(3, "bad regex".into())],
            ..sc::FilterOutcome::default()
        }
        .into();
        assert_eq!(
            o.errors,
            vec![FilterRuleError {
                rule_id: 3,
                error: "bad regex".into()
            }]
        );
        let t: FilterTestReport = sc::FilterTestReport {
            message_id: 9,
            outcome: sc::FilterOutcome::default(),
            rules: vec![(1, "subject contains \"x\" → star".into(), true)],
        }
        .into();
        assert_eq!(
            t.rules,
            vec![FilterRuleResult {
                id: 1,
                description: "subject contains \"x\" → star".into(),
                matched: true
            }]
        );
        let v: SpamVerdict = sc::Verdict::forced(sc::SpamLabel::Spam, "blocklist", "x").into();
        assert_eq!(v.label, SpamLabel::Spam);
        assert_eq!(v.reasons[0].code, "blocklist");
    }

    #[test]
    fn server_url_is_a_runtime_setting() {
        let dir = tempfile::tempdir().unwrap();
        let engine = bare_engine(&dir);
        assert_eq!(engine.server_url(), None);
        assert_eq!(engine.server_url_source(), "none");
        assert!(!engine.guest_links_available());
        assert!(!engine.key_directory_available());
        let bad = engine
            .set_server_url(Some("ftp://keys.sealbox.test".into()))
            .unwrap_err();
        assert!(bad.to_string().contains("http(s)://"), "{bad}");
        assert_eq!(
            engine
                .set_server_url(Some("https://keys.sealbox.test/".into()))
                .unwrap()
                .as_deref(),
            Some("https://keys.sealbox.test")
        );
        assert_eq!(engine.server_url_source(), "settings");
        assert_eq!(
            engine.directory_url().as_deref(),
            Some("https://keys.sealbox.test")
        );
        assert!(engine.guest_links_available() && engine.key_directory_available());
        // Persisted in the profile: the next engine on it sees the URL.
        drop(engine);
        let again = bare_engine(&dir);
        assert_eq!(
            again.server_url().as_deref(),
            Some("https://keys.sealbox.test")
        );
        assert_eq!(again.set_server_url(None).unwrap(), None);
        assert_eq!(again.server_url_source(), "none");
        assert_eq!(again.set_server_url(Some("  ".into())).unwrap(), None);
    }

    #[test]
    fn ui_wave_calls_need_an_account() {
        let dir = tempfile::tempdir().unwrap();
        let engine = bare_engine(&dir);
        let nobody = || "nobody@sealbox.test".to_string();
        let draft = Draft {
            to: vec!["x@sealbox.test".into()],
            cc: vec![],
            bcc: vec![],
            subject: "s".into(),
            text: "t".into(),
            html: None,
            attachments: vec![],
            in_reply_to: None,
            policy: SendPolicy::Auto,
            guest_mode: GuestMode::Passphrase,
            guest_recipient_hint: None,
        };
        let errors = [
            engine.folder_roles(nobody()).unwrap_err(),
            engine.folder_role_entries(nobody()).unwrap_err(),
            engine
                .compose_preview(nobody(), draft, ComposeOptions::default())
                .unwrap_err(),
            engine
                .signature_preview(nobody(), ComposeKind::New)
                .unwrap_err(),
            engine.spam_settings(nobody()).unwrap_err(),
            engine
                .spam_allow(nobody(), "a.example".into(), true)
                .unwrap_err(),
            engine.filter_rules(nobody()).unwrap_err(),
            engine.test_filter_rules(nobody(), 1).unwrap_err(),
        ];
        for e in errors {
            assert!(e.to_string().contains("account not found"), "{e}");
        }
        assert!(engine
            .spam_explain(42)
            .unwrap_err()
            .to_string()
            .contains("message not found"));
        // No account, no messages: an empty status, not an error.
        let st = engine.spam_status().unwrap();
        assert!(st.accounts.is_empty());
        assert_eq!(st.model_spam_messages, 0);
    }

    /// GreenMail server settings (plain IMAP 3143 / SMTP 3025, login = local part).
    fn greenmail() -> ServerConfig {
        let ep = |port| Endpoint {
            host: "127.0.0.1".into(),
            port,
            security: Security::Plain,
        };
        ServerConfig {
            imap: ep(3143),
            smtp: ep(3025),
            auth_hint: AuthHint {
                kind: AuthHintKind::Password,
                oauth_provider: None,
                help_url: None,
            },
            display_name: "GreenMail".into(),
            source: ConfigSource::Manual,
            username: UsernameForm::LocalPart,
        }
    }

    fn plain_draft(to: &str, subject: &str, text: &str, in_reply_to: Option<String>) -> Draft {
        Draft {
            to: vec![to.into()],
            cc: vec![],
            bcc: vec![],
            subject: subject.into(),
            text: text.into(),
            html: None,
            attachments: vec![],
            in_reply_to,
            policy: SendPolicy::AllowPlaintext,
            guest_mode: GuestMode::Passphrase,
            guest_recipient_hint: None,
        }
    }

    /// Sync `email` until a message with `subject` is listed under `role`; returns it.
    async fn wait_for(
        engine: &Engine,
        email: &str,
        role: FolderRole,
        subject: &str,
    ) -> MessageSummary {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if role == FolderRole::Inbox {
                engine.sync(email.to_string()).await.unwrap();
            } else {
                engine
                    .sync_folder_role(email.to_string(), role)
                    .await
                    .unwrap();
            }
            let rows = engine
                .list_messages(ListQuery {
                    account: Some(email.to_string()),
                    folder: None,
                    folder_role: Some(role),
                    limit: 200,
                })
                .unwrap();
            if let Some(m) = rows
                .into_iter()
                .find(|m| m.subject.as_deref() == Some(subject))
            {
                return m;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{subject:?} never showed up in {role:?}"
            );
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    /// The UI wave's whole slice through the bridge methods against GreenMail user u74:
    /// folder roles, threading fields, compose preview / signature / send_with (reply with
    /// quote), move by role + role sync + list by role, spam settings / allow / block /
    /// status / explain / learn, filter rules CRUD + dry run, and the publish refusal without
    /// a server. Run: `testing/mail_up.sh && CARGO_TARGET_DIR=../../target/app-rust cargo
    /// test -- --ignored` in `app/rust`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
    async fn ui_wave_slice_against_greenmail() {
        let dir = tempfile::tempdir().unwrap();
        let engine = bare_engine(&dir);
        let me = "u74@sealbox.test";
        let email = || me.to_string();
        engine
            .add_account(AddAccount {
                email: email(),
                display_name: Some("U74".into()),
                auth: AuthSpec {
                    kind: AuthKind::Password,
                    password: Some("u74pw".into()),
                    oauth_provider: None,
                    access_token: None,
                    refresh_token: None,
                    expires_at: None,
                },
                servers: Some(greenmail()),
                login: None,
            })
            .await
            .unwrap();

        // Folder roles: every role from the profile before the first sync.
        let entries = engine.folder_role_entries(email()).unwrap();
        assert_eq!(entries.len(), 8);
        assert!(entries.iter().all(|e| !e.learned), "{entries:?}");
        assert!(engine.folder_roles(email()).unwrap().is_empty());

        // Signature + compose preview.
        engine
            .set_signature(
                email(),
                SignatureSettings {
                    enabled: true,
                    text: "U74, via the bridge".into(),
                    html: None,
                    placement: SignaturePlacement::AboveQuote,
                    include_on: SignatureIncludeOn::All,
                },
            )
            .unwrap();
        let sig = engine
            .signature_preview(email(), ComposeKind::New)
            .unwrap()
            .expect("signature applies to new mail");
        assert!(sig.text.starts_with("-- \n") && sig.text.contains("U74, via the bridge"));
        let tag = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let subject = format!("bridge slice {tag}");
        let preview = engine
            .compose_preview(
                email(),
                plain_draft(me, &subject, "original body", None),
                ComposeOptions::default(),
            )
            .unwrap();
        assert_eq!(preview.kind, ComposeKind::New);
        assert!(preview.signature_applied);
        assert!(
            preview
                .text
                .contains("original body\n\n-- \nU74, via the bridge"),
            "{preview:?}"
        );
        let skipped = engine
            .compose_preview(
                email(),
                plain_draft(me, &subject, "original body", None),
                ComposeOptions {
                    skip_signature: true,
                    ..ComposeOptions::default()
                },
            )
            .unwrap();
        assert!(!skipped.signature_applied && !skipped.text.contains("-- \n"));

        // Send, receive, threading fields.
        let sent = engine
            .send_with(
                email(),
                plain_draft(me, &subject, "original body", None),
                ComposeOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(sent.mode, SendMode::Plaintext);
        let orig = wait_for(&engine, me, FolderRole::Inbox, &subject).await;
        assert_eq!(orig.message_id.as_deref(), Some(sent.message_id.as_str()));
        assert_eq!(
            orig.thread_id, sent.message_id,
            "a new conversation is keyed by its Message-ID"
        );
        assert!(orig.in_reply_to.is_empty() && orig.references.is_empty());
        let learned = engine.folder_roles(email()).unwrap();
        assert!(learned
            .iter()
            .any(|e| e.role == FolderRole::Inbox && e.learned));

        // Reply with the engine's quoting.
        let reply_subject = format!("Re: {subject}");
        let opts = ComposeOptions {
            kind: ComposeKind::Reply,
            quote: true,
            ..ComposeOptions::default()
        };
        let reply_draft =
            || plain_draft(me, &reply_subject, "my answer", Some(orig.id.to_string()));
        let preview = engine
            .compose_preview(email(), reply_draft(), opts.clone())
            .unwrap();
        assert_eq!(preview.kind, ComposeKind::Reply);
        assert!(preview.text.starts_with("my answer"), "{preview:?}");
        assert!(
            preview.text.contains("wrote:") && preview.text.contains("> original body"),
            "{preview:?}"
        );
        let rs = engine
            .send_with(email(), reply_draft(), opts)
            .await
            .unwrap();
        let reply = wait_for(&engine, me, FolderRole::Inbox, &reply_subject).await;
        assert_eq!(reply.message_id.as_deref(), Some(rs.message_id.as_str()));
        assert_eq!(reply.in_reply_to, vec![sent.message_id.clone()]);
        assert!(reply.references.contains(&sent.message_id));
        assert_eq!(
            reply.thread_id, orig.thread_id,
            "the reply joins the conversation"
        );

        // Move by role, role sync, list by role.
        let mv = engine
            .move_message(reply.id, FolderRole::Archive)
            .await
            .unwrap();
        assert_eq!(
            (mv.from_folder.as_str(), mv.to_folder.as_str()),
            ("INBOX", "Archive")
        );
        assert_eq!(mv.method, Some(MoveMethod::Move));
        let archived = wait_for(&engine, me, FolderRole::Archive, &reply_subject).await;
        assert_eq!(archived.folder, "Archive");
        assert_eq!(
            archived.thread_id, orig.thread_id,
            "still the same conversation"
        );
        let again = engine
            .move_message(archived.id, FolderRole::Archive)
            .await
            .unwrap();
        assert_eq!(again.method, None, "already there");

        // Spam settings, lists, status, explain, learn.
        let s = engine.spam_settings(email()).unwrap();
        assert!(s.enabled && s.move_to_folder == "Spam");
        let s = engine
            .set_spam_settings(
                email(),
                SpamSettings {
                    spam_threshold: 0.95,
                    ..s
                },
            )
            .unwrap();
        assert_eq!(s.spam_threshold, 0.95);
        assert!(engine
            .set_spam_settings(
                email(),
                SpamSettings {
                    unsure_threshold: 0.99,
                    ..s.clone()
                }
            )
            .unwrap_err()
            .to_string()
            .contains("invalid input"));
        let s = engine
            .spam_allow(email(), "@Friend.Example".into(), true)
            .unwrap();
        assert_eq!(s.allowlist, vec!["friend.example".to_string()]);
        let s = engine
            .spam_block(email(), "friend.example".into(), true)
            .unwrap();
        assert!(s.allowlist.is_empty() && s.blocklist == vec!["friend.example".to_string()]);
        let s = engine
            .spam_block(email(), "friend.example".into(), false)
            .unwrap();
        assert!(s.blocklist.is_empty());
        let st = engine.spam_status().unwrap();
        assert_eq!(st.accounts.len(), 1);
        assert_eq!(st.accounts[0].email, me);
        let ex = engine.spam_explain(orig.id).unwrap();
        assert_eq!(
            (ex.id, ex.account.as_str(), ex.folder.as_str()),
            (orig.id, me, "INBOX")
        );
        assert_eq!(ex.features.from_address.as_deref(), Some(me));
        assert_eq!(ex.subject.as_deref(), Some(subject.as_str()));
        let l = engine.spam_learn(orig.id, true).await.unwrap();
        assert_eq!(l.learned, SpamLabel::Spam);
        assert_eq!(l.verdict.label, SpamLabel::Spam);
        assert!(l.moved_to.is_some(), "{l:?}");
        let junk = engine
            .list_messages(ListQuery {
                account: Some(email()),
                folder: None,
                folder_role: Some(FolderRole::Junk),
                limit: 200,
            })
            .unwrap();
        assert!(
            junk.iter().any(|m| m.id == orig.id),
            "listed under the junk role: {junk:?}"
        );
        let l = engine.spam_learn(orig.id, false).await.unwrap();
        assert_eq!(
            (l.learned, l.previously_learned),
            (SpamLabel::Ham, Some(SpamLabel::Spam))
        );
        assert_eq!(l.moved_to.as_deref(), Some("INBOX"));

        // Filter rules: add, dry run, enable, update, replace, remove.
        let newsletter = FilterRule {
            id: 0,
            order: 0,
            enabled: true,
            name: "bridge".into(),
            matcher: FilterMatch {
                field: FilterField {
                    kind: FilterFieldKind::Subject,
                    header: None,
                },
                op: FilterOp::Contains,
                value: "bridge slice".into(),
                case_insensitive: true,
            },
            action: FilterAction {
                kind: FilterActionKind::MoveTo,
                folder: Some("Bridge".into()),
                flag: None,
            },
            stop: false,
        };
        let r1 = engine.add_filter_rule(email(), newsletter.clone()).unwrap();
        assert!(r1.id > 0 && r1.order > 0);
        let mut flag_rule = newsletter.clone();
        flag_rule.action = FilterAction {
            kind: FilterActionKind::AddFlag,
            folder: None,
            flag: Some("$Bridge".into()),
        };
        let r2 = engine.add_filter_rule(email(), flag_rule.clone()).unwrap();
        let t = engine.test_filter_rules(email(), orig.id).unwrap();
        assert_eq!(t.outcome.matched, vec![r1.id, r2.id]);
        assert_eq!(t.outcome.move_to.as_deref(), Some("Bridge"));
        assert_eq!(t.outcome.add_flags, vec!["$Bridge".to_string()]);
        assert!(t.rules.iter().all(|r| r.matched) && t.rules.len() == 2);
        let off = engine
            .set_filter_rule_enabled(email(), r2.id, false)
            .unwrap();
        assert!(!off.enabled);
        assert!(engine
            .test_filter_rules(email(), orig.id)
            .unwrap()
            .outcome
            .add_flags
            .is_empty());
        let mut bad = r1.clone();
        bad.matcher.field = FilterField {
            kind: FilterFieldKind::Header,
            header: None,
        };
        assert!(
            engine.update_filter_rule(email(), bad).is_err(),
            "a header field needs a name"
        );
        let mut bad_flag = flag_rule.clone();
        bad_flag.action.flag = Some("two words".into());
        assert!(engine.add_filter_rule(email(), bad_flag).is_err());
        let mut renamed = r1.clone();
        renamed.name = "renamed".into();
        assert_eq!(
            engine.update_filter_rule(email(), renamed).unwrap().name,
            "renamed"
        );
        let replaced = engine
            .set_filter_rules(email(), vec![flag_rule, newsletter])
            .unwrap();
        assert_eq!(
            replaced.iter().map(|r| r.order).collect::<Vec<_>>(),
            vec![10, 20]
        );
        assert_eq!(engine.filter_rules(email()).unwrap(), replaced);
        assert!(engine.remove_filter_rule(email(), replaced[0].id).unwrap());
        assert!(!engine.remove_filter_rule(email(), replaced[0].id).unwrap());
        assert_eq!(engine.filter_rules(email()).unwrap().len(), 1);

        // Publishing needs a server; the refusal says how to configure one.
        let e = engine.publish_key(email()).await.unwrap_err();
        assert!(e.to_string().contains("server set-url"), "{e}");
        assert!(engine.directory_status(email()).await.is_err());
    }

    #[test]
    fn open_lists_no_accounts_and_round_trips_config_types() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(dir.path().display().to_string()).unwrap();
        assert!(engine.list_accounts().unwrap().is_empty());
        assert!(engine.contacts().unwrap().is_empty());
        assert_eq!(engine.profile_dir(), dir.path().display().to_string());
        assert!(dir.path().join(sc::DB_FILE).exists());

        let gmail = detect_servers_offline("someone@gmail.com".into()).expect("gmail is built in");
        assert_eq!(gmail.imap.host, "imap.gmail.com");
        assert_eq!(gmail.imap.security, Security::Tls);
        assert_eq!(gmail.auth_hint.kind, AuthHintKind::OAuth2);
        assert_eq!(gmail.auth_hint.oauth_provider, Some(OAuthProvider::Google));
        let back: sc::ServerConfig = gmail.clone().into();
        let again: ServerConfig = back.into();
        assert_eq!(again, gmail);
        assert!(detect_servers_offline("x@no-such-domain.invalid".into()).is_none());
    }

    #[test]
    fn manual_config_round_trips() {
        let cfg = ServerConfig {
            imap: Endpoint {
                host: "127.0.0.1".into(),
                port: 3143,
                security: Security::Plain,
            },
            smtp: Endpoint {
                host: "127.0.0.1".into(),
                port: 3025,
                security: Security::Plain,
            },
            auth_hint: AuthHint {
                kind: AuthHintKind::Password,
                oauth_provider: None,
                help_url: None,
            },
            display_name: "GreenMail".into(),
            source: ConfigSource::Manual,
            username: UsernameForm::LocalPart,
        };
        let core: sc::ServerConfig = cfg.into();
        assert_eq!(core.source, sc::ConfigSource::Manual);
        assert_eq!(core.imap.security, sc::Security::Plain);
        assert_eq!(core.login_name("u01@sealbox.test"), "u01");
    }

    #[test]
    fn settings_dtos_round_trip() {
        let sig = SignatureSettings {
            enabled: true,
            text: "-- \nAda".into(),
            html: Some("<b>Ada</b><script>x</script>".into()),
            placement: SignaturePlacement::BelowQuote,
            include_on: SignatureIncludeOn::NewAndReplies,
        };
        let back: SignatureSettings = sc::SignatureSettings::from(sig.clone()).into();
        assert_eq!(back, sig);
        let ar = AutoReplySettings {
            enabled: true,
            start: Some(1_800_000_000),
            end: None,
            subject_template: "Away: {subject}".into(),
            body: "Back next week.".into(),
            reply_once_per_sender_days: 7,
            encrypt_when_possible: true,
            only_to_known_contacts: false,
        };
        let core: sc::AutoReplySettings = ar.clone().into();
        assert_eq!(core.start.map(|t| t.timestamp()), Some(1_800_000_000));
        let back: AutoReplySettings = core.into();
        assert_eq!(back, ar);
    }

    #[test]
    fn settings_need_an_account() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(dir.path().display().to_string()).unwrap();
        assert!(engine.get_signature("nobody@sealbox.test".into()).is_err());
        assert!(engine
            .auto_reply_log("nobody@sealbox.test".into(), 10)
            .is_err());
    }

    #[test]
    fn passphrase_has_five_groups() {
        let p = generate_guest_passphrase();
        assert_eq!(p.split('-').count(), 5);
        assert_ne!(p, generate_guest_passphrase());
    }

    #[test]
    fn errors_keep_the_engine_message() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(dir.path().display().to_string()).unwrap();
        let e = engine
            .my_fingerprint("nobody@sealbox.test".into())
            .unwrap_err();
        assert!(e.to_string().contains("account not found"), "{e}");
    }

    #[test]
    fn identity_and_recovery_without_network() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(dir.path().display().to_string()).unwrap();
        let fpr = "0123456789ABCDEF0123456789ABCDEF01234567";
        assert_eq!(
            Engine::parse_fingerprint_qr(format!("openpgp4fpr:{}", fpr.to_lowercase())).unwrap(),
            fpr
        );
        assert!(Engine::parse_fingerprint_qr("hello".into()).is_err());
        assert!(engine
            .fingerprint_qr_payload("nobody@sealbox.test".into())
            .is_err());
        assert!(engine
            .verify_contact("x@sealbox.test".into(), fpr.into())
            .is_err());
        let bad = Engine::recovery_phrase_validate("one two".into()).unwrap_err();
        assert!(bad.to_string().contains("12 words"), "{bad}");
        let ok = Engine::recovery_phrase_validate(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
        )
        .unwrap();
        assert!(ok.checksum_ok);
        assert_eq!(ok.words.len(), 12);
        assert!(engine
            .recovery_phrase_create("nobody@sealbox.test".into())
            .is_err());
        assert!(engine.backup_status("nobody@sealbox.test".into()).is_err());
    }

    fn draft_input(account: &str) -> DraftInput {
        DraftInput {
            id: None,
            account: account.into(),
            kind: ComposeKind::New,
            in_reply_to: None,
            forward_of: None,
            quote: false,
            to: vec![],
            cc: vec![],
            bcc: vec![],
            subject: String::new(),
            body_text: String::new(),
            attachments: vec![],
            policy: SendPolicy::Auto,
            guest_mode: GuestMode::Passphrase,
            guest_recipient_hint: None,
            no_signature: false,
        }
    }

    #[test]
    fn search_and_drafts_without_network() {
        let dir = tempfile::tempdir().unwrap();
        let engine = bare_engine(&dir);
        // An empty profile: nothing indexed, nothing found, no drafts.
        assert_eq!(engine.rebuild_search_index().unwrap().documents, 0);
        let any = SearchQuery {
            text: "anything".into(),
            ..SearchQuery::default()
        };
        assert!(engine.search(any).unwrap().is_empty());
        let unknown = engine
            .search(SearchQuery {
                account: Some("nobody@sealbox.test".into()),
                text: "anything".into(),
                ..SearchQuery::default()
            })
            .unwrap_err();
        assert!(
            unknown.to_string().contains("account not found"),
            "{unknown}"
        );
        assert!(engine.list_drafts(None).unwrap().is_empty());
        let missing = engine.get_draft(1).unwrap_err();
        assert!(missing.to_string().contains("no draft 1"), "{missing}");
        assert!(!engine.delete_draft(1).unwrap());
        let e = engine
            .save_draft(draft_input("nobody@sealbox.test"))
            .unwrap_err();
        assert!(e.to_string().contains("account not found"), "{e}");
        assert!(engine
            .list_drafts(Some("nobody@sealbox.test".into()))
            .unwrap_err()
            .to_string()
            .contains("account not found"));
        // Stored draft blobs: unknown ids and accounts fail cleanly.
        let nobody = || "nobody@sealbox.test".to_string();
        for e in [
            engine
                .put_draft_blob(nobody(), "a.txt".into(), "text/plain".into(), vec![1])
                .unwrap_err(),
            engine.list_draft_blobs(nobody()).unwrap_err(),
            engine.sweep_draft_blobs(nobody()).unwrap_err(),
        ] {
            assert!(e.to_string().contains("account not found"), "{e}");
        }
        let missing = engine.get_draft_blob(1).unwrap_err();
        assert!(missing.to_string().contains("no draft blob 1"), "{missing}");
        // Server drafts: unknown drafts and accounts fail cleanly, DTOs mirror the engine's.
        assert_eq!(engine.draft_server_info(1).unwrap(), None);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let e = rt.block_on(engine.push_draft(1)).unwrap_err();
        assert!(e.to_string().contains("no draft 1"), "{e}");
        let e = rt
            .block_on(engine.sync_drafts("nobody@sealbox.test".into()))
            .unwrap_err();
        assert!(e.to_string().contains("account not found"), "{e}");
        assert_eq!(
            DraftSyncReport::from(sc::DraftSyncReport {
                account: "a@sealbox.test".into(),
                folder: "Drafts".into(),
                uploaded: 1,
                imported: 2,
                updated: 3,
                removed_locally: 4,
                removed_on_server: 5,
                unreadable: 6,
            }),
            DraftSyncReport {
                account: "a@sealbox.test".into(),
                folder: "Drafts".into(),
                uploaded: 1,
                imported: 2,
                updated: 3,
                removed_locally: 4,
                removed_on_server: 5,
                unreadable: 6,
            }
        );
        let info = DraftServerInfo::from(sc::DraftServerInfo {
            uuid: "u".into(),
            origin: "server".into(),
            on_server: true,
            pending: false,
            remote_files: 2,
        });
        assert_eq!((info.origin, info.remote_files), (DraftOrigin::Server, 2));
        assert_eq!(
            DraftOrigin::from(sc::DraftOrigin::Local),
            DraftOrigin::Local
        );
        assert!(!engine.delete_draft_blob(1).unwrap());
        let blob = sc::DraftBlobInfo {
            id: 3,
            account: "a@sealbox.test".into(),
            filename: "a.txt".into(),
            content_type: "text/plain".into(),
            size: 5,
            created_at: 1_700_000_000,
        };
        assert_eq!(
            DraftBlobInfo::from(blob),
            DraftBlobInfo {
                id: 3,
                account: "a@sealbox.test".into(),
                filename: "a.txt".into(),
                content_type: "text/plain".into(),
                size: 5,
                created_at: 1_700_000_000,
            }
        );
        let back = DraftAttachment::from(sc::DraftAttachment {
            blob_id: Some(3),
            name: "a.txt".into(),
            ..sc::DraftAttachment::default()
        });
        assert_eq!((back.blob_id, back.path.as_str()), (Some(3), ""));

        // The DTOs reach the engine unchanged.
        let q: sc::SearchQuery = SearchQuery {
            account: Some("a@sealbox.test".into()),
            text: "zebra".into(),
            folder: Some("*".into()),
            limit: 7,
        }
        .into();
        assert_eq!(
            q,
            sc::SearchQuery {
                account: Some("a@sealbox.test".into()),
                text: "zebra".into(),
                folder: Some("*".into()),
                limit: 7,
            }
        );
        for p in [
            sc::SendPolicy::Auto,
            sc::SendPolicy::RequireEncryption,
            sc::SendPolicy::GuestLink,
            sc::SendPolicy::AllowPlaintext,
        ] {
            assert_eq!(sc::SendPolicy::from(SendPolicy::from(p)), p);
        }
        let input: sc::DraftInput = DraftInput {
            id: Some(4),
            kind: ComposeKind::Reply,
            in_reply_to: Some("<m@x>".into()),
            quote: true,
            to: vec!["b@sealbox.test".into()],
            cc: vec!["c@sealbox.test".into()],
            subject: "s".into(),
            body_text: "t".into(),
            attachments: vec![
                DraftAttachment {
                    path: "/tmp/f.pdf".into(),
                    blob_id: None,
                    name: "f.pdf".into(),
                    content_type: "application/pdf".into(),
                },
                DraftAttachment {
                    blob_id: Some(9),
                    ..DraftAttachment::default()
                },
            ],
            policy: SendPolicy::GuestLink,
            guest_mode: GuestMode::EmailCode,
            no_signature: true,
            ..draft_input("a@sealbox.test")
        }
        .into();
        assert_eq!(
            input,
            sc::DraftInput {
                id: Some(4),
                account: "a@sealbox.test".into(),
                kind: sc::ComposeKind::Reply,
                in_reply_to: Some("<m@x>".into()),
                forward_of: None,
                quote: true,
                to: vec!["b@sealbox.test".into()],
                cc: vec!["c@sealbox.test".into()],
                bcc: vec![],
                subject: "s".into(),
                body_text: "t".into(),
                attachments: vec![
                    sc::DraftAttachment {
                        path: "/tmp/f.pdf".into(),
                        blob_id: None,
                        name: "f.pdf".into(),
                        content_type: "application/pdf".into(),
                    },
                    sc::DraftAttachment {
                        blob_id: Some(9),
                        ..sc::DraftAttachment::default()
                    },
                ],
                policy: sc::SendPolicy::GuestLink,
                guest_mode: sc::GuestMode::EmailCode,
                guest_recipient_hint: None,
                no_signature: true,
            }
        );
    }

    /// Search and saved drafts through the bridge against GreenMail user u68: a mail to self
    /// found by a body word (INBOX only, then every folder with the Sent copy), its snippet
    /// marking the match; a draft with an attachment saved, updated under the same id, listed,
    /// sent with `send_draft` (and gone afterwards), and the sent mail found by search. Run:
    /// `testing/mail_up.sh && CARGO_TARGET_DIR=../../target/app-rust cargo test -- --ignored
    /// search_and_drafts` in `app/rust`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
    async fn search_and_drafts_against_greenmail() {
        let dir = tempfile::tempdir().unwrap();
        let engine = bare_engine(&dir);
        let me = "u68@sealbox.test";
        let email = || me.to_string();
        engine
            .add_account(AddAccount {
                email: email(),
                display_name: Some("U68".into()),
                auth: AuthSpec {
                    kind: AuthKind::Password,
                    password: Some("u68pw".into()),
                    oauth_provider: None,
                    access_token: None,
                    refresh_token: None,
                    expires_at: None,
                },
                servers: Some(greenmail()),
                login: None,
            })
            .await
            .unwrap();
        let tag = format!(
            "{}{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let word = format!("zebracorn{tag}");
        let subject = format!("search slice {tag}");
        engine
            .send(
                email(),
                plain_draft(me, &subject, &format!("the {word} grazes at dawn"), None),
            )
            .await
            .unwrap();
        let received = wait_for(&engine, me, FolderRole::Inbox, &subject).await;

        // Found by a body word; the snippet marks the match.
        let inbox_only = engine
            .search(SearchQuery {
                account: Some(email()),
                text: word.clone(),
                folder: Some("INBOX".into()),
                limit: 0,
            })
            .unwrap();
        assert_eq!(inbox_only.len(), 1, "{inbox_only:?}");
        let hit = &inbox_only[0];
        assert_eq!(hit.summary.id, received.id);
        assert_eq!(hit.summary.subject.as_deref(), Some(subject.as_str()));
        assert!(
            hit.snippet.contains(&format!("\u{E000}{word}\u{E001}")),
            "{:?}",
            hit.snippet
        );
        assert!(hit.rank > 0.0, "{}", hit.rank);
        // Every folder: the INBOX copy plus, once synced, the Sent copy.
        let everywhere = engine
            .search(SearchQuery {
                text: word.clone(),
                ..SearchQuery::default()
            })
            .unwrap();
        assert!(
            everywhere.iter().any(|h| h.summary.id == received.id),
            "{everywhere:?}"
        );
        assert!(everywhere
            .iter()
            .all(|h| h.summary.folder == "INBOX" || h.summary.folder.contains("Sent")));
        let stats = engine.rebuild_search_index().unwrap();
        assert!(stats.documents >= 1 && stats.memory_bytes > 0, "{stats:?}");

        // A draft with an attachment: saved, updated under the same id, listed, sent.
        let file = dir.path().join("notes.txt");
        std::fs::write(&file, b"attached notes").unwrap();
        let first = engine
            .save_draft(DraftInput {
                to: vec![email()],
                subject: format!("draft {tag}"),
                body_text: "half written".into(),
                attachments: vec![DraftAttachment {
                    path: file.display().to_string(),
                    blob_id: None,
                    name: String::new(),
                    content_type: "text/plain".into(),
                }],
                ..draft_input(me)
            })
            .unwrap();
        assert!(first.id > 0);
        assert_eq!(first.attachments.len(), 1);
        assert_eq!(first.attachments[0].name, "notes.txt");
        let draft_subject = format!("draft {tag} v2");
        let second = engine
            .save_draft(DraftInput {
                id: Some(first.id),
                to: vec![email()],
                cc: vec![],
                subject: draft_subject.clone(),
                body_text: format!("finished {word}"),
                attachments: first.attachments.clone(),
                ..draft_input(me)
            })
            .unwrap();
        assert_eq!(second.id, first.id, "saving with the id updates that draft");
        assert!(second.updated_at >= first.updated_at);
        let listed = engine.list_drafts(Some(email())).unwrap();
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert_eq!(listed[0].subject, draft_subject);
        assert_eq!(engine.get_draft(first.id).unwrap(), second);
        let report = engine.send_draft(first.id).await.unwrap();
        assert_eq!(report.mode, SendMode::Encrypted, "to self: our own key");
        assert!(
            engine.get_draft(first.id).is_err(),
            "a sent draft is deleted"
        );
        assert!(engine.list_drafts(None).unwrap().is_empty());
        wait_for(&engine, me, FolderRole::Inbox, &draft_subject).await;
        let sent_draft = engine
            .search(SearchQuery {
                text: format!("finished {word}"),
                folder: Some("INBOX".into()),
                ..SearchQuery::default()
            })
            .unwrap();
        assert_eq!(sent_draft.len(), 1, "{sent_draft:?}");
        assert_eq!(
            sent_draft[0].summary.subject.as_deref(),
            Some(draft_subject.as_str())
        );
        assert_eq!(sent_draft[0].summary.attachment_count, 1);

        // Deleting: true once, then false.
        let other = engine
            .save_draft(DraftInput {
                subject: "throw away".into(),
                ..draft_input(me)
            })
            .unwrap();
        assert!(other.id > first.id, "ids are never reused");
        assert!(engine.delete_draft(other.id).unwrap());
        assert!(!engine.delete_draft(other.id).unwrap());
    }

    #[test]
    fn sync_progress_events_mirror_the_engine() {
        for (core, dto) in [
            (sc::SyncPhase::Initial, SyncPhase::Initial),
            (sc::SyncPhase::Incremental, SyncPhase::Incremental),
            (sc::SyncPhase::Backfill, SyncPhase::Backfill),
        ] {
            assert_eq!(SyncPhase::from(core), dto);
        }
        let e = SyncEvent::progress(sc::SyncProgress {
            account: "a@sealbox.test".into(),
            folder: "INBOX".into(),
            phase: sc::SyncPhase::Backfill,
            fetched: 200,
            stored: 199,
            planned: 1000,
            total_known: 10_000,
            local: 700,
            more_to_backfill: true,
        });
        assert_eq!(
            e,
            SyncEvent {
                kind: SyncEventKind::Progress,
                progress: Some(SyncProgress {
                    account: "a@sealbox.test".into(),
                    folder: "INBOX".into(),
                    phase: SyncPhase::Backfill,
                    fetched: 200,
                    stored: 199,
                    planned: 1000,
                    total_known: 10_000,
                    local: 700,
                    more_to_backfill: true,
                }),
                report: None,
            }
        );
        let e = SyncEvent::done(sc::SyncReport {
            account: "a@sealbox.test".into(),
            new: 3,
            decrypted: 1,
            failed: 0,
            folders: vec![
                sc::FolderSync {
                    name: "INBOX".into(),
                    new: 3,
                    uidvalidity_reset: false,
                    more_to_backfill: true,
                    older_pending: Some(9_500),
                    removed: 2,
                    flags_changed: 1,
                },
                sc::FolderSync {
                    name: "Sent".into(),
                    new: 0,
                    uidvalidity_reset: true,
                    more_to_backfill: false,
                    older_pending: None,
                    removed: 0,
                    flags_changed: 0,
                },
            ],
            new_ids: vec![4, 5, 6],
        });
        assert_eq!((e.kind, e.progress.is_none()), (SyncEventKind::Done, true));
        let r = e.report.expect("Done carries the report");
        assert_eq!((r.new, r.decrypted, r.failed), (3, 1, 0));
        assert_eq!(r.new_ids, vec![4, 5, 6]);
        assert_eq!(
            r.folders,
            vec![
                FolderSync {
                    name: "INBOX".into(),
                    new: 3,
                    uidvalidity_reset: false,
                    more_to_backfill: true,
                    older_pending: Some(9_500),
                    removed: 2,
                    flags_changed: 1,
                },
                FolderSync {
                    name: "Sent".into(),
                    new: 0,
                    uidvalidity_reset: true,
                    more_to_backfill: false,
                    older_pending: None,
                    removed: 0,
                    flags_changed: 0,
                },
            ]
        );
    }

    #[test]
    fn message_summary_carries_the_stored_snippet() {
        let summary = |snippet: Option<&str>| sc::MessageSummary {
            id: 9,
            account: "a@sealbox.test".into(),
            folder: "INBOX".into(),
            uid: 4,
            message_id: Some("m@x".into()),
            from: sc::Address::default(),
            to: vec![],
            cc: vec![],
            subject: Some("s".into()),
            date: Some(1_700_000_000),
            received_at: 1_700_000_001,
            flags: vec![],
            seen: false,
            was_encrypted: false,
            decrypted: false,
            was_signed: false,
            signature: sc::SignatureSummary::default(),
            protected_subject: false,
            attachment_count: 0,
            raw_size: 10,
            decrypt_error: None,
            in_reply_to: vec![],
            references: vec![],
            thread_id: "m@x".into(),
            snippet: snippet.map(str::to_string),
        };
        let m = MessageSummary::from(summary(Some("Hello Bob, the numbers")));
        assert_eq!(m.snippet.as_deref(), Some("Hello Bob, the numbers"));
        assert_eq!(MessageSummary::from(summary(None)).snippet, None);
    }

    /// A watcher that cannot start ends its stream with the error instead of losing it
    /// (Dart never awaits a stream function's own result). No network: no such account.
    #[tokio::test]
    async fn a_failed_watch_ends_with_its_error() {
        let dir = tempfile::tempdir().unwrap();
        let engine = bare_engine(&dir);
        let mut items = Vec::new();
        engine
            .watch_items("nobody@sealbox.test", Duration::from_secs(5), |i| {
                items.push(i);
                true
            })
            .await;
        assert_eq!(items.len(), 1, "{items:?}");
        let message = items.remove(0).expect_err("the failure, not an event");
        assert!(message.contains("account not found"), "{message}");
    }

    /// A sync or backfill that fails sends exactly one item, the error (which `to_sink` makes
    /// the Dart stream's error), and no `Done`. No network: the account does not exist.
    #[tokio::test]
    async fn a_failed_sync_or_backfill_ends_with_its_error_only() {
        let dir = tempfile::tempdir().unwrap();
        let engine = bare_engine(&dir);
        let mut items = Vec::new();
        engine
            .sync_items("nobody@sealbox.test", |i| items.push(i))
            .await;
        engine
            .backfill_items("nobody@sealbox.test", Some(10), |i| items.push(i))
            .await;
        assert_eq!(items.len(), 2, "{items:?}");
        for item in items {
            let message = item.expect_err("a failure, not an event");
            assert!(message.contains("account not found"), "{message}");
        }
    }

    /// Progress through the stream functions' cores against GreenMail user u38 (daily
    /// scratch, emptied first), with a 3-message window, 2-message batches and backfill
    /// steps of 2: the first sync stores the newest 3 newest-first and says more is left; a
    /// bounded backfill stores 2 more; an unbounded one the rest, and then nothing is left.
    /// Every step ends with exactly one `Done`, after its `Progress` events. Run:
    /// `testing/mail_up.sh && cargo test -- --ignored sync_progress_streams` in `app/rust`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
    async fn sync_progress_streams_against_greenmail() {
        let me = "u38@sealbox.test";
        let purge = std::process::Command::new("python3")
            .args(["-I", "../../testing/gm_expunge.py", "u38", "u38pw", "INBOX"])
            .output()
            .expect("python3 runs testing/gm_expunge.py");
        assert!(purge.status.success(), "{purge:?}");
        let account = || AddAccount {
            email: me.into(),
            display_name: Some("U38".into()),
            auth: AuthSpec {
                kind: AuthKind::Password,
                password: Some("u38pw".into()),
                oauth_provider: None,
                access_token: None,
                refresh_token: None,
                expires_at: None,
            },
            servers: Some(greenmail()),
            login: None,
        };
        let tag = format!(
            "{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_micros()
        );
        // A default-window profile sends the seven messages and waits until all have arrived.
        let seed_dir = tempfile::tempdir().unwrap();
        let seeder = bare_engine(&seed_dir);
        seeder.add_account(account()).await.unwrap();
        for i in 1..=7 {
            let subject = format!("progress {tag} #{i}");
            seeder
                .send_with(
                    me.into(),
                    plain_draft(me, &subject, "hi", None),
                    ComposeOptions::default(),
                )
                .await
                .unwrap();
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            seeder.sync(me.into()).await.unwrap();
            let rows = seeder
                .list_messages(ListQuery {
                    account: Some(me.into()),
                    limit: 50,
                    ..ListQuery::default()
                })
                .unwrap();
            if rows.len() >= 7 {
                assert_eq!(rows.len(), 7, "INBOX was emptied first: {rows:?}");
                assert!(rows.iter().all(|m| m.snippet.is_some()), "{rows:?}");
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "only {} of 7 arrived",
                rows.len()
            );
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        // The profile under test: tiny window, batches and backfill steps.
        let dir = tempfile::tempdir().unwrap();
        let cfg = sc::EngineConfig {
            profile_key: sc::ProfileKeySource::Raw(vec![0x5c; 32]),
            sync_window: 3,
            backfill_per_sync: 2,
            fetch_batch: 2,
            ..sc::EngineConfig::default()
        };
        let engine = Engine {
            inner: Arc::new(sc::Engine::open_with(dir.path(), cfg).unwrap()),
        };
        engine.add_account(account()).await.unwrap();
        let inbox = |items: &[SyncItem]| -> Vec<SyncProgress> {
            items
                .iter()
                .filter_map(|i| i.as_ref().ok()?.progress.clone())
                .filter(|p| p.folder == "INBOX")
                .collect()
        };
        let done = |items: &[SyncItem]| -> SyncReport {
            let (last, rest) = items.split_last().expect("at least the Done event");
            assert!(
                rest.iter()
                    .all(|i| matches!(i, Ok(e) if e.kind == SyncEventKind::Progress)),
                "{items:?}"
            );
            let last = last.as_ref().expect("no error");
            assert_eq!(last.kind, SyncEventKind::Done);
            last.report.clone().expect("Done carries the report")
        };
        let inbox_folder = |r: &SyncReport| -> FolderSync {
            r.folders
                .iter()
                .find(|f| f.name == "INBOX")
                .cloned()
                .expect("INBOX in the report")
        };

        let mut first = Vec::new();
        engine.sync_items(me, |i| first.push(i)).await;
        let p = inbox(&first);
        assert_eq!(p.len(), 2, "3 messages in batches of 2: {p:?}");
        assert!(p
            .iter()
            .all(|p| p.phase == SyncPhase::Initial && p.planned == 3));
        assert_eq!((p[0].fetched, p[0].local), (2, 2));
        assert_eq!((p[1].fetched, p[1].stored, p[1].local), (3, 3, 3));
        assert!(p.iter().all(|p| p.total_known == 7 && p.more_to_backfill));
        let r = done(&first);
        assert_eq!(r.account, me);
        let f = inbox_folder(&r);
        assert_eq!(
            (f.new, f.more_to_backfill, f.older_pending),
            (3, true, Some(4))
        );
        let newest: Vec<String> = engine
            .list_messages(ListQuery {
                account: Some(me.into()),
                limit: 50,
                ..ListQuery::default()
            })
            .unwrap()
            .into_iter()
            .filter_map(|m| m.subject)
            .collect();
        assert_eq!(
            newest,
            (5..=7)
                .rev()
                .map(|i| format!("progress {tag} #{i}"))
                .collect::<Vec<_>>(),
            "the newest three, newest first"
        );

        let mut step = Vec::new();
        engine.backfill_items(me, Some(2), |i| step.push(i)).await;
        let p = inbox(&step);
        assert_eq!(p.len(), 1, "{p:?}");
        assert_eq!(
            (p[0].phase, p[0].fetched, p[0].planned, p[0].local),
            (SyncPhase::Backfill, 2, 2, 5)
        );
        assert!(p[0].more_to_backfill);
        let f = inbox_folder(&done(&step));
        assert_eq!(
            (f.new, f.more_to_backfill, f.older_pending),
            (2, true, Some(2))
        );

        let mut rest = Vec::new();
        engine.backfill_items(me, None, |i| rest.push(i)).await;
        let p = inbox(&rest);
        assert_eq!(
            p.last().map(|p| (p.local, p.more_to_backfill)),
            Some((7, false)),
            "{p:?}"
        );
        let f = inbox_folder(&done(&rest));
        assert_eq!(
            (f.new, f.more_to_backfill, f.older_pending),
            (2, false, Some(0))
        );

        // Nothing left: only `Done`, at once.
        let mut nothing = Vec::new();
        engine.backfill_items(me, None, |i| nothing.push(i)).await;
        assert_eq!(nothing.len(), 1, "{nothing:?}");
        assert!(done(&nothing).folders.is_empty());
    }
}
