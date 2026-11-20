//! Plain serde data structures exchanged with the UI (CLI today, Flutter bridge later).
//! Nothing here holds a connection or a key object; everything is `Clone + Serialize`.

use std::fmt;
use std::str::FromStr;

pub use sealbox_crypto::{PreferEncrypt, Recommendation, SignatureStatus};
pub use sealbox_mail::autodiscover::{
    AuthHint, ConfigSource, Endpoint, OAuthProvider, ServerConfig, UsernameForm,
};
pub use sealbox_mail::imap::{FolderRole, MoveMethod};
pub use sealbox_mail::Security;

/// Credentials for a new account. Never logged; `Debug` redacts the secret.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthSpec {
    /// Mailbox password or app password.
    Password { password: String },
    /// OAuth2 bearer token (XOAUTH2 on the wire). Refreshing is the caller's job for now.
    OAuth {
        #[serde(default)]
        provider: Option<String>,
        access_token: String,
        #[serde(default)]
        refresh_token: Option<String>,
        /// Unix seconds.
        #[serde(default)]
        expires_at: Option<i64>,
    },
}

impl fmt::Debug for AuthSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthSpec::Password { .. } => f.write_str("AuthSpec::Password(<redacted>)"),
            AuthSpec::OAuth { provider, .. } => f
                .debug_struct("AuthSpec::OAuth")
                .field("provider", provider)
                .field("access_token", &"<redacted>")
                .finish(),
        }
    }
}

/// Which kind of credential an account stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    Password,
    OAuth,
}

/// Input of [`crate::Engine::add_account`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AddAccount {
    pub email: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub auth: AuthSpec,
    /// Manual server override; `None` = autodiscover (built-in table, then network).
    #[serde(default)]
    pub servers: Option<ServerConfig>,
    /// Login name override (defaults to what the server configuration says, usually the
    /// full address; on an authentication failure the bare local part is tried as well).
    #[serde(default)]
    pub login: Option<String>,
}

/// A stored account (no secrets).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    pub created_at: i64,
}

/// What to do when not every recipient has a key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendPolicy {
    /// Encrypt + sign when every recipient has a usable key; otherwise refuse (never downgrade).
    #[default]
    Auto,
    /// Same as `Auto` today; reserved for "and never fall back to a guest link" once `Auto`
    /// learns to offer one.
    RequireEncryption,
    /// Encrypt when everyone has a key; otherwise send a passphrase-protected guest link.
    GuestLink,
    /// Send plaintext (still carrying our Autocrypt header).
    AllowPlaintext,
}

impl FromStr for SendPolicy {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(SendPolicy::Auto),
            "require" | "require_encryption" | "require-encryption" | "encrypt" => {
                Ok(SendPolicy::RequireEncryption)
            }
            "guest" | "guest_link" | "guest-link" => Ok(SendPolicy::GuestLink),
            "plaintext" | "plain" | "allow_plaintext" | "allow-plaintext" => {
                Ok(SendPolicy::AllowPlaintext)
            }
            other => Err(format!(
                "unknown policy `{other}` (expected auto|require|guest|plaintext)"
            )),
        }
    }
}

impl fmt::Display for SendPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SendPolicy::Auto => "auto",
            SendPolicy::RequireEncryption => "require",
            SendPolicy::GuestLink => "guest",
            SendPolicy::AllowPlaintext => "plaintext",
        })
    }
}

/// An attachment to send.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttachmentData {
    pub filename: String,
    /// e.g. `application/pdf`; empty = `application/octet-stream`.
    #[serde(default)]
    pub content_type: String,
    pub data: Vec<u8>,
}

impl fmt::Debug for AttachmentData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentData")
            .field("filename", &self.filename)
            .field("content_type", &self.content_type)
            .field("len", &self.data.len())
            .finish()
    }
}

/// How a guest link protects its message (G29). See `docs/GUEST_LINKS.md`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestMode {
    /// The link carries no secret; the sender shares the passphrase by another channel.
    #[default]
    Passphrase,
    /// The secret is in the link's `#fragment`: anyone with the link can read the message
    /// (protects against the server and the network only).
    OneClick,
    /// Secret in the fragment, and the server releases the ciphertext only after a one-time
    /// code mailed to the recipient address is entered (protects against a leaked link, not
    /// against whoever can read the recipient's mailbox).
    EmailCode,
}

/// An outgoing message.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Draft {
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    pub subject: String,
    pub text: String,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub attachments: Vec<AttachmentData>,
    /// Either a local message id (digits, from `list`) or a raw `Message-ID`.
    #[serde(default)]
    pub in_reply_to: Option<String>,
    #[serde(default)]
    pub policy: SendPolicy,
    /// Guest-link protection when the message goes out as a guest link.
    #[serde(default)]
    pub guest_mode: GuestMode,
    /// The address that receives the one-time code in [`GuestMode::EmailCode`]; `None` = the
    /// only recipient of the message.
    #[serde(default)]
    pub guest_recipient_hint: Option<String>,
}

/// Where a recipient's key came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeySource {
    /// The peer's own `Autocrypt:` header.
    Autocrypt,
    /// An `Autocrypt-Gossip:` header from a third party.
    Gossip,
    /// `key import`.
    Imported,
    /// The Sealbox key directory.
    Directory,
    /// One of our own accounts.
    Own,
    None,
}

/// Encryption status of one recipient.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecipientStatus {
    pub address: String,
    pub recommendation: Recommendation,
    pub fingerprint: Option<String>,
    pub source: KeySource,
}

impl RecipientStatus {
    /// Can we encrypt to this recipient right now?
    pub fn has_key(&self) -> bool {
        self.fingerprint.is_some() && self.recommendation != Recommendation::Disable
    }
}

/// How a message went out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendMode {
    Encrypted,
    Plaintext,
    GuestLink,
}

/// Guest-link details returned to the sender. `url` is exactly the link that was mailed
/// (with the secret in its fragment only when `secret_in_link`); in [`GuestMode::Passphrase`]
/// the sender must share `passphrase` by another channel.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GuestLinkInfo {
    pub url: String,
    pub passphrase: String,
    #[serde(default)]
    pub mode: GuestMode,
    pub expires_at: i64,
    /// The link (and therefore the notification mail) contains the decryption secret.
    #[serde(default)]
    pub secret_in_link: bool,
    /// The server requires a one-time code mailed to the recipient before it releases the
    /// ciphertext.
    #[serde(default)]
    pub recipient_verification: bool,
}

impl fmt::Debug for GuestLinkInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestLinkInfo")
            // The fragment may carry the secret (one-click / email-code): never print it.
            .field("url", &self.url.split('#').next().unwrap_or(""))
            .field("passphrase", &"<redacted>")
            .field("mode", &self.mode)
            .field("expires_at", &self.expires_at)
            .field("secret_in_link", &self.secret_in_link)
            .field("recipient_verification", &self.recipient_verification)
            .finish()
    }
}

/// Result of [`crate::Engine::send`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SendReport {
    pub message_id: String,
    pub mode: SendMode,
    pub encrypted: bool,
    pub recipients: Vec<RecipientStatus>,
    #[serde(default)]
    pub guest: Option<GuestLinkInfo>,
    pub sent_copy_appended: bool,
    #[serde(default)]
    pub sent_folder: Option<String>,
}

/// Per-folder part of a sync.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FolderSync {
    pub name: String,
    pub new: u32,
    pub uidvalidity_reset: bool,
    /// Older mail of the folder is not stored yet: its first sync fetched only the newest
    /// window ([`crate::EngineConfig::sync_window`]); later syncs and
    /// [`crate::Engine::backfill`] fetch the rest, newest first.
    #[serde(default)]
    pub more_to_backfill: bool,
    /// How many older messages are still to fetch, when this run counted them (a first sync
    /// and every backfill search below the window do; 0 once nothing older is left); `None`
    /// when it did not look (e.g. a `watch` round).
    #[serde(default)]
    pub older_pending: Option<u32>,
    /// Stored messages dropped because their UID is no longer on the server — deleted or
    /// moved away by webmail, the phone, or another client. See
    /// [`crate::Engine::reconcile_folder`].
    #[serde(default)]
    pub removed: u32,
    /// Stored messages whose flags the server reports differently (read elsewhere, starred
    /// elsewhere) and which were brought into line.
    #[serde(default)]
    pub flags_changed: u32,
}

/// Which part of a folder a sync step fetches (see [`crate::EngineConfig::sync_window`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncPhase {
    /// First sync of a folder: its newest window, the newest batch first.
    Initial,
    /// Mail that arrived since the last sync (above everything stored), oldest first.
    Incremental,
    /// Older mail below the window, the newest batch first, down to the first message.
    Backfill,
}

/// One stored batch of a running sync ([`crate::Engine::sync_with_progress`],
/// [`crate::Engine::backfill_with_progress`]): emitted after the batch is committed, so a UI can
/// refresh its list right away ("Syncing 1,200 of 10,000"). Counts are per folder and phase
/// of this run.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SyncProgress {
    pub account: String,
    pub folder: String,
    pub phase: SyncPhase,
    /// Messages fetched so far in this phase.
    pub fetched: u32,
    /// Of those, stored for the first time (one already stored is skipped).
    pub stored: u32,
    /// What this phase set out to fetch: the window, the new mail, or the backfill chunk.
    pub planned: u32,
    /// Messages in the folder on the server (`EXISTS` when the folder was selected).
    pub total_known: u32,
    /// Messages of the folder stored locally now.
    pub local: u32,
    /// Older mail is still waiting below the window after this batch.
    pub more_to_backfill: bool,
}

/// Result of [`crate::Engine::sync`].
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

impl SyncReport {
    /// Fold another run of the same account in; a folder present in both keeps one entry
    /// (counts added, the later run's backfill state).
    pub fn merge(&mut self, other: SyncReport) {
        self.new += other.new;
        self.decrypted += other.decrypted;
        self.failed += other.failed;
        for f in other.folders {
            match self.folders.iter_mut().find(|g| g.name == f.name) {
                Some(g) => {
                    g.new += f.new;
                    g.uidvalidity_reset |= f.uidvalidity_reset;
                    g.more_to_backfill = f.more_to_backfill;
                    g.older_pending = f.older_pending.or(g.older_pending);
                    g.removed += f.removed;
                    g.flags_changed += f.flags_changed;
                }
                None => self.folders.push(f),
            }
        }
        self.new_ids.extend(other.new_ids);
        self.new_ids.sort_unstable();
        self.new_ids.dedup();
    }

    /// Whether this run changed the stored mail at all: new messages, messages dropped because
    /// they are gone from the server, or flags brought into line. `watch` reports an event when
    /// this is true, so that mail read or deleted in webmail reaches the UI the same way new
    /// mail does.
    pub fn changed(&self) -> bool {
        self.new > 0
            || self
                .folders
                .iter()
                .any(|f| f.removed > 0 || f.flags_changed > 0)
    }
}

/// Event from [`crate::Engine::watch`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WatchEvent {
    /// IDLE is active.
    Idle { folder: String },
    /// New mail was synced (may be empty if the change was a flag update).
    NewMail { report: SyncReport },
    /// The IDLE timeout elapsed without server activity.
    Timeout,
}

/// An RFC 5322 address as shown to the user.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Address {
    #[serde(default)]
    pub name: Option<String>,
    pub address: String,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(n) if !n.is_empty() => write!(f, "{n} <{}>", self.address),
            _ => f.write_str(&self.address),
        }
    }
}

/// Signature verdict of a stored message.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigState {
    /// No signature.
    #[default]
    None,
    /// Verified with a known key (`fingerprint` set).
    Good,
    /// Signed by a known key but the signature does not verify.
    Bad,
    /// Signed by a key we do not know (`fingerprint` holds the issuer key id).
    UnknownKey,
}

/// Signature summary of a stored message.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignatureSummary {
    pub status: SigState,
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Address the signing key belongs to, when known.
    #[serde(default)]
    pub signer: Option<String>,
    /// G30: the sender's Autocrypt or signing key differs from the one seen before.
    #[serde(default)]
    pub key_changed: bool,
    /// G30: good signature by the key the user verified for this sender.
    #[serde(default)]
    pub signer_verified: bool,
}

/// Attachment metadata.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttachmentInfo {
    pub index: usize,
    pub filename: String,
    pub content_type: String,
    pub size: usize,
    /// The part's `Content-ID` without angle brackets, when it has one: what a `cid:` image
    /// URL in the HTML body names (an inline image, `docs/HTML_MAIL.md`). `None` for a part
    /// without one, and for messages stored before the store kept it.
    #[serde(default)]
    pub content_id: Option<String>,
}

/// The `Content-ID` a `cid:` URL names (RFC 2392): the rest of the URL, percent-decoded, angle
/// brackets dropped. `None` for any other URL, and for a `cid:` with nothing after it. An
/// escape that does not decode (a stray `%`, bytes that are not UTF-8) leaves the text as it
/// was, so such a URL can only match a `Content-ID` spelt exactly like it.
pub fn cid_content_id(src: &str) -> Option<String> {
    let rest = src
        .trim()
        .get(..4)
        .filter(|scheme| scheme.eq_ignore_ascii_case("cid:"))
        .and_then(|_| src.trim().get(4..))?;
    let decoded = percent_decode(rest).unwrap_or_else(|| rest.to_owned());
    let id = decoded.trim().trim_start_matches('<').trim_end_matches('>');
    (!id.is_empty()).then(|| id.to_owned())
}

/// `%XX` escapes decoded as UTF-8; `None` when one is malformed or the result is not UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// One row of `list`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MessageSummary {
    pub id: i64,
    pub account: String,
    pub folder: String,
    pub uid: u32,
    #[serde(default)]
    pub message_id: Option<String>,
    pub from: Address,
    pub to: Vec<Address>,
    #[serde(default)]
    pub cc: Vec<Address>,
    /// The protected subject when the message carried one, else the outer subject.
    #[serde(default)]
    pub subject: Option<String>,
    /// `Date` header, unix seconds.
    #[serde(default)]
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
    pub attachment_count: usize,
    pub raw_size: usize,
    #[serde(default)]
    pub decrypt_error: Option<String>,
    /// `In-Reply-To` header, angle brackets stripped.
    #[serde(default)]
    pub in_reply_to: Vec<String>,
    /// `References` header (oldest first), angle brackets stripped.
    #[serde(default)]
    pub references: Vec<String>,
    /// Conversation key computed by the store at insert time: the Message-ID of the earliest
    /// known ancestor in this account (walking `References` / `In-Reply-To` through the
    /// messages already stored), else the message's own Message-ID, else a synthetic
    /// `sbx-thread:<row id>`. A parent that arrives after its replies pulls them into its
    /// thread. Scoped to the account: compare together with [`MessageSummary::account`].
    #[serde(default)]
    pub thread_id: String,
    /// The start of the message for a list row: the first 160 characters of the text body,
    /// or of the HTML body reduced to text when there is no text (never markup), whitespace
    /// collapsed. Computed when the message is stored and sealed at rest like the bodies;
    /// `None` for a message without a readable body (e.g. one we could not decrypt).
    #[serde(default)]
    pub snippet: Option<String>,
}

/// `read`: the summary plus bodies and attachments.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MessageDetail {
    #[serde(flatten)]
    pub summary: MessageSummary,
    #[serde(default)]
    pub text: Option<String>,
    /// The HTML part **exactly as it arrived**: attacker-controlled, with whatever script, CSS
    /// and tracking the sender put in it. Kept for the send path, quoting and spam features.
    ///
    /// A UI must never render this. Use [`crate::Engine::message_html`], which sanitizes it and
    /// reports the remote images it blocked ([`crate::HtmlBody`], `docs/HTML_MAIL.md`).
    #[serde(default)]
    pub html: Option<String>,
    pub attachments: Vec<AttachmentInfo>,
    #[serde(default)]
    pub in_reply_to: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

impl MessageDetail {
    /// The attachment an `<img src="cid:…">` of this message names ([`inline_attachment`]).
    pub fn inline_part(&self, src: &str) -> Option<&AttachmentInfo> {
        inline_attachment(&self.attachments, src)
    }
}

/// The attachment an `<img src="cid:…">` names: the part whose `Content-ID` is the URL's
/// ([`cid_content_id`]; compared exactly, case-sensitive). `None` for any other URL and for a
/// `cid:` that no part carries.
pub fn inline_attachment<'a>(
    attachments: &'a [AttachmentInfo],
    src: &str,
) -> Option<&'a AttachmentInfo> {
    let cid = cid_content_id(src)?;
    attachments.iter().find(|a| {
        a.content_id
            .as_deref()
            .map(|c| c.trim().trim_start_matches('<').trim_end_matches('>'))
            == Some(cid.as_str())
    })
}

/// Filter for [`crate::Engine::list_messages`].
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ListQuery {
    /// `None` = every account (unified inbox).
    #[serde(default)]
    pub account: Option<String>,
    /// `None` = INBOX; `"*"` = every folder.
    #[serde(default)]
    pub folder: Option<String>,
    /// Pick the folder by special-use role instead of by name: resolved per account to the
    /// folder the server's `LIST` mapped to that role (remembered on sync), else the
    /// provider's default name. Takes precedence over `folder`.
    #[serde(default)]
    pub folder_role: Option<FolderRole>,
    /// 0 = default (50).
    #[serde(default)]
    pub limit: usize,
}

/// One special-use role of an account and the folder it maps to.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FolderRoleEntry {
    pub role: FolderRole,
    /// Folder name on the server.
    pub folder: String,
    /// `true` when the server's `LIST` (RFC 6154 attributes or name heuristics) said so on a
    /// sync; `false` when this is the provider profile's default, not yet confirmed.
    pub learned: bool,
}

/// Result of [`crate::Engine::publish_key`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublishReport {
    /// Fingerprint of the uploaded key.
    pub fingerprint: String,
    /// Base URL of the directory the key went to.
    pub server_url: String,
    /// Address → `unpublished` | `pending` | `published`, as the directory reports it after
    /// the upload (and the verification request).
    pub status: std::collections::BTreeMap<String, String>,
    /// A verification challenge was requested for the account address: the directory mails a
    /// link to it; [`crate::Engine::complete_directory_verification`] follows it. `false`
    /// when the address was already published (nothing to verify).
    pub token_issued: bool,
}

/// What the key directory holds for one of our addresses
/// ([`crate::Engine::directory_status`]).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectoryStatus {
    pub server_url: String,
    /// A key is published for the address.
    pub published: bool,
    /// `Some(true)` when the published key is the account's current key, `Some(false)` when
    /// another key is published for the address, `None` when nothing is published.
    pub fingerprint_matches: Option<bool>,
    /// `published` · `other_key` · `unpublished` · `awaiting_verification` (no challenge mail
    /// in INBOX yet) · `verification_failed` (the challenge link was refused: expired or used).
    pub state: String,
}

/// One known correspondent.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Contact {
    pub address: String,
    pub recommendation: Recommendation,
    #[serde(default)]
    pub fingerprint: Option<String>,
    pub source: KeySource,
    pub prefer_encrypt: PreferEncrypt,
    #[serde(default)]
    pub last_seen: Option<i64>,
    #[serde(default)]
    pub autocrypt_timestamp: Option<i64>,
    #[serde(default)]
    pub gossip_fingerprint: Option<String>,
    /// G30: the user verified the current key (fingerprint compared out of band).
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
    /// G30: set when a message brought a different key; cleared by acknowledge/verify.
    #[serde(default)]
    pub key_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub previous_fingerprint: Option<String>,
}

/// Flag modification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagOp {
    Add,
    Remove,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(index: usize, content_id: Option<&str>) -> AttachmentInfo {
        AttachmentInfo {
            index,
            filename: format!("p{index}.png"),
            content_type: "image/png".into(),
            size: 3,
            content_id: content_id.map(str::to_owned),
        }
    }

    #[test]
    fn a_cid_url_names_its_content_id() {
        assert_eq!(cid_content_id("cid:logo@x").as_deref(), Some("logo@x"));
        assert_eq!(cid_content_id("CID:logo@x").as_deref(), Some("logo@x"));
        assert_eq!(cid_content_id(" cid:<logo@x> ").as_deref(), Some("logo@x"));
        // RFC 2392: the URL is percent-encoded, the Content-ID is not
        assert_eq!(
            cid_content_id("cid:foo4%2Afoo1@bar.net").as_deref(),
            Some("foo4*foo1@bar.net")
        );
        assert_eq!(
            cid_content_id("cid:%E6%97%A5@x").as_deref(),
            Some("\u{65e5}@x")
        );
        // an escape that does not decode leaves the text as it is
        assert_eq!(cid_content_id("cid:a%zz@x").as_deref(), Some("a%zz@x"));
        assert_eq!(cid_content_id("cid:a%ff@x").as_deref(), Some("a%ff@x"));
        assert_eq!(cid_content_id("cid:a%4").as_deref(), Some("a%4"));
        for other in [
            "cid:",
            "cid:<>",
            "https://x/logo@x",
            "logo@x",
            "data:image/png;base64,AA",
            "",
        ] {
            assert_eq!(cid_content_id(other), None, "{other:?}");
        }
    }

    #[test]
    fn inline_attachment_matches_the_content_id_exactly() {
        let parts = [
            part(0, None),
            part(1, Some("logo@x")),
            part(2, Some("<Pic@x>")),
        ];
        let found = |src: &str| inline_attachment(&parts, src).map(|a| a.index);
        assert_eq!(found("cid:logo@x"), Some(1));
        assert_eq!(found("cid:logo%40x"), Some(1));
        assert_eq!(found("cid:Pic@x"), Some(2));
        // case-sensitive, and only cid: URLs
        for none in [
            "cid:LOGO@x",
            "cid:pic@x",
            "cid:missing@x",
            "https://x.example/logo@x",
        ] {
            assert_eq!(found(none), None, "{none:?}");
        }
    }
}
