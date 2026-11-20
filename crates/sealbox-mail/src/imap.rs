//! Async IMAP client (async-imap over tokio, rustls for TLS/STARTTLS).

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_imap::imap_proto::{Response, Status};
use async_imap::types::{Capability, Fetch, Flag};
use async_imap::{Authenticator, Client, Session};
use futures_util::TryStreamExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::error::ImapError;
use crate::net_policy::{self, ConnectOptions};
use crate::oauth::xoauth2_sasl_raw;
use crate::{tls, Auth, Security};

/// Default per-operation network timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Tag used for the one command we send before async-imap's own tag counter
/// takes over (the pre-login `CAPABILITY`).
const PREAUTH_TAG: &str = "sbcap";

/// Plain or TLS-wrapped TCP stream (one concrete type for `Session<T>`).
pub enum MailStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl fmt::Debug for MailStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MailStream::Plain(_) => f.write_str("MailStream::Plain"),
            MailStream::Tls(_) => f.write_str("MailStream::Tls"),
        }
    }
}

impl AsyncRead for MailStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MailStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MailStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MailStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MailStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MailStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MailStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MailStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MailStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MailStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// State of the selected mailbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mailbox {
    pub name: String,
    /// `UIDVALIDITY`; if it changes, all cached UIDs are invalid.
    pub uidvalidity: u32,
    /// `UIDNEXT` (0 when the server did not report it).
    pub uidnext: u32,
    pub exists: u32,
    pub recent: u32,
    pub unseen: Option<u32>,
    pub read_only: bool,
}

/// One entry of `LIST`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Folder {
    pub name: String,
    pub delimiter: Option<String>,
    /// Attributes such as `\Noselect`, `\HasChildren`, `\Sent`, `\Trash`.
    pub attributes: Vec<String>,
}

impl Folder {
    /// The attributes normalised to their wire form (`\Sent`, `\Noselect`, …),
    /// whichever way they were recorded (`Extension("\\Sent")` from the
    /// parser's Debug form, or a plain `\Sent`).
    pub fn normalized_attributes(&self) -> Vec<String> {
        self.attributes
            .iter()
            .map(|a| normalize_attribute(a))
            .collect()
    }

    /// Case-insensitive attribute test, e.g. `has_attribute("\\Sent")`.
    pub fn has_attribute(&self, attr: &str) -> bool {
        let want = attr.trim_start_matches('\\');
        self.normalized_attributes()
            .iter()
            .any(|a| a.trim_start_matches('\\').eq_ignore_ascii_case(want))
    }

    /// `\Noselect` (the folder is only a hierarchy node).
    pub fn is_noselect(&self) -> bool {
        self.has_attribute("\\Noselect")
    }

    /// Last hierarchy component (`[Gmail]/Sent Mail` → `Sent Mail`).
    pub fn leaf(&self) -> &str {
        match &self.delimiter {
            Some(d) if !d.is_empty() => self.name.rsplit(d.as_str()).next().unwrap_or(&self.name),
            _ => &self.name,
        }
    }
}

fn normalize_attribute(a: &str) -> String {
    let t = a.trim();
    // Debug form of `NameAttribute::Extension(Cow<str>)`: `Extension("\\Sent")`.
    if let Some(inner) = t
        .strip_prefix("Extension(")
        .and_then(|s| s.strip_suffix(')'))
    {
        let unq = inner.trim_matches('"').replace("\\\\", "\\");
        return unq;
    }
    match t {
        "NoInferiors" => "\\Noinferiors".to_owned(),
        "NoSelect" => "\\Noselect".to_owned(),
        "Marked" => "\\Marked".to_owned(),
        "Unmarked" => "\\Unmarked".to_owned(),
        other => other.to_owned(),
    }
}

/// Special-use roles (RFC 6154 plus the XLIST extras Gmail used to send).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderRole {
    Inbox,
    Sent,
    Drafts,
    Trash,
    Junk,
    Archive,
    /// Gmail "All Mail" (`\All`).
    All,
    /// `\Flagged` / Gmail "Starred".
    Flagged,
}

impl FolderRole {
    pub const ALL: [FolderRole; 8] = [
        FolderRole::Inbox,
        FolderRole::Sent,
        FolderRole::Drafts,
        FolderRole::Trash,
        FolderRole::Junk,
        FolderRole::Archive,
        FolderRole::All,
        FolderRole::Flagged,
    ];

    /// Stable lower-case name (`sent`, `junk`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            FolderRole::Inbox => "inbox",
            FolderRole::Sent => "sent",
            FolderRole::Drafts => "drafts",
            FolderRole::Trash => "trash",
            FolderRole::Junk => "junk",
            FolderRole::Archive => "archive",
            FolderRole::All => "all",
            FolderRole::Flagged => "flagged",
        }
    }

    /// Parse [`as_str`](Self::as_str) output (also accepts `spam`, `deleted`, `bin`).
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "inbox" => FolderRole::Inbox,
            "sent" => FolderRole::Sent,
            "drafts" | "draft" => FolderRole::Drafts,
            "trash" | "deleted" | "bin" => FolderRole::Trash,
            "junk" | "spam" => FolderRole::Junk,
            "archive" => FolderRole::Archive,
            "all" | "allmail" | "all_mail" => FolderRole::All,
            "flagged" | "starred" => FolderRole::Flagged,
            _ => return None,
        })
    }

    /// LIST attributes (RFC 6154 and XLIST) that denote this role.
    pub fn attributes(self) -> &'static [&'static str] {
        match self {
            FolderRole::Inbox => &["\\Inbox"],
            FolderRole::Sent => &["\\Sent"],
            FolderRole::Drafts => &["\\Drafts"],
            FolderRole::Trash => &["\\Trash"],
            FolderRole::Junk => &["\\Junk", "\\Spam"],
            FolderRole::Archive => &["\\Archive"],
            FolderRole::All => &["\\All", "\\AllMail"],
            FolderRole::Flagged => &["\\Flagged", "\\Starred"],
        }
    }

    /// Folder names (full or leaf, case-insensitive) that conventionally carry
    /// this role when the server advertises no SPECIAL-USE attributes.
    pub fn name_candidates(self) -> &'static [&'static str] {
        match self {
            FolderRole::Inbox => &["INBOX"],
            FolderRole::Sent => &[
                "Sent",
                "Sent Items",
                "Sent Messages",
                "Sent Mail",
                "[Gmail]/Sent Mail",
                "[Google Mail]/Sent Mail",
                "INBOX.Sent",
                "INBOX/Sent",
                "Sent-Mail",
                "Gesendet",
            ],
            FolderRole::Drafts => &[
                "Drafts",
                "Draft",
                "[Gmail]/Drafts",
                "[Google Mail]/Drafts",
                "INBOX.Drafts",
                "INBOX/Drafts",
                "Entwürfe",
            ],
            FolderRole::Trash => &[
                "Trash",
                "Deleted Items",
                "Deleted Messages",
                "Deleted",
                "Bin",
                "[Gmail]/Trash",
                "[Gmail]/Bin",
                "[Google Mail]/Trash",
                "[Google Mail]/Bin",
                "INBOX.Trash",
                "INBOX/Trash",
                "Papierkorb",
            ],
            FolderRole::Junk => &[
                "Junk",
                "Spam",
                "Junk E-mail",
                "Junk Email",
                "Junk Mail",
                "Bulk Mail",
                "Bulk",
                "[Gmail]/Spam",
                "[Google Mail]/Spam",
                "INBOX.Junk",
                "INBOX/Junk",
                "INBOX.Spam",
                "INBOX/Spam",
            ],
            FolderRole::Archive => &["Archive", "Archives", "INBOX.Archive", "INBOX/Archive"],
            FolderRole::All => &["[Gmail]/All Mail", "[Google Mail]/All Mail", "All Mail"],
            FolderRole::Flagged => &[
                "[Gmail]/Starred",
                "[Google Mail]/Starred",
                "Starred",
                "Flagged",
            ],
        }
    }
}

impl std::fmt::Display for FolderRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a special-use mapping was obtained.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecialUseSource {
    /// Nothing but INBOX could be mapped.
    #[default]
    None,
    /// Every mapped role came from a `\Sent`-style attribute (RFC 6154 / XLIST).
    SpecialUse,
    /// Every mapped role came from the folder-name heuristics.
    Heuristic,
    /// Some roles from attributes, the rest from names.
    Mixed,
}

/// The server's special-use folders, mapped by [`SpecialFolders::from_folders`].
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpecialFolders {
    pub inbox: String,
    pub sent: Option<String>,
    pub drafts: Option<String>,
    pub trash: Option<String>,
    pub junk: Option<String>,
    pub archive: Option<String>,
    pub all: Option<String>,
    pub flagged: Option<String>,
    pub source: SpecialUseSource,
    /// Hierarchy delimiter reported by the server (first non-empty one seen).
    pub delimiter: Option<String>,
}

impl SpecialFolders {
    /// Map LIST output to roles: `\Sent`-style attributes first (RFC 6154
    /// SPECIAL-USE, or XLIST's `\Spam`/`\AllMail`/`\Starred`), then the usual
    /// names (`Sent Items`, `[Gmail]/Spam`, `Deleted Items`, …) matched on the
    /// full name and on the last hierarchy component. `\Noselect` folders are
    /// never chosen.
    pub fn from_folders(folders: &[Folder]) -> Self {
        let mut out = SpecialFolders {
            inbox: "INBOX".to_owned(),
            delimiter: folders
                .iter()
                .filter_map(|f| f.delimiter.clone())
                .find(|d| !d.is_empty()),
            ..Default::default()
        };
        if let Some(f) = folders
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case("INBOX"))
        {
            out.inbox = f.name.clone();
        }
        let mut by_attr = 0usize;
        let mut by_name = 0usize;
        for role in FolderRole::ALL {
            if role == FolderRole::Inbox {
                continue;
            }
            let (name, from_attr) = match pick_role_folder(role, folders) {
                Some(x) => x,
                None => continue,
            };
            if from_attr {
                by_attr += 1;
            } else {
                by_name += 1;
            }
            out.set(role, Some(name));
        }
        out.source = match (by_attr, by_name) {
            (0, 0) => SpecialUseSource::None,
            (_, 0) => SpecialUseSource::SpecialUse,
            (0, _) => SpecialUseSource::Heuristic,
            _ => SpecialUseSource::Mixed,
        };
        out
    }

    /// The folder for a role, if mapped (`Inbox` is always mapped).
    pub fn get(&self, role: FolderRole) -> Option<&str> {
        match role {
            FolderRole::Inbox => Some(&self.inbox),
            FolderRole::Sent => self.sent.as_deref(),
            FolderRole::Drafts => self.drafts.as_deref(),
            FolderRole::Trash => self.trash.as_deref(),
            FolderRole::Junk => self.junk.as_deref(),
            FolderRole::Archive => self.archive.as_deref(),
            FolderRole::All => self.all.as_deref(),
            FolderRole::Flagged => self.flagged.as_deref(),
        }
    }

    /// Set (or clear) the folder for a role.
    pub fn set(&mut self, role: FolderRole, name: Option<String>) {
        match role {
            FolderRole::Inbox => self.inbox = name.unwrap_or_else(|| "INBOX".to_owned()),
            FolderRole::Sent => self.sent = name,
            FolderRole::Drafts => self.drafts = name,
            FolderRole::Trash => self.trash = name,
            FolderRole::Junk => self.junk = name,
            FolderRole::Archive => self.archive = name,
            FolderRole::All => self.all = name,
            FolderRole::Flagged => self.flagged = name,
        }
    }

    /// `(role, name)` for every mapped role.
    pub fn mapped(&self) -> Vec<(FolderRole, String)> {
        FolderRole::ALL
            .iter()
            .filter_map(|r| self.get(*r).map(|n| (*r, n.to_owned())))
            .collect()
    }
}

/// Find the folder for `role`; `true` when an attribute decided it.
pub fn pick_role_folder(role: FolderRole, folders: &[Folder]) -> Option<(String, bool)> {
    let selectable = folders.iter().filter(|f| !f.is_noselect());
    for f in selectable.clone() {
        if role.attributes().iter().any(|a| f.has_attribute(a)) {
            return Some((f.name.clone(), true));
        }
    }
    for cand in role.name_candidates() {
        if let Some(f) = selectable
            .clone()
            .find(|f| f.name.eq_ignore_ascii_case(cand))
        {
            return Some((f.name.clone(), false));
        }
    }
    for cand in role.name_candidates() {
        if cand.contains(['/', '.']) {
            continue;
        }
        if let Some(f) = selectable
            .clone()
            .find(|f| f.leaf().eq_ignore_ascii_case(cand))
        {
            return Some((f.name.clone(), false));
        }
    }
    None
}

/// Result of `STATUS`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MailboxStatus {
    pub name: String,
    pub messages: u32,
    pub recent: u32,
    pub uidnext: u32,
    pub uidvalidity: u32,
    pub unseen: Option<u32>,
}

/// Which protocol path [`ImapClient::r#move`] took.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoveMethod {
    /// `UID MOVE` (RFC 6851).
    Move,
    /// `UID COPY` + `\Deleted` + `UID EXPUNGE` (or `EXPUNGE` without UIDPLUS).
    CopyExpunge,
}

/// A message fetched by UID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedMessage {
    pub uid: u32,
    pub raw: Vec<u8>,
    pub flags: Vec<String>,
}

/// Why `idle_wait` returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdleEvent {
    /// The server reported a change (EXISTS / EXPUNGE / FETCH …).
    NewData,
    /// Nothing happened within the timeout.
    Timeout,
}

/// How `set_flags` modifies the flag set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagOp {
    Add,
    Remove,
    Replace,
}

/// XOAUTH2 SASL authenticator (RFC 7628 style, as used by Gmail / Outlook). Lent to
/// async-imap as `&mut`, so the error challenge can be read after a refused login.
#[derive(Default)]
struct XOAuth2Authenticator {
    initial: String,
    sent: bool,
    /// The server's error challenge (XOAUTH2 sends a JSON status object), if it sent one.
    error: Option<String>,
}

impl Authenticator for &mut XOAuth2Authenticator {
    type Response = String;

    fn process(&mut self, challenge: &[u8]) -> String {
        if self.sent {
            // The server sent an error challenge; keep it for the error, and answer empty so
            // the server finishes with a tagged NO carrying the human-readable reason.
            if self.error.is_none() {
                self.error = Some(String::from_utf8_lossy(challenge).into_owned());
            }
            String::new()
        } else {
            self.sent = true;
            std::mem::take(&mut self.initial)
        }
    }
}

/// Longest server text kept in a [`ImapError::LoginRejected`] reply.
const MAX_REPLY_CHARS: usize = 300;

/// `s` as quoted inside an IMAP string on the wire (async-imap's `LOGIN` arguments).
fn imap_quoted(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Every form in which `auth`'s secret could come back in a server's text: as given, as
/// quoted in `LOGIN`, as `Debug` escapes it, and for XOAUTH2 the SASL response raw and in
/// base64. Longest first, so a form is replaced before a shorter one it contains.
fn credential_forms(auth: &Auth) -> Vec<String> {
    let secret = match auth {
        Auth::Password { pass, .. } => pass,
        Auth::XOAuth2 { access_token, .. } => access_token,
    };
    let mut forms = vec![
        secret.clone(),
        imap_quoted(secret),
        secret.escape_debug().to_string(),
    ];
    if let Auth::XOAuth2 { user, access_token } = auth {
        forms.push(xoauth2_sasl_raw(user, access_token));
        forms.push(crate::oauth::xoauth2_sasl(user, access_token));
    }
    forms.retain(|f| !f.is_empty());
    forms.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    forms.dedup();
    forms
}

/// The response code at the start of `text` (`[AUTHENTICATIONFAILED] …`), if any.
fn leading_code(text: &str) -> Option<LoginCode> {
    let inside = text.strip_prefix('[')?;
    let end = inside.find([']', ' '])?;
    let atom = &inside[..end];
    let is_atom = !atom.is_empty()
        && atom
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    is_atom.then(|| LoginCode::from_atom(atom))
}

/// Code-less login refusals that are *sometimes* temporary, matched case-insensitively on the
/// server's text. Exchange Online answers a burst of new logins with `NO User is authenticated
/// but not connected.` and accepts the same token moments later (observed on Outlook.com, G21
/// 2026-11-17, and reproduced by hand) - but it sends the very same text for failures that
/// never clear: an XOAUTH2 `user=` that is not the token's mailbox, IMAP disabled for the
/// mailbox, or an app not allowed into it. So such a refusal keeps `code: None` (it counts as
/// rejected credentials wherever the code decides, e.g. the relay's parking); only a short,
/// bounded retry may treat it as possibly transient ([`ImapError::may_clear_on_retry`]).
const CODELESS_MAYBE_TRANSIENT_REFUSALS: &[&str] = &["user is authenticated but not connected"];

/// Is `text` (a refused login's reply) one of [`CODELESS_MAYBE_TRANSIENT_REFUSALS`]?
pub(crate) fn is_codeless_maybe_transient_refusal(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    CODELESS_MAYBE_TRANSIENT_REFUSALS
        .iter()
        .any(|needle| lower.contains(needle))
}

/// The [`ImapError::LoginRejected`] for async-imap's rendering of a tagged `NO` / `BAD`
/// (`status`) to `LOGIN` / `AUTHENTICATE`. Every form of the credential (`forms`, from
/// [`credential_forms`]) is replaced by `[redacted]`, control characters by spaces, and the
/// text is cut at [`MAX_REPLY_CHARS`].
fn login_rejected(
    host: &str,
    mechanism: &'static str,
    status: &str,
    rendered: &str,
    xoauth2_error: Option<&str>,
    forms: &[String],
) -> ImapError {
    let (parsed_code, info) = match split_outcome(rendered) {
        Some((code, info)) => (code, info.unwrap_or_default()),
        // Not async-imap's usual form: keep all of it (redacted like the rest).
        None => (None, rendered.to_owned()),
    };
    let mut text = match parsed_code {
        // A code imap-proto lifted out of the text (`[ALERT]`): put it back in front.
        Some(name) if !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric()) => {
            format!("[{}] {info}", name.to_ascii_uppercase())
        }
        _ => info,
    };
    if let Some(error) = xoauth2_error.map(str::trim).filter(|e| !e.is_empty()) {
        if !text.is_empty() {
            text.push_str("; ");
        }
        text.push_str("XOAUTH2 error: ");
        text.push_str(error);
    }
    for form in forms {
        text = text.replace(form.as_str(), "[redacted]");
    }
    let mut text = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_owned();
    if let Some((cut, _)) = text.char_indices().nth(MAX_REPLY_CHARS) {
        text.truncate(cut);
        text.push('…');
    }
    let code = leading_code(&text);
    let reply = if text.is_empty() {
        status.to_owned()
    } else {
        format!("{status} {text}")
    };
    ImapError::LoginRejected {
        host: host.to_owned(),
        mechanism,
        code,
        reply,
    }
}

/// An authenticated IMAP session.
pub struct ImapClient {
    session: Option<Session<MailStream>>,
    host: String,
    capabilities: Vec<String>,
    /// Capabilities advertised before login (what decides the SASL mechanism).
    preauth_capabilities: Vec<String>,
    auth_mechanism: &'static str,
    selected: Option<Mailbox>,
    timeout: Duration,
}

impl fmt::Debug for ImapClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImapClient")
            .field("host", &self.host)
            .field("connected", &self.session.is_some())
            .field("auth", &self.auth_mechanism)
            .field("selected", &self.selected.as_ref().map(|m| &m.name))
            .finish()
    }
}

/// Mechanism names reported by [`ImapClient::auth_mechanism`]. An OAuth login is always
/// [`AUTH_XOAUTH2`]: when the server does not advertise `AUTH=XOAUTH2` the connection fails
/// with [`ImapError::XOAuth2NotOffered`] instead of sending the token as a password.
pub const AUTH_LOGIN: &str = "LOGIN";
pub const AUTH_XOAUTH2: &str = "XOAUTH2";

/// The response code in front of a refused login ([`ImapError::LoginRejected`]): RFC 5530's
/// codes, plus `ALERT` (RFC 3501), as the server put them in brackets before its text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginCode {
    /// `AUTHENTICATIONFAILED`: the credentials are wrong (or the server will not say more).
    AuthenticationFailed,
    /// `AUTHORIZATIONFAILED`: authenticated, but this identity may not use the mailbox.
    AuthorizationFailed,
    /// `EXPIRED`: the credentials (or the account) have expired.
    Expired,
    /// `PRIVACYREQUIRED`: the server wants an encrypted connection first.
    PrivacyRequired,
    /// `CONTACTADMIN`: the account needs its administrator.
    ContactAdmin,
    /// `UNAVAILABLE`: a temporary failure on the server's side; the same credentials may work
    /// later. Not a verdict on them.
    Unavailable,
    /// `ALERT`: text the server wants the user to see.
    Alert,
    /// Any other code: its atom, upper-cased (`NOPERM`, `LIMIT` …).
    Other(String),
}

impl LoginCode {
    /// The code for a bracketed atom (case-insensitive).
    pub fn from_atom(atom: &str) -> Self {
        match atom.to_ascii_uppercase().as_str() {
            "AUTHENTICATIONFAILED" => LoginCode::AuthenticationFailed,
            "AUTHORIZATIONFAILED" => LoginCode::AuthorizationFailed,
            "EXPIRED" => LoginCode::Expired,
            "PRIVACYREQUIRED" => LoginCode::PrivacyRequired,
            "CONTACTADMIN" => LoginCode::ContactAdmin,
            "UNAVAILABLE" => LoginCode::Unavailable,
            "ALERT" => LoginCode::Alert,
            other => LoginCode::Other(other.to_owned()),
        }
    }

    /// The atom as sent on the wire (`AUTHENTICATIONFAILED`).
    pub fn as_str(&self) -> &str {
        match self {
            LoginCode::AuthenticationFailed => "AUTHENTICATIONFAILED",
            LoginCode::AuthorizationFailed => "AUTHORIZATIONFAILED",
            LoginCode::Expired => "EXPIRED",
            LoginCode::PrivacyRequired => "PRIVACYREQUIRED",
            LoginCode::ContactAdmin => "CONTACTADMIN",
            LoginCode::Unavailable => "UNAVAILABLE",
            LoginCode::Alert => "ALERT",
            LoginCode::Other(atom) => atom,
        }
    }

    /// A temporary failure (`UNAVAILABLE`, RFC 5530 §3): retrying the same credentials later
    /// may succeed, so it says nothing about them.
    pub fn is_temporary(&self) -> bool {
        matches!(self, LoginCode::Unavailable)
    }
}

impl fmt::Display for LoginCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Send `CAPABILITY` on a not-yet-authenticated connection and collect the
/// answer. async-imap only exposes capabilities after login, so this writes
/// one tagged command by hand (the stream is unbuffered on the write side).
async fn preauth_capabilities(client: &mut Client<MailStream>) -> Result<Vec<String>, ImapError> {
    client
        .get_mut()
        .write_all(format!("{PREAUTH_TAG} CAPABILITY\r\n").as_bytes())
        .await?;
    client.get_mut().flush().await?;
    let mut caps = Vec::new();
    loop {
        let Some(resp) = client.read_response().await? else {
            return Err(async_imap::error::Error::ConnectionLost.into());
        };
        match resp.parsed() {
            Response::Capabilities(list) => {
                caps.extend(list.iter().map(|c| match c {
                    async_imap::imap_proto::Capability::Imap4rev1 => "IMAP4rev1".to_owned(),
                    async_imap::imap_proto::Capability::Auth(a) => format!("AUTH={a}"),
                    async_imap::imap_proto::Capability::Atom(a) => a.to_string(),
                }));
            }
            Response::Done {
                tag,
                status,
                outcome,
            } if tag.0 == PREAUTH_TAG => {
                return match status {
                    Status::Ok => Ok(caps),
                    _ => Err(ImapError::Protocol(async_imap::error::Error::Bad(
                        outcome
                            .information
                            .as_deref()
                            .unwrap_or("CAPABILITY rejected")
                            .to_owned(),
                    ))),
                };
            }
            _ => {}
        }
    }
}

/// async-imap keeps nothing of a tagged `NO` / `BAD` but the string
/// `code: {code:?}, info: {information:?}`. Split it back into the `Debug` name of the code
/// imap-proto parsed (`Alert`; the RFC 5530 codes are unknown to imap-proto and stay at the
/// start of the text) and the server's text. `None` when `rendered` is not in that form.
fn split_outcome(rendered: &str) -> Option<(Option<&str>, Option<String>)> {
    let rest = rendered.strip_prefix("code: ")?;
    let (code, info) = if let Some(code) = rest.strip_suffix(", info: None") {
        (code, None)
    } else {
        // The text is a `Debug` string literal, in which every `"` is escaped, so the first
        // `, info: Some("` with an unescaped quote is the separator.
        let at = rest.find(", info: Some(\"")?;
        let literal = rest[at + ", info: Some(".len()..].strip_suffix(')')?;
        (&rest[..at], Some(unescape_debug_str(literal)?))
    };
    let code = match code {
        "None" => None,
        some => Some(some.strip_prefix("Some(")?.strip_suffix(')')?),
    };
    Some((code, info))
}

/// The value of a `"…"` literal as `str`'s `Debug` writes it; `None` for anything else.
fn unescape_debug_str(literal: &str) -> Option<String> {
    let inner = literal.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                '\\' => out.push('\\'),
                '"' => out.push('"'),
                '\'' => out.push('\''),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '0' => out.push('\0'),
                'u' => {
                    if chars.next()? != '{' {
                        return None;
                    }
                    let (mut value, mut digits) = (0u32, 0);
                    loop {
                        match chars.next()? {
                            '}' => break,
                            h => {
                                value = value.checked_mul(16)?.checked_add(h.to_digit(16)?)?;
                                digits += 1;
                            }
                        }
                    }
                    if digits == 0 {
                        return None;
                    }
                    out.push(char::from_u32(value)?);
                }
                _ => return None,
            },
            '"' => return None,
            c => out.push(c),
        }
    }
    Some(out)
}

/// The header in which Outlook.com / Exchange Online keep the `Message-ID` a client submitted
/// after replacing it with their own.
pub const ORIGINAL_MESSAGE_ID_HEADER: &str = "X-Microsoft-Original-Message-ID";

/// The `UID SEARCH` criteria for [`ImapClient::search_message_id`]: `(either, plain)`, where
/// `either` matches the id in `Message-ID` or in [`ORIGINAL_MESSAGE_ID_HEADER`] and `plain` in
/// `Message-ID` only (asked when `either` finds nothing: a server refusing `OR`). `None` for an id that is empty
/// or cannot be put in a quoted string (`"`, CR, LF): nothing can match it.
pub fn message_id_search_criteria(message_id: &str) -> Option<(String, String)> {
    let mid = message_id
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>');
    if mid.is_empty() || mid.contains(['"', '\\', '\r', '\n']) {
        return None;
    }
    let plain = format!("HEADER Message-ID \"<{mid}>\"");
    let either = format!("OR {plain} HEADER {ORIGINAL_MESSAGE_ID_HEADER} \"<{mid}>\"");
    Some((either, plain))
}

impl ImapClient {
    /// Connect, negotiate TLS as requested and authenticate. An OAuth token passed here has no
    /// [`BearerScope`](crate::BearerScope): it is only sent to a Google or Microsoft host (see
    /// [`connect_with`](Self::connect_with)).
    pub async fn connect(
        host: &str,
        port: u16,
        security: Security,
        auth: Auth,
    ) -> Result<Self, ImapError> {
        Self::connect_with_timeout(host, port, security, auth, DEFAULT_TIMEOUT).await
    }

    /// Like [`connect`](Self::connect) with an explicit timeout applied to
    /// the TCP connect, the TLS handshake and every subsequent operation.
    pub async fn connect_with_timeout(
        host: &str,
        port: u16,
        security: Security,
        auth: Auth,
        timeout: Duration,
    ) -> Result<Self, ImapError> {
        Self::connect_with(host, port, security, auth, &ConnectOptions::new(timeout)).await
    }

    /// Connect with explicit [`ConnectOptions`]. Before anything goes on the wire the
    /// transport policy is applied (`crate::net_policy`): `Security::Plain` only towards
    /// local/private hosts or `SEALBOX_ALLOW_PLAIN_HOSTS` ([`ImapError::Policy`] with
    /// `InsecureTransportRefused`), and an XOAUTH2 token only towards its provider's mail
    /// hosts, per `opts.bearer` (`OAuthHostMismatch`). A server that does not advertise
    /// `AUTH=XOAUTH2` before login gets no token at all ([`ImapError::XOAuth2NotOffered`]).
    pub async fn connect_with(
        host: &str,
        port: u16,
        security: Security,
        auth: Auth,
        opts: &ConnectOptions,
    ) -> Result<Self, ImapError> {
        Self::connect_via(host, None, port, security, auth, opts).await
    }

    /// Like [`connect_with`](Self::connect_with), but the TCP connection goes to one of
    /// `addrs` (tried in order) instead of to whatever `host` resolves to at this moment.
    /// `host` is still the name the transport policy, the TLS server name (SNI and the
    /// certificate check) and error messages use. For a caller that resolved and vetted `host`
    /// itself and must connect to exactly the addresses it checked, so that a DNS answer that
    /// changes between check and connect cannot redirect the session (the push relay,
    /// threat-model R9). With no address the connect fails like an unresolvable host.
    pub async fn connect_pinned(
        host: &str,
        addrs: &[IpAddr],
        port: u16,
        security: Security,
        auth: Auth,
        opts: &ConnectOptions,
    ) -> Result<Self, ImapError> {
        Self::connect_via(host, Some(addrs), port, security, auth, opts).await
    }

    /// [`connect_with`](Self::connect_with), dialling `pinned` when given.
    async fn connect_via(
        host: &str,
        pinned: Option<&[IpAddr]>,
        port: u16,
        security: Security,
        auth: Auth,
        opts: &ConnectOptions,
    ) -> Result<Self, ImapError> {
        net_policy::check_transport(host, port, security)?;
        if matches!(auth, Auth::XOAuth2 { .. }) {
            net_policy::check_bearer_host(opts.bearer, host)?;
        }
        let timeout = opts.timeout;
        let dial = async {
            match pinned {
                None => TcpStream::connect((host, port)).await,
                Some(ips) => {
                    let targets: Vec<SocketAddr> =
                        ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
                    TcpStream::connect(&targets[..]).await
                }
            }
        };
        let tcp = tokio::time::timeout(timeout, dial)
            .await
            .map_err(|_| ImapError::Timeout(timeout))?
            .map_err(|source| ImapError::Connect {
                host: host.to_owned(),
                port,
                source,
            })?;
        let _ = tcp.set_nodelay(true);

        let stream = match security {
            Security::Tls => MailStream::Tls(Box::new(tls_wrap(host, tcp, timeout).await?)),
            Security::StartTls | Security::Plain => MailStream::Plain(tcp),
        };

        let mut client = Client::new(stream);
        // Greeting.
        let greeting = tokio::time::timeout(timeout, client.read_response())
            .await
            .map_err(|_| ImapError::Timeout(timeout))??
            .ok_or(async_imap::error::Error::ConnectionLost)?;
        if let async_imap::imap_proto::Response::Data {
            status: async_imap::imap_proto::Status::Bye,
            outcome,
        } = greeting.parsed()
        {
            return Err(ImapError::Auth(format!(
                "server refused connection: {}",
                outcome.information.as_deref().unwrap_or("BYE")
            )));
        }

        if security == Security::StartTls {
            match client.run_command_and_check_ok("STARTTLS", None).await {
                Ok(()) => {}
                Err(async_imap::error::Error::No(_)) | Err(async_imap::error::Error::Bad(_)) => {
                    return Err(ImapError::StartTlsUnsupported);
                }
                Err(e) => return Err(e.into()),
            }
            let tcp = match client.into_inner() {
                MailStream::Plain(t) => t,
                MailStream::Tls(_) => return Err(ImapError::Tls("already TLS".into())),
            };
            let tls = tls_wrap(host, tcp, timeout).await?;
            client = Client::new(MailStream::Tls(Box::new(tls)));
        }

        // Pre-login capabilities decide the SASL mechanism. A failure here is
        // not fatal (some servers answer CAPABILITY oddly); we then simply try
        // what the caller asked for.
        let preauth_caps =
            match tokio::time::timeout(timeout, preauth_capabilities(&mut client)).await {
                Err(_) => return Err(ImapError::Timeout(timeout)),
                Ok(Ok(caps)) => caps,
                Ok(Err(e)) => {
                    tracing::debug!(host, "pre-login CAPABILITY failed: {e}");
                    Vec::new()
                }
            };
        let has_cap = |name: &str| preauth_caps.iter().any(|c| c.eq_ignore_ascii_case(name));
        let auth_mechanism = match &auth {
            // No `AUTH=XOAUTH2` before login: the token is not sent at all. In particular it
            // is never offered as a `LOGIN` password (docs/THREAT_MODEL.md R14). When the
            // pre-login CAPABILITY failed we still try XOAUTH2 — the token then only ever
            // travels inside the XOAUTH2 mechanism, to a host the policy accepted.
            Auth::XOAuth2 { .. } if !preauth_caps.is_empty() && !has_cap("AUTH=XOAUTH2") => {
                tracing::warn!(
                    host,
                    "IMAP server does not advertise AUTH=XOAUTH2; OAuth sign-in refused"
                );
                return Err(ImapError::XOAuth2NotOffered {
                    host: host.to_owned(),
                });
            }
            Auth::XOAuth2 { .. } => AUTH_XOAUTH2,
            Auth::Password { .. } => AUTH_LOGIN,
        };

        // A refusal may quote the credential back; its message must not (`LoginRejected`).
        let forms = credential_forms(&auth);
        let mut xoauth2 = XOAuth2Authenticator::default();
        let login = async {
            match auth {
                Auth::Password { user, pass } => client.login(user, pass).await,
                Auth::XOAuth2 { user, access_token } => {
                    xoauth2.initial = xoauth2_sasl_raw(&user, &access_token);
                    client.authenticate("XOAUTH2", &mut xoauth2).await
                }
            }
        };
        let outcome = tokio::time::timeout(timeout, login).await;
        let mut session = match outcome {
            Err(_) => return Err(ImapError::Timeout(timeout)),
            Ok(Ok(s)) => s,
            Ok(Err((e, _client))) => {
                let (status, rendered) = match &e {
                    async_imap::error::Error::No(m) => ("NO", m),
                    async_imap::error::Error::Bad(m) => ("BAD", m),
                    _ => return Err(ImapError::Protocol(e)),
                };
                return Err(login_rejected(
                    host,
                    auth_mechanism,
                    status,
                    rendered,
                    xoauth2.error.as_deref(),
                    &forms,
                ));
            }
        };

        let capabilities = match tokio::time::timeout(timeout, session.capabilities()).await {
            Ok(Ok(caps)) => caps
                .iter()
                .map(|c| match c {
                    Capability::Imap4rev1 => "IMAP4rev1".to_owned(),
                    Capability::Auth(a) => format!("AUTH={a}"),
                    Capability::Atom(a) => a.to_string(),
                })
                .collect(),
            _ => Vec::new(),
        };

        Ok(Self {
            session: Some(session),
            host: host.to_owned(),
            capabilities,
            preauth_capabilities: preauth_caps,
            auth_mechanism,
            selected: None,
            timeout,
        })
    }

    /// Capabilities advertised after login (e.g. `IDLE`, `UIDPLUS`, `MOVE`).
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Capabilities advertised before login (`AUTH=…`, `STARTTLS`, `LOGINDISABLED`).
    pub fn preauth_capabilities(&self) -> &[String] {
        &self.preauth_capabilities
    }

    /// How this session authenticated: [`AUTH_LOGIN`] (password) or [`AUTH_XOAUTH2`].
    pub fn auth_mechanism(&self) -> &'static str {
        self.auth_mechanism
    }

    /// Case-insensitive capability check.
    pub fn has_capability(&self, cap: &str) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.eq_ignore_ascii_case(cap))
    }

    /// The currently selected mailbox, if any.
    pub fn selected(&self) -> Option<&Mailbox> {
        self.selected.as_ref()
    }

    fn session(&mut self) -> Result<&mut Session<MailStream>, ImapError> {
        self.session.as_mut().ok_or(ImapError::NotConnected)
    }

    async fn timed<T, F>(&self, fut: F) -> Result<T, ImapError>
    where
        F: std::future::Future<Output = Result<T, ImapError>>,
    {
        tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| ImapError::Timeout(self.timeout))?
    }

    /// `LIST "" "*"`.
    pub async fn list_folders(&mut self) -> Result<Vec<Folder>, ImapError> {
        let timeout = self.timeout;
        let session = self.session()?;
        let fut = async {
            let names: Vec<async_imap::types::Name> = session
                .list(Some(""), Some("*"))
                .await?
                .try_collect()
                .await?;
            Ok::<_, ImapError>(
                names
                    .iter()
                    .map(|n| Folder {
                        name: n.name().to_owned(),
                        delimiter: n.delimiter().map(str::to_owned),
                        attributes: n.attributes().iter().map(|a| format!("{a:?}")).collect(),
                    })
                    .collect(),
            )
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ImapError::Timeout(timeout))?
    }

    /// `SELECT folder`.
    pub async fn select(&mut self, folder: &str) -> Result<Mailbox, ImapError> {
        let timeout = self.timeout;
        let session = self.session()?;
        let mb = tokio::time::timeout(timeout, session.select(folder))
            .await
            .map_err(|_| ImapError::Timeout(timeout))??;
        let mailbox = Mailbox {
            name: folder.to_owned(),
            uidvalidity: mb.uid_validity.unwrap_or(0),
            uidnext: mb.uid_next.unwrap_or(0),
            exists: mb.exists,
            recent: mb.recent,
            unseen: mb.unseen,
            read_only: false,
        };
        self.selected = Some(mailbox.clone());
        Ok(mailbox)
    }

    /// `EXAMINE folder` (read-only select).
    pub async fn examine(&mut self, folder: &str) -> Result<Mailbox, ImapError> {
        let timeout = self.timeout;
        let session = self.session()?;
        let mb = tokio::time::timeout(timeout, session.examine(folder))
            .await
            .map_err(|_| ImapError::Timeout(timeout))??;
        let mailbox = Mailbox {
            name: folder.to_owned(),
            uidvalidity: mb.uid_validity.unwrap_or(0),
            uidnext: mb.uid_next.unwrap_or(0),
            exists: mb.exists,
            recent: mb.recent,
            unseen: mb.unseen,
            read_only: true,
        };
        self.selected = Some(mailbox.clone());
        Ok(mailbox)
    }

    /// UIDs strictly greater than `since_uid` in the selected mailbox, ascending.
    /// Pass `0` for everything.
    pub async fn fetch_new_uids(&mut self, since_uid: u32) -> Result<Vec<u32>, ImapError> {
        if self.selected.is_none() {
            return Err(ImapError::NoMailboxSelected);
        }
        let timeout = self.timeout;
        let session = self.session()?;
        let query = format!("UID {}:*", since_uid.saturating_add(1));
        let set = tokio::time::timeout(timeout, session.uid_search(query))
            .await
            .map_err(|_| ImapError::Timeout(timeout))??;
        // `n:*` returns the highest UID even when it is < n (RFC 3501 §6.4.8).
        let mut uids: Vec<u32> = set.into_iter().filter(|u| *u > since_uid).collect();
        uids.sort_unstable();
        Ok(uids)
    }

    /// `UID SEARCH <criteria>` in the selected mailbox, ascending.
    pub async fn uid_search(&mut self, criteria: &str) -> Result<Vec<u32>, ImapError> {
        if self.selected.is_none() {
            return Err(ImapError::NoMailboxSelected);
        }
        let timeout = self.timeout;
        let session = self.session()?;
        let set = tokio::time::timeout(timeout, session.uid_search(criteria))
            .await
            .map_err(|_| ImapError::Timeout(timeout))??;
        let mut uids: Vec<u32> = set.into_iter().collect();
        uids.sort_unstable();
        Ok(uids)
    }

    /// Fetch the full RFC 822 bytes of one message (does not set `\Seen`).
    pub async fn fetch_rfc822(&mut self, uid: u32) -> Result<Vec<u8>, ImapError> {
        let mut batch = self.fetch_rfc822_batch(&[uid]).await?;
        batch
            .pop()
            .filter(|m| m.uid == uid)
            .map(|m| m.raw)
            .ok_or_else(|| {
                ImapError::Protocol(async_imap::error::Error::Bad(format!(
                    "UID {uid} not returned by FETCH"
                )))
            })
    }

    /// Fetch several messages in one round trip (`UID FETCH a,b,c (UID FLAGS BODY.PEEK[])`).
    /// Messages missing on the server are silently absent from the result.
    pub async fn fetch_rfc822_batch(
        &mut self,
        uids: &[u32],
    ) -> Result<Vec<FetchedMessage>, ImapError> {
        if self.selected.is_none() {
            return Err(ImapError::NoMailboxSelected);
        }
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let timeout = self.timeout;
        let session = self.session()?;
        let set = sequence_set(uids);
        let fut = async {
            let fetches: Vec<Fetch> = session
                .uid_fetch(set, "(UID FLAGS BODY.PEEK[])")
                .await?
                .try_collect()
                .await?;
            Ok::<_, ImapError>(
                fetches
                    .iter()
                    .filter_map(|f| {
                        Some(FetchedMessage {
                            uid: f.uid?,
                            raw: f.body()?.to_vec(),
                            flags: f.flags().map(flag_to_string).collect(),
                        })
                    })
                    .collect::<Vec<_>>(),
            )
        };
        let mut msgs = tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ImapError::Timeout(timeout))??;
        msgs.sort_by_key(|m| m.uid);
        Ok(msgs)
    }

    /// `UID FETCH a,b,c (UID RFC822.SIZE)`: the size in bytes of each message (what a
    /// `BODY.PEEK[]` of it returns), ascending by UID — so a caller can bound the bytes of its
    /// next batches before fetching them. Messages missing on the server are absent.
    pub async fn fetch_sizes(&mut self, uids: &[u32]) -> Result<Vec<(u32, u32)>, ImapError> {
        if self.selected.is_none() {
            return Err(ImapError::NoMailboxSelected);
        }
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let timeout = self.timeout;
        let session = self.session()?;
        let set = sequence_set(uids);
        let fut = async {
            let fetches: Vec<Fetch> = session
                .uid_fetch(set, "(UID RFC822.SIZE)")
                .await?
                .try_collect()
                .await?;
            Ok::<_, ImapError>(
                fetches
                    .iter()
                    .filter_map(|f| Some((f.uid?, f.size?)))
                    .collect::<Vec<_>>(),
            )
        };
        let mut sizes = tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ImapError::Timeout(timeout))??;
        sizes.sort_unstable();
        Ok(sizes)
    }

    /// Fetch just the flags of the given UIDs.
    pub async fn fetch_flags(
        &mut self,
        uids: &[u32],
    ) -> Result<Vec<(u32, Vec<String>)>, ImapError> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let got = self.fetch_flags_set(sequence_set(uids), false).await?;
        Ok(got
            .into_iter()
            .map(|(uid, flags, _)| (uid, flags))
            .collect())
    }

    /// Fetch the flags of every message whose UID lies in one of the inclusive `ranges`, in
    /// one `UID FETCH lo:hi,… (UID FLAGS)` — or `(UID FLAGS RFC822.SIZE)` with `with_sizes`,
    /// which then also answers each message's size (`None` when the server left it out). For
    /// a caller that knows which UIDs exist and wants a few wide ranges rather than a long
    /// list (a range may span UIDs that are gone: the server simply has nothing to say about
    /// them). Some servers (GreenMail) pay a cost per `FETCH` that grows with the size of the
    /// mailbox, so fewer, wider commands matter. Ascending by UID.
    pub async fn fetch_flags_ranges(
        &mut self,
        ranges: &[(u32, u32)],
        with_sizes: bool,
    ) -> Result<Vec<(u32, Vec<String>, Option<u32>)>, ImapError> {
        if ranges.is_empty() {
            return Ok(Vec::new());
        }
        self.fetch_flags_set(range_set(ranges), with_sizes).await
    }

    async fn fetch_flags_set(
        &mut self,
        set: String,
        with_sizes: bool,
    ) -> Result<Vec<(u32, Vec<String>, Option<u32>)>, ImapError> {
        if self.selected.is_none() {
            return Err(ImapError::NoMailboxSelected);
        }
        let timeout = self.timeout;
        let session = self.session()?;
        let items = if with_sizes {
            "(UID FLAGS RFC822.SIZE)"
        } else {
            "(UID FLAGS)"
        };
        let fut = async {
            let fetches: Vec<Fetch> = session.uid_fetch(set, items).await?.try_collect().await?;
            Ok::<_, ImapError>(
                fetches
                    .iter()
                    .filter_map(|f| Some((f.uid?, f.flags().map(flag_to_string).collect(), f.size)))
                    .collect::<Vec<_>>(),
            )
        };
        let mut got = tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ImapError::Timeout(timeout))??;
        got.sort_by_key(|(uid, _, _)| *uid);
        Ok(got)
    }

    /// `APPEND folder (flags) {len}`; `flags` like `["\\Seen"]`.
    pub async fn append(
        &mut self,
        folder: &str,
        raw: &[u8],
        flags: &[&str],
    ) -> Result<(), ImapError> {
        let timeout = self.timeout;
        let session = self.session()?;
        let flag_str = if flags.is_empty() {
            None
        } else {
            Some(format!("({})", flags.join(" ")))
        };
        tokio::time::timeout(
            timeout,
            session.append(folder, flag_str.as_deref(), None, raw),
        )
        .await
        .map_err(|_| ImapError::Timeout(timeout))??;
        Ok(())
    }

    /// `UID STORE uid ±FLAGS.SILENT (flags)`.
    pub async fn set_flags(
        &mut self,
        uids: &[u32],
        op: FlagOp,
        flags: &[&str],
    ) -> Result<(), ImapError> {
        if self.selected.is_none() {
            return Err(ImapError::NoMailboxSelected);
        }
        if uids.is_empty() {
            return Ok(());
        }
        let timeout = self.timeout;
        let session = self.session()?;
        let verb = match op {
            FlagOp::Add => "+FLAGS.SILENT",
            FlagOp::Remove => "-FLAGS.SILENT",
            FlagOp::Replace => "FLAGS.SILENT",
        };
        let query = format!("{verb} ({})", flags.join(" "));
        let set = sequence_set(uids);
        let fut = async {
            let _drained: Vec<Fetch> = session.uid_store(set, query).await?.try_collect().await?;
            Ok::<_, ImapError>(())
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ImapError::Timeout(timeout))?
    }

    /// `EXPUNGE` the selected mailbox.
    pub async fn expunge(&mut self) -> Result<(), ImapError> {
        let timeout = self.timeout;
        let session = self.session()?;
        let fut = async {
            let _seqs: Vec<u32> = session.expunge().await?.try_collect().await?;
            Ok::<_, ImapError>(())
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ImapError::Timeout(timeout))?
    }

    /// `NOOP` (also surfaces pending untagged responses).
    pub async fn noop(&mut self) -> Result<(), ImapError> {
        let timeout = self.timeout;
        let session = self.session()?;
        tokio::time::timeout(timeout, session.noop())
            .await
            .map_err(|_| ImapError::Timeout(timeout))??;
        Ok(())
    }

    /// Enter `IDLE` on the selected mailbox and wait until the server reports
    /// a change or `timeout` elapses (servers drop idle connections after ~30
    /// minutes, so callers should loop with timeouts ≤ 29 min). Returns the
    /// session to the normal state before returning.
    pub async fn idle_wait(&mut self, timeout: Duration) -> Result<IdleEvent, ImapError> {
        if self.selected.is_none() {
            return Err(ImapError::NoMailboxSelected);
        }
        if !self.has_capability("IDLE") {
            return Err(ImapError::IdleUnsupported);
        }
        let session = self.session.take().ok_or(ImapError::NotConnected)?;
        let mut handle = session.idle();
        if let Err(e) = handle.init().await {
            // The session is owned by the handle; it cannot be recovered here.
            return Err(e.into());
        }
        let outcome = {
            let (fut, _stop) = handle.wait_with_timeout(timeout);
            fut.await
        };
        let session = handle.done().await?;
        self.session = Some(session);
        match outcome? {
            async_imap::extensions::idle::IdleResponse::NewData(_) => Ok(IdleEvent::NewData),
            async_imap::extensions::idle::IdleResponse::Timeout
            | async_imap::extensions::idle::IdleResponse::ManualInterrupt => Ok(IdleEvent::Timeout),
        }
    }

    /// Like [`idle_wait`](Self::idle_wait), but without the gap between the previous command
    /// and the server's `+` continuation, and with `timeout` as a hard cap on the whole round.
    ///
    /// Mail that arrives after the previous command completed but before the server
    /// acknowledges `IDLE` is announced by many servers (GreenMail 2.1 among them, observed
    /// 2026-10-29) as untagged `EXISTS`/`RECENT` **before** the `+`. async-imap files those in
    /// the session's unsolicited-response queue instead of waking the IDLE wait, so
    /// `idle_wait` sleeps through them until `timeout`. This variant first discards whatever
    /// earlier commands left in that queue (those changes are already reflected in the
    /// caller's last `SELECT`/`EXAMINE`, so they must not cause a spurious wake-up), enters
    /// IDLE, and returns [`IdleEvent::NewData`] right away (after `DONE`) when a mailbox change
    /// was announced while entering. Otherwise it waits like `idle_wait`, except that
    /// `timeout` bounds the round as a whole, even when the server sends `* OK` keep-alives
    /// (async-imap restarts its timer on each one), and that entering and leaving IDLE are
    /// bounded by the per-operation timeout. A caller that re-reads the folder after every
    /// return (a push relay) therefore never misses an arrival.
    pub async fn idle_wait_gapless(&mut self, timeout: Duration) -> Result<IdleEvent, ImapError> {
        if self.selected.is_none() {
            return Err(ImapError::NoMailboxSelected);
        }
        if !self.has_capability("IDLE") {
            return Err(ImapError::IdleUnsupported);
        }
        let op_timeout = self.timeout;
        let session = self.session.take().ok_or(ImapError::NotConnected)?;
        // The IDLE handle feeds this same channel; clone the receiver because `idle()`
        // consumes the session.
        let unsolicited = session.unsolicited_responses.clone();
        while unsolicited.try_recv().is_ok() {}
        let mut handle = session.idle();
        tokio::time::timeout(op_timeout, handle.init())
            .await
            .map_err(|_| ImapError::Timeout(op_timeout))??;
        let mut announced = false;
        while let Ok(response) = unsolicited.try_recv() {
            announced |= is_mailbox_change(&response);
        }
        let outcome = if announced {
            Ok(IdleEvent::NewData)
        } else {
            // `_stop` must stay alive for the whole wait: dropping it interrupts the IDLE.
            let (wait, _stop) = handle.wait_with_timeout(timeout);
            match tokio::time::timeout(timeout, wait).await {
                Err(_) => Ok(IdleEvent::Timeout),
                Ok(Ok(async_imap::extensions::idle::IdleResponse::NewData(_))) => {
                    Ok(IdleEvent::NewData)
                }
                Ok(Ok(_)) => Ok(IdleEvent::Timeout),
                Ok(Err(e)) => Err(e),
            }
        };
        let session = tokio::time::timeout(op_timeout, handle.done())
            .await
            .map_err(|_| ImapError::Timeout(op_timeout))??;
        self.session = Some(session);
        Ok(outcome?)
    }

    /// `CREATE name`. Most servers answer `NO` when the folder already exists;
    /// use [`ensure_folder`](Self::ensure_folder) for "create unless present".
    pub async fn create_folder(&mut self, name: &str) -> Result<(), ImapError> {
        let timeout = self.timeout;
        let session = self.session()?;
        tokio::time::timeout(timeout, session.create(name))
            .await
            .map_err(|_| ImapError::Timeout(timeout))??;
        Ok(())
    }

    /// `CREATE name` unless a folder of that name (case-insensitive) is listed;
    /// returns `true` when it was created.
    pub async fn ensure_folder(&mut self, name: &str) -> Result<bool, ImapError> {
        let folders = self.list_folders().await?;
        if folders.iter().any(|f| f.name.eq_ignore_ascii_case(name)) {
            return Ok(false);
        }
        self.create_folder(name).await?;
        Ok(true)
    }

    /// `DELETE name`.
    pub async fn delete_folder(&mut self, name: &str) -> Result<(), ImapError> {
        let timeout = self.timeout;
        let session = self.session()?;
        tokio::time::timeout(timeout, session.delete(name))
            .await
            .map_err(|_| ImapError::Timeout(timeout))??;
        if self
            .selected
            .as_ref()
            .is_some_and(|m| m.name.eq_ignore_ascii_case(name))
        {
            self.selected = None;
        }
        Ok(())
    }

    /// `RENAME from to`.
    pub async fn rename_folder(&mut self, from: &str, to: &str) -> Result<(), ImapError> {
        let timeout = self.timeout;
        let session = self.session()?;
        tokio::time::timeout(timeout, session.rename(from, to))
            .await
            .map_err(|_| ImapError::Timeout(timeout))??;
        if let Some(m) = self.selected.as_mut() {
            if m.name.eq_ignore_ascii_case(from) {
                m.name = to.to_owned();
            }
        }
        Ok(())
    }

    /// `SUBSCRIBE name` (some servers only show subscribed folders to other clients).
    pub async fn subscribe(&mut self, name: &str) -> Result<(), ImapError> {
        let timeout = self.timeout;
        let session = self.session()?;
        tokio::time::timeout(timeout, session.subscribe(name))
            .await
            .map_err(|_| ImapError::Timeout(timeout))??;
        Ok(())
    }

    /// `UID COPY uids to_folder` from the selected mailbox.
    pub async fn copy(&mut self, uids: &[u32], to_folder: &str) -> Result<(), ImapError> {
        if self.selected.is_none() {
            return Err(ImapError::NoMailboxSelected);
        }
        if uids.is_empty() {
            return Ok(());
        }
        let timeout = self.timeout;
        let session = self.session()?;
        let set = sequence_set(uids);
        tokio::time::timeout(timeout, session.uid_copy(set, to_folder))
            .await
            .map_err(|_| ImapError::Timeout(timeout))??;
        Ok(())
    }

    /// Move messages out of the selected mailbox: `UID MOVE` (RFC 6851) when the
    /// server advertises `MOVE`, otherwise [`move_via_copy`](Self::move_via_copy).
    pub async fn r#move(&mut self, uids: &[u32], to_folder: &str) -> Result<MoveMethod, ImapError> {
        if self.selected.is_none() {
            return Err(ImapError::NoMailboxSelected);
        }
        if uids.is_empty() {
            return Ok(MoveMethod::Move);
        }
        if !self.has_capability("MOVE") {
            self.move_via_copy(uids, to_folder).await?;
            return Ok(MoveMethod::CopyExpunge);
        }
        let timeout = self.timeout;
        let session = self.session()?;
        let set = sequence_set(uids);
        tokio::time::timeout(timeout, session.uid_mv(set, to_folder))
            .await
            .map_err(|_| ImapError::Timeout(timeout))??;
        Ok(MoveMethod::Move)
    }

    /// The pre-RFC 6851 move: `UID COPY`, `+FLAGS.SILENT (\Deleted)`, then
    /// `UID EXPUNGE` of exactly those UIDs when `UIDPLUS` is available, else a
    /// plain `EXPUNGE` (which also removes anything else flagged `\Deleted`).
    pub async fn move_via_copy(&mut self, uids: &[u32], to_folder: &str) -> Result<(), ImapError> {
        if uids.is_empty() {
            return Ok(());
        }
        self.copy(uids, to_folder).await?;
        self.set_flags(uids, FlagOp::Add, &["\\Deleted"]).await?;
        if self.has_capability("UIDPLUS") {
            self.uid_expunge(uids).await
        } else {
            self.expunge().await
        }
    }

    /// `UID EXPUNGE uids` (RFC 4315 UIDPLUS).
    pub async fn uid_expunge(&mut self, uids: &[u32]) -> Result<(), ImapError> {
        if self.selected.is_none() {
            return Err(ImapError::NoMailboxSelected);
        }
        if uids.is_empty() {
            return Ok(());
        }
        let timeout = self.timeout;
        let session = self.session()?;
        let set = sequence_set(uids);
        let fut = async {
            let _seqs: Vec<u32> = session.uid_expunge(set).await?.try_collect().await?;
            Ok::<_, ImapError>(())
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ImapError::Timeout(timeout))?
    }

    /// `STATUS folder (MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)` without selecting it.
    pub async fn status(&mut self, folder: &str) -> Result<MailboxStatus, ImapError> {
        let timeout = self.timeout;
        let session = self.session()?;
        let mb = tokio::time::timeout(
            timeout,
            session.status(folder, "(MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)"),
        )
        .await
        .map_err(|_| ImapError::Timeout(timeout))??;
        Ok(MailboxStatus {
            name: folder.to_owned(),
            messages: mb.exists,
            recent: mb.recent,
            uidnext: mb.uid_next.unwrap_or(0),
            uidvalidity: mb.uid_validity.unwrap_or(0),
            unseen: mb.unseen,
        })
    }

    /// `LIST "" "*"` mapped to roles (RFC 6154 SPECIAL-USE attributes, XLIST
    /// attribute names, then name heuristics). The XLIST *command* is not
    /// issued: every provider that ever needed it (Gmail) now advertises
    /// SPECIAL-USE in plain LIST.
    pub async fn list_special_use(&mut self) -> Result<SpecialFolders, ImapError> {
        let folders = self.list_folders().await?;
        Ok(SpecialFolders::from_folders(&folders))
    }

    /// UIDs in the selected mailbox carrying `message_id` (with or without angle brackets)
    /// as their `Message-ID`, or as their [`ORIGINAL_MESSAGE_ID_HEADER`]: Outlook.com's SMTP
    /// replaces the Message-ID of a submitted message with its own and keeps ours only in that
    /// header, so a lookup by `Message-ID` alone never finds the delivered message nor the
    /// provider's Sent copy. One `UID SEARCH OR …` ([`message_id_search_criteria`]); when that
    /// finds nothing, the `Message-ID` alone is asked as well, because async-imap reports a
    /// `NO` / `BAD` to `SEARCH` as an empty result, so a server that refuses `OR` or the
    /// header cannot be told from one that has no match.
    pub async fn search_message_id(&mut self, message_id: &str) -> Result<Vec<u32>, ImapError> {
        let Some((either, plain)) = message_id_search_criteria(message_id) else {
            return Ok(Vec::new());
        };
        let hits = self.uid_search(&either).await?;
        if !hits.is_empty() {
            return Ok(hits);
        }
        self.uid_search(&plain).await
    }

    /// `LOGOUT` and close the connection.
    pub async fn logout(mut self) -> Result<(), ImapError> {
        let timeout = self.timeout;
        if let Some(mut session) = self.session.take() {
            tokio::time::timeout(timeout, session.logout())
                .await
                .map_err(|_| ImapError::Timeout(timeout))??;
        }
        Ok(())
    }

    /// Host this client is connected to.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Change the per-operation timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Run `f` under the client's timeout; helper for extension commands.
    pub async fn with_timeout<T, F>(&self, fut: F) -> Result<T, ImapError>
    where
        F: std::future::Future<Output = Result<T, ImapError>>,
    {
        self.timed(fut).await
    }
}

async fn tls_wrap(
    host: &str,
    tcp: TcpStream,
    timeout: Duration,
) -> Result<TlsStream<TcpStream>, ImapError> {
    let name = tls::server_name(host).ok_or_else(|| ImapError::ServerName(host.to_owned()))?;
    tokio::time::timeout(timeout, tls::connector().connect(name, tcp))
        .await
        .map_err(|_| ImapError::Timeout(timeout))?
        .map_err(|e| ImapError::Tls(e.to_string()))
}

/// Does this queued untagged response mean the selected mailbox changed (a message arrived or
/// was expunged, or flags changed)? Used by [`ImapClient::idle_wait_gapless`].
fn is_mailbox_change(response: &async_imap::types::UnsolicitedResponse) -> bool {
    use async_imap::types::UnsolicitedResponse as U;
    match response {
        U::Exists(_) | U::Recent(_) | U::Expunge(_) => true,
        U::Other(data) => matches!(
            data.parsed(),
            Response::Fetch(..) | Response::Vanished { .. }
        ),
        U::Status { .. } => false,
    }
}

fn flag_to_string(flag: Flag<'_>) -> String {
    match flag {
        Flag::Seen => "\\Seen".to_owned(),
        Flag::Answered => "\\Answered".to_owned(),
        Flag::Flagged => "\\Flagged".to_owned(),
        Flag::Deleted => "\\Deleted".to_owned(),
        Flag::Draft => "\\Draft".to_owned(),
        Flag::Recent => "\\Recent".to_owned(),
        Flag::MayCreate => "\\*".to_owned(),
        Flag::Custom(c) => c.into_owned(),
    }
}

/// Compress sorted UIDs into an IMAP sequence set (`1:3,7,9:10`).
pub fn sequence_set(uids: &[u32]) -> String {
    let mut sorted: Vec<u32> = uids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out = String::new();
    let mut i = 0;
    while i < sorted.len() {
        let start = sorted[i];
        let mut end = start;
        while i + 1 < sorted.len() && sorted[i + 1] == end + 1 {
            i += 1;
            end = sorted[i];
        }
        if !out.is_empty() {
            out.push(',');
        }
        if start == end {
            out.push_str(&start.to_string());
        } else {
            out.push_str(&format!("{start}:{end}"));
        }
        i += 1;
    }
    out
}

/// Inclusive UID ranges as an IMAP sequence set (`1:3,7,9:10`), in the order given.
pub fn range_set(ranges: &[(u32, u32)]) -> String {
    let mut out = String::new();
    for &(a, b) in ranges {
        let (lo, hi) = (a.min(b), a.max(b));
        if !out.is_empty() {
            out.push(',');
        }
        if lo == hi {
            out.push_str(&lo.to_string());
        } else {
            out.push_str(&format!("{lo}:{hi}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_sets_render_inclusive_ranges() {
        assert_eq!(range_set(&[(1, 3), (7, 7), (9, 10)]), "1:3,7,9:10");
        assert_eq!(
            range_set(&[(5, 2)]),
            "2:5",
            "a reversed range is normalised"
        );
        assert_eq!(range_set(&[]), "");
    }

    #[test]
    fn sequence_sets_compress_ranges() {
        assert_eq!(sequence_set(&[1, 2, 3, 7, 10, 9]), "1:3,7,9:10");
        assert_eq!(sequence_set(&[5]), "5");
        assert_eq!(sequence_set(&[]), "");
    }

    fn folder(name: &str, delim: &str, attrs: &[&str]) -> Folder {
        Folder {
            name: name.into(),
            delimiter: Some(delim.into()),
            attributes: attrs.iter().map(|a| a.to_string()).collect(),
        }
    }

    #[test]
    fn attributes_normalise_from_debug_and_wire_forms() {
        let f = folder(
            "[Gmail]/Sent Mail",
            "/",
            &[
                "Extension(\"\\\\Sent\")",
                "Extension(\"\\\\HasNoChildren\")",
            ],
        );
        assert_eq!(
            f.normalized_attributes(),
            vec!["\\Sent".to_string(), "\\HasNoChildren".to_string()]
        );
        assert!(f.has_attribute("\\Sent"));
        assert!(f.has_attribute("sent"));
        assert!(!f.is_noselect());
        assert_eq!(f.leaf(), "Sent Mail");
        let g = folder(
            "[Gmail]",
            "/",
            &["NoSelect", "Extension(\"\\\\HasChildren\")"],
        );
        assert!(g.is_noselect());
        let plain = folder("Spam", ".", &["\\Junk"]);
        assert!(plain.has_attribute("\\Junk"));
    }

    #[test]
    fn special_use_prefers_attributes_then_names() {
        // Gmail-style LIST with SPECIAL-USE.
        let gmail = vec![
            folder("INBOX", "/", &["Extension(\"\\\\HasNoChildren\")"]),
            folder(
                "[Gmail]",
                "/",
                &["NoSelect", "Extension(\"\\\\HasChildren\")"],
            ),
            folder("[Gmail]/All Mail", "/", &["Extension(\"\\\\All\")"]),
            folder("[Gmail]/Drafts", "/", &["Extension(\"\\\\Drafts\")"]),
            folder("[Gmail]/Sent Mail", "/", &["Extension(\"\\\\Sent\")"]),
            folder("[Gmail]/Spam", "/", &["Extension(\"\\\\Junk\")"]),
            folder("[Gmail]/Starred", "/", &["Extension(\"\\\\Flagged\")"]),
            folder("[Gmail]/Trash", "/", &["Extension(\"\\\\Trash\")"]),
            // A decoy named like a sent folder but without the attribute.
            folder("Sent", "/", &[]),
        ];
        let s = SpecialFolders::from_folders(&gmail);
        assert_eq!(s.sent.as_deref(), Some("[Gmail]/Sent Mail"));
        assert_eq!(s.junk.as_deref(), Some("[Gmail]/Spam"));
        assert_eq!(s.trash.as_deref(), Some("[Gmail]/Trash"));
        assert_eq!(s.drafts.as_deref(), Some("[Gmail]/Drafts"));
        assert_eq!(s.all.as_deref(), Some("[Gmail]/All Mail"));
        assert_eq!(s.flagged.as_deref(), Some("[Gmail]/Starred"));
        assert_eq!(s.archive, None);
        assert_eq!(s.source, SpecialUseSource::SpecialUse);
        assert_eq!(s.get(FolderRole::Inbox), Some("INBOX"));
        assert_eq!(s.delimiter.as_deref(), Some("/"));

        // Outlook.com names, no attributes.
        let outlook = vec![
            folder("INBOX", "/", &[]),
            folder("Sent Items", "/", &[]),
            folder("Deleted Items", "/", &[]),
            folder("Junk Email", "/", &[]),
            folder("Drafts", "/", &[]),
            folder("Archive", "/", &[]),
        ];
        let s = SpecialFolders::from_folders(&outlook);
        assert_eq!(s.sent.as_deref(), Some("Sent Items"));
        assert_eq!(s.trash.as_deref(), Some("Deleted Items"));
        assert_eq!(s.junk.as_deref(), Some("Junk Email"));
        assert_eq!(s.drafts.as_deref(), Some("Drafts"));
        assert_eq!(s.archive.as_deref(), Some("Archive"));
        assert_eq!(s.source, SpecialUseSource::Heuristic);

        // Yahoo / iCloud style, dotted namespace, mixed case; and XLIST names.
        let dotted = vec![
            folder("Inbox", ".", &[]),
            folder("INBOX.Sent", ".", &[]),
            folder("INBOX.Trash", ".", &[]),
            folder("Bulk Mail", ".", &["Extension(\"\\\\Spam\")"]),
            folder("Draft", ".", &[]),
        ];
        let s = SpecialFolders::from_folders(&dotted);
        assert_eq!(s.inbox, "Inbox");
        assert_eq!(s.sent.as_deref(), Some("INBOX.Sent"));
        assert_eq!(s.trash.as_deref(), Some("INBOX.Trash"));
        assert_eq!(s.junk.as_deref(), Some("Bulk Mail"));
        assert_eq!(s.drafts.as_deref(), Some("Draft"));
        assert_eq!(s.source, SpecialUseSource::Mixed);

        // Leaf-name matching for nested custom hierarchies; Noselect never wins.
        let nested = vec![
            folder("INBOX", "/", &[]),
            folder("Mail", "/", &["NoSelect"]),
            folder("Mail/Sent Messages", "/", &[]),
            folder("Mail/Deleted Messages", "/", &[]),
            folder("Sent", "/", &["NoSelect"]),
        ];
        let s = SpecialFolders::from_folders(&nested);
        assert_eq!(s.sent.as_deref(), Some("Mail/Sent Messages"));
        assert_eq!(s.trash.as_deref(), Some("Mail/Deleted Messages"));

        // Only INBOX (fresh GreenMail user).
        let bare = vec![folder("INBOX", ".", &[])];
        let s = SpecialFolders::from_folders(&bare);
        assert_eq!(s.source, SpecialUseSource::None);
        assert!(s.mapped().len() == 1);
    }

    #[test]
    fn folder_roles_round_trip() {
        for r in FolderRole::ALL {
            assert_eq!(FolderRole::parse(r.as_str()), Some(r));
        }
        assert_eq!(FolderRole::parse("Spam"), Some(FolderRole::Junk));
        assert_eq!(FolderRole::parse("Deleted"), Some(FolderRole::Trash));
        assert_eq!(FolderRole::parse("nope"), None);
    }

    #[test]
    fn message_id_search_matches_the_original_id_too() {
        let (either, plain) = message_id_search_criteria("<abc.1@sealbox.test>").expect("valid");
        assert_eq!(plain, "HEADER Message-ID \"<abc.1@sealbox.test>\"");
        assert_eq!(
            either,
            "OR HEADER Message-ID \"<abc.1@sealbox.test>\" \
             HEADER X-Microsoft-Original-Message-ID \"<abc.1@sealbox.test>\""
        );
        // Brackets and surrounding blanks are optional.
        assert_eq!(
            message_id_search_criteria("  abc.1@sealbox.test "),
            Some((either, plain))
        );
        // Nothing that cannot sit in a quoted string, and nothing empty.
        for bad in ["", "<>", "a\"b@x", "a\\b@x", "a\r\nb@x"] {
            assert_eq!(message_id_search_criteria(bad), None, "{bad:?}");
        }
    }

    /// [`ImapError::LoginRejected`] against scripted servers on loopback (no docker): raised for
    /// a `NO` / `BAD` to `LOGIN` and to `AUTHENTICATE XOAUTH2` (also after an XOAUTH2 error
    /// challenge), never for a `BYE` greeting, a network error or a missing `AUTH=XOAUTH2`, and
    /// its message never contains the credential in any form.
    mod login_rejection {
        use super::super::*;
        use crate::net_policy::BearerScope;
        use crate::oauth::{xoauth2_sasl, Provider};
        use base64::Engine as _;
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        /// Contains `"` and `\`, so its IMAP-quoted form on the wire differs from the raw one.
        const PASSWORD: &str = "pw\"q\\z-7f3a1c";
        /// The quoted form async-imap sends (`"pw\"q\\z-7f3a1c"` without the outer quotes).
        const PASSWORD_QUOTED: &str = "pw\\\"q\\\\z-7f3a1c";
        const TOKEN: &str = "ya29.login-rejected-91c2e7";
        const OAUTH_USER: &str = "u@gmail.com";
        const XOAUTH2_ERROR: &str =
            r#"{"status":"401","schemes":"bearer","scope":"https://mail.google.com/"}"#;

        #[derive(Clone, Copy, Debug)]
        pub(super) enum Script {
            /// `LOGIN` gets this tagged answer (after the tag).
            Login(&'static str),
            /// `LOGIN` gets `NO` quoting the command's arguments as sent (the quoted password).
            LoginEcho,
            /// `* BYE` instead of the greeting.
            Bye,
            /// `AUTH=XOAUTH2` advertised; `AUTHENTICATE` gets this tagged answer at once.
            Xoauth2(&'static str),
            /// `AUTH=XOAUTH2` advertised; the token gets a base64 JSON error challenge (Gmail's
            /// way), the client's empty answer `NO [AUTHENTICATIONFAILED] …`.
            Xoauth2ErrorChallenge,
            /// `AUTH=XOAUTH2` advertised; the token gets `NO` repeating the client's SASL
            /// response, base64 and decoded.
            Xoauth2Echo,
        }

        /// A one-connection scripted IMAP server; returns its port and every line received.
        pub(super) async fn serve(script: Script) -> (u16, Arc<Mutex<Vec<String>>>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let seen: Arc<Mutex<Vec<String>>> = Arc::default();
            let log = seen.clone();
            tokio::spawn(async move {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let (rd, mut wr) = sock.into_split();
                if let Script::Bye = script {
                    let _ = wr
                        .write_all(b"* BYE Too many connections, try later\r\n")
                        .await;
                    return;
                }
                let _ = wr.write_all(b"* OK scripted IMAP ready\r\n").await;
                let caps = match script {
                    Script::Xoauth2(_) | Script::Xoauth2ErrorChallenge | Script::Xoauth2Echo => {
                        "IMAP4rev1 IDLE AUTH=XOAUTH2"
                    }
                    _ => "IMAP4rev1 IDLE",
                };
                let mut lines = BufReader::new(rd).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    log.lock().expect("lock").push(line.clone());
                    let mut parts = line.splitn(3, ' ');
                    let tag = parts.next().unwrap_or("*").to_owned();
                    let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
                    let args = parts.next().unwrap_or("").to_owned();
                    let reply = match (cmd.as_str(), script) {
                        ("CAPABILITY", _) => format!("* CAPABILITY {caps}\r\n{tag} OK done\r\n"),
                        ("LOGIN", Script::Login(answer)) => format!("{tag} {answer}\r\n"),
                        ("LOGIN", Script::LoginEcho) => {
                            format!("{tag} NO LOGIN {args} is not valid here\r\n")
                        }
                        ("AUTHENTICATE", Script::Xoauth2(answer)) => format!("{tag} {answer}\r\n"),
                        ("AUTHENTICATE", Script::Xoauth2ErrorChallenge | Script::Xoauth2Echo) => {
                            let _ = wr.write_all(b"+ \r\n").await;
                            let Ok(Some(response)) = lines.next_line().await else {
                                break;
                            };
                            log.lock().expect("lock").push(response.clone());
                            if let Script::Xoauth2Echo = script {
                                let decoded = base64::engine::general_purpose::STANDARD
                                    .decode(response.trim())
                                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                                    .unwrap_or_default();
                                format!("{tag} NO cannot use {response} ({decoded})\r\n")
                            } else {
                                let challenge =
                                    base64::engine::general_purpose::STANDARD.encode(XOAUTH2_ERROR);
                                let _ = wr.write_all(format!("+ {challenge}\r\n").as_bytes()).await;
                                let Ok(Some(empty)) = lines.next_line().await else {
                                    break;
                                };
                                log.lock().expect("lock").push(empty);
                                format!(
                                    "{tag} NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)\r\n"
                                )
                            }
                        }
                        ("AUTHENTICATE", _) => format!("{tag} NO unsupported mechanism\r\n"),
                        ("LOGOUT", _) => {
                            let _ = wr
                                .write_all(format!("* BYE\r\n{tag} OK\r\n").as_bytes())
                                .await;
                            break;
                        }
                        _ => format!("{tag} OK done\r\n"),
                    };
                    if wr.write_all(reply.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
            (port, seen)
        }

        pub(super) fn password() -> Auth {
            Auth::Password {
                user: "u-login".into(),
                pass: PASSWORD.into(),
            }
        }

        fn token() -> Auth {
            Auth::XOAuth2 {
                user: OAUTH_USER.into(),
                access_token: TOKEN.into(),
            }
        }

        /// A token from a loopback mock IdP, so the scripted server on 127.0.0.1 may get it.
        pub(super) fn opts() -> ConnectOptions {
            ConnectOptions::new(Duration::from_secs(5)).with_bearer(Some(BearerScope {
                provider: Provider::Google,
                dev_idp: true,
            }))
        }

        async fn refused(script: Script, auth: Auth) -> ImapError {
            let (port, _) = serve(script).await;
            ImapClient::connect_with("127.0.0.1", port, Security::Plain, auth, &opts())
                .await
                .expect_err("the login must fail")
        }

        /// Neither the message nor the `Debug` form carries any form of the credential.
        fn assert_credential_free(err: &ImapError) {
            let sasl = xoauth2_sasl(OAUTH_USER, TOKEN);
            let text = err.to_string();
            let dbg = format!("{err:?}");
            for form in [
                PASSWORD,
                PASSWORD_QUOTED,
                "7f3a1c",
                TOKEN,
                "91c2e7",
                sasl.as_str(),
            ] {
                assert!(!text.contains(form), "{form:?} in {text}");
                assert!(!dbg.contains(form), "{form:?} in {dbg}");
            }
            assert!(!text.chars().any(char::is_control), "{text:?}");
        }

        /// The fields of a [`ImapError::LoginRejected`] (panics on any other error).
        fn rejected(err: &ImapError) -> (&str, &'static str, Option<&LoginCode>, &str) {
            assert_credential_free(err);
            match err {
                ImapError::LoginRejected {
                    host,
                    mechanism,
                    code,
                    reply,
                } => (host, mechanism, code.as_ref(), reply),
                other => panic!("expected LoginRejected, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn no_to_login_is_a_rejection_with_its_rfc5530_code() {
            let err = refused(
                Script::Login("NO [AUTHENTICATIONFAILED] Invalid credentials"),
                password(),
            )
            .await;
            let (host, mechanism, code, reply) = rejected(&err);
            assert_eq!(host, "127.0.0.1");
            assert_eq!(mechanism, AUTH_LOGIN);
            assert_eq!(code, Some(&LoginCode::AuthenticationFailed));
            assert_eq!(reply, "NO [AUTHENTICATIONFAILED] Invalid credentials");
            assert_eq!(
                err.to_string(),
                "login to 127.0.0.1 rejected (LOGIN): NO [AUTHENTICATIONFAILED] Invalid credentials"
            );
        }

        #[tokio::test]
        async fn greenmail_style_no_without_a_code() {
            let err = refused(
                Script::Login("NO LOGIN failed. Invalid login/password for user id u77"),
                password(),
            )
            .await;
            let (_, _, code, reply) = rejected(&err);
            assert_eq!(code, None);
            assert_eq!(
                reply,
                "NO LOGIN failed. Invalid login/password for user id u77"
            );
        }

        #[tokio::test]
        async fn bad_to_login_is_a_rejection() {
            let err = refused(
                Script::Login("BAD [PRIVACYREQUIRED] LOGIN only after STARTTLS"),
                password(),
            )
            .await;
            let (_, mechanism, code, reply) = rejected(&err);
            assert_eq!(mechanism, AUTH_LOGIN);
            assert_eq!(code, Some(&LoginCode::PrivacyRequired));
            assert_eq!(reply, "BAD [PRIVACYREQUIRED] LOGIN only after STARTTLS");
        }

        #[tokio::test]
        async fn unavailable_is_a_temporary_rejection() {
            let err = refused(
                Script::Login("NO [UNAVAILABLE] Backend down, try later"),
                password(),
            )
            .await;
            let (_, _, code, _) = rejected(&err);
            let code = code.expect("a code");
            assert_eq!(code, &LoginCode::Unavailable);
            assert!(code.is_temporary());
            assert!(!LoginCode::AuthenticationFailed.is_temporary());
            assert!(!LoginCode::Other("LIMIT".into()).is_temporary());
        }

        /// Exchange Online's code-less `NO User is authenticated but not connected.` (G21
        /// Outlook, 2026-11-17) is sometimes a temporary refusal and sometimes a permanent one
        /// (a `user=` that is not the token's mailbox, IMAP disabled): it keeps `code: None`,
        /// so it counts as rejected credentials, and is only marked worth a bounded retry.
        #[tokio::test]
        async fn exchange_not_connected_is_a_rejection_worth_a_bounded_retry() {
            let err = refused(
                Script::Xoauth2("NO User is authenticated but not connected."),
                token(),
            )
            .await;
            assert!(!err.is_transient_login(), "{err:?}");
            assert!(err.may_clear_on_retry(), "{err:?}");
            let (_, mechanism, code, reply) = rejected(&err);
            assert_eq!(mechanism, AUTH_XOAUTH2);
            assert_eq!(code, None);
            // The server's words are kept as they were; no code is invented in the text.
            assert_eq!(reply, "NO User is authenticated but not connected.");
        }

        #[test]
        fn only_known_codeless_refusals_may_clear_on_retry() {
            let classify = |info: &str| {
                let rendered = format!("code: None, info: Some(\"{info}\")");
                login_rejected("h", AUTH_XOAUTH2, "NO", &rendered, None, &[])
            };
            for text in [
                "User is authenticated but not connected.",
                "USER IS AUTHENTICATED BUT NOT CONNECTED",
            ] {
                let err = classify(text);
                assert!(err.may_clear_on_retry(), "{text}");
                assert!(!err.is_transient_login(), "{text}: not a temporary code");
            }
            for text in [
                "AUTHENTICATE failed.",
                "LOGIN failed. Invalid login/password",
            ] {
                let err = classify(text);
                assert!(!err.may_clear_on_retry(), "{text}");
                assert!(!err.is_transient_login(), "{text}");
            }
            // A code the server did send wins over the text.
            let err = classify("[AUTHENTICATIONFAILED] User is authenticated but not connected");
            assert!(!err.may_clear_on_retry());
            let err = classify("[UNAVAILABLE] try later");
            assert!(err.is_transient_login() && err.may_clear_on_retry());
            // Not a login refusal at all.
            for err in [
                ImapError::Auth("BYE".into()),
                ImapError::Timeout(Duration::from_secs(1)),
            ] {
                assert!(!err.is_transient_login() && !err.may_clear_on_retry());
            }
        }

        #[test]
        fn an_xoauth2_refusal_that_will_not_change_its_mind_is_the_alias_shape() {
            let xoauth2 = |info: &str| {
                let rendered = format!("code: None, info: Some(\"{info}\")");
                login_rejected("h", AUTH_XOAUTH2, "NO", &rendered, None, &[])
            };
            // The two refusals a real alias produces (Outlook.com and Exchange Online).
            for text in [
                "[AUTHENTICATIONFAILED] AUTHENTICATE failed.",
                "User is authenticated but not connected.",
            ] {
                assert!(xoauth2(text).refused_xoauth2_identity(), "{text}");
            }
            // `[UNAVAILABLE]` is the server asking for a later retry, not a verdict on who we
            // say we are — hinting at an alias there would send the owner down a blind alley.
            assert!(!xoauth2("[UNAVAILABLE] try later").refused_xoauth2_identity());
            // A password login is not this shape, whatever it says.
            let password = login_rejected(
                "h",
                AUTH_LOGIN,
                "NO",
                "code: None, info: Some(\"[AUTHENTICATIONFAILED] Invalid credentials\")",
                None,
                &[],
            );
            assert!(!password.refused_xoauth2_identity());
            // Nothing was sent, or nothing was answered.
            for err in [
                ImapError::Auth("BYE".into()),
                ImapError::XOAuth2NotOffered { host: "h".into() },
                ImapError::Timeout(Duration::from_secs(1)),
            ] {
                assert!(!err.refused_xoauth2_identity(), "{err}");
            }
        }

        #[tokio::test]
        async fn a_code_imap_proto_parses_itself_is_kept() {
            // imap-proto knows `[ALERT]` and lifts it out of the text; RFC 5530 codes it does
            // not know stay in front of the text.
            let err = refused(Script::Login("NO [ALERT] Account locked"), password()).await;
            let (_, _, code, reply) = rejected(&err);
            assert_eq!(code, Some(&LoginCode::Alert));
            assert_eq!(reply, "NO [ALERT] Account locked");
        }

        #[tokio::test]
        async fn control_characters_in_the_server_text_are_removed() {
            // ESC and BEL are valid IMAP TEXT-CHARs: a terminal escape must not reach a log.
            let err = refused(
                Script::Login("NO [AUTHENTICATIONFAILED] Bad\u{1b}[31m\tcredentials\u{7}"),
                password(),
            )
            .await;
            let (_, _, _, reply) = rejected(&err);
            assert_eq!(reply, "NO [AUTHENTICATIONFAILED] Bad [31m credentials");
        }

        #[test]
        fn a_long_server_text_is_cut() {
            let rendered = format!("code: None, info: Some(\"{}\")", "x".repeat(1000));
            let err = login_rejected("h", AUTH_LOGIN, "NO", &rendered, None, &[]);
            let (_, _, _, reply) = rejected(&err);
            assert_eq!(reply, format!("NO {}…", "x".repeat(MAX_REPLY_CHARS)));
        }

        #[tokio::test]
        async fn an_echoed_password_is_redacted() {
            let err = refused(Script::LoginEcho, password()).await;
            let (_, _, _, reply) = rejected(&err);
            assert!(reply.starts_with("NO LOGIN \"u-login\" "), "{reply}");
            assert!(reply.contains("[redacted]"), "{reply}");
        }

        #[tokio::test]
        async fn no_to_authenticate_xoauth2_is_a_rejection() {
            let err = refused(
                Script::Xoauth2("NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)"),
                token(),
            )
            .await;
            let (_, mechanism, code, reply) = rejected(&err);
            assert_eq!(mechanism, AUTH_XOAUTH2);
            assert_eq!(code, Some(&LoginCode::AuthenticationFailed));
            assert_eq!(
                reply,
                "NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)"
            );
        }

        #[tokio::test]
        async fn bad_to_authenticate_xoauth2_is_a_rejection() {
            let err = refused(Script::Xoauth2("BAD Invalid SASL argument"), token()).await;
            let (_, mechanism, code, reply) = rejected(&err);
            assert_eq!(mechanism, AUTH_XOAUTH2);
            assert_eq!(code, None);
            assert_eq!(reply, "BAD Invalid SASL argument");
        }

        #[tokio::test]
        async fn xoauth2_error_challenge_then_no_is_a_rejection_with_the_error() {
            let (port, seen) = serve(Script::Xoauth2ErrorChallenge).await;
            let err =
                ImapClient::connect_with("127.0.0.1", port, Security::Plain, token(), &opts())
                    .await
                    .expect_err("rejected");
            let (_, mechanism, code, reply) = rejected(&err);
            assert_eq!(mechanism, AUTH_XOAUTH2);
            assert_eq!(code, Some(&LoginCode::AuthenticationFailed));
            assert_eq!(
                reply,
                format!(
                    "NO [AUTHENTICATIONFAILED] Invalid credentials (Failure); XOAUTH2 error: \
                     {XOAUTH2_ERROR}"
                )
            );
            // The client answered the error challenge with exactly one empty response.
            let lines = seen.lock().expect("lock").clone();
            assert_eq!(lines.last().map(String::as_str), Some(""), "{lines:?}");
            assert_eq!(
                lines.iter().filter(|l| l.is_empty()).count(),
                1,
                "{lines:?}"
            );
        }

        #[tokio::test]
        async fn an_echoed_xoauth2_response_is_redacted() {
            let err = refused(Script::Xoauth2Echo, token()).await;
            let (_, _, _, reply) = rejected(&err);
            assert!(reply.starts_with("NO cannot use [redacted]"), "{reply}");
        }

        #[tokio::test]
        async fn a_bye_greeting_is_not_a_login_rejection() {
            let err = refused(Script::Bye, password()).await;
            assert!(matches!(err, ImapError::Auth(_)), "{err:?}");
        }

        #[tokio::test]
        async fn xoauth2_not_offered_is_not_a_login_rejection() {
            let err = refused(Script::Login("OK never reached"), token()).await;
            assert!(
                matches!(err, ImapError::XOAuth2NotOffered { .. }),
                "{err:?}"
            );
        }

        #[tokio::test]
        async fn a_network_error_is_not_a_login_rejection() {
            let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = closed.local_addr().expect("addr").port();
            drop(closed);
            let err =
                ImapClient::connect_with("127.0.0.1", port, Security::Plain, password(), &opts())
                    .await
                    .expect_err("closed port");
            assert!(matches!(err, ImapError::Connect { .. }), "{err:?}");
        }

        #[test]
        fn async_imap_outcomes_are_split_back_into_code_and_text() {
            assert_eq!(
                split_outcome(
                    r#"code: None, info: Some("[AUTHENTICATIONFAILED] Bad \"pw\" \\ x")"#
                ),
                Some((
                    None,
                    Some(r#"[AUTHENTICATIONFAILED] Bad "pw" \ x"#.to_owned())
                ))
            );
            assert_eq!(
                split_outcome(r#"code: Some(Alert), info: Some("Locked")"#),
                Some((Some("Alert"), Some("Locked".to_owned())))
            );
            assert_eq!(split_outcome("code: None, info: None"), Some((None, None)));
            // Server text that looks like the separator, and escapes Debug produces.
            assert_eq!(
                split_outcome(r#"code: None, info: Some("a, info: Some(\"b\") \u{1b}[31m\t")"#),
                Some((None, Some("a, info: Some(\"b\") \u{1b}[31m\t".to_owned())))
            );
            // Anything else is not async-imap's rendering.
            assert_eq!(split_outcome("LOGIN failed"), None);
            assert_eq!(
                split_outcome(r#"code: None, info: Some("unterminated)"#),
                None
            );
            assert_eq!(
                split_outcome(r#"code: None, info: Some("bad \q escape")"#),
                None
            );
        }
    }

    /// [`ImapClient::connect_pinned`]: the TCP connection goes to the given addresses, the
    /// name keeps deciding the transport policy, the TLS name and the error messages.
    mod pinned_connect {
        use super::super::*;
        use super::login_rejection::{opts, password, serve, Script};

        #[tokio::test]
        async fn connects_to_the_given_address_not_to_what_the_name_resolves_to() {
            // `.test` names never resolve through the system resolver: only the pin can work.
            let (port, seen) = serve(Script::Login("OK LOGIN completed")).await;
            let loopback: IpAddr = "127.0.0.1".parse().expect("ip");
            let client = ImapClient::connect_pinned(
                "imap.pinned.sealbox.test",
                &[loopback],
                port,
                Security::Plain,
                password(),
                &opts(),
            )
            .await
            .expect("pinned connect and login");
            assert_eq!(client.host(), "imap.pinned.sealbox.test");
            client.logout().await.expect("logout");
            let lines = seen.lock().expect("lock").clone();
            assert!(
                lines.iter().any(|l| l.contains(" LOGIN ")),
                "the login reached the pinned server: {lines:?}"
            );
        }

        #[tokio::test]
        async fn the_transport_policy_still_applies_to_the_name() {
            // A public name pinned to loopback is still a public name: no plaintext to it, and
            // nothing is dialled.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let accepted = tokio::spawn(async move {
                tokio::time::timeout(Duration::from_millis(300), listener.accept())
                    .await
                    .is_ok()
            });
            let err = ImapClient::connect_pinned(
                "imap.example.com",
                &["127.0.0.1".parse().expect("ip")],
                port,
                Security::Plain,
                password(),
                &opts(),
            )
            .await
            .expect_err("plain to a public name");
            assert!(matches!(err, ImapError::Policy(_)), "{err:?}");
            assert!(!accepted.await.expect("join"), "a connection was opened");
        }

        #[tokio::test]
        async fn no_address_fails_like_an_unresolvable_host() {
            let err = ImapClient::connect_pinned(
                "imap.pinned.sealbox.test",
                &[],
                993,
                Security::Plain,
                password(),
                &opts(),
            )
            .await
            .expect_err("nothing to dial");
            assert!(matches!(err, ImapError::Connect { .. }), "{err:?}");
        }
    }
}
