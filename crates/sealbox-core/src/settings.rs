//! Per-account and global settings: a small key/value table in the profile database
//! (`settings`: scope, key, JSON value, updated_at) with typed accessors, plus the plain
//! serde models the Flutter bridge mirrors 1:1 ([`AccountSettings`], [`SignatureSettings`],
//! [`AutoReplySettings`]). The auto-reply bookkeeping table (`autoreply_log`) lives here
//! too so that one `SCHEMA` carries everything the settings features need (gates G23/G24).

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use rusqlite::{params, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::signature::sanitize_html;
use crate::store::{now, Store};

/// Tables of the settings features. Executed by `Store::open` after the core schema
/// (idempotent `CREATE TABLE IF NOT EXISTS`).
pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS settings (
    scope      TEXT NOT NULL,
    account    TEXT NOT NULL DEFAULT '',
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (scope, account, key)
);
CREATE TABLE IF NOT EXISTS autoreply_log (
    id           INTEGER PRIMARY KEY,
    account      TEXT NOT NULL COLLATE NOCASE,
    sender       TEXT NOT NULL COLLATE NOCASE,
    period_start INTEGER NOT NULL DEFAULT 0,
    sent_at      INTEGER NOT NULL,
    message_id   TEXT NOT NULL,
    in_reply_to  TEXT,
    original_id  INTEGER,
    encrypted    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS autoreply_log_sender ON autoreply_log(account, sender, sent_at DESC);
"#;

/// Settings key of the signature block.
pub const KEY_SIGNATURE: &str = "signature";
/// Settings key of the auto-reply block.
pub const KEY_AUTOREPLY: &str = "autoreply";
/// Settings key of the auto-reply runtime state (period id + evaluation cursor).
pub(crate) const KEY_AUTOREPLY_STATE: &str = "autoreply_state";
/// Global settings key of the runtime Sealbox server URL ([`Engine::set_server_url`]).
pub const KEY_SERVER_URL: &str = "server_url";

/// Upper bound for a signature (text or HTML), in bytes.
pub const MAX_SIGNATURE_BYTES: usize = 64 * 1024;
/// Upper bound for an auto-reply body, in bytes.
pub const MAX_AUTOREPLY_BODY_BYTES: usize = 64 * 1024;

/// Whether a setting belongs to one account or to the whole profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingsScope {
    Global,
    Account,
}

impl SettingsScope {
    fn as_str(self) -> &'static str {
        match self {
            SettingsScope::Global => "global",
            SettingsScope::Account => "account",
        }
    }

    fn parse(s: &str) -> Self {
        if s == "account" {
            SettingsScope::Account
        } else {
            SettingsScope::Global
        }
    }
}

/// One raw row of the `settings` table (JSON value as stored).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingEntry {
    pub scope: SettingsScope,
    /// Lower-cased account address; empty for global settings.
    pub account: String,
    pub key: String,
    /// The JSON document.
    pub value: serde_json::Value,
    /// Unix seconds.
    pub updated_at: i64,
}

/// Where the signature goes in a reply or forward, relative to the quoted text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignaturePlacement {
    /// Below the new text, above the quote (Gmail/Outlook style). Default.
    #[default]
    AboveQuote,
    /// At the very end, below the quoted text (Thunderbird/mutt style).
    BelowQuote,
}

impl std::str::FromStr for SignaturePlacement {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "above" | "above-quote" | "top" => Ok(SignaturePlacement::AboveQuote),
            "below" | "below-quote" | "bottom" => Ok(SignaturePlacement::BelowQuote),
            other => Err(format!(
                "unknown placement `{other}` (expected above-quote|below-quote)"
            )),
        }
    }
}

/// Which kinds of message get the signature.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureIncludeOn {
    /// Only brand-new messages.
    NewOnly,
    /// New messages and replies, not forwards.
    NewAndReplies,
    /// New messages, replies and forwards. Default.
    #[default]
    All,
}

impl std::str::FromStr for SignatureIncludeOn {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "new" | "new-only" => Ok(SignatureIncludeOn::NewOnly),
            "new-and-replies" | "replies" => Ok(SignatureIncludeOn::NewAndReplies),
            "all" => Ok(SignatureIncludeOn::All),
            other => Err(format!(
                "unknown include-on `{other}` (expected new-only|new-and-replies|all)"
            )),
        }
    }
}

/// The per-account signature (gate G23).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SignatureSettings {
    pub enabled: bool,
    /// Plain-text signature; appended after the `-- ` separator line (RFC 3676 §4.3).
    pub text: String,
    /// Optional HTML signature. Sanitised with [`sanitize_html`] when stored and when
    /// applied; only emitted when the message has an HTML body (a `multipart/alternative`
    /// is produced then).
    pub html: Option<String>,
    pub placement: SignaturePlacement,
    pub include_on: SignatureIncludeOn,
}

impl Default for SignatureSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            text: String::new(),
            html: None,
            placement: SignaturePlacement::AboveQuote,
            include_on: SignatureIncludeOn::All,
        }
    }
}

impl SignatureSettings {
    /// Nothing to apply (disabled or empty).
    pub fn is_empty(&self) -> bool {
        self.text.trim().is_empty() && self.html.as_deref().is_none_or(|h| h.trim().is_empty())
    }

    /// Check limits and normalise: CRLF → LF, trailing whitespace trimmed, HTML sanitised,
    /// an empty HTML string becomes `None`.
    pub fn validate(&mut self) -> Result<()> {
        if self.text.len() > MAX_SIGNATURE_BYTES {
            return Err(Error::InvalidInput(format!(
                "signature text exceeds {MAX_SIGNATURE_BYTES} bytes"
            )));
        }
        self.text = self.text.replace("\r\n", "\n").trim_end().to_string();
        if let Some(h) = self.html.take() {
            if h.len() > MAX_SIGNATURE_BYTES {
                return Err(Error::InvalidInput(format!(
                    "signature HTML exceeds {MAX_SIGNATURE_BYTES} bytes"
                )));
            }
            let clean = sanitize_html(&h);
            if !clean.trim().is_empty() {
                self.html = Some(clean);
            }
        }
        Ok(())
    }
}

/// Default subject template of auto-replies; `{subject}` is the original subject.
pub const DEFAULT_AUTOREPLY_SUBJECT: &str = "Automatic reply: {subject}";

/// Holiday / out-of-office auto-reply (RFC 3834; gate G24).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoReplySettings {
    pub enabled: bool,
    /// Start of the absence (inclusive); `None` = active as soon as enabled.
    pub start: Option<DateTime<Utc>>,
    /// End of the absence (exclusive); `None` = until disabled.
    pub end: Option<DateTime<Utc>>,
    /// `{subject}` is replaced by the original message's subject.
    pub subject_template: String,
    pub body: String,
    /// A sender gets at most one reply per this many days within one vacation period;
    /// `0` = at most one reply per vacation period.
    pub reply_once_per_sender_days: u32,
    /// Encrypt + sign the reply when the sender has a usable key, else send plaintext.
    /// `false` = always plaintext.
    pub encrypt_when_possible: bool,
    /// Only answer people this account has written to before, or whose key was imported.
    pub only_to_known_contacts: bool,
}

impl Default for AutoReplySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            start: None,
            end: None,
            subject_template: DEFAULT_AUTOREPLY_SUBJECT.to_string(),
            body: String::new(),
            reply_once_per_sender_days: 7,
            encrypt_when_possible: true,
            only_to_known_contacts: false,
        }
    }
}

impl AutoReplySettings {
    /// Is the responder active right now (enabled and inside the window)?
    pub fn is_active_now(&self) -> bool {
        self.is_active_at(Utc::now())
    }

    /// Is the responder active at `now` (enabled and inside the window)?
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.enabled && self.start.is_none_or(|s| now >= s) && self.end.is_none_or(|e| now < e)
    }

    /// Check limits and normalise (empty template → default, CRLF → LF).
    pub fn validate(&mut self) -> Result<()> {
        if let (Some(s), Some(e)) = (self.start, self.end) {
            if e <= s {
                return Err(Error::InvalidInput(
                    "auto-reply: the end of the absence must be after its start".into(),
                ));
            }
        }
        if self.body.len() > MAX_AUTOREPLY_BODY_BYTES {
            return Err(Error::InvalidInput(format!(
                "auto-reply body exceeds {MAX_AUTOREPLY_BODY_BYTES} bytes"
            )));
        }
        if self.subject_template.trim().is_empty() {
            self.subject_template = DEFAULT_AUTOREPLY_SUBJECT.to_string();
        }
        if self
            .subject_template
            .chars()
            .any(|c| c.is_control() && c != '\t')
        {
            return Err(Error::InvalidInput(
                "auto-reply subject template must be a single line".into(),
            ));
        }
        self.body = self.body.replace("\r\n", "\n");
        if self.enabled && self.body.trim().is_empty() {
            return Err(Error::InvalidInput(
                "auto-reply: a message body is required to enable the responder".into(),
            ));
        }
        Ok(())
    }

    /// The subject of a reply to a message with `original_subject`.
    pub fn render_subject(&self, original_subject: Option<&str>) -> String {
        let orig = original_subject
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("(no subject)");
        let template = if self.subject_template.trim().is_empty() {
            DEFAULT_AUTOREPLY_SUBJECT
        } else {
            self.subject_template.as_str()
        };
        template.replace("{subject}", orig)
    }
}

/// Everything configurable per account.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountSettings {
    pub signature: SignatureSettings,
    pub autoreply: AutoReplySettings,
}

/// Runtime state of the auto-responder, per account (internal; not a user setting).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct AutoReplyState {
    /// Identifies the vacation period for the once-per-sender rule (unix seconds).
    pub period_start: i64,
    /// Highest local message id already evaluated; messages at or below are never
    /// (re)considered.
    pub cursor: i64,
}

/// One sent auto-reply (`sealbox settings autoreply log`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoReplyLogEntry {
    pub id: i64,
    pub account: String,
    pub sender: String,
    /// Start of the vacation period the reply belongs to (unix seconds).
    pub period_start: i64,
    /// Unix seconds.
    pub sent_at: i64,
    /// Message-ID of the reply we sent.
    pub message_id: String,
    /// Message-ID of the message answered.
    #[serde(default)]
    pub in_reply_to: Option<String>,
    /// Local id of the message answered.
    #[serde(default)]
    pub original_id: Option<i64>,
    pub encrypted: bool,
}

/// Parse a date/time given by a user: RFC 3339 (`2026-10-27T08:00:00Z`, with offset),
/// `YYYY-MM-DD HH:MM[:SS]` (UTC) or `YYYY-MM-DD` (midnight UTC).
pub fn parse_datetime(s: &str) -> std::result::Result<DateTime<Utc>, String> {
    let s = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Ok(naive.and_utc());
        }
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(d.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc());
    }
    Err(format!(
        "`{s}` is not a date/time (use 2026-10-27, 2026-10-27 08:00 or 2026-10-27T08:00:00Z)"
    ))
}

// ----- store ----------------------------------------------------------------------------

impl Store {
    pub(crate) fn get_setting_raw(
        &self,
        scope: SettingsScope,
        account: &str,
        key: &str,
    ) -> Result<Option<(String, i64)>> {
        let account = account.trim().to_ascii_lowercase();
        let row = self
            .conn()
            .query_row(
                "SELECT value, updated_at FROM settings WHERE scope = ?1 AND account = ?2 AND key = ?3",
                params![scope.as_str(), account, key],
                |r| Ok((r.get::<_, rusqlite::types::Value>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()?;
        row.map(|(v, t)| {
            Ok((
                self.open_setting_value(scope.as_str(), &account, key, v)?,
                t,
            ))
        })
        .transpose()
    }

    /// `secret.*` settings are wrapped at rest (G27, vault.rs); others are plain JSON text.
    fn open_setting_value(
        &self,
        scope: &str,
        account: &str,
        key: &str,
        v: rusqlite::types::Value,
    ) -> Result<String> {
        if crate::vault::is_secret_setting(key) {
            let id = crate::vault::settings_rowid(scope, account, key);
            return self.vault().open_text("settings", "value", &id, v);
        }
        match v {
            rusqlite::types::Value::Text(t) => Ok(t),
            other => Err(Error::InvalidInput(format!(
                "setting {key}: unexpected {:?}",
                other.data_type()
            ))),
        }
    }

    pub(crate) fn set_setting_raw(
        &self,
        scope: SettingsScope,
        account: &str,
        key: &str,
        value_json: &str,
    ) -> Result<()> {
        let account_lc = account.trim().to_ascii_lowercase();
        let value = if crate::vault::is_secret_setting(key) {
            let id = crate::vault::settings_rowid(scope.as_str(), &account_lc, key);
            self.vault()
                .seal_text("settings", "value", &id, value_json)?
        } else {
            rusqlite::types::Value::Text(value_json.to_string())
        };
        self.conn().execute(
            "INSERT INTO settings (scope, account, key, value, updated_at) VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(scope, account, key) DO UPDATE SET value = excluded.value, \
             updated_at = excluded.updated_at",
            params![scope.as_str(), account_lc, key, value, now()],
        )?;
        Ok(())
    }

    pub(crate) fn delete_setting(
        &self,
        scope: SettingsScope,
        account: &str,
        key: &str,
    ) -> Result<bool> {
        let n = self.conn().execute(
            "DELETE FROM settings WHERE scope = ?1 AND account = ?2 AND key = ?3",
            params![scope.as_str(), account.trim().to_ascii_lowercase(), key],
        )?;
        Ok(n > 0)
    }

    pub(crate) fn list_settings(
        &self,
        scope: SettingsScope,
        account: &str,
    ) -> Result<Vec<SettingEntry>> {
        let mut stmt = self.conn().prepare(
            "SELECT scope, account, key, value, updated_at FROM settings \
             WHERE scope = ?1 AND account = ?2 ORDER BY key",
        )?;
        let rows = stmt.query_map(
            params![scope.as_str(), account.trim().to_ascii_lowercase()],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, rusqlite::types::Value>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (scope, account, key, value, updated_at) = row?;
            let value = self.open_setting_value(&scope, &account, &key, value)?;
            out.push(SettingEntry {
                scope: SettingsScope::parse(&scope),
                account,
                key,
                value: serde_json::from_str(&value).unwrap_or(serde_json::Value::Null),
                updated_at,
            });
        }
        Ok(out)
    }

    /// Typed read; `Ok(None)` when unset.
    pub(crate) fn get_setting<T: DeserializeOwned>(
        &self,
        scope: SettingsScope,
        account: &str,
        key: &str,
    ) -> Result<Option<T>> {
        match self.get_setting_raw(scope, account, key)? {
            Some((json, _)) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    /// Typed write.
    pub(crate) fn set_setting<T: Serialize>(
        &self,
        scope: SettingsScope,
        account: &str,
        key: &str,
        value: &T,
    ) -> Result<()> {
        self.set_setting_raw(scope, account, key, &serde_json::to_string(value)?)
    }

    // ----- auto-reply bookkeeping ---------------------------------------------------------

    /// Record a sent auto-reply.
    pub(crate) fn insert_autoreply_log(&self, e: &AutoReplyLogEntry) -> Result<i64> {
        self.conn().execute(
            "INSERT INTO autoreply_log (account, sender, period_start, sent_at, message_id, \
             in_reply_to, original_id, encrypted) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                e.account.to_ascii_lowercase(),
                e.sender.to_ascii_lowercase(),
                e.period_start,
                e.sent_at,
                e.message_id,
                e.in_reply_to,
                e.original_id,
                e.encrypted
            ],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Has `sender` already received a reply from `account` in this vacation period at or
    /// after `since` (unix seconds)?
    pub(crate) fn autoreply_sent_since(
        &self,
        account: &str,
        sender: &str,
        period_start: i64,
        since: i64,
    ) -> Result<bool> {
        let n: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM autoreply_log WHERE account = ?1 AND sender = ?2 \
             AND period_start = ?3 AND sent_at >= ?4",
            params![
                account.to_ascii_lowercase(),
                sender.to_ascii_lowercase(),
                period_start,
                since
            ],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Newest first.
    pub(crate) fn autoreply_log(
        &self,
        account: &str,
        limit: usize,
    ) -> Result<Vec<AutoReplyLogEntry>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, account, sender, period_start, sent_at, message_id, in_reply_to, \
             original_id, encrypted FROM autoreply_log WHERE account = ?1 \
             ORDER BY sent_at DESC, id DESC LIMIT ?2",
        )?;
        let limit = i64::try_from(if limit == 0 { 100 } else { limit }).unwrap_or(100);
        let rows = stmt.query_map(params![account.to_ascii_lowercase(), limit], |r| {
            Ok(AutoReplyLogEntry {
                id: r.get(0)?,
                account: r.get(1)?,
                sender: r.get(2)?,
                period_start: r.get(3)?,
                sent_at: r.get(4)?,
                message_id: r.get(5)?,
                in_reply_to: r.get(6)?,
                original_id: r.get(7)?,
                encrypted: r.get::<_, bool>(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Highest local message id of an account (0 when it has none).
    pub(crate) fn max_message_id(&self, account_id: i64) -> Result<i64> {
        Ok(self.conn().query_row(
            "SELECT COALESCE(MAX(id), 0) FROM messages WHERE account_id = ?1",
            params![account_id],
            |r| r.get(0),
        )?)
    }

    /// Local ids of INBOX messages of an account above `after_id`, ascending.
    pub(crate) fn inbox_message_ids_after(
        &self,
        account_id: i64,
        after_id: i64,
    ) -> Result<Vec<i64>> {
        let mut stmt = self.conn().prepare(
            "SELECT m.id FROM messages m JOIN folders f ON f.id = m.folder_id \
             WHERE m.account_id = ?1 AND m.id > ?2 AND f.name = 'INBOX' COLLATE NOCASE \
             ORDER BY m.id",
        )?;
        let rows = stmt.query_map(params![account_id, after_id], |r| r.get::<_, i64>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Did this account ever send something to `addr` (outbox, state `sent`)?
    pub(crate) fn has_sent_to(&self, account_id: i64, addr: &str) -> Result<bool> {
        let needle = format!(
            "%\"{}\"%",
            addr.trim().to_ascii_lowercase().replace('"', "")
        );
        let n: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM outbox WHERE account_id = ?1 AND state = 'sent' \
             AND LOWER(recipients_json) LIKE ?2",
            params![account_id, needle],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }
}

// ----- engine ---------------------------------------------------------------------------

impl Engine {
    /// All settings of an account (defaults for anything unset).
    pub fn get_settings(&self, account: &str) -> Result<AccountSettings> {
        let acct = self.account_row(account)?;
        let store = self.store();
        Ok(AccountSettings {
            signature: store
                .get_setting(SettingsScope::Account, &acct.email, KEY_SIGNATURE)?
                .unwrap_or_default(),
            autoreply: store
                .get_setting(SettingsScope::Account, &acct.email, KEY_AUTOREPLY)?
                .unwrap_or_default(),
        })
    }

    /// Replace all settings of an account (validated).
    pub fn set_settings(
        &self,
        account: &str,
        settings: AccountSettings,
    ) -> Result<AccountSettings> {
        let signature = self.set_signature(account, settings.signature)?;
        let autoreply = self.set_autoreply(account, settings.autoreply)?;
        Ok(AccountSettings {
            signature,
            autoreply,
        })
    }

    /// The account's signature settings.
    pub fn get_signature(&self, account: &str) -> Result<SignatureSettings> {
        let acct = self.account_row(account)?;
        Ok(self
            .store()
            .get_setting(SettingsScope::Account, &acct.email, KEY_SIGNATURE)?
            .unwrap_or_default())
    }

    /// Store the signature (validated and sanitised); returns what was stored.
    pub fn set_signature(
        &self,
        account: &str,
        mut settings: SignatureSettings,
    ) -> Result<SignatureSettings> {
        let acct = self.account_row(account)?;
        settings.validate()?;
        self.store().set_setting(
            SettingsScope::Account,
            &acct.email,
            KEY_SIGNATURE,
            &settings,
        )?;
        Ok(settings)
    }

    /// The account's auto-reply settings.
    pub fn get_autoreply(&self, account: &str) -> Result<AutoReplySettings> {
        let acct = self.account_row(account)?;
        Ok(self
            .store()
            .get_setting(SettingsScope::Account, &acct.email, KEY_AUTOREPLY)?
            .unwrap_or_default())
    }

    /// Store the auto-reply settings (validated). Switching the responder on, or changing
    /// the start of the absence, starts a new vacation period: the once-per-sender rule
    /// resets and only mail arriving from now on is considered.
    pub fn set_autoreply(
        &self,
        account: &str,
        mut settings: AutoReplySettings,
    ) -> Result<AutoReplySettings> {
        let acct = self.account_row(account)?;
        settings.validate()?;
        let store = self.store();
        let previous: AutoReplySettings = store
            .get_setting(SettingsScope::Account, &acct.email, KEY_AUTOREPLY)?
            .unwrap_or_default();
        let mut state: AutoReplyState = store
            .get_setting(SettingsScope::Account, &acct.email, KEY_AUTOREPLY_STATE)?
            .unwrap_or_default();
        let new_period =
            settings.enabled && (!previous.enabled || previous.start != settings.start);
        if new_period {
            state.period_start = settings.start.map(|s| s.timestamp()).unwrap_or_else(now);
            state.cursor = store.max_message_id(acct.id)?;
            store.set_setting(
                SettingsScope::Account,
                &acct.email,
                KEY_AUTOREPLY_STATE,
                &state,
            )?;
        }
        store.set_setting(
            SettingsScope::Account,
            &acct.email,
            KEY_AUTOREPLY,
            &settings,
        )?;
        Ok(settings)
    }

    pub(crate) fn autoreply_state(&self, account_email: &str) -> Result<AutoReplyState> {
        Ok(self
            .store()
            .get_setting(SettingsScope::Account, account_email, KEY_AUTOREPLY_STATE)?
            .unwrap_or_default())
    }

    pub(crate) fn save_autoreply_state(
        &self,
        account_email: &str,
        state: &AutoReplyState,
    ) -> Result<()> {
        self.store().set_setting(
            SettingsScope::Account,
            account_email,
            KEY_AUTOREPLY_STATE,
            state,
        )
    }

    /// Sent auto-replies of an account, newest first (`limit` 0 = 100).
    pub fn autoreply_log(&self, account: &str, limit: usize) -> Result<Vec<AutoReplyLogEntry>> {
        let acct = self.account_row(account)?;
        self.store().autoreply_log(&acct.email, limit)
    }

    /// A global (profile-wide) setting as JSON; `Ok(None)` when unset.
    pub fn get_global_setting(&self, key: &str) -> Result<Option<serde_json::Value>> {
        self.store()
            .get_setting(SettingsScope::Global, "", validate_key(key)?)
    }

    /// Store a global setting (any JSON document).
    pub fn set_global_setting(&self, key: &str, value: &serde_json::Value) -> Result<()> {
        self.store()
            .set_setting(SettingsScope::Global, "", validate_key(key)?, value)
    }

    /// Remove a global setting; `Ok(false)` when it was not set.
    pub fn delete_global_setting(&self, key: &str) -> Result<bool> {
        self.store()
            .delete_setting(SettingsScope::Global, "", validate_key(key)?)
    }

    // ----- Sealbox server URL -------------------------------------------------------------

    /// Set (or, with `None`, clear) the Sealbox server used for the key directory, guest
    /// links, backups and the key-transparency log. Persisted in the global settings, so it
    /// survives restarts and wins over `SEALBOX_SERVER_URL`; a trailing slash is dropped.
    /// Returns the effective URL afterwards ([`Engine::server_url`]).
    pub fn set_server_url(&self, url: Option<String>) -> Result<Option<String>> {
        match url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            Some(u) => {
                let clean = u.trim_end_matches('/');
                if !(clean.starts_with("http://") || clean.starts_with("https://"))
                    || clean.len() <= "https://".len()
                {
                    return Err(Error::InvalidInput(format!(
                        "server URL must be http(s)://host[:port], got `{u}`"
                    )));
                }
                self.set_global_setting(KEY_SERVER_URL, &serde_json::Value::String(clean.into()))?;
            }
            None => {
                self.delete_global_setting(KEY_SERVER_URL)?;
            }
        }
        Ok(self.server_url())
    }

    /// The Sealbox server URL every server-side feature uses: the runtime override stored by
    /// [`Engine::set_server_url`], else `SEALBOX_SERVER_URL` from the environment the engine
    /// was opened with. `None` = no server (guest links, backups and publishing refuse with
    /// [`Error::ServerNotConfigured`] / [`Error::Guest`]).
    pub fn server_url(&self) -> Option<String> {
        let stored = self
            .get_global_setting(KEY_SERVER_URL)
            .ok()
            .flatten()
            .and_then(|v| {
                v.as_str()
                    .map(|s| s.trim().trim_end_matches('/').to_owned())
            })
            .filter(|s| !s.is_empty());
        stored.or_else(|| {
            self.config()
                .server_url
                .as_deref()
                .map(|s| s.trim().trim_end_matches('/').to_owned())
                .filter(|s| !s.is_empty())
        })
    }

    /// Base URL of the key directory (VKS `/vks/v1/*`, key-transparency `/v1/kt/*`): an
    /// explicit `SEALBOX_DIRECTORY_URL`, else the Sealbox server ([`Engine::server_url`]),
    /// which hosts the directory too.
    pub fn directory_url(&self) -> Option<String> {
        self.config()
            .directory_url
            .as_deref()
            .map(|s| s.trim().trim_end_matches('/').to_owned())
            .filter(|s| !s.is_empty())
            .or_else(|| self.server_url())
    }

    /// Where the effective server URL comes from: `settings`, `environment` or `none`.
    pub fn server_url_source(&self) -> &'static str {
        let stored = self
            .get_global_setting(KEY_SERVER_URL)
            .ok()
            .flatten()
            .and_then(|v| v.as_str().map(str::to_owned))
            .is_some_and(|s| !s.trim().is_empty());
        if stored {
            "settings"
        } else if self
            .config()
            .server_url
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
        {
            "environment"
        } else {
            "none"
        }
    }

    /// Every stored setting of one scope (raw JSON), for debugging and backups.
    pub fn list_settings(
        &self,
        scope: SettingsScope,
        account: Option<&str>,
    ) -> Result<Vec<SettingEntry>> {
        let account = match (scope, account) {
            (SettingsScope::Account, Some(a)) => self.account_row(a)?.email,
            (SettingsScope::Account, None) => {
                return Err(Error::InvalidInput(
                    "an account is required for account-scoped settings".into(),
                ))
            }
            (SettingsScope::Global, _) => String::new(),
        };
        self.store().list_settings(scope, &account)
    }
}

fn validate_key(key: &str) -> Result<&str> {
    let key = key.trim();
    if key.is_empty()
        || key.len() > 64
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(Error::InvalidInput(format!(
            "invalid settings key `{key}` (use letters, digits, `_`, `.`, `-`)"
        )));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;
    use crate::store::NewAccount;
    use crate::types::AuthKind;
    use chrono::TimeZone;
    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::Security;

    fn engine_with_account(email: &str) -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        engine
            .store()
            .insert_account(&NewAccount {
                email,
                display_name: "Test",
                imap: &Endpoint::new("127.0.0.1", 143, Security::Plain),
                smtp: &Endpoint::new("127.0.0.1", 25, Security::Plain),
                auth_kind: AuthKind::Password,
                login: "t",
                credential: "pw",
            })
            .unwrap();
        (dir, engine)
    }

    #[test]
    fn raw_settings_roundtrip_and_scopes() {
        let store = Store::open_in_memory().unwrap();
        assert!(store
            .get_setting_raw(SettingsScope::Global, "", "x")
            .unwrap()
            .is_none());
        store
            .set_setting_raw(SettingsScope::Global, "", "x", "{\"a\":1}")
            .unwrap();
        store
            .set_setting_raw(
                SettingsScope::Account,
                "Alice@Example.org",
                "x",
                "{\"a\":2}",
            )
            .unwrap();
        let (g, ts) = store
            .get_setting_raw(SettingsScope::Global, "", "x")
            .unwrap()
            .unwrap();
        assert_eq!(g, "{\"a\":1}");
        assert!(ts > 0);
        // account scope is case-insensitive and separate from global
        let (a, _) = store
            .get_setting_raw(SettingsScope::Account, "alice@example.org", "x")
            .unwrap()
            .unwrap();
        assert_eq!(a, "{\"a\":2}");
        // upsert
        store
            .set_setting_raw(SettingsScope::Global, "", "x", "{\"a\":3}")
            .unwrap();
        let list = store.list_settings(SettingsScope::Global, "").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].value["a"], 3);
        assert_eq!(list[0].scope, SettingsScope::Global);
        assert!(store
            .delete_setting(SettingsScope::Global, "", "x")
            .unwrap());
        assert!(!store
            .delete_setting(SettingsScope::Global, "", "x")
            .unwrap());
        let acct_list = store
            .list_settings(SettingsScope::Account, "ALICE@example.org")
            .unwrap();
        assert_eq!(acct_list.len(), 1);
        assert_eq!(acct_list[0].account, "alice@example.org");
    }

    #[test]
    fn typed_signature_and_autoreply_roundtrip_through_engine() {
        let (_dir, engine) = engine_with_account("alice@example.org");
        let defaults = engine.get_settings("alice@example.org").unwrap();
        assert_eq!(defaults, AccountSettings::default());
        assert!(!defaults.signature.enabled);
        assert_eq!(defaults.autoreply.reply_once_per_sender_days, 7);
        assert!(defaults.autoreply.encrypt_when_possible);
        assert!(!defaults.autoreply.only_to_known_contacts);
        assert_eq!(
            defaults.autoreply.subject_template,
            DEFAULT_AUTOREPLY_SUBJECT
        );
        assert!(matches!(
            engine.get_settings("nobody@example.org"),
            Err(Error::AccountNotFound(_))
        ));

        let stored = engine
            .set_signature(
                "Alice@Example.org",
                SignatureSettings {
                    enabled: true,
                    text: "Alice\r\nExample Corp  \r\n".into(),
                    html: Some("<b>Alice</b><script>alert(1)</script>".into()),
                    placement: SignaturePlacement::BelowQuote,
                    include_on: SignatureIncludeOn::NewOnly,
                },
            )
            .unwrap();
        assert_eq!(stored.text, "Alice\nExample Corp");
        assert_eq!(stored.html.as_deref(), Some("<b>Alice</b>"));
        let back = engine.get_signature("alice@example.org").unwrap();
        assert_eq!(back, stored);
        assert_eq!(back.placement, SignaturePlacement::BelowQuote);
        assert_eq!(back.include_on, SignatureIncludeOn::NewOnly);

        // JSON shape is stable for the bridge.
        let json = serde_json::to_value(&back).unwrap();
        assert_eq!(json["placement"], "below_quote");
        assert_eq!(json["include_on"], "new_only");
        let partial: SignatureSettings = serde_json::from_str("{\"enabled\":true}").unwrap();
        assert_eq!(partial.include_on, SignatureIncludeOn::All);

        let start = Utc.with_ymd_and_hms(2026, 12, 20, 0, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2027, 1, 3, 0, 0, 0).unwrap();
        let ar = engine
            .set_autoreply(
                "alice@example.org",
                AutoReplySettings {
                    enabled: true,
                    start: Some(start),
                    end: Some(end),
                    subject_template: "   ".into(),
                    body: "Away.\r\nBack in January.".into(),
                    reply_once_per_sender_days: 3,
                    encrypt_when_possible: false,
                    only_to_known_contacts: true,
                },
            )
            .unwrap();
        assert_eq!(ar.subject_template, DEFAULT_AUTOREPLY_SUBJECT);
        assert_eq!(ar.body, "Away.\nBack in January.");
        let back = engine.get_autoreply("alice@example.org").unwrap();
        assert_eq!(back, ar);
        assert!(!back.is_active_at(start - chrono::Duration::seconds(1)));
        assert!(back.is_active_at(start));
        assert!(back.is_active_at(end - chrono::Duration::seconds(1)));
        assert!(!back.is_active_at(end));
        assert_eq!(back.render_subject(Some("hello")), "Automatic reply: hello");
        assert_eq!(back.render_subject(None), "Automatic reply: (no subject)");
        let json = serde_json::to_value(&back).unwrap();
        assert_eq!(json["start"], "2026-12-20T00:00:00Z");
        let all = engine.get_settings("alice@example.org").unwrap();
        assert_eq!(all.autoreply, ar);
        assert_eq!(all.signature, stored);

        // A new period was opened with the window start as its id.
        let state = engine.autoreply_state("alice@example.org").unwrap();
        assert_eq!(state.period_start, start.timestamp());
        // Re-saving with the same start keeps the period; a new start opens a new one.
        engine
            .set_autoreply("alice@example.org", back.clone())
            .unwrap();
        assert_eq!(engine.autoreply_state("alice@example.org").unwrap(), state);
        let mut moved = back.clone();
        moved.start = Some(start + chrono::Duration::days(1));
        engine.set_autoreply("alice@example.org", moved).unwrap();
        assert_eq!(
            engine
                .autoreply_state("alice@example.org")
                .unwrap()
                .period_start,
            (start + chrono::Duration::days(1)).timestamp()
        );

        // Validation.
        assert!(matches!(
            engine.set_autoreply(
                "alice@example.org",
                AutoReplySettings {
                    enabled: true,
                    start: Some(end),
                    end: Some(start),
                    body: "x".into(),
                    ..AutoReplySettings::default()
                }
            ),
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(
            engine.set_autoreply(
                "alice@example.org",
                AutoReplySettings {
                    enabled: true,
                    body: "  ".into(),
                    ..AutoReplySettings::default()
                }
            ),
            Err(Error::InvalidInput(_))
        ));
        let disabled = engine
            .set_autoreply(
                "alice@example.org",
                AutoReplySettings {
                    enabled: false,
                    body: String::new(),
                    ..AutoReplySettings::default()
                },
            )
            .unwrap();
        assert!(!disabled.enabled);

        // set_settings replaces both blocks.
        let replaced = engine
            .set_settings("alice@example.org", AccountSettings::default())
            .unwrap();
        assert_eq!(replaced, AccountSettings::default());
        assert_eq!(
            engine.get_settings("alice@example.org").unwrap(),
            AccountSettings::default()
        );
    }

    #[test]
    fn global_settings_and_key_validation() {
        let (_dir, engine) = engine_with_account("alice@example.org");
        assert!(engine.get_global_setting("theme").unwrap().is_none());
        engine
            .set_global_setting("theme", &serde_json::json!({"mode": "dark"}))
            .unwrap();
        assert_eq!(
            engine.get_global_setting("theme").unwrap().unwrap()["mode"],
            "dark"
        );
        assert!(matches!(
            engine.set_global_setting("bad key", &serde_json::json!(1)),
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(
            engine.get_global_setting(""),
            Err(Error::InvalidInput(_))
        ));
        let listed = engine.list_settings(SettingsScope::Global, None).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key, "theme");
        assert!(matches!(
            engine.list_settings(SettingsScope::Account, None),
            Err(Error::InvalidInput(_))
        ));
        assert!(engine.delete_global_setting("theme").unwrap());
        assert!(!engine.delete_global_setting("theme").unwrap());
    }

    #[test]
    fn autoreply_log_roundtrip() {
        let store = Store::open_in_memory().unwrap();
        let entry = AutoReplyLogEntry {
            id: 0,
            account: "Alice@Example.org".into(),
            sender: "Bob@Example.org".into(),
            period_start: 100,
            sent_at: 1_000,
            message_id: "r1@example.org".into(),
            in_reply_to: Some("m1@example.org".into()),
            original_id: Some(7),
            encrypted: true,
        };
        store.insert_autoreply_log(&entry).unwrap();
        assert!(store
            .autoreply_sent_since("alice@example.org", "bob@example.org", 100, 900)
            .unwrap());
        assert!(!store
            .autoreply_sent_since("alice@example.org", "bob@example.org", 100, 1_001)
            .unwrap());
        // a different vacation period does not count
        assert!(!store
            .autoreply_sent_since("alice@example.org", "bob@example.org", 200, 0)
            .unwrap());
        assert!(!store
            .autoreply_sent_since("alice@example.org", "carol@example.org", 100, 0)
            .unwrap());
        let log = store.autoreply_log("ALICE@example.org", 10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].sender, "bob@example.org");
        assert_eq!(log[0].original_id, Some(7));
        assert!(log[0].encrypted);
        assert!(store
            .autoreply_log("nobody@example.org", 0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn datetime_parsing() {
        assert_eq!(
            parse_datetime("2026-10-27T08:00:00Z").unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 27, 8, 0, 0).unwrap()
        );
        assert_eq!(
            parse_datetime("2026-10-27T10:00:00+02:00").unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 27, 8, 0, 0).unwrap()
        );
        assert_eq!(
            parse_datetime("2026-10-27 08:30").unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 27, 8, 30, 0).unwrap()
        );
        assert_eq!(
            parse_datetime(" 2026-10-27 ").unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 27, 0, 0, 0).unwrap()
        );
        assert!(parse_datetime("tomorrow").is_err());
        assert!(parse_datetime("2026-13-01").is_err());
    }

    #[test]
    fn placement_and_include_on_parse() {
        assert_eq!(
            "below-quote".parse::<SignaturePlacement>().unwrap(),
            SignaturePlacement::BelowQuote
        );
        assert_eq!(
            "ABOVE_QUOTE".parse::<SignaturePlacement>().unwrap(),
            SignaturePlacement::AboveQuote
        );
        assert!("middle".parse::<SignaturePlacement>().is_err());
        assert_eq!(
            "new-and-replies".parse::<SignatureIncludeOn>().unwrap(),
            SignatureIncludeOn::NewAndReplies
        );
        assert_eq!(
            "new_only".parse::<SignatureIncludeOn>().unwrap(),
            SignatureIncludeOn::NewOnly
        );
        assert!("sometimes".parse::<SignatureIncludeOn>().is_err());
    }
}
