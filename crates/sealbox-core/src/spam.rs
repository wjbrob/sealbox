//! Spam detection inside the engine (gate G25): per-account [`SpamSettings`], the sync hook
//! that classifies every new INBOX message, moves spam to the provider's junk folder
//! (never deletes), stores the verdict on the message row, applies the user's filter rules
//! (`filters.rs`), and the feedback API (`spam_learn`, `spam_explain`, `spam_status`).
//!
//! The classifier itself lives in `sealbox-spam`; this module owns persistence (the per-user
//! Bayes model, the verdict columns), the IMAP side effects and the policy around them:
//!
//! * our own sent mail is never classified;
//! * `allowlist` / `blocklist` entries (addresses or domains) force the label;
//! * a message that decrypted with a **good** signature from a known contact is ham;
//! * DNSBL lookups run only when `dnsbl_enabled` (off by default — privacy, see `docs/SPAM.md`).

use std::collections::BTreeSet;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};
use sealbox_mail::imap::{FlagOp as ImapFlagOp, FolderRole, ImapClient};
use sealbox_spam::dnsbl::{self, DnsblConfig, HickoryResolver};
use sealbox_spam::eval::{self, EvalOptions, EvalReport};
use sealbox_spam::features::{self, AuthResults, Features};
use sealbox_spam::filters::{apply_rules, FilterOutcome, MessageFacts};
use sealbox_spam::{
    BayesModel, Classifier, Reason, RuleContext, RuleHit, SpamLabel, Thresholds, Verdict,
};

use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::settings::SettingsScope;
use crate::store::{now, AccountRow, FolderRow, MessageRow, Store};
use crate::types::SigState;

/// Settings key in the per-account settings table.
const SETTINGS_KEY: &str = "spam";
/// Default junk folder name when the server has none and the user set nothing.
pub const DEFAULT_SPAM_FOLDER: &str = "Spam";

/// Idempotent schema additions for spam + filters (called from `Store::open`).
pub(crate) fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS spam_model (
            id         INTEGER PRIMARY KEY CHECK (id = 1),
            model_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS filter_rules (
            id         INTEGER PRIMARY KEY,
            account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            ord        INTEGER NOT NULL DEFAULT 0,
            enabled    INTEGER NOT NULL DEFAULT 1,
            json       TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS filter_rules_account ON filter_rules(account_id, ord, id);",
    )?;
    let existing: BTreeSet<String> = {
        let mut stmt = conn.prepare("PRAGMA table_info(messages)")?;
        let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
        names.collect::<rusqlite::Result<_>>()?
    };
    for (col, ty) in [
        ("spam_score", "REAL"),
        ("spam_label", "TEXT"),
        ("spam_reasons_json", "TEXT"),
        ("spam_learned", "TEXT"),
    ] {
        if !existing.contains(col) {
            conn.execute(&format!("ALTER TABLE messages ADD COLUMN {col} {ty}"), [])?;
        }
    }
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS messages_spam_label ON messages(account_id, spam_label);",
    )?;
    Ok(())
}

fn default_true() -> bool {
    true
}
fn default_unsure() -> f64 {
    0.5
}
fn default_spam() -> f64 {
    0.9
}
fn default_folder() -> String {
    DEFAULT_SPAM_FOLDER.to_string()
}

/// Per-account spam settings (stored in the settings table under key `spam`).
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SpamSettings {
    /// Classify incoming mail at all.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Probability from which a message is shown as "unsure".
    #[serde(default = "default_unsure")]
    pub unsure_threshold: f64,
    /// Probability from which a message is spam and moved.
    #[serde(default = "default_spam")]
    pub spam_threshold: f64,
    /// Query Spamhaus ZEN/DBL through DNS. Reveals sender IPs and link domains to the
    /// resolver, hence off by default.
    #[serde(default)]
    pub dnsbl_enabled: bool,
    /// Folder spam is moved to. The default `Spam` means "the server's junk folder
    /// (`\Junk` / provider name), creating `Spam` when there is none".
    #[serde(default = "default_folder")]
    pub move_to_folder: String,
    /// Senders (addresses or domains) that are never spam.
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Senders (addresses or domains) that are always spam.
    #[serde(default)]
    pub blocklist: Vec<String>,
}

impl Default for SpamSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            unsure_threshold: default_unsure(),
            spam_threshold: default_spam(),
            dnsbl_enabled: false,
            move_to_folder: default_folder(),
            allowlist: Vec::new(),
            blocklist: Vec::new(),
        }
    }
}

impl SpamSettings {
    /// Normalise and check: thresholds inside (0,1) with `unsure ≤ spam`, non-empty folder,
    /// lower-cased deduplicated lists.
    pub fn validate(&mut self) -> Result<()> {
        for (name, v) in [
            ("unsure_threshold", self.unsure_threshold),
            ("spam_threshold", self.spam_threshold),
        ] {
            if !v.is_finite() || !(0.0..=1.0).contains(&v) {
                return Err(Error::InvalidInput(format!(
                    "{name} must be between 0 and 1"
                )));
            }
        }
        if self.unsure_threshold > self.spam_threshold {
            return Err(Error::InvalidInput(
                "unsure_threshold must not exceed spam_threshold".into(),
            ));
        }
        self.move_to_folder = self.move_to_folder.trim().to_string();
        if self.move_to_folder.is_empty() {
            return Err(Error::InvalidInput(
                "move_to_folder must not be empty".into(),
            ));
        }
        if self.move_to_folder.eq_ignore_ascii_case("INBOX") {
            return Err(Error::InvalidInput("move_to_folder cannot be INBOX".into()));
        }
        for list in [&mut self.allowlist, &mut self.blocklist] {
            let mut clean: Vec<String> = Vec::new();
            for e in list.iter() {
                let e = e.trim().trim_start_matches('@').to_ascii_lowercase();
                if e.is_empty() || e.contains(char::is_whitespace) {
                    return Err(Error::InvalidInput(format!(
                        "`{e}` is not an address or domain"
                    )));
                }
                if !clean.contains(&e) {
                    clean.push(e);
                }
            }
            *list = clean;
        }
        Ok(())
    }

    /// Classifier thresholds derived from the settings.
    pub fn thresholds(&self) -> Thresholds {
        Thresholds {
            unsure: self.unsure_threshold,
            spam: self.spam_threshold,
            ..Thresholds::default()
        }
    }

    /// Does `addr` match an entry (exact address, or domain / parent domain)?
    pub fn list_matches(list: &[String], addr: &str) -> Option<String> {
        let a = addr.trim().to_ascii_lowercase();
        let domain = a.rsplit_once('@').map(|(_, d)| d.to_string());
        list.iter()
            .find(|e| {
                let e = e.as_str();
                if e.contains('@') {
                    e == a
                } else {
                    domain
                        .as_deref()
                        .is_some_and(|d| d == e || d.ends_with(&format!(".{e}")))
                }
            })
            .cloned()
    }

    pub fn is_allowlisted(&self, addr: &str) -> Option<String> {
        Self::list_matches(&self.allowlist, addr)
    }

    pub fn is_blocklisted(&self, addr: &str) -> Option<String> {
        Self::list_matches(&self.blocklist, addr)
    }
}

/// What the message row remembers.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredSpamInfo {
    pub score: Option<f64>,
    pub label: Option<SpamLabel>,
    pub reasons: Vec<Reason>,
    /// The user's own feedback, if any.
    pub learned: Option<SpamLabel>,
}

/// `spam status` for one account.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SpamAccountStatus {
    pub email: String,
    pub settings: SpamSettings,
    /// Where spam goes (learned from the server when known, else the provider default).
    pub spam_folder: String,
    pub messages_spam: i64,
    pub messages_unsure: i64,
    pub messages_ham: i64,
    pub filter_rules: usize,
}

/// `spam status` for the profile.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SpamStatus {
    pub model_spam_messages: u32,
    pub model_ham_messages: u32,
    pub model_tokens: usize,
    /// 0..1 — how much the Bayes model is trusted right now (default thresholds).
    pub model_confidence: f64,
    pub accounts: Vec<SpamAccountStatus>,
}

/// Result of [`Engine::spam_learn`].
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SpamLearnReport {
    pub id: i64,
    pub learned: SpamLabel,
    pub previously_learned: Option<SpamLabel>,
    /// Folder the message was moved to, if it was moved.
    pub moved_to: Option<String>,
    pub model_spam_messages: u32,
    pub model_ham_messages: u32,
    /// Fresh verdict under the updated model.
    pub verdict: Verdict,
}

/// Compact view of the extracted features for `spam explain`.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SpamFeatureSummary {
    pub from_address: Option<String>,
    pub from_name: Option<String>,
    pub reply_to: Option<String>,
    pub urls: Vec<String>,
    pub attachments: Vec<String>,
    pub received_depth: usize,
    pub last_external_ip: Option<String>,
    pub auth: AuthResults,
    pub html_only: bool,
    pub tokens: usize,
}

impl SpamFeatureSummary {
    fn from_features(f: &Features) -> Self {
        Self {
            from_address: f.from_address.clone(),
            from_name: f.from_name.clone(),
            reply_to: f.reply_to_address.clone(),
            urls: f.urls.iter().map(|u| u.url.clone()).take(20).collect(),
            attachments: f
                .attachments
                .iter()
                .map(|a| format!("{} ({})", a.filename, a.content_type))
                .collect(),
            received_depth: f.received_depth,
            last_external_ip: f.last_external_ip.map(|ip| ip.to_string()),
            auth: f.auth.clone(),
            html_only: f.html_only,
            tokens: f.tokens.len(),
        }
    }
}

/// Result of [`Engine::spam_explain`].
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SpamExplanation {
    pub id: i64,
    pub account: String,
    pub folder: String,
    pub from: String,
    pub subject: Option<String>,
    /// What was stored at sync / learn time.
    pub stored: StoredSpamInfo,
    /// Fresh verdict under the current model and settings (no DNSBL: offline).
    pub verdict: Verdict,
    pub settings: SpamSettings,
    pub features: SpamFeatureSummary,
    /// What the account's filter rules would do with this message.
    pub filters: FilterOutcome,
}

/// Outcome of the hook for one message.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpamHookAction {
    pub id: i64,
    pub label: SpamLabel,
    pub moved_to: Option<String>,
    pub flags_added: Vec<String>,
}

fn map_spam_err(e: sealbox_spam::Error) -> Error {
    match e {
        sealbox_spam::Error::Unparseable => {
            Error::InvalidInput("message could not be parsed".into())
        }
        sealbox_spam::Error::InvalidFilter(m)
        | sealbox_spam::Error::Regex(m)
        | sealbox_spam::Error::Corpus(m) => Error::InvalidInput(m),
        sealbox_spam::Error::Io(e) => Error::Io(e),
        sealbox_spam::Error::Json(e) => Error::Json(e),
        other => Error::InvalidInput(other.to_string()),
    }
}

/// `(spam_score, spam_label, spam_reasons_json, spam_learned)` as stored on a message row.
type StoredSpamRow = (Option<f64>, Option<String>, Option<String>, Option<String>);

impl Store {
    pub(crate) fn load_spam_model(&self) -> Result<BayesModel> {
        let json: Option<String> = self
            .conn()
            .query_row("SELECT model_json FROM spam_model WHERE id = 1", [], |r| {
                r.get::<_, rusqlite::types::Value>(0)
            })
            .optional()?
            .map(|v| self.vault().open_text("spam_model", "model_json", "1", v)) // G27
            .transpose()?;
        Ok(match json {
            Some(j) => BayesModel::from_json(&j).unwrap_or_else(|e| {
                tracing::warn!("spam model unreadable ({e}); starting fresh");
                BayesModel::new()
            }),
            None => BayesModel::new(),
        })
    }

    pub(crate) fn save_spam_model(&self, model: &BayesModel) -> Result<()> {
        let json = model.to_json().map_err(map_spam_err)?;
        let json = self
            .vault()
            .seal_text("spam_model", "model_json", "1", &json)?; // G27
        self.conn().execute(
            "INSERT INTO spam_model (id, model_json, updated_at) VALUES (1, ?1, ?2) \
             ON CONFLICT(id) DO UPDATE SET model_json = excluded.model_json, updated_at = excluded.updated_at",
            params![json, now()],
        )?;
        Ok(())
    }

    pub(crate) fn stored_spam_info(&self, id: i64) -> Result<StoredSpamInfo> {
        let row: Option<StoredSpamRow> = self
            .conn()
            .query_row(
                "SELECT spam_score, spam_label, spam_reasons_json, spam_learned FROM messages WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let (score, label, reasons, learned) = row.ok_or(Error::MessageNotFound(id))?;
        Ok(StoredSpamInfo {
            score,
            label: label.and_then(|l| l.parse().ok()),
            reasons: reasons
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default(),
            learned: learned.and_then(|l| l.parse().ok()),
        })
    }

    pub(crate) fn store_spam_verdict(&self, id: i64, verdict: &Verdict) -> Result<()> {
        self.conn().execute(
            "UPDATE messages SET spam_score = ?1, spam_label = ?2, spam_reasons_json = ?3 WHERE id = ?4",
            params![
                verdict.spam_probability,
                verdict.label.as_str(),
                serde_json::to_string(&verdict.reasons)?,
                id
            ],
        )?;
        Ok(())
    }

    pub(crate) fn store_spam_learned(&self, id: i64, learned: Option<SpamLabel>) -> Result<()> {
        self.conn().execute(
            "UPDATE messages SET spam_learned = ?1 WHERE id = ?2",
            params![learned.map(|l| l.as_str()), id],
        )?;
        Ok(())
    }

    /// Point a stored message at its new server location after a move.
    pub(crate) fn relocate_message(
        &self,
        id: i64,
        folder_id: i64,
        uid: u32,
        flags: &[String],
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE messages SET folder_id = ?1, uid = ?2, flags_json = ?3 WHERE id = ?4",
            params![folder_id, i64::from(uid), serde_json::to_string(flags)?, id],
        )?;
        Ok(())
    }

    /// Lower-cased addresses of every account (usable while holding the store guard).
    pub(crate) fn own_addresses_lower(&self) -> Result<Vec<String>> {
        Ok(self
            .list_accounts()?
            .into_iter()
            .map(|a| a.email.trim().to_ascii_lowercase())
            .collect())
    }

    pub(crate) fn spam_label_counts(&self, account_id: i64) -> Result<(i64, i64, i64)> {
        let count = |label: &str| -> Result<i64> {
            Ok(self.conn().query_row(
                "SELECT COUNT(*) FROM messages WHERE account_id = ?1 AND spam_label = ?2",
                params![account_id, label],
                |r| r.get(0),
            )?)
        };
        Ok((count("spam")?, count("unsure")?, count("ham")?))
    }

    /// Addresses the user has corresponded with: everyone we sent to, everyone who announced
    /// an Autocrypt key, and every imported/directory key. (Mere senders are *not* contacts —
    /// that would make repeat spammers "known".)
    pub(crate) fn spam_contacts(&self) -> Result<Vec<String>> {
        let mut out: BTreeSet<String> = BTreeSet::new();
        let mut stmt = self.conn().prepare("SELECT recipients_json FROM outbox")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for j in rows {
            let list: Vec<String> = serde_json::from_str(&j?).unwrap_or_default();
            out.extend(list.into_iter().map(|a| a.trim().to_ascii_lowercase()));
        }
        for p in self.all_peers()? {
            if p.public_key.is_some() {
                out.insert(p.addr.trim().to_ascii_lowercase());
            }
        }
        for k in self.all_keys()? {
            out.insert(k.addr.trim().to_ascii_lowercase());
        }
        Ok(out.into_iter().filter(|a| a.contains('@')).collect())
    }
}

/// Everything the hook needs once per sync.
struct SpamRun {
    settings: SpamSettings,
    model: BayesModel,
    contacts: Vec<String>,
    own: Vec<String>,
    rules: Vec<sealbox_spam::FilterRule>,
}

impl Engine {
    // ----- settings ----------------------------------------------------------------------

    /// Spam settings of an account (defaults when never set).
    pub fn spam_settings(&self, email: &str) -> Result<SpamSettings> {
        let acct = self.account_row(email)?;
        self.spam_settings_for(&acct)
    }

    pub(crate) fn spam_settings_for(&self, acct: &AccountRow) -> Result<SpamSettings> {
        Ok(self
            .store()
            .get_setting::<SpamSettings>(SettingsScope::Account, &acct.email, SETTINGS_KEY)?
            .unwrap_or_default())
    }

    /// Replace the spam settings of an account (validated).
    pub fn set_spam_settings(
        &self,
        email: &str,
        mut settings: SpamSettings,
    ) -> Result<SpamSettings> {
        let acct = self.account_row(email)?;
        settings.validate()?;
        self.store()
            .set_setting(SettingsScope::Account, &acct.email, SETTINGS_KEY, &settings)?;
        Ok(settings)
    }

    /// Add (or remove) an allowlist entry; returns the new settings.
    pub fn spam_allow(&self, email: &str, entry: &str, add: bool) -> Result<SpamSettings> {
        let mut s = self.spam_settings(email)?;
        let e = entry.trim().trim_start_matches('@').to_ascii_lowercase();
        s.allowlist.retain(|x| x != &e);
        s.blocklist.retain(|x| x != &e);
        if add {
            s.allowlist.push(e);
        }
        self.set_spam_settings(email, s)
    }

    /// Add (or remove) a blocklist entry; returns the new settings.
    pub fn spam_block(&self, email: &str, entry: &str, add: bool) -> Result<SpamSettings> {
        let mut s = self.spam_settings(email)?;
        let e = entry.trim().trim_start_matches('@').to_ascii_lowercase();
        s.blocklist.retain(|x| x != &e);
        s.allowlist.retain(|x| x != &e);
        if add {
            s.blocklist.push(e);
        }
        self.set_spam_settings(email, s)
    }

    // ----- status / explain -----------------------------------------------------------------

    /// Model statistics and per-account settings.
    pub fn spam_status(&self) -> Result<SpamStatus> {
        let (model, accounts) = {
            let store = self.store();
            (store.load_spam_model()?, store.list_accounts()?)
        };
        let mut out = Vec::with_capacity(accounts.len());
        for acct in accounts {
            let settings = self.spam_settings_for(&acct)?;
            let (spam, unsure, ham) = self.store().spam_label_counts(acct.id)?;
            let rules = self.store().list_filter_rules(acct.id)?.len();
            out.push(SpamAccountStatus {
                spam_folder: self.spam_folder_name(&acct, &settings),
                email: acct.email.clone(),
                settings,
                messages_spam: spam,
                messages_unsure: unsure,
                messages_ham: ham,
                filter_rules: rules,
            });
        }
        let stats = model.stats();
        Ok(SpamStatus {
            model_spam_messages: stats.spam_messages,
            model_ham_messages: stats.ham_messages,
            model_tokens: stats.tokens,
            model_confidence: model.confidence(Thresholds::default().min_trained),
            accounts: out,
        })
    }

    /// Offline name of the junk folder: the user's explicit choice, else what sync learned
    /// from the server, else the provider default.
    pub(crate) fn spam_folder_name(&self, acct: &AccountRow, settings: &SpamSettings) -> String {
        if settings.move_to_folder != DEFAULT_SPAM_FOLDER {
            return settings.move_to_folder.clone();
        }
        self.folder_for_role(acct, FolderRole::Junk)
    }

    /// Stored verdict + a fresh explanation of one message (offline).
    pub fn spam_explain(&self, id: i64) -> Result<SpamExplanation> {
        let (row, acct, folder, raw, stored, model, contacts, own, rules) = {
            let store = self.store();
            let row = store.message(id)?;
            let acct = store
                .account_by_id(row.account_id)?
                .ok_or_else(|| Error::AccountNotFound(row.summary.account.clone()))?;
            let folder = store
                .folder_by_id(row.folder_id)?
                .ok_or(Error::MessageNotFound(id))?;
            let raw = store.message_raw(id)?;
            let stored = store.stored_spam_info(id)?;
            let model = store.load_spam_model()?;
            let contacts = store.spam_contacts()?;
            let rules = store.list_filter_rules(acct.id)?;
            (
                row,
                acct,
                folder,
                raw,
                stored,
                model,
                contacts,
                store.own_addresses_lower()?,
                rules,
            )
        };
        let settings = self.spam_settings_for(&acct)?;
        let f = features::extract(&raw).map_err(map_spam_err)?;
        let verdict = self.verdict_for(&row, &f, &settings, &model, &contacts, &own, &[]);
        let filters = apply_rules(&rules, &MessageFacts::from_features(&f));
        Ok(SpamExplanation {
            id,
            account: acct.email.clone(),
            folder: folder.name,
            from: row.summary.from.to_string(),
            subject: row.summary.subject.clone(),
            stored,
            verdict,
            settings,
            features: SpamFeatureSummary::from_features(&f),
            filters,
        })
    }

    /// Classify arbitrary raw bytes with the profile's model (and an account's settings and
    /// contacts when `email` is given). No DNSBL. For `sealbox spam check FILE` and tests.
    pub fn spam_classify_raw(&self, raw: &[u8], email: Option<&str>) -> Result<Verdict> {
        let (model, contacts, own) = {
            let store = self.store();
            (
                store.load_spam_model()?,
                store.spam_contacts()?,
                store.own_addresses_lower()?,
            )
        };
        let settings = match email {
            Some(e) => self.spam_settings(e)?,
            None => SpamSettings::default(),
        };
        let f = features::extract(raw).map_err(map_spam_err)?;
        let ctx = RuleContext {
            contacts: &contacts,
            own_addresses: &own,
        };
        let from = f.from_address.clone().unwrap_or_default();
        if let Some(e) = settings.is_blocklisted(&from) {
            return Ok(Verdict::forced(
                SpamLabel::Spam,
                "blocklist",
                format!("{from} matches blocklist entry {e}"),
            ));
        }
        if let Some(e) = settings.is_allowlisted(&from) {
            return Ok(Verdict::forced(
                SpamLabel::Ham,
                "allowlist",
                format!("{from} matches allowlist entry {e}"),
            ));
        }
        Ok(Classifier::new(&model, settings.thresholds()).classify(&f, &ctx, &[]))
    }

    /// Train on a labelled corpus and report precision/recall (see `sealbox_spam::eval`).
    pub fn spam_eval(corpus: &std::path::Path, opts: &EvalOptions) -> Result<EvalReport> {
        eval::evaluate(corpus, opts).map_err(map_spam_err)
    }

    #[allow(clippy::too_many_arguments)]
    fn verdict_for(
        &self,
        row: &MessageRow,
        f: &Features,
        settings: &SpamSettings,
        model: &BayesModel,
        contacts: &[String],
        own: &[String],
        extra: &[RuleHit],
    ) -> Verdict {
        let from = f
            .from_address
            .clone()
            .unwrap_or_else(|| row.summary.from.address.clone());
        if let Some(e) = settings.is_blocklisted(&from) {
            return Verdict::forced(
                SpamLabel::Spam,
                "blocklist",
                format!("{from} matches blocklist entry {e}"),
            );
        }
        if let Some(e) = settings.is_allowlisted(&from) {
            return Verdict::forced(
                SpamLabel::Ham,
                "allowlist",
                format!("{from} matches allowlist entry {e}"),
            );
        }
        if row.summary.signature.status == SigState::Good {
            if let Some(signer) = row.summary.signature.signer.as_deref() {
                let s = signer.to_ascii_lowercase();
                if contacts.iter().any(|c| c == &s) || own.iter().any(|o| o == &s) {
                    return Verdict::forced(
                        SpamLabel::Ham,
                        "signed_by_contact",
                        format!("good OpenPGP signature by {signer}"),
                    );
                }
            }
        }
        let ctx = RuleContext {
            contacts,
            own_addresses: own,
        };
        Classifier::new(model, settings.thresholds()).classify(f, &ctx, extra)
    }

    // ----- learning ----------------------------------------------------------------------------

    /// User feedback: (un)learn the message, store the label, and move it to the junk folder
    /// (`is_spam`) or back to INBOX (`!is_spam`). Takes the account's mailbox lock for the
    /// move.
    pub async fn spam_learn(&self, id: i64, is_spam: bool) -> Result<SpamLearnReport> {
        let (row, acct, folder, raw, stored, mut model, contacts, own) = {
            let store = self.store();
            let row = store.message(id)?;
            let acct = store
                .account_by_id(row.account_id)?
                .ok_or_else(|| Error::AccountNotFound(row.summary.account.clone()))?;
            let folder = store
                .folder_by_id(row.folder_id)?
                .ok_or(Error::MessageNotFound(id))?;
            let raw = store.message_raw(id)?;
            let stored = store.stored_spam_info(id)?;
            let model = store.load_spam_model()?;
            let contacts = store.spam_contacts()?;
            (
                row,
                acct,
                folder,
                raw,
                stored,
                model,
                contacts,
                store.own_addresses_lower()?,
            )
        };
        let settings = self.spam_settings_for(&acct)?;
        let f = features::extract(&raw).map_err(map_spam_err)?;
        let new_label = if is_spam {
            SpamLabel::Spam
        } else {
            SpamLabel::Ham
        };
        if stored.learned != Some(new_label) {
            if let Some(prev) = stored.learned {
                model.unlearn(&f.tokens, prev == SpamLabel::Spam);
            }
            model.learn(&f.tokens, is_spam);
            self.store().save_spam_model(&model)?;
            self.store().store_spam_learned(id, Some(new_label))?;
        }
        let mut verdict = self.verdict_for(&row, &f, &settings, &model, &contacts, &own, &[]);
        // The user's word is final for this message.
        verdict.label = new_label;
        verdict.reasons.insert(
            0,
            Reason {
                code: "user_feedback".into(),
                weight: 0.0,
                detail: format!("marked as {} by the user", new_label),
            },
        );
        self.store().store_spam_verdict(id, &verdict)?;

        // Move between INBOX and the junk folder (never while a sync of the account runs).
        let _guard = self.account_lock(acct.id).await;
        let mut client = self.imap_for(&acct).await?;
        let moved_to = {
            let junk = self
                .resolve_spam_folder(&acct, &mut client, &settings)
                .await?;
            let in_junk = folder.name.eq_ignore_ascii_case(&junk);
            let dest = if is_spam && !in_junk {
                Some((junk.clone(), vec!["\\Seen".to_string()]))
            } else if !is_spam && in_junk {
                Some(("INBOX".to_string(), Vec::new()))
            } else {
                None
            };
            match dest {
                Some((d, flags)) => {
                    let r = self
                        .spam_move(&acct, &mut client, &row, &folder, &d, &flags)
                        .await;
                    match r {
                        Ok(()) => Some(d),
                        Err(e) => {
                            let _ = client.logout().await;
                            return Err(e);
                        }
                    }
                }
                None => None,
            }
        };
        let _ = client.logout().await;
        let stats = model.stats();
        Ok(SpamLearnReport {
            id,
            learned: new_label,
            previously_learned: stored.learned,
            moved_to,
            model_spam_messages: stats.spam_messages,
            model_ham_messages: stats.ham_messages,
            verdict,
        })
    }

    // ----- IMAP side ---------------------------------------------------------------------------

    /// The junk folder on an open session: the user's explicit choice (created if missing),
    /// else the server's `\Junk` / provider folder, else a created `Spam`.
    pub(crate) async fn resolve_spam_folder(
        &self,
        acct: &AccountRow,
        client: &mut ImapClient,
        settings: &SpamSettings,
    ) -> Result<String> {
        if settings.move_to_folder != DEFAULT_SPAM_FOLDER {
            if client.ensure_folder(&settings.move_to_folder).await? {
                let _ = client.subscribe(&settings.move_to_folder).await;
            }
            return Ok(settings.move_to_folder.clone());
        }
        if let Ok(name) = self
            .resolve_folder_live(acct, client, FolderRole::Junk, false)
            .await
        {
            return Ok(name);
        }
        let folders = client.list_folders().await?;
        if let Some(f) = folders
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(DEFAULT_SPAM_FOLDER) && !f.is_noselect())
        {
            return Ok(f.name.clone());
        }
        if client.ensure_folder(DEFAULT_SPAM_FOLDER).await? {
            tracing::info!(email = %acct.email, "created folder {DEFAULT_SPAM_FOLDER}");
            let _ = client.subscribe(DEFAULT_SPAM_FOLDER).await;
        }
        if let Ok(folders) = client.list_folders().await {
            let _ = self.remember_folder_roles(acct, &folders);
        }
        Ok(DEFAULT_SPAM_FOLDER.to_string())
    }

    /// Move one stored message to `dest` on the server (MOVE, or COPY+EXPUNGE), optionally
    /// adding flags first, and point the local row at its new UID. Leaves the source folder
    /// selected. When the new UID cannot be determined the local row is dropped (the next
    /// sync of the destination would store it again).
    pub(crate) async fn spam_move(
        &self,
        acct: &AccountRow,
        client: &mut ImapClient,
        row: &MessageRow,
        from: &FolderRow,
        dest: &str,
        add_flags: &[String],
    ) -> Result<()> {
        if dest.eq_ignore_ascii_case(&from.name) {
            return Ok(());
        }
        let uid = row.summary.uid;
        if client.selected().map(|m| m.name.as_str()) != Some(from.name.as_str()) {
            client.select(&from.name).await?;
        }
        let mut flags = row.summary.flags.clone();
        if !add_flags.is_empty() {
            let refs: Vec<&str> = add_flags.iter().map(String::as_str).collect();
            client.set_flags(&[uid], ImapFlagOp::Add, &refs).await?;
            for f in add_flags {
                if !flags.iter().any(|x| x.eq_ignore_ascii_case(f)) {
                    flags.push(f.clone());
                }
            }
        }
        client.r#move(&[uid], dest).await?;
        // Find the message in its new home.
        let new_uid = match &row.summary.message_id {
            Some(mid) => {
                client.select(dest).await?;
                client
                    .search_message_id(mid)
                    .await
                    .ok()
                    .and_then(|uids| uids.last().copied())
            }
            None => client
                .select(dest)
                .await
                .ok()
                .and_then(|m| m.uidnext.checked_sub(1)),
        };
        let _ = client.select(&from.name).await;
        let store = self.store();
        match new_uid {
            Some(u) => {
                let dest_row = store.folder(acct.id, dest)?;
                if store
                    .relocate_message(row.summary.id, dest_row.id, u, &flags)
                    .is_err()
                {
                    store.delete_message(row.summary.id)?;
                }
            }
            None => store.delete_message(row.summary.id)?,
        }
        Ok(())
    }

    // ----- the sync hook -------------------------------------------------------------------------

    /// Called by `sync_folder` after new messages were stored. Classifies them, moves spam,
    /// applies filter rules. Never fails the sync: problems are logged.
    pub(crate) async fn spam_after_sync(
        &self,
        acct: &AccountRow,
        folder: &FolderRow,
        client: &mut ImapClient,
        new_ids: &[i64],
    ) -> Vec<SpamHookAction> {
        if new_ids.is_empty() || !folder.name.eq_ignore_ascii_case("INBOX") {
            return Vec::new();
        }
        match self
            .spam_after_sync_inner(acct, folder, client, new_ids)
            .await
        {
            Ok(actions) => actions,
            Err(e) => {
                tracing::warn!(email = %acct.email, "spam/filter pass failed: {e}");
                Vec::new()
            }
        }
    }

    async fn spam_after_sync_inner(
        &self,
        acct: &AccountRow,
        folder: &FolderRow,
        client: &mut ImapClient,
        new_ids: &[i64],
    ) -> Result<Vec<SpamHookAction>> {
        let settings = self.spam_settings_for(acct)?;
        let run = {
            let store = self.store();
            SpamRun {
                model: store.load_spam_model()?,
                contacts: store.spam_contacts()?,
                own: store.own_addresses_lower()?,
                rules: store.list_filter_rules(acct.id)?,
                settings,
            }
        };
        if !run.settings.enabled && run.rules.is_empty() {
            return Ok(Vec::new());
        }
        let resolver = if run.settings.enabled && run.settings.dnsbl_enabled {
            match HickoryResolver::new(Duration::from_secs(2)) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!("DNSBL resolver unavailable: {e}");
                    None
                }
            }
        } else {
            None
        };
        let dnsbl_cfg = DnsblConfig::default();
        let mut junk: Option<String> = None;
        let mut actions = Vec::new();
        for &id in new_ids {
            let (row, raw) = {
                let store = self.store();
                match store.message(id) {
                    Ok(row) => (row, store.message_raw(id)?),
                    Err(_) => continue, // already gone
                }
            };
            if row.folder_id != folder.id {
                continue;
            }
            let from_lower = row.summary.from.address.to_ascii_lowercase();
            if run.own.iter().any(|o| o == &from_lower) {
                continue; // our own mail (Sent copies, self-addressed) is never classified
            }
            let f = match features::extract(&raw) {
                Ok(f) => f,
                Err(e) => {
                    tracing::debug!(id, "spam: cannot extract features: {e}");
                    continue;
                }
            };
            let mut action = SpamHookAction {
                id,
                label: SpamLabel::Ham,
                moved_to: None,
                flags_added: Vec::new(),
            };
            if run.settings.enabled {
                let extra = match &resolver {
                    Some(r) => dnsbl::check(&f, r, &dnsbl_cfg).await,
                    None => Vec::new(),
                };
                let verdict = self.verdict_for(
                    &row,
                    &f,
                    &run.settings,
                    &run.model,
                    &run.contacts,
                    &run.own,
                    &extra,
                );
                self.store().store_spam_verdict(id, &verdict)?;
                action.label = verdict.label;
                if verdict.label == SpamLabel::Spam {
                    if junk.is_none() {
                        junk = Some(
                            self.resolve_spam_folder(acct, client, &run.settings)
                                .await?,
                        );
                    }
                    let dest = junk
                        .clone()
                        .unwrap_or_else(|| DEFAULT_SPAM_FOLDER.to_string());
                    match self
                        .spam_move(acct, client, &row, folder, &dest, &["\\Seen".to_string()])
                        .await
                    {
                        Ok(()) => {
                            tracing::info!(id, email = %acct.email, p = verdict.spam_probability, "spam moved to {dest}");
                            action.moved_to = Some(dest);
                        }
                        Err(e) => tracing::warn!(id, "could not move spam to {dest}: {e}"),
                    }
                    actions.push(action);
                    continue; // spam rules first; user rules do not run on spam
                }
            }
            if !run.rules.is_empty() {
                let outcome = apply_rules(&run.rules, &MessageFacts::from_features(&f));
                for (rid, err) in &outcome.errors {
                    tracing::warn!(rule = rid, "filter rule skipped: {err}");
                }
                if !outcome.is_noop() {
                    match self
                        .apply_filter_outcome(acct, client, &row, folder, &outcome)
                        .await
                    {
                        Ok(applied) => {
                            action.moved_to = applied.moved_to;
                            action.flags_added = applied.flags_added;
                        }
                        Err(e) => tracing::warn!(id, "filter actions failed: {e}"),
                    }
                }
            }
            actions.push(action);
        }
        Ok(actions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_validate_and_lists() {
        let mut s = SpamSettings::default();
        assert!(s.enabled && !s.dnsbl_enabled);
        assert_eq!(s.move_to_folder, "Spam");
        s.allowlist = vec![
            "@Example.ORG".into(),
            "Bob@x.test".into(),
            "example.org".into(),
        ];
        s.blocklist = vec!["spam.example".into()];
        s.validate().unwrap();
        assert_eq!(s.allowlist, vec!["example.org", "bob@x.test"]);
        assert!(s.is_allowlisted("Alice@Example.org").is_some());
        assert!(s.is_allowlisted("alice@mail.example.org").is_some());
        assert!(s.is_allowlisted("bob@x.test").is_some());
        assert!(s.is_allowlisted("carol@x.test").is_none());
        assert!(s.is_blocklisted("x@spam.example").is_some());
        assert!(s.is_blocklisted("x@notspam.example").is_none());
        s.unsure_threshold = 0.95;
        assert!(s.validate().is_err());
        s.unsure_threshold = 0.5;
        s.spam_threshold = 1.5;
        assert!(s.validate().is_err());
        s.spam_threshold = 0.9;
        s.move_to_folder = "inbox".into();
        assert!(s.validate().is_err());
        s.move_to_folder = " Junk ".into();
        s.validate().unwrap();
        assert_eq!(s.move_to_folder, "Junk");
        assert_eq!(s.thresholds().spam, 0.9);
        let json = serde_json::to_string(&s).unwrap();
        let back: SpamSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
        // Missing fields fall back to defaults.
        let partial: SpamSettings = serde_json::from_str("{\"enabled\": false}").unwrap();
        assert!(!partial.enabled);
        assert_eq!(partial.spam_threshold, 0.9);
    }

    #[test]
    fn migration_is_idempotent_and_adds_columns() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::store::SCHEMA).unwrap();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap();
        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(messages)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        for c in [
            "spam_score",
            "spam_label",
            "spam_reasons_json",
            "spam_learned",
        ] {
            assert!(cols.iter().any(|x| x == c), "missing {c}");
        }
        conn.execute(
            "INSERT INTO spam_model (id, model_json, updated_at) VALUES (1, '{}', 0)",
            [],
        )
        .unwrap();
        assert!(conn
            .execute(
                "INSERT INTO spam_model (id, model_json, updated_at) VALUES (2, '{}', 0)",
                []
            )
            .is_err());
    }
}
