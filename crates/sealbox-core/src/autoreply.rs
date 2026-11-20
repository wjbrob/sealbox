//! Holiday / out-of-office auto-reply (RFC 3834; gate G24).
//!
//! Evaluated from the sync pipeline after new INBOX messages are stored
//! ([`Engine::autoreply_after_sync`], called by `sync_folder`) and on demand
//! ([`Engine::run_autoreplies`]). For every new message the responder:
//!
//! 1. checks the account's [`AutoReplySettings`] (enabled, inside the window, message not
//!    older than the window start);
//! 2. applies the suppression rules of [`suppression_reason`] (RFC 3834 §2/§3 plus the
//!    usual conventions): `Auto-Submitted` other than `no`, `Precedence: bulk|list|junk`,
//!    `List-*` headers, `X-Auto-Response-Suppress`, `X-Autoreply`/`X-Autorespond`, a null
//!    (`Return-Path: <>`) or system sender (`MAILER-DAEMON`, `postmaster`, `noreply`, …),
//!    `multipart/report`, our own addresses;
//! 3. picks the target (`Reply-To`, else `From`), enforces "at most one reply per sender per
//!    [`AutoReplySettings::reply_once_per_sender_days`] within a vacation period"
//!    (`autoreply_log`) and, when configured, "only to known contacts" (people this account
//!    has written to, or whose key was imported);
//! 4. sends the reply through the regular pipeline with [`AUTO_REPLY_HEADERS`],
//!    `In-Reply-To`/`References`, **never a signature**, and the explicit policy
//!    "encrypt + sign when the sender has a usable key, else plaintext"
//!    (`SendExtras::plaintext_fallback`; `AllowPlaintext` when `encrypt_when_possible` is
//!    off).
//!
//! Messages are evaluated once: a per-account cursor (highest local id considered) is kept
//! in the settings table and reset whenever the responder is switched on.

use chrono::{DateTime, Utc};
use sealbox_mail::mime::Mailbox;
use serde::{Deserialize, Serialize};

use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::settings::{AutoReplyLogEntry, AutoReplySettings, AutoReplyState};
use crate::signature::{ComposeKind, ComposeOptions, SendExtras};
use crate::store::{AccountRow, MessageRow};
use crate::types::{Address, Draft, SendPolicy, SyncReport};

/// Value of the `Auto-Submitted` header on our replies (RFC 3834 §5).
pub const AUTO_SUBMITTED_VALUE: &str = "auto-replied";

/// The headers every auto-reply carries in addition to the normal ones
/// (`From`, `To`, `Subject`, `Date`, `Message-ID`, `In-Reply-To`, `References`, `Autocrypt`).
pub const AUTO_REPLY_HEADERS: &[(&str, &str)] = &[
    ("Auto-Submitted", AUTO_SUBMITTED_VALUE),
    ("Precedence", "auto_reply"),
    ("X-Auto-Response-Suppress", "All"),
];

/// Why no auto-reply was sent for a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressReason {
    /// The responder is switched off.
    Disabled,
    /// Now is outside `[start, end)`.
    OutsideWindow,
    /// The message is dated before the window start.
    OlderThanWindow,
    /// Only INBOX messages are answered.
    NotInbox,
    /// No `From` address.
    NoSender,
    /// `Return-Path: <>` (bounce / notification).
    NullSender,
    /// `MAILER-DAEMON`, `postmaster`, `noreply`, `no-reply`, `do-not-reply`, `bounce…`.
    SystemSender,
    /// From (or the reply target) is one of our own accounts.
    OwnAddress,
    /// `Auto-Submitted` present and not `no`.
    AutoSubmitted,
    /// `Precedence: bulk|list|junk|auto_reply`.
    Precedence,
    /// `List-Id`, `List-Unsubscribe`, `List-Post`, … (mailing list traffic).
    ListHeader,
    /// `X-Auto-Response-Suppress` (Exchange) other than `None`.
    AutoResponseSuppress,
    /// `X-Autoreply`, `X-Autorespond`, `X-Autoresponder`.
    AutoReplyHeader,
    /// `multipart/report` (delivery status / disposition notifications).
    Report,
    /// This sender already got a reply in the current period.
    AlreadyReplied,
    /// `only_to_known_contacts` and we never wrote to / imported a key for the sender.
    UnknownContact,
}

/// What happened for one message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AutoReplyAction {
    Replied {
        /// Message-ID of the reply.
        message_id: String,
        encrypted: bool,
        /// Address the reply went to.
        to: String,
    },
    Skipped {
        reason: SuppressReason,
    },
    Failed {
        error: String,
    },
}

/// Per-message outcome of a run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoReplyOutcome {
    /// Local message id.
    pub message: i64,
    #[serde(default)]
    pub sender: Option<String>,
    #[serde(flatten)]
    pub action: AutoReplyAction,
}

/// Result of [`Engine::run_autoreplies`] / one sync hook invocation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoReplyRunReport {
    pub account: String,
    /// The responder is enabled and inside its window right now.
    pub active: bool,
    pub evaluated: u32,
    pub replied: u32,
    pub skipped: u32,
    pub failed: u32,
    pub outcomes: Vec<AutoReplyOutcome>,
}

// ----- raw headers ------------------------------------------------------------------------

/// All header fields of a raw RFC 5322 message, unfolded, in order (`(name, value)`).
/// The parser in `sealbox-mail` exposes only the envelope fields the sync pipeline needs;
/// the suppression rules look at a dozen others, hence this small scanner.
pub fn raw_headers(raw: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(raw);
    let block = match text.find("\r\n\r\n") {
        Some(p) => &text[..p],
        None => match text.find("\n\n") {
            Some(p) => &text[..p],
            None => &text,
        },
    };
    let mut out = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in block.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, v)) = current.as_mut() {
                if !v.is_empty() {
                    v.push(' ');
                }
                v.push_str(line.trim());
            }
            continue;
        }
        if let Some(c) = current.take() {
            out.push(c);
        }
        if let Some((name, value)) = line.split_once(':') {
            if !name.is_empty() && name.bytes().all(|b| b.is_ascii_graphic()) {
                current = Some((name.trim().to_string(), value.trim().to_string()));
            }
        }
    }
    if let Some(c) = current.take() {
        out.push(c);
    }
    out
}

/// First value of header `name` (case-insensitive).
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    header(headers, name).is_some()
}

fn first_token(value: &str) -> String {
    value
        .split([';', ',', ' '])
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// `MAILER-DAEMON@`, `postmaster@`, `noreply`/`no-reply`/`no_reply`/`do-not-reply`/
/// `donotreply` anywhere in the local part, or a local part starting with `bounce`.
pub fn is_system_sender(address: &str) -> bool {
    let local = address
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .rsplit_once('@')
        .map(|(l, _)| l)
        .unwrap_or(address)
        .to_ascii_lowercase();
    if local.is_empty() {
        return true;
    }
    local == "mailer-daemon"
        || local == "postmaster"
        || local.starts_with("bounce")
        || [
            "noreply",
            "no-reply",
            "no_reply",
            "do-not-reply",
            "donotreply",
            "do_not_reply",
        ]
        .iter()
        .any(|p| local.contains(p))
}

const LIST_HEADERS: &[&str] = &[
    "List-Id",
    "List-Unsubscribe",
    "List-Post",
    "List-Help",
    "List-Subscribe",
    "List-Archive",
    "List-Owner",
];

/// The pure suppression rules (everything that needs no database). `from_addr` is the
/// `From` address, `content_type` the top-level `type/subtype`, `own_addresses` the
/// lower-cased addresses of our accounts. `None` = a reply may be sent.
pub fn suppression_reason(
    headers: &[(String, String)],
    from_addr: &str,
    content_type: Option<&str>,
    own_addresses: &[String],
) -> Option<SuppressReason> {
    let from = from_addr.trim();
    if from.is_empty() || !from.contains('@') {
        return Some(SuppressReason::NoSender);
    }
    if own_addresses.iter().any(|a| a.eq_ignore_ascii_case(from)) {
        return Some(SuppressReason::OwnAddress);
    }
    if let Some(rp) = header(headers, "Return-Path") {
        let rp: String = rp.chars().filter(|c| !c.is_whitespace()).collect();
        if rp == "<>" || rp.is_empty() {
            return Some(SuppressReason::NullSender);
        }
    }
    if is_system_sender(from) {
        return Some(SuppressReason::SystemSender);
    }
    if let Some(v) = header(headers, "Auto-Submitted") {
        if first_token(v) != "no" {
            return Some(SuppressReason::AutoSubmitted);
        }
    }
    if let Some(v) = header(headers, "Precedence") {
        if matches!(
            first_token(v).as_str(),
            "bulk" | "list" | "junk" | "auto_reply" | "auto-reply"
        ) {
            return Some(SuppressReason::Precedence);
        }
    }
    if LIST_HEADERS.iter().any(|h| has_header(headers, h)) {
        return Some(SuppressReason::ListHeader);
    }
    if let Some(v) = header(headers, "X-Auto-Response-Suppress") {
        if !v.trim().eq_ignore_ascii_case("none") {
            return Some(SuppressReason::AutoResponseSuppress);
        }
    }
    if [
        "X-Autoreply",
        "X-Autorespond",
        "X-Autoresponder",
        "X-Auto-Reply",
    ]
    .iter()
    .any(|h| has_header(headers, h))
    {
        return Some(SuppressReason::AutoReplyHeader);
    }
    let ctype = content_type
        .map(str::to_string)
        .or_else(|| header(headers, "Content-Type").map(first_token))
        .unwrap_or_default();
    if ctype.trim().eq_ignore_ascii_case("multipart/report") {
        return Some(SuppressReason::Report);
    }
    None
}

/// Where the reply goes: the first `Reply-To` address when present and valid, else `From`.
pub fn reply_target(headers: &[(String, String)], from: &Address) -> Address {
    if let Some(v) = header(headers, "Reply-To") {
        let candidate = Mailbox::parse(v).ok().or_else(|| {
            v.split(',')
                .next()
                .and_then(|first| Mailbox::parse(first).ok())
        });
        if let Some(m) = candidate {
            if m.address.contains('@') {
                return Address {
                    name: m.name,
                    address: m.address,
                };
            }
        }
    }
    from.clone()
}

fn auto_reply_headers() -> Vec<(String, String)> {
    AUTO_REPLY_HEADERS
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ----- engine ---------------------------------------------------------------------------

impl Engine {
    /// Sync hook: evaluate the new INBOX messages of `report`. Never fails the sync; problems
    /// are logged.
    pub(crate) async fn autoreply_after_sync(&self, acct: &AccountRow, report: &SyncReport) {
        if report.new_ids.is_empty()
            || !report
                .folders
                .iter()
                .any(|f| f.name.eq_ignore_ascii_case("INBOX"))
        {
            return;
        }
        match self.evaluate_autoreplies(acct, &report.new_ids).await {
            Ok(r) if r.evaluated > 0 => tracing::info!(
                account = %acct.email,
                evaluated = r.evaluated,
                replied = r.replied,
                skipped = r.skipped,
                failed = r.failed,
                "auto-reply evaluation"
            ),
            Ok(_) => {}
            Err(e) => tracing::warn!(account = %acct.email, "auto-reply evaluation failed: {e}"),
        }
    }

    /// Evaluate every INBOX message not yet considered (manual / scheduled runs).
    pub async fn run_autoreplies(&self, account: &str) -> Result<AutoReplyRunReport> {
        let acct = self.account_row(account)?;
        let state = self.autoreply_state(&acct.email)?;
        let ids = self
            .store()
            .inbox_message_ids_after(acct.id, state.cursor)?;
        self.evaluate_autoreplies(&acct, &ids).await
    }

    /// Evaluate the given local message ids (ascending). Ids at or below the cursor are
    /// ignored; the cursor is advanced afterwards.
    pub(crate) async fn evaluate_autoreplies(
        &self,
        acct: &AccountRow,
        ids: &[i64],
    ) -> Result<AutoReplyRunReport> {
        let settings = self.get_autoreply(&acct.email)?;
        let now = Utc::now();
        let mut report = AutoReplyRunReport {
            account: acct.email.clone(),
            active: settings.is_active_at(now),
            ..AutoReplyRunReport::default()
        };
        if ids.is_empty() || !settings.enabled {
            return Ok(report);
        }
        let mut state = self.autoreply_state(&acct.email)?;
        let own = self.own_addresses()?;
        let mut sorted: Vec<i64> = ids.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        for id in sorted {
            if id <= state.cursor {
                continue;
            }
            let outcome = self
                .autoreply_one(acct, &settings, &state, &own, now, id)
                .await;
            report.evaluated += 1;
            match &outcome.action {
                AutoReplyAction::Replied { .. } => report.replied += 1,
                AutoReplyAction::Skipped { .. } => report.skipped += 1,
                AutoReplyAction::Failed { .. } => report.failed += 1,
            }
            report.outcomes.push(outcome);
            state.cursor = id;
        }
        self.save_autoreply_state(&acct.email, &state)?;
        Ok(report)
    }

    /// Has this account written to `addr` before, or was a key imported for it?
    pub(crate) fn is_known_contact(&self, acct: &AccountRow, addr: &str) -> Result<bool> {
        let store = self.store();
        Ok(store.has_sent_to(acct.id, addr)? || !store.keys_for(addr)?.is_empty())
    }

    async fn autoreply_one(
        &self,
        acct: &AccountRow,
        settings: &AutoReplySettings,
        state: &AutoReplyState,
        own: &[String],
        now: DateTime<Utc>,
        id: i64,
    ) -> AutoReplyOutcome {
        let skipped = |sender: Option<String>, reason: SuppressReason| AutoReplyOutcome {
            message: id,
            sender,
            action: AutoReplyAction::Skipped { reason },
        };
        let loaded: Result<(MessageRow, Vec<u8>)> = (|| {
            let store = self.store();
            Ok((store.message(id)?, store.message_raw(id)?))
        })();
        let (row, raw) = match loaded {
            Ok(x) => x,
            Err(e) => {
                return AutoReplyOutcome {
                    message: id,
                    sender: None,
                    action: AutoReplyAction::Failed {
                        error: e.to_string(),
                    },
                }
            }
        };
        let sender = Some(row.summary.from.address.clone());
        if !row.summary.folder.eq_ignore_ascii_case("INBOX") {
            return skipped(sender, SuppressReason::NotInbox);
        }
        if !settings.is_active_at(now) {
            return skipped(sender, SuppressReason::OutsideWindow);
        }
        if let Some(start) = settings.start {
            let dated = row
                .summary
                .date
                .and_then(|t| DateTime::<Utc>::from_timestamp(t, 0))
                .or_else(|| DateTime::<Utc>::from_timestamp(row.summary.received_at, 0));
            if dated.is_some_and(|d| d < start) {
                return skipped(sender, SuppressReason::OlderThanWindow);
            }
        }
        let headers = raw_headers(&raw);
        let ctype = header(&headers, "Content-Type").map(first_token);
        if let Some(reason) =
            suppression_reason(&headers, &row.summary.from.address, ctype.as_deref(), own)
        {
            return skipped(sender, reason);
        }
        let target = reply_target(&headers, &row.summary.from);
        if own.iter().any(|a| a.eq_ignore_ascii_case(&target.address)) {
            return skipped(sender, SuppressReason::OwnAddress);
        }
        if is_system_sender(&target.address) {
            return skipped(sender, SuppressReason::SystemSender);
        }
        let since = if settings.reply_once_per_sender_days == 0 {
            0
        } else {
            now.timestamp() - i64::from(settings.reply_once_per_sender_days) * 86_400
        };
        match self.store().autoreply_sent_since(
            &acct.email,
            &target.address,
            state.period_start,
            since,
        ) {
            Ok(true) => return skipped(sender, SuppressReason::AlreadyReplied),
            Ok(false) => {}
            Err(e) => {
                return AutoReplyOutcome {
                    message: id,
                    sender,
                    action: AutoReplyAction::Failed {
                        error: e.to_string(),
                    },
                }
            }
        }
        if settings.only_to_known_contacts {
            match self.is_known_contact(acct, &target.address) {
                Ok(true) => {}
                Ok(false) => return skipped(sender, SuppressReason::UnknownContact),
                Err(e) => {
                    return AutoReplyOutcome {
                        message: id,
                        sender,
                        action: AutoReplyAction::Failed {
                            error: e.to_string(),
                        },
                    }
                }
            }
        }

        let draft = Draft {
            to: vec![target.address.clone()],
            subject: settings.render_subject(row.summary.subject.as_deref()),
            text: settings.body.clone(),
            in_reply_to: Some(id.to_string()),
            // "Encrypted when possible": Auto + plaintext fallback; otherwise plaintext.
            policy: if settings.encrypt_when_possible {
                SendPolicy::Auto
            } else {
                SendPolicy::AllowPlaintext
            },
            ..Draft::default()
        };
        let opts = ComposeOptions {
            kind: ComposeKind::Reply,
            quote: false,
            forward_of: None,
            skip_signature: true,
        };
        let extras = SendExtras {
            headers: auto_reply_headers(),
            plaintext_fallback: settings.encrypt_when_possible,
        };
        match self.send_composed(&acct.email, draft, opts, extras).await {
            Ok(rep) => {
                let entry = AutoReplyLogEntry {
                    id: 0,
                    account: acct.email.clone(),
                    sender: target.address.clone(),
                    period_start: state.period_start,
                    sent_at: now.timestamp(),
                    message_id: rep.message_id.clone(),
                    in_reply_to: row.summary.message_id.clone(),
                    original_id: Some(id),
                    encrypted: rep.encrypted,
                };
                if let Err(e) = self.store().insert_autoreply_log(&entry) {
                    tracing::warn!("auto-reply sent but not logged: {e}");
                }
                AutoReplyOutcome {
                    message: id,
                    sender,
                    action: AutoReplyAction::Replied {
                        message_id: rep.message_id,
                        encrypted: rep.encrypted,
                        to: target.address,
                    },
                }
            }
            Err(e) => AutoReplyOutcome {
                message: id,
                sender,
                action: AutoReplyAction::Failed {
                    error: match e {
                        Error::RecipientsWithoutKeys { missing } => {
                            format!("no usable key for {}", missing.join(", "))
                        }
                        other => other.to_string(),
                    },
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;
    use crate::settings::AutoReplySettings;
    use crate::store::{FolderRow, NewAccount};
    use crate::types::AuthKind;
    use chrono::{Duration, TimeZone};
    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::Security;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn suppression_rules_table() {
        let own = vec!["me@example.org".to_string()];
        type Case<'a> = (
            &'a str,
            Vec<(&'a str, &'a str)>,
            &'a str,
            Option<&'a str>,
            Option<SuppressReason>,
        );
        let cases: Vec<Case<'_>> = vec![
            (
                "plain mail",
                vec![("From", "Bob <bob@x.org>")],
                "bob@x.org",
                Some("text/plain"),
                None,
            ),
            (
                "auto-submitted no",
                vec![("Auto-Submitted", "no")],
                "bob@x.org",
                None,
                None,
            ),
            (
                "auto-submitted auto-replied",
                vec![("Auto-Submitted", "auto-replied")],
                "bob@x.org",
                None,
                Some(SuppressReason::AutoSubmitted),
            ),
            (
                "auto-submitted generated",
                vec![("Auto-Submitted", "auto-generated; owner-notify")],
                "bob@x.org",
                None,
                Some(SuppressReason::AutoSubmitted),
            ),
            (
                "auto-submitted case",
                vec![("AUTO-SUBMITTED", "Auto-Replied")],
                "bob@x.org",
                None,
                Some(SuppressReason::AutoSubmitted),
            ),
            (
                "precedence bulk",
                vec![("Precedence", "bulk")],
                "bob@x.org",
                None,
                Some(SuppressReason::Precedence),
            ),
            (
                "precedence list",
                vec![("Precedence", "List")],
                "bob@x.org",
                None,
                Some(SuppressReason::Precedence),
            ),
            (
                "precedence junk",
                vec![("Precedence", "junk")],
                "bob@x.org",
                None,
                Some(SuppressReason::Precedence),
            ),
            (
                "precedence auto_reply",
                vec![("Precedence", "auto_reply")],
                "bob@x.org",
                None,
                Some(SuppressReason::Precedence),
            ),
            (
                "precedence normal",
                vec![("Precedence", "normal")],
                "bob@x.org",
                None,
                None,
            ),
            (
                "list-id",
                vec![("List-Id", "Dev <dev.lists.example.org>")],
                "bob@x.org",
                None,
                Some(SuppressReason::ListHeader),
            ),
            (
                "list-unsubscribe",
                vec![("List-Unsubscribe", "<mailto:u@x>")],
                "bob@x.org",
                None,
                Some(SuppressReason::ListHeader),
            ),
            (
                "list-post",
                vec![("list-post", "<mailto:dev@x>")],
                "bob@x.org",
                None,
                Some(SuppressReason::ListHeader),
            ),
            (
                "x-auto-response-suppress all",
                vec![("X-Auto-Response-Suppress", "All")],
                "bob@x.org",
                None,
                Some(SuppressReason::AutoResponseSuppress),
            ),
            (
                "x-auto-response-suppress oof",
                vec![("X-Auto-Response-Suppress", "OOF, AutoReply")],
                "bob@x.org",
                None,
                Some(SuppressReason::AutoResponseSuppress),
            ),
            (
                "x-auto-response-suppress none",
                vec![("X-Auto-Response-Suppress", "None")],
                "bob@x.org",
                None,
                None,
            ),
            (
                "x-autoreply",
                vec![("X-Autoreply", "yes")],
                "bob@x.org",
                None,
                Some(SuppressReason::AutoReplyHeader),
            ),
            (
                "x-autorespond",
                vec![("X-Autorespond", "1")],
                "bob@x.org",
                None,
                Some(SuppressReason::AutoReplyHeader),
            ),
            (
                "null return-path",
                vec![("Return-Path", "<>")],
                "bob@x.org",
                None,
                Some(SuppressReason::NullSender),
            ),
            (
                "return-path ok",
                vec![("Return-Path", "<bob@x.org>")],
                "bob@x.org",
                None,
                None,
            ),
            (
                "mailer-daemon",
                vec![],
                "MAILER-DAEMON@x.org",
                None,
                Some(SuppressReason::SystemSender),
            ),
            (
                "postmaster",
                vec![],
                "postmaster@x.org",
                None,
                Some(SuppressReason::SystemSender),
            ),
            (
                "noreply",
                vec![],
                "noreply@shop.example",
                None,
                Some(SuppressReason::SystemSender),
            ),
            (
                "no-reply",
                vec![],
                "no-reply@shop.example",
                None,
                Some(SuppressReason::SystemSender),
            ),
            (
                "do-not-reply",
                vec![],
                "Do-Not-Reply@shop.example",
                None,
                Some(SuppressReason::SystemSender),
            ),
            (
                "donotreply",
                vec![],
                "donotreply@shop.example",
                None,
                Some(SuppressReason::SystemSender),
            ),
            (
                "bounces",
                vec![],
                "bounces+123@mailer.example",
                None,
                Some(SuppressReason::SystemSender),
            ),
            (
                "report",
                vec![],
                "bob@x.org",
                Some("multipart/report"),
                Some(SuppressReason::Report),
            ),
            (
                "report via header",
                vec![(
                    "Content-Type",
                    "multipart/report; report-type=delivery-status; boundary=b",
                )],
                "bob@x.org",
                None,
                Some(SuppressReason::Report),
            ),
            (
                "own address",
                vec![],
                "Me@Example.org",
                None,
                Some(SuppressReason::OwnAddress),
            ),
            (
                "no sender",
                vec![],
                "",
                None,
                Some(SuppressReason::NoSender),
            ),
            (
                "bad sender",
                vec![],
                "nobody",
                None,
                Some(SuppressReason::NoSender),
            ),
            (
                "encrypted mail is fine",
                vec![(
                    "Content-Type",
                    "multipart/encrypted; protocol=\"application/pgp-encrypted\"",
                )],
                "bob@x.org",
                Some("multipart/encrypted"),
                None,
            ),
        ];
        for (name, headers, from, ctype, expected) in cases {
            let got = suppression_reason(&h(&headers), from, ctype, &own);
            assert_eq!(got, expected, "case `{name}`");
        }
    }

    #[test]
    fn raw_header_scanner_and_reply_target() {
        let raw = b"From: Bob <bob@x.org>\r\nReply-To: Robert\r\n <robert@y.org>,\r\n other@y.org\r\nSubject: hi\r\nX-Auto-Response-Suppress:\r\n All\r\n\r\nbody\r\nFrom: not a header\r\n";
        let headers = raw_headers(raw);
        assert_eq!(headers.len(), 4, "{headers:?}");
        assert_eq!(
            header(&headers, "reply-to"),
            Some("Robert <robert@y.org>, other@y.org")
        );
        assert_eq!(header(&headers, "X-Auto-Response-Suppress"), Some("All"));
        assert_eq!(header(&headers, "Missing"), None);
        let from = Address {
            name: Some("Bob".into()),
            address: "bob@x.org".into(),
        };
        let t = reply_target(&headers, &from);
        assert_eq!(t.address, "robert@y.org");
        assert_eq!(t.name.as_deref(), Some("Robert"));
        // Invalid Reply-To falls back to From; LF-only messages parse too.
        let headers = raw_headers(b"From: bob@x.org\nReply-To: nonsense\n\nbody");
        assert_eq!(reply_target(&headers, &from), from);
        assert_eq!(reply_target(&[], &from), from);
        assert!(raw_headers(b"").is_empty());
        assert!(is_system_sender("MAILER-DAEMON@mx.example"));
        assert!(!is_system_sender("alice@example.org"));
        assert!(!is_system_sender("replyme@example.org"));
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        engine: Engine,
        acct: AccountRow,
        inbox: FolderRow,
        sent: FolderRow,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(
            dir.path(),
            EngineConfig {
                network_timeout: std::time::Duration::from_secs(2),
                ..EngineConfig::default()
            },
        )
        .unwrap();
        let alice = sealbox_crypto::Identity::generate("Alice", "alice@example.org").unwrap();
        let (acct, inbox, sent) = {
            let store = engine.store();
            // Port 9 (discard) is closed on this host: sends fail fast and deterministically.
            let id = store
                .insert_account(&NewAccount {
                    email: "alice@example.org",
                    display_name: "Alice",
                    imap: &Endpoint::new("127.0.0.1", 9, Security::Plain),
                    smtp: &Endpoint::new("127.0.0.1", 9, Security::Plain),
                    auth_kind: AuthKind::Password,
                    login: "alice",
                    credential: "pw",
                })
                .unwrap();
            store
                .insert_identity(
                    id,
                    &alice.fingerprint(),
                    "alice@example.org",
                    &alice.to_armored_secret(None).unwrap(),
                    &alice.public().to_armored().unwrap(),
                )
                .unwrap();
            let acct = store.account_by_id(id).unwrap().unwrap();
            (
                acct,
                store.folder(id, "INBOX").unwrap(),
                store.folder(id, "Sent").unwrap(),
            )
        };
        Fixture {
            _dir: dir,
            engine,
            acct,
            inbox,
            sent,
        }
    }

    impl Fixture {
        /// Store a hand-made message and return its local id.
        fn store_raw(
            &self,
            folder: &FolderRow,
            uid: u32,
            raw: &[u8],
            received: DateTime<Utc>,
        ) -> i64 {
            let mut ctx = self.engine.sync_context(&self.acct).unwrap();
            let p = self
                .engine
                .process_message(&mut ctx, &self.acct, folder, uid, raw, vec![], received)
                .unwrap();
            self.engine
                .store()
                .insert_message(&p.message)
                .unwrap()
                .unwrap()
        }
    }

    fn mail(from: &str, extra: &str, date: DateTime<Utc>, uid: u32) -> Vec<u8> {
        format!(
            "From: {from}\r\nTo: alice@example.org\r\nSubject: hello {uid}\r\nDate: {}\r\n\
             Message-ID: <m{uid}@x.org>\r\n{extra}MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nbody\r\n",
            date.to_rfc2822()
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn evaluation_applies_window_rules_dedupe_and_cursor() {
        let f = fixture();
        let t0 = Utc.with_ymd_and_hms(2026, 10, 27, 8, 0, 0).unwrap();
        let now = Utc::now();

        // Disabled: nothing is evaluated, the cursor stays.
        let id1 = f.store_raw(&f.inbox, 1, &mail("bob@x.org", "", now, 1), now);
        let r = f
            .engine
            .evaluate_autoreplies(&f.acct, &[id1])
            .await
            .unwrap();
        assert_eq!((r.evaluated, r.replied, r.skipped, r.failed), (0, 0, 0, 0));
        assert!(!r.active);

        // Enable with a window around now: the message stored *before* enabling is behind the
        // cursor and never considered; new ones are.
        f.engine
            .set_autoreply(
                "alice@example.org",
                AutoReplySettings {
                    enabled: true,
                    start: Some(now - Duration::hours(1)),
                    end: Some(now + Duration::hours(1)),
                    body: "Away".into(),
                    ..AutoReplySettings::default()
                },
            )
            .unwrap();
        let state = f.engine.autoreply_state("alice@example.org").unwrap();
        assert_eq!(state.cursor, id1);
        let r = f
            .engine
            .evaluate_autoreplies(&f.acct, &[id1])
            .await
            .unwrap();
        assert_eq!(r.evaluated, 0);

        // A plain mail from Bob: every rule passes and the send is attempted (and fails here:
        // no SMTP server), i.e. the decision was "reply".
        let id2 = f.store_raw(&f.inbox, 2, &mail("Bob <bob@x.org>", "", now, 2), now);
        // Suppressed variants.
        let id3 = f.store_raw(
            &f.inbox,
            3,
            &mail("bob@x.org", "Auto-Submitted: auto-replied\r\n", now, 3),
            now,
        );
        let id4 = f.store_raw(
            &f.inbox,
            4,
            &mail("bob@x.org", "List-Id: <l.x.org>\r\n", now, 4),
            now,
        );
        let id5 = f.store_raw(&f.inbox, 5, &mail("MAILER-DAEMON@x.org", "", now, 5), now);
        let id6 = f.store_raw(
            &f.inbox,
            6,
            &mail("bob@x.org", "", t0 - Duration::days(30), 6),
            now,
        );
        let id7 = f.store_raw(&f.inbox, 7, &mail("alice@example.org", "", now, 7), now);
        let id8 = f.store_raw(
            &f.inbox,
            8,
            &mail("bob@x.org", "Precedence: bulk\r\n", now, 8),
            now,
        );
        let id9 = f.store_raw(
            &f.inbox,
            9,
            &mail("bob@x.org", "Return-Path: <>\r\n", now, 9),
            now,
        );
        let id10 = f.store_raw(&f.sent, 1, &mail("bob@x.org", "", now, 10), now);
        let r = f
            .engine
            .evaluate_autoreplies(&f.acct, &[id2, id3, id4, id5, id6, id7, id8, id9, id10])
            .await
            .unwrap();
        assert!(r.active);
        assert_eq!(r.evaluated, 9, "{r:?}");
        let action = |id: i64| {
            r.outcomes
                .iter()
                .find(|o| o.message == id)
                .map(|o| o.action.clone())
                .unwrap_or_else(|| panic!("no outcome for {id}: {r:?}"))
        };
        assert!(
            matches!(action(id2), AutoReplyAction::Failed { .. }),
            "{:?}",
            action(id2)
        );
        let reason = |id: i64| match action(id) {
            AutoReplyAction::Skipped { reason } => reason,
            other => panic!("expected skip for {id}, got {other:?}"),
        };
        assert_eq!(reason(id3), SuppressReason::AutoSubmitted);
        assert_eq!(reason(id4), SuppressReason::ListHeader);
        assert_eq!(reason(id5), SuppressReason::SystemSender);
        assert_eq!(reason(id6), SuppressReason::OlderThanWindow);
        assert_eq!(reason(id7), SuppressReason::OwnAddress);
        assert_eq!(reason(id8), SuppressReason::Precedence);
        assert_eq!(reason(id9), SuppressReason::NullSender);
        assert_eq!(reason(id10), SuppressReason::NotInbox);
        assert_eq!(r.failed, 1);
        assert_eq!(r.skipped, 8);
        assert_eq!(
            f.engine
                .autoreply_state("alice@example.org")
                .unwrap()
                .cursor,
            id10
        );

        // Nothing is evaluated twice.
        let again = f
            .engine
            .evaluate_autoreplies(&f.acct, &[id2, id3])
            .await
            .unwrap();
        assert_eq!(again.evaluated, 0);
        // run_autoreplies picks up only what is after the cursor.
        let id11 = f.store_raw(
            &f.inbox,
            11,
            &mail("bob@x.org", "Reply-To: noreply@x.org\r\n", now, 11),
            now,
        );
        let run = f.engine.run_autoreplies("alice@example.org").await.unwrap();
        assert_eq!(run.evaluated, 1);
        assert_eq!(run.outcomes[0].message, id11);
        assert!(matches!(
            run.outcomes[0].action,
            AutoReplyAction::Skipped {
                reason: SuppressReason::SystemSender
            }
        ));

        // Dedupe: a logged reply suppresses the next one from the same sender in this period.
        let state = f.engine.autoreply_state("alice@example.org").unwrap();
        f.engine
            .store()
            .insert_autoreply_log(&AutoReplyLogEntry {
                id: 0,
                account: "alice@example.org".into(),
                sender: "carol@x.org".into(),
                period_start: state.period_start,
                sent_at: now.timestamp(),
                message_id: "r@example.org".into(),
                in_reply_to: None,
                original_id: None,
                encrypted: false,
            })
            .unwrap();
        let id12 = f.store_raw(&f.inbox, 12, &mail("carol@x.org", "", now, 12), now);
        let run = f.engine.run_autoreplies("alice@example.org").await.unwrap();
        assert_eq!(run.outcomes[0].message, id12);
        assert!(matches!(
            run.outcomes[0].action,
            AutoReplyAction::Skipped {
                reason: SuppressReason::AlreadyReplied
            }
        ));
        assert_eq!(
            f.engine
                .autoreply_log("alice@example.org", 0)
                .unwrap()
                .len(),
            1
        );

        // Known contacts only: Dave is unknown, Erin was written to before.
        let mut s = f.engine.get_autoreply("alice@example.org").unwrap();
        s.only_to_known_contacts = true;
        f.engine.set_autoreply("alice@example.org", s).unwrap();
        f.engine
            .store()
            .insert_outbox(&crate::store::NewOutbox {
                account_id: f.acct.id,
                message_id: "o@example.org",
                recipients: &["Erin@x.org".to_string()],
                subject: "s",
                mode: "plaintext",
                state: "sent",
                error: None,
                sent_copy_appended: true,
            })
            .unwrap();
        let id13 = f.store_raw(&f.inbox, 13, &mail("dave@x.org", "", now, 13), now);
        let id14 = f.store_raw(&f.inbox, 14, &mail("erin@x.org", "", now, 14), now);
        let run = f.engine.run_autoreplies("alice@example.org").await.unwrap();
        assert_eq!(run.evaluated, 2);
        let find = |id: i64| {
            run.outcomes
                .iter()
                .find(|o| o.message == id)
                .unwrap()
                .action
                .clone()
        };
        assert!(matches!(
            find(id13),
            AutoReplyAction::Skipped {
                reason: SuppressReason::UnknownContact
            }
        ));
        assert!(
            matches!(find(id14), AutoReplyAction::Failed { .. }),
            "{:?}",
            find(id14)
        );

        // Outside the window.
        let mut s = f.engine.get_autoreply("alice@example.org").unwrap();
        s.start = Some(now + Duration::days(1));
        s.end = Some(now + Duration::days(2));
        s.only_to_known_contacts = false;
        f.engine.set_autoreply("alice@example.org", s).unwrap();
        let id15 = f.store_raw(&f.inbox, 15, &mail("frank@x.org", "", now, 15), now);
        let run = f.engine.run_autoreplies("alice@example.org").await.unwrap();
        assert!(!run.active);
        assert_eq!(run.outcomes[0].message, id15);
        assert!(matches!(
            run.outcomes[0].action,
            AutoReplyAction::Skipped {
                reason: SuppressReason::OutsideWindow
            }
        ));
        // Report JSON shape for the bridge.
        let json = serde_json::to_value(&run).unwrap();
        assert_eq!(json["outcomes"][0]["action"], "skipped");
        assert_eq!(json["outcomes"][0]["reason"], "outside_window");
    }
}
