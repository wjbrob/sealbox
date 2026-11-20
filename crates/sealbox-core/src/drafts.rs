//! Saved drafts (engine half): save (upsert by id), list, show, delete, and send through the
//! regular compose + send pipeline ([`Engine::send_with`]), deleting the draft once sent.
//!
//! **At rest** — the same protection level as a stored message: `drafts.subject` and
//! `drafts.body_text` are sealed like `message_blobs.text_body` (vault envelope, AAD
//! `drafts:<column>:<id>`, listed in `vault::WRAPPED` so the legacy migration, a rewrap and
//! the status count cover them); recipients, the reply/forward context and the attachment
//! references stay plaintext like a message's addresses and attachment file names.
//!
//! **Attachments** are a stored blob or a file reference (exactly one per
//! [`DraftAttachment`]). A **blob** ([`Engine::put_draft_blob`], table `draft_blobs`) is a copy
//! of the file sealed like `attachments.data` (AAD `draft_blobs:data:<id>`, in
//! `vault::WRAPPED`); only drafts of the account that stored it can reference it, and it is
//! deleted with the draft once the draft is sent or deleted (a failed send keeps both).
//! [`Engine::sweep_draft_blobs`] deletes blobs that no draft references once they are ten
//! minutes old (a client that stored one and died before saving the draft). A **file
//! reference** (`path`, canonicalised when saved) is read when the draft is sent, so a file
//! moved or deleted in between fails the send (the draft is kept); nothing of it is copied.
//!
//! **One send at a time**: while [`Engine::send_draft`] runs for a draft, a second call for
//! it fails at once with [`Error::DraftBeingSent`] (per engine: two processes sharing one
//! profile are not serialised).
//!
//! **On the server** (`drafts_imap.rs`): every draft has a uuid (table `draft_sync`) and a copy
//! in the account's IMAP Drafts role folder, PGP/MIME encrypted and signed to the account's
//! **own key only** — the real subject a protected header, a placeholder outside, no
//! recipients outside, flagged `\Draft`, headers `X-Sealbox-Draft: <uuid>` and (when it has
//! file references) `X-Sealbox-Draft-Files: <n>`. Inside: a JSON manifest (every field of the
//! draft) and the stored blobs as MIME parts; file references stay local-only.
//! [`Engine::push_draft`] replaces the copy (APPEND the new one, then `\Deleted` + expunge the
//! old UIDs — never the other way round); a local delete or send leaves a tombstone (the
//! `draft_sync` row loses its `draft_id`) whose server copy [`Engine::purge_deleted_drafts`]
//! removes (`send_draft` does at once, best effort). [`Engine::sync_drafts`] (also run by
//! `sync_folder_role(Drafts)`) imports server copies this device can open (own key, signed by
//! it), de-duplicates by uuid, lets the newer `updated_at` win when both sides changed, uploads
//! local changes, and deletes a local draft whose server copy disappeared only if it was not
//! edited here since the last sync. A device without the key sees the messages but cannot read
//! them (counted as `unreadable`, never deleted). Webmail shows a placeholder-subject draft.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::types::Value;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::signature::{ComposeKind, ComposeOptions};
use crate::store::{AccountRow, Store};
use crate::types::{AttachmentData, Draft, GuestMode, SendPolicy, SendReport};

/// Schema of the drafts, draft-blob and draft-sync tables (applied by `Store::open`). A
/// `draft_sync` row (uuid, revisions, server state) follows each draft; deleting the draft
/// leaves it as a tombstone (`draft_id` NULL) until the server copy is gone. `AUTOINCREMENT`: an
/// id is never handed out twice, so a stale id held by a UI cannot overwrite a newer draft,
/// and a stale blob reference can never name another file.
pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS drafts (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id           INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind                 TEXT NOT NULL DEFAULT 'new',
    in_reply_to          TEXT,
    forward_of           TEXT,
    quote                INTEGER NOT NULL DEFAULT 0,
    references_json      TEXT NOT NULL DEFAULT '[]',
    to_json              TEXT NOT NULL DEFAULT '[]',
    cc_json              TEXT NOT NULL DEFAULT '[]',
    bcc_json             TEXT NOT NULL DEFAULT '[]',
    subject              TEXT NOT NULL,
    body_text            TEXT NOT NULL,
    attachments_json     TEXT NOT NULL DEFAULT '[]',
    policy               TEXT NOT NULL DEFAULT 'auto',
    guest_mode           TEXT NOT NULL DEFAULT 'passphrase',
    guest_recipient_hint TEXT,
    no_signature         INTEGER NOT NULL DEFAULT 0,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS drafts_account ON drafts(account_id, updated_at);
CREATE TABLE IF NOT EXISTS draft_blobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id   INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    size         INTEGER NOT NULL,
    data         BLOB NOT NULL,
    created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS draft_blobs_account ON draft_blobs(account_id, created_at);
CREATE TABLE IF NOT EXISTS draft_sync (
    uuid              TEXT PRIMARY KEY,
    account_id        INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    draft_id          INTEGER UNIQUE REFERENCES drafts(id) ON DELETE SET NULL,
    origin            TEXT NOT NULL DEFAULT 'local',
    local_rev         INTEGER NOT NULL DEFAULT 1,
    synced_rev        INTEGER NOT NULL DEFAULT 0,
    server_updated_at INTEGER,
    remote_files      INTEGER NOT NULL DEFAULT 0,
    deleted_at        INTEGER
);
CREATE INDEX IF NOT EXISTS draft_sync_account ON draft_sync(account_id);
"#;

/// Blobs no draft references are swept ([`Engine::sweep_draft_blobs`]) once this old: long
/// enough for a client to store a file and then save the draft that references it.
pub(crate) const ORPHAN_BLOB_GRACE_SECS: i64 = 10 * 60;

/// A file attached to a draft: a sealed copy in the store (`blob_id`, from
/// [`Engine::put_draft_blob`]) or a reference to a file (`path`, read when the draft is sent).
/// Exactly one of the two is set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftAttachment {
    /// Path of the file; [`Engine::save_draft`] stores it canonicalised (absolute). Empty
    /// for a stored blob.
    #[serde(default)]
    pub path: String,
    /// The stored blob holding the file (sealed at rest); `None` = the file at `path`.
    /// Missing in drafts saved before blobs existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_id: Option<i64>,
    /// File name the recipient sees; empty = the file name of `path` / the blob's name.
    #[serde(default)]
    pub name: String,
    /// MIME type; empty = the blob's type, else `application/octet-stream`.
    #[serde(default)]
    pub content_type: String,
}

/// A file stored for an account's drafts ([`Engine::put_draft_blob`]). Metadata only: the
/// sealed bytes come from [`Engine::get_draft_blob`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftBlobInfo {
    pub id: i64,
    /// The account (address) whose drafts may reference it.
    pub account: String,
    /// Name it was stored under (the default name of an attachment referencing it).
    pub filename: String,
    /// MIME type it was stored with; may be empty.
    pub content_type: String,
    /// Bytes.
    pub size: u64,
    /// Unix seconds.
    pub created_at: i64,
}

/// The drafts an [`Engine`] is sending right now (see [`Engine::send_draft`]).
#[derive(Debug, Default)]
pub(crate) struct DraftSends(Mutex<HashSet<i64>>);

impl DraftSends {
    fn ids(&self) -> MutexGuard<'_, HashSet<i64>> {
        match self.0.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Marks draft `id` as being sent until the claim is dropped; [`Error::DraftBeingSent`]
    /// when it already is.
    fn claim(&self, id: i64) -> Result<SendClaim<'_>> {
        if self.ids().insert(id) {
            Ok(SendClaim { sends: self, id })
        } else {
            Err(Error::DraftBeingSent(id))
        }
    }
}

/// Releases its draft id when dropped: when the send returns, fails, or is cancelled.
struct SendClaim<'a> {
    sends: &'a DraftSends,
    id: i64,
}

impl Drop for SendClaim<'_> {
    fn drop(&mut self) {
        self.sends.ids().remove(&self.id);
    }
}

/// Input of [`Engine::save_draft`]: the whole draft (saving replaces every field).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
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

/// A saved draft ([`Engine::get_draft`], [`Engine::list_drafts`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedDraft {
    pub id: i64,
    /// Sending account (address).
    pub account: String,
    pub kind: ComposeKind,
    /// Message-ID (no angle brackets) of the message answered, or its local id when it has
    /// none. Resolved when saving: local ids are not stable across moves.
    #[serde(default)]
    pub in_reply_to: Option<String>,
    /// Message-ID (or local id) of the message forwarded.
    #[serde(default)]
    pub forward_of: Option<String>,
    pub quote: bool,
    /// The answered message's `References` plus its Message-ID, oldest first. Informational:
    /// sending recomputes them from the stored original (as `send` does).
    #[serde(default)]
    pub references: Vec<String>,
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    pub subject: String,
    pub body_text: String,
    #[serde(default)]
    pub attachments: Vec<DraftAttachment>,
    pub policy: SendPolicy,
    pub guest_mode: GuestMode,
    #[serde(default)]
    pub guest_recipient_hint: Option<String>,
    pub no_signature: bool,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds; lists are newest first by this.
    pub updated_at: i64,
    /// Where the draft was first saved: here, or on another device (imported from the
    /// account's Drafts folder by [`Engine::sync_drafts`]).
    #[serde(default)]
    pub origin: DraftOrigin,
    /// File references the device that saved it kept there (`X-Sealbox-Draft-Files`): they
    /// are not in its server copy, so not here.
    #[serde(default)]
    pub remote_files: u32,
}

/// Where a saved draft was first saved ([`SavedDraft::origin`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftOrigin {
    /// Saved on this device.
    #[default]
    Local,
    /// Imported from the server (saved on another device with the same key).
    Server,
}

fn kind_str(k: ComposeKind) -> &'static str {
    match k {
        ComposeKind::New => "new",
        ComposeKind::Reply => "reply",
        ComposeKind::Forward => "forward",
    }
}

fn kind_from(s: &str) -> ComposeKind {
    match s {
        "reply" => ComposeKind::Reply,
        "forward" => ComposeKind::Forward,
        _ => ComposeKind::New,
    }
}

fn guest_mode_str(m: GuestMode) -> &'static str {
    match m {
        GuestMode::Passphrase => "passphrase",
        GuestMode::OneClick => "one_click",
        GuestMode::EmailCode => "email_code",
    }
}

fn guest_mode_from(s: &str) -> GuestMode {
    match s {
        "one_click" => GuestMode::OneClick,
        "email_code" => GuestMode::EmailCode,
        _ => GuestMode::Passphrase,
    }
}

fn strip_brackets(s: &str) -> &str {
    s.trim().trim_start_matches('<').trim_end_matches('>')
}

/// A stored reference as `Draft::in_reply_to` / `ComposeOptions::forward_of` expect it: a
/// local id stays digits, a Message-ID goes in angle brackets so that one made of digits is
/// never taken for a local id.
fn reference_for_send(stored: &str) -> String {
    if !stored.is_empty() && stored.bytes().all(|b| b.is_ascii_digit()) {
        stored.to_string()
    } else {
        format!("<{stored}>")
    }
}

fn clean_list(list: &[String]) -> Vec<String> {
    list.iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// What [`Engine::save_draft`] writes (validated, references resolved).
pub(crate) struct DraftRecord {
    pub account_id: i64,
    pub kind: ComposeKind,
    pub in_reply_to: Option<String>,
    pub forward_of: Option<String>,
    pub quote: bool,
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
    /// `Some` when the record comes from a server copy (`drafts_imap.rs`): kept clean.
    pub from_server: Option<FromServer>,
}

/// A record read from a server copy: its uuid, times and the saving device's file count.
pub(crate) struct FromServer {
    pub uuid: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub remote_files: i64,
}

const DRAFT_COLUMNS: &str = "d.id, a.email, d.kind, d.in_reply_to, d.forward_of, d.quote, \
     d.references_json, d.to_json, d.cc_json, d.bcc_json, d.subject, d.body_text, \
     d.attachments_json, d.policy, d.guest_mode, d.guest_recipient_hint, d.no_signature, \
     d.created_at, d.updated_at, COALESCE(s.origin, 'local'), COALESCE(s.remote_files, 0)";

/// The tables [`DRAFT_COLUMNS`] are read from.
const DRAFT_FROM: &str = "FROM drafts d JOIN accounts a ON a.id = d.account_id \
     LEFT JOIN draft_sync s ON s.draft_id = d.id";

fn json_list<T: serde::de::DeserializeOwned>(s: &str) -> Vec<T> {
    serde_json::from_str(s).unwrap_or_default()
}

/// The id the next row of `table` (`drafts` or `draft_blobs`, both AUTOINCREMENT) gets,
/// chosen up front so the AAD of its sealed columns can bind it: past the AUTOINCREMENT
/// high-water mark, so deleted ids are never reused. (`sqlite_sequence` is missing only when
/// the tables were created before AUTOINCREMENT; there, the highest id is all there is.)
fn next_row_id(conn: &Connection, table: &str) -> Result<i64> {
    let has_sequence: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' \
         AND name = 'sqlite_sequence')",
        [],
        |r| r.get(0),
    )?;
    let sql = if has_sequence {
        format!(
            "SELECT MAX(COALESCE((SELECT seq FROM sqlite_sequence WHERE name = '{table}'), 0), \
             COALESCE((SELECT MAX(id) FROM {table}), 0)) + 1"
        )
    } else {
        format!("SELECT COALESCE(MAX(id), 0) + 1 FROM {table}")
    };
    Ok(conn.query_row(&sql, [], |r| r.get(0))?)
}

/// The stored blobs a draft's `attachments_json` references.
fn blob_ids_of(attachments_json: &str) -> HashSet<i64> {
    json_list::<DraftAttachment>(attachments_json)
        .iter()
        .filter_map(|a| a.blob_id)
        .collect()
}

/// Every blob id some saved draft references.
fn referenced_blob_ids(conn: &Connection) -> Result<HashSet<i64>> {
    let mut stmt = conn.prepare("SELECT attachments_json FROM drafts")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let mut ids = HashSet::new();
    for json in rows {
        ids.extend(blob_ids_of(&json?));
    }
    Ok(ids)
}

const BLOB_COLUMNS: &str =
    "b.id, a.email, b.filename, b.content_type, b.size, b.created_at, b.account_id";

/// A blob row (metadata, never the data) and the id of the account owning it.
fn blob_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, DraftBlobInfo)> {
    Ok((
        r.get(6)?,
        DraftBlobInfo {
            id: r.get(0)?,
            account: r.get(1)?,
            filename: r.get(2)?,
            content_type: r.get(3)?,
            size: u64::try_from(r.get::<_, i64>(4)?).unwrap_or(0),
            created_at: r.get(5)?,
        },
    ))
}

/// A draft row with its subject and body still wrapped.
fn draft_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(SavedDraft, Value, Value)> {
    let policy: String = r.get(13)?;
    Ok((
        SavedDraft {
            id: r.get(0)?,
            account: r.get(1)?,
            kind: kind_from(&r.get::<_, String>(2)?),
            in_reply_to: r.get(3)?,
            forward_of: r.get(4)?,
            quote: r.get(5)?,
            references: json_list(&r.get::<_, String>(6)?),
            to: json_list(&r.get::<_, String>(7)?),
            cc: json_list(&r.get::<_, String>(8)?),
            bcc: json_list(&r.get::<_, String>(9)?),
            subject: String::new(),
            body_text: String::new(),
            attachments: json_list(&r.get::<_, String>(12)?),
            policy: policy.parse().unwrap_or_default(),
            guest_mode: guest_mode_from(&r.get::<_, String>(14)?),
            guest_recipient_hint: r.get(15)?,
            no_signature: r.get(16)?,
            created_at: r.get(17)?,
            updated_at: r.get(18)?,
            origin: if r.get::<_, String>(19)? == "server" {
                DraftOrigin::Server
            } else {
                DraftOrigin::Local
            },
            remote_files: u32::try_from(r.get::<_, i64>(20)?).unwrap_or(0),
        },
        r.get(10)?,
        r.get(11)?,
    ))
}

impl Store {
    /// Insert (`id = None`, the id is chosen under the write lock) or replace draft `id`, and
    /// keep its `draft_sync` row: a local save creates it (fresh uuid) or bumps `local_rev`; a
    /// record from a server copy keeps the server's uuid and times and is clean.
    pub(crate) fn upsert_draft(&self, id: Option<i64>, d: &DraftRecord) -> Result<i64> {
        let tx = Transaction::new_unchecked(self.conn(), TransactionBehavior::Immediate)?;
        let id = match id {
            Some(id) => id,
            None => next_row_id(&tx, "drafts")?,
        };
        let rid = id.to_string();
        let v = self.vault();
        let subject = v.seal_text("drafts", "subject", &rid, &d.subject)?;
        let body = v.seal_text("drafts", "body_text", &rid, &d.body_text)?;
        let now = crate::store::now();
        let (created, updated) = d
            .from_server
            .as_ref()
            .map_or((now, now), |s| (s.created_at, s.updated_at));
        tx.execute(
            "INSERT INTO drafts (id, account_id, kind, in_reply_to, forward_of, quote, \
             references_json, to_json, cc_json, bcc_json, subject, body_text, attachments_json, \
             policy, guest_mode, guest_recipient_hint, no_signature, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
             ?18, ?19) \
             ON CONFLICT(id) DO UPDATE SET account_id = excluded.account_id, \
             kind = excluded.kind, in_reply_to = excluded.in_reply_to, \
             forward_of = excluded.forward_of, quote = excluded.quote, \
             references_json = excluded.references_json, to_json = excluded.to_json, \
             cc_json = excluded.cc_json, bcc_json = excluded.bcc_json, \
             subject = excluded.subject, body_text = excluded.body_text, \
             attachments_json = excluded.attachments_json, policy = excluded.policy, \
             guest_mode = excluded.guest_mode, \
             guest_recipient_hint = excluded.guest_recipient_hint, \
             no_signature = excluded.no_signature, updated_at = excluded.updated_at",
            params![
                id,
                d.account_id,
                kind_str(d.kind),
                d.in_reply_to,
                d.forward_of,
                d.quote,
                serde_json::to_string(&d.references)?,
                serde_json::to_string(&d.to)?,
                serde_json::to_string(&d.cc)?,
                serde_json::to_string(&d.bcc)?,
                subject,
                body,
                serde_json::to_string(&d.attachments)?,
                d.policy.to_string(),
                guest_mode_str(d.guest_mode),
                d.guest_recipient_hint,
                d.no_signature,
                created,
                updated,
            ],
        )?;
        match &d.from_server {
            None => tx.execute(
                "INSERT INTO draft_sync (uuid, account_id, draft_id) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(draft_id) DO UPDATE SET local_rev = local_rev + 1, \
                 account_id = excluded.account_id",
                params![crate::drafts_imap::new_uuid(), d.account_id, id],
            )?,
            Some(s) => tx.execute(
                "INSERT INTO draft_sync (uuid, account_id, draft_id, origin, local_rev, \
                 synced_rev, server_updated_at, remote_files) \
                 VALUES (?1, ?2, ?3, 'server', 0, 0, ?4, ?5) \
                 ON CONFLICT(draft_id) DO UPDATE SET synced_rev = local_rev, \
                 server_updated_at = excluded.server_updated_at, \
                 remote_files = excluded.remote_files",
                params![s.uuid, d.account_id, id, s.updated_at, s.remote_files],
            )?,
        };
        tx.commit()?;
        Ok(id)
    }

    fn finish_draft(
        &self,
        (mut d, subject, body): (SavedDraft, Value, Value),
    ) -> Result<SavedDraft> {
        let rid = d.id.to_string();
        d.subject = self.vault().open_text("drafts", "subject", &rid, subject)?;
        d.body_text = self.vault().open_text("drafts", "body_text", &rid, body)?;
        Ok(d)
    }

    pub(crate) fn draft(&self, id: i64) -> Result<Option<SavedDraft>> {
        self.conn()
            .query_row(
                &format!("SELECT {DRAFT_COLUMNS} {DRAFT_FROM} WHERE d.id = ?1"),
                params![id],
                draft_from_row,
            )
            .optional()?
            .map(|r| self.finish_draft(r))
            .transpose()
    }

    pub(crate) fn drafts(&self, account_id: Option<i64>) -> Result<Vec<SavedDraft>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {DRAFT_COLUMNS} {DRAFT_FROM} \
             WHERE ?1 IS NULL OR d.account_id = ?1 ORDER BY d.updated_at DESC, d.id DESC"
        ))?;
        let rows = stmt.query_map(params![account_id], draft_from_row)?;
        let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(|r| self.finish_draft(r)).collect()
    }

    /// Delete draft `id` and, in the same transaction, the blobs it references that no other
    /// draft does. `false` when there was no such draft.
    pub(crate) fn remove_draft(&self, id: i64) -> Result<bool> {
        let tx = Transaction::new_unchecked(self.conn(), TransactionBehavior::Immediate)?;
        let row: Option<(i64, String)> = tx
            .query_row(
                "SELECT account_id, attachments_json FROM drafts WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((account_id, attachments)) = row else {
            return Ok(false);
        };
        tx.execute("DELETE FROM drafts WHERE id = ?1", params![id])?;
        let blobs = blob_ids_of(&attachments);
        if !blobs.is_empty() {
            let still_referenced = referenced_blob_ids(&tx)?;
            for blob in blobs.difference(&still_referenced) {
                tx.execute(
                    "DELETE FROM draft_blobs WHERE id = ?1 AND account_id = ?2",
                    params![blob, account_id],
                )?;
            }
        }
        tx.commit()?;
        Ok(true)
    }

    fn insert_draft_blob(
        &self,
        account_id: i64,
        filename: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<i64> {
        let tx = Transaction::new_unchecked(self.conn(), TransactionBehavior::Immediate)?;
        let id = next_row_id(&tx, "draft_blobs")?;
        let data = self
            .vault()
            .seal_blob("draft_blobs", "data", &id.to_string(), bytes)?;
        tx.execute(
            "INSERT INTO draft_blobs (id, account_id, filename, content_type, size, data, \
             created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id,
                account_id,
                filename,
                content_type,
                i64::try_from(bytes.len()).unwrap_or(i64::MAX),
                data,
                crate::store::now(),
            ],
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// A blob's owning account id and metadata; nothing is unsealed.
    fn draft_blob_row(&self, id: i64) -> Result<Option<(i64, DraftBlobInfo)>> {
        Ok(self
            .conn()
            .query_row(
                &format!(
                    "SELECT {BLOB_COLUMNS} FROM draft_blobs b \
                     JOIN accounts a ON a.id = b.account_id WHERE b.id = ?1"
                ),
                params![id],
                blob_from_row,
            )
            .optional()?)
    }

    /// A blob's bytes, unsealed.
    fn draft_blob_bytes(&self, id: i64) -> Result<Option<Vec<u8>>> {
        let data: Option<Value> = self
            .conn()
            .query_row(
                "SELECT data FROM draft_blobs WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        data.map(|v| {
            self.vault()
                .open_blob("draft_blobs", "data", &id.to_string(), v)
        })
        .transpose()
    }

    fn draft_blob_rows(&self, account_id: i64) -> Result<Vec<DraftBlobInfo>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {BLOB_COLUMNS} FROM draft_blobs b JOIN accounts a ON a.id = b.account_id \
             WHERE b.account_id = ?1 ORDER BY b.created_at, b.id"
        ))?;
        let rows = stmt.query_map(params![account_id], blob_from_row)?;
        Ok(rows
            .map(|r| r.map(|(_, info)| info))
            .collect::<rusqlite::Result<_>>()?)
    }

    fn remove_draft_blob(&self, id: i64) -> Result<bool> {
        Ok(self
            .conn()
            .execute("DELETE FROM draft_blobs WHERE id = ?1", params![id])?
            > 0)
    }

    /// Delete `account_id`'s blobs created before `created_before` that no draft references.
    fn sweep_draft_blobs(&self, account_id: i64, created_before: i64) -> Result<usize> {
        let tx = Transaction::new_unchecked(self.conn(), TransactionBehavior::Immediate)?;
        let referenced = referenced_blob_ids(&tx)?;
        let old: Vec<i64> = {
            let mut stmt =
                tx.prepare("SELECT id FROM draft_blobs WHERE account_id = ?1 AND created_at < ?2")?;
            let rows = stmt.query_map(params![account_id, created_before], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut swept = 0;
        for id in old.into_iter().filter(|id| !referenced.contains(id)) {
            swept += tx.execute("DELETE FROM draft_blobs WHERE id = ?1", params![id])?;
        }
        tx.commit()?;
        Ok(swept)
    }
}

impl Engine {
    /// The stored reference and `References` of the message a reply answers: a local id
    /// becomes that message's Message-ID; a Message-ID that is not stored is kept as is.
    fn draft_reply_context(&self, raw: &str, quote: bool) -> Result<(String, Vec<String>)> {
        let store = self.store();
        let row = match raw.trim().parse::<i64>() {
            Ok(id) => Some(store.message(id)?),
            Err(_) => store.message_by_message_id(strip_brackets(raw))?,
        };
        match row {
            Some(r) => {
                let mid = r
                    .summary
                    .message_id
                    .as_deref()
                    .map(strip_brackets)
                    .filter(|m| !m.is_empty())
                    .map(str::to_owned);
                let mut refs: Vec<String> = r.references.clone();
                match mid {
                    Some(mid) => {
                        if !refs.contains(&mid) {
                            refs.push(mid.clone());
                        }
                        Ok((mid, refs))
                    }
                    None => Ok((r.summary.id.to_string(), refs)),
                }
            }
            None if quote => Err(Error::InvalidInput(
                "cannot quote: the replied-to message is not stored locally".into(),
            )),
            None => {
                let mid = strip_brackets(raw).to_string();
                if mid.is_empty() {
                    return Err(Error::InvalidInput("empty in_reply_to".into()));
                }
                Ok((mid.clone(), vec![mid]))
            }
        }
    }

    /// The stored reference of the message a forward carries (it must be stored locally).
    fn draft_forward_reference(&self, raw: &str) -> Result<String> {
        let store = self.store();
        let row = match raw.trim().parse::<i64>() {
            Ok(id) => Some(store.message(id)?),
            Err(_) => store.message_by_message_id(strip_brackets(raw))?,
        };
        let row = row.ok_or_else(|| {
            Error::InvalidInput(
                "forward: `forward_of` must name a stored message (local id or Message-ID)".into(),
            )
        })?;
        Ok(row
            .summary
            .message_id
            .as_deref()
            .map(strip_brackets)
            .filter(|m| !m.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| row.summary.id.to_string()))
    }

    /// Save a draft: `input.id = None` creates one, `Some(id)` replaces that draft (or
    /// re-creates it under that id when it is gone). The subject and body are sealed at rest
    /// like message bodies. Recipients may be empty or incomplete (it is a draft); a reply
    /// target given as a local id is stored as its Message-ID. Each attachment is a stored
    /// blob of this account ([`Engine::put_draft_blob`]; its name and type are the defaults)
    /// or a path naming an existing file (stored canonicalised), never both. Nothing is sent.
    pub fn save_draft(&self, input: DraftInput) -> Result<SavedDraft> {
        if input.id.is_some_and(|id| id <= 0) {
            return Err(Error::InvalidInput("draft ids are positive".into()));
        }
        let acct = self.account_row(&input.account)?;
        let in_reply_to = input
            .in_reply_to
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let forward_of = input
            .forward_of
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let kind = match (input.kind, in_reply_to, forward_of) {
            (_, Some(_), Some(_)) => {
                return Err(Error::InvalidInput(
                    "a draft replies (in_reply_to) or forwards (forward_of), not both".into(),
                ))
            }
            (ComposeKind::New | ComposeKind::Reply, Some(_), None) => ComposeKind::Reply,
            (ComposeKind::New | ComposeKind::Forward, None, Some(_)) => ComposeKind::Forward,
            (ComposeKind::New, None, None) => ComposeKind::New,
            (ComposeKind::Reply, None, _) => {
                return Err(Error::InvalidInput(
                    "a reply draft needs in_reply_to".into(),
                ))
            }
            (ComposeKind::Forward, _, None) => {
                return Err(Error::InvalidInput(
                    "a forward draft needs forward_of".into(),
                ))
            }
        };
        let (in_reply_to, references) = match in_reply_to {
            Some(raw) => {
                let (r, refs) = self.draft_reply_context(raw, input.quote)?;
                (Some(r), refs)
            }
            None => (None, Vec::new()),
        };
        let forward_of = forward_of
            .map(|raw| self.draft_forward_reference(raw))
            .transpose()?;
        let attachments = input
            .attachments
            .iter()
            .map(|a| self.checked_attachment(&acct, a))
            .collect::<Result<Vec<_>>>()?;
        let record = DraftRecord {
            account_id: acct.id,
            kind,
            in_reply_to,
            forward_of,
            quote: input.quote,
            references,
            to: clean_list(&input.to),
            cc: clean_list(&input.cc),
            bcc: clean_list(&input.bcc),
            subject: input.subject,
            body_text: input.body_text,
            attachments,
            policy: input.policy,
            guest_mode: input.guest_mode,
            guest_recipient_hint: input
                .guest_recipient_hint
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty()),
            no_signature: input.no_signature,
            from_server: None,
        };
        let store = self.store();
        let id = store.upsert_draft(input.id, &record)?;
        store
            .draft(id)?
            .ok_or_else(|| Error::InvalidInput(format!("draft {id} vanished while saving")))
    }

    /// One attachment of a draft being saved: exactly one of a stored blob of `acct` (name
    /// and type default to the blob's) or an existing file (canonicalised; the name defaults
    /// to the file's).
    fn checked_attachment(
        &self,
        acct: &AccountRow,
        a: &DraftAttachment,
    ) -> Result<DraftAttachment> {
        let path = a.path.trim();
        let name = a.name.trim();
        let content_type = a.content_type.trim();
        match (a.blob_id, path.is_empty()) {
            (Some(_), false) => Err(Error::InvalidInput(format!(
                "draft attachment {path}: a file path or a stored blob, not both"
            ))),
            (None, true) => Err(Error::InvalidInput(
                "a draft attachment needs a file path or a stored blob".into(),
            )),
            (Some(blob), true) => {
                let info = self
                    .store()
                    .draft_blob_row(blob)?
                    .filter(|(owner, _)| *owner == acct.id)
                    .map(|(_, info)| info)
                    .ok_or_else(|| {
                        Error::InvalidInput(format!(
                            "draft attachment: no stored blob {blob} for {}",
                            acct.email
                        ))
                    })?;
                Ok(DraftAttachment {
                    path: String::new(),
                    blob_id: Some(blob),
                    name: if name.is_empty() {
                        info.filename
                    } else {
                        name.to_string()
                    },
                    content_type: if content_type.is_empty() {
                        info.content_type
                    } else {
                        content_type.to_string()
                    },
                })
            }
            (None, false) => {
                let file = std::fs::canonicalize(path).map_err(|e| {
                    Error::InvalidInput(format!("draft attachment {}: {e}", a.path))
                })?;
                if !file.is_file() {
                    return Err(Error::InvalidInput(format!(
                        "draft attachment {} is not a file",
                        a.path
                    )));
                }
                Ok(DraftAttachment {
                    path: file.to_string_lossy().into_owned(),
                    blob_id: None,
                    name: if name.is_empty() {
                        file_name(&file)
                    } else {
                        name.to_string()
                    },
                    content_type: content_type.to_string(),
                })
            }
        }
    }

    /// Saved drafts, most recently updated first; `account` = only that account's.
    pub fn list_drafts(&self, account: Option<&str>) -> Result<Vec<SavedDraft>> {
        let account_id = match account.map(str::trim).filter(|a| !a.is_empty()) {
            Some(a) => Some(self.account_row(a)?.id),
            None => None,
        };
        self.store().drafts(account_id)
    }

    /// One saved draft; an unknown id is [`Error::InvalidInput`].
    pub fn get_draft(&self, id: i64) -> Result<SavedDraft> {
        self.store()
            .draft(id)?
            .ok_or_else(|| Error::InvalidInput(format!("no draft {id}")))
    }

    /// Delete a draft and the stored blobs only it references; `false` when there was none
    /// with that id.
    pub fn delete_draft(&self, id: i64) -> Result<bool> {
        self.store().remove_draft(id)
    }

    /// Send a saved draft through [`Engine::send_with`] — the same policy, signature,
    /// quoting, forwarding, Sent-copy and outbox handling as `send` — and delete it (with its
    /// stored blobs) once the message is out. A failure (refused policy, missing attachment
    /// file or blob, network) keeps the draft and its blobs. While it runs, another call for
    /// the same draft fails at once with [`Error::DraftBeingSent`] and sends nothing, so one
    /// draft is never sent twice by this engine.
    pub async fn send_draft(&self, id: i64) -> Result<SendReport> {
        let _sending = self.draft_sends.claim(id)?;
        let d = self.get_draft(id)?;
        let account_id = self.account_row(&d.account)?.id;
        let mut attachments = Vec::with_capacity(d.attachments.len());
        for a in &d.attachments {
            attachments.push(match a.blob_id {
                Some(blob) => self.blob_attachment(account_id, blob, a)?,
                None => {
                    let path = Path::new(&a.path);
                    let data = std::fs::read(path).map_err(|e| {
                        Error::InvalidInput(format!("draft attachment {}: {e}", a.path))
                    })?;
                    AttachmentData {
                        filename: if a.name.is_empty() {
                            file_name(path)
                        } else {
                            a.name.clone()
                        },
                        content_type: a.content_type.clone(),
                        data,
                    }
                }
            });
        }
        let draft = Draft {
            to: d.to.clone(),
            cc: d.cc.clone(),
            bcc: d.bcc.clone(),
            subject: d.subject.clone(),
            text: d.body_text.clone(),
            html: None,
            attachments,
            in_reply_to: d.in_reply_to.as_deref().map(reference_for_send),
            policy: d.policy,
            guest_mode: d.guest_mode,
            guest_recipient_hint: d.guest_recipient_hint.clone(),
        };
        let opts = ComposeOptions {
            kind: d.kind,
            quote: d.quote,
            forward_of: d.forward_of.as_deref().map(reference_for_send),
            skip_signature: d.no_signature,
        };
        let report = self.send_with(&d.account, draft, opts).await?;
        // The mail is out: a failure to drop the draft must not read as a failed send.
        if let Err(e) = self.delete_draft(id) {
            tracing::warn!(id, "draft {id} was sent but could not be deleted: {e}");
        } else if let Err(e) = self.purge_deleted_drafts(&d.account).await {
            // The tombstone stays: the next draft sync removes the server copy.
            tracing::warn!(
                id,
                "draft {id} was sent; its server copy stays until a sync: {e}"
            );
        }
        Ok(report)
    }

    /// A stored-blob attachment of a draft of `account_id`, unsealed for sending.
    fn blob_attachment(
        &self,
        account_id: i64,
        blob: i64,
        a: &DraftAttachment,
    ) -> Result<AttachmentData> {
        let gone = || {
            Error::InvalidInput(format!(
                "draft attachment {}: stored blob {blob} is gone",
                a.name
            ))
        };
        let store = self.store();
        let (owner, info) = store.draft_blob_row(blob)?.ok_or_else(gone)?;
        if owner != account_id {
            return Err(Error::InvalidInput(format!(
                "draft attachment {}: blob {blob} belongs to another account",
                a.name
            )));
        }
        let data = store.draft_blob_bytes(blob)?.ok_or_else(gone)?;
        Ok(AttachmentData {
            filename: if a.name.is_empty() {
                info.filename
            } else {
                a.name.clone()
            },
            content_type: if a.content_type.is_empty() {
                info.content_type
            } else {
                a.content_type.clone()
            },
            data,
        })
    }

    // ----- stored blobs (sealed draft attachments) -----------------------------------------

    /// Store a sealed copy of a file for `account_email`'s drafts and return its id; a draft
    /// references it with [`DraftAttachment::blob_id`]. Sealed at rest like a stored
    /// attachment (AAD `draft_blobs:data:<id>`, in `vault::WRAPPED`). An empty `filename` is
    /// stored as `attachment`. Unreferenced blobs are swept after ten minutes
    /// ([`Engine::sweep_draft_blobs`]).
    pub fn put_draft_blob(
        &self,
        account_email: &str,
        filename: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<i64> {
        let acct = self.account_row(account_email)?;
        let filename = match filename.trim() {
            "" => "attachment",
            name => name,
        };
        self.store()
            .insert_draft_blob(acct.id, filename, content_type.trim(), bytes)
    }

    /// A stored blob: its metadata and its bytes (unsealed). An unknown id is
    /// [`Error::InvalidInput`].
    pub fn get_draft_blob(&self, id: i64) -> Result<(DraftBlobInfo, Vec<u8>)> {
        let missing = || Error::InvalidInput(format!("no draft blob {id}"));
        let store = self.store();
        let (_, info) = store.draft_blob_row(id)?.ok_or_else(missing)?;
        let data = store.draft_blob_bytes(id)?.ok_or_else(missing)?;
        Ok((info, data))
    }

    /// Delete a stored blob; `false` when there was none. A draft still referencing it fails
    /// to send until the attachment is removed (sending and deleting a draft delete its
    /// blobs themselves).
    pub fn delete_draft_blob(&self, id: i64) -> Result<bool> {
        self.store().remove_draft_blob(id)
    }

    /// `account_email`'s stored blobs, oldest first (metadata only; nothing is unsealed).
    pub fn list_draft_blobs(&self, account_email: &str) -> Result<Vec<DraftBlobInfo>> {
        let acct = self.account_row(account_email)?;
        self.store().draft_blob_rows(acct.id)
    }

    /// Delete `account_email`'s stored blobs that no saved draft references and that are
    /// more than ten minutes old (stored by a client that died before saving the draft, or
    /// left behind when a draft dropped the attachment); returns how many. Apps call it at
    /// start-up.
    pub fn sweep_draft_blobs(&self, account_email: &str) -> Result<usize> {
        let acct = self.account_row(account_email)?;
        let swept = self
            .store()
            .sweep_draft_blobs(acct.id, crate::store::now() - ORPHAN_BLOB_GRACE_SECS)?;
        if swept > 0 {
            tracing::info!(swept, "removed {swept} unreferenced draft blob(s)");
        }
        Ok(swept)
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "attachment".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{EngineConfig, DB_FILE};
    use crate::store::{NewAccount, NewMessage};
    use crate::types::{Address, AuthKind, SendMode, SignatureSummary};
    use crate::vault::ProfileKeySource;
    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::mime::MessageKind;
    use sealbox_mail::Security;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, watch};

    fn new_account(store: &Store, email: &str) -> i64 {
        let ep = Endpoint::new("127.0.0.1", 3143, Security::Plain);
        store
            .insert_account(&NewAccount {
                email,
                display_name: "",
                imap: &ep,
                smtp: &ep,
                auth_kind: AuthKind::Password,
                login: email,
                credential: "pw",
            })
            .unwrap()
    }

    fn engine_with(dir: &Path, key: ProfileKeySource) -> Engine {
        Engine::open_with(
            dir,
            EngineConfig {
                profile_key: key,
                ..EngineConfig::default()
            },
        )
        .unwrap()
    }

    /// A keyed engine (the crate's test default key) with one account.
    fn engine() -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        new_account(&e.store(), "alice@example.org");
        (dir, e)
    }

    fn input(subject: &str, body: &str) -> DraftInput {
        DraftInput {
            account: "alice@example.org".into(),
            to: vec!["bob@example.org".into(), "  ".into()],
            subject: subject.into(),
            body_text: body.into(),
            ..Default::default()
        }
    }

    /// Store a received message to reply to / forward.
    fn stored_message(e: &Engine, mid: Option<&str>, refs: &[&str]) -> i64 {
        let mut store = e.store();
        let account_id = store
            .account_by_email("alice@example.org")
            .unwrap()
            .unwrap()
            .id;
        let folder_id = store.folder(account_id, "INBOX").unwrap().id;
        let uid = store
            .conn()
            .query_row("SELECT COUNT(*) + 1 FROM messages", [], |r| {
                r.get::<_, u32>(0)
            })
            .unwrap();
        store
            .insert_message(&NewMessage {
                account_id,
                folder_id,
                uid,
                message_id: mid.map(str::to_owned),
                from: Address {
                    name: None,
                    address: "bob@example.org".into(),
                },
                to: vec![],
                cc: vec![],
                subject: Some("original".into()),
                protected_subject: false,
                date: Some(1_700_000_000),
                received_at: 1_700_000_000,
                flags: vec![],
                was_encrypted: false,
                decrypted: false,
                was_signed: false,
                signature: SignatureSummary::default(),
                signatures_json: "[]".into(),
                text: Some("original text".into()),
                html: None,
                in_reply_to: vec![],
                references: refs.iter().map(|r| r.to_string()).collect(),
                decrypt_error: None,
                raw: b"raw".to_vec(),
                attachments: vec![],
            })
            .unwrap()
            .unwrap()
    }

    fn profile_bytes(dir: &Path) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_file() {
                out.extend(std::fs::read(p).unwrap());
            }
        }
        out
    }

    fn contains(hay: &[u8], needle: &str) -> bool {
        hay.windows(needle.len()).any(|w| w == needle.as_bytes())
    }

    #[test]
    fn save_list_get_update_delete() {
        let (_dir, e) = engine();
        let saved = e.save_draft(input("Hello", "first body")).unwrap();
        assert!(saved.id > 0);
        assert_eq!(saved.account, "alice@example.org");
        assert_eq!(saved.kind, ComposeKind::New);
        assert_eq!(
            saved.to,
            vec!["bob@example.org".to_string()],
            "blank dropped"
        );
        assert_eq!(saved.subject, "Hello");
        assert_eq!(saved.body_text, "first body");
        assert_eq!(saved.policy, SendPolicy::Auto);
        assert_eq!(saved.created_at, saved.updated_at);
        assert_eq!(e.get_draft(saved.id).unwrap(), saved);

        // Upsert by id: everything replaced, created_at kept.
        let mut upd = input("Hello again", "second body");
        upd.id = Some(saved.id);
        upd.cc = vec!["carol@example.org".into()];
        upd.policy = SendPolicy::GuestLink;
        upd.guest_mode = GuestMode::OneClick;
        upd.no_signature = true;
        let updated = e.save_draft(upd).unwrap();
        assert_eq!(updated.id, saved.id);
        assert_eq!(updated.subject, "Hello again");
        assert_eq!(updated.cc, vec!["carol@example.org".to_string()]);
        assert_eq!(updated.policy, SendPolicy::GuestLink);
        assert_eq!(updated.guest_mode, GuestMode::OneClick);
        assert!(updated.no_signature);
        assert_eq!(updated.created_at, saved.created_at);

        // A second account's draft; listing per account and overall (newest first).
        new_account(&e.store(), "work@example.org");
        let mut w = input("Work", "w");
        w.account = "WORK@example.org".into();
        let work = e.save_draft(w).unwrap();
        assert_eq!(work.account, "work@example.org");
        let all: Vec<i64> = e.list_drafts(None).unwrap().iter().map(|d| d.id).collect();
        assert_eq!(all.len(), 2);
        assert!(all.contains(&work.id) && all.contains(&saved.id));
        let mine: Vec<i64> = e
            .list_drafts(Some("alice@example.org"))
            .unwrap()
            .iter()
            .map(|d| d.id)
            .collect();
        assert_eq!(mine, vec![saved.id]);
        assert!(matches!(
            e.list_drafts(Some("nobody@example.org")),
            Err(Error::AccountNotFound(_))
        ));

        // Delete: true once, then false; get is InvalidInput.
        assert!(e.delete_draft(saved.id).unwrap());
        assert!(!e.delete_draft(saved.id).unwrap());
        assert!(matches!(e.get_draft(saved.id), Err(Error::InvalidInput(_))));
        // Saving under a gone id re-creates it there.
        let mut again = input("Back", "b");
        again.id = Some(saved.id);
        assert_eq!(e.save_draft(again).unwrap().id, saved.id);
        // Bad input.
        let mut bad = input("x", "y");
        bad.id = Some(0);
        assert!(matches!(e.save_draft(bad), Err(Error::InvalidInput(_))));
        let mut bad = input("x", "y");
        bad.account = "nobody@example.org".into();
        assert!(matches!(e.save_draft(bad), Err(Error::AccountNotFound(_))));
        // Removing the account removes its drafts.
        e.remove_account("work@example.org").unwrap();
        assert!(matches!(e.get_draft(work.id), Err(Error::InvalidInput(_))));
    }

    /// Ids are never handed out twice: a UI still holding the id of a sent (deleted) draft
    /// must not overwrite a newer, unrelated draft when it saves again.
    #[test]
    fn draft_ids_are_not_reused_after_a_delete() {
        let (_dir, e) = engine();
        let a = e.save_draft(input("a", "a")).unwrap().id;
        let b = e.save_draft(input("b", "b")).unwrap().id;
        assert!(e.delete_draft(b).unwrap());
        let c = e.save_draft(input("c", "c")).unwrap().id;
        assert!(c > b, "id {b} was reused");
        assert!(e.delete_draft(c).unwrap() && e.delete_draft(a).unwrap());
        let d = e.save_draft(input("d", "d")).unwrap().id;
        assert!(d > c, "id {c} was reused after the table emptied");
    }

    /// A drafts table created before AUTOINCREMENT (no `sqlite_sequence`) still saves.
    #[test]
    fn a_drafts_table_without_autoincrement_still_saves() {
        let dir = tempfile::tempdir().unwrap();
        {
            let conn = rusqlite::Connection::open(dir.path().join(DB_FILE)).unwrap();
            let old = SCHEMA.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "INTEGER PRIMARY KEY");
            assert_ne!(old, SCHEMA);
            conn.execute_batch(&old).unwrap();
        }
        let e = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        let has_sequence: bool = e
            .store()
            .conn()
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE name = 'sqlite_sequence')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!has_sequence);
        new_account(&e.store(), "alice@example.org");
        let a = e.save_draft(input("a", "a")).unwrap().id;
        let b = e.save_draft(input("b", "b")).unwrap().id;
        assert_eq!((a, b), (1, 2));
        assert_eq!(e.get_draft(b).unwrap().subject, "b");
    }

    #[test]
    fn reply_and_forward_context_is_resolved_when_saving() {
        let (_dir, e) = engine();
        let orig = stored_message(&e, Some("orig@example.org"), &["root@example.org"]);
        // A local id becomes the Message-ID + References; New is stored as Reply.
        let mut r = input("Re: original", "my answer");
        r.in_reply_to = Some(orig.to_string());
        r.quote = true;
        let reply = e.save_draft(r).unwrap();
        assert_eq!(reply.kind, ComposeKind::Reply);
        assert_eq!(reply.in_reply_to.as_deref(), Some("orig@example.org"));
        assert_eq!(
            reply.references,
            vec![
                "root@example.org".to_string(),
                "orig@example.org".to_string()
            ]
        );
        assert_eq!(reference_for_send("orig@example.org"), "<orig@example.org>");
        assert_eq!(reference_for_send("12345"), "12345");
        // A Message-ID that is not stored is kept (no quoting possible).
        let mut r = input("Re: elsewhere", "x");
        r.in_reply_to = Some("<far@example.org>".into());
        let far = e.save_draft(r).unwrap();
        assert_eq!(far.in_reply_to.as_deref(), Some("far@example.org"));
        assert_eq!(far.references, vec!["far@example.org".to_string()]);
        let mut r = input("Re: elsewhere", "x");
        r.in_reply_to = Some("far@example.org".into());
        r.quote = true;
        assert!(matches!(e.save_draft(r), Err(Error::InvalidInput(_))));
        // An unknown local id is an error.
        let mut r = input("Re", "x");
        r.in_reply_to = Some("999".into());
        assert!(matches!(e.save_draft(r), Err(Error::MessageNotFound(999))));
        // Forward: must be stored; a message without Message-ID keeps its local id.
        let anon = stored_message(&e, None, &[]);
        let mut f = input("Fwd: original", "see below");
        f.forward_of = Some(anon.to_string());
        let fwd = e.save_draft(f).unwrap();
        assert_eq!(fwd.kind, ComposeKind::Forward);
        assert_eq!(fwd.forward_of, Some(anon.to_string()));
        let mut f = input("Fwd", "x");
        f.forward_of = Some("nowhere@example.org".into());
        assert!(matches!(e.save_draft(f), Err(Error::InvalidInput(_))));
        // Contradictory kinds.
        let mut both = input("x", "y");
        both.in_reply_to = Some(orig.to_string());
        both.forward_of = Some(orig.to_string());
        assert!(e.save_draft(both).is_err());
        let mut kind_only = input("x", "y");
        kind_only.kind = ComposeKind::Reply;
        assert!(e.save_draft(kind_only).is_err());
        let mut kind_only = input("x", "y");
        kind_only.kind = ComposeKind::Forward;
        assert!(e.save_draft(kind_only).is_err());
    }

    #[test]
    fn attachments_are_canonical_file_references() {
        let (dir, e) = engine();
        let file = dir.path().join("report.pdf");
        std::fs::write(&file, b"%PDF").unwrap();
        let relative_dir = tempfile::tempdir_in(dir.path()).unwrap();
        let mut d = input("With file", "see attached");
        d.attachments = vec![
            DraftAttachment {
                path: file.to_string_lossy().into_owned(),
                blob_id: None,
                name: String::new(),
                content_type: "application/pdf".into(),
            },
            DraftAttachment {
                path: format!("{}/../report.pdf", relative_dir.path().display()),
                blob_id: None,
                name: "renamed.pdf".into(),
                content_type: String::new(),
            },
        ];
        let saved = e.save_draft(d).unwrap();
        let canonical = std::fs::canonicalize(&file).unwrap();
        assert_eq!(saved.attachments.len(), 2);
        for a in &saved.attachments {
            assert_eq!(Path::new(&a.path), canonical);
        }
        assert_eq!(saved.attachments[0].name, "report.pdf");
        assert_eq!(saved.attachments[1].name, "renamed.pdf");
        let mut missing = input("x", "y");
        missing.attachments = vec![DraftAttachment {
            path: dir.path().join("nope.bin").to_string_lossy().into_owned(),
            ..Default::default()
        }];
        assert!(matches!(e.save_draft(missing), Err(Error::InvalidInput(_))));
        let mut a_dir = input("x", "y");
        a_dir.attachments = vec![DraftAttachment {
            path: dir.path().to_string_lossy().into_owned(),
            ..Default::default()
        }];
        assert!(matches!(e.save_draft(a_dir), Err(Error::InvalidInput(_))));
    }

    #[tokio::test]
    async fn send_failures_keep_the_draft() {
        let (dir, e) = engine();
        // Refused before any network use (this account has no key, and no recipients).
        let mut d = input("Nobody", "x");
        d.to.clear();
        let id = e.save_draft(d).unwrap().id;
        assert!(e.send_draft(id).await.is_err());
        assert!(e.get_draft(id).is_ok());
        // The attachment file disappeared after saving.
        let file = dir.path().join("gone.txt");
        std::fs::write(&file, b"x").unwrap();
        let mut d = input("Gone", "x");
        d.attachments = vec![DraftAttachment {
            path: file.to_string_lossy().into_owned(),
            ..Default::default()
        }];
        let id = e.save_draft(d).unwrap().id;
        std::fs::remove_file(&file).unwrap();
        let err = e.send_draft(id).await.unwrap_err();
        assert!(err.to_string().contains("gone.txt"), "{err}");
        assert!(e.get_draft(id).is_ok());
        assert!(matches!(
            e.send_draft(4242).await,
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn subject_and_body_are_sealed_at_rest_and_counted() {
        let (dir, e) = engine();
        let before = e.profile_key_status().unwrap();
        let saved = e
            .save_draft(DraftInput {
                to: vec!["recipient-visible@example.org".into()],
                ..input("Sekrit-draft-subject", "Sekrit-draft-body")
            })
            .unwrap();
        let after = e.profile_key_status().unwrap();
        assert_eq!(after.plaintext_rows, 0);
        assert_eq!(
            after.wrapped_rows,
            before.wrapped_rows + 2,
            "vault::WRAPPED must cover drafts.subject and drafts.body_text"
        );
        e.store()
            .conn()
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .unwrap();
        let disk = profile_bytes(dir.path());
        assert!(!contains(&disk, "Sekrit-draft-subject"));
        assert!(!contains(&disk, "Sekrit-draft-body"));
        assert!(contains(&disk, "recipient-visible@example.org"), "control");
        // The AAD binds the row: another draft's ciphertext does not open here.
        let other = e.save_draft(input("other", "other body")).unwrap();
        e.store()
            .conn()
            .execute(
                "UPDATE drafts SET body_text = (SELECT body_text FROM drafts WHERE id = ?1) \
                 WHERE id = ?2",
                params![saved.id, other.id],
            )
            .unwrap();
        assert!(matches!(
            e.get_draft(other.id),
            Err(Error::SecretIntegrity(_))
        ));
    }

    #[test]
    fn drafts_survive_a_rewrap_of_a_keyed_profile() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine_with(dir.path(), ProfileKeySource::Raw(vec![5u8; 32]));
        new_account(&e.store(), "alice@example.org");
        let id = e
            .save_draft(input("before rewrap", "kept body"))
            .unwrap()
            .id;
        e.rewrap_profile(ProfileKeySource::Raw(vec![6u8; 32]))
            .unwrap();
        let d = e.get_draft(id).unwrap();
        assert_eq!(
            (d.subject.as_str(), d.body_text.as_str()),
            ("before rewrap", "kept body")
        );
    }

    #[test]
    fn drafts_survive_legacy_migration_and_rewrap() {
        let dir = tempfile::tempdir().unwrap();
        // A plaintext (pre-G27 style) profile holding a draft.
        let legacy_id = {
            let store = Store::open(&dir.path().join(DB_FILE)).unwrap();
            let account_id = new_account(&store, "alice@example.org");
            store
                .upsert_draft(
                    None,
                    &DraftRecord {
                        account_id,
                        kind: ComposeKind::New,
                        in_reply_to: None,
                        forward_of: None,
                        quote: false,
                        references: vec![],
                        to: vec!["bob@example.org".into()],
                        cc: vec![],
                        bcc: vec![],
                        subject: "legacy draft subject".into(),
                        body_text: "legacy draft body".into(),
                        attachments: vec![],
                        policy: SendPolicy::Auto,
                        guest_mode: GuestMode::Passphrase,
                        guest_recipient_hint: None,
                        no_signature: false,
                        from_server: None,
                    },
                )
                .unwrap()
        };
        assert!(contains(&profile_bytes(dir.path()), "legacy draft body"));
        // The first keyed open wraps the draft columns (recode_all) and reads them back.
        let key1 = ProfileKeySource::Raw(vec![1u8; 32]);
        let e = engine_with(dir.path(), key1.clone());
        assert_eq!(e.profile_key_status().unwrap().plaintext_rows, 0);
        let d = e.get_draft(legacy_id).unwrap();
        assert_eq!(d.subject, "legacy draft subject");
        assert_eq!(d.body_text, "legacy draft body");
        let keyed_id = e
            .save_draft(input("keyed subject", "keyed body"))
            .unwrap()
            .id;
        assert!(!contains(&profile_bytes(dir.path()), "legacy draft body"));
        // Rewrap to another key: both drafts re-encrypted, still readable.
        let key2 = ProfileKeySource::Raw(vec![2u8; 32]);
        e.rewrap_profile(key2.clone()).unwrap();
        assert_eq!(
            e.get_draft(legacy_id).unwrap().body_text,
            "legacy draft body"
        );
        assert_eq!(e.get_draft(keyed_id).unwrap().subject, "keyed subject");
        drop(e);
        assert!(matches!(
            Engine::open_with(
                dir.path(),
                EngineConfig {
                    profile_key: key1,
                    ..EngineConfig::default()
                }
            ),
            Err(Error::ProfileLocked(_))
        ));
        let e = engine_with(dir.path(), key2);
        assert_eq!(e.get_draft(keyed_id).unwrap().body_text, "keyed body");
        assert_eq!(e.list_drafts(None).unwrap().len(), 2);
    }

    // ----- stored blobs ---------------------------------------------------------------------

    fn stored(blob: i64) -> DraftAttachment {
        DraftAttachment {
            blob_id: Some(blob),
            ..Default::default()
        }
    }

    /// A 64-byte marker that must never be found on disk in the clear.
    fn marker(tag: &str) -> String {
        let m = format!("SEALDRAFTS-BLOB-{tag}-");
        let m = format!("{m:x<64}");
        assert_eq!(m.len(), 64);
        m
    }

    /// `marker` + 2 KiB of noise + `marker`: what a test file holds.
    fn file_bytes(marker: &str) -> Vec<u8> {
        let mut b = marker.as_bytes().to_vec();
        b.extend((0..2048u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8));
        b.extend_from_slice(marker.as_bytes());
        b
    }

    fn checkpoint(e: &Engine) {
        e.store()
            .conn()
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .unwrap();
    }

    fn blob_count(e: &Engine) -> i64 {
        e.store()
            .conn()
            .query_row("SELECT COUNT(*) FROM draft_blobs", [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn draft_blobs_round_trip_and_belong_to_their_account() {
        let (dir, e) = engine();
        new_account(&e.store(), "work@example.org");
        let before = e.profile_key_status().unwrap();
        let bytes = b"%PDF-1.7 stored for a draft".to_vec();
        let id = e
            .put_draft_blob(
                "ALICE@example.org",
                " report.pdf ",
                "application/pdf",
                &bytes,
            )
            .unwrap();
        let after = e.profile_key_status().unwrap();
        assert_eq!(
            after.wrapped_rows,
            before.wrapped_rows + 1,
            "vault::WRAPPED must cover draft_blobs.data"
        );
        assert_eq!(after.plaintext_rows, 0);
        let (info, data) = e.get_draft_blob(id).unwrap();
        assert_eq!(data, bytes);
        assert_eq!(
            info,
            DraftBlobInfo {
                id,
                account: "alice@example.org".into(),
                filename: "report.pdf".into(),
                content_type: "application/pdf".into(),
                size: bytes.len() as u64,
                created_at: info.created_at,
            }
        );
        assert!(info.created_at > 0);
        assert_eq!(
            e.list_draft_blobs("alice@example.org").unwrap(),
            vec![info.clone()]
        );
        assert!(e.list_draft_blobs("work@example.org").unwrap().is_empty());
        let unnamed = e
            .put_draft_blob("alice@example.org", "  ", "", b"")
            .unwrap();
        assert!(unnamed > id);
        assert_eq!(e.get_draft_blob(unnamed).unwrap().0.filename, "attachment");
        assert!(matches!(
            e.put_draft_blob("nobody@example.org", "x", "", b"x"),
            Err(Error::AccountNotFound(_))
        ));

        // A draft references blobs; name and type default to the blob's.
        let mut d = input("With stored files", "see attached");
        d.attachments = vec![
            stored(id),
            DraftAttachment {
                name: "renamed.txt".into(),
                content_type: "text/plain".into(),
                ..stored(unnamed)
            },
        ];
        let saved = e.save_draft(d).unwrap();
        assert_eq!(
            saved.attachments,
            vec![
                DraftAttachment {
                    path: String::new(),
                    blob_id: Some(id),
                    name: "report.pdf".into(),
                    content_type: "application/pdf".into(),
                },
                DraftAttachment {
                    path: String::new(),
                    blob_id: Some(unnamed),
                    name: "renamed.txt".into(),
                    content_type: "text/plain".into(),
                },
            ]
        );
        assert_eq!(e.get_draft(saved.id).unwrap(), saved);

        // Only drafts of the blob's account may reference it; exactly one of path / blob.
        let mut other = input("x", "y");
        other.account = "work@example.org".into();
        other.attachments = vec![stored(id)];
        assert!(matches!(e.save_draft(other), Err(Error::InvalidInput(_))));
        let mut unknown = input("x", "y");
        unknown.attachments = vec![stored(unnamed + 100)];
        assert!(matches!(e.save_draft(unknown), Err(Error::InvalidInput(_))));
        let file = dir.path().join("both.txt");
        std::fs::write(&file, b"f").unwrap();
        let mut both = input("x", "y");
        both.attachments = vec![DraftAttachment {
            path: file.to_string_lossy().into_owned(),
            ..stored(id)
        }];
        assert!(matches!(e.save_draft(both), Err(Error::InvalidInput(_))));
        let mut neither = input("x", "y");
        neither.attachments = vec![DraftAttachment::default()];
        assert!(matches!(e.save_draft(neither), Err(Error::InvalidInput(_))));

        // Drafts saved before blobs existed: no `blob_id` in the stored JSON = a file
        // reference, and a file reference is stored exactly as before.
        let old = r#"[{"path":"/tmp/a.pdf","name":"a.pdf","content_type":""}]"#;
        let parsed: Vec<DraftAttachment> = serde_json::from_str(old).unwrap();
        assert_eq!(parsed[0].blob_id, None);
        assert_eq!(serde_json::to_string(&parsed).unwrap(), old);
        assert!(blob_ids_of(old).is_empty());

        // delete_draft_blob: once; deleting the draft takes its remaining blob along.
        assert!(e.delete_draft_blob(unnamed).unwrap());
        assert!(!e.delete_draft_blob(unnamed).unwrap());
        assert!(matches!(
            e.get_draft_blob(unnamed),
            Err(Error::InvalidInput(_))
        ));
        assert!(e.delete_draft(saved.id).unwrap());
        assert!(matches!(e.get_draft_blob(id), Err(Error::InvalidInput(_))));
        assert_eq!(blob_count(&e), 0);
        // Removing an account removes its blobs.
        let w = e
            .put_draft_blob("work@example.org", "w.bin", "", b"w")
            .unwrap();
        e.remove_account("work@example.org").unwrap();
        assert!(matches!(e.get_draft_blob(w), Err(Error::InvalidInput(_))));
        // Ids are never reused.
        assert!(
            e.put_draft_blob("alice@example.org", "n", "", b"n")
                .unwrap()
                > w
        );
    }

    #[test]
    fn the_sweep_deletes_only_old_unreferenced_blobs_of_that_account() {
        let (_dir, e) = engine();
        new_account(&e.store(), "work@example.org");
        let put =
            |acct: &str, name: &str| e.put_draft_blob(acct, name, "", name.as_bytes()).unwrap();
        let old_orphan = put("alice@example.org", "old-orphan");
        let new_orphan = put("alice@example.org", "new-orphan");
        let old_used = put("alice@example.org", "old-used");
        let shared = put("alice@example.org", "shared");
        let work_orphan = put("work@example.org", "work-orphan");
        let mut d = input("uses two", "x");
        d.attachments = vec![stored(old_used), stored(shared)];
        let first = e.save_draft(d).unwrap().id;
        let mut d = input("uses one", "x");
        d.attachments = vec![stored(shared)];
        let second = e.save_draft(d).unwrap().id;
        let age = |id: i64, secs: i64| {
            e.store()
                .conn()
                .execute(
                    "UPDATE draft_blobs SET created_at = created_at - ?1 WHERE id = ?2",
                    params![secs, id],
                )
                .unwrap();
        };
        for id in [old_orphan, old_used, shared, work_orphan] {
            age(id, ORPHAN_BLOB_GRACE_SECS + 1);
        }
        age(new_orphan, ORPHAN_BLOB_GRACE_SECS - 60);
        let ids = |acct: &str| -> HashSet<i64> {
            e.list_draft_blobs(acct)
                .unwrap()
                .iter()
                .map(|b| b.id)
                .collect()
        };

        assert_eq!(e.sweep_draft_blobs("alice@example.org").unwrap(), 1);
        assert_eq!(
            ids("alice@example.org"),
            HashSet::from([new_orphan, old_used, shared])
        );
        assert_eq!(
            ids("work@example.org"),
            HashSet::from([work_orphan]),
            "another account's orphan is left alone"
        );
        assert_eq!(e.sweep_draft_blobs("alice@example.org").unwrap(), 0);
        assert!(matches!(
            e.sweep_draft_blobs("nobody@example.org"),
            Err(Error::AccountNotFound(_))
        ));

        // A blob two drafts reference outlives the first one's deletion.
        assert!(e.delete_draft(first).unwrap());
        assert_eq!(
            ids("alice@example.org"),
            HashSet::from([new_orphan, shared])
        );
        assert!(e.delete_draft(second).unwrap());
        assert_eq!(ids("alice@example.org"), HashSet::from([new_orphan]));
        // Once ten minutes old, the last orphan goes too.
        age(new_orphan, 61);
        assert_eq!(e.sweep_draft_blobs("alice@example.org").unwrap(), 1);
        assert!(ids("alice@example.org").is_empty());
        assert_eq!(e.sweep_draft_blobs("work@example.org").unwrap(), 1);
    }

    #[test]
    fn draft_blobs_survive_legacy_migration_and_rewrap_and_are_bound_to_their_row() {
        let dir = tempfile::tempdir().unwrap();
        let mark = marker("legacy");
        // A plaintext (pre-G27 style) profile holding a blob.
        let legacy = {
            let store = Store::open(&dir.path().join(DB_FILE)).unwrap();
            let account_id = new_account(&store, "alice@example.org");
            store
                .insert_draft_blob(account_id, "legacy.bin", "", &file_bytes(&mark))
                .unwrap()
        };
        assert!(contains(&profile_bytes(dir.path()), &mark), "fixture");
        // The first keyed open wraps the blob (recode_all) and reads it back.
        let key1 = ProfileKeySource::Raw(vec![3u8; 32]);
        let e = engine_with(dir.path(), key1.clone());
        assert_eq!(e.profile_key_status().unwrap().plaintext_rows, 0);
        assert_eq!(e.get_draft_blob(legacy).unwrap().1, file_bytes(&mark));
        let fresh = e
            .put_draft_blob("alice@example.org", "fresh.bin", "", b"fresh bytes")
            .unwrap();
        checkpoint(&e);
        assert!(!contains(&profile_bytes(dir.path()), &mark));
        // Rewrap to another key: both re-encrypted, still readable.
        let key2 = ProfileKeySource::Raw(vec![4u8; 32]);
        e.rewrap_profile(key2.clone()).unwrap();
        assert_eq!(e.get_draft_blob(legacy).unwrap().1, file_bytes(&mark));
        assert_eq!(e.get_draft_blob(fresh).unwrap().1, b"fresh bytes");
        // The AAD binds the row: one blob's ciphertext moved onto another does not open.
        let moved = e
            .put_draft_blob("alice@example.org", "m", "", b"m")
            .unwrap();
        e.store()
            .conn()
            .execute(
                "UPDATE draft_blobs SET data = (SELECT data FROM draft_blobs WHERE id = ?1) \
                 WHERE id = ?2",
                params![fresh, moved],
            )
            .unwrap();
        assert!(matches!(
            e.get_draft_blob(moved),
            Err(Error::SecretIntegrity(_))
        ));
        assert!(e.delete_draft_blob(moved).unwrap());
        drop(e);
        // The old key is refused before any row is read, as for every sealed column.
        assert!(matches!(
            Engine::open_with(
                dir.path(),
                EngineConfig {
                    profile_key: key1,
                    ..EngineConfig::default()
                }
            ),
            Err(Error::ProfileLocked(_))
        ));
        let e = engine_with(dir.path(), key2);
        assert_eq!(e.get_draft_blob(legacy).unwrap().1, file_bytes(&mark));
        assert_eq!(e.list_draft_blobs("alice@example.org").unwrap().len(), 2);
    }

    // ----- sending (scripted SMTP) --------------------------------------------------------

    /// A scripted SMTP submission server on 127.0.0.1. Each connection is reported on
    /// `connected` and then waits for `gate`: `None` holds it before the greeting,
    /// `Some(true)` greets it and accepts every message (any AUTH succeeds), `Some(false)`
    /// hangs up. The DATA of each accepted message arrives on `messages`.
    struct ScriptedSmtp {
        port: u16,
        connected: mpsc::UnboundedReceiver<()>,
        gate: watch::Sender<Option<bool>>,
        messages: mpsc::UnboundedReceiver<Vec<u8>>,
    }

    async fn scripted_smtp(gate: Option<bool>) -> ScriptedSmtp {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (connected_tx, connected) = mpsc::unbounded_channel();
        let (message_tx, messages) = mpsc::unbounded_channel();
        let (gate, gate_rx) = watch::channel(gate);
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let _ = connected_tx.send(());
                let (mut gate_rx, message_tx) = (gate_rx.clone(), message_tx.clone());
                tokio::spawn(async move {
                    let serve = loop {
                        if let Some(serve) = *gate_rx.borrow_and_update() {
                            break serve;
                        }
                        if gate_rx.changed().await.is_err() {
                            break false;
                        }
                    };
                    if serve {
                        smtp_session(sock, message_tx).await;
                    }
                });
            }
        });
        ScriptedSmtp {
            port,
            connected,
            gate,
            messages,
        }
    }

    async fn smtp_session(sock: TcpStream, messages: mpsc::UnboundedSender<Vec<u8>>) {
        let (r, mut w) = sock.into_split();
        let mut lines = BufReader::new(r).lines();
        if w.write_all(b"220 scripted ESMTP\r\n").await.is_err() {
            return;
        }
        let mut data: Option<Vec<u8>> = None;
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(buf) = data.as_mut() {
                if line == "." {
                    let _ = messages.send(data.take().unwrap_or_default());
                    if w.write_all(b"250 2.0.0 queued\r\n").await.is_err() {
                        return;
                    }
                } else {
                    buf.extend_from_slice(line.strip_prefix('.').unwrap_or(&line).as_bytes());
                    buf.extend_from_slice(b"\r\n");
                }
                continue;
            }
            let upper = line.to_ascii_uppercase();
            let reply: &[u8] = if upper.starts_with("EHLO") {
                b"250-scripted\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n"
            } else if upper.starts_with("AUTH") {
                b"235 2.7.0 accepted\r\n"
            } else if upper.starts_with("DATA") {
                data = Some(Vec::new());
                b"354 go ahead\r\n"
            } else if upper.starts_with("QUIT") {
                let _ = w.write_all(b"221 bye\r\n").await;
                return;
            } else {
                b"250 OK\r\n"
            };
            if w.write_all(reply).await.is_err() {
                return;
            }
        }
    }

    /// A keyed engine whose account alice@example.org has an identity and submits through
    /// the scripted server on `smtp_port` (IMAP port 9 is closed: the Sent copy is skipped).
    fn sending_engine(smtp_port: u16) -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::open_with(
            dir.path(),
            EngineConfig {
                network_timeout: Duration::from_secs(10),
                ..EngineConfig::default()
            },
        )
        .unwrap();
        let alice = sealbox_crypto::Identity::generate("Alice", "alice@example.org").unwrap();
        {
            let store = e.store();
            let id = store
                .insert_account(&NewAccount {
                    email: "alice@example.org",
                    display_name: "Alice",
                    imap: &Endpoint::new("127.0.0.1", 9, Security::Plain),
                    smtp: &Endpoint::new("127.0.0.1", smtp_port, Security::Plain),
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
        }
        (dir, e)
    }

    /// The attachments of a submitted plaintext message.
    fn attachments_of(raw: &[u8]) -> Vec<(String, Vec<u8>)> {
        match sealbox_mail::mime::parse(raw).unwrap().kind {
            MessageKind::Plain(body) => body
                .attachments
                .into_iter()
                .map(|a| (a.filename, a.data))
                .collect(),
            other => panic!("not a plaintext message: {other:?}"),
        }
    }

    async fn within<T>(secs: u64, f: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(secs), f)
            .await
            .expect("timed out")
    }

    #[tokio::test]
    async fn blob_bytes_never_reach_the_disk_and_go_with_the_draft() {
        let mut smtp = scripted_smtp(Some(true)).await;
        let (dir, e) = sending_engine(smtp.port);
        let mark = marker("disk");
        let bytes = file_bytes(&mark);
        let blob = e
            .put_draft_blob("alice@example.org", "visible-name.bin", "", &bytes)
            .unwrap();
        let mut d = input("Plan", "attached");
        d.policy = SendPolicy::AllowPlaintext;
        d.attachments = vec![stored(blob)];
        let id = e.save_draft(d.clone()).unwrap().id;
        checkpoint(&e);
        let disk = profile_bytes(dir.path());
        assert!(!contains(&disk, &mark), "blob bytes in plaintext on disk");
        assert!(
            contains(&disk, "visible-name.bin"),
            "control: names stay plaintext"
        );
        assert!(!dir.path().join("draft-attachments").exists());

        // Deleting the draft deletes the blob; nothing of it on disk afterwards either.
        let deleted = {
            let b = e
                .put_draft_blob("alice@example.org", "deleted.bin", "", &file_bytes(&mark))
                .unwrap();
            let mut d = input("Deleted", "x");
            d.attachments = vec![stored(b)];
            let id = e.save_draft(d).unwrap().id;
            assert!(e.delete_draft(id).unwrap());
            b
        };
        assert!(e.get_draft_blob(deleted).is_err());

        // Sending reads the sealed bytes; once the mail is out the draft and blob are gone.
        let report = within(30, e.send_draft(id)).await.unwrap();
        assert_eq!(report.mode, SendMode::Plaintext);
        let raw = within(5, smtp.messages.recv()).await.unwrap();
        assert_eq!(
            attachments_of(&raw),
            vec![("visible-name.bin".to_string(), bytes)]
        );
        assert!(matches!(e.get_draft(id), Err(Error::InvalidInput(_))));
        assert!(matches!(
            e.get_draft_blob(blob),
            Err(Error::InvalidInput(_))
        ));
        assert_eq!(blob_count(&e), 0);
        checkpoint(&e);
        assert!(!contains(&profile_bytes(dir.path()), &mark));

        // A draft whose blob was deleted underneath it fails to send and is kept.
        let b = e
            .put_draft_blob("alice@example.org", "short-lived.bin", "", b"x")
            .unwrap();
        let mut d = input("Orphaned", "x");
        d.policy = SendPolicy::AllowPlaintext;
        d.attachments = vec![stored(b)];
        let id = e.save_draft(d).unwrap().id;
        assert!(e.delete_draft_blob(b).unwrap());
        let err = within(30, e.send_draft(id)).await.unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err}");
        assert!(err.to_string().contains("short-lived.bin"), "{err}");
        assert!(e.get_draft(id).is_ok());
        assert!(smtp.messages.try_recv().is_err(), "nothing was submitted");
    }

    /// Two concurrent sends of one draft: while the first waits for the server's greeting,
    /// the second fails at once with `DraftBeingSent`. A failed send keeps the draft and
    /// its blob and releases the draft; the retry sends exactly one message.
    #[tokio::test]
    async fn a_second_send_of_a_draft_in_flight_fails_fast() {
        let mut smtp = scripted_smtp(None).await;
        let (_dir, e) = sending_engine(smtp.port);
        let e = Arc::new(e);
        let bytes = file_bytes(&marker("race"));
        let blob = e
            .put_draft_blob("alice@example.org", "once.bin", "", &bytes)
            .unwrap();
        let mut d = input("Once", "only once");
        d.policy = SendPolicy::AllowPlaintext;
        d.attachments = vec![stored(blob)];
        let id = e.save_draft(d).unwrap().id;
        let unrelated = e.save_draft(input("Unrelated", "x")).unwrap().id;

        let send = |e: &Arc<Engine>| {
            let e = Arc::clone(e);
            tokio::spawn(async move { e.send_draft(id).await })
        };
        let first = send(&e);
        within(30, smtp.connected.recv()).await.unwrap();
        // The first send is connected and held before the greeting.
        let second = within(5, send(&e)).await.unwrap();
        assert!(
            matches!(second, Err(Error::DraftBeingSent(d)) if d == id),
            "{second:?}"
        );
        assert_eq!(
            second.unwrap_err().to_string(),
            format!("draft {id} is being sent")
        );
        // Only that draft is busy (this one is refused by policy, before any network use).
        assert!(matches!(
            within(5, e.send_draft(unrelated)).await,
            Err(Error::RecipientsWithoutKeys { .. })
        ));
        // The server hangs up: the first send fails, the draft and its blob stay.
        smtp.gate.send_replace(Some(false));
        let failed = within(30, first).await.unwrap();
        assert!(
            failed.is_err() && !matches!(failed, Err(Error::DraftBeingSent(_))),
            "{failed:?}"
        );
        assert!(e.get_draft(id).is_ok());
        assert_eq!(e.get_draft_blob(blob).unwrap().1, bytes);
        // Released: the retry goes through, once.
        smtp.gate.send_replace(Some(true));
        let report = within(30, send(&e)).await.unwrap().unwrap();
        assert_eq!(report.mode, SendMode::Plaintext);
        let raw = within(5, smtp.messages.recv()).await.unwrap();
        assert_eq!(attachments_of(&raw), vec![("once.bin".to_string(), bytes)]);
        assert!(smtp.messages.try_recv().is_err(), "exactly one message");
        assert!(matches!(
            e.send_draft(id).await,
            Err(Error::InvalidInput(_))
        ));
        assert!(e.get_draft_blob(blob).is_err());
    }
}
