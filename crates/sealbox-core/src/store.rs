//! The local SQLite store (rusqlite, bundled). One database per profile directory.
//!
//! Secrets at rest (G27, `vault.rs`): `identities.secret_armored`, `accounts.credential`,
//! the `oauth_tokens` secrets, `message_blobs.text_body/html_body/raw`, `messages.snippet`,
//! `attachments.data`, `spam_model.model_json` and `secret.*` settings are written as `sbx1`
//! envelopes (XChaCha20-Poly1305, AAD `table:column:rowid`; `message_blobs` keeps the
//! `messages:<column>:<id>` AAD of the columns it took over) and unwrapped on read. Rows that
//! carry a wrapped column get their id chosen *before* the INSERT so the AAD can bind it.
//! Addresses, subjects, flags, dates, folder names and sizes stay plaintext so that listing,
//! sorting and threading keep working in SQL (`docs/SECRETS_AT_REST.md`). The database file
//! is still created 0600 inside a 0700 profile directory.

use std::collections::HashMap;
use std::path::Path;

use rusqlite::types::Value;
use rusqlite::{params, Connection, OptionalExtension};
use sealbox_crypto::PeerState;
use sealbox_mail::autodiscover::Endpoint;
use sealbox_mail::oauth::Provider;
use sealbox_mail::{Auth, BearerScope, Security};

use crate::error::{Error, Result};
use crate::providers::ProviderId;
use crate::types::{
    AccountInfo, Address, AttachmentInfo, AuthKind, AuthSpec, KeySource, ListQuery, MessageDetail,
    MessageSummary, SigState, SignatureSummary,
};
use crate::vault::Vault;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name  TEXT NOT NULL DEFAULT '',
    imap_host     TEXT NOT NULL,
    imap_port     INTEGER NOT NULL,
    imap_security TEXT NOT NULL,
    smtp_host     TEXT NOT NULL,
    smtp_port     INTEGER NOT NULL,
    smtp_security TEXT NOT NULL,
    auth_kind     TEXT NOT NULL,
    login         TEXT NOT NULL,
    credential    TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS identities (
    id              INTEGER PRIMARY KEY,
    account_id      INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    fingerprint     TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL,
    secret_armored  TEXT NOT NULL,
    public_armored  TEXT NOT NULL,
    created_at      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS peers (
    addr       TEXT PRIMARY KEY COLLATE NOCASE,
    state_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS keys (
    addr        TEXT NOT NULL COLLATE NOCASE,
    source      TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    armored     TEXT NOT NULL,
    imported_at INTEGER NOT NULL,
    PRIMARY KEY (addr, source)
);
CREATE TABLE IF NOT EXISTS folders (
    id          INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL DEFAULT 0,
    last_uid    INTEGER NOT NULL DEFAULT 0,
    UNIQUE (account_id, name)
);
CREATE TABLE IF NOT EXISTS messages (
    id                INTEGER PRIMARY KEY,
    account_id        INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    folder_id         INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    uid               INTEGER NOT NULL,
    message_id        TEXT,
    from_name         TEXT,
    from_addr         TEXT NOT NULL DEFAULT '',
    to_json           TEXT NOT NULL DEFAULT '[]',
    cc_json           TEXT NOT NULL DEFAULT '[]',
    subject           TEXT,
    protected_subject INTEGER NOT NULL DEFAULT 0,
    date              INTEGER,
    received_at       INTEGER NOT NULL,
    flags_json        TEXT NOT NULL DEFAULT '[]',
    was_encrypted     INTEGER NOT NULL DEFAULT 0,
    decrypted         INTEGER NOT NULL DEFAULT 0,
    was_signed        INTEGER NOT NULL DEFAULT 0,
    sig_status        TEXT NOT NULL DEFAULT 'none',
    sig_fingerprint   TEXT,
    sig_signer        TEXT,
    signatures_json   TEXT NOT NULL DEFAULT '[]',
    in_reply_to_json  TEXT NOT NULL DEFAULT '[]',
    references_json   TEXT NOT NULL DEFAULT '[]',
    decrypt_error     TEXT,
    raw_size          INTEGER NOT NULL,
    thread_id         TEXT NOT NULL DEFAULT '',
    UNIQUE (account_id, folder_id, uid)
);
CREATE INDEX IF NOT EXISTS messages_date ON messages(date DESC, id DESC);
CREATE INDEX IF NOT EXISTS messages_mid ON messages(message_id);
-- A message's sealed blobs, out of its hot row (`migrate_message_blobs`); `raw` last, so
-- reading the bodies stops before the raw MIME.
CREATE TABLE IF NOT EXISTS message_blobs (
    message_id INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    text_body  TEXT,
    html_body  TEXT,
    raw        BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS attachments (
    id           INTEGER PRIMARY KEY,
    message_id   INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    idx          INTEGER NOT NULL,
    filename     TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size         INTEGER NOT NULL,
    data         BLOB NOT NULL,
    content_id   TEXT,
    UNIQUE (message_id, idx)
);
-- Messages that are the server copies of saved drafts (`drafts_imap.rs`): a message in the
-- account's Drafts role folder carrying `X-Sealbox-Draft`. Never listed, never indexed.
CREATE TABLE IF NOT EXISTS draft_copies (
    message_id INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS outbox (
    id                 INTEGER PRIMARY KEY,
    account_id         INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    message_id         TEXT NOT NULL,
    recipients_json    TEXT NOT NULL,
    subject            TEXT NOT NULL,
    mode               TEXT NOT NULL,
    state              TEXT NOT NULL,
    error              TEXT,
    sent_copy_appended INTEGER NOT NULL DEFAULT 0,
    created_at         INTEGER NOT NULL
);
"#;

/// Current unix time in seconds.
pub(crate) fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn security_to_str(s: Security) -> &'static str {
    match s {
        Security::Tls => "tls",
        Security::StartTls => "starttls",
        Security::Plain => "plain",
    }
}

fn security_from_str(s: &str) -> Security {
    match s {
        "tls" => Security::Tls,
        "starttls" => Security::StartTls,
        _ => Security::Plain,
    }
}

fn key_source_to_str(s: KeySource) -> &'static str {
    match s {
        KeySource::Autocrypt => "autocrypt",
        KeySource::Gossip => "gossip",
        KeySource::Imported => "imported",
        KeySource::Directory => "directory",
        KeySource::Own => "own",
        KeySource::None => "none",
    }
}

fn key_source_from_str(s: &str) -> KeySource {
    match s {
        "autocrypt" => KeySource::Autocrypt,
        "gossip" => KeySource::Gossip,
        "imported" => KeySource::Imported,
        "directory" => KeySource::Directory,
        "own" => KeySource::Own,
        _ => KeySource::None,
    }
}

fn sig_state_to_str(s: SigState) -> &'static str {
    match s {
        SigState::None => "none",
        SigState::Good => "good",
        SigState::Bad => "bad",
        SigState::UnknownKey => "unknown_key",
    }
}

fn sig_state_from_str(s: &str) -> SigState {
    match s {
        "good" => SigState::Good,
        "bad" => SigState::Bad,
        "unknown_key" => SigState::UnknownKey,
        _ => SigState::None,
    }
}

fn json_vec<T: serde::de::DeserializeOwned>(s: &str) -> Vec<T> {
    serde_json::from_str(s).unwrap_or_default()
}

fn to_u32(v: i64) -> u32 {
    u32::try_from(v).unwrap_or(0)
}

/// The id the next INSERT into `table` gets (`MAX(id) + 1`, what SQLite picks itself for an
/// INTEGER PRIMARY KEY without AUTOINCREMENT). Chosen up front so a wrapped column's AAD can
/// carry it; callers hold the store mutex (and a transaction where it matters).
fn next_id(conn: &Connection, table: &str) -> Result<i64> {
    Ok(conn.query_row(
        &format!("SELECT COALESCE(MAX(id), 0) + 1 FROM {table}"),
        [],
        |r| r.get(0),
    )?)
}

/// Run `f` in a `BEGIN IMMEDIATE` transaction, rolled back on error. The write lock comes
/// first (waiting up to the busy timeout while another connection holds it), so nothing `f`
/// reads — a column list, a table, the schema version — can change under it before it
/// commits: the second of two connections migrating at once finds the work done.
fn in_immediate<T>(conn: &Connection, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
    conn.execute_batch("BEGIN IMMEDIATE;")?;
    match f(conn) {
        Ok(v) => {
            conn.execute_batch("COMMIT;")?;
            Ok(v)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(e)
        }
    }
}

/// Run `f` inside `SAVEPOINT name`: atomic on its own (outside a transaction a savepoint is
/// one) and nested in the caller's transaction otherwise — [`migrate`] runs every schema step
/// inside one `BEGIN IMMEDIATE`, where a plain `BEGIN` would fail.
fn in_savepoint<T>(conn: &Connection, name: &str, f: impl FnOnce() -> Result<T>) -> Result<T> {
    conn.execute_batch(&format!("SAVEPOINT {name};"))?;
    match f() {
        Ok(v) => {
            conn.execute_batch(&format!("RELEASE {name};"))?;
            Ok(v)
        }
        Err(e) => {
            let _ = conn.execute_batch(&format!("ROLLBACK TO {name}; RELEASE {name};"));
            Err(e)
        }
    }
}

// ----- threading ------------------------------------------------------------------------

/// Idempotent migration for reference threading: adds `messages.thread_id` (profiles created
/// before the column existed), its index, and back-fills every row that has none, oldest
/// first per account, with [`thread_id_for`] — so a profile synced by an older build groups
/// its mail exactly like a fresh sync would.
pub(crate) fn migrate_threads(conn: &Connection) -> Result<()> {
    let has_column = {
        let mut stmt = conn.prepare("PRAGMA table_info(messages)")?;
        let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
        let mut found = false;
        for n in names {
            if n? == "thread_id" {
                found = true;
            }
        }
        found
    };
    if !has_column {
        conn.execute(
            "ALTER TABLE messages ADD COLUMN thread_id TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS messages_thread ON messages(account_id, thread_id);",
    )?;
    let pending: Vec<(i64, i64, Option<String>, String, String)> = {
        // Through `messages_thread` per account: this runs on every open, and a bare
        // `WHERE thread_id = ''` reads every row (the column sits behind the bodies and the
        // raw MIME, so that is the whole file).
        let mut stmt = conn.prepare(
            "SELECT m.id, m.account_id, m.message_id, m.in_reply_to_json, m.references_json \
             FROM accounts a JOIN messages m INDEXED BY messages_thread \
             ON m.account_id = a.id AND m.thread_id = '' \
             ORDER BY m.account_id, COALESCE(m.date, m.received_at), m.id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    if pending.is_empty() {
        return Ok(());
    }
    in_savepoint(conn, "migrate_threads", || {
        for (id, account_id, message_id, in_reply_to, references) in &pending {
            let in_reply_to: Vec<String> = json_vec(in_reply_to);
            let references: Vec<String> = json_vec(references);
            let tid = thread_id_for(
                conn,
                *account_id,
                *id,
                message_id.as_deref(),
                &in_reply_to,
                &references,
            )?;
            conn.execute(
                "UPDATE messages SET thread_id = ?1 WHERE id = ?2",
                params![tid, id],
            )?;
        }
        Ok(())
    })?;
    tracing::info!(rows = pending.len(), "threads back-filled");
    Ok(())
}

fn push_unique(list: &mut Vec<String>, value: String) {
    if !value.is_empty() && !list.contains(&value) {
        list.push(value);
    }
}

/// The reference index behind threading: one row per (account, referenced Message-ID,
/// referencing message) for every id in a stored message's `In-Reply-To` and `References`,
/// exactly as those JSON columns hold it (the MIME parser already trims it and strips the
/// angle brackets). [`threads_referencing`] looks it up by `(account_id, ref)` instead of
/// scanning every row of the account, and `messages_account_mid` serves
/// [`threads_of_message`]: O(log n) per insert instead of O(n) (docs/PERFORMANCE.md).
pub(crate) const REFS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS message_refs (
    account_id  INTEGER NOT NULL,
    ref         TEXT NOT NULL,
    message_row INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    PRIMARY KEY (account_id, ref, message_row)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS message_refs_row ON message_refs(message_row);
CREATE INDEX IF NOT EXISTS messages_account_mid ON messages(account_id, message_id);
"#;

/// `meta` key recording that `message_refs` was back-filled from the JSON columns.
const META_REFS_BACKFILLED: &str = "message_refs_backfilled";

/// `meta` key of the signer-key generation (see [`KEYS_GENERATION_SCHEMA`]).
const META_KEYS_GENERATION: &str = "keys_generation";

/// The signer-key generation: a counter in `meta`, raised by triggers on every write that
/// changes what a sync caches about keys — our identities, accounts (own addresses), imported
/// and directory keys, and a peer's announced or gossiped key (a peer row whose keys stay the
/// same, i.e. a `last_seen` bump, does not count). Triggers, so every writer counts: another
/// sync, the UI, the CLI in another process, the recovery restore. A long-lived sync context
/// (`watch`) compares its generation with this one and reloads only when they differ.
pub(crate) const KEYS_GENERATION_SCHEMA: &str = r#"
INSERT OR IGNORE INTO meta (key, value) VALUES ('keys_generation', '0');
CREATE TRIGGER IF NOT EXISTS keys_gen_peer_ins AFTER INSERT ON peers
  WHEN json_extract(NEW.state_json, '$.public_key') IS NOT NULL
    OR json_extract(NEW.state_json, '$.gossip_key') IS NOT NULL
  BEGIN UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'keys_generation'; END;
CREATE TRIGGER IF NOT EXISTS keys_gen_peer_upd AFTER UPDATE ON peers
  WHEN OLD.addr IS NOT NEW.addr
    OR json_extract(OLD.state_json, '$.public_key') IS NOT json_extract(NEW.state_json, '$.public_key')
    OR json_extract(OLD.state_json, '$.gossip_key') IS NOT json_extract(NEW.state_json, '$.gossip_key')
  BEGIN UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'keys_generation'; END;
CREATE TRIGGER IF NOT EXISTS keys_gen_peer_del AFTER DELETE ON peers
  BEGIN UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'keys_generation'; END;
CREATE TRIGGER IF NOT EXISTS keys_gen_keys_ins AFTER INSERT ON keys
  BEGIN UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'keys_generation'; END;
CREATE TRIGGER IF NOT EXISTS keys_gen_keys_upd AFTER UPDATE ON keys
  BEGIN UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'keys_generation'; END;
CREATE TRIGGER IF NOT EXISTS keys_gen_keys_del AFTER DELETE ON keys
  BEGIN UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'keys_generation'; END;
CREATE TRIGGER IF NOT EXISTS keys_gen_ident_ins AFTER INSERT ON identities
  BEGIN UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'keys_generation'; END;
CREATE TRIGGER IF NOT EXISTS keys_gen_ident_upd AFTER UPDATE ON identities
  BEGIN UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'keys_generation'; END;
CREATE TRIGGER IF NOT EXISTS keys_gen_ident_del AFTER DELETE ON identities
  BEGIN UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'keys_generation'; END;
CREATE TRIGGER IF NOT EXISTS keys_gen_acct_ins AFTER INSERT ON accounts
  BEGIN UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'keys_generation'; END;
CREATE TRIGGER IF NOT EXISTS keys_gen_acct_upd AFTER UPDATE OF email ON accounts
  BEGIN UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'keys_generation'; END;
CREATE TRIGGER IF NOT EXISTS keys_gen_acct_del AFTER DELETE ON accounts
  BEGIN UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'keys_generation'; END;
"#;

/// Idempotent migration for the reference index: creates `message_refs` and the indexes
/// threading needs, then (once per profile, keyed in `meta`) back-fills `message_refs` from
/// every stored row's `in_reply_to_json` / `references_json`, so a profile synced by an older
/// build threads exactly like a fresh one. Runs before [`migrate_threads`], whose back-fill
/// looks the references up.
pub(crate) fn migrate_message_refs(conn: &Connection) -> Result<()> {
    conn.execute_batch(REFS_SCHEMA)?;
    let done: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![META_REFS_BACKFILLED],
            |r| r.get(0),
        )
        .optional()?;
    if done.is_some() {
        return Ok(());
    }
    let n = in_savepoint(conn, "migrate_message_refs", || {
        let n = conn.execute(
            "INSERT OR IGNORE INTO message_refs (account_id, ref, message_row) \
             SELECT m.account_id, j.value, m.id FROM messages m, json_each(m.in_reply_to_json) j \
             WHERE json_valid(m.in_reply_to_json) AND j.type = 'text' \
             UNION ALL \
             SELECT m.account_id, j.value, m.id FROM messages m, json_each(m.references_json) j \
             WHERE json_valid(m.references_json) AND j.type = 'text'",
            [],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, '1')",
            params![META_REFS_BACKFILLED],
        )?;
        Ok(n)
    })?;
    if n > 0 {
        tracing::info!(refs = n, "message references back-filled");
    }
    Ok(())
}

/// Record the `In-Reply-To` / `References` ids of the stored message `row_id` in
/// `message_refs` (part of the insert's transaction).
fn insert_refs(conn: &Connection, account_id: i64, row_id: i64, m: &NewMessage) -> Result<()> {
    let mut stmt = conn.prepare_cached(
        "INSERT OR IGNORE INTO message_refs (account_id, ref, message_row) VALUES (?1, ?2, ?3)",
    )?;
    for r in m.in_reply_to.iter().chain(m.references.iter()) {
        stmt.execute(params![account_id, r, row_id])?;
    }
    Ok(())
}

/// Thread ids of the stored messages of `account_id` (other than `row_id`) whose
/// `References` or `In-Reply-To` name `message_id` — an exact match on the id, the same rows
/// the former `instr` scan of the JSON columns found, via the `message_refs` index.
fn threads_referencing(
    conn: &Connection,
    account_id: i64,
    row_id: i64,
    message_id: &str,
) -> Result<Vec<String>> {
    let mut stmt = conn.prepare_cached(THREADS_REFERENCING_SQL)?;
    let rows = stmt.query_map(params![account_id, row_id, message_id], |r| {
        r.get::<_, String>(0)
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// [`threads_referencing`]'s query (`?1` account, `?2` row to skip, `?3` the Message-ID).
const THREADS_REFERENCING_SQL: &str = "SELECT m.thread_id FROM message_refs r \
     JOIN messages m ON m.id = r.message_row \
     WHERE r.account_id = ?1 AND r.ref = ?3 AND r.message_row != ?2 ORDER BY r.message_row";

/// [`threads_of_message`]'s query (`?1` account, `?2` the Message-ID, `?3` row to skip).
/// Pinned to the `(account_id, message_id)` index: without `ANALYZE` statistics the planner
/// would pick `messages_thread (account_id)` and visit every row of the account.
const THREADS_OF_MESSAGE_SQL: &str = "SELECT thread_id FROM messages \
     INDEXED BY messages_account_mid \
     WHERE account_id = ?1 AND message_id = ?2 AND id != ?3 ORDER BY id";

/// Thread ids of the stored copies of `message_id` in `account_id` (other than `row_id`).
fn threads_of_message(
    conn: &Connection,
    account_id: i64,
    row_id: i64,
    message_id: &str,
) -> Result<Vec<String>> {
    let mut stmt = conn.prepare_cached(THREADS_OF_MESSAGE_SQL)?;
    let rows = stmt.query_map(params![account_id, message_id, row_id], |r| {
        r.get::<_, String>(0)
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// The thread id for the message `row_id` of `account_id` (about to be inserted, or being
/// back-filled), merging the threads of its already-stored relatives into it:
///
/// 1. walk `References` (oldest first) then `In-Reply-To`: the first ancestor that is stored
///    — or that another stored message also references (a sibling whose parent is missing) —
///    gives the thread; every other relative's thread is merged into it;
/// 2. no known relative: the message's own Message-ID, else `sbx-thread:<row id>`;
/// 3. replies that arrived before this message (they reference it) are pulled into its thread,
///    which is how a late parent re-links its children.
///
/// Threads are scoped to one account. Callers hold the store mutex and a transaction.
fn thread_id_for(
    conn: &Connection,
    account_id: i64,
    row_id: i64,
    message_id: Option<&str>,
    in_reply_to: &[String],
    references: &[String],
) -> Result<String> {
    let mut ancestors: Vec<&str> = Vec::new();
    for a in references.iter().chain(in_reply_to.iter()) {
        let a = a.trim().trim_start_matches('<').trim_end_matches('>');
        if !a.is_empty() && !ancestors.contains(&a) {
            ancestors.push(a);
        }
    }
    let own = message_id
        .map(|m| m.trim().trim_start_matches('<').trim_end_matches('>'))
        .filter(|m| !m.is_empty());
    let mut related: Vec<String> = Vec::new();
    for a in &ancestors {
        if own.is_some_and(|m| m == *a) {
            continue; // a message naming itself
        }
        for t in threads_of_message(conn, account_id, row_id, a)? {
            push_unique(&mut related, t);
        }
        for t in threads_referencing(conn, account_id, row_id, a)? {
            push_unique(&mut related, t);
        }
    }
    let mut children: Vec<String> = Vec::new();
    if let Some(mid) = own {
        // Another copy of the same message (e.g. a self-addressed mail in Sent and INBOX).
        for t in threads_of_message(conn, account_id, row_id, mid)? {
            push_unique(&mut related, t);
        }
        for t in threads_referencing(conn, account_id, row_id, mid)? {
            push_unique(&mut children, t);
        }
    }
    let thread_id = match related.first() {
        Some(t) => t.clone(),
        None => match own {
            Some(m) => m.to_owned(),
            None => format!("sbx-thread:{row_id}"),
        },
    };
    for t in related.iter().skip(1).chain(children.iter()) {
        if *t != thread_id {
            conn.execute(
                "UPDATE messages SET thread_id = ?1 WHERE account_id = ?2 AND thread_id = ?3",
                params![thread_id, account_id, t],
            )?;
        }
    }
    Ok(thread_id)
}

/// Insert one message inside the caller's transaction (see [`Store::insert_message`]):
/// `Ok(None)` if `(account, folder, uid)` already exists. Writes the metadata row and, sealed,
/// its bodies and raw MIME into `message_blobs`; threads it, records its references and
/// indexes it for search.
fn insert_in(tx: &Connection, v: &Vault, m: &NewMessage) -> Result<Option<i64>> {
    let exists: Option<i64> = tx
        .query_row(
            "SELECT id FROM messages WHERE account_id = ?1 AND folder_id = ?2 AND uid = ?3",
            params![m.account_id, m.folder_id, i64::from(m.uid)],
            |r| r.get(0),
        )
        .optional()?;
    if exists.is_some() {
        return Ok(None);
    }
    let id = next_id(tx, "messages")?;
    let rid = id.to_string();
    let text = v.seal_opt_text("messages", "text_body", &rid, m.text.as_deref())?;
    let html = v.seal_opt_text("messages", "html_body", &rid, m.html.as_deref())?;
    let raw = v.seal_blob("messages", "raw", &rid, &m.raw)?;
    let snippet = snippet_of(m.text.as_deref(), m.html.as_deref());
    let snippet = v.seal_opt_text("messages", "snippet", &rid, snippet.as_deref())?;
    let thread_id = thread_id_for(
        tx,
        m.account_id,
        id,
        m.message_id.as_deref(),
        &m.in_reply_to,
        &m.references,
    )?;
    tx.prepare_cached(
        "INSERT INTO messages (id, account_id, folder_id, uid, message_id, from_name, from_addr, \
         to_json, cc_json, subject, protected_subject, date, received_at, flags_json, \
         was_encrypted, decrypted, was_signed, sig_status, sig_fingerprint, sig_signer, \
         signatures_json, in_reply_to_json, references_json, decrypt_error, raw_size, \
         thread_id, snippet) VALUES (?25, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, \
         ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?26, ?27)",
    )?
    .execute(params![
        m.account_id,
        m.folder_id,
        i64::from(m.uid),
        m.message_id,
        m.from.name,
        m.from.address,
        serde_json::to_string(&m.to)?,
        serde_json::to_string(&m.cc)?,
        m.subject,
        m.protected_subject,
        m.date,
        m.received_at,
        serde_json::to_string(&m.flags)?,
        m.was_encrypted,
        m.decrypted,
        m.was_signed,
        sig_state_to_str(m.signature.status),
        m.signature.fingerprint,
        m.signature.signer,
        m.signatures_json,
        serde_json::to_string(&m.in_reply_to)?,
        serde_json::to_string(&m.references)?,
        m.decrypt_error,
        m.raw.len() as i64,
        id,
        thread_id,
        snippet,
    ])?;
    // OR REPLACE: a blob row left behind by a message deleted without the cascade (foreign
    // keys off) must not block the id `next_id` hands out again.
    tx.prepare_cached(
        "INSERT OR REPLACE INTO message_blobs (message_id, text_body, html_body, raw) \
         VALUES (?1, ?2, ?3, ?4)",
    )?
    .execute(params![id, text, html, raw])?;
    insert_refs(tx, m.account_id, id, m)?; // reference index for threading
    if is_draft_copy(tx, m)? {
        // A saved draft's server copy (drafts_imap.rs): the draft is listed as a draft.
        tx.prepare_cached("INSERT OR IGNORE INTO draft_copies (message_id) VALUES (?1)")?
            .execute(params![id])?;
    } else {
        crate::search::index_inserted(tx, id, m)?; // in-memory search index (search.rs)
    }
    for (idx, a) in m.attachments.iter().enumerate() {
        let aid = next_id(tx, "attachments")?;
        let data = v.seal_blob("attachments", "data", &aid.to_string(), &a.data)?;
        tx.execute(
            "INSERT INTO attachments \
             (id, message_id, idx, filename, content_type, size, data, content_id) \
             VALUES (?7, ?1, ?2, ?3, ?4, ?5, ?6, ?8)",
            params![
                id,
                idx as i64,
                a.filename,
                a.content_type,
                a.data.len() as i64,
                data,
                aid,
                a.content_id
            ],
        )?;
    }
    Ok(Some(id))
}

/// A stored account including its credential (never leaves the crate).
#[derive(Clone)]
pub(crate) struct AccountRow {
    pub id: i64,
    pub email: String,
    pub display_name: String,
    pub imap: Endpoint,
    pub smtp: Endpoint,
    pub auth_kind: AuthKind,
    pub login: String,
    pub credential: String,
    pub created_at: i64,
    /// The provider profile the owner stated for this account; `None` = guess from the IMAP
    /// host. See [`migrate_account_provider`].
    pub provider: Option<ProviderId>,
}

impl std::fmt::Debug for AccountRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountRow")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("imap", &self.imap)
            .field("smtp", &self.smtp)
            .field("auth_kind", &self.auth_kind)
            .field("login", &self.login)
            .finish_non_exhaustive()
    }
}

impl AccountRow {
    /// The transport credential for IMAP/SMTP.
    pub(crate) fn mail_auth(&self) -> Auth {
        match self.auth_kind {
            AuthKind::Password => Auth::Password {
                user: self.login.clone(),
                pass: self.credential.clone(),
            },
            AuthKind::OAuth => {
                let token = serde_json::from_str::<AuthSpec>(&self.credential)
                    .ok()
                    .and_then(|a| match a {
                        AuthSpec::OAuth { access_token, .. } => Some(access_token),
                        AuthSpec::Password { .. } => None,
                    })
                    .unwrap_or_default();
                Auth::XOAuth2 {
                    user: self.login.clone(),
                    access_token: token,
                }
            }
        }
    }

    /// Who issued the account's OAuth token, from the stored credential (`AuthSpec::OAuth`'s
    /// `provider`): decides which hosts the token may be presented to (docs/THREAT_MODEL.md
    /// R14). `None` for password accounts and for tokens without a known provider (the mail
    /// layer then only accepts Google / Microsoft hosts). Never marks a mock IdP: that needs
    /// the `oauth_tokens` row (`OAuthTokenRow::bearer_scope`).
    pub(crate) fn bearer_scope(&self) -> Option<BearerScope> {
        if self.auth_kind != AuthKind::OAuth {
            return None;
        }
        match serde_json::from_str::<AuthSpec>(&self.credential).ok()? {
            AuthSpec::OAuth {
                provider: Some(p), ..
            } => Provider::parse(&p).map(BearerScope::new),
            _ => None,
        }
    }

    pub(crate) fn info(&self, fingerprint: Option<String>) -> AccountInfo {
        AccountInfo {
            id: self.id,
            email: self.email.clone(),
            display_name: self.display_name.clone(),
            imap: self.imap.clone(),
            smtp: self.smtp.clone(),
            auth_kind: self.auth_kind,
            login: self.login.clone(),
            fingerprint,
            created_at: self.created_at,
        }
    }
}

/// Account to insert.
pub(crate) struct NewAccount<'a> {
    pub email: &'a str,
    pub display_name: &'a str,
    pub imap: &'a Endpoint,
    pub smtp: &'a Endpoint,
    pub auth_kind: AuthKind,
    pub login: &'a str,
    pub credential: &'a str,
}

#[derive(Clone)]
pub(crate) struct IdentityRow {
    pub id: i64,
    #[allow(dead_code)]
    pub account_id: i64,
    pub fingerprint: String,
    pub email: String,
    pub secret_armored: String,
    pub public_armored: String,
    #[allow(dead_code)]
    pub created_at: i64,
}

impl std::fmt::Debug for IdentityRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityRow")
            .field("id", &self.id)
            .field("fingerprint", &self.fingerprint)
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

/// Sync state of one folder. Every server UID in `[floor_uid, last_uid]` that existed when it
/// was fetched is stored: new mail is fetched above `last_uid` (oldest first, so the
/// watermark never skips anything), older mail below `floor_uid` (newest first). A first sync
/// fetches only the newest window and sets both; `floor_uid` ≤ 1 means nothing older is left
/// (0 for folders synced before the window existed, which always started at UID 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FolderRow {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    pub uidvalidity: u32,
    pub last_uid: u32,
    pub floor_uid: u32,
}

impl FolderRow {
    /// Older mail is still to be fetched below the floor.
    pub(crate) fn more_to_backfill(&self) -> bool {
        self.floor_uid > 1
    }
}

/// Idempotent migration: `folders.floor_uid` (the newest-first window and its backfill, see
/// [`FolderRow`]). Existing rows get 0: they were synced from UID 1, nothing older is missing.
/// `accounts.provider`: the provider profile the *owner* says this account is, overriding what
/// the IMAP host looks like.
///
/// `profile_for_host` guesses from the host name, which is right for `imap.gmail.com` and wrong
/// twice over: a company domain hosted on Microsoft 365 or Google Workspace has its own IMAP
/// host and so is classified `Generic`, losing the quirks it actually has; and a provider
/// simulator on `127.0.0.1` is classified `Greenmail`, which is why the provider conformance
/// suite could not run against one. Empty means "not stated" — keep guessing from the host.
pub(crate) fn migrate_account_provider(conn: &Connection) -> Result<()> {
    let has_column = {
        let mut stmt = conn.prepare("PRAGMA table_info(accounts)")?;
        let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
        let mut found = false;
        for n in names {
            if n? == "provider" {
                found = true;
            }
        }
        found
    };
    if !has_column {
        conn.execute(
            "ALTER TABLE accounts ADD COLUMN provider TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    Ok(())
}

pub(crate) fn migrate_folder_floor(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(folders)")?;
    let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
    let mut found = false;
    for n in names {
        if n? == "floor_uid" {
            found = true;
        }
    }
    if !found {
        conn.execute(
            "ALTER TABLE folders ADD COLUMN floor_uid INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    Ok(())
}

/// Idempotent migration: `attachments.content_id`, the part's `Content-ID` — what a `cid:`
/// image URL in the HTML body names (`docs/HTML_MAIL.md`, "Inline images"). Plaintext like
/// `filename` and `content_type`. Rows stored before the column keep `NULL`, so their inline
/// images stay placeholders.
pub(crate) fn migrate_attachment_content_id(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(attachments)")?;
    let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
    let mut found = false;
    for n in names {
        if n? == "content_id" {
            found = true;
        }
    }
    if !found {
        conn.execute("ALTER TABLE attachments ADD COLUMN content_id TEXT", [])?;
    }
    Ok(())
}

/// The columns [`migrate_message_blobs`] moves out of `messages`, each with the value it holds
/// once emptied (until it is dropped; `raw` is `NOT NULL`).
const LEGACY_BLOB_COLUMNS: [(&str, &str); 3] =
    [("text_body", "NULL"), ("html_body", "NULL"), ("raw", "X''")];

/// Messages per transaction in [`migrate_message_blobs`]: bounds the WAL, and the pages one
/// batch frees in `messages` are reused by the next batch's blobs, so the file grows by about
/// one batch instead of by a second copy of the mailbox.
const BLOB_MIGRATION_BATCH: usize = 500;

/// The column names of `table`.
fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
    Ok(names.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Idempotent migration, blobs out of the hot row (docs/PERFORMANCE.md, phase 3). A profile
/// created before `message_blobs` holds the sealed bodies and the raw MIME in every `messages`
/// row, so each `UPDATE` of a row (spam verdict, thread merge, flags, the snippet) rewrote them
/// with their overflow pages. They move to `message_blobs`, [`BLOB_MIGRATION_BATCH`] rows per
/// transaction, bytes unchanged: an envelope's AAD names `messages:<column>:<id>` before and
/// after (`vault::WRAPPED`), so no key is needed and the profile may still be locked (this runs
/// in [`Store::open`], before the vault is unlocked). Then the emptied columns are dropped. A
/// crash between batches resumes where it stopped; every later open costs one `table_info`.
pub(crate) fn migrate_message_blobs(conn: &Connection) -> Result<()> {
    if legacy_blob_columns(conn)?.is_empty() {
        return Ok(());
    }
    let Err(e) = move_message_blobs(conn) else {
        return Ok(());
    };
    // Another process opening the same profile (the app next to the CLI) may have finished
    // the migration while this one was busy: its dropped columns make our statements fail.
    if legacy_blob_columns(conn)?.is_empty() {
        tracing::info!("message_blobs migration finished by another connection ({e})");
        return Ok(());
    }
    Err(e)
}

/// The blob columns `messages` still has (all three on a profile from before
/// `message_blobs`, none after [`migrate_message_blobs`]).
fn legacy_blob_columns(conn: &Connection) -> Result<Vec<(&'static str, &'static str)>> {
    let cols = table_columns(conn, "messages")?;
    Ok(LEGACY_BLOB_COLUMNS
        .iter()
        .copied()
        .filter(|(c, _)| cols.iter().any(|n| n == c))
        .collect())
}

/// SQL: the `messages` row still holds a blob in one of the `legacy` columns.
fn holds_blobs(legacy: &[(&str, &str)]) -> String {
    legacy
        .iter()
        .map(|(c, _)| match *c {
            "raw" => "length(raw) > 0".to_owned(),
            c => format!("{c} IS NOT NULL"),
        })
        .collect::<Vec<_>>()
        .join(" OR ")
}

/// [`migrate_message_blobs`]'s work: the batches, then the columns.
fn move_message_blobs(conn: &Connection) -> Result<()> {
    let legacy = legacy_blob_columns(conn)?;
    let started = std::time::Instant::now();
    // What a legacy row holds for each blob (a column already gone: its emptied value), and
    // the test for a row that still holds any.
    let value = |name: &str, empty: &str| {
        if legacy.iter().any(|(c, _)| *c == name) {
            name.to_owned()
        } else {
            empty.to_owned()
        }
    };
    let holds = holds_blobs(&legacy);
    // While the old columns hold the blobs they are the truth (REPLACE); a row emptied by an
    // interrupted earlier run already has its blob row and is skipped.
    let copy = format!(
        "INSERT OR REPLACE INTO message_blobs (message_id, text_body, html_body, raw) \
         SELECT id, {t}, {h}, {r} FROM messages WHERE id BETWEEN ?1 AND ?2 \
         AND ({holds} OR NOT EXISTS \
         (SELECT 1 FROM message_blobs b WHERE b.message_id = messages.id))",
        t = value("text_body", "NULL"),
        h = value("html_body", "NULL"),
        r = value("raw", "X''"),
    );
    let sets = legacy
        .iter()
        .map(|(c, empty)| format!("{c} = {empty}"))
        .collect::<Vec<_>>()
        .join(", ");
    let empty = format!("UPDATE messages SET {sets} WHERE id BETWEEN ?1 AND ?2 AND ({holds})");
    let ids: Vec<i64> = {
        let mut stmt = conn.prepare("SELECT id FROM messages ORDER BY id")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let mut moved = 0usize;
    for chunk in ids.chunks(BLOB_MIGRATION_BATCH) {
        let (Some(lo), Some(hi)) = (chunk.first(), chunk.last()) else {
            continue;
        };
        let tx = conn.unchecked_transaction()?;
        moved += tx.execute(&copy, params![lo, hi])?;
        tx.execute(&empty, params![lo, hi])?;
        tx.commit()?;
    }
    // The emptied columns go in one IMMEDIATE transaction (write lock first, then the columns
    // are read again: another connection may have dropped them meanwhile). SQLite rewrites the
    // now small rows once per column.
    in_immediate(conn, drop_emptied_blob_columns)?;
    if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
        tracing::warn!("WAL checkpoint after the message_blobs migration: {e}");
    }
    tracing::info!(
        messages = moved,
        ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "message blobs moved out of the message rows"
    );
    Ok(())
}

/// Drop the blob columns `messages` still has, only when no row holds a blob any more (inside
/// the caller's transaction).
fn drop_emptied_blob_columns(conn: &Connection) -> Result<()> {
    let legacy = legacy_blob_columns(conn)?;
    if legacy.is_empty() {
        return Ok(());
    }
    let left: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM messages WHERE {}",
            holds_blobs(&legacy)
        ),
        [],
        |r| r.get(0),
    )?;
    if left > 0 {
        return Err(Error::InvalidInput(format!(
            "message_blobs migration: {left} message rows still hold their blobs"
        )));
    }
    for (c, _) in &legacy {
        conn.execute_batch(&format!("ALTER TABLE messages DROP COLUMN {c};"))?;
    }
    Ok(())
}

/// The tables a profile had before `message_blobs` (tests): `messages` with the bodies and the
/// raw MIME in the row, exactly as builds up to this migration created it.
#[cfg(test)]
const LEGACY_BLOB_SCHEMA: &str = r#"
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL DEFAULT '', imap_host TEXT NOT NULL, imap_port INTEGER NOT NULL,
    imap_security TEXT NOT NULL, smtp_host TEXT NOT NULL, smtp_port INTEGER NOT NULL,
    smtp_security TEXT NOT NULL, auth_kind TEXT NOT NULL, login TEXT NOT NULL,
    credential TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE folders (
    id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL, uidvalidity INTEGER NOT NULL DEFAULT 0,
    last_uid INTEGER NOT NULL DEFAULT 0, UNIQUE (account_id, name)
);
CREATE TABLE messages (
    id                INTEGER PRIMARY KEY,
    account_id        INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    folder_id         INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    uid               INTEGER NOT NULL,
    message_id        TEXT,
    from_name         TEXT,
    from_addr         TEXT NOT NULL DEFAULT '',
    to_json           TEXT NOT NULL DEFAULT '[]',
    cc_json           TEXT NOT NULL DEFAULT '[]',
    subject           TEXT,
    protected_subject INTEGER NOT NULL DEFAULT 0,
    date              INTEGER,
    received_at       INTEGER NOT NULL,
    flags_json        TEXT NOT NULL DEFAULT '[]',
    was_encrypted     INTEGER NOT NULL DEFAULT 0,
    decrypted         INTEGER NOT NULL DEFAULT 0,
    was_signed        INTEGER NOT NULL DEFAULT 0,
    sig_status        TEXT NOT NULL DEFAULT 'none',
    sig_fingerprint   TEXT,
    sig_signer        TEXT,
    signatures_json   TEXT NOT NULL DEFAULT '[]',
    text_body         TEXT,
    html_body         TEXT,
    in_reply_to_json  TEXT NOT NULL DEFAULT '[]',
    references_json   TEXT NOT NULL DEFAULT '[]',
    decrypt_error     TEXT,
    raw               BLOB NOT NULL,
    raw_size          INTEGER NOT NULL,
    thread_id         TEXT NOT NULL DEFAULT '',
    UNIQUE (account_id, folder_id, uid)
);
CREATE INDEX messages_date ON messages(date DESC, id DESC);
CREATE INDEX messages_mid ON messages(message_id);
CREATE TABLE attachments (
    id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    idx INTEGER NOT NULL, filename TEXT NOT NULL, content_type TEXT NOT NULL,
    size INTEGER NOT NULL, data BLOB NOT NULL, content_id TEXT, UNIQUE (message_id, idx)
);
"#;

/// A profile database as builds before `message_blobs` wrote it (tests): account 1
/// `legacy@example.org` (credential `legacy-password`), folder 1 `INBOX`, messages `1..=n` with
/// text `body <id>`, HTML `<p>html <id></p>` on odd ids and raw `raw <id>` in the row —
/// sealed under `key` with the `messages:<column>:<id>` AAD, or plaintext (`None`, pre-G27).
#[cfg(test)]
pub(crate) fn legacy_blob_db(path: &Path, key: Option<&[u8; 32]>, n: i64) -> Result<()> {
    legacy_db(path, key, n, LEGACY_BLOB_SCHEMA)
}

/// [`LEGACY_BLOB_SCHEMA`] from before reference threading too (no `messages.thread_id`).
#[cfg(test)]
pub(crate) fn legacy_pre_threads_schema() -> String {
    let s = LEGACY_BLOB_SCHEMA.replace("    thread_id         TEXT NOT NULL DEFAULT '',\n", "");
    assert!(!s.contains("thread_id"), "the legacy schema changed shape");
    s
}

/// [`legacy_blob_db`] with the given table definitions.
#[cfg(test)]
pub(crate) fn legacy_db(path: &Path, key: Option<&[u8; 32]>, n: i64, schema: &str) -> Result<()> {
    use crate::vault::{aad, seal};
    let conn = Connection::open(path)?;
    conn.execute_batch(schema)?;
    let text = |table: &str, col: &str, id: i64, s: &str| -> Result<Value> {
        Ok(match key {
            Some(k) => Value::Blob(seal(k, &aad(table, col, &id.to_string()), s.as_bytes())?),
            None => Value::Text(s.to_owned()),
        })
    };
    conn.execute(
        "INSERT INTO accounts (id, email, imap_host, imap_port, imap_security, smtp_host, \
         smtp_port, smtp_security, auth_kind, login, credential, created_at) VALUES (1, \
         'legacy@example.org', '127.0.0.1', 9, 'plain', '127.0.0.1', 9, 'plain', 'password', \
         'legacy', ?1, 0)",
        params![text("accounts", "credential", 1, "legacy-password")?],
    )?;
    conn.execute(
        "INSERT INTO folders (id, account_id, name) VALUES (1, 1, 'INBOX')",
        [],
    )?;
    let tx = conn.unchecked_transaction()?;
    for id in 1..=n {
        let html = (id % 2 == 1)
            .then(|| text("messages", "html_body", id, &format!("<p>html {id}</p>")))
            .transpose()?;
        let raw = format!("raw {id}");
        let raw_v = match key {
            Some(k) => Value::Blob(seal(
                k,
                &aad("messages", "raw", &id.to_string()),
                raw.as_bytes(),
            )?),
            None => Value::Blob(raw.clone().into_bytes()),
        };
        tx.execute(
            "INSERT INTO messages (id, account_id, folder_id, uid, message_id, from_addr, subject, \
             date, received_at, text_body, html_body, raw, raw_size) \
             VALUES (?1, 1, 1, ?1, ?2, 'x@example.org', ?3, ?1, ?1, ?4, ?5, ?6, ?7)",
            params![
                id,
                format!("m{id}@example.org"),
                format!("subject {id}"),
                text("messages", "text_body", id, &format!("body {id}"))?,
                html,
                raw_v,
                raw.len() as i64
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Idempotent migration for the message list: `messages.snippet` (sealed, `vault::WRAPPED`)
/// and `messages_folder_order`, the index [`LIST_FOLDER_SQL`] walks — without it every list
/// call sorted the whole folder (and read every row of it, bodies included). Rows stored
/// before the column get their snippet from the bodies on read.
pub(crate) fn migrate_message_list(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(messages)")?;
    let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
    let mut found = false;
    for n in names {
        if n? == "snippet" {
            found = true;
        }
    }
    if !found {
        conn.execute("ALTER TABLE messages ADD COLUMN snippet TEXT", [])?;
    }
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS messages_folder_order \
         ON messages(folder_id, COALESCE(date, received_at) DESC, id DESC);",
    )?;
    Ok(())
}

/// The newest `?2` (sort key, id) of folder `?1`, the order [`Store::list_messages`] keeps.
const LIST_FOLDER_SQL: &str = "SELECT COALESCE(date, received_at), id FROM messages \
     INDEXED BY messages_folder_order WHERE folder_id = ?1 \
     AND NOT EXISTS (SELECT 1 FROM draft_copies c WHERE c.message_id = messages.id) \
     ORDER BY COALESCE(date, received_at) DESC, id DESC LIMIT ?2";

/// True for a saved draft's server copy (`drafts_imap.rs`): it carries `X-Sealbox-Draft` and
/// lands in its account's Drafts role folder. The folder check keeps a mail anyone could
/// send with that header from hiding itself in the INBOX.
fn is_draft_copy(tx: &Connection, m: &NewMessage) -> Result<bool> {
    if crate::drafts_imap::header_value(&m.raw, crate::drafts_imap::DRAFT_HEADER).is_none() {
        return Ok(false);
    }
    Ok(tx
        .prepare_cached(
            "SELECT EXISTS (SELECT 1 FROM folder_roles r JOIN folders f \
             ON f.account_id = r.account_id AND f.name = r.name COLLATE NOCASE \
             WHERE f.id = ?1 AND r.role = 'drafts')",
        )?
        .query_row(params![m.folder_id], |r| r.get(0))?)
}

/// Characters of a list snippet.
pub(crate) const SNIPPET_CHARS: usize = 160;

/// The list snippet of a message (see [`MessageSummary::snippet`]): the text body, else the
/// HTML body reduced to text by the same allow-list as the HTML view, whitespace collapsed,
/// at most [`SNIPPET_CHARS`] characters; `None` when that leaves nothing.
pub(crate) fn snippet_of(text: Option<&str>, html: Option<&str>) -> Option<String> {
    fn collapse(t: &str) -> String {
        let mut out = String::new();
        let mut n = 0usize;
        for w in t.split_whitespace() {
            if n >= SNIPPET_CHARS {
                break;
            }
            if !out.is_empty() {
                out.push(' ');
                n += 1;
            }
            for c in w.chars() {
                if n >= SNIPPET_CHARS {
                    break;
                }
                out.push(c);
                n += 1;
            }
        }
        out.trim_end().to_string()
    }
    let s = match text.filter(|t| !t.trim().is_empty()) {
        Some(t) => collapse(t),
        None => collapse(&sealbox_mail::html::html_to_text(html?)),
    };
    (!s.is_empty()).then_some(s)
}

/// An [`AttachmentInfo`] from the columns `idx, filename, content_type, size, content_id`.
fn attachment_info_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AttachmentInfo> {
    Ok(AttachmentInfo {
        index: usize::try_from(r.get::<_, i64>(0)?).unwrap_or(0),
        filename: r.get(1)?,
        content_type: r.get(2)?,
        size: usize::try_from(r.get::<_, i64>(3)?).unwrap_or(0),
        content_id: r.get(4)?,
    })
}

const FOLDER_COLUMNS: &str = "id, account_id, name, uidvalidity, last_uid, floor_uid";

fn folder_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<FolderRow> {
    Ok(FolderRow {
        id: r.get(0)?,
        account_id: r.get(1)?,
        name: r.get(2)?,
        uidvalidity: to_u32(r.get(3)?),
        last_uid: to_u32(r.get(4)?),
        floor_uid: to_u32(r.get(5)?),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyRow {
    pub addr: String,
    pub source: KeySource,
    pub fingerprint: String,
    pub armored: String,
    pub imported_at: i64,
}

/// Attachment to store with a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NewAttachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
    /// The part's `Content-ID` without angle brackets (see [`AttachmentInfo::content_id`]).
    pub content_id: Option<String>,
}

impl From<sealbox_mail::mime::Attachment> for NewAttachment {
    /// A parsed part as the sync stores it. The `Content-ID` is the sender's text: angle
    /// brackets, surrounding whitespace and control characters go (the CLI prints it to a
    /// terminal), and one that leaves nothing is no `Content-ID`.
    fn from(a: sealbox_mail::mime::Attachment) -> Self {
        let content_id = a.content_id.and_then(|cid| {
            let cid: String = cid
                .trim()
                .trim_start_matches('<')
                .trim_end_matches('>')
                .chars()
                .filter(|c| !c.is_control())
                .collect();
            let cid = cid.trim();
            (!cid.is_empty()).then(|| cid.to_owned())
        });
        Self {
            filename: a.filename,
            content_type: a.content_type,
            data: a.data,
            content_id,
        }
    }
}

/// A fully processed message ready to be stored.
#[derive(Clone, Debug)]
pub(crate) struct NewMessage {
    pub account_id: i64,
    pub folder_id: i64,
    pub uid: u32,
    pub message_id: Option<String>,
    pub from: Address,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub subject: Option<String>,
    pub protected_subject: bool,
    pub date: Option<i64>,
    pub received_at: i64,
    pub flags: Vec<String>,
    pub was_encrypted: bool,
    pub decrypted: bool,
    pub was_signed: bool,
    pub signature: SignatureSummary,
    pub signatures_json: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub decrypt_error: Option<String>,
    pub raw: Vec<u8>,
    pub attachments: Vec<NewAttachment>,
}

/// A stored message (without bodies).
#[derive(Clone, Debug)]
pub(crate) struct MessageRow {
    pub summary: MessageSummary,
    pub account_id: i64,
    pub folder_id: i64,
    pub text: Option<String>,
    pub html: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
}

/// Outbox bookkeeping row.
pub(crate) struct NewOutbox<'a> {
    pub account_id: i64,
    pub message_id: &'a str,
    pub recipients: &'a [String],
    pub subject: &'a str,
    pub mode: &'a str,
    pub state: &'a str,
    pub error: Option<&'a str>,
    pub sent_copy_appended: bool,
}

const MESSAGE_COLUMNS: &str =
    "m.id, a.email, f.name, m.uid, m.message_id, m.from_name, m.from_addr, \
     m.to_json, m.cc_json, m.subject, m.protected_subject, m.date, m.received_at, m.flags_json, \
     m.was_encrypted, m.decrypted, m.was_signed, m.sig_status, m.sig_fingerprint, m.sig_signer, \
     m.decrypt_error, m.raw_size, \
     (SELECT COUNT(*) FROM attachments t WHERE t.message_id = m.id), \
     m.account_id, m.folder_id, b.text_body, b.html_body, m.in_reply_to_json, m.references_json, \
     m.thread_id, m.snippet";

/// The join [`MESSAGE_COLUMNS`] reads the bodies through (`b`; a message without a blob row
/// reads as one without bodies).
const MESSAGE_BLOBS_JOIN: &str = "LEFT JOIN message_blobs b ON b.message_id = m.id";

/// [`MESSAGE_COLUMNS`] for summaries: the bodies are read only for a row without a stored
/// snippet (one stored before the column existed), to derive it.
const SUMMARY_COLUMNS: &str =
    "m.id, a.email, f.name, m.uid, m.message_id, m.from_name, m.from_addr, \
     m.to_json, m.cc_json, m.subject, m.protected_subject, m.date, m.received_at, m.flags_json, \
     m.was_encrypted, m.decrypted, m.was_signed, m.sig_status, m.sig_fingerprint, m.sig_signer, \
     m.decrypt_error, m.raw_size, \
     (SELECT COUNT(*) FROM attachments t WHERE t.message_id = m.id), \
     m.account_id, m.folder_id, \
     CASE WHEN m.snippet IS NULL THEN \
       (SELECT b.text_body FROM message_blobs b WHERE b.message_id = m.id) END, \
     CASE WHEN m.snippet IS NULL THEN \
       (SELECT b.html_body FROM message_blobs b WHERE b.message_id = m.id) END, \
     m.in_reply_to_json, m.references_json, m.thread_id, m.snippet";

/// A message row as read, its wrapped values still sealed: text body, HTML body, snippet.
type RawMessageRow = (MessageRow, Value, Value, Value);

const MESSAGE_FROM: &str =
    "FROM messages m JOIN accounts a ON a.id = m.account_id JOIN folders f ON f.id = m.folder_id";

/// The store schema this build writes and understands, kept in `meta.schema_version` by
/// [`migrate`]: 1 up to the `messages` row with the blobs in it, 2 since `message_blobs`. A
/// profile with a higher number was written by a newer build whose layout this one would
/// break (an `INSERT` naming a column the newer one dropped), so [`Store::open`] refuses it
/// with [`Error::ProfileNewer`] before writing anything. Raise it with every migration an
/// older build cannot live with.
pub(crate) const SCHEMA_VERSION: i64 = 2;

/// The profile's `meta.schema_version`; `None` for a new file (no `meta` yet). A value that
/// is not a number reads as 0 (older than every build).
fn profile_schema_version(conn: &Connection) -> Result<Option<i64>> {
    let has_meta: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta')",
        [],
        |r| r.get(0),
    )?;
    if !has_meta {
        return Ok(None);
    }
    Ok(conn
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .optional()?)
}

/// `journal_mode=WAL` (persistent in the file). Switching a new or rollback-journal file
/// needs a moment of exclusive access that SQLite does not wait for, so two first opens at
/// the same moment retry briefly instead of failing with `database is locked`.
fn enable_wal(conn: &Connection) -> Result<()> {
    let mut tries = 0;
    loop {
        match conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get::<_, String>(0)) {
            Ok(_) => return Ok(()),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::DatabaseBusy && tries < 100 =>
            {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// The schema and every migration of [`Store::open`], race-safe: two connections (the app
/// next to the CLI, two processes) opening the same profile at the same moment both succeed.
/// Every schema step runs in ONE `BEGIN IMMEDIATE` transaction ([`in_immediate`]): each
/// check a step makes is read under the write lock, and the connection that comes second
/// finds the work done. The version guard comes first, so a newer profile is refused before
/// anything is written; the version is raised before the blobs move, so from then on an
/// older build refuses the profile too. The blob move ([`migrate_message_blobs`]) follows in
/// its own batches (a bounded WAL) and is race-safe by itself.
fn migrate(conn: &Connection) -> Result<()> {
    in_immediate(conn, |c| {
        let profile = profile_schema_version(c)?;
        if let Some(v) = profile.filter(|v| *v > SCHEMA_VERSION) {
            return Err(Error::ProfileNewer {
                profile: v,
                engine: SCHEMA_VERSION,
            });
        }
        c.execute_batch(SCHEMA)?;
        c.execute_batch(crate::vault::SCHEMA)?; // profile_meta (G27)
        c.execute_batch(crate::settings::SCHEMA)?; // settings + autoreply_log (G23/G24)
        c.execute_batch(crate::oauth::SCHEMA)?; // oauth_tokens (G21)
        c.execute_batch(crate::providers::SCHEMA)?; // folder_roles (G21)
        c.execute_batch(crate::guest::SCHEMA)?; // guest_links (G29)
        c.execute_batch(crate::identity::SCHEMA)?; // identity_*, kt_pins (G30)
        c.execute_batch(crate::drafts::SCHEMA)?; // drafts, draft_sync (vault::WRAPPED)
        crate::spam::migrate(c)?; // spam_model, filter_rules, messages.spam_* (G25)
        migrate_message_refs(c)?; // message_refs + threading indexes (O(log n) inserts)
        migrate_threads(c)?; // messages.thread_id + back-fill (reference threading)
        migrate_folder_floor(c)?; // folders.floor_uid (newest-first window + backfill)
        migrate_account_provider(c)?; // accounts.provider (owner-stated provider profile)
        migrate_message_list(c)?; // messages.snippet + the list index
        migrate_attachment_content_id(c)?; // attachments.content_id (inline cid: images)
        c.execute_batch(KEYS_GENERATION_SCHEMA)?; // signer-key generation (sync contexts)
        if profile != Some(SCHEMA_VERSION) {
            // Only when it changes: an open must not commit a write (other connections
            // would see `data_version` move and rebuild their search index).
            c.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?1) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![SCHEMA_VERSION.to_string()],
            )?;
        }
        Ok(())
    })?;
    migrate_message_blobs(conn) // bodies + raw MIME out of the hot row (message_blobs)
}

/// The store handle. Not `Sync` by itself; the engine wraps it in a mutex.
pub(crate) struct Store {
    conn: Connection,
    vault: Vault,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Store")
    }
}

impl Store {
    /// Open (or create) the database at `path` and apply the schema. The store starts in
    /// plaintext mode; `Engine::open_with` unlocks it (`vault::unlock` + [`Store::set_vault`]).
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        restrict_permissions(path);
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        enable_wal(&conn)?;
        conn.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL; PRAGMA secure_delete=ON;",
        )?;
        migrate(&conn)?; // schema + migrations, race-safe; refuses a newer profile
        restrict_permissions(path);
        Ok(Self {
            conn,
            vault: Vault::plaintext(),
        })
    }

    /// The underlying connection, for feature modules that keep their own tables
    /// (`settings.rs`).
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    pub(crate) fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// The at-rest envelope of this profile (feature modules wrap their own columns).
    pub(crate) fn vault(&self) -> &Vault {
        &self.vault
    }

    pub(crate) fn set_vault(&mut self, vault: Vault) {
        self.vault = vault;
    }

    /// In-memory store for tests (plaintext mode; see [`Store::open_in_memory_keyed`]).
    #[cfg(test)]
    pub(crate) fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        migrate(&conn)?;
        Ok(Self {
            conn,
            vault: Vault::plaintext(),
        })
    }

    /// In-memory store keyed with `master` (tests of the wrapped path).
    #[cfg(test)]
    pub(crate) fn open_in_memory_keyed(master: &[u8]) -> Result<Self> {
        let mut s = Self::open_in_memory()?;
        s.vault = Vault::with_master(master)?;
        Ok(s)
    }

    // ----- accounts ---------------------------------------------------------------------

    pub(crate) fn insert_account(&self, a: &NewAccount<'_>) -> Result<i64> {
        if self.account_by_email(a.email)?.is_some() {
            return Err(Error::AccountExists(a.email.to_string()));
        }
        let id = next_id(&self.conn, "accounts")?;
        let credential =
            self.vault
                .seal_text("accounts", "credential", &id.to_string(), a.credential)?;
        self.conn.execute(
            "INSERT INTO accounts (id, email, display_name, imap_host, imap_port, imap_security, \
             smtp_host, smtp_port, smtp_security, auth_kind, login, credential, created_at) \
             VALUES (?13, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                a.email,
                a.display_name,
                a.imap.host,
                i64::from(a.imap.port),
                security_to_str(a.imap.security),
                a.smtp.host,
                i64::from(a.smtp.port),
                security_to_str(a.smtp.security),
                match a.auth_kind {
                    AuthKind::Password => "password",
                    AuthKind::OAuth => "oauth",
                },
                a.login,
                credential,
                now(),
                id,
            ],
        )?;
        Ok(id)
    }

    /// Unwrap `accounts.credential` of a row read by [`Store::account_from_row`].
    fn finish_account(&self, (mut a, cred): (AccountRow, Value)) -> Result<AccountRow> {
        a.credential = self
            .vault
            .open_text("accounts", "credential", &a.id.to_string(), cred)?;
        Ok(a)
    }

    fn account_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(AccountRow, Value)> {
        let imap_sec: String = row.get(5)?;
        let smtp_sec: String = row.get(8)?;
        let auth_kind: String = row.get(9)?;
        let a = AccountRow {
            id: row.get(0)?,
            email: row.get(1)?,
            display_name: row.get(2)?,
            imap: Endpoint {
                host: row.get(3)?,
                port: u16::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
                security: security_from_str(&imap_sec),
            },
            smtp: Endpoint {
                host: row.get(6)?,
                port: u16::try_from(row.get::<_, i64>(7)?).unwrap_or(0),
                security: security_from_str(&smtp_sec),
            },
            auth_kind: if auth_kind == "oauth" {
                AuthKind::OAuth
            } else {
                AuthKind::Password
            },
            login: row.get(10)?,
            credential: String::new(),
            created_at: row.get(12)?,
            provider: ProviderId::parse(&row.get::<_, String>(13)?),
        };
        Ok((a, row.get::<_, Value>(11)?))
    }

    const ACCOUNT_COLUMNS: &'static str =
        "id, email, display_name, imap_host, imap_port, imap_security, \
         smtp_host, smtp_port, smtp_security, auth_kind, login, credential, created_at, provider";

    pub(crate) fn account_by_email(&self, email: &str) -> Result<Option<AccountRow>> {
        let sql = format!(
            "SELECT {} FROM accounts WHERE email = ?1 COLLATE NOCASE",
            Self::ACCOUNT_COLUMNS
        );
        self.conn
            .query_row(&sql, params![email.trim()], Self::account_from_row)
            .optional()?
            .map(|r| self.finish_account(r))
            .transpose()
    }

    pub(crate) fn account_by_id(&self, id: i64) -> Result<Option<AccountRow>> {
        let sql = format!(
            "SELECT {} FROM accounts WHERE id = ?1",
            Self::ACCOUNT_COLUMNS
        );
        self.conn
            .query_row(&sql, params![id], Self::account_from_row)
            .optional()?
            .map(|r| self.finish_account(r))
            .transpose()
    }

    pub(crate) fn list_accounts(&self) -> Result<Vec<AccountRow>> {
        let sql = format!("SELECT {} FROM accounts ORDER BY id", Self::ACCOUNT_COLUMNS);
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], Self::account_from_row)?;
        let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(|r| self.finish_account(r)).collect()
    }

    /// Set (or clear, with `None`) the owner-stated provider of an account.
    pub(crate) fn set_account_provider(&self, id: i64, provider: Option<ProviderId>) -> Result<()> {
        self.conn.execute(
            "UPDATE accounts SET provider = ?1 WHERE id = ?2",
            params![provider.map(ProviderId::as_str).unwrap_or(""), id],
        )?;
        Ok(())
    }

    pub(crate) fn delete_account(&self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM accounts WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ----- identities -------------------------------------------------------------------

    pub(crate) fn insert_identity(
        &self,
        account_id: i64,
        fingerprint: &str,
        email: &str,
        secret_armored: &str,
        public_armored: &str,
    ) -> Result<i64> {
        let id = next_id(&self.conn, "identities")?;
        let secret = self.vault.seal_text(
            "identities",
            "secret_armored",
            &id.to_string(),
            secret_armored,
        )?;
        self.conn.execute(
            "INSERT INTO identities (id, account_id, fingerprint, email, secret_armored, public_armored, created_at) \
             VALUES (?7, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![account_id, fingerprint, email, secret, public_armored, now(), id],
        )?;
        Ok(id)
    }

    fn identity_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(IdentityRow, Value)> {
        Ok((
            IdentityRow {
                id: row.get(0)?,
                account_id: row.get(1)?,
                fingerprint: row.get(2)?,
                email: row.get(3)?,
                secret_armored: String::new(),
                public_armored: row.get(5)?,
                created_at: row.get(6)?,
            },
            row.get::<_, Value>(4)?,
        ))
    }

    fn finish_identity(&self, (mut i, secret): (IdentityRow, Value)) -> Result<IdentityRow> {
        i.secret_armored =
            self.vault
                .open_text("identities", "secret_armored", &i.id.to_string(), secret)?;
        Ok(i)
    }

    pub(crate) fn identities_for_account(&self, account_id: i64) -> Result<Vec<IdentityRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, account_id, fingerprint, email, secret_armored, public_armored, created_at \
             FROM identities WHERE account_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![account_id], Self::identity_from_row)?;
        let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(|r| self.finish_identity(r)).collect()
    }

    pub(crate) fn all_identities(&self) -> Result<Vec<IdentityRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, account_id, fingerprint, email, secret_armored, public_armored, created_at \
             FROM identities ORDER BY id",
        )?;
        let rows = stmt.query_map([], Self::identity_from_row)?;
        let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(|r| self.finish_identity(r)).collect()
    }

    /// Identity previously generated for an address (any account), e.g. after re-adding.
    pub(crate) fn identity_by_email(&self, email: &str) -> Result<Option<IdentityRow>> {
        self.conn
            .query_row(
                "SELECT id, account_id, fingerprint, email, secret_armored, public_armored, created_at \
                 FROM identities WHERE email = ?1 COLLATE NOCASE ORDER BY id LIMIT 1",
                params![email],
                Self::identity_from_row,
            )
            .optional()?
            .map(|r| self.finish_identity(r))
            .transpose()
    }

    /// The signer-key generation ([`KEYS_GENERATION_SCHEMA`]): one indexed read.
    pub(crate) fn keys_generation(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE key = ?1",
                params![META_KEYS_GENERATION],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    // ----- peers (Autocrypt) ------------------------------------------------------------

    pub(crate) fn peer(&self, addr: &str) -> Result<Option<PeerState>> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT state_json FROM peers WHERE addr = ?1 COLLATE NOCASE",
                params![addr.trim()],
                |r| r.get(0),
            )
            .optional()?;
        match json {
            Some(j) => Ok(Some(serde_json::from_str(&j)?)),
            None => Ok(None),
        }
    }

    pub(crate) fn save_peer(&self, state: &PeerState) -> Result<()> {
        let json = serde_json::to_string(state)?;
        self.conn.execute(
            "INSERT INTO peers (addr, state_json, updated_at) VALUES (?1, ?2, ?3) \
             ON CONFLICT(addr) DO UPDATE SET state_json = excluded.state_json, updated_at = excluded.updated_at",
            params![state.addr.trim().to_ascii_lowercase(), json, now()],
        )?;
        Ok(())
    }

    pub(crate) fn all_peers(&self) -> Result<Vec<PeerState>> {
        let mut stmt = self
            .conn
            .prepare("SELECT state_json FROM peers ORDER BY addr")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for j in rows {
            if let Ok(p) = serde_json::from_str::<PeerState>(&j?) {
                out.push(p);
            }
        }
        Ok(out)
    }

    // ----- imported / directory keys -----------------------------------------------------

    pub(crate) fn upsert_key(
        &self,
        addr: &str,
        source: KeySource,
        fingerprint: &str,
        armored: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO keys (addr, source, fingerprint, armored, imported_at) VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(addr, source) DO UPDATE SET fingerprint = excluded.fingerprint, \
             armored = excluded.armored, imported_at = excluded.imported_at",
            params![
                addr.trim().to_ascii_lowercase(),
                key_source_to_str(source),
                fingerprint,
                armored,
                now()
            ],
        )?;
        Ok(())
    }

    fn key_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<KeyRow> {
        let source: String = row.get(1)?;
        Ok(KeyRow {
            addr: row.get(0)?,
            source: key_source_from_str(&source),
            fingerprint: row.get(2)?,
            armored: row.get(3)?,
            imported_at: row.get(4)?,
        })
    }

    pub(crate) fn keys_for(&self, addr: &str) -> Result<Vec<KeyRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT addr, source, fingerprint, armored, imported_at FROM keys \
             WHERE addr = ?1 COLLATE NOCASE ORDER BY imported_at DESC",
        )?;
        let rows = stmt.query_map(params![addr.trim()], Self::key_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub(crate) fn all_keys(&self) -> Result<Vec<KeyRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT addr, source, fingerprint, armored, imported_at FROM keys ORDER BY addr",
        )?;
        let rows = stmt.query_map([], Self::key_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // ----- folders ----------------------------------------------------------------------

    /// Get or create the sync state row for a folder.
    pub(crate) fn folder(&self, account_id: i64, name: &str) -> Result<FolderRow> {
        self.conn.execute(
            "INSERT OR IGNORE INTO folders (account_id, name) VALUES (?1, ?2)",
            params![account_id, name],
        )?;
        Ok(self.conn.query_row(
            &format!("SELECT {FOLDER_COLUMNS} FROM folders WHERE account_id = ?1 AND name = ?2"),
            params![account_id, name],
            folder_from_row,
        )?)
    }

    pub(crate) fn folder_by_id(&self, id: i64) -> Result<Option<FolderRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {FOLDER_COLUMNS} FROM folders WHERE id = ?1"),
                params![id],
                folder_from_row,
            )
            .optional()?)
    }

    /// Every folder row of an account, INBOX first (then in creation order).
    pub(crate) fn folders_of_account(&self, account_id: i64) -> Result<Vec<FolderRow>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {FOLDER_COLUMNS} FROM folders WHERE account_id = ?1 \
             ORDER BY (name = 'INBOX' COLLATE NOCASE) DESC, id"
        ))?;
        let rows = stmt.query_map(params![account_id], folder_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub(crate) fn update_folder(&self, id: i64, uidvalidity: u32, last_uid: u32) -> Result<()> {
        self.conn.execute(
            "UPDATE folders SET uidvalidity = ?1, last_uid = ?2 WHERE id = ?3",
            params![i64::from(uidvalidity), i64::from(last_uid), id],
        )?;
        Ok(())
    }

    /// Both watermarks of a folder at once (see [`FolderRow`]).
    pub(crate) fn set_folder_marks(
        &self,
        id: i64,
        uidvalidity: u32,
        last_uid: u32,
        floor_uid: u32,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE folders SET uidvalidity = ?1, last_uid = ?2, floor_uid = ?3 WHERE id = ?4",
            params![
                i64::from(uidvalidity),
                i64::from(last_uid),
                i64::from(floor_uid),
                id
            ],
        )?;
        Ok(())
    }

    /// UIDVALIDITY changed: forget every message of the folder and restart from UID 0 (the
    /// next sync is a first sync again: newest window, then backfill).
    pub(crate) fn reset_folder(&self, id: i64, uidvalidity: u32) -> Result<()> {
        self.conn
            .execute("DELETE FROM messages WHERE folder_id = ?1", params![id])?;
        self.set_folder_marks(id, uidvalidity, 0, 0)
    }

    /// Messages stored for the folder (through the `(account, folder, uid)` key).
    pub(crate) fn folder_message_count(&self, account_id: i64, folder_id: i64) -> Result<u32> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE account_id = ?1 AND folder_id = ?2",
            params![account_id, folder_id],
            |r| r.get(0),
        )?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    /// Whether anything is stored for the folder (through the `(account, folder, uid)` key).
    pub(crate) fn folder_has_messages(&self, account_id: i64, folder_id: i64) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM messages WHERE account_id = ?1 AND folder_id = ?2)",
            params![account_id, folder_id],
            |r| r.get(0),
        )?)
    }

    /// Every stored message of one folder as `(uid, id, flags)`, ascending by UID — the set
    /// [`crate::Engine::reconcile_folder`] holds up against the server's. Server copies of
    /// saved drafts are included: they are rows in `messages` like any other, and when a
    /// re-save replaces one the old UID is gone from the server and the row must go too.
    pub(crate) fn uids_with_ids(&self, folder_id: i64) -> Result<Vec<(u32, i64, Vec<String>)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT uid, id, flags_json FROM messages WHERE folder_id = ?1 ORDER BY uid",
        )?;
        let rows = stmt.query_map(params![folder_id], |r| {
            Ok((
                r.get::<_, i64>(0)? as u32,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (uid, id, flags_json) = row?;
            out.push((
                uid,
                id,
                serde_json::from_str(&flags_json).unwrap_or_default(),
            ));
        }
        Ok(out)
    }

    // ----- messages ---------------------------------------------------------------------

    /// Store a message; `Ok(None)` if `(account, folder, uid)` already exists. (The sync
    /// stores through [`Store::insert_batch`]; this one-message form serves the tests.)
    #[cfg(test)]
    pub(crate) fn insert_message(&mut self, m: &NewMessage) -> Result<Option<i64>> {
        let tx = self.conn.transaction()?;
        let id = insert_in(&tx, &self.vault, m)?;
        tx.commit()?;
        Ok(id)
    }

    /// Store a fetched batch and move the folder's watermarks past it in ONE transaction (one
    /// commit per batch instead of one per message): either all of it is stored with its
    /// marks, or nothing and the marks stay. Entries are `None` for messages already stored.
    pub(crate) fn insert_batch(
        &mut self,
        msgs: &[&NewMessage],
        marks: &FolderRow,
    ) -> Result<Vec<Option<i64>>> {
        let tx = self.conn.transaction()?;
        let mut ids = Vec::with_capacity(msgs.len());
        for m in msgs {
            ids.push(insert_in(&tx, &self.vault, m)?);
        }
        tx.execute(
            "UPDATE folders SET uidvalidity = ?1, last_uid = ?2, floor_uid = ?3 WHERE id = ?4",
            params![
                i64::from(marks.uidvalidity),
                i64::from(marks.last_uid),
                i64::from(marks.floor_uid),
                marks.id
            ],
        )?;
        tx.commit()?;
        Ok(ids)
    }

    /// A message row with its still-wrapped bodies (`text_body`, `html_body`) and snippet.
    fn message_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawMessageRow> {
        let flags: Vec<String> = json_vec(&row.get::<_, String>(13)?);
        let sig_status: String = row.get(17)?;
        let summary = MessageSummary {
            id: row.get(0)?,
            account: row.get(1)?,
            folder: row.get(2)?,
            uid: to_u32(row.get(3)?),
            message_id: row.get(4)?,
            from: Address {
                name: row.get(5)?,
                address: row.get(6)?,
            },
            to: json_vec(&row.get::<_, String>(7)?),
            cc: json_vec(&row.get::<_, String>(8)?),
            subject: row.get(9)?,
            protected_subject: row.get::<_, bool>(10)?,
            date: row.get(11)?,
            received_at: row.get(12)?,
            seen: flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")),
            flags,
            was_encrypted: row.get::<_, bool>(14)?,
            decrypted: row.get::<_, bool>(15)?,
            was_signed: row.get::<_, bool>(16)?,
            signature: SignatureSummary {
                status: sig_state_from_str(&sig_status),
                fingerprint: row.get(18)?,
                signer: row.get(19)?,
                ..Default::default()
            },
            decrypt_error: row.get(20)?,
            raw_size: usize::try_from(row.get::<_, i64>(21)?).unwrap_or(0),
            attachment_count: usize::try_from(row.get::<_, i64>(22)?).unwrap_or(0),
            in_reply_to: json_vec(&row.get::<_, String>(27)?),
            references: json_vec(&row.get::<_, String>(28)?),
            thread_id: row.get(29)?,
            snippet: None,
        };
        Ok((
            MessageRow {
                in_reply_to: summary.in_reply_to.clone(),
                references: summary.references.clone(),
                summary,
                account_id: row.get(23)?,
                folder_id: row.get(24)?,
                text: None,
                html: None,
            },
            row.get::<_, Value>(25)?,
            row.get::<_, Value>(26)?,
            row.get::<_, Value>(30)?,
        ))
    }

    /// The snippet of a row: its stored (sealed) one, else derived from the given bodies. A
    /// value that does not open is logged and left out: it must not cost the whole list.
    fn open_snippet(
        &self,
        id: i64,
        snippet: Value,
        text: Option<&str>,
        html: Option<&str>,
    ) -> Option<String> {
        if matches!(snippet, Value::Null) {
            return snippet_of(text, html);
        }
        match self
            .vault
            .open_opt_text("messages", "snippet", &id.to_string(), snippet)
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(id, "snippet of message {id} left out: {e}");
                None
            }
        }
    }

    /// The summary of a row read with [`SUMMARY_COLUMNS`]: only the snippet is unwrapped
    /// (or, for a row without one, derived from its bodies — which are then opened here).
    fn finish_summary(&self, (m, text, html, snippet): RawMessageRow) -> MessageSummary {
        let id = m.summary.id;
        let mut summary = m.summary;
        summary.snippet = if matches!(snippet, Value::Null) {
            let rid = id.to_string();
            let open =
                |col: &str, v: Value| match self.vault.open_opt_text("messages", col, &rid, v) {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!(id, "body of message {id} left out of its snippet: {e}");
                        None
                    }
                };
            let (t, h) = (open("text_body", text), open("html_body", html));
            snippet_of(t.as_deref(), h.as_deref())
        } else {
            self.open_snippet(id, snippet, None, None)
        };
        summary
    }

    /// Unwrap the bodies (and the snippet) of a row read by [`Store::message_from_row`].
    fn finish_message(&self, (mut m, text, html, snippet): RawMessageRow) -> Result<MessageRow> {
        let rid = m.summary.id.to_string();
        m.text = self
            .vault
            .open_opt_text("messages", "text_body", &rid, text)?;
        m.html = self
            .vault
            .open_opt_text("messages", "html_body", &rid, html)?;
        m.summary.snippet =
            self.open_snippet(m.summary.id, snippet, m.text.as_deref(), m.html.as_deref());
        Ok(m)
    }

    /// Stored messages matching `q` by folder *name* (`q.folder_role` is the engine's business:
    /// see [`Store::list_messages_in_folders`]).
    pub(crate) fn list_messages(&self, q: &ListQuery) -> Result<Vec<MessageSummary>> {
        self.list_messages_where(q, None)
    }

    /// Stored messages in the given `(account id, folder name)` pairs — what a role resolves
    /// to per account (`q.folder` is ignored; `q.account` still applies).
    pub(crate) fn list_messages_in_folders(
        &self,
        q: &ListQuery,
        folders: &[(i64, String)],
    ) -> Result<Vec<MessageSummary>> {
        if folders.is_empty() {
            return Ok(Vec::new());
        }
        self.list_messages_where(q, Some(folders))
    }

    fn list_messages_where(
        &self,
        q: &ListQuery,
        folders: Option<&[(i64, String)]>,
    ) -> Result<Vec<MessageSummary>> {
        let limit = if q.limit == 0 { 50 } else { q.limit };
        // 1. The folders in scope: a handful of rows, filtered exactly as before.
        let mut sql = String::from(
            "SELECT f.id FROM folders f JOIN accounts a ON a.id = f.account_id WHERE 1 = 1",
        );
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(acct) = &q.account {
            sql.push_str(" AND a.email = ? COLLATE NOCASE");
            args.push(Box::new(acct.trim().to_string()));
        }
        match folders {
            Some(pairs) => {
                let clauses: Vec<&str> = pairs
                    .iter()
                    .map(|_| "(f.account_id = ? AND f.name = ? COLLATE NOCASE)")
                    .collect();
                sql.push_str(" AND (");
                sql.push_str(&clauses.join(" OR "));
                sql.push(')');
                for (account_id, name) in pairs {
                    args.push(Box::new(*account_id));
                    args.push(Box::new(name.clone()));
                }
            }
            None => {
                let folder = q.folder.clone().unwrap_or_else(|| "INBOX".to_string());
                if folder != "*" {
                    sql.push_str(" AND f.name = ? COLLATE NOCASE");
                    args.push(Box::new(folder));
                }
            }
        }
        let folder_ids: Vec<i64> = {
            let mut stmt = self.conn.prepare(&sql)?;
            let params: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
            let rows = stmt.query_map(params.as_slice(), |r| r.get::<_, i64>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        // 2. The newest `limit` of each folder through `messages_folder_order`, merged in the
        //    order the single query had: COALESCE(date, received_at) DESC, id DESC.
        let mut top: Vec<(i64, i64)> = Vec::new();
        {
            let mut stmt = self.conn.prepare_cached(LIST_FOLDER_SQL)?;
            let n = i64::try_from(limit).unwrap_or(i64::MAX);
            for fid in folder_ids {
                let rows = stmt.query_map(params![fid, n], |r| Ok((r.get(0)?, r.get(1)?)))?;
                for r in rows {
                    top.push(r?);
                }
            }
        }
        top.sort_unstable_by(|x, y| y.cmp(x));
        top.truncate(limit);
        // 3. Those rows' summaries, in that order. Listing never unwraps bodies.
        let ids: Vec<i64> = top.iter().map(|t| t.1).collect();
        let mut by_id: HashMap<i64, MessageSummary> = self
            .summaries_by_ids(&ids)?
            .into_iter()
            .map(|m| (m.id, m))
            .collect();
        Ok(ids.iter().filter_map(|id| by_id.remove(id)).collect())
    }

    pub(crate) fn message(&self, id: i64) -> Result<MessageRow> {
        let sql =
            format!("SELECT {MESSAGE_COLUMNS} {MESSAGE_FROM} {MESSAGE_BLOBS_JOIN} WHERE m.id = ?1");
        let r = self
            .conn
            .query_row(&sql, params![id], Self::message_from_row)
            .optional()?
            .ok_or(Error::MessageNotFound(id))?;
        self.finish_message(r)
    }

    pub(crate) fn message_by_message_id(&self, mid: &str) -> Result<Option<MessageRow>> {
        let sql = format!(
            "SELECT {MESSAGE_COLUMNS} {MESSAGE_FROM} {MESSAGE_BLOBS_JOIN} \
             WHERE m.message_id = ?1 ORDER BY m.id DESC LIMIT 1"
        );
        self.conn
            .query_row(&sql, params![mid.trim()], Self::message_from_row)
            .optional()?
            .map(|r| self.finish_message(r))
            .transpose()
    }

    pub(crate) fn message_detail(&self, id: i64) -> Result<MessageDetail> {
        let row = self.message(id)?;
        let attachments = self.attachments(id)?;
        Ok(MessageDetail {
            summary: row.summary,
            text: row.text,
            html: row.html,
            attachments,
            in_reply_to: row.in_reply_to,
            references: row.references,
        })
    }

    pub(crate) fn message_raw(&self, id: i64) -> Result<Vec<u8>> {
        let v = self
            .conn
            .query_row(
                "SELECT raw FROM message_blobs WHERE message_id = ?1",
                params![id],
                |r| r.get::<_, Value>(0),
            )
            .optional()?
            .ok_or(Error::MessageNotFound(id))?;
        // AAD `messages:raw:<id>`, the column the blob moved from (`vault::WRAPPED`).
        self.vault.open_blob("messages", "raw", &id.to_string(), v)
    }

    pub(crate) fn attachments(&self, message_id: i64) -> Result<Vec<AttachmentInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT idx, filename, content_type, size, content_id FROM attachments \
             WHERE message_id = ?1 ORDER BY idx",
        )?;
        let rows = stmt.query_map(params![message_id], attachment_info_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub(crate) fn attachment(
        &self,
        message_id: i64,
        index: usize,
    ) -> Result<(AttachmentInfo, Vec<u8>)> {
        let (info, aid, data) = self
            .conn
            .query_row(
                "SELECT idx, filename, content_type, size, content_id, id, data FROM attachments \
                 WHERE message_id = ?1 AND idx = ?2",
                params![message_id, index as i64],
                |r| {
                    Ok((
                        attachment_info_from_row(r)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, Value>(6)?,
                    ))
                },
            )
            .optional()?
            .ok_or(Error::AttachmentNotFound {
                message: message_id,
                index,
            })?;
        let data = self
            .vault
            .open_blob("attachments", "data", &aid.to_string(), data)?;
        Ok((info, data))
    }

    pub(crate) fn update_flags(&self, id: i64, flags: &[String]) -> Result<()> {
        self.conn.execute(
            "UPDATE messages SET flags_json = ?1 WHERE id = ?2",
            params![serde_json::to_string(flags)?, id],
        )?;
        Ok(())
    }

    pub(crate) fn delete_message(&self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM messages WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ----- outbox -----------------------------------------------------------------------

    pub(crate) fn insert_outbox(&self, o: &NewOutbox<'_>) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO outbox (account_id, message_id, recipients_json, subject, mode, state, \
             error, sent_copy_appended, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                o.account_id,
                o.message_id,
                serde_json::to_string(o.recipients)?,
                o.subject,
                o.mode,
                o.state,
                o.error,
                o.sent_copy_appended,
                now()
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    // ----- search (search.rs) -----------------------------------------------------------

    /// Summaries of the messages with these ids, in no particular order (unknown ids are
    /// skipped). Bodies are never unwrapped (except to derive the snippet of a row stored
    /// before snippets existed).
    pub(crate) fn summaries_by_ids(&self, ids: &[i64]) -> Result<Vec<MessageSummary>> {
        let mut out = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(500) {
            let marks = vec!["?"; chunk.len()].join(", ");
            let sql = format!("SELECT {SUMMARY_COLUMNS} {MESSAGE_FROM} WHERE m.id IN ({marks})");
            let mut stmt = self.conn.prepare(&sql)?;
            let rows = stmt.query_map(
                rusqlite::params_from_iter(chunk.iter()),
                Self::message_from_row,
            )?;
            for r in rows {
                out.push(self.finish_summary(r?));
            }
        }
        Ok(out)
    }
}

/// Best effort `chmod 0600` of the database (and its WAL/SHM side files when present).
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let p = if suffix.is_empty() {
                path.to_path_buf()
            } else {
                let mut s = path.as_os_str().to_owned();
                s.push(suffix);
                std::path::PathBuf::from(s)
            };
            if p.exists() {
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(host: &str, port: u16, sec: Security) -> Endpoint {
        Endpoint::new(host, port, sec)
    }

    fn add_account(store: &Store, email: &str) -> i64 {
        store
            .insert_account(&NewAccount {
                email,
                display_name: "Test",
                imap: &endpoint("127.0.0.1", 3143, Security::Plain),
                smtp: &endpoint("127.0.0.1", 3025, Security::StartTls),
                auth_kind: AuthKind::Password,
                login: "test",
                credential: "pw",
            })
            .unwrap()
    }

    fn sample_message(account_id: i64, folder_id: i64, uid: u32) -> NewMessage {
        NewMessage {
            account_id,
            folder_id,
            uid,
            message_id: Some(format!("m{uid}@example.org")),
            from: Address {
                name: Some("Bob".into()),
                address: "bob@example.org".into(),
            },
            to: vec![Address {
                name: None,
                address: "alice@example.org".into(),
            }],
            cc: vec![],
            subject: Some("Protected subject".into()),
            protected_subject: true,
            date: Some(1_700_000_000 + i64::from(uid)),
            received_at: 1_700_000_100,
            flags: vec!["\\Seen".into()],
            was_encrypted: true,
            decrypted: true,
            was_signed: true,
            signature: SignatureSummary {
                status: SigState::Good,
                fingerprint: Some("ABCD".into()),
                signer: Some("bob@example.org".into()),
                ..Default::default()
            },
            signatures_json: "[]".into(),
            text: Some("hello".into()),
            html: None,
            in_reply_to: vec!["root@example.org".into()],
            references: vec!["root@example.org".into()],
            decrypt_error: None,
            raw: b"raw bytes".to_vec(),
            attachments: vec![NewAttachment {
                filename: "a.bin".into(),
                content_type: "application/octet-stream".into(),
                data: vec![1, 2, 3],
                content_id: None,
            }],
        }
    }

    #[test]
    fn attachment_content_id_roundtrip() {
        // keyed, so the sealed `data` path is the one under test
        let mut store = Store::open_in_memory_keyed(&[7u8; 32]).unwrap();
        let acct = add_account(&store, "alice@example.org");
        let folder = store.folder(acct, "INBOX").unwrap();
        let mut m = sample_message(acct, folder.id, 3);
        m.html = Some("<p>hi <img src=\"cid:logo@x\"></p>".into());
        m.attachments.push(NewAttachment {
            filename: "logo.png".into(),
            content_type: "image/png".into(),
            data: vec![0x89, b'P', b'N', b'G'],
            content_id: Some("logo@x".into()),
        });
        let id = store.insert_message(&m).unwrap().unwrap();
        let list = store.attachments(id).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].content_id, None, "a part without a Content-ID");
        assert_eq!(list[1].content_id.as_deref(), Some("logo@x"));
        assert_eq!(list[1].filename, "logo.png");
        assert_eq!(list[1].size, 4);
        let (info, data) = store.attachment(id, 1).unwrap();
        assert_eq!(info, list[1]);
        assert_eq!(data, vec![0x89, b'P', b'N', b'G']);
        let d = store.message_detail(id).unwrap();
        assert_eq!(d.attachments, list);
        assert_eq!(d.inline_part("cid:logo@x").map(|a| a.index), Some(1));
        assert_eq!(d.inline_part("cid:other@x"), None);
    }

    #[test]
    fn a_parsed_content_id_is_stored_without_brackets_or_controls() {
        let part = |cid: Option<&str>| {
            NewAttachment::from(sealbox_mail::mime::Attachment {
                filename: "a.png".into(),
                content_type: "image/png".into(),
                data: vec![1],
                content_id: cid.map(str::to_owned),
            })
            .content_id
        };
        assert_eq!(part(Some("logo@x")).as_deref(), Some("logo@x"));
        assert_eq!(part(Some(" <logo@x> ")).as_deref(), Some("logo@x"));
        assert_eq!(
            part(Some("lo\u{1b}[2Jgo@x\r\n")).as_deref(),
            Some("lo[2Jgo@x"),
            "the CLI prints it to a terminal"
        );
        assert_eq!(part(Some("<>")), None);
        assert_eq!(part(Some(" \u{7} ")), None);
        assert_eq!(part(None), None);
    }

    #[test]
    fn an_attachments_table_without_content_id_is_migrated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        // A profile of the previous version: the same schema without `attachments.content_id`,
        // and one attachment row the way that version wrote it.
        let old_schema = SCHEMA.replace("    content_id   TEXT,\n", "");
        assert_ne!(old_schema, SCHEMA, "the fixture really drops the column");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&old_schema).unwrap();
            // (the row's message is not needed to read it back: no foreign-key check here)
            conn.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
            conn.execute(
                "INSERT INTO attachments (id, message_id, idx, filename, content_type, size, data) \
                 VALUES (1, 7, 0, 'old.png', 'image/png', 3, x'010203')",
                [],
            )
            .unwrap();
        }
        let has_column = |store: &Store| {
            let mut stmt = store
                .conn
                .prepare("PRAGMA table_info(attachments)")
                .unwrap();
            let names: Vec<String> = stmt
                .query_map([], |r| r.get::<_, String>(1))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            names.iter().filter(|n| *n == "content_id").count()
        };
        let store = Store::open(&path).unwrap();
        assert_eq!(has_column(&store), 1);
        assert_eq!(
            store.attachments(7).unwrap(),
            vec![AttachmentInfo {
                index: 0,
                filename: "old.png".into(),
                content_type: "image/png".into(),
                size: 3,
                content_id: None,
            }],
            "the old row reads back, without a Content-ID"
        );
        assert_eq!(store.attachment(7, 0).unwrap().1, vec![1, 2, 3]);
        drop(store);
        // opening again is a no-op, and new rows carry their Content-ID
        let mut store = Store::open(&path).unwrap();
        assert_eq!(has_column(&store), 1);
        let acct = add_account(&store, "alice@example.org");
        let folder = store.folder(acct, "INBOX").unwrap();
        let mut m = sample_message(acct, folder.id, 1);
        m.attachments[0].content_id = Some("new@x".into());
        let id = store.insert_message(&m).unwrap().unwrap();
        assert_eq!(
            store.attachments(id).unwrap()[0].content_id.as_deref(),
            Some("new@x")
        );
    }

    #[test]
    fn account_and_identity_roundtrip() {
        let store = Store::open_in_memory().unwrap();
        let id = add_account(&store, "Alice@Example.org");
        let a = store
            .account_by_email("alice@example.org")
            .unwrap()
            .unwrap();
        assert_eq!(a.id, id);
        assert_eq!(a.imap.port, 3143);
        assert_eq!(a.smtp.security, Security::StartTls);
        assert!(matches!(a.mail_auth(), Auth::Password { ref user, .. } if user == "test"));
        assert!(matches!(
            store.insert_account(&NewAccount {
                email: "alice@example.org",
                display_name: "",
                imap: &a.imap,
                smtp: &a.smtp,
                auth_kind: AuthKind::Password,
                login: "x",
                credential: "y",
            }),
            Err(Error::AccountExists(_))
        ));
        store
            .insert_identity(id, "FPR1", "alice@example.org", "secret", "public")
            .unwrap();
        let ids = store.identities_for_account(id).unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].fingerprint, "FPR1");
        assert_eq!(
            store
                .identity_by_email("ALICE@example.org")
                .unwrap()
                .unwrap()
                .secret_armored,
            "secret"
        );
        store.delete_account(id).unwrap();
        assert!(store.account_by_id(id).unwrap().is_none());
        assert!(store.identities_for_account(id).unwrap().is_empty());
    }

    #[test]
    fn peer_and_key_roundtrip() {
        let store = Store::open_in_memory().unwrap();
        let mut p = PeerState::new("Bob@Example.org");
        p.last_seen = Some(chrono::Utc::now());
        store.save_peer(&p).unwrap();
        let back = store.peer("bob@example.org").unwrap().unwrap();
        assert_eq!(back, p);
        assert_eq!(store.all_peers().unwrap().len(), 1);
        store
            .upsert_key("bob@example.org", KeySource::Imported, "FP", "armor")
            .unwrap();
        store
            .upsert_key("bob@example.org", KeySource::Imported, "FP2", "armor2")
            .unwrap();
        let keys = store.keys_for("BOB@example.org").unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].fingerprint, "FP2");
        assert_eq!(keys[0].source, KeySource::Imported);
    }

    #[test]
    fn folder_message_attachment_roundtrip() {
        let mut store = Store::open_in_memory().unwrap();
        let acct = add_account(&store, "alice@example.org");
        let folder = store.folder(acct, "INBOX").unwrap();
        assert_eq!(folder.last_uid, 0);
        store.update_folder(folder.id, 42, 7).unwrap();
        let folder = store.folder(acct, "INBOX").unwrap();
        assert_eq!((folder.uidvalidity, folder.last_uid), (42, 7));

        let id = store
            .insert_message(&sample_message(acct, folder.id, 8))
            .unwrap()
            .unwrap();
        assert!(store
            .insert_message(&sample_message(acct, folder.id, 8))
            .unwrap()
            .is_none());
        let d = store.message_detail(id).unwrap();
        assert_eq!(d.summary.subject.as_deref(), Some("Protected subject"));
        assert!(d.summary.protected_subject);
        assert!(d.summary.seen);
        assert!(d.summary.was_encrypted && d.summary.decrypted);
        assert_eq!(d.summary.signature.status, SigState::Good);
        assert_eq!(d.summary.signature.fingerprint.as_deref(), Some("ABCD"));
        assert_eq!(d.summary.attachment_count, 1);
        assert_eq!(d.summary.raw_size, 9);
        assert_eq!(d.text.as_deref(), Some("hello"));
        assert_eq!(d.in_reply_to, vec!["root@example.org".to_string()]);
        assert_eq!(d.attachments[0].filename, "a.bin");
        let (info, data) = store.attachment(id, 0).unwrap();
        assert_eq!(info.size, 3);
        assert_eq!(data, vec![1, 2, 3]);
        assert!(matches!(
            store.attachment(id, 1),
            Err(Error::AttachmentNotFound { .. })
        ));
        assert_eq!(store.message_raw(id).unwrap(), b"raw bytes");
        assert_eq!(
            store
                .message_by_message_id("m8@example.org")
                .unwrap()
                .unwrap()
                .summary
                .id,
            id
        );

        let list = store
            .list_messages(&ListQuery {
                account: None,
                folder: None,
                folder_role: None,
                limit: 10,
            })
            .unwrap();
        assert_eq!(list.len(), 1);
        assert!(store
            .list_messages(&ListQuery {
                account: Some("nobody@example.org".into()),
                folder: None,
                folder_role: None,
                limit: 10,
            })
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .list_messages(&ListQuery {
                    account: None,
                    folder: Some("*".into()),
                    folder_role: None,
                    limit: 0,
                })
                .unwrap()
                .len(),
            1
        );

        store
            .update_flags(id, &["\\Seen".into(), "\\Flagged".into()])
            .unwrap();
        assert_eq!(store.message(id).unwrap().summary.flags.len(), 2);

        // UIDVALIDITY reset forgets the messages
        store.set_folder_marks(folder.id, 42, 7, 3).unwrap();
        assert!(store.folder(acct, "INBOX").unwrap().more_to_backfill());
        assert!(store.folder_has_messages(acct, folder.id).unwrap());
        store.reset_folder(folder.id, 43).unwrap();
        assert!(matches!(store.message(id), Err(Error::MessageNotFound(_))));
        let folder = store.folder(acct, "INBOX").unwrap();
        assert_eq!(
            (folder.uidvalidity, folder.last_uid, folder.floor_uid),
            (43, 0, 0),
            "a reset clears the backfill floor too"
        );
        assert!(!store.folder_has_messages(acct, folder.id).unwrap());

        store
            .insert_outbox(&NewOutbox {
                account_id: acct,
                message_id: "x@y",
                recipients: &["bob@example.org".into()],
                subject: "s",
                mode: "encrypted",
                state: "sent",
                error: None,
                sent_copy_appended: true,
            })
            .unwrap();
    }

    /// A plain message with explicit threading headers.
    fn threaded(
        account_id: i64,
        folder_id: i64,
        uid: u32,
        mid: Option<&str>,
        in_reply_to: &[&str],
        refs: &[&str],
    ) -> NewMessage {
        let mut m = sample_message(account_id, folder_id, uid);
        m.message_id = mid.map(str::to_owned);
        m.in_reply_to = in_reply_to.iter().map(|s| s.to_string()).collect();
        m.references = refs.iter().map(|s| s.to_string()).collect();
        m.attachments.clear();
        m
    }

    fn thread_of(store: &Store, id: i64) -> String {
        store.message(id).unwrap().summary.thread_id
    }

    #[test]
    fn threads_follow_references_and_relink_late_parents() {
        let mut store = Store::open_in_memory().unwrap();
        let acct = add_account(&store, "alice@example.org");
        let inbox = store.folder(acct, "INBOX").unwrap().id;
        let sent = store.folder(acct, "Sent").unwrap().id;
        let ins = |store: &mut Store, m: NewMessage| store.insert_message(&m).unwrap().unwrap();

        // A three-message chain, in order: A ← B (reply, in Sent) ← C.
        let a = ins(&mut store, threaded(acct, inbox, 1, Some("a@x"), &[], &[]));
        let b = ins(
            &mut store,
            threaded(acct, sent, 1, Some("b@x"), &["a@x"], &["a@x"]),
        );
        let c = ins(
            &mut store,
            threaded(acct, inbox, 2, Some("c@x"), &["b@x"], &["a@x", "b@x"]),
        );
        assert_eq!(thread_of(&store, a), "a@x");
        assert_eq!(thread_of(&store, b), "a@x");
        assert_eq!(thread_of(&store, c), "a@x");
        // The summary carries the headers too.
        let cs = store.message(c).unwrap().summary;
        assert_eq!(cs.in_reply_to, vec!["b@x".to_string()]);
        assert_eq!(cs.references, vec!["a@x".to_string(), "b@x".to_string()]);

        // Unrelated mail gets its own thread; no Message-ID at all → synthetic.
        let d = ins(&mut store, threaded(acct, inbox, 3, Some("d@x"), &[], &[]));
        assert_eq!(thread_of(&store, d), "d@x");
        let anon = ins(&mut store, threaded(acct, inbox, 4, None, &[], &[]));
        assert_eq!(thread_of(&store, anon), format!("sbx-thread:{anon}"));

        // Replies arrive before their parent P: the first forms a thread of its own, the
        // sibling joins it (same unknown parent), and P pulls both into its thread.
        let r1 = ins(
            &mut store,
            threaded(acct, inbox, 5, Some("r1@x"), &["p@x"], &["p@x"]),
        );
        let r2 = ins(
            &mut store,
            threaded(acct, inbox, 6, Some("r2@x"), &["p@x"], &["p@x"]),
        );
        assert_eq!(thread_of(&store, r1), "r1@x");
        assert_eq!(
            thread_of(&store, r2),
            "r1@x",
            "siblings of a missing parent share a thread"
        );
        let p = ins(&mut store, threaded(acct, inbox, 7, Some("p@x"), &[], &[]));
        assert_eq!(thread_of(&store, p), "p@x");
        assert_eq!(
            thread_of(&store, r1),
            "p@x",
            "late parent re-links its replies"
        );
        assert_eq!(thread_of(&store, r2), "p@x");
        // A grandchild referencing only the (now stored) root walks to it.
        let g = ins(
            &mut store,
            threaded(acct, inbox, 8, Some("g@x"), &["r2@x"], &["p@x", "r2@x"]),
        );
        assert_eq!(thread_of(&store, g), "p@x");

        // Threads are per account: the same Message-ID elsewhere does not merge.
        let other = add_account(&store, "bob@example.org");
        let other_inbox = store.folder(other, "INBOX").unwrap().id;
        let o = ins(
            &mut store,
            threaded(other, other_inbox, 1, Some("o@x"), &["a@x"], &["a@x"]),
        );
        assert_eq!(thread_of(&store, o), "o@x");
        assert_eq!(thread_of(&store, a), "a@x");

        // Role listing: pairs of (account, folder).
        let rows = store
            .list_messages_in_folders(
                &ListQuery {
                    limit: 50,
                    ..Default::default()
                },
                &[(acct, "Sent".into())],
            )
            .unwrap();
        assert_eq!(rows.iter().map(|m| m.id).collect::<Vec<_>>(), vec![b]);
        assert!(store
            .list_messages_in_folders(&ListQuery::default(), &[])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn thread_backfill_recomputes_rows_without_a_thread() {
        let mut store = Store::open_in_memory().unwrap();
        let acct = add_account(&store, "alice@example.org");
        let inbox = store.folder(acct, "INBOX").unwrap().id;
        let mut ids = Vec::new();
        for (uid, (mid, irt, refs)) in [
            ("a@x", vec![], vec![]),
            ("b@x", vec!["a@x"], vec!["a@x"]),
            ("r1@x", vec!["p@x"], vec!["p@x"]),
            ("p@x", vec![], vec![]),
            ("c@x", vec!["b@x"], vec!["a@x", "b@x"]),
        ]
        .into_iter()
        .enumerate()
        {
            let mut m = threaded(acct, inbox, uid as u32 + 1, Some(mid), &irt, &refs);
            m.date = Some(1_700_000_000 + uid as i64 * 60);
            ids.push(store.insert_message(&m).unwrap().unwrap());
        }
        // Simulate a profile written by a build without the column.
        store
            .conn()
            .execute("UPDATE messages SET thread_id = ''", [])
            .unwrap();
        assert_eq!(thread_of(&store, ids[0]), "");
        migrate_threads(store.conn()).unwrap();
        assert_eq!(thread_of(&store, ids[0]), "a@x");
        assert_eq!(thread_of(&store, ids[1]), "a@x");
        assert_eq!(thread_of(&store, ids[4]), "a@x");
        assert_eq!(thread_of(&store, ids[2]), "p@x");
        assert_eq!(thread_of(&store, ids[3]), "p@x");
        // Idempotent.
        migrate_threads(store.conn()).unwrap();
        assert_eq!(thread_of(&store, ids[2]), "p@x");
    }

    /// VM steps the two threading lookups ran since the last call (counters reset), and the
    /// rows they visited in full-table scans.
    fn threading_work(store: &Store) -> (i64, i64) {
        use rusqlite::StatementStatus::{FullscanStep, VmStep};
        let mut vm = 0i64;
        let mut scans = 0i64;
        for sql in [THREADS_REFERENCING_SQL, THREADS_OF_MESSAGE_SQL] {
            let stmt = store.conn().prepare_cached(sql).unwrap();
            vm += i64::from(stmt.reset_status(VmStep));
            scans += i64::from(stmt.reset_status(FullscanStep));
        }
        (vm, scans)
    }

    fn median<T: Copy + Ord>(v: &[T]) -> T {
        let mut s = v.to_vec();
        s.sort_unstable();
        s[s.len() / 2]
    }

    /// Threading is O(log n) per insert: over 2,000 messages (30 % replies whose References
    /// carry the parent's chain, like real mail) the lookups never scan the table, and the
    /// last 100 inserts cost no more than twice the first 100 — in SQLite VM steps
    /// (deterministic) and in wall time (the median, so one noisy neighbour does not decide).
    #[test]
    fn threading_cost_per_insert_stays_flat() {
        let mut store = Store::open_in_memory().unwrap();
        let acct = add_account(&store, "alice@example.org");
        let inbox = store.folder(acct, "INBOX").unwrap().id;
        const N: usize = 2000;
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut chains: Vec<Vec<String>> = Vec::with_capacity(N);
        let (mut wall, mut vm) = (Vec::with_capacity(N), Vec::with_capacity(N));
        let mut scanned = 0i64;
        threading_work(&store);
        for i in 0..N {
            let mut m = threaded(acct, inbox, i as u32 + 1, None, &[], &[]);
            m.message_id = Some(format!("m{i}@perf.example"));
            let refs = if i > 0 && rnd() % 10 < 3 {
                let p = (rnd() % i as u64) as usize;
                let mut r = chains[p].clone();
                r.push(format!("m{p}@perf.example"));
                let skip = r.len().saturating_sub(10);
                m.in_reply_to = vec![format!("m{p}@perf.example")];
                r.split_off(skip)
            } else {
                Vec::new()
            };
            m.references = refs.clone();
            chains.push(refs);
            let t = std::time::Instant::now();
            store.insert_message(&m).unwrap().unwrap();
            wall.push(t.elapsed());
            let (steps, scans) = threading_work(&store);
            vm.push(steps);
            scanned += scans;
        }
        assert_eq!(scanned, 0, "a threading lookup scanned the messages table");
        let (vm_first, vm_last) = (median(&vm[..100]), median(&vm[N - 100..]));
        assert!(
            vm_last <= 2 * vm_first.max(1),
            "threading VM steps grew with the table: first 100 {vm_first}, last 100 {vm_last}"
        );
        let (t_first, t_last) = (median(&wall[..100]), median(&wall[N - 100..]));
        assert!(
            t_last <= 2 * t_first,
            "insert got slower with the table: first 100 {t_first:?}, last 100 {t_last:?}"
        );
    }

    fn listed(store: &Store, q: ListQuery) -> Vec<MessageSummary> {
        store.list_messages(&q).unwrap()
    }

    /// The list snippet: computed at insert from the text body (else the HTML stripped to
    /// text — never markup), whitespace collapsed, at most 160 characters; sealed at rest like
    /// the bodies; on every summary (list, search, detail). Rows stored before the column
    /// existed get the same snippet from their bodies on read.
    #[test]
    fn snippets_are_computed_at_insert_sealed_and_listed() {
        let mut store = Store::open_in_memory_keyed(&[7u8; 32]).unwrap();
        let acct = add_account(&store, "alice@example.org");
        let inbox = store.folder(acct, "INBOX").unwrap().id;
        let mut put = |uid: u32, text: Option<&str>, html: Option<&str>| {
            let mut m = threaded(acct, inbox, uid, Some(&format!("s{uid}@x")), &[], &[]);
            m.text = text.map(str::to_owned);
            m.html = html.map(str::to_owned);
            m.date = Some(1_700_000_000 + i64::from(uid));
            store.insert_message(&m).unwrap().unwrap()
        };
        let plain = put(1, Some("  Hello  there,\r\n\r\nsee you\tat ten.\n"), None);
        let html_only = put(
            2,
            None,
            Some(
                "<!DOCTYPE html><html><head><style>p { color: red }</style>\
                 <title>t</title></head><body><p>Weekly <b>digest</b></p>\
                 <script>alert(1)</script><p>number 7</p></body></html>",
            ),
        );
        let empty = put(3, Some("   \n "), None);
        let long_text = "ünïcödé ".repeat(40);
        let long = put(
            4,
            Some(&long_text),
            Some("<p>ignored: there is a text body</p>"),
        );
        let by_id = |rows: &[MessageSummary], id: i64| {
            rows.iter().find(|m| m.id == id).unwrap().snippet.clone()
        };
        let rows = listed(&store, ListQuery::default());
        assert_eq!(
            by_id(&rows, plain).as_deref(),
            Some("Hello there, see you at ten.")
        );
        assert_eq!(
            by_id(&rows, html_only).as_deref(),
            Some("Weekly digest number 7")
        );
        assert_eq!(by_id(&rows, empty), None);
        let s = by_id(&rows, long).unwrap();
        assert_eq!(
            s.chars().count(),
            160 - 1,
            "160 characters, the trailing space trimmed"
        );
        assert!(long_text.starts_with(&s));
        // The detail and search paths carry it too.
        assert_eq!(
            store.message(plain).unwrap().summary.snippet.as_deref(),
            Some("Hello there, see you at ten.")
        );
        assert_eq!(
            store.summaries_by_ids(&[html_only]).unwrap()[0]
                .snippet
                .as_deref(),
            Some("Weekly digest number 7")
        );
        // Sealed on disk, counted by the status.
        assert!(!sql_contains(&store, "messages", "snippet", b"Hello there"));
        assert!(sql_contains(
            &store,
            "messages",
            "snippet",
            crate::vault::MAGIC
        ));
        assert_eq!(crate::vault::count_rows(store.conn()).unwrap().1, 0);
        // A row from before the column: same snippet, from the bodies.
        store
            .conn()
            .execute("UPDATE messages SET snippet = NULL", [])
            .unwrap();
        let rows = listed(&store, ListQuery::default());
        assert_eq!(
            by_id(&rows, plain).as_deref(),
            Some("Hello there, see you at ten.")
        );
        assert_eq!(
            by_id(&rows, html_only).as_deref(),
            Some("Weekly digest number 7")
        );
        // A snippet that does not open (moved from another row) costs the snippet, not the list.
        store
            .conn()
            .execute_batch(&format!(
                "UPDATE messages SET snippet = \
                 (SELECT text_body FROM message_blobs WHERE message_id = {plain}) WHERE id = {long};"
            ))
            .unwrap();
        let rows = listed(&store, ListQuery::default());
        assert_eq!(rows.len(), 4);
        assert_eq!(by_id(&rows, long), None);
    }

    /// The list is served by `messages_folder_order` (no scan, no sort of the whole folder),
    /// merges several folders in date order and breaks ties by id, newest first, exactly as
    /// the old single query did.
    #[test]
    fn listing_uses_the_folder_order_index_and_merges_folders() {
        let mut store = Store::open_in_memory().unwrap();
        let a = add_account(&store, "alice@example.org");
        let b = add_account(&store, "bob@example.org");
        let (ai, bi) = (
            store.folder(a, "INBOX").unwrap().id,
            store.folder(b, "INBOX").unwrap().id,
        );
        let sent = store.folder(a, "Sent").unwrap().id;
        let mut ids = Vec::new();
        for (uid, (folder, acct, date)) in [
            (ai, a, Some(100)),
            (bi, b, Some(300)),
            (ai, a, Some(200)),
            (sent, a, Some(250)),
            (bi, b, None), // no Date: received_at (1_700_000_100) sorts it first
            (ai, a, Some(300)),
        ]
        .into_iter()
        .enumerate()
        {
            let mut m = threaded(acct, folder, uid as u32 + 1, None, &[], &[]);
            m.date = date;
            ids.push(store.insert_message(&m).unwrap().unwrap());
        }
        let order = |q: ListQuery| -> Vec<i64> { listed(&store, q).iter().map(|m| m.id).collect() };
        // Unified INBOX: both accounts; the two 300s tie and the higher id comes first.
        assert_eq!(
            order(ListQuery {
                limit: 4,
                ..ListQuery::default()
            }),
            vec![ids[4], ids[5], ids[1], ids[2]]
        );
        assert_eq!(
            order(ListQuery {
                account: Some("Alice@example.org".into()),
                folder: Some("*".into()),
                limit: 10,
                ..ListQuery::default()
            }),
            vec![ids[5], ids[3], ids[2], ids[0]]
        );
        assert_eq!(
            order(ListQuery {
                account: Some("bob@example.org".into()),
                folder: Some("inbox".into()),
                limit: 1,
                ..ListQuery::default()
            }),
            vec![ids[4]]
        );
        let p = plan(&store, LIST_FOLDER_SQL);
        assert!(
            p.iter().any(|l| l.contains("messages_folder_order"))
                && !p
                    .iter()
                    .any(|l| l.contains("TEMP B-TREE") || l.starts_with("SCAN")),
            "{p:?}"
        );
    }

    /// The signer-key generation moves on exactly the writes a sync context caches: a peer's
    /// key (not a `last_seen` bump), imported/directory keys, identities, accounts.
    #[test]
    fn the_keys_generation_moves_on_key_writes_only() {
        let store = Store::open_in_memory().unwrap();
        let mut g = store.keys_generation().unwrap();
        let mut moved = |store: &Store, what: &str, expect: bool| {
            let now = store.keys_generation().unwrap();
            assert_eq!(now != g, expect, "{what}: generation {g} -> {now}");
            g = now;
        };
        let acct = add_account(&store, "alice@example.org");
        moved(&store, "account added", true);
        store
            .insert_identity(acct, "FPR", "alice@example.org", "secret", "public")
            .unwrap();
        moved(&store, "identity added", true);
        let mut p = PeerState::new("bob@example.org");
        p.last_seen = Some(chrono::Utc::now());
        store.save_peer(&p).unwrap();
        moved(&store, "a peer without a key", false);
        p.public_key = Some(vec![1, 2, 3]);
        store.save_peer(&p).unwrap();
        moved(&store, "the peer's key arrives", true);
        p.last_seen = Some(chrono::Utc::now() + chrono::Duration::seconds(5));
        store.save_peer(&p).unwrap();
        moved(&store, "last_seen bump", false);
        p.gossip_key = Some(vec![9]);
        store.save_peer(&p).unwrap();
        moved(&store, "gossip key", true);
        store
            .upsert_key("carol@example.org", KeySource::Imported, "FP", "armor")
            .unwrap();
        moved(&store, "imported key", true);
        store
            .conn()
            .execute("DELETE FROM peers WHERE addr = 'bob@example.org'", [])
            .unwrap();
        moved(&store, "peer deleted", true);
        let mut m = sample_message(acct, store.folder(acct, "INBOX").unwrap().id, 1);
        m.attachments.clear();
        let mut store = store;
        store.insert_message(&m).unwrap();
        moved(&store, "a message stored", false);
        store.delete_account(acct).unwrap();
        moved(&store, "account (and identity) removed", true);
    }

    /// A batch and its folder marks commit together or not at all.
    #[test]
    fn a_batch_and_its_marks_are_one_transaction() {
        let mut store = Store::open_in_memory().unwrap();
        let acct = add_account(&store, "alice@example.org");
        let folder = store.folder(acct, "INBOX").unwrap();
        let a = threaded(acct, folder.id, 1, Some("a@x"), &[], &[]);
        let b = threaded(acct, folder.id, 2, Some("b@x"), &["a@x"], &["a@x"]);
        let marks = FolderRow {
            uidvalidity: 9,
            last_uid: 2,
            floor_uid: 1,
            ..folder.clone()
        };
        let ids = store.insert_batch(&[&a, &b, &a], &marks).unwrap();
        assert!(ids[0].is_some() && ids[1].is_some());
        assert_eq!(ids[2], None, "already stored, inside the same batch");
        assert_eq!(store.folder(acct, "INBOX").unwrap(), marks);
        assert_eq!(thread_of(&store, ids[1].unwrap()), "a@x");
        // A failing row (no such folder: the FK refuses it) rolls the batch back, marks too.
        let c = threaded(acct, folder.id, 3, Some("c@x"), &[], &[]);
        let mut bad = threaded(acct, folder.id, 4, Some("d@x"), &[], &[]);
        bad.folder_id = 999;
        let later = FolderRow {
            last_uid: 4,
            ..marks.clone()
        };
        assert!(store.insert_batch(&[&c, &bad], &later).is_err());
        assert_eq!(store.folder(acct, "INBOX").unwrap(), marks);
        assert!(store.message_by_message_id("c@x").unwrap().is_none());
        assert!(store.folder_has_messages(acct, folder.id).unwrap());
        assert_eq!(store.folder_message_count(acct, folder.id).unwrap(), 2);
    }

    /// The query plan of `sql` (one line per step).
    fn plan(store: &Store, sql: &str) -> Vec<String> {
        let mut stmt = store
            .conn()
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap();
        let n = stmt.parameter_count();
        let args: Vec<rusqlite::types::Value> = (0..n).map(|_| Value::Integer(0)).collect();
        let rows = stmt
            .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                r.get::<_, String>(3)
            })
            .unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    #[test]
    fn message_refs_are_exact_follow_deletes_and_backfill_legacy_profiles() {
        let mut store = Store::open_in_memory().unwrap();
        let acct = add_account(&store, "alice@example.org");
        let inbox = store.folder(acct, "INBOX").unwrap().id;
        // Both lookups are index searches, never scans.
        for sql in [THREADS_REFERENCING_SQL, THREADS_OF_MESSAGE_SQL] {
            let p = plan(&store, sql);
            assert!(
                p.iter().all(|l| l.starts_with("SEARCH")) && !p.is_empty(),
                "{sql}: {p:?}"
            );
        }
        let ins = |store: &mut Store, m: NewMessage| store.insert_message(&m).unwrap().unwrap();
        // Message-IDs full of `_` and `%` match exactly, never as a pattern or a substring.
        let a = ins(
            &mut store,
            threaded(acct, inbox, 1, Some("a_b%c@x"), &[], &[]),
        );
        let b = ins(
            &mut store,
            threaded(acct, inbox, 2, Some("b@x"), &["a_b%c@x"], &["a_b%c@x"]),
        );
        let near = ins(
            &mut store,
            threaded(acct, inbox, 3, Some("n@x"), &["xa_b%c@x"], &["a_bXc@x"]),
        );
        assert_eq!(thread_of(&store, b), "a_b%c@x");
        assert_eq!(thread_of(&store, near), "n@x");
        let refs = |store: &Store| -> i64 {
            store
                .conn()
                .query_row("SELECT COUNT(*) FROM message_refs", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(refs(&store), 3, "b: one ref (deduplicated), near: two");
        // Deleting a message drops its references with it (FK cascade).
        store.delete_message(near).unwrap();
        assert_eq!(refs(&store), 1);

        // A profile written before the table existed: no refs, no threads. The migration
        // back-fills the references from the JSON columns (once), then the threads.
        let c = ins(
            &mut store,
            threaded(acct, inbox, 4, Some("c@x"), &["b@x"], &["a_b%c@x", "b@x"]),
        );
        store
            .conn()
            .execute_batch(
                "DELETE FROM message_refs; DELETE FROM meta WHERE key = 'message_refs_backfilled'; \
                 UPDATE messages SET thread_id = '';",
            )
            .unwrap();
        migrate_message_refs(store.conn()).unwrap();
        migrate_threads(store.conn()).unwrap();
        assert_eq!(refs(&store), 3);
        for id in [a, b, c] {
            assert_eq!(thread_of(&store, id), "a_b%c@x");
        }
        // Keyed in `meta`: a second run neither scans again nor duplicates.
        store
            .conn()
            .execute(
                "DELETE FROM message_refs WHERE message_row = ?1",
                params![c],
            )
            .unwrap();
        migrate_message_refs(store.conn()).unwrap();
        assert_eq!(refs(&store), 1, "the back-fill ran once only");
    }

    /// A profile from before `message_blobs` (the old `messages` table, the blobs sealed in
    /// the row) is migrated by `Store::open`, without the key: every envelope moved byte for
    /// byte into `message_blobs` (same AAD), readable with the key, the old columns dropped. An
    /// earlier run interrupted after a batch resumes; the next open changes nothing.
    #[test]
    fn legacy_blob_columns_move_to_message_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sealbox.db");
        let master = [9u8; 32];
        let key = crate::vault::derive_data_key(&master).unwrap();
        let n = i64::try_from(2 * BLOB_MIGRATION_BATCH + 3).unwrap(); // three batches
        legacy_blob_db(&path, Some(&key), n).unwrap();
        let envelope = |conn: &Connection, sql: &str, id: i64| -> Vec<u8> {
            conn.query_row(sql, params![id], |r| r.get(0)).unwrap()
        };
        let (raw_before, text_before) = {
            let conn = Connection::open(&path).unwrap();
            // An earlier run stopped after moving message 1 (its batch committed).
            conn.execute_batch(SCHEMA).unwrap();
            conn.execute_batch(
                "INSERT INTO message_blobs SELECT id, text_body, html_body, raw FROM messages \
                 WHERE id = 1; \
                 UPDATE messages SET text_body = NULL, html_body = NULL, raw = X'' WHERE id = 1;",
            )
            .unwrap();
            (
                envelope(&conn, "SELECT raw FROM messages WHERE id = ?1", 2),
                envelope(&conn, "SELECT text_body FROM messages WHERE id = ?1", n),
            )
        };
        assert!(raw_before.starts_with(crate::vault::MAGIC));
        let mut store = Store::open(&path).unwrap(); // plaintext vault: no key needed
        let cols = table_columns(store.conn(), "messages").unwrap();
        for c in ["text_body", "html_body", "raw"] {
            assert!(!cols.iter().any(|x| x == c), "messages.{c} not dropped");
        }
        assert!(cols.iter().any(|x| x == "snippet") && cols.iter().any(|x| x == "raw_size"));
        let blobs: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM message_blobs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(blobs, n);
        let sql_raw = "SELECT raw FROM message_blobs WHERE message_id = ?1";
        let sql_text = "SELECT text_body FROM message_blobs WHERE message_id = ?1";
        assert_eq!(
            envelope(store.conn(), sql_raw, 2),
            raw_before,
            "moved, not resealed"
        );
        assert_eq!(envelope(store.conn(), sql_text, n), text_before);
        // Locked, the bodies stay sealed; with the key every one opens.
        assert!(matches!(store.message(2), Err(Error::ProfileLocked(_))));
        store.set_vault(Vault::with_master(&master).unwrap());
        for id in [1, 2, 3, n / 2, n] {
            let m = store.message(id).unwrap();
            assert_eq!(m.text.as_deref(), Some(format!("body {id}").as_str()));
            let html = (id % 2 == 1).then(|| format!("<p>html {id}</p>"));
            assert_eq!(m.html, html, "message {id}");
            assert_eq!(
                store.message_raw(id).unwrap(),
                format!("raw {id}").into_bytes()
            );
        }
        // Rows from before the snippet column: the list derives it from the moved bodies.
        let rows = store
            .list_messages(&ListQuery {
                limit: 3,
                ..ListQuery::default()
            })
            .unwrap();
        assert_eq!(
            rows[0].snippet.as_deref(),
            Some(format!("body {n}").as_str())
        );
        assert_eq!(crate::vault::count_rows(store.conn()).unwrap().1, 0);
        // Writes after the migration go to the new table.
        let folder = store.folder(1, "INBOX").unwrap();
        let id = store
            .insert_message(&sample_message(1, folder.id, 9_999))
            .unwrap()
            .unwrap();
        assert_eq!(id, n + 1);
        assert_eq!(store.message_raw(id).unwrap(), b"raw bytes");
        drop(store);
        // Idempotent: the next open finds nothing to move.
        let store = Store::open(&path).unwrap();
        let blobs: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM message_blobs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(blobs, n + 1);
        assert_eq!(envelope(store.conn(), sql_raw, 2), raw_before);
    }

    /// Two connections running the blob migration on the same legacy profile at once (the app
    /// next to the CLI, both on WAL like `Store::open`): both succeed, whichever finishes
    /// first, and every blob arrives once. (The other migrations of `Store::open` are not
    /// raced here: two first opens of a legacy profile at once can already fail there, e.g.
    /// `duplicate column name: spam_score` from two `ALTER TABLE … ADD COLUMN`s.)
    #[test]
    fn two_connections_migrating_blobs_at_once_both_succeed() {
        for _ in 0..5 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("sealbox.db");
            let n = i64::try_from(3 * BLOB_MIGRATION_BATCH).unwrap();
            legacy_blob_db(&path, None, n).unwrap();
            {
                let conn = Connection::open(&path).unwrap();
                conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
                conn.execute_batch(SCHEMA).unwrap(); // message_blobs, as Store::open creates it
            }
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let runs: Vec<_> = (0..2)
                .map(|_| {
                    let (path, barrier) = (path.clone(), barrier.clone());
                    std::thread::spawn(move || -> Result<()> {
                        let conn = Connection::open(&path)?;
                        conn.busy_timeout(std::time::Duration::from_secs(10))?;
                        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;")?;
                        barrier.wait();
                        migrate_message_blobs(&conn)
                    })
                })
                .collect();
            for r in runs {
                r.join().unwrap().unwrap();
            }
            let store = Store::open(&path).unwrap();
            let blobs: i64 = store
                .conn()
                .query_row("SELECT COUNT(*) FROM message_blobs", [], |r| r.get(0))
                .unwrap();
            assert_eq!(blobs, n);
            assert!(legacy_blob_columns(store.conn()).unwrap().is_empty());
            for id in [1, n / 2, n] {
                assert_eq!(
                    store.message_raw(id).unwrap(),
                    format!("raw {id}").into_bytes()
                );
            }
        }
    }

    /// Two connections (two threads; the app next to the CLI) open the same legacy keyed
    /// profile at the same moment — the older shapes too: no `spam_*` columns, no
    /// `message_blobs`, no `snippet` / `floor_uid` / `message_refs`, and (second shape) no
    /// `thread_id`, in a file still in rollback-journal mode. Both opens succeed, the profile
    /// ends up exactly migrated, and every sealed body opens with the key.
    #[test]
    fn concurrent_first_opens_of_a_legacy_keyed_profile_both_succeed() {
        let master = [7u8; 32];
        let key = crate::vault::derive_data_key(&master).unwrap();
        let n = i64::try_from(2 * BLOB_MIGRATION_BATCH + 7).unwrap();
        let pre_threads = legacy_pre_threads_schema();
        for (shape, schema) in [
            ("blob-era", LEGACY_BLOB_SCHEMA),
            ("pre-threads", &pre_threads),
        ] {
            for round in 0..4 {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("sealbox.db");
                legacy_db(&path, Some(&key), n, schema).unwrap();
                let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
                let opens: Vec<_> = (0..2)
                    .map(|_| {
                        let (path, barrier) = (path.clone(), barrier.clone());
                        std::thread::spawn(move || {
                            barrier.wait();
                            Store::open(&path).map(drop)
                        })
                    })
                    .collect();
                for o in opens {
                    if let Err(e) = o.join().unwrap() {
                        panic!("{shape} round {round}: an open failed: {e}");
                    }
                }
                let mut store = Store::open(&path).unwrap();
                let c = store.conn();
                let cols = table_columns(c, "messages").unwrap();
                for col in ["thread_id", "snippet", "spam_score", "spam_label"] {
                    assert!(cols.iter().any(|x| x == col), "{shape}: no messages.{col}");
                }
                assert!(legacy_blob_columns(c).unwrap().is_empty(), "{shape}");
                assert_eq!(profile_schema_version(c).unwrap(), Some(SCHEMA_VERSION));
                let one = |sql: &str| -> i64 { c.query_row(sql, [], |r| r.get(0)).unwrap() };
                assert_eq!(one("SELECT COUNT(*) FROM message_blobs"), n, "{shape}");
                assert_eq!(one("SELECT COUNT(*) FROM messages WHERE thread_id = ''"), 0);
                assert_eq!(one("SELECT COUNT(*) FROM folders WHERE floor_uid = 0"), 1);
                store.set_vault(Vault::with_master(&master).unwrap());
                for id in [1, n / 2, n] {
                    let m = store.message(id).unwrap();
                    assert_eq!(m.text.as_deref(), Some(format!("body {id}").as_str()));
                    assert_eq!(
                        store.message_raw(id).unwrap(),
                        format!("raw {id}").into_bytes()
                    );
                }
            }
        }
    }

    /// `meta.schema_version` is a real number: a new profile gets [`SCHEMA_VERSION`], an
    /// older one ('1') is raised to it, and opening a current profile writes nothing at all.
    #[test]
    fn the_schema_version_is_kept_and_a_current_open_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sealbox.db");
        drop(Store::open(&path).unwrap());
        let version = |path: &Path| -> String {
            Connection::open(path)
                .unwrap()
                .query_row(
                    "SELECT value FROM meta WHERE key = 'schema_version'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(version(&path), SCHEMA_VERSION.to_string());
        let bytes = std::fs::read(&path).unwrap();
        drop(Store::open(&path).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "a current open wrote");
        let legacy = dir.path().join("legacy.db");
        legacy_blob_db(&legacy, None, 3).unwrap();
        Connection::open(&legacy)
            .unwrap()
            .execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', '1')",
                [],
            )
            .unwrap();
        drop(Store::open(&legacy).unwrap());
        assert_eq!(version(&legacy), SCHEMA_VERSION.to_string());
    }

    /// A profile written by a newer build (a higher `meta.schema_version`) is refused with
    /// the typed error before anything is written: the file stays byte for byte the same.
    #[test]
    fn a_newer_profile_is_refused_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sealbox.db");
        drop(Store::open(&path).unwrap());
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
                params![(SCHEMA_VERSION + 1).to_string()],
            )
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        let err = Store::open(&path).map(drop).unwrap_err();
        match &err {
            Error::ProfileNewer { profile, engine } => {
                assert_eq!((*profile, *engine), (SCHEMA_VERSION + 1, SCHEMA_VERSION));
            }
            other => panic!("expected ProfileNewer, got {other:?}"),
        }
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("update Sealbox"), "{err}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "the refused open wrote"
        );
        let wal = dir.path().join("sealbox.db-wal");
        assert!(!wal.exists() || std::fs::metadata(&wal).unwrap().len() == 0);
        // A newer profile with a brand-new table of its own is refused the same way.
        let c = Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE from_the_future (x INTEGER);")
            .unwrap();
        drop(c);
        assert!(matches!(
            Store::open(&path).map(drop),
            Err(Error::ProfileNewer { .. })
        ));
    }

    fn sql_contains(store: &Store, table: &str, col: &str, needle: &[u8]) -> bool {
        let mut stmt = store
            .conn()
            .prepare(&format!(
                "SELECT CAST({col} AS BLOB) FROM {table} WHERE {col} IS NOT NULL"
            ))
            .unwrap();
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0)).unwrap();
        let found = rows
            .map(|r| r.unwrap())
            .any(|b| b.windows(needle.len()).any(|w| w == needle));
        found
    }

    #[test]
    fn keyed_store_wraps_and_binds_rows() {
        let mut store = Store::open_in_memory_keyed(&[9u8; 32]).unwrap();
        let acct = add_account(&store, "alice@example.org");
        store
            .insert_identity(
                acct,
                "FPR1",
                "alice@example.org",
                "SECRET-KEY-MATERIAL",
                "public",
            )
            .unwrap();
        let folder = store.folder(acct, "INBOX").unwrap();
        let mut m = sample_message(acct, folder.id, 1);
        m.text = Some("the body text".into());
        m.html = Some("<p>the html</p>".into());
        m.raw = b"From: bob\r\n\r\nraw secret body".to_vec();
        let id1 = store.insert_message(&m).unwrap().unwrap();
        let id2 = store
            .insert_message(&sample_message(acct, folder.id, 2))
            .unwrap()
            .unwrap();
        store
            .set_setting_raw(
                crate::settings::SettingsScope::Account,
                "alice@example.org",
                "secret.token",
                "\"hidden-setting\"",
            )
            .unwrap();
        let gsecret = store
            .vault()
            .seal_text("guest_links", "secret", "<g1@x>", "guest-passphrase-xyz")
            .unwrap();
        store
            .conn()
            .execute(
                "INSERT INTO guest_links (message_id, account_id, guest_id, bare_url, mode, secret, \
                 expires_at, to_addrs, cc_addrs, bcc_addrs, subject, recipients_json, created_at) \
                 VALUES ('<g1@x>', ?1, 'gid', 'u', 'passphrase', ?2, 0, '[]', '[]', '[]', 's', '[]', 0)",
                params![acct, gsecret],
            )
            .unwrap();
        // On disk: envelopes only.
        for (t, c, needle) in [
            ("accounts", "credential", &b"pw"[..]),
            ("identities", "secret_armored", b"SECRET-KEY"),
            ("message_blobs", "text_body", b"the body"),
            ("message_blobs", "html_body", b"the html"),
            ("message_blobs", "raw", b"raw secret"),
            ("attachments", "data", &[1u8, 2, 3][..]),
            ("settings", "value", b"hidden-setting"),
            ("guest_links", "secret", b"guest-passphrase"),
        ] {
            assert!(!sql_contains(&store, t, c, needle), "{t}.{c} leaks");
            assert!(
                sql_contains(&store, t, c, crate::vault::MAGIC),
                "{t}.{c} not wrapped"
            );
        }
        // Subjects / addresses stay queryable.
        assert!(sql_contains(
            &store,
            "messages",
            "subject",
            b"Protected subject"
        ));
        let (wrapped, plain) = crate::vault::count_rows(store.conn()).unwrap();
        assert_eq!(plain, 0);
        assert!(wrapped >= 9, "{wrapped}");
        // API round trip.
        let a = store
            .account_by_email("alice@example.org")
            .unwrap()
            .unwrap();
        assert_eq!(a.credential, "pw");
        assert_eq!(
            store.identities_for_account(acct).unwrap()[0].secret_armored,
            "SECRET-KEY-MATERIAL"
        );
        let d = store.message_detail(id1).unwrap();
        assert_eq!(d.text.as_deref(), Some("the body text"));
        assert_eq!(d.html.as_deref(), Some("<p>the html</p>"));
        assert_eq!(store.message_raw(id1).unwrap(), m.raw);
        assert_eq!(store.attachment(id1, 0).unwrap().1, vec![1, 2, 3]);
        assert_eq!(
            store
                .get_setting_raw(
                    crate::settings::SettingsScope::Account,
                    "Alice@example.org",
                    "secret.token"
                )
                .unwrap()
                .unwrap()
                .0,
            "\"hidden-setting\""
        );
        // The hot row is metadata only: no blob column, no blob bytes.
        let cols = table_columns(store.conn(), "messages").unwrap();
        for c in ["text_body", "html_body", "raw"] {
            assert!(!cols.iter().any(|n| n == c), "messages.{c} is back");
        }
        for needle in [
            &b"the body"[..],
            b"the html",
            b"raw secret",
            crate::vault::MAGIC,
        ] {
            for c in [
                "subject",
                "flags_json",
                "signatures_json",
                "references_json",
            ] {
                assert!(!sql_contains(&store, "messages", c, needle), "messages.{c}");
            }
        }
        // Swapping ciphertexts between rows is detected (raw and bodies alike).
        store
            .conn()
            .execute(
                "UPDATE message_blobs SET raw = (SELECT raw FROM message_blobs WHERE message_id = ?1) \
                 WHERE message_id = ?2",
                params![id1, id2],
            )
            .unwrap();
        assert!(matches!(
            store.message_raw(id2),
            Err(Error::SecretIntegrity(_))
        ));
        store
            .conn()
            .execute(
                "UPDATE message_blobs SET text_body = \
                 (SELECT text_body FROM message_blobs WHERE message_id = ?1) WHERE message_id = ?2",
                params![id1, id2],
            )
            .unwrap();
        assert!(matches!(store.message(id2), Err(Error::SecretIntegrity(_))));
        // ... and between columns.
        store
            .conn()
            .execute(
                "UPDATE message_blobs SET html_body = text_body WHERE message_id = ?1",
                params![id1],
            )
            .unwrap();
        assert!(store.message(id1).is_err());
        // ... and a `messages:` envelope of another column cannot pose as the raw MIME.
        store
            .conn()
            .execute(
                "UPDATE message_blobs SET raw = (SELECT snippet FROM messages WHERE id = ?1) \
                 WHERE message_id = ?1",
                params![id1],
            )
            .unwrap();
        assert!(matches!(
            store.message_raw(id1),
            Err(Error::SecretIntegrity(_))
        ));
        // Deleting the message deletes its blobs (ON DELETE CASCADE).
        store.delete_message(id2).unwrap();
        let blobs: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM message_blobs WHERE message_id = ?1",
                params![id2],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(blobs, 0);
        assert!(matches!(
            store.message_raw(id2),
            Err(Error::MessageNotFound(_))
        ));
        // Listing never needs the bodies (id1's no longer open; id2 is gone).
        assert_eq!(
            store
                .list_messages(&ListQuery {
                    account: None,
                    folder: None,
                    folder_role: None,
                    limit: 10,
                })
                .unwrap()
                .len(),
            1
        );
        // A plaintext row in a keyed profile is refused, not trusted.
        store
            .conn()
            .execute(
                "UPDATE accounts SET credential = 'injected' WHERE id = ?1",
                params![acct],
            )
            .unwrap();
        assert!(matches!(
            store.account_by_id(acct),
            Err(Error::SecretIntegrity(_))
        ));
    }
}
