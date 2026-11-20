//! SQLite persistence (rusqlite, bundled). One connection behind a mutex; every query runs on
//! the blocking pool via [`Db::call`].
//!
//! Tables: `keys`, `emails`, `challenges`, `upload_tokens` (directory), `guest_messages`,
//! `guest_replies` (guest links), `backups`. All tokens are stored as SHA-256 hex.

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("database lock poisoned")]
    Poisoned,
    #[error("database worker stopped: {0}")]
    Join(String),
}

/// Shared handle to the database.
#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS keys (
    fpr         TEXT PRIMARY KEY,
    keytext     TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS emails (
    email        TEXT NOT NULL,
    fpr          TEXT NOT NULL REFERENCES keys(fpr) ON DELETE CASCADE,
    status       TEXT NOT NULL CHECK (status IN ('unpublished','pending','published')),
    published_at INTEGER,
    PRIMARY KEY (email, fpr)
);
CREATE INDEX IF NOT EXISTS emails_by_email ON emails(email, status);
CREATE TABLE IF NOT EXISTS challenges (
    token_hash  TEXT PRIMARY KEY,
    fpr         TEXT NOT NULL,
    email       TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
);
CREATE TABLE IF NOT EXISTS upload_tokens (
    token_hash  TEXT PRIMARY KEY,
    fpr         TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS guest_messages (
    id                TEXT PRIMARY KEY,
    ciphertext        TEXT NOT NULL,
    sender_key        TEXT,
    pickup_token_hash TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS guest_messages_expiry ON guest_messages(expires_at);
CREATE TABLE IF NOT EXISTS guest_replies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id  TEXT NOT NULL REFERENCES guest_messages(id) ON DELETE CASCADE,
    ciphertext  TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS guest_replies_by_message ON guest_replies(message_id);
CREATE TABLE IF NOT EXISTS backups (
    fpr         TEXT PRIMARY KEY,
    blob        BLOB NOT NULL,
    keytext     TEXT NOT NULL,
    token_hash  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
PRAGMA user_version = 1;
"#;

/// G29: e-mail-code gates on guest messages and the short-lived access tokens they issue.
/// Only hashes are stored: the recipient address is a salted SHA-256, codes and tokens are
/// SHA-256. Rows go with their message (`ON DELETE CASCADE`).
const GUEST_GATE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS guest_gates (
    message_id       TEXT PRIMARY KEY REFERENCES guest_messages(id) ON DELETE CASCADE,
    recipient_hash   TEXT NOT NULL,
    code_hash        TEXT,
    code_expires_at  INTEGER,
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until     INTEGER,
    created_at       INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS guest_access_tokens (
    token_hash  TEXT PRIMARY KEY,
    message_id  TEXT NOT NULL REFERENCES guest_messages(id) ON DELETE CASCADE,
    expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS guest_access_tokens_expiry ON guest_access_tokens(expires_at);
"#;

impl Db {
    /// Open (or create) the database at `path` and migrate the schema.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// A private in-memory database (unit tests, throwaway tooling).
    pub fn open_in_memory() -> Result<Self, DbError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, DbError> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;",
        )?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version < 1 {
            conn.execute_batch(SCHEMA_V1)?;
        }
        conn.execute_batch(GUEST_GATE_SCHEMA)?; // G29, idempotent
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Run `f` with the connection on the blocking thread pool.
    ///
    /// `E` is usually [`DbError`]; a handler may use its own error type (anything
    /// `From<DbError>`) to do validation inside the same critical section.
    pub async fn call<T, E, F>(&self, f: F) -> Result<T, E>
    where
        T: Send + 'static,
        E: From<DbError> + Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, E> + Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().map_err(|_| E::from(DbError::Poisoned))?;
            f(&mut guard)
        })
        .await
        .map_err(|e| E::from(DbError::Join(e.to_string())))?
    }
}

// ---------------------------------------------------------------------------------------------
// Key directory
// ---------------------------------------------------------------------------------------------

/// Publication status of one e-mail address on one key (VKS vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailStatus {
    Unpublished,
    Pending,
    Published,
}

impl EmailStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            EmailStatus::Unpublished => "unpublished",
            EmailStatus::Pending => "pending",
            EmailStatus::Published => "published",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "published" => EmailStatus::Published,
            "pending" => EmailStatus::Pending,
            _ => EmailStatus::Unpublished,
        }
    }
}

/// Insert or replace a key and reconcile its address rows: new addresses start `unpublished`,
/// existing ones keep their status, addresses no longer in the key are dropped.
pub fn upsert_key(
    conn: &mut Connection,
    fpr: &str,
    keytext: &str,
    emails: &[String],
    now: i64,
) -> Result<(), DbError> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO keys (fpr, keytext, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)
         ON CONFLICT(fpr) DO UPDATE SET keytext = excluded.keytext, updated_at = excluded.updated_at",
        params![fpr, keytext, now],
    )?;
    for email in emails {
        tx.execute(
            "INSERT OR IGNORE INTO emails (email, fpr, status) VALUES (?1, ?2, 'unpublished')",
            params![email, fpr],
        )?;
    }
    // Remove addresses that disappeared from the key.
    let placeholders = std::iter::repeat_n("?", emails.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = if emails.is_empty() {
        "DELETE FROM emails WHERE fpr = ?1".to_owned()
    } else {
        format!("DELETE FROM emails WHERE fpr = ?1 AND email NOT IN ({placeholders})")
    };
    let mut p: Vec<&dyn rusqlite::ToSql> = vec![&fpr];
    for e in emails {
        p.push(e);
    }
    tx.execute(&sql, p.as_slice())?;
    tx.commit()?;
    Ok(())
}

/// `(email, status)` rows of a key, in insertion order.
pub fn key_statuses(conn: &Connection, fpr: &str) -> Result<Vec<(String, EmailStatus)>, DbError> {
    let mut stmt =
        conn.prepare("SELECT email, status FROM emails WHERE fpr = ?1 ORDER BY rowid")?;
    let rows = stmt.query_map([fpr], |r| {
        Ok((
            r.get::<_, String>(0)?,
            EmailStatus::parse(&r.get::<_, String>(1)?),
        ))
    })?;
    rows.map(|r| r.map_err(DbError::from)).collect()
}

/// Status of one address on one key, if the key carries it.
pub fn email_status(
    conn: &Connection,
    fpr: &str,
    email: &str,
) -> Result<Option<EmailStatus>, DbError> {
    conn.query_row(
        "SELECT status FROM emails WHERE fpr = ?1 AND email = ?2",
        params![fpr, email],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .map(|s| s.map(|s| EmailStatus::parse(&s)))
    .map_err(DbError::from)
}

pub fn set_email_status(
    conn: &Connection,
    fpr: &str,
    email: &str,
    status: EmailStatus,
    now: i64,
) -> Result<(), DbError> {
    let published_at = (status == EmailStatus::Published).then_some(now);
    conn.execute(
        "UPDATE emails SET status = ?3, published_at = ?4 WHERE fpr = ?1 AND email = ?2",
        params![fpr, email, status.as_str(), published_at],
    )?;
    Ok(())
}

/// Armored key text by fingerprint (any status).
pub fn key_text(conn: &Connection, fpr: &str) -> Result<Option<String>, DbError> {
    conn.query_row("SELECT keytext FROM keys WHERE fpr = ?1", [fpr], |r| {
        r.get(0)
    })
    .optional()
    .map_err(DbError::from)
}

pub fn insert_upload_token(
    conn: &Connection,
    token_hash: &str,
    fpr: &str,
    now: i64,
    expires_at: i64,
) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO upload_tokens (token_hash, fpr, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![token_hash, fpr, now, expires_at],
    )?;
    Ok(())
}

/// Fingerprint an upload token refers to, if the token is valid and unexpired.
pub fn upload_token_fpr(
    conn: &Connection,
    token_hash: &str,
    now: i64,
) -> Result<Option<String>, DbError> {
    conn.query_row(
        "SELECT fpr FROM upload_tokens WHERE token_hash = ?1 AND expires_at > ?2",
        params![token_hash, now],
        |r| r.get(0),
    )
    .optional()
    .map_err(DbError::from)
}

pub fn insert_challenge(
    conn: &Connection,
    token_hash: &str,
    fpr: &str,
    email: &str,
    now: i64,
    expires_at: i64,
) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO challenges (token_hash, fpr, email, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![token_hash, fpr, email, now, expires_at],
    )?;
    Ok(())
}

/// Consume a challenge: marks the address published on that key and unpublishes it on every
/// other key (an address maps to at most one key). Returns `(fpr, email)` or `None`.
pub fn consume_challenge(
    conn: &mut Connection,
    token_hash: &str,
    now: i64,
) -> Result<Option<(String, String)>, DbError> {
    let tx = conn.transaction()?;
    let found: Option<(String, String)> = tx
        .query_row(
            "SELECT fpr, email FROM challenges
             WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
            params![token_hash, now],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((fpr, email)) = found else {
        return Ok(None);
    };
    tx.execute(
        "UPDATE challenges SET used_at = ?2 WHERE token_hash = ?1",
        params![token_hash, now],
    )?;
    tx.execute(
        "UPDATE emails SET status = 'unpublished', published_at = NULL
         WHERE email = ?1 AND fpr <> ?2 AND status = 'published'",
        params![email, fpr],
    )?;
    tx.execute(
        "UPDATE emails SET status = 'published', published_at = ?3 WHERE email = ?1 AND fpr = ?2",
        params![email, fpr, now],
    )?;
    tx.commit()?;
    Ok(Some((fpr, email)))
}

/// Key text of the key on which `email` is published.
pub fn published_key_by_email(
    conn: &Connection,
    email: &str,
) -> Result<Option<(String, String)>, DbError> {
    conn.query_row(
        "SELECT k.fpr, k.keytext FROM emails e JOIN keys k ON k.fpr = e.fpr
         WHERE e.email = ?1 AND e.status = 'published' LIMIT 1",
        [email],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
    .map_err(DbError::from)
}

/// Key text plus its published addresses; `None` if the key is unknown or nothing is published.
pub fn published_key_by_fpr(
    conn: &Connection,
    fpr: &str,
) -> Result<Option<(String, Vec<String>)>, DbError> {
    let Some(keytext) = key_text(conn, fpr)? else {
        return Ok(None);
    };
    let mut stmt = conn.prepare(
        "SELECT email FROM emails WHERE fpr = ?1 AND status = 'published' ORDER BY rowid",
    )?;
    let emails: Vec<String> = stmt
        .query_map([fpr], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    if emails.is_empty() {
        return Ok(None);
    }
    Ok(Some((keytext, emails)))
}

// ---------------------------------------------------------------------------------------------
// Guest messages
// ---------------------------------------------------------------------------------------------

/// A stored guest message (ciphertext only).
#[derive(Debug, Clone)]
pub struct GuestMessage {
    pub id: String,
    pub ciphertext: String,
    pub sender_key: Option<String>,
    pub pickup_token_hash: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct GuestReply {
    pub id: i64,
    pub ciphertext: String,
    pub created_at: i64,
}

pub fn insert_guest(conn: &Connection, m: &GuestMessage) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO guest_messages (id, ciphertext, sender_key, pickup_token_hash, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![m.id, m.ciphertext, m.sender_key, m.pickup_token_hash, m.created_at, m.expires_at],
    )?;
    Ok(())
}

/// A guest message that has not expired as of `now`.
pub fn get_guest(conn: &Connection, id: &str, now: i64) -> Result<Option<GuestMessage>, DbError> {
    conn.query_row(
        "SELECT id, ciphertext, sender_key, pickup_token_hash, created_at, expires_at
         FROM guest_messages WHERE id = ?1 AND expires_at > ?2",
        params![id, now],
        |r| {
            Ok(GuestMessage {
                id: r.get(0)?,
                ciphertext: r.get(1)?,
                sender_key: r.get(2)?,
                pickup_token_hash: r.get(3)?,
                created_at: r.get(4)?,
                expires_at: r.get(5)?,
            })
        },
    )
    .optional()
    .map_err(DbError::from)
}

pub fn count_replies(conn: &Connection, message_id: &str) -> Result<i64, DbError> {
    conn.query_row(
        "SELECT COUNT(*) FROM guest_replies WHERE message_id = ?1",
        [message_id],
        |r| r.get(0),
    )
    .map_err(DbError::from)
}

pub fn insert_reply(
    conn: &Connection,
    message_id: &str,
    ciphertext: &str,
    now: i64,
) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO guest_replies (message_id, ciphertext, created_at) VALUES (?1, ?2, ?3)",
        params![message_id, ciphertext, now],
    )?;
    Ok(())
}

pub fn list_replies(conn: &Connection, message_id: &str) -> Result<Vec<GuestReply>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT id, ciphertext, created_at FROM guest_replies WHERE message_id = ?1 ORDER BY id",
    )?;
    let rows = stmt.query_map([message_id], |r| {
        Ok(GuestReply {
            id: r.get(0)?,
            ciphertext: r.get(1)?,
            created_at: r.get(2)?,
        })
    })?;
    rows.map(|r| r.map_err(DbError::from)).collect()
}

/// Code-gate state of a guest message (G29).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestGate {
    pub message_id: String,
    pub recipient_hash: String,
    pub code_hash: Option<String>,
    pub code_expires_at: Option<i64>,
    pub failed_attempts: i64,
    pub locked_until: Option<i64>,
}

/// Store a message and, when given, its gate in one transaction.
pub fn insert_guest_with_gate(
    conn: &mut Connection,
    m: &GuestMessage,
    recipient_hash: Option<&str>,
) -> Result<(), DbError> {
    let tx = conn.transaction()?;
    insert_guest(&tx, m)?;
    if let Some(h) = recipient_hash {
        tx.execute(
            "INSERT INTO guest_gates (message_id, recipient_hash, created_at) VALUES (?1, ?2, ?3)",
            params![m.id, h, m.created_at],
        )?;
    }
    tx.commit()?;
    Ok(())
}

pub fn get_gate(conn: &Connection, message_id: &str) -> Result<Option<GuestGate>, DbError> {
    conn.query_row(
        "SELECT message_id, recipient_hash, code_hash, code_expires_at, failed_attempts, locked_until
         FROM guest_gates WHERE message_id = ?1",
        [message_id],
        |r| {
            Ok(GuestGate {
                message_id: r.get(0)?,
                recipient_hash: r.get(1)?,
                code_hash: r.get(2)?,
                code_expires_at: r.get(3)?,
                failed_attempts: r.get(4)?,
                locked_until: r.get(5)?,
            })
        },
    )
    .optional()
    .map_err(DbError::from)
}

/// Write back the mutable part of a gate.
pub fn update_gate(conn: &Connection, g: &GuestGate) -> Result<(), DbError> {
    conn.execute(
        "UPDATE guest_gates SET code_hash = ?2, code_expires_at = ?3, failed_attempts = ?4,
             locked_until = ?5 WHERE message_id = ?1",
        params![
            g.message_id,
            g.code_hash,
            g.code_expires_at,
            g.failed_attempts,
            g.locked_until
        ],
    )?;
    Ok(())
}

pub fn insert_access_token(
    conn: &Connection,
    token_hash: &str,
    message_id: &str,
    expires_at: i64,
) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO guest_access_tokens (token_hash, message_id, expires_at) VALUES (?1, ?2, ?3)",
        params![token_hash, message_id, expires_at],
    )?;
    Ok(())
}

/// Is `token_hash` a live access token for `message_id`? (Lookup by primary key; the hash is
/// of a 256-bit random token, so the index lookup leaks nothing useful about timing.)
pub fn access_token_valid(
    conn: &Connection,
    token_hash: &str,
    message_id: &str,
    now: i64,
) -> Result<bool, DbError> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM guest_access_tokens
         WHERE token_hash = ?1 AND message_id = ?2 AND expires_at > ?3",
        params![token_hash, message_id, now],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// What a purge removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub guest_messages: usize,
    pub challenges: usize,
    pub upload_tokens: usize,
}

/// Delete expired guest messages (replies cascade), challenges and upload tokens.
pub fn purge_expired(conn: &Connection, now: i64) -> Result<PurgeReport, DbError> {
    let guest_messages =
        conn.execute("DELETE FROM guest_messages WHERE expires_at <= ?1", [now])?;
    let challenges = conn.execute("DELETE FROM challenges WHERE expires_at <= ?1", [now])?;
    let upload_tokens = conn.execute("DELETE FROM upload_tokens WHERE expires_at <= ?1", [now])?;
    conn.execute(
        "DELETE FROM guest_access_tokens WHERE expires_at <= ?1",
        [now],
    )?;
    Ok(PurgeReport {
        guest_messages,
        challenges,
        upload_tokens,
    })
}

// ---------------------------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Backup {
    pub blob: Vec<u8>,
    pub keytext: String,
    pub token_hash: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub fn get_backup(conn: &Connection, fpr: &str) -> Result<Option<Backup>, DbError> {
    conn.query_row(
        "SELECT blob, keytext, token_hash, created_at, updated_at FROM backups WHERE fpr = ?1",
        [fpr],
        |r| {
            Ok(Backup {
                blob: r.get(0)?,
                keytext: r.get(1)?,
                token_hash: r.get(2)?,
                created_at: r.get(3)?,
                updated_at: r.get(4)?,
            })
        },
    )
    .optional()
    .map_err(DbError::from)
}

/// The key pinned to a backup slot (set on the first PUT), if any.
pub fn backup_key(conn: &Connection, fpr: &str) -> Result<Option<String>, DbError> {
    conn.query_row("SELECT keytext FROM backups WHERE fpr = ?1", [fpr], |r| {
        r.get(0)
    })
    .optional()
    .map_err(DbError::from)
}

pub fn put_backup(
    conn: &Connection,
    fpr: &str,
    blob: &[u8],
    keytext: &str,
    token_hash: &str,
    now: i64,
) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO backups (fpr, blob, keytext, token_hash, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)
         ON CONFLICT(fpr) DO UPDATE SET blob = excluded.blob, keytext = excluded.keytext,
             token_hash = excluded.token_hash, updated_at = excluded.updated_at",
        params![fpr, blob, keytext, token_hash, now],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_and_key_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.conn.lock().unwrap();
        let emails = vec!["a@x.org".to_owned(), "b@x.org".to_owned()];
        upsert_key(&mut conn, "FPR1", "KEY", &emails, 10).unwrap();
        assert_eq!(key_statuses(&conn, "FPR1").unwrap().len(), 2);
        set_email_status(&conn, "FPR1", "a@x.org", EmailStatus::Published, 11).unwrap();
        // Re-upload without b@ drops it, keeps a@ published.
        upsert_key(&mut conn, "FPR1", "KEY2", &emails[..1], 12).unwrap();
        let st = key_statuses(&conn, "FPR1").unwrap();
        assert_eq!(st, vec![("a@x.org".to_owned(), EmailStatus::Published)]);
        assert_eq!(
            published_key_by_email(&conn, "a@x.org")
                .unwrap()
                .map(|k| k.1)
                .as_deref(),
            Some("KEY2")
        );
        assert!(published_key_by_email(&conn, "b@x.org").unwrap().is_none());
    }

    #[test]
    fn challenge_moves_address_between_keys() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.conn.lock().unwrap();
        let e = vec!["a@x.org".to_owned()];
        upsert_key(&mut conn, "OLD", "K1", &e, 1).unwrap();
        upsert_key(&mut conn, "NEW", "K2", &e, 2).unwrap();
        set_email_status(&conn, "OLD", "a@x.org", EmailStatus::Published, 3).unwrap();
        insert_challenge(&conn, "h", "NEW", "a@x.org", 4, 100).unwrap();
        assert_eq!(
            consume_challenge(&mut conn, "h", 5).unwrap(),
            Some(("NEW".to_owned(), "a@x.org".to_owned()))
        );
        assert_eq!(
            consume_challenge(&mut conn, "h", 6).unwrap(),
            None,
            "single use"
        );
        assert_eq!(
            published_key_by_email(&conn, "a@x.org")
                .unwrap()
                .map(|k| k.0)
                .as_deref(),
            Some("NEW")
        );
        assert_eq!(
            email_status(&conn, "OLD", "a@x.org").unwrap(),
            Some(EmailStatus::Unpublished)
        );
        assert!(consume_challenge(&mut conn, "missing", 7)
            .unwrap()
            .is_none());
    }

    #[test]
    fn guest_purge_cascades_replies() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.conn.lock().unwrap();
        let m = GuestMessage {
            id: "id1".into(),
            ciphertext: "ct".into(),
            sender_key: None,
            pickup_token_hash: "h".into(),
            created_at: 1,
            expires_at: 10,
        };
        insert_guest(&conn, &m).unwrap();
        insert_reply(&conn, "id1", "r", 2).unwrap();
        assert!(get_guest(&conn, "id1", 5).unwrap().is_some());
        assert!(
            get_guest(&conn, "id1", 10).unwrap().is_none(),
            "expired rows are invisible"
        );
        let rep = purge_expired(&conn, 10).unwrap();
        assert_eq!(rep.guest_messages, 1);
        assert_eq!(count_replies(&conn, "id1").unwrap(), 0);
    }
}
