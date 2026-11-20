//! Persistence for hosted signups: one row per address ever provisioned.
//!
//! The row is the reservation: it is inserted *before* the mailbox is created on Stalwart (the
//! UNIQUE constraints make two concurrent signups for the same name impossible) and deleted again
//! if provisioning fails. We keep no password — only its SHA-256 — plus the e-mail, creation
//! time, a keyed hash of the client IP (for the daily caps) and the invite code used.

use rusqlite::{params, Connection, OptionalExtension};

use crate::db::DbError;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS hosted_signups (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    local_part            TEXT NOT NULL UNIQUE,
    email                 TEXT NOT NULL UNIQUE,
    password_sha256       TEXT NOT NULL,
    recovery_email_sha256 TEXT,
    ip_hash               TEXT NOT NULL,
    invite_code           TEXT,
    stalwart_id           TEXT,
    created_at            INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS hosted_signups_ip ON hosted_signups(ip_hash, created_at);
CREATE INDEX IF NOT EXISTS hosted_signups_created ON hosted_signups(created_at);
"#;

/// Create the table (idempotent). Called once at startup by the hosted service.
pub fn ensure_schema(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

/// A reservation to insert.
#[derive(Debug)]
pub struct NewSignup<'a> {
    pub local_part: &'a str,
    pub email: &'a str,
    pub password_sha256: &'a str,
    pub recovery_email_sha256: Option<&'a str>,
    pub ip_hash: &'a str,
    pub invite_code: Option<&'a str>,
    pub created_at: i64,
}

/// Result of [`reserve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveOutcome {
    /// Row id of the new reservation.
    Reserved(i64),
    /// The name (or address) already has a row.
    Taken,
}

/// Insert the reservation row; `Taken` on a UNIQUE conflict.
pub fn reserve(conn: &Connection, s: &NewSignup<'_>) -> Result<ReserveOutcome, DbError> {
    let r = conn.execute(
        "INSERT INTO hosted_signups
            (local_part, email, password_sha256, recovery_email_sha256, ip_hash, invite_code, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            s.local_part,
            s.email,
            s.password_sha256,
            s.recovery_email_sha256,
            s.ip_hash,
            s.invite_code,
            s.created_at
        ],
    );
    match r {
        Ok(_) => Ok(ReserveOutcome::Reserved(conn.last_insert_rowid())),
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Ok(ReserveOutcome::Taken)
        }
        Err(e) => Err(e.into()),
    }
}

/// Drop a reservation whose provisioning failed.
pub fn release(conn: &Connection, id: i64) -> Result<(), DbError> {
    conn.execute("DELETE FROM hosted_signups WHERE id = ?1", [id])?;
    Ok(())
}

/// Record the Stalwart account id once the mailbox exists.
pub fn set_stalwart_id(conn: &Connection, id: i64, stalwart_id: &str) -> Result<(), DbError> {
    conn.execute(
        "UPDATE hosted_signups SET stalwart_id = ?2 WHERE id = ?1",
        params![id, stalwart_id],
    )?;
    Ok(())
}

/// Has this local part been provisioned (or reserved) before?
pub fn exists(conn: &Connection, local_part: &str) -> Result<bool, DbError> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM hosted_signups WHERE local_part = ?1",
            [local_part],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Signups since `since` (Unix seconds), optionally for one IP hash only.
pub fn count_since(conn: &Connection, ip_hash: Option<&str>, since: i64) -> Result<u32, DbError> {
    let n: i64 = match ip_hash {
        Some(h) => conn.query_row(
            "SELECT COUNT(*) FROM hosted_signups WHERE ip_hash = ?1 AND created_at >= ?2",
            params![h, since],
            |r| r.get(0),
        )?,
        None => conn.query_row(
            "SELECT COUNT(*) FROM hosted_signups WHERE created_at >= ?1",
            [since],
            |r| r.get(0),
        )?,
    };
    Ok(n.max(0) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        ensure_schema(&c).unwrap();
        c
    }

    fn row<'a>(local: &'a str, email: &'a str, ip: &'a str, at: i64) -> NewSignup<'a> {
        NewSignup {
            local_part: local,
            email,
            password_sha256: "deadbeef",
            recovery_email_sha256: None,
            ip_hash: ip,
            invite_code: None,
            created_at: at,
        }
    }

    #[test]
    fn reserve_is_unique_and_releasable() {
        let c = conn();
        let a = reserve(&c, &row("alice", "alice@h.test", "ip1", 100)).unwrap();
        let ReserveOutcome::Reserved(id) = a else {
            panic!("first reserve must succeed");
        };
        assert_eq!(
            reserve(&c, &row("alice", "alice@h.test", "ip2", 101)).unwrap(),
            ReserveOutcome::Taken
        );
        assert!(exists(&c, "alice").unwrap());
        release(&c, id).unwrap();
        assert!(!exists(&c, "alice").unwrap());
        assert!(matches!(
            reserve(&c, &row("alice", "alice@h.test", "ip2", 102)).unwrap(),
            ReserveOutcome::Reserved(_)
        ));
    }

    #[test]
    fn counts_by_ip_and_window() {
        let c = conn();
        for (i, at) in [(1, 10), (2, 20), (3, 30)] {
            let l = format!("user{i}");
            let e = format!("user{i}@h.test");
            reserve(&c, &row(&l, &e, "ipA", at)).unwrap();
        }
        reserve(&c, &row("other", "other@h.test", "ipB", 25)).unwrap();
        assert_eq!(count_since(&c, Some("ipA"), 0).unwrap(), 3);
        assert_eq!(count_since(&c, Some("ipA"), 20).unwrap(), 2);
        assert_eq!(count_since(&c, Some("ipB"), 0).unwrap(), 1);
        assert_eq!(count_since(&c, None, 0).unwrap(), 4);
        assert_eq!(count_since(&c, None, 31).unwrap(), 0);
    }
}
