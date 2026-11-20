//! Key-transparency log for the key directory (gate G30, `docs/IDENTITY.md`).
//!
//! An append-only RFC 6962 Merkle tree whose leaves are the canonical JSON
//! `{"action":"publish"|"unpublish","email_hash":<hex SHA-256 of the lower-cased address>,
//! "fingerprint":<upper-case hex>,"time":<unix seconds>}`. Every change of the directory's
//! published `(address, key)` pairs appends leaves ([`record_directory_changes`], hooked into the
//! VKS verify and upload paths, and run once at start-up to backfill). Each append stores a tree
//! head signed with the log's Ed25519 key, generated on first start and kept in the server DB
//! (`kt_signing_key`). Clients pin the public key (`GET /v1/kt/key`) and verify heads,
//! inclusion and consistency themselves; the server is not trusted to be honest, only to be
//! caught when it is not.

pub mod merkle;

use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::{Db, DbError};
use merkle::Hash;

/// Tables of the log. Created on demand by [`ensure`] (idempotent).
pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS kt_leaves (
    idx         INTEGER PRIMARY KEY,
    email_hash  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    action      TEXT NOT NULL CHECK (action IN ('publish','unpublish')),
    time        INTEGER NOT NULL,
    leaf        TEXT NOT NULL,
    leaf_hash   BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS kt_leaves_by_email ON kt_leaves(email_hash, idx);
CREATE TABLE IF NOT EXISTS kt_heads (
    tree_size   INTEGER PRIMARY KEY,
    root_hash   TEXT NOT NULL,
    timestamp   INTEGER NOT NULL,
    signature   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kt_signing_key (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    secret      BLOB NOT NULL,
    public      BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);
"#;

/// Domain-separation prefix of the signed tree head message.
pub const STH_CONTEXT: &str = "sealbox-kt-sth-v1";

/// One leaf. Field order is alphabetical so the compact `serde_json` encoding is canonical.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub action: String,
    pub email_hash: String,
    pub fingerprint: String,
    pub time: i64,
}

impl Entry {
    pub fn leaf_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// A signed tree head (`GET /v1/kt/sth`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sth {
    pub tree_size: u64,
    pub root_hash: String,
    pub timestamp: i64,
    pub signature: String,
}

/// Lower-case hex SHA-256 of the trimmed, lower-cased address.
pub fn email_hash(email: &str) -> String {
    hex::encode(Sha256::digest(email.trim().to_lowercase().as_bytes()))
}

/// The bytes a tree-head signature covers.
pub fn sth_signing_input(tree_size: u64, root_hex: &str, timestamp: i64) -> Vec<u8> {
    format!(
        "{STH_CONTEXT}\n{tree_size}\n{}\n{timestamp}\n",
        root_hex.to_ascii_lowercase()
    )
    .into_bytes()
}

fn now() -> i64 {
    crate::util::now()
}

fn to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Create the tables, the signing key and the empty-tree head if missing.
pub fn ensure(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(SCHEMA)?;
    let key = signing_key(conn)?;
    let has_head: Option<i64> = conn
        .query_row(
            "SELECT tree_size FROM kt_heads WHERE tree_size = 0",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if has_head.is_none() {
        store_head(conn, &key, 0, &merkle::empty_root(), now())?;
    }
    Ok(())
}

/// The log's signing key, generated (OS CSPRNG) and stored on first use.
pub fn signing_key(conn: &Connection) -> Result<SigningKey, DbError> {
    let stored: Option<Vec<u8>> = conn
        .query_row("SELECT secret FROM kt_signing_key WHERE id = 1", [], |r| {
            r.get(0)
        })
        .optional()?;
    if let Some(secret) = stored.and_then(|s| <[u8; 32]>::try_from(s).ok()) {
        return Ok(SigningKey::from_bytes(&secret));
    }
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let key = SigningKey::from_bytes(&secret);
    conn.execute(
        "INSERT INTO kt_signing_key (id, secret, public, created_at) VALUES (1, ?1, ?2, ?3)",
        params![
            secret.to_vec(),
            key.verifying_key().to_bytes().to_vec(),
            now()
        ],
    )?;
    tracing::info!(
        public_key = %hex::encode(key.verifying_key().to_bytes()),
        "key-transparency signing key generated"
    );
    Ok(key)
}

/// Hex public key of the log.
pub fn public_key_hex(conn: &Connection) -> Result<String, DbError> {
    ensure(conn)?;
    Ok(hex::encode(signing_key(conn)?.verifying_key().to_bytes()))
}

fn store_head(
    conn: &Connection,
    key: &SigningKey,
    size: u64,
    root: &Hash,
    timestamp: i64,
) -> Result<(), DbError> {
    let root_hex = hex::encode(root);
    let sig = key.sign(&sth_signing_input(size, &root_hex, timestamp));
    conn.execute(
        "INSERT OR REPLACE INTO kt_heads (tree_size, root_hash, timestamp, signature) \
         VALUES (?1, ?2, ?3, ?4)",
        params![
            to_i64(size),
            root_hex,
            timestamp,
            STANDARD.encode(sig.to_bytes())
        ],
    )?;
    Ok(())
}

/// Leaf hashes of the first `size` leaves (all when `None`).
pub fn leaf_hashes(conn: &Connection, size: Option<u64>) -> Result<Vec<Hash>, DbError> {
    let limit = size.map(to_i64).unwrap_or(-1);
    let mut stmt = conn.prepare("SELECT leaf_hash FROM kt_leaves ORDER BY idx LIMIT ?1")?;
    let rows = stmt.query_map([limit], |r| r.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for r in rows {
        let v = r?;
        out.push(<[u8; 32]>::try_from(v).map_err(|_| {
            DbError::Sqlite(rusqlite::Error::InvalidColumnType(
                0,
                "leaf_hash".into(),
                rusqlite::types::Type::Blob,
            ))
        })?);
    }
    Ok(out)
}

/// Number of leaves.
pub fn tree_size(conn: &Connection) -> Result<u64, DbError> {
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM kt_leaves", [], |r| r.get(0))?;
    Ok(to_u64(n))
}

/// The stored head for `size`.
pub fn head(conn: &Connection, size: u64) -> Result<Option<Sth>, DbError> {
    Ok(conn
        .query_row(
            "SELECT tree_size, root_hash, timestamp, signature FROM kt_heads WHERE tree_size = ?1",
            [to_i64(size)],
            |r| {
                Ok(Sth {
                    tree_size: to_u64(r.get(0)?),
                    root_hash: r.get(1)?,
                    timestamp: r.get(2)?,
                    signature: r.get(3)?,
                })
            },
        )
        .optional()?)
}

/// The newest signed tree head.
pub fn latest_sth(conn: &Connection) -> Result<Sth, DbError> {
    ensure(conn)?;
    let size = tree_size(conn)?;
    match head(conn, size)? {
        Some(h) => Ok(h),
        None => {
            // A head is written with every append; rebuild it if it went missing.
            let key = signing_key(conn)?;
            let root = merkle::root(&leaf_hashes(conn, Some(size))?);
            store_head(conn, &key, size, &root, now())?;
            head(conn, size)?.ok_or(DbError::Sqlite(rusqlite::Error::QueryReturnedNoRows))
        }
    }
}

/// Append entries in one transaction, writing a signed head after each.
pub fn append(conn: &mut Connection, entries: &[Entry]) -> Result<u64, DbError> {
    ensure(conn)?;
    let key = signing_key(conn)?;
    let tx = conn.transaction()?;
    let mut hashes = leaf_hashes(&tx, None)?;
    for e in entries {
        let leaf = e.leaf_json();
        let lh = merkle::leaf_hash(leaf.as_bytes());
        let idx = hashes.len() as i64;
        tx.execute(
            "INSERT INTO kt_leaves (idx, email_hash, fingerprint, action, time, leaf, leaf_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                idx,
                e.email_hash,
                e.fingerprint,
                e.action,
                e.time,
                leaf,
                lh.to_vec()
            ],
        )?;
        hashes.push(lh);
        store_head(
            &tx,
            &key,
            hashes.len() as u64,
            &merkle::root(&hashes),
            e.time,
        )?;
    }
    tx.commit()?;
    Ok(hashes.len() as u64)
}

/// Diff the directory's published `(address, key)` pairs against the state the log describes
/// and append `unpublish` then `publish` leaves for every difference. Idempotent; returns the
/// number of leaves appended.
pub fn sync_directory(conn: &mut Connection, time: i64) -> Result<usize, DbError> {
    ensure(conn)?;
    let mut current: BTreeSet<(String, String)> = BTreeSet::new();
    {
        let mut stmt = conn.prepare("SELECT email, fpr FROM emails WHERE status = 'published'")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for r in rows {
            let (email, fpr) = r?;
            current.insert((email_hash(&email), fpr.to_ascii_uppercase()));
        }
    }
    let mut logged: BTreeSet<(String, String)> = BTreeSet::new();
    {
        let mut stmt =
            conn.prepare("SELECT email_hash, fingerprint, action FROM kt_leaves ORDER BY idx")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for r in rows {
            let (h, f, a) = r?;
            if a == "publish" {
                logged.insert((h, f));
            } else {
                logged.remove(&(h, f));
            }
        }
    }
    let mut entries: Vec<Entry> = Vec::new();
    for (h, f) in logged.difference(&current) {
        entries.push(Entry {
            action: "unpublish".into(),
            email_hash: h.clone(),
            fingerprint: f.clone(),
            time,
        });
    }
    for (h, f) in current.difference(&logged) {
        entries.push(Entry {
            action: "publish".into(),
            email_hash: h.clone(),
            fingerprint: f.clone(),
            time,
        });
    }
    if entries.is_empty() {
        return Ok(0);
    }
    append(conn, &entries)?;
    Ok(entries.len())
}

/// The hook of the VKS write paths: bring the log up to date with the directory. A failure is
/// logged, never surfaced to the publishing client (the directory change already happened);
/// the next change or the next start-up appends what is missing.
pub fn record_directory_changes(conn: &mut Connection, time: i64) {
    match sync_directory(conn, time) {
        Ok(0) => {}
        Ok(n) => tracing::info!(appended = n, "key-transparency log updated"),
        Err(e) => tracing::error!(error = %e, "key-transparency append failed"),
    }
}

/// Start-up: create the tables and key, backfill entries for keys published before the log.
pub async fn init(db: &Db) -> Result<String, DbError> {
    db.call(|c| {
        sync_directory(c, now())?;
        public_key_hex(c)
    })
    .await
}

/// Leaf, index and audit path of the newest entry for `email_hash` within the first `size`
/// leaves.
pub fn inclusion(
    conn: &Connection,
    email_hash: &str,
    size: u64,
) -> Result<Option<(u64, Entry, Vec<Hash>)>, DbError> {
    let found: Option<(i64, String, String, String, i64)> = conn
        .query_row(
            "SELECT idx, email_hash, fingerprint, action, time FROM kt_leaves \
             WHERE email_hash = ?1 AND idx < ?2 ORDER BY idx DESC LIMIT 1",
            params![email_hash, to_i64(size)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((idx, email_hash, fingerprint, action, time)) = found else {
        return Ok(None);
    };
    let hashes = leaf_hashes(conn, Some(size))?;
    let path = merkle::inclusion_path(to_u64(idx) as usize, &hashes);
    Ok(Some((
        to_u64(idx),
        Entry {
            action,
            email_hash,
            fingerprint,
            time,
        },
        path,
    )))
}

/// Consistency proof between sizes `from` and `to` (`0 <= from <= to <= tree size`).
pub fn consistency(conn: &Connection, from: u64, to: u64) -> Result<Vec<Hash>, DbError> {
    let hashes = leaf_hashes(conn, Some(to))?;
    Ok(merkle::consistency_proof(from as usize, &hashes))
}

/// `(index, entry, leaf_hash)` for up to `limit` leaves from `start`.
pub fn entries(
    conn: &Connection,
    start: u64,
    limit: u64,
) -> Result<Vec<(u64, Entry, Hash)>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT idx, email_hash, fingerprint, action, time, leaf_hash FROM kt_leaves \
         WHERE idx >= ?1 ORDER BY idx LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![to_i64(start), to_i64(limit)], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            Entry {
                email_hash: r.get(1)?,
                fingerprint: r.get(2)?,
                action: r.get(3)?,
                time: r.get(4)?,
            },
            r.get::<_, Vec<u8>>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (i, e, h) = r?;
        out.push((to_u64(i), e, <[u8; 32]>::try_from(h).unwrap_or([0; 32])));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    fn mem() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE emails (email TEXT, fpr TEXT, status TEXT, published_at INTEGER);",
        )
        .unwrap();
        c
    }

    fn verify(conn: &Connection, sth: &Sth) -> bool {
        let vk = signing_key(conn).unwrap().verifying_key();
        let sig: [u8; 64] = STANDARD.decode(&sth.signature).unwrap().try_into().unwrap();
        vk.verify(
            &sth_signing_input(sth.tree_size, &sth.root_hash, sth.timestamp),
            &Signature::from_bytes(&sig),
        )
        .is_ok()
    }

    #[test]
    fn heads_are_signed_and_directory_diff_appends() {
        let mut c = mem();
        let h0 = latest_sth(&c).unwrap();
        assert_eq!(h0.tree_size, 0);
        assert_eq!(h0.root_hash, hex::encode(merkle::empty_root()));
        assert!(verify(&c, &h0));
        let key1 = public_key_hex(&c).unwrap();

        c.execute(
            "INSERT INTO emails VALUES ('a@x.org', 'AAAA', 'published', 1)",
            [],
        )
        .unwrap();
        assert_eq!(sync_directory(&mut c, 10).unwrap(), 1);
        assert_eq!(sync_directory(&mut c, 11).unwrap(), 0, "idempotent");
        // Key rotation for a@x.org: unpublish AAAA, publish BBBB (in that order).
        c.execute("UPDATE emails SET status = 'unpublished'", [])
            .unwrap();
        c.execute(
            "INSERT INTO emails VALUES ('a@x.org', 'BBBB', 'published', 2)",
            [],
        )
        .unwrap();
        assert_eq!(sync_directory(&mut c, 20).unwrap(), 2);
        let all = entries(&c, 0, 10).unwrap();
        let acts: Vec<_> = all
            .iter()
            .map(|(_, e, _)| (e.action.as_str(), e.fingerprint.as_str()))
            .collect();
        assert_eq!(
            acts,
            vec![
                ("publish", "AAAA"),
                ("unpublish", "AAAA"),
                ("publish", "BBBB")
            ]
        );
        assert_eq!(all[0].1.email_hash, email_hash("A@X.org"));

        let sth = latest_sth(&c).unwrap();
        assert_eq!(sth.tree_size, 3);
        assert!(verify(&c, &sth));
        for size in 0..=3 {
            assert!(verify(&c, &head(&c, size).unwrap().unwrap()));
        }
        // Inclusion of the newest entry; consistency between every pair of sizes.
        let (idx, e, path) = inclusion(&c, &email_hash("a@x.org"), 3).unwrap().unwrap();
        assert_eq!((idx, e.fingerprint.as_str()), (2, "BBBB"));
        let root: Hash = hex::decode(&sth.root_hash).unwrap().try_into().unwrap();
        assert!(merkle::verify_inclusion(
            idx,
            3,
            &merkle::leaf_hash(e.leaf_json().as_bytes()),
            &path,
            &root
        ));
        let (idx, e, _) = inclusion(&c, &email_hash("a@x.org"), 1).unwrap().unwrap();
        assert_eq!((idx, e.fingerprint.as_str()), (0, "AAAA"));
        for from in 0..=3u64 {
            for to in from..=3u64 {
                let a: Hash = hex::decode(head(&c, from).unwrap().unwrap().root_hash)
                    .unwrap()
                    .try_into()
                    .unwrap();
                let b: Hash = hex::decode(head(&c, to).unwrap().unwrap().root_hash)
                    .unwrap()
                    .try_into()
                    .unwrap();
                let p = consistency(&c, from, to).unwrap();
                assert!(
                    merkle::verify_consistency(from, to, &a, &b, &p),
                    "{from}->{to}"
                );
            }
        }
        assert_eq!(public_key_hex(&c).unwrap(), key1, "key is stable");
    }
}
