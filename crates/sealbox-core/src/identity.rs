//! G30 — identity: key-change alerts, verified contacts, fingerprint QR payloads and the client
//! side of the key-transparency (KT) log. Design and threat model: `docs/IDENTITY.md`.
//!
//! * **Key continuity.** Every key we see for a correspondent is remembered per address
//!   (`identity_keys`). Keys from the sender itself (its Autocrypt header, a good signature),
//!   keys the user imported and keys the user verified are *continuity* keys. A message whose
//!   Autocrypt or signing key is not among the continuity keys of a known sender raises an
//!   alert: [`SignatureSummary::key_changed`] on that message and
//!   [`Contact::key_changed_at`]/[`Contact::previous_fingerprint`] on the contact, until
//!   [`Engine::acknowledge_key_change`] or [`Engine::verify_contact`]. Gossip and directory keys
//!   are recorded too but never vouch for a key (a third party or the server could plant them).
//! * **Verification.** [`Engine::verify_contact`] pins the fingerprint the user compared out of
//!   band (QR payload `OPENPGP4FPR:<hex>`); a good signature by exactly that key sets
//!   [`SignatureSummary::signer_verified`].
//! * **Key transparency.** [`Engine::kt_audit`] checks the server's append-only Merkle log
//!   (RFC 6962 hashing, Ed25519-signed tree heads, TOFU-pinned log key in `kt_pins`): the tree
//!   head signature, consistency with the last head this profile saw, and that the newest log
//!   entry for the account's address publishes exactly the account's key.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use sealbox_crypto::{AutocryptHeader, PublicKey};
use sealbox_mail::mime::ParsedHeaders;
use serde::{Deserialize, Serialize};

use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::store::{AccountRow, FolderRow};
use crate::types::{Contact, KeySource, MessageSummary, SigState, SignatureSummary};

pub use kt::{
    ConsistencyProof, InclusionProof, KtEntriesPage, KtEntry, KtIndexedEntry, KtKey, SignedTreeHead,
};

/// Tables of this module (executed by `Store::open`). Nothing here is secret: addresses and
/// fingerprints stay plaintext in the profile like the rest of the address book.
pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS identity_keys (
    addr        TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    source      TEXT NOT NULL,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    PRIMARY KEY (addr, fingerprint, source)
);
CREATE TABLE IF NOT EXISTS identity_contacts (
    addr                 TEXT PRIMARY KEY,
    current_fingerprint  TEXT,
    key_changed_at       INTEGER,
    previous_fingerprint TEXT,
    verified_fingerprint TEXT,
    verified_at          INTEGER
);
CREATE TABLE IF NOT EXISTS identity_messages (
    account_id      INTEGER NOT NULL,
    folder_id       INTEGER NOT NULL,
    uid             INTEGER NOT NULL,
    key_changed     INTEGER NOT NULL DEFAULT 0,
    signer_verified INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, folder_id, uid)
);
CREATE TABLE IF NOT EXISTS kt_pins (
    server        TEXT PRIMARY KEY,
    public_key    TEXT NOT NULL,
    pinned_at     INTEGER NOT NULL,
    sth_tree_size INTEGER,
    sth_root_hash TEXT,
    sth_timestamp INTEGER,
    sth_signature TEXT
);
"#;

/// Key sources that vouch for continuity (the sender itself, or the user).
const CONTINUITY_SOURCES: [&str; 4] = ["autocrypt", "signature", "import", "verified"];

/// Prefix of the fingerprint QR payload (OpenKeychain / Delta Chat convention).
pub const QR_PREFIX: &str = "OPENPGP4FPR:";

/// Environment switch: verify every key-directory lookup against the KT log before using it.
pub const KT_VERIFY_LOOKUPS_ENV: &str = "SEALBOX_KT_VERIFY_LOOKUPS";

/// Result of [`Engine::kt_audit`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KtAuditReport {
    /// Tree size of the signed tree head the server presented.
    pub log_size: u64,
    /// The tree head's Ed25519 signature verifies with the pinned log key.
    pub sth_verified: bool,
    /// The newest log entry for the address publishes exactly our key, with a valid
    /// inclusion proof against the verified tree head.
    pub own_key_included: bool,
    /// The tree head is an append-only extension of the last one this profile accepted
    /// (true on the first audit, when there is nothing to compare).
    pub consistency_ok: bool,
    /// Human-readable findings; empty when everything checked out.
    pub alerts: Vec<String>,
}

impl KtAuditReport {
    /// Everything verified and no alert.
    pub fn is_clean(&self) -> bool {
        self.sth_verified && self.own_key_included && self.consistency_ok && self.alerts.is_empty()
    }
}

/// Options for [`Engine::kt_audit_with`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KtAuditOptions {
    /// Server base URL. Default: `EngineConfig::directory_url`, then `server_url`.
    pub server: Option<String>,
    /// Ed25519 log public key (64 hex chars or base64) to use instead of the TOFU pin; it is
    /// stored as the new pin.
    pub kt_key: Option<String>,
}

/// Upper-case hex fingerprint (v4: 40, v6: 64 hex digits), accepting spaces, colons and `0x`.
pub fn normalize_fingerprint(s: &str) -> Option<String> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    let hex: String = t
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if (hex.len() == 40 || hex.len() == 64) && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hex.to_ascii_uppercase())
    } else {
        None
    }
}

/// `OPENPGP4FPR:<FINGERPRINT>` for a fingerprint.
pub fn qr_payload_for(fingerprint: &str) -> Result<String> {
    let fp = normalize_fingerprint(fingerprint)
        .ok_or_else(|| Error::InvalidInput(format!("`{fingerprint}` is not a fingerprint")))?;
    Ok(format!("{QR_PREFIX}{fp}"))
}

/// Parse a scanned `OPENPGP4FPR:` payload (case-insensitive prefix; a `#a=…&n=…` suffix as
/// written by OpenKeychain/Delta Chat is ignored) into an upper-case fingerprint.
pub fn parse_qr_payload(payload: &str) -> Result<String> {
    let p = payload.trim();
    let bad = || Error::InvalidInput("not an OPENPGP4FPR: fingerprint payload".into());
    let head = p.get(..QR_PREFIX.len()).ok_or_else(bad)?;
    if !head.eq_ignore_ascii_case(QR_PREFIX) {
        return Err(bad());
    }
    let rest = p.get(QR_PREFIX.len()..).ok_or_else(bad)?;
    let fp = rest.split('#').next().unwrap_or_default();
    normalize_fingerprint(fp).ok_or_else(bad)
}

fn norm_addr(a: &str) -> String {
    a.trim().to_ascii_lowercase()
}

fn ts(t: Option<i64>) -> Option<DateTime<Utc>> {
    t.and_then(|t| DateTime::<Utc>::from_timestamp(t, 0))
}

/// One `identity_contacts` row.
#[derive(Debug, Default, Clone)]
struct ContactRow {
    current_fingerprint: Option<String>,
    key_changed_at: Option<i64>,
    previous_fingerprint: Option<String>,
    verified_fingerprint: Option<String>,
    verified_at: Option<i64>,
}

fn contact_row(conn: &Connection, addr: &str) -> Result<Option<ContactRow>> {
    Ok(conn
        .query_row(
            "SELECT current_fingerprint, key_changed_at, previous_fingerprint, \
             verified_fingerprint, verified_at FROM identity_contacts WHERE addr = ?1",
            params![addr],
            |r| {
                Ok(ContactRow {
                    current_fingerprint: r.get(0)?,
                    key_changed_at: r.get(1)?,
                    previous_fingerprint: r.get(2)?,
                    verified_fingerprint: r.get(3)?,
                    verified_at: r.get(4)?,
                })
            },
        )
        .optional()?)
}

fn save_contact_row(conn: &Connection, addr: &str, r: &ContactRow) -> Result<()> {
    conn.execute(
        "INSERT INTO identity_contacts (addr, current_fingerprint, key_changed_at, \
         previous_fingerprint, verified_fingerprint, verified_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(addr) DO UPDATE SET current_fingerprint = excluded.current_fingerprint, \
         key_changed_at = excluded.key_changed_at, previous_fingerprint = excluded.previous_fingerprint, \
         verified_fingerprint = excluded.verified_fingerprint, verified_at = excluded.verified_at",
        params![
            addr,
            r.current_fingerprint,
            r.key_changed_at,
            r.previous_fingerprint,
            r.verified_fingerprint,
            r.verified_at
        ],
    )?;
    Ok(())
}

fn record_key(conn: &Connection, addr: &str, fp: &str, source: &str, now: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO identity_keys (addr, fingerprint, source, first_seen, last_seen) \
         VALUES (?1, ?2, ?3, ?4, ?4) ON CONFLICT(addr, fingerprint, source) \
         DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen)",
        params![addr, fp, source, now],
    )?;
    Ok(())
}

/// Continuity fingerprints of `addr`, most recently seen first.
fn continuity_keys(conn: &Connection, addr: &str) -> Result<Vec<String>> {
    let sources = CONTINUITY_SOURCES
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut stmt = conn.prepare(&format!(
        "SELECT fingerprint, MAX(last_seen) AS seen FROM identity_keys \
         WHERE addr = ?1 AND source IN ({sources}) \
         GROUP BY fingerprint ORDER BY seen DESC, fingerprint"
    ))?;
    let rows = stmt.query_map(params![addr], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

impl Engine {
    /// The contact entry for one address (as [`Engine::contacts`] shows it).
    fn contact_for(&self, address: &str) -> Result<Contact> {
        let addr = norm_addr(address);
        self.contacts()?
            .into_iter()
            .find(|c| c.address == addr)
            .ok_or_else(|| Error::InvalidInput(format!("no contact {addr} (sync first)")))
    }

    /// Mark `address` verified: `fingerprint` (hex, or an `OPENPGP4FPR:` payload) must equal
    /// the contact's current key, otherwise nothing changes and an error is returned. Clears a
    /// pending key-change alert.
    pub fn verify_contact(&self, address: &str, fingerprint: &str) -> Result<Contact> {
        let addr = norm_addr(address);
        let want = normalize_fingerprint(fingerprint)
            .or_else(|| parse_qr_payload(fingerprint).ok())
            .ok_or_else(|| Error::InvalidInput(format!("`{fingerprint}` is not a fingerprint")))?;
        let c = self.contact_for(&addr)?;
        let current = c
            .fingerprint
            .as_deref()
            .and_then(normalize_fingerprint)
            .ok_or_else(|| Error::InvalidInput(format!("no key is known for {addr}")))?;
        if current != want {
            return Err(Error::InvalidInput(format!(
                "fingerprint mismatch: the current key of {addr} is {current}, not {want}; \
                 the contact was not verified"
            )));
        }
        {
            let store = self.store();
            let conn = store.conn();
            let now = Utc::now().timestamp();
            record_key(conn, &addr, &current, "verified", now)?;
            let mut row = contact_row(conn, &addr)?.unwrap_or_default();
            row.current_fingerprint = Some(current.clone());
            row.verified_fingerprint = Some(current);
            row.verified_at = Some(now);
            row.key_changed_at = None;
            row.previous_fingerprint = None;
            save_contact_row(conn, &addr, &row)?;
        }
        self.contact_for(&addr)
    }

    /// Remove the verification mark of `address`.
    pub fn unverify_contact(&self, address: &str) -> Result<Contact> {
        let addr = norm_addr(address);
        self.contact_for(&addr)?;
        {
            let store = self.store();
            let conn = store.conn();
            if let Some(mut row) = contact_row(conn, &addr)? {
                row.verified_fingerprint = None;
                row.verified_at = None;
                save_contact_row(conn, &addr, &row)?;
            }
        }
        self.contact_for(&addr)
    }

    /// Accept the new key of `address` without verifying it (clears the key-change alert).
    pub fn acknowledge_key_change(&self, address: &str) -> Result<Contact> {
        let addr = norm_addr(address);
        self.contact_for(&addr)?;
        {
            let store = self.store();
            let conn = store.conn();
            if let Some(mut row) = contact_row(conn, &addr)? {
                row.key_changed_at = None;
                row.previous_fingerprint = None;
                save_contact_row(conn, &addr, &row)?;
            }
        }
        self.contact_for(&addr)
    }

    /// `OPENPGP4FPR:<40 hex>` for the key of one of our accounts (show it as a QR code).
    pub fn fingerprint_qr_payload(&self, email: &str) -> Result<String> {
        qr_payload_for(&self.my_fingerprint(email)?)
    }

    /// Parse a scanned fingerprint payload into an upper-case fingerprint.
    pub fn parse_fingerprint_qr(payload: &str) -> Result<String> {
        parse_qr_payload(payload)
    }

    /// Hook of the receive pipeline (called right after the signature verdict, i.e. after the
    /// Autocrypt peer update): key-change detection and the verified-signer mark. Never fails
    /// the sync; problems are logged.
    pub(crate) fn identity_on_message(
        &self,
        acct: &AccountRow,
        folder: &FolderRow,
        uid: u32,
        h: &ParsedHeaders,
        from_is_own: bool,
        mut sig: SignatureSummary,
    ) -> SignatureSummary {
        match self.identity_observe(acct.id, folder.id, uid, h, from_is_own, &sig) {
            Ok((changed, verified)) => {
                sig.key_changed = changed;
                sig.signer_verified = verified;
            }
            Err(e) => tracing::warn!(uid, "identity check skipped: {e}"),
        }
        sig
    }

    fn identity_observe(
        &self,
        account_id: i64,
        folder_id: i64,
        uid: u32,
        h: &ParsedHeaders,
        from_is_own: bool,
        sig: &SignatureSummary,
    ) -> Result<(bool, bool)> {
        let uid = i64::from(uid);
        let addr = h.from.first().map(|m| norm_addr(&m.address));
        let peer = match (&addr, from_is_own || h.from.len() != 1) {
            (Some(a), false) => self.store().peer(a)?,
            _ => None,
        };
        let store = self.store();
        let conn = store.conn();
        // A re-fetch of a message we already stored keeps the verdict it got the first time.
        let stored: Option<i64> = conn
            .query_row(
                "SELECT id FROM messages WHERE account_id = ?1 AND folder_id = ?2 AND uid = ?3",
                params![account_id, folder_id, uid],
                |r| r.get(0),
            )
            .optional()?;
        if stored.is_some() {
            let flags: Option<(bool, bool)> = conn
                .query_row(
                    "SELECT key_changed, signer_verified FROM identity_messages \
                     WHERE account_id = ?1 AND folder_id = ?2 AND uid = ?3",
                    params![account_id, folder_id, uid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            return Ok(flags.unwrap_or_default());
        }
        // Flags of a message that no longer exists (UIDVALIDITY reset) must not stick.
        conn.execute(
            "DELETE FROM identity_messages WHERE account_id = ?1 AND folder_id = ?2 AND uid = ?3",
            params![account_id, folder_id, uid],
        )?;
        let Some(addr) = addr.filter(|a| a.contains('@') && !from_is_own && h.from.len() == 1)
        else {
            return Ok((false, false));
        };
        let now = Utc::now().timestamp();

        // Keys learned without a message: imports vouch (user action); directory and gossip
        // keys are only remembered.
        for k in store.keys_for(&addr)? {
            let source = match k.source {
                KeySource::Imported => "import",
                KeySource::Directory => "directory",
                _ => continue,
            };
            if let Some(fp) = normalize_fingerprint(&k.fingerprint) {
                record_key(conn, &addr, &fp, source, now)?;
            }
        }
        if let Some(g) = peer.as_ref().and_then(|p| p.gossip_public_key()) {
            if let Some(fp) = normalize_fingerprint(&g.fingerprint()) {
                record_key(conn, &addr, &fp, "gossip", now)?;
            }
        }

        // What this message presents: the Autocrypt key (only when the peer state accepted it,
        // so out-of-order old mail does not count) and the key of a good signature.
        let mut observed: Vec<(String, &'static str)> = Vec::new();
        let accepted = peer
            .as_ref()
            .and_then(|p| p.public_key())
            .and_then(|k| normalize_fingerprint(&k.fingerprint()));
        let values: Vec<&str> = h.autocrypt.iter().map(String::as_str).collect();
        if let Some(hdr) = AutocryptHeader::parse_for_sender(&values, &addr) {
            if let Some(fp) = hdr
                .public_key()
                .ok()
                .and_then(|k| normalize_fingerprint(&k.fingerprint()))
            {
                if accepted.as_deref() == Some(fp.as_str()) {
                    observed.push((fp, "autocrypt"));
                }
            }
        }
        if sig.status == SigState::Good
            && sig
                .signer
                .as_deref()
                .is_none_or(|s| s.eq_ignore_ascii_case(&addr))
        {
            if let Some(fp) = sig.fingerprint.as_deref().and_then(normalize_fingerprint) {
                observed.push((fp, "signature"));
            }
        }

        let history = continuity_keys(conn, &addr)?;
        let changed_to = if history.is_empty() {
            None // first contact: trust on first use
        } else {
            observed
                .iter()
                .find(|(fp, _)| !history.contains(fp))
                .map(|(fp, _)| fp.clone())
        };
        for (fp, source) in &observed {
            record_key(conn, &addr, fp, source, now)?;
        }
        let mut row = contact_row(conn, &addr)?.unwrap_or_default();
        if let Some(new_fp) = &changed_to {
            if row.key_changed_at.is_none() {
                // A fresh alert: remember the key we trusted until now.
                row.key_changed_at = Some(now);
                row.previous_fingerprint = row
                    .current_fingerprint
                    .clone()
                    .filter(|f| f != new_fp && history.contains(f))
                    .or_else(|| history.iter().find(|f| *f != new_fp).cloned())
                    .filter(|f| f != new_fp);
            }
            row.current_fingerprint = Some(new_fp.clone());
            save_contact_row(conn, &addr, &row)?;
            tracing::info!(contact = %addr, "key change detected");
        } else if let Some((fp, _)) = observed.first() {
            if row.current_fingerprint.as_deref() != Some(fp.as_str()) {
                row.current_fingerprint = Some(fp.clone());
                save_contact_row(conn, &addr, &row)?;
            }
        }
        let signer_verified = row.verified_fingerprint.as_deref().is_some_and(|v| {
            observed
                .iter()
                .any(|(fp, src)| *src == "signature" && fp == v)
        });
        let key_changed = changed_to.is_some();
        if key_changed || signer_verified {
            conn.execute(
                "INSERT OR REPLACE INTO identity_messages \
                 (account_id, folder_id, uid, key_changed, signer_verified) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![account_id, folder_id, uid, key_changed, signer_verified],
            )?;
        }
        Ok((key_changed, signer_verified))
    }

    /// Overlay verification and key-change state onto [`Engine::contacts`] rows.
    pub(crate) fn identity_decorate_contacts(&self, out: &mut [Contact]) {
        let rows: Result<HashMap<String, ContactRow>> = (|| {
            let store = self.store();
            let mut stmt = store.conn().prepare(
                "SELECT addr, current_fingerprint, key_changed_at, previous_fingerprint, \
                 verified_fingerprint, verified_at FROM identity_contacts",
            )?;
            let it = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    ContactRow {
                        current_fingerprint: r.get(1)?,
                        key_changed_at: r.get(2)?,
                        previous_fingerprint: r.get(3)?,
                        verified_fingerprint: r.get(4)?,
                        verified_at: r.get(5)?,
                    },
                ))
            })?;
            Ok(it.collect::<std::result::Result<HashMap<_, _>, _>>()?)
        })();
        let rows = match rows {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("identity state unavailable: {e}");
                return;
            }
        };
        for c in out {
            let Some(r) = rows.get(&c.address) else {
                continue;
            };
            let current = c.fingerprint.as_deref().and_then(normalize_fingerprint);
            c.verified = r.verified_fingerprint.is_some() && r.verified_fingerprint == current;
            c.verified_at = if c.verified { ts(r.verified_at) } else { None };
            c.key_changed_at = ts(r.key_changed_at);
            c.previous_fingerprint = r.key_changed_at.and(r.previous_fingerprint.clone());
        }
    }

    /// Overlay the per-message identity flags onto stored message summaries.
    pub(crate) fn identity_decorate_messages<'a>(
        &self,
        rows: impl Iterator<Item = &'a mut MessageSummary>,
    ) {
        let flags: Result<HashMap<i64, (bool, bool)>> = (|| {
            let store = self.store();
            let mut stmt = store.conn().prepare(
                "SELECT m.id, i.key_changed, i.signer_verified FROM identity_messages i \
                 JOIN messages m ON m.account_id = i.account_id AND m.folder_id = i.folder_id \
                 AND m.uid = i.uid",
            )?;
            let it = stmt.query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?))))?;
            Ok(it.collect::<std::result::Result<HashMap<_, _>, _>>()?)
        })();
        let flags = match flags {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!("identity flags unavailable: {e}");
                return;
            }
        };
        if flags.is_empty() {
            return;
        }
        for m in rows {
            if let Some((changed, verified)) = flags.get(&m.id) {
                m.signature.key_changed = *changed;
                m.signature.signer_verified = *verified;
            }
        }
    }

    // ----- key transparency ---------------------------------------------------------------

    fn kt_base(&self, server: Option<&str>) -> Result<String> {
        server
            .map(str::to_string)
            .or_else(|| self.directory_url())
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                Error::ServerNotConfigured(
                    "no key-transparency server: pass --server, run `sealbox server set-url` \
                     or set SEALBOX_DIRECTORY_URL"
                        .into(),
                )
            })
    }

    fn kt_pin(&self, base: &str) -> Result<Option<(String, Option<SignedTreeHead>)>> {
        let store = self.store();
        let row = store
            .conn()
            .query_row(
                "SELECT public_key, sth_tree_size, sth_root_hash, sth_timestamp, sth_signature \
                 FROM kt_pins WHERE server = ?1",
                params![base],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<i64>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                        r.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()?;
        Ok(row.map(|(key, size, root, time, sig)| {
            let sth = match (size, root, time, sig) {
                (Some(size), Some(root_hash), Some(timestamp), Some(signature)) => {
                    Some(SignedTreeHead {
                        tree_size: u64::try_from(size).unwrap_or(0),
                        root_hash,
                        timestamp,
                        signature,
                    })
                }
                _ => None,
            };
            (key, sth)
        }))
    }

    fn kt_save_pin(&self, base: &str, key: &[u8; 32], sth: Option<&SignedTreeHead>) -> Result<()> {
        let store = self.store();
        let conn = store.conn();
        conn.execute(
            "INSERT INTO kt_pins (server, public_key, pinned_at) VALUES (?1, ?2, ?3) \
             ON CONFLICT(server) DO UPDATE SET public_key = excluded.public_key",
            params![base, kt::to_hex(key), Utc::now().timestamp()],
        )?;
        if let Some(s) = sth {
            conn.execute(
                "UPDATE kt_pins SET sth_tree_size = ?2, sth_root_hash = ?3, sth_timestamp = ?4, \
                 sth_signature = ?5 WHERE server = ?1",
                params![
                    base,
                    i64::try_from(s.tree_size).unwrap_or(i64::MAX),
                    s.root_hash,
                    s.timestamp,
                    s.signature
                ],
            )?;
        }
        Ok(())
    }

    /// [`Engine::kt_audit_with`] with the configured server and the stored pin.
    pub async fn kt_audit(&self, email: &str) -> Result<KtAuditReport> {
        self.kt_audit_with(email, &KtAuditOptions::default()).await
    }

    /// Audit the key-transparency log for one of our accounts: verify the signed tree head
    /// with the pinned log key (pinned on first use, or `opts.kt_key`), its consistency with
    /// the last tree head this profile accepted, and that the newest entry for `email`
    /// publishes the account's current key (inclusion proof). Only a verified, consistent head
    /// is remembered for the next audit.
    pub async fn kt_audit_with(&self, email: &str, opts: &KtAuditOptions) -> Result<KtAuditReport> {
        let base = self.kt_base(opts.server.as_deref())?;
        let own = self.my_fingerprint(email)?;
        let pin = self.kt_pin(&base)?;
        let override_key = match opts.kt_key.as_deref() {
            Some(k) => Some(kt::parse_public_key(k).ok_or_else(|| {
                Error::InvalidInput("--kt-key must be a 32-byte Ed25519 key (hex or base64)".into())
            })?),
            None => None,
        };
        let pinned =
            override_key.or_else(|| pin.as_ref().and_then(|(k, _)| kt::parse_public_key(k)));
        let previous = pin.as_ref().and_then(|(_, s)| s.clone());
        let out = kt::audit(
            self.http(),
            &base,
            email,
            &own,
            pinned.as_ref(),
            previous.as_ref(),
        )
        .await;
        // Pin on first use (or the explicit override); advance the stored head only when it
        // verified and is consistent.
        if let Some(key) = override_key.or(pinned).or(out.served_key) {
            self.kt_save_pin(&base, &key, out.accepted.as_ref())?;
        }
        Ok(out.report)
    }

    /// One page of raw log entries (`GET /v1/kt/entries`).
    pub async fn kt_entries(
        &self,
        server: Option<&str>,
        start: u64,
        limit: u64,
    ) -> Result<KtEntriesPage> {
        let base = self.kt_base(server)?;
        let url = format!("{base}/v1/kt/entries?start={start}&limit={limit}");
        kt::get_json(self.http(), &url)
            .await
            .map_err(Error::Directory)
    }

    /// Directory lookups with `SEALBOX_KT_VERIFY_LOOKUPS=1`: use a directory key only if the
    /// log's newest entry for the address publishes exactly that key (inclusion-proven against
    /// a tree head signed by the pinned log key and consistent with the last one seen).
    pub(crate) async fn kt_lookup_ok(&self, address: &str, key: &PublicKey) -> bool {
        let on = std::env::var(KT_VERIFY_LOOKUPS_ENV)
            .map(|v| matches!(v.trim(), "1" | "true" | "yes"))
            .unwrap_or(false);
        if !on {
            return true;
        }
        let Ok(base) = self.kt_base(None) else {
            return false;
        };
        let pin = match self.kt_pin(&base) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("kt pin unreadable: {e}");
                return false;
            }
        };
        let pinned = pin.as_ref().and_then(|(k, _)| kt::parse_public_key(k));
        let previous = pin.as_ref().and_then(|(_, s)| s.clone());
        let out = kt::audit(
            self.http(),
            &base,
            address,
            &key.fingerprint(),
            pinned.as_ref(),
            previous.as_ref(),
        )
        .await;
        if let Some(k) = pinned.or(out.served_key) {
            if let Err(e) = self.kt_save_pin(&base, &k, out.accepted.as_ref()) {
                tracing::warn!("kt pin not saved: {e}");
            }
        }
        if !out.report.is_clean() {
            tracing::warn!(
                address,
                alerts = ?out.report.alerts,
                "directory key rejected: not proven by the key-transparency log"
            );
        }
        out.report.is_clean()
    }
}

/// The key-transparency wire format and the client-side verifier (RFC 6962 / RFC 9162 §2.1).
/// Kept free of engine state so independent code (the server's gate test) can run the exact
/// client checks.
pub mod kt {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    use super::{normalize_fingerprint, KtAuditReport};

    /// Domain-separation prefix of the signed tree head message.
    pub const STH_CONTEXT: &str = "sealbox-kt-sth-v1";

    /// One log leaf. Field order is alphabetical, which makes `serde_json::to_vec` of this
    /// struct the canonical JSON the leaf hash is computed over.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct KtEntry {
        /// `"publish"` or `"unpublish"`.
        pub action: String,
        /// Lower-case hex SHA-256 of the lower-cased address.
        pub email_hash: String,
        /// Upper-case hex fingerprint.
        pub fingerprint: String,
        /// Unix seconds.
        pub time: i64,
    }

    impl KtEntry {
        /// Canonical leaf bytes.
        pub fn leaf_bytes(&self) -> Vec<u8> {
            serde_json::to_vec(self).unwrap_or_default()
        }
        pub fn leaf_hash(&self) -> [u8; 32] {
            leaf_hash(&self.leaf_bytes())
        }
    }

    /// `GET /v1/kt/sth`.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SignedTreeHead {
        pub tree_size: u64,
        /// Lower-case hex.
        pub root_hash: String,
        pub timestamp: i64,
        /// Base64 Ed25519 signature over [`sth_signing_input`].
        pub signature: String,
    }

    /// `GET /v1/kt/key`.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct KtKey {
        pub algorithm: String,
        /// Hex.
        pub public_key: String,
    }

    /// `GET /v1/kt/proof/by-email/{email}`.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct InclusionProof {
        pub tree_size: u64,
        pub leaf_index: u64,
        /// The newest entry for the address within `tree_size`.
        pub entry: KtEntry,
        pub leaf_hash: String,
        pub audit_path: Vec<String>,
        pub sth: SignedTreeHead,
    }

    /// `GET /v1/kt/consistency?from=&to=`.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ConsistencyProof {
        pub from: u64,
        pub to: u64,
        pub proof: Vec<String>,
    }

    /// One entry of `GET /v1/kt/entries`.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct KtIndexedEntry {
        pub index: u64,
        pub entry: KtEntry,
        pub leaf_hash: String,
    }

    /// `GET /v1/kt/entries?start=&limit=`.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct KtEntriesPage {
        pub tree_size: u64,
        pub start: u64,
        pub entries: Vec<KtIndexedEntry>,
    }

    fn sha256(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    /// RFC 6962 leaf hash: `SHA-256(0x00 || data)`.
    pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
        sha256(&[&[0u8], data])
    }

    /// RFC 6962 interior node: `SHA-256(0x01 || left || right)`.
    pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        sha256(&[&[1u8], left, right])
    }

    /// Root of the empty tree: `SHA-256("")`.
    pub fn empty_root() -> [u8; 32] {
        sha256(&[])
    }

    /// Lower-case hex SHA-256 of the trimmed, lower-cased address.
    pub fn email_hash(email: &str) -> String {
        to_hex(&sha256(&[email.trim().to_lowercase().as_bytes()]))
    }

    /// The bytes an STH signature covers.
    pub fn sth_signing_input(tree_size: u64, root_hex: &str, timestamp: i64) -> Vec<u8> {
        format!(
            "{STH_CONTEXT}\n{tree_size}\n{}\n{timestamp}\n",
            root_hex.to_ascii_lowercase()
        )
        .into_bytes()
    }

    pub fn to_hex(b: &[u8]) -> String {
        const D: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            s.push(D[(x >> 4) as usize] as char);
            s.push(D[(x & 15) as usize] as char);
        }
        s
    }

    pub fn from_hex(s: &str) -> Option<Vec<u8>> {
        let s = s.trim();
        if !s.len().is_multiple_of(2) {
            return None;
        }
        (0..s.len())
            .step_by(2)
            .map(|i| s.get(i..i + 2).and_then(|p| u8::from_str_radix(p, 16).ok()))
            .collect()
    }

    pub fn hash32(s: &str) -> Option<[u8; 32]> {
        from_hex(s).and_then(|v| v.try_into().ok())
    }

    /// A 32-byte Ed25519 public key from hex or base64.
    pub fn parse_public_key(s: &str) -> Option<[u8; 32]> {
        use base64::Engine as _;
        hash32(s).or_else(|| {
            base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .ok()
                .and_then(|v| v.try_into().ok())
        })
    }

    /// Verify an STH signature with `key`.
    pub fn verify_sth(sth: &SignedTreeHead, key: &[u8; 32]) -> bool {
        use base64::Engine as _;
        let Ok(vk) = VerifyingKey::from_bytes(key) else {
            return false;
        };
        let Some(sig) = base64::engine::general_purpose::STANDARD
            .decode(sth.signature.trim())
            .ok()
            .and_then(|v| <[u8; 64]>::try_from(v).ok())
        else {
            return false;
        };
        if hash32(&sth.root_hash).is_none() {
            return false;
        }
        let msg = sth_signing_input(sth.tree_size, &sth.root_hash, sth.timestamp);
        vk.verify(&msg, &Signature::from_bytes(&sig)).is_ok()
    }

    /// RFC 9162 §2.1.3.2: verify that `leaf` is entry `index` of the tree of `size` with `root`.
    pub fn verify_inclusion(
        index: u64,
        size: u64,
        leaf: &[u8; 32],
        path: &[[u8; 32]],
        root: &[u8; 32],
    ) -> bool {
        if index >= size {
            return false;
        }
        let (mut fnode, mut snode) = (index, size - 1);
        let mut r = *leaf;
        for p in path {
            if snode == 0 {
                return false;
            }
            if fnode & 1 == 1 || fnode == snode {
                r = node_hash(p, &r);
                if fnode & 1 == 0 {
                    while fnode & 1 == 0 && fnode != 0 {
                        fnode >>= 1;
                        snode >>= 1;
                    }
                }
            } else {
                r = node_hash(&r, p);
            }
            fnode >>= 1;
            snode >>= 1;
        }
        snode == 0 && &r == root
    }

    /// RFC 9162 §2.1.4.2: verify that the tree of size `second` with `second_root` extends the
    /// tree of size `first` with `first_root`.
    pub fn verify_consistency(
        first: u64,
        second: u64,
        first_root: &[u8; 32],
        second_root: &[u8; 32],
        proof: &[[u8; 32]],
    ) -> bool {
        if first > second {
            return false;
        }
        if first == second {
            return proof.is_empty() && first_root == second_root;
        }
        if first == 0 {
            return proof.is_empty() && first_root == &empty_root();
        }
        if proof.is_empty() {
            return false;
        }
        let mut path: Vec<[u8; 32]> = proof.to_vec();
        if first.is_power_of_two() {
            path.insert(0, *first_root);
        }
        let (mut fnode, mut snode) = (first - 1, second - 1);
        while fnode & 1 == 1 {
            fnode >>= 1;
            snode >>= 1;
        }
        let (mut fr, mut sr) = (path[0], path[0]);
        for c in &path[1..] {
            if snode == 0 {
                return false;
            }
            if fnode & 1 == 1 || fnode == snode {
                fr = node_hash(c, &fr);
                sr = node_hash(c, &sr);
                if fnode & 1 == 0 {
                    while fnode & 1 == 0 && fnode != 0 {
                        fnode >>= 1;
                        snode >>= 1;
                    }
                }
            } else {
                sr = node_hash(&sr, c);
            }
            fnode >>= 1;
            snode >>= 1;
        }
        &fr == first_root && &sr == second_root && snode == 0
    }

    fn hashes(v: &[String]) -> Option<Vec<[u8; 32]>> {
        v.iter().map(|s| hash32(s)).collect()
    }

    /// Check an inclusion proof as served: the entry's leaf hash is recomputed locally (the
    /// server's `leaf_hash` is not trusted) and proven against `sth`.
    pub fn check_inclusion(proof: &InclusionProof, sth: &SignedTreeHead) -> bool {
        let (Some(root), Some(path)) = (hash32(&sth.root_hash), hashes(&proof.audit_path)) else {
            return false;
        };
        proof.tree_size == sth.tree_size
            && verify_inclusion(
                proof.leaf_index,
                sth.tree_size,
                &proof.entry.leaf_hash(),
                &path,
                &root,
            )
    }

    /// Check a served consistency proof between two heads.
    pub fn check_consistency(
        old: &SignedTreeHead,
        new: &SignedTreeHead,
        proof: &ConsistencyProof,
    ) -> bool {
        let (Some(a), Some(b), Some(p)) = (
            hash32(&old.root_hash),
            hash32(&new.root_hash),
            hashes(&proof.proof),
        ) else {
            return false;
        };
        proof.from == old.tree_size
            && proof.to == new.tree_size
            && verify_consistency(old.tree_size, new.tree_size, &a, &b, &p)
    }

    /// GET a JSON document; `Err` carries a printable reason, `Ok(None)` on 404.
    pub(crate) async fn get_json_opt<T: serde::de::DeserializeOwned>(
        http: &reqwest::Client,
        url: &str,
    ) -> Result<Option<T>, String> {
        let resp = http
            .get(url)
            .send()
            .await
            .map_err(|e| format!("{url}: {e}"))?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(format!("{url} answered {}", resp.status()));
        }
        resp.json::<T>()
            .await
            .map(Some)
            .map_err(|e| format!("{url}: bad JSON: {e}"))
    }

    pub(crate) async fn get_json<T: serde::de::DeserializeOwned>(
        http: &reqwest::Client,
        url: &str,
    ) -> Result<T, String> {
        get_json_opt(http, url)
            .await?
            .ok_or_else(|| format!("{url}: not found"))
    }

    /// Result of [`audit`].
    #[derive(Clone, Debug, Default)]
    pub struct AuditOutcome {
        pub report: KtAuditReport,
        /// The key the server presented at `/v1/kt/key` (for TOFU pinning).
        pub served_key: Option<[u8; 32]>,
        /// The head to remember: set only when it verified and is consistent.
        pub accepted: Option<SignedTreeHead>,
    }

    /// The client audit, independent of any profile: fetch and verify the STH (with `pinned`,
    /// or the served key on first use), check consistency with `previous`, and prove that the
    /// newest log entry for `email` publishes `expected_fingerprint`.
    pub async fn audit(
        http: &reqwest::Client,
        base: &str,
        email: &str,
        expected_fingerprint: &str,
        pinned: Option<&[u8; 32]>,
        previous: Option<&SignedTreeHead>,
    ) -> AuditOutcome {
        let base = base.trim_end_matches('/');
        let mut out = AuditOutcome::default();
        let alerts = &mut out.report.alerts;

        match get_json::<KtKey>(http, &format!("{base}/v1/kt/key")).await {
            Ok(k) => out.served_key = parse_public_key(&k.public_key),
            Err(e) => alerts.push(format!("log key unavailable: {e}")),
        }
        let key = match (pinned, out.served_key.as_ref()) {
            (Some(p), Some(s)) if p != s => {
                alerts.push(format!(
                    "the log's signing key changed: the server now presents {}, the pinned key is {}; \
                     tree heads are checked against the pinned key",
                    to_hex(s),
                    to_hex(p)
                ));
                Some(*p)
            }
            (Some(p), _) => Some(*p),
            (None, s) => s.copied(),
        };
        let Some(key) = key else {
            return out;
        };
        let sth = match get_json::<SignedTreeHead>(http, &format!("{base}/v1/kt/sth")).await {
            Ok(s) => s,
            Err(e) => {
                out.report
                    .alerts
                    .push(format!("tree head unavailable: {e}"));
                return out;
            }
        };
        out.report.log_size = sth.tree_size;
        out.report.sth_verified = verify_sth(&sth, &key);
        if !out.report.sth_verified {
            out.report.alerts.push(
                "the signed tree head does not verify with the pinned log key: the server may be \
                 presenting a forged log"
                    .into(),
            );
        }

        // Consistency with the last head this client accepted.
        out.report.consistency_ok = match previous {
            None => true,
            Some(prev) if prev.tree_size > sth.tree_size => {
                out.report.alerts.push(format!(
                    "the log shrank from {} to {} entries: entries were removed or the server forked the log",
                    prev.tree_size, sth.tree_size
                ));
                false
            }
            Some(prev) if prev.tree_size == sth.tree_size => {
                let same = prev.root_hash.eq_ignore_ascii_case(&sth.root_hash);
                if !same {
                    out.report.alerts.push(format!(
                        "the log of size {} now has a different root than before: the server rewrote history (fork)",
                        sth.tree_size
                    ));
                }
                same
            }
            Some(prev) => {
                let url = format!(
                    "{base}/v1/kt/consistency?from={}&to={}",
                    prev.tree_size, sth.tree_size
                );
                let ok = match get_json::<ConsistencyProof>(http, &url).await {
                    Ok(p) => check_consistency(prev, &sth, &p),
                    Err(e) => {
                        out.report
                            .alerts
                            .push(format!("consistency proof unavailable: {e}"));
                        false
                    }
                };
                if !ok {
                    out.report.alerts.push(format!(
                        "the log is not an append-only extension of the head of size {} seen before: possible fork",
                        prev.tree_size
                    ));
                }
                ok
            }
        };

        // Inclusion of our key.
        let encoded =
            percent_encoding::utf8_percent_encode(email.trim(), percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        let url = format!(
            "{base}/v1/kt/proof/by-email/{encoded}?tree_size={}",
            sth.tree_size
        );
        let want_fp = normalize_fingerprint(expected_fingerprint).unwrap_or_default();
        match get_json_opt::<InclusionProof>(http, &url).await {
            Ok(None) => out.report.alerts.push(format!(
                "{} has no entry in the log (the key was never published to this directory)",
                email.trim()
            )),
            Err(e) => out
                .report
                .alerts
                .push(format!("inclusion proof unavailable: {e}")),
            Ok(Some(p)) => {
                let proven = p.entry.email_hash == email_hash(email) && check_inclusion(&p, &sth);
                let fp = normalize_fingerprint(&p.entry.fingerprint).unwrap_or_default();
                if !proven {
                    out.report.alerts.push(format!(
                        "the inclusion proof for {} does not verify against the tree head",
                        email.trim()
                    ));
                } else if p.entry.action != "publish" {
                    out.report.alerts.push(format!(
                        "the log says {} was unpublished (key {fp}) at {}",
                        email.trim(),
                        p.entry.time
                    ));
                } else if fp != want_fp {
                    out.report.alerts.push(format!(
                        "SUBSTITUTION: the log says {} is published with key {fp}, expected {want_fp}",
                        email.trim()
                    ));
                }
                out.report.own_key_included = proven
                    && out.report.sth_verified
                    && p.entry.action == "publish"
                    && fp == want_fp
                    && !want_fp.is_empty();
            }
        }
        if out.report.sth_verified && out.report.consistency_ok {
            out.accepted = Some(sth);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::kt::*;
    use super::*;

    /// The RFC 6962 reference leaves used by the certificate-transparency test suites.
    fn ct_leaves() -> Vec<Vec<u8>> {
        vec![
            vec![],
            vec![0x00],
            vec![0x10],
            vec![0x20, 0x21],
            vec![0x30, 0x31],
            vec![0x40, 0x41, 0x42, 0x43],
            vec![0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
            (0x60..=0x6f).collect(),
        ]
    }

    /// Reference tree construction (RFC 6962 §2.1), independent of the verifier.
    fn mth(l: &[[u8; 32]]) -> [u8; 32] {
        match l.len() {
            0 => empty_root(),
            1 => l[0],
            n => {
                let k = split(n);
                node_hash(&mth(&l[..k]), &mth(&l[k..]))
            }
        }
    }
    fn split(n: usize) -> usize {
        let mut k = 1;
        while k * 2 < n {
            k *= 2;
        }
        k
    }
    fn path(m: usize, l: &[[u8; 32]]) -> Vec<[u8; 32]> {
        if l.len() <= 1 {
            return vec![];
        }
        let k = split(l.len());
        if m < k {
            let mut p = path(m, &l[..k]);
            p.push(mth(&l[k..]));
            p
        } else {
            let mut p = path(m - k, &l[k..]);
            p.push(mth(&l[..k]));
            p
        }
    }
    fn subproof(m: usize, l: &[[u8; 32]], b: bool) -> Vec<[u8; 32]> {
        let n = l.len();
        if m == n {
            return if b { vec![] } else { vec![mth(l)] };
        }
        let k = split(n);
        if m <= k {
            let mut p = subproof(m, &l[..k], b);
            p.push(mth(&l[k..]));
            p
        } else {
            let mut p = subproof(m - k, &l[k..], false);
            p.push(mth(&l[..k]));
            p
        }
    }

    #[test]
    fn rfc6962_known_roots() {
        let hs: Vec<[u8; 32]> = ct_leaves().iter().map(|l| leaf_hash(l)).collect();
        let want = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        for (i, w) in want.iter().enumerate() {
            assert_eq!(to_hex(&mth(&hs[..=i])), *w, "root of size {}", i + 1);
        }
        assert_eq!(
            to_hex(&empty_root()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn inclusion_and_consistency_all_sizes() {
        let hs: Vec<[u8; 32]> = (0..33u32).map(|i| leaf_hash(&i.to_be_bytes())).collect();
        for n in 1..=hs.len() {
            let root = mth(&hs[..n]);
            for m in 0..n {
                let p = path(m, &hs[..n]);
                assert!(verify_inclusion(m as u64, n as u64, &hs[m], &p, &root));
                // Wrong leaf, wrong index, wrong root, truncated path all fail.
                assert!(!verify_inclusion(
                    m as u64,
                    n as u64,
                    &hs[(m + 1) % 33],
                    &p,
                    &root
                ));
                if n > 1 {
                    assert!(!verify_inclusion(
                        ((m + 1) % n) as u64,
                        n as u64,
                        &hs[m],
                        &p,
                        &root
                    ));
                    assert!(!verify_inclusion(
                        m as u64,
                        n as u64,
                        &hs[m],
                        &p[1..],
                        &root
                    ));
                }
                assert!(!verify_inclusion(m as u64, n as u64, &hs[m], &p, &[7; 32]));
            }
            assert!(!verify_inclusion(n as u64, n as u64, &hs[0], &[], &root));
            for m in 1..=n {
                let proof = subproof(m, &hs[..n], true);
                let old = mth(&hs[..m]);
                assert!(
                    verify_consistency(m as u64, n as u64, &old, &root, &proof),
                    "consistency {m} -> {n}"
                );
                if m < n {
                    assert!(!verify_consistency(
                        m as u64, n as u64, &[9; 32], &root, &proof
                    ));
                    assert!(!verify_consistency(
                        m as u64, n as u64, &old, &[9; 32], &proof
                    ));
                    assert!(!verify_consistency(n as u64, m as u64, &root, &old, &proof));
                }
            }
        }
    }

    #[test]
    fn sth_signature_round_trip() {
        use base64::Engine as _;
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let root = to_hex(&[3u8; 32]);
        let sig = sk.sign(&sth_signing_input(5, &root, 1_700_000_000));
        let mut sth = SignedTreeHead {
            tree_size: 5,
            root_hash: root,
            timestamp: 1_700_000_000,
            signature: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        };
        assert!(verify_sth(&sth, &pk));
        assert!(!verify_sth(&sth, &[1u8; 32]));
        sth.tree_size = 6;
        assert!(!verify_sth(&sth, &pk));
        sth.tree_size = 5;
        sth.root_hash = to_hex(&[4u8; 32]);
        assert!(!verify_sth(&sth, &pk));
    }

    #[test]
    fn canonical_leaf_and_hashes() {
        let e = KtEntry {
            action: "publish".into(),
            email_hash: email_hash(" Alice@Example.org "),
            fingerprint: "ABCD".into(),
            time: 7,
        };
        let s = String::from_utf8(e.leaf_bytes()).unwrap();
        assert_eq!(
            s,
            format!(
                "{{\"action\":\"publish\",\"email_hash\":\"{}\",\"fingerprint\":\"ABCD\",\"time\":7}}",
                email_hash("alice@example.org")
            )
        );
        assert_eq!(email_hash("alice@example.org").len(), 64);
    }

    #[test]
    fn qr_payloads() {
        let fp = "0123456789abcdef0123456789ABCDEF01234567";
        let p = qr_payload_for(fp).unwrap();
        assert_eq!(p, "OPENPGP4FPR:0123456789ABCDEF0123456789ABCDEF01234567");
        assert_eq!(parse_qr_payload(&p).unwrap(), fp.to_ascii_uppercase());
        assert_eq!(
            parse_qr_payload("openpgp4fpr:0123456789ABCDEF0123456789ABCDEF01234567#a=x%40y.z&n=X")
                .unwrap(),
            fp.to_ascii_uppercase()
        );
        assert!(parse_qr_payload("OPENPGP4FPR:1234").is_err());
        assert!(parse_qr_payload("mailto:x@y.z").is_err());
        assert!(parse_qr_payload("").is_err());
        assert_eq!(
            normalize_fingerprint("0123 4567 89AB CDEF 0123  4567 89AB CDEF 0123 4567").as_deref(),
            Some("0123456789ABCDEF0123456789ABCDEF01234567")
        );
    }

    // ----- key-change alerts through the real receive pipeline -----------------------------

    use crate::engine::EngineConfig;
    use crate::store::NewAccount;
    use crate::types::{AuthKind, ListQuery};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use chrono::TimeZone;
    use sealbox_crypto::{encrypt_and_sign_armored, minimal_key_for_autocrypt, Identity};
    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::mime::{
        autocrypt_header_value, build_pgp_mime_encrypted, build_plain, InnerOptions, Mailbox,
        MessageDraft, OuterHeaders,
    };
    use sealbox_mail::Security;

    struct Fx {
        _dir: tempfile::TempDir,
        engine: Engine,
        acct: AccountRow,
        folder: FolderRow,
        alice: Identity,
    }

    fn fx() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        let alice = Identity::generate("Alice", "alice@example.org").unwrap();
        let (acct, folder) = {
            let store = engine.store();
            let id = store
                .insert_account(&NewAccount {
                    email: "alice@example.org",
                    display_name: "Alice",
                    imap: &Endpoint::new("127.0.0.1", 143, Security::Plain),
                    smtp: &Endpoint::new("127.0.0.1", 25, Security::Plain),
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
            (
                store.account_by_id(id).unwrap().unwrap(),
                store.folder(id, "INBOX").unwrap(),
            )
        };
        Fx {
            _dir: dir,
            engine,
            acct,
            folder,
            alice,
        }
    }

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 1 + day, 12, 0, 0).unwrap()
    }

    fn draft(bob: &Identity, day: u32, subject: &str) -> MessageDraft {
        let mut d = MessageDraft::new(
            Mailbox::named("Bob", "bob@example.org"),
            vec![Mailbox::new("alice@example.org")],
            subject,
            "body\n",
        );
        d.date = at(day).timestamp();
        let keydata = minimal_key_for_autocrypt(bob).unwrap();
        d.extra_headers.push((
            "Autocrypt".into(),
            autocrypt_header_value("bob@example.org", true, &B64.encode(&keydata)),
        ));
        d
    }

    fn receive(f: &Fx, uid: u32, raw: &[u8], day: u32) -> SignatureSummary {
        let mut ctx = f.engine.sync_context(&f.acct).unwrap();
        let p = f
            .engine
            .process_message(&mut ctx, &f.acct, &f.folder, uid, raw, vec![], at(day))
            .unwrap();
        f.engine
            .store()
            .insert_message(&p.message)
            .unwrap()
            .unwrap();
        p.message.signature
    }

    fn bob(f: &Fx) -> Contact {
        f.engine.contact_for("bob@example.org").unwrap()
    }

    #[test]
    fn key_change_alert_ack_and_verify() {
        let f = fx();
        let bob1 = Identity::generate("Bob", "bob@example.org").unwrap();
        let bob2 = Identity::generate("Bob", "bob@example.org").unwrap();
        let bob3 = Identity::generate("Bob", "bob@example.org").unwrap();

        // First contact: trust on first use, no alert.
        let s = receive(&f, 1, &build_plain(&draft(&bob1, 1, "one")).unwrap(), 1);
        assert!(!s.key_changed);
        let c = bob(&f);
        assert_eq!(c.fingerprint.as_deref(), Some(bob1.fingerprint().as_str()));
        assert!(c.key_changed_at.is_none() && !c.verified);

        // Same key again: nothing.
        let s = receive(&f, 2, &build_plain(&draft(&bob1, 2, "two")).unwrap(), 2);
        assert!(!s.key_changed);

        // A new key: alert on the message and the contact.
        let s = receive(&f, 3, &build_plain(&draft(&bob2, 3, "three")).unwrap(), 3);
        assert!(s.key_changed);
        let c = bob(&f);
        assert!(c.key_changed_at.is_some());
        assert_eq!(
            c.previous_fingerprint.as_deref(),
            Some(bob1.fingerprint().as_str())
        );
        assert_eq!(c.fingerprint.as_deref(), Some(bob2.fingerprint().as_str()));
        let listed = f
            .engine
            .list_messages(ListQuery {
                account: None,
                folder: Some("INBOX".into()),
                folder_role: None,
                limit: 10,
            })
            .unwrap();
        let three = listed
            .iter()
            .find(|m| m.subject.as_deref() == Some("three"))
            .unwrap();
        assert!(three.signature.key_changed);
        assert!(
            f.engine
                .get_message(three.id)
                .unwrap()
                .summary
                .signature
                .key_changed
        );
        assert!(listed
            .iter()
            .filter(|m| m.subject.as_deref() != Some("three"))
            .all(|m| !m.signature.key_changed));

        // Later mail with the new key: the message is fine, the contact keeps the alert.
        let s = receive(&f, 4, &build_plain(&draft(&bob2, 4, "four")).unwrap(), 4);
        assert!(!s.key_changed);
        assert!(bob(&f).key_changed_at.is_some());

        // Verification must match the current key.
        assert!(f
            .engine
            .verify_contact("bob@example.org", &bob1.fingerprint())
            .is_err());
        assert!(bob(&f).key_changed_at.is_some() && !bob(&f).verified);
        let qr = qr_payload_for(&bob2.fingerprint()).unwrap();
        let c = f.engine.verify_contact("Bob@Example.org", &qr).unwrap();
        assert!(c.verified && c.verified_at.is_some());
        assert!(c.key_changed_at.is_none() && c.previous_fingerprint.is_none());

        // An encrypted message signed by the verified key → signer_verified.
        let d = draft(&bob2, 5, "five");
        let inner = sealbox_mail::mime::render_inner_for_encryption(
            &d,
            &InnerOptions {
                gossip_headers: vec![],
                legacy_display: false,
            },
        )
        .unwrap();
        let armored =
            encrypt_and_sign_armored(&inner, &[&f.alice.public(), &bob2.public()], Some(&bob2))
                .unwrap();
        let raw = build_pgp_mime_encrypted(&OuterHeaders::for_protected(&d), &armored).unwrap();
        let s = receive(&f, 5, &raw, 5);
        assert_eq!(s.status, SigState::Good);
        assert!(s.signer_verified && !s.key_changed);

        // Another key change: verification no longer applies, alert until acknowledged.
        let s = receive(&f, 6, &build_plain(&draft(&bob3, 6, "six")).unwrap(), 6);
        assert!(s.key_changed);
        let c = bob(&f);
        assert!(!c.verified && c.key_changed_at.is_some());
        assert_eq!(
            c.previous_fingerprint.as_deref(),
            Some(bob2.fingerprint().as_str())
        );
        let c = f.engine.acknowledge_key_change("bob@example.org").unwrap();
        assert!(c.key_changed_at.is_none() && !c.verified);
        let c = f.engine.unverify_contact("bob@example.org").unwrap();
        assert!(!c.verified);
        assert!(f
            .engine
            .acknowledge_key_change("nobody@example.org")
            .is_err());

        // Re-processing an already stored UID keeps the verdict it got the first time.
        let mut ctx = f.engine.sync_context(&f.acct).unwrap();
        let p = f
            .engine
            .process_message(
                &mut ctx,
                &f.acct,
                &f.folder,
                3,
                &build_plain(&draft(&bob2, 3, "three")).unwrap(),
                vec![],
                at(3),
            )
            .unwrap();
        assert!(p.message.signature.key_changed);
    }

    #[test]
    fn qr_payload_of_own_account() {
        let f = fx();
        let p = f
            .engine
            .fingerprint_qr_payload("alice@example.org")
            .unwrap();
        assert_eq!(
            p,
            format!("OPENPGP4FPR:{}", f.alice.fingerprint().to_ascii_uppercase())
        );
        assert_eq!(
            Engine::parse_fingerprint_qr(&p).unwrap(),
            f.alice.fingerprint().to_ascii_uppercase()
        );
    }
}
