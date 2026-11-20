//! Saved drafts on the server: the account's IMAP Drafts role folder holds one copy of each
//! draft, PGP/MIME encrypted and signed to the account's own key only, so other devices with
//! the same key see them (`drafts.rs`, "On the server", has the model). This is the MIME and
//! IMAP half: building and opening a server copy, replacing and deleting copies, and the sync.

use std::collections::{HashMap, HashSet};

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::OsRng;
use rusqlite::{params, OptionalExtension};
use sealbox_crypto::{decrypt_and_verify, encrypt_and_sign_armored, Identity};
use sealbox_mail::imap::{FlagOp, FolderRole, ImapClient};
use sealbox_mail::mime::{
    build_pgp_mime_encrypted, parse, parse_decrypted_inner, render_inner_for_encryption,
    Attachment, InnerOptions, Mailbox, MessageDraft, MessageKind, OuterHeaders,
};
use serde::{Deserialize, Serialize};

use crate::drafts::{DraftAttachment, DraftRecord, FromServer, SavedDraft};
use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::signature::ComposeKind;
use crate::store::{AccountRow, Store};
use crate::types::{GuestMode, SendPolicy};

/// Header of a server copy naming the draft (its uuid).
pub const DRAFT_HEADER: &str = "X-Sealbox-Draft";
/// Header of a server copy with the number of file references that stayed on the device
/// that saved it (only present when there are some).
pub const DRAFT_FILES_HEADER: &str = "X-Sealbox-Draft-Files";
const MANIFEST_TYPE: &str = "application/x-sealbox-draft+json";
/// How long the tombstone of a draft deleted or sent here (or deleted elsewhere) is kept:
/// while it is, a copy of that draft that re-appears on the server (a stale device, an old
/// copy replayed into the mailbox) is deleted again instead of being imported as new.
pub(crate) const TOMBSTONE_DAYS: i64 = 90;
const MANIFEST_NAME: &str = "sealbox-draft.json";

/// A fresh random (version 4) uuid for a draft.
pub(crate) fn new_uuid() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// What [`Engine::sync_drafts`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftSyncReport {
    pub account: String,
    /// The Drafts role folder.
    pub folder: String,
    /// Local drafts written to the server (new here, or changed here since the last sync).
    pub uploaded: usize,
    /// Server drafts this device did not have.
    pub imported: usize,
    /// Local drafts replaced by a newer server copy.
    pub updated: usize,
    /// Local drafts deleted because their server copy was deleted elsewhere (sent or
    /// discarded on another device) and they were not edited here since the last sync.
    pub removed_locally: usize,
    /// Server copies deleted: of drafts deleted or sent here, and older duplicates.
    pub removed_on_server: usize,
    /// Sealbox drafts on the server this device cannot open: encrypted to another key, or
    /// not signed by the account's own key. Never imported, never deleted.
    pub unreadable: usize,
}

/// The server state of one draft ([`Engine::draft_server_info`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftServerInfo {
    pub uuid: String,
    /// `local`: saved on this device first; `server`: imported from the Drafts folder.
    pub origin: String,
    /// A copy of the draft has been written to or read from the server.
    pub on_server: bool,
    /// Edited here since the server copy was written or read (the next push / sync uploads).
    pub pending: bool,
    /// File references the saving device kept local: they are not in the server copy.
    pub remote_files: usize,
}

/// One attachment part of a server copy (the stored blobs, in order).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestFile {
    name: String,
    content_type: String,
}

/// Every field of a draft, inside the encryption (JSON part of the server copy).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Manifest {
    v: u32,
    uuid: String,
    kind: ComposeKind,
    #[serde(default)]
    in_reply_to: Option<String>,
    #[serde(default)]
    forward_of: Option<String>,
    #[serde(default)]
    quote: bool,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    #[serde(default)]
    bcc: Vec<String>,
    subject: String,
    body_text: String,
    #[serde(default)]
    files: Vec<ManifestFile>,
    #[serde(default)]
    local_files: usize,
    policy: SendPolicy,
    guest_mode: GuestMode,
    #[serde(default)]
    guest_recipient_hint: Option<String>,
    #[serde(default)]
    no_signature: bool,
    created_at: i64,
    updated_at: i64,
}

/// A stored blob going into a server copy: name, type, bytes.
type BlobPart = (String, String, Vec<u8>);

/// The server copy of draft `d` (uuid `uuid`) for `account`: the raw RFC 5322 bytes.
fn build_server_copy(
    account: &str,
    identity: &Identity,
    uuid: &str,
    d: &SavedDraft,
    blobs: Vec<BlobPart>,
) -> Result<Vec<u8>> {
    let local_files = d.attachments.iter().filter(|a| a.blob_id.is_none()).count();
    let manifest = Manifest {
        v: 1,
        uuid: uuid.to_string(),
        kind: d.kind,
        in_reply_to: d.in_reply_to.clone(),
        forward_of: d.forward_of.clone(),
        quote: d.quote,
        references: d.references.clone(),
        to: d.to.clone(),
        cc: d.cc.clone(),
        bcc: d.bcc.clone(),
        subject: d.subject.clone(),
        body_text: d.body_text.clone(),
        files: blobs
            .iter()
            .map(|(name, content_type, _)| ManifestFile {
                name: name.clone(),
                content_type: content_type.clone(),
            })
            .collect(),
        local_files,
        policy: d.policy,
        guest_mode: d.guest_mode,
        guest_recipient_hint: d.guest_recipient_hint.clone(),
        no_signature: d.no_signature,
        created_at: d.created_at,
        updated_at: d.updated_at,
    };
    // No recipients in any header (they may be incomplete, and stay inside the manifest).
    let mut md = MessageDraft::new(
        Mailbox::new(account.to_string()),
        Vec::new(),
        d.subject.clone(),
        d.body_text.clone(),
    );
    md.date = d.updated_at;
    md.attachments.push(Attachment::new(
        MANIFEST_NAME,
        MANIFEST_TYPE,
        serde_json::to_vec(&manifest)?,
    ));
    for (name, content_type, bytes) in blobs {
        let content_type = if content_type.is_empty() {
            "application/octet-stream".to_string()
        } else {
            content_type
        };
        md.attachments
            .push(Attachment::new(name, content_type, bytes));
    }
    let inner = render_inner_for_encryption(&md, &InnerOptions::default())?;
    let own = identity.public();
    let armored = encrypt_and_sign_armored(&inner, &[&own], Some(identity))?;
    let mut outer = OuterHeaders::for_protected(&md);
    outer
        .extra_headers
        .push((DRAFT_HEADER.to_string(), uuid.to_string()));
    if local_files > 0 {
        outer
            .extra_headers
            .push((DRAFT_FILES_HEADER.to_string(), local_files.to_string()));
    }
    Ok(build_pgp_mime_encrypted(&outer, &armored)?)
}

/// The value of header `name` in `raw` (first occurrence, unfolded, trimmed).
pub(crate) fn header_value(raw: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let head = text
        .split("\r\n\r\n")
        .next()
        .unwrap_or_default()
        .split("\n\n")
        .next()
        .unwrap_or_default()
        .replace("\r\n", "\n");
    let mut value: Option<String> = None;
    for line in head.split('\n') {
        if let Some(v) = value.as_mut() {
            if line.starts_with([' ', '\t']) {
                v.push(' ');
                v.push_str(line.trim());
                continue;
            }
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                value = Some(v.trim().to_string());
            }
        }
    }
    value
}

/// A server copy opened with the account's key: its manifest and blob bytes, in order.
#[derive(Debug)]
struct OpenedCopy {
    manifest: Manifest,
    files: Vec<Vec<u8>>,
}

/// Open a server copy: PGP/MIME, decrypts with `identity`, signed by it (a copy anyone else
/// encrypted to this key is refused), a manifest with the header's uuid, one part per file.
fn open_server_copy(
    raw: &[u8],
    uuid: &str,
    identity: &Identity,
) -> std::result::Result<OpenedCopy, String> {
    let parsed = parse(raw).map_err(|e| e.to_string())?;
    let MessageKind::PgpMimeEncrypted { ciphertext } = parsed.kind else {
        return Err("not PGP/MIME encrypted".into());
    };
    let own = identity.public();
    let dec = decrypt_and_verify(&ciphertext, &[identity], &[&own]).map_err(|e| e.to_string())?;
    if !dec.signed_by_known_key() {
        return Err("not signed by the account's own key".into());
    }
    let inner = parse_decrypted_inner(&dec.plaintext).map_err(|e| e.to_string())?;
    let mut manifest: Option<Manifest> = None;
    let mut files = Vec::new();
    for a in inner.body.attachments {
        let is_manifest = a
            .content_type
            .split(';')
            .next()
            .is_some_and(|t| t.trim().eq_ignore_ascii_case(MANIFEST_TYPE));
        if is_manifest && manifest.is_none() {
            manifest = Some(serde_json::from_slice(&a.data).map_err(|e| e.to_string())?);
        } else {
            files.push(a.data);
        }
    }
    let manifest = manifest.ok_or("no draft manifest")?;
    if manifest.uuid != uuid {
        return Err("manifest uuid differs from the header".into());
    }
    if manifest.files.len() != files.len() {
        return Err("attachment parts do not match the manifest".into());
    }
    Ok(OpenedCopy { manifest, files })
}

/// A `draft_sync` row.
#[derive(Clone, Debug)]
struct SyncRow {
    uuid: String,
    account_id: i64,
    draft_id: Option<i64>,
    origin: String,
    local_rev: i64,
    synced_rev: i64,
    server_updated_at: Option<i64>,
    remote_files: i64,
}

impl SyncRow {
    fn pending(&self) -> bool {
        self.local_rev > self.synced_rev
    }
}

const SYNC_COLUMNS: &str = "uuid, account_id, draft_id, origin, local_rev, synced_rev, \
     server_updated_at, remote_files";

fn sync_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SyncRow> {
    Ok(SyncRow {
        uuid: r.get(0)?,
        account_id: r.get(1)?,
        draft_id: r.get(2)?,
        origin: r.get(3)?,
        local_rev: r.get(4)?,
        synced_rev: r.get(5)?,
        server_updated_at: r.get(6)?,
        remote_files: r.get(7)?,
    })
}

impl Store {
    /// Every draft of `account_id` gets a `draft_sync` row (drafts saved before rows existed).
    fn ensure_sync_rows(&self, account_id: i64) -> Result<()> {
        self.migrate_draft_sync()?;
        let missing: Vec<i64> = {
            let mut stmt = self.conn().prepare(
                "SELECT d.id FROM drafts d LEFT JOIN draft_sync s ON s.draft_id = d.id \
                 WHERE d.account_id = ?1 AND s.uuid IS NULL",
            )?;
            let rows = stmt.query_map(params![account_id], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for id in missing {
            self.conn().execute(
                "INSERT INTO draft_sync (uuid, account_id, draft_id) VALUES (?1, ?2, ?3)",
                params![new_uuid(), account_id, id],
            )?;
        }
        Ok(())
    }

    fn sync_rows(&self, account_id: i64) -> Result<Vec<SyncRow>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {SYNC_COLUMNS} FROM draft_sync WHERE account_id = ?1 ORDER BY uuid"
        ))?;
        let rows = stmt.query_map(params![account_id], sync_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    fn sync_row_by_uuid(&self, uuid: &str) -> Result<Option<SyncRow>> {
        Ok(self
            .conn()
            .query_row(
                &format!("SELECT {SYNC_COLUMNS} FROM draft_sync WHERE uuid = ?1"),
                params![uuid],
                sync_row,
            )
            .optional()?)
    }

    fn sync_row_of_draft(&self, draft_id: i64) -> Result<Option<SyncRow>> {
        Ok(self
            .conn()
            .query_row(
                &format!("SELECT {SYNC_COLUMNS} FROM draft_sync WHERE draft_id = ?1"),
                params![draft_id],
                sync_row,
            )
            .optional()?)
    }

    /// The copy of revision `rev` (draft time `updated_at`) is on the server.
    fn mark_pushed(&self, uuid: &str, rev: i64, updated_at: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE draft_sync SET synced_rev = MAX(synced_rev, ?2), server_updated_at = ?3 \
             WHERE uuid = ?1",
            params![uuid, rev, updated_at],
        )?;
        Ok(())
    }

    /// `draft_sync.deleted_at` arrived after the table did: add it to an older table.
    fn migrate_draft_sync(&self) -> Result<()> {
        let has: bool = self.conn().query_row(
            "SELECT EXISTS (SELECT 1 FROM pragma_table_info('draft_sync') \
             WHERE name = 'deleted_at')",
            [],
            |r| r.get(0),
        )?;
        if !has {
            self.conn()
                .execute_batch("ALTER TABLE draft_sync ADD COLUMN deleted_at INTEGER")?;
        }
        Ok(())
    }

    /// Keep tombstone `uuid` (its first-seen time): a copy of it that re-appears is deleted.
    fn keep_tombstone(&self, uuid: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE draft_sync SET draft_id = NULL, deleted_at = COALESCE(deleted_at, ?2) \
             WHERE uuid = ?1",
            params![uuid, crate::store::now()],
        )?;
        Ok(())
    }

    /// Forget `account_id`'s tombstones older than [`TOMBSTONE_DAYS`].
    fn prune_tombstones(&self, account_id: i64) -> Result<()> {
        self.conn().execute(
            "DELETE FROM draft_sync WHERE account_id = ?1 AND draft_id IS NULL \
             AND deleted_at IS NOT NULL AND deleted_at < ?2",
            params![account_id, crate::store::now() - TOMBSTONE_DAYS * 86_400],
        )?;
        Ok(())
    }

    /// Tombstones whose server copies are still to be removed (not yet kept).
    fn unpurged_tombstones(&self, account_id: i64) -> Result<Vec<SyncRow>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {SYNC_COLUMNS} FROM draft_sync WHERE account_id = ?1 \
             AND draft_id IS NULL AND deleted_at IS NULL"
        ))?;
        let rows = stmt.query_map(params![account_id], sync_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

/// Mark `uids` `\Deleted` in the selected folder and expunge exactly those (`UID EXPUNGE`
/// with UIDPLUS; a plain `EXPUNGE` otherwise).
async fn remove_uids(client: &mut ImapClient, uids: &[u32]) -> Result<()> {
    if uids.is_empty() {
        return Ok(());
    }
    client.set_flags(uids, FlagOp::Add, &["\\Deleted"]).await?;
    if client.has_capability("UIDPLUS") {
        client.uid_expunge(uids).await?;
    } else {
        client.expunge().await?;
    }
    Ok(())
}

/// UIDs of the Sealbox drafts in the selected folder: the copies of `uuid`, or every draft
/// (`None`, a zero-length `HEADER` search: RFC 3501 §6.4.4). A server that refuses the
/// `HEADER` search is asked for every UID, and the headers are checked here instead.
async fn sealbox_uids(client: &mut ImapClient, uuid: Option<&str>) -> Result<Vec<u32>> {
    let value = uuid.unwrap_or_default();
    if !value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Ok(Vec::new());
    }
    match client
        .uid_search(&format!("HEADER {DRAFT_HEADER} \"{value}\""))
        .await
    {
        Ok(uids) => Ok(uids),
        Err(e) => {
            tracing::info!("HEADER search refused ({e}); checking every message's headers");
            let all = client.uid_search("ALL").await?;
            let mut out = Vec::new();
            for chunk in all.chunks(100) {
                for m in client.fetch_rfc822_batch(chunk).await? {
                    let found = header_value(&m.raw, DRAFT_HEADER);
                    if found.is_some_and(|v| uuid.is_none_or(|u| v == u)) {
                        out.push(m.uid);
                    }
                }
            }
            Ok(out)
        }
    }
}

/// UIDs of the server copies of draft `uuid` in the selected folder.
async fn copies_of(client: &mut ImapClient, uuid: &str) -> Result<Vec<u32>> {
    if uuid.is_empty() {
        return Ok(Vec::new());
    }
    sealbox_uids(client, Some(uuid)).await
}

impl Engine {
    /// The account's Drafts role folder, created when the server has none.
    async fn drafts_folder(&self, acct: &AccountRow, client: &mut ImapClient) -> Result<String> {
        self.resolve_folder_live(acct, client, FolderRole::Drafts, true)
            .await
    }

    /// The server copy of draft `d` with uuid `uuid` (its blobs unsealed into it).
    fn server_copy(&self, acct: &AccountRow, uuid: &str, d: &SavedDraft) -> Result<Vec<u8>> {
        let (_, identity) = self.identity_for(acct)?;
        let mut blobs = Vec::new();
        for a in &d.attachments {
            if let Some(blob) = a.blob_id {
                let (info, data) = self.get_draft_blob(blob)?;
                let name = if a.name.is_empty() {
                    info.filename
                } else {
                    a.name.clone()
                };
                let content_type = if a.content_type.is_empty() {
                    info.content_type
                } else {
                    a.content_type.clone()
                };
                blobs.push((name, content_type, data));
            }
        }
        build_server_copy(&acct.email, &identity, uuid, d, blobs)
    }

    /// Write draft `d`'s current version to the selected Drafts `folder`: APPEND the new copy
    /// (`\Draft`), then delete and expunge the copies that were there before.
    async fn push_locked(
        &self,
        acct: &AccountRow,
        client: &mut ImapClient,
        folder: &str,
        d: &SavedDraft,
    ) -> Result<()> {
        let row = {
            let store = self.store();
            store.ensure_sync_rows(acct.id)?;
            store
                .sync_row_of_draft(d.id)?
                .ok_or_else(|| Error::InvalidInput(format!("draft {} has no sync row", d.id)))?
        };
        let raw = self.server_copy(acct, &row.uuid, d)?;
        client.select(folder).await?;
        let old = copies_of(client, &row.uuid).await?;
        client.append(folder, &raw, &["\\Draft", "\\Seen"]).await?;
        remove_uids(client, &old).await?;
        self.store()
            .mark_pushed(&row.uuid, row.local_rev, d.updated_at)?;
        Ok(())
    }

    /// Put draft `id`'s current version on the server (the account's Drafts role folder),
    /// replacing its earlier copy: what a save does next. Takes the account's mailbox lock.
    pub async fn push_draft(&self, id: i64) -> Result<()> {
        let d = self.get_draft(id)?;
        let acct = self.account_row(&d.account)?;
        let _guard = self.account_lock(acct.id).await;
        let mut client = self.imap_for(&acct).await?;
        let result = async {
            let folder = self.drafts_folder(&acct, &mut client).await?;
            self.push_locked(&acct, &mut client, &folder, &d).await
        }
        .await;
        let _ = client.logout().await;
        result
    }

    /// Delete the server copies of drafts deleted or sent on this device (their tombstones);
    /// returns how many copies went. Tombstones of drafts that never reached the server need
    /// no connection. Tombstones are kept ([`TOMBSTONE_DAYS`]), so a copy that re-appears is
    /// deleted again by the next sync. `send_draft` runs it once the mail is out.
    pub async fn purge_deleted_drafts(&self, email: &str) -> Result<usize> {
        let acct = self.account_row(email)?;
        let tombs: Vec<SyncRow> = {
            let store = self.store();
            store.migrate_draft_sync()?;
            store.prune_tombstones(acct.id)?;
            let mut out = Vec::new();
            for r in store.unpurged_tombstones(acct.id)? {
                if r.server_updated_at.is_none() {
                    store.keep_tombstone(&r.uuid)?;
                } else {
                    out.push(r);
                }
            }
            out
        };
        if tombs.is_empty() {
            return Ok(0);
        }
        let _guard = self.account_lock(acct.id).await;
        let mut client = self.imap_for(&acct).await?;
        let result = async {
            let folder = self.drafts_folder(&acct, &mut client).await?;
            client.select(&folder).await?;
            let mut n = 0;
            for t in &tombs {
                let uids = copies_of(&mut client, &t.uuid).await?;
                remove_uids(&mut client, &uids).await?;
                n += uids.len();
                self.store().keep_tombstone(&t.uuid)?;
            }
            Ok(n)
        }
        .await;
        let _ = client.logout().await;
        result
    }

    /// The server state of draft `id` (`None` for an unknown id).
    pub fn draft_server_info(&self, id: i64) -> Result<Option<DraftServerInfo>> {
        Ok(self
            .store()
            .sync_row_of_draft(id)?
            .map(|r| DraftServerInfo {
                pending: r.pending(),
                on_server: r.server_updated_at.is_some(),
                remote_files: usize::try_from(r.remote_files).unwrap_or(0),
                origin: r.origin,
                uuid: r.uuid,
            }))
    }

    /// Two-way sync of `email`'s drafts with its Drafts role folder (created when missing):
    /// imports server drafts this device does not have, takes a newer server copy, uploads
    /// local changes, removes the server copies of drafts deleted or sent here, and deletes a
    /// local draft whose server copy disappeared if it was not edited here since the last
    /// sync. Takes the account's mailbox lock.
    pub async fn sync_drafts(&self, email: &str) -> Result<DraftSyncReport> {
        let acct = self.account_row(email)?;
        let _guard = self.account_lock(acct.id).await;
        let mut client = self.imap_for(&acct).await?;
        let result = async {
            let folder = self.drafts_folder(&acct, &mut client).await?;
            self.sync_drafts_locked(&acct, &mut client, &folder).await
        }
        .await;
        let _ = client.logout().await;
        result
    }

    /// [`Engine::sync_drafts`] on a connected client, the account lock held by the caller.
    pub(crate) async fn sync_drafts_locked(
        &self,
        acct: &AccountRow,
        client: &mut ImapClient,
        folder: &str,
    ) -> Result<DraftSyncReport> {
        let mut report = DraftSyncReport {
            account: acct.email.clone(),
            folder: folder.to_string(),
            ..DraftSyncReport::default()
        };
        let (_, identity) = self.identity_for(acct)?;
        client.select(folder).await?;
        let uids = sealbox_uids(client, None).await?;
        let mut server: HashMap<String, (u32, OpenedCopy)> = HashMap::new();
        let mut doomed: Vec<u32> = Vec::new();
        for m in client.fetch_rfc822_batch(&uids).await? {
            let Some(uuid) = header_value(&m.raw, DRAFT_HEADER) else {
                continue;
            };
            let copy = match open_server_copy(&m.raw, &uuid, &identity) {
                Ok(c) => c,
                Err(e) => {
                    tracing::info!(uid = m.uid, "a draft on the server cannot be opened: {e}");
                    report.unreadable += 1;
                    continue;
                }
            };
            // De-duplicate by uuid: the newest copy stays, older ones go.
            match server.remove(&uuid) {
                Some((uid, kept))
                    if (kept.manifest.updated_at, uid) > (copy.manifest.updated_at, m.uid) =>
                {
                    doomed.push(m.uid);
                    server.insert(uuid, (uid, kept));
                }
                Some((uid, _)) => {
                    doomed.push(uid);
                    server.insert(uuid, (m.uid, copy));
                }
                None => {
                    server.insert(uuid, (m.uid, copy));
                }
            }
        }
        report.removed_on_server += doomed.len();
        // Copies a Drafts role sync stored before they were marked: never listed as mail.
        {
            let store = self.store();
            let mut mark = store.conn().prepare_cached(
                "INSERT OR IGNORE INTO draft_copies (message_id) SELECT m.id FROM messages m \
                 JOIN folders f ON f.id = m.folder_id \
                 WHERE f.account_id = ?1 AND f.name = ?2 AND m.uid = ?3",
            )?;
            for uid in &uids {
                mark.execute(params![acct.id, folder, i64::from(*uid)])?;
            }
        }
        self.store().ensure_sync_rows(acct.id)?;
        let mut seen: HashSet<String> = HashSet::new();
        for (uuid, (uid, copy)) in server {
            seen.insert(uuid.clone());
            let row = self.store().sync_row_by_uuid(&uuid)?;
            match row {
                Some(r) if r.account_id != acct.id => {
                    doomed.push(uid); // the draft moved to another account
                    report.removed_on_server += 1;
                }
                Some(r) if r.draft_id.is_none() => {
                    doomed.push(uid); // deleted or sent here (or a stale copy coming back)
                    report.removed_on_server += 1;
                    self.store().keep_tombstone(&uuid)?;
                }
                Some(r) => {
                    let draft_id = r.draft_id.unwrap_or_default();
                    let local = self.get_draft(draft_id)?;
                    let server_newer = r
                        .server_updated_at
                        .is_none_or(|t| copy.manifest.updated_at > t);
                    if server_newer && (!r.pending() || copy.manifest.updated_at > local.updated_at)
                    {
                        self.apply_server_copy(acct, Some(&local), &copy)?;
                        report.updated += 1;
                    } else if r.pending() {
                        let local = self.get_draft(draft_id)?;
                        self.push_locked(acct, client, folder, &local).await?;
                        report.uploaded += 1;
                    }
                }
                None => {
                    self.apply_server_copy(acct, None, &copy)?;
                    report.imported += 1;
                }
            }
        }
        let rows = self.store().sync_rows(acct.id)?;
        for r in rows.into_iter().filter(|r| !seen.contains(&r.uuid)) {
            match r.draft_id {
                None => self.store().keep_tombstone(&r.uuid)?,
                Some(id) if r.server_updated_at.is_some() && !r.pending() => {
                    // Its server copy was deleted elsewhere and nothing changed here.
                    self.store().remove_draft(id)?;
                    self.store().keep_tombstone(&r.uuid)?;
                    report.removed_locally += 1;
                }
                Some(id) => {
                    let d = self.get_draft(id)?;
                    self.push_locked(acct, client, folder, &d).await?;
                    report.uploaded += 1;
                }
            }
        }
        client.select(folder).await?;
        remove_uids(client, &doomed).await?;
        self.store().prune_tombstones(acct.id)?;
        Ok(report)
    }

    /// Store a server copy as a local draft: new (`local = None`) or replacing `local`'s
    /// fields and blobs; `local`'s file references stay (they never travel).
    fn apply_server_copy(
        &self,
        acct: &AccountRow,
        local: Option<&SavedDraft>,
        copy: &OpenedCopy,
    ) -> Result<()> {
        let m = &copy.manifest;
        let mut attachments = Vec::new();
        for (f, bytes) in m.files.iter().zip(&copy.files) {
            let blob = self.put_draft_blob(&acct.email, &f.name, &f.content_type, bytes)?;
            attachments.push(DraftAttachment {
                path: String::new(),
                blob_id: Some(blob),
                name: f.name.clone(),
                content_type: f.content_type.clone(),
            });
        }
        if let Some(d) = local {
            attachments.extend(
                d.attachments
                    .iter()
                    .filter(|a| a.blob_id.is_none())
                    .cloned(),
            );
        }
        let record = DraftRecord {
            account_id: acct.id,
            kind: m.kind,
            in_reply_to: m.in_reply_to.clone(),
            forward_of: m.forward_of.clone(),
            quote: m.quote,
            references: m.references.clone(),
            to: m.to.clone(),
            cc: m.cc.clone(),
            bcc: m.bcc.clone(),
            subject: m.subject.clone(),
            body_text: m.body_text.clone(),
            attachments,
            policy: m.policy,
            guest_mode: m.guest_mode,
            guest_recipient_hint: m.guest_recipient_hint.clone(),
            no_signature: m.no_signature,
            from_server: Some(FromServer {
                uuid: m.uuid.clone(),
                created_at: m.created_at,
                updated_at: m.updated_at,
                remote_files: i64::try_from(m.local_files).unwrap_or(i64::MAX),
            }),
        };
        let store = self.store();
        store.upsert_draft(local.map(|d| d.id), &record)?;
        // The blobs the replaced version held, unless still referenced.
        if let Some(d) = local {
            let referenced: HashSet<i64> = store
                .drafts(None)?
                .iter()
                .flat_map(|x| x.attachments.iter().filter_map(|a| a.blob_id))
                .collect();
            for blob in d.attachments.iter().filter_map(|a| a.blob_id) {
                if !referenced.contains(&blob) {
                    store
                        .conn()
                        .execute("DELETE FROM draft_blobs WHERE id = ?1", params![blob])?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drafts::DraftInput;
    use crate::engine::EngineConfig;
    use crate::store::NewAccount;
    use crate::types::AuthKind;
    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::Security;

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /// A keyed engine with alice@example.org and her identity (no server).
    fn engine() -> (tempfile::TempDir, Engine, Identity) {
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        let alice = Identity::generate("Alice", "alice@example.org").unwrap();
        {
            let store = e.store();
            let ep = Endpoint::new("127.0.0.1", 9, Security::Plain);
            let id = store
                .insert_account(&NewAccount {
                    email: "alice@example.org",
                    display_name: "Alice",
                    imap: &ep,
                    smtp: &ep,
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
        (dir, e, alice)
    }

    #[test]
    fn uuids_are_random_v4() {
        let a = new_uuid();
        let b = new_uuid();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");
        assert!("89ab".contains(&a[19..20]), "{a}");
    }

    #[test]
    fn a_server_copy_is_sealed_to_the_own_key_and_round_trips() {
        let (dir, e, alice) = engine();
        let marker = format!("{:x<64}", "DRAFTSYNC-BODY-MARKER-");
        let subject = "Quarterly plan, not for the server";
        let blob = e
            .put_draft_blob(
                "alice@example.org",
                "plan.pdf",
                "application/pdf",
                b"%PDF-1.7 x",
            )
            .unwrap();
        let file = dir.path().join("local.txt");
        std::fs::write(&file, b"local only").unwrap();
        let d = e
            .save_draft(DraftInput {
                account: "alice@example.org".into(),
                to: vec!["bob@example.org".into(), "half-typed@".into()],
                bcc: vec!["secret-bcc@example.org".into()],
                subject: subject.into(),
                body_text: marker.clone(),
                attachments: vec![
                    DraftAttachment {
                        blob_id: Some(blob),
                        ..Default::default()
                    },
                    DraftAttachment {
                        path: file.to_string_lossy().into_owned(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            })
            .unwrap();
        let acct = e.account_row("alice@example.org").unwrap();
        let info = e.draft_server_info(d.id).unwrap().unwrap();
        assert_eq!(
            (info.origin.as_str(), info.on_server, info.pending),
            ("local", false, true)
        );
        let raw = e.server_copy(&acct, &info.uuid, &d).unwrap();
        // Nothing readable outside: no subject, body, recipients or file bytes.
        for needle in [
            subject.as_bytes(),
            marker.as_bytes(),
            b"bob@example.org".as_slice(),
            b"secret-bcc@example.org".as_slice(),
            b"%PDF-1.7".as_slice(),
            b"local only".as_slice(),
        ] {
            assert!(
                !contains(&raw, needle),
                "{} in the clear",
                String::from_utf8_lossy(needle)
            );
        }
        assert_eq!(header_value(&raw, DRAFT_HEADER), Some(info.uuid.clone()));
        assert_eq!(header_value(&raw, DRAFT_FILES_HEADER).as_deref(), Some("1"));
        assert_eq!(header_value(&raw, "subject").as_deref(), Some("..."));
        assert!(header_value(&raw, "to").is_none());
        assert!(contains(&raw, b"multipart/encrypted"));

        // The own key opens it: every field, the blob, the file count.
        let opened = open_server_copy(&raw, &info.uuid, &alice).unwrap();
        let m = &opened.manifest;
        assert_eq!(
            (m.subject.as_str(), m.body_text.as_str()),
            (subject, marker.as_str())
        );
        assert_eq!(m.to, d.to);
        assert_eq!(m.bcc, d.bcc);
        assert_eq!(m.local_files, 1);
        assert_eq!(m.updated_at, d.updated_at);
        assert_eq!(
            m.files,
            vec![ManifestFile {
                name: "plan.pdf".into(),
                content_type: "application/pdf".into()
            }]
        );
        assert_eq!(opened.files, vec![b"%PDF-1.7 x".to_vec()]);
        // Another key cannot; a copy under another uuid is refused.
        let mallory = Identity::generate("Mallory", "alice@example.org").unwrap();
        assert!(open_server_copy(&raw, &info.uuid, &mallory).is_err());
        assert!(open_server_copy(&raw, &new_uuid(), &alice).is_err());
        // A copy encrypted to Alice by someone else (not signed by her key) is refused.
        let forged = {
            let other = Identity::generate("Eve", "eve@example.org").unwrap();
            build_server_copy("alice@example.org", &other, &info.uuid, &d, Vec::new()).unwrap()
        };
        assert!(open_server_copy(&forged, &info.uuid, &alice).is_err());

        // Applying it on a second device (new draft) keeps uuid, times and the file count.
        let (_dir2, e2, _) = engine();
        let acct2 = e2.account_row("alice@example.org").unwrap();
        e2.apply_server_copy(&acct2, None, &opened).unwrap();
        let imported = e2.list_drafts(None).unwrap();
        assert_eq!(imported.len(), 1);
        let i = &imported[0];
        assert_eq!((i.subject.as_str(), i.updated_at), (subject, d.updated_at));
        assert_eq!(
            i.attachments.len(),
            1,
            "file references stay on the saving device"
        );
        let bytes = e2
            .get_draft_blob(i.attachments[0].blob_id.unwrap())
            .unwrap()
            .1;
        assert_eq!(bytes, b"%PDF-1.7 x");
        let info2 = e2.draft_server_info(i.id).unwrap().unwrap();
        assert_eq!(
            (
                info2.uuid.as_str(),
                info2.origin.as_str(),
                info2.pending,
                info2.remote_files
            ),
            (info.uuid.as_str(), "server", false, 1)
        );
        // A local edit there makes it pending; deleting leaves a tombstone.
        let mut again = DraftInput {
            id: Some(i.id),
            account: "alice@example.org".into(),
            subject: "edited".into(),
            ..Default::default()
        };
        again.attachments = i.attachments.clone();
        e2.save_draft(again).unwrap();
        assert!(e2.draft_server_info(i.id).unwrap().unwrap().pending);
        assert!(e2.delete_draft(i.id).unwrap());
        let tomb = e2.store().sync_row_by_uuid(&info.uuid).unwrap().unwrap();
        assert_eq!(tomb.draft_id, None);
    }

    #[test]
    fn header_values_unfold_and_ignore_the_body() {
        let raw = b"Subject: x\r\nX-Sealbox-Draft: abc-\r\n def\r\nTo: y\r\n\r\nX-Sealbox-Draft: body\r\n";
        assert_eq!(
            header_value(raw, "x-sealbox-draft").as_deref(),
            Some("abc- def")
        );
        assert_eq!(
            header_value(b"A: 1\n\nX-Sealbox-Draft: no\n", DRAFT_HEADER),
            None
        );
    }

    /// Store a received message in `folder` with `extra` headers; returns its id.
    fn store_message(e: &Engine, folder: &str, uid: u32, extra: &str, word: &str) -> i64 {
        use crate::store::NewMessage;
        use crate::types::{Address, SignatureSummary};
        let mut store = e.store();
        let account_id = store
            .account_by_email("alice@example.org")
            .unwrap()
            .unwrap()
            .id;
        let folder_id = store.folder(account_id, folder).unwrap().id;
        let raw =
            format!("From: Alice <alice@example.org>\r\nSubject: ...\r\n{extra}\r\n\r\n{word}\r\n");
        store
            .insert_message(&NewMessage {
                account_id,
                folder_id,
                uid,
                message_id: Some(format!("{word}@example.org")),
                from: Address {
                    name: None,
                    address: "alice@example.org".into(),
                },
                to: vec![],
                cc: vec![],
                subject: Some(format!("subject {word}")),
                protected_subject: false,
                date: Some(1_700_000_000),
                received_at: 1_700_000_000,
                flags: vec![],
                was_encrypted: false,
                decrypted: false,
                was_signed: false,
                signature: SignatureSummary::default(),
                signatures_json: "[]".into(),
                text: Some(format!("body {word}")),
                html: None,
                in_reply_to: vec![],
                references: vec![],
                decrypt_error: None,
                raw: raw.into_bytes(),
                attachments: vec![],
            })
            .unwrap()
            .unwrap()
    }

    /// The "shown twice" fix: a draft's server copy stored by a Drafts role sync is no
    /// message — not listed, not searched — while the same header elsewhere hides nothing.
    #[test]
    fn server_copies_stored_by_a_drafts_sync_are_not_listed_or_searched() {
        let (_dir, e, _) = engine();
        {
            let store = e.store();
            store
                .conn()
                .execute(
                    "INSERT INTO folder_roles (account_id, role, name, source, updated_at) \
                     VALUES (1, 'drafts', 'Drafts', 'list', 0)",
                    [],
                )
                .unwrap();
        }
        let header = format!("{DRAFT_HEADER}: {}", new_uuid());
        let copy = store_message(&e, "Drafts", 1, &header, "zebracopy");
        let plain_draft = store_message(&e, "Drafts", 2, "X-Other: 1", "zebradraft");
        let spoof = store_message(&e, "INBOX", 1, &header, "zebraspoof");
        let listed: Vec<i64> = e
            .list_messages(crate::types::ListQuery {
                folder: Some("*".into()),
                ..Default::default()
            })
            .unwrap()
            .iter()
            .map(|m| m.id)
            .collect();
        assert!(
            !listed.contains(&copy),
            "the server copy is listed: {listed:?}"
        );
        assert!(
            listed.contains(&plain_draft),
            "another client's draft stays a message"
        );
        assert!(
            listed.contains(&spoof),
            "the header outside Drafts hides nothing"
        );
        let found = |word: &str| {
            e.search(crate::search::SearchQuery {
                text: word.into(),
                folder: Some("*".into()),
                ..Default::default()
            })
            .unwrap()
            .len()
        };
        assert_eq!(found("zebracopy"), 0, "server copies are not indexed");
        assert_eq!((found("zebradraft"), found("zebraspoof")), (1, 1));
        // A copy stored before marking existed is marked by the next draft sync's backfill
        // (here: by hand, the same statement), and the index rebuild skips it.
        e.store()
            .conn()
            .execute("DELETE FROM draft_copies", [])
            .unwrap();
        e.store()
            .conn()
            .execute(
                "INSERT OR IGNORE INTO draft_copies (message_id) VALUES (?1)",
                params![copy],
            )
            .unwrap();
        e.rebuild_search_index().unwrap();
        assert_eq!(found("zebracopy"), 0);
        assert_eq!(found("zebraspoof"), 1);
    }

    #[test]
    fn saved_drafts_carry_their_origin_and_remote_files() {
        let (_dir, e, alice) = engine();
        let d = e
            .save_draft(DraftInput {
                account: "alice@example.org".into(),
                subject: "here".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            (d.origin, d.remote_files),
            (crate::drafts::DraftOrigin::Local, 0)
        );
        let acct = e.account_row("alice@example.org").unwrap();
        let uuid = new_uuid();
        let mut from_elsewhere = d.clone();
        from_elsewhere.attachments = vec![DraftAttachment {
            path: "/elsewhere/file.txt".into(),
            ..Default::default()
        }];
        let raw =
            build_server_copy(&acct.email, &alice, &uuid, &from_elsewhere, Vec::new()).unwrap();
        let opened = open_server_copy(&raw, &uuid, &alice).unwrap();
        e.apply_server_copy(&acct, None, &opened).unwrap();
        let imported = e
            .list_drafts(None)
            .unwrap()
            .into_iter()
            .find(|x| x.id != d.id)
            .unwrap();
        assert_eq!(
            (imported.origin, imported.remote_files),
            (crate::drafts::DraftOrigin::Server, 1)
        );
        let json = serde_json::to_value(&imported).unwrap();
        assert_eq!(
            (json["origin"].as_str(), json["remote_files"].as_u64()),
            (Some("server"), Some(1))
        );
    }

    #[tokio::test]
    async fn tombstones_of_drafts_never_on_the_server_go_without_a_connection() {
        let (_dir, e, _) = engine();
        let d = e
            .save_draft(DraftInput {
                account: "alice@example.org".into(),
                subject: "local only".into(),
                ..Default::default()
            })
            .unwrap();
        assert!(e.delete_draft(d.id).unwrap());
        // IMAP is port 9 (closed): this would fail if it tried to connect.
        assert_eq!(
            e.purge_deleted_drafts("alice@example.org").await.unwrap(),
            0
        );
        // The tombstone stays (a copy re-appearing under its uuid is deleted, not imported)
        // until it is TOMBSTONE_DAYS old.
        let rows = e.store().sync_rows(1).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].draft_id, None);
        let uuid = rows[0].uuid.clone();
        assert!(
            e.store().unpurged_tombstones(1).unwrap().is_empty(),
            "kept once purged"
        );
        e.store()
            .conn()
            .execute(
                "UPDATE draft_sync SET deleted_at = deleted_at - ?1 WHERE uuid = ?2",
                params![TOMBSTONE_DAYS * 86_400 + 1, uuid],
            )
            .unwrap();
        assert_eq!(
            e.purge_deleted_drafts("alice@example.org").await.unwrap(),
            0
        );
        assert!(
            e.store().sync_rows(1).unwrap().is_empty(),
            "pruned after TOMBSTONE_DAYS"
        );
    }
}
