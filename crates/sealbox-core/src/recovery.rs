//! Recovery and multi-device (gate G15): a 12-word recovery phrase, a client-encrypted backup
//! of the account on the Sealbox server, restore on a new device, and Autocrypt Setup Message
//! export/import (Delta Chat / Thunderbird interop). See `docs/RECOVERY.md`.
//!
//! Key material (nothing derived from the phrase is ever stored on the device):
//!
//! ```text
//! phrase   = 12 BIP39 English words (128 bits of OS randomness + 4-bit SHA-256 checksum)
//! norm     = the 12 words, lower case, single spaces
//! master   = Argon2id(norm, salt = "sealbox-recovery:" ‖ lower(email)), m = 64 MiB, t = 3, p = 1
//! key      = HKDF-SHA256(master, info = "sealbox-recovery-v1 backup-key")   → XChaCha20-Poly1305
//! token    = base64url(HKDF-SHA256(master, info = "sealbox-recovery-v1 backup-token"))
//! ```
//!
//! The server stores the backup under the account key's fingerprint
//! (`PUT /v1/backup/{fpr}`, detached signature by that key) and keeps only a hash of `token`.
//!
//! Bundle wire format (what the server stores):
//!
//! ```text
//! blob = "SBXR" ‖ 0x01 ‖ nonce (24) ‖ XChaCha20-Poly1305(key, nonce, deflate(JSON bundle), AAD) ‖ tag (16)
//! AAD  = "SBXR" ‖ 0x01 ‖ "|" ‖ lower(email) ‖ "|" ‖ FINGERPRINT
//! ```

use std::io::{Read, Write};
use std::sync::OnceLock;

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine as _;
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rusqlite::params;
use rusqlite::types::Value;
use sealbox_crypto::{
    setup_code_generate, setup_message_create, setup_message_open, sign_detached_binary, Identity,
    PeerState, PublicKey, AUTOCRYPT_SETUP_HEADER, AUTOCRYPT_SETUP_MIME_TYPE,
};
use sealbox_mail::autodiscover::Endpoint;
use sealbox_mail::mime::{
    self, build_plain, parse_autocrypt_header, Attachment, Mailbox, MessageDraft,
};
use sealbox_mail::ImapError;
use sealbox_spam::{BayesModel, FilterRule};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::directory;
use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::settings::SettingsScope;
use crate::store::{now, AccountRow, NewAccount, NewOutbox, Store};
use crate::transport;
use crate::types::{AccountInfo, AuthKind, AuthSpec, KeySource};

// ----- constants ----------------------------------------------------------------------------

/// Number of words in a recovery phrase.
pub const PHRASE_WORDS: usize = 12;
/// Salt prefix of the phrase KDF (the lower-cased address follows).
pub const KDF_SALT_PREFIX: &str = "sealbox-recovery:";
/// Argon2id memory cost (KiB), iterations, lanes — the same cost as the profile passphrase.
const ARGON2_M_KIB: u32 = 64 * 1024;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;
const HKDF_INFO_KEY: &[u8] = b"sealbox-recovery-v1 backup-key";
const HKDF_INFO_TOKEN: &[u8] = b"sealbox-recovery-v1 backup-token";
/// Magic and version of the encrypted bundle.
const MAGIC: &[u8; 4] = b"SBXR";
const WIRE_VERSION: u8 = 1;
/// Version of the JSON bundle inside.
pub const BUNDLE_VERSION: u32 = 1;
const BUNDLE_FORMAT: &str = "sealbox-recovery-bundle";
/// Decompression cap (a bundle is keys + settings; never this big).
const MAX_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;
/// Header names of `PUT /v1/backup/{fpr}` (see `sealbox-server/src/routes/backup.rs`).
const SIGNATURE_HEADER: &str = "X-Sealbox-Signature";
const KEY_HEADER: &str = "X-Sealbox-Key";
const TOKEN_HEADER: &str = "X-Sealbox-Backup-Token";
/// Account-scoped settings this module keeps (metadata only; never the phrase).
const SETTING_LAST_BACKUP: &str = "recovery.last_backup";
const SETTING_PHRASE_CREATED: &str = "recovery.phrase_created_at";
/// Settings never copied into a backup: runtime state and our own bookkeeping.
const SKIPPED_SETTINGS: &[&str] = &[
    crate::settings::KEY_AUTOREPLY_STATE,
    SETTING_LAST_BACKUP,
    SETTING_PHRASE_CREATED,
];
/// A backup older than this is flagged by [`Engine::backup_status`].
pub const BACKUP_REMINDER_SECS: i64 = 30 * 24 * 3600;
/// File name of the setup-message attachment (Delta Chat's name).
pub const SETUP_FILE_NAME: &str = "autocrypt-setup-message.html";
/// Subject of the setup message (what Delta Chat and Thunderbird use).
pub const SETUP_SUBJECT: &str = "Autocrypt Setup Message";
/// Newest messages per folder looked at when discovering the account key from the mailbox.
const DISCOVERY_SCAN: usize = 25;

const WORDLIST_TXT: &str = include_str!("bip39_english.txt");

// ----- public types -------------------------------------------------------------------------

/// A recovery phrase (contract: `docs/CONTRACTS_2026-10-27b.md`, "Recovery"). Created by
/// [`Engine::recovery_phrase_create`] and shown once; never stored. `Debug` redacts the words
/// and the words are wiped on drop.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPhrase {
    /// 12 words from the BIP39 English list, lower case.
    pub words: Vec<String>,
    /// The BIP39 checksum (last 4 bits) matches.
    pub checksum_ok: bool,
}

impl RecoveryPhrase {
    /// The words joined by single spaces (the normalised form the KDF takes).
    pub fn phrase(&self) -> Zeroizing<String> {
        Zeroizing::new(self.words.join(" "))
    }
}

impl std::fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryPhrase")
            .field(
                "words",
                &format_args!("<{} words redacted>", self.words.len()),
            )
            .field("checksum_ok", &self.checksum_ok)
            .finish()
    }
}

impl Drop for RecoveryPhrase {
    fn drop(&mut self) {
        for w in &mut self.words {
            w.zeroize();
        }
    }
}

/// Result of [`Engine::backup_to_server`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupReport {
    /// Fingerprint of the account key; the server slot is `/v1/backup/{fingerprint}`.
    pub fingerprint: String,
    /// Size of the encrypted blob as uploaded.
    pub bytes: u64,
    pub server_url: String,
    /// Unix seconds.
    pub created_at: i64,
}

/// What [`Engine::backup_status`] reports (local bookkeeping only; no network).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupStatus {
    pub email: String,
    /// The last successful backup made from this device, if any.
    pub last_backup: Option<BackupReport>,
    /// When a recovery phrase was last shown for this account on this device (unix seconds).
    pub phrase_created_at: Option<i64>,
    /// A reminder for the UI: no backup yet, or the last one is older than 30 days.
    pub reminder: Option<String>,
}

/// Options of [`Engine::backup_to_server_with`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupOptions {
    /// Also put the account's mail credential (app password or OAuth credential JSON) and
    /// `secret.*` settings into the bundle. Default `false`: see `docs/RECOVERY.md`.
    #[serde(default)]
    pub include_credentials: bool,
}

/// Options of [`Engine::restore_from_server_with`].
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreOptions {
    /// The backup slot (account key fingerprint). `None` = find it: the key directory on the
    /// same server (`/vks/v1/by-email`), then the `Autocrypt:` headers of our own mail in the
    /// mailbox (needs `credentials`).
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Mail credential to store with the restored account (and to test before anything is
    /// written). `None` = use the credential in the bundle if it has one, else none (the
    /// account then needs `Engine::set_account_credential` before it can sync).
    #[serde(default)]
    pub credentials: Option<AuthSpec>,
    /// Server overrides; `None` = the configuration stored in the backup.
    #[serde(default)]
    pub imap: Option<Endpoint>,
    #[serde(default)]
    pub smtp: Option<Endpoint>,
    #[serde(default)]
    pub login: Option<String>,
}

impl std::fmt::Debug for RestoreOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoreOptions")
            .field("fingerprint", &self.fingerprint)
            .field("credentials", &self.credentials)
            .field("imap", &self.imap)
            .field("smtp", &self.smtp)
            .field("login", &self.login)
            .finish()
    }
}

/// Result of [`Engine::setup_message_export`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupExport {
    /// The 36-digit setup code (`dddd-dddd-…`, 9 blocks). Show it on this device only.
    pub setup_code: String,
    /// Message-ID of the setup message mailed to ourselves (without angle brackets).
    pub message_id: String,
}

impl std::fmt::Debug for SetupExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupExport")
            .field("setup_code", &"<redacted>")
            .field("message_id", &self.message_id)
            .finish()
    }
}

// ----- BIP39 --------------------------------------------------------------------------------

fn wordlist() -> &'static [&'static str] {
    static LIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    LIST.get_or_init(|| {
        WORDLIST_TXT
            .lines()
            .map(str::trim)
            .filter(|w| !w.is_empty())
            .collect()
    })
}

/// 16 bytes of entropy → 12 words (BIP39: 128 bits ‖ first 4 bits of SHA-256).
pub fn entropy_to_words(entropy: &[u8; 16]) -> Vec<String> {
    let list = wordlist();
    let check = Sha256::digest(entropy)[0] >> 4;
    // 132 bits as a big-endian bit string: entropy then 4 checksum bits.
    let mut acc: u128 = u128::from_be_bytes(*entropy);
    let mut out = Vec::with_capacity(PHRASE_WORDS);
    // Take 11 bits at a time from the 132-bit value (128 entropy bits << 4 | check).
    for i in 0..PHRASE_WORDS {
        let shift = 132 - 11 * (i + 1);
        let idx = if shift >= 4 {
            ((acc >> (shift - 4)) & 0x7FF) as usize
        } else {
            // The last word: low 7 entropy bits + 4 checksum bits.
            (((acc & 0x7F) << 4) as usize) | usize::from(check)
        };
        out.push(list.get(idx).copied().unwrap_or("abandon").to_string());
    }
    acc.zeroize();
    out
}

/// Resolve one user-typed word: exact match, or a unique prefix of at least 4 letters (BIP39
/// words are unique in their first four letters).
fn resolve_word(token: &str) -> Option<(usize, &'static str)> {
    let list = wordlist();
    if let Ok(i) = list.binary_search(&token) {
        return Some((i, list[i]));
    }
    if token.len() >= 4 {
        let start = list.partition_point(|w| *w < token);
        let mut hits = list[start..].iter().take_while(|w| w.starts_with(token));
        if let (Some(w), None) = (hits.next(), hits.next()) {
            return Some((start, *w));
        }
    }
    None
}

/// Parse a typed phrase: split on anything that is not a letter, lower-case, resolve each word.
/// Errors name the problem (word count, unknown word); the checksum is reported, not enforced.
pub fn parse_phrase(input: &str) -> Result<(RecoveryPhrase, Option<Zeroizing<[u8; 16]>>)> {
    let lowered = Zeroizing::new(input.to_lowercase());
    let tokens: Vec<&str> = lowered
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.len() != PHRASE_WORDS {
        return Err(Error::InvalidInput(format!(
            "a recovery phrase has {PHRASE_WORDS} words; got {}",
            tokens.len()
        )));
    }
    let mut idx = [0usize; PHRASE_WORDS];
    let mut words = Vec::with_capacity(PHRASE_WORDS);
    for (n, t) in tokens.iter().enumerate() {
        match resolve_word(t) {
            Some((i, w)) => {
                idx[n] = i;
                words.push(w.to_string());
            }
            None => {
                return Err(Error::InvalidInput(format!(
                    "word {} of the recovery phrase is not in the word list",
                    n + 1
                )))
            }
        }
    }
    // 132 bits back: 128 entropy + 4 checksum.
    let mut acc: u128 = 0;
    for (n, i) in idx.iter().enumerate() {
        if n < PHRASE_WORDS - 1 {
            acc = (acc << 11) | (*i as u128);
        } else {
            acc = (acc << 7) | ((*i as u128) >> 4);
        }
    }
    let check = (idx[PHRASE_WORDS - 1] & 0xF) as u8;
    let entropy = Zeroizing::new(acc.to_be_bytes());
    acc.zeroize();
    idx.zeroize();
    let ok = Sha256::digest(entropy.as_ref())[0] >> 4 == check;
    Ok((
        RecoveryPhrase {
            words,
            checksum_ok: ok,
        },
        ok.then_some(entropy),
    ))
}

/// A phrase that is well-formed *and* passes the checksum, else `InvalidInput`.
fn checked_phrase(input: &str) -> Result<RecoveryPhrase> {
    let (p, _) = parse_phrase(input)?;
    if !p.checksum_ok {
        return Err(Error::InvalidInput(
            "the recovery phrase checksum does not match: a word is wrong or two words are swapped"
                .into(),
        ));
    }
    Ok(p)
}

// ----- KDF ----------------------------------------------------------------------------------

/// Keys derived from a phrase for one address.
pub(crate) struct RecoveryKeys {
    pub backup_key: Zeroizing<[u8; 32]>,
    /// The `X-Sealbox-Backup-Token` (43 URL-safe chars); the server keeps its SHA-256.
    pub token: Zeroizing<String>,
}

/// Argon2id → HKDF. `normalised` is [`RecoveryPhrase::phrase`].
pub(crate) fn derive_keys(normalised: &str, email: &str) -> Result<RecoveryKeys> {
    let salt = format!("{KDF_SALT_PREFIX}{}", email.trim().to_lowercase());
    let params = argon2::Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32))
        .map_err(|e| Error::InvalidInput(format!("argon2 params: {e}")))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut master = Zeroizing::new([0u8; 32]);
    a.hash_password_into(normalised.as_bytes(), salt.as_bytes(), master.as_mut())
        .map_err(|e| Error::InvalidInput(format!("argon2: {e}")))?;
    let hk = hkdf::Hkdf::<Sha256>::new(None, master.as_ref());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO_KEY, key.as_mut())
        .map_err(|e| Error::InvalidInput(format!("hkdf: {e}")))?;
    let mut tok = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO_TOKEN, tok.as_mut())
        .map_err(|e| Error::InvalidInput(format!("hkdf: {e}")))?;
    Ok(RecoveryKeys {
        backup_key: key,
        token: Zeroizing::new(B64URL.encode(tok.as_ref())),
    })
}

async fn derive_keys_blocking(
    normalised: Zeroizing<String>,
    email: String,
) -> Result<RecoveryKeys> {
    tokio::task::spawn_blocking(move || derive_keys(&normalised, &email))
        .await
        .map_err(|e| Error::InvalidInput(format!("key derivation task: {e}")))?
}

// ----- bundle -------------------------------------------------------------------------------

/// The account as stored in a bundle (servers, login; the credential only on request).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct BundleAccount {
    pub email: String,
    pub display_name: String,
    pub imap: Endpoint,
    pub smtp: Endpoint,
    pub auth_kind: AuthKind,
    pub login: String,
    #[serde(default)]
    pub credential: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct BundleIdentity {
    pub fingerprint: String,
    pub email: String,
    pub secret_armored: String,
    pub public_armored: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct BundleKey {
    pub addr: String,
    pub source: KeySource,
    pub fingerprint: String,
    pub armored: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct BundleSetting {
    pub scope: SettingsScope,
    pub key: String,
    /// The stored JSON value.
    pub value: serde_json::Value,
}

/// Rows of a contact-verification table (G30 keeps verified-contact marks in its own table;
/// any table whose name contains `verif` is carried over column by column).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct BundleTable {
    pub table: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
}

/// Bundle v1 (the JSON inside the encrypted blob).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Bundle {
    pub format: String,
    pub version: u32,
    pub created_at: i64,
    pub app: String,
    pub account: BundleAccount,
    /// The account's secret keys, primary first.
    pub identities: Vec<BundleIdentity>,
    /// Autocrypt peer states (every contact of the profile).
    pub peers: Vec<PeerState>,
    /// Imported / directory keys.
    pub keys: Vec<BundleKey>,
    #[serde(default)]
    pub verified: Vec<BundleTable>,
    /// Account and global settings: signature, auto-reply, spam settings, …
    pub settings: Vec<BundleSetting>,
    pub filter_rules: Vec<FilterRule>,
    /// The per-user Bayes spam model.
    #[serde(default)]
    pub spam_model_json: Option<String>,
}

fn aad(email: &str, fpr: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(48 + email.len());
    a.extend_from_slice(MAGIC);
    a.push(WIRE_VERSION);
    a.push(b'|');
    a.extend_from_slice(email.trim().to_lowercase().as_bytes());
    a.push(b'|');
    a.extend_from_slice(fpr.trim().to_ascii_uppercase().as_bytes());
    a
}

/// deflate + XChaCha20-Poly1305 with the wire header.
pub(crate) fn seal_bundle(key: &[u8; 32], email: &str, fpr: &str, json: &[u8]) -> Result<Vec<u8>> {
    let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(json)?;
    let compressed = Zeroizing::new(z.finish()?);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: compressed.as_slice(),
                aad: &aad(email, fpr),
            },
        )
        .map_err(|_| Error::SecretIntegrity("recovery bundle encryption failed".into()))?;
    let mut out = Vec::with_capacity(5 + nonce.len() + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(WIRE_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`seal_bundle`]; any tampering (header, nonce, ciphertext, other address or
/// fingerprint) fails with `SecretIntegrity`.
pub(crate) fn open_bundle(
    key: &[u8; 32],
    email: &str,
    fpr: &str,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < 5 + 24 + 16 || &blob[..4] != MAGIC {
        return Err(Error::SecretIntegrity(
            "not a Sealbox recovery bundle".into(),
        ));
    }
    if blob[4] != WIRE_VERSION {
        return Err(Error::InvalidInput(format!(
            "recovery bundle format {} is newer than this app understands; update Sealbox",
            blob[4]
        )));
    }
    let nonce = XNonce::from_slice(&blob[5..29]);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let compressed = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &blob[29..],
                    aad: &aad(email, fpr),
                },
            )
            .map_err(|_| {
                Error::SecretIntegrity(
                    "the recovery bundle failed authentication (wrong phrase or tampered backup)"
                        .into(),
                )
            })?,
    );
    let mut out = Zeroizing::new(Vec::new());
    flate2::read::DeflateDecoder::new(compressed.as_slice())
        .take(MAX_BUNDLE_BYTES + 1)
        .read_to_end(&mut out)?;
    if out.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(Error::InvalidInput("recovery bundle is too large".into()));
    }
    Ok(out)
}

fn spam_err(e: sealbox_spam::Error) -> Error {
    Error::InvalidInput(e.to_string())
}

/// Read a SQLite value as JSON (blobs are refused: verification marks are text/integers).
fn sql_to_json(v: Value) -> Option<serde_json::Value> {
    Some(match v {
        Value::Null => serde_json::Value::Null,
        Value::Integer(i) => serde_json::Value::from(i),
        Value::Real(f) => serde_json::Value::from(f),
        Value::Text(t) => serde_json::Value::String(t),
        Value::Blob(_) => return None,
    })
}

fn json_to_sql(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Integer(i64::from(*b)),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::Integer(i),
            None => Value::Real(n.as_f64().unwrap_or(0.0)),
        },
        serde_json::Value::String(s) => Value::Text(s.clone()),
        other => Value::Text(other.to_string()),
    }
}

fn ident_ok(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn table_columns(store: &Store, table: &str) -> Result<Vec<String>> {
    let mut stmt = store
        .conn()
        .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))?;
    let cols = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(cols)
}

fn verification_tables(store: &Store) -> Result<Vec<String>> {
    let mut stmt = store.conn().prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE '%verif%' ORDER BY name",
    )?;
    let names = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names.into_iter().filter(|n| ident_ok(n)).collect())
}

fn collect_verified(store: &Store) -> Result<Vec<BundleTable>> {
    let mut out = Vec::new();
    'tables: for table in verification_tables(store)? {
        let columns = table_columns(store, &table)?;
        if columns.is_empty() || !columns.iter().all(|c| ident_ok(c)) {
            continue;
        }
        let mut stmt = store
            .conn()
            .prepare(&format!("SELECT * FROM \"{table}\""))?;
        let n = columns.len();
        let raw = stmt
            .query_map([], |r| {
                (0..n)
                    .map(|i| r.get::<_, Value>(i))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut rows = Vec::with_capacity(raw.len());
        for r in raw {
            let mut row = Vec::with_capacity(n);
            for v in r {
                match sql_to_json(v) {
                    Some(j) => row.push(j),
                    None => continue 'tables, // a wrapped/binary column: not ours to copy
                }
            }
            rows.push(row);
        }
        out.push(BundleTable {
            table,
            columns,
            rows,
        });
    }
    Ok(out)
}

fn restore_verified(store: &Store, tables: &[BundleTable]) -> Result<()> {
    let local = verification_tables(store)?;
    for t in tables {
        if !local.iter().any(|l| l == &t.table) || !t.columns.iter().all(|c| ident_ok(c)) {
            tracing::info!(table = %t.table, "verification table not present here; skipped");
            continue;
        }
        let have = table_columns(store, &t.table)?;
        if !t.columns.iter().all(|c| have.contains(c)) {
            tracing::warn!(table = %t.table, "verification table has a different shape; skipped");
            continue;
        }
        let cols = t
            .columns
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let marks = vec!["?"; t.columns.len()].join(", ");
        let sql = format!(
            "INSERT OR REPLACE INTO \"{}\" ({cols}) VALUES ({marks})",
            t.table
        );
        for row in &t.rows {
            if row.len() != t.columns.len() {
                continue;
            }
            let vals: Vec<Value> = row.iter().map(json_to_sql).collect();
            store
                .conn()
                .execute(&sql, rusqlite::params_from_iter(vals.iter()))?;
        }
    }
    Ok(())
}

fn credential_for(auth: &AuthSpec) -> Result<(AuthKind, String)> {
    Ok(match auth {
        AuthSpec::Password { password } => (AuthKind::Password, password.clone()),
        AuthSpec::OAuth { .. } => (AuthKind::OAuth, serde_json::to_string(auth)?),
    })
}

/// The `Autocrypt-Setup-Message` header value of a raw mail, if any.
fn top_header(raw: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let head_end = text
        .find("\r\n\r\n")
        .or_else(|| text.find("\n\n"))
        .unwrap_or(text.len());
    let head = &text[..head_end];
    let prefix = format!("{}:", name.to_ascii_lowercase());
    head.lines()
        .find(|l| l.to_ascii_lowercase().starts_with(&prefix))
        .map(|l| l[prefix.len()..].trim().to_string())
}

fn setup_html(armored: &str) -> String {
    format!(
        "<!DOCTYPE html>\r\n<html>\r\n<head>\r\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\r\n\
         <title>Autocrypt Setup Message</title>\r\n</head>\r\n<body>\r\n<h1>Autocrypt Setup Message</h1>\r\n\
         <p>This is the Autocrypt Setup Message used to transfer your end-to-end encryption setup between clients.</p>\r\n\
         <p>To decrypt and use your setup, open this message in an Autocrypt-compliant client (Sealbox, Delta Chat, Thunderbird) \
         and enter the setup code shown on the device that created it.</p>\r\n<pre>\r\n{}\r\n</pre>\r\n</body>\r\n</html>\r\n",
        armored.trim().replace('\n', "\r\n").replace("\r\r\n", "\r\n")
    )
}

const SETUP_TEXT: &str = "This message contains all information to transfer your Autocrypt \
settings along with your secret key securely from your original device.\r\n\r\n\
To set up your new device for Autocrypt, please follow the instructions that should be \
presented by your new device.\r\n\r\n\
You can keep this message and use it as a backup for your secret key. If you want to do this, \
you should write down the setup code and store it securely.\r\n";

// ----- Engine API ---------------------------------------------------------------------------

impl Engine {
    /// A new 12-word recovery phrase for `email` from 128 bits of OS randomness. It is stored
    /// nowhere: show it once and let the user write it down. Only the time of creation is
    /// remembered (for the backup reminder).
    pub fn recovery_phrase_create(&self, email: &str) -> Result<RecoveryPhrase> {
        let acct = self.account_row(email)?;
        let mut entropy = Zeroizing::new([0u8; 16]);
        OsRng.fill_bytes(entropy.as_mut());
        let words = entropy_to_words(&entropy);
        self.store().set_setting(
            SettingsScope::Account,
            &acct.email,
            SETTING_PHRASE_CREATED,
            &now(),
        )?;
        Ok(RecoveryPhrase {
            words,
            checksum_ok: true,
        })
    }

    /// Check a typed phrase. `Err(InvalidInput)` for a wrong word count or a word outside the
    /// list (naming its position); otherwise the normalised words and whether the checksum
    /// matches. Accepts unique 4-letter prefixes, any case, any separators.
    pub fn recovery_phrase_validate(words: &str) -> Result<RecoveryPhrase> {
        Ok(parse_phrase(words)?.0)
    }

    /// [`Engine::backup_to_server_with`] with the default options (no credentials).
    pub async fn backup_to_server(
        &self,
        email: &str,
        server_url: &str,
        phrase: &str,
    ) -> Result<BackupReport> {
        self.backup_to_server_with(email, server_url, phrase, &BackupOptions::default())
            .await
    }

    /// Encrypt the account's keys, contacts and settings with the phrase and upload them to
    /// `PUT {server_url}/v1/backup/{fingerprint}`. A later run replaces the backup (and its
    /// token, so a new phrase invalidates the old one).
    pub async fn backup_to_server_with(
        &self,
        email: &str,
        server_url: &str,
        phrase: &str,
        opts: &BackupOptions,
    ) -> Result<BackupReport> {
        let phrase = checked_phrase(phrase)?;
        let server = server_url.trim().trim_end_matches('/').to_string();
        if !(server.starts_with("http://") || server.starts_with("https://")) {
            return Err(Error::InvalidInput(format!(
                "`{server_url}` is not an http(s) URL"
            )));
        }
        let acct = self.account_row(email)?;
        let (primary_row, identity) = self.identity_for(&acct)?;
        let fpr = primary_row.fingerprint.clone();
        let bundle = self.build_bundle(&acct, opts)?;
        let json = Zeroizing::new(serde_json::to_vec(&bundle)?);
        drop(bundle);
        let keys = derive_keys_blocking(phrase.phrase(), acct.email.clone()).await?;
        let blob = seal_bundle(&keys.backup_key, &acct.email, &fpr, &json)?;
        let sig = sign_detached_binary(&blob, &identity)?;
        let public = identity.public().to_armored()?;
        let url = format!("{server}/v1/backup/{fpr}");
        let resp = self
            .http()
            .put(&url)
            .header(SIGNATURE_HEADER, B64.encode(&sig))
            .header(KEY_HEADER, B64.encode(public.as_bytes()))
            .header(TOKEN_HEADER, keys.token.as_str())
            .header("Content-Type", "application/octet-stream")
            .body(blob.clone())
            .send()
            .await
            .map_err(|e| Error::Connection(format!("{url}: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Connection(format!(
                "backup server answered {status}: {}",
                body.chars().take(200).collect::<String>()
            )));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Connection(format!("{url}: bad JSON: {e}")))?;
        if body["backup_token"].as_str() != Some(keys.token.as_str()) {
            return Err(Error::Connection(
                "backup server did not accept the recovery token (older server?)".into(),
            ));
        }
        let report = BackupReport {
            fingerprint: fpr,
            bytes: blob.len() as u64,
            server_url: server,
            created_at: now(),
        };
        self.store().set_setting(
            SettingsScope::Account,
            &acct.email,
            SETTING_LAST_BACKUP,
            &report,
        )?;
        Ok(report)
    }

    /// Local backup bookkeeping for the account (no network): last backup and a reminder.
    pub fn backup_status(&self, email: &str) -> Result<BackupStatus> {
        let acct = self.account_row(email)?;
        let store = self.store();
        let last: Option<BackupReport> =
            store.get_setting(SettingsScope::Account, &acct.email, SETTING_LAST_BACKUP)?;
        let phrase_at: Option<i64> =
            store.get_setting(SettingsScope::Account, &acct.email, SETTING_PHRASE_CREATED)?;
        let reminder = match &last {
            None => Some(
                "No recovery backup yet: create a recovery phrase and back up, or you lose your \
                 encrypted mail with this device."
                    .to_string(),
            ),
            Some(b) if now() - b.created_at > BACKUP_REMINDER_SECS => Some(format!(
                "Your last recovery backup is {} days old: back up again so new contacts and \
                 settings are included.",
                (now() - b.created_at) / 86_400
            )),
            Some(_) => None,
        };
        Ok(BackupStatus {
            email: acct.email,
            last_backup: last,
            phrase_created_at: phrase_at,
            reminder,
        })
    }

    pub(crate) fn build_bundle(&self, acct: &AccountRow, opts: &BackupOptions) -> Result<Bundle> {
        let store = self.store();
        let identities = store
            .identities_for_account(acct.id)?
            .into_iter()
            .map(|i| BundleIdentity {
                fingerprint: i.fingerprint,
                email: i.email,
                secret_armored: i.secret_armored,
                public_armored: i.public_armored,
            })
            .collect::<Vec<_>>();
        if identities.is_empty() {
            return Err(Error::NoIdentity(acct.email.clone()));
        }
        let keys = store
            .all_keys()?
            .into_iter()
            .map(|k| BundleKey {
                addr: k.addr,
                source: k.source,
                fingerprint: k.fingerprint,
                armored: k.armored,
            })
            .collect();
        let mut settings = Vec::new();
        for (scope, account) in [
            (SettingsScope::Account, acct.email.as_str()),
            (SettingsScope::Global, ""),
        ] {
            for e in store.list_settings(scope, account)? {
                if SKIPPED_SETTINGS.contains(&e.key.as_str()) {
                    continue;
                }
                if crate::vault::is_secret_setting(&e.key) && !opts.include_credentials {
                    continue;
                }
                settings.push(BundleSetting {
                    scope,
                    key: e.key,
                    value: e.value,
                });
            }
        }
        let model = store.load_spam_model()?;
        let spam_model_json = if model.is_empty() {
            None
        } else {
            Some(model.to_json().map_err(spam_err)?)
        };
        Ok(Bundle {
            format: BUNDLE_FORMAT.into(),
            version: BUNDLE_VERSION,
            created_at: now(),
            app: concat!("sealbox-core/", env!("CARGO_PKG_VERSION")).into(),
            account: BundleAccount {
                email: acct.email.clone(),
                display_name: acct.display_name.clone(),
                imap: acct.imap.clone(),
                smtp: acct.smtp.clone(),
                auth_kind: acct.auth_kind,
                login: acct.login.clone(),
                credential: opts.include_credentials.then(|| acct.credential.clone()),
            },
            identities,
            peers: store.all_peers()?,
            keys,
            verified: collect_verified(&store)?,
            settings,
            filter_rules: store.list_filter_rules(acct.id)?,
            spam_model_json,
        })
    }

    /// [`Engine::restore_from_server_with`] with default options: the slot is found in the
    /// server's key directory; no credential is stored unless the backup carries one.
    pub async fn restore_from_server(
        &self,
        server_url: &str,
        email: &str,
        phrase: &str,
    ) -> Result<AccountInfo> {
        self.restore_from_server_with(server_url, email, phrase, &RestoreOptions::default())
            .await
    }

    /// Restore an account on a new device: download the backup with the phrase-derived token,
    /// decrypt it and import keys, contacts, verified marks and settings, then re-create the
    /// account with the stored server configuration. Nothing is written unless every step
    /// before the import succeeded (download, decrypt, credential test); the import itself is
    /// one transaction. A wrong phrase is refused by the server (401) → `Error::Connection`.
    pub async fn restore_from_server_with(
        &self,
        server_url: &str,
        email: &str,
        phrase: &str,
        opts: &RestoreOptions,
    ) -> Result<AccountInfo> {
        let phrase = checked_phrase(phrase)?;
        let email = email.trim().to_string();
        if !email.contains('@') {
            return Err(Error::InvalidInput(format!(
                "`{email}` is not an e-mail address"
            )));
        }
        if self.store().account_by_email(&email)?.is_some() {
            return Err(Error::AccountExists(email));
        }
        let server = server_url.trim().trim_end_matches('/').to_string();
        let keys = derive_keys_blocking(phrase.phrase(), email.clone()).await?;

        // A probe account for the credential test and the mailbox key discovery.
        // Servers come from the overrides, else autodiscovery (the bundle is not open yet).
        let probe = match &opts.credentials {
            Some(auth) => {
                let (auth_kind, credential) = credential_for(auth)?;
                let discovered = match (&opts.imap, &opts.smtp) {
                    (Some(_), Some(_)) => None,
                    _ => self.detect_servers(&email).await.ok(),
                };
                let imap = opts
                    .imap
                    .clone()
                    .or_else(|| discovered.as_ref().map(|d| d.imap.clone()));
                let smtp = opts
                    .smtp
                    .clone()
                    .or_else(|| discovered.as_ref().map(|d| d.smtp.clone()));
                let login = opts
                    .login
                    .clone()
                    .filter(|l| !l.trim().is_empty())
                    .or_else(|| discovered.as_ref().map(|d| d.login_name(&email)))
                    .unwrap_or_else(|| email.clone());
                match (imap, smtp) {
                    (Some(imap), Some(smtp)) => Some(AccountRow {
                        id: 0,
                        email: email.clone(),
                        display_name: String::new(),
                        imap,
                        smtp,
                        auth_kind,
                        login,
                        credential,
                        created_at: 0,
                        provider: None, // not carried in a recovery bundle
                    }),
                    _ => None,
                }
            }
            None => None,
        };

        // Fail early and honestly when the backup server itself is unreachable, so a network
        // problem is never reported as "no backup found" (the directory lookup below swallows errors).
        {
            let health = format!("{server}/v1/health");
            let ok = self
                .http()
                .get(&health)
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if !ok {
                return Err(Error::Connection(format!(
                    "backup server unreachable: {server} did not answer /v1/health"
                )));
            }
        }

        // Candidate slots, most specific first.
        let mut candidates: Vec<String> = Vec::new();
        let push = |c: &mut Vec<String>, f: String| {
            let f = f.trim().to_ascii_uppercase();
            if !f.is_empty() && !c.contains(&f) {
                c.push(f);
            }
        };
        if let Some(f) = &opts.fingerprint {
            push(&mut candidates, f.clone());
        } else {
            if let Some(k) = directory::lookup_key(self.http(), &server, &email).await {
                push(&mut candidates, k.fingerprint());
            }
            if let Some(p) = &probe {
                for f in self.fingerprints_from_mailbox(p).await? {
                    push(&mut candidates, f);
                }
            }
        }

        let mut refused = false;
        let mut found: Option<(String, Vec<u8>)> = None;
        for fpr in &candidates {
            let url = format!("{server}/v1/backup/{fpr}");
            let resp = self
                .http()
                .get(&url)
                .query(&[("token", keys.token.as_str())])
                .send()
                .await
                .map_err(|e| Error::Connection(format!("{server}: {e}")))?;
            match resp.status().as_u16() {
                200 => {
                    let body = resp
                        .bytes()
                        .await
                        .map_err(|e| Error::Connection(format!("{server}: {e}")))?;
                    found = Some((fpr.clone(), body.to_vec()));
                    break;
                }
                401 => refused = true,
                404 => {}
                s => {
                    return Err(Error::Connection(format!(
                        "backup server answered {s} for {fpr}"
                    )))
                }
            }
        }
        let Some((fpr, blob)) = found else {
            if refused {
                return Err(Error::Connection(
                    "the backup server refused the recovery token (401): wrong recovery phrase \
                     for this address"
                        .into(),
                ));
            }
            return Err(Error::InvalidInput(if candidates.is_empty() {
                format!(
                    "no backup slot found for {email}: the key is not in the server's directory; \
                     pass the fingerprint shown at backup time, or the mail credentials so the \
                     key can be found in your mailbox"
                )
            } else {
                format!(
                    "no backup for {email} on {server} (tried {})",
                    candidates.join(", ")
                )
            }));
        };

        let json = open_bundle(&keys.backup_key, &email, &fpr, &blob)?;
        let bundle: Bundle = serde_json::from_slice(&json)?;
        drop(json);
        if bundle.format != BUNDLE_FORMAT || bundle.version > BUNDLE_VERSION {
            return Err(Error::InvalidInput(format!(
                "unsupported recovery bundle {} v{}; update Sealbox",
                bundle.format, bundle.version
            )));
        }
        if !bundle.account.email.eq_ignore_ascii_case(&email) {
            return Err(Error::SecretIntegrity(
                "the backup belongs to another address".into(),
            ));
        }
        // Every key must parse and match its fingerprint; the primary must own the slot.
        for (n, i) in bundle.identities.iter().enumerate() {
            let id = Identity::from_armored_secret(&i.secret_armored, None)?;
            if !id.fingerprint().eq_ignore_ascii_case(&i.fingerprint)
                || (n == 0 && !id.fingerprint().eq_ignore_ascii_case(&fpr))
            {
                return Err(Error::SecretIntegrity(
                    "a key in the backup does not match its fingerprint".into(),
                ));
            }
        }
        if bundle.identities.is_empty() {
            return Err(Error::NoIdentity(email));
        }

        // Account record: stored servers unless overridden; the credential from the caller,
        // else from the bundle (only when it was included), else none.
        let imap = opts
            .imap
            .clone()
            .unwrap_or_else(|| bundle.account.imap.clone());
        let smtp = opts
            .smtp
            .clone()
            .unwrap_or_else(|| bundle.account.smtp.clone());
        let login = opts
            .login
            .clone()
            .filter(|l| !l.trim().is_empty())
            .unwrap_or_else(|| bundle.account.login.clone());
        let (auth_kind, credential) = match &opts.credentials {
            Some(a) => credential_for(a)?,
            None => (
                bundle.account.auth_kind,
                bundle.account.credential.clone().unwrap_or_default(),
            ),
        };
        let mut row = AccountRow {
            id: 0,
            email: bundle.account.email.clone(),
            display_name: bundle.account.display_name.clone(),
            imap,
            smtp,
            auth_kind,
            login,
            credential,
            created_at: 0,
            provider: None, // not carried in a recovery bundle
        };
        if opts.credentials.is_some() {
            // Test the credential before writing anything (a typo must not leave an account).
            match transport::connect_imap(&row, self.config().network_timeout).await {
                Ok(c) => {
                    let _ = c.logout().await;
                }
                Err(e @ Error::Imap(ImapError::Auth(_) | ImapError::LoginRejected { .. })) => {
                    // Like `add_account`: retry with the bare local part.
                    let local = email.split_once('@').map(|(l, _)| l.to_string());
                    match local.filter(|l| *l != row.login) {
                        Some(l) => {
                            row.login = l;
                            let c = transport::connect_imap(&row, self.config().network_timeout)
                                .await?;
                            let _ = c.logout().await;
                        }
                        None => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }

        let id = self.import_bundle(&row, &bundle)?;
        let row = self
            .store()
            .account_by_id(id)?
            .ok_or_else(|| Error::AccountNotFound(email.clone()))?;
        Ok(row.info(Some(fpr)))
    }

    /// Write a decrypted bundle into the profile in one transaction.
    fn import_bundle(&self, row: &AccountRow, bundle: &Bundle) -> Result<i64> {
        let store = self.store();
        store.conn().execute_batch("BEGIN IMMEDIATE")?;
        let res = (|| -> Result<i64> {
            for i in &bundle.identities {
                let taken: Option<i64> = store
                    .conn()
                    .query_row(
                        "SELECT id FROM identities WHERE fingerprint = ?1",
                        params![i.fingerprint],
                        |r| r.get(0),
                    )
                    .ok();
                if taken.is_some() {
                    return Err(Error::InvalidInput(format!(
                        "key {} is already in this profile",
                        i.fingerprint
                    )));
                }
            }
            let id = store.insert_account(&NewAccount {
                email: &row.email,
                display_name: &row.display_name,
                imap: &row.imap,
                smtp: &row.smtp,
                auth_kind: row.auth_kind,
                login: &row.login,
                credential: &row.credential,
            })?;
            for i in &bundle.identities {
                store.insert_identity(
                    id,
                    &i.fingerprint,
                    &i.email,
                    &i.secret_armored,
                    &i.public_armored,
                )?;
            }
            for p in &bundle.peers {
                if store.peer(&p.addr)?.is_none() {
                    store.save_peer(p)?;
                }
            }
            for k in &bundle.keys {
                if !store
                    .keys_for(&k.addr)?
                    .iter()
                    .any(|x| x.source == k.source)
                {
                    store.upsert_key(&k.addr, k.source, &k.fingerprint, &k.armored)?;
                }
            }
            for s in &bundle.settings {
                if SKIPPED_SETTINGS.contains(&s.key.as_str()) {
                    continue;
                }
                match s.scope {
                    SettingsScope::Account => {
                        store.set_setting_raw(s.scope, &row.email, &s.key, &s.value.to_string())?
                    }
                    SettingsScope::Global => {
                        // Never override what this device already has.
                        if store.get_setting_raw(s.scope, "", &s.key)?.is_none() {
                            store.set_setting_raw(s.scope, "", &s.key, &s.value.to_string())?;
                        }
                    }
                }
            }
            for r in &bundle.filter_rules {
                store.insert_filter_rule(id, r)?;
            }
            if let Some(j) = &bundle.spam_model_json {
                if store.load_spam_model()?.is_empty() {
                    store.save_spam_model(&BayesModel::from_json(j).map_err(spam_err)?)?;
                }
            }
            restore_verified(&store, &bundle.verified)?;
            Ok(id)
        })();
        match res {
            Ok(id) => {
                store.conn().execute_batch("COMMIT")?;
                Ok(id)
            }
            Err(e) => {
                let _ = store.conn().execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Fingerprints announced in the `Autocrypt:` headers of our own mail (Sent, then INBOX),
    /// newest first. Used to find the backup slot when the key is not in the directory.
    async fn fingerprints_from_mailbox(&self, probe: &AccountRow) -> Result<Vec<String>> {
        let email = probe.email.to_ascii_lowercase();
        if email.contains('"') || email.contains('\\') {
            return Ok(Vec::new());
        }
        let mut row = probe.clone_for_probe();
        let mut client = match transport::connect_imap(&row, self.config().network_timeout).await {
            Ok(c) => c,
            Err(e @ Error::Imap(ImapError::Auth(_) | ImapError::LoginRejected { .. })) => {
                let local = email.split_once('@').map(|(l, _)| l.to_string());
                match local.filter(|l| *l != row.login) {
                    Some(l) => {
                        row.login = l;
                        transport::connect_imap(&row, self.config().network_timeout).await?
                    }
                    None => return Err(e),
                }
            }
            Err(e) => return Err(e),
        };
        let mut folders = Vec::new();
        if let Ok(list) = client.list_folders().await {
            if let Some(s) = transport::find_sent_folder(&list) {
                folders.push(s);
            }
        }
        folders.push("INBOX".to_string());
        let mut out: Vec<String> = Vec::new();
        for folder in folders {
            if client.select(&folder).await.is_err() {
                continue;
            }
            let uids = client
                .uid_search(&format!("FROM \"{email}\""))
                .await
                .unwrap_or_default();
            let newest: Vec<u32> = uids.iter().rev().take(DISCOVERY_SCAN).copied().collect();
            let mut msgs = client.fetch_rfc822_batch(&newest).await.unwrap_or_default();
            msgs.sort_by_key(|m| std::cmp::Reverse(m.uid));
            for m in msgs {
                let Ok(parsed) = mime::parse(&m.raw) else {
                    continue;
                };
                if !parsed
                    .headers
                    .from
                    .first()
                    .is_some_and(|f| f.address.eq_ignore_ascii_case(&email))
                {
                    continue;
                }
                for value in &parsed.headers.autocrypt {
                    let Some(h) = parse_autocrypt_header(value) else {
                        continue;
                    };
                    if !h.addr.eq_ignore_ascii_case(&email) {
                        continue;
                    }
                    let Ok(bytes) = B64.decode(h.keydata.as_bytes()) else {
                        continue;
                    };
                    if let Ok(k) = PublicKey::from_bytes(&bytes) {
                        let f = k.fingerprint();
                        if !out.contains(&f) {
                            out.push(f);
                        }
                    }
                }
            }
        }
        let _ = client.logout().await;
        Ok(out)
    }

    /// Replace the stored mail credential of an account (after a restore without one).
    pub fn set_account_credential(&self, email: &str, auth: &AuthSpec) -> Result<AccountInfo> {
        let acct = self.account_row(email)?;
        let (kind, credential) = credential_for(auth)?;
        {
            let store = self.store();
            store.update_account_credential(acct.id, &credential)?;
            if kind != acct.auth_kind {
                let kind_str = match kind {
                    AuthKind::Password => "password",
                    AuthKind::OAuth => "oauth",
                };
                store.conn().execute(
                    "UPDATE accounts SET auth_kind = ?1 WHERE id = ?2",
                    params![kind_str, acct.id],
                )?;
            }
        }
        self.account(email)
    }

    // ----- Autocrypt Setup Message ------------------------------------------------------

    /// Autocrypt Level 1 Setup Message: a fresh 36-digit setup code, the secret key encrypted
    /// with it (`Passphrase-Format: numeric9x4`), mailed to ourselves (`Autocrypt-Setup-Message:
    /// v1`, an `application/autocrypt-setup` attachment) over the account's SMTP. Import it on
    /// the other device (Sealbox, Delta Chat, Thunderbird) with the code shown here.
    pub async fn setup_message_export(&self, email: &str) -> Result<SetupExport> {
        let acct = self.account_row(email)?;
        let (_row, identity) = self.identity_for(&acct)?;
        let code = Zeroizing::new(setup_code_generate());
        let armored = setup_message_create(&identity, &code)?;
        let me = if acct.display_name.is_empty() {
            Mailbox::new(acct.email.clone())
        } else {
            Mailbox::named(acct.display_name.clone(), acct.email.clone())
        };
        let mut md = MessageDraft::new(me.clone(), vec![me], SETUP_SUBJECT, SETUP_TEXT);
        md.attachments.push(Attachment::new(
            SETUP_FILE_NAME,
            AUTOCRYPT_SETUP_MIME_TYPE,
            setup_html(&armored).into_bytes(),
        ));
        md.extra_headers
            .push((AUTOCRYPT_SETUP_HEADER.to_string(), "v1".to_string()));
        let raw = build_plain(&md)?;
        let rcpts = vec![acct.email.clone()];
        let smtp = self.smtp_for(&acct).await?;
        let sent = smtp.send_raw(&acct.email, &rcpts, &raw).await;
        smtp.shutdown().await;
        let state = if sent.is_ok() { "sent" } else { "failed" };
        let err = sent.as_ref().err().map(|e| e.to_string());
        let _ = self.store().insert_outbox(&NewOutbox {
            account_id: acct.id,
            message_id: &md.message_id,
            recipients: &rcpts,
            subject: SETUP_SUBJECT,
            mode: "setup_message",
            state,
            error: err.as_deref(),
            sent_copy_appended: false,
        });
        sent.map_err(Error::Smtp)?;
        Ok(SetupExport {
            setup_code: code.to_string(),
            message_id: md.message_id,
        })
    }

    /// Import an Autocrypt Setup Message: `source` is a local message id (from `list`), a
    /// Message-ID, or the path of a file (the `.eml`, or the `autocrypt-setup-message.html`
    /// attachment Delta Chat / Thunderbird produce). The key must belong to an account of this
    /// profile; it becomes the account's primary key (the old key stays, so mail encrypted to
    /// it still opens). Messages that could not be decrypted are dropped locally and fetched
    /// again on the next sync. A wrong code changes nothing.
    pub fn setup_message_import(&self, source: &str, setup_code: &str) -> Result<AccountInfo> {
        let source = source.trim();
        // (raw bytes, is a mail, account it was found in)
        let (raw, account_hint): (Vec<u8>, Option<i64>) = if let Ok(id) = source.parse::<i64>() {
            let store = self.store();
            let row = store.message(id)?;
            (store.message_raw(id)?, Some(row.account_id))
        } else if std::path::Path::new(source).is_file() {
            (std::fs::read(source)?, None)
        } else {
            let mid = source.trim_start_matches('<').trim_end_matches('>');
            let store = self.store();
            let row = store.message_by_message_id(mid)?.ok_or_else(|| {
                Error::InvalidInput(format!(
                    "`{source}` is neither a message id, a stored Message-ID nor a file"
                ))
            })?;
            (store.message_raw(row.summary.id)?, Some(row.account_id))
        };

        let looks_like_mail = top_header(&raw, "From").is_some();
        let payload: String = if looks_like_mail {
            let parsed = mime::parse(&raw)?;
            let header_ok = top_header(&raw, AUTOCRYPT_SETUP_HEADER)
                .is_some_and(|v| v.eq_ignore_ascii_case("v1"));
            let part = match &parsed.kind {
                mime::MessageKind::Plain(body) => body.attachments.iter().find(|a| {
                    a.content_type
                        .to_ascii_lowercase()
                        .starts_with(AUTOCRYPT_SETUP_MIME_TYPE)
                }),
                _ => None,
            };
            let Some(part) = part.filter(|_| header_ok) else {
                return Err(Error::InvalidInput(
                    "not an Autocrypt Setup Message (needs `Autocrypt-Setup-Message: v1` and an \
                     application/autocrypt-setup part)"
                        .into(),
                ));
            };
            // Level 1: From and To are our own address.
            let from = parsed.headers.from.first().map(|m| m.address.clone());
            let to_self = parsed
                .headers
                .to
                .iter()
                .any(|t| Some(&t.address) == from.as_ref());
            if !to_self {
                return Err(Error::InvalidInput(
                    "a setup message must be sent from an address to itself".into(),
                ));
            }
            String::from_utf8_lossy(&part.data).into_owned()
        } else {
            String::from_utf8_lossy(&raw).into_owned()
        };

        let identity = setup_message_open(&payload, setup_code).map_err(|e| {
            Error::InvalidInput(format!("wrong setup code or damaged setup message ({e})"))
        })?;
        let emails = identity.emails();
        let accounts = self.store().list_accounts()?;
        let acct = accounts
            .into_iter()
            .find(|a| {
                account_hint.is_none_or(|h| h == a.id)
                    && emails.iter().any(|e| e.eq_ignore_ascii_case(&a.email))
            })
            .ok_or_else(|| {
                Error::InvalidInput(format!(
                    "the key in the setup message is for {}; add that account first (a setup \
                     message carries only the key, not the server settings)",
                    emails.join(", ")
                ))
            })?;
        let secret = Zeroizing::new(identity.to_armored_secret(None)?);
        let public = identity.public().to_armored()?;
        let fpr = identity.fingerprint();

        let store = self.store();
        store.conn().execute_batch("BEGIN IMMEDIATE")?;
        let res = (|| -> Result<()> {
            let existing = store.identities_for_account(acct.id)?;
            if existing.first().is_some_and(|i| i.fingerprint == fpr) {
                return Ok(()); // already the primary key
            }
            // Imported key first (primary = lowest id), then the previous keys.
            store.conn().execute(
                "DELETE FROM identities WHERE account_id = ?1",
                params![acct.id],
            )?;
            store.conn().execute(
                "DELETE FROM identities WHERE fingerprint = ?1",
                params![fpr],
            )?;
            store.insert_identity(acct.id, &fpr, &acct.email, &secret, &public)?;
            for i in existing.iter().filter(|i| i.fingerprint != fpr) {
                store.insert_identity(
                    acct.id,
                    &i.fingerprint,
                    &i.email,
                    &i.secret_armored,
                    &i.public_armored,
                )?;
            }
            // Mail that failed to decrypt is fetched again on the next sync.
            let pending: Vec<(i64, i64)> = {
                let mut stmt = store.conn().prepare(
                    "SELECT folder_id, MIN(uid) FROM messages WHERE account_id = ?1 \
                     AND was_encrypted = 1 AND decrypted = 0 GROUP BY folder_id",
                )?;
                let rows = stmt
                    .query_map(params![acct.id], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                rows
            };
            store.conn().execute(
                "DELETE FROM messages WHERE account_id = ?1 AND was_encrypted = 1 AND decrypted = 0",
                params![acct.id],
            )?;
            for (folder, min_uid) in pending {
                store.conn().execute(
                    "UPDATE folders SET last_uid = MIN(last_uid, ?1) WHERE id = ?2",
                    params![(min_uid - 1).max(0), folder],
                )?;
            }
            Ok(())
        })();
        match res {
            Ok(()) => store.conn().execute_batch("COMMIT")?,
            Err(e) => {
                let _ = store.conn().execute_batch("ROLLBACK");
                return Err(e);
            }
        }
        drop(store);
        let row = self
            .store()
            .account_by_id(acct.id)?
            .ok_or_else(|| Error::AccountNotFound(acct.email.clone()))?;
        Ok(row.info(Some(fpr)))
    }
}

impl AccountRow {
    fn clone_for_probe(&self) -> AccountRow {
        AccountRow {
            id: self.id,
            email: self.email.clone(),
            display_name: self.display_name.clone(),
            imap: self.imap.clone(),
            smtp: self.smtp.clone(),
            auth_kind: self.auth_kind,
            login: self.login.clone(),
            credential: self.credential.clone(),
            created_at: self.created_at,
            provider: self.provider,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;
    use crate::store::NewAccount;
    use sealbox_mail::Security;

    fn hex16(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn wordlist_is_the_bip39_english_list() {
        assert_eq!(wordlist().len(), 2048);
        assert_eq!(
            format!("{:x}", Sha256::digest(WORDLIST_TXT.as_bytes())),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        assert!(wordlist().windows(2).all(|w| w[0] < w[1]), "sorted");
    }

    /// The 128-bit vectors of the BIP39 reference (trezor/python-mnemonic vectors.json).
    #[test]
    fn bip39_vectors() {
        let vectors = [
            ("00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
            ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow"),
            ("80808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"),
            ("ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"),
            ("9e885d952ad362caeb4efe34a8e91bd2", "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"),
            ("c0ba5a8e914111210f2bd131f3d5e08d", "scheme spot photo card baby mountain device kick cradle pact join borrow"),
            ("f30f8c1da665478f49b001d94c5fc452", "vessel ladder alter error federal sibling chat ability sun glass valve picture"),
        ];
        for (hex, phrase) in vectors {
            let e = hex16(hex);
            assert_eq!(entropy_to_words(&e).join(" "), phrase, "encode {hex}");
            let (p, ent) = parse_phrase(phrase).unwrap();
            assert!(p.checksum_ok, "checksum {hex}");
            assert_eq!(*ent.unwrap(), e, "decode {hex}");
        }
    }

    #[test]
    fn checksum_and_parsing() {
        // Swapping two words breaks the checksum (for this vector).
        let bad = "legal winner thank year wave sausage worth useful legal winner yellow thank";
        let (p, ent) = parse_phrase(bad).unwrap();
        assert!(!p.checksum_ok);
        assert!(ent.is_none());
        assert!(checked_phrase(bad).is_err());
        // Separators, case and 4-letter prefixes.
        let typed = " 1. OZONE, drill grab fibe curt grace\npudding thank crui elder eigh picn ";
        let (p, _) = parse_phrase(typed).unwrap();
        assert!(p.checksum_ok);
        assert_eq!(
            p.phrase().as_str(),
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
        );
        // Ambiguous or unknown words, wrong counts.
        assert!(parse_phrase("abandon abandon").is_err());
        let unknown = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon bitcoinz";
        let err = parse_phrase(unknown).unwrap_err().to_string();
        assert!(err.contains("word 12"), "{err}");
        // Debug never shows words.
        assert!(!format!("{p:?}").contains("ozone"));
    }

    #[test]
    fn random_phrases_round_trip() {
        for _ in 0..200 {
            let mut e = [0u8; 16];
            OsRng.fill_bytes(&mut e);
            let words = entropy_to_words(&e);
            assert_eq!(words.len(), 12);
            let (p, ent) = parse_phrase(&words.join(" ")).unwrap();
            assert!(p.checksum_ok);
            assert_eq!(*ent.unwrap(), e);
        }
    }

    #[test]
    fn kdf_is_deterministic_and_separates_inputs() {
        let ph = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let a = derive_keys(ph, "Alice@Example.org").unwrap();
        let b = derive_keys(ph, "alice@example.org").unwrap();
        assert_eq!(*a.backup_key, *b.backup_key, "address is case-insensitive");
        assert_eq!(*a.token, *b.token);
        assert_ne!(
            a.backup_key.as_slice(),
            B64URL.decode(a.token.as_str()).unwrap().as_slice()
        );
        assert_eq!(a.token.len(), 43);
        assert!(a
            .token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        let c = derive_keys(ph, "bob@example.org").unwrap();
        assert_ne!(*a.backup_key, *c.backup_key);
        assert_ne!(*a.token, *c.token);
        let d = derive_keys(
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "alice@example.org",
        )
        .unwrap();
        assert_ne!(*a.backup_key, *d.backup_key);
        // Pinned vector: a change to the KDF would orphan every existing backup.
        assert_eq!(
            a.token.as_str(),
            "j8Zs1FoBE8iEKO93sF4I29SaHvKO-dKnD-vDI4vRX3Y"
        );
    }

    #[test]
    fn bundle_seal_open_and_tamper() {
        let key = [7u8; 32];
        let fpr = "0123456789ABCDEF0123456789ABCDEF01234567";
        let json = br#"{"hello":"world","pad":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let blob = seal_bundle(&key, "a@x.org", fpr, json).unwrap();
        assert_eq!(&blob[..4], b"SBXR");
        assert_eq!(blob[4], 1);
        assert!(!blob.windows(5).any(|w| w == b"hello"), "ciphertext only");
        assert_eq!(
            &open_bundle(&key, "A@x.org", fpr, &blob).unwrap()[..],
            &json[..]
        );
        // Every byte matters.
        for i in [0usize, 4, 5, 28, 29, blob.len() / 2, blob.len() - 1] {
            let mut t = blob.clone();
            t[i] ^= 0x01;
            assert!(open_bundle(&key, "a@x.org", fpr, &t).is_err(), "byte {i}");
        }
        // Wrong key, other address, other slot, truncation.
        assert!(open_bundle(&[8u8; 32], "a@x.org", fpr, &blob).is_err());
        assert!(open_bundle(&key, "b@x.org", fpr, &blob).is_err());
        assert!(open_bundle(&key, "a@x.org", &fpr.replace('0', "1"), &blob).is_err());
        assert!(open_bundle(&key, "a@x.org", fpr, &blob[..blob.len() - 1]).is_err());
        assert!(open_bundle(&key, "a@x.org", fpr, &blob[..20]).is_err());
        // Two seals of the same input differ (random nonce).
        assert_ne!(blob, seal_bundle(&key, "a@x.org", fpr, json).unwrap());
    }

    fn engine_with_account(email: &str) -> (tempfile::TempDir, Engine, Identity) {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        let id = Identity::generate("A", email).unwrap();
        {
            let store = engine.store();
            let acct = store
                .insert_account(&NewAccount {
                    email,
                    display_name: "A",
                    imap: &Endpoint::new("127.0.0.1", 143, Security::Plain),
                    smtp: &Endpoint::new("127.0.0.1", 25, Security::Plain),
                    auth_kind: AuthKind::Password,
                    login: "a",
                    credential: "app-password-123",
                })
                .unwrap();
            store
                .insert_identity(
                    acct,
                    &id.fingerprint(),
                    email,
                    &id.to_armored_secret(None).unwrap(),
                    &id.public().to_armored().unwrap(),
                )
                .unwrap();
        }
        (dir, engine, id)
    }

    #[test]
    fn bundle_round_trip_through_import() {
        let (_d1, a, id) = engine_with_account("a@x.org");
        let peer = Identity::generate("P", "p@x.org").unwrap();
        a.import_peer_key("p@x.org", &peer.public().to_armored().unwrap())
            .unwrap();
        let mut sig = a.get_signature("a@x.org").unwrap();
        sig.enabled = true;
        sig.text = "-- restored signature".into();
        a.set_signature("a@x.org", sig.clone()).unwrap();
        a.spam_allow("a@x.org", "friend@x.org", true).unwrap();
        a.store()
            .set_setting(SettingsScope::Account, "a@x.org", "secret.token", &"s3cr3t")
            .unwrap();
        let acct = a.account_row("a@x.org").unwrap();

        let bundle = a.build_bundle(&acct, &BackupOptions::default()).unwrap();
        assert!(
            bundle.account.credential.is_none(),
            "no credential by default"
        );
        assert!(!bundle.settings.iter().any(|s| s.key.starts_with("secret.")));
        let with = a
            .build_bundle(
                &acct,
                &BackupOptions {
                    include_credentials: true,
                },
            )
            .unwrap();
        assert_eq!(with.account.credential.as_deref(), Some("app-password-123"));

        let key = [3u8; 32];
        let json = serde_json::to_vec(&bundle).unwrap();
        let blob = seal_bundle(&key, "a@x.org", &id.fingerprint(), &json).unwrap();
        let back: Bundle = serde_json::from_slice(
            &open_bundle(&key, "a@x.org", &id.fingerprint(), &blob).unwrap(),
        )
        .unwrap();

        let (_d2, b) = {
            let d = tempfile::tempdir().unwrap();
            let e = Engine::open_with(d.path(), EngineConfig::default()).unwrap();
            (d, e)
        };
        let row = AccountRow {
            id: 0,
            email: back.account.email.clone(),
            display_name: back.account.display_name.clone(),
            imap: back.account.imap.clone(),
            smtp: back.account.smtp.clone(),
            auth_kind: back.account.auth_kind,
            login: back.account.login.clone(),
            credential: String::new(),
            created_at: 0,
            provider: None,
        };
        b.import_bundle(&row, &back).unwrap();
        assert_eq!(b.my_fingerprint("a@x.org").unwrap(), id.fingerprint());
        assert!(b.contacts().unwrap().iter().any(|c| c.address == "p@x.org"
            && c.fingerprint.as_deref() == Some(peer.fingerprint().as_str())));
        assert_eq!(b.get_signature("a@x.org").unwrap().text, sig.text);
        assert!(b
            .spam_settings("a@x.org")
            .unwrap()
            .allowlist
            .iter()
            .any(|x| x == "friend@x.org"));
        // A second import of the same keys is refused and leaves no partial account.
        let row2 = AccountRow {
            email: "other@x.org".into(),
            ..row
        };
        assert!(b.import_bundle(&row2, &back).is_err());
        assert!(b.account("other@x.org").is_err(), "rolled back");
    }

    #[test]
    fn setup_html_carries_the_armor() {
        let id = Identity::generate("A", "a@x.org").unwrap();
        let code = setup_code_generate();
        let armored = setup_message_create(&id, &code).unwrap();
        let html = setup_html(&armored);
        assert!(html.contains("Passphrase-Format: numeric9x4"));
        let back = setup_message_open(&html, &code).unwrap();
        assert_eq!(back.fingerprint(), id.fingerprint());
        assert!(setup_message_open(&html, &setup_code_generate()).is_err());
    }
}
