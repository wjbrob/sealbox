//! Secrets at rest (gate G27): envelope encryption of the sensitive columns of `sealbox.db`.
//!
//! * **Envelope**: XChaCha20-Poly1305, a fresh random 24-byte nonce per write, AAD =
//!   `table:column:rowid`, so a ciphertext moved to another row or column fails to open.
//!   Wire format (stored as a SQLite BLOB): `b"sbx1" ‖ nonce[24] ‖ ciphertext‖tag[16]`. Legacy
//!   rows are TEXT (or BLOBs without the prefix) and are wrapped on the first keyed open.
//! * **Data key** = HKDF-SHA256(master, info = `"sealbox-profile-v1"`).
//! * **Master key** per [`ProfileKeySource`]: a random 32-byte key in the OS keyring
//!   (desktop), Argon2id(passphrase, `profile.salt`) with m = 64 MiB, t = 3, p = 1, a raw
//!   32-byte key handed in by the app (mobile: Android Keystore / iOS Keychain), or `None`
//!   (plaintext, only with `SEALBOX_ALLOW_PLAINTEXT_PROFILE=1`).
//! * **Key-check value** `profile_meta.kcv`: an envelope of a constant; a wrong key fails
//!   fast with [`Error::ProfileLocked`] before any row is read.
//!
//! See `docs/SECRETS_AT_REST.md` for the threat model and what stays plaintext.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rusqlite::types::Value;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::engine::Engine;
use crate::error::{Error, Result};

/// Wire-format prefix of a wrapped value.
pub const MAGIC: &[u8; 4] = b"sbx1";
/// XChaCha20 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// HKDF info string of the data key.
pub const HKDF_INFO: &[u8] = b"sealbox-profile-v1";
/// Default environment variable holding the profile passphrase.
pub const PASSPHRASE_ENV: &str = "SEALBOX_PROFILE_PASSPHRASE";
/// Names a different variable to read the passphrase from (what `--profile-passphrase-env` sets).
pub const PASSPHRASE_ENV_NAME_ENV: &str = "SEALBOX_PROFILE_PASSPHRASE_ENV";
/// `keyring` | `passphrase` | `none`: the key source [`ProfileKeySource::from_env`] picks.
pub const PROFILE_KEY_ENV: &str = "SEALBOX_PROFILE_KEY";
/// Must be `1` for a plaintext (`None`) profile to open.
pub const ALLOW_PLAINTEXT_ENV: &str = "SEALBOX_ALLOW_PLAINTEXT_PROFILE";
/// `1` = behave as if no OS keyring were reachable (CI, tests).
pub const NO_KEYRING_ENV: &str = "SEALBOX_NO_KEYRING";
/// Argon2id salt file inside the profile directory.
pub const SALT_FILE: &str = "profile.salt";
const SALT_NEW_FILE: &str = "profile.salt.new";
/// Keyring service name.
pub const KEYRING_SERVICE: &str = "sealbox";
/// Argon2id memory cost (KiB), iterations, lanes.
pub const ARGON2_M_KIB: u32 = 64 * 1024;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u32 = 1;

const KCV_PLAINTEXT: &[u8] = b"sealbox-kcv-v1";
const KCV_AAD: &str = "profile_meta:kcv:1";

/// Where the profile master key comes from.
#[derive(Clone, PartialEq, Eq)]
pub enum ProfileKeySource {
    /// A random 32-byte key in the OS keyring (Secret Service / Keychain / Credential
    /// Manager), created on first use. Headless fallback: `SEALBOX_PROFILE_PASSPHRASE`, then
    /// plaintext only with `SEALBOX_ALLOW_PLAINTEXT_PROFILE=1` (one WARN, reported in status).
    Keyring,
    /// Argon2id(passphrase, `profile.salt`).
    Passphrase(String),
    /// A raw 32-byte master key (mobile: the app keeps it in Android Keystore / iOS Keychain).
    Raw(Vec<u8>),
    /// Plaintext profile. Opens only with `SEALBOX_ALLOW_PLAINTEXT_PROFILE=1`.
    None,
}

impl std::fmt::Debug for ProfileKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keyring => f.write_str("Keyring"),
            Self::Passphrase(_) => f.write_str("Passphrase(<redacted>)"),
            Self::Raw(_) => f.write_str("Raw(<redacted>)"),
            Self::None => f.write_str("None"),
        }
    }
}

impl Default for ProfileKeySource {
    /// `Keyring` (the desktop default). Unit tests of this crate use a fixed raw key so they
    /// exercise the wrapped path without touching the developer's keyring.
    fn default() -> Self {
        #[cfg(test)]
        {
            Self::Raw(vec![0x5b; 32])
        }
        #[cfg(not(test))]
        {
            Self::Keyring
        }
    }
}

static PROCESS_OVERRIDE: OnceLock<Mutex<Option<ProfileKeySource>>> = OnceLock::new();

impl ProfileKeySource {
    /// Short name: `keyring`, `passphrase`, `raw`, `none`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Keyring => "keyring",
            Self::Passphrase(_) => "passphrase",
            Self::Raw(_) => "raw",
            Self::None => "none",
        }
    }

    /// The source [`crate::EngineConfig::from_env`] uses: a process override
    /// ([`ProfileKeySource::set_process_default`], what the CLI flags set), else
    /// `SEALBOX_PROFILE_KEY` (`keyring` default | `passphrase` | `none`), the passphrase read
    /// from `$SEALBOX_PROFILE_PASSPHRASE_ENV` (default `SEALBOX_PROFILE_PASSPHRASE`).
    pub fn from_env() -> Self {
        if let Some(m) = PROCESS_OVERRIDE.get() {
            let guard = match m.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if let Some(src) = guard.as_ref() {
                return src.clone();
            }
        }
        let kind = std::env::var(PROFILE_KEY_ENV)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        match kind.as_str() {
            "passphrase" => Self::Passphrase(env_passphrase().unwrap_or_default()),
            "none" | "plaintext" => Self::None,
            "" | "keyring" => Self::Keyring,
            other => {
                tracing::warn!(
                    "{PROFILE_KEY_ENV}={other:?} is not keyring|passphrase|none; using keyring"
                );
                Self::Keyring
            }
        }
    }

    /// Make [`ProfileKeySource::from_env`] return `src` for the rest of the process (the CLI's
    /// `--profile-key` / `--profile-passphrase-env`). Avoids mutating the environment.
    pub fn set_process_default(src: ProfileKeySource) {
        let m = PROCESS_OVERRIDE.get_or_init(|| Mutex::new(None));
        let mut guard = match m.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *guard = Some(src);
    }
}

/// The passphrase from the configured environment variable, if set and non-empty.
pub fn env_passphrase() -> Option<String> {
    let var = std::env::var(PASSPHRASE_ENV_NAME_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| PASSPHRASE_ENV.to_string());
    std::env::var(var).ok().filter(|p| !p.is_empty())
}

fn plaintext_allowed() -> bool {
    std::env::var(ALLOW_PLAINTEXT_ENV).is_ok_and(|v| v.trim() == "1")
}

/// What `Engine::profile_key_status` reports.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProfileKeyStatus {
    /// Effective source: `keyring`, `passphrase`, `raw` or `none`.
    pub source: String,
    /// Non-NULL sensitive values stored as `sbx1` envelopes.
    pub wrapped_rows: u64,
    /// Non-NULL sensitive values stored in the clear (0 for a healthy keyed profile).
    pub plaintext_rows: u64,
    /// How the master key is obtained, e.g. `argon2id(m=65536,t=3,p=1)+hkdf-sha256`.
    pub kdf: Option<String>,
    /// Set when the requested source was not usable and another was taken (headless
    /// keyring fallback), or when the profile is plaintext.
    pub fallback: Option<String>,
}

// ----- envelope --------------------------------------------------------------------------

/// `table:column:rowid`.
pub(crate) fn aad(table: &str, column: &str, rowid: &str) -> String {
    format!("{table}:{column}:{rowid}")
}

/// HKDF-SHA256(master, info = "sealbox-profile-v1").
pub(crate) fn derive_data_key(master: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = hkdf::Hkdf::<Sha256>::new(None, master);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, out.as_mut())
        .map_err(|_| Error::InvalidInput("HKDF output length".into()))?;
    Ok(out)
}

/// Argon2id(passphrase, salt), m = 64 MiB, t = 3, p = 1 → 32-byte master.
pub(crate) fn argon2id(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32))
        .map_err(|e| Error::InvalidInput(format!("argon2 params: {e}")))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .map_err(|e| Error::InvalidInput(format!("argon2: {e}")))?;
    Ok(out)
}

/// True when `b` has the shape of an `sbx1` envelope.
pub(crate) fn is_envelope(b: &[u8]) -> bool {
    b.len() >= MAGIC.len() + NONCE_LEN + TAG_LEN && b.starts_with(MAGIC)
}

/// Encrypt `plaintext` under `key` with a fresh nonce: `sbx1 ‖ nonce ‖ ct‖tag`.
pub(crate) fn seal(key: &[u8; 32], aad: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| Error::SecretIntegrity(format!("{aad}: encryption failed")))?;
    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt an envelope; any mismatch (key, AAD, tampering) is [`Error::SecretIntegrity`].
pub(crate) fn open(key: &[u8; 32], aad: &str, wire: &[u8]) -> Result<Vec<u8>> {
    if !is_envelope(wire) {
        return Err(Error::SecretIntegrity(format!(
            "{aad}: not an sbx1 envelope"
        )));
    }
    let nonce = XNonce::from_slice(&wire[MAGIC.len()..MAGIC.len() + NONCE_LEN]);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &wire[MAGIC.len() + NONCE_LEN..],
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| Error::SecretIntegrity(format!("{aad}: authentication failed")))
}

// ----- the vault (per open store) ---------------------------------------------------------

/// The unlocked data key (or plaintext mode) of an open profile.
pub(crate) struct Vault {
    key: Option<Zeroizing<[u8; 32]>>,
    source: &'static str,
    kdf: Option<String>,
    fallback: Option<String>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("keyed", &self.key.is_some())
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Plaintext mode (legacy/None profiles, `Store::open` before unlocking).
    pub(crate) fn plaintext() -> Self {
        Self {
            key: None,
            source: "none",
            kdf: None,
            fallback: None,
        }
    }

    /// Keyed with an already derived data key (tests).
    #[cfg(test)]
    pub(crate) fn with_master(master: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Some(derive_data_key(master)?),
            source: "raw",
            kdf: Some("raw+hkdf-sha256".into()),
            fallback: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn is_keyed(&self) -> bool {
        self.key.is_some()
    }

    fn locked_err(aad: &str) -> Error {
        Error::ProfileLocked(format!(
            "{aad} is wrapped but the profile was opened without a key"
        ))
    }

    /// Wrap bytes (keyed) or pass them through as a BLOB (plaintext mode).
    pub(crate) fn seal_blob(&self, table: &str, col: &str, rowid: &str, b: &[u8]) -> Result<Value> {
        match &self.key {
            Some(k) => Ok(Value::Blob(seal(k, &aad(table, col, rowid), b)?)),
            None => Ok(Value::Blob(b.to_vec())),
        }
    }

    /// Wrap text (keyed → BLOB envelope) or store it as TEXT (plaintext mode).
    pub(crate) fn seal_text(&self, table: &str, col: &str, rowid: &str, s: &str) -> Result<Value> {
        match &self.key {
            Some(k) => Ok(Value::Blob(seal(k, &aad(table, col, rowid), s.as_bytes())?)),
            None => Ok(Value::Text(s.to_string())),
        }
    }

    pub(crate) fn seal_opt_text(
        &self,
        table: &str,
        col: &str,
        rowid: &str,
        s: Option<&str>,
    ) -> Result<Value> {
        match s {
            Some(s) => self.seal_text(table, col, rowid, s),
            None => Ok(Value::Null),
        }
    }

    /// Unwrap a BLOB column value.
    pub(crate) fn open_blob(
        &self,
        table: &str,
        col: &str,
        rowid: &str,
        v: Value,
    ) -> Result<Vec<u8>> {
        let a = aad(table, col, rowid);
        match (&self.key, v) {
            (Some(k), Value::Blob(b)) => open(k, &a, &b),
            (Some(_), Value::Text(_)) => {
                Err(Error::SecretIntegrity(format!("{a}: stored unwrapped")))
            }
            (None, Value::Blob(b)) => Ok(b),
            (None, Value::Text(t)) => Ok(t.into_bytes()),
            (_, other) => Err(Error::SecretIntegrity(format!(
                "{a}: unexpected {:?}",
                other.data_type()
            ))),
        }
    }

    /// Unwrap a TEXT column value.
    pub(crate) fn open_text(
        &self,
        table: &str,
        col: &str,
        rowid: &str,
        v: Value,
    ) -> Result<String> {
        let a = aad(table, col, rowid);
        match (&self.key, v) {
            (Some(k), Value::Blob(b)) => {
                let pt = open(k, &a, &b)?;
                String::from_utf8(pt).map_err(|_| Error::SecretIntegrity(format!("{a}: not UTF-8")))
            }
            (Some(_), Value::Text(_)) => {
                Err(Error::SecretIntegrity(format!("{a}: stored unwrapped")))
            }
            (None, Value::Text(t)) => Ok(t),
            (None, Value::Blob(b)) if is_envelope(&b) => Err(Self::locked_err(&a)),
            (None, Value::Blob(b)) => {
                String::from_utf8(b).map_err(|_| Error::SecretIntegrity(format!("{a}: not UTF-8")))
            }
            (_, other) => Err(Error::SecretIntegrity(format!(
                "{a}: unexpected {:?}",
                other.data_type()
            ))),
        }
    }

    pub(crate) fn open_opt_text(
        &self,
        table: &str,
        col: &str,
        rowid: &str,
        v: Value,
    ) -> Result<Option<String>> {
        match v {
            Value::Null => Ok(None),
            v => self.open_text(table, col, rowid, v).map(Some),
        }
    }
}

// ----- profile metadata ---------------------------------------------------------------------

/// Schema of the key metadata (applied by `Store::open`).
pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS profile_meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
"#;

#[derive(Debug, Default, Clone)]
pub(crate) struct ProfileMeta {
    pub kcv: Option<Vec<u8>>,
    /// `keyring` | `argon2id` | `raw`.
    pub kdf: Option<String>,
    pub keyring_user: Option<String>,
}

fn meta_get(conn: &Connection, key: &str) -> Result<Option<Value>> {
    Ok(conn
        .query_row(
            "SELECT value FROM profile_meta WHERE key = ?1",
            params![key],
            |r| r.get::<_, Value>(0),
        )
        .optional()?)
}

fn value_text(v: Value) -> Option<String> {
    match v {
        Value::Text(t) => Some(t),
        Value::Blob(b) => String::from_utf8(b).ok(),
        _ => None,
    }
}

pub(crate) fn read_meta(conn: &Connection) -> Result<ProfileMeta> {
    Ok(ProfileMeta {
        kcv: meta_get(conn, "kcv")?.and_then(|v| match v {
            Value::Blob(b) => Some(b),
            _ => None,
        }),
        kdf: meta_get(conn, "kdf")?.and_then(value_text),
        keyring_user: meta_get(conn, "keyring_user")?.and_then(value_text),
    })
}

fn write_meta(conn: &Connection, setup: &KeySetup, key: &[u8; 32]) -> Result<()> {
    conn.execute("DELETE FROM profile_meta", [])?;
    let kcv = seal(key, KCV_AAD, KCV_PLAINTEXT)?;
    let put = |k: &str, v: Value| -> Result<()> {
        conn.execute(
            "INSERT INTO profile_meta (key, value) VALUES (?1, ?2)",
            params![k, v],
        )?;
        Ok(())
    };
    put("kcv", Value::Blob(kcv))?;
    put("kdf", Value::Text(setup.meta_kdf.to_string()))?;
    if let Some(u) = &setup.keyring_user {
        put("keyring_user", Value::Text(u.clone()))?;
    }
    put("wrapped_at", Value::Text(crate::store::now().to_string()))?;
    Ok(())
}

fn kcv_ok(key: &[u8; 32], kcv: &[u8]) -> bool {
    open(key, KCV_AAD, kcv).is_ok_and(|p| p == KCV_PLAINTEXT)
}

// ----- wrapped columns ------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Text,
    Blob,
}

/// One sensitive column: how its AAD row id is formed and which rows are in scope.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WrappedColumn {
    pub table: &'static str,
    /// The table named in the AAD (`aad_table:column:rowid`): the table itself, except for
    /// `message_blobs`, whose envelopes keep the `messages:<column>:<id>` AAD of the columns
    /// they moved out of (`store::migrate_message_blobs` moves them without the key).
    pub aad_table: &'static str,
    pub column: &'static str,
    /// SQL expression whose value is the AAD row id.
    pub id_expr: &'static str,
    /// Extra `AND …` filter (settings: only keys flagged secret).
    pub filter: &'static str,
    pub kind: Kind,
}

/// Settings whose key starts with this prefix are wrapped.
pub const SECRET_SETTING_PREFIX: &str = "secret.";

/// True for a settings key whose value is wrapped at rest.
pub fn is_secret_setting(key: &str) -> bool {
    key.starts_with(SECRET_SETTING_PREFIX)
}

/// AAD row id of a settings value (the composite primary key; SQLite rowids of a table
/// without an INTEGER PRIMARY KEY may change on VACUUM, so they are not used here).
pub(crate) fn settings_rowid(scope: &str, account: &str, key: &str) -> String {
    format!("{scope}/{account}/{key}")
}

pub(crate) const WRAPPED: &[WrappedColumn] = &[
    WrappedColumn {
        table: "identities",
        aad_table: "identities",
        column: "secret_armored",
        id_expr: "id",
        filter: "",
        kind: Kind::Text,
    },
    WrappedColumn {
        table: "accounts",
        aad_table: "accounts",
        column: "credential",
        id_expr: "id",
        filter: "",
        kind: Kind::Text,
    },
    WrappedColumn {
        table: "oauth_tokens",
        aad_table: "oauth_tokens",
        column: "access_token",
        id_expr: "account_id",
        filter: "",
        kind: Kind::Text,
    },
    WrappedColumn {
        table: "oauth_tokens",
        aad_table: "oauth_tokens",
        column: "refresh_token",
        id_expr: "account_id",
        filter: "",
        kind: Kind::Text,
    },
    WrappedColumn {
        table: "oauth_tokens",
        aad_table: "oauth_tokens",
        column: "client_secret",
        id_expr: "account_id",
        filter: "",
        kind: Kind::Text,
    },
    WrappedColumn {
        table: "message_blobs",
        aad_table: "messages",
        column: "text_body",
        id_expr: "message_id",
        filter: "",
        kind: Kind::Text,
    },
    WrappedColumn {
        table: "message_blobs",
        aad_table: "messages",
        column: "html_body",
        id_expr: "message_id",
        filter: "",
        kind: Kind::Text,
    },
    WrappedColumn {
        table: "message_blobs",
        aad_table: "messages",
        column: "raw",
        id_expr: "message_id",
        filter: "",
        kind: Kind::Blob,
    },
    WrappedColumn {
        table: "messages",
        aad_table: "messages",
        column: "snippet",
        id_expr: "id",
        filter: "",
        kind: Kind::Text,
    },
    WrappedColumn {
        table: "attachments",
        aad_table: "attachments",
        column: "data",
        id_expr: "id",
        filter: "",
        kind: Kind::Blob,
    },
    WrappedColumn {
        table: "spam_model",
        aad_table: "spam_model",
        column: "model_json",
        id_expr: "id",
        filter: "",
        kind: Kind::Text,
    },
    WrappedColumn {
        table: "guest_links",
        aad_table: "guest_links",
        column: "secret",
        id_expr: "message_id",
        filter: "",
        kind: Kind::Text,
    },
    WrappedColumn {
        table: "settings",
        aad_table: "settings",
        column: "value",
        id_expr: "scope || '/' || account || '/' || key",
        filter: "AND substr(key, 1, 7) = 'secret.'",
        kind: Kind::Text,
    },
    WrappedColumn {
        table: "drafts",
        aad_table: "drafts",
        column: "subject",
        id_expr: "id",
        filter: "",
        kind: Kind::Text,
    },
    WrappedColumn {
        table: "drafts",
        aad_table: "drafts",
        column: "body_text",
        id_expr: "id",
        filter: "",
        kind: Kind::Text,
    },
    WrappedColumn {
        table: "draft_blobs",
        aad_table: "draft_blobs",
        column: "data",
        id_expr: "id",
        filter: "",
        kind: Kind::Blob,
    },
];

const ENVELOPE_SQL: &str = "typeof({c}) = 'blob' AND substr({c}, 1, 4) = X'73627831'";

fn id_string(v: &Value) -> String {
    match v {
        Value::Integer(i) => i.to_string(),
        Value::Text(t) => t.clone(),
        Value::Real(r) => r.to_string(),
        Value::Blob(b) => String::from_utf8_lossy(b).into_owned(),
        Value::Null => String::new(),
    }
}

/// Count (wrapped, plaintext) non-NULL sensitive values.
pub(crate) fn count_rows(conn: &Connection) -> Result<(u64, u64)> {
    let mut wrapped = 0u64;
    let mut plain = 0u64;
    for c in WRAPPED {
        let env = ENVELOPE_SQL.replace("{c}", c.column);
        let sql = format!(
            "SELECT COALESCE(SUM(CASE WHEN {env} THEN 1 ELSE 0 END), 0), COUNT({col}) \
             FROM {t} WHERE {col} IS NOT NULL {f}",
            col = c.column,
            t = c.table,
            f = c.filter
        );
        let (w, n): (i64, i64) = conn.query_row(&sql, [], |r| Ok((r.get(0)?, r.get(1)?)))?;
        wrapped += u64::try_from(w).unwrap_or(0);
        plain += u64::try_from(n - w).unwrap_or(0);
    }
    Ok((wrapped, plain))
}

/// Re-encode every sensitive value: decode with `from` (`None` = the value is plaintext,
/// whatever it looks like) and encode with `to` (`None` = store plaintext). Runs inside the
/// caller's transaction; row by row so a large mailbox never sits in memory at once.
fn recode_all(conn: &Connection, from: Option<&[u8; 32]>, to: Option<&[u8; 32]>) -> Result<u64> {
    let mut n = 0u64;
    for c in WRAPPED {
        let ids: Vec<Value> = {
            let sql = format!(
                "SELECT {id} FROM {t} WHERE {col} IS NOT NULL {f}",
                id = c.id_expr,
                t = c.table,
                col = c.column,
                f = c.filter
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], |r| r.get::<_, Value>(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let select = format!(
            "SELECT {col} FROM {t} WHERE ({id}) = ?1 {f}",
            col = c.column,
            t = c.table,
            id = c.id_expr,
            f = c.filter
        );
        let update = format!(
            "UPDATE {t} SET {col} = ?1 WHERE ({id}) = ?2 {f}",
            col = c.column,
            t = c.table,
            id = c.id_expr,
            f = c.filter
        );
        for id in ids {
            let rowid = id_string(&id);
            let a = aad(c.aad_table, c.column, &rowid);
            let v: Value = conn.query_row(&select, params![id], |r| r.get(0))?;
            let plain: Vec<u8> = match (from, v) {
                (_, Value::Null) => continue,
                (Some(k), Value::Blob(b)) => open(k, &a, &b)?,
                (Some(_), _) => {
                    return Err(Error::SecretIntegrity(format!("{a}: stored unwrapped")));
                }
                (None, Value::Blob(b)) => b,
                (None, Value::Text(t)) => t.into_bytes(),
                (None, other) => {
                    return Err(Error::SecretIntegrity(format!(
                        "{a}: unexpected {:?}",
                        other.data_type()
                    )))
                }
            };
            let plain = Zeroizing::new(plain);
            let out = match to {
                Some(k) => Value::Blob(seal(k, &a, &plain)?),
                None => match c.kind {
                    Kind::Blob => Value::Blob(plain.to_vec()),
                    Kind::Text => Value::Text(
                        String::from_utf8(plain.to_vec())
                            .map_err(|_| Error::SecretIntegrity(format!("{a}: not UTF-8")))?,
                    ),
                },
            };
            conn.execute(&update, params![out, id])?;
            n += 1;
        }
    }
    Ok(n)
}

// ----- unlocking -----------------------------------------------------------------------------

/// How a freshly keyed profile records its key source.
#[derive(Debug, Clone)]
pub(crate) struct KeySetup {
    meta_kdf: &'static str,
    keyring_user: Option<String>,
}

/// Result of resolving a [`ProfileKeySource`] against a profile.
pub(crate) struct Unlocked {
    pub vault: Vault,
    /// `Some` when the profile has no key yet and this open keys it (migration).
    pub setup: Option<KeySetup>,
}

fn kdf_desc(meta_kdf: &str) -> String {
    match meta_kdf {
        "argon2id" => format!("argon2id(m={ARGON2_M_KIB},t={ARGON2_T},p={ARGON2_P})+hkdf-sha256"),
        other => format!("{other}+hkdf-sha256"),
    }
}

static FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_once(msg: &str) {
    if !FALLBACK_WARNED.swap(true, Ordering::SeqCst) {
        tracing::warn!("{msg}");
    }
}

fn random_key() -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(k.as_mut());
    k
}

/// Keyring user name for a profile directory: `profile-` + 32 hex of SHA-256(abs path).
pub(crate) fn keyring_user_for(profile_dir: &Path) -> String {
    let abs = std::fs::canonicalize(profile_dir).unwrap_or_else(|_| profile_dir.to_path_buf());
    let digest = Sha256::digest(abs.to_string_lossy().as_bytes());
    let hex: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
    format!("profile-{hex}")
}

fn read_salt(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok().filter(|s| s.len() >= 16)
}

fn write_salt(path: &Path, salt: &[u8]) -> Result<()> {
    std::fs::write(path, salt)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn finish(
    master: &[u8],
    meta: &ProfileMeta,
    source: &'static str,
    meta_kdf: &'static str,
    keyring_user: Option<String>,
    fallback: Option<String>,
) -> Result<Unlocked> {
    let key = derive_data_key(master)?;
    let setup = match &meta.kcv {
        Some(kcv) => {
            if !kcv_ok(&key, kcv) {
                return Err(Error::ProfileLocked(format!(
                    "wrong {source} key for this profile (key-check value mismatch)"
                )));
            }
            None
        }
        None => Some(KeySetup {
            meta_kdf,
            keyring_user,
        }),
    };
    Ok(Unlocked {
        vault: Vault {
            key: Some(key),
            source,
            kdf: Some(kdf_desc(meta_kdf)),
            fallback,
        },
        setup,
    })
}

fn unlock_passphrase(
    profile_dir: &Path,
    meta: &ProfileMeta,
    pass: &str,
    fallback: Option<String>,
) -> Result<Unlocked> {
    if pass.is_empty() {
        return Err(Error::ProfileLocked(format!(
            "empty profile passphrase (is {PASSPHRASE_ENV} set?)"
        )));
    }
    let salt_path = profile_dir.join(SALT_FILE);
    let new_path = profile_dir.join(SALT_NEW_FILE);
    if meta.kcv.is_none() {
        // First keyed open: reuse a salt left by an interrupted attempt, else create one.
        let salt = match read_salt(&salt_path) {
            Some(s) => s,
            None => {
                let mut s = vec![0u8; 16];
                OsRng.fill_bytes(&mut s);
                write_salt(&salt_path, &s)?;
                s
            }
        };
        let master = argon2id(pass, &salt)?;
        return finish(
            master.as_ref(),
            meta,
            "passphrase",
            "argon2id",
            None,
            fallback,
        );
    }
    if meta.kdf.as_deref() != Some("argon2id") {
        return Err(Error::ProfileLocked(format!(
            "this profile is keyed by {} , not a passphrase",
            meta.kdf.as_deref().unwrap_or("an unknown source")
        )));
    }
    // Keyed: profile.salt, then profile.salt.new (a rewrap interrupted after commit).
    let mut last = Error::ProfileLocked(format!("{SALT_FILE} is missing from the profile"));
    for (i, p) in [&salt_path, &new_path].into_iter().enumerate() {
        let Some(salt) = read_salt(p) else { continue };
        let master = argon2id(pass, &salt)?;
        match finish(
            master.as_ref(),
            meta,
            "passphrase",
            "argon2id",
            None,
            fallback.clone(),
        ) {
            Ok(u) => {
                if i == 1 {
                    std::fs::rename(&new_path, &salt_path)?;
                } else if new_path.exists() {
                    let _ = std::fs::remove_file(&new_path);
                }
                return Ok(u);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn unlock_none(meta: &ProfileMeta, reason: Option<String>) -> Result<Unlocked> {
    if meta.kcv.is_some() {
        return Err(Error::ProfileLocked(
            "this profile is encrypted at rest; a key is required".into(),
        ));
    }
    if !plaintext_allowed() {
        return Err(Error::ProfileLocked(format!(
            "refusing to open a plaintext profile: set {ALLOW_PLAINTEXT_ENV}=1 to allow it"
        )));
    }
    let note = reason.unwrap_or_else(|| "plaintext profile (explicitly allowed)".into());
    tracing::warn!("profile is NOT encrypted at rest: {note}");
    Ok(Unlocked {
        vault: Vault {
            key: None,
            source: "none",
            kdf: None,
            fallback: Some(note),
        },
        setup: None,
    })
}

/// Resolve `src` for the profile at `profile_dir` whose metadata is `meta`. Verifies the
/// key-check value; never reads a sensitive row.
pub(crate) fn unlock(
    profile_dir: &Path,
    meta: &ProfileMeta,
    src: &ProfileKeySource,
) -> Result<Unlocked> {
    match src {
        ProfileKeySource::Raw(k) => {
            if k.len() != 32 {
                return Err(Error::InvalidInput(format!(
                    "raw profile key must be 32 bytes, got {}",
                    k.len()
                )));
            }
            if meta.kcv.is_some() && meta.kdf.as_deref() != Some("raw") {
                return Err(Error::ProfileLocked(format!(
                    "this profile is keyed by {}, not a raw key",
                    meta.kdf.as_deref().unwrap_or("an unknown source")
                )));
            }
            finish(k, meta, "raw", "raw", None, None)
        }
        ProfileKeySource::Passphrase(p) => unlock_passphrase(profile_dir, meta, p, None),
        ProfileKeySource::None => unlock_none(meta, None),
        ProfileKeySource::Keyring => match meta.kdf.as_deref() {
            Some("argon2id") if meta.kcv.is_some() => match env_passphrase() {
                Some(p) => unlock_passphrase(
                    profile_dir,
                    meta,
                    &p,
                    Some(format!("profile is passphrase-keyed; used ${PASSPHRASE_ENV}")),
                ),
                None => Err(Error::ProfileLocked(format!(
                    "this profile is protected by a passphrase: use --profile-key passphrase or set {PASSPHRASE_ENV}"
                ))),
            },
            Some("raw") if meta.kcv.is_some() => Err(Error::ProfileLocked(
                "this profile is keyed by the app (raw key); open it through the app".into(),
            )),
            _ => unlock_keyring(profile_dir, meta),
        },
    }
}

fn unlock_keyring(profile_dir: &Path, meta: &ProfileMeta) -> Result<Unlocked> {
    let user = meta
        .keyring_user
        .clone()
        .unwrap_or_else(|| keyring_user_for(profile_dir));
    match os_keyring::get(&user) {
        Ok(Some(master)) => finish(
            master.as_ref(),
            meta,
            "keyring",
            "keyring",
            Some(user),
            None,
        ),
        Ok(None) if meta.kcv.is_some() => Err(Error::ProfileLocked(format!(
            "the keyring has no entry {KEYRING_SERVICE}/{user} for this encrypted profile"
        ))),
        Ok(None) => {
            let master = random_key();
            os_keyring::set(&user, master.as_ref()).map_err(|e| {
                Error::ProfileLocked(format!(
                    "could not store the profile key in the keyring: {e}"
                ))
            })?;
            finish(
                master.as_ref(),
                meta,
                "keyring",
                "keyring",
                Some(user),
                None,
            )
        }
        Err(reason) => {
            if meta.kcv.is_some() {
                // Keyed by the keyring and the keyring is gone: never downgrade.
                return Err(Error::ProfileLocked(format!(
                    "the profile key is in the OS keyring, which is not reachable ({reason})"
                )));
            }
            if let Some(p) = env_passphrase() {
                let note = format!("no OS keyring reachable ({reason}); using ${PASSPHRASE_ENV}");
                warn_once(&note);
                return unlock_passphrase(profile_dir, meta, &p, Some(note));
            }
            if plaintext_allowed() {
                let note = format!(
                    "no OS keyring reachable ({reason}); plaintext allowed by {ALLOW_PLAINTEXT_ENV}=1"
                );
                warn_once(&note);
                return unlock_none(meta, Some(note));
            }
            Err(Error::ProfileLocked(format!(
                "no OS keyring reachable ({reason}): set {PASSPHRASE_ENV} (or --profile-key passphrase), \
                 or {ALLOW_PLAINTEXT_ENV}=1 for an unencrypted profile"
            )))
        }
    }
}

// ----- store integration -----------------------------------------------------------------------

/// Install `u` on an open connection: re-check under an IMMEDIATE transaction and, when the
/// profile is not keyed yet, write the key metadata and wrap every legacy plaintext value.
pub(crate) fn install(conn: &mut Connection, u: &Unlocked) -> Result<u64> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let meta = read_meta(&tx)?;
    let mut migrated = 0;
    match (&u.vault.key, &meta.kcv, &u.setup) {
        (Some(k), Some(kcv), _) => {
            // Another process may have keyed the profile meanwhile: check again.
            if !kcv_ok(k, kcv) {
                return Err(Error::ProfileLocked("wrong key for this profile".into()));
            }
        }
        (Some(k), None, Some(setup)) => {
            write_meta(&tx, setup, k)?;
            migrated = recode_all(&tx, None, Some(k))?;
            if migrated > 0 {
                tracing::info!("profile migrated: {migrated} legacy values wrapped");
            }
        }
        (Some(_), None, None) => {
            return Err(Error::ProfileLocked("profile key metadata vanished".into()));
        }
        (None, Some(_), _) => {
            return Err(Error::ProfileLocked(
                "this profile is encrypted at rest; a key is required".into(),
            ))
        }
        (None, None, _) => {}
    }
    tx.commit()?;
    if migrated > 0 {
        scrub(conn);
    }
    Ok(migrated)
}

/// After a migration or rewrap: drop the old plaintext/ciphertext page images from the WAL
/// and the free pages of the file (`secure_delete` zeroes freed cells; VACUUM rebuilds the
/// file). Best effort: another open connection can make it busy, which is only logged.
pub(crate) fn scrub(conn: &Connection) {
    if let Err(e) = conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")
    {
        tracing::warn!("profile scrub after rewrap incomplete (another process has it open?): {e}");
    }
}

/// A rewrap target: data key (None = plaintext), metadata to record, source, note.
type StagedKey = (
    Option<Zeroizing<[u8; 32]>>,
    Option<KeySetup>,
    &'static str,
    Option<String>,
);

impl Engine {
    /// Key source and how many sensitive values are wrapped / still plaintext.
    pub fn profile_key_status(&self) -> Result<ProfileKeyStatus> {
        let store = self.store();
        let (wrapped_rows, plaintext_rows) = count_rows(store.conn())?;
        let v = store.vault();
        Ok(ProfileKeyStatus {
            source: v.source.to_string(),
            wrapped_rows,
            plaintext_rows,
            kdf: v.kdf.clone(),
            fallback: v.fallback.clone(),
        })
    }

    /// Re-encrypt every sensitive value under a new key source in one transaction. The old
    /// key stops working; a keyring entry of the old key is deleted after the commit.
    /// `Keyring` always creates a fresh random key (key rotation); `None` needs
    /// `SEALBOX_ALLOW_PLAINTEXT_PROFILE=1`.
    pub fn rewrap_profile(&self, new: ProfileKeySource) -> Result<ProfileKeyStatus> {
        let dir = self.profile_dir().to_path_buf();
        let salt_new = dir.join(SALT_NEW_FILE);
        // 1. The new key, staged so that a failure leaves the old one intact.
        let mut cleanup_user: Option<String> = None;
        let (new_key, setup, source, fallback): StagedKey = match &new {
            ProfileKeySource::Keyring => {
                let user = format!("{}-{}", keyring_user_for(&dir), crate::store::now());
                let master = random_key();
                os_keyring::set(&user, master.as_ref()).map_err(|e| {
                    Error::ProfileLocked(format!("OS keyring not usable for rewrap: {e}"))
                })?;
                cleanup_user = Some(user.clone());
                (
                    Some(derive_data_key(master.as_ref())?),
                    Some(KeySetup {
                        meta_kdf: "keyring",
                        keyring_user: Some(user),
                    }),
                    "keyring",
                    None,
                )
            }
            ProfileKeySource::Passphrase(p) => {
                if p.is_empty() {
                    return Err(Error::InvalidInput("empty new passphrase".into()));
                }
                let mut salt = vec![0u8; 16];
                OsRng.fill_bytes(&mut salt);
                write_salt(&salt_new, &salt)?;
                let master = argon2id(p, &salt)?;
                (
                    Some(derive_data_key(master.as_ref())?),
                    Some(KeySetup {
                        meta_kdf: "argon2id",
                        keyring_user: None,
                    }),
                    "passphrase",
                    None,
                )
            }
            ProfileKeySource::Raw(k) => {
                if k.len() != 32 {
                    return Err(Error::InvalidInput(
                        "raw profile key must be 32 bytes".into(),
                    ));
                }
                (
                    Some(derive_data_key(k)?),
                    Some(KeySetup {
                        meta_kdf: "raw",
                        keyring_user: None,
                    }),
                    "raw",
                    None,
                )
            }
            ProfileKeySource::None => {
                if !plaintext_allowed() {
                    return Err(Error::InvalidInput(format!(
                        "rewrap to plaintext needs {ALLOW_PLAINTEXT_ENV}=1"
                    )));
                }
                (
                    None,
                    None,
                    "none",
                    Some("plaintext profile (rewrapped to none)".into()),
                )
            }
        };
        let undo = |user: &Option<String>| {
            if let Some(u) = user {
                let _ = os_keyring::delete(u);
            }
            let _ = std::fs::remove_file(&salt_new);
        };
        // 2. One transaction: recode every value, replace the metadata.
        let mut store = self.store();
        let old_meta = read_meta(store.conn())?;
        let result = (|| -> Result<()> {
            let old_key = store.vault().key.clone();
            let tx = store
                .conn_mut()
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            recode_all(&tx, old_key.as_deref(), new_key.as_deref())?;
            match (&new_key, &setup) {
                (Some(k), Some(s)) => write_meta(&tx, s, k)?,
                _ => {
                    tx.execute("DELETE FROM profile_meta", [])?;
                }
            }
            tx.commit()?;
            Ok(())
        })();
        if let Err(e) = result {
            undo(&cleanup_user);
            return Err(e);
        }
        // 3. Committed: finalise files and retire the old keyring entry.
        let salt_path = dir.join(SALT_FILE);
        if matches!(new, ProfileKeySource::Passphrase(_)) {
            std::fs::rename(&salt_new, &salt_path)?;
        } else if salt_path.exists() {
            let _ = std::fs::remove_file(&salt_path);
        }
        if old_meta.kdf.as_deref() == Some("keyring") {
            let old_user = old_meta
                .keyring_user
                .clone()
                .unwrap_or_else(|| keyring_user_for(&dir));
            if cleanup_user.as_deref() != Some(old_user.as_str()) {
                if let Err(e) = os_keyring::delete(&old_user) {
                    tracing::warn!("old keyring entry {old_user} not deleted: {e}");
                }
            }
        }
        scrub(store.conn());
        store.set_vault(Vault {
            key: new_key,
            source,
            kdf: setup.as_ref().map(|s| kdf_desc(s.meta_kdf)),
            fallback,
        });
        drop(store);
        self.profile_key_status()
    }
}

/// Path of the salt file of a profile (for docs/tests).
pub fn salt_path(profile_dir: &Path) -> PathBuf {
    profile_dir.join(SALT_FILE)
}

// ----- OS keyring ------------------------------------------------------------------------------

/// The OS keyring. Every call runs on its own thread (the Secret Service client must not
/// nest inside the caller's async runtime) with a timeout, so a keyring that never answers
/// (locked collection waiting on a prompt nobody sees) counts as unreachable.
mod os_keyring {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    use super::KEYRING_SERVICE;
    use super::NO_KEYRING_ENV;
    use zeroize::Zeroizing;

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

    fn disabled() -> Option<String> {
        if std::env::var(NO_KEYRING_ENV).is_ok_and(|v| v.trim() == "1") {
            return Some(format!("{NO_KEYRING_ENV}=1"));
        }
        None
    }

    /// Cheap reachability check before talking to the Secret Service: cron and CI have no
    /// session bus, and zbus would otherwise fail slowly or try to autolaunch one.
    #[cfg(target_os = "linux")]
    fn precheck() -> Result<(), String> {
        match std::env::var("DBUS_SESSION_BUS_ADDRESS") {
            Ok(addr) if !addr.trim().is_empty() => {
                for part in addr.split(';') {
                    if let Some(rest) = part.strip_prefix("unix:") {
                        for kv in rest.split(',') {
                            if let Some(p) = kv.strip_prefix("path=") {
                                if std::path::Path::new(p).exists() {
                                    return Ok(());
                                }
                                return Err(format!("session bus socket {p} does not exist"));
                            }
                        }
                    }
                }
                Ok(())
            }
            _ => match std::env::var("XDG_RUNTIME_DIR") {
                Ok(d) if std::path::Path::new(&d).join("bus").exists() => Ok(()),
                _ => Err("no D-Bus session bus (DBUS_SESSION_BUS_ADDRESS unset)".into()),
            },
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn precheck() -> Result<(), String> {
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn on_thread<T: Send + 'static>(
        f: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        if let Some(r) = disabled() {
            return Err(r);
        }
        precheck()?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("sealbox-keyring".into())
            .spawn(move || {
                let _ = tx.send(f());
            })
            .map_err(|e| format!("spawn: {e}"))?;
        rx.recv_timeout(TIMEOUT)
            .map_err(|_| format!("keyring did not answer within {}s", TIMEOUT.as_secs()))?
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn entry(user: &str) -> Result<keyring::Entry, String> {
        keyring::Entry::new(KEYRING_SERVICE, user).map_err(|e| e.to_string())
    }

    /// `Ok(None)` = reachable, no entry. `Err` = keyring unreachable/unusable.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(super) fn get(user: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        use base64::Engine as _;
        let user = user.to_string();
        on_thread(move || match entry(&user)?.get_password() {
            Ok(p) => {
                let p = Zeroizing::new(p);
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(p.trim())
                    .map_err(|e| format!("keyring entry is not base64: {e}"))?;
                if bytes.len() != 32 {
                    return Err(format!("keyring entry has {} bytes, want 32", bytes.len()));
                }
                Ok(Some(Zeroizing::new(bytes)))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        })
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(super) fn set(user: &str, key: &[u8]) -> Result<(), String> {
        use base64::Engine as _;
        let user = user.to_string();
        let b64 = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(key));
        on_thread(move || entry(&user)?.set_password(&b64).map_err(|e| e.to_string()))
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(super) fn delete(user: &str) -> Result<(), String> {
        let user = user.to_string();
        on_thread(move || match entry(&user)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub(super) fn get(_user: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        Err(disabled().unwrap_or_else(|| {
            "no OS keyring on this platform (the app passes ProfileKeySource::Raw)".into()
        }))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub(super) fn set(user: &str, _key: &[u8]) -> Result<(), String> {
        get(user).map(|_| ())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub(super) fn delete(_user: &str) -> Result<(), String> {
        Ok(())
    }

    /// Test hook: is the keyring reachable from here?
    #[cfg(test)]
    pub(super) fn probe() -> Result<(), String> {
        get("probe-nonexistent-entry").map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const K: [u8; 32] = [7u8; 32];

    #[test]
    fn envelope_round_trip_and_format() {
        let w = seal(&K, "messages:raw:1", b"hello body").unwrap();
        assert!(w.starts_with(MAGIC));
        assert_eq!(w.len(), 4 + NONCE_LEN + 10 + TAG_LEN);
        assert!(is_envelope(&w));
        assert_eq!(open(&K, "messages:raw:1", &w).unwrap(), b"hello body");
        // empty plaintext works too
        let e = seal(&K, "a:b:1", b"").unwrap();
        assert_eq!(open(&K, "a:b:1", &e).unwrap(), b"");
    }

    #[test]
    fn aad_binding_swapped_rows_and_columns_fail() {
        let a = seal(&K, &aad("messages", "text_body", "1"), b"one").unwrap();
        let b = seal(&K, &aad("messages", "text_body", "2"), b"two").unwrap();
        assert!(matches!(
            open(&K, &aad("messages", "text_body", "2"), &a),
            Err(Error::SecretIntegrity(_))
        ));
        assert!(open(&K, &aad("messages", "text_body", "1"), &b).is_err());
        assert!(open(&K, &aad("messages", "html_body", "1"), &a).is_err());
        assert!(open(&K, &aad("attachments", "text_body", "1"), &a).is_err());
    }

    #[test]
    fn tamper_and_wrong_key_fail() {
        let w = seal(&K, "t:c:1", b"secret").unwrap();
        for i in [4, 4 + NONCE_LEN, w.len() - 1] {
            let mut t = w.clone();
            t[i] ^= 1;
            assert!(open(&K, "t:c:1", &t).is_err(), "flip at {i}");
        }
        assert!(open(&K, "t:c:1", &w[..w.len() - 1]).is_err());
        assert!(open(&[8u8; 32], "t:c:1", &w).is_err());
        assert!(open(&K, "t:c:1", b"sbx1short").is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let mut seen = HashSet::new();
        for _ in 0..2000 {
            let w = seal(&K, "t:c:1", b"same").unwrap();
            assert!(seen.insert(w[4..4 + NONCE_LEN].to_vec()));
        }
    }

    #[test]
    fn kdf_and_kcv() {
        let k1 = derive_data_key(&[1u8; 32]).unwrap();
        let k2 = derive_data_key(&[1u8; 32]).unwrap();
        let k3 = derive_data_key(&[2u8; 32]).unwrap();
        assert_eq!(*k1, *k2);
        assert_ne!(*k1, *k3);
        assert_ne!(*k1, [1u8; 32]);
        // HKDF-SHA256 test vector shape: info binds the output
        let hk = hkdf::Hkdf::<Sha256>::new(None, &[1u8; 32]);
        let mut other = [0u8; 32];
        hk.expand(b"another-info", &mut other).unwrap();
        assert_ne!(*k1, other);

        let salt = b"0123456789abcdef";
        let a = argon2id("correct horse", salt).unwrap();
        let b = argon2id("correct horse", salt).unwrap();
        let c = argon2id("correct horsf", salt).unwrap();
        let d = argon2id("correct horse", b"0123456789abcdeX").unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
        assert_ne!(*a, *d);

        let key = derive_data_key(a.as_ref()).unwrap();
        let kcv = seal(&key, KCV_AAD, KCV_PLAINTEXT).unwrap();
        assert!(kcv_ok(&key, &kcv));
        let wrong = derive_data_key(c.as_ref()).unwrap();
        assert!(!kcv_ok(&wrong, &kcv));
    }

    #[test]
    fn vault_text_blob_modes() {
        let v = Vault::with_master(&K).unwrap();
        let s = v.seal_text("accounts", "credential", "3", "pw").unwrap();
        assert!(matches!(&s, Value::Blob(b) if is_envelope(b)));
        assert_eq!(
            v.open_text("accounts", "credential", "3", s.clone())
                .unwrap(),
            "pw"
        );
        assert!(v
            .open_text("accounts", "credential", "4", s.clone())
            .is_err());
        // keyed vault refuses unwrapped values
        assert!(v
            .open_text("accounts", "credential", "3", Value::Text("pw".into()))
            .is_err());
        // plaintext vault: TEXT round trip, refuses envelopes with ProfileLocked
        let p = Vault::plaintext();
        assert_eq!(
            p.seal_text("accounts", "credential", "3", "pw").unwrap(),
            Value::Text("pw".into())
        );
        assert!(matches!(
            p.open_text("accounts", "credential", "3", s),
            Err(Error::ProfileLocked(_))
        ));
        assert_eq!(v.open_opt_text("m", "h", "1", Value::Null).unwrap(), None);
    }

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static L: OnceLock<Mutex<()>> = OnceLock::new();
        match L.get_or_init(|| Mutex::new(())).lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    #[test]
    fn keyring_fallback_headless() {
        let _g = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let meta = ProfileMeta::default();
        std::env::set_var(NO_KEYRING_ENV, "1");
        std::env::remove_var(PASSPHRASE_ENV);
        std::env::remove_var(PASSPHRASE_ENV_NAME_ENV);
        std::env::remove_var(ALLOW_PLAINTEXT_ENV);
        assert!(os_keyring::probe().is_err());
        // nothing to fall back to: locked, never silently plaintext
        assert!(matches!(
            unlock(dir.path(), &meta, &ProfileKeySource::Keyring),
            Err(Error::ProfileLocked(_))
        ));
        // passphrase fallback
        std::env::set_var(PASSPHRASE_ENV, "headless pass");
        let u = unlock(dir.path(), &meta, &ProfileKeySource::Keyring).unwrap();
        assert_eq!(u.vault.source, "passphrase");
        assert!(u
            .vault
            .fallback
            .as_deref()
            .unwrap_or("")
            .contains("no OS keyring"));
        assert!(u.setup.is_some());
        assert!(dir.path().join(SALT_FILE).exists());
        // explicit plaintext allow (no passphrase)
        std::env::remove_var(PASSPHRASE_ENV);
        let dir2 = tempfile::tempdir().unwrap();
        std::env::set_var(ALLOW_PLAINTEXT_ENV, "1");
        let u = unlock(dir2.path(), &meta, &ProfileKeySource::Keyring).unwrap();
        assert!(!u.vault.is_keyed());
        assert!(u.vault.fallback.is_some());
        // ... but a keyring-keyed profile never downgrades
        let keyed = ProfileMeta {
            kcv: Some(seal(&K, KCV_AAD, KCV_PLAINTEXT).unwrap()),
            kdf: Some("keyring".into()),
            keyring_user: None,
        };
        std::env::set_var(PASSPHRASE_ENV, "headless pass");
        assert!(matches!(
            unlock(dir2.path(), &keyed, &ProfileKeySource::Keyring),
            Err(Error::ProfileLocked(_))
        ));
        assert!(matches!(
            unlock(dir2.path(), &keyed, &ProfileKeySource::None),
            Err(Error::ProfileLocked(_))
        ));
        std::env::remove_var(ALLOW_PLAINTEXT_ENV);
        std::env::remove_var(PASSPHRASE_ENV);
        std::env::remove_var(NO_KEYRING_ENV);
    }

    #[test]
    fn none_requires_allow_flag() {
        let _g = env_lock();
        std::env::remove_var(ALLOW_PLAINTEXT_ENV);
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            unlock(dir.path(), &ProfileMeta::default(), &ProfileKeySource::None),
            Err(Error::ProfileLocked(_))
        ));
        assert!(matches!(
            unlock(
                dir.path(),
                &ProfileMeta::default(),
                &ProfileKeySource::Raw(vec![1; 31])
            ),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn from_env_and_override_debug_redacts() {
        let s = format!("{:?}", ProfileKeySource::Passphrase("hunter2".into()));
        assert!(!s.contains("hunter2"));
        assert!(!format!("{:?}", ProfileKeySource::Raw(vec![0xAB; 32])).contains("171"));
        assert_eq!(ProfileKeySource::Keyring.kind(), "keyring");
    }

    fn legacy_profile(dir: &Path) -> i64 {
        // Exactly what a pre-G27 build wrote: plaintext TEXT/BLOB values, no profile_meta.
        let mut store = crate::store::Store::open(&dir.join(crate::engine::DB_FILE)).unwrap();
        let ep = sealbox_mail::autodiscover::Endpoint::new(
            "127.0.0.1",
            9,
            sealbox_mail::Security::Plain,
        );
        let id = store
            .insert_account(&crate::store::NewAccount {
                email: "legacy@example.org",
                display_name: "Legacy",
                imap: &ep,
                smtp: &ep,
                auth_kind: crate::types::AuthKind::Password,
                login: "legacy",
                credential: "legacy-password",
            })
            .unwrap();
        store
            .insert_identity(id, "FPRL", "legacy@example.org", "LEGACY-SECRET", "pub")
            .unwrap();
        let folder = store.folder(id, "INBOX").unwrap();
        store
            .insert_message(&crate::store::NewMessage {
                account_id: id,
                folder_id: folder.id,
                uid: 1,
                message_id: Some("l1@example.org".into()),
                from: crate::types::Address {
                    name: None,
                    address: "x@example.org".into(),
                },
                to: vec![],
                cc: vec![],
                subject: Some("legacy subject".into()),
                protected_subject: false,
                date: Some(1),
                received_at: 1,
                flags: vec![],
                was_encrypted: false,
                decrypted: false,
                was_signed: false,
                signature: crate::types::SignatureSummary {
                    status: crate::types::SigState::None,
                    fingerprint: None,
                    signer: None,
                    ..Default::default()
                },
                signatures_json: "[]".into(),
                text: Some("legacy body".into()),
                html: None,
                in_reply_to: vec![],
                references: vec![],
                decrypt_error: None,
                raw: b"Subject: legacy subject\r\n\r\nlegacy body".to_vec(),
                attachments: vec![],
            })
            .unwrap()
            .unwrap()
    }

    fn cfg(src: ProfileKeySource) -> crate::engine::EngineConfig {
        crate::engine::EngineConfig {
            profile_key: src,
            ..crate::engine::EngineConfig::default()
        }
    }

    #[test]
    fn engine_migrates_locks_and_rewraps() {
        let _g = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let mid = legacy_profile(dir.path());
        let a = ProfileKeySource::Raw(vec![1u8; 32]);
        {
            let e = Engine::open_with(dir.path(), cfg(a.clone())).unwrap();
            let st = e.profile_key_status().unwrap();
            assert_eq!((st.source.as_str(), st.plaintext_rows), ("raw", 0));
            assert!(st.wrapped_rows >= 4, "{st:?}");
            assert_eq!(
                e.get_message(mid).unwrap().text.as_deref(),
                Some("legacy body")
            );
            assert!(matches!(e.config().profile_key, ProfileKeySource::Raw(ref k) if k.is_empty()));
        }
        // wrong key / wrong kind / no key: locked
        for bad in [
            ProfileKeySource::Raw(vec![2u8; 32]),
            ProfileKeySource::Passphrase("guess".into()),
            ProfileKeySource::None,
        ] {
            let r = Engine::open_with(dir.path(), cfg(bad.clone()));
            assert!(matches!(r, Err(Error::ProfileLocked(_))), "{bad:?}: {r:?}");
        }
        // rewrap raw -> passphrase -> raw
        {
            let e = Engine::open_with(dir.path(), cfg(a.clone())).unwrap();
            let st = e
                .rewrap_profile(ProfileKeySource::Passphrase("p1".into()))
                .unwrap();
            assert_eq!(st.source, "passphrase");
            assert_eq!(st.plaintext_rows, 0);
            assert_eq!(
                e.get_message(mid).unwrap().text.as_deref(),
                Some("legacy body")
            );
        }
        assert!(dir.path().join(SALT_FILE).exists());
        assert!(matches!(
            Engine::open_with(dir.path(), cfg(a.clone())),
            Err(Error::ProfileLocked(_))
        ));
        assert!(matches!(
            Engine::open_with(dir.path(), cfg(ProfileKeySource::Passphrase("p2".into()))),
            Err(Error::ProfileLocked(_))
        ));
        {
            let e = Engine::open_with(dir.path(), cfg(ProfileKeySource::Passphrase("p1".into())))
                .unwrap();
            assert_eq!(e.account("legacy@example.org").unwrap().login, "legacy");
            let st = e
                .rewrap_profile(ProfileKeySource::Raw(vec![3u8; 32]))
                .unwrap();
            assert_eq!(st.source, "raw");
        }
        assert!(!dir.path().join(SALT_FILE).exists());
        assert!(
            Engine::open_with(dir.path(), cfg(ProfileKeySource::Passphrase("p1".into()))).is_err()
        );
        let e = Engine::open_with(dir.path(), cfg(ProfileKeySource::Raw(vec![3u8; 32]))).unwrap();
        assert_eq!(
            e.get_raw_message(mid).unwrap(),
            b"Subject: legacy subject\r\n\r\nlegacy body"
        );
        // rewrap to plaintext needs the explicit flag
        std::env::remove_var(ALLOW_PLAINTEXT_ENV);
        assert!(e.rewrap_profile(ProfileKeySource::None).is_err());
        std::env::set_var(ALLOW_PLAINTEXT_ENV, "1");
        let st = e.rewrap_profile(ProfileKeySource::None).unwrap();
        assert_eq!((st.source.as_str(), st.wrapped_rows), ("none", 0));
        assert!(st.plaintext_rows >= 4);
        drop(e);
        let e = Engine::open_with(dir.path(), cfg(ProfileKeySource::None)).unwrap();
        assert_eq!(
            e.get_message(mid).unwrap().text.as_deref(),
            Some("legacy body")
        );
        std::env::remove_var(ALLOW_PLAINTEXT_ENV);
    }

    /// A pre-G27 profile from before `message_blobs` too (plaintext bodies and raw MIME in the
    /// `messages` row): the first keyed open moves the blobs (`Store::open`), then wraps them
    /// under the `messages:<column>:<id>` AAD; the status count, a wrong key and a rewrap all
    /// cover the new table.
    #[test]
    fn legacy_plaintext_blob_columns_move_then_wrap() {
        let _g = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join(crate::engine::DB_FILE);
        crate::store::legacy_blob_db(&db, None, 3).unwrap();
        let a = ProfileKeySource::Raw(vec![4u8; 32]);
        {
            let e = Engine::open_with(dir.path(), cfg(a.clone())).unwrap();
            let st = e.profile_key_status().unwrap();
            assert_eq!(st.plaintext_rows, 0, "{st:?}");
            // credential + 3 text + 2 HTML + 3 raw
            assert!(st.wrapped_rows >= 9, "{st:?}");
            let m = e.get_message(3).unwrap();
            assert_eq!(m.text.as_deref(), Some("body 3"));
            assert_eq!(m.html.as_deref(), Some("<p>html 3</p>"));
            assert_eq!(e.get_raw_message(2).unwrap(), b"raw 2");
            let k = derive_data_key(&[4u8; 32]).unwrap();
            let raw: Vec<u8> = e
                .store()
                .conn()
                .query_row(
                    "SELECT raw FROM message_blobs WHERE message_id = 2",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(open(&k, "messages:raw:2", &raw).unwrap(), b"raw 2");
            assert!(open(&k, "message_blobs:raw:2", &raw).is_err());
            assert!(open(&k, "messages:raw:1", &raw).is_err());
        }
        assert!(matches!(
            Engine::open_with(dir.path(), cfg(ProfileKeySource::Raw(vec![5u8; 32]))),
            Err(Error::ProfileLocked(_))
        ));
        let e = Engine::open_with(dir.path(), cfg(a)).unwrap();
        let st = e
            .rewrap_profile(ProfileKeySource::Raw(vec![6u8; 32]))
            .unwrap();
        assert_eq!(st.plaintext_rows, 0);
        assert!(st.wrapped_rows >= 9, "{st:?}");
        assert_eq!(e.get_raw_message(1).unwrap(), b"raw 1");
        assert_eq!(
            e.get_message(1).unwrap().html.as_deref(),
            Some("<p>html 1</p>")
        );
        drop(e);
        let e = Engine::open_with(dir.path(), cfg(ProfileKeySource::Raw(vec![6u8; 32]))).unwrap();
        assert_eq!(e.get_message(2).unwrap().text.as_deref(), Some("body 2"));
    }

    /// Real OS keyring round trip. Opt-in (`SEALBOX_TEST_REAL_KEYRING=1`) because it writes
    /// to the developer's keyring (an entry `sealbox/sealbox-unit-test-…`, deleted again).
    #[test]
    fn real_keyring_round_trip_opt_in() {
        if std::env::var("SEALBOX_TEST_REAL_KEYRING").ok().as_deref() != Some("1") {
            eprintln!("skipped: set SEALBOX_TEST_REAL_KEYRING=1");
            return;
        }
        let _g = env_lock();
        std::env::remove_var(NO_KEYRING_ENV);
        let user = format!("sealbox-unit-test-{}", std::process::id());
        let key = random_key();
        os_keyring::set(&user, key.as_ref()).expect("keyring set");
        let back = os_keyring::get(&user).expect("keyring get").expect("entry");
        assert_eq!(back.as_slice(), key.as_ref());
        os_keyring::delete(&user).expect("keyring delete");
        assert!(os_keyring::get(&user).expect("keyring get").is_none());
    }
}
