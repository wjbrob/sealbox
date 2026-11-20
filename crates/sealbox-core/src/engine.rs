//! The [`Engine`]: profile directory, store handle, configuration, account and key
//! management, and the local (offline) reading API. Network pipelines live in `sync.rs`
//! and `send.rs`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use sealbox_crypto::{Identity, PeerState, PreferEncrypt, PublicKey};
use sealbox_mail::autodiscover::{self, ServerConfig};
use sealbox_mail::imap::FlagOp as ImapFlagOp;
use sealbox_mail::{net_policy, ImapError};

use crate::error::{Error, Result};
use crate::policy::{self, ExtraKey, ResolvedRecipient};
use crate::store::{AccountRow, IdentityRow, NewAccount, Store};
use crate::transport::{self, NETWORK_TIMEOUT};
use crate::types::{
    AccountInfo, AddAccount, AttachmentInfo, AuthKind, AuthSpec, Contact, FlagOp, KeySource,
    ListQuery, MessageDetail, MessageSummary, RecipientStatus,
};
use crate::vault::{self, ProfileKeySource};

/// File name of the database inside the profile directory.
pub const DB_FILE: &str = "sealbox.db";

/// Engine configuration. [`EngineConfig::from_env`] reads `SEALBOX_DIRECTORY_URL`,
/// `SEALBOX_SERVER_URL`, `SEALBOX_NETWORK_TIMEOUT_SECS` and the profile key source
/// ([`ProfileKeySource::from_env`]: `SEALBOX_PROFILE_KEY`, `SEALBOX_PROFILE_PASSPHRASE`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineConfig {
    /// Base URL of a VKS-compatible key directory (`GET /vks/v1/by-email/{email}`).
    /// `None` = never looked up.
    pub directory_url: Option<String>,
    /// Base URL of the Sealbox server for guest links (`POST /v1/guest`). `None` = the
    /// guest-link policy is unavailable.
    pub server_url: Option<String>,
    /// Timeout for each network operation.
    pub network_timeout: Duration,
    /// Our own `prefer-encrypt` setting (Autocrypt Level 1). Sealbox defaults to `mutual`.
    pub prefer_encrypt: PreferEncrypt,
    /// Lifetime requested for guest messages (server clamps). `None` = server default.
    pub guest_expiry_secs: Option<i64>,
    /// Where the at-rest key of the profile comes from (G27). Default: the OS keyring. After
    /// [`Engine::open_with`] the secret inside `Passphrase`/`Raw` is dropped from the stored
    /// config (it is emptied), the derived key lives only in the store.
    pub profile_key: ProfileKeySource,
    /// First sync of a folder: only its newest `sync_window` messages, newest first, so a big
    /// mailbox shows its recent mail in seconds; the rest is backfilled (below). 0 = the whole
    /// folder in the first sync, oldest first (the behaviour before the window existed).
    /// Env: `SEALBOX_SYNC_WINDOW`.
    pub sync_window: usize,
    /// Every later [`Engine::sync`] (and [`Engine::sync_folder_role`]) fetches up to this many
    /// older messages per folder below the window, newest first, after the new mail; 0 = only
    /// [`Engine::backfill`] does. [`Engine::watch`] never backfills. Env: `SEALBOX_SYNC_BACKFILL`.
    pub backfill_per_sync: usize,
    /// At most this many messages per `UID FETCH` round trip…
    pub fetch_batch: usize,
    /// …and at most this many bytes (by `RFC822.SIZE`, asked for first; a bigger message
    /// travels alone; 0 = no byte limit). The next batch is on the wire while one is
    /// processed, so about two batches are in memory at a time.
    pub fetch_batch_bytes: usize,
}

/// Default [`EngineConfig::sync_window`].
pub const DEFAULT_SYNC_WINDOW: usize = 500;
/// Default [`EngineConfig::backfill_per_sync`].
pub const DEFAULT_BACKFILL_PER_SYNC: usize = 1000;
/// Default [`EngineConfig::fetch_batch`].
pub const DEFAULT_FETCH_BATCH: usize = 200;
/// Default [`EngineConfig::fetch_batch_bytes`] (8 MiB).
pub const DEFAULT_FETCH_BATCH_BYTES: usize = 8 << 20;

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            directory_url: None,
            server_url: None,
            network_timeout: NETWORK_TIMEOUT,
            prefer_encrypt: PreferEncrypt::Mutual,
            guest_expiry_secs: None,
            profile_key: ProfileKeySource::default(),
            sync_window: DEFAULT_SYNC_WINDOW,
            backfill_per_sync: DEFAULT_BACKFILL_PER_SYNC,
            fetch_batch: DEFAULT_FETCH_BATCH,
            fetch_batch_bytes: DEFAULT_FETCH_BATCH_BYTES,
        }
    }
}

impl EngineConfig {
    /// Defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let non_empty = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let timeout = non_empty("SEALBOX_NETWORK_TIMEOUT_SECS")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(NETWORK_TIMEOUT);
        let count = |k: &str, default: usize| {
            non_empty(k)
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(default)
        };
        Self {
            directory_url: non_empty("SEALBOX_DIRECTORY_URL"),
            server_url: non_empty("SEALBOX_SERVER_URL"),
            network_timeout: timeout,
            profile_key: ProfileKeySource::from_env(),
            sync_window: count("SEALBOX_SYNC_WINDOW", DEFAULT_SYNC_WINDOW),
            backfill_per_sync: count("SEALBOX_SYNC_BACKFILL", DEFAULT_BACKFILL_PER_SYNC),
            ..Self::default()
        }
    }
}

/// The Sealbox engine. One per profile directory; cheap to share behind an `Arc`.
pub struct Engine {
    profile_dir: PathBuf,
    store: Mutex<Store>,
    config: EngineConfig,
    http: reqwest::Client,
    /// Per-account mailbox locks (see [`Engine::account_lock`]).
    sync_locks: Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>,
    /// Drafts being sent right now ([`Engine::send_draft`] refuses a second send of one).
    pub(crate) draft_sends: crate::drafts::DraftSends,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("profile_dir", &self.profile_dir)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Open (creating if needed) the profile at `profile_dir` with [`EngineConfig::from_env`].
    pub fn open(profile_dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(profile_dir, EngineConfig::from_env())
    }

    /// Open with an explicit configuration. Unlocks the profile with `config.profile_key`:
    /// a missing or wrong key fails with [`Error::ProfileLocked`] before any sensitive row is
    /// read; a legacy plaintext profile is wrapped in one transaction on its first keyed open.
    pub fn open_with(profile_dir: impl AsRef<Path>, mut config: EngineConfig) -> Result<Self> {
        let profile_dir = profile_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&profile_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&profile_dir, std::fs::Permissions::from_mode(0o700));
        }
        let mut store = Store::open(&profile_dir.join(DB_FILE))?;
        let meta = vault::read_meta(store.conn())?;
        let unlocked = vault::unlock(&profile_dir, &meta, &config.profile_key)?;
        vault::install(store.conn_mut(), &unlocked)?;
        store.set_vault(unlocked.vault);
        config.profile_key = match config.profile_key {
            ProfileKeySource::Passphrase(_) => ProfileKeySource::Passphrase(String::new()),
            ProfileKeySource::Raw(_) => ProfileKeySource::Raw(Vec::new()),
            other => other,
        };
        let http = reqwest::Client::builder()
            .timeout(config.network_timeout)
            .user_agent(concat!("sealbox-core/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::Connection(format!("HTTP client: {e}")))?;
        Ok(Self {
            profile_dir,
            store: Mutex::new(store),
            config,
            http,
            sync_locks: Mutex::new(HashMap::new()),
            draft_sends: Default::default(),
        })
    }

    /// The profile directory.
    pub fn profile_dir(&self) -> &Path {
        &self.profile_dir
    }

    /// The configuration the engine was opened with (environment / explicit). The Sealbox
    /// server URL may be overridden at runtime: read it through [`Engine::server_url`] and
    /// [`Engine::directory_url`], never from here.
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub(crate) fn store(&self) -> MutexGuard<'_, Store> {
        match self.store.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// The mailbox lock of one account. Everything that changes what is stored for an account
    /// as a result of talking to its IMAP server takes it, so two of them never interleave:
    /// [`Engine::sync`] (for the whole INBOX + Sent run), [`Engine::sync_folder_role`], the
    /// catch-up and every IDLE-triggered sync inside [`Engine::watch`] (released while IDLE
    /// waits, so a manual sync can run in between), [`Engine::move_message`] /
    /// [`Engine::delete_message`] and [`Engine::spam_learn`] (both move messages). The spam /
    /// filter pass and the auto-reply pass run inside a sync and are covered by its lock.
    /// Flag changes ([`Engine::set_flags`]) and sending are not serialised: they only touch
    /// their own row / the Sent folder. Not re-entrant: never take it twice on one path.
    pub(crate) async fn account_lock(&self, account_id: i64) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut map = match self.sync_locks.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            map.entry(account_id)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }

    // ----- accounts ---------------------------------------------------------------------

    /// Built-in provider table only (no network). What `account add --dry-run` shows.
    pub fn detect_servers_offline(email: &str) -> Option<ServerConfig> {
        autodiscover::discover_offline(email)
    }

    /// Full autodiscovery: built-in table, then ISPDB / autoconfig / SRV / MX / guesses. The
    /// result passes the transport policy (`sealbox_mail::net_policy`): a configuration that
    /// needs plaintext towards a public host is an error, not an answer.
    pub async fn detect_servers(&self, email: &str) -> Result<ServerConfig> {
        if let Some(cfg) = Self::detect_servers_offline(email) {
            net_policy::check_server_config(&cfg)?;
            return Ok(cfg);
        }
        let opts = autodiscover::DiscoverOptions {
            allow_network: true,
            timeout: self.config.network_timeout.min(Duration::from_secs(15)),
        };
        Ok(autodiscover::discover_with(email, &opts).await?)
    }

    /// Add an account: autodiscover unless servers are given, test IMAP and SMTP, generate
    /// an OpenPGP identity for the address if none exists, persist everything. Servers that
    /// fail the transport policy (plaintext towards a public host) are refused before any
    /// connection ([`Error::TransportPolicy`]); an OAuth token only goes to the hosts of the
    /// provider named in `AuthSpec::OAuth` (Google / Microsoft hosts when none is named).
    pub async fn add_account(&self, req: AddAccount) -> Result<AccountInfo> {
        let email = req.email.trim().to_string();
        if email.is_empty() || !email.contains('@') {
            return Err(Error::InvalidInput(format!(
                "`{email}` is not an e-mail address"
            )));
        }
        if self.store().account_by_email(&email)?.is_some() {
            return Err(Error::AccountExists(email));
        }
        let servers = match req.servers {
            Some(s) => s,
            None => self.detect_servers(&email).await?,
        };
        net_policy::check_server_config(&servers)?;
        let display_name = req
            .display_name
            .map(|n| n.trim().to_string())
            .unwrap_or_default();
        let (auth_kind, credential) = match &req.auth {
            AuthSpec::Password { password } => (AuthKind::Password, password.clone()),
            AuthSpec::OAuth { .. } => (AuthKind::OAuth, serde_json::to_string(&req.auth)?),
        };

        // Login candidates: explicit override, else what the config says, then the bare
        // local part as a fallback on an authentication failure.
        let mut candidates: Vec<String> = Vec::new();
        match req
            .login
            .as_deref()
            .map(str::trim)
            .filter(|l| !l.is_empty())
        {
            Some(l) => candidates.push(l.to_string()),
            None => {
                candidates.push(servers.login_name(&email));
                if let Some((local, _)) = email.split_once('@') {
                    if !candidates.iter().any(|c| c == local) {
                        candidates.push(local.to_string());
                    }
                }
            }
        }
        let mut probe = AccountRow {
            id: 0,
            email: email.clone(),
            display_name: display_name.clone(),
            imap: servers.imap.clone(),
            smtp: servers.smtp.clone(),
            auth_kind,
            login: String::new(),
            credential: credential.clone(),
            created_at: 0,
            // A pre-insert probe: it exists to try logins, and no provider has been stated for
            // an account that is not stored yet.
            provider: None,
        };
        let mut last_err: Option<Error> = None;
        let mut login_ok: Option<String> = None;
        for cand in &candidates {
            probe.login = cand.clone();
            match transport::connect_imap(&probe, self.config.network_timeout).await {
                Ok(client) => {
                    let _ = client.logout().await;
                    login_ok = Some(cand.clone());
                    break;
                }
                Err(e @ Error::Imap(ImapError::Auth(_) | ImapError::LoginRejected { .. })) => {
                    tracing::debug!(login = %cand, "IMAP login rejected: {e}");
                    last_err = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        let login = match login_ok {
            Some(l) => l,
            None => {
                return Err(
                    last_err.unwrap_or_else(|| Error::Connection("IMAP login failed".into()))
                )
            }
        };
        probe.login = login.clone();

        let smtp = transport::smtp_client(&probe, self.config.network_timeout)?;
        match smtp.test_connection().await {
            Ok(true) => {}
            Ok(false) => {
                return Err(Error::Connection(format!(
                    "SMTP {}:{} rejected the connection",
                    probe.smtp.host, probe.smtp.port
                )))
            }
            Err(e) => return Err(Error::Smtp(e)),
        }
        smtp.shutdown().await;

        // Identity: reuse one previously generated for this address, else generate.
        let existing = self.store().identity_by_email(&email)?;
        let identity = match &existing {
            Some(row) => Identity::from_armored_secret(&row.secret_armored, None)?,
            None => Identity::generate(&display_name, &email)?,
        };
        let secret = identity.to_armored_secret(None)?;
        let public = identity.public().to_armored()?;
        let fingerprint = identity.fingerprint();

        let store = self.store();
        let id = store.insert_account(&NewAccount {
            email: &email,
            display_name: &display_name,
            imap: &servers.imap,
            smtp: &servers.smtp,
            auth_kind,
            login: &login,
            credential: &credential,
        })?;
        if existing.is_none() {
            store.insert_identity(id, &fingerprint, &email, &secret, &public)?;
        }
        let row = store
            .account_by_id(id)?
            .ok_or_else(|| Error::AccountNotFound(email.clone()))?;
        Ok(row.info(Some(fingerprint)))
    }

    /// Every account (no secrets).
    pub fn list_accounts(&self) -> Result<Vec<AccountInfo>> {
        let store = self.store();
        let mut out = Vec::new();
        for a in store.list_accounts()? {
            let fp = store
                .identities_for_account(a.id)?
                .first()
                .map(|i| i.fingerprint.clone());
            out.push(a.info(fp));
        }
        Ok(out)
    }

    /// One account by address.
    pub fn account(&self, email: &str) -> Result<AccountInfo> {
        let row = self.account_row(email)?;
        let fp = self
            .store()
            .identities_for_account(row.id)?
            .first()
            .map(|i| i.fingerprint.clone());
        Ok(row.info(fp))
    }

    /// Remove an account and everything stored for it (messages, identity, sync state).
    pub fn remove_account(&self, email: &str) -> Result<()> {
        let row = self.account_row(email)?;
        self.store().delete_account(row.id)
    }

    pub(crate) fn account_row(&self, email: &str) -> Result<AccountRow> {
        self.store()
            .account_by_email(email)?
            .ok_or_else(|| Error::AccountNotFound(email.trim().to_string()))
    }

    /// The account's identity row and the unlocked key.
    pub(crate) fn identity_for(&self, acct: &AccountRow) -> Result<(IdentityRow, Identity)> {
        let row = self
            .store()
            .identities_for_account(acct.id)?
            .into_iter()
            .next()
            .ok_or_else(|| Error::NoIdentity(acct.email.clone()))?;
        let id = Identity::from_armored_secret(&row.secret_armored, None)?;
        Ok((row, id))
    }

    /// All unlocked identities of an account (one today; more after key rotation).
    pub(crate) fn identities_for(&self, acct: &AccountRow) -> Result<Vec<Identity>> {
        let rows = self.store().identities_for_account(acct.id)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(Identity::from_armored_secret(&r.secret_armored, None)?);
        }
        Ok(out)
    }

    // ----- keys -------------------------------------------------------------------------

    /// Fingerprint of the account's OpenPGP key.
    pub fn my_fingerprint(&self, email: &str) -> Result<String> {
        let acct = self.account_row(email)?;
        Ok(self.identity_for(&acct)?.0.fingerprint)
    }

    /// ASCII-armored public key of the account.
    pub fn export_public_key(&self, email: &str) -> Result<String> {
        let acct = self.account_row(email)?;
        Ok(self.identity_for(&acct)?.0.public_armored)
    }

    /// Import somebody's public key for `address` (e.g. received out of band). The key must
    /// carry a User ID for that address and be usable for encryption.
    pub fn import_peer_key(&self, address: &str, armored: &str) -> Result<Contact> {
        let address = address.trim().to_ascii_lowercase();
        if !address.contains('@') {
            return Err(Error::InvalidInput(format!(
                "`{address}` is not an e-mail address"
            )));
        }
        let key = PublicKey::from_armored(armored)?;
        if !key.encryption_capable() {
            return Err(Error::Crypto(sealbox_crypto::Error::NoEncryptionKey {
                fingerprint: key.fingerprint(),
            }));
        }
        if !key
            .emails()
            .iter()
            .any(|e| e.eq_ignore_ascii_case(&address))
        {
            return Err(Error::InvalidInput(format!(
                "key {} has no User ID for {address} (found: {})",
                key.fingerprint(),
                key.emails().join(", ")
            )));
        }
        self.store().upsert_key(
            &address,
            KeySource::Imported,
            &key.fingerprint(),
            &key.to_armored()?,
        )?;
        self.contacts()?
            .into_iter()
            .find(|c| c.address == address)
            .ok_or_else(|| Error::InvalidInput("import did not register".into()))
    }

    /// Everyone we know a key or Autocrypt state for, with the current recommendation
    /// (resolved exactly like `send` does; own accounts excluded).
    pub fn contacts(&self) -> Result<Vec<Contact>> {
        // Never call a locking helper while holding the store guard (std Mutex is not reentrant).
        let (peers, keys) = {
            let store = self.store();
            (store.all_peers()?, store.all_keys()?)
        };
        let own = self.own_addresses()?;
        let mut addresses: BTreeMap<String, Option<PeerState>> = BTreeMap::new();
        for p in peers {
            addresses.insert(p.addr.trim().to_ascii_lowercase(), Some(p));
        }
        for k in keys {
            addresses.entry(k.addr.to_ascii_lowercase()).or_insert(None);
        }
        let mut out = Vec::with_capacity(addresses.len());
        for (addr, peer) in addresses {
            if own.contains(&addr) {
                continue;
            }
            let r = self.resolve_recipient_full(&addr, false)?;
            out.push(Contact {
                address: addr,
                recommendation: r.status.recommendation,
                fingerprint: r.status.fingerprint,
                source: r.status.source,
                prefer_encrypt: peer
                    .as_ref()
                    .map(|p| p.prefer_encrypt)
                    .unwrap_or(PreferEncrypt::NoPreference),
                last_seen: peer
                    .as_ref()
                    .and_then(|p| p.last_seen.map(|t| t.timestamp())),
                autocrypt_timestamp: peer
                    .as_ref()
                    .and_then(|p| p.autocrypt_timestamp.map(|t| t.timestamp())),
                gossip_fingerprint: peer
                    .as_ref()
                    .and_then(|p| p.gossip_public_key().map(|k| k.fingerprint())),
                verified: false,
                verified_at: None,
                key_changed_at: None,
                previous_fingerprint: None,
            });
        }
        self.identity_decorate_contacts(&mut out); // G30
        Ok(out)
    }

    /// Resolve one address the way `send` would (own accounts → Autocrypt → imported keys).
    pub fn resolve_recipient(
        &self,
        address: &str,
        reply_to_encrypted: bool,
    ) -> Result<RecipientStatus> {
        Ok(self
            .resolve_recipient_full(address, reply_to_encrypted)?
            .status)
    }

    pub(crate) fn resolve_recipient_full(
        &self,
        address: &str,
        reply_to_encrypted: bool,
    ) -> Result<ResolvedRecipient> {
        let address = address.trim();
        let store = self.store();
        let own = store
            .all_identities()?
            .into_iter()
            .find(|i| i.email.eq_ignore_ascii_case(address))
            .and_then(|i| PublicKey::from_armored(&i.public_armored).ok());
        let peer = store.peer(address)?;
        let mut extra: Vec<ExtraKey> = Vec::new();
        for k in store.keys_for(address)? {
            if let Ok(pk) = PublicKey::from_armored(&k.armored) {
                extra.push(ExtraKey {
                    source: k.source,
                    key: pk,
                    imported_at: chrono::DateTime::<chrono::Utc>::from_timestamp(k.imported_at, 0)
                        .unwrap_or(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH),
                });
            }
        }
        // Imported keys beat directory keys.
        extra.sort_by_key(|e| match e.source {
            KeySource::Imported => 0,
            KeySource::Directory => 1,
            _ => 2,
        });
        Ok(policy::resolve(
            address,
            own.as_ref(),
            peer.as_ref(),
            &extra,
            reply_to_encrypted,
        ))
    }

    /// Every public key that may have signed something we receive: our own identities,
    /// all Autocrypt peer keys (announced and gossiped) and imported/directory keys.
    pub(crate) fn known_signers(&self) -> Result<(Vec<PublicKey>, BTreeMap<String, String>)> {
        let store = self.store();
        let mut keys: Vec<PublicKey> = Vec::new();
        let mut fp_to_addr: BTreeMap<String, String> = BTreeMap::new();
        let mut push = |k: PublicKey, addr: &str| {
            let fp = k.fingerprint();
            fp_to_addr
                .entry(fp.clone())
                .or_insert_with(|| addr.to_ascii_lowercase());
            if !keys.iter().any(|x| x.fingerprint() == fp) {
                keys.push(k);
            }
        };
        for i in store.all_identities()? {
            if let Ok(k) = PublicKey::from_armored(&i.public_armored) {
                push(k, &i.email);
            }
        }
        for p in store.all_peers()? {
            if let Some(k) = p
                .public_key
                .as_deref()
                .and_then(|b| PublicKey::from_bytes(b).ok())
            {
                push(k, &p.addr);
            }
            if let Some(k) = p
                .gossip_key
                .as_deref()
                .and_then(|b| PublicKey::from_bytes(b).ok())
            {
                push(k, &p.addr);
            }
        }
        for k in store.all_keys()? {
            if let Ok(pk) = PublicKey::from_armored(&k.armored) {
                push(pk, &k.addr);
            }
        }
        Ok((keys, fp_to_addr))
    }

    /// Load (or create) the Autocrypt peer state for an address.
    pub(crate) fn peer_state(&self, addr: &str) -> Result<PeerState> {
        Ok(self
            .store()
            .peer(addr)?
            .unwrap_or_else(|| PeerState::new(&addr.trim().to_ascii_lowercase())))
    }

    /// Addresses of all our accounts (lower-cased).
    pub(crate) fn own_addresses(&self) -> Result<Vec<String>> {
        Ok(self
            .store()
            .list_accounts()?
            .into_iter()
            .map(|a| a.email.to_ascii_lowercase())
            .collect())
    }

    // ----- reading (local, no network) ---------------------------------------------------

    /// Stored messages, newest first. With `query.folder_role` set, the folder is resolved per
    /// account (the role the server's `LIST` mapped on a sync, else the provider default), so
    /// a unified "Trash" works across a Gmail and an Outlook account.
    pub fn list_messages(&self, query: ListQuery) -> Result<Vec<MessageSummary>> {
        let mut rows = match query.folder_role {
            Some(role) => {
                // Resolve outside the store guard: `folder_for_role` locks the store itself.
                let accounts = match &query.account {
                    Some(a) => vec![self.account_row(a)?],
                    None => self.store().list_accounts()?,
                };
                let pairs: Vec<(i64, String)> = accounts
                    .iter()
                    .map(|a| (a.id, self.folder_for_role(a, role)))
                    .collect();
                self.store().list_messages_in_folders(&query, &pairs)?
            }
            None => self.store().list_messages(&query)?,
        };
        self.identity_decorate_messages(rows.iter_mut()); // G30
        Ok(rows)
    }

    /// One message with its decrypted bodies and attachment list.
    pub fn get_message(&self, id: i64) -> Result<MessageDetail> {
        let mut d = self.store().message_detail(id)?;
        self.identity_decorate_messages(std::iter::once(&mut d.summary)); // G30
        Ok(d)
    }

    /// The raw RFC 822 bytes as fetched.
    pub fn get_raw_message(&self, id: i64) -> Result<Vec<u8>> {
        self.store().message_raw(id)
    }

    /// Attachment bytes.
    pub fn get_attachment(&self, id: i64, index: usize) -> Result<(AttachmentInfo, Vec<u8>)> {
        self.store().attachment(id, index)
    }

    /// Add or remove IMAP flags on the server and locally; returns the new flag set.
    pub async fn set_flags(&self, id: i64, op: FlagOp, flags: &[String]) -> Result<Vec<String>> {
        let (row, acct, folder) = {
            let store = self.store();
            let row = store.message(id)?;
            let acct = store
                .account_by_id(row.account_id)?
                .ok_or_else(|| Error::AccountNotFound(row.summary.account.clone()))?;
            let folder = store
                .folder_by_id(row.folder_id)?
                .ok_or_else(|| Error::MessageNotFound(id))?;
            (row, acct, folder)
        };
        let flag_refs: Vec<&str> = flags.iter().map(String::as_str).collect();
        let mut client = self.imap_for(&acct).await?;
        client.select(&folder.name).await?;
        let imap_op = match op {
            FlagOp::Add => ImapFlagOp::Add,
            FlagOp::Remove => ImapFlagOp::Remove,
        };
        client
            .set_flags(&[row.summary.uid], imap_op, &flag_refs)
            .await?;
        let fetched = client.fetch_flags(&[row.summary.uid]).await?;
        let _ = client.logout().await;
        let new_flags = match fetched.into_iter().find(|(u, _)| *u == row.summary.uid) {
            Some((_, f)) => f,
            None => {
                // Server did not echo: apply locally.
                let mut f = row.summary.flags.clone();
                match op {
                    FlagOp::Add => {
                        for x in flags {
                            if !f.iter().any(|y| y.eq_ignore_ascii_case(x)) {
                                f.push(x.clone());
                            }
                        }
                    }
                    FlagOp::Remove => {
                        f.retain(|y| !flags.iter().any(|x| x.eq_ignore_ascii_case(y)))
                    }
                }
                f
            }
        };
        self.store().update_flags(id, &new_flags)?;
        Ok(new_flags)
    }

    /// Delete a message: moved to the provider's Trash folder (created when missing), or
    /// `\Deleted` + expunged when it already sits in Trash; dropped locally either way.
    /// See `providers.rs` (`Engine::delete_to_trash`).
    pub async fn delete_message(&self, id: i64) -> Result<()> {
        self.delete_to_trash(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> (tempfile::TempDir, Arc<Engine>) {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        (dir, Arc::new(engine))
    }

    /// The mailbox lock is exclusive per account and independent across accounts: a second
    /// taker of the same account waits until the first guard is dropped, another account's
    /// taker does not wait at all.
    #[tokio::test]
    async fn account_lock_is_exclusive_per_account() {
        let (_dir, engine) = engine();
        let first = engine.account_lock(1).await;

        let e = engine.clone();
        let mut same = tokio::spawn(async move {
            let _g = e.account_lock(1).await;
        });
        // Another account is not blocked by account 1's guard.
        let other = tokio::time::timeout(Duration::from_millis(500), engine.account_lock(2))
            .await
            .expect("account 2 must not wait for account 1");
        // The second taker of account 1 is still parked behind the first guard.
        assert!(
            tokio::time::timeout(Duration::from_millis(300), &mut same)
                .await
                .is_err(),
            "account 1 was locked twice at once"
        );
        drop(first);
        tokio::time::timeout(Duration::from_secs(5), same)
            .await
            .expect("released lock is taken")
            .unwrap();
        drop(other);
        // Re-taking after everyone released works (the map keeps one mutex per account).
        drop(engine.account_lock(1).await);
        drop(engine.account_lock(2).await);
    }
}
