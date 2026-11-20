//! OAuth2 inside the engine: persistent per-account tokens (`oauth_tokens`), a refresh
//! before every IMAP/SMTP connection, and the interactive authorization-code flow
//! (`begin_oauth` → browser → `wait_oauth_code` → `finish_oauth`).
//!
//! The current access token is mirrored into `accounts.credential` as the
//! [`AuthSpec::OAuth`] JSON that `AccountRow::mail_auth` reads, so every transport path keeps
//! working unchanged; `oauth_tokens` is the source of truth and carries what a refresh needs
//! (client id/secret, token endpoint, refresh token, expiry).
//!
//! **Where a token may go** (docs/THREAT_MODEL.md R14). Every connection carries the token's
//! [`BearerScope`] (provider + whether it came from a loopback mock IdP), and `sealbox_mail`
//! presents the token only to that provider's mail hosts (`net_policy::mail_domains`); a mock
//! IdP's tokens may also go to local/private hosts such as GreenMail — the test/dev escape
//! hatch, which tokens from the real endpoints never get. A server without `AUTH=XOAUTH2` on
//! IMAP gets no token at all (`ImapError::XOAuth2NotOffered`): there is no "token as `LOGIN`
//! password" fallback. GreenMail's IMAP has no XOAUTH2, so the G21 local test reaches it
//! through a small XOAUTH2 front (`crates/sealbox-cli/tests/gate_g21_local.rs`).

use std::time::Duration;

use rusqlite::types::Value;
use rusqlite::{params, OptionalExtension};
use sealbox_crypto::Identity;
use sealbox_mail::autodiscover::ServerConfig;
use sealbox_mail::imap::ImapClient;
use sealbox_mail::oauth::{self as mail_oauth, AuthRequest, OAuthEndpoints, Provider, Token};
use sealbox_mail::smtp::SmtpClient;
use sealbox_mail::{net_policy, BearerScope, ImapError};
use tokio::net::TcpListener;

use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::store::{now, AccountRow, NewAccount, Store};
use crate::transport;
use crate::types::{AccountInfo, AuthKind, AuthSpec};

/// Migration for this module (applied by `Store::open`).
pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS oauth_tokens (
    account_id    INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    provider      TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    client_secret TEXT,
    auth_url      TEXT NOT NULL,
    token_url     TEXT NOT NULL,
    access_token  TEXT NOT NULL,
    refresh_token TEXT,
    expires_at    INTEGER,
    scopes_json   TEXT NOT NULL DEFAULT '[]',
    updated_at    INTEGER NOT NULL,
    refresh_count INTEGER NOT NULL DEFAULT 0
);
"#;

/// Refresh when the access token expires within this window.
pub const REFRESH_SKEW: Duration = Duration::from_secs(5 * 60);
/// Default time to wait for the browser to come back to the loopback listener.
pub const DEFAULT_CODE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Stored OAuth state of an account. Never leaves the crate; `Debug` redacts secrets.
#[derive(Clone)]
pub(crate) struct OAuthTokenRow {
    pub account_id: i64,
    pub provider: Provider,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub auth_url: String,
    pub token_url: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix seconds.
    pub expires_at: Option<i64>,
    pub scopes: Vec<String>,
    pub updated_at: i64,
    pub refresh_count: i64,
}

impl std::fmt::Debug for OAuthTokenRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthTokenRow")
            .field("account_id", &self.account_id)
            .field("provider", &self.provider)
            .field("client_id", &self.client_id)
            .field("token_url", &self.token_url)
            .field("expires_at", &self.expires_at)
            .field("refresh_count", &self.refresh_count)
            .finish_non_exhaustive()
    }
}

impl OAuthTokenRow {
    fn token(&self) -> Token {
        Token {
            access_token: self.access_token.clone(),
            refresh_token: self.refresh_token.clone(),
            expires_at: self.expires_at.and_then(|t| u64::try_from(t).ok()),
            scopes: self.scopes.clone(),
        }
    }

    fn endpoints(&self) -> OAuthEndpoints {
        OAuthEndpoints {
            auth_url: self.auth_url.clone(),
            token_url: self.token_url.clone(),
        }
    }

    /// Where this token may be presented: its provider's mail hosts, plus local/private hosts
    /// when it came from a loopback mock IdP (R14).
    pub(crate) fn bearer_scope(&self) -> BearerScope {
        BearerScope::for_endpoints(self.provider, &self.endpoints())
    }

    /// The `accounts.credential` JSON (what `AccountRow::mail_auth` reads).
    fn credential_json(&self) -> Result<String> {
        Ok(serde_json::to_string(&AuthSpec::OAuth {
            provider: Some(self.provider.as_str().to_owned()),
            access_token: self.access_token.clone(),
            refresh_token: self.refresh_token.clone(),
            expires_at: self.expires_at,
        })?)
    }

    fn status(&self) -> OAuthStatus {
        OAuthStatus {
            provider: self.provider,
            client_id: self.client_id.clone(),
            has_client_secret: self.client_secret.as_deref().is_some_and(|s| !s.is_empty()),
            token_url: self.token_url.clone(),
            endpoints_overridden: self.endpoints().is_override(self.provider),
            dev_hosts_allowed: self.bearer_scope().dev_idp,
            expires_at: self.expires_at,
            expires_in_secs: self.expires_at.map(|t| t - now()),
            has_refresh_token: self.refresh_token.as_deref().is_some_and(|s| !s.is_empty()),
            scopes: self.scopes.clone(),
            updated_at: self.updated_at,
            refresh_count: self.refresh_count,
        }
    }
}

/// Secret-free view of an account's OAuth state.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OAuthStatus {
    pub provider: Provider,
    pub client_id: String,
    pub has_client_secret: bool,
    pub token_url: String,
    /// The endpoints are not the provider's real ones (test mock IdP).
    pub endpoints_overridden: bool,
    /// Both endpoints are loopback (a mock IdP), so besides the provider's own mail hosts the
    /// token may also be presented to local/private hosts (tests / development, R14).
    pub dev_hosts_allowed: bool,
    /// Unix seconds.
    pub expires_at: Option<i64>,
    /// Seconds until expiry (negative = expired), if known.
    pub expires_in_secs: Option<i64>,
    pub has_refresh_token: bool,
    pub scopes: Vec<String>,
    pub updated_at: i64,
    /// How many times the engine refreshed the token so far.
    pub refresh_count: i64,
}

impl Store {
    pub(crate) fn oauth_token(&self, account_id: i64) -> Result<Option<OAuthTokenRow>> {
        // Secrets are read as raw values and unwrapped below (G27, vault.rs).
        let row = self
            .conn()
            .query_row(
                "SELECT account_id, provider, client_id, client_secret, auth_url, token_url, \
                 access_token, refresh_token, expires_at, scopes_json, updated_at, refresh_count \
                 FROM oauth_tokens WHERE account_id = ?1",
                params![account_id],
                |r| {
                    let provider: String = r.get(1)?;
                    let scopes: String = r.get(9)?;
                    Ok((
                        OAuthTokenRow {
                            account_id: r.get(0)?,
                            provider: Provider::parse(&provider).unwrap_or(Provider::Google),
                            client_id: r.get(2)?,
                            client_secret: None,
                            auth_url: r.get(4)?,
                            token_url: r.get(5)?,
                            access_token: String::new(),
                            refresh_token: None,
                            expires_at: r.get(8)?,
                            scopes: serde_json::from_str(&scopes).unwrap_or_default(),
                            updated_at: r.get(10)?,
                            refresh_count: r.get(11)?,
                        },
                        r.get::<_, Value>(3)?,
                        r.get::<_, Value>(6)?,
                        r.get::<_, Value>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((mut t, secret, access, refresh)) = row else {
            return Ok(None);
        };
        let (v, id) = (self.vault(), t.account_id.to_string());
        t.client_secret = v.open_opt_text("oauth_tokens", "client_secret", &id, secret)?;
        t.access_token = v.open_text("oauth_tokens", "access_token", &id, access)?;
        t.refresh_token = v.open_opt_text("oauth_tokens", "refresh_token", &id, refresh)?;
        Ok(Some(t))
    }

    pub(crate) fn upsert_oauth_token(&self, t: &OAuthTokenRow) -> Result<()> {
        let (v, id) = (self.vault(), t.account_id.to_string());
        let secret = v.seal_opt_text(
            "oauth_tokens",
            "client_secret",
            &id,
            t.client_secret.as_deref(),
        )?;
        let access = v.seal_text("oauth_tokens", "access_token", &id, &t.access_token)?;
        let refresh = v.seal_opt_text(
            "oauth_tokens",
            "refresh_token",
            &id,
            t.refresh_token.as_deref(),
        )?;
        self.conn().execute(
            "INSERT INTO oauth_tokens (account_id, provider, client_id, client_secret, auth_url, \
             token_url, access_token, refresh_token, expires_at, scopes_json, updated_at, \
             refresh_count) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
             ON CONFLICT(account_id) DO UPDATE SET provider = excluded.provider, \
             client_id = excluded.client_id, client_secret = excluded.client_secret, \
             auth_url = excluded.auth_url, token_url = excluded.token_url, \
             access_token = excluded.access_token, refresh_token = excluded.refresh_token, \
             expires_at = excluded.expires_at, scopes_json = excluded.scopes_json, \
             updated_at = excluded.updated_at, refresh_count = excluded.refresh_count",
            params![
                t.account_id,
                t.provider.as_str(),
                t.client_id,
                secret,
                t.auth_url,
                t.token_url,
                access,
                refresh,
                t.expires_at,
                serde_json::to_string(&t.scopes)?,
                t.updated_at,
                t.refresh_count,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn update_account_credential(
        &self,
        account_id: i64,
        credential: &str,
    ) -> Result<()> {
        let credential = self.vault().seal_text(
            "accounts",
            "credential",
            &account_id.to_string(),
            credential,
        )?;
        self.conn().execute(
            "UPDATE accounts SET credential = ?1 WHERE id = ?2",
            params![credential, account_id],
        )?;
        Ok(())
    }
}

/// An authorization in progress: the loopback listener is bound (so the redirect URI is
/// final), the URL is ready to open. Consumed by [`Engine::finish_oauth`].
pub struct OAuthStart {
    pub provider: Provider,
    pub email: String,
    /// Open this in a browser.
    pub url: String,
    /// CSRF state carried in the redirect.
    pub state: String,
    pub loopback_port: u16,
    pub redirect_uri: String,
    pub client_id: String,
    pub endpoints: OAuthEndpoints,
    /// Manual server override; `None` = autodiscover (built-in table, then network).
    pub servers: Option<ServerConfig>,
    pub display_name: Option<String>,
    /// Login name override (default: what the server configuration says; on an IMAP
    /// authentication failure the bare local part is tried as well).
    pub login: Option<String>,
    client_secret: Option<String>,
    pkce_verifier: String,
    listener: Option<TcpListener>,
}

impl OAuthStart {
    /// Where the token of this flow may be presented (R14).
    pub fn bearer_scope(&self) -> BearerScope {
        BearerScope::for_endpoints(self.provider, &self.endpoints)
    }

    /// Check manually given `servers` against the transport policy before the browser round
    /// trip: plaintext only towards local/private hosts, and both hosts must be allowed to
    /// receive this provider's token. Autodiscovered servers are checked when they are known
    /// (in [`Engine::add_oauth_account`]); without `servers` this is a no-op.
    pub fn preflight(&self) -> Result<()> {
        if let Some(servers) = &self.servers {
            net_policy::check_server_config(servers)?;
            let scope = Some(self.bearer_scope());
            net_policy::check_bearer_host(scope, &servers.imap.host)?;
            net_policy::check_bearer_host(scope, &servers.smtp.host)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for OAuthStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthStart")
            .field("provider", &self.provider)
            .field("email", &self.email)
            .field("url", &self.url)
            .field("state", &self.state)
            .field("loopback_port", &self.loopback_port)
            .field("client_id", &self.client_id)
            .field("endpoints", &self.endpoints)
            .finish_non_exhaustive()
    }
}

fn oauth_err(context: &str, e: sealbox_mail::OAuthError) -> Error {
    Error::Connection(format!("OAuth {context}: {e}"))
}

impl Engine {
    /// Start the authorization-code + PKCE flow for `email` at `provider`: binds an ephemeral
    /// loopback port, builds the authorization URL (with `login_hint`), returns both. Nothing
    /// is stored yet. The endpoints come from the provider unless overridden by
    /// `SEALBOX_OAUTH_AUTH_URL` / `SEALBOX_OAUTH_TOKEN_URL` (tests).
    pub async fn begin_oauth(
        &self,
        provider: Provider,
        email: &str,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<OAuthStart> {
        let email = email.trim().to_string();
        if email.is_empty() || !email.contains('@') {
            return Err(Error::InvalidInput(format!(
                "`{email}` is not an e-mail address"
            )));
        }
        if client_id.trim().is_empty() {
            return Err(Error::InvalidInput(format!(
                "no OAuth client id for {provider}: pass --client-id or set the client id variable"
            )));
        }
        if self.store().account_by_email(&email)?.is_some() {
            return Err(Error::AccountExists(email));
        }
        let endpoints = OAuthEndpoints::from_env(provider);
        let listener = mail_oauth::bind_loopback(0)
            .await
            .map_err(|e| oauth_err("listener", e))?;
        let loopback_port = listener.local_addr()?.port();
        let redirect_uri = provider.loopback_redirect_uri(loopback_port);
        let req = AuthRequest::with_endpoints(
            &endpoints,
            provider,
            client_id.trim(),
            &redirect_uri,
            Some(&email),
        )
        .map_err(|e| oauth_err("request", e))?;
        Ok(OAuthStart {
            provider,
            email,
            url: req.url,
            state: req.state,
            loopback_port,
            redirect_uri,
            client_id: client_id.trim().to_string(),
            endpoints,
            servers: None,
            display_name: None,
            login: None,
            client_secret: client_secret
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
            pkce_verifier: req.pkce_verifier,
            listener: Some(listener),
        })
    }

    /// Wait for the browser redirect on the bound loopback port and return the
    /// authorization code (the `state` is verified).
    pub async fn wait_oauth_code(
        &self,
        start: &mut OAuthStart,
        timeout: Duration,
    ) -> Result<String> {
        let listener = start.listener.take().ok_or_else(|| {
            Error::InvalidInput("the OAuth loopback listener was already consumed".into())
        })?;
        let code = mail_oauth::wait_for_code_on(listener, Some(&start.state), timeout)
            .await
            .map_err(|e| oauth_err("redirect", e))?;
        Ok(code.code)
    }

    /// Exchange the code for tokens, verify IMAP + SMTP with XOAUTH2, generate/reuse the
    /// OpenPGP identity, store the account and its tokens.
    pub async fn finish_oauth(&self, start: OAuthStart, code: &str) -> Result<AccountInfo> {
        let token = mail_oauth::exchange_code_with(
            &start.endpoints,
            &start.client_id,
            start.client_secret.as_deref(),
            &start.redirect_uri,
            code.trim(),
            &start.pkce_verifier,
        )
        .await
        .map_err(|e| oauth_err("token exchange", e))?;
        self.add_oauth_account(start, token).await
    }

    /// Store an OAuth account from an already-obtained token: verifies IMAP and SMTP with
    /// XOAUTH2 (a server without `AUTH=XOAUTH2` on IMAP is an error, the token is never sent
    /// as a password), then persists account + tokens. The servers must pass the transport
    /// policy and belong to the provider (or be local/private for a mock IdP's token), checked
    /// before anything is sent.
    pub async fn add_oauth_account(&self, start: OAuthStart, token: Token) -> Result<AccountInfo> {
        let email = start.email.trim().to_string();
        if self.store().account_by_email(&email)?.is_some() {
            return Err(Error::AccountExists(email));
        }
        if token.access_token.trim().is_empty() {
            return Err(Error::Connection(
                "OAuth token response carried an empty access token".into(),
            ));
        }
        let servers = match start.servers.clone() {
            Some(s) => s,
            None => self.detect_servers(&email).await?,
        };
        net_policy::check_server_config(&servers)?;
        let scope = Some(start.bearer_scope());
        net_policy::check_bearer_host(scope, &servers.imap.host)?;
        net_policy::check_bearer_host(scope, &servers.smtp.host)?;
        let display_name = start
            .display_name
            .clone()
            .map(|n| n.trim().to_string())
            .unwrap_or_default();
        let mut candidates: Vec<String> = Vec::new();
        match start
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
        let scopes = if token.scopes.is_empty() {
            start
                .provider
                .scopes()
                .iter()
                .map(|s| (*s).to_owned())
                .collect()
        } else {
            token.scopes.clone()
        };
        let mut record = OAuthTokenRow {
            account_id: 0,
            provider: start.provider,
            client_id: start.client_id.clone(),
            client_secret: start.client_secret.clone(),
            auth_url: start.endpoints.auth_url.clone(),
            token_url: start.endpoints.token_url.clone(),
            access_token: token.access_token.clone(),
            refresh_token: token.refresh_token.clone(),
            expires_at: token.expires_at.and_then(|t| i64::try_from(t).ok()),
            scopes,
            updated_at: now(),
            refresh_count: 0,
        };
        let credential = record.credential_json()?;
        let mut probe = AccountRow {
            id: 0,
            email: email.clone(),
            display_name: display_name.clone(),
            imap: servers.imap.clone(),
            smtp: servers.smtp.clone(),
            auth_kind: AuthKind::OAuth,
            login: String::new(),
            credential: credential.clone(),
            created_at: 0,
            provider: None, // pre-insert probe
        };
        let timeout = self.config().network_timeout;
        let mut last_err: Option<Error> = None;
        let mut login_ok: Option<(String, &'static str)> = None;
        for cand in &candidates {
            probe.login = cand.clone();
            // No retry here: Exchange answers a login that is not the token's mailbox with
            // the same code-less refusal it sends for a burst of logins, and the next
            // candidate is the useful retry (a misconfigured account fails at once).
            match transport::connect_imap_scoped(&probe, scope, timeout, &transport::NO_LOGIN_RETRY)
                .await
            {
                Ok(client) => {
                    let mech = client.auth_mechanism();
                    let _ = client.logout().await;
                    login_ok = Some((cand.clone(), mech));
                    break;
                }
                Err(e @ Error::Imap(ImapError::Auth(_) | ImapError::LoginRejected { .. })) => {
                    tracing::debug!(login = %cand, "IMAP XOAUTH2 login rejected: {e}");
                    last_err = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        let (login, imap_mechanism) = match login_ok {
            Some(l) => l,
            None => {
                return Err(last_err.unwrap_or_else(|| {
                    Error::Connection("IMAP login with the OAuth token failed".into())
                }))
            }
        };
        probe.login = login.clone();

        let smtp = transport::smtp_client_scoped(&probe, scope, timeout)?;
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
        let smtp_mechanism = smtp.auth_mechanism();
        smtp.shutdown().await;

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
            auth_kind: AuthKind::OAuth,
            login: &login,
            credential: &credential,
        })?;
        if existing.is_none() {
            store.insert_identity(id, &fingerprint, &email, &secret, &public)?;
        }
        record.account_id = id;
        store.upsert_oauth_token(&record)?;
        let row = store
            .account_by_id(id)?
            .ok_or_else(|| Error::AccountNotFound(email.clone()))?;
        tracing::info!(
            email,
            provider = %start.provider,
            imap = imap_mechanism,
            smtp = %smtp_mechanism,
            "OAuth account added"
        );
        Ok(row.info(Some(fingerprint)))
    }

    /// Secret-free OAuth state of an account (`None` for password accounts and for OAuth
    /// accounts added before token persistence existed).
    pub fn oauth_status(&self, email: &str) -> Result<Option<OAuthStatus>> {
        let acct = self.account_row(email)?;
        Ok(self.store().oauth_token(acct.id)?.map(|t| t.status()))
    }

    /// Refresh the account's access token if it expires within [`REFRESH_SKEW`] (or when
    /// `force`), persist it, and return the new status. `Ok(None)` for non-OAuth accounts.
    pub async fn refresh_oauth(&self, email: &str, force: bool) -> Result<Option<OAuthStatus>> {
        let acct = self.account_row(email)?;
        if acct.auth_kind != AuthKind::OAuth {
            return Ok(None);
        }
        let Some(row) = self.store().oauth_token(acct.id)? else {
            return Ok(None);
        };
        if !force && !row.token().expires_within(REFRESH_SKEW) {
            return Ok(Some(row.status()));
        }
        let updated = self.refresh_row(&acct, row).await?;
        Ok(Some(updated.status()))
    }

    async fn refresh_row(&self, acct: &AccountRow, row: OAuthTokenRow) -> Result<OAuthTokenRow> {
        let Some(refresh_token) = row.refresh_token.clone().filter(|r| !r.trim().is_empty()) else {
            return Err(Error::Connection(format!(
                "the OAuth access token for {} has expired and no refresh token is stored; \
                 run `sealbox account add --oauth {}` again to re-consent",
                acct.email, row.provider
            )));
        };
        let fresh = mail_oauth::refresh_with(
            &row.endpoints(),
            row.provider,
            &row.client_id,
            row.client_secret.as_deref(),
            &refresh_token,
        )
        .await
        .map_err(|e| {
            Error::Connection(format!(
                "OAuth token refresh for {} failed: {e}. If this persists (revoked consent, \
                 `invalid_grant`), run `sealbox account add --oauth {}` again",
                acct.email, row.provider
            ))
        })?;
        let updated = OAuthTokenRow {
            access_token: fresh.access_token,
            refresh_token: fresh.refresh_token.or(Some(refresh_token)),
            expires_at: fresh.expires_at.and_then(|t| i64::try_from(t).ok()),
            scopes: if fresh.scopes.is_empty() {
                row.scopes.clone()
            } else {
                fresh.scopes
            },
            updated_at: now(),
            refresh_count: row.refresh_count + 1,
            ..row
        };
        let credential = updated.credential_json()?;
        {
            let store = self.store();
            store.upsert_oauth_token(&updated)?;
            store.update_account_credential(acct.id, &credential)?;
        }
        tracing::info!(
            email = %acct.email,
            provider = %updated.provider,
            expires_at = ?updated.expires_at,
            refresh_count = updated.refresh_count,
            "OAuth access token refreshed"
        );
        Ok(updated)
    }

    /// The account row with a usable access token: refreshed when it expires within
    /// [`REFRESH_SKEW`], plus the token's [`BearerScope`] (from the `oauth_tokens` row, which
    /// knows whether a mock IdP issued it). Password accounts (and OAuth accounts without a
    /// stored token record) are returned unchanged, with the scope from the stored credential.
    pub(crate) async fn refresh_if_needed(
        &self,
        acct: &AccountRow,
    ) -> Result<(AccountRow, Option<BearerScope>)> {
        if acct.auth_kind != AuthKind::OAuth {
            return Ok((acct.clone(), None));
        }
        let Some(row) = self.store().oauth_token(acct.id)? else {
            tracing::debug!(
                email = %acct.email,
                "OAuth account without a token record; cannot refresh (re-add it with --oauth)"
            );
            return Ok((acct.clone(), acct.bearer_scope()));
        };
        let row = if row.token().expires_within(REFRESH_SKEW) {
            self.refresh_row(acct, row).await?
        } else {
            row
        };
        let mut fresh = acct.clone();
        fresh.credential = row.credential_json()?;
        Ok((fresh, Some(row.bearer_scope())))
    }

    /// IMAP session for an account, after the token refresh hook.
    pub(crate) async fn imap_for(&self, acct: &AccountRow) -> Result<ImapClient> {
        let (acct, scope) = self.refresh_if_needed(acct).await?;
        transport::connect_imap_scoped(
            &acct,
            scope,
            self.config().network_timeout,
            &transport::TRANSIENT_LOGIN_RETRY_DELAYS,
        )
        .await
    }

    /// SMTP client for an account, after the token refresh hook.
    pub(crate) async fn smtp_for(&self, acct: &AccountRow) -> Result<SmtpClient> {
        let (acct, scope) = self.refresh_if_needed(acct).await?;
        transport::smtp_client_scoped(&acct, scope, self.config().network_timeout)
    }

    /// A raw, authenticated IMAP session for an account (token refreshed first). For
    /// diagnostics and the conformance suite; the engine's own pipelines use `imap_for`.
    pub async fn imap_session(&self, email: &str) -> Result<ImapClient> {
        let acct = self.account_row(email)?;
        self.imap_for(&acct).await
    }

    /// A raw SMTP client for an account (token refreshed first).
    pub async fn smtp_session(&self, email: &str) -> Result<SmtpClient> {
        let acct = self.account_row(email)?;
        self.smtp_for(&acct).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;
    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::Security;

    #[test]
    fn token_rows_round_trip_and_mirror_the_credential() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        let store = engine.store();
        let id = store
            .insert_account(&NewAccount {
                email: "o@example.org",
                display_name: "O",
                imap: &Endpoint::new("imap.gmail.com", 993, Security::Tls),
                smtp: &Endpoint::new("smtp.gmail.com", 465, Security::Tls),
                auth_kind: AuthKind::OAuth,
                login: "o@example.org",
                credential: "{}",
            })
            .unwrap();
        assert!(store.oauth_token(id).unwrap().is_none());
        let row = OAuthTokenRow {
            account_id: id,
            provider: Provider::Google,
            client_id: "cid".into(),
            client_secret: None,
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token_url: "https://oauth2.googleapis.com/token".into(),
            access_token: "at".into(),
            refresh_token: Some("refresh-secret-xyz".into()),
            expires_at: Some(now() + 3600),
            scopes: vec!["https://mail.google.com/".into()],
            updated_at: now(),
            refresh_count: 0,
        };
        store.upsert_oauth_token(&row).unwrap();
        let back = store.oauth_token(id).unwrap().unwrap();
        assert_eq!(back.access_token, "at");
        assert_eq!(back.refresh_token.as_deref(), Some("refresh-secret-xyz"));
        assert_eq!(back.provider, Provider::Google);
        assert!(!back.token().expires_within(REFRESH_SKEW));
        let st = back.status();
        assert!(st.has_refresh_token && !st.has_client_secret && !st.endpoints_overridden);
        assert!(!st.dev_hosts_allowed, "real endpoints: no dev escape hatch");
        assert_eq!(back.bearer_scope(), BearerScope::new(Provider::Google));
        assert!(!format!("{back:?}").contains("refresh-secret"));
        // The credential JSON parses back to an OAuth AuthSpec with the access token.
        let json = back.credential_json().unwrap();
        store.update_account_credential(id, &json).unwrap();
        let acct = store.account_by_id(id).unwrap().unwrap();
        match acct.mail_auth() {
            sealbox_mail::Auth::XOAuth2 { user, access_token } => {
                assert_eq!(user, "o@example.org");
                assert_eq!(access_token, "at");
            }
            other => panic!("{other:?}"),
        }
        // The provider travels with the stored credential.
        assert_eq!(
            acct.bearer_scope(),
            Some(BearerScope::new(Provider::Google))
        );
        // Rotation keeps the old refresh token when the provider sends none.
        let rotated = OAuthTokenRow {
            refresh_token: None,
            refresh_count: 1,
            ..back.clone()
        };
        store.upsert_oauth_token(&rotated).unwrap();
        assert_eq!(store.oauth_token(id).unwrap().unwrap().refresh_count, 1);
        // Deleting the account cascades.
        store.delete_account(id).unwrap();
        assert!(store.oauth_token(id).unwrap().is_none());
    }

    #[tokio::test]
    async fn begin_oauth_binds_a_port_and_builds_the_url() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        let start = engine
            .begin_oauth(Provider::Microsoft, "x@outlook.com", "client-1", None)
            .await
            .unwrap();
        assert!(start.loopback_port > 0);
        assert_eq!(
            start.redirect_uri,
            format!("http://localhost:{}", start.loopback_port)
        );
        assert!(start.url.starts_with("https://login.microsoftonline.com/"));
        assert!(start.url.contains("login_hint=x%40outlook.com"));
        assert!(start.url.contains(&format!("state={}", start.state)));
        assert!(!format!("{start:?}").contains("pkce_verifier\":"));
        assert!(matches!(
            engine
                .begin_oauth(Provider::Google, "nope", "c", None)
                .await,
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(
            engine
                .begin_oauth(Provider::Google, "a@gmail.com", "  ", None)
                .await,
            Err(Error::InvalidInput(_))
        ));
    }

    /// An OAuth account whose IMAP/SMTP host is not its provider's: the engine refuses before
    /// any connection, unless the token came from a loopback mock IdP and the host is local.
    #[tokio::test]
    async fn tokens_are_pinned_to_their_provider_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(
            dir.path(),
            EngineConfig {
                network_timeout: Duration::from_secs(3),
                ..EngineConfig::default()
            },
        )
        .unwrap();
        // Nothing listens on this port: a connection attempt fails with `Connect`.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let add = |email: &str| {
            engine
                .store()
                .insert_account(&NewAccount {
                    email,
                    display_name: "",
                    imap: &Endpoint::new("127.0.0.1", port, Security::Plain),
                    smtp: &Endpoint::new("127.0.0.1", port, Security::Plain),
                    auth_kind: AuthKind::OAuth,
                    login: email,
                    credential: "{}",
                })
                .unwrap()
        };
        let row = |account_id: i64, auth_url: &str, token_url: &str| OAuthTokenRow {
            account_id,
            provider: Provider::Google,
            client_id: "cid".into(),
            client_secret: None,
            auth_url: auth_url.into(),
            token_url: token_url.into(),
            access_token: "tok".into(),
            refresh_token: None,
            expires_at: Some(now() + 3600),
            scopes: vec![],
            updated_at: now(),
            refresh_count: 0,
        };

        // Real Google endpoints, local mail host: refused, nothing dialled.
        let real = add("real@example.org");
        let r = row(
            real,
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
        );
        engine.store().upsert_oauth_token(&r).unwrap();
        engine
            .store()
            .update_account_credential(real, &r.credential_json().unwrap())
            .unwrap();
        let err = engine.imap_session("real@example.org").await.unwrap_err();
        assert!(
            matches!(
                &err,
                Error::Imap(ImapError::Policy(
                    sealbox_mail::TransportPolicyError::OAuthHostMismatch {
                        provider: Some(Provider::Google),
                        ..
                    }
                ))
            ),
            "{err:?}"
        );
        assert_eq!(err.exit_code(), 4);
        let err = engine.smtp_session("real@example.org").await.unwrap_err();
        assert!(
            matches!(
                &err,
                Error::Smtp(sealbox_mail::SmtpError::Policy(
                    sealbox_mail::TransportPolicyError::OAuthHostMismatch { .. }
                ))
            ),
            "{err:?}"
        );
        assert!(
            !engine
                .oauth_status("real@example.org")
                .unwrap()
                .unwrap()
                .dev_hosts_allowed
        );

        // A loopback mock IdP's token may go to the local host: the policy lets it through and
        // the connection itself fails (nobody listens).
        let dev = add("dev@example.org");
        let r = row(
            dev,
            &format!("http://127.0.0.1:{port}/auth"),
            &format!("http://127.0.0.1:{port}/token"),
        );
        engine.store().upsert_oauth_token(&r).unwrap();
        engine
            .store()
            .update_account_credential(dev, &r.credential_json().unwrap())
            .unwrap();
        let err = engine.imap_session("dev@example.org").await.unwrap_err();
        assert!(
            !matches!(&err, Error::Imap(ImapError::Policy(_))),
            "policy must pass for a mock IdP token on loopback: {err:?}"
        );
        assert!(matches!(&err, Error::Imap(_)), "{err:?}");
        assert!(
            engine
                .oauth_status("dev@example.org")
                .unwrap()
                .unwrap()
                .dev_hosts_allowed
        );
    }

    /// A loopback IMAP server offering `AUTH=XOAUTH2` that answers every `AUTHENTICATE` with
    /// Exchange's code-less `NO User is authenticated but not connected.`; returns its port and
    /// the number of connections accepted.
    async fn not_connected_imap() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let accepted = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let (rd, mut wr) = sock.into_split();
                    if wr.write_all(b"* OK scripted IMAP ready\r\n").await.is_err() {
                        return;
                    }
                    let mut lines = BufReader::new(rd).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let mut parts = line.splitn(3, ' ');
                        let tag = parts.next().unwrap_or("*").to_owned();
                        let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
                        let reply = match cmd.as_str() {
                            "CAPABILITY" => format!(
                                "* CAPABILITY IMAP4rev1 IDLE AUTH=XOAUTH2\r\n{tag} OK done\r\n"
                            ),
                            "AUTHENTICATE" => {
                                format!("{tag} NO User is authenticated but not connected.\r\n")
                            }
                            _ => format!("{tag} OK\r\n"),
                        };
                        if wr.write_all(reply.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (port, accepted)
    }

    /// The OAuth add-account probe does not spend the 5 + 10 + 20 s transient-login retry on
    /// each login candidate: a candidate Exchange refuses with `User is authenticated but not
    /// connected` (typically a login that is not the token's mailbox) is followed by the next
    /// one at once, and the final error is a plain rejected login, not a temporary one.
    #[tokio::test]
    async fn the_oauth_login_probe_does_not_retry_each_candidate() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(
            dir.path(),
            EngineConfig {
                network_timeout: Duration::from_secs(3),
                ..EngineConfig::default()
            },
        )
        .unwrap();
        let (port, connections) = not_connected_imap().await;
        let mut start = engine
            .begin_oauth(Provider::Microsoft, "probe@outlook.com", "client-1", None)
            .await
            .unwrap();
        // A loopback mock IdP: its token may go to the local scripted server.
        start.endpoints = OAuthEndpoints {
            auth_url: "http://127.0.0.1:9/auth".into(),
            token_url: "http://127.0.0.1:9/token".into(),
        };
        start.servers = Some(ServerConfig::manual(
            Endpoint::new("127.0.0.1", port, Security::Plain),
            Endpoint::new("127.0.0.1", port, Security::Plain),
            "manual",
        ));
        let token = Token {
            access_token: "probe-token-xyz".into(),
            refresh_token: None,
            expires_at: None,
            scopes: vec![],
        };
        let began = std::time::Instant::now();
        let err = tokio::time::timeout(
            Duration::from_secs(4),
            engine.add_oauth_account(start, token),
        )
        .await
        .expect("the probe must not wait out the transient-login retry")
        .unwrap_err();
        assert!(began.elapsed() < Duration::from_secs(4));
        assert!(
            matches!(
                &err,
                Error::Imap(ImapError::LoginRejected { code: None, reply, .. })
                    if reply.contains("not connected")
            ),
            "{err:?}"
        );
        if let Error::Imap(e) = &err {
            assert!(!e.is_transient_login(), "{e:?}");
        }
        assert_eq!(
            connections.load(Ordering::SeqCst),
            2,
            "one attempt per candidate (the address, then its local part)"
        );
        assert!(engine
            .store()
            .account_by_email("probe@outlook.com")
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn preflight_checks_manual_servers_before_the_browser() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        let mut start = engine
            .begin_oauth(Provider::Google, "x@gmail.com", "client-1", None)
            .await
            .unwrap();
        start
            .preflight()
            .expect("no manual servers: nothing to check");
        start.servers = Some(ServerConfig::manual(
            Endpoint::new("imap.gmail.com", 993, Security::Tls),
            Endpoint::new("smtp.gmail.com", 465, Security::Tls),
            "gmail",
        ));
        start.preflight().expect("google hosts");
        start.servers = Some(ServerConfig::manual(
            Endpoint::new("imap.evilgmail.com", 993, Security::Tls),
            Endpoint::new("smtp.gmail.com", 465, Security::Tls),
            "x",
        ));
        let err = start.preflight().unwrap_err();
        assert!(
            matches!(
                &err,
                Error::TransportPolicy(sealbox_mail::TransportPolicyError::OAuthHostMismatch {
                    host,
                    ..
                }) if host == "imap.evilgmail.com"
            ),
            "{err:?}"
        );
        assert_eq!(err.exit_code(), 4);
        start.servers = Some(ServerConfig::manual(
            Endpoint::new("imap.gmail.com", 143, Security::Plain),
            Endpoint::new("smtp.gmail.com", 465, Security::Tls),
            "x",
        ));
        assert!(matches!(
            start.preflight().unwrap_err(),
            Error::TransportPolicy(
                sealbox_mail::TransportPolicyError::InsecureTransportRefused { .. }
            )
        ));
    }

    #[tokio::test]
    async fn add_account_refuses_plaintext_to_a_public_host_before_connecting() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        let err = engine
            .add_account(crate::types::AddAccount {
                email: "a@example.com".into(),
                display_name: None,
                auth: AuthSpec::Password {
                    password: "secret".into(),
                },
                servers: Some(ServerConfig::manual(
                    Endpoint::new("imap.example.com", 993, Security::Tls),
                    Endpoint::new("smtp.example.com", 25, Security::Plain),
                    "manual",
                )),
                login: None,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::TransportPolicy(
                    sealbox_mail::TransportPolicyError::InsecureTransportRefused { host, port: 25 }
                ) if host == "smtp.example.com"
            ),
            "{err:?}"
        );
        assert_eq!(err.exit_code(), 4);
        assert!(err
            .to_string()
            .contains("SEALBOX_ALLOW_PLAIN_HOSTS=smtp.example.com"));
        assert!(engine
            .store()
            .account_by_email("a@example.com")
            .unwrap()
            .is_none());
    }
}
