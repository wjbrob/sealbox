//! Hosted mailboxes: "Create a new Sealbox address" for people without a mailbox they want to
//! use. The backend provisions `name@<hosted domain>` on a Stalwart mail server through its
//! management API and hands the generated password to the client **once**.
//!
//! * `GET  /v1/hosted/info` — domain, whether signups are open, the name rules, IMAP/SMTP.
//! * `GET  /v1/hosted/availability?local_part=` — is a name free?
//! * `POST /v1/hosted/signup {local_part, invite_code?, recovery_email?}` → 201 with the
//!   address, password and server settings.
//!
//! Abuse controls: a sliding-window limiter per IP for attempts, a per-IP daily cap and a
//! global daily cap on *successful* signups (counted from the database), optional invite codes
//! (`SEALBOX_HOSTED_SIGNUPS=invite` + `SEALBOX_HOSTED_INVITES=a,b,c`) and a `closed` mode.
//! The server never keeps the password (only its SHA-256), never logs it, and stores a keyed
//! hash of the client IP rather than the IP.

pub mod stalwart;
pub mod store;
pub mod validate;

use std::time::Duration;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;

use crate::{
    config::Config,
    db::{Db, DbError},
    error::{AppError, AppResult},
    util,
};

use self::stalwart::{StalwartClient, StalwartError};
use self::store::ReserveOutcome;

/// Who may sign up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum SignupMode {
    /// Anyone (subject to the caps).
    Open,
    /// Only with a valid invite code.
    Invite,
    /// Nobody; the endpoints answer but refuse.
    Closed,
}

/// IMAP or SMTP endpoint handed to clients. `security` is `plain`, `starttls` or `tls`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub host: String,
    pub port: u16,
    pub security: String,
}

/// Static configuration of the hosted-mailbox service.
#[derive(Debug, Clone)]
pub struct HostedConfig {
    pub domain: String,
    pub imap: EndpointInfo,
    pub smtp: EndpointInfo,
    pub signups: SignupMode,
    /// Accepted invite codes (compared case-sensitively after trimming).
    pub invites: Vec<String>,
    /// Successful signups per IP per 24 h.
    pub per_ip_daily: u32,
    /// Successful signups across all clients per 24 h.
    pub global_daily: u32,
    /// Signup *attempts* per IP per hour (burst protection, in-memory).
    pub attempts_per_hour: u32,
    /// Availability checks per IP per hour.
    pub availability_per_hour: u32,
    /// Key for the IP hash stored with each signup.
    pub ip_hash_key: String,
    /// Timeout for each Stalwart call.
    pub stalwart_timeout: Duration,
}

/// `POST /v1/hosted/signup` body.
#[derive(Debug, Clone, Deserialize)]
pub struct SignupRequest {
    pub local_part: String,
    #[serde(default)]
    pub invite_code: Option<String>,
    /// An address the user already owns, for a future account-recovery flow. Only its SHA-256
    /// is stored.
    #[serde(default)]
    pub recovery_email: Option<String>,
}

/// `POST /v1/hosted/signup` response — the only time the password is ever shown.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignupResponse {
    pub email: String,
    /// Login name for IMAP/SMTP (the full address).
    pub login: String,
    pub password: String,
    pub domain: String,
    pub imap: EndpointInfo,
    pub smtp: EndpointInfo,
    /// Unix seconds.
    pub created_at: i64,
}

impl std::fmt::Debug for SignupResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupResponse")
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// Name rules, reported by `/v1/hosted/info`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requirements {
    pub min_length: usize,
    pub max_length: usize,
    pub pattern: String,
    pub reserved: Vec<String>,
    pub reserved_prefixes: Vec<String>,
}

/// `GET /v1/hosted/info` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoResponse {
    pub domain: String,
    pub signups: SignupMode,
    pub invite_required: bool,
    pub requirements: Requirements,
    pub imap: EndpointInfo,
    pub smtp: EndpointInfo,
}

/// `GET /v1/hosted/availability` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilityResponse {
    /// The normalised name that was checked.
    pub local_part: String,
    /// The address it would become.
    pub email: String,
    pub available: bool,
    /// `None` when available; otherwise `too_short`, `too_long`, `invalid_characters`,
    /// `invalid_shape`, `reserved` or `taken`.
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

/// The hosted-mailbox service: configuration + Stalwart client + cached domain id.
pub struct HostedService {
    pub config: HostedConfig,
    client: StalwartClient,
    domain_id: OnceCell<String>,
}

impl std::fmt::Debug for HostedService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedService")
            .field("config", &self.config)
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

/// Seconds in the daily-cap window.
const DAY: i64 = 24 * 3600;

impl HostedService {
    pub fn new(config: HostedConfig, client: StalwartClient) -> Self {
        Self {
            config,
            client,
            domain_id: OnceCell::new(),
        }
    }

    /// Build from the process configuration; `Ok(None)` when hosted signups are not configured
    /// (no `SEALBOX_HOSTED_DOMAIN`).
    pub fn from_config(cfg: &Config) -> anyhow::Result<Option<Self>> {
        let Some(domain) = cfg
            .hosted_domain
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
        else {
            return Ok(None);
        };
        let domain = domain.to_ascii_lowercase();
        let url = cfg
            .stalwart_url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("SEALBOX_STALWART_URL is required with SEALBOX_HOSTED_DOMAIN")
            })?;
        let secret = cfg
            .stalwart_admin_secret
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "SEALBOX_STALWART_ADMIN_SECRET is required with SEALBOX_HOSTED_DOMAIN"
                )
            })?;
        let security = |s: &str| -> anyhow::Result<String> {
            let s = s.trim().to_ascii_lowercase();
            anyhow::ensure!(
                matches!(s.as_str(), "plain" | "starttls" | "tls"),
                "security must be plain|starttls|tls, got {s:?}"
            );
            Ok(s)
        };
        let host_or = |h: &Option<String>| {
            h.as_deref()
                .map(str::trim)
                .filter(|h| !h.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("mail.{domain}"))
        };
        let invites = cfg
            .hosted_invites
            .as_deref()
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if cfg.hosted_signups == SignupMode::Invite && invites.is_empty() {
            tracing::warn!("SEALBOX_HOSTED_SIGNUPS=invite but SEALBOX_HOSTED_INVITES is empty: nobody can sign up");
        }
        let config = HostedConfig {
            domain: domain.clone(),
            imap: EndpointInfo {
                host: host_or(&cfg.hosted_imap_host),
                port: cfg.hosted_imap_port,
                security: security(&cfg.hosted_imap_security)?,
            },
            smtp: EndpointInfo {
                host: host_or(&cfg.hosted_smtp_host),
                port: cfg.hosted_smtp_port,
                security: security(&cfg.hosted_smtp_security)?,
            },
            signups: cfg.hosted_signups,
            invites,
            per_ip_daily: cfg.hosted_per_ip_daily,
            global_daily: cfg.hosted_global_daily,
            attempts_per_hour: 20,
            availability_per_hour: 120,
            ip_hash_key: cfg
                .hosted_ip_hash_key
                .clone()
                .filter(|k| !k.is_empty())
                .unwrap_or_else(|| {
                    tracing::info!("SEALBOX_HOSTED_IP_HASH_KEY unset: using a random per-process key (daily caps reset on restart)");
                    util::random_token(32)
                }),
            stalwart_timeout: Duration::from_secs(20),
        };
        let client = StalwartClient::new(
            url,
            &cfg.stalwart_admin_user,
            secret,
            config.stalwart_timeout,
        )?;
        Ok(Some(Self::new(config, client)))
    }

    /// Create the signup table (idempotent).
    pub async fn ensure_schema(&self, db: &Db) -> Result<(), DbError> {
        db.call(|c| store::ensure_schema(c)).await
    }

    /// The Stalwart client (tests).
    pub fn client(&self) -> &StalwartClient {
        &self.client
    }

    /// `name@domain`.
    pub fn email_for(&self, local_part: &str) -> String {
        format!("{local_part}@{}", self.config.domain)
    }

    /// Keyed SHA-256 of a client IP, hex.
    pub fn ip_hash(&self, ip: &str) -> String {
        let mut h = Sha256::new();
        h.update(self.config.ip_hash_key.as_bytes());
        h.update(b"\0");
        h.update(ip.as_bytes());
        hex::encode(h.finalize())
    }

    /// What `/v1/hosted/info` reports.
    pub fn info(&self) -> InfoResponse {
        InfoResponse {
            domain: self.config.domain.clone(),
            signups: self.config.signups,
            invite_required: self.config.signups == SignupMode::Invite,
            requirements: Requirements {
                min_length: validate::MIN_LEN,
                max_length: validate::MAX_LEN,
                pattern: validate::PATTERN.to_owned(),
                reserved: validate::RESERVED.iter().map(|s| s.to_string()).collect(),
                reserved_prefixes: validate::RESERVED_PREFIXES
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            },
            imap: self.config.imap.clone(),
            smtp: self.config.smtp.clone(),
        }
    }

    async fn domain_id(&self) -> AppResult<String> {
        let id = self
            .domain_id
            .get_or_try_init(|| async {
                match self.client.domain_id(&self.config.domain).await {
                    Ok(Some(id)) => Ok(id),
                    Ok(None) => Err(anyhow::anyhow!(
                        "domain {} does not exist on the Stalwart server",
                        self.config.domain
                    )),
                    Err(e) => Err(anyhow::Error::from(e)),
                }
            })
            .await
            .map_err(AppError::Internal)?;
        Ok(id.clone())
    }

    /// Is `raw_local` free? Checks the rules, our reservations and Stalwart.
    pub async fn availability(&self, db: &Db, raw_local: &str) -> AppResult<AvailabilityResponse> {
        let shown = raw_local.trim().to_ascii_lowercase();
        let local = match validate::normalize(raw_local) {
            Ok(l) => l,
            Err(rej) => {
                return Ok(AvailabilityResponse {
                    email: self.email_for(&shown),
                    local_part: shown,
                    available: false,
                    reason: Some(rej.tag().to_owned()),
                    message: Some(rej.message().to_owned()),
                })
            }
        };
        let taken = {
            let l = local.clone();
            db.call(move |c| store::exists(c, &l)).await?
        } || self
            .client
            .account_exists(&local)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(AvailabilityResponse {
            email: self.email_for(&local),
            local_part: local,
            available: !taken,
            reason: taken.then(|| "taken".to_owned()),
            message: taken.then(|| "that name is already taken".to_owned()),
        })
    }

    /// Provision a mailbox. `ip` is the client address (for caps). Errors map to 400 (rules,
    /// closed, invite), 409 (taken), 429 (caps) and 500 (Stalwart unreachable).
    pub async fn signup(&self, db: &Db, ip: &str, req: SignupRequest) -> AppResult<SignupResponse> {
        // Policy first, so a closed server never touches Stalwart.
        let invite = match self.config.signups {
            SignupMode::Closed => {
                return Err(AppError::BadRequest("signups are closed".into()));
            }
            SignupMode::Open => req
                .invite_code
                .as_deref()
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(str::to_owned),
            SignupMode::Invite => {
                let code = req
                    .invite_code
                    .as_deref()
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .ok_or_else(|| AppError::BadRequest("an invite code is required".into()))?;
                if !validate::invite_code_shaped(code)
                    || !self
                        .config
                        .invites
                        .iter()
                        .any(|i| util::ct_eq(i.as_bytes(), code.as_bytes()))
                {
                    return Err(AppError::BadRequest("invalid invite code".into()));
                }
                Some(code.to_owned())
            }
        };
        let local = validate::normalize(&req.local_part)
            .map_err(|r| AppError::BadRequest(r.message().into()))?;
        let recovery_hash = match req.recovery_email.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(r) => {
                if !r.contains('@') || r.len() > 254 || r.contains(char::is_whitespace) {
                    return Err(AppError::BadRequest(
                        "recovery_email is not an e-mail address".into(),
                    ));
                }
                Some(util::token_hash(&r.to_ascii_lowercase()))
            }
        };

        // Daily caps (successful signups recorded in the database).
        let now = util::now();
        let ip_hash = self.ip_hash(ip);
        let (per_ip, global) = {
            let h = ip_hash.clone();
            db.call(move |c| -> Result<(u32, u32), DbError> {
                Ok((
                    store::count_since(c, Some(&h), now - DAY)?,
                    store::count_since(c, None, now - DAY)?,
                ))
            })
            .await?
        };
        if per_ip >= self.config.per_ip_daily || global >= self.config.global_daily {
            tracing::info!(per_ip, global, "hosted signup refused by daily cap");
            return Err(AppError::RateLimited);
        }

        // Reserve the name before talking to Stalwart (UNIQUE row = the lock).
        let email = self.email_for(&local);
        let password = validate::generate_password();
        let password_hash = util::token_hash(&password);
        let row_id = {
            let (l, e, h, i, r) = (
                local.clone(),
                email.clone(),
                ip_hash.clone(),
                invite.clone(),
                recovery_hash.clone(),
            );
            db.call(move |c| {
                store::reserve(
                    c,
                    &store::NewSignup {
                        local_part: &l,
                        email: &e,
                        password_sha256: &password_hash,
                        recovery_email_sha256: r.as_deref(),
                        ip_hash: &h,
                        invite_code: i.as_deref(),
                        created_at: now,
                    },
                )
            })
            .await?
        };
        let row_id = match row_id {
            ReserveOutcome::Reserved(id) => id,
            ReserveOutcome::Taken => {
                return Err(AppError::Conflict("that name is already taken".into()));
            }
        };

        // Provision on Stalwart; roll the reservation back on any failure.
        let provisioned = async {
            let domain_id = self.domain_id().await?;
            self.client
                .create_account(&local, &domain_id, &password, "Sealbox hosted mailbox")
                .await
                .map_err(|e| match e {
                    e if e.is_already_exists() => {
                        AppError::Conflict("that name is already taken".into())
                    }
                    StalwartError::Api { kind, description } => {
                        tracing::error!(kind, description, "stalwart refused the account");
                        AppError::Internal(anyhow::anyhow!("mail server refused the account"))
                    }
                    other => AppError::Internal(other.into()),
                })
        }
        .await;
        let stalwart_id = match provisioned {
            Ok(id) => id,
            Err(e) => {
                if let Err(db_err) = db.call(move |c| store::release(c, row_id)).await {
                    tracing::error!(error = %db_err, "could not release hosted reservation");
                }
                return Err(e);
            }
        };
        {
            let sid = stalwart_id.clone();
            db.call(move |c| store::set_stalwart_id(c, row_id, &sid))
                .await?;
        }
        tracing::info!(email = %email, invite = invite.is_some(), "hosted mailbox created");
        Ok(SignupResponse {
            login: email.clone(),
            email,
            password,
            domain: self.config.domain.clone(),
            imap: self.config.imap.clone(),
            smtp: self.config.smtp.clone(),
            created_at: now,
        })
    }
}

impl From<StalwartError> for AppError {
    fn from(e: StalwartError) -> Self {
        AppError::Internal(e.into())
    }
}
