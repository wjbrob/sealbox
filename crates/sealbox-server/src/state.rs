//! Shared application state and its construction.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use crate::{
    db::{self, Db, PurgeReport},
    hosted::HostedService,
    mail::MailSender,
    ratelimit::RateLimiter,
    util,
};

/// Tunables; the defaults are what production runs with and what the gate test exercises.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Max request body (JSON or raw) in bytes. Default 25 MiB.
    pub max_body_bytes: usize,
    /// Max size of an uploaded key (`keytext`) in bytes. Default 1 MiB.
    pub max_key_bytes: usize,
    /// Key uploads per IP per hour.
    pub upload_per_hour: u32,
    /// `request-verify` calls per IP per hour.
    pub request_verify_per_hour: u32,
    /// Challenge mails per (key, address) per hour.
    pub challenge_mails_per_address_per_hour: u32,
    /// Challenge-link attempts per IP per hour.
    pub verify_attempts_per_hour: u32,
    /// Guest message posts per IP per hour.
    pub guest_post_per_hour: u32,
    /// Guest replies per IP per hour.
    pub reply_per_hour: u32,
    /// Backup PUTs per IP per hour.
    pub backup_put_per_hour: u32,
    /// Replies kept per guest message.
    pub max_replies_per_message: i64,
    /// Longest allowed guest-message lifetime (seconds). Default 30 days.
    pub max_guest_expiry_secs: i64,
    /// Lifetime when the client sends none. Default 7 days.
    pub default_guest_expiry_secs: i64,
    /// Lifetime of upload tokens and challenge links (seconds). Default 24 h.
    pub token_ttl_secs: i64,
    /// G29 e-mail-code gate: a code is valid this long (seconds). Default 10 min.
    pub guest_code_ttl_secs: i64,
    /// Wrong codes allowed before the gate locks. Default 5.
    pub guest_code_max_attempts: i64,
    /// Lock duration after too many wrong codes (seconds). Default 15 min.
    pub guest_code_lock_secs: i64,
    /// Lifetime of the access token a correct code yields (seconds). Default 15 min.
    pub guest_access_token_ttl_secs: i64,
    /// Code mails per guest message per hour.
    pub guest_code_mails_per_message_per_hour: u32,
    /// `send-code` calls per IP per hour.
    pub guest_code_requests_per_ip_per_hour: u32,
    /// `verify` calls per IP per hour (on top of the per-message lock).
    pub guest_verify_per_ip_per_hour: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 25 * 1024 * 1024,
            max_key_bytes: 1024 * 1024,
            upload_per_hour: 60,
            request_verify_per_hour: 30,
            challenge_mails_per_address_per_hour: 3,
            verify_attempts_per_hour: 120,
            guest_post_per_hour: 120,
            reply_per_hour: 120,
            backup_put_per_hour: 60,
            max_replies_per_message: 100,
            max_guest_expiry_secs: 30 * 24 * 3600,
            default_guest_expiry_secs: 7 * 24 * 3600,
            token_ttl_secs: 24 * 3600,
            guest_code_ttl_secs: 600,
            guest_code_max_attempts: 5,
            guest_code_lock_secs: 900,
            guest_access_token_ttl_secs: 900,
            guest_code_mails_per_message_per_hour: 5,
            guest_code_requests_per_ip_per_hour: 20,
            guest_verify_per_ip_per_hour: 60,
        }
    }
}

/// Everything needed to build an [`AppState`].
pub struct StateOptions {
    pub db_path: PathBuf,
    /// Public base URL without trailing slash (used in links we hand out).
    pub public_url: String,
    pub static_dir: PathBuf,
    pub mailer: Arc<dyn MailSender>,
    pub trust_proxy: bool,
    pub limits: Limits,
}

struct Inner {
    db: Db,
    mailer: Arc<dyn MailSender>,
    public_url: String,
    static_dir: PathBuf,
    limiter: RateLimiter,
    limits: Limits,
    trust_proxy: bool,
    started: Instant,
    /// Hosted-mailbox service, attached after construction (see [`AppState::set_hosted`]).
    hosted: OnceLock<HostedService>,
}

/// Cheap-to-clone handle shared by all handlers.
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

impl AppState {
    /// Open the database (migrating the schema) and assemble the state.
    pub fn new(opts: StateOptions) -> Result<Self, db::DbError> {
        let db = Db::open(&opts.db_path)?;
        Ok(Self(Arc::new(Inner {
            db,
            mailer: opts.mailer,
            public_url: opts.public_url.trim_end_matches('/').to_owned(),
            static_dir: opts.static_dir,
            limiter: RateLimiter::new(),
            limits: opts.limits,
            trust_proxy: opts.trust_proxy,
            started: Instant::now(),
            hosted: OnceLock::new(),
        })))
    }

    /// Attach the hosted-mailbox service (enables `/v1/hosted/*`). Returns `false` if one was
    /// already attached; the first one stays.
    pub fn set_hosted(&self, service: HostedService) -> bool {
        self.0.hosted.set(service).is_ok()
    }

    /// The hosted-mailbox service, when configured.
    pub fn hosted(&self) -> Option<&HostedService> {
        self.0.hosted.get()
    }

    pub fn db(&self) -> &Db {
        &self.0.db
    }

    pub fn mailer(&self) -> &dyn MailSender {
        self.0.mailer.as_ref()
    }

    pub fn public_url(&self) -> &str {
        &self.0.public_url
    }

    pub fn static_dir(&self) -> &Path {
        &self.0.static_dir
    }

    pub fn limits(&self) -> &Limits {
        &self.0.limits
    }

    pub fn trust_proxy(&self) -> bool {
        self.0.trust_proxy
    }

    pub fn uptime(&self) -> Duration {
        self.0.started.elapsed()
    }

    /// `true` if `(scope, key)` is within `per_hour` events per hour.
    pub fn allow(&self, scope: &'static str, key: &str, per_hour: u32) -> bool {
        self.0
            .limiter
            .check(scope, key, per_hour, Duration::from_secs(3600))
    }

    /// Delete expired guest messages, challenges and upload tokens now.
    pub async fn purge_expired(&self) -> Result<PurgeReport, db::DbError> {
        let now = util::now();
        self.db().call(move |c| db::purge_expired(c, now)).await
    }

    /// Spawn the periodic purge; abort the handle at shutdown.
    pub fn spawn_purge_task(&self, every: Duration) -> tokio::task::JoinHandle<()> {
        let state = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                match state.purge_expired().await {
                    Ok(r) if r != PurgeReport::default() => {
                        tracing::info!(?r, "purged expired rows")
                    }
                    Ok(_) => {}
                    Err(e) => tracing::error!(error = %e, "purge failed"),
                }
            }
        })
    }
}
