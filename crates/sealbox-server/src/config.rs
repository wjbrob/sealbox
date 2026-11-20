//! Process configuration: clap flags, each with an `SEALBOX_*` environment fallback.

use std::{net::SocketAddr, path::PathBuf};

use clap::{Parser, ValueEnum};

/// Command-line / environment configuration of the `sealbox-server` binary.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "sealbox-server",
    version,
    about = "Sealbox backend: key directory, guest messages, encrypted backups"
)]
pub struct Config {
    /// Socket address to listen on.
    #[arg(long, env = "SEALBOX_BIND", default_value = "127.0.0.1:8787")]
    pub bind: SocketAddr,

    /// SQLite database path (created on first start, schema migrated automatically).
    #[arg(long, env = "SEALBOX_DB", default_value = "sealbox-server.sqlite")]
    pub db: PathBuf,

    /// Public base URL used in guest links and challenge e-mails (no trailing slash),
    /// e.g. `https://sealbox.example`. Defaults to `http://{bind}`.
    #[arg(long, env = "SEALBOX_PUBLIC_URL")]
    pub public_url: Option<String>,

    /// Directory holding the static guest viewer (`index.html`, `viewer.js`, `vendor/`).
    #[arg(long, env = "SEALBOX_STATIC_DIR", default_value = "./web/guest")]
    pub static_dir: PathBuf,

    /// SMTP host used to send address-verification challenge mails. Unset = challenge mails
    /// are dropped (logged, without their content) and nobody can verify an address.
    #[arg(long, env = "SEALBOX_SMTP_HOST")]
    pub smtp_host: Option<String>,

    /// SMTP port.
    #[arg(long, env = "SEALBOX_SMTP_PORT", default_value_t = 587)]
    pub smtp_port: u16,

    /// SMTP user name (optional; omit for unauthenticated relays such as a local GreenMail/mailpit).
    #[arg(long, env = "SEALBOX_SMTP_USER")]
    pub smtp_user: Option<String>,

    /// SMTP password / app password.
    #[arg(long, env = "SEALBOX_SMTP_PASS", hide_env_values = true)]
    pub smtp_pass: Option<String>,

    /// `From:` address of challenge mails, e.g. `Sealbox <noreply@sealbox.example>`.
    #[arg(
        long,
        env = "SEALBOX_SMTP_FROM",
        default_value = "Sealbox <noreply@localhost>"
    )]
    pub smtp_from: String,

    /// How to secure the SMTP connection.
    #[arg(long, env = "SEALBOX_SMTP_TLS", value_enum, default_value_t = SmtpTlsMode::Starttls)]
    pub smtp_tls: SmtpTlsMode,

    /// Trust `X-Forwarded-For` for the per-IP rate limiter (only when behind your own reverse proxy).
    #[arg(long, env = "SEALBOX_TRUST_PROXY", default_value_t = false)]
    pub trust_proxy: bool,

    /// Seconds between purges of expired guest messages / challenges / tokens.
    #[arg(long, env = "SEALBOX_PURGE_INTERVAL_SECS", default_value_t = 60)]
    pub purge_interval_secs: u64,

    /// Lock after too many wrong guest e-mail codes, in seconds (G29). Default 15 minutes;
    /// the gate script shortens it to exercise the unlock path.
    #[arg(long, env = "SEALBOX_GUEST_CODE_LOCK_SECS", default_value_t = 900)]
    pub guest_code_lock_secs: i64,

    // ----- hosted mailboxes ("Create a new Sealbox address"), see docs/HOSTED_MAILBOX.md -----
    /// Domain new hosted addresses are created under. Unset = `/v1/hosted/*` is disabled.
    #[arg(long, env = "SEALBOX_HOSTED_DOMAIN")]
    pub hosted_domain: Option<String>,

    /// Base URL of the Stalwart management API, e.g. `http://127.0.0.1:8084`.
    #[arg(long, env = "SEALBOX_STALWART_URL")]
    pub stalwart_url: Option<String>,

    /// Stalwart administrator login (an admin account, or the recovery admin).
    #[arg(long, env = "SEALBOX_STALWART_ADMIN_USER", default_value = "admin")]
    pub stalwart_admin_user: String,

    /// Stalwart administrator secret.
    #[arg(long, env = "SEALBOX_STALWART_ADMIN_SECRET", hide_env_values = true)]
    pub stalwart_admin_secret: Option<String>,

    /// IMAP host handed to new hosted accounts (default `mail.<hosted domain>`).
    #[arg(long, env = "SEALBOX_HOSTED_IMAP_HOST")]
    pub hosted_imap_host: Option<String>,

    /// IMAP port handed to new hosted accounts.
    #[arg(long, env = "SEALBOX_HOSTED_IMAP_PORT", default_value_t = 993)]
    pub hosted_imap_port: u16,

    /// IMAP security handed to new hosted accounts: `plain`, `starttls` or `tls`.
    #[arg(long, env = "SEALBOX_HOSTED_IMAP_SECURITY", default_value = "tls")]
    pub hosted_imap_security: String,

    /// SMTP host handed to new hosted accounts (default `mail.<hosted domain>`).
    #[arg(long, env = "SEALBOX_HOSTED_SMTP_HOST")]
    pub hosted_smtp_host: Option<String>,

    /// SMTP (submission) port handed to new hosted accounts.
    #[arg(long, env = "SEALBOX_HOSTED_SMTP_PORT", default_value_t = 587)]
    pub hosted_smtp_port: u16,

    /// SMTP security handed to new hosted accounts: `plain`, `starttls` or `tls`.
    #[arg(long, env = "SEALBOX_HOSTED_SMTP_SECURITY", default_value = "starttls")]
    pub hosted_smtp_security: String,

    /// Who may sign up: `open`, `invite` (needs a code from SEALBOX_HOSTED_INVITES) or `closed`.
    #[arg(long, env = "SEALBOX_HOSTED_SIGNUPS", value_enum, default_value_t = crate::hosted::SignupMode::Invite)]
    pub hosted_signups: crate::hosted::SignupMode,

    /// Comma-separated invite codes.
    #[arg(long, env = "SEALBOX_HOSTED_INVITES", hide_env_values = true)]
    pub hosted_invites: Option<String>,

    /// Successful hosted signups allowed per client IP per 24 h.
    #[arg(long, env = "SEALBOX_HOSTED_PER_IP_DAILY", default_value_t = 3)]
    pub hosted_per_ip_daily: u32,

    /// Successful hosted signups allowed across all clients per 24 h.
    #[arg(long, env = "SEALBOX_HOSTED_GLOBAL_DAILY", default_value_t = 200)]
    pub hosted_global_daily: u32,

    /// Key for the IP hash stored with each signup (random per process when unset).
    #[arg(long, env = "SEALBOX_HOSTED_IP_HASH_KEY", hide_env_values = true)]
    pub hosted_ip_hash_key: Option<String>,
}

/// TLS mode for the outgoing SMTP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SmtpTlsMode {
    /// Plain connection upgraded with STARTTLS (port 587).
    Starttls,
    /// Implicit TLS from the first byte (port 465).
    Tls,
    /// No TLS at all — only for a local test relay.
    None,
}

impl Config {
    /// The public base URL without a trailing slash.
    pub fn effective_public_url(&self) -> String {
        let url = self
            .public_url
            .clone()
            .unwrap_or_else(|| format!("http://{}", self.bind));
        url.trim_end_matches('/').to_owned()
    }
}
