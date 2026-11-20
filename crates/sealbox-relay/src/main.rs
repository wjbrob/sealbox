//! `sealbox-relay` binary: the push relay process (gate G16).
//!
//! ```text
//! SEALBOX_RELAY_API_TOKEN=… sealbox-relay --bind 127.0.0.1:8090 --max-registrations 1000
//! ```
//!
//! Refuses to start (exit status 2) on a non-loopback `--bind` without an API token unless
//! `--allow-open-relay` is given ([`sealbox_relay::bind_policy`]), and on a malformed
//! `--imap-allow-hosts` / `--webhook-allow-hosts`. IMAP servers and webhooks must be public
//! destinations unless `--imap-allow-private` / `--webhook-allow-private` (development) are
//! given. Stops on Ctrl-C / SIGTERM: in-flight requests
//! finish, every IDLE worker is cancelled and waited for (bounded), then the process exits.
//! Registrations are not persisted: clients re-register after a restart (see
//! `docs/PUSH_RELAY.md`).

use std::{net::SocketAddr, time::Duration};

use anyhow::Context as _;
use clap::{builder::BoolishValueParser, ArgAction, Parser};
use sealbox_relay::{
    api,
    bind_policy::{self, Exposure},
    AllowHosts, ImapAllowHosts, Options, Secret, WorkerConfig,
};
use tokio::net::TcpListener;

/// Sealbox push relay: IMAP IDLE → content-free push.
#[derive(Parser, Debug)]
#[command(name = "sealbox-relay", version, about)]
struct Cli {
    /// Address to listen on for the registration API.
    #[arg(long, env = "SEALBOX_RELAY_BIND", default_value = "127.0.0.1:8090")]
    bind: String,

    /// Bearer token clients must present on /v1/push/* (`Authorization: Bearer …`). Required
    /// when --bind is not a loopback address (see --allow-open-relay). Prefer the environment
    /// variable: a flag is visible in `ps`.
    #[arg(long, env = "SEALBOX_RELAY_API_TOKEN", hide_env_values = true)]
    api_token: Option<String>,

    /// Start without an API token even though --bind is not a loopback address. Anyone who can
    /// reach the relay can then register mailboxes; logged as a warning at startup.
    #[arg(long, env = "SEALBOX_RELAY_ALLOW_OPEN_RELAY", action = ArgAction::SetTrue,
          value_parser = BoolishValueParser::new())]
    allow_open_relay: bool,

    /// Maximum number of concurrent registrations (each holds one IMAP connection).
    #[arg(long, env = "SEALBOX_RELAY_MAX_REGISTRATIONS", default_value_t = 1000)]
    max_registrations: usize,

    /// Registration attempts per client address per minute; beyond that 429 with Retry-After.
    /// 0 disables the limit.
    #[arg(long, env = "SEALBOX_RELAY_REGISTER_RATE_LIMIT", default_value_t = 30)]
    register_rate_limit: u32,

    /// Comma-separated IMAP host allow-list: exact host names (`imap.gmail.com`), `.suffix`
    /// entries (`.office365.com` admits every name under office365.com) and IP addresses. When
    /// set, no other IMAP host is accepted.
    #[arg(long, env = "SEALBOX_RELAY_IMAP_ALLOW_HOSTS", value_delimiter = ',')]
    imap_allow_hosts: Vec<String>,

    /// Development and tests only: accept IMAP servers that resolve to loopback, private,
    /// link-local, unique-local or other non-public addresses (a local test server).
    #[arg(long, env = "SEALBOX_RELAY_IMAP_ALLOW_PRIVATE", action = ArgAction::SetTrue,
          value_parser = BoolishValueParser::new())]
    imap_allow_private: bool,

    /// Development and tests only: accept webhook destinations that resolve to loopback,
    /// private, link-local, unique-local or other non-public addresses.
    #[arg(long, env = "SEALBOX_RELAY_WEBHOOK_ALLOW_PRIVATE", action = ArgAction::SetTrue,
          value_parser = BoolishValueParser::new())]
    webhook_allow_private: bool,

    /// Development only: accept http:// webhooks to a non-public destination (needs
    /// --webhook-allow-private as well; http to a public host is always refused).
    #[arg(long, env = "SEALBOX_RELAY_WEBHOOK_ALLOW_HTTP_PRIVATE", action = ArgAction::SetTrue,
          value_parser = BoolishValueParser::new())]
    webhook_allow_http_private: bool,

    /// Comma-separated webhook host allow-list, e.g. `push.example.com,203.0.113.7`. A name also
    /// admits its subdomains. When set, no other webhook host is accepted.
    #[arg(long, env = "SEALBOX_RELAY_WEBHOOK_ALLOW_HOSTS", value_delimiter = ',')]
    webhook_allow_hosts: Vec<String>,

    /// How long a parked registration (its credentials were rejected three times) stays
    /// visible before it is evicted: a number with an optional unit `s` (default), `m`, `h` or
    /// `d`, e.g. `24h`, `90m`, `3600`. `0` evicts it at once.
    #[arg(long, env = "SEALBOX_RELAY_PARKED_TTL", default_value = "24h",
          value_parser = parse_ttl)]
    parked_ttl: Duration,

    /// Log filter (tracing `EnvFilter` syntax, e.g. `info`, `sealbox_relay=debug`).
    #[arg(long, env = "SEALBOX_RELAY_LOG", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let filter = tracing_subscriber::EnvFilter::try_new(&cli.log_level)
        .map_err(|e| anyhow::anyhow!("invalid --log-level {:?}: {e}", cli.log_level))?;
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let api_token = cli
        .api_token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(Secret::new);
    let authenticated = api_token.is_some();

    // Resolve --bind once: the exposure decision and the listener use the same addresses, and
    // a refusal happens before any port is bound.
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(cli.bind.as_str())
        .await
        .with_context(|| format!("cannot resolve --bind {:?}", cli.bind))?
        .collect();
    let exposure = match bind_policy::decide(&addrs, authenticated, cli.allow_open_relay) {
        Ok(exposure) => exposure,
        Err(refusal) => refuse(&refusal),
    };
    let webhook_allow_hosts = match AllowHosts::parse(&cli.webhook_allow_hosts) {
        Ok(list) => list,
        Err(invalid) => refuse(&invalid),
    };
    let allow_list = webhook_allow_hosts
        .as_ref()
        .map(AllowHosts::entries)
        .unwrap_or_default();
    let imap_allow_hosts = match ImapAllowHosts::parse(&cli.imap_allow_hosts) {
        Ok(list) => list,
        Err(invalid) => refuse(&invalid),
    };
    let imap_allow_list = imap_allow_hosts
        .as_ref()
        .map(ImapAllowHosts::entries)
        .unwrap_or_default();

    let state = api::AppState::new(Options {
        max_registrations: cli.max_registrations,
        api_token,
        imap_allow_private: cli.imap_allow_private,
        imap_allow_hosts,
        webhook_allow_private: cli.webhook_allow_private,
        webhook_allow_http_private: cli.webhook_allow_http_private,
        webhook_allow_hosts,
        register_rate_limit: cli.register_rate_limit,
        worker: WorkerConfig {
            parked_ttl: cli.parked_ttl,
            ..WorkerConfig::default()
        },
        ..Options::default()
    })?;

    // Install the SIGTERM handler before the listener is announced: a SIGTERM that arrives
    // right after startup is then a graceful shutdown too, not the default disposition.
    #[cfg(unix)]
    let term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());

    let listener = TcpListener::bind(&addrs[..]).await?;
    let addr = listener.local_addr()?;
    tracing::info!(
        %addr,
        authenticated,
        max_registrations = cli.max_registrations,
        register_rate_limit = cli.register_rate_limit,
        imap_allow_private = cli.imap_allow_private,
        imap_allow_hosts = imap_allow_list.len(),
        parked_ttl_secs = cli.parked_ttl.as_secs(),
        webhook_allow_private = cli.webhook_allow_private,
        webhook_allow_http_private = cli.webhook_allow_http_private,
        webhook_allow_hosts = allow_list.len(),
        "sealbox-relay listening"
    );
    if !imap_allow_list.is_empty() {
        tracing::info!("IMAP allow-list: {}", imap_allow_list.join(", "));
    }
    if !allow_list.is_empty() {
        tracing::info!("webhook allow-list: {}", allow_list.join(", "));
    }
    match exposure {
        Exposure::Authenticated => {}
        Exposure::OpenLoopback => tracing::warn!(
            "no API token configured: anyone who can reach {addr} can register mailboxes \
             (loopback only; set --api-token / SEALBOX_RELAY_API_TOKEN)"
        ),
        Exposure::OpenOverride => {
            let warning = format!(
                "OPEN RELAY: listening on {addr} without an API token (--allow-open-relay). \
                 Anyone who can reach this address can register mailboxes and make this relay \
                 connect to IMAP servers and post webhooks on their behalf"
            );
            tracing::warn!("{warning}");
            // Also on stderr, in case the log filter hides warnings.
            eprintln!("WARNING: {warning}");
        }
    }
    if cli.imap_allow_private {
        tracing::warn!(
            "--imap-allow-private: registrations may make this relay connect to IMAP servers on \
             loopback, private and link-local addresses (development and tests only)"
        );
    }
    if cli.webhook_allow_private {
        tracing::warn!(
            "--webhook-allow-private: webhooks may target loopback, private and link-local \
             addresses, including cloud metadata services (development and tests only)"
        );
    }
    if cli.webhook_allow_http_private {
        if cli.webhook_allow_private {
            tracing::warn!(
                "--webhook-allow-http-private: plain-http webhooks to non-public destinations \
                 are accepted (development only)"
            );
        } else {
            tracing::warn!(
                "--webhook-allow-http-private has no effect without --webhook-allow-private"
            );
        }
    }

    let shutdown = async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut term = match term {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("cannot listen for SIGTERM: {e}");
                    let _ = ctrl_c.await;
                    return;
                }
            };
            tokio::select! {
                _ = ctrl_c => {}
                _ = term.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
        }
        tracing::info!("shutdown requested");
    };

    api::serve(listener, state.clone(), shutdown).await?;
    state.shutdown().await;
    tracing::info!("sealbox-relay stopped");
    Ok(())
}

/// A configuration the relay will not run with: logged, printed, exit status 2. Nothing has
/// been bound or spawned yet, so exiting here skips no cleanup.
fn refuse(reason: &str) -> ! {
    tracing::error!("{reason}");
    eprintln!("sealbox-relay: {reason}");
    std::process::exit(EXIT_REFUSED)
}

/// Exit status of a refused configuration (an open relay off loopback, a bad allow-list).
const EXIT_REFUSED: i32 = 2;

/// `--parked-ttl`: a whole number with an optional unit, `s` (the default), `m`, `h` or `d`.
fn parse_ttl(text: &str) -> Result<Duration, String> {
    let invalid = || {
        format!("{text:?}: expected a whole number with an optional unit s, m, h or d (e.g. 24h)")
    };
    let (digits, unit) = match text.find(|c: char| !c.is_ascii_digit()) {
        Some(at) => text.split_at(at),
        None => (text, "s"),
    };
    let factor: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return Err(invalid()),
    };
    let n: u64 = digits.parse().map_err(|_| invalid())?;
    n.checked_mul(factor)
        .map(Duration::from_secs)
        .ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("sealbox-relay").chain(args.iter().copied()))
            .expect("parse")
    }

    #[test]
    fn policy_flags_parse_with_safe_defaults() {
        let cli = parse(&[]);
        assert_eq!(cli.bind, "127.0.0.1:8090");
        assert!(!cli.allow_open_relay);
        assert!(!cli.webhook_allow_private);
        assert!(!cli.webhook_allow_http_private);
        assert!(cli.webhook_allow_hosts.is_empty());
        assert!(!cli.imap_allow_private);
        assert!(cli.imap_allow_hosts.is_empty());
        assert_eq!(cli.register_rate_limit, 30);
        assert_eq!(cli.parked_ttl, Duration::from_secs(24 * 60 * 60));
        assert_eq!(cli.parked_ttl, sealbox_relay::DEFAULT_PARKED_TTL);

        let cli = parse(&[
            "--bind",
            "0.0.0.0:8090",
            "--allow-open-relay",
            "--webhook-allow-private",
            "--webhook-allow-http-private",
            "--webhook-allow-hosts",
            "push.example.com,203.0.113.7",
            "--register-rate-limit",
            "5",
            "--imap-allow-private",
            "--imap-allow-hosts",
            "imap.gmail.com,.office365.com",
            "--parked-ttl",
            "90m",
        ]);
        assert_eq!(cli.parked_ttl, Duration::from_secs(90 * 60));
        assert!(cli.imap_allow_private);
        let imap = ImapAllowHosts::parse(&cli.imap_allow_hosts)
            .expect("valid")
            .expect("non-empty");
        assert_eq!(imap.entries(), ["imap.gmail.com", ".office365.com"]);
        assert!(cli.allow_open_relay);
        assert!(cli.webhook_allow_private);
        assert!(cli.webhook_allow_http_private);
        assert_eq!(cli.webhook_allow_hosts, ["push.example.com", "203.0.113.7"]);
        assert_eq!(cli.register_rate_limit, 5);
        let allow = AllowHosts::parse(&cli.webhook_allow_hosts)
            .expect("valid")
            .expect("non-empty");
        assert_eq!(allow.entries(), ["push.example.com", "203.0.113.7"]);

        // Boolean flags take no value on the command line.
        assert!(Cli::try_parse_from(["sealbox-relay", "--allow-open-relay=maybe"]).is_err());
        assert!(Cli::try_parse_from(["sealbox-relay", "--parked-ttl", "1 day"]).is_err());
    }

    #[test]
    fn parked_ttl_takes_whole_numbers_with_a_unit() {
        for (text, secs) in [
            ("0", 0),
            ("45", 45),
            ("45s", 45),
            ("30m", 1800),
            ("24h", 86_400),
            ("7d", 604_800),
        ] {
            assert_eq!(parse_ttl(text), Ok(Duration::from_secs(secs)), "{text}");
        }
        for bad in [
            "",
            "h",
            "-1",
            "1.5h",
            "24 h",
            "24H",
            "10w",
            "1h30m",
            "99999999999999999999d",
        ] {
            assert!(parse_ttl(bad).is_err(), "{bad:?}");
        }
    }
}
