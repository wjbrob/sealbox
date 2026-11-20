//! `sealbox-server` binary: parse config, open the database, serve until SIGINT/SIGTERM.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use clap::Parser;
use sealbox_server::{
    config::Config,
    mail::{MailSender, NullMailSender, SmtpConfig, SmtpMailSender},
    AppState, Limits, StateOptions,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info")),
        )
        .init();

    let cfg = Config::parse();
    let public_url = cfg.effective_public_url();

    let mailer: Arc<dyn MailSender> = match &cfg.smtp_host {
        Some(host) => Arc::new(
            SmtpMailSender::new(&SmtpConfig {
                host: host.clone(),
                port: cfg.smtp_port,
                user: cfg.smtp_user.clone(),
                pass: cfg.smtp_pass.clone(),
                from: cfg.smtp_from.clone(),
                tls: cfg.smtp_tls,
            })
            .context("configuring SMTP")?,
        ),
        None => Arc::new(NullMailSender),
    };
    tracing::info!(mailer = %mailer.describe(), "challenge mail transport");

    if !cfg.static_dir.join("index.html").is_file() {
        tracing::warn!(dir = %cfg.static_dir.display(), "static dir has no index.html; /g/{{id}} will fail");
    }

    let state = AppState::new(StateOptions {
        db_path: cfg.db.clone(),
        public_url: public_url.clone(),
        static_dir: cfg.static_dir.clone(),
        mailer,
        trust_proxy: cfg.trust_proxy,
        limits: Limits {
            guest_code_lock_secs: cfg.guest_code_lock_secs.max(1),
            ..Limits::default()
        },
    })
    .with_context(|| format!("opening database {}", cfg.db.display()))?;
    let kt_key = sealbox_server::kt::init(state.db())
        .await
        .context("key-transparency log")?;
    tracing::info!(public_key = %kt_key, "key-transparency log ready (GET /v1/kt/key)");

    match sealbox_server::hosted::HostedService::from_config(&cfg)
        .context("hosted mailbox config")?
    {
        Some(hosted) => {
            hosted
                .ensure_schema(state.db())
                .await
                .context("creating the hosted_signups table")?;
            tracing::info!(
                domain = %hosted.config.domain,
                signups = ?hosted.config.signups,
                stalwart = %hosted.client().base_url(),
                "hosted mailbox signups enabled"
            );
            state.set_hosted(hosted);
        }
        None => tracing::info!("hosted mailbox signups disabled (SEALBOX_HOSTED_DOMAIN unset)"),
    }

    let purge = state.spawn_purge_task(Duration::from_secs(cfg.purge_interval_secs.max(5)));

    let listener = tokio::net::TcpListener::bind(cfg.bind)
        .await
        .with_context(|| format!("binding {}", cfg.bind))?;
    tracing::info!(bind = %cfg.bind, public_url = %public_url, db = %cfg.db.display(), "sealbox-server listening");

    sealbox_server::serve(listener, state, shutdown_signal())
        .await
        .context("server error")?;
    purge.abort();
    tracing::info!("shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "failed to listen for ctrl-c");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => tracing::error!(error = %e, "failed to listen for SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
