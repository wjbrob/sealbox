//! `sealbox account add --email A --oauth google|microsoft …` — the loopback PKCE flow:
//! bind the loopback port, print the authorization URL (open it only with `--open-browser`),
//! wait for the redirect, exchange the code, verify IMAP + SMTP with XOAUTH2, store the
//! account and its tokens. Client ids come from flags or the environment
//! (`GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET`, `MS_OAUTH_CLIENT_ID`), which the
//! gate scripts fill from `.gate/config.local.env`.
//!
//! The token is pinned to the provider (docs/THREAT_MODEL.md R14): it is only presented to
//! Google's (`gmail.com`, `googlemail.com`, `google.com`) or Microsoft's (`office365.com`,
//! `outlook.com`, `live.com`, `hotmail.com`, `microsoft.com`) mail hosts, and only through
//! XOAUTH2 — an IMAP server without `AUTH=XOAUTH2` is an error, never a password login with
//! the token. Manual `--imap/--smtp` servers are checked against that (and against the
//! plaintext rule) before the browser is involved. Only a token from a loopback mock IdP
//! (`SEALBOX_OAUTH_AUTH_URL` / `SEALBOX_OAUTH_TOKEN_URL`, tests) may also go to local/private
//! hosts such as GreenMail.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::anyhow;
use clap::ValueEnum;
use sealbox_core::sealbox_mail::net_policy;
use sealbox_core::sealbox_mail::oauth::Provider;
use sealbox_core::{Engine, ServerConfig};

use crate::AddArgs;

/// One JSON object per line (an event stream a caller can parse as it arrives).
fn print_json_line<T: serde::Serialize>(v: &T) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, v)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// `--oauth` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OAuthArg {
    Google,
    Microsoft,
}

impl From<OAuthArg> for Provider {
    fn from(a: OAuthArg) -> Self {
        match a {
            OAuthArg::Google => Provider::Google,
            OAuthArg::Microsoft => Provider::Microsoft,
        }
    }
}

/// Environment variable consulted for the client id when no flag is given.
pub fn default_client_id_env(p: Provider) -> &'static str {
    match p {
        Provider::Google => "GOOGLE_OAUTH_CLIENT_ID",
        Provider::Microsoft => "MS_OAUTH_CLIENT_ID",
    }
}

/// Environment variable consulted for the (optional) client secret.
pub fn default_client_secret_env(p: Provider) -> &'static str {
    match p {
        Provider::Google => "GOOGLE_OAUTH_CLIENT_SECRET",
        Provider::Microsoft => "MS_OAUTH_CLIENT_SECRET",
    }
}

fn non_empty_env(var: &str) -> Option<String> {
    std::env::var(var).ok().filter(|v| !v.trim().is_empty())
}

/// The hint for the gotcha that cost a day on a real account, or `None` when this failure is
/// not that shape.
///
/// Outlook/Exchange refuses `AUTHENTICATE XOAUTH2` when the `user=` is an **alias** of a
/// mailbox rather than its primary address. Everything before it has already succeeded — the
/// browser consent, the token exchange — so the CLI's last word is "authentication failed",
/// which reads as if the sign-in were the problem. It was not, and re-consenting will fail the
/// same way for as long as the login stays an alias.
///
/// The server never says which address it wanted (it will not confirm an alias exists, and the
/// same refusal is what a genuinely wrong token gets), so this is a **hint, not a diagnosis**:
/// it names the possibility and the flag that tests it, and says nothing it cannot support.
fn alias_hint(e: &sealbox_core::Error, email: &str, user: Option<&str>) -> Option<String> {
    let sealbox_core::Error::Imap(imap) = e else {
        return None;
    };
    if !imap.refused_xoauth2_identity() {
        return None;
    }
    let tried = match user.map(str::trim).filter(|u| !u.is_empty()) {
        Some(u) => format!("the login you gave (`--user {u}`)"),
        None => format!("a login derived from {email}"),
    };
    Some(format!(
        "hint: the sign-in itself worked — consent was given and a token was issued — and the \
         IMAP server then refused that token for {tried}.\n\
         hint: Outlook and Exchange reject OAuth under an *alias* of a mailbox, with exactly \
         this refusal and no indication that is the reason. If {email} is an alias, retry with \
         the mailbox's primary address:\n    \
         sealbox account add --email {email} --user <primary address> …\n\
         hint: the primary address is the one Outlook shows under Account info / \"Email aliases\" \
         — the account keeps receiving at {email} either way."
    ))
}

pub async fn account_add_oauth(
    profile: &Path,
    json: bool,
    a: &AddArgs,
    which: OAuthArg,
    manual: Option<ServerConfig>,
) -> anyhow::Result<()> {
    let provider: Provider = which.into();
    let client_id = match (&a.client_id, &a.client_id_env) {
        (Some(id), _) => id.clone(),
        (None, Some(var)) => {
            non_empty_env(var).ok_or_else(|| anyhow!("environment variable {var} is not set"))?
        }
        (None, None) => {
            let var = default_client_id_env(provider);
            non_empty_env(var).ok_or_else(|| {
                anyhow!(
                    "no OAuth client id for {provider}: pass --client-id ID, --client-id-env VAR, \
                     or export {var} (how to create one: docs/PROVIDERS_CONFORMANCE.md)"
                )
            })?
        }
    };
    let client_secret = match &a.client_secret_env {
        Some(var) => Some(
            non_empty_env(var).ok_or_else(|| anyhow!("environment variable {var} is not set"))?,
        ),
        None => non_empty_env(default_client_secret_env(provider)),
    };

    let engine = Engine::open(profile)?;
    let mut start = engine
        .begin_oauth(provider, &a.email, &client_id, client_secret.as_deref())
        .await?;
    start.servers = manual;
    start.display_name = a.name.clone();
    start.login = a.user.clone();
    // Refuse servers this token could never be sent to before anybody consents in a browser.
    start.preflight()?;

    // Announce the URL before blocking on the redirect (tests and humans read this).
    if json {
        print_json_line(&serde_json::json!({
            "event": "oauth_start",
            "provider": provider.as_str(),
            "email": start.email,
            "url": start.url,
            "loopback_port": start.loopback_port,
            "redirect_uri": start.redirect_uri,
            "endpoints_overridden": start.endpoints.is_override(provider),
        }))?;
    } else {
        println!(
            "Sign in to {provider} for {} by opening this URL:",
            start.email
        );
        println!();
        println!("  {}", start.url);
        println!();
        println!(
            "Waiting up to {} s for the browser to come back to {} …",
            a.oauth_timeout, start.redirect_uri
        );
    }
    let _ = std::io::stdout().flush();
    if a.open_browser {
        match std::process::Command::new("xdg-open")
            .arg(&start.url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(_) => eprintln!("(opened with xdg-open)"),
            Err(e) => eprintln!("warning: xdg-open failed ({e}); open the URL by hand"),
        }
    }

    let code = engine
        .wait_oauth_code(&mut start, Duration::from_secs(a.oauth_timeout.max(1)))
        .await?;
    let info = match engine.finish_oauth(start, &code).await {
        Ok(info) => info,
        Err(e) => {
            // The sign-in worked and the server still said "authentication failed": say so,
            // before the owner spends a day re-doing the part that was never broken.
            if let Some(hint) = alias_hint(&e, &a.email, a.user.as_deref()) {
                eprintln!("{hint}");
            }
            return Err(e.into());
        }
    };
    // `--provider` applies here too. It used to be handled only on the password path, so
    // `account add --oauth microsoft --provider outlook` — a company domain hosted on M365,
    // which is the main reason the flag exists — silently kept the profile guessed from the
    // host instead of the one the owner stated.
    if let Some(p) = a.provider.as_deref() {
        engine.set_account_provider(&info.email, Some(crate::parse_provider(p)?))?;
    }
    let status = engine.oauth_status(&info.email)?;
    if json {
        return print_json_line(&serde_json::json!({
            "event": "account_added",
            "account": info,
            "oauth": status,
        }));
    }
    println!(
        "added {} via OAuth ({provider}; login {}, imap {}:{}, smtp {}:{})",
        info.email, info.login, info.imap.host, info.imap.port, info.smtp.host, info.smtp.port
    );
    if let Some(s) = &status {
        println!(
            "the token is only ever sent with XOAUTH2 to {} mail servers ({}){}",
            provider.display_name(),
            net_policy::mail_domains(provider).join(", "),
            if s.dev_hosts_allowed {
                " and, because it comes from a loopback test IdP, to local/private hosts"
            } else {
                ""
            }
        );
    }
    if let Some(s) = status {
        println!(
            "token: expires in {} s, refresh token {}",
            s.expires_in_secs.unwrap_or(-1),
            if s.has_refresh_token {
                "stored (the engine refreshes before every connection)"
            } else {
                "MISSING — re-consent will be needed when it expires"
            }
        );
    }
    println!(
        "key fingerprint: {}",
        info.fingerprint.as_deref().unwrap_or("-")
    );
    Ok(())
}
