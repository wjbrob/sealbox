//! `sealbox account create-hosted` and `sealbox account hosted-info`: the "Create a new
//! Sealbox address" flow against a Sealbox server (see `docs/HOSTED_MAILBOX.md`).

use std::io::Write;
use std::path::Path;

use clap::Args;
use sealbox_core::hosted::{HostedCreateRequest, HostedCreated};
use sealbox_core::Engine;

/// Create a brand-new hosted address on a Sealbox server and add it to this profile.
#[derive(Args, Debug)]
pub struct CreateHostedArgs {
    /// Sealbox server base URL (e.g. https://sealbox.example)
    #[arg(long, env = "SEALBOX_SERVER_URL")]
    pub server: String,
    /// Requested name before the `@` (3–32 chars: a-z 0-9 . _ -)
    #[arg(long)]
    pub name: String,
    /// Invite code (when the server requires one)
    #[arg(long)]
    pub invite: Option<String>,
    /// Display name for the new account
    #[arg(long)]
    pub display_name: Option<String>,
    /// An address you already own, kept (hashed) for account recovery
    #[arg(long)]
    pub recovery_email: Option<String>,
    /// Also print the generated mailbox password (it is stored in the profile either way)
    #[arg(long)]
    pub show_password: bool,
}

/// Show what a Sealbox server offers for hosted addresses, optionally checking one name.
#[derive(Args, Debug)]
pub struct HostedInfoArgs {
    /// Sealbox server base URL
    #[arg(long, env = "SEALBOX_SERVER_URL")]
    pub server: String,
    /// Check whether this name is available
    #[arg(long)]
    pub check: Option<String>,
}

fn print_json<T: serde::Serialize>(v: &T) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, v)?;
    out.write_all(b"\n")?;
    Ok(())
}

/// What `--json` prints for `create-hosted`: the account, and the password only on request.
#[derive(serde::Serialize)]
struct CreatedOutput<'a> {
    #[serde(flatten)]
    account: &'a sealbox_core::AccountInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
}

pub async fn create(profile: &Path, json: bool, a: CreateHostedArgs) -> anyhow::Result<()> {
    let engine = Engine::open(profile)?;
    let HostedCreated { account, password } = engine
        .create_hosted_account(HostedCreateRequest {
            server_url: a.server,
            local_part: a.name,
            invite_code: a.invite,
            recovery_email: a.recovery_email,
            display_name: a.display_name,
        })
        .await?;
    if json {
        return print_json(&CreatedOutput {
            account: &account,
            password: a.show_password.then_some(password.as_str()),
        });
    }
    println!(
        "created {} (imap {}:{}, smtp {}:{})",
        account.email, account.imap.host, account.imap.port, account.smtp.host, account.smtp.port
    );
    println!(
        "key fingerprint: {}",
        account.fingerprint.as_deref().unwrap_or("-")
    );
    if a.show_password {
        println!("password: {password}");
    } else {
        println!("(the mailbox password is stored in this profile; --show-password prints it)");
    }
    Ok(())
}

pub async fn info(profile: &Path, json: bool, a: HostedInfoArgs) -> anyhow::Result<()> {
    let engine = Engine::open(profile)?;
    let info = engine.hosted_info(&a.server).await?;
    let availability = match &a.check {
        Some(name) => Some(engine.hosted_availability(&a.server, name).await?),
        None => None,
    };
    if json {
        return print_json(&serde_json::json!({
            "info": info,
            "availability": availability,
        }));
    }
    println!("domain:   {}", info.domain);
    println!(
        "signups:  {:?}{}",
        info.signups,
        if info.invite_required {
            " (invite code required)"
        } else {
            ""
        }
    );
    println!(
        "names:    {}–{} chars, {}",
        info.requirements.min_length, info.requirements.max_length, info.requirements.pattern
    );
    println!(
        "imap:     {}:{} {}",
        info.imap.host, info.imap.port, info.imap.security
    );
    println!(
        "smtp:     {}:{} {}",
        info.smtp.host, info.smtp.port, info.smtp.security
    );
    if let Some(av) = availability {
        println!(
            "{}: {}",
            av.email,
            if av.available {
                "available".to_string()
            } else {
                format!(
                    "not available ({})",
                    av.message.or(av.reason).unwrap_or_default()
                )
            }
        );
    }
    Ok(())
}
