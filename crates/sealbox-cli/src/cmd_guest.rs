//! `sealbox guest …` and the guest-link options of `sealbox send` (gate G29).
//! Threat model per mode: `docs/GUEST_LINKS.md`.

use std::path::Path;

use clap::{Subcommand, ValueEnum};
use sealbox_core::{Engine, EngineConfig, GuestLinkInfo, GuestMode, SendReport};

#[derive(Subcommand, Debug)]
pub enum GuestCmd {
    /// Mail a fresh notification for a guest link sent earlier (same message, same id).
    /// ID is the Message-ID printed by `send`, the guest id, or the link.
    Resend { id: String },
}

/// `--guest-mode` values.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum GuestModeArg {
    /// No secret in the mail; share the passphrase by another channel (default).
    #[default]
    Passphrase,
    /// Secret in the link: anyone with the link can read the message.
    OneClick,
    /// Secret in the link, plus a one-time code the server mails to the recipient.
    EmailCode,
}

impl From<GuestModeArg> for GuestMode {
    fn from(m: GuestModeArg) -> Self {
        match m {
            GuestModeArg::Passphrase => GuestMode::Passphrase,
            GuestModeArg::OneClick => GuestMode::OneClick,
            GuestModeArg::EmailCode => GuestMode::EmailCode,
        }
    }
}

/// Engine for a send: `--guest-expiry` overrides the requested guest lifetime.
pub fn engine_for_send(profile: &Path, guest_expiry: Option<i64>) -> anyhow::Result<Engine> {
    let mut cfg = EngineConfig::from_env();
    if guest_expiry.is_some() {
        cfg.guest_expiry_secs = guest_expiry;
    }
    Ok(Engine::open_with(profile, cfg)?)
}

/// Human-readable guest-link lines for `send` / `guest resend`.
pub fn print_guest(g: &GuestLinkInfo) {
    println!("  link:       {}", g.url);
    match g.mode {
        GuestMode::Passphrase => {
            println!("  mode:       passphrase (the e-mail does not contain the passphrase)");
            println!(
                "  passphrase: {}  (share this another way: in person, by phone or in a chat; never by e-mail)",
                g.passphrase
            );
        }
        GuestMode::OneClick => {
            println!("  mode:       one-click (the key is in the link)");
            println!(
                "  warning:    anyone who has this link or can read the recipient's mailbox can read the message"
            );
        }
        GuestMode::EmailCode => {
            println!(
                "  mode:       email-code (the key is in the link; the server also asks for a code mailed to the recipient)"
            );
            println!(
                "  note:       protects against a leaked or forwarded link, not against anyone who can read the recipient's mailbox"
            );
        }
    }
}

pub async fn run(profile: &Path, json: bool, cmd: GuestCmd) -> anyhow::Result<()> {
    match cmd {
        GuestCmd::Resend { id } => {
            let engine = Engine::open(profile)?;
            let report: SendReport = engine.resend_guest_link(&id).await?;
            if json {
                return crate::print_json(&report);
            }
            println!("resent <{}> 🔗 guest link", report.message_id);
            if let Some(g) = &report.guest {
                print_guest(g);
            }
            Ok(())
        }
    }
}
