//! `sealbox settings …` — per-account signature (gate G23) and holiday auto-reply (gate G24).
//! Thin shell over `sealbox_core::settings` / `autoreply`; `--json` prints the core structs.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use clap::{Args, Subcommand, ValueEnum};
use sealbox_core::settings::parse_datetime;
use sealbox_core::{
    AutoReplyAction, AutoReplySettings, Engine, SignatureIncludeOn, SignaturePlacement,
    SignatureSettings,
};

#[derive(Subcommand, Debug)]
pub enum SettingsCmd {
    /// Show every setting of an account
    Show {
        #[arg(long)]
        account: String,
    },
    /// Per-account signature (text + sanitised HTML)
    Signature {
        #[command(subcommand)]
        cmd: SignatureCmd,
    },
    /// Holiday / out-of-office auto-reply (RFC 3834)
    Autoreply {
        #[command(subcommand)]
        cmd: AutoreplyCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum SignatureCmd {
    /// Show the signature settings
    Show {
        #[arg(long)]
        account: String,
    },
    /// Change the signature; giving text or HTML enables it unless --disable is passed
    Set(SignatureSetArgs),
    /// Disable and clear the signature
    Clear {
        #[arg(long)]
        account: String,
    },
}

#[derive(Args, Debug)]
pub struct SignatureSetArgs {
    #[arg(long)]
    account: String,
    /// Plain-text signature (the `-- ` separator is added automatically)
    #[arg(long, conflicts_with = "text_file")]
    text: Option<String>,
    /// Read the plain-text signature from a file ("-" for stdin)
    #[arg(long)]
    text_file: Option<PathBuf>,
    /// HTML signature from a file; sanitised (no scripts, styles, events, remote images)
    #[arg(long, conflicts_with = "no_html")]
    html_file: Option<PathBuf>,
    /// Remove the HTML variant
    #[arg(long)]
    no_html: bool,
    /// Where the signature goes in replies/forwards
    #[arg(long, value_enum)]
    placement: Option<PlacementArg>,
    /// Which messages get the signature
    #[arg(long = "include-on", value_enum)]
    include_on: Option<IncludeOnArg>,
    #[arg(long, conflicts_with = "disable")]
    enable: bool,
    #[arg(long)]
    disable: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PlacementArg {
    AboveQuote,
    BelowQuote,
}

impl From<PlacementArg> for SignaturePlacement {
    fn from(p: PlacementArg) -> Self {
        match p {
            PlacementArg::AboveQuote => SignaturePlacement::AboveQuote,
            PlacementArg::BelowQuote => SignaturePlacement::BelowQuote,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum IncludeOnArg {
    NewOnly,
    NewAndReplies,
    All,
}

impl From<IncludeOnArg> for SignatureIncludeOn {
    fn from(p: IncludeOnArg) -> Self {
        match p {
            IncludeOnArg::NewOnly => SignatureIncludeOn::NewOnly,
            IncludeOnArg::NewAndReplies => SignatureIncludeOn::NewAndReplies,
            IncludeOnArg::All => SignatureIncludeOn::All,
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum AutoreplyCmd {
    /// Show the auto-reply settings (and whether it is active right now)
    Show {
        #[arg(long)]
        account: String,
    },
    /// Change the auto-reply; `enabled` only changes with --enable / --disable
    Set(AutoreplySetArgs),
    /// Sent auto-replies, newest first
    Log {
        #[arg(long)]
        account: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Evaluate stored INBOX mail not yet considered and send the replies that are due
    Run {
        #[arg(long)]
        account: String,
    },
}

#[derive(Args, Debug)]
pub struct AutoreplySetArgs {
    #[arg(long)]
    account: String,
    /// Switch the responder on (starts a new vacation period)
    #[arg(long, conflicts_with = "disable")]
    enable: bool,
    #[arg(long)]
    disable: bool,
    /// Start of the absence: 2026-12-20, "2026-12-20 18:00" (UTC) or RFC 3339
    #[arg(long = "from", conflicts_with = "no_from")]
    from: Option<String>,
    /// End of the absence (exclusive), same formats
    #[arg(long = "to", conflicts_with = "no_to")]
    to: Option<String>,
    /// No start: active as soon as enabled
    #[arg(long)]
    no_from: bool,
    /// No end: active until disabled
    #[arg(long)]
    no_to: bool,
    /// Subject template; `{subject}` is the original subject
    #[arg(long)]
    subject: Option<String>,
    #[arg(long, conflicts_with = "body_file")]
    body: Option<String>,
    /// Read the body from a file ("-" for stdin)
    #[arg(long)]
    body_file: Option<PathBuf>,
    /// At most one reply per sender per this many days (0 = once per vacation period)
    #[arg(long = "once-per-days")]
    once_per_days: Option<u32>,
    /// Always send the reply in plaintext
    #[arg(long, conflicts_with = "encrypt")]
    no_encrypt: bool,
    /// Encrypt + sign when the sender has a usable key (default)
    #[arg(long)]
    encrypt: bool,
    /// Only reply to people this account has written to, or whose key was imported
    #[arg(long, conflicts_with = "any_sender")]
    only_known_contacts: bool,
    /// Reply to anyone (default)
    #[arg(long)]
    any_sender: bool,
}

fn read_text(path: &Path, what: &str) -> anyhow::Result<String> {
    let bytes = if path == Path::new("-") {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)?;
        buf
    } else {
        std::fs::read(path).with_context(|| format!("reading {}", path.display()))?
    };
    String::from_utf8(bytes).with_context(|| format!("{what} is not UTF-8"))
}

fn print_json<T: serde::Serialize>(v: &T) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, v)?;
    std::io::Write::write_all(&mut out, b"\n")?;
    Ok(())
}

fn placement_name(p: SignaturePlacement) -> &'static str {
    match p {
        SignaturePlacement::AboveQuote => "above-quote",
        SignaturePlacement::BelowQuote => "below-quote",
    }
}

fn include_on_name(i: SignatureIncludeOn) -> &'static str {
    match i {
        SignatureIncludeOn::NewOnly => "new-only",
        SignatureIncludeOn::NewAndReplies => "new-and-replies",
        SignatureIncludeOn::All => "all",
    }
}

fn print_signature(account: &str, s: &SignatureSettings) {
    println!(
        "signature of {account}: {}",
        if s.enabled { "enabled" } else { "disabled" }
    );
    println!("  placement:  {}", placement_name(s.placement));
    println!("  include on: {}", include_on_name(s.include_on));
    println!(
        "  html:       {}",
        match &s.html {
            Some(h) => format!("{} bytes (sanitised)", h.len()),
            None => "none".to_string(),
        }
    );
    if s.text.is_empty() {
        println!("  text:       (empty)");
    } else {
        println!("  text:");
        for line in s.text.lines() {
            println!("    | {line}");
        }
    }
}

fn print_autoreply(account: &str, s: &AutoReplySettings) {
    println!(
        "auto-reply of {account}: {}{}",
        if s.enabled { "enabled" } else { "disabled" },
        if s.is_active_now() {
            " (active now)"
        } else if s.enabled {
            " (outside the window)"
        } else {
            ""
        }
    );
    println!(
        "  from:            {}",
        s.start
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| "(when enabled)".into())
    );
    println!(
        "  to:              {}",
        s.end
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| "(until disabled)".into())
    );
    println!("  subject:         {}", s.subject_template);
    println!(
        "  once per sender: {}",
        if s.reply_once_per_sender_days == 0 {
            "once per vacation period".to_string()
        } else {
            format!("every {} day(s)", s.reply_once_per_sender_days)
        }
    );
    println!(
        "  encryption:      {}",
        if s.encrypt_when_possible {
            "when the sender has a key"
        } else {
            "never (plaintext)"
        }
    );
    println!(
        "  recipients:      {}",
        if s.only_to_known_contacts {
            "known contacts only"
        } else {
            "anyone (lists, bounces and auto-mail excluded)"
        }
    );
    if s.body.is_empty() {
        println!("  body:            (empty)");
    } else {
        println!("  body:");
        for line in s.body.lines() {
            println!("    | {line}");
        }
    }
}

pub async fn run(profile: &Path, json: bool, cmd: SettingsCmd) -> anyhow::Result<()> {
    let engine = Engine::open(profile)?;
    match cmd {
        SettingsCmd::Show { account } => {
            let s = engine.get_settings(&account)?;
            if json {
                return print_json(&s);
            }
            print_signature(&account, &s.signature);
            println!();
            print_autoreply(&account, &s.autoreply);
            Ok(())
        }
        SettingsCmd::Signature { cmd } => match cmd {
            SignatureCmd::Show { account } => {
                let s = engine.get_signature(&account)?;
                if json {
                    return print_json(&s);
                }
                print_signature(&account, &s);
                Ok(())
            }
            SignatureCmd::Clear { account } => {
                let s = engine.set_signature(&account, SignatureSettings::default())?;
                if json {
                    return print_json(&s);
                }
                println!("signature of {account} cleared");
                Ok(())
            }
            SignatureCmd::Set(a) => {
                let mut s = engine.get_signature(&a.account)?;
                let mut content_given = false;
                if let Some(t) = a.text {
                    s.text = t;
                    content_given = true;
                } else if let Some(p) = &a.text_file {
                    s.text = read_text(p, "signature text")?;
                    content_given = true;
                }
                if let Some(p) = &a.html_file {
                    s.html = Some(read_text(p, "signature HTML")?);
                    content_given = true;
                }
                if a.no_html {
                    s.html = None;
                }
                if let Some(p) = a.placement {
                    s.placement = p.into();
                }
                if let Some(i) = a.include_on {
                    s.include_on = i.into();
                }
                if a.enable || (content_given && !a.disable) {
                    s.enabled = true;
                }
                if a.disable {
                    s.enabled = false;
                }
                let stored = engine.set_signature(&a.account, s)?;
                if json {
                    return print_json(&stored);
                }
                print_signature(&a.account, &stored);
                Ok(())
            }
        },
        SettingsCmd::Autoreply { cmd } => match cmd {
            AutoreplyCmd::Show { account } => {
                let s = engine.get_autoreply(&account)?;
                if json {
                    return print_json(&s);
                }
                print_autoreply(&account, &s);
                Ok(())
            }
            AutoreplyCmd::Set(a) => {
                let mut s = engine.get_autoreply(&a.account)?;
                if let Some(f) = &a.from {
                    s.start = Some(parse_datetime(f).map_err(|e| anyhow::anyhow!("--from: {e}"))?);
                }
                if a.no_from {
                    s.start = None;
                }
                if let Some(t) = &a.to {
                    s.end = Some(parse_datetime(t).map_err(|e| anyhow::anyhow!("--to: {e}"))?);
                }
                if a.no_to {
                    s.end = None;
                }
                if let Some(subj) = a.subject {
                    s.subject_template = subj;
                }
                if let Some(b) = a.body {
                    s.body = b;
                } else if let Some(p) = &a.body_file {
                    s.body = read_text(p, "auto-reply body")?;
                }
                if let Some(n) = a.once_per_days {
                    s.reply_once_per_sender_days = n;
                }
                if a.no_encrypt {
                    s.encrypt_when_possible = false;
                }
                if a.encrypt {
                    s.encrypt_when_possible = true;
                }
                if a.only_known_contacts {
                    s.only_to_known_contacts = true;
                }
                if a.any_sender {
                    s.only_to_known_contacts = false;
                }
                if a.enable {
                    s.enabled = true;
                }
                if a.disable {
                    s.enabled = false;
                }
                let stored = engine.set_autoreply(&a.account, s)?;
                if json {
                    return print_json(&stored);
                }
                print_autoreply(&a.account, &stored);
                Ok(())
            }
            AutoreplyCmd::Log { account, limit } => {
                let log = engine.autoreply_log(&account, limit)?;
                if json {
                    return print_json(&log);
                }
                if log.is_empty() {
                    println!("(no auto-replies sent from {account})");
                }
                for e in &log {
                    println!(
                        "{}  {:<32} {} <{}>  in-reply-to {}",
                        e.sent_at,
                        e.sender,
                        if e.encrypted { "🔒" } else { "plain" },
                        e.message_id,
                        e.in_reply_to.as_deref().unwrap_or("-")
                    );
                }
                Ok(())
            }
            AutoreplyCmd::Run { account } => {
                let r = engine.run_autoreplies(&account).await?;
                if json {
                    return print_json(&r);
                }
                println!(
                    "{}: {} evaluated, {} replied, {} skipped, {} failed{}",
                    r.account,
                    r.evaluated,
                    r.replied,
                    r.skipped,
                    r.failed,
                    if r.active {
                        ""
                    } else {
                        " (responder not active)"
                    }
                );
                for o in &r.outcomes {
                    let sender = o.sender.as_deref().unwrap_or("-");
                    match &o.action {
                        AutoReplyAction::Replied {
                            message_id,
                            encrypted,
                            to,
                        } => println!(
                            "  #{} {sender}: replied to {to} <{message_id}>{}",
                            o.message,
                            if *encrypted { " 🔒" } else { "" }
                        ),
                        AutoReplyAction::Skipped { reason } => {
                            println!("  #{} {sender}: skipped ({reason:?})", o.message)
                        }
                        AutoReplyAction::Failed { error } => {
                            println!("  #{} {sender}: FAILED: {error}", o.message)
                        }
                    }
                }
                if r.failed > 0 {
                    bail!("{} auto-reply(ies) failed", r.failed);
                }
                Ok(())
            }
        },
    }
}
