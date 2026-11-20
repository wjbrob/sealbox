//! `sealbox contacts …`, `sealbox key qr` and `sealbox kt …` (gate G30, `docs/IDENTITY.md`):
//! key-change alerts, verified contacts, fingerprint QR codes, key-transparency audits.

use std::io::Write;
use std::path::Path;

use clap::{Args, Subcommand};
use sealbox_core::{Contact, Engine, KtAuditOptions, KtAuditReport, Recommendation};

/// Exit code of `kt audit` when any check failed (the report is still printed).
pub const EXIT_KT_AUDIT_FAILED: i32 = 6;

#[derive(Subcommand, Debug)]
pub enum ContactsCmd {
    /// List contacts (default): ⚠ = key changed (unacknowledged), ✓ = verified
    List,
    /// Accept a contact's new key without verifying it (clears ⚠)
    Ack { address: String },
    /// Mark a contact verified after comparing fingerprints out of band; refused unless the
    /// fingerprint (hex or an OPENPGP4FPR: payload) matches the contact's current key
    Verify {
        address: String,
        #[arg(long)]
        fingerprint: String,
    },
    /// Remove the verified mark
    Unverify { address: String },
}

#[derive(Subcommand, Debug)]
pub enum KtCmd {
    /// Audit the key-transparency log for an account: tree-head signature (TOFU-pinned log
    /// key), consistency with the last head seen, inclusion of the account's key. Exit 6 if
    /// any check fails.
    Audit(KtAuditArgs),
    /// Raw log entries
    Entries {
        /// Server base URL (default: $SEALBOX_DIRECTORY_URL)
        #[arg(long)]
        server: Option<String>,
        #[arg(long, default_value_t = 0)]
        start: u64,
        #[arg(long, default_value_t = 100)]
        limit: u64,
    },
}

#[derive(Args, Debug)]
pub struct KtAuditArgs {
    #[arg(long)]
    pub account: String,
    /// Server base URL (default: $SEALBOX_DIRECTORY_URL, then $SEALBOX_SERVER_URL)
    #[arg(long)]
    pub server: Option<String>,
    /// Ed25519 log key (hex or base64) to trust instead of the pinned one; becomes the pin
    #[arg(long)]
    pub kt_key: Option<String>,
}

fn print_json<T: serde::Serialize>(v: &T) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, v)?;
    out.write_all(b"\n")?;
    Ok(())
}

/// Status column of a contact: `⚠` (key changed), `✓` (verified) or blank.
pub fn contact_marks(c: &Contact) -> &'static str {
    match (c.key_changed_at.is_some(), c.verified) {
        (true, _) => "⚠",
        (false, true) => "✓",
        _ => " ",
    }
}

fn print_contact_line(c: &Contact) {
    let rec = match c.recommendation {
        Recommendation::Encrypt => "encrypt",
        Recommendation::Available => "available",
        Recommendation::Discourage => "discourage",
        Recommendation::Disable => "disable",
    };
    println!(
        "{} {:<32} {:<10} {:<10} {:?} {}",
        contact_marks(c),
        c.address,
        rec,
        format!("{:?}", c.source).to_lowercase(),
        c.prefer_encrypt,
        c.fingerprint.as_deref().unwrap_or("-")
    );
    if let Some(at) = c.key_changed_at {
        println!(
            "  ⚠ key changed {} (was {}); compare fingerprints, then `sealbox contacts verify {} --fingerprint …` or `sealbox contacts ack {}`",
            at.format("%Y-%m-%d %H:%M UTC"),
            c.previous_fingerprint.as_deref().unwrap_or("unknown"),
            c.address,
            c.address
        );
    }
}

pub fn contacts(profile: &Path, json: bool, cmd: Option<ContactsCmd>) -> anyhow::Result<()> {
    let engine = Engine::open(profile)?;
    let changed = match cmd.unwrap_or(ContactsCmd::List) {
        ContactsCmd::List => {
            let contacts = engine.contacts()?;
            if json {
                return print_json(&contacts);
            }
            if contacts.is_empty() {
                println!("(no contacts yet — sync an account first)");
            }
            for c in &contacts {
                print_contact_line(c);
            }
            return Ok(());
        }
        ContactsCmd::Ack { address } => engine.acknowledge_key_change(&address)?,
        ContactsCmd::Verify {
            address,
            fingerprint,
        } => engine.verify_contact(&address, &fingerprint)?,
        ContactsCmd::Unverify { address } => engine.unverify_contact(&address)?,
    };
    if json {
        return print_json(&changed);
    }
    print_contact_line(&changed);
    Ok(())
}

/// `key qr --account A`: the `OPENPGP4FPR:` payload and a terminal QR code of it.
pub fn key_qr(engine: &Engine, json: bool, account: &str) -> anyhow::Result<()> {
    let payload = engine.fingerprint_qr_payload(account)?;
    let fingerprint = Engine::parse_fingerprint_qr(&payload)?;
    let code = qrcode::QrCode::new(payload.as_bytes())?;
    let art = code
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(true)
        .build();
    if json {
        return print_json(&serde_json::json!({
            "account": account,
            "fingerprint": fingerprint,
            "payload": payload,
            "qr": art,
        }));
    }
    println!("{art}");
    println!("{payload}");
    Ok(())
}

fn print_report(r: &KtAuditReport) {
    let yn = |b: bool| if b { "ok" } else { "FAILED" };
    println!("log size:          {}", r.log_size);
    println!("tree head:         {}", yn(r.sth_verified));
    println!("consistency:       {}", yn(r.consistency_ok));
    println!("own key included:  {}", yn(r.own_key_included));
    for a in &r.alerts {
        println!("⚠ {a}");
    }
}

pub async fn kt(profile: &Path, json: bool, cmd: KtCmd) -> anyhow::Result<()> {
    let engine = Engine::open(profile)?;
    match cmd {
        KtCmd::Audit(a) => {
            let report = engine
                .kt_audit_with(
                    &a.account,
                    &KtAuditOptions {
                        server: a.server,
                        kt_key: a.kt_key,
                    },
                )
                .await?;
            if json {
                print_json(&report)?;
            } else {
                print_report(&report);
            }
            if !report.is_clean() {
                let _ = std::io::stdout().flush();
                std::process::exit(EXIT_KT_AUDIT_FAILED);
            }
            Ok(())
        }
        KtCmd::Entries {
            server,
            start,
            limit,
        } => {
            let page = engine.kt_entries(server.as_deref(), start, limit).await?;
            if json {
                return print_json(&page);
            }
            println!("tree size {}", page.tree_size);
            for e in &page.entries {
                println!(
                    "{:>6}  {:<9} {}  {}  {}",
                    e.index, e.entry.action, e.entry.fingerprint, e.entry.email_hash, e.entry.time
                );
            }
            Ok(())
        }
    }
}
