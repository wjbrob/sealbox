//! `sealbox draft save|list|show|attach|detach|delete|send|sync` — saved drafts (engine:
//! `drafts.rs`, `drafts_imap.rs`). Subject and body are sealed at rest; every save also puts
//! the draft on the server — the account's Drafts folder, encrypted to the account's own key
//! (`draft sync` brings in what other devices saved and removes what was sent or deleted).
//! `draft attach` keeps a sealed copy of a file (it travels with the server copy);
//! `draft save --attach` keeps a file reference, read when the draft is sent (local only).
//! `--json` prints `SavedDraft` (list: an array) and, for `send`, the same `SendReport` as
//! `sealbox send`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Args, Subcommand};
use sealbox_core::{
    ComposeKind, DraftAttachment, DraftInput, Engine, SavedDraft, SendMode, SendReport,
};

use crate::cmd_guest::{self, GuestModeArg};
use crate::PolicyArg;

#[derive(Subcommand, Debug)]
pub enum DraftCmd {
    /// Save a new draft, or update one with --id N (options not given keep their value)
    Save(Box<DraftSaveArgs>),
    /// List saved drafts, most recently updated first
    List {
        #[arg(long)]
        account: Option<String>,
    },
    /// Show one draft
    Show { id: i64 },
    /// Attach a file as a sealed copy kept in this profile (encrypted at rest like a received
    /// attachment, deleted with the draft); the original may move or go away afterwards
    Attach {
        id: i64,
        file: PathBuf,
        /// File name the recipient sees (default: the file's own name)
        #[arg(long)]
        name: Option<String>,
        /// MIME type (default: guessed from the file name)
        #[arg(long)]
        content_type: Option<String>,
    },
    /// Remove attachment N (the number in brackets in `draft show`) from a draft; a stored
    /// copy is deleted with it
    Detach { id: i64, n: usize },
    /// Delete a draft
    #[command(visible_alias = "rm")]
    Delete { id: i64 },
    /// Sync the drafts with the account's Drafts folder on the server (encrypted to the
    /// account's own key): import other devices' drafts, upload local changes, remove what was
    /// sent or deleted elsewhere
    Sync {
        /// Only this account (default: every account)
        #[arg(long)]
        account: Option<String>,
    },
    /// Send a draft (its policy, signature, quoting and attachments as saved) and delete it
    /// once the message is out; on any failure the draft is kept
    Send {
        id: i64,
        /// Requested guest-link lifetime in seconds (the server clamps)
        #[arg(long)]
        guest_expiry: Option<i64>,
    },
}

#[derive(Args, Debug)]
pub struct DraftSaveArgs {
    /// Update this draft instead of creating a new one
    #[arg(long)]
    id: Option<i64>,
    /// Sending account (required for a new draft)
    #[arg(long)]
    from: Option<String>,
    #[arg(long, value_delimiter = ',')]
    to: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    cc: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    bcc: Vec<String>,
    #[arg(long)]
    subject: Option<String>,
    #[arg(long, conflicts_with = "body_file")]
    body: Option<String>,
    /// Read the body from a file ("-" for stdin)
    #[arg(long)]
    body_file: Option<PathBuf>,
    /// Attach a file by reference (repeatable; replaces the draft's attachments). The file is
    /// read when the draft is sent, not now; `draft attach` keeps a sealed copy instead
    #[arg(long = "attach")]
    attachments: Vec<PathBuf>,
    #[arg(long, value_enum)]
    policy: Option<PolicyArg>,
    /// Local message id (from `list`) or a Message-ID to reply to
    #[arg(long, conflicts_with = "forward")]
    in_reply_to: Option<String>,
    /// Quote the replied-to message below the text when sending
    #[arg(long)]
    quote: bool,
    /// Forward a stored message (local id or Message-ID) when sending
    #[arg(long)]
    forward: Option<String>,
    /// Do not add the account signature when sending
    #[arg(long)]
    no_signature: bool,
    /// How a guest link (`--policy guest`) is protected; see docs/GUEST_LINKS.md
    #[arg(long, value_enum)]
    guest_mode: Option<GuestModeArg>,
    /// email-code mode: the address that receives the code (default: the only recipient)
    #[arg(long)]
    guest_recipient: Option<String>,
}

/// The engine input for `draft save`: the stored draft (with --id) overlaid with what was
/// given on the command line.
fn draft_input(engine: &Engine, a: DraftSaveArgs) -> anyhow::Result<DraftInput> {
    let mut d = match a.id {
        Some(id) => input_of(engine.get_draft(id)?),
        None => DraftInput::default(),
    };
    match a.from {
        Some(f) => d.account = f,
        None if a.id.is_none() => {
            return Err(sealbox_core::Error::InvalidInput(
                "--from is required for a new draft".into(),
            )
            .into())
        }
        None => {}
    }
    for (given, field) in [(a.to, &mut d.to), (a.cc, &mut d.cc), (a.bcc, &mut d.bcc)] {
        if !given.is_empty() {
            *field = given;
        }
    }
    if let Some(s) = a.subject {
        d.subject = s;
    }
    if let Some(b) = a.body {
        d.body_text = b;
    } else if let Some(f) = a.body_file {
        d.body_text =
            String::from_utf8(crate::read_file_or_stdin(&f)?).context("body is not UTF-8")?;
    }
    if !a.attachments.is_empty() {
        d.attachments = a
            .attachments
            .iter()
            .map(|p| DraftAttachment {
                path: p.to_string_lossy().into_owned(),
                blob_id: None,
                name: String::new(),
                content_type: crate::guess_content_type(p),
            })
            .collect();
    }
    if let Some(p) = a.policy {
        d.policy = p.into();
    }
    if let Some(r) = a.in_reply_to {
        d.kind = ComposeKind::Reply;
        d.in_reply_to = Some(r);
        d.forward_of = None;
    }
    if let Some(f) = a.forward {
        d.kind = ComposeKind::Forward;
        d.forward_of = Some(f);
        d.in_reply_to = None;
    }
    d.quote |= a.quote;
    d.no_signature |= a.no_signature;
    if let Some(m) = a.guest_mode {
        d.guest_mode = m.into();
    }
    if let Some(r) = a.guest_recipient {
        d.guest_recipient_hint = Some(r);
    }
    Ok(d)
}

/// The engine input that saves `s` back as it is.
fn input_of(s: SavedDraft) -> DraftInput {
    DraftInput {
        id: Some(s.id),
        account: s.account,
        kind: s.kind,
        in_reply_to: s.in_reply_to,
        forward_of: s.forward_of,
        quote: s.quote,
        to: s.to,
        cc: s.cc,
        bcc: s.bcc,
        subject: s.subject,
        body_text: s.body_text,
        attachments: s.attachments,
        policy: s.policy,
        guest_mode: s.guest_mode,
        guest_recipient_hint: s.guest_recipient_hint,
        no_signature: s.no_signature,
    }
}

fn stored_copies(d: &SavedDraft) -> Vec<i64> {
    d.attachments.iter().filter_map(|a| a.blob_id).collect()
}

/// Delete the stored copies among `blobs` that no saved draft references any more.
fn release_unreferenced(engine: &Engine, blobs: &[i64]) -> anyhow::Result<()> {
    if blobs.is_empty() {
        return Ok(());
    }
    let drafts = engine.list_drafts(None)?;
    for blob in blobs {
        if !drafts.iter().any(|d| stored_copies(d).contains(blob)) {
            engine.delete_draft_blob(*blob)?;
        }
    }
    Ok(())
}

fn kind_name(k: ComposeKind) -> &'static str {
    match k {
        ComposeKind::New => "new",
        ComposeKind::Reply => "reply",
        ComposeKind::Forward => "forward",
    }
}

/// Put draft `id` on the server after a local save; a failure is a warning (the draft is
/// saved; `draft sync` retries).
async fn push(engine: &Engine, id: i64) {
    if let Err(e) = engine.push_draft(id).await {
        eprintln!(
            "warning: draft {id} is saved here, but its server copy was not updated ({e}); \
             `sealbox draft sync` retries"
        );
    }
}

fn print_list(engine: &Engine, drafts: &[SavedDraft]) {
    if drafts.is_empty() {
        println!("(no drafts)");
        return;
    }
    for d in drafts {
        let origin = match engine.draft_server_info(d.id) {
            Ok(Some(i)) if i.origin == "server" => " (server)",
            _ => "",
        };
        println!(
            "{:>5}{origin} {}  {:<24} {:<7} {:<28} {}",
            d.id,
            crate::fmt_date(Some(d.updated_at)),
            crate::truncate(&d.account, 24),
            kind_name(d.kind),
            crate::truncate(&d.to.join(", "), 28),
            if d.subject.is_empty() {
                "(no subject)"
            } else {
                d.subject.as_str()
            }
        );
    }
}

/// `sizes`: bytes of the account's stored copies, by blob id.
fn print_draft(
    d: &SavedDraft,
    sizes: &HashMap<i64, u64>,
    server: Option<&sealbox_core::DraftServerInfo>,
) {
    println!("Draft:    {}  ({})", d.id, kind_name(d.kind));
    println!("From:     {}", d.account);
    for (label, list) in [("To:", &d.to), ("Cc:", &d.cc), ("Bcc:", &d.bcc)] {
        if !list.is_empty() {
            println!("{label:<9} {}", list.join(", "));
        }
    }
    println!("Subject:  {}", d.subject);
    if let Some(r) = &d.in_reply_to {
        println!("Reply to: <{r}>{}", if d.quote { "  (quoted)" } else { "" });
    }
    if let Some(f) = &d.forward_of {
        println!("Forward:  <{f}>");
    }
    println!(
        "Policy:   {}{}",
        d.policy,
        if d.no_signature {
            "  (no signature)"
        } else {
            ""
        }
    );
    println!("Updated:  {}", crate::fmt_date(Some(d.updated_at)));
    if let Some(i) = server {
        let state = match (i.on_server, i.pending) {
            (false, _) => "not on the server yet",
            (true, true) => "changed here since the server copy",
            (true, false) => "on the server",
        };
        let from = if i.origin == "server" {
            ", came from the server"
        } else {
            ""
        };
        println!("Server:   {state}{from} (draft {})", i.uuid);
        if i.remote_files > 0 {
            println!(
                "          {} file reference(s) stayed on the device that saved it",
                i.remote_files
            );
        }
    }
    if !d.attachments.is_empty() {
        println!("Attachments:");
        for (n, a) in d.attachments.iter().enumerate() {
            match a.blob_id.map(|blob| sizes.get(&blob)) {
                Some(Some(size)) => println!("  [{n}] {}  (stored, {size} bytes)", a.name),
                Some(None) => println!("  [{n}] {}  (stored copy missing)", a.name),
                None => println!("  [{n}] {} ← {}  (read when sent)", a.name, a.path),
            }
        }
    }
    println!();
    println!("{}", d.body_text);
}

fn print_report(r: &SendReport) {
    let how = match r.mode {
        SendMode::Encrypted => "🔒 encrypted + signed (PGP/MIME)",
        SendMode::Plaintext => "plaintext (with Autocrypt header)",
        SendMode::GuestLink => "🔗 guest link",
    };
    println!("sent <{}> {how}", r.message_id);
    for rc in &r.recipients {
        println!(
            "  {:<32} {:?} {}",
            rc.address,
            rc.recommendation,
            rc.fingerprint.as_deref().unwrap_or("-")
        );
    }
    if let Some(g) = &r.guest {
        cmd_guest::print_guest(g);
    }
    match (&r.sent_folder, r.sent_copy_appended) {
        (None, _) => eprintln!("warning: the Sent copy could not be stored on the server"),
        (Some(f), false) => eprintln!("(the provider stored the Sent copy in {f} itself)"),
        _ => {}
    }
}

pub async fn run(profile: &Path, json: bool, cmd: DraftCmd) -> anyhow::Result<()> {
    match cmd {
        DraftCmd::Save(a) => {
            let engine = Engine::open(profile)?;
            let previous = match a.id {
                Some(id) => engine.get_draft(id).map(|d| stored_copies(&d))?,
                None => Vec::new(),
            };
            let input = draft_input(&engine, *a)?;
            let saved = engine.save_draft(input)?;
            // `--attach` replaced the attachments: drop the stored copies left behind.
            release_unreferenced(&engine, &previous)?;
            push(&engine, saved.id).await;
            if json {
                return crate::print_json(&saved);
            }
            println!("saved draft {} ({})", saved.id, saved.account);
            Ok(())
        }
        DraftCmd::List { account } => {
            let engine = Engine::open(profile)?;
            let drafts = engine.list_drafts(account.as_deref())?;
            if json {
                return crate::print_json(&drafts);
            }
            print_list(&engine, &drafts);
            Ok(())
        }
        DraftCmd::Show { id } => {
            let engine = Engine::open(profile)?;
            let d = engine.get_draft(id)?;
            if json {
                return crate::print_json(&d);
            }
            let sizes = engine
                .list_draft_blobs(&d.account)?
                .into_iter()
                .map(|b| (b.id, b.size))
                .collect();
            let server = engine.draft_server_info(d.id)?;
            print_draft(&d, &sizes, server.as_ref());
            Ok(())
        }
        DraftCmd::Attach {
            id,
            file,
            name,
            content_type,
        } => {
            let engine = Engine::open(profile)?;
            let draft = engine.get_draft(id)?;
            let bytes =
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let name = name.unwrap_or_else(|| {
                file.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            });
            let content_type = content_type.unwrap_or_else(|| crate::guess_content_type(&file));
            let blob = engine.put_draft_blob(&draft.account, &name, &content_type, &bytes)?;
            let mut input = input_of(draft);
            input.attachments.push(DraftAttachment {
                blob_id: Some(blob),
                ..Default::default()
            });
            let saved = match engine.save_draft(input) {
                Ok(saved) => saved,
                Err(e) => {
                    // Nothing references the copy: do not leave it behind.
                    let _ = engine.delete_draft_blob(blob);
                    return Err(e.into());
                }
            };
            push(&engine, saved.id).await;
            if json {
                return crate::print_json(&saved);
            }
            let shown = saved
                .attachments
                .last()
                .map(|a| a.name.clone())
                .unwrap_or_default();
            println!(
                "attached {shown} to draft {id} (stored, {} bytes)",
                bytes.len()
            );
            Ok(())
        }
        DraftCmd::Detach { id, n } => {
            let engine = Engine::open(profile)?;
            let draft = engine.get_draft(id)?;
            if n >= draft.attachments.len() {
                return Err(sealbox_core::Error::InvalidInput(format!(
                    "draft {id} has no attachment {n} (see `sealbox draft show {id}`)"
                ))
                .into());
            }
            let mut input = input_of(draft);
            let removed = input.attachments.remove(n);
            let saved = engine.save_draft(input)?;
            if let Some(blob) = removed.blob_id {
                release_unreferenced(&engine, &[blob])?;
            }
            push(&engine, saved.id).await;
            if json {
                return crate::print_json(&saved);
            }
            println!("removed {} from draft {id}", removed.name);
            Ok(())
        }
        DraftCmd::Delete { id } => {
            let engine = Engine::open(profile)?;
            let account = engine.get_draft(id).ok().map(|d| d.account);
            if !engine.delete_draft(id)? {
                return Err(sealbox_core::Error::InvalidInput(format!("no draft {id}")).into());
            }
            if let Some(account) = account {
                if let Err(e) = engine.purge_deleted_drafts(&account).await {
                    eprintln!(
                        "warning: draft {id} is deleted here; its server copy stays until \
                         `sealbox draft sync` ({e})"
                    );
                }
            }
            if json {
                return crate::print_json(&serde_json::json!({ "id": id, "deleted": true }));
            }
            println!("deleted draft {id}");
            Ok(())
        }
        DraftCmd::Sync { account } => {
            let engine = Engine::open(profile)?;
            let accounts = match account {
                Some(a) => vec![a],
                None => engine
                    .list_accounts()?
                    .into_iter()
                    .map(|a| a.email)
                    .collect(),
            };
            let mut reports = Vec::new();
            for a in &accounts {
                reports.push(engine.sync_drafts(a).await?);
            }
            if json {
                return crate::print_json(&reports);
            }
            for r in &reports {
                println!(
                    "{} ({}): {} imported, {} updated, {} uploaded, {} removed here, {} removed on \
                     the server, {} unreadable",
                    r.account,
                    r.folder,
                    r.imported,
                    r.updated,
                    r.uploaded,
                    r.removed_locally,
                    r.removed_on_server,
                    r.unreadable
                );
                if r.unreadable > 0 {
                    println!(
                        "  (unreadable: encrypted to another key, or not signed by this \
                         account's key — restore the identity to read them)"
                    );
                }
            }
            Ok(())
        }
        DraftCmd::Send { id, guest_expiry } => {
            let engine = cmd_guest::engine_for_send(profile, guest_expiry)?;
            let report = engine.send_draft(id).await?;
            if json {
                return crate::print_json(&report);
            }
            print_report(&report);
            println!("draft {id} sent and deleted");
            Ok(())
        }
    }
}
