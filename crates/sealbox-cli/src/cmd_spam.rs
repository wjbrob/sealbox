//! `sealbox spam …` — spam detection (gate G25): status, learn, explain, check, eval,
//! settings, allow / block. Thin shell over `sealbox_core::spam`; `--json` prints the core
//! structs (`SpamStatus`, `SpamLearnReport`, `SpamExplanation`, `Verdict`, `EvalReport`,
//! `SpamSettings`).

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use clap::{Args, Subcommand};
use sealbox_core::sealbox_spam::eval::summary as eval_summary;
use sealbox_core::{Engine, EvalOptions, SpamExplanation, SpamSettings, SpamStatus, Verdict};

#[derive(Subcommand, Debug)]
pub enum SpamCmd {
    /// Model statistics and per-account settings
    Status {
        #[arg(long)]
        account: Option<String>,
    },
    /// Teach the classifier (--spam moves the message to the junk folder, --ham back to INBOX)
    Learn {
        id: i64,
        #[arg(long, conflicts_with = "ham")]
        spam: bool,
        #[arg(long)]
        ham: bool,
    },
    /// Why a message got its score: stored verdict, fresh evaluation, features, filter rules
    Explain { id: i64 },
    /// Classify a raw RFC 5322 file ("-" for stdin) without storing anything
    Check {
        file: PathBuf,
        /// Use this account's settings and contacts
        #[arg(long)]
        account: Option<String>,
    },
    /// Train on a labelled corpus (DIR/ham/**, DIR/spam/**) and report precision / recall / F1
    Eval(EvalArgs),
    /// Per-account settings
    Settings {
        #[command(subcommand)]
        cmd: SettingsCmd,
    },
    /// Never treat mail from ADDR (an address or a domain) as spam
    Allow {
        addr: String,
        #[arg(long)]
        account: String,
        /// Remove the entry instead
        #[arg(long)]
        remove: bool,
    },
    /// Always treat mail from ADDR (an address or a domain) as spam
    Block {
        addr: String,
        #[arg(long)]
        account: String,
        /// Remove the entry instead
        #[arg(long)]
        remove: bool,
    },
}

#[derive(Args, Debug)]
pub struct EvalArgs {
    /// Corpus root with `ham/` and `spam/` sub-directories (testing/corpus/fetch_corpus.sh)
    #[arg(long)]
    corpus: PathBuf,
    #[arg(long, default_value_t = 42)]
    seed: u64,
    /// Share of each class used for training; the rest is held out
    #[arg(long, default_value_t = 0.7)]
    train_fraction: f64,
    /// Cross-validate inside the training split (feature work) — never scores the held-out part
    #[arg(long)]
    dev: bool,
    /// Cap on messages per class (0 = all)
    #[arg(long, default_value_t = 0)]
    max_per_class: usize,
    /// Minimum precision for exit 0 (ignored with --dev)
    #[arg(long, default_value_t = 0.98)]
    min_precision: f64,
    /// Minimum recall for exit 0 (ignored with --dev)
    #[arg(long, default_value_t = 0.85)]
    min_recall: f64,
    /// How many misclassified files to list
    #[arg(long, default_value_t = 20)]
    list: usize,
}

#[derive(Subcommand, Debug)]
pub enum SettingsCmd {
    /// Show the spam settings of an account
    Show {
        #[arg(long)]
        account: String,
    },
    /// Change one or more settings
    Set(SettingsSetArgs),
    /// Back to the defaults (keeps nothing, including the lists)
    Reset {
        #[arg(long)]
        account: String,
    },
}

#[derive(Args, Debug)]
pub struct SettingsSetArgs {
    #[arg(long)]
    account: String,
    /// Classify incoming mail at all
    #[arg(long)]
    enabled: Option<bool>,
    /// Probability from which a message is "unsure" (0..1)
    #[arg(long)]
    unsure_threshold: Option<f64>,
    /// Probability from which a message is spam and moved (0..1)
    #[arg(long)]
    spam_threshold: Option<f64>,
    /// Query Spamhaus ZEN/DBL over DNS (reveals sender IPs / link domains to the resolver)
    #[arg(long)]
    dnsbl: Option<bool>,
    /// Folder spam is moved to ("Spam" = the server's junk folder, created when missing)
    #[arg(long)]
    folder: Option<String>,
}

fn print_json<T: serde::Serialize>(v: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn print_settings(email: &str, s: &SpamSettings) {
    println!("{email}:");
    println!("  enabled:          {}", s.enabled);
    println!("  spam_threshold:   {:.2}", s.spam_threshold);
    println!("  unsure_threshold: {:.2}", s.unsure_threshold);
    println!(
        "  dnsbl_enabled:    {}{}",
        s.dnsbl_enabled,
        if s.dnsbl_enabled {
            "  (sender IPs and link domains are sent to the DNS resolver)"
        } else {
            ""
        }
    );
    println!("  move_to_folder:   {}", s.move_to_folder);
    println!(
        "  allowlist:        {}",
        if s.allowlist.is_empty() {
            "-".to_string()
        } else {
            s.allowlist.join(", ")
        }
    );
    println!(
        "  blocklist:        {}",
        if s.blocklist.is_empty() {
            "-".to_string()
        } else {
            s.blocklist.join(", ")
        }
    );
}

fn print_verdict(v: &Verdict) {
    println!(
        "Verdict:  {}  p={:.5}  (bayes {:+.2} at {:.0}% confidence, rules {:+.2}, log-odds {:+.2})",
        v.label,
        v.spam_probability,
        v.bayes_log_odds.clamp(-99.0, 99.0) * v.bayes_confidence,
        v.bayes_confidence * 100.0,
        v.rules_score,
        v.log_odds
    );
    if v.reasons.is_empty() {
        println!("Reasons:  (none — nothing suspicious, nothing learned)");
    } else {
        println!("Reasons:");
        for r in &v.reasons {
            println!("  {:+5.1}  {:<24} {}", r.weight, r.code, r.detail);
        }
    }
}

fn print_status(s: &SpamStatus) {
    println!(
        "model: {} spam / {} ham learned, {} tokens, confidence {:.0}%",
        s.model_spam_messages,
        s.model_ham_messages,
        s.model_tokens,
        s.model_confidence * 100.0
    );
    for a in &s.accounts {
        print_settings(&a.email, &a.settings);
        println!("  spam folder:      {}", a.spam_folder);
        println!(
            "  messages:         {} spam, {} unsure, {} ham; {} filter rule(s)",
            a.messages_spam, a.messages_unsure, a.messages_ham, a.filter_rules
        );
    }
}

fn print_explanation(x: &SpamExplanation) {
    println!("Message {} in {} of {}", x.id, x.folder, x.account);
    println!("From:     {}", x.from);
    println!(
        "Subject:  {}",
        x.subject.as_deref().unwrap_or("(no subject)")
    );
    match (&x.stored.label, x.stored.score) {
        (Some(l), Some(p)) => println!(
            "Stored:   {l}  p={p:.5}{}",
            x.stored
                .learned
                .map(|l| format!("  (marked {l} by you)"))
                .unwrap_or_default()
        ),
        _ => println!("Stored:   (not classified yet — synced before spam detection was enabled?)"),
    }
    print_verdict(&x.verdict);
    let f = &x.features;
    println!("Features:");
    println!(
        "  sender {}{}",
        f.from_address.as_deref().unwrap_or("-"),
        f.from_name
            .as_deref()
            .map(|n| format!(" (display name {n:?})"))
            .unwrap_or_default()
    );
    if let Some(r) = &f.reply_to {
        println!("  reply-to {r}");
    }
    println!(
        "  {} link(s){}",
        f.urls.len(),
        if f.urls.is_empty() {
            String::new()
        } else {
            format!(
                ": {}",
                f.urls.iter().take(5).cloned().collect::<Vec<_>>().join(" ")
            )
        }
    );
    if !f.attachments.is_empty() {
        println!("  attachments: {}", f.attachments.join(", "));
    }
    println!(
        "  {} Received header(s), last external relay {}",
        f.received_depth,
        f.last_external_ip.as_deref().unwrap_or("-")
    );
    if f.auth.present {
        println!(
            "  authentication-results: spf={:?} dkim={:?} dmarc={:?}",
            f.auth.spf, f.auth.dkim, f.auth.dmarc
        );
    }
    if f.html_only {
        println!("  HTML-only body");
    }
    println!("  {} tokens", f.tokens);
    if x.settings.dnsbl_enabled {
        println!("  (DNSBL lookups are not repeated by explain; see the stored reasons)");
    }
    if x.filters.matched.is_empty() {
        println!("Filters:  no rule matches");
    } else {
        println!(
            "Filters:  rule(s) {:?} match → {}{}{}{}",
            x.filters.matched,
            x.filters
                .move_to
                .as_deref()
                .map(|f| format!("move to {f} "))
                .unwrap_or_default(),
            if x.filters.mark_read {
                "mark read "
            } else {
                ""
            },
            if x.filters.star { "star " } else { "" },
            if x.filters.add_flags.is_empty() {
                String::new()
            } else {
                format!("flags {}", x.filters.add_flags.join(" "))
            }
        );
    }
}

pub async fn run(profile: &Path, json: bool, cmd: SpamCmd) -> anyhow::Result<()> {
    match cmd {
        SpamCmd::Status { account } => {
            let engine = Engine::open(profile)?;
            let mut status = engine.spam_status()?;
            if let Some(a) = account {
                status
                    .accounts
                    .retain(|x| x.email.eq_ignore_ascii_case(a.trim()));
                if status.accounts.is_empty() {
                    bail!("no account {a}");
                }
            }
            if json {
                return print_json(&status);
            }
            print_status(&status);
            Ok(())
        }
        SpamCmd::Learn { id, spam, ham } => {
            if spam == ham {
                let err = clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "exactly one of --spam or --ham is required\n",
                );
                err.exit();
            }
            let engine = Engine::open(profile)?;
            let report = engine.spam_learn(id, spam).await?;
            if json {
                return print_json(&report);
            }
            println!(
                "learned message {} as {}{}; model now {} spam / {} ham",
                report.id,
                report.learned,
                report
                    .moved_to
                    .as_deref()
                    .map(|f| format!(", moved to {f}"))
                    .unwrap_or_default(),
                report.model_spam_messages,
                report.model_ham_messages
            );
            Ok(())
        }
        SpamCmd::Explain { id } => {
            let engine = Engine::open(profile)?;
            let x = engine.spam_explain(id)?;
            if json {
                return print_json(&x);
            }
            print_explanation(&x);
            Ok(())
        }
        SpamCmd::Check { file, account } => {
            let raw = if file == Path::new("-") {
                let mut buf = Vec::new();
                std::io::stdin().read_to_end(&mut buf)?;
                buf
            } else {
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?
            };
            let engine = Engine::open(profile)?;
            let v = engine.spam_classify_raw(&raw, account.as_deref())?;
            if json {
                return print_json(&v);
            }
            print_verdict(&v);
            Ok(())
        }
        SpamCmd::Eval(a) => {
            let opts = EvalOptions {
                seed: a.seed,
                train_fraction: a.train_fraction,
                dev: a.dev,
                max_per_class: a.max_per_class,
                list_errors: a.list,
                ..EvalOptions::default()
            };
            let report = Engine::spam_eval(&a.corpus, &opts)?;
            if json {
                print_json(&report)?;
            } else {
                println!("{}", eval_summary(&report));
                if !report.false_positives.is_empty() {
                    println!("false positives (ham labelled spam):");
                    for p in &report.false_positives {
                        println!("  {p}");
                    }
                }
                if !report.false_negatives.is_empty() {
                    println!("false negatives (spam not labelled spam):");
                    for p in &report.false_negatives {
                        println!("  {p}");
                    }
                }
            }
            if !a.dev && !report.meets(a.min_precision, a.min_recall) {
                bail!(
                    "target not met: precision {:.4} (need >= {:.2}), recall {:.4} (need >= {:.2})",
                    report.precision,
                    a.min_precision,
                    report.recall,
                    a.min_recall
                );
            }
            Ok(())
        }
        SpamCmd::Settings { cmd } => {
            let engine = Engine::open(profile)?;
            match cmd {
                SettingsCmd::Show { account } => {
                    let s = engine.spam_settings(&account)?;
                    if json {
                        return print_json(&s);
                    }
                    print_settings(&account, &s);
                    Ok(())
                }
                SettingsCmd::Set(a) => {
                    let mut s = engine.spam_settings(&a.account)?;
                    if let Some(v) = a.enabled {
                        s.enabled = v;
                    }
                    if let Some(v) = a.unsure_threshold {
                        s.unsure_threshold = v;
                    }
                    if let Some(v) = a.spam_threshold {
                        s.spam_threshold = v;
                    }
                    if let Some(v) = a.dnsbl {
                        s.dnsbl_enabled = v;
                    }
                    if let Some(v) = a.folder {
                        s.move_to_folder = v;
                    }
                    let s = engine.set_spam_settings(&a.account, s)?;
                    if json {
                        return print_json(&s);
                    }
                    print_settings(&a.account, &s);
                    Ok(())
                }
                SettingsCmd::Reset { account } => {
                    let s = engine.set_spam_settings(&account, SpamSettings::default())?;
                    if json {
                        return print_json(&s);
                    }
                    print_settings(&account, &s);
                    Ok(())
                }
            }
        }
        SpamCmd::Allow {
            addr,
            account,
            remove,
        } => {
            let engine = Engine::open(profile)?;
            let s = engine.spam_allow(&account, &addr, !remove)?;
            if json {
                return print_json(&s);
            }
            println!(
                "{} {addr} {} the allowlist of {account}",
                if remove { "removed" } else { "added" },
                if remove { "from" } else { "to" }
            );
            Ok(())
        }
        SpamCmd::Block {
            addr,
            account,
            remove,
        } => {
            let engine = Engine::open(profile)?;
            let s = engine.spam_block(&account, &addr, !remove)?;
            if json {
                return print_json(&s);
            }
            println!(
                "{} {addr} {} the blocklist of {account}",
                if remove { "removed" } else { "added" },
                if remove { "from" } else { "to" }
            );
            Ok(())
        }
    }
}
