//! `sealbox recovery …` — recovery phrase, encrypted server backup, restore on a new device,
//! Autocrypt Setup Message export/import (gate G15). See `docs/RECOVERY.md`.
//!
//! Secrets (the phrase, the mail password, the setup code) are read from environment
//! variables named on the command line, never from argv, so they stay out of `ps` and shell
//! history.

use std::path::Path;

use anyhow::{bail, Context};
use clap::{Args, Subcommand};
use sealbox_core::{AuthSpec, BackupOptions, Engine, RecoveryPhrase, RestoreOptions, SetupExport};

#[derive(Subcommand, Debug)]
pub enum RecoveryCmd {
    /// Create a new 12-word recovery phrase (shown once, stored nowhere)
    Phrase {
        #[arg(long)]
        account: String,
    },
    /// Check a recovery phrase (word list + checksum) without using it
    Validate {
        /// Environment variable holding the phrase
        #[arg(long)]
        phrase_env: String,
    },
    /// Encrypt keys, contacts and settings with the phrase and upload them to the server
    Backup {
        #[arg(long)]
        account: String,
        /// Sealbox server base URL (default: $SEALBOX_SERVER_URL)
        #[arg(long, env = "SEALBOX_SERVER_URL")]
        server: String,
        /// Environment variable holding the phrase
        #[arg(long)]
        phrase_env: String,
        /// Also back up the mail credential (off by default; see docs/RECOVERY.md)
        #[arg(long)]
        include_credentials: bool,
    },
    /// Last backup made from this device and the reminder state (no network)
    Status {
        #[arg(long)]
        account: String,
    },
    /// Restore an account from the server backup into this (new) profile
    Restore(RestoreArgs),
    /// Store the mail (app) password of an account restored without one
    SetPassword {
        #[arg(long)]
        account: String,
        /// Environment variable holding the password
        #[arg(long)]
        password_env: String,
    },
    /// Mail an Autocrypt Setup Message to yourself and print the setup code
    SetupExport {
        #[arg(long)]
        account: String,
    },
    /// Import an Autocrypt Setup Message (local message id, Message-ID or file)
    SetupImport {
        /// Local message id (from `list`), Message-ID, or a file (.eml / .html attachment)
        source: String,
        /// Environment variable holding the setup code
        #[arg(long, conflicts_with = "code")]
        code_env: Option<String>,
        /// The setup code (prefer --code-env)
        #[arg(long)]
        code: Option<String>,
    },
}

#[derive(Args, Debug)]
pub struct RestoreArgs {
    #[arg(long)]
    email: String,
    /// Sealbox server base URL (default: $SEALBOX_SERVER_URL)
    #[arg(long, env = "SEALBOX_SERVER_URL")]
    server: String,
    /// Environment variable holding the phrase
    #[arg(long)]
    phrase_env: String,
    /// Backup slot (account key fingerprint) if the key is neither in the server's directory
    /// nor findable in the mailbox
    #[arg(long)]
    fingerprint: Option<String>,
    /// IMAP override host:port[:tls|starttls|plain] (default: the backed-up configuration)
    #[arg(long)]
    imap: Option<String>,
    /// SMTP override host:port[:tls|starttls|plain]
    #[arg(long)]
    smtp: Option<String>,
    /// Login override
    #[arg(long)]
    user: Option<String>,
    /// Environment variable holding the mail (app) password to store with the account
    #[arg(long)]
    password_env: Option<String>,
}

fn secret_env(var: &str, what: &str) -> anyhow::Result<String> {
    let v = std::env::var(var).with_context(|| format!("{what}: ${var} is not set"))?;
    if v.trim().is_empty() {
        bail!("{what}: ${var} is empty");
    }
    Ok(v)
}

fn print_phrase(p: &RecoveryPhrase) {
    println!("Your recovery phrase (write it down now; it is not stored and not shown again):");
    println!();
    for (i, w) in p.words.iter().enumerate() {
        print!("{:>3}. {:<10}", i + 1, w);
        if i % 4 == 3 {
            println!();
        }
    }
    println!();
    println!("Anyone with these 12 words and access to the backup server can restore your keys.");
    println!("Next: sealbox recovery backup --account <A> --server <URL> --phrase-env <VAR>");
}

pub async fn run(profile: &Path, json: bool, cmd: RecoveryCmd) -> anyhow::Result<()> {
    match cmd {
        RecoveryCmd::Phrase { account } => {
            let engine = Engine::open(profile)?;
            let p = engine.recovery_phrase_create(&account)?;
            if json {
                return crate::print_json(&p);
            }
            print_phrase(&p);
            Ok(())
        }
        RecoveryCmd::Validate { phrase_env } => {
            let phrase = secret_env(&phrase_env, "recovery phrase")?;
            let p = Engine::recovery_phrase_validate(&phrase)?;
            if json {
                return crate::print_json(&serde_json::json!({
                    "words": p.words.len(),
                    "checksum_ok": p.checksum_ok,
                }));
            }
            if p.checksum_ok {
                println!("recovery phrase OK (12 words, checksum matches)");
                Ok(())
            } else {
                bail!("the checksum does not match: a word is wrong or two words are swapped")
            }
        }
        RecoveryCmd::Backup {
            account,
            server,
            phrase_env,
            include_credentials,
        } => {
            let phrase = zeroize_string(secret_env(&phrase_env, "recovery phrase")?);
            let engine = Engine::open(profile)?;
            let report = engine
                .backup_to_server_with(
                    &account,
                    &server,
                    &phrase,
                    &BackupOptions {
                        include_credentials,
                    },
                )
                .await?;
            if json {
                return crate::print_json(&report);
            }
            println!(
                "backed up {account} → {}/v1/backup/{} ({} bytes, encrypted with your phrase{})",
                report.server_url,
                report.fingerprint,
                report.bytes,
                if include_credentials {
                    "; includes the mail credential"
                } else {
                    ""
                }
            );
            Ok(())
        }
        RecoveryCmd::Status { account } => {
            let engine = Engine::open(profile)?;
            let s = engine.backup_status(&account)?;
            if json {
                return crate::print_json(&s);
            }
            match &s.last_backup {
                Some(b) => println!(
                    "last backup: {} ({} bytes) to {} slot {}",
                    crate::fmt_date(Some(b.created_at)),
                    b.bytes,
                    b.server_url,
                    b.fingerprint
                ),
                None => println!("last backup: never"),
            }
            if let Some(r) = &s.reminder {
                println!("reminder: {r}");
            }
            Ok(())
        }
        RecoveryCmd::Restore(a) => {
            let phrase = zeroize_string(secret_env(&a.phrase_env, "recovery phrase")?);
            let credentials = match &a.password_env {
                Some(var) => Some(AuthSpec::Password {
                    password: secret_env(var, "mail password")?,
                }),
                None => None,
            };
            let opts = RestoreOptions {
                fingerprint: a.fingerprint.clone(),
                credentials,
                imap: a.imap.as_deref().map(crate::parse_endpoint).transpose()?,
                smtp: a.smtp.as_deref().map(crate::parse_endpoint).transpose()?,
                login: a.user.clone(),
            };
            let engine = Engine::open(profile)?;
            let info = engine
                .restore_from_server_with(&a.server, &a.email, &phrase, &opts)
                .await?;
            if json {
                return crate::print_json(&info);
            }
            println!(
                "restored {} (key {}) — run `sealbox sync --account {}` to fetch your mail",
                info.email,
                info.fingerprint.as_deref().unwrap_or("-"),
                info.email
            );
            if opts.credentials.is_none() {
                println!(
                    "note: no mail password was given; add it before syncing: sealbox recovery set-password --account <A> --password-env <VAR>"
                );
            }
            Ok(())
        }
        RecoveryCmd::SetPassword {
            account,
            password_env,
        } => {
            let password = secret_env(&password_env, "mail password")?;
            let engine = Engine::open(profile)?;
            let info = engine.set_account_credential(&account, &AuthSpec::Password { password })?;
            if json {
                return crate::print_json(&info);
            }
            println!("password stored for {}", info.email);
            Ok(())
        }
        RecoveryCmd::SetupExport { account } => {
            let engine = Engine::open(profile)?;
            let e: SetupExport = engine.setup_message_export(&account).await?;
            if json {
                return crate::print_json(&e);
            }
            println!(
                "Autocrypt Setup Message sent to {account} <{}>",
                e.message_id
            );
            println!("Setup code (type it on the other device; it is not stored):");
            println!("  {}", e.setup_code);
            Ok(())
        }
        RecoveryCmd::SetupImport {
            source,
            code_env,
            code,
        } => {
            let code = match (code_env, code) {
                (Some(var), _) => secret_env(&var, "setup code")?,
                (None, Some(c)) => c,
                (None, None) => bail!("give the setup code with --code-env VAR (or --code)"),
            };
            let engine = Engine::open(profile)?;
            let info = engine.setup_message_import(&source, &code)?;
            if json {
                return crate::print_json(&info);
            }
            println!(
                "imported key {} for {} — run `sealbox sync --account {}` to decrypt your mail",
                info.fingerprint.as_deref().unwrap_or("-"),
                info.email,
                info.email
            );
            Ok(())
        }
    }
}

fn zeroize_string(s: String) -> zeroize_lite::Secret {
    zeroize_lite::Secret(s)
}

/// A string wiped on drop (the CLI has no `zeroize` dependency of its own).
mod zeroize_lite {
    pub struct Secret(pub String);
    impl std::ops::Deref for Secret {
        type Target = str;
        fn deref(&self) -> &str {
            &self.0
        }
    }
    impl Drop for Secret {
        fn drop(&mut self) {
            // Overwrite in place; `String` keeps its buffer.
            let len = self.0.len();
            self.0.clear();
            self.0.extend(std::iter::repeat_n('\0', len));
        }
    }
}
