//! Shared helpers for the CLI gate tests: drive the real `sealbox` binary against the local
//! GreenMail server (`testing/mail_up.sh`).
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sealbox_mail::imap::ImapClient;
use sealbox_mail::{Auth, Security};

pub const SMTP: &str = "127.0.0.1:3025:plain";
pub const IMAP: &str = "127.0.0.1:3143:plain";
pub const IMAP_HOST: &str = "127.0.0.1";
pub const IMAP_PORT: u16 = 3143;
pub const DOMAIN: &str = "sealbox.test";

/// A unique token for subjects/bodies so reruns never collide.
pub fn nonce(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{tag}-{nanos}-{}", std::process::id())
}

/// Result of one CLI invocation.
#[derive(Debug)]
pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout is not JSON ({e}):\n--- stdout\n{}\n--- stderr\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

/// A temporary profile directory driven through the `sealbox` binary.
pub struct Profile {
    pub dir: tempfile::TempDir,
    pub name: String,
    /// At-rest passphrase every invocation gets (`SEALBOX_PROFILE_KEY=passphrase`, G27), so
    /// the gates exercise the wrapped store and never touch the developer's OS keyring.
    pub passphrase: String,
}

impl Profile {
    pub fn new(name: &str) -> Self {
        Self {
            dir: tempfile::Builder::new()
                .prefix(&format!("sealbox-{name}-"))
                .tempdir()
                .expect("tempdir"),
            name: name.to_string(),
            passphrase: format!("harness-{name}-{}", nonce("pp")),
        }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The engine in-process, unlocked with this profile's passphrase (G27).
    pub fn engine(&self) -> sealbox_core::Engine {
        let cfg = sealbox_core::EngineConfig {
            profile_key: sealbox_core::ProfileKeySource::Passphrase(self.passphrase.clone()),
            ..sealbox_core::EngineConfig::from_env()
        };
        sealbox_core::Engine::open_with(self.dir.path(), cfg).expect("open profile")
    }

    /// Build the command (not yet run). Environment is scrubbed of anything that would
    /// point at another profile or a server.
    pub fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sealbox"));
        c.arg("--profile").arg(self.dir.path());
        c.args(args);
        c.env_remove("SEALBOX_HOME");
        c.env_remove("SEALBOX_DIRECTORY_URL");
        c.env_remove("SEALBOX_SERVER_URL");
        c.env_remove("SEALBOX_ALLOW_PLAINTEXT_PROFILE");
        c.env_remove("SEALBOX_PROFILE_PASSPHRASE_ENV");
        c.env("SEALBOX_PROFILE_KEY", "passphrase");
        c.env("SEALBOX_PROFILE_PASSPHRASE", &self.passphrase);
        c.env("SEALBOX_LOG", "warn");
        c.stdin(Stdio::null());
        c
    }

    pub fn run(&self, args: &[&str]) -> Run {
        self.run_env(args, &[])
    }

    /// Like [`Profile::run`] with environment overrides (`None` removes the variable).
    pub fn run_env(&self, args: &[&str], env: &[(&str, Option<&str>)]) -> Run {
        let mut c = self.cmd(args);
        for (k, v) in env {
            match v {
                Some(v) => c.env(k, v),
                None => c.env_remove(k),
            };
        }
        let out: Output = c.output().expect("spawn sealbox");
        let r = Run {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        };
        eprintln!(
            "[{}] sealbox {} -> {}\n{}{}",
            self.name,
            args.join(" "),
            r.code,
            indent(&r.stdout),
            if r.stderr.is_empty() {
                String::new()
            } else {
                format!(
                    "  (stderr) {}",
                    r.stderr.trim_end().replace('\n', "\n  (stderr) ")
                )
            }
        );
        r
    }

    /// Run and require exit 0; returns stdout.
    pub fn ok(&self, args: &[&str]) -> String {
        let r = self.run(args);
        assert_eq!(
            r.code,
            0,
            "sealbox {} failed ({}):\n{}\n{}",
            args.join(" "),
            r.code,
            r.stdout,
            r.stderr
        );
        r.stdout
    }

    /// Run with `--json`, require exit 0 and parse stdout.
    pub fn json(&self, args: &[&str]) -> serde_json::Value {
        let mut full = vec!["--json"];
        full.extend_from_slice(args);
        let r = self.run(&full);
        assert_eq!(
            r.code,
            0,
            "sealbox {} failed ({}):\n{}\n{}",
            full.join(" "),
            r.code,
            r.stdout,
            r.stderr
        );
        r.json()
    }

    /// `account add` for a GreenMail user with manual servers.
    pub fn add_greenmail_account(&self, user: &str) -> serde_json::Value {
        let email = format!("{user}@{DOMAIN}");
        let pw = format!("{user}pw");
        let name = {
            let mut c = user.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        };
        let v = self.json(&[
            "account",
            "add",
            "--email",
            &email,
            "--name",
            &name,
            "--password",
            &pw,
            "--imap",
            IMAP,
            "--smtp",
            SMTP,
        ]);
        assert_eq!(v["email"], email);
        assert!(
            v["fingerprint"]
                .as_str()
                .map(|f| f.len() == 40)
                .unwrap_or(false),
            "no fingerprint in {v}"
        );
        v
    }

    /// Fingerprint of an own account's key.
    pub fn fingerprint(&self, email: &str) -> String {
        let v = self.json(&["key", "show", "--address", email]);
        v["fingerprint"]
            .as_str()
            .unwrap_or_else(|| panic!("no fingerprint in {v}"))
            .to_string()
    }

    /// `sync` one account, returning the report.
    pub fn sync(&self, email: &str) -> serde_json::Value {
        let v = self.json(&["sync", "--account", email]);
        v.as_array()
            .and_then(|a| a.first().cloned())
            .unwrap_or_else(|| panic!("sync did not return a report array: {v}"))
    }

    /// `list --json` for a folder (`"*"` = all), newest first.
    pub fn list(&self, account: Option<&str>, folder: &str) -> Vec<serde_json::Value> {
        let mut args = vec!["list", "--folder", folder, "--limit", "200"];
        if let Some(a) = account {
            args.extend_from_slice(&["--account", a]);
        }
        self.json(&args).as_array().cloned().unwrap_or_default()
    }

    /// Find a stored message by subject (after sync).
    pub fn find_by_subject(
        &self,
        account: Option<&str>,
        folder: &str,
        subject: &str,
    ) -> serde_json::Value {
        self.list(account, folder)
            .into_iter()
            .find(|m| m["subject"].as_str() == Some(subject))
            .unwrap_or_else(|| panic!("no message with subject {subject:?} in {folder}"))
    }
}

fn indent(s: &str) -> String {
    if s.trim().is_empty() {
        return String::new();
    }
    let t: String = s.trim_end().lines().map(|l| format!("  {l}\n")).collect();
    t
}

/// Log in to GreenMail as `user` over IMAP.
pub async fn imap_login(user: &str) -> ImapClient {
    let pass = format!("{user}pw");
    match ImapClient::connect(
        IMAP_HOST,
        IMAP_PORT,
        Security::Plain,
        Auth::Password {
            user: user.into(),
            pass: pass.clone(),
        },
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bare login failed ({e}); trying {user}@{DOMAIN}");
            ImapClient::connect(
                IMAP_HOST,
                IMAP_PORT,
                Security::Plain,
                Auth::Password {
                    user: format!("{user}@{DOMAIN}"),
                    pass,
                },
            )
            .await
            .expect("IMAP login")
        }
    }
}

/// Number of messages in a GreenMail user's INBOX.
pub async fn inbox_count(user: &str) -> u32 {
    let mut imap = imap_login(user).await;
    let mb = imap.select("INBOX").await.expect("select INBOX");
    let _ = imap.logout().await;
    mb.exists
}

/// All raw messages in a user's INBOX as `(uid, raw)`.
pub async fn inbox_raw(user: &str) -> Vec<(u32, Vec<u8>)> {
    let mut imap = imap_login(user).await;
    imap.select("INBOX").await.expect("select INBOX");
    let uids = imap.fetch_new_uids(0).await.expect("search");
    let mut out = Vec::new();
    for chunk in uids.chunks(50) {
        for m in imap.fetch_rfc822_batch(chunk).await.expect("fetch") {
            out.push((m.uid, m.raw));
        }
    }
    let _ = imap.logout().await;
    out
}

/// Flags of one UID in a user's folder.
pub async fn flags_of(user: &str, folder: &str, uid: u32) -> Vec<String> {
    let mut imap = imap_login(user).await;
    imap.select(folder).await.expect("select");
    let f = imap.fetch_flags(&[uid]).await.expect("flags");
    let _ = imap.logout().await;
    f.into_iter()
        .find(|(u, _)| *u == uid)
        .map(|(_, f)| f)
        .unwrap_or_default()
}

/// Poll until `pred` is true or `timeout` elapses.
pub async fn wait_until<F, Fut>(timeout: Duration, mut pred: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if pred().await {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Write `bytes` to a fresh temp file and return its path.
pub fn temp_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).expect("write temp file");
    p
}

/// Deterministic pseudo-random bytes (no extra dependency needed).
pub fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed ^ 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}
