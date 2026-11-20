//! Gate G29 (server half) — guest-link modes: the e-mail-code gate on `/v1/guest/{id}`.
//!
//! In-process server on 127.0.0.1:0, temp SQLite, the in-memory mail sink capturing the code.
//! Covers: ungated messages unchanged; gated GET → 401 `verification_required`; send-code
//! answers the same for a wrong address and mails nothing; the code mail; wrong codes count
//! down, the 5th locks (send-code and verify refused while locked, the code burnt); after the
//! lock a fresh code yields a token that unlocks GET; bad tokens; code expiry; per-message
//! send-code rate limit; replies still work; only hashes in the database; purge cascades. Then
//! the real viewer in headless Chromium (via `web/guest/test/drive.mjs`) for all three modes,
//! recording every request to prove the fragment secret never leaves the page.

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use sealbox_server::{mail::MemoryMailSink, AppState, Limits, StateOptions};
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::oneshot};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn scratch_dir() -> PathBuf {
    let base = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join("target"));
    let dir = base.join("gate-g29-server");
    fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

struct TestServer {
    base: String,
    db_path: PathBuf,
    state: AppState,
    sink: Arc<MemoryMailSink>,
    http: reqwest::Client,
    _dir: tempfile::TempDir,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl TestServer {
    async fn start(limits: Limits) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("srv-")
            .tempdir_in(scratch_dir())
            .expect("tempdir");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let sink = MemoryMailSink::new();
        let db_path = dir.path().join("g29.sqlite");
        let state = AppState::new(StateOptions {
            db_path: db_path.clone(),
            public_url: base.clone(),
            static_dir: repo_root().join("web/guest"),
            mailer: sink.clone(),
            trust_proxy: false,
            limits,
        })
        .expect("state");
        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(sealbox_server::serve(listener, state.clone(), async move {
            let _ = rx.await;
        }));
        Self {
            base,
            db_path,
            state,
            sink,
            http: reqwest::Client::new(),
            _dir: dir,
            shutdown: Some(tx),
            task: Some(task),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let r = self
            .http
            .post(self.url(path))
            .json(&body)
            .send()
            .await
            .expect("post");
        let status = r.status().as_u16();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    async fn get(&self, path: &str) -> (u16, Value) {
        let r = self.http.get(self.url(path)).send().await.expect("get");
        let status = r.status().as_u16();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    /// Wait for the background code mail and return (to, code).
    async fn take_code(&self) -> (String, String) {
        for _ in 0..100 {
            let mut mails = self.sink.take();
            if let Some(m) = mails.pop() {
                assert_eq!(m.subject, "Your Sealbox code");
                let code = six_digits(&m.body).expect("6-digit code in the mail");
                return (m.to, code);
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("no code mail arrived");
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
        }
    }
}

fn six_digits(s: &str) -> Option<String> {
    s.split(|c: char| !c.is_ascii_digit())
        .find(|w| w.len() == 6)
        .map(str::to_owned)
}

/// A fixed, valid-looking armored message for the API tests (the server never parses it).
const FAKE_CT: &str = "-----BEGIN PGP MESSAGE-----\n\nwy4ECQMI\n=abcd\n-----END PGP MESSAGE-----";

/// gpg --symmetric in an isolated GNUPGHOME (agent killed afterwards).
fn gpg_symmetric(passphrase: &str, plaintext: &str) -> String {
    let dir = tempfile::Builder::new()
        .prefix("gpg-")
        .tempdir_in(scratch_dir())
        .expect("gpg dir");
    let home = dir.path().join("home");
    fs::create_dir(&home).expect("home");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let mut child = Command::new("/usr/bin/gpg")
        .arg("--homedir")
        .arg(&home)
        .args([
            "--batch",
            "--yes",
            "--no-tty",
            "--pinentry-mode",
            "loopback",
            "--armor",
            "--symmetric",
            "--passphrase",
            passphrase,
            "-o",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("gpg");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(plaintext.as_bytes())
        .expect("write");
    let out = child.wait_with_output().expect("gpg out");
    let _ = Command::new("/usr/bin/gpgconf")
        .arg("--homedir")
        .arg(&home)
        .args(["--kill", "all"])
        .status();
    assert!(out.status.success(), "gpg --symmetric failed");
    String::from_utf8(out.stdout).expect("armored")
}

fn db_bytes(path: &Path) -> Vec<u8> {
    let mut all = fs::read(path).unwrap_or_default();
    for ext in ["-wal", "-shm"] {
        let p = PathBuf::from(format!("{}{ext}", path.display()));
        all.extend(fs::read(p).unwrap_or_default());
    }
    all
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

fn short_limits() -> Limits {
    Limits {
        guest_code_lock_secs: 2,
        ..Limits::default()
    }
}

#[tokio::test]
async fn ungated_message_is_unchanged() {
    let s = TestServer::start(Limits::default()).await;
    let (st, created) = s
        .post(
            "/v1/guest",
            json!({ "ciphertext_armored": FAKE_CT, "recipient_email": "u42@sealbox.test" }),
        )
        .await;
    assert_eq!(st, 201);
    assert_eq!(created["recipient_verification"], false);
    let id = created["id"].as_str().expect("id");
    let (st, body) = s.get(&format!("/v1/guest/{id}")).await;
    assert_eq!(st, 200);
    assert!(body["ciphertext_armored"].as_str().is_some());
    // The address was not needed, so it was not kept.
    assert!(!contains(&db_bytes(&s.db_path), "u42@sealbox.test"));
    // send-code / verify on an ungated message are refused.
    let (st, body) = s
        .post(
            &format!("/v1/guest/{id}/send-code"),
            json!({ "email": "u42@sealbox.test" }),
        )
        .await;
    assert_eq!((st, body["error"].as_str()), (400, Some("not_gated")));
    let (st, _) = s
        .post(
            &format!("/v1/guest/{id}/verify"),
            json!({ "code": "123456" }),
        )
        .await;
    assert_eq!(st, 400);
    // require_email_code without an address is a client error.
    let (st, _) = s
        .post(
            "/v1/guest",
            json!({ "ciphertext_armored": FAKE_CT, "require_email_code": true }),
        )
        .await;
    assert_eq!(st, 400);
    let (st, _) = s
        .post(
            "/v1/guest",
            json!({ "ciphertext_armored": FAKE_CT, "require_email_code": true, "recipient_email": "not an address" }),
        )
        .await;
    assert_eq!(st, 400);
    s.stop().await;
}

#[tokio::test]
async fn email_code_gate_full_cycle() {
    let s = TestServer::start(short_limits()).await;
    let rcpt = "U44@Sealbox.test";
    let (st, created) = s
        .post(
            "/v1/guest",
            json!({
                "ciphertext_armored": FAKE_CT,
                "expires_in_secs": 3600,
                "recipient_email": rcpt,
                "require_email_code": true,
            }),
        )
        .await;
    assert_eq!(st, 201, "{created}");
    assert_eq!(created["recipient_verification"], true);
    let id = created["id"].as_str().expect("id").to_owned();
    let pickup = created["pickup_token"].as_str().expect("pickup").to_owned();

    // Gated: no ciphertext without a token, and nothing about the message leaks.
    let (st, body) = s.get(&format!("/v1/guest/{id}")).await;
    assert_eq!(st, 401);
    assert_eq!(body, json!({ "error": "verification_required" }));
    let (st, body) = s.get(&format!("/v1/guest/{id}?token=bogus")).await;
    assert_eq!(
        (st, body["error"].as_str()),
        (401, Some("verification_required"))
    );

    // Verify before any code was issued.
    let (st, body) = s
        .post(
            &format!("/v1/guest/{id}/verify"),
            json!({ "code": "000000" }),
        )
        .await;
    assert_eq!((st, body["error"].as_str()), (400, Some("no_active_code")));
    // Malformed code.
    let (st, _) = s
        .post(&format!("/v1/guest/{id}/verify"), json!({ "code": "12ab" }))
        .await;
    assert_eq!(st, 400);

    // Wrong address: same answer, no mail.
    let (st_wrong, body_wrong) = s
        .post(
            &format!("/v1/guest/{id}/send-code"),
            json!({ "email": "someone-else@sealbox.test" }),
        )
        .await;
    assert_eq!(st_wrong, 202);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        s.sink.take().is_empty(),
        "a code went to a non-recipient address"
    );

    // Right address (case and whitespace normalised): the code mail goes to that address.
    let (st, body) = s
        .post(
            &format!("/v1/guest/{id}/send-code"),
            json!({ "email": "  u44@sealbox.TEST " }),
        )
        .await;
    assert_eq!(st, 202);
    assert_eq!(
        body, body_wrong,
        "answer must not reveal whether the address matched"
    );
    assert_eq!(body["expires_in"], 600);
    let (to, code) = s.take_code().await;
    assert_eq!(to, "u44@sealbox.test");
    let wrong = if code == "000001" { "000002" } else { "000001" };

    // Four wrong codes count down; the fifth locks.
    for left in (1..=4).rev() {
        let (st, body) = s
            .post(&format!("/v1/guest/{id}/verify"), json!({ "code": wrong }))
            .await;
        assert_eq!(st, 401, "{body}");
        assert_eq!(body["error"], "invalid_code");
        assert_eq!(body["attempts_left"], left);
    }
    let (st, body) = s
        .post(&format!("/v1/guest/{id}/verify"), json!({ "code": wrong }))
        .await;
    assert_eq!(
        (st, body["error"].as_str()),
        (429, Some("locked")),
        "{body}"
    );
    assert!(body["retry_after"].as_i64().unwrap_or(0) >= 1);
    // While locked: even the right code is refused, and no new code can be requested.
    let (st, body) = s
        .post(&format!("/v1/guest/{id}/verify"), json!({ "code": code }))
        .await;
    assert_eq!((st, body["error"].as_str()), (429, Some("locked")));
    let (st, body) = s
        .post(
            &format!("/v1/guest/{id}/send-code"),
            json!({ "email": rcpt }),
        )
        .await;
    assert_eq!((st, body["error"].as_str()), (429, Some("locked")));

    // After the lock the old code is burnt; a fresh one works.
    tokio::time::sleep(Duration::from_millis(2300)).await;
    let (st, body) = s
        .post(&format!("/v1/guest/{id}/verify"), json!({ "code": code }))
        .await;
    assert_eq!((st, body["error"].as_str()), (400, Some("no_active_code")));
    let (st, _) = s
        .post(
            &format!("/v1/guest/{id}/send-code"),
            json!({ "email": rcpt }),
        )
        .await;
    assert_eq!(st, 202);
    let (_, code2) = s.take_code().await;
    let (st, body) = s
        .post(
            &format!("/v1/guest/{id}/verify"),
            json!({ "code": format!("{} {}", &code2[..3], &code2[3..]) }),
        )
        .await;
    assert_eq!(st, 200, "{body}");
    let token = body["access_token"].as_str().expect("token").to_owned();
    assert_eq!(body["expires_in"], 900);
    // A code works once.
    let (st, _) = s
        .post(&format!("/v1/guest/{id}/verify"), json!({ "code": code2 }))
        .await;
    assert_eq!(st, 400);

    // The token unlocks the ciphertext (and only for this message).
    let (st, body) = s.get(&format!("/v1/guest/{id}?token={token}")).await;
    assert_eq!(st, 200);
    assert!(body["ciphertext_armored"]
        .as_str()
        .is_some_and(|c| c.starts_with("-----BEGIN PGP MESSAGE-----")));
    let (_, other) = s
        .post(
            "/v1/guest",
            json!({ "ciphertext_armored": FAKE_CT, "recipient_email": rcpt, "require_email_code": true }),
        )
        .await;
    let other_id = other["id"].as_str().expect("id");
    let (st, _) = s.get(&format!("/v1/guest/{other_id}?token={token}")).await;
    assert_eq!(st, 401, "a token must not open another message");

    // Replies and pickup are unchanged on a gated message.
    let (st, _) = s
        .post(
            &format!("/v1/guest/{id}/reply"),
            json!({ "ciphertext_armored": FAKE_CT }),
        )
        .await;
    assert_eq!(st, 204);
    let (st, body) = s
        .get(&format!("/v1/guest/{id}/replies?token={pickup}"))
        .await;
    assert_eq!(st, 200);
    assert_eq!(body["replies"].as_array().map(Vec::len), Some(1));

    // Only hashes at rest: no address, no code, no token.
    let bytes = db_bytes(&s.db_path);
    for secret in [
        "u44@sealbox.test",
        "U44@Sealbox.test",
        code.as_str(),
        code2.as_str(),
        token.as_str(),
    ] {
        assert!(
            !contains(&bytes, secret),
            "{secret:?} found in the server database"
        );
    }
    s.stop().await;
}

#[tokio::test]
async fn codes_expire_and_send_code_is_rate_limited() {
    let s = TestServer::start(Limits {
        guest_code_ttl_secs: 1,
        guest_code_mails_per_message_per_hour: 3,
        ..Limits::default()
    })
    .await;
    let (_, created) = s
        .post(
            "/v1/guest",
            json!({ "ciphertext_armored": FAKE_CT, "recipient_email": "u45@sealbox.test", "require_email_code": true }),
        )
        .await;
    let id = created["id"].as_str().expect("id").to_owned();
    let (st, _) = s
        .post(
            &format!("/v1/guest/{id}/send-code"),
            json!({ "email": "u45@sealbox.test" }),
        )
        .await;
    assert_eq!(st, 202);
    let (_, code) = s.take_code().await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let (st, body) = s
        .post(&format!("/v1/guest/{id}/verify"), json!({ "code": code }))
        .await;
    assert_eq!((st, body["error"].as_str()), (400, Some("no_active_code")));
    for _ in 0..2 {
        let (st, _) = s
            .post(
                &format!("/v1/guest/{id}/send-code"),
                json!({ "email": "u45@sealbox.test" }),
            )
            .await;
        assert_eq!(st, 202);
    }
    let (st, body) = s
        .post(
            &format!("/v1/guest/{id}/send-code"),
            json!({ "email": "u45@sealbox.test" }),
        )
        .await;
    assert_eq!((st, body["error"].as_str()), (429, Some("rate_limited")));
    s.stop().await;
}

#[tokio::test]
async fn expired_gated_message_is_gone_and_purged_with_its_gate() {
    let s = TestServer::start(Limits::default()).await;
    let (_, created) = s
        .post(
            "/v1/guest",
            json!({ "ciphertext_armored": FAKE_CT, "expires_in_secs": 1, "recipient_email": "u45@sealbox.test", "require_email_code": true }),
        )
        .await;
    let id = created["id"].as_str().expect("id").to_owned();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let (st, _) = s.get(&format!("/v1/guest/{id}")).await;
    assert_eq!(st, 404);
    let (st, _) = s
        .post(
            &format!("/v1/guest/{id}/send-code"),
            json!({ "email": "u45@sealbox.test" }),
        )
        .await;
    assert_eq!(st, 404);
    let report = s.state.purge_expired().await.expect("purge");
    assert_eq!(report.guest_messages, 1);
    let left: i64 = s
        .state
        .db()
        .call(|c| {
            c.query_row("SELECT COUNT(*) FROM guest_gates", [], |r| r.get(0))
                .map_err(sealbox_server::db::DbError::from)
        })
        .await
        .expect("count");
    assert_eq!(left, 0, "gate rows must go with their message");
    s.stop().await;
}

// ------------------------------------------------------------------------------------------
// The real viewer in headless Chromium
// ------------------------------------------------------------------------------------------

fn browser() -> Option<&'static str> {
    [
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
    ]
    .into_iter()
    .find(|b| Path::new(b).exists())
}

/// Run `drive.mjs` with `plan`; `on_need` answers `NEED <name>` prompts. Returns the final JSON.
async fn drive<F, Fut>(plan: Value, mut on_need: F) -> Value
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = String>,
{
    let browser = browser().expect("browser");
    let mut child = Command::new("node")
        .arg(repo_root().join("web/guest/test/drive.mjs"))
        .args(["--browser", browser, "--plan", &plan.to_string()])
        .env("CARGO_TARGET_DIR", scratch_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("node drive.mjs");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut last = String::new();
    while let Some(line) = rx.recv().await {
        if let Some(name) = line.strip_prefix("NEED ") {
            let answer = on_need(name.to_owned()).await;
            writeln!(stdin, "{answer}").expect("answer driver");
        } else {
            last = line;
        }
    }
    let _ = tokio::task::spawn_blocking(move || child.wait()).await;
    serde_json::from_str(&last).unwrap_or_else(|e| panic!("driver output {last:?}: {e}"))
}

fn assert_driver_ok(r: &Value, what: &str) {
    assert_eq!(
        r["ok"],
        true,
        "{what}: {}",
        serde_json::to_string_pretty(r).unwrap_or_default()
    );
}

#[tokio::test]
async fn viewer_handles_all_three_modes_in_headless_chromium() {
    if browser().is_none() || Command::new("node").arg("--version").output().is_err() {
        eprintln!("SKIP: no chromium/node; headless G29 viewer check not run");
        return;
    }
    let s = TestServer::start(short_limits()).await;
    let secret = "wxyz-2345-abcd-efgh-jkmn";
    let marker = "SEALBOX-G29-VIEWER-OK";
    let ct = gpg_symmetric(secret, &format!("Hello guest {marker}\n"));
    let frag = secret.replace('-', "%2D");

    // (1) Passphrase mode: bare link → prompt; wrong passphrase refused; right one decrypts.
    let (_, c) = s
        .post("/v1/guest", json!({ "ciphertext_armored": ct }))
        .await;
    let link = c["url"].as_str().expect("url").to_owned();
    let r = drive(
        json!({ "secrets": [secret], "steps": [
            { "open": link },
            { "waitVisible": "#unlock" },
            { "waitText": "It was not sent by e-mail" },
            { "assertNoText": marker },
            { "fill": "#passphrase", "value": "wrong-pass" },
            { "submit": "#unlock" },
            { "waitText": "does not open this message" },
            { "assertNoText": marker },
            { "fill": "#passphrase", "value": secret },
            { "submit": "#unlock" },
            { "waitText": marker },
            { "waitText": "Decrypted in your browser" },
        ]}),
        |_| async { String::new() },
    )
    .await;
    assert_driver_ok(&r, "passphrase mode");

    // (2) One-click: secret in the fragment → auto-decrypt with the warning; fragment removed
    // from the address bar.
    let r = drive(
        json!({ "secrets": [secret], "steps": [
            { "open": format!("{link}#{frag}") },
            { "waitText": marker },
            { "waitText": "anyone who has the link can read it" },
            { "assertUrlNoFragment": true },
        ]}),
        |_| async { String::new() },
    )
    .await;
    assert_driver_ok(&r, "one-click mode");

    // (3) Email code: gate screen → address → code from the mail sink → decrypt with the
    // fragment secret. A wrong code first shows the countdown.
    let (_, c) = s
        .post(
            "/v1/guest",
            json!({ "ciphertext_armored": ct, "recipient_email": "u44@sealbox.test", "require_email_code": true }),
        )
        .await;
    let gated = c["url"].as_str().expect("url").to_owned();
    let sink = s.sink.clone();
    let r = drive(
        json!({ "secrets": [secret], "steps": [
            { "open": format!("{gated}#{frag}") },
            { "waitVisible": "#gate-email" },
            { "waitText": "one-time code" },
            { "assertNoText": marker },
            { "fill": "#gate-address", "value": "u44@sealbox.test" },
            { "submit": "#gate-email" },
            { "waitVisible": "#gate-code" },
            { "waitText": "a code is on its way" },
            { "fill": "#gate-code-input", "value": "999999" },
            { "submit": "#gate-code" },
            { "waitText": "attempts left" },
            { "fillFromStdin": "#gate-code-input", "name": "code" },
            { "submit": "#gate-code" },
            { "waitText": marker },
            { "waitText": "Decrypted in your browser" },
        ]}),
        move |_| {
            let sink = sink.clone();
            async move {
                for _ in 0..200 {
                    if let Some(m) = sink.take().pop() {
                        return six_digits(&m.body).unwrap_or_default();
                    }
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
                String::new()
            }
        },
    )
    .await;
    assert_driver_ok(&r, "email-code mode");
    let urls: Vec<&str> = r["requests"]
        .as_array()
        .expect("requests")
        .iter()
        .filter_map(|q| q["url"].as_str())
        .collect();
    assert!(urls.iter().any(|u| u.ends_with("/send-code")));
    assert!(urls.iter().any(|u| u.ends_with("/verify")));
    assert!(urls.iter().any(|u| u.contains("?token=")));

    // (4) Expired: the viewer says so.
    let (_, c) = s
        .post(
            "/v1/guest",
            json!({ "ciphertext_armored": ct, "expires_in_secs": 1 }),
        )
        .await;
    let short = c["url"].as_str().expect("url").to_owned();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let r = drive(
        json!({ "secrets": [secret], "steps": [
            { "open": format!("{short}#{frag}") },
            { "waitText": "has expired or does not exist" },
            { "assertNoText": marker },
        ]}),
        |_| async { String::new() },
    )
    .await;
    assert_driver_ok(&r, "expired");

    assert!(
        !contains(&db_bytes(&s.db_path), secret) && !contains(&db_bytes(&s.db_path), marker),
        "secret or plaintext in the server database"
    );
    eprintln!("headless viewer: passphrase, one-click, email-code and expiry all behave");
    s.stop().await;
}
