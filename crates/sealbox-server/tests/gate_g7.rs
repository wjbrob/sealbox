//! Gate G7 — server: key upload → e-mail challenge → verified lookup; guest message
//! post / fetch / reply; signed backups; expiry; and the browser viewer (Node interop test
//! against gpg, plus a headless-Chromium decrypt when a browser is installed).
//!
//! Everything runs in-process on 127.0.0.1:0 with a temp SQLite file and the in-memory mail
//! sink. gpg (the interop oracle) uses an isolated GNUPGHOME under the cargo target dir.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use pgp::{composed::Deserializable, types::KeyDetails};
use sealbox_server::{
    mail::MemoryMailSink,
    routes::backup::{KEY_HEADER, SIGNATURE_HEADER, TOKEN_HEADER},
    AppState, Limits, StateOptions,
};
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::oneshot};

// ------------------------------------------------------------------------------------------
// Harness
// ------------------------------------------------------------------------------------------

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
    let dir = base.join("gate-g7");
    fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

struct TestServer {
    base: String,
    state: AppState,
    sink: Arc<MemoryMailSink>,
    http: reqwest::Client,
    _dir: tempfile::TempDir,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl TestServer {
    async fn start() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("srv-")
            .tempdir_in(scratch_dir())
            .expect("tempdir");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let base = format!("http://{addr}");
        let sink = MemoryMailSink::new();
        let state = AppState::new(StateOptions {
            db_path: dir.path().join("g7.sqlite"),
            public_url: base.clone(),
            static_dir: repo_root().join("web/guest"),
            mailer: sink.clone(),
            trust_proxy: false,
            limits: Limits::default(),
        })
        .expect("state");
        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(sealbox_server::serve(listener, state.clone(), async move {
            let _ = rx.await;
        }));
        Self {
            base,
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

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
        }
    }
}

/// gpg in an isolated home; the agent is killed on drop.
struct Gpg {
    home: PathBuf,
    _dir: tempfile::TempDir,
}

impl Gpg {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("gpg-")
            .tempdir_in(scratch_dir())
            .expect("gpg tempdir");
        let home = dir.path().join("home");
        fs::create_dir(&home).expect("gnupghome");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("chmod 700");
        }
        Self { home, _dir: dir }
    }

    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Vec<u8> {
        use std::{io::Write, process::Stdio};
        let mut cmd = Command::new("/usr/bin/gpg");
        cmd.arg("--homedir")
            .arg(&self.home)
            .args([
                "--batch",
                "--yes",
                "--no-tty",
                "--pinentry-mode",
                "loopback",
            ])
            .args(args)
            .env("GNUPGHOME", &self.home)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn gpg");
        if let Some(data) = stdin {
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(data)
                .expect("write stdin");
        }
        let out = child.wait_with_output().expect("gpg output");
        assert!(
            out.status.success(),
            "gpg {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    fn gen_key(&self, uid: &str) {
        self.run(
            &[
                "--passphrase",
                "",
                "--quick-gen-key",
                uid,
                "default",
                "default",
                "never",
            ],
            None,
        );
    }

    fn add_uid(&self, key: &str, uid: &str) {
        self.run(&["--passphrase", "", "--quick-add-uid", key, uid], None);
    }

    fn export_pub(&self, id: &str) -> String {
        String::from_utf8(self.run(&["--armor", "--export", id], None)).expect("utf8")
    }

    fn fingerprint(&self, id: &str) -> String {
        let out =
            String::from_utf8(self.run(&["--with-colons", "--list-keys", id], None)).expect("utf8");
        out.lines()
            .find(|l| l.starts_with("fpr:"))
            .and_then(|l| l.split(':').nth(9))
            .expect("fpr line")
            .to_uppercase()
    }

    fn detach_sign(&self, signer: &str, data: &[u8]) -> String {
        String::from_utf8(self.run(
            &["--armor", "--detach-sign", "-u", signer, "-o", "-"],
            Some(data),
        ))
        .expect("utf8")
    }

    fn symmetric(&self, passphrase: &str, plaintext: &[u8]) -> String {
        String::from_utf8(self.run(
            &[
                "--armor",
                "--symmetric",
                "--cipher-algo",
                "AES256",
                "--passphrase",
                passphrase,
                "-o",
                "-",
            ],
            Some(plaintext),
        ))
        .expect("utf8")
    }

    fn encrypt_to(&self, recipient: &str, plaintext: &[u8]) -> String {
        String::from_utf8(self.run(
            &[
                "--armor",
                "--encrypt",
                "--trust-model",
                "always",
                "-r",
                recipient,
                "-o",
                "-",
            ],
            Some(plaintext),
        ))
        .expect("utf8")
    }

    fn decrypt(&self, armored: &str, passphrase: Option<&str>) -> Vec<u8> {
        let mut args = vec!["--decrypt"];
        if let Some(p) = passphrase {
            args.extend(["--passphrase", p]);
        }
        self.run(&args, Some(armored.as_bytes()))
    }

    fn import(&self, armored: &str) {
        self.run(&["--import"], Some(armored.as_bytes()));
    }

    fn list_uids(&self, id: &str) -> Vec<String> {
        let out =
            String::from_utf8(self.run(&["--with-colons", "--list-keys", id], None)).expect("utf8");
        out.lines()
            .filter(|l| l.starts_with("uid:"))
            .filter_map(|l| l.split(':').nth(9).map(str::to_owned))
            .collect()
    }
}

impl Drop for Gpg {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/gpgconf")
            .arg("--homedir")
            .arg(&self.home)
            .args(["--kill", "all"])
            .output();
    }
}

fn uids_of(armored: &str) -> Vec<String> {
    let (key, _) = pgp::composed::SignedPublicKey::from_string(armored).expect("parse key");
    key.verify_bindings().expect("served key self-consistent");
    key.details
        .users
        .iter()
        .filter_map(|u| u.id.as_str().map(str::to_owned))
        .collect()
}

fn fpr_of(armored: &str) -> String {
    let (key, _) = pgp::composed::SignedPublicKey::from_string(armored).expect("parse key");
    key.fingerprint().to_string().to_uppercase()
}

// ------------------------------------------------------------------------------------------
// Health + hygiene
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn health_and_security_headers() {
    let s = TestServer::start().await;
    let res = s
        .http
        .get(s.url("/v1/health"))
        .send()
        .await
        .expect("health");
    assert_eq!(res.status(), 200);
    let csp = res
        .headers()
        .get("content-security-policy")
        .expect("csp")
        .to_str()
        .expect("ascii")
        .to_owned();
    assert!(csp.contains("script-src 'self'"), "csp: {csp}");
    assert!(csp.contains("default-src 'none'"), "csp: {csp}");
    assert_eq!(res.headers()["x-content-type-options"], "nosniff");
    assert_eq!(res.headers()["cache-control"], "no-store");
    assert_eq!(res.headers()["x-frame-options"], "DENY");
    let body: Value = res.json().await.expect("json");
    assert_eq!(body["ok"], true);
    assert_eq!(body["version"], sealbox_server::VERSION);

    // Unknown routes answer JSON 404; the viewer page is served for any well-formed id.
    let res = s.http.get(s.url("/nope")).send().await.expect("404");
    assert_eq!(res.status(), 404);
    let res = s
        .http
        .get(s.url("/g/AbCdEfGhIjKlMnOpQrStUv"))
        .send()
        .await
        .expect("viewer");
    assert_eq!(res.status(), 200);
    assert!(res.headers()["content-type"]
        .to_str()
        .expect("ct")
        .starts_with("text/html"));
    let html = res.text().await.expect("html");
    assert!(html.contains("/static/viewer.js") && html.contains("/static/vendor/openpgp.min.js"));
    for (path, needle) in [
        ("/static/viewer.js", "javascript"),
        ("/static/viewer-core.mjs", "javascript"),
        ("/static/vendor/openpgp.min.js", "javascript"),
        ("/static/style.css", "text/css"),
    ] {
        let res = s.http.get(s.url(path)).send().await.expect(path);
        assert_eq!(res.status(), 200, "{path}");
        let ct = res.headers()["content-type"]
            .to_str()
            .expect("ct")
            .to_owned();
        assert!(ct.contains(needle), "{path}: content-type {ct}");
    }
    s.stop().await;
}

// ------------------------------------------------------------------------------------------
// Key directory
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn directory_upload_challenge_verify_lookup() {
    let s = TestServer::start().await;
    let gpg = Gpg::new();
    gpg.gen_key("Alice Test <alice@sealbox.test>");
    gpg.add_uid(
        "alice@sealbox.test",
        "Alice Second <Alice-Second@sealbox.test>",
    );
    let alice_pub = gpg.export_pub("alice@sealbox.test");
    let alice_fpr = gpg.fingerprint("alice@sealbox.test");

    // Garbage is rejected.
    let res = s
        .http
        .post(s.url("/vks/v1/upload"))
        .json(&json!({ "keytext": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n" }))
        .send()
        .await
        .expect("upload garbage");
    assert_eq!(res.status(), 400);

    // Upload.
    let res = s
        .http
        .post(s.url("/vks/v1/upload"))
        .json(&json!({ "keytext": alice_pub }))
        .send()
        .await
        .expect("upload");
    assert_eq!(
        res.status(),
        200,
        "{}",
        res.text().await.unwrap_or_default()
    );
    let up: Value = res.json().await.expect("json");
    assert_eq!(up["key_fpr"], alice_fpr);
    assert_eq!(up["status"]["alice@sealbox.test"], "unpublished");
    assert_eq!(up["status"]["alice-second@sealbox.test"], "unpublished");
    let token = up["token"].as_str().expect("token").to_owned();

    // Nothing is published yet.
    for path in [
        "/vks/v1/by-email/alice@sealbox.test",
        &format!("/vks/v1/by-fingerprint/{alice_fpr}"),
    ] {
        let res = s.http.get(s.url(path)).send().await.expect(path);
        assert_eq!(res.status(), 404, "{path}");
    }

    // Bad token.
    let res = s
        .http
        .post(s.url("/vks/v1/request-verify"))
        .json(&json!({ "token": "not-a-token", "addresses": ["alice@sealbox.test"] }))
        .send()
        .await
        .expect("rv");
    assert_eq!(res.status(), 400);

    // Request verification of one address → one challenge mail.
    let res = s
        .http
        .post(s.url("/vks/v1/request-verify"))
        .json(&json!({ "token": token, "addresses": ["Alice@sealbox.test"] }))
        .send()
        .await
        .expect("request-verify");
    assert_eq!(
        res.status(),
        200,
        "{}",
        res.text().await.unwrap_or_default()
    );
    let rv: Value = res.json().await.expect("json");
    assert_eq!(rv["status"]["alice@sealbox.test"], "pending");
    assert_eq!(rv["status"]["alice-second@sealbox.test"], "unpublished");

    let mails = s.sink.take();
    assert_eq!(mails.len(), 1, "exactly one challenge mail");
    assert_eq!(mails[0].to, "alice@sealbox.test");
    assert!(mails[0].body.contains(&alice_fpr));
    let prefix = s.url("/vks/v1/verify/");
    let link = mails[0]
        .body
        .split_whitespace()
        .find(|w| w.starts_with(&prefix))
        .expect("challenge link in mail")
        .to_owned();

    // Still 404 before the click.
    let res = s
        .http
        .get(s.url("/vks/v1/by-email/alice@sealbox.test"))
        .send()
        .await
        .expect("by-email");
    assert_eq!(res.status(), 404);

    // Click the link: published. Second click: gone (single use).
    let res = s.http.get(&link).send().await.expect("verify");
    assert_eq!(res.status(), 200);
    assert!(res.text().await.expect("html").contains("Address verified"));
    let res = s.http.get(&link).send().await.expect("verify again");
    assert_eq!(res.status(), 404);

    // by-email returns the key reduced to that single user ID.
    let res = s
        .http
        .get(s.url("/vks/v1/by-email/alice@sealbox.test"))
        .send()
        .await
        .expect("by-email");
    assert_eq!(res.status(), 200);
    assert!(res.headers()["content-type"]
        .to_str()
        .expect("ct")
        .starts_with("application/pgp-keys"));
    let served = res.text().await.expect("armored");
    assert_eq!(fpr_of(&served), alice_fpr);
    assert_eq!(uids_of(&served), vec!["Alice Test <alice@sealbox.test>"]);

    // gpg imports what we serve and sees exactly that user ID.
    let importer = Gpg::new();
    importer.import(&served);
    assert_eq!(
        importer.list_uids("alice@sealbox.test"),
        vec!["Alice Test <alice@sealbox.test>"]
    );

    // Case-insensitive lookup; unverified / unknown addresses stay 404.
    let res = s
        .http
        .get(s.url("/vks/v1/by-email/ALICE@sealbox.test"))
        .send()
        .await
        .expect("by-email upper");
    assert_eq!(res.status(), 200);
    for path in [
        "/vks/v1/by-email/alice-second@sealbox.test",
        "/vks/v1/by-email/nobody@sealbox.test",
        "/vks/v1/by-fingerprint/0000000000000000000000000000000000000000",
    ] {
        let res = s.http.get(s.url(path)).send().await.expect(path);
        assert_eq!(res.status(), 404, "{path}");
    }

    // A stripped re-upload (stale client or a stranger re-posting the public key with user
    // IDs removed) cannot unpublish anything: the directory merges certificates.
    let stripped = String::from_utf8(gpg.run(
        &[
            "--armor",
            "--export",
            "--export-filter",
            "keep-uid=mbox=alice-second@sealbox.test",
            "alice@sealbox.test",
        ],
        None,
    ))
    .expect("utf8");
    assert_eq!(
        uids_of(&stripped),
        vec!["Alice Second <Alice-Second@sealbox.test>"],
        "precondition: the stripped export lacks the published UID"
    );
    let res = s
        .http
        .post(s.url("/vks/v1/upload"))
        .json(&json!({ "keytext": stripped }))
        .send()
        .await
        .expect("upload stripped");
    assert_eq!(res.status(), 200);
    let up2: Value = res.json().await.expect("json");
    assert_eq!(up2["status"]["alice@sealbox.test"], "published");
    assert_eq!(up2["status"]["alice-second@sealbox.test"], "unpublished");
    let res = s
        .http
        .get(s.url("/vks/v1/by-email/alice@sealbox.test"))
        .send()
        .await
        .expect("by-email after stripped upload");
    assert_eq!(res.status(), 200);
    assert_eq!(
        uids_of(&res.text().await.expect("armored")),
        vec!["Alice Test <alice@sealbox.test>"]
    );

    // Revoking a user ID and re-uploading removes that address from the directory.
    gpg.run(
        &[
            "--passphrase",
            "",
            "--quick-revoke-uid",
            "alice@sealbox.test",
            "Alice Second <Alice-Second@sealbox.test>",
        ],
        None,
    );
    let res = s
        .http
        .post(s.url("/vks/v1/upload"))
        .json(&json!({ "keytext": gpg.export_pub("alice@sealbox.test") }))
        .send()
        .await
        .expect("upload revoked uid");
    assert_eq!(res.status(), 200);
    let up3: Value = res.json().await.expect("json");
    assert_eq!(up3["status"]["alice@sealbox.test"], "published");
    assert!(
        up3["status"].get("alice-second@sealbox.test").is_none(),
        "revoked UID gone: {}",
        up3["status"]
    );

    // by-fingerprint: only published UIDs, fingerprint case/spacing-insensitive.
    let spaced = alice_fpr
        .to_lowercase()
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    let res = s
        .http
        .get(s.url(&format!("/vks/v1/by-fingerprint/{spaced}")))
        .send()
        .await
        .expect("by-fpr");
    assert_eq!(res.status(), 200);
    assert_eq!(
        uids_of(&res.text().await.expect("armored")),
        vec!["Alice Test <alice@sealbox.test>"]
    );
    s.stop().await;
}

// ------------------------------------------------------------------------------------------
// Guest messages
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn guest_post_fetch_reply_pickup_and_expiry() {
    let s = TestServer::start().await;
    let gpg = Gpg::new();
    gpg.gen_key("Sender <sender@sealbox.test>");
    let sender_pub = gpg.export_pub("sender@sealbox.test");
    let plaintext = b"hello guest, this is secret\n";
    let ciphertext = gpg.symmetric("open sesame", plaintext);

    // Not an OpenPGP message → 400.
    let res = s
        .http
        .post(s.url("/v1/guest"))
        .json(&json!({ "ciphertext_armored": "just text" }))
        .send()
        .await
        .expect("post bad");
    assert_eq!(res.status(), 400);

    let res = s
        .http
        .post(s.url("/v1/guest"))
        .json(&json!({
            "ciphertext_armored": ciphertext,
            "expires_in_secs": 3600,
            "sender_key_armored": sender_pub,
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(
        res.status(),
        201,
        "{}",
        res.text().await.unwrap_or_default()
    );
    let created: Value = res.json().await.expect("json");
    let id = created["id"].as_str().expect("id").to_owned();
    let pickup = created["pickup_token"].as_str().expect("pickup").to_owned();
    assert_eq!(created["url"], s.url(&format!("/g/{id}")));
    assert_eq!(id.len(), 22);
    assert!(created["expires_at"].as_i64() > created["created_at"].as_i64());

    // Fetch: the ciphertext comes back byte-identical (modulo trailing newline) and gpg opens it.
    let res = s
        .http
        .get(s.url(&format!("/v1/guest/{id}")))
        .send()
        .await
        .expect("fetch");
    assert_eq!(res.status(), 200);
    let fetched: Value = res.json().await.expect("json");
    let ct = fetched["ciphertext_armored"].as_str().expect("ct");
    assert_eq!(ct.trim(), ciphertext.trim());
    assert_eq!(
        fetched["sender_key_armored"].as_str().map(fpr_of),
        Some(gpg.fingerprint("sender@sealbox.test"))
    );
    assert_eq!(fetched["reply_count"], 0);
    assert_eq!(gpg.decrypt(ct, Some("open sesame")), plaintext);

    // Reply (encrypted to the sender's key) → 204; pickup needs the token.
    let reply_ct = gpg.encrypt_to("sender@sealbox.test", b"thanks, got it\n");
    let res = s
        .http
        .post(s.url(&format!("/v1/guest/{id}/reply")))
        .json(&json!({ "ciphertext_armored": reply_ct }))
        .send()
        .await
        .expect("reply");
    assert_eq!(res.status(), 204);

    let res = s
        .http
        .get(s.url(&format!("/v1/guest/{id}/replies")))
        .send()
        .await
        .expect("replies no token");
    assert_eq!(res.status(), 400);
    let res = s
        .http
        .get(s.url(&format!(
            "/v1/guest/{id}/replies?token=wrongwrongwrongwrong"
        )))
        .send()
        .await
        .expect("replies wrong token");
    assert_eq!(res.status(), 401);
    let res = s
        .http
        .get(s.url(&format!("/v1/guest/{id}/replies?token={pickup}")))
        .send()
        .await
        .expect("replies");
    assert_eq!(res.status(), 200);
    let replies: Value = res.json().await.expect("json");
    let list = replies["replies"].as_array().expect("array");
    assert_eq!(list.len(), 1);
    let stored = list[0]["ciphertext_armored"].as_str().expect("ct");
    assert_eq!(gpg.decrypt(stored, None), b"thanks, got it\n");

    // Unknown / malformed ids.
    for path in [
        "/v1/guest/AbCdEfGhIjKlMnOpQrStUv",
        "/v1/guest/short",
        "/v1/guest/../etc",
    ] {
        let res = s.http.get(s.url(path)).send().await.expect(path);
        assert_eq!(res.status(), 404, "{path}");
    }

    // Expiry: a 1-second message disappears, and the purge removes the row.
    let res = s
        .http
        .post(s.url("/v1/guest"))
        .json(&json!({ "ciphertext_armored": ciphertext, "expires_in_secs": 1 }))
        .send()
        .await
        .expect("post short");
    assert_eq!(res.status(), 201);
    let short: Value = res.json().await.expect("json");
    let short_id = short["id"].as_str().expect("id").to_owned();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let res = s
        .http
        .get(s.url(&format!("/v1/guest/{short_id}")))
        .send()
        .await
        .expect("fetch expired");
    assert_eq!(res.status(), 404, "expired message must be invisible");
    let res = s
        .http
        .post(s.url(&format!("/v1/guest/{short_id}/reply")))
        .json(&json!({ "ciphertext_armored": reply_ct }))
        .send()
        .await
        .expect("reply expired");
    assert_eq!(res.status(), 404);
    let purged = s.state.purge_expired().await.expect("purge");
    assert!(
        purged.guest_messages >= 1,
        "purge removed the expired row: {purged:?}"
    );
    let res = s
        .http
        .get(s.url(&format!("/v1/guest/{short_id}")))
        .send()
        .await
        .expect("fetch purged");
    assert_eq!(res.status(), 404);
    // The long-lived one is untouched.
    let res = s
        .http
        .get(s.url(&format!("/v1/guest/{id}")))
        .send()
        .await
        .expect("fetch live");
    assert_eq!(res.status(), 200);
    s.stop().await;
}

// ------------------------------------------------------------------------------------------
// Backups
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn backup_put_requires_valid_signature() {
    let s = TestServer::start().await;
    let gpg = Gpg::new();
    gpg.gen_key("Alice Backup <alice-backup@sealbox.test>");
    gpg.gen_key("Bob Backup <bob-backup@sealbox.test>");
    let alice_pub = gpg.export_pub("alice-backup@sealbox.test");
    let alice_fpr = gpg.fingerprint("alice-backup@sealbox.test");
    let bob_pub = gpg.export_pub("bob-backup@sealbox.test");
    let bob_fpr = gpg.fingerprint("bob-backup@sealbox.test");

    // Alice's key is known to the directory (upload only; publication is not required).
    let res = s
        .http
        .post(s.url("/vks/v1/upload"))
        .json(&json!({ "keytext": alice_pub }))
        .send()
        .await
        .expect("upload");
    assert_eq!(res.status(), 200);

    let blob: Vec<u8> = (0..4096u32).map(|i| (i * 7 % 251) as u8).collect();
    let good_sig = gpg.detach_sign("alice-backup@sealbox.test", &blob);
    let other_sig = gpg.detach_sign("alice-backup@sealbox.test", b"something else");
    let b64 = |s: &str| STANDARD.encode(s.as_bytes());

    // Missing signature → 400; signature over other data → 401; nonsense signature → 401.
    let res = s
        .http
        .put(s.url(&format!("/v1/backup/{alice_fpr}")))
        .body(blob.clone())
        .send()
        .await
        .expect("put no sig");
    assert_eq!(res.status(), 400);
    let res = s
        .http
        .put(s.url(&format!("/v1/backup/{alice_fpr}")))
        .header(SIGNATURE_HEADER, b64(&other_sig))
        .body(blob.clone())
        .send()
        .await
        .expect("put bad sig");
    assert_eq!(res.status(), 401);
    let res = s
        .http
        .put(s.url(&format!("/v1/backup/{alice_fpr}")))
        .header(SIGNATURE_HEADER, STANDARD.encode(b"not a signature at all"))
        .body(blob.clone())
        .send()
        .await
        .expect("put garbage sig");
    assert_eq!(res.status(), 401);
    let res = s
        .http
        .get(s.url(&format!("/v1/backup/{alice_fpr}?token=whatever-whatever")))
        .send()
        .await
        .expect("get none");
    assert_eq!(res.status(), 404);

    // Good signature → stored, token issued.
    let res = s
        .http
        .put(s.url(&format!("/v1/backup/{alice_fpr}")))
        .header(SIGNATURE_HEADER, b64(&good_sig))
        .body(blob.clone())
        .send()
        .await
        .expect("put good");
    assert_eq!(
        res.status(),
        200,
        "{}",
        res.text().await.unwrap_or_default()
    );
    let put: Value = res.json().await.expect("json");
    assert_eq!(put["ok"], true);
    assert_eq!(put["fingerprint"], alice_fpr);
    assert_eq!(put["size"], blob.len());
    let token = put["backup_token"].as_str().expect("token").to_owned();

    // GET: wrong token 401, right token → identical bytes.
    let res = s
        .http
        .get(s.url(&format!(
            "/v1/backup/{alice_fpr}?token=wrong-token-wrong-token"
        )))
        .send()
        .await
        .expect("get wrong");
    assert_eq!(res.status(), 401);
    let res = s
        .http
        .get(s.url(&format!("/v1/backup/{alice_fpr}?token={token}")))
        .send()
        .await
        .expect("get");
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["content-type"], "application/octet-stream");
    assert_eq!(res.bytes().await.expect("bytes").to_vec(), blob);

    // Bob is unknown: needs X-Sealbox-Key on the first PUT, and may choose his own token.
    let bob_blob = b"bob's encrypted backup".to_vec();
    let bob_sig = gpg.detach_sign("bob-backup@sealbox.test", &bob_blob);
    let res = s
        .http
        .put(s.url(&format!("/v1/backup/{bob_fpr}")))
        .header(SIGNATURE_HEADER, b64(&bob_sig))
        .body(bob_blob.clone())
        .send()
        .await
        .expect("put bob no key");
    assert_eq!(res.status(), 400);
    // Key with the wrong fingerprint for the slot → 400.
    let res = s
        .http
        .put(s.url(&format!("/v1/backup/{bob_fpr}")))
        .header(SIGNATURE_HEADER, b64(&bob_sig))
        .header(KEY_HEADER, b64(&alice_pub))
        .body(bob_blob.clone())
        .send()
        .await
        .expect("put bob wrong key");
    assert_eq!(res.status(), 400);
    let res = s
        .http
        .put(s.url(&format!("/v1/backup/{bob_fpr}")))
        .header(SIGNATURE_HEADER, b64(&bob_sig))
        .header(KEY_HEADER, b64(&bob_pub))
        .header(TOKEN_HEADER, "bob-chosen-recovery-token-0001")
        .body(bob_blob.clone())
        .send()
        .await
        .expect("put bob");
    assert_eq!(
        res.status(),
        200,
        "{}",
        res.text().await.unwrap_or_default()
    );
    let put: Value = res.json().await.expect("json");
    assert_eq!(put["backup_token"], "bob-chosen-recovery-token-0001");
    let res = s
        .http
        .get(s.url(&format!(
            "/v1/backup/{bob_fpr}?token=bob-chosen-recovery-token-0001"
        )))
        .send()
        .await
        .expect("get bob");
    assert_eq!(res.status(), 200);
    assert_eq!(res.bytes().await.expect("bytes").to_vec(), bob_blob);

    // The slot is pinned to Bob's key: Alice signing under Bob's fingerprint is refused, even
    // if she presents her own key in the header.
    let alice_over_bob = gpg.detach_sign("alice-backup@sealbox.test", &bob_blob);
    let res = s
        .http
        .put(s.url(&format!("/v1/backup/{bob_fpr}")))
        .header(SIGNATURE_HEADER, b64(&alice_over_bob))
        .header(KEY_HEADER, b64(&alice_pub))
        .body(bob_blob.clone())
        .send()
        .await
        .expect("put alice over bob");
    assert_eq!(res.status(), 401);
    s.stop().await;
}

// ------------------------------------------------------------------------------------------
// Hygiene: body limit and per-IP rate limit
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn oversized_bodies_and_floods_are_rejected() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    let s = TestServer::start().await;
    let limit = s.state.limits().max_body_bytes;

    // In-process (no socket), so the 413 is observed deterministically.
    let app = sealbox_server::app(s.state.clone());
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/backup/0000000000000000000000000000000000000000")
                .header(SIGNATURE_HEADER, "AAAA")
                .body(Body::from(vec![b'x'; limit + 1]))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(res.status(), 413);
    let mut big_json = String::with_capacity(limit + 64);
    big_json.push_str("{\"ciphertext_armored\":\"");
    big_json.extend(std::iter::repeat_n('a', limit + 1));
    big_json.push_str("\"}");
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/guest")
                .header("content-type", "application/json")
                .body(Body::from(big_json))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(res.status(), 413);

    // Challenge-link guesses from one IP are capped per hour.
    let cap = s.state.limits().verify_attempts_per_hour;
    for i in 0..cap {
        let res = s
            .http
            .get(s.url("/vks/v1/verify/not-a-real-challenge-token-0000"))
            .send()
            .await
            .expect("verify");
        assert_eq!(res.status(), 404, "attempt {i}");
    }
    let res = s
        .http
        .get(s.url("/vks/v1/verify/not-a-real-challenge-token-0000"))
        .send()
        .await
        .expect("verify over cap");
    assert_eq!(res.status(), 429);
    s.stop().await;
}

// ------------------------------------------------------------------------------------------
// Browser viewer
// ------------------------------------------------------------------------------------------

fn on_path(bin: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {bin} >/dev/null 2>&1")])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn viewer_node_interop_test() {
    if !on_path("node") {
        eprintln!("SKIP: node not on PATH; viewer interop test not run");
        return;
    }
    let out = Command::new("node")
        .args(["--test", "web/guest/test/viewer.test.mjs"])
        .current_dir(repo_root())
        .env(
            "CARGO_TARGET_DIR",
            scratch_dir().parent().expect("target dir"),
        )
        .output()
        .expect("run node --test");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "node --test failed\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(stdout.contains("# fail 0"), "node test summary: {stdout}");
    let passed = stdout
        .lines()
        .find(|l| l.starts_with("# pass "))
        .unwrap_or("# pass ?");
    eprintln!("viewer.test.mjs: {passed}");
}

/// The real thing: headless Chromium opens `/g/{id}#passphrase` and the DOM must contain the
/// decrypted text. Skipped (loudly) when no Chromium/Chrome binary is installed.
#[tokio::test]
async fn viewer_decrypts_in_headless_chromium() {
    let browser = [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
    ]
    .into_iter()
    .find(|b| on_path(b));
    let Some(browser) = browser else {
        eprintln!("SKIP: no chromium/google-chrome on PATH; headless viewer check not run");
        return;
    };
    let s = TestServer::start().await;
    let gpg = Gpg::new();
    let marker = "SEALBOX-G7-PLAINTEXT-OK";
    let plaintext = format!("Headless check {marker}\nline two <not html>\n");
    let ciphertext = gpg.symmetric("correct horse battery", plaintext.as_bytes());
    let res = s
        .http
        .post(s.url("/v1/guest"))
        .json(&json!({ "ciphertext_armored": ciphertext, "expires_in_secs": 600 }))
        .send()
        .await
        .expect("post");
    assert_eq!(res.status(), 201);
    let created: Value = res.json().await.expect("json");
    let id = created["id"].as_str().expect("id").to_owned();
    let page = format!("{}#correct%20horse%20battery", s.url(&format!("/g/{id}")));

    let profile = tempfile::Builder::new()
        .prefix("chromium-")
        .tempdir_in(scratch_dir())
        .expect("profile dir");
    let page_for_task = page.clone();
    let profile_path = profile.path().to_path_buf();
    let out = tokio::task::spawn_blocking(move || {
        Command::new(browser)
            .args([
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                "--no-first-run",
                "--disable-extensions",
                "--virtual-time-budget=30000",
                "--dump-dom",
            ])
            .arg(format!("--user-data-dir={}", profile_path.display()))
            .arg(&page_for_task)
            .output()
    })
    .await
    .expect("join")
    .expect("run browser");
    let dom = String::from_utf8_lossy(&out.stdout);
    assert!(
        dom.contains(marker),
        "headless browser did not show the decrypted text.\nstatus: {}\n--- dom ---\n{}\n--- stderr ---\n{}",
        out.status,
        dom.chars().take(4000).collect::<String>(),
        String::from_utf8_lossy(&out.stderr).chars().take(2000).collect::<String>()
    );
    assert!(
        dom.contains("&lt;not html&gt;"),
        "plaintext must be rendered escaped, got: {}",
        dom.chars().take(4000).collect::<String>()
    );
    assert!(
        dom.contains("Decrypted in your browser"),
        "status line missing"
    );
    eprintln!("headless {browser}: viewer decrypted the guest message");
    s.stop().await;
}
