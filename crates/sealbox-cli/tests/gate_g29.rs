//! Gate G29 — guest-link modes end to end: the real `sealbox` binary sends through GreenMail,
//! a real `sealbox-server` (started by `scripts/gate_g29.sh` on an ephemeral port, mailing its
//! codes through GreenMail SMTP) stores the ciphertext, and the real viewer runs in headless
//! Chromium (`web/guest/test/drive.mjs`). GreenMail users u41 (sender) … u45.
//!
//! (a) default passphrase mode: the notification in the recipient's INBOX has the bare link
//!     and not the passphrase, says so, and the viewer opens only with the passphrase;
//! (b) one-click: fragment in the link, the mail warns, the viewer auto-decrypts;
//! (c) email-code: GET without a token is 401, the code arrives by mail, five wrong codes
//!     lock, after the lock a fresh code yields a token and the viewer decrypts;
//! (d) an expired message is refused (API, viewer, resend);
//! (e) `sealbox guest resend` mails a second notification for the same id;
//! (f) no plaintext, passphrase or recipient address in the server's SQLite file.
//!
//! Run via `scripts/gate_g29.sh` (needs `testing/mail_up.sh`), which sets
//! `SEALBOX_G29_SERVER`, `SEALBOX_G29_DB` and `SEALBOX_G29_LOCK_SECS`.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{imap_login, nonce, Profile, Run};
use serde_json::{json, Value};

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} not set; run scripts/gate_g29.sh"))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

/// Run the CLI with the guest server configured.
fn run_with_server(p: &Profile, server: &str, args: &[&str]) -> Run {
    let mut full = vec!["--json"];
    full.extend_from_slice(args);
    let out = p
        .cmd(&full)
        .env("SEALBOX_SERVER_URL", server)
        .output()
        .expect("spawn sealbox");
    let r = Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    eprintln!(
        "[{}] sealbox {} -> {}\n{}{}",
        p.name,
        full.join(" "),
        r.code,
        r.stdout,
        r.stderr
    );
    r
}

fn ok_json(p: &Profile, server: &str, args: &[&str]) -> Value {
    let r = run_with_server(p, server, args);
    assert_eq!(
        r.code, 0,
        "sealbox {args:?} failed: {}{}",
        r.stdout, r.stderr
    );
    r.json()
}

/// Decoded text body of a plain message.
fn text_of(raw: &[u8]) -> String {
    match sealbox_mail::mime::parse(raw).expect("parse mail").kind {
        sealbox_mail::mime::MessageKind::Plain(b) => b.text.unwrap_or_default(),
        other => panic!("notification is not a plain mail: {other:?}"),
    }
}

fn subject_of(raw: &[u8]) -> String {
    sealbox_mail::mime::parse(raw)
        .ok()
        .and_then(|m| m.headers.subject)
        .unwrap_or_default()
}

/// Every message in `user`'s INBOX with exactly `subject`, oldest first, as (uid, raw).
async fn mails_with_subject(user: &str, subject: &str) -> Vec<(u32, Vec<u8>)> {
    let mut imap = imap_login(user).await;
    imap.select("INBOX").await.expect("select");
    let uids = imap.fetch_new_uids(0).await.expect("uids");
    let mut out = Vec::new();
    for chunk in uids.chunks(50) {
        for m in imap.fetch_rfc822_batch(chunk).await.expect("fetch") {
            if subject_of(&m.raw) == subject {
                out.push((m.uid, m.raw));
            }
        }
    }
    let _ = imap.logout().await;
    out.sort_by_key(|(u, _)| *u);
    out
}

async fn wait_for_mails(user: &str, subject: &str, n: usize) -> Vec<(u32, Vec<u8>)> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let found = mails_with_subject(user, subject).await;
        if found.len() >= n {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "{user}: expected {n} mail(s) with subject {subject:?}, have {}",
            found.len()
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

fn six_digits(s: &str) -> Option<String> {
    s.split(|c: char| !c.is_ascii_digit())
        .find(|w| w.len() == 6)
        .map(str::to_owned)
}

/// The newest "Your Sealbox code" mail in `user`'s INBOX with a UID above `after`.
async fn next_code(user: &str, after: u32) -> (u32, String) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mails = mails_with_subject(user, "Your Sealbox code").await;
        if let Some((uid, raw)) = mails.into_iter().rfind(|(u, _)| *u > after) {
            if let Some(code) = six_digits(&text_of(&raw)) {
                return (uid, code);
            }
        }
        assert!(Instant::now() < deadline, "no code mail reached {user}");
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

async fn last_code_uid(user: &str) -> u32 {
    mails_with_subject(user, "Your Sealbox code")
        .await
        .last()
        .map(|(u, _)| *u)
        .unwrap_or(0)
}

fn browser() -> &'static str {
    [
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
    ]
    .into_iter()
    .find(|b| Path::new(b).exists())
    .expect("G29 needs chromium or google-chrome")
}

/// Run `drive.mjs` with `plan`; `on_need` answers `NEED <name>` prompts.
async fn drive<F, Fut>(plan: Value, mut on_need: F) -> Value
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = String>,
{
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join("target"));
    let mut child = Command::new("node")
        .arg(repo_root().join("web/guest/test/drive.mjs"))
        .args(["--browser", browser(), "--plan", &plan.to_string()])
        .env("CARGO_TARGET_DIR", target)
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
    eprintln!("viewer ({what}): ok");
}

fn db_bytes(path: &str) -> Vec<u8> {
    let mut all = std::fs::read(path).unwrap_or_default();
    for ext in ["-wal", "-shm"] {
        all.extend(std::fs::read(format!("{path}{ext}")).unwrap_or_default());
    }
    all
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

async fn http_get(url: &str) -> (u16, Value) {
    let r = reqwest::get(url).await.expect("GET");
    let s = r.status().as_u16();
    (s, r.json().await.unwrap_or(Value::Null))
}

async fn http_post(url: &str, body: Value) -> (u16, Value) {
    let r = reqwest::Client::new()
        .post(url)
        .json(&body)
        .send()
        .await
        .expect("POST");
    let s = r.status().as_u16();
    (s, r.json().await.unwrap_or(Value::Null))
}

fn guest_id(url: &str) -> String {
    url.rsplit_once("/g/")
        .map(|(_, r)| r.split('#').next().unwrap_or(r).to_owned())
        .expect("guest id in url")
}

#[tokio::test]
#[ignore = "needs GreenMail (testing/mail_up.sh) and a server from scripts/gate_g29.sh"]
async fn guest_link_modes_end_to_end() {
    let server = env("SEALBOX_G29_SERVER");
    let server_db = env("SEALBOX_G29_DB");
    let lock_secs: u64 = env("SEALBOX_G29_LOCK_SECS").parse().expect("lock secs");
    let sender = Profile::new("u41");
    sender.add_greenmail_account("u41");
    let tag = nonce("g29");
    let mut secrets: Vec<String> = Vec::new();
    let mut markers: Vec<String> = Vec::new();

    let send = |to: &str, subject: &str, body: &str, extra: &[&str]| {
        let mut args = vec![
            "send",
            "--from",
            "u41@sealbox.test",
            "--to",
            to,
            "--subject",
            subject,
            "--body",
            body,
            "--policy",
            "guest",
        ];
        args.extend_from_slice(extra);
        ok_json(&sender, &server, &args)
    };

    // ---------------------------------------------------------------- (a) passphrase (default)
    let subj_a = format!("G29 passphrase {tag}");
    let marker_a = format!("G29-A-PLAINTEXT-{tag}");
    let rep_a = send("u42@sealbox.test", &subj_a, &marker_a, &[]);
    let g = &rep_a["guest"];
    assert_eq!(rep_a["mode"], "guest_link");
    assert_eq!(g["mode"], "passphrase");
    assert_eq!(g["secret_in_link"], false);
    assert_eq!(g["recipient_verification"], false);
    let link_a = g["url"].as_str().expect("url").to_owned();
    let pass_a = g["passphrase"].as_str().expect("passphrase").to_owned();
    assert!(
        !link_a.contains('#'),
        "default link must not carry a secret: {link_a}"
    );
    assert!(link_a.starts_with(&format!("{server}/g/")));
    secrets.push(pass_a.clone());
    markers.push(marker_a.clone());

    let mails = wait_for_mails("u42", &subj_a, 1).await;
    let raw = &mails[0].1;
    let text = text_of(raw);
    for form in [
        pass_a.clone(),
        pass_a.replace('-', ""),
        pass_a.replace('-', "%2D"),
    ] {
        assert!(
            !contains(raw, &form),
            "raw notification contains the passphrase"
        );
        assert!(
            !text.contains(&form),
            "notification text contains the passphrase"
        );
    }
    assert!(
        text.lines().any(|l| l.trim() == link_a),
        "link line missing:\n{text}"
    );
    assert!(text.contains("To read it you need a passphrase. This e-mail does not contain it"));
    assert!(text.contains("another way (in person, by phone or in a chat)"));
    assert!(
        !text.contains(&marker_a),
        "plaintext leaked into the notification"
    );
    eprintln!("(a) notification:\n{text}");

    let r = drive(
        json!({ "secrets": [pass_a], "steps": [
            { "open": link_a },
            { "waitVisible": "#unlock" },
            { "assertNoText": marker_a },
            { "fill": "#passphrase", "value": "aaaa-bbbb-cccc-dddd-eeee" },
            { "submit": "#unlock" },
            { "waitText": "does not open this message" },
            { "assertNoText": marker_a },
            { "fill": "#passphrase", "value": pass_a },
            { "submit": "#unlock" },
            { "waitText": marker_a },
        ]}),
        |_| async { String::new() },
    )
    .await;
    assert_driver_ok(&r, "(a) passphrase");

    // ---------------------------------------------------------------- (b) one-click
    let subj_b = format!("G29 one-click {tag}");
    let marker_b = format!("G29-B-PLAINTEXT-{tag}");
    let rep_b = send(
        "u43@sealbox.test",
        &subj_b,
        &marker_b,
        &["--guest-mode", "one-click"],
    );
    let g = &rep_b["guest"];
    assert_eq!(g["mode"], "one_click");
    assert_eq!(g["secret_in_link"], true);
    let link_b = g["url"].as_str().expect("url").to_owned();
    let pass_b = g["passphrase"].as_str().expect("passphrase").to_owned();
    assert!(link_b.contains('#'), "one-click link needs the fragment");
    secrets.push(pass_b.clone());
    markers.push(marker_b.clone());
    let mails = wait_for_mails("u43", &subj_b, 1).await;
    let text = text_of(&mails[0].1);
    assert!(
        text.lines().any(|l| l.trim() == link_b),
        "link line missing:\n{text}"
    );
    assert!(text.contains("Anyone who has the link"));
    assert!(text.contains("can read the message"));
    assert!(text.contains("not from people who can see this e-mail"));
    let r = drive(
        json!({ "secrets": [pass_b], "steps": [
            { "open": link_b },
            { "waitText": marker_b },
            { "waitText": "anyone who has the link can read it" },
            { "assertUrlNoFragment": true },
        ]}),
        |_| async { String::new() },
    )
    .await;
    assert_driver_ok(&r, "(b) one-click");

    // ---------------------------------------------------------------- (c) email code
    let subj_c = format!("G29 email-code {tag}");
    let marker_c = format!("G29-C-PLAINTEXT-{tag}");
    let rep_c = send(
        "u44@sealbox.test",
        &subj_c,
        &marker_c,
        &["--guest-mode", "email-code"],
    );
    let g = &rep_c["guest"];
    assert_eq!(g["mode"], "email_code");
    assert_eq!(g["secret_in_link"], true);
    assert_eq!(g["recipient_verification"], true);
    let link_c = g["url"].as_str().expect("url").to_owned();
    let pass_c = g["passphrase"].as_str().expect("passphrase").to_owned();
    secrets.push(pass_c.clone());
    markers.push(marker_c.clone());
    let id_c = guest_id(&link_c);
    let mails = wait_for_mails("u44", &subj_c, 1).await;
    let text = text_of(&mails[0].1);
    assert!(text.contains("e-mails a one-time code to u44@sealbox.test"));
    assert!(text.contains("does not protect it from anyone who can read the u44@sealbox.test"));

    let (st, body) = http_get(&format!("{server}/v1/guest/{id_c}")).await;
    assert_eq!(st, 401);
    assert_eq!(body["error"], "verification_required");

    let before = last_code_uid("u44").await;
    let (st, _) = http_post(
        &format!("{server}/v1/guest/{id_c}/send-code"),
        json!({ "email": "u44@sealbox.test" }),
    )
    .await;
    assert_eq!(st, 202);
    let (uid1, code1) = next_code("u44", before).await;
    let wrong = if code1 == "000001" {
        "000002"
    } else {
        "000001"
    };
    for left in (1..=4).rev() {
        let (st, body) = http_post(
            &format!("{server}/v1/guest/{id_c}/verify"),
            json!({ "code": wrong }),
        )
        .await;
        assert_eq!((st, body["attempts_left"].as_i64()), (401, Some(left)));
    }
    let (st, body) = http_post(
        &format!("{server}/v1/guest/{id_c}/verify"),
        json!({ "code": wrong }),
    )
    .await;
    assert_eq!((st, body["error"].as_str()), (429, Some("locked")));
    let (st, _) = http_post(
        &format!("{server}/v1/guest/{id_c}/verify"),
        json!({ "code": code1 }),
    )
    .await;
    assert_eq!(st, 429, "the right code must not work while locked");
    tokio::time::sleep(Duration::from_secs(lock_secs + 1)).await;
    let (st, _) = http_post(
        &format!("{server}/v1/guest/{id_c}/send-code"),
        json!({ "email": "u44@sealbox.test" }),
    )
    .await;
    assert_eq!(st, 202);
    let (uid2, code2) = next_code("u44", uid1).await;
    let (st, body) = http_post(
        &format!("{server}/v1/guest/{id_c}/verify"),
        json!({ "code": code2 }),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    let token = body["access_token"].as_str().expect("token");
    let (st, body) = http_get(&format!("{server}/v1/guest/{id_c}?token={token}")).await;
    assert_eq!(st, 200);
    assert!(body["ciphertext_armored"].as_str().is_some());

    // The viewer: address → code (read from the u44 INBOX over IMAP) → decrypt.
    let mut seen = uid2;
    let r = drive(
        json!({ "secrets": [pass_c], "steps": [
            { "open": link_c },
            { "waitVisible": "#gate-email" },
            { "assertNoText": marker_c },
            { "fill": "#gate-address", "value": "u44@sealbox.test" },
            { "submit": "#gate-email" },
            { "waitVisible": "#gate-code" },
            { "fillFromStdin": "#gate-code-input", "name": "code" },
            { "submit": "#gate-code" },
            { "waitText": marker_c, "timeoutMs": 30000 },
        ]}),
        |_| {
            let after = seen;
            async move {
                let (uid, code) = next_code("u44", after).await;
                let _ = uid;
                code
            }
        },
    )
    .await;
    assert_driver_ok(&r, "(c) email-code");
    seen = last_code_uid("u44").await;
    assert!(seen > uid2, "the viewer's code mail was not delivered");

    // ---------------------------------------------------------------- (d) expiry
    let subj_d = format!("G29 expiry {tag}");
    let marker_d = format!("G29-D-PLAINTEXT-{tag}");
    let rep_d = send(
        "u45@sealbox.test",
        &subj_d,
        &marker_d,
        &["--guest-mode", "one-click", "--guest-expiry", "2"],
    );
    let link_d = rep_d["guest"]["url"].as_str().expect("url").to_owned();
    secrets.push(
        rep_d["guest"]["passphrase"]
            .as_str()
            .expect("pass")
            .to_owned(),
    );
    markers.push(marker_d.clone());
    tokio::time::sleep(Duration::from_secs(4)).await;
    let (st, _) = http_get(&format!("{server}/v1/guest/{}", guest_id(&link_d))).await;
    assert_eq!(st, 404, "expired message must be refused");
    let r = drive(
        json!({ "secrets": [secrets.last()], "steps": [
            { "open": link_d },
            { "waitText": "has expired or does not exist" },
            { "assertNoText": marker_d },
        ]}),
        |_| async { String::new() },
    )
    .await;
    assert_driver_ok(&r, "(d) expired");
    let mid_d = rep_d["message_id"].as_str().expect("mid");
    let r = run_with_server(&sender, &server, &["guest", "resend", mid_d]);
    assert_ne!(r.code, 0, "resending an expired guest link must fail");
    assert!(r.stdout.contains("expired"), "{}", r.stdout);

    // ---------------------------------------------------------------- (e) resend
    let mid_a = rep_a["message_id"].as_str().expect("mid").to_owned();
    let rep_e = ok_json(&sender, &server, &["guest", "resend", &mid_a]);
    assert_ne!(rep_e["message_id"], rep_a["message_id"]);
    assert_eq!(rep_e["guest"]["url"], link_a.as_str());
    assert_eq!(rep_e["guest"]["mode"], "passphrase");
    let mails = wait_for_mails("u42", &subj_a, 2).await;
    assert_eq!(mails.len(), 2, "exactly one extra notification");
    for (_, raw) in &mails {
        let t = text_of(raw);
        assert!(t.lines().any(|l| l.trim() == link_a), "same link in both");
        assert!(
            !contains(raw, &pass_a),
            "resent notification contains the passphrase"
        );
    }
    // Resend by guest id works too and for the one-click link keeps the fragment.
    let rep_e2 = ok_json(&sender, &server, &["guest", "resend", &guest_id(&link_b)]);
    assert_eq!(rep_e2["guest"]["url"], link_b.as_str());
    wait_for_mails("u43", &subj_b, 2).await;

    // ---------------------------------------------------------------- (f) server database
    let bytes = db_bytes(&server_db);
    assert!(
        !bytes.is_empty(),
        "server database {server_db} is empty or missing"
    );
    for s in &secrets {
        assert!(
            !contains(&bytes, s),
            "a guest secret is in the server database"
        );
    }
    for m in &markers {
        assert!(
            !contains(&bytes, m),
            "plaintext {m} is in the server database"
        );
    }
    for addr in [
        "u42@sealbox.test",
        "u43@sealbox.test",
        "u44@sealbox.test",
        "u45@sealbox.test",
    ] {
        assert!(
            !contains(&bytes, addr),
            "recipient {addr} is in the server database"
        );
    }
    for c in [&code1, &code2] {
        // A 6-digit code could appear by chance inside base64; only flag it as text.
        assert!(
            !contains(&bytes, &format!("\"{c}\"")),
            "a code is in the server database"
        );
    }
    eprintln!("G29: all six checks passed");
}
