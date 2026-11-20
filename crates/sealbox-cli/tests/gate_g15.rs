//! Gate G15 — recovery & multi-device, through the real `sealbox` binary against GreenMail
//! (users u56–u60) and an in-process `sealbox-server` on an ephemeral port.
//!
//! (1) A (u56) and Bob (u57) exchange encrypted mail.
//! (2) A creates a recovery phrase and backs up to the server.
//! (3) A wrong phrase is refused (server 401, CLI exit 4) and leaves no state; a phrase with a
//!     bad checksum is refused before any network.
//! (4) A FRESH profile B restores with the phrase + the mail password; B syncs and decrypts
//!     the old mail, Bob is still a known contact, settings came back, B sends encrypted.
//! (5) A second backup with a new phrase overwrites the first (old phrase → 401, new content).
//! (6) Restore without credentials via the server's key directory, then `set-password`.
//! (7) Autocrypt Setup Message export from A → import into fresh profile C with the code →
//!     C decrypts; a wrong code changes nothing.
//! (8) The server database holds no plaintext, no secret key, no phrase.
//!
//! Run: `testing/mail_up.sh && cargo test -p sealbox-cli --test gate_g15 -- --ignored`

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use sealbox_server::mail::MemoryMailSink;
use sealbox_server::{AppState, Limits, StateOptions};
use serde_json::{json, Value};
use tokio::net::TcpListener;

const A: &str = "u56@sealbox.test";
const BOB: &str = "u57@sealbox.test";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct Server {
    base: String,
    db: PathBuf,
    sink: Arc<MemoryMailSink>,
    _dir: tempfile::TempDir,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn start_server() -> Server {
    let dir = tempfile::Builder::new()
        .prefix("sealbox-g15-srv-")
        .tempdir()
        .expect("tempdir");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let sink = MemoryMailSink::new();
    let db = dir.path().join("g15.sqlite");
    let state = AppState::new(StateOptions {
        db_path: db.clone(),
        public_url: base.clone(),
        static_dir: repo_root().join("web/guest"),
        mailer: sink.clone(),
        trust_proxy: false,
        limits: Limits::default(),
    })
    .expect("server state");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(sealbox_server::serve(listener, state, async move {
        let _ = rx.await;
    }));
    Server {
        base,
        db,
        sink,
        _dir: dir,
        _shutdown: tx,
    }
}

/// `--json` run with extra environment, exit 0 required.
fn jenv(p: &Profile, args: &[&str], env: &[(&str, Option<&str>)]) -> Value {
    let mut full = vec!["--json"];
    full.extend_from_slice(args);
    let r = p.run_env(&full, env);
    assert_eq!(
        r.code,
        0,
        "sealbox {} failed:\n{}\n{}",
        full.join(" "),
        r.stdout,
        r.stderr
    );
    r.json()
}

fn words(v: &Value) -> String {
    v["words"]
        .as_array()
        .expect("words")
        .iter()
        .map(|w| w.as_str().expect("word"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn send(p: &Profile, from: &str, to: &str, subject: &str, body: &str, policy: &str) -> Value {
    p.json(&[
        "send",
        "--from",
        from,
        "--to",
        to,
        "--subject",
        subject,
        "--body",
        body,
        "--policy",
        policy,
    ])
}

/// Sync until a message with `mid` is stored; returns its summary.
async fn wait_mid(p: &Profile, account: &str, mid: &str) -> Value {
    let mut found = None;
    let ok = wait_until(Duration::from_secs(30), || {
        p.sync(account);
        found = p
            .list(Some(account), "*")
            .into_iter()
            .find(|m| m["message_id"].as_str() == Some(mid));
        let hit = found.is_some();
        async move { hit }
    })
    .await;
    assert!(ok, "[{}] message <{mid}> never arrived", p.name);
    found.expect("found")
}

fn read_text(p: &Profile, m: &Value) -> String {
    let id = m["id"].as_i64().expect("id").to_string();
    let r = p.json(&["read", &id]);
    r["text"].as_str().unwrap_or_default().to_string()
}

fn accounts(p: &Profile) -> Vec<Value> {
    p.json(&["account", "list"])
        .as_array()
        .cloned()
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn recovery_backup_restore_and_setup_message() {
    let srv = start_server().await;
    let server = srv.base.as_str();
    let tag = nonce("g15");
    eprintln!("G15 server {server}, tag {tag}");

    // ------------------------------------------------------------- (1) encrypted exchange
    let a = Profile::new("a");
    let bob = Profile::new("bob");
    a.add_greenmail_account("u56");
    bob.add_greenmail_account("u57");
    let a_fpr = a.fingerprint(A);
    let bob_fpr = bob.fingerprint(BOB);

    let hello = send(
        &bob,
        BOB,
        A,
        &format!("hello {tag}"),
        "first contact",
        "plaintext",
    );
    wait_mid(&a, A, hello["message_id"].as_str().unwrap()).await;

    let s1_body = format!("old secret one {tag}");
    let s1 = send(&a, A, BOB, &format!("s1 {tag}"), &s1_body, "require");
    assert_eq!(s1["mode"], "encrypted", "{s1}");
    let s1_mid = s1["message_id"].as_str().unwrap().to_string();
    let m = wait_mid(&bob, BOB, &s1_mid).await;
    assert_eq!(read_text(&bob, &m).trim(), s1_body);

    let s2_body = format!("old secret two {tag}");
    let s2 = send(&bob, BOB, A, &format!("s2 {tag}"), &s2_body, "require");
    assert_eq!(s2["mode"], "encrypted", "{s2}");
    let s2_mid = s2["message_id"].as_str().unwrap().to_string();
    let m = wait_mid(&a, A, &s2_mid).await;
    assert_eq!(m["decrypted"], true);
    println!("G15 (1) encrypted exchange u56<->u57: ok (A key {a_fpr})");

    // Settings that must survive: signature, spam allowlist.
    {
        let e = a.engine();
        let mut sig = e.get_signature(A).unwrap();
        sig.enabled = true;
        sig.text = format!("sig-v1 {tag}");
        e.set_signature(A, sig).unwrap();
        e.spam_allow(A, "friend@sealbox.test", true).unwrap();
    }

    // ------------------------------------------------------------- (2) phrase + backup
    let p1v = a.json(&["recovery", "phrase", "--account", A]);
    assert_eq!(p1v["checksum_ok"], true);
    let p1 = words(&p1v);
    assert_eq!(p1.split(' ').count(), 12);
    let p1env = [("G15_PHRASE", Some(p1.as_str()))];
    let v = jenv(
        &a,
        &["recovery", "validate", "--phrase-env", "G15_PHRASE"],
        &p1env,
    );
    assert_eq!(v["checksum_ok"], true);
    let b1 = jenv(
        &a,
        &[
            "recovery",
            "backup",
            "--account",
            A,
            "--server",
            server,
            "--phrase-env",
            "G15_PHRASE",
        ],
        &p1env,
    );
    assert_eq!(b1["fingerprint"], a_fpr.as_str());
    let b1_bytes = b1["bytes"].as_u64().unwrap();
    assert!(b1_bytes > 1000, "{b1}");
    let st = a.json(&["recovery", "status", "--account", A]);
    assert_eq!(st["last_backup"]["fingerprint"], a_fpr.as_str());
    assert!(st["reminder"].is_null(), "{st}");
    println!(
        "G15 (2) phrase (12 words, checksum ok) + backup: ok ({b1_bytes} bytes, slot {a_fpr})"
    );

    // ------------------------------------------------------------- (3) wrong phrase
    let wrong = words(&a.json(&["recovery", "phrase", "--account", A])); // valid, but not P1
    assert_ne!(wrong, p1);
    let w = Profile::new("w");
    let restore_args = |phrase_var: &str| -> Vec<String> {
        [
            "recovery",
            "restore",
            "--email",
            A,
            "--server",
            server,
            "--phrase-env",
            phrase_var,
            "--imap",
            IMAP,
            "--smtp",
            SMTP,
            "--password-env",
            "G15_PW",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    };
    let args: Vec<String> = restore_args("G15_PHRASE");
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = w.run_env(
        &argv,
        &[
            ("G15_PHRASE", Some(wrong.as_str())),
            ("G15_PW", Some("u56pw")),
        ],
    );
    assert_eq!(
        r.code, 4,
        "wrong phrase must exit 4: {}{}",
        r.stdout, r.stderr
    );
    assert!(r.stderr.contains("401"), "{}", r.stderr);
    assert!(
        accounts(&w).is_empty(),
        "no partial account after a wrong phrase"
    );
    assert!(
        w.json(&["contacts"]).as_array().unwrap().is_empty(),
        "no partial contacts"
    );
    // Literal server answer for a wrong token.
    let resp = reqwest::get(format!(
        "{server}/v1/backup/{a_fpr}?token=wrong-token-wrong-token"
    ))
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    // Bad checksum: refused locally (exit 2).
    let mut sw: Vec<&str> = p1.split(' ').collect();
    let (x, y) = (sw[0], sw[1]);
    let swapped = if x != y {
        sw.swap(0, 1);
        sw.join(" ")
    } else {
        sw[11] = if sw[11] == "zoo" { "abandon" } else { "zoo" };
        sw.join(" ")
    };
    let r = w.run_env(
        &argv,
        &[
            ("G15_PHRASE", Some(swapped.as_str())),
            ("G15_PW", Some("u56pw")),
        ],
    );
    // A swap can keep a valid checksum (1 in 16); then it is just another wrong phrase.
    assert!(r.code == 2 || r.code == 4, "{}{}", r.stdout, r.stderr);
    assert!(accounts(&w).is_empty());
    println!("G15 (3) wrong phrase -> server 401, CLI exit 4, no partial state: ok");

    // ------------------------------------------------------------- (4) restore on B
    let b = Profile::new("b");
    let info = jenv(
        &b,
        &argv,
        &[("G15_PHRASE", Some(p1.as_str())), ("G15_PW", Some("u56pw"))],
    );
    assert_eq!(info["email"], A);
    assert_eq!(info["fingerprint"], a_fpr.as_str());
    assert_eq!(b.fingerprint(A), a_fpr, "B holds A's key");
    let contacts = b.json(&["contacts"]);
    let bob_c = contacts
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["address"] == BOB)
        .unwrap_or_else(|| panic!("Bob not a contact on B: {contacts}"));
    assert_eq!(bob_c["fingerprint"], bob_fpr.as_str());
    {
        let e = b.engine();
        assert_eq!(e.get_signature(A).unwrap().text, format!("sig-v1 {tag}"));
        assert!(e
            .spam_settings(A)
            .unwrap()
            .allowlist
            .iter()
            .any(|x| x == "friend@sealbox.test"));
    }
    let m1 = wait_mid(&b, A, &s1_mid).await; // A's Sent copy
    assert_eq!(m1["decrypted"], true, "{m1}");
    assert_eq!(read_text(&b, &m1).trim(), s1_body);
    let m2 = wait_mid(&b, A, &s2_mid).await; // Bob's reply in INBOX
    assert_eq!(m2["decrypted"], true, "{m2}");
    assert_eq!(read_text(&b, &m2).trim(), s2_body);
    let s3_body = format!("from the restored device {tag}");
    let s3 = send(&b, A, BOB, &format!("s3 {tag}"), &s3_body, "require");
    assert_eq!(
        s3["mode"], "encrypted",
        "B encrypts to Bob without a new key exchange: {s3}"
    );
    let m3 = wait_mid(&bob, BOB, s3["message_id"].as_str().unwrap()).await;
    assert!(read_text(&bob, &m3).contains(&s3_body));
    println!("G15 (4) fresh profile restore: key, contact, settings back; old mail decrypts; sends encrypted: ok");

    // ------------------------------------------------------------- (5) second backup overwrites
    {
        let e = a.engine();
        let mut sig = e.get_signature(A).unwrap();
        sig.text = format!("sig-v2 {tag}");
        e.set_signature(A, sig).unwrap();
    }
    let p2 = words(&a.json(&["recovery", "phrase", "--account", A]));
    let p2env = [("G15_PHRASE", Some(p2.as_str()))];
    let b2v = jenv(
        &a,
        &[
            "recovery",
            "backup",
            "--account",
            A,
            "--server",
            server,
            "--phrase-env",
            "G15_PHRASE",
        ],
        &p2env,
    );
    assert_eq!(b2v["fingerprint"], a_fpr.as_str());
    let b2 = Profile::new("b2");
    let fp_args = [
        "recovery",
        "restore",
        "--email",
        A,
        "--server",
        server,
        "--phrase-env",
        "G15_PHRASE",
        "--fingerprint",
        &a_fpr,
    ];
    let r = b2.run_env(&fp_args, &[("G15_PHRASE", Some(p1.as_str()))]);
    assert_eq!(
        r.code, 4,
        "the old phrase no longer opens the slot: {}",
        r.stderr
    );
    assert!(r.stderr.contains("401"));
    assert!(accounts(&b2).is_empty());
    let info = jenv(&b2, &fp_args, &p2env);
    assert_eq!(info["fingerprint"], a_fpr.as_str());
    assert_eq!(
        b2.engine().get_signature(A).unwrap().text,
        format!("sig-v2 {tag}"),
        "second backup replaced the first"
    );
    println!("G15 (5) second backup overwrites (old phrase -> 401, new settings restored): ok");

    // ------------------------------------------------------------- (6) directory lookup, no creds
    let http = reqwest::Client::new();
    let up: Value = http
        .post(format!("{server}/vks/v1/upload"))
        .json(&json!({ "keytext": a.ok(&["key", "export", "--address", A]) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(up["key_fpr"], a_fpr.as_str(), "{up}");
    let rv = http
        .post(format!("{server}/vks/v1/request-verify"))
        .json(&json!({ "token": up["token"], "addresses": [A] }))
        .send()
        .await
        .unwrap();
    assert_eq!(rv.status().as_u16(), 200);
    let mail = srv.sink.take().pop().expect("challenge mail");
    let link = mail
        .body
        .split_whitespace()
        .find(|w| w.starts_with(&format!("{server}/vks/v1/verify/")))
        .expect("verify link")
        .to_string();
    assert_eq!(http.get(&link).send().await.unwrap().status().as_u16(), 200);
    let d = Profile::new("d");
    let info = jenv(
        &d,
        &[
            "recovery",
            "restore",
            "--email",
            A,
            "--server",
            server,
            "--phrase-env",
            "G15_PHRASE",
        ],
        &p2env,
    );
    assert_eq!(info["fingerprint"], a_fpr.as_str());
    jenv(
        &d,
        &[
            "recovery",
            "set-password",
            "--account",
            A,
            "--password-env",
            "G15_PW",
        ],
        &[("G15_PW", Some("u56pw"))],
    );
    let m2d = wait_mid(&d, A, &s2_mid).await;
    assert_eq!(m2d["decrypted"], true);
    println!("G15 (6) restore without credentials via the key directory + set-password + sync: ok");

    // ------------------------------------------------------------- (7) Autocrypt Setup Message
    let ex = a.json(&["recovery", "setup-export", "--account", A]);
    let code = ex["setup_code"].as_str().unwrap().to_string();
    let setup_mid = ex["message_id"].as_str().unwrap().to_string();
    assert_eq!(code.len(), 44, "9 blocks of 4 digits: {code}");
    let raw = inbox_raw("u56")
        .await
        .into_iter()
        .map(|(_, r)| String::from_utf8_lossy(&r).into_owned())
        .find(|r| r.contains(&setup_mid))
        .expect("setup message in u56 INBOX");
    assert!(raw.contains("Autocrypt-Setup-Message: v1"), "{raw}");
    assert!(raw.contains("application/autocrypt-setup"));
    assert!(
        !raw.contains("PRIVATE KEY BLOCK"),
        "key travels encrypted only"
    );

    let c = Profile::new("c");
    c.add_greenmail_account("u56");
    let c_old = c.fingerprint(A);
    assert_ne!(c_old, a_fpr);
    let sm = wait_mid(&c, A, &setup_mid).await;
    let m2c = wait_mid(&c, A, &s2_mid).await;
    assert_eq!(m2c["decrypted"], false, "C cannot read A's mail yet");
    let sm_id = sm["id"].as_i64().unwrap().to_string();
    let mut bad: Vec<char> = code.chars().collect();
    let i = bad.len() - 1;
    bad[i] = if bad[i] == '0' { '1' } else { '0' };
    let bad: String = bad.into_iter().collect();
    let r = c.run_env(
        &["recovery", "setup-import", &sm_id, "--code-env", "G15_CODE"],
        &[("G15_CODE", Some(bad.as_str()))],
    );
    assert_ne!(r.code, 0, "wrong setup code must fail");
    assert!(r.stderr.contains("wrong setup code"), "{}", r.stderr);
    assert_eq!(c.fingerprint(A), c_old, "wrong code changes nothing");
    let info = jenv(
        &c,
        &["recovery", "setup-import", &sm_id, "--code-env", "G15_CODE"],
        &[("G15_CODE", Some(code.as_str()))],
    );
    assert_eq!(info["fingerprint"], a_fpr.as_str());
    assert_eq!(c.fingerprint(A), a_fpr);
    let ok = wait_until(Duration::from_secs(30), || {
        c.sync(A);
        let done = c
            .list(Some(A), "*")
            .iter()
            .any(|m| m["message_id"].as_str() == Some(s2_mid.as_str()) && m["decrypted"] == true);
        async move { done }
    })
    .await;
    assert!(ok, "C never decrypted S2 after the setup import");
    let m2c = c
        .list(Some(A), "*")
        .into_iter()
        .find(|m| m["message_id"].as_str() == Some(s2_mid.as_str()))
        .unwrap();
    assert_eq!(read_text(&c, &m2c).trim(), s2_body);
    println!("G15 (7) setup message export -> import with code into fresh profile, decrypts; wrong code fails: ok");

    // ------------------------------------------------------------- (8) server sees nothing
    let db = std::fs::read(&srv.db).unwrap_or_default();
    let mut wal = srv.db.clone().into_os_string();
    wal.push("-wal");
    let db = [db, std::fs::read(PathBuf::from(wal)).unwrap_or_default()].concat();
    assert!(!db.is_empty());
    let hay = String::from_utf8_lossy(&db);
    for needle in [
        s1_body.as_str(),
        s2_body.as_str(),
        "PRIVATE KEY",
        &format!("sig-v2 {tag}"),
        p1.as_str(),
        p2.as_str(),
        "u56pw",
    ] {
        assert!(!hay.contains(needle), "server database contains {needle:?}");
    }
    println!("G15 (8) server database: no plaintext, secret key, phrase or password: ok");
    println!("G15 PASS");
}
