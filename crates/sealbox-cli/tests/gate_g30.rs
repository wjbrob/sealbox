//! Gate G30 — identity, end to end through the `sealbox` binary, GreenMail (users u51/u52) and
//! a real `sealbox-server` (started by `scripts/gate_g30.sh` on an ephemeral port, challenge
//! mail through GreenMail SMTP).
//!
//! (a) u51 and u52 exchange Autocrypt keys; the first contact raises no alert;
//! (b) u52 starts over with a NEW identity and writes again → u51 sees `key_changed` on that
//!     message and ⚠ on the contact (with the previous fingerprint);
//! (c) `contacts ack` clears the alert;
//! (d) `contacts verify` with a wrong fingerprint is refused; with the right one the contact is
//!     verified and the next signed message from u52 carries `signer_verified`;
//! (e) `key qr` prints the OPENPGP4FPR: payload of the account key;
//! (f) u51's key is published to the directory (VKS upload → challenge mail → link), then
//!     `kt audit` reports sth_verified + own_key_included + consistency_ok, `kt entries` lists
//!     the entry, and a second audit is consistent with the first;
//! (g) a tampered tree head in the server database fails the audit (exit 6).

mod common;

use std::time::Duration;

use common::*;
use serde_json::Value;

const A: &str = "u51@sealbox.test";
const B: &str = "u52@sealbox.test";

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} not set (run scripts/gate_g30.sh)"))
}

/// Empty a GreenMail INBOX so mail from earlier runs (other keys!) cannot interfere.
async fn purge_inbox(user: &str) {
    let mut imap = imap_login(user).await;
    imap.select("INBOX").await.expect("select");
    let uids = imap.fetch_new_uids(0).await.expect("uids");
    if !uids.is_empty() {
        imap.set_flags(&uids, sealbox_mail::imap::FlagOp::Add, &["\\Deleted"])
            .await
            .expect("flag");
        imap.expunge().await.expect("expunge");
    }
    let _ = imap.logout().await;
}

fn send(p: &Profile, from: &str, to: &str, subject: &str, policy: Option<&str>) -> Value {
    let mut args = vec![
        "send",
        "--from",
        from,
        "--to",
        to,
        "--subject",
        subject,
        "--body",
        "identity gate body",
    ];
    if let Some(pol) = policy {
        args.extend_from_slice(&["--policy", pol]);
    }
    p.json(&args)
}

/// Sync `account` until a message with `subject` is stored; return it.
async fn receive(p: &Profile, account: &str, subject: &str) -> Value {
    let found = wait_until(Duration::from_secs(30), || async {
        p.sync(account);
        p.list(Some(account), "INBOX")
            .iter()
            .any(|m| m["subject"].as_str() == Some(subject))
    })
    .await;
    assert!(found, "{subject:?} never reached {account}");
    p.find_by_subject(Some(account), "INBOX", subject)
}

fn contact(p: &Profile, addr: &str) -> Value {
    let all = p.json(&["contacts"]);
    all.as_array()
        .and_then(|a| a.iter().find(|c| c["address"] == addr).cloned())
        .unwrap_or_else(|| panic!("{addr} not in contacts: {all}"))
}

fn contact_line(p: &Profile, addr: &str) -> String {
    p.ok(&["contacts"])
        .lines()
        .find(|l| {
            l.split_whitespace().nth(1) == Some(addr) || l.split_whitespace().next() == Some(addr)
        })
        .map(str::to_string)
        .unwrap_or_else(|| panic!("{addr} not in the contacts listing"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs GreenMail (testing/mail_up.sh) and a server from scripts/gate_g30.sh"]
async fn identity_key_change_verification_and_transparency() {
    let server = env("SEALBOX_G30_SERVER");
    let server_db = env("SEALBOX_G30_DB");
    let tag = nonce("g30");
    purge_inbox("u51").await;
    purge_inbox("u52").await;

    let a = Profile::new("u51");
    a.add_greenmail_account("u51");
    let a_fp = a.fingerprint(A);
    let b1 = Profile::new("u52-old");
    b1.add_greenmail_account("u52");
    let b1_fp = b1.fingerprint(B);

    // ---------------------------------------------------------------- (a) key exchange
    let s1 = format!("hello u52 {tag}");
    assert_eq!(send(&a, A, B, &s1, Some("plaintext"))["mode"], "plaintext");
    receive(&b1, B, &s1).await;
    let s2 = format!("hello u51 {tag}");
    assert_eq!(send(&b1, B, A, &s2, None)["mode"], "encrypted");
    let m2 = receive(&a, A, &s2).await;
    assert_eq!(m2["signature"]["status"], "good", "{m2}");
    assert_eq!(m2["signature"]["key_changed"], false);
    assert_eq!(m2["signature"]["signer_verified"], false);
    let c = contact(&a, B);
    assert_eq!(c["fingerprint"], b1_fp.as_str());
    assert!(
        c["key_changed_at"].is_null() && c["verified"] == false,
        "{c}"
    );

    // ---------------------------------------------------------------- (b) new identity
    tokio::time::sleep(Duration::from_millis(1500)).await; // Autocrypt dates have 1 s resolution
    let b2 = Profile::new("u52-new");
    b2.add_greenmail_account("u52");
    let b2_fp = b2.fingerprint(B);
    assert_ne!(b1_fp, b2_fp);
    let s3 = format!("new key {tag}");
    send(&b2, B, A, &s3, Some("plaintext"));
    let m3 = receive(&a, A, &s3).await;
    eprintln!("message from the new identity: {}", m3["signature"]);
    assert_eq!(m3["signature"]["key_changed"], true, "{m3}");
    let c = contact(&a, B);
    eprintln!("contact after the key change: {c}");
    assert!(c["key_changed_at"].is_string(), "{c}");
    assert_eq!(c["previous_fingerprint"], b1_fp.as_str());
    assert_eq!(c["fingerprint"], b2_fp.as_str());
    let line = contact_line(&a, B);
    assert!(line.starts_with('⚠'), "no ⚠ in {line:?}");
    assert!(
        a.ok(&["contacts"]).contains(&b1_fp),
        "previous key not shown"
    );
    let listing = a.ok(&["list", "--account", A]);
    assert!(
        listing.lines().any(|l| l.contains(&s3) && l.contains('⚠')),
        "{listing}"
    );
    // The earlier message keeps its own verdict.
    let m2 = a.find_by_subject(Some(A), "INBOX", &s2);
    assert_eq!(m2["signature"]["key_changed"], false);

    // ---------------------------------------------------------------- (c) acknowledge
    let c = a.json(&["contacts", "ack", B]);
    assert!(
        c["key_changed_at"].is_null() && c["previous_fingerprint"].is_null(),
        "{c}"
    );
    assert!(!contact_line(&a, B).starts_with('⚠'));

    // ---------------------------------------------------------------- (d) verification
    let r = a.run(&["contacts", "verify", B, "--fingerprint", &b1_fp]);
    assert_ne!(r.code, 0, "a wrong fingerprint must be refused");
    assert!(r.stderr.contains("mismatch"), "{}", r.stderr);
    assert_eq!(contact(&a, B)["verified"], false);
    let c = a.json(&["contacts", "verify", B, "--fingerprint", &b2_fp]);
    assert_eq!(c["verified"], true, "{c}");
    assert!(c["verified_at"].is_string());
    assert!(contact_line(&a, B).starts_with('✓'));

    let s4 = format!("to the new key {tag}");
    assert_eq!(send(&a, A, B, &s4, None)["mode"], "encrypted");
    receive(&b2, B, &s4).await;
    let s5 = format!("signed by the verified key {tag}");
    assert_eq!(send(&b2, B, A, &s5, None)["mode"], "encrypted");
    let m5 = receive(&a, A, &s5).await;
    eprintln!("message signed by the verified key: {}", m5["signature"]);
    assert_eq!(m5["signature"]["status"], "good");
    assert_eq!(m5["signature"]["fingerprint"], b2_fp.as_str());
    assert_eq!(m5["signature"]["signer_verified"], true, "{m5}");
    assert_eq!(m5["signature"]["key_changed"], false);
    let id = m5["id"].as_i64().expect("id").to_string();
    let read = a.json(&["read", &id, "--no-mark"]);
    assert_eq!(read["signature"]["signer_verified"], true);

    // ---------------------------------------------------------------- (e) QR payload
    let qr = a.json(&["key", "qr", "--account", A]);
    assert_eq!(
        qr["payload"],
        format!("OPENPGP4FPR:{}", a_fp.to_uppercase())
    );
    assert!(qr["qr"].as_str().is_some_and(|s| s.lines().count() > 10));

    // ---------------------------------------------------------------- (f) transparency
    let http = reqwest::Client::new();
    let armored = a.json(&["key", "export", "--address", A])["armored"]
        .as_str()
        .expect("armored")
        .to_string();
    let up: Value = http
        .post(format!("{server}/vks/v1/upload"))
        .json(&serde_json::json!({ "keytext": armored }))
        .send()
        .await
        .expect("upload")
        .json()
        .await
        .expect("json");
    let token = up["token"].as_str().expect("token");
    let rv = http
        .post(format!("{server}/vks/v1/request-verify"))
        .json(&serde_json::json!({ "token": token, "addresses": [A] }))
        .send()
        .await
        .expect("request-verify");
    assert_eq!(rv.status(), 200, "{}", rv.text().await.unwrap_or_default());
    let prefix = format!("{server}/vks/v1/verify/");
    let mut link = None;
    for _ in 0..60 {
        for (_, raw) in inbox_raw("u51").await {
            let Ok(p) = sealbox_mail::mime::parse(&raw) else {
                continue;
            };
            if let sealbox_mail::mime::MessageKind::Plain(body) = p.kind {
                let text = body.text.unwrap_or_default();
                if let Some(w) = text.split_whitespace().find(|w| w.starts_with(&prefix)) {
                    link = Some(w.to_string());
                }
            }
        }
        if link.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let link = link.expect("challenge mail with the verify link");
    let r = http.get(&link).send().await.expect("verify");
    assert_eq!(r.status(), 200);

    let audit = a.json(&["kt", "audit", "--account", A, "--server", &server]);
    eprintln!("kt audit: {audit}");
    assert_eq!(audit["sth_verified"], true, "{audit}");
    assert_eq!(audit["own_key_included"], true, "{audit}");
    assert_eq!(audit["consistency_ok"], true, "{audit}");
    assert!(audit["log_size"].as_u64().unwrap_or(0) >= 1);
    assert_eq!(audit["alerts"].as_array().map(Vec::len), Some(0));
    let entries = a.json(&["kt", "entries", "--server", &server]);
    assert!(
        entries["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .any(
                |e| e["entry"]["fingerprint"] == a_fp.as_str() && e["entry"]["action"] == "publish"
            ),
        "{entries}"
    );
    let again = a.json(&["kt", "audit", "--account", A, "--server", &server]);
    assert_eq!(again["consistency_ok"], true, "{again}");
    assert_eq!(again["sth_verified"], true);
    // u52 has published nothing: not included, exit 6.
    let r = b2.run(&["--json", "kt", "audit", "--account", B, "--server", &server]);
    assert_eq!(r.code, 6, "{}", r.stdout);
    assert_eq!(r.json()["own_key_included"], false);

    // ---------------------------------------------------------------- (g) tampered head
    let out = std::process::Command::new("sqlite3")
        .arg(&server_db)
        .arg(format!(
            "UPDATE kt_heads SET root_hash = '{}' WHERE tree_size = (SELECT MAX(tree_size) FROM kt_heads);",
            "ab".repeat(32)
        ))
        .output()
        .expect("sqlite3");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = a.run(&["--json", "kt", "audit", "--account", A, "--server", &server]);
    eprintln!("kt audit of the tampered head: {}", r.stdout);
    assert_eq!(r.code, 6);
    let v = r.json();
    assert_eq!(v["sth_verified"], false);
    assert_eq!(v["own_key_included"], false);
    assert!(v["alerts"].as_array().is_some_and(|a| a
        .iter()
        .any(|x| x.as_str().unwrap_or("").contains("forged"))));
}
