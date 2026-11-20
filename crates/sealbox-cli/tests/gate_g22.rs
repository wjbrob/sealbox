//! Gate G22 — hosted mailbox end to end through the real `sealbox` binary:
//! two "Create a new Sealbox address" signups against a running `sealbox-server` that provisions
//! on the docker Stalwart, an encrypted exchange between them through Stalwart, sync + decrypt,
//! raw server bytes without plaintext, a reserved name refused, a signup over the per-IP cap
//! refused, and the availability endpoint.
//!
//! Driven by `scripts/gate_g22.sh`, which starts Stalwart + the server and sets
//! `SEALBOX_G22_SERVER_URL` (+ `SEALBOX_G22_INVITE`, `SEALBOX_G22_DOMAIN`, `SEALBOX_G22_IMAP`).

mod common;

use std::time::Duration;

use common::{nonce, wait_until, Profile};
use sealbox_mail::imap::ImapClient;
use sealbox_mail::{Auth, Security};

fn strs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// All raw INBOX messages of a hosted account on Stalwart, as `(uid, raw)`.
async fn hosted_inbox_raw(login: &str, password: &str) -> Vec<(u32, Vec<u8>)> {
    let imap = env_or("SEALBOX_G22_IMAP", "127.0.0.1:1143");
    let (host, port) = imap.rsplit_once(':').expect("host:port");
    let mut client = ImapClient::connect(
        host,
        port.parse().expect("port"),
        Security::Plain,
        Auth::Password {
            user: login.to_string(),
            pass: password.to_string(),
        },
    )
    .await
    .expect("IMAP login to Stalwart with the hosted password");
    client.select("INBOX").await.expect("select INBOX");
    let uids = client.fetch_new_uids(0).await.expect("uids");
    let mut out = Vec::new();
    for chunk in uids.chunks(50) {
        for m in client.fetch_rfc822_batch(chunk).await.expect("fetch") {
            out.push((m.uid, m.raw));
        }
    }
    let _ = client.logout().await;
    out
}

#[tokio::test]
#[ignore = "needs Stalwart + sealbox-server (scripts/gate_g22.sh)"]
async fn hosted_accounts_exchange_encrypted_mail() {
    let server = std::env::var("SEALBOX_G22_SERVER_URL")
        .expect("SEALBOX_G22_SERVER_URL must point at a sealbox-server with hosted signups");
    let invite = std::env::var("SEALBOX_G22_INVITE").ok();
    let domain = env_or("SEALBOX_G22_DOMAIN", "hosted.sealbox.test");
    let tag = nonce("g22");
    let suffix = tag
        .rsplit('-')
        .next()
        .unwrap_or("0")
        .chars()
        .rev()
        .take(6)
        .collect::<String>();
    let unique = format!("{}{}", std::process::id() % 10_000, suffix);
    let name_a = format!("g22a-{unique}");
    let name_b = format!("g22b-{unique}");
    let name_c = format!("g22c-{unique}");
    let email_a = format!("{name_a}@{domain}");
    let email_b = format!("{name_b}@{domain}");

    let alice = Profile::new("hosted-a");
    let bob = Profile::new("hosted-b");

    // (1) The server advertises hosted signups; the name is available.
    let info = alice.json(&[
        "account",
        "hosted-info",
        "--server",
        &server,
        "--check",
        &name_a,
    ]);
    assert_eq!(info["info"]["domain"], domain.as_str(), "{info}");
    assert_eq!(info["info"]["imap"]["security"], "plain");
    assert_eq!(info["availability"]["available"], true, "{info}");
    assert_eq!(info["availability"]["email"], email_a.as_str());
    let human = alice.ok(&[
        "account",
        "hosted-info",
        "--server",
        &server,
        "--check",
        "postmaster",
    ]);
    assert!(human.contains("reserved"), "{human}");

    let create_args = |name: &str, show: bool| -> Vec<String> {
        let mut v = vec![
            "account".to_string(),
            "create-hosted".into(),
            "--server".into(),
            server.clone(),
            "--name".into(),
            name.to_string(),
        ];
        if let Some(i) = &invite {
            v.push("--invite".into());
            v.push(i.clone());
        }
        if show {
            v.push("--show-password".into());
        }
        v
    };

    // (2) Alice creates her address; the password is printed only with --show-password.
    let args = create_args(&name_a, true);
    let a = alice.json(&strs(&args));
    assert_eq!(a["email"], email_a.as_str(), "{a}");
    assert_eq!(a["login"], email_a.as_str());
    assert_eq!(a["imap"]["port"], 1143);
    assert_eq!(a["smtp"]["port"], 1587);
    assert_eq!(a["auth_kind"], "password");
    let fp_a = a["fingerprint"].as_str().expect("fingerprint").to_string();
    assert_eq!(fp_a.len(), 40);
    let pw_a = a["password"]
        .as_str()
        .expect("password shown on request")
        .to_string();
    assert_eq!(pw_a.len(), 24);
    assert!(pw_a.bytes().all(|b| b.is_ascii_alphanumeric()));

    // (3) Bob creates his without showing the password: it appears nowhere in the output.
    let args = create_args(&name_b, false);
    let b = bob.json(&strs(&args));
    assert_eq!(b["email"], email_b.as_str(), "{b}");
    assert!(
        b.get("password").is_none(),
        "password must not be printed by default: {b}"
    );
    let fp_b = b["fingerprint"].as_str().expect("fingerprint").to_string();
    assert_ne!(fp_a, fp_b);
    let listed = bob.ok(&["account", "list"]);
    assert!(listed.contains(&email_b));
    assert!(!listed.contains(&pw_a));

    // (4) The name is taken now; a reserved name is refused (usage error, exit 2) and a third
    //     signup from this IP exceeds the per-IP daily cap (policy refusal, exit 3).
    let av = alice.json(&[
        "account",
        "hosted-info",
        "--server",
        &server,
        "--check",
        &name_a,
    ]);
    assert_eq!(av["availability"]["available"], false);
    assert_eq!(av["availability"]["reason"], "taken");
    let args = create_args("postmaster", false);
    let r = alice.run(&strs(&args));
    assert_eq!(r.code, 2, "reserved name must be a usage error: {r:?}");
    assert!(
        r.stdout.contains("reserved") || r.stderr.contains("reserved"),
        "{r:?}"
    );
    let args = create_args(&name_c, false);
    let r = alice.run(&strs(&args));
    assert_eq!(
        r.code, 3,
        "signup over the per-IP cap must be refused: {r:?}"
    );
    assert!(alice.list(None, "INBOX").is_empty());
    let dup = create_args(&name_a, false);
    let r = bob.run(&strs(&dup));
    assert_ne!(r.code, 0, "duplicate name must fail: {r:?}");

    // (5) Alice → Bob first contact in plaintext (carries her Autocrypt header) through Stalwart.
    let hello_subject = format!("hello {tag}");
    let r = alice.json(&[
        "send",
        "--from",
        &email_a,
        "--to",
        &email_b,
        "--subject",
        &hello_subject,
        "--body",
        &format!("first contact {tag}"),
        "--policy",
        "plaintext",
    ]);
    assert_eq!(r["mode"], "plaintext", "{r}");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            bob.sync(&email_b);
            bob.list(Some(&email_b), "INBOX")
                .iter()
                .any(|m| m["subject"].as_str() == Some(hello_subject.as_str()))
        })
        .await,
        "Alice's first mail never reached Bob through Stalwart"
    );
    let contacts = bob.json(&["contacts"]);
    let alice_contact = contacts
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["address"] == email_a.as_str())
        .unwrap_or_else(|| panic!("alice not in contacts: {contacts}"));
    assert_eq!(alice_contact["fingerprint"], fp_a.as_str());

    // (6) Bob → Alice with the default policy: encrypted + signed, protected Subject.
    let secret_subject = format!("secret subject {tag}");
    let secret_body = format!("secret body {tag} — only Alice may read this");
    let r = bob.json(&[
        "send",
        "--from",
        &email_b,
        "--to",
        &email_a,
        "--subject",
        &secret_subject,
        "--body",
        &secret_body,
    ]);
    assert_eq!(r["mode"], "encrypted", "{r}");
    assert_eq!(r["encrypted"], true);
    assert_eq!(r["recipients"][0]["fingerprint"], fp_a.as_str());
    assert_eq!(r["sent_copy_appended"], true, "{r}");
    let secret_mid = r["message_id"].as_str().unwrap().to_string();

    assert!(
        wait_until(Duration::from_secs(30), || async {
            alice.sync(&email_a);
            alice
                .list(Some(&email_a), "INBOX")
                .iter()
                .any(|m| m["message_id"].as_str() == Some(secret_mid.as_str()))
        })
        .await,
        "Bob's encrypted mail never reached Alice through Stalwart"
    );
    let msg = alice.find_by_subject(Some(&email_a), "INBOX", &secret_subject);
    assert_eq!(msg["was_encrypted"], true, "{msg}");
    assert_eq!(msg["decrypted"], true);
    assert_eq!(msg["protected_subject"], true);
    assert_eq!(msg["signature"]["status"], "good");
    assert_eq!(msg["signature"]["fingerprint"], fp_b.as_str());
    let id = msg["id"].as_i64().unwrap().to_string();
    let detail = alice.json(&["read", &id]);
    assert!(
        detail["text"].as_str().unwrap().contains(&secret_body),
        "{detail}"
    );

    // (7) Raw bytes on Stalwart: the encrypted mail is PGP/MIME and carries no plaintext; the
    //     whole INBOX never contains the secret subject or body.
    let raw_inbox = hosted_inbox_raw(&email_a, &pw_a).await;
    let raw = raw_inbox
        .iter()
        .map(|(_, r)| String::from_utf8_lossy(r).into_owned())
        .find(|r| r.contains(&secret_mid))
        .unwrap_or_else(|| panic!("encrypted message {secret_mid} not found on the server"));
    assert!(raw.contains("multipart/encrypted"), "{raw}");
    assert!(raw.contains("-----BEGIN PGP MESSAGE-----"));
    assert!(!raw.contains(&secret_body));
    assert!(!raw.contains(&secret_subject));
    let head = raw.split("\r\n\r\n").next().unwrap_or("");
    assert!(
        head.contains("Subject: ...") || head.contains("Subject: =?"),
        "outer subject must be protected: {head}"
    );
    let all: String = raw_inbox
        .iter()
        .map(|(_, r)| String::from_utf8_lossy(r).into_owned())
        .collect();
    assert!(!all.contains(&secret_body));
    assert!(!all.contains(&secret_subject));
    assert!(
        !all.contains(&pw_a),
        "the mailbox password must never travel in mail"
    );

    // (8) Alice replies encrypted; Bob decrypts it too (both directions through Stalwart).
    let reply_subject = format!("re: secret {tag}");
    let reply_body = format!("reply body {tag}");
    let r = alice.json(&[
        "send",
        "--from",
        &email_a,
        "--to",
        &email_b,
        "--subject",
        &reply_subject,
        "--body",
        &reply_body,
        "--in-reply-to",
        &id,
    ]);
    assert_eq!(r["mode"], "encrypted", "{r}");
    assert!(
        wait_until(Duration::from_secs(30), || async {
            bob.sync(&email_b);
            bob.list(Some(&email_b), "INBOX")
                .iter()
                .any(|m| m["subject"].as_str() == Some(reply_subject.as_str()))
        })
        .await,
        "Alice's encrypted reply never reached Bob"
    );
    let reply = bob.find_by_subject(Some(&email_b), "INBOX", &reply_subject);
    assert_eq!(reply["decrypted"], true, "{reply}");
    assert_eq!(reply["signature"]["status"], "good");
    let rid = reply["id"].as_i64().unwrap().to_string();
    let d = bob.json(&["read", &rid]);
    assert!(d["text"].as_str().unwrap().contains(&reply_body));
}
