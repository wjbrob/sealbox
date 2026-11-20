//! Gate G4 — first encrypted end-to-end mail through GreenMail via the `sealbox` CLI:
//! Alice→Bob first contact (plaintext + Autocrypt) bootstraps Bob's knowledge of Alice's key;
//! Bob→Alice goes out encrypted; Alice decrypts, verifies and sees the protected Subject;
//! Alice→Bob encrypted reply with an attachment; raw-wire inspection; policy refusal.
//!
//! Needs `testing/mail_up.sh`. Run with
//! `cargo test -p sealbox-cli --test gate_g4 -- --ignored`.

mod common;

use std::time::Duration;

use common::{inbox_count, inbox_raw, nonce, pseudo_random, temp_file, wait_until, Profile};

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn alice_and_bob_exchange_encrypted_mail() {
    let alice = Profile::new("alice");
    let bob = Profile::new("bob");
    let tag = nonce("g4");

    // (1) Both add their GreenMail account with manual servers; a key is generated.
    let a = alice.add_greenmail_account("alice");
    let b = bob.add_greenmail_account("bob");
    let alice_fp = a["fingerprint"].as_str().unwrap().to_string();
    let bob_fp = b["fingerprint"].as_str().unwrap().to_string();
    assert_ne!(alice_fp, bob_fp);
    assert_eq!(alice.fingerprint("alice@sealbox.test"), alice_fp);
    let listed = alice.json(&["account", "list"]);
    assert_eq!(listed[0]["email"], "alice@sealbox.test");
    assert_eq!(
        listed[0]["login"], "alice",
        "GreenMail login is the bare name"
    );
    // Secrets never appear in any output.
    let acct_text = alice.ok(&["account", "list"]);
    assert!(!acct_text.contains("alicepw"));

    // (2) Alice → Bob, first contact, plaintext (carries her Autocrypt header).
    let hello_subject = format!("hello {tag}");
    let hello_body = format!("first contact {tag}");
    let r = alice.json(&[
        "send",
        "--from",
        "alice@sealbox.test",
        "--to",
        "bob@sealbox.test",
        "--subject",
        &hello_subject,
        "--body",
        &hello_body,
        "--policy",
        "plaintext",
    ]);
    assert_eq!(r["mode"], "plaintext");
    assert_eq!(r["encrypted"], false);
    assert_eq!(r["recipients"][0]["recommendation"], "disable");
    let hello_mid = r["message_id"].as_str().unwrap().to_string();

    // (3) Bob syncs → Alice is a contact with a usable key.
    assert!(
        wait_until(Duration::from_secs(20), || async {
            let rep = bob.sync("bob@sealbox.test");
            rep["new"].as_u64().unwrap_or(0) >= 1
                || bob
                    .list(Some("bob@sealbox.test"), "INBOX")
                    .iter()
                    .any(|m| m["message_id"].as_str() == Some(hello_mid.as_str()))
        })
        .await,
        "Alice's first mail never reached Bob"
    );
    let hello = bob.find_by_subject(Some("bob@sealbox.test"), "INBOX", &hello_subject);
    assert_eq!(hello["was_encrypted"], false);
    assert_eq!(hello["signature"]["status"], "none");
    let contacts = bob.json(&["contacts"]);
    let alice_contact = contacts
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["address"] == "alice@sealbox.test")
        .unwrap_or_else(|| panic!("alice not in contacts: {contacts}"));
    let rec = alice_contact["recommendation"].as_str().unwrap();
    assert!(
        rec == "available" || rec == "encrypt",
        "unexpected recommendation {rec}"
    );
    assert_eq!(alice_contact["fingerprint"], alice_fp.as_str());
    assert_eq!(alice_contact["source"], "autocrypt");
    assert_eq!(alice_contact["prefer_encrypt"], "mutual");
    let human = bob.ok(&["contacts"]);
    assert!(human.contains("alice@sealbox.test"));

    // (4) Bob → Alice with the default policy: must go out encrypted.
    let secret_subject = format!("secret subject {tag}");
    let secret_body = format!("secret body {tag} — nobody but Alice may read this");
    let r = bob.json(&[
        "send",
        "--from",
        "bob@sealbox.test",
        "--to",
        "alice@sealbox.test",
        "--subject",
        &secret_subject,
        "--body",
        &secret_body,
    ]);
    assert_eq!(r["mode"], "encrypted", "{r}");
    assert_eq!(r["encrypted"], true);
    assert_eq!(r["recipients"][0]["fingerprint"], alice_fp.as_str());
    assert_eq!(r["sent_copy_appended"], true, "{r}");
    let secret_mid = r["message_id"].as_str().unwrap().to_string();

    // (5) Alice syncs and reads it: plaintext body, encrypted, Good signature by Bob,
    //     protected Subject restored.
    assert!(
        wait_until(Duration::from_secs(20), || async {
            alice.sync("alice@sealbox.test");
            alice
                .list(Some("alice@sealbox.test"), "INBOX")
                .iter()
                .any(|m| m["message_id"].as_str() == Some(secret_mid.as_str()))
        })
        .await,
        "Bob's encrypted mail never reached Alice"
    );
    let m = alice.find_by_subject(Some("alice@sealbox.test"), "INBOX", &secret_subject);
    let id = m["id"].as_i64().unwrap();
    let read = alice.json(&["read", &id.to_string()]);
    assert_eq!(read["text"].as_str().unwrap().trim(), secret_body);
    assert_eq!(read["was_encrypted"], true);
    assert_eq!(read["decrypted"], true);
    assert_eq!(read["signature"]["status"], "good");
    assert_eq!(read["signature"]["fingerprint"], bob_fp.as_str());
    assert_eq!(read["signature"]["signer"], "bob@sealbox.test");
    assert_eq!(read["subject"], secret_subject.as_str());
    assert_eq!(read["protected_subject"], true);
    let human = alice.ok(&["read", &id.to_string()]);
    assert!(human.contains(&secret_body));
    assert!(human.contains("🔒"));
    assert!(human.contains(&bob_fp));
    let list_human = alice.ok(&["list", "--account", "alice@sealbox.test"]);
    assert!(list_human.contains("🔒"), "{list_human}");
    assert!(list_human.contains("✍️"), "{list_human}");

    // (6) Alice → Bob: encrypted reply with an attachment; Bob gets identical bytes back.
    let blob = pseudo_random(4096, 0xA11CE);
    let blob_path = temp_file(alice.path(), "payload.bin", &blob);
    let reply_subject = format!("re: secret {tag}");
    let reply_body = format!("reply body {tag} with attachment");
    let r = alice.json(&[
        "send",
        "--from",
        "alice@sealbox.test",
        "--to",
        "bob@sealbox.test",
        "--subject",
        &reply_subject,
        "--body",
        &reply_body,
        "--attach",
        blob_path.to_str().unwrap(),
        "--in-reply-to",
        &id.to_string(),
    ]);
    assert_eq!(r["mode"], "encrypted", "{r}");
    let reply_mid = r["message_id"].as_str().unwrap().to_string();
    assert!(
        wait_until(Duration::from_secs(20), || async {
            bob.sync("bob@sealbox.test");
            bob.list(Some("bob@sealbox.test"), "INBOX")
                .iter()
                .any(|m| m["message_id"].as_str() == Some(reply_mid.as_str()))
        })
        .await,
        "Alice's reply never reached Bob"
    );
    let m = bob.find_by_subject(Some("bob@sealbox.test"), "INBOX", &reply_subject);
    let rid = m["id"].as_i64().unwrap();
    let read = bob.json(&["read", &rid.to_string()]);
    assert_eq!(read["text"].as_str().unwrap().trim(), reply_body);
    assert_eq!(read["was_encrypted"], true);
    assert_eq!(read["signature"]["status"], "good");
    assert_eq!(read["signature"]["fingerprint"], alice_fp.as_str());
    assert_eq!(read["attachment_count"], 1);
    assert_eq!(read["attachments"][0]["filename"], "payload.bin");
    assert_eq!(read["attachments"][0]["size"], 4096);
    assert_eq!(read["in_reply_to"][0], secret_mid.as_str());
    let out_path = bob.path().join("payload.out");
    bob.ok(&[
        "attachment",
        "save",
        &rid.to_string(),
        "0",
        out_path.to_str().unwrap(),
    ]);
    assert_eq!(
        std::fs::read(&out_path).unwrap(),
        blob,
        "attachment bytes differ"
    );

    // (7) Raw wire check straight from Bob's INBOX over IMAP.
    let raw_inbox = inbox_raw("bob").await;
    let find_raw = |mid: &str| -> String {
        raw_inbox
            .iter()
            .map(|(_, raw)| String::from_utf8_lossy(raw).into_owned())
            .find(|s| s.contains(mid))
            .unwrap_or_else(|| panic!("message <{mid}> not found in Bob's INBOX"))
    };
    let raw_reply = find_raw(&reply_mid);
    let head = raw_reply.split("\r\n\r\n").next().unwrap_or("");
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: multipart/encrypted"),
        "reply is not multipart/encrypted:\n{head}"
    );
    assert!(
        head.contains("protocol=\"application/pgp-encrypted\""),
        "missing RFC 3156 protocol parameter:\n{head}"
    );
    assert!(
        head.contains("Subject: ..."),
        "outer subject must be \"...\":\n{head}"
    );
    assert!(
        head.contains("Autocrypt: addr=alice@sealbox.test"),
        "{head}"
    );
    assert!(raw_reply.contains("application/pgp-encrypted"));
    assert!(raw_reply.contains("Version: 1"));
    assert!(raw_reply.contains("-----BEGIN PGP MESSAGE-----"));
    for secret in [&reply_subject, &reply_body] {
        assert!(
            !raw_reply.contains(secret.as_str()),
            "secret {secret:?} leaked into the raw encrypted mail"
        );
    }
    assert!(!raw_reply.contains("payload.bin"), "attachment name leaked");
    // The whole INBOX (all raw bytes) never contains Bob's secret body either.
    let all_raw: String = raw_inbox
        .iter()
        .map(|(_, r)| String::from_utf8_lossy(r).into_owned())
        .collect();
    assert!(!all_raw.contains(&secret_body));
    assert!(!all_raw.contains(&secret_subject));
    // The first-contact mail was plaintext with Alice's Autocrypt header.
    let raw_hello = find_raw(&hello_mid);
    assert!(raw_hello.contains("Autocrypt: addr=alice@sealbox.test; prefer-encrypt=mutual;"));
    assert!(raw_hello.contains(&hello_body));

    // (8) `--policy require` to Carol (no key) exits 3 and sends nothing.
    let before = inbox_count("carol").await;
    let r = bob.run(&[
        "send",
        "--from",
        "bob@sealbox.test",
        "--to",
        "carol@sealbox.test",
        "--subject",
        &format!("must not go out {tag}"),
        "--body",
        &format!("must not go out {tag}"),
        "--policy",
        "require",
    ]);
    assert_eq!(
        r.code, 3,
        "expected exit 3, got {} / {}",
        r.stdout, r.stderr
    );
    assert!(r.stderr.contains("carol@sealbox.test"));
    let r = bob.run(&[
        "--json",
        "send",
        "--from",
        "bob@sealbox.test",
        "--to",
        "alice@sealbox.test,carol@sealbox.test",
        "--subject",
        "x",
        "--body",
        "y",
    ]);
    assert_eq!(r.code, 3, "default policy must also refuse: {}", r.stderr);
    assert_eq!(r.json()["missing_keys"][0], "carol@sealbox.test");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        inbox_count("carol").await,
        before,
        "a refused send reached Carol"
    );

    // (9) A second sync fetches nothing new (Alice's first sync here still picks up the
    //     Sent copy of her reply, which must itself be decryptable by her).
    let rep = bob.sync("bob@sealbox.test");
    assert_eq!(rep["new"], 0, "{rep}");
    assert_eq!(rep["failed"], 0);
    let rep = alice.sync("alice@sealbox.test");
    assert_eq!(rep["failed"], 0, "{rep}");
    let rep = alice.sync("alice@sealbox.test");
    assert_eq!(rep["new"], 0, "{rep}");
    let sent_copy = alice.find_by_subject(Some("alice@sealbox.test"), "Sent", &reply_subject);
    assert_eq!(sent_copy["was_encrypted"], true);
    assert_eq!(sent_copy["decrypted"], true, "{sent_copy}");
    assert_eq!(sent_copy["attachment_count"], 1);
}
