//! Gate G8 — the CLI as a desktop client: offline autodiscover dry runs, one profile with two
//! accounts and a unified inbox, incremental sync, flags, stable JSON, key export/import
//! followed by an encrypted send without any prior Autocrypt exchange, IMAP IDLE `watch`,
//! and the Sent-folder copy being decryptable by its sender.
//!
//! Needs `testing/mail_up.sh`. Run with
//! `cargo test -p sealbox-cli --test gate_g8 -- --ignored`.

mod common;

use std::io::Read;
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::{flags_of, nonce, wait_until, Profile};

/// Keys every `list` row and `read` object must carry (documented in README.md).
const SUMMARY_KEYS: &[&str] = &[
    "id",
    "account",
    "folder",
    "uid",
    "message_id",
    "from",
    "to",
    "cc",
    "subject",
    "date",
    "received_at",
    "flags",
    "seen",
    "was_encrypted",
    "decrypted",
    "was_signed",
    "signature",
    "protected_subject",
    "attachment_count",
    "raw_size",
    "decrypt_error",
];
const DETAIL_KEYS: &[&str] = &["text", "html", "attachments", "in_reply_to", "references"];

fn assert_keys(v: &serde_json::Value, keys: &[&str]) {
    let obj = v
        .as_object()
        .unwrap_or_else(|| panic!("not an object: {v}"));
    for k in keys {
        assert!(obj.contains_key(*k), "missing key {k:?} in {v}");
    }
}

#[test]
#[ignore = "part of the G8 gate (fast, offline)"]
fn dry_run_detects_gmail_and_outlook_offline() {
    let p = Profile::new("dry");
    let g = p.json(&[
        "account",
        "add",
        "--email",
        "someone@gmail.com",
        "--dry-run",
    ]);
    assert_eq!(g["servers"]["imap"]["host"], "imap.gmail.com");
    assert_eq!(g["servers"]["imap"]["port"], 993);
    assert_eq!(g["servers"]["imap"]["security"], "Tls");
    assert_eq!(g["servers"]["smtp"]["host"], "smtp.gmail.com");
    assert_eq!(g["servers"]["source"], "BuiltIn");
    assert_eq!(g["login"], "someone@gmail.com");
    assert!(g["auth_hint"].as_str().unwrap().contains("OAuth2"));
    let text = p.ok(&[
        "account",
        "add",
        "--email",
        "someone@gmail.com",
        "--dry-run",
    ]);
    assert!(text.contains("imap.gmail.com:993 tls"), "{text}");
    assert!(text.contains("smtp.gmail.com:465 tls"), "{text}");

    let o = p.json(&[
        "account",
        "add",
        "--email",
        "someone@outlook.com",
        "--dry-run",
    ]);
    assert_eq!(o["servers"]["imap"]["host"], "outlook.office365.com");
    assert_eq!(o["servers"]["smtp"]["host"], "smtp.office365.com");
    assert_eq!(o["servers"]["smtp"]["port"], 587);
    assert_eq!(o["servers"]["smtp"]["security"], "StartTls");
    assert_eq!(o["servers"]["source"], "BuiltIn");
    // Nothing was stored by a dry run.
    assert!(p.json(&["account", "list"]).as_array().unwrap().is_empty());
    // Manual servers are echoed back verbatim.
    let m = p.json(&[
        "account",
        "add",
        "--email",
        "x@example.org",
        "--imap",
        "mail.example.org:143:starttls",
        "--smtp",
        "mail.example.org:587:starttls",
        "--dry-run",
    ]);
    assert_eq!(m["servers"]["imap"]["host"], "mail.example.org");
    assert_eq!(m["servers"]["imap"]["security"], "StartTls");
    // Usage errors exit 2.
    let r = p.run(&[
        "account",
        "add",
        "--email",
        "x@example.org",
        "--imap",
        "h:1:plain",
    ]);
    assert_eq!(r.code, 2, "--imap without --smtp must be a usage error");
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn cli_works_as_a_desktop_client() {
    let tag = nonce("g8");
    // One desktop profile holding two accounts, and Bob on another machine.
    let desk = Profile::new("desk");
    let bob = Profile::new("bob");
    desk.add_greenmail_account("alice");
    desk.add_greenmail_account("carol");
    bob.add_greenmail_account("bob");
    let accounts = desk.json(&["account", "list"]);
    assert_eq!(accounts.as_array().unwrap().len(), 2);
    let alice_fp = desk.fingerprint("alice@sealbox.test");
    let carol_fp = desk.fingerprint("carol@sealbox.test");
    assert_ne!(alice_fp, carol_fp);

    // Baseline: everything that is already in the mailboxes gets synced once.
    desk.ok(&["sync"]);
    bob.sync("bob@sealbox.test");

    // Bob writes to both (plaintext: he knows no keys yet).
    let s_alice = format!("to alice {tag}");
    let s_carol = format!("to carol {tag}");
    for (to, subj) in [
        ("alice@sealbox.test", &s_alice),
        ("carol@sealbox.test", &s_carol),
    ] {
        let r = bob.json(&[
            "send",
            "--from",
            "bob@sealbox.test",
            "--to",
            to,
            "--subject",
            subj,
            "--body",
            &format!("body {tag}"),
            "--policy",
            "plaintext",
        ]);
        assert_eq!(r["mode"], "plaintext");
    }

    // Unified inbox: `sync` (all accounts) then `list` without --account shows both.
    assert!(
        wait_until(Duration::from_secs(20), || async {
            let reps = desk.json(&["sync"]);
            assert_eq!(reps.as_array().unwrap().len(), 2, "{reps}");
            let all = desk.list(None, "INBOX");
            all.iter().any(|m| m["subject"] == s_alice.as_str())
                && all.iter().any(|m| m["subject"] == s_carol.as_str())
        })
        .await,
        "Bob's mails did not arrive in both accounts"
    );
    let all = desk.list(None, "INBOX");
    let ma = all
        .iter()
        .find(|m| m["subject"] == s_alice.as_str())
        .unwrap();
    let mc = all
        .iter()
        .find(|m| m["subject"] == s_carol.as_str())
        .unwrap();
    assert_eq!(ma["account"], "alice@sealbox.test");
    assert_eq!(mc["account"], "carol@sealbox.test");
    assert_keys(ma, SUMMARY_KEYS);
    assert_eq!(
        desk.list(Some("carol@sealbox.test"), "INBOX")
            .iter()
            .filter(|m| m["subject"] == s_alice.as_str())
            .count(),
        0,
        "--account must filter"
    );
    let unified_text = desk.ok(&["list"]);
    assert!(
        unified_text.contains("alice@sealbox.test") && unified_text.contains("carol@sealbox.test")
    );

    // Incremental sync: nothing new now; exactly one new for Carol after one more mail.
    for rep in desk.json(&["sync"]).as_array().unwrap() {
        assert_eq!(rep["new"], 0, "{rep}");
    }
    let s_carol2 = format!("to carol again {tag}");
    bob.json(&[
        "send",
        "--from",
        "bob@sealbox.test",
        "--to",
        "carol@sealbox.test",
        "--subject",
        &s_carol2,
        "--body",
        "again",
        "--policy",
        "plaintext",
    ]);
    assert!(
        wait_until(Duration::from_secs(20), || async {
            desk.list(Some("carol@sealbox.test"), "INBOX")
                .iter()
                .any(|m| m["subject"] == s_carol2.as_str())
                || {
                    let rep = desk.sync("carol@sealbox.test");
                    rep["new"].as_u64() == Some(1)
                }
        })
        .await
    );
    assert_eq!(desk.sync("alice@sealbox.test")["new"], 0);
    assert_eq!(desk.sync("carol@sealbox.test")["new"], 0);

    // Flags: a fresh message is unseen; `read` marks it \Seen locally and on the server.
    let ma = desk.find_by_subject(Some("alice@sealbox.test"), "INBOX", &s_alice);
    assert_eq!(ma["seen"], false, "{ma}");
    let id = ma["id"].as_i64().unwrap();
    let uid = ma["uid"].as_u64().unwrap() as u32;
    let read = desk.json(&["read", &id.to_string()]);
    assert_keys(&read, SUMMARY_KEYS);
    assert_keys(&read, DETAIL_KEYS);
    assert_eq!(read["seen"], true);
    assert_eq!(read["text"].as_str().unwrap().trim(), format!("body {tag}"));
    assert_eq!(read["was_encrypted"], false);
    let server_flags = flags_of("alice", "INBOX", uid).await;
    assert!(
        server_flags.iter().any(|f| f == "\\Seen"),
        "server flags {server_flags:?}"
    );
    let again = desk.find_by_subject(Some("alice@sealbox.test"), "INBOX", &s_alice);
    assert_eq!(again["seen"], true);
    // flag --add/--remove round trip
    let f = desk.json(&["flag", &id.to_string(), "--add", "\\Flagged"]);
    assert!(f["flags"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x == "\\Flagged"));
    let f = desk.json(&["flag", &id.to_string(), "--remove", "\\Flagged"]);
    assert!(!f["flags"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x == "\\Flagged"));
    // `read --raw` returns the RFC 822 bytes
    let raw = desk.ok(&["read", &id.to_string(), "--raw"]);
    assert!(raw.contains("Message-ID:"), "{raw}");
    assert!(raw.contains(&s_alice));

    // Key export / import between profiles, then an encrypted send with no Autocrypt
    // exchange at all (Bob never received mail from Alice).
    let key_file = desk.path().join("alice.asc");
    desk.ok(&[
        "key",
        "export",
        "--address",
        "alice@sealbox.test",
        "--file",
        key_file.to_str().unwrap(),
    ]);
    let armored = std::fs::read_to_string(&key_file).unwrap();
    assert!(armored.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    assert!(!armored.contains("PRIVATE"));
    let imported = bob.json(&[
        "key",
        "import",
        "--address",
        "alice@sealbox.test",
        "--file",
        key_file.to_str().unwrap(),
    ]);
    assert_eq!(imported["fingerprint"], alice_fp.as_str());
    assert_eq!(imported["source"], "imported");
    // "available" for a brand-new peer; "encrypt" when Bob already saw Alice announce
    // prefer-encrypt=mutual (GreenMail keeps mail from earlier runs around).
    assert!(
        imported["recommendation"] == "available" || imported["recommendation"] == "encrypt",
        "{imported}"
    );
    let wrong = bob.run(&[
        "key",
        "import",
        "--address",
        "carol@sealbox.test",
        "--file",
        key_file.to_str().unwrap(),
    ]);
    assert_ne!(
        wrong.code, 0,
        "a key without a User ID for the address must be refused"
    );
    let show = bob.json(&["key", "show", "--address", "alice@sealbox.test"]);
    assert_eq!(show["fingerprint"], alice_fp.as_str());

    let enc_subject = format!("imported-key encrypted {tag}");
    let enc_body = format!("only alice can read this {tag}");
    let r = bob.json(&[
        "send",
        "--from",
        "bob@sealbox.test",
        "--to",
        "alice@sealbox.test",
        "--subject",
        &enc_subject,
        "--body",
        &enc_body,
    ]);
    assert_eq!(r["mode"], "encrypted", "{r}");
    assert_eq!(r["recipients"][0]["source"], "imported");
    let enc_mid = r["message_id"].as_str().unwrap().to_string();
    assert!(
        wait_until(Duration::from_secs(20), || async {
            desk.sync("alice@sealbox.test");
            desk.list(Some("alice@sealbox.test"), "INBOX")
                .iter()
                .any(|m| m["message_id"].as_str() == Some(enc_mid.as_str()))
        })
        .await
    );
    let m = desk.find_by_subject(Some("alice@sealbox.test"), "INBOX", &enc_subject);
    assert_eq!(m["was_encrypted"], true);
    assert_eq!(m["decrypted"], true);
    assert_eq!(m["protected_subject"], true);
    // Bob's Autocrypt header rides on the encrypted mail, so his signature verifies.
    assert_eq!(m["signature"]["status"], "good", "{m}");
    let d = desk.json(&["read", &m["id"].to_string(), "--no-mark"]);
    assert_eq!(d["text"].as_str().unwrap().trim(), enc_body);
    // Carol (same profile, no key for her at Bob's) is still unreachable encrypted:
    let r = bob.run(&[
        "send",
        "--from",
        "bob@sealbox.test",
        "--to",
        "carol@sealbox.test",
        "--subject",
        "x",
        "--body",
        "y",
    ]);
    assert_eq!(r.code, 3);

    // Sent-folder copy: Bob syncs and can read his own encrypted mail from Sent.
    bob.sync("bob@sealbox.test");
    let sent = bob.list(Some("bob@sealbox.test"), "Sent");
    let copy = sent
        .iter()
        .find(|m| m["message_id"].as_str() == Some(enc_mid.as_str()))
        .unwrap_or_else(|| {
            panic!("sent copy <{enc_mid}> missing from Bob's Sent folder: {sent:?}")
        });
    assert_eq!(copy["was_encrypted"], true);
    assert_eq!(copy["decrypted"], true, "{copy}");
    assert_eq!(copy["subject"], enc_subject.as_str());
    assert_eq!(copy["seen"], true);
    let copy_detail = bob.json(&["read", &copy["id"].to_string(), "--no-mark"]);
    assert_eq!(copy_detail["text"].as_str().unwrap().trim(), enc_body);
    assert_eq!(copy_detail["signature"]["status"], "good");
    let star = bob.list(Some("bob@sealbox.test"), "*");
    assert!(star.iter().any(|m| m["folder"] == "Sent"));

    // watch: IDLE picks up a message delivered while waiting (bounded by --timeout).
    desk.sync("carol@sealbox.test");
    let mut child = desk
        .cmd(&[
            "watch",
            "--account",
            "carol@sealbox.test",
            "--timeout",
            "45",
            "--once",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn watch");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let idle_subject = format!("delivered during idle {tag}");
    bob.json(&[
        "send",
        "--from",
        "bob@sealbox.test",
        "--to",
        "carol@sealbox.test",
        "--subject",
        &idle_subject,
        "--body",
        "wake up",
        "--policy",
        "plaintext",
    ]);
    let started = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            break st;
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!("watch did not return within 60 s");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    eprintln!("watch stdout:\n{out}\nwatch stderr:\n{err}");
    assert!(status.success(), "watch exited {status:?}: {err}");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "watch took {:?}: IDLE did not wake up promptly",
        started.elapsed()
    );
    assert!(
        out.contains(&idle_subject),
        "watch output lacks the new message:\n{out}"
    );
    let m = desk.find_by_subject(Some("carol@sealbox.test"), "INBOX", &idle_subject);
    assert_eq!(m["account"], "carol@sealbox.test");

    // JSON watch output is NDJSON of events.
    let r = desk.run(&[
        "--json",
        "watch",
        "--account",
        "carol@sealbox.test",
        "--timeout",
        "2",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let first_line = r.stdout.lines().find(|l| l.trim_start().starts_with('{'));
    assert!(first_line.is_some(), "no JSON event in {}", r.stdout);

    // Removing an account drops its messages from the unified view.
    desk.ok(&["account", "remove", "--email", "carol@sealbox.test"]);
    assert_eq!(desk.json(&["account", "list"]).as_array().unwrap().len(), 1);
    assert!(desk
        .list(None, "*")
        .iter()
        .all(|m| m["account"] != "carol@sealbox.test"));
}
