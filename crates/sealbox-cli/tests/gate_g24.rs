//! Gate G24 — holiday / out-of-office auto-reply (RFC 3834) through the real `sealbox`
//! binary against GreenMail (users u13–u20): one reply per sender per period with the
//! RFC 3834 headers, suppression for lists / auto-submitted / bounces, encrypted when the
//! sender has a key, "known contacts only", the window, the log.
//!
//! Needs `testing/mail_up.sh`. Run with
//! `cargo test -p sealbox-cli --test gate_g24 -- --ignored`.

mod common;

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use common::{inbox_raw, nonce, wait_until, Profile};
use sealbox_mail::mime::{build_plain, parse, Mailbox, MessageDraft, MessageKind};
use sealbox_mail::smtp::SmtpClient;
use sealbox_mail::Security;

const U13: &str = "u13@sealbox.test";
const U17: &str = "u17@sealbox.test";

async fn submit(from: &str, to: &str, raw: &[u8]) {
    let smtp = SmtpClient::connect("127.0.0.1", 3025, Security::Plain, None).expect("smtp client");
    smtp.send_raw(from, &[to.to_string()], raw)
        .await
        .expect("SMTP submit");
    smtp.shutdown().await;
}

/// Submit a hand-made plaintext message (no Autocrypt header) and return its Message-ID.
async fn smtp_plain(
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
    extra: &[(&str, &str)],
) -> String {
    let mut d = MessageDraft::new(Mailbox::new(from), vec![Mailbox::new(to)], subject, body);
    for (k, v) in extra {
        d.extra_headers.push((k.to_string(), v.to_string()));
    }
    let raw = build_plain(&d).expect("build");
    submit(from, to, &raw).await;
    d.message_id
}

fn head(raw: &str) -> &str {
    raw.split("\r\n\r\n").next().unwrap_or("")
}

/// Raw auto-replies (`Auto-Submitted: auto-replied`) in `user`'s INBOX whose outer
/// `In-Reply-To` is `message_id`.
async fn auto_replies_to(user: &str, message_id: &str) -> Vec<String> {
    let needle = format!("In-Reply-To: <{message_id}>");
    inbox_raw(user)
        .await
        .into_iter()
        .map(|(_, r)| String::from_utf8_lossy(&r).into_owned())
        .filter(|s| head(s).contains("Auto-Submitted: auto-replied") && head(s).contains(&needle))
        .collect()
}

/// Sync the vacationer until the message with `message_id` is stored (the sync hook sends
/// the auto-reply synchronously).
async fn sync_until_stored(profile: &Profile, email: &str, message_id: &str) {
    assert!(
        wait_until(Duration::from_secs(20), || async {
            profile.sync(email);
            profile
                .list(Some(email), "*")
                .iter()
                .any(|m| m["message_id"].as_str() == Some(message_id))
        })
        .await,
        "message <{message_id}> never synced into {email}"
    );
}

async fn expect_single_reply(user: &str, message_id: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let replies = auto_replies_to(user, message_id).await;
        if replies.len() == 1 {
            // Give a hypothetical duplicate a moment to show up.
            tokio::time::sleep(Duration::from_millis(800)).await;
            let again = auto_replies_to(user, message_id).await;
            assert_eq!(again.len(), 1, "more than one auto-reply reached {user}");
            return replies.into_iter().next().unwrap();
        }
        assert!(
            replies.len() <= 1,
            "{} auto-replies reached {user} for <{message_id}>",
            replies.len()
        );
        assert!(
            Instant::now() < deadline,
            "no auto-reply reached {user} for <{message_id}>"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn expect_no_reply(user: &str, message_id: &str, why: &str) {
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let replies = auto_replies_to(user, message_id).await;
    assert!(
        replies.is_empty(),
        "{why}: {} unexpected auto-reply(ies) reached {user}:\n{}",
        replies.len(),
        replies.join("\n----\n")
    );
}

fn plain_text(raw: &str) -> String {
    match parse(raw.as_bytes()).expect("parse").kind {
        MessageKind::Plain(b) => b.text.unwrap_or_default().replace("\r\n", "\n"),
        other => panic!("expected a plain message, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn out_of_office_replies_once_with_suppression_and_encryption() {
    let u13 = Profile::new("u13");
    u13.add_greenmail_account("u13");
    let u17 = Profile::new("u17");
    u17.add_greenmail_account("u17");
    // GreenMail keeps mailboxes between runs: sync once so that leftovers from earlier runs
    // are behind the responder's cursor (only mail arriving after enabling is answered).
    u13.sync(U13);
    let tag = nonce("g24");
    let away = format!("I am out of the office until next week {tag}");

    // (1) Enable on u13 with a window containing now.
    let shown = u13.json(&["settings", "autoreply", "show", "--account", U13]);
    assert_eq!(shown["enabled"], false, "{shown}");
    assert_eq!(shown["reply_once_per_sender_days"], 7);
    assert_eq!(shown["encrypt_when_possible"], true);
    assert_eq!(shown["only_to_known_contacts"], false);
    let set = u13.json(&[
        "settings",
        "autoreply",
        "set",
        "--account",
        U13,
        "--enable",
        "--from",
        "2000-01-01",
        "--to",
        "2100-01-01",
        "--subject",
        "Automatic reply: {subject}",
        "--body",
        &away,
        "--once-per-days",
        "7",
    ]);
    assert_eq!(set["enabled"], true, "{set}");
    assert_eq!(set["start"], "2000-01-01T00:00:00Z");
    assert_eq!(set["end"], "2100-01-01T00:00:00Z");
    assert_eq!(set["body"], away.as_str());
    let human = u13.ok(&["settings", "autoreply", "show", "--account", U13]);
    assert!(human.contains("active now"), "{human}");
    // A bad window is a usage error.
    let r = u13.run(&[
        "settings",
        "autoreply",
        "set",
        "--account",
        U13,
        "--from",
        "2100-01-01",
        "--to",
        "2000-01-01",
    ]);
    assert_eq!(r.code, 2, "{} {}", r.stdout, r.stderr);

    // (2) u14 (no key) writes → exactly one plaintext auto-reply with the RFC 3834 headers.
    let ping = smtp_plain(
        "u14@sealbox.test",
        U13,
        &format!("ping {tag}"),
        "are you there?\r\n",
        &[],
    )
    .await;
    sync_until_stored(&u13, U13, &ping).await;
    let reply = expect_single_reply("u14", &ping).await;
    let h = head(&reply);
    for expected in [
        "Auto-Submitted: auto-replied",
        "Precedence: auto_reply",
        "X-Auto-Response-Suppress: All",
        &format!("In-Reply-To: <{ping}>"),
        &format!("References: <{ping}>"),
        &format!("Subject: Automatic reply: ping {tag}"),
        "From: \"U13\" <u13@sealbox.test>",
        "Autocrypt: addr=u13@sealbox.test",
    ] {
        assert!(h.contains(expected), "missing `{expected}` in:\n{h}");
    }
    assert!(h.contains("u14@sealbox.test"), "{h}");
    assert!(
        !h.to_ascii_lowercase().contains("multipart/encrypted"),
        "u14 has no key: the reply must be plaintext\n{h}"
    );
    let text = plain_text(&reply);
    assert!(text.contains(&away), "{text}");
    assert!(
        !text.contains("-- "),
        "auto-replies never carry a signature:\n{text}"
    );

    // (3) u14 writes again → no second reply within the period.
    let ping2 = smtp_plain(
        "u14@sealbox.test",
        U13,
        &format!("ping again {tag}"),
        "still there?\r\n",
        &[],
    )
    .await;
    sync_until_stored(&u13, U13, &ping2).await;
    expect_no_reply("u14", &ping2, "second mail from the same sender").await;
    assert_eq!(auto_replies_to("u14", &ping).await.len(), 1);

    // (4) Mailing-list traffic, (5) auto-submitted mail and (6) a bounce get nothing.
    let list_mid = smtp_plain(
        "u15@sealbox.test",
        U13,
        &format!("[dev] list post {tag}"),
        "list body\r\n",
        &[
            ("List-Id", "Dev <dev.lists.sealbox.test>"),
            ("List-Unsubscribe", "<mailto:dev-leave@sealbox.test>"),
            ("Precedence", "list"),
        ],
    )
    .await;
    sync_until_stored(&u13, U13, &list_mid).await;
    expect_no_reply("u15", &list_mid, "List-Id mail").await;

    let auto_mid = smtp_plain(
        "u16@sealbox.test",
        U13,
        &format!("Automatic reply: something {tag}"),
        "I am away too\r\n",
        &[("Auto-Submitted", "auto-replied")],
    )
    .await;
    sync_until_stored(&u13, U13, &auto_mid).await;
    expect_no_reply("u16", &auto_mid, "Auto-Submitted mail").await;

    let bounce_mid = format!("{}@sealbox.test", nonce("bounce"));
    let bounce = format!(
        "From: Mail Delivery System <MAILER-DAEMON@sealbox.test>\r\nTo: {U13}\r\n\
         Subject: Undelivered Mail Returned to Sender {tag}\r\nMessage-ID: <{bounce_mid}>\r\n\
         MIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=delivery-status; boundary=\"b\"\r\n\r\n\
         --b\r\nContent-Type: text/plain\r\n\r\nThis is the mail system at host sealbox.test.\r\n\
         --b\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; sealbox.test\r\n\
         --b--\r\n"
    );
    submit("MAILER-DAEMON@sealbox.test", U13, bounce.as_bytes()).await;
    sync_until_stored(&u13, U13, &bounce_mid).await;
    // Nothing may have been sent to the daemon: the log must not know it.
    let log = u13.json(&["settings", "autoreply", "log", "--account", U13]);
    assert!(
        !log.to_string()
            .to_ascii_lowercase()
            .contains("mailer-daemon"),
        "{log}"
    );

    // (7) u17 has exchanged Autocrypt keys (its first mail carries the header) → the
    //     auto-reply goes out encrypted + signed and u17 decrypts it with the CLI.
    let r = u17.json(&[
        "send",
        "--from",
        U17,
        "--to",
        U13,
        "--subject",
        &format!("hello from u17 {tag}"),
        "--body",
        "first contact with my key",
        "--policy",
        "plaintext",
    ]);
    let u17_mid = r["message_id"].as_str().unwrap().to_string();
    sync_until_stored(&u13, U13, &u17_mid).await;
    let reply = expect_single_reply("u17", &u17_mid).await;
    let h = head(&reply);
    assert!(
        h.to_ascii_lowercase().contains("multipart/encrypted"),
        "reply to a key-holder must be encrypted:\n{h}"
    );
    assert!(h.contains("protocol=\"application/pgp-encrypted\""), "{h}");
    assert!(
        h.contains("Subject: ..."),
        "protected subject expected:\n{h}"
    );
    assert!(h.contains("Auto-Submitted: auto-replied"), "{h}");
    assert!(h.contains("Precedence: auto_reply"), "{h}");
    assert!(
        !reply.contains(&away),
        "body leaked in the encrypted auto-reply"
    );
    let reply_subject = format!("Automatic reply: hello from u17 {tag}");
    let deadline = Instant::now() + Duration::from_secs(20);
    let reply_id = loop {
        u17.sync(U17);
        let found = u17
            .list(Some(U17), "INBOX")
            .into_iter()
            .find(|m| m["subject"].as_str() == Some(reply_subject.as_str()))
            .and_then(|m| m["id"].as_i64());
        if let Some(id) = found {
            break id;
        }
        assert!(
            Instant::now() < deadline,
            "u17 could not decrypt / find the auto-reply"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    };
    let read = u17.json(&["read", &reply_id.to_string()]);
    assert_eq!(read["was_encrypted"], true, "{read}");
    assert_eq!(read["decrypted"], true, "{read}");
    assert_eq!(read["protected_subject"], true);
    assert_eq!(read["signature"]["status"], "good", "{read}");
    assert_eq!(read["signature"]["signer"], U13);
    assert_eq!(read["in_reply_to"][0], u17_mid.as_str());
    let text = read["text"].as_str().unwrap().replace("\r\n", "\n");
    assert!(text.contains(&away), "{text}");
    assert!(!text.contains("-- "), "{text}");

    // (8) Known contacts only: u19 is a stranger, u20 was written to before.
    let set = u13.json(&[
        "settings",
        "autoreply",
        "set",
        "--account",
        U13,
        "--only-known-contacts",
    ]);
    assert_eq!(set["only_to_known_contacts"], true);
    assert_eq!(set["enabled"], true, "flags must not touch `enabled`");
    let stranger = smtp_plain(
        "u19@sealbox.test",
        U13,
        &format!("stranger {tag}"),
        "hi\r\n",
        &[],
    )
    .await;
    sync_until_stored(&u13, U13, &stranger).await;
    expect_no_reply("u19", &stranger, "unknown contact").await;
    u13.json(&[
        "send",
        "--from",
        U13,
        "--to",
        "u20@sealbox.test",
        "--subject",
        &format!("hi u20 {tag}"),
        "--body",
        "let's keep in touch",
        "--policy",
        "plaintext",
    ]);
    let known = smtp_plain(
        "u20@sealbox.test",
        U13,
        &format!("from a known contact {tag}"),
        "hello back\r\n",
        &[],
    )
    .await;
    sync_until_stored(&u13, U13, &known).await;
    let reply = expect_single_reply("u20", &known).await;
    assert!(plain_text(&reply).contains(&away));
    u13.json(&[
        "settings",
        "autoreply",
        "set",
        "--account",
        U13,
        "--any-sender",
    ]);

    // (9) Outside the window → nothing.
    let set = u13.json(&[
        "settings",
        "autoreply",
        "set",
        "--account",
        U13,
        "--from",
        "2020-01-01",
        "--to",
        "2020-01-02",
    ]);
    assert_eq!(set["enabled"], true);
    let human = u13.ok(&["settings", "autoreply", "show", "--account", U13]);
    assert!(human.contains("outside the window"), "{human}");
    let late = smtp_plain(
        "u18@sealbox.test",
        U13,
        &format!("too late {tag}"),
        "anyone?\r\n",
        &[],
    )
    .await;
    sync_until_stored(&u13, U13, &late).await;
    expect_no_reply("u18", &late, "outside the window").await;

    // (10) The log knows exactly u14, u17 (encrypted) and u20; a manual run finds nothing
    //      left to evaluate; the whole settings block round-trips.
    let log = u13.json(&["settings", "autoreply", "log", "--account", U13]);
    let entries = log.as_array().expect("log array");
    let senders: BTreeSet<&str> = entries
        .iter()
        .filter_map(|e| e["sender"].as_str())
        .collect();
    assert_eq!(
        senders,
        ["u14@sealbox.test", "u17@sealbox.test", "u20@sealbox.test"]
            .into_iter()
            .collect::<BTreeSet<_>>(),
        "{log}"
    );
    assert_eq!(entries.len(), 3, "{log}");
    for e in entries {
        let enc = e["sender"] == U17;
        assert_eq!(e["encrypted"], enc, "{e}");
        assert!(e["message_id"].as_str().is_some_and(|m| m.contains('@')));
        assert!(e["in_reply_to"].as_str().is_some());
    }
    let human = u13.ok(&["settings", "autoreply", "log", "--account", U13]);
    assert!(
        human.contains("u17@sealbox.test") && human.contains("🔒"),
        "{human}"
    );
    let run = u13.json(&["settings", "autoreply", "run", "--account", U13]);
    assert_eq!(run["evaluated"], 0, "{run}");
    assert_eq!(run["active"], false);
    let all = u13.json(&["settings", "show", "--account", U13]);
    assert_eq!(all["autoreply"]["enabled"], true);
    assert_eq!(all["autoreply"]["body"], away.as_str());

    // (11) Disable.
    let set = u13.json(&[
        "settings",
        "autoreply",
        "set",
        "--account",
        U13,
        "--disable",
    ]);
    assert_eq!(set["enabled"], false);
    assert!(!u13
        .ok(&["settings", "autoreply", "show", "--account", U13])
        .contains("active now"));
}
