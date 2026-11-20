//! Gate G25 — spam detection + filtering end to end against GreenMail (users u21–u25):
//! u22 sends u21 a ham mail and an obvious spam mail (lottery / phishing wording, a dangerous
//! double-extension attachment, a lookalike of u21's contact as sender, a lookalike link);
//! after `sync` the spam sits `\Seen` in u21's Spam folder **on the server** and the ham in
//! INBOX; `spam explain` lists the reasons; `spam learn --ham` moves it back and updates the
//! model (and a later sync does not duplicate it); `spam learn --spam` moves it again; a
//! filter rule `subject contains "[newsletter]" → move:Newsletters` routes the next matching
//! mail; a blocklisted domain is spam regardless of content; disabling detection stops it.
//!
//! Needs `testing/mail_up.sh`. Run with
//! `cargo test -p sealbox-cli --test gate_g25 -- --ignored`.

mod common;

use std::time::Duration;

use common::{imap_login, nonce, wait_until, Profile};
use sealbox_mail::smtp::SmtpClient;
use sealbox_mail::{Auth, Security};

const U21: &str = "u21@sealbox.test";
const U22: &str = "u22@sealbox.test";

/// `(uid, subject, flags)` of every message in a user's folder on the server; empty when the
/// folder does not exist.
async fn folder_messages(user: &str, folder: &str) -> Vec<(u32, String, Vec<String>)> {
    let mut imap = imap_login(user).await;
    if imap.select(folder).await.is_err() {
        let _ = imap.logout().await;
        return Vec::new();
    }
    let uids = imap.fetch_new_uids(0).await.expect("search");
    let mut out = Vec::new();
    for chunk in uids.chunks(50) {
        for m in imap.fetch_rfc822_batch(chunk).await.expect("fetch") {
            let subject = sealbox_mail::mime::parse(&m.raw)
                .ok()
                .and_then(|p| p.headers.subject)
                .unwrap_or_default();
            out.push((m.uid, subject, m.flags));
        }
    }
    let _ = imap.logout().await;
    out
}

async fn server_has(user: &str, folder: &str, subject: &str) -> bool {
    folder_messages(user, folder)
        .await
        .iter()
        .any(|(_, s, _)| s == subject)
}

/// Submit raw bytes over SMTP as `user` (GreenMail does not check the From header, which is
/// exactly what a phisher relies on).
async fn smtp_submit(user: &str, envelope_from: &str, to: &str, raw: &[u8]) {
    let client = SmtpClient::connect_with_timeout(
        "127.0.0.1",
        3025,
        Security::Plain,
        Some(Auth::Password {
            user: user.into(),
            pass: format!("{user}pw"),
        }),
        Duration::from_secs(30),
    )
    .expect("smtp connect");
    client
        .send_raw(envelope_from, &[to.to_string()], raw)
        .await
        .expect("smtp submit");
    client.shutdown().await;
}

fn spam_mail(subject: &str) -> Vec<u8> {
    // No Message-ID, no Date, HTML-free: the rules alone must catch it (fresh model).
    format!(
        "From: \"u22@sealbox.test\" <u22@sea1box.test>\r\n\
To: {U21}\r\n\
Reply-To: claims-office@gmail.com\r\n\
Subject: {subject}\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"g25b\"\r\n\
\r\n\
--g25b\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Dear winner,\r\n\
\r\n\
CONGRATULATIONS! You have been selected in our international lottery.\r\n\
To claim your prize of 1,000,000 USD please verify your account at\r\n\
http://sealbox.test.secure-login.example/verify/account within 24 hours.\r\n\
\r\n\
Kind regards, the claims office\r\n\
--g25b\r\n\
Content-Type: application/octet-stream; name=\"prize-details.pdf.exe\"\r\n\
Content-Disposition: attachment; filename=\"prize-details.pdf.exe\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
--g25b--\r\n"
    )
    .into_bytes()
}

fn innocuous_mail(from: &str, subject: &str) -> Vec<u8> {
    format!(
        "From: Nice Person <{from}>\r\n\
To: {U21}\r\n\
Subject: {subject}\r\n\
Date: Mon, 27 Oct 2026 10:00:00 +0000\r\n\
Message-ID: <{}@{}>\r\n\
\r\n\
Hello, just checking in about the meeting notes. Thanks!\r\n",
        nonce("mid"),
        from.rsplit('@').next().unwrap_or("example")
    )
    .into_bytes()
}

fn reason_codes(v: &serde_json::Value) -> Vec<String> {
    v["reasons"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|r| r["code"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn spam_is_moved_ham_stays_learning_and_filters_work() {
    let tag = nonce("g25");
    let u21 = Profile::new("u21");
    let u22 = Profile::new("u22");
    u21.add_greenmail_account("u21");
    u22.add_greenmail_account("u22");
    // Mailboxes persist between runs: swallow whatever is there first.
    u21.ok(&["sync"]);

    // ---- 1. ham from u22 (plaintext; the Autocrypt header makes u22 a contact of u21) ----
    let ham_subject = format!("lunch tomorrow? {tag}");
    u22.ok(&[
        "send",
        "--from",
        U22,
        "--to",
        U21,
        "--subject",
        &ham_subject,
        "--body",
        "Hi, are we still on for lunch at 12 tomorrow? See you then.",
        "--policy",
        "plaintext",
    ]);

    // ---- 2. obvious spam submitted over SMTP as u22 with a forged lookalike sender ----
    let spam_subject = format!("CONGRATULATIONS you have WON {tag}");
    smtp_submit("u22", U22, U21, &spam_mail(&spam_subject)).await;
    assert!(
        wait_until(Duration::from_secs(20), || async {
            server_has("u21", "INBOX", &spam_subject).await
                && server_has("u21", "INBOX", &ham_subject).await
        })
        .await,
        "both mails must reach u21's INBOX"
    );

    // ---- 3. sync: spam → Spam folder on the server (\Seen), ham stays in INBOX ----
    let report = u21.sync(U21);
    assert!(report["new"].as_u64().unwrap_or(0) >= 2, "{report}");
    let ham = u21.find_by_subject(Some(U21), "INBOX", &ham_subject);
    let spam = u21.find_by_subject(Some(U21), "Spam", &spam_subject);
    assert_eq!(spam["folder"], "Spam");
    assert_eq!(spam["seen"], true, "spam is marked read: {spam}");
    let spam_id = spam["id"].as_i64().unwrap().to_string();
    let ham_id = ham["id"].as_i64().unwrap().to_string();
    let inbox = folder_messages("u21", "INBOX").await;
    let junk = folder_messages("u21", "Spam").await;
    assert!(
        inbox.iter().any(|(_, s, _)| s == &ham_subject),
        "ham must stay in INBOX"
    );
    assert!(
        !inbox.iter().any(|(_, s, _)| s == &spam_subject),
        "spam must leave INBOX"
    );
    let (junk_uid, _, junk_flags) = junk
        .iter()
        .find(|(_, s, _)| s == &spam_subject)
        .expect("spam must be in the Spam folder on the server");
    assert!(
        junk_flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")),
        "spam must be \\Seen on the server: {junk_flags:?}"
    );
    assert_eq!(
        spam["uid"].as_u64().unwrap() as u32,
        *junk_uid,
        "local row points at the new UID"
    );
    assert!(
        !inbox.iter().any(|(_, s, _)| s == &spam_subject),
        "nothing was deleted, only moved"
    );

    // ---- 4. explain lists the reasons ----
    let x = u21.json(&["spam", "explain", &spam_id]);
    assert_eq!(x["stored"]["label"], "spam", "{x}");
    assert_eq!(x["verdict"]["label"], "spam");
    let codes = reason_codes(&x["verdict"]);
    for expected in [
        "dangerous_attachment",
        "double_extension",
        "lookalike_sender",
        "display_name_spoof",
        "phish_language",
        "scam_language",
        "lookalike_url",
    ] {
        assert!(
            codes.contains(&expected.to_string()),
            "missing reason {expected} in {codes:?}"
        );
    }
    assert!(x["verdict"]["spam_probability"].as_f64().unwrap() > 0.99);
    assert!(!x["features"]["attachments"].as_array().unwrap().is_empty());
    let text = u21.ok(&["spam", "explain", &spam_id]);
    assert!(
        text.contains("dangerous_attachment") && text.contains("Reasons:"),
        "{text}"
    );
    let xh = u21.json(&["spam", "explain", &ham_id]);
    assert_eq!(xh["stored"]["label"], "ham", "{xh}");
    assert!(
        reason_codes(&xh["verdict"]).contains(&"known_sender".to_string()),
        "u22 is a contact after the first mail: {xh}"
    );

    // ---- 5. learn --ham: back to INBOX, model updated, no duplicate on the next sync ----
    let before = u21.json(&["spam", "status"]);
    let ham_before = before["model_ham_messages"].as_u64().unwrap();
    let r = u21.json(&["spam", "learn", "--ham", &spam_id]);
    assert_eq!(r["moved_to"], "INBOX", "{r}");
    assert_eq!(r["learned"], "ham");
    assert_eq!(r["model_ham_messages"].as_u64().unwrap(), ham_before + 1);
    assert!(
        server_has("u21", "INBOX", &spam_subject).await,
        "learn --ham moves it back on the server"
    );
    assert!(!server_has("u21", "Spam", &spam_subject).await);
    let back = u21.find_by_subject(Some(U21), "INBOX", &spam_subject);
    assert_eq!(
        back["id"].as_i64().unwrap().to_string(),
        spam_id,
        "same local id after the move"
    );
    u21.sync(U21);
    let copies = u21
        .list(Some(U21), "*")
        .into_iter()
        .filter(|m| m["subject"].as_str() == Some(spam_subject.as_str()))
        .count();
    assert_eq!(
        copies, 1,
        "a later sync must not duplicate the moved message"
    );
    let x2 = u21.json(&["spam", "explain", &spam_id]);
    assert_eq!(x2["stored"]["learned"], "ham");
    assert_eq!(x2["stored"]["label"], "ham");

    // ---- 6. learn --spam: moves it to Spam again and flips the model ----
    let r = u21.json(&["spam", "learn", "--spam", &spam_id]);
    assert_eq!(r["moved_to"], "Spam", "{r}");
    assert_eq!(r["previously_learned"], "ham");
    assert_eq!(r["model_ham_messages"].as_u64().unwrap(), ham_before);
    assert!(r["model_spam_messages"].as_u64().unwrap() >= 1);
    assert!(server_has("u21", "Spam", &spam_subject).await);
    assert!(!server_has("u21", "INBOX", &spam_subject).await);

    // ---- 7. filter rule: [newsletter] → Newsletters ----
    let rule = u21.json(&[
        "filter",
        "add",
        "--account",
        U21,
        "--field",
        "subject",
        "--op",
        "contains",
        "--value",
        "[newsletter]",
        "--action",
        "move:Newsletters",
    ]);
    let rule_id = rule["id"].as_i64().unwrap();
    assert!(rule_id > 0, "{rule}");
    assert_eq!(rule["action"]["move_to"]["folder"], "Newsletters");
    let rules = u21.json(&["filter", "list", "--account", U21]);
    assert_eq!(rules.as_array().unwrap().len(), 1);
    let news_subject = format!("[Newsletter] October issue {tag}");
    u22.ok(&[
        "send",
        "--from",
        U22,
        "--to",
        U21,
        "--subject",
        &news_subject,
        "--body",
        "This month: nothing much. Unsubscribe any time.",
        "--policy",
        "plaintext",
    ]);
    assert!(
        wait_until(Duration::from_secs(20), || async {
            server_has("u21", "INBOX", &news_subject).await
        })
        .await
    );
    u21.sync(U21);
    assert!(
        server_has("u21", "Newsletters", &news_subject).await,
        "filter rule must move the newsletter on the server"
    );
    assert!(!server_has("u21", "INBOX", &news_subject).await);
    let news = u21.find_by_subject(Some(U21), "Newsletters", &news_subject);
    let news_id = news["id"].as_i64().unwrap().to_string();
    let t = u21.json(&["filter", "test", &news_id, "--account", U21]);
    assert_eq!(t["outcome"]["move_to"], "Newsletters", "{t}");
    assert!(t["rules"].as_array().unwrap().iter().any(|r| r[2] == true));

    // ---- 8. blocklist: innocuous content from a blocked domain is spam ----
    u21.ok(&["spam", "block", "spammer.example", "--account", U21]);
    let blocked_subject = format!("meeting notes {tag}");
    smtp_submit(
        "u22",
        "nice@spammer.example",
        U21,
        &innocuous_mail("nice@spammer.example", &blocked_subject),
    )
    .await;
    assert!(
        wait_until(Duration::from_secs(20), || async {
            server_has("u21", "INBOX", &blocked_subject).await
        })
        .await
    );
    u21.sync(U21);
    assert!(
        server_has("u21", "Spam", &blocked_subject).await,
        "blocklisted sender goes to Spam"
    );
    let b = u21.find_by_subject(Some(U21), "Spam", &blocked_subject);
    let xb = u21.json(&["spam", "explain", &b["id"].as_i64().unwrap().to_string()]);
    assert_eq!(xb["stored"]["reasons"][0]["code"], "blocklist", "{xb}");
    let status = u21.json(&["spam", "status", "--account", U21]);
    assert_eq!(
        status["accounts"][0]["settings"]["blocklist"][0],
        "spammer.example"
    );
    assert_eq!(status["accounts"][0]["spam_folder"], "Spam");
    assert!(status["accounts"][0]["messages_spam"].as_i64().unwrap() >= 2);

    // ---- 9. detection off: the same spam stays in INBOX; back on afterwards ----
    u21.ok(&[
        "spam",
        "settings",
        "set",
        "--account",
        U21,
        "--enabled",
        "false",
    ]);
    let off_subject = format!("CONGRATULATIONS you have WON again {tag}");
    smtp_submit("u22", U22, U21, &spam_mail(&off_subject)).await;
    assert!(
        wait_until(Duration::from_secs(20), || async {
            server_has("u21", "INBOX", &off_subject).await
        })
        .await
    );
    u21.sync(U21);
    assert!(
        server_has("u21", "INBOX", &off_subject).await,
        "detection disabled: nothing moves"
    );
    let s = u21.json(&[
        "spam",
        "settings",
        "set",
        "--account",
        U21,
        "--enabled",
        "true",
    ]);
    assert_eq!(s["enabled"], true);
    // Removing the filter rule works too.
    assert_eq!(
        u21.json(&["filter", "rm", &rule_id.to_string(), "--account", U21])["removed"],
        true
    );
    assert!(u21
        .json(&["filter", "list", "--account", U21])
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
#[ignore = "part of the G25 gate (fast, offline)"]
fn offline_check_and_settings_validation() {
    let p = Profile::new("g25-offline");
    let dir = p.path().to_path_buf();
    let spam = common::temp_file(&dir, "spam.eml", &spam_mail("You have WON"));
    let v = p.json(&["spam", "check", spam.to_str().unwrap()]);
    assert_eq!(v["label"], "spam", "{v}");
    assert!(reason_codes(&v).contains(&"dangerous_attachment".to_string()));
    let ham = common::temp_file(
        &dir,
        "ham.eml",
        &innocuous_mail("friend@example.org", "notes"),
    );
    let v = p.json(&["spam", "check", ham.to_str().unwrap()]);
    assert_eq!(v["label"], "ham", "{v}");
    // Settings validation is a usage error (exit 2) and needs an account.
    let r = p.run(&[
        "spam",
        "settings",
        "show",
        "--account",
        "nobody@sealbox.test",
    ]);
    assert_ne!(r.code, 0);
    // Filter parsing errors are reported, not panics.
    let r = p.run(&[
        "filter",
        "add",
        "--account",
        "nobody@sealbox.test",
        "--field",
        "nope",
        "--op",
        "contains",
        "--value",
        "x",
        "--action",
        "read",
    ]);
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("unknown field") || r.stdout.contains("unknown field"),
        "{r:?}"
    );
}
