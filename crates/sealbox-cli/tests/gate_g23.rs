//! Gate G23 — per-account signatures through the real `sealbox` binary against GreenMail
//! (users u11/u12): set via the CLI (text + sanitised HTML), applied to new mail and to
//! quoted replies in both placements, in plaintext and encrypted messages, switchable per
//! message and per kind, and never on an auto-reply.
//!
//! Needs `testing/mail_up.sh`. Run with
//! `cargo test -p sealbox-cli --test gate_g23 -- --ignored`.

mod common;

use std::time::{Duration, Instant};

use common::{inbox_raw, nonce, temp_file, Profile};
use sealbox_mail::mime::{parse, MessageKind};

const U11: &str = "u11@sealbox.test";
const U12: &str = "u12@sealbox.test";

/// The raw message carrying `message_id` from `user`'s INBOX (waits up to 20 s).
async fn wait_raw(user: &str, message_id: &str) -> String {
    let needle = format!("<{message_id}>");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let found = inbox_raw(user)
            .await
            .into_iter()
            .map(|(_, r)| String::from_utf8_lossy(&r).into_owned())
            .find(|s| s.contains(&needle));
        if let Some(raw) = found {
            return raw;
        }
        assert!(
            Instant::now() < deadline,
            "message <{message_id}> never reached {user}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

fn head(raw: &str) -> &str {
    raw.split("\r\n\r\n").next().unwrap_or("")
}

/// Decoded text and HTML bodies of a plaintext (non-PGP) message, LF line endings.
fn plain_bodies(raw: &str) -> (String, Option<String>) {
    match parse(raw.as_bytes()).expect("parse").kind {
        MessageKind::Plain(b) => {
            let text = b.text.clone().unwrap_or_default().replace("\r\n", "\n");
            let html = b
                .html
                .filter(|h| Some(h) != b.text.as_ref())
                .map(|h| h.replace("\r\n", "\n"));
            (text, html)
        }
        other => panic!("expected a plain message, got {other:?}"),
    }
}

/// Sync `profile` until the INBOX message matching `pred` is stored; returns its local id.
async fn synced_id_where(
    profile: &Profile,
    email: &str,
    what: &str,
    pred: impl Fn(&serde_json::Value) -> bool,
) -> i64 {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        profile.sync(email);
        if let Some(id) = profile
            .list(Some(email), "INBOX")
            .into_iter()
            .find(|m| pred(m))
            .and_then(|m| m["id"].as_i64())
        {
            return id;
        }
        assert!(
            Instant::now() < deadline,
            "{what} never synced into {email}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Sync `profile` until the message with `message_id` is stored; returns its local id.
async fn synced_id(profile: &Profile, email: &str, message_id: &str) -> i64 {
    synced_id_where(profile, email, &format!("message <{message_id}>"), |m| {
        m["message_id"].as_str() == Some(message_id)
    })
    .await
}

fn assert_sanitised(html: &str, context: &str) {
    assert!(html.contains("<b>U11</b>"), "{context}: bold lost:\n{html}");
    assert!(
        html.contains("href=\"https://sealbox.test/u11\""),
        "{context}: https link lost:\n{html}"
    );
    assert!(html.contains("Sealbox Inc."), "{context}:\n{html}");
    for bad in [
        "<script",
        "alert(",
        "evil.example",
        "t.gif",
        "onclick",
        "steal(",
    ] {
        assert!(!html.contains(bad), "{context}: `{bad}` survived:\n{html}");
    }
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn signatures_are_applied_sanitised_and_placed() {
    let u11 = Profile::new("u11");
    let u12 = Profile::new("u12");
    u11.add_greenmail_account("u11");
    u12.add_greenmail_account("u12");
    let tag = nonce("g23");

    // (1) Defaults, then set text + (dirty) HTML through the CLI; the stored HTML is clean.
    let shown = u11.json(&["settings", "signature", "show", "--account", U11]);
    assert_eq!(shown["enabled"], false, "{shown}");
    assert_eq!(shown["placement"], "above_quote");
    assert_eq!(shown["include_on"], "all");
    let sig_text = format!("U11 Tester\nSealbox Inc. {tag}");
    let dirty_html = "<div><b>U11</b> <a href=\"https://sealbox.test/u11\">site</a>\
                      <script>alert('x')</script>\
                      <img src=\"http://evil.example/t.gif\" width=\"1\" height=\"1\">\
                      <p onclick=\"steal()\">Sealbox Inc.</p></div>";
    let text_path = temp_file(u11.path(), "sig.txt", sig_text.as_bytes());
    let html_path = temp_file(u11.path(), "sig.html", dirty_html.as_bytes());
    let set = u11.json(&[
        "settings",
        "signature",
        "set",
        "--account",
        U11,
        "--text-file",
        text_path.to_str().unwrap(),
        "--html-file",
        html_path.to_str().unwrap(),
        "--placement",
        "above-quote",
        "--include-on",
        "all",
        "--enable",
    ]);
    assert_eq!(set["enabled"], true, "{set}");
    assert_eq!(set["text"], sig_text.as_str());
    assert_sanitised(set["html"].as_str().unwrap(), "stored html");
    let all = u11.json(&["settings", "show", "--account", U11]);
    assert_eq!(all["signature"]["enabled"], true);
    assert_eq!(all["autoreply"]["enabled"], false);
    let human = u11.ok(&["settings", "signature", "show", "--account", U11]);
    assert!(
        human.contains("enabled") && human.contains("U11 Tester"),
        "{human}"
    );

    // (2) u12 → u11 first contact (plaintext + Autocrypt): something to reply to and quote.
    let orig_subject = format!("question {tag}");
    let orig_body = format!("Could you help with {tag}?\nSecond line.");
    let r = u12.json(&[
        "send",
        "--from",
        U12,
        "--to",
        U11,
        "--subject",
        &orig_subject,
        "--body",
        &orig_body,
        "--policy",
        "plaintext",
    ]);
    let orig_mid = r["message_id"].as_str().unwrap().to_string();
    let orig_id = synced_id(&u11, U11, &orig_mid).await;

    // (3) New mail, plaintext: text gets "-- " + signature, HTML alternative is sanitised.
    let r = u11.json(&[
        "send",
        "--from",
        U11,
        "--to",
        U12,
        "--subject",
        &format!("new plain {tag}"),
        "--body",
        &format!("Hello u12 {tag}"),
        "--policy",
        "plaintext",
    ]);
    assert_eq!(r["mode"], "plaintext");
    let new_plain_mid = r["message_id"].as_str().unwrap().to_string();
    let raw = wait_raw("u12", &new_plain_mid).await;
    assert!(
        raw.to_ascii_lowercase().contains("multipart/alternative"),
        "HTML signature must produce multipart/alternative:\n{}",
        head(&raw)
    );
    let (text, html) = plain_bodies(&raw);
    assert_eq!(
        text,
        format!("Hello u12 {tag}\n\n-- \n{sig_text}\n"),
        "text signature with `-- ` separator"
    );
    let html = html.expect("html alternative");
    assert_sanitised(&html, "plaintext mail html");
    assert!(html.contains("-- <br>"), "{html}");
    assert!(html.contains(&format!("Hello u12 {tag}")), "{html}");

    // (4) New mail, encrypted (u11 learnt u12's key in step 2): nothing leaks on the wire,
    //     the decrypted text and HTML carry the signature.
    let r = u11.json(&[
        "send",
        "--from",
        U11,
        "--to",
        U12,
        "--subject",
        &format!("new encrypted {tag}"),
        "--body",
        &format!("Secret hello {tag}"),
    ]);
    assert_eq!(r["mode"], "encrypted", "{r}");
    let new_enc_mid = r["message_id"].as_str().unwrap().to_string();
    let raw = wait_raw("u12", &new_enc_mid).await;
    assert!(
        head(&raw)
            .to_ascii_lowercase()
            .contains("multipart/encrypted"),
        "{}",
        head(&raw)
    );
    assert!(
        !raw.contains("U11 Tester"),
        "signature leaked in ciphertext mail"
    );
    assert!(!raw.contains(&tag), "body leaked in ciphertext mail");
    let id = synced_id(&u12, U12, &new_enc_mid).await;
    let read = u12.json(&["read", &id.to_string()]);
    assert_eq!(read["was_encrypted"], true);
    assert_eq!(read["decrypted"], true, "{read}");
    let text = read["text"].as_str().unwrap().replace("\r\n", "\n");
    assert_eq!(text, format!("Secret hello {tag}\n\n-- \n{sig_text}\n"));
    assert_sanitised(
        &read["html"]
            .as_str()
            .expect("html in encrypted mail")
            .replace("\r\n", "\n"),
        "encrypted mail html",
    );

    // (5) Quoted reply, plaintext, signature above the quote.
    let r = u11.json(&[
        "send",
        "--from",
        U11,
        "--to",
        U12,
        "--subject",
        &format!("Re: question {tag}"),
        "--body",
        &format!("Sure {tag}"),
        "--in-reply-to",
        &orig_id.to_string(),
        "--quote",
        "--policy",
        "plaintext",
    ]);
    let reply_mid = r["message_id"].as_str().unwrap().to_string();
    let raw = wait_raw("u12", &reply_mid).await;
    assert!(
        head(&raw).contains(&format!("In-Reply-To: <{orig_mid}>")),
        "{}",
        head(&raw)
    );
    let (text, html) = plain_bodies(&raw);
    let sig_block = format!("-- \n{sig_text}\n");
    let pos_sig = text
        .find(&sig_block)
        .unwrap_or_else(|| panic!("no signature:\n{text}"));
    let pos_quote = text
        .find(" wrote:\n")
        .unwrap_or_else(|| panic!("no quote header:\n{text}"));
    assert!(
        pos_sig < pos_quote,
        "signature must be above the quote:\n{text}"
    );
    assert!(text.starts_with(&format!("Sure {tag}\n\n-- \n")), "{text}");
    assert!(
        text.contains(&format!(
            "U12 <u12@sealbox.test> wrote:\n> Could you help with {tag}?\n> Second line.\n"
        )),
        "quote format:\n{text}"
    );
    assert!(
        text.contains("On ") && text.contains("2026"),
        "attribution date:\n{text}"
    );
    let html = html.expect("html");
    assert!(html.contains("<blockquote type=\"cite\">"), "{html}");
    assert!(
        html.find("sealbox-signature").unwrap() < html.find("sealbox-quote-header").unwrap(),
        "html placement:\n{html}"
    );

    // (6) Placement below the quote, encrypted quoted reply, decrypted by u12.
    let set = u11.json(&[
        "settings",
        "signature",
        "set",
        "--account",
        U11,
        "--placement",
        "below-quote",
    ]);
    assert_eq!(set["placement"], "below_quote");
    assert_eq!(set["enabled"], true, "placement change keeps it enabled");
    let r = u11.json(&[
        "send",
        "--from",
        U11,
        "--to",
        U12,
        "--subject",
        &format!("Re: question (below) {tag}"),
        "--body",
        &format!("Below {tag}"),
        "--in-reply-to",
        &orig_id.to_string(),
        "--quote",
    ]);
    assert_eq!(r["mode"], "encrypted", "{r}");
    let below_mid = r["message_id"].as_str().unwrap().to_string();
    let id = synced_id(&u12, U12, &below_mid).await;
    let read = u12.json(&["read", &id.to_string()]);
    assert_eq!(read["decrypted"], true, "{read}");
    assert_eq!(read["in_reply_to"][0], orig_mid.as_str());
    let text = read["text"].as_str().unwrap().replace("\r\n", "\n");
    let pos_sig = text
        .find(&sig_block)
        .unwrap_or_else(|| panic!("no signature:\n{text}"));
    let pos_quote = text.find(" wrote:\n").unwrap();
    assert!(
        pos_quote < pos_sig,
        "signature must be below the quote:\n{text}"
    );
    assert!(text.ends_with(&sig_block), "{text}");
    assert!(
        text.contains(&format!("> Could you help with {tag}?")),
        "{text}"
    );

    // (7) include-on new-only: a reply gets no signature; (8) --no-signature on new mail.
    u11.json(&[
        "settings",
        "signature",
        "set",
        "--account",
        U11,
        "--include-on",
        "new-only",
    ]);
    let r = u11.json(&[
        "send",
        "--from",
        U11,
        "--to",
        U12,
        "--subject",
        &format!("Re: no sig on replies {tag}"),
        "--body",
        &format!("Plain reply {tag}"),
        "--in-reply-to",
        &orig_id.to_string(),
        "--policy",
        "plaintext",
    ]);
    let raw = wait_raw("u12", r["message_id"].as_str().unwrap()).await;
    let (text, html) = plain_bodies(&raw);
    assert_eq!(
        text.trim_end(),
        format!("Plain reply {tag}"),
        "no signature expected:\n{text}"
    );
    assert!(
        html.is_none(),
        "no HTML alternative without a signature: {html:?}"
    );
    u11.json(&[
        "settings",
        "signature",
        "set",
        "--account",
        U11,
        "--include-on",
        "all",
    ]);
    let r = u11.json(&[
        "send",
        "--from",
        U11,
        "--to",
        U12,
        "--subject",
        &format!("no-signature flag {tag}"),
        "--body",
        &format!("Unsigned {tag}"),
        "--no-signature",
        "--policy",
        "plaintext",
    ]);
    let raw = wait_raw("u12", r["message_id"].as_str().unwrap()).await;
    let (text, _) = plain_bodies(&raw);
    assert!(!text.contains("-- "), "--no-signature ignored:\n{text}");

    // (9) An auto-reply never carries the signature.
    let away_body = format!("I am away {tag}");
    let set = u11.json(&[
        "settings",
        "autoreply",
        "set",
        "--account",
        U11,
        "--enable",
        "--from",
        "2000-01-01",
        "--to",
        "2100-01-01",
        "--body",
        &away_body,
    ]);
    assert_eq!(set["enabled"], true, "{set}");
    let r = u12.json(&[
        "send",
        "--from",
        U12,
        "--to",
        U11,
        "--subject",
        &format!("are you there {tag}"),
        "--body",
        "ping",
        "--policy",
        "plaintext",
    ]);
    let ping_mid = r["message_id"].as_str().unwrap().to_string();
    synced_id(&u11, U11, &ping_mid).await; // the sync hook sends the auto-reply
    let reply_subject = format!("Automatic reply: are you there {tag}");
    let reply_id = synced_id_where(&u12, U12, "the auto-reply", |m| {
        m["subject"].as_str() == Some(reply_subject.as_str())
    })
    .await;
    let read = u12.json(&["read", &reply_id.to_string()]);
    let text = read["text"].as_str().unwrap().replace("\r\n", "\n");
    assert!(text.contains(&away_body), "{text}");
    assert!(
        !text.contains("-- "),
        "auto-reply carries a signature:\n{text}"
    );
    assert!(
        !text.contains("U11 Tester"),
        "auto-reply carries a signature:\n{text}"
    );
    assert!(
        read["html"].is_null(),
        "auto-reply must not get an HTML signature: {read}"
    );
    assert_eq!(read["in_reply_to"][0], ping_mid.as_str());
    let raw_reply = wait_raw("u12", read["message_id"].as_str().unwrap()).await;
    assert!(
        head(&raw_reply).contains("Auto-Submitted: auto-replied"),
        "{}",
        head(&raw_reply)
    );
    u11.json(&[
        "settings",
        "autoreply",
        "set",
        "--account",
        U11,
        "--disable",
    ]);

    // (10) Clear.
    let cleared = u11.json(&["settings", "signature", "clear", "--account", U11]);
    assert_eq!(cleared["enabled"], false);
    assert_eq!(cleared["text"], "");
    assert!(cleared["html"].is_null());
    let r = u11.run(&[
        "settings",
        "signature",
        "show",
        "--account",
        "nobody@sealbox.test",
    ]);
    assert_eq!(r.code, 1, "unknown account: {}", r.stderr);
}
