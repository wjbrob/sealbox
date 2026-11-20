//! `sealbox read` — one message: headers, security, signature, attachments, body.
//!
//! Two things here are not just printing:
//!
//! * **HTML** (`docs/HTML_MAIL.md`). The stored HTML part is attacker-controlled, so the
//!   terminal never sees it: `--html` prints [`Engine::message_html`]'s sanitized markup, and a
//!   message with no text part is shown as `html_to_text` of that same sanitized HTML. Remote
//!   images stay blocked unless `--load-images` is given, and the blocked count is reported.
//!   Each inline `cid:` image is listed after the markup with the attachment it shows (the
//!   part with that `Content-ID`).
//! * **Signer ≠ sender** (R4, `docs/THREAT_MODEL.md`). A good signature only says *whose key*
//!   signed; anyone can put any address in `From`. When the signing key belongs to someone else,
//!   `read` says so in as many words instead of printing a reassuring "good signature" — the
//!   same rule the app's thread view applies (`app/lib/src/core/signer_mismatch.dart`).

use std::path::Path;

use anyhow::Context;
use sealbox_core::{Contact, Engine, FlagOp, HtmlBody, MessageDetail, SigState};

/// `sealbox read <id> [--raw] [--no-mark] [--html] [--load-images]`.
pub async fn read(
    profile: &Path,
    json: bool,
    id: i64,
    raw: bool,
    no_mark: bool,
    html: bool,
    load_images: bool,
) -> anyhow::Result<()> {
    let engine = Engine::open(profile)?;
    if raw {
        let bytes = engine.get_raw_message(id)?;
        if json {
            return print_json(&serde_json::json!({
                "id": id,
                "raw": String::from_utf8_lossy(&bytes),
            }));
        }
        let mut out = std::io::stdout().lock();
        use std::io::Write;
        out.write_all(&bytes)?;
        return Ok(());
    }
    let mut detail = engine.get_message(id)?;
    if !no_mark && !detail.summary.seen {
        match engine
            .set_flags(id, FlagOp::Add, &["\\Seen".to_string()])
            .await
        {
            Ok(flags) => {
                detail.summary.seen = flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen"));
                detail.summary.flags = flags;
            }
            Err(e) => eprintln!("warning: could not mark as read: {e}"),
        }
    }
    // Never the raw HTML: only what the sanitizer produced.
    let body = engine.message_html(id, load_images)?;
    let mismatch = signer_mismatch(&detail, &engine)?;
    if json {
        return print_json(&read_json(&detail, body.as_ref(), mismatch.as_ref())?);
    }
    print_detail(&detail, body.as_ref(), mismatch.as_ref(), html);
    Ok(())
}

/// A good signature made with a key that belongs to someone other than the sender (R4).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SignerMismatch {
    /// Address the signing key belongs to.
    pub signer: String,
    /// The message's `From` address.
    pub sender: String,
}

impl SignerMismatch {
    /// The one-line warning, worded as in the app.
    pub fn line(&self) -> String {
        format!("signed by {} — but sent by {}", self.signer, self.sender)
    }

    fn explanation(&self) -> String {
        format!(
            "The signature is valid, but the key that made it belongs to {}, not to the sender \
             {}. It does not show that {1} wrote this message: anyone can put any address in \
             From. Check with {1} another way before you act on it.",
            self.signer, self.sender
        )
    }
}

fn address(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

fn hex(fingerprint: Option<&str>) -> String {
    fingerprint
        .unwrap_or("")
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_uppercase()
}

/// The mismatch to warn about, resolving contacts only when the signature could be one.
fn signer_mismatch(d: &MessageDetail, engine: &Engine) -> anyhow::Result<Option<SignerMismatch>> {
    let sig = &d.summary.signature;
    if sig.status != SigState::Good || sig.signer_verified {
        return Ok(None);
    }
    let sender = address(&d.summary.from.address);
    if sender.is_empty() {
        return Ok(None);
    }
    let named = sig.signer.as_deref().map(address).unwrap_or_default();
    let (contacts, own) = if !named.is_empty() && named != sender {
        (Vec::new(), Vec::new())
    } else if hex(sig.fingerprint.as_deref()).is_empty() {
        return Ok(None);
    } else {
        let own = engine
            .list_accounts()?
            .into_iter()
            .map(|a| a.email)
            .collect();
        (engine.contacts()?, own)
    };
    Ok(decide(
        sig.signer.as_deref(),
        sig.fingerprint.as_deref(),
        &d.summary.from.address,
        &contacts,
        &own,
    ))
}

/// The decision itself, without the engine: a signer the engine named, else a key the user
/// verified for another address; never when both sides are the user's own addresses.
fn decide(
    named_signer: Option<&str>,
    fingerprint: Option<&str>,
    from: &str,
    contacts: &[Contact],
    own: &[String],
) -> Option<SignerMismatch> {
    let sender = address(from);
    let named = named_signer.unwrap_or("").trim();
    let signer = if !named.is_empty() && address(named) != sender {
        named.to_owned()
    } else {
        // A key the user verified for another address is that address's key, whatever the
        // engine's own address map says (it keeps the first address a key was seen with).
        let fp = hex(fingerprint);
        if fp.is_empty() {
            return None;
        }
        contacts
            .iter()
            .find(|c| {
                c.verified && hex(c.fingerprint.as_deref()) == fp && address(&c.address) != sender
            })
            .map(|c| c.address.trim().to_owned())?
    };
    let own: Vec<String> = own.iter().map(|a| address(a)).collect();
    if own.contains(&address(&signer)) && own.contains(&sender) {
        return None;
    }
    Some(SignerMismatch {
        signer,
        sender: from.trim().to_owned(),
    })
}

/// `read --json`: the message detail with the sanitized HTML body and the R4 warning added.
/// Existing keys keep their meaning and place (the gates read `text`, `id`, `html`, …).
fn read_json(
    d: &MessageDetail,
    body: Option<&HtmlBody>,
    mismatch: Option<&SignerMismatch>,
) -> anyhow::Result<serde_json::Value> {
    let mut v = serde_json::to_value(d)?;
    let map = v
        .as_object_mut()
        .context("a message detail serialises to an object")?;
    map.insert("html_body".into(), serde_json::to_value(body)?);
    map.insert(
        "signer_mismatch".into(),
        serde_json::to_value(mismatch.map(|m| {
            serde_json::json!({
                "signer": m.signer,
                "sender": m.sender,
                "line": m.line(),
            })
        }))?,
    );
    Ok(v)
}

fn print_json<T: serde::Serialize>(v: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn print_detail(
    d: &MessageDetail,
    body: Option<&HtmlBody>,
    mismatch: Option<&SignerMismatch>,
    html: bool,
) {
    let s = &d.summary;
    println!("Id:       {}", s.id);
    println!("Account:  {}  [{}]", s.account, s.folder);
    println!("From:     {}", s.from);
    if !s.to.is_empty() {
        println!(
            "To:       {}",
            s.to.iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !s.cc.is_empty() {
        println!(
            "Cc:       {}",
            s.cc.iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!("Date:     {}", fmt_date(s.date));
    println!(
        "Subject:  {}{}",
        s.subject.as_deref().unwrap_or("(no subject)"),
        if s.protected_subject {
            "  (protected)"
        } else {
            ""
        }
    );
    if let Some(mid) = &s.message_id {
        println!("Message-ID: <{mid}>");
    }
    let sec = if s.was_encrypted && s.decrypted {
        "🔒 encrypted (decrypted)".to_string()
    } else if s.was_encrypted {
        format!(
            "⚠ encrypted, NOT decrypted: {}",
            s.decrypt_error.as_deref().unwrap_or("unknown error")
        )
    } else {
        "plaintext (not encrypted)".to_string()
    };
    println!("Security: {sec}");
    let sig = match s.signature.status {
        SigState::Good => match mismatch {
            // R4: do not call a foreign key's signature the sender's
            Some(m) => format!(
                "⚠ {} (valid signature by {})",
                m.line(),
                s.signature.fingerprint.as_deref().unwrap_or("?")
            ),
            None => format!(
                "✍️ good signature by {}{}",
                s.signature.fingerprint.as_deref().unwrap_or("?"),
                s.signature
                    .signer
                    .as_deref()
                    .map(|a| format!(" ({a})"))
                    .unwrap_or_default()
            ),
        },
        SigState::Bad => format!(
            "⚠ BAD signature from {}",
            s.signature.fingerprint.as_deref().unwrap_or("?")
        ),
        SigState::UnknownKey => format!(
            "⚠ signed by an unknown key ({})",
            s.signature.fingerprint.as_deref().unwrap_or("?")
        ),
        SigState::None => "unsigned".to_string(),
    };
    println!("Signature: {sig}");
    if let Some(m) = mismatch {
        println!("          {}", m.explanation());
    }
    println!("Flags:    {}", s.flags.join(" "));
    if !d.attachments.is_empty() {
        println!("Attachments:");
        for a in &d.attachments {
            println!(
                "  [{}] {} ({}, {} bytes)",
                a.index,
                printable(&a.filename),
                printable(&a.content_type),
                a.size
            );
        }
    }
    println!();
    print_body(d, body, html);
}

/// The body section: `--html` shows the sanitized markup, otherwise the text part, otherwise the
/// sanitized HTML as text. Never the HTML as it arrived — including the case where the markup
/// *is* the stored text field (an HTML-only mail, see `Engine::message_html`): then the HTML
/// body the engine returned came from that text, and its text rendering is what we print.
fn print_body(d: &MessageDetail, body: Option<&HtmlBody>, html: bool) {
    let markup_in_text = d.html.is_none()
        && d.text
            .as_deref()
            .is_some_and(sealbox_core::sealbox_mail::html::looks_like_html_document);
    let text = d
        .text
        .as_deref()
        .filter(|_| !markup_in_text)
        .map(|t| t.replace("\r\n", "\n"));
    if html {
        match body {
            Some(b) => {
                println!("{}", blocked_note(b));
                println!("{}", b.html);
                for line in inline_image_lines(d, &b.html) {
                    println!("{line}");
                }
            }
            None => match &text {
                Some(t) => println!("(no HTML part — the text body follows)\n\n{t}"),
                None => println!("(no HTML part)"),
            },
        }
        return;
    }
    match (&text, body) {
        (Some(t), _) => println!("{t}"),
        (None, Some(b)) => {
            println!("[HTML only — shown as text; --html prints the sanitized HTML]");
            println!("{}", blocked_note(b));
            println!("{}", b.text);
        }
        (None, None) => println!("(empty body)"),
    }
}

/// `--html`: one line per inline image of the sanitized markup — each distinct `cid:` URL,
/// with the attachment whose `Content-ID` it names (what the app renders in its place), or a
/// note that no part has it (the app shows a placeholder).
fn inline_image_lines(d: &MessageDetail, html: &str) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut lines = Vec::new();
    for src in img_sources(html) {
        let Some(cid) = sealbox_core::cid_content_id(&src) else {
            continue;
        };
        if seen.contains(&cid) {
            continue;
        }
        lines.push(match d.inline_part(&src) {
            Some(a) => format!(
                "inline image: cid:{} → attachment {} ({}, {}, {} bytes)",
                printable(&cid),
                a.index,
                printable(&a.filename),
                printable(&a.content_type),
                a.size
            ),
            None => format!(
                "inline image: cid:{} → no part of this message has that Content-ID \
                 (shown as a placeholder)",
                printable(&cid)
            ),
        });
        seen.push(cid);
    }
    lines
}

/// The `src` of every `<img>` in *sanitized* markup, entity-decoded. Its serializer writes each
/// attribute as `name="value"` with `"` and `&` escaped, and every `<` in text as `&lt;`, so the
/// tags can be read without a parser: a `<img` is a tag start, a value ends at the next `"`.
fn img_sources(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("<img") {
        let mut tag = &rest[start + "<img".len()..];
        loop {
            tag = tag.trim_start();
            if tag.is_empty() || tag.starts_with('>') || tag.starts_with("/>") {
                break;
            }
            let name_end = tag
                .find(|c: char| c == '=' || c == '>' || c.is_whitespace())
                .unwrap_or(tag.len());
            let name = &tag[..name_end];
            tag = &tag[name_end..];
            if let Some(value) = tag.strip_prefix("=\"") {
                let end = value.find('"').unwrap_or(value.len());
                if name.eq_ignore_ascii_case("src") {
                    out.push(unescape_attribute(&value[..end]));
                }
                tag = value.get(end + 1..).unwrap_or("");
            } else if name.is_empty() {
                break; // not `name="value"`: not markup the sanitizer wrote
            }
        }
        rest = tag;
    }
    out
}

/// The entities the serializer writes inside an attribute value.
fn unescape_attribute(v: &str) -> String {
    v.replace("&quot;", "\"")
        .replace("&nbsp;", "\u{a0}")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Text from a mail as it may go to a terminal: without control characters (a filename or a
/// Content-ID can carry `ESC [ 2 J` as easily as a body can).
fn printable(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// What a UI shows as "N images blocked · Load images".
fn blocked_note(b: &HtmlBody) -> String {
    match b.remote_images {
        0 => String::new(),
        1 => "[1 remote image blocked — --load-images keeps its URL]\n".into(),
        n => format!("[{n} remote images blocked — --load-images keeps their URLs]\n"),
    }
}

fn fmt_date(ts: Option<i64>) -> String {
    ts.map(|t| {
        // `YYYY-MM-DD HH:MM` in UTC (civil-from-days, Howard Hinnant's algorithm).
        let days = t.div_euclid(86_400);
        let secs = t.rem_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!(
            "{y:04}-{m:02}-{d:02} {:02}:{:02}",
            secs / 3600,
            (secs % 3600) / 60
        )
    })
    .unwrap_or_else(|| "-".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealbox_core::{KeySource, PreferEncrypt, Recommendation};

    fn contact(address: &str, fingerprint: &str, verified: bool) -> Contact {
        Contact {
            address: address.into(),
            recommendation: Recommendation::Available,
            fingerprint: Some(fingerprint.into()),
            source: KeySource::Autocrypt,
            prefer_encrypt: PreferEncrypt::NoPreference,
            last_seen: None,
            autocrypt_timestamp: None,
            gossip_fingerprint: None,
            verified,
            verified_at: None,
            key_changed_at: None,
            previous_fingerprint: None,
        }
    }

    const FP: &str = "AAAA BBBB CCCC DDDD";

    #[test]
    fn a_signer_the_engine_names_is_compared_with_the_sender() {
        let m = decide(
            Some("eve@evil.test"),
            Some(FP),
            "bob@sealbox.test",
            &[],
            &[],
        );
        assert_eq!(
            m.as_ref().map(SignerMismatch::line).as_deref(),
            Some("signed by eve@evil.test — but sent by bob@sealbox.test")
        );
        // same address, any spelling: no warning
        for signer in ["bob@sealbox.test", " Bob@Sealbox.TEST ", ""] {
            assert_eq!(
                decide(Some(signer), Some(FP), "bob@sealbox.test", &[], &[]),
                None
            );
        }
        assert_eq!(decide(None, Some(FP), "bob@sealbox.test", &[], &[]), None);
    }

    #[test]
    fn a_key_verified_for_another_address_outranks_the_engines_address_map() {
        // the engine says the key is Bob's (first address it was seen with), but the user
        // verified the same fingerprint for Eve
        let contacts = [
            contact("eve@evil.test", "aaaabbbbccccdddd", true),
            contact("carol@sealbox.test", "1111222233334444", true),
        ];
        let m = decide(
            Some("bob@sealbox.test"),
            Some(FP),
            "bob@sealbox.test",
            &contacts,
            &[],
        );
        assert_eq!(m.map(|m| m.signer), Some("eve@evil.test".into()));
        // an unverified contact with that key proves nothing
        let unverified = [contact("eve@evil.test", FP, false)];
        assert_eq!(
            decide(None, Some(FP), "bob@sealbox.test", &unverified, &[]),
            None
        );
        // no fingerprint, nothing to match
        assert_eq!(decide(None, None, "bob@sealbox.test", &contacts, &[]), None);
    }

    #[test]
    fn two_own_addresses_are_not_a_mismatch() {
        let own = ["me@work.test".to_string(), "me@home.test".to_string()];
        assert_eq!(
            decide(Some("me@home.test"), Some(FP), "me@work.test", &[], &own),
            None,
            "a Sent copy from the profile's other account"
        );
        // but an own key signing someone else's mail is still worth a warning
        assert!(decide(Some("me@home.test"), Some(FP), "bob@x.test", &[], &own).is_some());
    }

    fn part(
        index: usize,
        filename: &str,
        content_id: Option<&str>,
    ) -> sealbox_core::AttachmentInfo {
        sealbox_core::AttachmentInfo {
            index,
            filename: filename.into(),
            content_type: "image/png".into(),
            size: 68,
            content_id: content_id.map(str::to_owned),
        }
    }

    #[test]
    fn img_sources_reads_the_sanitizers_markup() {
        let html = "<p>a <img src=\"cid:logo@x\" alt=\"a &quot;b&quot; > c\"> \
                    &lt;img src=\"cid:text@x\"&gt; <img alt=\"<img src=&quot;cid:alt@x&quot;>\" \
                    src=\"cid:a&amp;b@x\"><img src=\"https://x.example/i.png\" width=\"5\"></p>\
                    <span class=\"sealbox-blocked-image\" data-src=\"cid:span@x\"></span>";
        assert_eq!(
            img_sources(html),
            ["cid:logo@x", "cid:a&b@x", "https://x.example/i.png"],
            "only real <img> tags, values entity-decoded; text and other attributes ignored"
        );
        assert!(img_sources("<img").is_empty());
        assert!(img_sources("<img src=\"cid:x").len() == 1);
    }

    #[test]
    fn inline_images_name_their_part() {
        let mut d: MessageDetail = serde_json::from_value(serde_json::json!({
            "id": 1, "account": "a@x", "folder": "INBOX", "uid": 1,
            "from": {"name": null, "address": "s@x"}, "to": [], "received_at": 0,
            "flags": [], "seen": true, "was_encrypted": false, "decrypted": false,
            "was_signed": false, "signature": {"status": "none"}, "protected_subject": false,
            "attachment_count": 2, "raw_size": 1, "attachments": [],
        }))
        .expect("a minimal detail");
        d.attachments = vec![
            part(0, "report.pdf", None),
            part(1, "lo\u{1b}[2Jgo.png", Some("logo@x")),
        ];
        let html = "<p><img src=\"cid:logo@x\" alt=\"Logo\"><img src=\"cid:logo%40x\">\
                    <img src=\"cid:missing@x\"><img src=\"https://x.example/a.png\"></p>";
        assert_eq!(
            inline_image_lines(&d, html),
            [
                "inline image: cid:logo@x → attachment 1 (lo[2Jgo.png, image/png, 68 bytes)",
                "inline image: cid:missing@x → no part of this message has that Content-ID \
                 (shown as a placeholder)",
            ],
            "one line per distinct Content-ID, control characters dropped"
        );
        assert!(inline_image_lines(&d, "<p>no images</p>").is_empty());
    }

    #[test]
    fn the_blocked_note_counts() {
        let body = |n: u32| HtmlBody {
            html: "<p>x</p>".into(),
            remote_images: n,
            text: "x".into(),
        };
        assert_eq!(blocked_note(&body(0)), "");
        assert!(blocked_note(&body(1)).starts_with("[1 remote image blocked"));
        assert!(blocked_note(&body(4)).starts_with("[4 remote images blocked"));
    }
}
