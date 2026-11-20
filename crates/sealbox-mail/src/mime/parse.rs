//! Incoming message classification and parsing (mail-parser underneath).

use mail_parser::{Address, HeaderValue, Message, MessageParser, MimeHeaders, PartType};

use super::headers::unfold_header_value;
use super::types::{Attachment, Mailbox};
use crate::error::MimeError;

/// Envelope-level headers of a parsed message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedHeaders {
    pub from: Vec<Mailbox>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub subject: Option<String>,
    /// Unix timestamp of the `Date` header, if parseable.
    pub date: Option<i64>,
    /// Message-ID without angle brackets.
    pub message_id: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    /// Raw (unfolded) `Autocrypt:` header values, in order.
    pub autocrypt: Vec<String>,
    /// Raw (unfolded) `Autocrypt-Gossip:` header values, in order.
    pub autocrypt_gossip: Vec<String>,
    /// Top-level `Content-Type` as `type/subtype`.
    pub content_type: Option<String>,
}

/// Decoded plaintext content.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlainBody {
    pub text: Option<String>,
    pub html: Option<String>,
    pub attachments: Vec<Attachment>,
}

/// What kind of message this is, with the payload the crypto layer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageKind {
    Plain(PlainBody),
    /// RFC 3156 `multipart/encrypted`; `ciphertext` is the (armored) second part body.
    PgpMimeEncrypted {
        ciphertext: Vec<u8>,
    },
    /// RFC 3156 `multipart/signed`; `signed_part` is byte-exact (headers included),
    /// `signature` the armored detached signature.
    PgpMimeSigned {
        signed_part: Vec<u8>,
        signature: Vec<u8>,
        micalg: Option<String>,
    },
    /// Legacy inline PGP in a text body (`-----BEGIN PGP MESSAGE-----` or signed message).
    InlinePgp {
        armored: String,
    },
}

/// A parsed incoming message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedMessage {
    pub headers: ParsedHeaders,
    pub kind: MessageKind,
}

/// Header fields recovered from inside an encrypted / signed payload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtectedHeaders {
    /// `protected-headers="v1"` (or draft-lamps `hp=`) was present on the payload.
    pub present: bool,
    pub subject: Option<String>,
    pub from: Vec<Mailbox>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub date: Option<i64>,
    pub message_id: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub autocrypt_gossip: Vec<String>,
}

/// Result of parsing the decrypted inner entity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecryptedInner {
    pub headers: ProtectedHeaders,
    pub body: PlainBody,
}

/// Parse a raw RFC 5322 message and classify it.
pub fn parse(raw: &[u8]) -> Result<ParsedMessage, MimeError> {
    let msg = MessageParser::default()
        .parse(raw)
        .ok_or(MimeError::Unparseable)?;
    let headers = envelope_headers(&msg);
    let kind = classify(&msg, raw, 0)?;
    Ok(ParsedMessage { headers, kind })
}

/// Parse the plaintext produced by decrypting a PGP/MIME payload (or the
/// signed part of a `multipart/signed` message) and return the protected
/// headers plus the body.
pub fn parse_decrypted_inner(raw: &[u8]) -> Result<DecryptedInner, MimeError> {
    let msg = MessageParser::default()
        .parse(raw)
        .ok_or(MimeError::Unparseable)?;
    let root_ct = msg.root_part().content_type();
    let present = root_ct.is_some_and(|ct| {
        ct.attribute("protected-headers")
            .is_some_and(|v| v.eq_ignore_ascii_case("v1"))
            || ct.has_attribute("hp")
    });
    let env = envelope_headers(&msg);
    let headers = ProtectedHeaders {
        present,
        subject: env.subject,
        from: env.from,
        to: env.to,
        cc: env.cc,
        date: env.date,
        message_id: env.message_id,
        in_reply_to: env.in_reply_to,
        references: env.references,
        autocrypt_gossip: env.autocrypt_gossip,
    };
    Ok(DecryptedInner {
        headers,
        body: plain_body(&msg),
    })
}

fn envelope_headers(msg: &Message<'_>) -> ParsedHeaders {
    let mut h = ParsedHeaders {
        from: addresses(msg.from()),
        to: addresses(msg.to()),
        cc: addresses(msg.cc()),
        subject: msg.subject().map(str::to_owned),
        date: msg.date().map(|d| d.to_timestamp()),
        message_id: msg.message_id().map(strip_angles),
        in_reply_to: id_list(msg.in_reply_to()),
        references: id_list(msg.references()),
        autocrypt: Vec::new(),
        autocrypt_gossip: Vec::new(),
        content_type: msg
            .content_type()
            .map(|ct| format_ctype(ct.ctype(), ct.subtype())),
    };
    for (name, raw) in msg.headers_raw() {
        if name.eq_ignore_ascii_case("autocrypt") {
            h.autocrypt.push(unfold_header_value(raw));
        } else if name.eq_ignore_ascii_case("autocrypt-gossip") {
            h.autocrypt_gossip.push(unfold_header_value(raw));
        }
    }
    h
}

fn format_ctype(ctype: &str, subtype: Option<&str>) -> String {
    match subtype {
        Some(s) => format!("{}/{}", ctype.to_ascii_lowercase(), s.to_ascii_lowercase()),
        None => ctype.to_ascii_lowercase(),
    }
}

fn addresses(a: Option<&Address<'_>>) -> Vec<Mailbox> {
    a.map(|a| {
        a.iter()
            .filter_map(|addr| {
                addr.address().map(|address| Mailbox {
                    name: addr.name().map(str::to_owned),
                    address: address.to_owned(),
                })
            })
            .collect()
    })
    .unwrap_or_default()
}

fn id_list(v: &HeaderValue<'_>) -> Vec<String> {
    match v {
        HeaderValue::Text(t) => vec![strip_angles(t)],
        HeaderValue::TextList(l) => l.iter().map(|t| strip_angles(t)).collect(),
        _ => Vec::new(),
    }
}

fn strip_angles(id: &str) -> String {
    id.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_owned()
}

fn plain_body(msg: &Message<'_>) -> PlainBody {
    let is_legacy_display = |p: &mail_parser::MessagePart<'_>| {
        p.content_type().is_some_and(|ct| {
            ct.ctype().eq_ignore_ascii_case("text")
                && ct
                    .subtype()
                    .is_some_and(|s| s.eq_ignore_ascii_case("rfc822-headers"))
        })
    };
    // mail-parser lists the HTML part under `text_bodies()` too when the message has no
    // text/plain alternative, and `text_contents()` of an HTML part is its *source*: only a
    // real text part is the text body, so an HTML-only mail comes out as `text: None,
    // html: Some(..)` instead of markup in the text field (found by the HTML work, 2026-10-29).
    let text = msg
        .text_bodies()
        .find(|p| !is_legacy_display(p) && matches!(p.body, PartType::Text(_)))
        .and_then(|p| p.text_contents().map(str::to_owned));
    // … and symmetrically it lists a text part under `html_bodies()` when there is no HTML.
    let html = msg
        .html_bodies()
        .find(|p| !is_legacy_display(p) && matches!(p.body, PartType::Html(_)))
        .and_then(|p| p.text_contents().map(str::to_owned));
    let attachments = msg
        .attachments()
        .filter(|p| !is_legacy_display(p))
        .map(|p| {
            let content_type = p
                .content_type()
                .map(|ct| format_ctype(ct.ctype(), ct.subtype()))
                .unwrap_or_else(|| "application/octet-stream".to_owned());
            Attachment {
                filename: p.attachment_name().unwrap_or("").to_owned(),
                content_type,
                data: p.contents().to_vec(),
                content_id: p.content_id().map(strip_angles),
            }
        })
        .collect();
    PlainBody {
        text,
        html,
        attachments,
    }
}

fn classify(msg: &Message<'_>, raw: &[u8], depth: u8) -> Result<MessageKind, MimeError> {
    let root = msg.root_part();
    let ct = root.content_type();
    let ctype = ct.map(|c| c.ctype().to_ascii_lowercase());
    let subtype = ct.and_then(|c| c.subtype()).map(|s| s.to_ascii_lowercase());
    let param = |name: &str| {
        ct.and_then(|c| c.attribute(name))
            .map(|v| v.to_ascii_lowercase())
    };
    let body_start = (root.raw_body_offset() as usize).min(raw.len());
    let body = &raw[body_start..];

    if ctype.as_deref() == Some("multipart") {
        match subtype.as_deref() {
            Some("encrypted") => {
                let protocol = param("protocol");
                if protocol.is_none() || protocol.as_deref() == Some("application/pgp-encrypted") {
                    let boundary = param_raw(ct, "boundary").ok_or_else(|| {
                        MimeError::Structure("multipart/encrypted", "missing boundary".into())
                    })?;
                    let parts = split_multipart(body, &boundary);
                    let payload = parts
                        .iter()
                        .find(|p| {
                            part_content_type(p).as_deref() == Some("application/octet-stream")
                        })
                        .or_else(|| parts.get(1))
                        .ok_or_else(|| {
                            MimeError::Structure(
                                "multipart/encrypted",
                                format!("expected 2 parts, found {}", parts.len()),
                            )
                        })?;
                    let (_, ciphertext) = split_entity(payload);
                    return Ok(MessageKind::PgpMimeEncrypted {
                        ciphertext: ciphertext.trim_ascii().to_vec(),
                    });
                }
            }
            Some("signed") => {
                let protocol = param("protocol");
                if protocol.is_none() || protocol.as_deref() == Some("application/pgp-signature") {
                    let boundary = param_raw(ct, "boundary").ok_or_else(|| {
                        MimeError::Structure("multipart/signed", "missing boundary".into())
                    })?;
                    let parts = split_multipart(body, &boundary);
                    if parts.len() < 2 {
                        return Err(MimeError::Structure(
                            "multipart/signed",
                            format!("expected 2 parts, found {}", parts.len()),
                        ));
                    }
                    let (_, signature) = split_entity(parts[1]);
                    return Ok(MessageKind::PgpMimeSigned {
                        signed_part: parts[0].to_vec(),
                        signature: signature.trim_ascii().to_vec(),
                        micalg: param("micalg"),
                    });
                }
            }
            Some("mixed") if depth == 0 => {
                // Some gateways wrap the PGP/MIME entity in multipart/mixed.
                if let Some(ids) = root.sub_parts() {
                    for id in ids {
                        let Some(part) = msg.part(*id) else { continue };
                        let is_pgp = part.content_type().is_some_and(|c| {
                            c.ctype().eq_ignore_ascii_case("multipart")
                                && c.subtype().is_some_and(|s| {
                                    s.eq_ignore_ascii_case("encrypted")
                                        || s.eq_ignore_ascii_case("signed")
                                })
                        });
                        if is_pgp {
                            let start = part.raw_header_offset() as usize;
                            let end = (part.raw_end_offset() as usize).min(raw.len());
                            if start < end {
                                let sub_raw = &raw[start..end];
                                if let Some(sub) = MessageParser::default().parse(sub_raw) {
                                    return classify(&sub, sub_raw, depth + 1);
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let plain = plain_body(msg);
    if let Some(armored) = plain.text.as_deref().and_then(inline_pgp_block) {
        return Ok(MessageKind::InlinePgp { armored });
    }
    Ok(MessageKind::Plain(plain))
}

fn param_raw(ct: Option<&mail_parser::ContentType<'_>>, name: &str) -> Option<String> {
    ct.and_then(|c| c.attribute(name)).map(str::to_owned)
}

fn part_content_type(part: &[u8]) -> Option<String> {
    let (headers, _) = split_entity(part);
    let text = String::from_utf8_lossy(headers);
    let unfolded = text
        .replace("\r\n ", " ")
        .replace("\r\n\t", " ")
        .replace("\n ", " ");
    for line in unfolded.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-type") {
                let v = value.trim();
                let main = v
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                return Some(main);
            }
        }
    }
    None
}

fn inline_pgp_block(text: &str) -> Option<String> {
    const STARTS: [(&str, &str); 2] = [
        ("-----BEGIN PGP MESSAGE-----", "-----END PGP MESSAGE-----"),
        (
            "-----BEGIN PGP SIGNED MESSAGE-----",
            "-----END PGP SIGNATURE-----",
        ),
    ];
    for (begin, end) in STARTS {
        if let Some(s) = text.find(begin) {
            if let Some(e) = text[s..].find(end) {
                return Some(text[s..s + e + end.len()].to_owned());
            }
        }
    }
    None
}

/// Split a multipart body into its raw parts (headers + body, byte-exact,
/// excluding the CRLF that precedes each delimiter) per RFC 2046 §5.1.1.
/// Preamble and epilogue are dropped.
pub fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Vec<&'a [u8]> {
    let delim = format!("--{boundary}");
    let delim = delim.as_bytes();
    let mut parts = Vec::new();
    let mut current_start: Option<usize> = None;
    let mut i = 0;
    while i + delim.len() <= body.len() {
        let at_line_start = i == 0 || body[i - 1] == b'\n';
        if at_line_start && &body[i..i + delim.len()] == delim {
            let mut j = i + delim.len();
            let closing = body.get(j..j + 2) == Some(b"--");
            if closing {
                j += 2;
            }
            // transport padding
            while j < body.len() && (body[j] == b' ' || body[j] == b'\t') {
                j += 1;
            }
            let line_ok = j >= body.len() || body[j] == b'\r' || body[j] == b'\n';
            if line_ok {
                if let Some(start) = current_start {
                    let mut end = i;
                    if end > start && body[end - 1] == b'\n' {
                        end -= 1;
                        if end > start && body[end - 1] == b'\r' {
                            end -= 1;
                        }
                    }
                    parts.push(&body[start..end.max(start)]);
                }
                if closing {
                    return parts;
                }
                // skip the delimiter line's CRLF
                if j < body.len() && body[j] == b'\r' {
                    j += 1;
                }
                if j < body.len() && body[j] == b'\n' {
                    j += 1;
                }
                current_start = Some(j);
                i = j;
                continue;
            }
        }
        i += 1;
    }
    if let Some(start) = current_start {
        // Unterminated multipart: take the rest as the last part.
        parts.push(&body[start.min(body.len())..]);
    }
    parts
}

/// Split a MIME entity into (header block, body) at the first blank line.
/// The header slice excludes the blank line; an entity without a blank line
/// is treated as headers only.
pub fn split_entity(entity: &[u8]) -> (&[u8], &[u8]) {
    if entity.starts_with(b"\r\n") {
        return (&[], &entity[2..]);
    }
    if entity.starts_with(b"\n") {
        return (&[], &entity[1..]);
    }
    if let Some(pos) = find(entity, b"\r\n\r\n") {
        return (&entity[..pos + 2], &entity[pos + 4..]);
    }
    if let Some(pos) = find(entity, b"\n\n") {
        return (&entity[..pos + 1], &entity[pos + 2..]);
    }
    (entity, &[])
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

impl PlainBody {
    /// Does the body contain anything at all?
    pub fn is_empty(&self) -> bool {
        self.text.as_deref().is_none_or(str::is_empty)
            && self.html.as_deref().is_none_or(str::is_empty)
            && self.attachments.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain_of(raw: &str) -> PlainBody {
        match parse(raw.as_bytes()).expect("parse").kind {
            MessageKind::Plain(p) => p,
            other => panic!("not a plain message: {other:?}"),
        }
    }

    #[test]
    fn html_only_mail_has_no_text_body_and_keeps_its_html() {
        let raw = concat!(
            "From: a@sealbox.test\r\nTo: b@sealbox.test\r\nSubject: html only\r\n",
            "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n",
            "<html><body><p>Hello <b>there</b></p></body></html>\r\n",
        );
        let body = plain_of(raw);
        assert_eq!(
            body.text, None,
            "HTML source must not be taken as the text body"
        );
        assert!(body
            .html
            .as_deref()
            .is_some_and(|h| h.contains("<b>there</b>")));
    }

    #[test]
    fn alternative_mail_keeps_both_parts_and_plain_mail_only_text() {
        let alt = concat!(
            "From: a@sealbox.test\r\nTo: b@sealbox.test\r\nSubject: alt\r\nMIME-Version: 1.0\r\n",
            "Content-Type: multipart/alternative; boundary=\"b\"\r\n\r\n",
            "--b\r\nContent-Type: text/plain\r\n\r\nplain words\r\n",
            "--b\r\nContent-Type: text/html\r\n\r\n<p>rich words</p>\r\n--b--\r\n",
        );
        let body = plain_of(alt);
        assert_eq!(body.text.as_deref().map(str::trim), Some("plain words"));
        assert!(body
            .html
            .as_deref()
            .is_some_and(|h| h.contains("rich words")));

        let plain = "From: a@sealbox.test\r\nTo: b@sealbox.test\r\nSubject: p\r\n\r\njust text\r\n";
        let body = plain_of(plain);
        assert_eq!(body.text.as_deref().map(str::trim), Some("just text"));
        assert_eq!(body.html, None);
    }

    #[test]
    fn encrypted_entity_wrapped_in_multipart_mixed_is_recognised() {
        let raw = concat!(
            "From: a@sealbox.test\r\n",
            "To: b@sealbox.test\r\n",
            "Subject: ...\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=\"outer\"\r\n",
            "\r\n",
            "--outer\r\n",
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"inner\"\r\n",
            "\r\n",
            "--inner\r\n",
            "Content-Type: application/pgp-encrypted\r\n",
            "\r\n",
            "Version: 1\r\n",
            "--inner\r\n",
            "Content-Type: application/octet-stream\r\n",
            "\r\n",
            "-----BEGIN PGP MESSAGE-----\r\n\r\nAAAA\r\n=abcd\r\n-----END PGP MESSAGE-----\r\n",
            "--inner--\r\n",
            "--outer\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "gateway footer\r\n",
            "--outer--\r\n",
        );
        let parsed = parse(raw.as_bytes()).expect("parse");
        match parsed.kind {
            MessageKind::PgpMimeEncrypted { ciphertext } => {
                let text = String::from_utf8(ciphertext).unwrap();
                assert!(text.starts_with("-----BEGIN PGP MESSAGE-----"));
                assert!(text.ends_with("-----END PGP MESSAGE-----"));
            }
            other => panic!("expected encrypted, got {other:?}"),
        }
    }

    #[test]
    fn signed_without_protocol_param_still_parses() {
        let raw = concat!(
            "Content-Type: multipart/signed; micalg=pgp-sha512; boundary=b\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "signed text\r\n",
            "--b\r\n",
            "Content-Type: application/pgp-signature\r\n",
            "\r\n",
            "-----BEGIN PGP SIGNATURE-----\r\n\r\nAAAA\r\n-----END PGP SIGNATURE-----\r\n",
            "--b--\r\n",
        );
        let parsed = parse(raw.as_bytes()).expect("parse");
        match parsed.kind {
            MessageKind::PgpMimeSigned {
                signed_part,
                signature,
                micalg,
            } => {
                assert_eq!(signed_part, b"Content-Type: text/plain\r\n\r\nsigned text");
                assert!(signature.starts_with(b"-----BEGIN PGP SIGNATURE-----"));
                assert_eq!(micalg.as_deref(), Some("pgp-sha512"));
            }
            other => panic!("expected signed, got {other:?}"),
        }
    }

    #[test]
    fn broken_input_is_an_error_not_a_panic() {
        assert!(matches!(parse(b""), Err(MimeError::Unparseable)) || parse(b"").is_ok());
        let bad = b"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"\r\n\r\nno boundary";
        assert!(matches!(parse(bad), Err(MimeError::Structure(..))));
        let one_part = b"Content-Type: multipart/signed; boundary=z\r\n\r\n--z\r\nContent-Type: text/plain\r\n\r\nx\r\n--z--\r\n";
        assert!(matches!(parse(one_part), Err(MimeError::Structure(..))));
    }
}
