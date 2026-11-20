//! Message construction: plain RFC 5322, the protected inner entity, and the
//! RFC 3156 `multipart/encrypted` / `multipart/signed` wrappers.

use std::borrow::Cow;

use mail_builder::headers::address::Address;
use mail_builder::headers::content_type::ContentType;
use mail_builder::headers::date::Date;
use mail_builder::headers::message_id::MessageId;
use mail_builder::headers::raw::Raw;
use mail_builder::headers::text::Text;
use mail_builder::mime::{BodyPart, MimePart};
use mail_builder::MessageBuilder;

use super::headers::sanitize_header_value;
use super::types::{is_addr_spec, Attachment, Mailbox, MessageDraft};
use crate::error::MimeError;

/// What goes in the outer `Subject` when the real one is protected inside the
/// encrypted payload (Thunderbird / Delta Chat convention).
pub const PROTECTED_SUBJECT_PLACEHOLDER: &str = "...";

const PROTECTED_HEADERS_PARAM: (&str, &str) = ("protected-headers", "v1");

/// Headers of the outer (cleartext) message that wraps a PGP/MIME payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OuterHeaders {
    pub from: Mailbox,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub subject: String,
    pub date: i64,
    pub message_id: String,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    /// e.g. `Autocrypt`; values must be single-line (see `sanitize_header_value`).
    pub extra_headers: Vec<(String, String)>,
}

impl OuterHeaders {
    /// Outer headers that mirror the draft, subject included (for signed-only mail).
    pub fn from_draft(draft: &MessageDraft) -> Self {
        Self {
            from: draft.from.clone(),
            to: draft.to.clone(),
            cc: draft.cc.clone(),
            subject: draft.subject.clone(),
            date: draft.date,
            message_id: draft.message_id.clone(),
            in_reply_to: draft.in_reply_to.clone(),
            references: draft.references.clone(),
            extra_headers: draft.extra_headers.clone(),
        }
    }

    /// Outer headers for an encrypted message whose real subject lives in the
    /// protected inner part: the outer subject becomes `"..."`.
    pub fn for_protected(draft: &MessageDraft) -> Self {
        let mut h = Self::from_draft(draft);
        h.subject = PROTECTED_SUBJECT_PLACEHOLDER.to_owned();
        h
    }
}

/// Options for the inner (to-be-encrypted) entity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InnerOptions {
    /// `Autocrypt-Gossip` header values to place inside the encrypted payload
    /// (Autocrypt Level 1 §2.2 requires gossip to be inside the encryption).
    pub gossip_headers: Vec<String>,
    /// Add a `text/rfc822-headers; protected-headers="v1"` legacy-display part
    /// so that clients without protected-header support still show the Subject.
    pub legacy_display: bool,
}

/// Render a plaintext RFC 5322 message (no PGP). `Bcc` is never written.
pub fn build_plain(draft: &MessageDraft) -> Result<Vec<u8>, MimeError> {
    let mut b = MessageBuilder::new();
    b = envelope_headers(b, &HeaderSet::from_draft(draft, &draft.subject))?;
    b = b.body(body_tree(draft, false, &InnerOptions::default()));
    Ok(b.write_to_vec()?)
}

/// Render the MIME entity that will be encrypted. Its top-level
/// `Content-Type` carries `protected-headers="v1"` and the entity repeats
/// `Subject`, `From`, `To`, `Cc`, `Date`, `Message-ID`, `In-Reply-To` and
/// `References` so that the recipient can verify / display them from inside
/// the ciphertext. Output uses CRLF line endings.
pub fn render_inner_for_encryption(
    draft: &MessageDraft,
    opts: &InnerOptions,
) -> Result<Vec<u8>, MimeError> {
    let mut b = MessageBuilder::new();
    let mut set = HeaderSet::from_draft(draft, &draft.subject);
    set.extra = opts
        .gossip_headers
        .iter()
        .map(|v| ("Autocrypt-Gossip".to_owned(), v.clone()))
        .collect();
    b = envelope_headers(b, &set)?;
    b = b.body(body_tree(draft, true, opts));
    Ok(b.write_to_vec()?)
}

/// Render the exact bytes to be detached-signed for a `multipart/signed`
/// message: the first body part including its MIME headers, CRLF line
/// endings, 7-bit safe (RFC 3156 §5). Sign *these bytes*, then pass them
/// unchanged to [`build_pgp_mime_signed`].
pub fn prepare_signed_part(draft: &MessageDraft) -> Result<Vec<u8>, MimeError> {
    let bytes = render_inner_for_encryption(draft, &InnerOptions::default())?;
    Ok(canonicalize_crlf(&bytes))
}

/// Wrap an ASCII-armored OpenPGP message in RFC 3156 `multipart/encrypted`.
pub fn build_pgp_mime_encrypted(
    outer: &OuterHeaders,
    ciphertext_armored: &str,
) -> Result<Vec<u8>, MimeError> {
    let armored = crlf_text(ciphertext_armored.trim());

    let version = MimePart::new(
        ContentType::new("application/pgp-encrypted"),
        BodyPart::Text(Cow::Borrowed("Version: 1\r\n")),
    )
    .header(
        "Content-Description",
        Raw::new("PGP/MIME version identification"),
    )
    .transfer_encoding("7bit");

    let payload = MimePart::new(
        ContentType::new("application/octet-stream").attribute("name", "encrypted.asc"),
        BodyPart::Text(Cow::Owned(armored)),
    )
    .header("Content-Description", Raw::new("OpenPGP encrypted message"))
    .header(
        "Content-Disposition",
        ContentType::new("inline").attribute("filename", "encrypted.asc"),
    )
    .transfer_encoding("7bit");

    let root = MimePart::new(
        ContentType::new("multipart/encrypted").attribute("protocol", "application/pgp-encrypted"),
        BodyPart::Multipart(vec![version, payload]),
    );

    let mut b = MessageBuilder::new();
    b = envelope_headers(b, &HeaderSet::from_outer(outer))?;
    b = b.body(root);
    Ok(b.write_to_vec()?)
}

/// Wrap a signed part (the bytes returned by [`prepare_signed_part`]) and its
/// ASCII-armored detached signature in RFC 3156 `multipart/signed`.
/// `micalg` is e.g. `pgp-sha256` / `pgp-sha512`.
pub fn build_pgp_mime_signed(
    outer: &OuterHeaders,
    signed_part: &[u8],
    signature_armored: &str,
    micalg: &str,
) -> Result<Vec<u8>, MimeError> {
    if !signed_part.is_ascii() {
        return Err(MimeError::Structure(
            "multipart/signed",
            "signed part must be 7-bit (RFC 3156 §5)".into(),
        ));
    }
    let armored = crlf_text(signature_armored.trim());

    // Raw part: written byte-for-byte, so the signature stays valid.
    let first = MimePart::raw(BodyPart::Binary(Cow::Borrowed(signed_part)));

    let sig = MimePart::new(
        ContentType::new("application/pgp-signature").attribute("name", "signature.asc"),
        BodyPart::Text(Cow::Owned(armored)),
    )
    .header("Content-Description", Raw::new("OpenPGP digital signature"))
    .header(
        "Content-Disposition",
        ContentType::new("attachment").attribute("filename", "signature.asc"),
    )
    .transfer_encoding("7bit");

    let root = MimePart::new(
        ContentType::new("multipart/signed")
            .attribute("micalg", micalg.to_ascii_lowercase())
            .attribute("protocol", "application/pgp-signature"),
        BodyPart::Multipart(vec![first, sig]),
    );

    let mut b = MessageBuilder::new();
    b = envelope_headers(b, &HeaderSet::from_outer(outer))?;
    b = b.body(root);
    Ok(b.write_to_vec()?)
}

// ---------------------------------------------------------------------------

struct HeaderSet<'a> {
    from: &'a Mailbox,
    to: &'a [Mailbox],
    cc: &'a [Mailbox],
    subject: &'a str,
    date: i64,
    message_id: &'a str,
    in_reply_to: Option<&'a str>,
    references: &'a [String],
    extra: Vec<(String, String)>,
}

impl<'a> HeaderSet<'a> {
    fn from_draft(d: &'a MessageDraft, subject: &'a str) -> Self {
        Self {
            from: &d.from,
            to: &d.to,
            cc: &d.cc,
            subject,
            date: d.date,
            message_id: &d.message_id,
            in_reply_to: d.in_reply_to.as_deref(),
            references: &d.references,
            extra: d.extra_headers.clone(),
        }
    }

    fn from_outer(o: &'a OuterHeaders) -> Self {
        Self {
            from: &o.from,
            to: &o.to,
            cc: &o.cc,
            subject: &o.subject,
            date: o.date,
            message_id: &o.message_id,
            in_reply_to: o.in_reply_to.as_deref(),
            references: &o.references,
            extra: o.extra_headers.clone(),
        }
    }
}

fn address<'x>(m: &Mailbox) -> Result<Address<'x>, MimeError> {
    if !is_addr_spec(&m.address) {
        return Err(MimeError::InvalidAddress(m.address.clone()));
    }
    let name = m
        .name
        .as_deref()
        .map(|n| n.trim())
        .filter(|n| !n.is_empty())
        .map(|n| n.replace(['\r', '\n'], " "));
    Ok(Address::new_address(name, m.address.clone()))
}

fn address_list<'x>(list: &[Mailbox]) -> Result<Address<'x>, MimeError> {
    Ok(Address::new_list(
        list.iter().map(address).collect::<Result<Vec<_>, _>>()?,
    ))
}

fn strip_angles(id: &str) -> String {
    id.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_owned()
}

fn envelope_headers<'x>(
    mut b: MessageBuilder<'x>,
    h: &HeaderSet<'_>,
) -> Result<MessageBuilder<'x>, MimeError> {
    b = b.from(address(h.from)?);
    if !h.to.is_empty() {
        b = b.to(address_list(h.to)?);
    }
    if !h.cc.is_empty() {
        b = b.cc(address_list(h.cc)?);
    }
    b = b.subject(Text::new(sanitize_header_value(h.subject)?));
    b = b.date(Date::new(h.date));
    b = b.message_id(MessageId::new(strip_angles(h.message_id)));
    if let Some(irt) = h.in_reply_to {
        b = b.in_reply_to(MessageId::new(strip_angles(irt)));
    }
    if !h.references.is_empty() {
        b = b.references(MessageId::new_list(
            h.references.iter().map(|r| strip_angles(r)),
        ));
    }
    for (name, value) in &h.extra {
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_graphic() && c != b':') {
            return Err(MimeError::InvalidHeader(
                name.clone(),
                "header names must be printable ASCII without ':'".into(),
            ));
        }
        b = b.header(name.clone(), Raw::new(sanitize_header_value(value)?));
    }
    Ok(b)
}

fn text_part<'x>(ctype: &'static str, body: &'x str, protected: bool) -> MimePart<'x> {
    let mut ct = ContentType::new(ctype).attribute("charset", "utf-8");
    if protected {
        ct = ct.attribute(PROTECTED_HEADERS_PARAM.0, PROTECTED_HEADERS_PARAM.1);
    }
    MimePart::new(ct, BodyPart::Text(Cow::Borrowed(body)))
}

fn attachment_part(a: &Attachment) -> MimePart<'_> {
    let ctype = if a.content_type.is_empty() {
        "application/octet-stream"
    } else {
        a.content_type.as_str()
    };
    let part = MimePart::new(
        ContentType::new(ctype).attribute("name", a.filename.as_str()),
        BodyPart::Binary(Cow::Borrowed(&a.data)),
    );
    match &a.content_id {
        Some(cid) => part
            .header(
                "Content-Disposition",
                ContentType::new("inline").attribute("filename", a.filename.as_str()),
            )
            .cid(cid.as_str()),
        None => part.attachment(a.filename.as_str()),
    }
}

fn multipart<'x>(subtype: &'static str, parts: Vec<MimePart<'x>>, protected: bool) -> MimePart<'x> {
    let mut ct = ContentType::new(subtype);
    if protected {
        ct = ct.attribute(PROTECTED_HEADERS_PARAM.0, PROTECTED_HEADERS_PARAM.1);
    }
    MimePart::new(ct, BodyPart::Multipart(parts))
}

/// The body tree for a draft. When `protected` is set the *top-level* part
/// carries `protected-headers="v1"` (whatever its type), which is the marker
/// Thunderbird/Enigmail/Delta Chat look for.
fn body_tree<'x>(draft: &'x MessageDraft, protected: bool, opts: &InnerOptions) -> MimePart<'x> {
    let has_attachments = !draft.attachments.is_empty();
    let legacy = protected && opts.legacy_display;
    let wrap_mixed = has_attachments || legacy;

    let content = match &draft.html_body {
        Some(html) => multipart(
            "multipart/alternative",
            vec![
                text_part("text/plain", &draft.text_body, false),
                text_part("text/html", html, false),
            ],
            protected && !wrap_mixed,
        ),
        None => text_part("text/plain", &draft.text_body, protected && !wrap_mixed),
    };

    if !wrap_mixed {
        return content;
    }

    let mut parts = Vec::with_capacity(draft.attachments.len() + 2);
    if legacy {
        parts.push(
            MimePart::new(
                ContentType::new("text/rfc822-headers")
                    .attribute(PROTECTED_HEADERS_PARAM.0, PROTECTED_HEADERS_PARAM.1),
                BodyPart::Text(Cow::Owned(format!(
                    "Subject: {}\r\n",
                    draft.subject.replace(['\r', '\n'], " ")
                ))),
            )
            .header("Content-Disposition", ContentType::new("inline")),
        );
    }
    parts.push(content);
    parts.extend(draft.attachments.iter().map(attachment_part));
    multipart("multipart/mixed", parts, protected)
}

/// Convert bare LF to CRLF without doubling existing CRLFs.
pub(crate) fn canonicalize_crlf(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + 16);
    let mut prev_cr = false;
    for &b in input {
        if b == b'\n' && !prev_cr {
            out.push(b'\r');
        }
        out.push(b);
        prev_cr = b == b'\r';
    }
    out
}

fn crlf_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for line in s.split_inclusive('\n') {
        let body = line.trim_end_matches(['\r', '\n']);
        out.push_str(body);
        out.push_str("\r\n");
    }
    out
}
