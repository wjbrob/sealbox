//! Signatures (gate G23) and the compose layer of the send pipeline.
//!
//! * [`sanitize_html`] — allowlist HTML sanitiser for HTML signatures (no scripts, styles,
//!   event handlers or remote images; links only `http(s):`/`mailto:`, images only
//!   `cid:`/`data:image/`).
//! * [`compose`] — assembles the final text (and, when there is one, HTML) body from the
//!   user's text, the quoted original and the signature: the signature follows the `-- `
//!   separator line (RFC 3676 §4.3) and, for replies/forwards, sits above or below the quote
//!   per [`SignaturePlacement`].
//! * [`quote_reply`] / [`quote_forward`] — the `On <date>, <from> wrote:` + `> ` quoting and
//!   the `-------- Forwarded Message --------` block with headers.
//! * [`Engine::send_with`] — `send` plus [`ComposeOptions`]; `Engine::send` is the same with
//!   the defaults. Auto-replies go through the crate-private `send_composed` with the
//!   signature switched off.
//! * [`Engine::compose_preview`] / [`Engine::signature_preview`] — what `send_with` would
//!   send (bodies after quoting and signature) and the signature block alone, for a compose
//!   screen; nothing is sent.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::settings::{SignatureIncludeOn, SignaturePlacement, SignatureSettings};
use crate::store::MessageRow;
use crate::types::{Address, AttachmentData, Draft, SendReport};

/// The signature separator line (RFC 3676 §4.3): dash, dash, space, newline.
pub const SIGNATURE_SEPARATOR: &str = "-- ";

/// How a draft came to be. Drives signature inclusion/placement and quoting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComposeKind {
    #[default]
    New,
    /// `Draft::in_reply_to` names the message answered.
    Reply,
    /// [`ComposeOptions::forward_of`] names the message forwarded.
    Forward,
}

/// Options of [`Engine::send_with`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ComposeOptions {
    /// `New` with `Draft::in_reply_to` set is treated as `Reply`.
    pub kind: ComposeKind,
    /// Quote the original below the text (`On <date>, <from> wrote:` + `> `). Only stored
    /// messages can be quoted. Implied for forwards.
    pub quote: bool,
    /// For forwards: local id (digits) or Message-ID of the stored message to forward; its
    /// text goes below a `-------- Forwarded Message --------` header block and its
    /// attachments are carried along.
    pub forward_of: Option<String>,
    /// Never add the account signature (auto-replies).
    pub skip_signature: bool,
}

/// Result of [`Engine::compose_preview`]: exactly the bodies [`Engine::send_with`] would
/// send for the same draft and options.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposePreview {
    /// The effective kind (`New` with `Draft::in_reply_to` set becomes `Reply`).
    pub kind: ComposeKind,
    /// Final text body: the draft text, then quote and signature per the settings.
    pub text: String,
    /// Final HTML body when the draft or the signature has one.
    #[serde(default)]
    pub html: Option<String>,
    /// The account signature was added.
    pub signature_applied: bool,
    /// File names of the forwarded message's attachments that `send_with` carries along.
    #[serde(default)]
    pub forwarded_attachments: Vec<String>,
}

/// The signature block alone ([`Engine::signature_preview`]), as it would be appended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignaturePreview {
    /// The text block starting with the `-- ` separator line (empty when the signature is
    /// HTML-only).
    pub text: String,
    /// The sanitised HTML block, when an HTML variant is configured.
    #[serde(default)]
    pub html: Option<String>,
    pub placement: SignaturePlacement,
}

/// What composing a draft did (crate-internal).
pub(crate) struct Composition {
    pub kind: ComposeKind,
    pub account_email: String,
    pub signature_applied: bool,
    pub forwarded_attachments: Vec<String>,
}

/// Crate-internal extras for the raw send pipeline.
#[derive(Clone, Debug, Default)]
pub(crate) struct SendExtras {
    /// Additional outer headers (e.g. `Auto-Submitted`).
    pub headers: Vec<(String, String)>,
    /// When the policy would refuse because a recipient has no key, send plaintext instead
    /// (auto-replies: "encrypted when possible"). Never set for user mail.
    pub plaintext_fallback: bool,
}

/// Does `include_on` cover a message of this kind?
pub fn signature_applies(include_on: SignatureIncludeOn, kind: ComposeKind) -> bool {
    match include_on {
        SignatureIncludeOn::NewOnly => kind == ComposeKind::New,
        SignatureIncludeOn::NewAndReplies => kind != ComposeKind::Forward,
        SignatureIncludeOn::All => true,
    }
}

// ----- HTML sanitiser ---------------------------------------------------------------------

const ALLOWED_TAGS: &[&str] = &[
    "p", "br", "b", "i", "u", "a", "span", "div", "ul", "ol", "li", "img", "strong", "em",
];
const VOID_TAGS: &[&str] = &["br", "img"];
/// Elements dropped *with* their content.
const DROP_WITH_CONTENT: &[&str] = &[
    "script",
    "style",
    "iframe",
    "object",
    "embed",
    "svg",
    "math",
    "title",
    "head",
    "textarea",
    "noscript",
    "template",
    "frame",
    "frameset",
    "applet",
    "xmp",
    "plaintext",
    "noframes",
];

fn allowed_tag(name: &str) -> Option<&'static str> {
    ALLOWED_TAGS.iter().copied().find(|t| *t == name)
}

/// Reduce HTML to the signature allowlist: `p br b i u strong em span div ul ol li`,
/// `a` (only `href` with `http:`/`https:`/`mailto:`, plus `title`) and `img` (only `src`
/// with `cid:` or `data:image/`, plus `alt`/`width`/`height`). Everything else is dropped —
/// script/style/iframe/object/svg… together with their content, other unknown tags keeping
/// their text. No attribute survives except the ones listed (so no `on*`, `style`, `class`).
/// Comments and declarations go; unclosed allowed elements are closed; a literal `<` that
/// does not start a tag becomes `&lt;`. Idempotent.
pub fn sanitize_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut stack: Vec<&'static str> = Vec::new();
    let mut skipping: Option<String> = None;
    let mut rest = input;
    while !rest.is_empty() {
        let Some(lt) = rest.find('<') else {
            if skipping.is_none() {
                out.push_str(rest);
            }
            break;
        };
        let (text, tail) = rest.split_at(lt);
        if skipping.is_none() {
            out.push_str(text);
        }
        if tail.starts_with("<!--") {
            match tail.find("-->") {
                Some(e) => rest = &tail[e + 3..],
                None => break,
            }
            continue;
        }
        if tail.starts_with("<!") || tail.starts_with("<?") {
            match tail.find('>') {
                Some(e) => rest = &tail[e + 1..],
                None => break,
            }
            continue;
        }
        let after = &tail[1..];
        let closing = after.starts_with('/');
        let name_start = if closing { &after[1..] } else { after };
        let name_len = name_start
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric())
            .count();
        if name_len == 0 {
            if skipping.is_none() {
                out.push_str("&lt;");
            }
            rest = after;
            continue;
        }
        let name = name_start[..name_len].to_ascii_lowercase();
        let Some((attr_text, consumed)) = scan_tag_end(&name_start[name_len..]) else {
            // Unterminated tag: drop the remainder.
            break;
        };
        rest = &name_start[name_len + consumed..];

        if let Some(skip) = &skipping {
            if closing && *skip == name {
                skipping = None;
            }
            continue;
        }
        if closing {
            if let Some(tag) = allowed_tag(&name) {
                if !VOID_TAGS.contains(&tag) {
                    if let Some(pos) = stack.iter().rposition(|t| *t == tag) {
                        while stack.len() > pos {
                            if let Some(t) = stack.pop() {
                                out.push_str("</");
                                out.push_str(t);
                                out.push('>');
                            }
                        }
                    }
                }
            }
            continue;
        }
        if DROP_WITH_CONTENT.contains(&name.as_str()) {
            skipping = Some(name);
            continue;
        }
        let Some(tag) = allowed_tag(&name) else {
            continue;
        };
        let attrs = clean_attributes(tag, &parse_attributes(attr_text));
        if tag == "img" && !attrs.iter().any(|(k, _)| k == "src") {
            // An image without an allowed source is dropped entirely.
            continue;
        }
        out.push('<');
        out.push_str(tag);
        for (k, v) in &attrs {
            out.push(' ');
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(&escape_attr(v));
            out.push('"');
        }
        out.push('>');
        if !VOID_TAGS.contains(&tag) {
            stack.push(tag);
        }
    }
    while let Some(t) = stack.pop() {
        out.push_str("</");
        out.push_str(t);
        out.push('>');
    }
    out
}

/// Find the end of a tag after its name, honouring quoted attribute values (a quote only
/// opens a value right after `=`, as in HTML; inside an unquoted value it is an ordinary
/// character). Returns the attribute text and the number of bytes consumed (including `>`).
fn scan_tag_end(s: &str) -> Option<(&str, usize)> {
    let mut quote: Option<u8> = None;
    let mut expect_value = false;
    for (i, b) in s.bytes().enumerate() {
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' if expect_value => {
                    quote = Some(b);
                    expect_value = false;
                }
                b'>' => return Some((&s[..i], i + 1)),
                b'=' => expect_value = true,
                b' ' | b'\t' | b'\r' | b'\n' => {}
                _ => expect_value = false,
            },
        }
    }
    None
}

fn parse_attributes(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        let start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'/'
        {
            i += 1;
        }
        if i == start {
            break;
        }
        let name = s[start..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let q = bytes[i];
                i += 1;
                let vstart = i;
                while i < bytes.len() && bytes[i] != q {
                    i += 1;
                }
                value = s[vstart..i].to_string();
                if i < bytes.len() {
                    i += 1;
                }
            } else {
                let vstart = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                value = s[vstart..i].to_string();
            }
        }
        out.push((name, value));
    }
    out
}

fn safe_url(value: &str, schemes: &[&str]) -> Option<String> {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .collect();
    let lower = cleaned.to_ascii_lowercase();
    if schemes.iter().any(|s| lower.starts_with(s)) {
        Some(cleaned)
    } else {
        None
    }
}

fn clean_attributes(tag: &str, attrs: &[(String, String)]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in attrs {
        let keep = match (tag, k.as_str()) {
            ("a", "href") => safe_url(v, &["http://", "https://", "mailto:"]),
            ("a", "title") => Some(v.clone()),
            ("img", "src") => safe_url(v, &["cid:", "data:image/"]),
            ("img", "alt") => Some(v.clone()),
            ("img", "width") | ("img", "height") => {
                if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
                    Some(v.clone())
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(val) = keep {
            if !out.iter().any(|(x, _): &(String, String)| x == k) {
                out.push((k.clone(), val));
            }
        }
    }
    out
}

fn escape_attr(v: &str) -> String {
    v.replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Escape text for HTML (`& < > "`).
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// Plain text → HTML fragment (escaped, lines joined with `<br>`).
pub fn text_to_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    for (i, line) in text.replace("\r\n", "\n").trim_end().lines().enumerate() {
        if i > 0 {
            out.push_str("<br>\n");
        }
        out.push_str(&escape_html(line));
    }
    out
}

/// Crude HTML → text for quoting messages that only have an HTML body.
fn html_to_text_lossy(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    let lower = html.to_ascii_lowercase();
    let mut i = 0;
    let bytes = html.as_bytes();
    while i < bytes.len() {
        if !in_tag && bytes[i] == b'<' {
            if lower[i..].starts_with("<br")
                || lower[i..].starts_with("</p")
                || lower[i..].starts_with("</div")
            {
                out.push('\n');
            }
            in_tag = true;
        } else if in_tag {
            if bytes[i] == b'>' {
                in_tag = false;
            }
        } else {
            // copy one UTF-8 scalar
            let ch_len = utf8_len(bytes[i]);
            out.push_str(&html[i..(i + ch_len).min(bytes.len())]);
            i += ch_len;
            continue;
        }
        i += 1;
    }
    out.replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

fn utf8_len(first: u8) -> usize {
    match first {
        b if b < 0x80 => 1,
        b if b & 0xE0 == 0xC0 => 2,
        b if b & 0xF0 == 0xE0 => 3,
        _ => 4,
    }
}

// ----- quoting ---------------------------------------------------------------------------

/// The original message rendered for quoting, as text and as HTML.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quoted {
    pub text: String,
    pub html: String,
}

fn fmt_date(ts: Option<i64>) -> String {
    ts.and_then(|t| DateTime::<Utc>::from_timestamp(t, 0))
        .map(|d| d.to_rfc2822())
        .unwrap_or_else(|| "an unknown date".to_string())
}

fn prefix_lines(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 64);
    for line in text.replace("\r\n", "\n").trim_end().lines() {
        if line.starts_with('>') {
            out.push('>');
        } else if line.is_empty() {
            out.push('>');
            out.push('\n');
            continue;
        } else {
            out.push_str("> ");
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// `On <date>, <from> wrote:` followed by the text with every line prefixed by `> `.
pub fn quote_reply(date: Option<i64>, from: &Address, text: &str) -> String {
    format!(
        "On {}, {} wrote:\n{}",
        fmt_date(date),
        from,
        prefix_lines(text)
    )
}

fn quote_reply_html(date: Option<i64>, from: &Address, text: &str) -> String {
    format!(
        "<div class=\"sealbox-quote-header\">On {}, {} wrote:</div>\n<blockquote type=\"cite\">{}</blockquote>",
        escape_html(&fmt_date(date)),
        escape_html(&from.to_string()),
        text_to_html(text)
    )
}

/// Headers shown above a forwarded message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForwardHeaders {
    pub subject: Option<String>,
    pub date: Option<i64>,
    pub from: Address,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
}

fn join_addresses(list: &[Address]) -> String {
    list.iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// `-------- Forwarded Message --------` plus `Subject/Date/From/To/Cc` and the text.
pub fn quote_forward(h: &ForwardHeaders, text: &str) -> String {
    let mut out = String::from("-------- Forwarded Message --------\n");
    out.push_str(&format!(
        "Subject: {}\n",
        h.subject.as_deref().unwrap_or("(no subject)")
    ));
    out.push_str(&format!("Date: {}\n", fmt_date(h.date)));
    out.push_str(&format!("From: {}\n", h.from));
    if !h.to.is_empty() {
        out.push_str(&format!("To: {}\n", join_addresses(&h.to)));
    }
    if !h.cc.is_empty() {
        out.push_str(&format!("Cc: {}\n", join_addresses(&h.cc)));
    }
    out.push('\n');
    out.push_str(text.replace("\r\n", "\n").trim_end());
    out.push('\n');
    out
}

fn quote_forward_html(h: &ForwardHeaders, text: &str) -> String {
    let mut head = format!(
        "Subject: {}\nDate: {}\nFrom: {}\n",
        h.subject.as_deref().unwrap_or("(no subject)"),
        fmt_date(h.date),
        h.from
    );
    if !h.to.is_empty() {
        head.push_str(&format!("To: {}\n", join_addresses(&h.to)));
    }
    if !h.cc.is_empty() {
        head.push_str(&format!("Cc: {}\n", join_addresses(&h.cc)));
    }
    format!(
        "<div class=\"sealbox-forward-header\">-------- Forwarded Message --------<br>\n{}</div>\n<div class=\"sealbox-forward-body\">{}</div>",
        text_to_html(&head),
        text_to_html(text)
    )
}

fn original_text(row: &MessageRow) -> String {
    match (&row.text, &row.html) {
        (Some(t), _) if !t.trim().is_empty() => t.clone(),
        (_, Some(h)) => html_to_text_lossy(h),
        (Some(t), None) => t.clone(),
        (None, None) => String::new(),
    }
}

fn quoted_reply(row: &MessageRow) -> Quoted {
    let text = original_text(row);
    Quoted {
        text: quote_reply(row.summary.date, &row.summary.from, &text),
        html: quote_reply_html(row.summary.date, &row.summary.from, &text),
    }
}

fn quoted_forward(row: &MessageRow) -> Quoted {
    let text = original_text(row);
    let h = ForwardHeaders {
        subject: row.summary.subject.clone(),
        date: row.summary.date,
        from: row.summary.from.clone(),
        to: row.summary.to.clone(),
        cc: row.summary.cc.clone(),
    };
    Quoted {
        text: quote_forward(&h, &text),
        html: quote_forward_html(&h, &text),
    }
}

// ----- composition ------------------------------------------------------------------------

/// The final bodies of a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Composed {
    pub text: String,
    /// Present when the draft had an HTML body or the applied signature has one.
    pub html: Option<String>,
}

fn ensure_blank_line(out: &mut String) {
    if out.is_empty() {
        return;
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.ends_with("\n\n") {
        out.push('\n');
    }
}

fn signature_block_text(sig: &str) -> String {
    format!(
        "{SIGNATURE_SEPARATOR}\n{}\n",
        sig.replace("\r\n", "\n").trim_end()
    )
}

fn signature_block_html(sig_html: &str) -> String {
    format!("<div class=\"sealbox-signature\">-- <br>\n{sig_html}</div>")
}

/// Assemble the text body: `body`, then the signature block and the quote in the order
/// given by `placement` (each separated by a blank line).
pub fn compose_text(
    body: &str,
    quoted: Option<&str>,
    signature: Option<&str>,
    placement: SignaturePlacement,
) -> String {
    let mut out = body.replace("\r\n", "\n");
    let sig = signature.map(signature_block_text);
    let mut push = |block: &str| {
        ensure_blank_line(&mut out);
        out.push_str(block);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    };
    match (quoted, sig.as_deref(), placement) {
        (None, None, _) => {}
        (None, Some(s), _) => push(s),
        (Some(q), None, _) => push(q),
        (Some(q), Some(s), SignaturePlacement::AboveQuote) => {
            push(s);
            push(q);
        }
        (Some(q), Some(s), SignaturePlacement::BelowQuote) => {
            push(q);
            push(s);
        }
    }
    out
}

/// Assemble the HTML body (fragment), or `None` when the message is text-only.
pub fn compose_html(
    body_html: Option<&str>,
    body_text: &str,
    quoted_html: Option<&str>,
    signature_html: Option<&str>,
    placement: SignaturePlacement,
) -> Option<String> {
    if body_html.is_none() && signature_html.is_none() {
        return None;
    }
    let mut out = match body_html {
        Some(h) => h.to_string(),
        None => format!(
            "<div class=\"sealbox-body\">{}</div>",
            text_to_html(body_text)
        ),
    };
    let sig = signature_html.map(signature_block_html);
    let mut push = |block: &str| {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(block);
    };
    match (quoted_html, sig.as_deref(), placement) {
        (None, None, _) => {}
        (None, Some(s), _) => push(s),
        (Some(q), None, _) => push(q),
        (Some(q), Some(s), SignaturePlacement::AboveQuote) => {
            push(s);
            push(q);
        }
        (Some(q), Some(s), SignaturePlacement::BelowQuote) => {
            push(q);
            push(s);
        }
    }
    Some(out)
}

/// Text + HTML composition for one message. `signature` is the (enabled, applicable)
/// signature or `None`. The HTML signature is sanitised again here; when the draft has no
/// HTML body but the signature does, the HTML alternative is derived from the text body.
pub fn compose(
    body_text: &str,
    body_html: Option<&str>,
    quoted: Option<&Quoted>,
    signature: Option<&SignatureSettings>,
) -> Composed {
    let placement = signature.map(|s| s.placement).unwrap_or_default();
    let sig_text: Option<String> = signature
        .map(|s| s.text.trim_end().to_string())
        .filter(|t| !t.is_empty());
    let sig_html: Option<String> = signature.and_then(|s| {
        let html = s
            .html
            .as_deref()
            .map(sanitize_html)
            .filter(|h| !h.trim().is_empty());
        // No HTML variant configured: mirror the text signature in the HTML alternative
        // (only used when the message has an HTML body at all).
        html.or_else(|| sig_text.as_deref().map(text_to_html))
    });
    // A text-only signature on a text-only draft must not create an HTML alternative.
    let html_wanted = body_html.is_some()
        || signature.is_some_and(|s| s.html.as_deref().is_some_and(|h| !h.trim().is_empty()));
    let text = compose_text(
        body_text,
        quoted.map(|q| q.text.as_str()),
        sig_text.as_deref(),
        placement,
    );
    let html = if html_wanted {
        compose_html(
            body_html,
            body_text,
            quoted.map(|q| q.html.as_str()),
            sig_html.as_deref(),
            placement,
        )
    } else {
        None
    };
    Composed { text, html }
}

// ----- engine ---------------------------------------------------------------------------

impl Engine {
    /// Like [`Engine::send`] with explicit [`ComposeOptions`] (reply/forward quoting, kind,
    /// signature control). `Engine::send` is `send_with(…, ComposeOptions::default())`.
    pub async fn send_with(
        &self,
        account_email: &str,
        draft: Draft,
        opts: ComposeOptions,
    ) -> Result<SendReport> {
        self.send_composed(account_email, draft, opts, SendExtras::default())
            .await
    }

    /// Load a stored message by local id (digits) or Message-ID, for quoting.
    fn stored_message_for_quote(&self, reference: Option<&str>) -> Result<Option<MessageRow>> {
        let Some(raw) = reference.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        let store = self.store();
        match raw.parse::<i64>() {
            Ok(id) => Ok(Some(store.message(id)?)),
            Err(_) => {
                Ok(store
                    .message_by_message_id(raw.trim_start_matches('<').trim_end_matches('>'))?)
            }
        }
    }

    /// Compose (quote + signature) and hand over to the raw pipeline.
    pub(crate) async fn send_composed(
        &self,
        account_email: &str,
        mut draft: Draft,
        opts: ComposeOptions,
        extras: SendExtras,
    ) -> Result<SendReport> {
        let c = self.compose_draft(account_email, &mut draft, &opts, true)?;
        self.send_inner(&c.account_email, draft, extras).await
    }

    /// What [`Engine::send_with`] would send for `draft` + `opts`: the final text and HTML
    /// bodies after quoting and the signature, without sending anything. Fails exactly
    /// where `send_with` would fail before contacting the network (unknown account, a reply
    /// to quote or a forward that is not stored locally).
    pub fn compose_preview(
        &self,
        account_email: &str,
        mut draft: Draft,
        opts: ComposeOptions,
    ) -> Result<ComposePreview> {
        let c = self.compose_draft(account_email, &mut draft, &opts, false)?;
        Ok(ComposePreview {
            kind: c.kind,
            text: draft.text,
            html: draft.html,
            signature_applied: c.signature_applied,
            forwarded_attachments: c.forwarded_attachments,
        })
    }

    /// The signature block [`Engine::send_with`] would append to a message of `kind` from
    /// `account_email`, or `None` when the signature is disabled, empty or does not apply
    /// to that kind (`include_on`).
    pub fn signature_preview(
        &self,
        account_email: &str,
        kind: ComposeKind,
    ) -> Result<Option<SignaturePreview>> {
        let acct = self.account_row(account_email)?;
        let s = self.get_signature(&acct.email)?;
        if !(s.enabled && !s.is_empty() && signature_applies(s.include_on, kind)) {
            return Ok(None);
        }
        let text = if s.text.trim().is_empty() {
            String::new()
        } else {
            signature_block_text(&s.text)
        };
        let html = s
            .html
            .as_deref()
            .map(sanitize_html)
            .filter(|h| !h.trim().is_empty())
            .map(|h| signature_block_html(&h));
        Ok(Some(SignaturePreview {
            text,
            html,
            placement: s.placement,
        }))
    }

    /// Apply quoting and the signature to `draft` in place. With `with_attachments` the
    /// forwarded message's attachments are loaded into the draft (sending); without, only
    /// their names are reported (preview).
    pub(crate) fn compose_draft(
        &self,
        account_email: &str,
        draft: &mut Draft,
        opts: &ComposeOptions,
        with_attachments: bool,
    ) -> Result<Composition> {
        let acct = self.account_row(account_email)?;
        let kind = match opts.kind {
            ComposeKind::New if draft.in_reply_to.is_some() => ComposeKind::Reply,
            k => k,
        };
        let mut forwarded_attachments: Vec<String> = Vec::new();
        let quoted: Option<Quoted> = match kind {
            ComposeKind::Reply if opts.quote => {
                let row = self
                    .stored_message_for_quote(draft.in_reply_to.as_deref())?
                    .ok_or_else(|| {
                        Error::InvalidInput(
                            "cannot quote: the replied-to message is not stored locally".into(),
                        )
                    })?;
                Some(quoted_reply(&row))
            }
            ComposeKind::Forward => {
                let row = self
                    .stored_message_for_quote(opts.forward_of.as_deref())?
                    .ok_or_else(|| {
                        Error::InvalidInput(
                            "forward: `forward_of` must name a stored message (local id or Message-ID)"
                                .into(),
                        )
                    })?;
                // Carry the original attachments along.
                let id = row.summary.id;
                let infos = self.store().attachments(id)?;
                for info in infos {
                    forwarded_attachments.push(info.filename.clone());
                    if with_attachments {
                        let (meta, data) = self.store().attachment(id, info.index)?;
                        draft.attachments.push(AttachmentData {
                            filename: meta.filename,
                            content_type: meta.content_type,
                            data,
                        });
                    }
                }
                Some(quoted_forward(&row))
            }
            _ => None,
        };
        let signature = if opts.skip_signature {
            None
        } else {
            let s = self.get_signature(&acct.email)?;
            (s.enabled && !s.is_empty() && signature_applies(s.include_on, kind)).then_some(s)
        };
        let signature_applied = signature.is_some();
        let composed = compose(
            &draft.text,
            draft.html.as_deref(),
            quoted.as_ref(),
            signature.as_ref(),
        );
        draft.text = composed.text;
        draft.html = composed.html;
        Ok(Composition {
            kind,
            account_email: acct.email,
            signature_applied,
            forwarded_attachments,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(text: &str, html: Option<&str>, placement: SignaturePlacement) -> SignatureSettings {
        SignatureSettings {
            enabled: true,
            text: text.into(),
            html: html.map(str::to_string),
            placement,
            include_on: SignatureIncludeOn::All,
        }
    }

    #[test]
    fn sanitiser_drops_scripts_styles_events_and_remote_images() {
        let dirty = "<div onclick=\"x()\" style=\"color:red\">Hi <b>there</b>\
                     <script>alert(1)</script><style>b{color:red}</style>\
                     <img src=\"http://evil.example/track.gif\" width=1 height=1>\
                     <img src=\"cid:logo\" alt=\"Logo\" width=\"80\" height=\"x\">\
                     <IMG SRC='data:image/png;base64,AAAA'>\
                     <img src=\"data:text/html,oops\">\
                     <a href=\"javascript:alert(1)\">bad</a> \
                     <a href=\"HTTPS://example.org/?a=1&b=2\" target=_blank title='t'>ok</a> \
                     <a href=\"mailto:a@b.c\">m</a>\
                     <!-- comment --><?xml foo?><!DOCTYPE html>\
                     <table><tr><td>cell</td></tr></table><iframe src=x>frame</iframe>\
                     <p>1 &lt; 2 and 3 < 4</p><u>u</u><em>e</em><strong>s</strong></div>";
        let clean = sanitize_html(dirty);
        assert!(!clean.contains("<script"), "{clean}");
        assert!(!clean.contains("alert"), "{clean}");
        assert!(!clean.contains("<style"), "{clean}");
        assert!(!clean.contains("color:red"), "{clean}");
        assert!(!clean.contains("onclick"), "{clean}");
        assert!(!clean.contains("evil.example"), "{clean}");
        assert!(!clean.contains("track.gif"), "{clean}");
        assert!(!clean.contains("javascript:"), "{clean}");
        assert!(!clean.contains("data:text/html"), "{clean}");
        assert!(!clean.contains("target="), "{clean}");
        assert!(!clean.contains("comment"), "{clean}");
        assert!(!clean.contains("xml"), "{clean}");
        assert!(!clean.contains("DOCTYPE"), "{clean}");
        assert!(!clean.contains("<table"), "{clean}");
        assert!(!clean.contains("<iframe"), "{clean}");
        assert!(!clean.contains("frame"), "{clean}");
        assert!(clean.contains("cell"), "{clean}");
        assert!(
            clean.contains("<img src=\"cid:logo\" alt=\"Logo\" width=\"80\">"),
            "{clean}"
        );
        assert!(
            clean.contains("<img src=\"data:image/png;base64,AAAA\">"),
            "{clean}"
        );
        assert!(
            clean.contains("<a href=\"HTTPS://example.org/?a=1&b=2\" title=\"t\">ok</a>"),
            "{clean}"
        );
        assert!(clean.contains("<a href=\"mailto:a@b.c\">m</a>"), "{clean}");
        assert!(clean.contains("<a>bad</a>"), "{clean}");
        assert!(clean.contains("<p>1 &lt; 2 and 3 &lt; 4</p>"), "{clean}");
        assert!(clean.starts_with("<div>Hi <b>there</b>"), "{clean}");
        assert!(
            clean.ends_with("<u>u</u><em>e</em><strong>s</strong></div>"),
            "{clean}"
        );
        // idempotent
        assert_eq!(sanitize_html(&clean), clean);
    }

    #[test]
    fn sanitiser_closes_unbalanced_tags_and_handles_tricks() {
        assert_eq!(sanitize_html("<b>bold <i>both"), "<b>bold <i>both</i></b>");
        assert_eq!(sanitize_html("<b>x</i></b>"), "<b>x</b>");
        assert_eq!(sanitize_html("a</b>b"), "ab");
        assert_eq!(sanitize_html("<br/><br />"), "<br><br>");
        assert_eq!(sanitize_html("<p>unterminated <b"), "<p>unterminated </p>");
        assert_eq!(
            sanitize_html("<a href=\"java\tscript:alert(1)\">x</a>"),
            "<a>x</a>"
        );
        assert_eq!(
            sanitize_html("<a href=\"http://x/\" href=\"javascript:y\">x</a>"),
            "<a href=\"http://x/\">x</a>"
        );
        assert_eq!(
            sanitize_html("<a href=\"http://x/\">x</a><script>never</script><script>"),
            "<a href=\"http://x/\">x</a>"
        );
        assert_eq!(
            sanitize_html("<a href=http://q/\"onclick=x>y</a>"),
            "<a href=\"http://q/&quot;onclick=x\">y</a>"
        );
        assert_eq!(sanitize_html("plain text & more"), "plain text & more");
        assert_eq!(sanitize_html(""), "");
        assert_eq!(sanitize_html("<svg><script>1</script></svg>after"), "after");
        assert_eq!(sanitize_html("<p>é ü 日本</p>"), "<p>é ü 日本</p>");
    }

    #[test]
    fn text_composition_placement_and_separator() {
        // New mail: body, blank line, "-- ", signature.
        assert_eq!(
            compose_text(
                "Hello",
                None,
                Some("Alice\nCorp"),
                SignaturePlacement::AboveQuote
            ),
            "Hello\n\n-- \nAlice\nCorp\n"
        );
        // Body ending with newlines gets exactly one blank line.
        assert_eq!(
            compose_text(
                "Hello\n\n\n",
                None,
                Some("A"),
                SignaturePlacement::AboveQuote
            ),
            "Hello\n\n\n-- \nA\n"
        );
        assert_eq!(
            compose_text("Hello\n", None, Some("A"), SignaturePlacement::AboveQuote),
            "Hello\n\n-- \nA\n"
        );
        let quote = "On Tue, 27 Oct 2026 06:00:00 +0000, Bob <bob@x> wrote:\n> hi\n";
        let above = compose_text(
            "Thanks",
            Some(quote),
            Some("A"),
            SignaturePlacement::AboveQuote,
        );
        assert_eq!(above, format!("Thanks\n\n-- \nA\n\n{quote}"));
        let below = compose_text(
            "Thanks",
            Some(quote),
            Some("A"),
            SignaturePlacement::BelowQuote,
        );
        assert_eq!(below, format!("Thanks\n\n{quote}\n-- \nA\n"));
        // No signature: just the quote.
        assert_eq!(
            compose_text("Thanks", Some(quote), None, SignaturePlacement::AboveQuote),
            format!("Thanks\n\n{quote}")
        );
        // Nothing at all.
        assert_eq!(
            compose_text(
                "Just text\r\nCRLF",
                None,
                None,
                SignaturePlacement::AboveQuote
            ),
            "Just text\nCRLF"
        );
        // Empty body with a signature.
        assert_eq!(
            compose_text("", None, Some("A"), SignaturePlacement::AboveQuote),
            "-- \nA\n"
        );
    }

    #[test]
    fn full_composition_creates_html_only_when_needed() {
        let text_only = compose(
            "Hi",
            None,
            None,
            Some(&sig("A", None, SignaturePlacement::AboveQuote)),
        );
        assert_eq!(text_only.text, "Hi\n\n-- \nA\n");
        assert_eq!(text_only.html, None);

        let with_html_sig = compose(
            "Hi <you>",
            None,
            None,
            Some(&sig(
                "A",
                Some("<b>A</b><script>x</script><img src=\"http://r/\">"),
                SignaturePlacement::AboveQuote,
            )),
        );
        assert_eq!(with_html_sig.text, "Hi <you>\n\n-- \nA\n");
        let html = with_html_sig.html.unwrap();
        assert!(
            html.starts_with("<div class=\"sealbox-body\">Hi &lt;you&gt;</div>"),
            "{html}"
        );
        assert!(
            html.contains("<div class=\"sealbox-signature\">-- <br>\n<b>A</b></div>"),
            "{html}"
        );
        assert!(
            !html.contains("script") && !html.contains("http://r/"),
            "{html}"
        );

        // HTML draft + text-only signature: the HTML alternative mirrors the text signature.
        let html_draft = compose(
            "Hi",
            Some("<p>Hi</p>"),
            None,
            Some(&sig("A & B", None, SignaturePlacement::AboveQuote)),
        );
        assert_eq!(
            html_draft.html.as_deref(),
            Some("<p>Hi</p>\n<div class=\"sealbox-signature\">-- <br>\nA &amp; B</div>")
        );

        // Reply with quote, below placement, HTML present.
        let q = Quoted {
            text: "On d, f wrote:\n> q\n".into(),
            html: "<blockquote type=\"cite\">q</blockquote>".into(),
        };
        let reply = compose(
            "Re",
            Some("<p>Re</p>"),
            Some(&q),
            Some(&sig("A", Some("<i>A</i>"), SignaturePlacement::BelowQuote)),
        );
        assert_eq!(reply.text, "Re\n\nOn d, f wrote:\n> q\n\n-- \nA\n");
        assert_eq!(
            reply.html.as_deref(),
            Some("<p>Re</p>\n<blockquote type=\"cite\">q</blockquote>\n<div class=\"sealbox-signature\">-- <br>\n<i>A</i></div>")
        );

        // Disabled / empty signatures are not applied by the caller; `None` here.
        let none = compose("x", None, Some(&q), None);
        assert_eq!(none.text, "x\n\nOn d, f wrote:\n> q\n");
        assert_eq!(none.html, None);
    }

    #[test]
    fn quoting_formats() {
        let from = Address {
            name: Some("Bob".into()),
            address: "bob@example.org".into(),
        };
        let q = quote_reply(Some(1_793_075_241), &from, "line one\r\n\r\n> old\nlast");
        assert_eq!(
            q,
            "On Tue, 27 Oct 2026 04:27:21 +0000, Bob <bob@example.org> wrote:\n> line one\n>\n>> old\n> last\n"
        );
        assert!(quote_reply(None, &from, "x")
            .starts_with("On an unknown date, Bob <bob@example.org> wrote:\n> x\n"));
        let fwd = quote_forward(
            &ForwardHeaders {
                subject: Some("Sub".into()),
                date: Some(1_793_075_241),
                from: from.clone(),
                to: vec![Address {
                    name: None,
                    address: "alice@example.org".into(),
                }],
                cc: vec![],
            },
            "body\n",
        );
        assert_eq!(
            fwd,
            "-------- Forwarded Message --------\nSubject: Sub\nDate: Tue, 27 Oct 2026 04:27:21 +0000\nFrom: Bob <bob@example.org>\nTo: alice@example.org\n\nbody\n"
        );
        assert_eq!(
            html_to_text_lossy("<p>a &amp; b</p><div>c<br>d</div>"),
            "a & b\nc\nd\n"
        );
    }

    #[test]
    fn include_on_rules() {
        use ComposeKind::*;
        use SignatureIncludeOn::*;
        assert!(signature_applies(NewOnly, New));
        assert!(!signature_applies(NewOnly, Reply));
        assert!(!signature_applies(NewOnly, Forward));
        assert!(signature_applies(NewAndReplies, New));
        assert!(signature_applies(NewAndReplies, Reply));
        assert!(!signature_applies(NewAndReplies, Forward));
        assert!(signature_applies(All, Forward));
        let opts: ComposeOptions =
            serde_json::from_str("{\"kind\":\"reply\",\"quote\":true}").unwrap();
        assert_eq!(opts.kind, Reply);
        assert!(opts.quote && !opts.skip_signature && opts.forward_of.is_none());
    }
}
