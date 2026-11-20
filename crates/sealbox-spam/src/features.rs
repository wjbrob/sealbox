//! Feature extraction: raw RFC 5322 bytes → [`Features`] (tokens for the Bayes model plus
//! the structural attributes the rules look at).
//!
//! Header hygiene: `Received`, `Return-Path`, `Delivered-To`, `To`/`Cc`, mailbox-state headers
//! (`Status`, `X-Keywords`, `X-UID` …) and the output of *other* spam filters (`X-Spam-*`,
//! `X-Razor*`, `X-Bogosity` …) are never tokenised. The first group is either constant for a
//! user or an artefact of how a corpus was collected; the second would let a forged
//! `X-Spam-Status: No` whitelist a message (and would be cheating in the evaluation).

use std::net::IpAddr;

use mail_parser::{HeaderName, HeaderValue, Host, Message, MessageParser, MimeHeaders};

pub use crate::util::HtmlTricks;
use crate::util::{
    address_domain, extract_ipv4s, extract_urls, html_to_text, is_public_ip, registrable_domain,
    tld, tokenize, unfold, url_host,
};

/// Result of one authentication method in `Authentication-Results`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    /// temperror / permerror / policy / unknown.
    Other,
}

impl AuthResult {
    fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "pass" => AuthResult::Pass,
            "fail" | "hardfail" => AuthResult::Fail,
            "softfail" => AuthResult::SoftFail,
            "neutral" => AuthResult::Neutral,
            "none" => AuthResult::None,
            _ => AuthResult::Other,
        }
    }

    fn token(self) -> &'static str {
        match self {
            AuthResult::Pass => "pass",
            AuthResult::Fail => "fail",
            AuthResult::SoftFail => "softfail",
            AuthResult::Neutral => "neutral",
            AuthResult::None => "none",
            AuthResult::Other => "other",
        }
    }
}

/// Parsed `Authentication-Results` (the top-most header, i.e. the user's own provider).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthResults {
    /// An `Authentication-Results` header was present at all.
    pub present: bool,
    pub spf: Option<AuthResult>,
    pub dkim: Option<AuthResult>,
    pub dmarc: Option<AuthResult>,
}

impl AuthResults {
    fn parse(value: &str) -> Self {
        let mut out = AuthResults {
            present: true,
            ..Default::default()
        };
        // authserv-id; method=result comment...; method=result ...
        for seg in value.split(';').skip(1) {
            let seg = seg.trim();
            let Some((method, rest)) = seg.split_once('=') else {
                continue;
            };
            let result = rest
                .split(|c: char| c.is_whitespace() || c == '(')
                .next()
                .unwrap_or("");
            let r = AuthResult::parse(result);
            match method.trim().to_ascii_lowercase().as_str() {
                "spf" => out.spf.get_or_insert(r),
                "dkim" => out.dkim.get_or_insert(r),
                "dmarc" => out.dmarc.get_or_insert(r),
                _ => continue,
            };
        }
        out
    }

    /// Any of the three methods failed.
    pub fn any_fail(&self) -> bool {
        [self.spf, self.dkim, self.dmarc]
            .iter()
            .any(|r| matches!(r, Some(AuthResult::Fail)))
    }

    /// Any of the three methods passed.
    pub fn any_pass(&self) -> bool {
        [self.spf, self.dkim, self.dmarc]
            .iter()
            .any(|r| matches!(r, Some(AuthResult::Pass)))
    }
}

/// One URL found in the body.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UrlInfo {
    pub url: String,
    pub host: String,
    /// Registrable domain (`example.co.uk`), or the IP literal.
    pub domain: String,
    pub tld: Option<String>,
    pub raw_ip: bool,
    /// Path or query mentions login/verify/account/secure/update/password.
    pub credential_path: bool,
}

/// One attachment.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttachmentMeta {
    pub filename: String,
    pub content_type: String,
    /// Lower-cased final extension without the dot.
    pub extension: String,
    /// `invoice.pdf.exe`-style name.
    pub double_extension: bool,
    pub size: usize,
}

/// Everything the classifier and the filter engine look at.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Features {
    /// Tokens for the Bayes model (lower-cased words, prefixed structural tokens).
    pub tokens: Vec<String>,
    pub from_address: Option<String>,
    pub from_name: Option<String>,
    pub from_domain: Option<String>,
    pub reply_to_address: Option<String>,
    pub reply_to_domain: Option<String>,
    pub sender_address: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub message_id: Option<String>,
    pub date: Option<i64>,
    pub list_id: Option<String>,
    pub precedence: Option<String>,
    pub auto_submitted: Option<String>,
    /// All headers as `(name, unfolded value)` in order.
    pub headers: Vec<(String, String)>,
    /// Decoded text body (the HTML stripped to text when there is no text part).
    pub text: String,
    pub has_text: bool,
    pub has_html: bool,
    pub html_only: bool,
    pub html_tricks: HtmlTricks,
    pub urls: Vec<UrlInfo>,
    pub attachments: Vec<AttachmentMeta>,
    /// Number of `Received` headers.
    pub received_depth: usize,
    /// Public relay IPs from the `Received` chain, most recent first.
    pub received_ips: Vec<IpAddr>,
    /// The first public IP seen from the top: the last relay outside the recipient's provider.
    pub last_external_ip: Option<IpAddr>,
    pub auth: AuthResults,
    /// Upper-case share of the letters in subject + body start.
    pub caps_ratio: f32,
    pub exclamations: u32,
    pub money_mentions: u32,
    /// `From:` address is an IP literal.
    pub from_raw_ip: bool,
    pub raw_size: usize,
}

const MAX_BODY_TOKENS: usize = 4000;
const MAX_BODY_BIGRAMS: usize = 1000;

/// Headers whose values never become tokens (see the module docs).
fn header_is_excluded(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("x-spam")
        || n.starts_with("x-razor")
        || n.starts_with("x-pyzor")
        || n.starts_with("x-dspam")
        || n.starts_with("x-bogosity")
        || n.starts_with("x-virus")
        || n.starts_with("x-sa-")
        || n.starts_with("arc-")
        || n.starts_with("x-google")
        || n.starts_with("x-ms-")
        || n.starts_with("x-microsoft")
        || n.starts_with("x-uid")
        || matches!(
            n.as_str(),
            "received"
                | "return-path"
                | "delivered-to"
                | "envelope-to"
                | "x-original-to"
                | "to"
                | "cc"
                | "bcc"
                | "status"
                | "x-status"
                | "x-keywords"
                | "lines"
                | "message-id"
                | "resent-message-id"
                | "date"
                | "in-reply-to"
                | "references"
                | "dkim-signature"
                | "domainkey-signature"
                | "authentication-results"
                | "received-spf"
                | "subject"
                | "from"
                | "reply-to"
                | "autocrypt"
                | "autocrypt-gossip"
        )
}

/// Attachment extensions that run code when opened.
pub const DANGEROUS_EXTENSIONS: &[&str] = &[
    "exe",
    "js",
    "jse",
    "scr",
    "vbs",
    "vbe",
    "iso",
    "img",
    "lnk",
    "bat",
    "cmd",
    "com",
    "pif",
    "hta",
    "jar",
    "ps1",
    "psm1",
    "msi",
    "msp",
    "wsf",
    "wsh",
    "cpl",
    "reg",
    "dll",
    "chm",
    "application",
    "gadget",
    "inf",
    "scf",
    "url",
    "vb",
    "ws",
    "sct",
    "shb",
    "sys",
    "drv",
    "ace",
    "docm",
    "xlsm",
    "pptm",
    "dotm",
];

fn extension_of(name: &str) -> (String, bool) {
    let lower = name.trim().to_ascii_lowercase();
    let parts: Vec<&str> = lower.rsplit('.').collect();
    if parts.len() < 2 {
        return (String::new(), false);
    }
    let ext = parts[0].to_string();
    let short =
        |p: &str| (1..=5).contains(&p.len()) && p.chars().all(|c| c.is_ascii_alphanumeric());
    let double = parts.len() >= 3
        && short(parts[0])
        && short(parts[1])
        && !parts[1].chars().all(|c| c.is_ascii_digit());
    (ext, double)
}

fn addr_list(a: Option<&mail_parser::Address<'_>>) -> Vec<String> {
    a.map(|a| {
        a.iter()
            .filter_map(|x| x.address().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

fn credential_path(url: &str) -> bool {
    let l = url.to_ascii_lowercase();
    let path = l.split_once("://").map(|x| x.1).unwrap_or(&l);
    let path = path.split_once('/').map(|(_, p)| p).unwrap_or("");
    [
        "login", "signin", "sign-in", "verify", "account", "secure", "update", "password",
        "confirm", "auth", "webscr", "wallet",
    ]
    .iter()
    .any(|k| path.contains(k))
}

/// Parse `raw` and extract everything. `Err` only when mail-parser cannot read the bytes
/// at all (truly empty input); malformed messages still yield features.
pub fn extract(raw: &[u8]) -> crate::Result<Features> {
    let raw = strip_mbox_from(raw);
    let msg = MessageParser::default()
        .parse(raw)
        .ok_or(crate::Error::Unparseable)?;
    Ok(from_message(&msg, raw.len()))
}

/// Drop a leading mbox `From sender date` separator line.
fn strip_mbox_from(raw: &[u8]) -> &[u8] {
    if raw.starts_with(b"From ") {
        if let Some(nl) = raw.iter().position(|b| *b == b'\n') {
            return &raw[nl + 1..];
        }
    }
    raw
}

fn from_message(msg: &Message<'_>, raw_size: usize) -> Features {
    let mut f = Features {
        raw_size,
        ..Default::default()
    };
    let mut tokens: Vec<String> = Vec::new();

    // ---- envelope headers -----------------------------------------------------------------
    let from = msg.from().and_then(|a| a.first().cloned());
    f.from_address = from
        .as_ref()
        .and_then(|a| a.address().map(|s| s.trim().to_string()));
    f.from_name = from
        .as_ref()
        .and_then(|a| a.name().map(unfold))
        .filter(|n| !n.is_empty());
    f.from_domain = f.from_address.as_deref().and_then(address_domain);
    f.from_raw_ip = f
        .from_domain
        .as_deref()
        .map(|d| d.trim_matches(['[', ']']).parse::<IpAddr>().is_ok())
        .unwrap_or(false);
    f.reply_to_address = msg
        .reply_to()
        .and_then(|a| a.first())
        .and_then(|a| a.address().map(|s| s.trim().to_string()));
    f.reply_to_domain = f.reply_to_address.as_deref().and_then(address_domain);
    f.sender_address = msg
        .sender()
        .and_then(|a| a.first())
        .and_then(|a| a.address().map(|s| s.trim().to_string()));
    f.to = addr_list(msg.to());
    f.cc = addr_list(msg.cc());
    f.subject = msg.subject().map(unfold).unwrap_or_default();
    f.message_id = msg
        .message_id()
        .map(|m| m.trim_matches(['<', '>']).to_string());
    f.date = msg.date().map(|d| d.to_timestamp());
    f.list_id = header_text(msg, "List-Id");
    f.precedence = header_text(msg, "Precedence").map(|p| p.to_ascii_lowercase());
    f.auto_submitted = header_text(msg, "Auto-Submitted").map(|p| p.to_ascii_lowercase());

    // ---- all headers (filters, explain) + header tokens ---------------------------------------
    let mut received_count = 0usize;
    let mut auth_seen = false;
    for (name, raw) in msg.headers_raw() {
        let value = unfold(raw);
        let lname = name.to_ascii_lowercase();
        f.headers.push((name.to_string(), value.clone()));
        match lname.as_str() {
            "received" => received_count += 1,
            "authentication-results" if !auth_seen => {
                auth_seen = true;
                f.auth = AuthResults::parse(&value);
            }
            _ => {}
        }
        if header_is_excluded(name) {
            continue;
        }
        // The first word of the value is the signal (mailer, priority, content type, list
        // address …); a bare presence token when there is none. Measured on the corpus: this
        // beats "presence token for every header" and "values only for categorical headers".
        let first = value
            .split(|c: char| c.is_whitespace() || c == ';' || c == ',')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if !first.is_empty() && first.chars().count() <= 40 {
            tokens.push(format!("H:{lname}:{first}"));
        } else {
            tokens.push(format!("H:{lname}"));
        }
        if lname == "content-type" {
            if let Some(cs) = value.to_ascii_lowercase().split(';').find_map(|p| {
                p.trim()
                    .strip_prefix("charset=")
                    .map(|c| c.trim_matches('"').to_string())
            }) {
                tokens.push(format!("H:charset:{cs}"));
            }
        }
    }
    f.received_depth = received_count;

    // ---- Received chain (top = most recent hop) -----------------------------------------------
    let structured: Vec<Option<IpAddr>> = msg
        .header_values(HeaderName::Received)
        .map(|hv| match hv {
            HeaderValue::Received(r) => r.from_ip.or(match &r.from {
                Some(Host::IpAddr(ip)) => Some(*ip),
                _ => None,
            }),
            _ => None,
        })
        .collect();
    let raw_received: Vec<&str> = f
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("received"))
        .map(|(_, v)| v.as_str())
        .collect();
    for (i, v) in raw_received.iter().enumerate() {
        // The structured `from` IP first, then every literal in the line (the `from` host
        // comes before the `by` host, so the first public one is the sending relay).
        let mut ips: Vec<IpAddr> = extract_ipv4s(v).into_iter().map(IpAddr::V4).collect();
        if let Some(Some(ip)) = structured.get(i) {
            ips.insert(0, *ip);
        }
        if let Some(ip) = ips.into_iter().find(|ip| is_public_ip(*ip)) {
            f.received_ips.push(ip);
        }
    }
    f.last_external_ip = f.received_ips.first().copied();

    // ---- bodies -----------------------------------------------------------------------------
    let text = msg.body_text(0).map(|t| t.into_owned());
    let html = msg.body_html(0).map(|t| t.into_owned());
    // mail-parser synthesises an HTML view from text (and vice versa); only count real parts.
    let real_text = msg.text_bodies().any(|p| p.is_text() && !p.is_text_html());
    let real_html = msg.html_bodies().any(|p| p.is_text_html());
    f.has_text = real_text && text.as_deref().is_some_and(|t| !t.trim().is_empty());
    f.has_html = real_html && html.as_deref().is_some_and(|h| !h.trim().is_empty());
    f.html_only = f.has_html && !f.has_text;
    let (html_text, tricks) = match &html {
        Some(h) if f.has_html => html_to_text(h),
        _ => (String::new(), HtmlTricks::default()),
    };
    f.html_tricks = tricks;
    f.text = if f.has_text {
        text.clone().unwrap_or_default()
    } else {
        html_text.clone()
    };

    // ---- URLs -------------------------------------------------------------------------------
    let mut url_sources = String::new();
    url_sources.push_str(&f.text);
    url_sources.push(' ');
    if let Some(h) = &html {
        if f.has_html {
            url_sources.push_str(h);
        }
    }
    let mut seen_urls = std::collections::BTreeSet::new();
    for url in extract_urls(&url_sources) {
        let Some(host) = url_host(&url) else { continue };
        if !seen_urls.insert(url.clone()) {
            continue;
        }
        let raw_ip = host.parse::<IpAddr>().is_ok();
        f.urls.push(UrlInfo {
            domain: registrable_domain(&host),
            tld: tld(&host),
            raw_ip,
            credential_path: credential_path(&url),
            url,
            host,
        });
        if f.urls.len() >= 64 {
            break;
        }
    }

    // ---- attachments ------------------------------------------------------------------------
    for part in msg.attachments() {
        if part.is_message() {
            continue;
        }
        let filename = part
            .attachment_name()
            .map(|n| n.trim().to_string())
            .unwrap_or_default();
        let content_type = part
            .content_type()
            .map(|ct| match ct.subtype() {
                Some(s) => format!(
                    "{}/{}",
                    ct.ctype().to_ascii_lowercase(),
                    s.to_ascii_lowercase()
                ),
                None => ct.ctype().to_ascii_lowercase(),
            })
            .unwrap_or_else(|| "application/octet-stream".into());
        if filename.is_empty() && content_type.starts_with("text/") {
            continue; // inline text alternative mis-detected as an attachment
        }
        let (extension, double_extension) = extension_of(&filename);
        f.attachments.push(AttachmentMeta {
            filename,
            content_type,
            extension,
            double_extension,
            size: part.contents().len(),
        });
    }

    // ---- shouting / punctuation / money ---------------------------------------------------
    let sample: String = f
        .subject
        .chars()
        .chain(std::iter::once(' '))
        .chain(f.text.chars().take(2000))
        .collect();
    let letters = sample.chars().filter(|c| c.is_alphabetic()).count();
    let upper = sample.chars().filter(|c| c.is_uppercase()).count();
    f.caps_ratio = if letters >= 20 {
        upper as f32 / letters as f32
    } else {
        0.0
    };
    f.exclamations = sample.chars().filter(|c| *c == '!').count() as u32;
    f.money_mentions = count_money(&sample);

    // ---- tokens -------------------------------------------------------------------------------
    let subject_words = tokenize(&f.subject);
    for w in &subject_words {
        tokens.push(format!("S:{w}"));
    }
    for pair in subject_words.windows(2) {
        tokens.push(format!("S2:{}_{}", pair[0], pair[1]));
    }
    let body_words = tokenize(&f.text);
    for w in body_words.iter().take(MAX_BODY_TOKENS) {
        tokens.push(w.clone());
    }
    for pair in body_words.windows(2).take(MAX_BODY_BIGRAMS) {
        tokens.push(format!("B2:{}_{}", pair[0], pair[1]));
    }
    if let Some(d) = &f.from_domain {
        tokens.push(format!("FD:{}", registrable_domain(d)));
        if let Some(t) = tld(d) {
            tokens.push(format!("FT:{t}"));
        }
    }
    if let Some(n) = &f.from_name {
        for w in tokenize(n) {
            tokens.push(format!("FN:{w}"));
        }
    }
    if let Some(d) = &f.reply_to_domain {
        tokens.push(format!("RD:{}", registrable_domain(d)));
    }
    for u in &f.urls {
        tokens.push(format!("U:{}", u.domain));
        if let Some(t) = &u.tld {
            tokens.push(format!("UT:{t}"));
        }
    }
    for a in &f.attachments {
        if !a.extension.is_empty() {
            tokens.push(format!("AE:{}", a.extension));
        }
        tokens.push(format!("AC:{}", a.content_type));
    }
    let mut attr = |name: &str| tokens.push(format!("A:{name}"));
    if f.html_only {
        attr("html_only");
    }
    if f.has_html {
        attr("has_html");
    }
    if f.html_tricks.hidden_text {
        attr("hidden_text");
    }
    if f.html_tricks.tiny_font {
        attr("tiny_font");
    }
    if f.html_tricks.comment_obfuscation >= 2 {
        attr("comment_obfuscation");
    }
    if f.html_tricks.image_only {
        attr("image_only");
    }
    if f.caps_ratio > 0.5 {
        attr("caps_high");
    }
    if f.exclamations >= 3 {
        attr("exclamations");
    }
    if f.money_mentions >= 2 {
        attr("money");
    }
    if f.message_id.is_none() {
        attr("no_message_id");
    }
    if f.date.is_none() {
        attr("no_date");
    }
    if f.urls.iter().any(|u| u.raw_ip) {
        attr("ip_url");
    }
    if f.urls.iter().any(|u| u.credential_path) {
        attr("credential_url");
    }
    if f.from_raw_ip {
        attr("ip_from");
    }
    if f.urls.len() >= 5 {
        attr("many_urls");
    }
    if f.subject.trim().is_empty() {
        attr("empty_subject");
    }
    if let (Some(fd), Some(rd)) = (&f.from_domain, &f.reply_to_domain) {
        if registrable_domain(fd) != registrable_domain(rd) {
            attr("replyto_mismatch");
        }
    }
    if f.list_id.is_some() {
        attr("list");
    }
    if f.headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("in-reply-to") || n.eq_ignore_ascii_case("references"))
    {
        attr("is_reply");
    }
    if matches!(
        f.precedence.as_deref(),
        Some("bulk") | Some("list") | Some("junk")
    ) {
        attr("bulk");
    }
    let bucket = match f.received_depth {
        0 => "0",
        1 => "1",
        2 => "2",
        3 => "3",
        4..=5 => "4-5",
        _ => "6+",
    };
    tokens.push(format!("A:received:{bucket}"));
    if f.auth.present {
        if let Some(r) = f.auth.spf {
            tokens.push(format!("A:spf:{}", r.token()));
        }
        if let Some(r) = f.auth.dkim {
            tokens.push(format!("A:dkim:{}", r.token()));
        }
        if let Some(r) = f.auth.dmarc {
            tokens.push(format!("A:dmarc:{}", r.token()));
        }
    }
    f.tokens = tokens;
    f
}

fn header_text(msg: &Message<'_>, name: &str) -> Option<String> {
    msg.header_raw(name).map(unfold).filter(|v| !v.is_empty())
}

fn count_money(s: &str) -> u32 {
    let mut n = 0u32;
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if matches!(c, '$' | '€' | '£') && chars.get(i + 1).is_some_and(|d| d.is_ascii_digit()) {
            n += 1;
        }
    }
    let lower = s.to_lowercase();
    for kw in ["usd", "dollars", "euros", "million", "billion"] {
        n += lower.matches(kw).count() as u32;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    const HAM: &str = "Received: from lugh.tuatha.org (root@lugh.tuatha.org [194.125.145.45]) by dogma.slashnull.org\r\n\
Received: from localhost (localhost [127.0.0.1]) by phobos\r\n\
Authentication-Results: mx.example.net; dkim=pass header.i=@example.org; spf=pass smtp.mailfrom=example.org; dmarc=pass (p=NONE) header.from=example.org\r\n\
From: Bob Example <bob@example.org>\r\n\
To: alice@example.org\r\n\
Subject: Lunch tomorrow?\r\n\
Date: Thu, 22 Aug 2002 06:18:18 -0600\r\n\
Message-ID: <abc@example.org>\r\n\
List-Id: Friends <friends.example.org>\r\n\
X-Mailer: Mutt 2.2\r\n\
X-Spam-Status: Yes, score=99\r\n\
Content-Type: text/plain; charset=\"utf-8\"\r\n\
\r\n\
Hi Alice, lunch at 12? See http://www.example.org/menu.\r\n";

    #[test]
    fn extracts_headers_bodies_urls_and_tokens() {
        let f = extract(HAM.as_bytes()).unwrap();
        assert_eq!(f.from_address.as_deref(), Some("bob@example.org"));
        assert_eq!(f.from_name.as_deref(), Some("Bob Example"));
        assert_eq!(f.from_domain.as_deref(), Some("example.org"));
        assert_eq!(f.subject, "Lunch tomorrow?");
        assert_eq!(f.message_id.as_deref(), Some("abc@example.org"));
        assert!(f.date.is_some());
        assert_eq!(f.list_id.as_deref(), Some("Friends <friends.example.org>"));
        assert_eq!(f.received_depth, 2);
        assert_eq!(f.received_ips.len(), 1);
        assert_eq!(f.last_external_ip, Some("194.125.145.45".parse().unwrap()));
        assert!(f.auth.present);
        assert_eq!(f.auth.dkim, Some(AuthResult::Pass));
        assert_eq!(f.auth.dmarc, Some(AuthResult::Pass));
        assert!(f.has_text && !f.has_html && !f.html_only);
        assert_eq!(f.urls.len(), 1);
        assert_eq!(f.urls[0].domain, "example.org");
        assert!(f.tokens.contains(&"S:lunch".to_string()));
        assert!(f.tokens.contains(&"S2:lunch_tomorrow".to_string()));
        assert!(f.tokens.contains(&"alice".to_string()));
        assert!(f.tokens.contains(&"FD:example.org".to_string()));
        assert!(f.tokens.contains(&"U:example.org".to_string()));
        assert!(f.tokens.contains(&"H:x-mailer:mutt".to_string()));
        assert!(f.tokens.contains(&"A:list".to_string()));
        assert!(f.tokens.contains(&"A:dkim:pass".to_string()));
        assert!(f.tokens.contains(&"H:charset:utf-8".to_string()));
        // Other filters' verdicts and recipient headers never become tokens.
        assert!(!f.tokens.iter().any(|t| t.starts_with("H:x-spam")));
        assert!(!f.tokens.iter().any(|t| t.starts_with("H:to")));
        assert!(!f.tokens.iter().any(|t| t.starts_with("H:received")));
    }

    #[test]
    fn html_only_with_tricks_and_attachment() {
        let raw = "From: \"PayPal Security\" <alerts@paypa1-secure.com>\r\n\
Reply-To: someone@other.example\r\n\
Subject: URGENT!!! Verify your account NOW\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<html><body><p>Please <a href=\"http://192.168.1.1/login/verify.php\">verify your account</a> or it will be suspended.</p>\
<span style=\"font-size:0px\">hidden</span><p>You have WON $1,000,000 USD!</p></body></html>\r\n\
--b\r\n\
Content-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r\n\
Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA\r\n\
--b--\r\n";
        let f = extract(raw.as_bytes()).unwrap();
        assert!(f.html_only, "{f:?}");
        assert!(f.html_tricks.tiny_font);
        assert!(f.text.contains("verify your account"));
        assert_eq!(f.urls.len(), 1);
        assert!(f.urls[0].raw_ip);
        assert!(f.urls[0].credential_path);
        assert_eq!(f.attachments.len(), 1);
        assert_eq!(f.attachments[0].extension, "exe");
        assert!(f.attachments[0].double_extension);
        assert!(f.message_id.is_none() && f.date.is_none());
        assert_eq!(f.reply_to_domain.as_deref(), Some("other.example"));
        assert!(f.exclamations >= 3);
        assert!(f.money_mentions >= 2);
        assert!(f.tokens.contains(&"A:html_only".to_string()));
        assert!(f.tokens.contains(&"A:ip_url".to_string()));
        assert!(f.tokens.contains(&"A:no_message_id".to_string()));
        assert!(f.tokens.contains(&"A:replyto_mismatch".to_string()));
        assert!(f.tokens.contains(&"AE:exe".to_string()));
        assert!(f.tokens.contains(&"FN:paypal".to_string()));
    }

    #[test]
    fn mbox_from_line_is_skipped_and_empty_fails() {
        let raw = format!("From bob@example.org Thu Aug 22 13:27:39 2002\n{HAM}");
        let f = extract(raw.as_bytes()).unwrap();
        assert_eq!(f.from_address.as_deref(), Some("bob@example.org"));
        assert!(extract(b"").is_err());
    }

    #[test]
    fn extension_detection() {
        assert_eq!(extension_of("a.exe"), ("exe".into(), false));
        assert_eq!(extension_of("invoice.pdf.exe"), ("exe".into(), true));
        assert_eq!(extension_of("archive.tar.gz"), ("gz".into(), true));
        assert_eq!(extension_of("photo.2024.jpg"), ("jpg".into(), false));
        assert_eq!(extension_of("README"), (String::new(), false));
    }

    #[test]
    fn auth_results_parsing() {
        let a = AuthResults::parse(
            "mx.google.com; dkim=fail (signature error) header.i=@x.com; spf=softfail (google.com: ...) smtp.mailfrom=x.com; dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=x.com",
        );
        assert_eq!(a.dkim, Some(AuthResult::Fail));
        assert_eq!(a.spf, Some(AuthResult::SoftFail));
        assert_eq!(a.dmarc, Some(AuthResult::Fail));
        assert!(a.any_fail() && !a.any_pass());
    }
}
