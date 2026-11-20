use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::MimeError;

/// An RFC 5322 mailbox: optional display name plus addr-spec.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
pub struct Mailbox {
    pub name: Option<String>,
    pub address: String,
}

impl Mailbox {
    /// A bare address without display name.
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            name: None,
            address: address.into(),
        }
    }

    /// `name <address>`.
    pub fn named(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            address: address.into(),
        }
    }

    /// Parse `Name <a@b>`, `"Name" <a@b>`, `<a@b>` or `a@b`.
    pub fn parse(s: &str) -> Result<Self, MimeError> {
        let s = s.trim();
        let invalid = || MimeError::InvalidAddress(s.to_owned());
        if let Some(open) = s.rfind('<') {
            let close = s[open..].find('>').map(|c| open + c).ok_or_else(invalid)?;
            let address = s[open + 1..close].trim();
            if !is_addr_spec(address) {
                return Err(invalid());
            }
            let name = s[..open].trim().trim_matches('"').trim();
            Ok(Self {
                name: (!name.is_empty()).then(|| name.to_owned()),
                address: address.to_owned(),
            })
        } else if is_addr_spec(s) {
            Ok(Self::new(s))
        } else {
            Err(invalid())
        }
    }

    /// The part after `@`, lower-cased.
    pub fn domain(&self) -> Option<String> {
        self.address
            .rsplit_once('@')
            .map(|(_, d)| d.to_ascii_lowercase())
    }
}

impl fmt::Display for Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(n) if !n.is_empty() => write!(f, "{} <{}>", n, self.address),
            _ => f.write_str(&self.address),
        }
    }
}

/// Minimal addr-spec sanity check: one `@`, non-empty local part and domain,
/// no whitespace or control characters.
pub(crate) fn is_addr_spec(s: &str) -> bool {
    match s.rsplit_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && !domain.is_empty()
                && !s
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || c == '<' || c == '>')
        }
        None => false,
    }
}

/// A file attached to a message.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Attachment {
    pub filename: String,
    /// e.g. `application/pdf`; defaults to `application/octet-stream`.
    pub content_type: String,
    pub data: Vec<u8>,
    /// Set to embed the part inline (`Content-Disposition: inline; Content-ID: <cid>`).
    pub content_id: Option<String>,
}

impl Attachment {
    pub fn new(
        filename: impl Into<String>,
        content_type: impl Into<String>,
        data: Vec<u8>,
    ) -> Self {
        Self {
            filename: filename.into(),
            content_type: content_type.into(),
            data,
            content_id: None,
        }
    }
}

/// Everything needed to render an outgoing message.
///
/// `message_id` and `date` are filled by [`MessageDraft::new`] so that the
/// outer message and the protected (encrypted / signed) inner part carry the
/// same values. Override them before rendering if the store needs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageDraft {
    pub from: Mailbox,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    /// Envelope-only recipients; never written into any header.
    pub bcc: Vec<Mailbox>,
    pub subject: String,
    pub text_body: String,
    pub html_body: Option<String>,
    pub attachments: Vec<Attachment>,
    /// Message-ID being replied to, without angle brackets.
    pub in_reply_to: Option<String>,
    /// Thread references, without angle brackets, oldest first.
    pub references: Vec<String>,
    /// Message-ID of this message, without angle brackets.
    pub message_id: String,
    /// Unix timestamp (seconds) for the `Date` header.
    pub date: i64,
    /// Additional outer headers, e.g. `("Autocrypt", "addr=…; keydata=…")`.
    /// Values must not contain bare CR/LF; use [`super::sanitize_header_value`].
    pub extra_headers: Vec<(String, String)>,
}

impl MessageDraft {
    pub fn new(
        from: Mailbox,
        to: Vec<Mailbox>,
        subject: impl Into<String>,
        text_body: impl Into<String>,
    ) -> Self {
        let domain = from
            .domain()
            .unwrap_or_else(|| "sealbox.invalid".to_owned());
        Self {
            from,
            to,
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: subject.into(),
            text_body: text_body.into(),
            html_body: None,
            attachments: Vec::new(),
            in_reply_to: None,
            references: Vec::new(),
            message_id: generate_message_id(&domain),
            date: now_unix(),
            extra_headers: Vec::new(),
        }
    }

    /// All envelope recipients (To + Cc + Bcc), deduplicated, in order.
    pub fn envelope_recipients(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for m in self.to.iter().chain(&self.cc).chain(&self.bcc) {
            if !out.iter().any(|a| a.eq_ignore_ascii_case(&m.address)) {
                out.push(m.address.clone());
            }
        }
        out
    }
}

/// Current time as unix seconds.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A fresh Message-ID (without angle brackets) in `unique@domain` form.
pub fn generate_message_id(domain: &str) -> String {
    let unique = mail_builder::mime::make_boundary(".");
    let domain = if domain.is_empty() {
        "sealbox.invalid"
    } else {
        domain
    };
    format!("{unique}@{domain}")
}
