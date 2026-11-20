//! Small helpers shared across modules.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::{DateTime, TimeZone, Utc};
use pgp::types::Timestamp;

/// Upper-case hex, the conventional presentation for fingerprints and key ids.
pub(crate) fn hex_upper(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub(crate) fn b64_decode(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s).ok()
}

/// Extract the address part of an OpenPGP User ID ("Name <a@b>" → "a@b", "a@b" → "a@b").
pub(crate) fn email_of_user_id(uid: &str) -> Option<String> {
    if let (Some(open), Some(close)) = (uid.rfind('<'), uid.rfind('>')) {
        if open < close {
            let inner = uid[open + 1..close].trim();
            if inner.contains('@') {
                return Some(inner.to_string());
            }
        }
    }
    let t = uid.trim();
    if t.contains('@') && !t.contains(char::is_whitespace) {
        return Some(t.to_string());
    }
    None
}

/// Case-insensitive address comparison (Autocrypt canonicalizes addresses by lower-casing).
pub(crate) fn addr_eq(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

pub(crate) fn timestamp_to_datetime(ts: Timestamp) -> DateTime<Utc> {
    Utc.timestamp_opt(i64::from(ts.as_secs()), 0)
        .single()
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
}

/// Fold a long header *value* RFC 5322 style: the first line gets `first_width` characters
/// (so that `Name: ` + first line stays under 78), every continuation line starts with CRLF+SP
/// and carries at most `width` characters. `atoms` are pieces that may be split anywhere.
pub(crate) fn fold_value(prefix: &str, body: &str, width: usize) -> String {
    let mut out = String::with_capacity(body.len() + body.len() / width * 3 + prefix.len());
    out.push_str(prefix);
    let mut col = prefix.len();
    for ch in body.chars() {
        if col >= width {
            out.push_str("\r\n ");
            col = 1;
        }
        out.push(ch);
        col += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_email() {
        assert_eq!(hex_upper(&[0xde, 0xad, 0x01]), "DEAD01");
        assert_eq!(
            email_of_user_id("Alice Example <alice@example.org>").as_deref(),
            Some("alice@example.org")
        );
        assert_eq!(
            email_of_user_id("alice@example.org").as_deref(),
            Some("alice@example.org")
        );
        assert_eq!(email_of_user_id("just a name"), None);
        assert!(addr_eq("Alice@Example.org", "alice@example.org"));
    }

    #[test]
    fn folding_keeps_lines_short() {
        let body: String = std::iter::repeat_n('A', 300).collect();
        let folded = fold_value("keydata=", &body, 76);
        for line in folded.split("\r\n") {
            assert!(line.len() <= 76, "line too long: {}", line.len());
        }
        let unfolded: String = folded.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(unfolded, format!("keydata={body}"));
    }
}
