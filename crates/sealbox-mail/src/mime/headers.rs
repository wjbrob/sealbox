//! Header folding/unfolding helpers and Autocrypt header values.

use crate::error::MimeError;

/// Preferred maximum line length (RFC 5322 §2.1.1: SHOULD be ≤ 78).
pub const SOFT_LINE_LIMIT: usize = 78;
/// Hard maximum line length (RFC 5322 §2.1.1: MUST be ≤ 998).
const HARD_LINE_LIMIT: usize = 998;
/// Autocrypt Level 1 §2.1: keydata is folded by inserting whitespace.
const KEYDATA_CHUNK: usize = 76;

/// Render `Name: value` folded per RFC 5322 §2.2.3 so that every line stays
/// within 78 characters whenever the value contains whitespace to break at.
/// Tokens longer than 78 characters are emitted on a line of their own (the
/// 998-octet hard limit is enforced by breaking such tokens as a last resort,
/// which is only safe for values whose grammar ignores folding whitespace,
/// e.g. Autocrypt `keydata`). The result ends with CRLF.
pub fn fold_header(name: &str, value: &str) -> String {
    let value = unfold_header_value(value);
    let mut out = String::with_capacity(name.len() + value.len() + 16);
    out.push_str(name);
    out.push(':');
    let mut column = name.len() + 1;
    let mut first = true;
    for token in value.split_ascii_whitespace() {
        if first {
            out.push(' ');
            column += 1;
            first = false;
        } else if column + 1 + token.len() > SOFT_LINE_LIMIT {
            out.push_str("\r\n ");
            column = 1;
        } else {
            out.push(' ');
            column += 1;
        }
        let mut rest = token;
        while rest.len() > HARD_LINE_LIMIT - column {
            let cut = floor_char_boundary(rest, HARD_LINE_LIMIT - column);
            if cut == 0 {
                break;
            }
            out.push_str(&rest[..cut]);
            out.push_str("\r\n ");
            column = 1;
            rest = &rest[cut..];
        }
        out.push_str(rest);
        column += rest.len();
    }
    out.push_str("\r\n");
    out
}

fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// Remove folding (CRLF / LF followed by whitespace) from a raw header value
/// and trim surrounding whitespace. Each fold becomes a single space.
pub fn unfold_header_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' | '\n' => {
                while matches!(chars.peek(), Some('\r') | Some('\n')) {
                    chars.next();
                }
                if !out.ends_with(' ') {
                    out.push(' ');
                }
            }
            _ => out.push(c),
        }
    }
    out.trim().to_owned()
}

/// Make a user-supplied value safe to put in a header: bare CR/LF become
/// spaces, other control characters are rejected.
pub fn sanitize_header_value(value: &str) -> Result<String, MimeError> {
    let unfolded = unfold_header_value(value);
    if unfolded.chars().any(|c| c.is_control() && c != '\t') {
        return Err(MimeError::InvalidHeader(
            value.chars().take(32).collect(),
            "control characters are not allowed".into(),
        ));
    }
    Ok(unfolded)
}

/// Parsed `Autocrypt:` / `Autocrypt-Gossip:` header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutocryptHeader {
    pub addr: String,
    /// `prefer-encrypt=mutual` was present.
    pub prefer_encrypt_mutual: bool,
    /// Base64 keydata with all whitespace removed.
    pub keydata: String,
}

/// Build the value of an `Autocrypt:` header (Autocrypt Level 1 §2.1).
/// `keydata_b64` is the base64 of the minimal OpenPGP key; it is chunked with
/// spaces every 76 characters so that header folding never produces a line
/// over the limit.
pub fn autocrypt_header_value(
    addr: &str,
    prefer_encrypt_mutual: bool,
    keydata_b64: &str,
) -> String {
    let mut v = format!("addr={addr}; ");
    if prefer_encrypt_mutual {
        v.push_str("prefer-encrypt=mutual; ");
    }
    v.push_str("keydata=");
    push_chunked(&mut v, keydata_b64);
    v
}

/// Base64 (standard alphabet, padded, unchunked) of binary Autocrypt keydata —
/// the form [`autocrypt_header_value`] / [`autocrypt_gossip_header_value`] take.
pub fn autocrypt_keydata_b64(keydata: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(keydata)
}

/// Build the value of an `Autocrypt-Gossip:` header (Autocrypt Level 1 §2.2).
pub fn autocrypt_gossip_header_value(addr: &str, keydata_b64: &str) -> String {
    let mut v = format!("addr={addr}; keydata=");
    push_chunked(&mut v, keydata_b64);
    v
}

fn push_chunked(out: &mut String, keydata_b64: &str) {
    let clean: String = keydata_b64.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = clean.as_bytes();
    // The first chunk shares its line with the `keydata=` attribute name so
    // that every folded line stays within 78 columns.
    let first_len = KEYDATA_CHUNK
        .saturating_sub("keydata=".len())
        .min(bytes.len());
    let (first, rest) = bytes.split_at(first_len);
    // base64 is ASCII, so every chunk is valid UTF-8.
    out.push_str(std::str::from_utf8(first).unwrap_or(""));
    for chunk in rest.chunks(KEYDATA_CHUNK) {
        out.push(' ');
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
    }
}

/// Parse an Autocrypt header value. Returns `None` when the header is invalid
/// per Level 1 §2.1 (missing `addr`/`keydata`, or an unknown critical
/// attribute, i.e. one whose name does not start with `_`).
pub fn parse_autocrypt_header(value: &str) -> Option<AutocryptHeader> {
    let value = unfold_header_value(value);
    let mut addr = None;
    let mut keydata = None;
    let mut prefer_encrypt_mutual = false;
    for attr in value.split(';') {
        let attr = attr.trim();
        if attr.is_empty() {
            continue;
        }
        let (k, v) = attr.split_once('=')?;
        let k = k.trim();
        let v = v.trim();
        match k {
            "addr" => addr = Some(v.to_ascii_lowercase()),
            "prefer-encrypt" => prefer_encrypt_mutual = v.eq_ignore_ascii_case("mutual"),
            "keydata" => keydata = Some(v.chars().filter(|c| !c.is_whitespace()).collect()),
            other if other.starts_with('_') => {}
            _ => return None,
        }
    }
    Some(AutocryptHeader {
        addr: addr?,
        prefer_encrypt_mutual,
        keydata: keydata?,
    })
}
