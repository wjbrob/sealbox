//! Autocrypt Level 1 (<https://autocrypt.org/level1.html>): the `Autocrypt:` header, minimal
//! keys, `Autocrypt-Gossip`, per-peer state with the Level 1 update rules, the encryption
//! recommendation, and the Autocrypt Setup Message.

use chrono::{DateTime, Duration, Utc};
use pgp::armor::Headers;
use pgp::composed::{
    ArmorOptions, MessageBuilder, SignedKeyDetails, SignedPublicKey, SignedPublicSubKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::SignatureType;
use pgp::types::{KeyDetails as _, KeyVersion as PgpKeyVersion, Password, SignedUser, StringToKey};
use rand::RngCore;

use crate::error::{Error, Result};
use crate::keys::{user_id_string, EncryptionTarget, Identity, PublicKey};
use crate::util::{addr_eq, b64_decode, b64_encode, email_of_user_id, fold_value};

/// Header field name.
pub const AUTOCRYPT_HEADER: &str = "Autocrypt";
/// Gossip header field name (inside the encrypted MIME part only).
pub const AUTOCRYPT_GOSSIP_HEADER: &str = "Autocrypt-Gossip";
/// Setup message marker header (`Autocrypt-Setup-Message: v1`).
pub const AUTOCRYPT_SETUP_HEADER: &str = "Autocrypt-Setup-Message";
/// MIME type of the setup message attachment.
pub const AUTOCRYPT_SETUP_MIME_TYPE: &str = "application/autocrypt-setup";
/// Headers above this size are invalid (Level 1 §"Header injection").
pub const MAX_HEADER_SIZE: usize = 10 * 1024;
/// A key is "stale" when `last_seen - autocrypt_timestamp` exceeds this many days.
pub const STALE_AFTER_DAYS: i64 = 35;

/// The `prefer-encrypt` attribute.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PreferEncrypt {
    #[default]
    NoPreference,
    Mutual,
}

/// A parsed or to-be-rendered `Autocrypt:` header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutocryptHeader {
    /// `addr=` — the single address this header is valid for.
    pub addr: String,
    /// `prefer-encrypt=mutual` or absent.
    pub prefer_encrypt: PreferEncrypt,
    /// Binary (not armored) minimal transferable public key.
    pub keydata: Vec<u8>,
}

impl AutocryptHeader {
    /// Build a header for `addr` carrying the minimal form of `key`.
    pub fn new(addr: &str, prefer_encrypt: PreferEncrypt, key: &PublicKey) -> Result<Self> {
        let minimal = minimal_public_key(key, Some(addr))?;
        Ok(Self {
            addr: addr.trim().to_string(),
            prefer_encrypt,
            keydata: minimal.to_bytes()?,
        })
    }

    /// Build the header we send for one of our identities. `addr` defaults to the identity's
    /// primary e-mail address.
    pub fn for_identity(
        identity: &Identity,
        addr: Option<&str>,
        prefer_encrypt: PreferEncrypt,
    ) -> Result<Self> {
        let addr = match addr {
            Some(a) => a.to_string(),
            None => identity
                .primary_email()
                .ok_or_else(|| Error::InvalidKey("identity has no e-mail User ID".into()))?,
        };
        Self::new(&addr, prefer_encrypt, &identity.public())
    }

    /// The header *value*, folded for the wire: `addr=…; [prefer-encrypt=mutual;]` on the first
    /// line, then `keydata=` plus base64 on CRLF+SP continuation lines of at most 76 columns.
    pub fn render(&self) -> String {
        format!(
            "{}\r\n{}",
            self.first_line(),
            fold_value(" keydata=", &b64_encode(&self.keydata), 76)
        )
    }

    /// Single-line value (no folding) — for storage or for a MIME library that folds itself.
    pub fn render_unfolded(&self) -> String {
        format!(
            "{} keydata={}",
            self.first_line(),
            b64_encode(&self.keydata)
        )
    }

    fn first_line(&self) -> String {
        match self.prefer_encrypt {
            PreferEncrypt::Mutual => format!("addr={}; prefer-encrypt=mutual;", self.addr),
            PreferEncrypt::NoPreference => format!("addr={};", self.addr),
        }
    }

    /// Parse one header value (folded or not). Enforces the Level 1 rules: unknown critical
    /// attributes invalidate the header, `_`-prefixed ones are ignored, `addr` and `keydata`
    /// are mandatory, `keydata` must be a parseable OpenPGP key, size limit 10 KiB.
    pub fn parse(value: &str) -> Result<Self> {
        let parsed = parse_attributes(value)?;
        Ok(Self {
            addr: parsed.addr,
            prefer_encrypt: parsed.prefer_encrypt,
            keydata: parsed.keydata,
        })
    }

    /// Level 1 processing of *all* `Autocrypt` headers of a message from `from_addr`:
    /// returns the header only if exactly one of them is valid and its `addr` matches.
    pub fn parse_for_sender(values: &[&str], from_addr: &str) -> Option<Self> {
        let mut valid: Vec<Self> = values
            .iter()
            .filter_map(|v| Self::parse(v).ok())
            .filter(|h| addr_eq(&h.addr, from_addr))
            .collect();
        if valid.len() == 1 {
            valid.pop()
        } else {
            None
        }
    }

    /// The key carried in `keydata` (self-signatures verified).
    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_bytes(&self.keydata)
    }
}

/// An `Autocrypt-Gossip:` header (same syntax, no `prefer-encrypt`, lives inside the
/// encrypted payload).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutocryptGossip {
    pub addr: String,
    pub keydata: Vec<u8>,
}

impl AutocryptGossip {
    /// Gossip `key` for recipient `addr` (minimal form).
    pub fn new(addr: &str, key: &PublicKey) -> Result<Self> {
        let minimal = minimal_public_key(key, Some(addr))?;
        Ok(Self {
            addr: addr.trim().to_string(),
            keydata: minimal.to_bytes()?,
        })
    }

    /// Folded header value.
    pub fn render(&self) -> String {
        format!(
            "addr={};\r\n{}",
            self.addr,
            fold_value(" keydata=", &b64_encode(&self.keydata), 76)
        )
    }

    /// Parse a gossip header value (a `prefer-encrypt` attribute, if present, is ignored).
    pub fn parse(value: &str) -> Result<Self> {
        let parsed = parse_attributes(value)?;
        Ok(Self {
            addr: parsed.addr,
            keydata: parsed.keydata,
        })
    }

    /// The gossiped key.
    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_bytes(&self.keydata)
    }
}

struct ParsedAttrs {
    addr: String,
    prefer_encrypt: PreferEncrypt,
    keydata: Vec<u8>,
}

fn parse_attributes(value: &str) -> Result<ParsedAttrs> {
    let invalid = |m: &str| Error::InvalidAutocryptHeader(m.to_string());
    if value.len() > MAX_HEADER_SIZE {
        return Err(invalid("header larger than 10 KiB"));
    }
    let mut addr: Option<String> = None;
    let mut prefer_encrypt = PreferEncrypt::NoPreference;
    let mut keydata: Option<Vec<u8>> = None;
    for attr in value.split(';') {
        let attr = attr.trim();
        if attr.is_empty() {
            continue;
        }
        let (name, val) = attr
            .split_once('=')
            .ok_or_else(|| invalid("attribute without '='"))?;
        let name = name.trim().to_ascii_lowercase();
        let val = val.trim();
        match name.as_str() {
            "addr" => {
                if addr.is_some() {
                    return Err(invalid("duplicate addr"));
                }
                if val.is_empty() || !val.contains('@') {
                    return Err(invalid("addr is not an e-mail address"));
                }
                addr = Some(val.to_string());
            }
            "prefer-encrypt" => {
                prefer_encrypt = if val.eq_ignore_ascii_case("mutual") {
                    PreferEncrypt::Mutual
                } else {
                    PreferEncrypt::NoPreference
                };
            }
            "keydata" => {
                if keydata.is_some() {
                    return Err(invalid("duplicate keydata"));
                }
                let compact: String = val.chars().filter(|c| !c.is_whitespace()).collect();
                let bytes = b64_decode(&compact).ok_or_else(|| invalid("keydata is not base64"))?;
                if bytes.is_empty() {
                    return Err(invalid("empty keydata"));
                }
                keydata = Some(bytes);
            }
            n if n.starts_with('_') => {} // non-critical, ignored
            other => {
                return Err(invalid(&format!("unknown critical attribute `{other}`")));
            }
        }
    }
    let addr = addr.ok_or_else(|| invalid("missing addr"))?;
    let keydata = keydata.ok_or_else(|| invalid("missing keydata"))?;
    PublicKey::from_bytes(&keydata).map_err(|e| invalid(&format!("keydata: {e}")))?;
    Ok(ParsedAttrs {
        addr,
        prefer_encrypt,
        keydata,
    })
}

/// Reduce a certificate to the Level 1 minimal form: primary key, the User ID matching `addr`
/// (else the primary/first one) with its newest self-signature, and the live encryption subkey
/// with its newest binding signature — exactly five packets for v4 keys (v6 keys keep their
/// direct-key signature as well, since it carries the algorithm preferences).
///
/// For a post-quantum hybrid key ([`crate::KeyProfile::HybridPqc`]) the **classical (X25519)
/// subkey** is exported, not the ML-KEM-768+X25519 one: Autocrypt Level 1 peers (Delta Chat,
/// Thunderbird, K-9) only implement the classical algorithms, and the composite public key
/// would add ~1.6 KB of base64 to every header. The PQC subkey travels with the full
/// certificate (key directory, attached key). A certificate with *only* a PQC subkey falls back
/// to that subkey rather than failing.
pub fn minimal_public_key(key: &PublicKey, addr: Option<&str>) -> Result<PublicKey> {
    let cert: &SignedPublicKey = key.cert();
    let now = Utc::now();
    let target = key
        .classical_encryption_target(now)
        .or_else(|| key.encryption_target(now))
        .ok_or_else(|| Error::NoEncryptionKey {
            fingerprint: key.fingerprint(),
        })?;
    let users = &cert.details.users;
    let chosen: &SignedUser = addr
        .and_then(|a| {
            users.iter().find(|u| {
                email_of_user_id(&user_id_string(&u.id))
                    .map(|e| addr_eq(&e, a))
                    .unwrap_or(false)
            })
        })
        .or_else(|| users.iter().find(|u| u.is_primary()))
        .or_else(|| users.first())
        .ok_or_else(|| Error::InvalidKey("key has no User ID".into()))?;
    let self_sig = chosen
        .signatures
        .iter()
        .filter(|s| {
            matches!(
                s.typ(),
                Some(
                    SignatureType::CertGeneric
                        | SignatureType::CertPersona
                        | SignatureType::CertCasual
                        | SignatureType::CertPositive
                )
            )
        })
        .max_by_key(|s| s.created().map(|t| t.as_secs()).unwrap_or(0))
        .ok_or_else(|| Error::InvalidKey("User ID without self-signature".into()))?
        .clone();
    let user = SignedUser::new(chosen.id.clone(), vec![self_sig]);

    let subkeys = match target {
        EncryptionTarget::Subkey(sub) => {
            let binding = sub
                .signatures
                .iter()
                .filter(|s| s.typ() == Some(SignatureType::SubkeyBinding))
                .max_by_key(|s| s.created().map(|t| t.as_secs()).unwrap_or(0))
                .ok_or_else(|| Error::InvalidKey("subkey without binding signature".into()))?
                .clone();
            vec![SignedPublicSubKey::new(sub.key.clone(), vec![binding])]
        }
        EncryptionTarget::Primary(_) => Vec::new(),
    };
    let direct = if cert.version() == PgpKeyVersion::V6 {
        cert.details.direct_signatures.clone()
    } else {
        Vec::new()
    };
    let details = SignedKeyDetails::new(Vec::new(), direct, vec![user], Vec::new());
    let minimal = SignedPublicKey::new(cert.primary_key.clone(), details, subkeys);
    PublicKey::from_cert(minimal)
}

/// Binary minimal key for `identity` (the bytes that go into `keydata=`).
pub fn minimal_key_for_autocrypt(identity: &Identity) -> Result<Vec<u8>> {
    let addr = identity.primary_email();
    minimal_public_key(&identity.public(), addr.as_deref())?.to_bytes()
}

/// Per-peer Autocrypt state (Level 1 §"Peer State Management"). Serializable for the store.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerState {
    /// Canonical (as received) address of the peer.
    pub addr: String,
    /// Effective date of the most recent message seen from the peer.
    pub last_seen: Option<DateTime<Utc>>,
    /// Effective date of the youngest message that carried a valid `Autocrypt` header.
    pub autocrypt_timestamp: Option<DateTime<Utc>>,
    /// `keydata` of that header (binary minimal key).
    pub public_key: Option<Vec<u8>>,
    /// `prefer-encrypt` of that header.
    pub prefer_encrypt: PreferEncrypt,
    /// Effective date of the most recent `Autocrypt-Gossip` about the peer.
    pub gossip_timestamp: Option<DateTime<Utc>>,
    /// `keydata` of that gossip header.
    pub gossip_key: Option<Vec<u8>>,
}

impl PeerState {
    /// Empty state for `addr`.
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.trim().to_string(),
            last_seen: None,
            autocrypt_timestamp: None,
            public_key: None,
            prefer_encrypt: PreferEncrypt::NoPreference,
            gossip_timestamp: None,
            gossip_key: None,
        }
    }

    /// Apply the Level 1 update rules for a message from this peer with `effective_date`
    /// (see [`effective_date`]). `header` is the message's single valid `Autocrypt` header, or
    /// `None` if it had none (which still bumps `last_seen` — that is how dropping Autocrypt
    /// is detected). A header whose `addr` does not match this peer is ignored.
    /// Returns `true` if anything changed.
    pub fn update_from_header(
        &mut self,
        header: Option<&AutocryptHeader>,
        effective_date: DateTime<Utc>,
    ) -> bool {
        // 1. older than autocrypt_timestamp → no changes
        if let Some(ts) = self.autocrypt_timestamp {
            if effective_date < ts {
                return false;
            }
        }
        let mut changed = false;
        // 2. bump last_seen
        if self.last_seen.map(|ls| effective_date > ls).unwrap_or(true) {
            self.last_seen = Some(effective_date);
            changed = true;
        }
        // 3. no valid header → stop
        let Some(h) = header.filter(|h| addr_eq(&h.addr, &self.addr)) else {
            return changed;
        };
        // 4–6.
        self.autocrypt_timestamp = Some(effective_date);
        self.public_key = Some(h.keydata.clone());
        self.prefer_encrypt = h.prefer_encrypt;
        true
    }

    /// Apply the gossip rules: ignored unless `effective_date` is at least as recent as the
    /// stored `gossip_timestamp`. The caller must already have checked that `gossip.addr` is
    /// among the message's To/Cc/Reply-To addresses (rule 1). Returns `true` if changed.
    pub fn update_from_gossip(
        &mut self,
        gossip: &AutocryptGossip,
        effective_date: DateTime<Utc>,
    ) -> bool {
        if !addr_eq(&gossip.addr, &self.addr) {
            return false;
        }
        if let Some(ts) = self.gossip_timestamp {
            if ts > effective_date {
                return false;
            }
        }
        self.gossip_timestamp = Some(effective_date);
        self.gossip_key = Some(gossip.keydata.clone());
        true
    }

    pub fn last_seen(&self) -> Option<DateTime<Utc>> {
        self.last_seen
    }

    pub fn autocrypt_timestamp(&self) -> Option<DateTime<Utc>> {
        self.autocrypt_timestamp
    }

    pub fn prefer_encrypt(&self) -> PreferEncrypt {
        self.prefer_encrypt
    }

    /// The peer's own announced key, if present and currently usable for encryption.
    pub fn public_key(&self) -> Option<PublicKey> {
        self.public_key.as_deref().and_then(usable_key)
    }

    /// The gossiped key, if present and currently usable for encryption.
    pub fn gossip_public_key(&self) -> Option<PublicKey> {
        self.gossip_key.as_deref().and_then(usable_key)
    }

    /// The key we would encrypt to: the announced key, else the gossiped one.
    pub fn target_key(&self) -> Option<PublicKey> {
        self.public_key().or_else(|| self.gossip_public_key())
    }
}

fn usable_key(bytes: &[u8]) -> Option<PublicKey> {
    PublicKey::from_bytes(bytes)
        .ok()
        .filter(|k| k.encryption_capable())
}

/// The UI recommendation for one recipient (Level 1 §"Provide a recommendation").
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Recommendation {
    /// Encryption is not possible: hide the option.
    Disable,
    /// Possible but not advisable (gossip-only or stale key): offer, do not default, warn.
    Discourage,
    /// Possible: offer, do not default to it.
    Available,
    /// Default to encryption.
    Encrypt,
}

/// Recommendation assuming our own account has `prefer-encrypt=mutual` (Sealbox always does).
pub fn recommendation(peer: &PeerState, reply_to_encrypted: bool) -> Recommendation {
    recommendation_with(peer, PreferEncrypt::Mutual, reply_to_encrypted)
}

/// Full Level 1 algorithm with an explicit own `prefer-encrypt` setting.
pub fn recommendation_with(
    peer: &PeerState,
    own_prefer_encrypt: PreferEncrypt,
    reply_to_encrypted: bool,
) -> Recommendation {
    let announced = peer.public_key();
    let gossiped = peer.gossip_public_key();
    if announced.is_none() && gossiped.is_none() {
        return Recommendation::Disable;
    }
    let preliminary = if announced.is_none() {
        Recommendation::Discourage
    } else {
        match (peer.autocrypt_timestamp, peer.last_seen) {
            (Some(at), Some(ls)) if ls - at > Duration::days(STALE_AFTER_DAYS) => {
                Recommendation::Discourage
            }
            _ => Recommendation::Available,
        }
    };
    if reply_to_encrypted
        && matches!(
            preliminary,
            Recommendation::Available | Recommendation::Discourage
        )
    {
        return Recommendation::Encrypt;
    }
    if preliminary == Recommendation::Available
        && peer.prefer_encrypt == PreferEncrypt::Mutual
        && own_prefer_encrypt == PreferEncrypt::Mutual
    {
        return Recommendation::Encrypt;
    }
    preliminary
}

/// Combine per-recipient recommendations for a message with several recipients
/// (first matching rule wins: any `Disable` → `Disable`; all `Encrypt` → `Encrypt`;
/// any `Discourage` → `Discourage`; else `Available`). No recipients → `Disable`.
pub fn aggregate_recommendation(recs: &[Recommendation]) -> Recommendation {
    if recs.is_empty() || recs.contains(&Recommendation::Disable) {
        return Recommendation::Disable;
    }
    if recs.iter().all(|r| *r == Recommendation::Encrypt) {
        return Recommendation::Encrypt;
    }
    if recs.contains(&Recommendation::Discourage) {
        return Recommendation::Discourage;
    }
    Recommendation::Available
}

/// The message's effective date: its `Date` header, unless that is missing or in the future,
/// in which case the time of receipt.
pub fn effective_date(
    date_header: Option<DateTime<Utc>>,
    received_at: DateTime<Utc>,
) -> DateTime<Utc> {
    match date_header {
        Some(d) if d <= received_at => d,
        _ => received_at,
    }
}

/// A fresh Setup Code: nine blocks of four decimal digits (`1234-5678-…`), ≈119.6 bits,
/// from OS randomness with rejection sampling (no modulo bias).
pub fn setup_code_generate() -> String {
    let mut rng = rand::rngs::OsRng;
    let mut digit = || loop {
        let v = rng.next_u32();
        if v < 4_000_000_000 {
            return char::from(b'0' + (v % 10) as u8);
        }
    };
    let mut out = String::with_capacity(44);
    for block in 0..9 {
        if block > 0 {
            out.push('-');
        }
        for _ in 0..4 {
            out.push(digit());
        }
    }
    out
}

/// Canonical `dddd-dddd-…` form of a user-entered setup code (whitespace tolerated, bare 36
/// digits accepted).
fn normalize_setup_code(input: &str) -> Result<String> {
    let digits: String = input.chars().filter(|c| c.is_ascii_digit()).collect();
    let non_digit_ok = input
        .chars()
        .all(|c| c.is_ascii_digit() || c == '-' || c.is_whitespace());
    if digits.len() != 36 || !non_digit_ok {
        return Err(Error::InvalidSetupCode);
    }
    let blocks: Vec<&str> = (0..9).map(|i| &digits[i * 4..i * 4 + 4]).collect();
    Ok(blocks.join("-"))
}

/// Build the armored body of an Autocrypt Setup Message for `identity`: the armored secret
/// key (with `Autocrypt-Prefer-Encrypt: mutual`) symmetrically encrypted under `setup_code`
/// (AES-256, iterated+salted SHA-256 S2K, SEIPDv1) with the `Passphrase-Format: numeric9x4`
/// and `Passphrase-Begin` armor headers. The caller wraps it in the `multipart/mixed` mail
/// with `Autocrypt-Setup-Message: v1` and an `application/autocrypt-setup` attachment.
pub fn setup_message_create(identity: &Identity, setup_code: &str) -> Result<String> {
    let code = normalize_setup_code(setup_code)?;
    let mut inner_headers = Headers::new();
    inner_headers.insert(
        "Autocrypt-Prefer-Encrypt".to_string(),
        vec!["mutual".to_string()],
    );
    let inner = identity.secret().to_armored_string(ArmorOptions {
        headers: Some(&inner_headers),
        include_checksum: true,
    })?;

    let mut outer_headers = Headers::new();
    outer_headers.insert(
        "Passphrase-Format".to_string(),
        vec!["numeric9x4".to_string()],
    );
    outer_headers.insert("Passphrase-Begin".to_string(), vec![code[..2].to_string()]);

    let mut rng = rand::thread_rng();
    let mut b = MessageBuilder::from_bytes("", inner.into_bytes())
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    let s2k = StringToKey::new_iterated(&mut rng, HashAlgorithm::Sha256, 224);
    b.encrypt_with_password(s2k, &Password::from(code.as_str()))?;
    Ok(b.to_armored_string(
        &mut rng,
        ArmorOptions {
            headers: Some(&outer_headers),
            include_checksum: true,
        },
    )?)
}

/// Open a Setup Message body (text around the armor is ignored) with `setup_code` and return
/// the contained identity.
pub fn setup_message_open(body: &str, setup_code: &str) -> Result<Identity> {
    let code = normalize_setup_code(setup_code)?;
    let armored = extract_armor(body, "PGP MESSAGE")
        .ok_or_else(|| Error::InvalidInput("no PGP MESSAGE armor in setup message".into()))?;
    let plain = crate::guest::guest_decrypt(armored, &code)?;
    let plain = String::from_utf8(plain)?;
    let key = extract_armor(&plain, "PGP PRIVATE KEY BLOCK")
        .ok_or_else(|| Error::InvalidInput("setup message does not contain a key".into()))?;
    Identity::from_armored_secret(key, None)
}

fn extract_armor<'a>(text: &'a str, kind: &str) -> Option<&'a str> {
    let begin = format!("-----BEGIN {kind}-----");
    let end = format!("-----END {kind}-----");
    let start = text.find(&begin)?;
    let stop = text[start..].find(&end)? + start + end.len();
    Some(&text[start..stop])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{decrypt_and_verify, encrypt_and_sign};
    use chrono::TimeZone;

    fn alice() -> Identity {
        Identity::generate("Alice", "alice@autocrypt.example").unwrap()
    }

    fn t(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap() + Duration::days(i64::from(day))
    }

    #[test]
    fn header_render_parse_roundtrip_and_folding() {
        let a = alice();
        let h = AutocryptHeader::for_identity(&a, None, PreferEncrypt::Mutual).unwrap();
        let rendered = h.render();
        let mut lines = rendered.split("\r\n");
        assert_eq!(
            lines.next().unwrap(),
            "addr=alice@autocrypt.example; prefer-encrypt=mutual;"
        );
        let rest: Vec<&str> = lines.collect();
        assert!(rest[0].starts_with(" keydata="));
        for l in &rest {
            assert!(l.starts_with(' ') && l.len() <= 76, "bad fold: {l:?}");
        }
        let parsed = AutocryptHeader::parse(&rendered).unwrap();
        assert_eq!(parsed, h);
        let parsed2 = AutocryptHeader::parse(&h.render_unfolded()).unwrap();
        assert_eq!(parsed2, h);
        assert_eq!(parsed.public_key().unwrap().fingerprint(), a.fingerprint());

        let np = AutocryptHeader::for_identity(&a, None, PreferEncrypt::NoPreference).unwrap();
        assert!(np
            .render()
            .starts_with("addr=alice@autocrypt.example;\r\n keydata="));
        assert_eq!(
            AutocryptHeader::parse(&np.render()).unwrap().prefer_encrypt,
            PreferEncrypt::NoPreference
        );
    }

    #[test]
    fn header_parse_rules() {
        let a = alice();
        let h = AutocryptHeader::for_identity(&a, None, PreferEncrypt::Mutual).unwrap();
        let b64 = b64_encode(&h.keydata);
        // non-critical attribute ignored
        let v = format!("addr=alice@autocrypt.example; _x=1; prefer-encrypt=mutual; keydata={b64}");
        assert!(AutocryptHeader::parse(&v).is_ok());
        // unknown critical attribute → invalid
        let v = format!("addr=alice@autocrypt.example; foo=1; keydata={b64}");
        assert!(matches!(
            AutocryptHeader::parse(&v),
            Err(Error::InvalidAutocryptHeader(_))
        ));
        // unknown prefer-encrypt value → nopreference
        let v = format!("addr=alice@autocrypt.example; prefer-encrypt=yes; keydata={b64}");
        assert_eq!(
            AutocryptHeader::parse(&v).unwrap().prefer_encrypt,
            PreferEncrypt::NoPreference
        );
        // missing pieces
        assert!(AutocryptHeader::parse(&format!("keydata={b64}")).is_err());
        assert!(AutocryptHeader::parse("addr=a@b.c").is_err());
        assert!(AutocryptHeader::parse("addr=a@b.c; keydata=AAAA").is_err());
        // oversize
        let huge = format!("addr=a@b.c; keydata={}", "A".repeat(MAX_HEADER_SIZE + 1));
        assert!(AutocryptHeader::parse(&huge).is_err());
        // From-address handling: mismatch → none, two valid → none, one valid → some
        let r = h.render();
        assert!(AutocryptHeader::parse_for_sender(&[&r], "bob@autocrypt.example").is_none());
        assert!(AutocryptHeader::parse_for_sender(&[&r, &r], "alice@autocrypt.example").is_none());
        assert!(AutocryptHeader::parse_for_sender(
            &[&r, "addr=x; junk"],
            "ALICE@autocrypt.example"
        )
        .is_some());
    }

    #[test]
    fn minimal_key_is_five_packets_and_encrypts() {
        use pgp::packet::{PacketParser, PacketTrait};
        use pgp::types::Tag;
        let a = alice();
        let min = minimal_key_for_autocrypt(&a).unwrap();
        let tags: Vec<Tag> = PacketParser::new(&min[..])
            .map(|p| p.unwrap().tag())
            .collect();
        assert_eq!(
            tags,
            vec![
                Tag::PublicKey,
                Tag::UserId,
                Tag::Signature,
                Tag::PublicSubkey,
                Tag::Signature
            ]
        );
        let full = a.public().to_bytes().unwrap();
        assert!(min.len() <= full.len());
        let key = PublicKey::from_bytes(&min).unwrap();
        assert!(key.encryption_capable());
        let ct = encrypt_and_sign(b"via minimal key", &[&key], None).unwrap();
        assert_eq!(
            decrypt_and_verify(&ct, &[&a], &[]).unwrap().plaintext,
            b"via minimal key"
        );
    }

    #[test]
    fn gossip_roundtrip() {
        let a = alice();
        let g = AutocryptGossip::new("alice@autocrypt.example", &a.public()).unwrap();
        let r = g.render();
        assert!(r.starts_with("addr=alice@autocrypt.example;\r\n keydata="));
        assert_eq!(AutocryptGossip::parse(&r).unwrap(), g);
        assert_eq!(g.public_key().unwrap().fingerprint(), a.fingerprint());
    }

    #[test]
    fn peer_state_update_rules() {
        let a = alice();
        let h = AutocryptHeader::for_identity(&a, None, PreferEncrypt::Mutual).unwrap();
        let mut p = PeerState::new("alice@autocrypt.example");
        assert_eq!(recommendation(&p, false), Recommendation::Disable);

        // message without header: only last_seen moves
        assert!(p.update_from_header(None, t(1)));
        assert_eq!(p.last_seen, Some(t(1)));
        assert_eq!(p.autocrypt_timestamp, None);
        assert_eq!(recommendation(&p, false), Recommendation::Disable);

        // valid header
        assert!(p.update_from_header(Some(&h), t(2)));
        assert_eq!(p.autocrypt_timestamp, Some(t(2)));
        assert_eq!(p.last_seen, Some(t(2)));
        assert_eq!(p.prefer_encrypt, PreferEncrypt::Mutual);
        assert_eq!(p.public_key.as_ref(), Some(&h.keydata));
        assert_eq!(recommendation(&p, false), Recommendation::Encrypt);
        assert_eq!(
            recommendation_with(&p, PreferEncrypt::NoPreference, false),
            Recommendation::Available
        );

        // older message: no changes at all
        assert!(!p.update_from_header(None, t(1)));
        assert_eq!(p.last_seen, Some(t(2)));

        // header for someone else is ignored (still bumps last_seen)
        let other = AutocryptHeader {
            addr: "bob@autocrypt.example".into(),
            ..h.clone()
        };
        assert!(p.update_from_header(Some(&other), t(3)));
        assert_eq!(p.last_seen, Some(t(3)));
        assert_eq!(p.autocrypt_timestamp, Some(t(2)));

        // peer stops sending Autocrypt for > 35 days → discourage, but reply-to-encrypted wins
        assert!(p.update_from_header(None, t(40)));
        assert_eq!(recommendation(&p, false), Recommendation::Discourage);
        assert_eq!(recommendation(&p, true), Recommendation::Encrypt);
        // fresh header makes it available/encrypt again
        let np = AutocryptHeader {
            prefer_encrypt: PreferEncrypt::NoPreference,
            ..h.clone()
        };
        assert!(p.update_from_header(Some(&np), t(41)));
        assert_eq!(recommendation(&p, false), Recommendation::Available);
        assert_eq!(recommendation(&p, true), Recommendation::Encrypt);
        assert_eq!(p.target_key().unwrap().fingerprint(), a.fingerprint());

        // serde roundtrip
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<PeerState>(&json).unwrap(), p);
    }

    #[test]
    fn gossip_rules_and_aggregate() {
        let a = alice();
        let g = AutocryptGossip::new("alice@autocrypt.example", &a.public()).unwrap();
        let mut p = PeerState::new("alice@autocrypt.example");
        assert!(p.update_from_gossip(&g, t(5)));
        assert_eq!(p.gossip_timestamp, Some(t(5)));
        assert!(
            !p.update_from_gossip(&g, t(4)),
            "older gossip must be ignored"
        );
        assert_eq!(recommendation(&p, false), Recommendation::Discourage);
        assert_eq!(recommendation(&p, true), Recommendation::Encrypt);
        assert_eq!(p.target_key().unwrap().fingerprint(), a.fingerprint());
        let wrong = AutocryptGossip {
            addr: "x@y.z".into(),
            ..g.clone()
        };
        assert!(!p.update_from_gossip(&wrong, t(9)));

        use Recommendation::*;
        assert_eq!(aggregate_recommendation(&[]), Disable);
        assert_eq!(aggregate_recommendation(&[Encrypt, Disable]), Disable);
        assert_eq!(aggregate_recommendation(&[Encrypt, Encrypt]), Encrypt);
        assert_eq!(aggregate_recommendation(&[Encrypt, Discourage]), Discourage);
        assert_eq!(aggregate_recommendation(&[Encrypt, Available]), Available);

        let now = t(10);
        assert_eq!(effective_date(Some(t(9)), now), t(9));
        assert_eq!(effective_date(Some(t(11)), now), now);
        assert_eq!(effective_date(None, now), now);
    }

    #[test]
    fn setup_message_roundtrip() {
        let a = alice();
        let code = setup_code_generate();
        assert_eq!(code.len(), 44);
        assert_eq!(code.split('-').count(), 9);
        assert!(code
            .split('-')
            .all(|b| b.len() == 4 && b.bytes().all(|c| c.is_ascii_digit())));

        let body = setup_message_create(&a, &code).unwrap();
        assert!(body.contains("Passphrase-Format: numeric9x4"));
        assert!(body.contains(&format!("Passphrase-Begin: {}", &code[..2])));
        let wrapped = format!("This is an Autocrypt Setup Message.\n\n{body}\n\ntrailing text\n");
        let back = setup_message_open(&wrapped, &code).unwrap();
        assert_eq!(back.fingerprint(), a.fingerprint());
        // spaces and bare digits are tolerated
        let spaced = code.replace('-', " ");
        assert_eq!(
            setup_message_open(&wrapped, &spaced).unwrap().fingerprint(),
            a.fingerprint()
        );
        // wrong code / malformed code
        let mut wrong = code.clone().into_bytes();
        wrong[0] = if wrong[0] == b'0' { b'1' } else { b'0' };
        assert!(matches!(
            setup_message_open(&wrapped, std::str::from_utf8(&wrong).unwrap()),
            Err(Error::BadPassphrase)
        ));
        assert!(matches!(
            setup_message_open(&wrapped, "1234"),
            Err(Error::InvalidSetupCode)
        ));
        assert!(matches!(
            setup_message_create(&a, "abcd"),
            Err(Error::InvalidSetupCode)
        ));
    }
}
