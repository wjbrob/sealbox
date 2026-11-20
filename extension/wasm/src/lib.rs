//! sealbox-wasm — the Sealbox crypto + PGP/MIME core for browsers (gate G28).
//!
//! A thin `wasm-bindgen` layer over `sealbox-crypto` (rPGP) and the pure `mime` module of
//! `sealbox-mail`. Nothing in here talks to the network: the extension's service worker does
//! the documented Gmail REST API calls and hands raw RFC 5322 bytes in and out.
//!
//! Conventions for the JS API (TypeScript types are generated into `sealbox_wasm.d.ts`):
//! * keys are ASCII-armored strings; secret keys are passed **unlocked** (the extension keeps
//!   them wrapped at rest with [`wrap_secret`] and unwraps them only in memory);
//! * message bytes are `Uint8Array` (strings are accepted where noted and UTF-8 encoded);
//! * errors are thrown as `Error` with a human-readable message.
//!
//! wasm32-unknown-unknown has no std clock: never call `MessageDraft::new` / `now_unix` here
//! (they read `SystemTime`); dates come from JavaScript's `Date`.

#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sealbox_crypto::{Decrypted, Identity, PreferEncrypt, PublicKey, SignatureStatus};
use sealbox_mail::mime::{self, Attachment, InnerOptions, Mailbox, MessageDraft, MessageKind};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

type JsResult<T> = Result<T, JsError>;

fn err(context: &str, e: impl std::fmt::Display) -> JsError {
    JsError::new(&format!("{context}: {e}"))
}

fn to_js<T: Serialize>(v: &T) -> JsResult<JsValue> {
    let ser = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    v.serialize(&ser).map_err(|e| err("serialize", e))
}

fn from_js<T: for<'de> Deserialize<'de>>(v: JsValue, what: &str) -> JsResult<T> {
    serde_wasm_bindgen::from_value(v).map_err(|e| err(what, e))
}

/// `string | Uint8Array` → bytes (strings are UTF-8 encoded).
fn bytes_of(v: &JsValue, what: &str) -> JsResult<Vec<u8>> {
    if let Some(s) = v.as_string() {
        return Ok(s.into_bytes());
    }
    if v.is_instance_of::<js_sys::Uint8Array>() {
        return Ok(js_sys::Uint8Array::new(v).to_vec());
    }
    if v.is_instance_of::<js_sys::ArrayBuffer>() {
        return Ok(js_sys::Uint8Array::new(v).to_vec());
    }
    Err(JsError::new(&format!(
        "{what}: expected a string or Uint8Array"
    )))
}

fn now_unix_js() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &'static str = r#"
/** Mailbox: `"Name <a@b>"`, `"a@b"`, or an object. */
export type MailboxInput = string | { name?: string | null; address: string };
export interface MailboxOut { name?: string; address: string }

export interface AttachmentInput { filename: string; contentType?: string; data: Uint8Array; contentId?: string }
export interface AttachmentOut { filename: string; contentType: string; data: Uint8Array; contentId?: string }

/** An outgoing message. `messageId` / `date` are filled by `finalizeDraft` when absent;
 *  call it once and reuse the result so the inner (protected) and outer headers agree. */
export interface Draft {
  from: MailboxInput;
  to?: MailboxInput[];
  cc?: MailboxInput[];
  bcc?: MailboxInput[];
  subject?: string;
  text?: string;
  html?: string | null;
  attachments?: AttachmentInput[];
  inReplyTo?: string | null;
  references?: string[];
  messageId?: string | null;
  /** Unix seconds. */
  date?: number | null;
  /** Extra outer headers, e.g. `[["Autocrypt", autocryptHeader(...)]]`. */
  extraHeaders?: [string, string][];
  /** `Autocrypt-Gossip` values placed inside the encrypted part. */
  gossipHeaders?: string[];
  /** Add a legacy-display part showing the protected Subject. */
  legacyDisplay?: boolean;
}

export interface IdentityInfo {
  /** Unlocked armored secret key (only from generate/import). */
  secretArmored?: string;
  publicArmored: string;
  fingerprint: string;
  keyId: string;
  userIds: string[];
  emails: string[];
  primaryEmail?: string;
  encryptionCapable?: boolean;
}

export type SignatureStatus =
  | { status: "good"; fingerprint: string }
  | { status: "bad"; fingerprint: string }
  | { status: "unknown_key"; key_id: string };

export interface DecryptResult {
  plaintext: Uint8Array;
  /** `plaintext` as UTF-8 when it is valid UTF-8. */
  text?: string;
  signatures: SignatureStatus[];
  signedByKnownKey: boolean;
}

export interface ParsedHeaders {
  from: MailboxOut[]; to: MailboxOut[]; cc: MailboxOut[];
  subject?: string; date?: number; messageId?: string;
  inReplyTo: string[]; references: string[];
  autocrypt: string[]; autocryptGossip: string[];
  contentType?: string;
}

export interface ParsedMessage {
  headers: ParsedHeaders;
  kind: "plain" | "pgpMimeEncrypted" | "pgpMimeSigned" | "inlinePgp";
  text?: string; html?: string; attachments?: AttachmentOut[];
  /** Armored ciphertext (pgpMimeEncrypted) or armored block (inlinePgp). */
  ciphertext?: string;
  signedPart?: Uint8Array; signature?: string; micalg?: string;
}

export interface ProtectedHeaders {
  present: boolean; subject?: string;
  from: MailboxOut[]; to: MailboxOut[]; cc: MailboxOut[];
  date?: number; messageId?: string; inReplyTo: string[]; references: string[];
  autocryptGossip: string[];
}

export interface DecryptedInner {
  protectedHeaders: ProtectedHeaders;
  text?: string; html?: string; attachments: AttachmentOut[];
}

export interface DecryptedMessage extends DecryptedInner {
  headers: ParsedHeaders;
  kind: "pgpMimeEncrypted" | "inlinePgp";
  /** Protected subject when present, else the outer one. */
  subject?: string;
  signatures: SignatureStatus[];
  signedByKnownKey: boolean;
}

export interface EncryptedDraft { raw: Uint8Array; messageId: string; draft: Draft }

export interface AutocryptParsed {
  addr: string; preferEncrypt: "mutual" | "nopreference";
  publicArmored: string; fingerprint: string;
}
export interface AutocryptParseResult { valid: AutocryptParsed[]; forSender?: AutocryptParsed }

export interface WrappedSecret {
  v: 1; kdf: "argon2id"; m: number; t: number; p: number;
  salt: string; nonce: string; ct: string;
}
"#;

// ---------------------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_armored: Option<String>,
    public_armored: String,
    fingerprint: String,
    key_id: String,
    user_ids: Vec<String>,
    emails: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    primary_email: Option<String>,
    encryption_capable: bool,
}

fn identity_info(id: &Identity, with_secret: bool) -> JsResult<IdentityInfo> {
    let public = id.public();
    Ok(IdentityInfo {
        secret_armored: if with_secret {
            Some(
                id.to_armored_secret(None)
                    .map_err(|e| err("export secret", e))?,
            )
        } else {
            None
        },
        public_armored: public.to_armored().map_err(|e| err("export public", e))?,
        fingerprint: id.fingerprint(),
        key_id: id.key_id(),
        user_ids: id.user_ids(),
        emails: id.emails(),
        primary_email: id.primary_email(),
        encryption_capable: public.encryption_capable(),
    })
}

fn identity_from(armored: &str) -> JsResult<Identity> {
    Identity::from_armored_secret(armored, None).map_err(|e| err("secret key", e))
}

fn public_from(armored: &str) -> JsResult<PublicKey> {
    PublicKey::from_armored(armored).map_err(|e| err("public key", e))
}

/// Version of this core and of the rPGP it links.
#[wasm_bindgen]
pub fn version() -> String {
    format!(
        "sealbox-wasm {} (rPGP {})",
        env!("CARGO_PKG_VERSION"),
        sealbox_crypto::capabilities::RPGP_VERSION
    )
}

/// Generate a v4 Ed25519/Curve25519 identity (gpg-compatible).
#[wasm_bindgen(js_name = generateIdentity, unchecked_return_type = "IdentityInfo")]
pub fn generate_identity(name: &str, email: &str) -> JsResult<JsValue> {
    let id = Identity::generate(name, email).map_err(|e| err("generate", e))?;
    to_js(&identity_info(&id, true)?)
}

/// Import an armored secret key (optionally passphrase-protected). The returned
/// `secretArmored` is the **unlocked** key — wrap it with `wrapSecret` before storing.
#[wasm_bindgen(js_name = importIdentity, unchecked_return_type = "IdentityInfo")]
pub fn import_identity(armored_secret: &str, passphrase: Option<String>) -> JsResult<JsValue> {
    let id = Identity::from_armored_secret(armored_secret, passphrase.as_deref())
        .map_err(|e| err("import", e))?;
    to_js(&identity_info(&id, true)?)
}

/// Armored public key (certificate) of an armored secret key.
#[wasm_bindgen(js_name = exportPublicKey)]
pub fn export_public_key(armored_secret: &str) -> JsResult<String> {
    identity_from(armored_secret)?
        .public()
        .to_armored()
        .map_err(|e| err("export public", e))
}

/// Fingerprint / user ids of an armored public key.
#[wasm_bindgen(js_name = inspectPublicKey, unchecked_return_type = "IdentityInfo")]
pub fn inspect_public_key(armored_public: &str) -> JsResult<JsValue> {
    let k = public_from(armored_public)?;
    to_js(&IdentityInfo {
        secret_armored: None,
        public_armored: k.to_armored().map_err(|e| err("export public", e))?,
        fingerprint: k.fingerprint(),
        key_id: k.key_id(),
        user_ids: k.user_ids(),
        emails: k.emails(),
        primary_email: k.primary_email(),
        encryption_capable: k.encryption_capable(),
    })
}

// ---------------------------------------------------------------------------------------
// OpenPGP messages
// ---------------------------------------------------------------------------------------

/// Encrypt to every recipient (armored public keys) and sign with `signerSecret` if given.
/// Returns an ASCII-armored OpenPGP message. Include your own public key in the recipients
/// to be able to read your Sent copy.
#[wasm_bindgen(js_name = encryptAndSign)]
pub fn encrypt_and_sign(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] plain: JsValue,
    recipients_armored: Vec<String>,
    signer_secret: Option<String>,
) -> JsResult<String> {
    let plain = bytes_of(&plain, "plaintext")?;
    encrypt_bytes(&plain, &recipients_armored, signer_secret.as_deref())
}

fn encrypt_bytes(plain: &[u8], recipients: &[String], signer: Option<&str>) -> JsResult<String> {
    let keys = recipients
        .iter()
        .map(|a| public_from(a))
        .collect::<JsResult<Vec<_>>>()?;
    let refs: Vec<&PublicKey> = keys.iter().collect();
    let signer = signer.map(identity_from).transpose()?;
    sealbox_crypto::encrypt_and_sign_armored(plain, &refs, signer.as_ref())
        .map_err(|e| err("encrypt", e))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecryptOut {
    #[serde(with = "serde_bytes")]
    plaintext: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    signatures: Vec<SignatureStatus>,
    signed_by_known_key: bool,
}

fn decrypt_bytes(message: &[u8], secrets: &[String], known: &[String]) -> JsResult<Decrypted> {
    let ids = secrets
        .iter()
        .map(|a| identity_from(a))
        .collect::<JsResult<Vec<_>>>()?;
    let id_refs: Vec<&Identity> = ids.iter().collect();
    // Unparseable known keys are skipped (a contact list may hold junk), not fatal.
    let keys: Vec<PublicKey> = known
        .iter()
        .filter_map(|a| PublicKey::from_armored(a).ok())
        .collect();
    let key_refs: Vec<&PublicKey> = keys.iter().collect();
    sealbox_crypto::decrypt_and_verify(message, &id_refs, &key_refs).map_err(|e| err("decrypt", e))
}

/// Decrypt an armored or binary OpenPGP message with any of the (unlocked, armored) secret
/// keys and verify its signatures against `knownKeysArmored`.
#[wasm_bindgen(js_name = decryptAndVerify, unchecked_return_type = "DecryptResult")]
pub fn decrypt_and_verify(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] message: JsValue,
    secrets_armored: Vec<String>,
    known_keys_armored: Vec<String>,
) -> JsResult<JsValue> {
    let message = bytes_of(&message, "message")?;
    let d = decrypt_bytes(&message, &secrets_armored, &known_keys_armored)?;
    let signed_by_known_key = d.signed_by_known_key();
    to_js(&DecryptOut {
        text: String::from_utf8(d.plaintext.clone()).ok(),
        plaintext: d.plaintext,
        signatures: d.signatures,
        signed_by_known_key,
    })
}

// ---------------------------------------------------------------------------------------
// Drafts and PGP/MIME
// ---------------------------------------------------------------------------------------

#[derive(Deserialize, Serialize, Clone)]
#[serde(untagged)]
enum MailboxIn {
    Text(String),
    Obj {
        #[serde(default)]
        name: Option<String>,
        address: String,
    },
}

impl MailboxIn {
    fn to_mailbox(&self) -> JsResult<Mailbox> {
        match self {
            MailboxIn::Text(s) => Mailbox::parse(s).map_err(|e| err("address", e)),
            MailboxIn::Obj { name, address } => {
                let m = Mailbox::parse(address).map_err(|e| err("address", e))?;
                Ok(Mailbox {
                    name: name.clone().filter(|n| !n.trim().is_empty()),
                    address: m.address,
                })
            }
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct AttachmentIn {
    filename: String,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_id: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DraftIn {
    from: MailboxIn,
    #[serde(default)]
    to: Vec<MailboxIn>,
    #[serde(default)]
    cc: Vec<MailboxIn>,
    #[serde(default)]
    bcc: Vec<MailboxIn>,
    #[serde(default)]
    subject: String,
    #[serde(default, alias = "textBody")]
    text: String,
    #[serde(default, alias = "htmlBody")]
    html: Option<String>,
    #[serde(default)]
    attachments: Vec<AttachmentIn>,
    #[serde(default)]
    in_reply_to: Option<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    message_id: Option<String>,
    #[serde(default)]
    date: Option<f64>,
    #[serde(default)]
    extra_headers: Vec<(String, String)>,
    #[serde(default)]
    gossip_headers: Vec<String>,
    #[serde(default)]
    legacy_display: bool,
}

impl DraftIn {
    /// Fill `messageId` / `date` if absent (from JS's clock; std has none on wasm32).
    fn finalize(mut self) -> JsResult<Self> {
        if self
            .message_id
            .as_deref()
            .is_none_or(|m| m.trim().is_empty())
        {
            let domain = self
                .from
                .to_mailbox()?
                .domain()
                .unwrap_or_else(|| "sealbox.invalid".into());
            self.message_id = Some(mime::generate_message_id(&domain));
        }
        if self.date.is_none() {
            self.date = Some(now_unix_js() as f64);
        }
        Ok(self)
    }

    fn to_draft(&self) -> JsResult<MessageDraft> {
        let list = |v: &[MailboxIn]| {
            v.iter()
                .map(MailboxIn::to_mailbox)
                .collect::<JsResult<Vec<_>>>()
        };
        let from = self.from.to_mailbox()?;
        let message_id = match &self.message_id {
            Some(m) if !m.trim().is_empty() => m.trim().trim_matches(['<', '>']).to_string(),
            _ => mime::generate_message_id(
                &from.domain().unwrap_or_else(|| "sealbox.invalid".into()),
            ),
        };
        Ok(MessageDraft {
            from,
            to: list(&self.to)?,
            cc: list(&self.cc)?,
            bcc: list(&self.bcc)?,
            subject: self.subject.clone(),
            text_body: self.text.clone(),
            html_body: self.html.clone().filter(|h| !h.is_empty()),
            attachments: self
                .attachments
                .iter()
                .map(|a| Attachment {
                    filename: a.filename.clone(),
                    content_type: a
                        .content_type
                        .clone()
                        .filter(|c| !c.is_empty())
                        .unwrap_or_else(|| "application/octet-stream".into()),
                    data: a.data.clone(),
                    content_id: a.content_id.clone(),
                })
                .collect(),
            in_reply_to: self.in_reply_to.clone().filter(|s| !s.is_empty()),
            references: self.references.clone(),
            message_id,
            date: self.date.map(|d| d as i64).unwrap_or_else(now_unix_js),
            extra_headers: self.extra_headers.clone(),
        })
    }

    fn inner_options(&self) -> InnerOptions {
        InnerOptions {
            gossip_headers: self.gossip_headers.clone(),
            legacy_display: self.legacy_display,
        }
    }
}

fn draft_from(v: JsValue) -> JsResult<DraftIn> {
    from_js(v, "draft")
}

/// Return the draft with `messageId` and `date` filled in (idempotent).
#[wasm_bindgen(js_name = finalizeDraft, unchecked_return_type = "Draft")]
pub fn finalize_draft(
    #[wasm_bindgen(unchecked_param_type = "Draft")] draft: JsValue,
) -> JsResult<JsValue> {
    to_js(&draft_from(draft)?.finalize()?)
}

/// The MIME entity to encrypt (protected headers v1, CRLF). Finalize the draft first.
#[wasm_bindgen(js_name = renderInnerForEncryption)]
pub fn render_inner_for_encryption(
    #[wasm_bindgen(unchecked_param_type = "Draft")] draft: JsValue,
) -> JsResult<Vec<u8>> {
    let d = draft_from(draft)?;
    mime::render_inner_for_encryption(&d.to_draft()?, &d.inner_options())
        .map_err(|e| err("render inner", e))
}

/// Wrap armored ciphertext in RFC 3156 `multipart/encrypted` with protected outer headers
/// (outer Subject `...`). Returns the raw RFC 5322 message.
#[wasm_bindgen(js_name = buildPgpMimeEncrypted)]
pub fn build_pgp_mime_encrypted(
    #[wasm_bindgen(unchecked_param_type = "Draft")] draft: JsValue,
    ciphertext: &str,
) -> JsResult<Vec<u8>> {
    let d = draft_from(draft)?.to_draft()?;
    mime::build_pgp_mime_encrypted(&mime::OuterHeaders::for_protected(&d), ciphertext)
        .map_err(|e| err("build PGP/MIME", e))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedDraftOut {
    #[serde(with = "serde_bytes")]
    raw: Vec<u8>,
    message_id: String,
    draft: DraftIn,
}

/// One-shot: finalize → render inner → encrypt (+sign) → `multipart/encrypted`.
#[wasm_bindgen(js_name = encryptDraft, unchecked_return_type = "EncryptedDraft")]
pub fn encrypt_draft(
    #[wasm_bindgen(unchecked_param_type = "Draft")] draft: JsValue,
    recipients_armored: Vec<String>,
    signer_secret: Option<String>,
) -> JsResult<JsValue> {
    let d = draft_from(draft)?.finalize()?;
    let md = d.to_draft()?;
    let inner = mime::render_inner_for_encryption(&md, &d.inner_options())
        .map_err(|e| err("render inner", e))?;
    let armored = encrypt_bytes(&inner, &recipients_armored, signer_secret.as_deref())?;
    let raw = mime::build_pgp_mime_encrypted(&mime::OuterHeaders::for_protected(&md), &armored)
        .map_err(|e| err("build PGP/MIME", e))?;
    to_js(&EncryptedDraftOut {
        raw,
        message_id: md.message_id.clone(),
        draft: d,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HeadersOut {
    from: Vec<Mailbox>,
    to: Vec<Mailbox>,
    cc: Vec<Mailbox>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_id: Option<String>,
    in_reply_to: Vec<String>,
    references: Vec<String>,
    autocrypt: Vec<String>,
    autocrypt_gossip: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
}

impl From<mime::ParsedHeaders> for HeadersOut {
    fn from(h: mime::ParsedHeaders) -> Self {
        Self {
            from: h.from,
            to: h.to,
            cc: h.cc,
            subject: h.subject,
            date: h.date,
            message_id: h.message_id,
            in_reply_to: h.in_reply_to,
            references: h.references,
            autocrypt: h.autocrypt,
            autocrypt_gossip: h.autocrypt_gossip,
            content_type: h.content_type,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentOut {
    filename: String,
    content_type: String,
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_id: Option<String>,
}

fn attachments_out(v: Vec<Attachment>) -> Vec<AttachmentOut> {
    v.into_iter()
        .map(|a| AttachmentOut {
            filename: a.filename,
            content_type: a.content_type,
            data: a.data,
            content_id: a.content_id,
        })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParsedOut {
    headers: HeadersOut,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attachments: Option<Vec<AttachmentOut>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    signed_part: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    micalg: Option<String>,
}

fn parsed_out(p: mime::ParsedMessage) -> ParsedOut {
    let mut out = ParsedOut {
        headers: p.headers.into(),
        kind: "plain",
        text: None,
        html: None,
        attachments: None,
        ciphertext: None,
        signed_part: None,
        signature: None,
        micalg: None,
    };
    match p.kind {
        MessageKind::Plain(b) => {
            out.text = b.text;
            out.html = b.html;
            out.attachments = Some(attachments_out(b.attachments));
        }
        MessageKind::PgpMimeEncrypted { ciphertext } => {
            out.kind = "pgpMimeEncrypted";
            out.ciphertext = Some(String::from_utf8_lossy(&ciphertext).into_owned());
        }
        MessageKind::PgpMimeSigned {
            signed_part,
            signature,
            micalg,
        } => {
            out.kind = "pgpMimeSigned";
            out.signed_part = Some(signed_part);
            out.signature = Some(String::from_utf8_lossy(&signature).into_owned());
            out.micalg = micalg;
        }
        MessageKind::InlinePgp { armored } => {
            out.kind = "inlinePgp";
            out.ciphertext = Some(armored);
        }
    }
    out
}

/// Parse and classify a raw RFC 5322 message (e.g. Gmail `format=raw`, base64url-decoded).
#[wasm_bindgen(js_name = parseMessage, unchecked_return_type = "ParsedMessage")]
pub fn parse_message(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] raw: JsValue,
) -> JsResult<JsValue> {
    let raw = bytes_of(&raw, "raw message")?;
    let p = mime::parse(&raw).map_err(|e| err("parse", e))?;
    to_js(&parsed_out(p))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProtectedOut {
    present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    from: Vec<Mailbox>,
    to: Vec<Mailbox>,
    cc: Vec<Mailbox>,
    #[serde(skip_serializing_if = "Option::is_none")]
    date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_id: Option<String>,
    in_reply_to: Vec<String>,
    references: Vec<String>,
    autocrypt_gossip: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InnerOut {
    protected_headers: ProtectedOut,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<String>,
    attachments: Vec<AttachmentOut>,
}

fn inner_out(i: mime::DecryptedInner) -> InnerOut {
    let h = i.headers;
    InnerOut {
        protected_headers: ProtectedOut {
            present: h.present,
            subject: h.subject,
            from: h.from,
            to: h.to,
            cc: h.cc,
            date: h.date,
            message_id: h.message_id,
            in_reply_to: h.in_reply_to,
            references: h.references,
            autocrypt_gossip: h.autocrypt_gossip,
        },
        text: i.body.text,
        html: i.body.html,
        attachments: attachments_out(i.body.attachments),
    }
}

/// Parse the plaintext of a decrypted PGP/MIME payload (protected headers + body).
#[wasm_bindgen(js_name = parseDecryptedInner, unchecked_return_type = "DecryptedInner")]
pub fn parse_decrypted_inner(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] raw: JsValue,
) -> JsResult<JsValue> {
    let raw = bytes_of(&raw, "decrypted entity")?;
    let i = mime::parse_decrypted_inner(&raw).map_err(|e| err("parse inner", e))?;
    to_js(&inner_out(i))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecryptedMessageOut {
    headers: HeadersOut,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    #[serde(flatten)]
    inner: InnerOut,
    signatures: Vec<SignatureStatus>,
    signed_by_known_key: bool,
}

/// One-shot receive path: parse → decrypt + verify → parse the protected inner entity.
/// Handles RFC 3156 `multipart/encrypted` and legacy inline PGP.
#[wasm_bindgen(js_name = decryptMessage, unchecked_return_type = "DecryptedMessage")]
pub fn decrypt_message(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] raw: JsValue,
    secrets_armored: Vec<String>,
    known_keys_armored: Vec<String>,
) -> JsResult<JsValue> {
    let raw = bytes_of(&raw, "raw message")?;
    let p = mime::parse(&raw).map_err(|e| err("parse", e))?;
    let (kind, ciphertext) = match p.kind {
        MessageKind::PgpMimeEncrypted { ciphertext } => ("pgpMimeEncrypted", ciphertext),
        MessageKind::InlinePgp { armored } => ("inlinePgp", armored.into_bytes()),
        _ => return Err(JsError::new("not an encrypted message")),
    };
    let d = decrypt_bytes(&ciphertext, &secrets_armored, &known_keys_armored)?;
    let signed_by_known_key = d.signed_by_known_key();
    let inner = if kind == "pgpMimeEncrypted" {
        inner_out(mime::parse_decrypted_inner(&d.plaintext).map_err(|e| err("parse inner", e))?)
    } else {
        InnerOut {
            protected_headers: ProtectedOut {
                present: false,
                subject: None,
                from: vec![],
                to: vec![],
                cc: vec![],
                date: None,
                message_id: None,
                in_reply_to: vec![],
                references: vec![],
                autocrypt_gossip: vec![],
            },
            text: Some(String::from_utf8_lossy(&d.plaintext).into_owned()),
            html: None,
            attachments: vec![],
        }
    };
    let headers: HeadersOut = p.headers.into();
    let subject = inner
        .protected_headers
        .subject
        .clone()
        .filter(|_| inner.protected_headers.present)
        .or_else(|| headers.subject.clone());
    to_js(&DecryptedMessageOut {
        headers,
        kind,
        subject,
        inner,
        signatures: d.signatures,
        signed_by_known_key,
    })
}

// ---------------------------------------------------------------------------------------
// Autocrypt
// ---------------------------------------------------------------------------------------

/// `Autocrypt:` header value for `addr` carrying the minimal form of `publicArmored`
/// (keydata chunked so header folding never exceeds the line limit).
#[wasm_bindgen(js_name = autocryptHeader)]
pub fn autocrypt_header(
    addr: &str,
    public_armored: &str,
    prefer_mutual: Option<bool>,
) -> JsResult<String> {
    let key = public_from(public_armored)?;
    let pref = if prefer_mutual.unwrap_or(true) {
        PreferEncrypt::Mutual
    } else {
        PreferEncrypt::NoPreference
    };
    let h =
        sealbox_crypto::AutocryptHeader::new(addr, pref, &key).map_err(|e| err("autocrypt", e))?;
    Ok(mime::autocrypt_header_value(
        &h.addr,
        pref == PreferEncrypt::Mutual,
        &mime::autocrypt_keydata_b64(&h.keydata),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AutocryptOut {
    addr: String,
    prefer_encrypt: &'static str,
    public_armored: String,
    fingerprint: String,
}

fn autocrypt_out(h: &sealbox_crypto::AutocryptHeader) -> Option<AutocryptOut> {
    let k = h.public_key().ok()?;
    Some(AutocryptOut {
        addr: h.addr.clone(),
        prefer_encrypt: match h.prefer_encrypt {
            PreferEncrypt::Mutual => "mutual",
            PreferEncrypt::NoPreference => "nopreference",
        },
        public_armored: k.to_armored().ok()?,
        fingerprint: k.fingerprint(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AutocryptParseOut {
    valid: Vec<AutocryptOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    for_sender: Option<AutocryptOut>,
}

/// Parse `Autocrypt:` header values (Level 1 rules). With `fromAddr`, `forSender` is the
/// header to use for that sender (only when exactly one valid header matches).
#[wasm_bindgen(js_name = parseAutocryptHeaders, unchecked_return_type = "AutocryptParseResult")]
pub fn parse_autocrypt_headers(
    values: Vec<String>,
    from_addr: Option<String>,
) -> JsResult<JsValue> {
    let valid = values
        .iter()
        .filter_map(|v| sealbox_crypto::AutocryptHeader::parse(v).ok())
        .filter_map(|h| autocrypt_out(&h))
        .collect();
    let for_sender = from_addr.and_then(|from| {
        let refs: Vec<&str> = values.iter().map(String::as_str).collect();
        sealbox_crypto::AutocryptHeader::parse_for_sender(&refs, &from)
            .as_ref()
            .and_then(autocrypt_out)
    });
    to_js(&AutocryptParseOut { valid, for_sender })
}

// ---------------------------------------------------------------------------------------
// Key storage wrapping (Argon2id → XChaCha20-Poly1305)
// ---------------------------------------------------------------------------------------

const WRAP_AAD: &[u8] = b"sealbox-ext-keystore-v1";
/// Argon2id defaults: 64 MiB, 3 passes, 1 lane (the same cost as the desktop profile key).
const WRAP_M_KIB: u32 = 64 * 1024;
const WRAP_T: u32 = 3;
const WRAP_P: u32 = 1;

#[derive(Serialize, Deserialize)]
struct Wrapped {
    v: u8,
    kdf: String,
    m: u32,
    t: u32,
    p: u32,
    salt: String,
    nonce: String,
    ct: String,
}

fn derive_key(passphrase: &str, salt: &[u8], m: u32, t: u32, p: u32) -> JsResult<[u8; 32]> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| err("argon2 params", e))?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| err("argon2", e))?;
    Ok(key)
}

fn random<const N: usize>() -> JsResult<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| err("random", e))?;
    Ok(b)
}

fn wrap_with(plaintext: &str, passphrase: &str, m: u32, t: u32) -> JsResult<String> {
    if passphrase.is_empty() {
        return Err(JsError::new("passphrase must not be empty"));
    }
    let salt = random::<16>()?;
    let nonce = random::<24>()?;
    let mut key = derive_key(passphrase, &salt, m, t, WRAP_P)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    key.zeroize();
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| JsError::new("wrap failed"))?;
    let w = Wrapped {
        v: 1,
        kdf: "argon2id".into(),
        m,
        t,
        p: WRAP_P,
        salt: B64.encode(salt),
        nonce: B64.encode(nonce),
        ct: B64.encode(ct),
    };
    serde_json_string(&w)
}

fn serde_json_string(w: &Wrapped) -> JsResult<String> {
    let v = to_js(w)?;
    js_sys::JSON::stringify(&v)
        .map(String::from)
        .map_err(|_| JsError::new("JSON.stringify failed"))
}

/// Wrap a secret (e.g. an unlocked armored key) under a passphrase:
/// Argon2id (64 MiB, t=3, p=1) → XChaCha20-Poly1305. Returns a JSON `WrappedSecret`.
#[wasm_bindgen(js_name = wrapSecret)]
pub fn wrap_secret(plaintext: &str, passphrase: &str) -> JsResult<String> {
    wrap_with(plaintext, passphrase, WRAP_M_KIB, WRAP_T)
}

/// Like `wrapSecret` with explicit Argon2id cost (memory in KiB, passes). For tests only.
#[wasm_bindgen(js_name = wrapSecretWithCost)]
pub fn wrap_secret_with_cost(
    plaintext: &str,
    passphrase: &str,
    m_kib: u32,
    t: u32,
) -> JsResult<String> {
    wrap_with(plaintext, passphrase, m_kib.max(8 * 1024), t.max(1))
}

/// Inverse of `wrapSecret`. Throws on a wrong passphrase or a tampered envelope.
#[wasm_bindgen(js_name = unwrapSecret)]
pub fn unwrap_secret(wrapped_json: &str, passphrase: &str) -> JsResult<String> {
    let v =
        js_sys::JSON::parse(wrapped_json).map_err(|_| JsError::new("wrapped secret: not JSON"))?;
    let w: Wrapped = from_js(v, "wrapped secret")?;
    if w.v != 1 || w.kdf != "argon2id" {
        return Err(JsError::new("wrapped secret: unsupported format"));
    }
    // Refuse absurd costs from a corrupted / hostile store (DoS), and trivially weak ones.
    if !(8 * 1024..=1024 * 1024).contains(&w.m)
        || !(1..=16).contains(&w.t)
        || !(1..=4).contains(&w.p)
    {
        return Err(JsError::new("wrapped secret: KDF parameters out of range"));
    }
    let salt = B64.decode(&w.salt).map_err(|e| err("salt", e))?;
    let nonce = B64.decode(&w.nonce).map_err(|e| err("nonce", e))?;
    let ct = B64.decode(&w.ct).map_err(|e| err("ciphertext", e))?;
    if nonce.len() != 24 || salt.len() < 16 {
        return Err(JsError::new("wrapped secret: bad salt/nonce"));
    }
    let mut key = derive_key(passphrase, &salt, w.m, w.t, w.p)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    key.zeroize();
    let pt = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ct,
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| JsError::new("wrong passphrase or corrupted key store"))?;
    String::from_utf8(pt).map_err(|e| err("wrapped secret", e))
}
