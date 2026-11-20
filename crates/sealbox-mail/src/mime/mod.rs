//! RFC 5322 / MIME message construction and parsing, including PGP/MIME
//! (RFC 3156) and the Thunderbird/Enigmail/Autocrypt "protected headers"
//! convention (`protected-headers="v1"`).
//!
//! Nothing here performs cryptography. The caller (sealbox-core via
//! sealbox-crypto) produces ciphertext / signatures; this module produces the
//! exact bytes to encrypt or sign and wraps the results.
//!
//! Typical flows:
//!
//! * **Encrypt**: `render_inner_for_encryption(&draft, &opts)` → encrypt those
//!   bytes → `build_pgp_mime_encrypted(&OuterHeaders::for_protected(&draft), armored)`.
//! * **Sign**: `prepare_signed_part(&draft)` → detached-sign those exact bytes →
//!   `build_pgp_mime_signed(&OuterHeaders::from_draft(&draft), &part, armored_sig, "pgp-sha256")`.
//! * **Receive**: `parse(raw)` → on `PgpMimeEncrypted` decrypt the ciphertext →
//!   `parse_decrypted_inner(plaintext)` to recover the protected Subject and body.

mod build;
mod headers;
mod parse;
mod types;

pub use build::{
    build_pgp_mime_encrypted, build_pgp_mime_signed, build_plain, prepare_signed_part,
    render_inner_for_encryption, InnerOptions, OuterHeaders, PROTECTED_SUBJECT_PLACEHOLDER,
};
pub use headers::{
    autocrypt_gossip_header_value, autocrypt_header_value, autocrypt_keydata_b64, fold_header,
    parse_autocrypt_header, sanitize_header_value, unfold_header_value, AutocryptHeader,
    SOFT_LINE_LIMIT,
};
pub use parse::{
    parse, parse_decrypted_inner, split_entity, split_multipart, DecryptedInner, MessageKind,
    ParsedHeaders, ParsedMessage, PlainBody, ProtectedHeaders,
};
pub use types::{generate_message_id, now_unix, Attachment, Mailbox, MessageDraft};
