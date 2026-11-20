//! Fuzz target `mime_parse`: the MIME layer of the receive pipeline — what
//! `sealbox-core::sync::process_message` runs on every message fetched over IMAP:
//! `sealbox_mail::mime::parse` → per kind: PGP/MIME decrypt (`decrypt_and_verify`), RFC 3156
//! `multipart/signed` detached verification (`verify_detached`), inline PGP → the inner entity
//! through `parse_decrypted_inner` (protected headers, gossip). The input is also parsed as a
//! decrypted inner entity on its own (anyone can encrypt one to us) and run through the RFC 2046
//! splitter (`split_multipart` / `split_entity`) with its first line as the boundary.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sealbox_crypto::{decrypt_and_verify, verify_detached, AutocryptGossip, AutocryptHeader};
use sealbox_mail::mime::{self, MessageKind};

fuzz_target!(|data: &[u8]| {
    let fx = sealbox_fuzz::fixtures();
    let decryptors = fx.decryptors();
    let known = fx.known_signers();

    if let Ok(msg) = mime::parse(data) {
        let h = &msg.headers;
        if let Some(from) = h.from.first() {
            let values: Vec<&str> = h.autocrypt.iter().map(String::as_str).collect();
            let _ = AutocryptHeader::parse_for_sender(&values, &from.address);
        }
        match &msg.kind {
            MessageKind::PgpMimeEncrypted { ciphertext } => {
                if let Ok(dec) = decrypt_and_verify(ciphertext, &decryptors, &known) {
                    inner(&dec.plaintext);
                }
            }
            MessageKind::PgpMimeSigned {
                signed_part,
                signature,
                ..
            } => {
                let _ = verify_detached(signed_part, signature, &known);
                inner(signed_part);
            }
            MessageKind::InlinePgp { armored } => {
                let _ = decrypt_and_verify(armored.as_bytes(), &decryptors, &known);
            }
            MessageKind::Plain(body) => {
                let _ = body.is_empty();
            }
        }
    }

    inner(data);

    if let Some(pos) = data.iter().position(|&b| b == b'\n') {
        let boundary = String::from_utf8_lossy(&data[..pos]);
        let boundary = boundary.trim();
        if !boundary.is_empty() && boundary.len() <= 70 {
            for part in mime::split_multipart(&data[pos + 1..], boundary) {
                let _ = mime::split_entity(part);
            }
        }
    }
});

/// What the pipeline does with decrypted / signed inner entities.
fn inner(plaintext: &[u8]) {
    if let Ok(inner) = mime::parse_decrypted_inner(plaintext) {
        for g in &inner.headers.autocrypt_gossip {
            let _ = AutocryptGossip::parse(g);
        }
    }
}
