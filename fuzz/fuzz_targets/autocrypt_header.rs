//! Fuzz target `autocrypt_header`: Autocrypt Level 1 header values and the keys they carry —
//! `sealbox_crypto::AutocryptHeader::{parse, parse_for_sender}`, `AutocryptGossip::parse`,
//! `sealbox_mail::mime::parse_autocrypt_header` (the second parser, used by recovery), the
//! transferable-public-key parser behind `keydata` (`PublicKey::from_bytes`) and the
//! secret-key import used for setup messages (`Identity::from_secret_bytes`).
//!
//! Input = one mode byte (`% 3`, see `fuzz/src/params.rs::autocrypt_mode`) + payload:
//! HEADER / GOSSIP — a header value (UTF-8, lossily decoded); KEYDATA — raw key bytes.
//!
//! Oracles beyond "no panic": what we render from a parsed header must parse back to the same
//! header (we re-send peers' keys as gossip), and the minimal key we derive from any accepted
//! certificate must be readable again. Every accepted encryption-capable key is also encrypted
//! to once, because a reply to a malicious Autocrypt key runs exactly that code.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sealbox_crypto::{
    encrypt_and_sign, minimal_public_key, sign_detached, AutocryptGossip, AutocryptHeader,
    Identity, PreferEncrypt, PublicKey, AUTOCRYPT_MAX_HEADER_SIZE,
};
use sealbox_fuzz::{autocrypt_mode, split_mode, PEER_EMAIL};

fuzz_target!(|data: &[u8]| {
    let (mode, payload) = split_mode(data, 3);
    match mode {
        autocrypt_mode::HEADER => header(payload),
        autocrypt_mode::GOSSIP => gossip(payload),
        _ => keydata(payload),
    }
});

fn header(payload: &[u8]) {
    let text = String::from_utf8_lossy(payload);
    let _ = sealbox_mail::mime::parse_autocrypt_header(&text);
    let _ = AutocryptHeader::parse_for_sender(&[&text, &text], PEER_EMAIL);
    if let Ok(h) = AutocryptHeader::parse(&text) {
        let _ = AutocryptHeader::parse_for_sender(&[&text], &h.addr);
        for rendered in [h.render(), h.render_unfolded()] {
            if rendered.len() > AUTOCRYPT_MAX_HEADER_SIZE {
                continue;
            }
            match AutocryptHeader::parse(&rendered) {
                Ok(again) => assert_eq!(again, h, "Autocrypt header changed by render → parse"),
                Err(e) => panic!("rendered Autocrypt header does not parse again: {e}"),
            }
        }
        if let Ok(pk) = h.public_key() {
            use_key(&pk, Some(&h.addr));
        }
    }
}

fn gossip(payload: &[u8]) {
    let text = String::from_utf8_lossy(payload);
    if let Ok(g) = AutocryptGossip::parse(&text) {
        let rendered = g.render();
        if rendered.len() <= AUTOCRYPT_MAX_HEADER_SIZE {
            match AutocryptGossip::parse(&rendered) {
                Ok(again) => assert_eq!(again, g, "Autocrypt-Gossip changed by render → parse"),
                Err(e) => panic!("rendered Autocrypt-Gossip does not parse again: {e}"),
            }
        }
        if let Ok(pk) = g.public_key() {
            use_key(&pk, Some(&g.addr));
        }
    }
}

fn keydata(payload: &[u8]) {
    if let Ok(pk) = PublicKey::from_bytes(payload) {
        use_key(&pk, None);
        let addr = pk
            .primary_email()
            .unwrap_or_else(|| "fuzz@sealbox.test".to_owned());
        if let Ok(h) = AutocryptHeader::new(&addr, PreferEncrypt::Mutual, &pk) {
            let rendered = h.render();
            if rendered.len() <= AUTOCRYPT_MAX_HEADER_SIZE {
                match AutocryptHeader::parse(&rendered) {
                    Ok(again) => assert_eq!(again, h, "built Autocrypt header does not round-trip"),
                    Err(e) => panic!("Autocrypt header built from an accepted key fails: {e}"),
                }
            }
        }
    }
    // Setup-message import: the secret key becomes one of our identities and signs mail.
    if let Ok(id) = Identity::from_secret_bytes(payload, None) {
        let _ = id.fingerprint();
        let _ = id.emails();
        let _ = sign_detached(b"probe", &id);
        use_key(&id.public(), None);
    }
}

/// Everything the product does with a peer certificate it accepted.
fn use_key(pk: &PublicKey, addr: Option<&str>) {
    let _ = pk.fingerprint();
    let _ = pk.key_id();
    let _ = pk.emails();
    let _ = pk.expires_at();
    let _ = pk.is_revoked();
    let _ = pk.supports_seipd_v2();
    let _ = pk.to_armored();
    if let Ok(minimal) = minimal_public_key(pk, addr) {
        if let Ok(bytes) = minimal.to_bytes() {
            if let Err(e) = PublicKey::from_bytes(&bytes) {
                panic!("minimal key derived from an accepted certificate does not parse: {e}");
            }
        }
    }
    if pk.encryption_capable() {
        let _ = encrypt_and_sign(b"probe", &[pk], None);
    }
}
