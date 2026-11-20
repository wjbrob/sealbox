//! Fuzz target `pgp_decrypt`: OpenPGP message decryption + verification
//! (`sealbox_crypto::decrypt_and_verify`, the call behind every PGP/MIME and inline-PGP mail)
//! and detached-signature verification (`verify_detached`, RFC 3156 `multipart/signed`).
//!
//! Input = one mode byte (`% 4`, see `fuzz/src/params.rs::pgp_mode`) + payload:
//! * RAW — the payload is a whole message, armored or binary, decrypted with the v4 and v6
//!   fuzz identities and verified against the fuzz peer + identities;
//! * WRAP_V1 / WRAP_V2 — the payload is the decrypted packet stream: the harness wraps it in a
//!   valid PKESK + SEIPDv1 (v4 identity) or v6 PKESK + SEIPDv2/OCB (v6 identity), which is
//!   what any sender holding our public key can produce — so the fuzzer drives literal,
//!   compressed, one-pass-signature and signature parsing, decompression and verification;
//! * DETACHED — the payload is a detached signature over a fixed text.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sealbox_crypto::{decrypt_and_verify, verify_detached};
use sealbox_fuzz::{fixtures, pgp_mode, split_mode, DETACHED_SIGNED_DATA};

fuzz_target!(|data: &[u8]| {
    let fx = fixtures();
    let decryptors = fx.decryptors();
    let known = fx.known_signers();
    let (mode, payload) = split_mode(data, 4);
    match mode {
        pgp_mode::RAW => {
            let _ = decrypt_and_verify(payload, &decryptors, &known);
        }
        pgp_mode::WRAP_V1 => {
            if let Some(msg) = fx.wrap_pkesk_seipd_v1(payload) {
                let _ = decrypt_and_verify(&msg, &decryptors, &known);
            }
        }
        pgp_mode::WRAP_V2 => {
            if let Some(msg) = fx.wrap_pkesk_seipd_v2(payload) {
                let _ = decrypt_and_verify(&msg, &decryptors, &known);
            }
        }
        _ => {
            let _ = verify_detached(DETACHED_SIGNED_DATA, payload, &known);
        }
    }
});
