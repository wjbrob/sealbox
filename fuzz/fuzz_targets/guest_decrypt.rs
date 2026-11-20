//! Fuzz target `guest_decrypt`: the passphrase "guest envelope" (`sealbox_crypto::
//! guest_decrypt_bytes`, OpenPGP SKESK + SEIPD) and the Autocrypt Setup Message
//! (`setup_message_open`, which opens such an envelope and imports the secret key inside).
//!
//! Input = one mode byte (`% 4`, see `fuzz/src/params.rs::guest_mode`) + payload:
//! * RAW — a whole envelope (armored or binary), passphrase `GUEST_PASSPHRASE`; the seeds
//!   include both production profiles (iterated S2K count 255, and Argon2id 64 MiB);
//! * WRAP_V1 / WRAP_V2 — the payload is the decrypted packet stream, wrapped by the harness in
//!   SKESKv4 + SEIPDv1 or SKESKv6 + SEIPDv2/OCB (cheap S2K, same passphrase);
//! * SETUP_MESSAGE — the payload is the text of a setup message, opened with `SETUP_CODE`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sealbox_crypto::{guest_decrypt_bytes, setup_message_open};
use sealbox_fuzz::{fixtures, guest_mode, split_mode, GUEST_PASSPHRASE, SETUP_CODE};

fuzz_target!(|data: &[u8]| {
    let fx = fixtures();
    let (mode, payload) = split_mode(data, 4);
    match mode {
        guest_mode::RAW => {
            let _ = guest_decrypt_bytes(payload, GUEST_PASSPHRASE);
        }
        guest_mode::WRAP_V1 => {
            if let Some(msg) = fx.wrap_skesk_seipd_v1(payload) {
                let _ = guest_decrypt_bytes(&msg, GUEST_PASSPHRASE);
            }
        }
        guest_mode::WRAP_V2 => {
            if let Some(msg) = fx.wrap_skesk_seipd_v2(payload) {
                let _ = guest_decrypt_bytes(&msg, GUEST_PASSPHRASE);
            }
        }
        _ => {
            let text = String::from_utf8_lossy(payload);
            let _ = setup_message_open(&text, SETUP_CODE);
        }
    }
});
