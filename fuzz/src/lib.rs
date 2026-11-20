//! Shared fixtures for the Sealbox libFuzzer harnesses (gate G13, `scripts/gate_security.sh`).
//!
//! Every harness feeds attacker-controlled bytes to the *real* parser entry points that the
//! product runs on untrusted input (see `docs/THREAT_MODEL.md`, "Attack surface"). A panic,
//! abort, sanitizer report, leak, out-of-memory or timeout is a bug; an `Err` is the expected
//! outcome for garbage, so harnesses discard results instead of unwrapping them.
//!
//! The fixed fuzz identities (`fuzz/seeds/keys/`, TEST keys made once by `fuzz/seedgen`) are
//! compiled in with `include_str!`, so the committed seed messages decrypt and verify here.
//! The *wrapped* modes build a valid PKESK/SKESK + SEIPD container around the fuzz input, so
//! that the fuzzer controls the decrypted packet stream directly (literal, compressed,
//! one-pass-signature and signature packets, decompression, verification) instead of having
//! to forge ciphertext — the plaintext a malicious sender can always produce by encrypting to
//! the victim's public key. `cargo run --manifest-path fuzz/seedgen/Cargo.toml -- --check`
//! replays every seed through the same code (`fixtures.rs`) and checks that it reaches the
//! success path it was made for.

#![forbid(unsafe_code)]

mod fixtures;
mod params;

use std::sync::OnceLock;

pub use fixtures::{split_mode, Fixtures};
pub use params::*;

const IDENTITY_SECRET: &str = include_str!("../seeds/keys/fuzz-identity.sec.asc");
const IDENTITY_V6_SECRET: &str = include_str!("../seeds/keys/fuzz-identity-v6.sec.asc");
const PEER_PUBLIC: &str = include_str!("../seeds/keys/fuzz-peer.pub.asc");

/// The process-wide fixtures. Panics only if the committed fuzz keys are broken (a setup
/// error, never a finding about the fuzz input).
pub fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        Fixtures::from_armored(IDENTITY_SECRET, IDENTITY_V6_SECRET, PEER_PUBLIC)
            .unwrap_or_else(|e| panic!("fuzz fixtures (fuzz/seeds/keys/) are broken: {e}"))
    })
}
