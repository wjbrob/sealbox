//! sealbox-crypto — OpenPGP key material, encrypt/sign/decrypt/verify, PGP/MIME detached
//! signatures, Autocrypt Level 1 and the passphrase "guest envelope", built on rPGP.
//!
//! Design notes (see `docs/ARCHITECTURE.md`):
//! * Keys are **v4 by default** (Ed25519 + Curve25519 legacy OIDs) for maximum interop with
//!   gpg 2.x, Thunderbird, Proton and OpenPGP.js; RFC 9580 v6 keys are available on request.
//! * Encrypted messages are AES-256 **SEIPDv1 (MDC)** unless *every* recipient advertises
//!   SEIPDv2, in which case AES-256/OCB SEIPDv2 is used. Decryption refuses anything that is
//!   not integrity protected (legacy SED packets) — EFAIL class attacks are rejected up front.
//! * The guest envelope is OpenPGP symmetric encryption (SKESK + SEIPDv1) so that `gpg
//!   --decrypt --passphrase` and OpenPGP.js can both open it.
//! * Post-quantum: with the `pqc` cargo feature, [`KeyProfile::HybridPqc`] identities carry an
//!   extra ML-KEM-768+X25519 encryption subkey (RFC 9980) next to the classical X25519 one, and
//!   encryption to any certificate that has a live PQC subkey uses it. Off in the product build
//!   until gpg/Thunderbird interoperate; see the `keys` module docs and gate G14.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![warn(missing_debug_implementations)]

mod autocrypt;
mod detached;
mod error;
mod guest;
mod keys;
mod message;
mod util;

pub use autocrypt::{
    aggregate_recommendation, effective_date, minimal_key_for_autocrypt, minimal_public_key,
    recommendation, recommendation_with, setup_code_generate, setup_message_create,
    setup_message_open, AutocryptGossip, AutocryptHeader, PeerState, PreferEncrypt, Recommendation,
    AUTOCRYPT_GOSSIP_HEADER, AUTOCRYPT_HEADER, AUTOCRYPT_SETUP_HEADER, AUTOCRYPT_SETUP_MIME_TYPE,
    MAX_HEADER_SIZE as AUTOCRYPT_MAX_HEADER_SIZE,
};
pub use detached::{micalg, sign_detached, sign_detached_binary, verify_detached, MICALG};
pub use error::{Error, Result};
pub use guest::{
    generate_passphrase, guest_decrypt, guest_decrypt_bytes, guest_encrypt, guest_encrypt_with,
    GuestProfile,
};
pub use keys::{Identity, KeyGenOptions, KeyProfile, KeyVersion, PublicKey};
pub use message::{
    decrypt_and_verify, encrypt_and_sign, encrypt_and_sign_armored, encrypt_and_sign_with,
    Decrypted, EncryptOptions, SignatureStatus, MAX_PLAINTEXT_BYTES,
};

/// What the underlying rPGP build supports. Discovered by reading the rPGP 0.21 sources; the
/// booleans are compile-time facts about the crate we link against.
pub mod capabilities {
    /// Version of the `pgp` (rPGP) crate compiled in.
    pub const RPGP_VERSION: &str = pgp::VERSION;
    /// RFC 9580 v6 keys (Ed25519/X25519 new formats) — `KeyVersion::V6`.
    pub const V6_KEYS: bool = true;
    /// RFC 9580 SEIPDv2 (AEAD: OCB/GCM/EAX) encryption containers.
    pub const SEIPD_V2: bool = true;
    /// RFC 9580 Argon2 string-to-key (S2K type 4), only legal in v6 SKESK / SEIPDv2.
    pub const ARGON2_S2K: bool = true;
    /// Post-quantum hybrid encryption (ML-KEM-768+X25519, RFC 9980) — behind the `pqc` cargo
    /// feature. When false, `KeyProfile::HybridPqc` cannot be generated and algorithm-35
    /// subkeys on peer certificates are ignored in favour of their X25519 subkey.
    pub const PQC: bool = cfg!(feature = "pqc");
    /// GnuPG's proprietary OCB-encrypted-data packet (LibrePGP) can be *read*.
    pub const GNUPG_AEAD_READ: bool = true;
}
