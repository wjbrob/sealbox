//! Fixed parameters shared by the fuzz harnesses (`fuzz/src/lib.rs`) and the seed generator
//! (`fuzz/seedgen`, which pulls this file in with `#[path]`), so that the committed seeds
//! decrypt with exactly what the harness uses. Everything here is TEST material: the fuzz
//! identities live in `fuzz/seeds/keys/` and are public on purpose (gitleaks allow-list:
//! `.gitleaks.toml`).

/// User ID e-mail of the v4 fuzz identity (the recipient most seeds are encrypted to).
pub const IDENTITY_EMAIL: &str = "fuzz-identity@sealbox.test";
/// User ID e-mail of the v6 (RFC 9580) fuzz identity (SEIPDv2 / v6 PKESK seeds).
pub const IDENTITY_V6_EMAIL: &str = "fuzz-identity-v6@sealbox.test";
/// User ID e-mail of the fuzz peer (the sender: signs the seeds, is a known signer).
pub const PEER_EMAIL: &str = "fuzz-peer@sealbox.test";

/// File names under `fuzz/seeds/keys/`.
pub const IDENTITY_SECRET_FILE: &str = "fuzz-identity.sec.asc";
pub const IDENTITY_PUBLIC_FILE: &str = "fuzz-identity.pub.asc";
pub const IDENTITY_V6_SECRET_FILE: &str = "fuzz-identity-v6.sec.asc";
pub const IDENTITY_V6_PUBLIC_FILE: &str = "fuzz-identity-v6.pub.asc";
pub const PEER_SECRET_FILE: &str = "fuzz-peer.sec.asc";
pub const PEER_PUBLIC_FILE: &str = "fuzz-peer.pub.asc";

/// Passphrase of every guest-envelope seed (and of the harness's wrapped guest modes).
pub const GUEST_PASSPHRASE: &str = "fuzz-guest-passphrase";
/// Setup Code of the Autocrypt Setup Message seeds (nine blocks of four digits).
pub const SETUP_CODE: &str = "1234-5678-9012-3456-7890-1234-5678-9012-3456";
/// Domain handed to `parse_autoconfig_xml` (it only ends up in error texts / display name).
pub const AUTOCONFIG_DOMAIN: &str = "example.com";
/// The data every detached-signature seed of `pgp_decrypt` mode 3 is made over.
pub const DETACHED_SIGNED_DATA: &[u8] =
    b"Content-Type: text/plain; charset=utf-8\r\n\r\nsigned by the fuzz peer\r\n";

/// Coded iteration count for the iterated+salted S2K of the harness's *wrapped* guest modes:
/// 0 decodes to 1024 octets, so a wrapped execution costs microseconds instead of the
/// production profile's 65 MB of hashing (the real profiles are covered by raw seeds).
pub const WRAP_S2K_COUNT: u8 = 0;
/// Fixed salt of that S2K (determinism: libFuzzer wants the same input to take the same path).
pub const WRAP_S2K_SALT: [u8; 8] = *b"fuzzsalt";

/// First byte of every `pgp_decrypt` input selects the mode (`byte % 4`); the rest is the payload.
pub mod pgp_mode {
    /// Payload is a complete (armored or binary) OpenPGP message.
    pub const RAW: u8 = 0;
    /// Payload is the *plaintext packet stream* inside a SEIPDv1 container whose session key
    /// is PKESK-encrypted to the v4 fuzz identity — reaches literal/compressed/one-pass
    /// signature parsing, decompression and signature verification directly.
    pub const WRAP_V1: u8 = 1;
    /// Same, inside a SEIPDv2 (AES-256/OCB) container keyed by a v6 PKESK to the v6 identity.
    pub const WRAP_V2: u8 = 2;
    /// Payload is an (armored or binary) detached signature over [`super::DETACHED_SIGNED_DATA`].
    pub const DETACHED: u8 = 3;
}

/// First byte of every `guest_decrypt` input selects the mode (`byte % 4`).
pub mod guest_mode {
    /// Payload is a complete guest envelope (armored or binary), passphrase
    /// [`super::GUEST_PASSPHRASE`].
    pub const RAW: u8 = 0;
    /// Payload is the plaintext packet stream inside SKESKv4 (cheap S2K) + SEIPDv1.
    pub const WRAP_V1: u8 = 1;
    /// Payload is the plaintext packet stream inside SKESKv6 (cheap S2K) + SEIPDv2/OCB.
    pub const WRAP_V2: u8 = 2;
    /// Payload is the text of an Autocrypt Setup Message, opened with [`super::SETUP_CODE`].
    pub const SETUP_MESSAGE: u8 = 3;
}

/// First byte of every `autocrypt_header` input selects the mode (`byte % 3`).
pub mod autocrypt_mode {
    /// Payload is an `Autocrypt:` header value (UTF-8, lossily decoded).
    pub const HEADER: u8 = 0;
    /// Payload is an `Autocrypt-Gossip:` header value.
    pub const GOSSIP: u8 = 1;
    /// Payload is raw `keydata` (a binary or armored transferable public / secret key).
    pub const KEYDATA: u8 = 2;
}
