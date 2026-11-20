//! Error type for sealbox-crypto.

/// Everything this crate can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A low-level OpenPGP error from rPGP.
    #[error("OpenPGP error: {0}")]
    Pgp(#[from] pgp::errors::Error),

    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// The key could not be parsed, or its self-signatures do not verify.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// A secret key is passphrase protected and no (or the wrong) passphrase was given.
    #[error("secret key is locked: passphrase required or wrong")]
    KeyLocked,

    #[error("key {fingerprint} has no usable encryption subkey (expired, revoked or missing)")]
    NoEncryptionKey { fingerprint: String },

    #[error("identity has no signing-capable key")]
    NoSigningKey,

    #[error("at least one recipient is required")]
    NoRecipients,

    /// `decrypt_and_verify` was handed something that is not an encrypted OpenPGP message.
    #[error("message is not encrypted")]
    NotEncrypted,

    /// The ciphertext is a legacy Symmetrically-Encrypted-Data packet without MDC/AEAD.
    /// We refuse to decrypt these (EFAIL / malleability).
    #[error("message is not integrity protected (no MDC/AEAD) — refusing to decrypt")]
    MissingIntegrityProtection,

    /// MDC or AEAD tag verification failed: ciphertext was modified.
    #[error("integrity check failed: ciphertext was tampered with")]
    IntegrityFailure,

    /// None of the supplied identities can decrypt this message.
    #[error("none of the supplied keys can decrypt this message")]
    NoDecryptionKey,

    /// Symmetric decryption failed: wrong passphrase or tampered message.
    #[error("wrong passphrase or corrupt message")]
    BadPassphrase,

    /// The decrypted plaintext could not be parsed as an OpenPGP message.
    #[error("corrupt message: {0}")]
    Corrupt(String),

    /// The message would decrypt (and decompress) to more than `limit` bytes — a decompression
    /// bomb or an absurdly large message. Nothing is returned; see
    /// [`crate::MAX_PLAINTEXT_BYTES`].
    #[error("message plaintext exceeds the {limit}-byte limit")]
    TooLarge { limit: u64 },

    #[error("invalid Autocrypt header: {0}")]
    InvalidAutocryptHeader(String),

    #[error("invalid Autocrypt setup code (expected 36 digits as 9 blocks of 4)")]
    InvalidSetupCode,

    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The operation needs a cargo feature this build was compiled without — today only the
    /// post-quantum hybrid key profile (`KeyProfile::HybridPqc`), which needs `pqc`.
    #[error("not supported by this build: {0}")]
    Unsupported(String),

    #[error("utf-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
