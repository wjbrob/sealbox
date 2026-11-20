//! Bridge smoke tests and the key-preview call. Everything mail-related lives in
//! [`crate::api::engine`]; this module exists so `main.dart` can prove the bridge works
//! before an engine is opened (the "[sealbox] bridge OK" line the G9 gate greps for).

use anyhow::Result;
use sealbox_core::sealbox_crypto::Identity;

/// Version of the Rust side the app is linked against (`<bridge crate>+core<engine crate>`).
#[flutter_rust_bridge::frb(sync)]
pub fn sealbox_version() -> String {
    format!("{}+core", env!("CARGO_PKG_VERSION"))
}

/// Smoke-test call: proves strings cross the bridge in both directions.
#[flutter_rust_bridge::frb(sync)]
pub fn greet(name: String) -> String {
    format!("Hello, {name}! Sealbox core says hi.")
}

/// What the UI needs to show for a freshly generated identity key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPreview {
    /// Primary-key fingerprint, upper-case hex (40 chars for a v4 key).
    pub fingerprint: String,
    /// Key creation time, seconds since the Unix epoch.
    pub created_at: i64,
}

/// Generates a real OpenPGP key pair through `sealbox-crypto` (the same code path the
/// engine uses for account identities: Ed25519 primary, Curve25519 encryption subkey, user
/// id `name <email>`) and returns its fingerprint.
///
/// The secret key is dropped on return: this is a *preview* used to exercise the bridge.
/// Persistent identity keys are created by `Engine::add_account`.
pub fn generate_identity_preview(name: String, email: String) -> Result<IdentityPreview> {
    let id = Identity::generate(name.trim(), email.trim())?;
    Ok(IdentityPreview {
        fingerprint: id.fingerprint(),
        created_at: id.created_at().timestamp(),
    })
}

#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    // NOT `setup_default_user_utils()`: that installs the platform console logger (android_logger /
    // os_log) at `Trace`, and `async-imap` logs the whole IMAP conversation at that level — the
    // `LOGIN "<user>" "<password>"` line, XOAUTH2 bearers and raw mail ended up in logcat
    // (found by the G13 review, docs/THREAT_MODEL.md R2). Warnings and errors only, on every
    // platform; `SEALBOX_LOG=trace` on a developer machine is an explicit opt-in to protocol traces.
    flutter_rust_bridge::setup_log_to_console(log::LevelFilter::Warn);
    flutter_rust_bridge::setup_backtrace();
    // Engine tracing to stderr, filtered by SEALBOX_LOG (default: warnings and errors). The
    // desktop review loop greps the app's stderr for error lines, so keep this quiet by default.
    let filter = tracing_subscriber::EnvFilter::try_from_env("SEALBOX_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_greet() {
        assert_eq!(sealbox_version(), "0.1.0+core");
        assert_eq!(greet("Ada".into()), "Hello, Ada! Sealbox core says hi.");
    }

    #[test]
    fn identity_preview_is_a_real_v4_fingerprint() {
        let p = generate_identity_preview("Alice".into(), "alice@sealbox.test".into()).unwrap();
        assert_eq!(
            p.fingerprint.len(),
            40,
            "v4 fingerprint is 20 bytes = 40 hex chars"
        );
        assert!(p.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(p.fingerprint, p.fingerprint.to_uppercase());
        assert!(
            p.created_at > 1_700_000_000,
            "created_at must be a current unix time"
        );
    }

    #[test]
    fn identity_preview_is_fresh_randomness_each_call() {
        let a = generate_identity_preview("A".into(), "a@sealbox.test".into()).unwrap();
        let b = generate_identity_preview("A".into(), "a@sealbox.test".into()).unwrap();
        assert_ne!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn identity_preview_rejects_bad_email() {
        assert!(generate_identity_preview("A".into(), "not-an-email".into()).is_err());
    }
}
