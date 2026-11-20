//! Shared rustls client configuration (webpki roots, ring provider).

use std::sync::{Arc, OnceLock};

use rustls::RootCertStore;
use rustls_pki_types::ServerName;

/// Make `ring` the process-wide default crypto provider (idempotent).
///
/// Every TLS user in this crate (tokio-rustls for IMAP, lettre for SMTP,
/// reqwest for autoconfig/OAuth, hickory for DNS) calls this first, so that
/// `rustls::ClientConfig::builder()` never has to guess between providers
/// when a downstream crate happens to enable `aws-lc-rs` as well.
pub fn ensure_crypto_provider() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        // Err means another provider was installed first; that is fine too.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A process-wide rustls client config trusting the Mozilla root store.
pub fn client_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            ensure_crypto_provider();
            let roots: RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// A `TlsConnector` built from [`client_config`].
pub fn connector() -> tokio_rustls::TlsConnector {
    tokio_rustls::TlsConnector::from(client_config())
}

/// Parse a host name into the owned `ServerName` rustls wants.
pub fn server_name(host: &str) -> Option<ServerName<'static>> {
    ServerName::try_from(host.to_owned()).ok()
}
