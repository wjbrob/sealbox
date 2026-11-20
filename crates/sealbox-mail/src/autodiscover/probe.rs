//! Last resort: common host names with a TCP (+TLS) probe.

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use super::{AuthHint, ConfigSource, Endpoint, ServerConfig, UsernameForm};
use crate::error::DiscoverError;
use crate::{tls, Security};

/// Service family for greeting checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    Imap,
    Smtp,
}

/// Probe one endpoint: TCP connect, then either a verified TLS handshake
/// (implicit TLS) or a plausible plaintext greeting (STARTTLS / plain).
pub async fn probe_endpoint(ep: &Endpoint, service: Service, timeout: Duration) -> bool {
    let fut = async {
        let tcp = TcpStream::connect((ep.host.as_str(), ep.port)).await.ok()?;
        match ep.security {
            Security::Tls => {
                let name = tls::server_name(&ep.host)?;
                let mut stream = tls::connector().connect(name, tcp).await.ok()?;
                let mut buf = [0u8; 64];
                let n = stream.read(&mut buf).await.ok()?;
                Some(greeting_ok(&buf[..n], service))
            }
            Security::StartTls | Security::Plain => {
                let mut tcp = tcp;
                let mut buf = [0u8; 64];
                let n = tcp.read(&mut buf).await.ok()?;
                Some(greeting_ok(&buf[..n], service))
            }
        }
    };
    matches!(tokio::time::timeout(timeout, fut).await, Ok(Some(true)))
}

fn greeting_ok(bytes: &[u8], service: Service) -> bool {
    match service {
        Service::Imap => bytes.starts_with(b"* OK") || bytes.starts_with(b"* PREAUTH"),
        Service::Smtp => bytes.starts_with(b"220"),
    }
}

/// Try `imap.`/`mail.` and `smtp.`/`mail.` hosts on the standard ports.
pub async fn guess(domain: &str, timeout: Duration) -> Result<ServerConfig, DiscoverError> {
    let imap_candidates = [
        Endpoint::new(format!("imap.{domain}"), 993, Security::Tls),
        Endpoint::new(format!("mail.{domain}"), 993, Security::Tls),
        Endpoint::new(domain.to_owned(), 993, Security::Tls),
        Endpoint::new(format!("imap.{domain}"), 143, Security::StartTls),
        Endpoint::new(format!("mail.{domain}"), 143, Security::StartTls),
    ];
    let smtp_candidates = [
        Endpoint::new(format!("smtp.{domain}"), 465, Security::Tls),
        Endpoint::new(format!("mail.{domain}"), 465, Security::Tls),
        Endpoint::new(format!("smtp.{domain}"), 587, Security::StartTls),
        Endpoint::new(format!("mail.{domain}"), 587, Security::StartTls),
        Endpoint::new(domain.to_owned(), 465, Security::Tls),
        Endpoint::new(domain.to_owned(), 587, Security::StartTls),
    ];

    let imap_results = futures_util::future::join_all(
        imap_candidates
            .iter()
            .map(|ep| probe_endpoint(ep, Service::Imap, timeout)),
    );
    let smtp_results = futures_util::future::join_all(
        smtp_candidates
            .iter()
            .map(|ep| probe_endpoint(ep, Service::Smtp, timeout)),
    );
    let (imap_results, smtp_results) = tokio::join!(imap_results, smtp_results);

    let imap = imap_candidates
        .iter()
        .zip(imap_results)
        .find(|(_, ok)| *ok)
        .map(|(ep, _)| ep.clone())
        .ok_or_else(|| DiscoverError::NotFound(domain.to_owned()))?;
    let smtp = smtp_candidates
        .iter()
        .zip(smtp_results)
        .find(|(_, ok)| *ok)
        .map(|(ep, _)| ep.clone())
        .ok_or_else(|| DiscoverError::NotFound(domain.to_owned()))?;

    Ok(ServerConfig {
        imap,
        smtp,
        auth_hint: AuthHint::Password,
        display_name: domain.to_owned(),
        source: ConfigSource::Guess,
        username: UsernameForm::FullAddress,
    })
}
