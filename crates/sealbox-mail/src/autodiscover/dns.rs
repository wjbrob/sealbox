//! RFC 6186 SRV lookups and MX-based provider inference (hickory-resolver).

use std::time::Duration;

use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;

use super::{table, Endpoint, ServerConfig};
use crate::error::DiscoverError;
use crate::Security;

fn resolver(timeout: Duration) -> Result<TokioResolver, DiscoverError> {
    crate::tls::ensure_crypto_provider();
    let mut builder =
        TokioResolver::builder_tokio().map_err(|e| DiscoverError::Dns(e.to_string()))?;
    let opts = builder.options_mut();
    opts.timeout = timeout
        .max(Duration::from_secs(1))
        .min(Duration::from_secs(10));
    opts.attempts = 2;
    builder
        .build()
        .map_err(|e| DiscoverError::Dns(e.to_string()))
}

async fn srv_best(resolver: &TokioResolver, name: &str) -> Option<(String, u16)> {
    let lookup = resolver.srv_lookup(name).await.ok()?;
    let mut records: Vec<(u16, u16, String, u16)> = lookup
        .answers()
        .iter()
        .filter_map(|r| match &r.data {
            RData::SRV(srv) => {
                let target = srv.target.to_utf8().trim_end_matches('.').to_owned();
                // RFC 2782: a target of "." means "service decidedly not available".
                if target.is_empty() || srv.port == 0 {
                    None
                } else {
                    Some((srv.priority, u16::MAX - srv.weight, target, srv.port))
                }
            }
            _ => None,
        })
        .collect();
    records.sort();
    records
        .into_iter()
        .next()
        .map(|(_, _, host, port)| (host, port))
}

/// RFC 6186: `_imaps._tcp` / `_imap._tcp` and `_submissions._tcp` /
/// `_submission._tcp`. Either half may be `None`.
pub async fn srv_endpoints(
    domain: &str,
    timeout: Duration,
) -> Result<(Option<Endpoint>, Option<Endpoint>), DiscoverError> {
    let resolver = resolver(timeout)?;
    let run = async {
        let imap = match srv_best(&resolver, &format!("_imaps._tcp.{domain}.")).await {
            Some((host, port)) => Some(Endpoint::new(host, port, Security::Tls)),
            None => srv_best(&resolver, &format!("_imap._tcp.{domain}."))
                .await
                .map(|(host, port)| Endpoint::new(host, port, Security::StartTls)),
        };
        let smtp = match srv_best(&resolver, &format!("_submissions._tcp.{domain}.")).await {
            Some((host, port)) => Some(Endpoint::new(host, port, Security::Tls)),
            None => srv_best(&resolver, &format!("_submission._tcp.{domain}."))
                .await
                .map(|(host, port)| Endpoint::new(host, port, Security::StartTls)),
        };
        (imap, smtp)
    };
    tokio::time::timeout(timeout * 4, run)
        .await
        .map_err(|_| DiscoverError::Dns(format!("SRV lookup for {domain} timed out")))
}

/// MX exchange hosts for `domain`, lowest preference first.
pub async fn mx_hosts(domain: &str, timeout: Duration) -> Result<Vec<String>, DiscoverError> {
    let resolver = resolver(timeout)?;
    let lookup = tokio::time::timeout(timeout * 2, resolver.mx_lookup(format!("{domain}.")))
        .await
        .map_err(|_| DiscoverError::Dns(format!("MX lookup for {domain} timed out")))?
        .map_err(|e| DiscoverError::Dns(e.to_string()))?;
    let mut records: Vec<(u16, String)> = lookup
        .answers()
        .iter()
        .filter_map(|r| match &r.data {
            RData::MX(mx) => Some((
                mx.preference,
                mx.exchange
                    .to_utf8()
                    .trim_end_matches('.')
                    .to_ascii_lowercase(),
            )),
            _ => None,
        })
        .collect();
    records.sort();
    Ok(records.into_iter().map(|(_, h)| h).collect())
}

/// Infer a hosted provider (Google Workspace, Microsoft 365, …) from MX records.
pub async fn mx_provider(
    domain: &str,
    timeout: Duration,
) -> Result<Option<ServerConfig>, DiscoverError> {
    let hosts = mx_hosts(domain, timeout).await?;
    Ok(hosts.iter().find_map(|h| table::provider_for_mx(h)))
}
