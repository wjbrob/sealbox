//! Provider autodiscovery: built-in table → Mozilla ISPDB → domain autoconfig
//! → RFC 6186 SRV → MX-based provider inference → host guesses with probing.

mod dns;
mod ispdb;
mod probe;
pub mod table;

use std::time::Duration;

use crate::error::DiscoverError;
use crate::Security;

pub use dns::{mx_hosts, srv_endpoints};
pub use ispdb::{domain_autoconfig_lookup, ispdb_lookup, parse_autoconfig_xml};
pub use probe::{guess, probe_endpoint};

/// One server endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub security: Security,
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16, security: Security) -> Self {
        Self {
            host: host.into(),
            port,
            security,
        }
    }
}

/// OAuth2 identity providers Sealbox knows how to talk to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum OAuthProvider {
    Google,
    Microsoft,
    Yahoo,
}

/// What kind of credential the provider wants from a third-party client.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AuthHint {
    /// Sign in with the provider's OAuth2 flow (XOAUTH2 on the wire).
    OAuth2(OAuthProvider),
    /// The normal password will not work; the user must generate an app password.
    AppPassword { help_url: String },
    /// The regular mailbox password works.
    Password,
}

/// Which login name the server expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum UsernameForm {
    /// `alice@example.com`
    FullAddress,
    /// `alice`
    LocalPart,
}

/// Where a configuration came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ConfigSource {
    BuiltIn,
    Ispdb,
    DomainAutoconfig,
    Srv,
    Mx,
    Guess,
    /// Typed in by the user (or passed as `--imap/--smtp`); nothing was discovered.
    Manual,
}

impl ConfigSource {
    /// Stable lower-case name (`built_in`, `ispdb`, …, `manual`).
    pub fn as_str(self) -> &'static str {
        match self {
            ConfigSource::BuiltIn => "built_in",
            ConfigSource::Ispdb => "ispdb",
            ConfigSource::DomainAutoconfig => "domain_autoconfig",
            ConfigSource::Srv => "srv",
            ConfigSource::Mx => "mx",
            ConfigSource::Guess => "guess",
            ConfigSource::Manual => "manual",
        }
    }
}

impl ServerConfig {
    /// A configuration typed in by the user: password auth, full-address login.
    pub fn manual(imap: Endpoint, smtp: Endpoint, display_name: impl Into<String>) -> Self {
        Self {
            imap,
            smtp,
            auth_hint: AuthHint::Password,
            display_name: display_name.into(),
            source: ConfigSource::Manual,
            username: UsernameForm::FullAddress,
        }
    }
}

/// Discovered server configuration for an e-mail address.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServerConfig {
    pub imap: Endpoint,
    pub smtp: Endpoint,
    pub auth_hint: AuthHint,
    pub display_name: String,
    pub source: ConfigSource,
    pub username: UsernameForm,
}

impl ServerConfig {
    /// The login name to use for `email` with this configuration.
    pub fn login_name(&self, email: &str) -> String {
        match self.username {
            UsernameForm::FullAddress => email.to_owned(),
            UsernameForm::LocalPart => email
                .split_once('@')
                .map(|(l, _)| l.to_owned())
                .unwrap_or_else(|| email.to_owned()),
        }
    }
}

/// Knobs for [`discover_with`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoverOptions {
    /// Allow HTTP / DNS / TCP probing after the built-in table misses.
    pub allow_network: bool,
    /// Timeout for each network step.
    pub timeout: Duration,
}

impl Default for DiscoverOptions {
    fn default() -> Self {
        Self {
            allow_network: true,
            timeout: Duration::from_secs(8),
        }
    }
}

/// Lower-cased domain part of an address.
pub fn domain_of(email: &str) -> Result<String, DiscoverError> {
    let email = email.trim();
    match email.rsplit_once('@') {
        Some((local, domain))
            if !local.is_empty()
                && !domain.is_empty()
                && !domain.contains(['/', ' ', '\\', '?', '#']) =>
        {
            Ok(domain.trim_end_matches('.').to_ascii_lowercase())
        }
        _ => Err(DiscoverError::InvalidEmail(email.to_owned())),
    }
}

/// Built-in table only; works offline.
pub fn discover_offline(email: &str) -> Option<ServerConfig> {
    let domain = domain_of(email).ok()?;
    table::lookup(&domain)
}

/// Full discovery with default options.
pub async fn discover(email: &str) -> Result<ServerConfig, DiscoverError> {
    discover_with(email, &DiscoverOptions::default()).await
}

/// Full discovery chain. Each network step is attempted in order and the first
/// complete answer wins; SRV may contribute only one half, in which case the
/// other half is filled from the guesses.
///
/// The answer must pass the transport policy (`crate::net_policy`, docs/THREAT_MODEL.md
/// R12): a configuration that needs `plain` towards a public host — only an autoconfig
/// document can say that — is refused with [`DiscoverError::Policy`] instead of being
/// returned. TLS and STARTTLS candidates are always preferred over `plain` ones.
pub async fn discover_with(
    email: &str,
    opts: &DiscoverOptions,
) -> Result<ServerConfig, DiscoverError> {
    let cfg = discover_unchecked(email, opts).await?;
    crate::net_policy::check_server_config(&cfg)?;
    Ok(cfg)
}

async fn discover_unchecked(
    email: &str,
    opts: &DiscoverOptions,
) -> Result<ServerConfig, DiscoverError> {
    let domain = domain_of(email)?;
    if let Some(cfg) = table::lookup(&domain) {
        return Ok(cfg);
    }
    if !opts.allow_network {
        return Err(DiscoverError::NotFound(domain));
    }
    let t = opts.timeout;

    if let Ok(cfg) = ispdb_lookup(&domain, t).await {
        return Ok(cfg);
    }
    if let Ok(cfg) = domain_autoconfig_lookup(&domain, email, t).await {
        return Ok(cfg);
    }

    let (srv_imap, srv_smtp) = srv_endpoints(&domain, t).await.unwrap_or((None, None));
    if let (Some(imap), Some(smtp)) = (&srv_imap, &srv_smtp) {
        return Ok(ServerConfig {
            imap: imap.clone(),
            smtp: smtp.clone(),
            auth_hint: AuthHint::Password,
            display_name: domain.clone(),
            source: ConfigSource::Srv,
            username: UsernameForm::FullAddress,
        });
    }

    if let Ok(Some(cfg)) = dns::mx_provider(&domain, t).await {
        return Ok(cfg);
    }

    let mut guessed = guess(&domain, t).await?;
    if srv_imap.is_some() || srv_smtp.is_some() {
        if let Some(imap) = srv_imap {
            guessed.imap = imap;
        }
        if let Some(smtp) = srv_smtp {
            guessed.smtp = smtp;
        }
        guessed.source = ConfigSource::Srv;
    }
    Ok(guessed)
}
