//! Transport policy for IMAP and SMTP: the one place that decides whether a connection may run
//! without TLS (docs/THREAT_MODEL.md R12) and which hosts may receive an OAuth2 bearer token
//! (R14). [`crate::imap::ImapClient`] and [`crate::smtp::SmtpClient`] apply it before their
//! first network write, [`crate::autodiscover::discover_with`] applies it to what it found, and
//! `sealbox-core` calls [`check_server_config`] where an account is added.
//!
//! # Plaintext (`Security::Plain`)
//!
//! Allowed only towards local or private hosts, decided from the **literal host string**. No
//! DNS lookup is made: a public name that resolves to a private address does not qualify, and a
//! name in a private-looking zone is never resolved to check.
//!
//! * loopback: `127.0.0.0/8`, `::1`, `localhost` and names under `.localhost`;
//! * private networks: `10.0.0.0/8` (which holds `10.0.2.2`, the Android emulator's alias for the
//!   host machine), `172.16.0.0/12`, `192.168.0.0/16`, IPv6 unique-local `fc00::/7`;
//! * link-local: `169.254.0.0/16`, `fe80::/10` (a `%zone` suffix is accepted);
//! * special-use names under `.test`, `.local`, `.internal`, `.lan`, `.home`, `.invalid`;
//! * the exact hosts listed in `SEALBOX_ALLOW_PLAIN_HOSTS=host1,host2` (read once per process;
//!   case-insensitive, a trailing dot and IPv6 brackets ignored, no wildcards or suffixes).
//!
//! Everything else gets [`TransportPolicyError::InsecureTransportRefused`]. `Tls` and `StartTls`
//! are not affected. IPv4-mapped IPv6 literals (`::ffff:a.b.c.d`) are judged as the IPv4 address;
//! other spellings the system resolver would also accept (`127.1`, `0x7f.0.0.1`) are treated as
//! names, which only ever errs towards refusing.
//!
//! # OAuth2 bearer tokens
//!
//! A token is presented only to its provider's own mail hosts, matched on a domain boundary
//! (`imap.evilgmail.com` is not Gmail): Google → `gmail.com`, `googlemail.com`, `google.com`;
//! Microsoft → `office365.com`, `outlook.com`, `live.com`, `hotmail.com`, `microsoft.com`.
//! Anything else is [`TransportPolicyError::OAuthHostMismatch`], raised before a connection is
//! opened. A caller that does not say which provider issued the token ([`ConnectOptions`] without
//! a [`BearerScope`]) gets the provider inferred from the host, so an unscoped token still goes
//! only to a Google or Microsoft host.
//!
//! **Test / development escape hatch.** When the token came from a mock identity provider whose
//! authorization *and* token endpoints are loopback URLs (`SEALBOX_OAUTH_AUTH_URL` /
//! `SEALBOX_OAUTH_TOKEN_URL`, see [`crate::oauth::OAuthEndpoints::is_loopback_mock`]), the
//! [`BearerScope`] is marked `dev_idp` and local/private mail hosts (the list above, without the
//! `SEALBOX_ALLOW_PLAIN_HOSTS` additions) are accepted as well. Tokens from the providers' real
//! endpoints never get this, so production pinning is unchanged.
//!
//! Sending the token as a `LOGIN` password when a server lacks `AUTH=XOAUTH2` is not a policy
//! decision but a fixed rule of the IMAP client: it never happens
//! ([`crate::ImapError::XOAuth2NotOffered`]).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;
use std::time::Duration;

use crate::autodiscover::{Endpoint, ServerConfig};
use crate::error::TransportPolicyError;
use crate::oauth::{OAuthEndpoints, Provider};
use crate::Security;

/// Comma-separated exact host names that may be reached without TLS in addition to the local
/// and private hosts (read once per process).
pub const ENV_ALLOW_PLAIN_HOSTS: &str = "SEALBOX_ALLOW_PLAIN_HOSTS";

/// Mail-host domains a Google token may be presented to.
pub const GOOGLE_MAIL_DOMAINS: &[&str] = &["gmail.com", "googlemail.com", "google.com"];
/// Mail-host domains a Microsoft token may be presented to.
pub const MICROSOFT_MAIL_DOMAINS: &[&str] = &[
    "office365.com",
    "outlook.com",
    "live.com",
    "hotmail.com",
    "microsoft.com",
];

/// Special-use top-level names (RFC 6761 / RFC 6762 / ICANN `.internal` / home-network
/// conventions) whose hosts count as local. `localhost` is handled separately (loopback).
const LOCAL_TLDS: &[&str] = &["test", "local", "internal", "lan", "home", "invalid"];

/// How a host string is classified for the plaintext rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostClass {
    /// `127.0.0.0/8`, `::1`, `localhost`, `*.localhost`.
    Loopback,
    /// RFC 1918 IPv4 ranges (incl. the Android emulator alias `10.0.2.2`) and IPv6 `fc00::/7`.
    PrivateNetwork,
    /// `169.254.0.0/16`, `fe80::/10`.
    LinkLocal,
    /// A name under `.test`, `.local`, `.internal`, `.lan`, `.home` or `.invalid`.
    SpecialUseName,
    /// Anything else, including every name not in a special-use zone.
    Public,
}

impl HostClass {
    /// True for every class except [`HostClass::Public`].
    pub fn is_local(self) -> bool {
        !matches!(self, HostClass::Public)
    }

    /// Short human-readable label (`loopback`, `private network`, …).
    pub fn describe(self) -> &'static str {
        match self {
            HostClass::Loopback => "loopback",
            HostClass::PrivateNetwork => "private network",
            HostClass::LinkLocal => "link-local",
            HostClass::SpecialUseName => "special-use name",
            HostClass::Public => "public",
        }
    }
}

/// Classify a host from its literal spelling (no DNS).
pub fn classify_host(host: &str) -> HostClass {
    let h = host.trim();
    let unbracketed = h
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(h);
    // IP literals first: exactly what `TcpStream::connect` would parse.
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return classify_ip(ip);
    }
    // `fe80::1%eth0`: a scoped IPv6 literal (the resolver honours the zone).
    if let Some((addr, zone)) = unbracketed.split_once('%') {
        if !zone.is_empty() {
            if let Ok(v6) = addr.parse::<Ipv6Addr>() {
                return classify_ip(IpAddr::V6(v6));
            }
        }
        return HostClass::Public;
    }
    classify_name(unbracketed)
}

fn classify_ip(ip: IpAddr) -> HostClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => classify_v4(v4),
            None => classify_v6(v6),
        },
    }
}

fn classify_v4(ip: Ipv4Addr) -> HostClass {
    if ip.is_loopback() {
        HostClass::Loopback
    } else if ip.is_private() {
        // 10/8, 172.16/12, 192.168/16 — 10.0.2.2 (Android emulator → host) is in 10/8.
        HostClass::PrivateNetwork
    } else if ip.is_link_local() {
        HostClass::LinkLocal
    } else {
        HostClass::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> HostClass {
    let first = ip.segments()[0];
    if ip.is_loopback() {
        HostClass::Loopback
    } else if first & 0xfe00 == 0xfc00 {
        HostClass::PrivateNetwork
    } else if first & 0xffc0 == 0xfe80 {
        HostClass::LinkLocal
    } else {
        HostClass::Public
    }
}

fn classify_name(name: &str) -> HostClass {
    let n = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let labels: Vec<&str> = n.split('.').collect();
    let well_formed = !n.is_empty()
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if !well_formed {
        return HostClass::Public;
    }
    let tld = labels[labels.len() - 1];
    if tld == "localhost" {
        // `localhost` itself and anything under it (RFC 6761 §6.3).
        return HostClass::Loopback;
    }
    // A bare special label (`test`, `lan`) would be completed with the resolver's search
    // domains, which can be public: require at least one label in front of it.
    if labels.len() >= 2 && LOCAL_TLDS.contains(&tld) {
        return HostClass::SpecialUseName;
    }
    HostClass::Public
}

/// Normalised form used to compare hosts with the override list: lower case, no surrounding
/// whitespace, no IPv6 brackets, no trailing dot.
fn normalize(host: &str) -> String {
    let h = host.trim();
    let h = h
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(h);
    h.strip_suffix('.').unwrap_or(h).to_ascii_lowercase()
}

/// Parse a `SEALBOX_ALLOW_PLAIN_HOSTS` value: comma-separated, whitespace and empty entries
/// ignored, each entry normalised like the hosts it is compared with.
pub fn parse_host_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(normalize)
        .filter(|h| !h.is_empty())
        .collect()
}

static ALLOW_PLAIN: LazyLock<Vec<String>> = LazyLock::new(|| {
    let list = std::env::var(ENV_ALLOW_PLAIN_HOSTS)
        .map(|v| parse_host_list(&v))
        .unwrap_or_default();
    if !list.is_empty() {
        tracing::warn!(
            hosts = %list.join(","),
            "{ENV_ALLOW_PLAIN_HOSTS}: plaintext IMAP/SMTP allowed to these hosts"
        );
    }
    list
});

/// The hosts `SEALBOX_ALLOW_PLAIN_HOSTS` adds (normalised; read on first use).
pub fn allowed_plain_hosts() -> &'static [String] {
    &ALLOW_PLAIN
}

/// Why plaintext is acceptable for a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlainAllowance {
    /// The host is local or private ([`HostClass::is_local`]).
    Local(HostClass),
    /// The host is listed in `SEALBOX_ALLOW_PLAIN_HOSTS`.
    Override,
}

impl PlainAllowance {
    /// Short label for diagnostics (`loopback`, `SEALBOX_ALLOW_PLAIN_HOSTS`, …).
    pub fn describe(self) -> &'static str {
        match self {
            PlainAllowance::Local(c) => c.describe(),
            PlainAllowance::Override => ENV_ALLOW_PLAIN_HOSTS,
        }
    }
}

/// Is plaintext acceptable for `host` given an explicit override list? `None` = refused.
pub fn plain_allowance_with(host: &str, overrides: &[String]) -> Option<PlainAllowance> {
    let class = classify_host(host);
    if class.is_local() {
        return Some(PlainAllowance::Local(class));
    }
    let h = normalize(host);
    if !h.is_empty() && overrides.contains(&h) {
        return Some(PlainAllowance::Override);
    }
    None
}

/// [`plain_allowance_with`] with the process-wide `SEALBOX_ALLOW_PLAIN_HOSTS`.
pub fn plain_allowance(host: &str) -> Option<PlainAllowance> {
    plain_allowance_with(host, allowed_plain_hosts())
}

/// [`check_transport`] with an explicit override list (tests, embedders).
pub fn check_transport_with(
    host: &str,
    port: u16,
    security: Security,
    overrides: &[String],
) -> Result<(), TransportPolicyError> {
    match security {
        Security::Tls | Security::StartTls => Ok(()),
        Security::Plain => match plain_allowance_with(host, overrides) {
            Some(_) => Ok(()),
            None => Err(TransportPolicyError::InsecureTransportRefused {
                host: host.trim().to_owned(),
                port,
            }),
        },
    }
}

/// The R12 rule for one connection: `Plain` only to local/private/override hosts.
pub fn check_transport(
    host: &str,
    port: u16,
    security: Security,
) -> Result<(), TransportPolicyError> {
    check_transport_with(host, port, security, allowed_plain_hosts())
}

/// [`check_transport`] for an endpoint.
pub fn check_endpoint(ep: &Endpoint) -> Result<(), TransportPolicyError> {
    check_transport(&ep.host, ep.port, ep.security)
}

/// Both halves of a (discovered or typed-in) server configuration; IMAP is checked first.
pub fn check_server_config(cfg: &ServerConfig) -> Result<(), TransportPolicyError> {
    check_endpoint(&cfg.imap)?;
    check_endpoint(&cfg.smtp)
}

/// Is `host` equal to `domain` or below it (domain-boundary match, case-insensitive, trailing
/// dot ignored)? `imap.gmail.com` is under `gmail.com`; `imap.evilgmail.com` is not.
pub fn host_is_under(host: &str, domain: &str) -> bool {
    let h = normalize(host);
    let d = normalize(domain);
    !d.is_empty() && (h == d || h.ends_with(&format!(".{d}")))
}

/// The mail-host domains a token from `provider` may be presented to.
pub fn mail_domains(provider: Provider) -> &'static [&'static str] {
    match provider {
        Provider::Google => GOOGLE_MAIL_DOMAINS,
        Provider::Microsoft => MICROSOFT_MAIL_DOMAINS,
    }
}

/// The OAuth provider whose mail hosts include `host`, if any.
pub fn provider_for_host(host: &str) -> Option<Provider> {
    [Provider::Google, Provider::Microsoft]
        .into_iter()
        .find(|p| mail_domains(*p).iter().any(|d| host_is_under(host, d)))
}

/// Who issued an OAuth2 bearer token, which decides where it may be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BearerScope {
    pub provider: Provider,
    /// The token came from a loopback mock identity provider (tests / development): local and
    /// private mail hosts are accepted in addition to the provider's own.
    pub dev_idp: bool,
}

impl BearerScope {
    /// A token from the provider's real endpoints.
    pub fn new(provider: Provider) -> Self {
        Self {
            provider,
            dev_idp: false,
        }
    }

    /// A token obtained from `endpoints`: `dev_idp` exactly when they are a loopback override
    /// of the provider's real endpoints.
    pub fn for_endpoints(provider: Provider, endpoints: &OAuthEndpoints) -> Self {
        Self {
            provider,
            dev_idp: endpoints.is_loopback_mock(provider),
        }
    }

    /// May a token of this scope be presented to `host`?
    pub fn allows_host(&self, host: &str) -> bool {
        mail_domains(self.provider)
            .iter()
            .any(|d| host_is_under(host, d))
            || (self.dev_idp && classify_host(host).is_local())
    }
}

/// The R14 rule: may a bearer token be presented to `host`? `scope = None` (provider unknown)
/// accepts only hosts of a known provider.
pub fn check_bearer_host(
    scope: Option<BearerScope>,
    host: &str,
) -> Result<(), TransportPolicyError> {
    let ok = match scope {
        Some(s) => s.allows_host(host),
        None => provider_for_host(host).is_some(),
    };
    if ok {
        Ok(())
    } else {
        Err(TransportPolicyError::OAuthHostMismatch {
            provider: scope.map(|s| s.provider),
            host: host.trim().to_owned(),
        })
    }
}

/// Per-connection options for [`crate::imap::ImapClient::connect_with`] and
/// [`crate::smtp::SmtpClient::connect_with`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectOptions {
    /// Applied to the TCP connect, the TLS handshake and every later operation.
    pub timeout: Duration,
    /// Who issued the XOAUTH2 bearer (ignored for password logins). `None` = unknown: the
    /// provider is inferred from the host and other hosts are refused.
    pub bearer: Option<BearerScope>,
}

impl ConnectOptions {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            bearer: None,
        }
    }

    pub fn with_bearer(mut self, scope: Option<BearerScope>) -> Self {
        self.bearer = scope;
        self
    }
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none() -> Vec<String> {
        Vec::new()
    }

    #[test]
    fn loopback_literals_and_names() {
        for h in [
            "127.0.0.1",
            "127.8.9.10",
            "::1",
            "[::1]",
            "::ffff:127.0.0.1",
            "localhost",
            "LOCALHOST",
            "localhost.",
            "mail.localhost",
            "Mail.LocalHost.",
        ] {
            assert_eq!(classify_host(h), HostClass::Loopback, "{h}");
        }
    }

    #[test]
    fn private_ranges_and_the_emulator_alias() {
        for h in [
            "10.0.0.1",
            "10.0.2.2",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.20",
            "fc00::1",
            "fd12:3456:789a::1",
            "[fd00::25]",
            "::ffff:192.168.0.1",
        ] {
            assert_eq!(classify_host(h), HostClass::PrivateNetwork, "{h}");
        }
        // Just outside the RFC 1918 ranges.
        for h in [
            "172.15.255.255",
            "172.32.0.1",
            "192.169.0.1",
            "11.0.0.1",
            "fe00::1",
        ] {
            assert_eq!(classify_host(h), HostClass::Public, "{h}");
        }
    }

    #[test]
    fn link_local() {
        for h in [
            "169.254.0.1",
            "169.254.169.254",
            "fe80::1",
            "FE80::abcd",
            "fe80::1%eth0",
        ] {
            assert_eq!(classify_host(h), HostClass::LinkLocal, "{h}");
        }
        assert_eq!(classify_host("febf::1"), HostClass::LinkLocal);
        assert_eq!(classify_host("fec0::1"), HostClass::Public);
        // A zone on a global address does not make it local.
        assert_eq!(classify_host("2001:db8::1%eth0"), HostClass::Public);
        assert_eq!(classify_host("fe80::1%"), HostClass::Public);
    }

    #[test]
    fn special_use_names() {
        for h in [
            "mail.sealbox.test",
            "sealbox.test",
            "imap.Example.TEST",
            "printer.local",
            "box.local.",
            "mx.corp.internal",
            "nas.lan",
            "router.home",
            "x.invalid",
            "sealbox-mail.test",
            "under_score.lan",
        ] {
            assert_eq!(classify_host(h), HostClass::SpecialUseName, "{h}");
        }
        // Bare special labels would be completed with search domains: not local.
        for h in ["test", "local", "lan", "home", "internal", "invalid"] {
            assert_eq!(classify_host(h), HostClass::Public, "{h}");
        }
    }

    #[test]
    fn public_hosts() {
        for h in [
            "8.8.8.8",
            "192.0.2.1",
            "100.64.0.1",
            "0.0.0.0",
            "::",
            "2001:4860:4860::8888",
            "imap.gmail.com",
            "mail.example.com",
            "test.example.com",
            "localhost.example.com",
            "local.example",
            "evil.lan.example.com",
            "127.0.0.1.nip.io",
            "10.0.0.1.example.com",
            "127.1",
            "127.0.0.1.",
            "",
            " ",
            "a..test",
            ".test",
            "bad host.test",
            "a/b.test",
            "user@mail.test",
        ] {
            assert_eq!(classify_host(h), HostClass::Public, "{h:?}");
        }
    }

    #[test]
    fn plain_policy_refuses_public_hosts_and_names_the_override() {
        let err = check_transport_with("imap.example.com", 143, Security::Plain, &none())
            .expect_err("public host must be refused");
        assert_eq!(
            err,
            TransportPolicyError::InsecureTransportRefused {
                host: "imap.example.com".into(),
                port: 143
            }
        );
        let text = err.to_string();
        assert!(text.contains("imap.example.com:143"), "{text}");
        assert!(
            text.contains("SEALBOX_ALLOW_PLAIN_HOSTS=imap.example.com"),
            "{text}"
        );
        assert!(text.contains("tls or starttls"), "{text}");
        // Public IP literal too.
        assert!(check_transport_with("203.0.113.7", 25, Security::Plain, &none()).is_err());
        // IPv6 literal: host and port stay readable.
        let v6 = check_transport_with("2001:db8::25", 587, Security::Plain, &none())
            .expect_err("public v6");
        assert!(v6.to_string().contains("[2001:db8::25]:587"), "{v6}");
    }

    #[test]
    fn plain_policy_allows_local_hosts_and_never_touches_tls() {
        for h in [
            "127.0.0.1",
            "10.0.2.2",
            "192.168.1.5",
            "::1",
            "mail.sealbox.test",
        ] {
            check_transport_with(h, 3143, Security::Plain, &none()).expect(h);
        }
        for sec in [Security::Tls, Security::StartTls] {
            check_transport_with("imap.example.com", 993, sec, &none()).expect("tls is fine");
            check_transport_with("8.8.8.8", 465, sec, &none()).expect("tls is fine");
        }
    }

    #[test]
    fn override_is_an_exact_case_insensitive_match() {
        let list = parse_host_list(" Mail.Example.com. , ,[2001:DB8::1],imap.corp.example ");
        assert_eq!(
            list,
            vec![
                "mail.example.com".to_string(),
                "2001:db8::1".to_string(),
                "imap.corp.example".to_string()
            ]
        );
        assert_eq!(
            plain_allowance_with("MAIL.EXAMPLE.COM", &list),
            Some(PlainAllowance::Override)
        );
        assert_eq!(
            plain_allowance_with("mail.example.com.", &list),
            Some(PlainAllowance::Override)
        );
        assert_eq!(
            plain_allowance_with("2001:db8::1", &list),
            Some(PlainAllowance::Override)
        );
        // No suffix / subdomain / parent matching.
        assert_eq!(plain_allowance_with("x.mail.example.com", &list), None);
        assert_eq!(plain_allowance_with("example.com", &list), None);
        assert_eq!(plain_allowance_with("mail.example.co", &list), None);
        check_transport_with("Mail.Example.com", 143, Security::Plain, &list).expect("listed");
        assert!(check_transport_with("other.example.com", 143, Security::Plain, &list).is_err());
        // Local hosts report their class, not the override.
        assert_eq!(
            plain_allowance_with("127.0.0.1", &list),
            Some(PlainAllowance::Local(HostClass::Loopback))
        );
        assert!(parse_host_list("").is_empty());
        assert!(parse_host_list(" , ,").is_empty());
    }

    #[test]
    fn server_config_checks_both_halves() {
        let mk = |imap: Endpoint, smtp: Endpoint| ServerConfig::manual(imap, smtp, "x");
        let ok = mk(
            Endpoint::new("imap.example.com", 993, Security::Tls),
            Endpoint::new("127.0.0.1", 3025, Security::Plain),
        );
        check_server_config(&ok).expect("tls + loopback plain");
        let bad = mk(
            Endpoint::new("imap.example.com", 993, Security::Tls),
            Endpoint::new("smtp.example.com", 25, Security::Plain),
        );
        assert_eq!(
            check_server_config(&bad).unwrap_err(),
            TransportPolicyError::InsecureTransportRefused {
                host: "smtp.example.com".into(),
                port: 25
            }
        );
    }

    #[test]
    fn provider_hosts_need_a_domain_boundary() {
        for (host, want) in [
            ("imap.gmail.com", Some(Provider::Google)),
            ("smtp.gmail.com.", Some(Provider::Google)),
            ("IMAP.GoogleMail.com", Some(Provider::Google)),
            ("imap.google.com", Some(Provider::Google)),
            ("gmail.com", Some(Provider::Google)),
            ("outlook.office365.com", Some(Provider::Microsoft)),
            ("smtp.office365.com", Some(Provider::Microsoft)),
            ("smtp-mail.outlook.com", Some(Provider::Microsoft)),
            ("imap-mail.outlook.com", Some(Provider::Microsoft)),
            ("outlook.live.com", Some(Provider::Microsoft)),
            ("imap.hotmail.com", Some(Provider::Microsoft)),
            ("mail.microsoft.com", Some(Provider::Microsoft)),
            ("imap.evilgmail.com", None),
            ("gmail.com.evil.example", None),
            ("notoutlook.com", None),
            ("live.com-mail.example", None),
            ("imap.mail.yahoo.com", None),
            ("127.0.0.1", None),
            ("142.250.27.108", None),
        ] {
            assert_eq!(provider_for_host(host), want, "{host}");
        }
    }

    #[test]
    fn bearer_is_pinned_to_its_provider() {
        let google = BearerScope::new(Provider::Google);
        let microsoft = BearerScope::new(Provider::Microsoft);
        check_bearer_host(Some(google), "imap.gmail.com").expect("gmail");
        check_bearer_host(Some(google), "smtp.gmail.com").expect("gmail smtp");
        check_bearer_host(Some(microsoft), "outlook.office365.com").expect("o365");
        check_bearer_host(Some(microsoft), "smtp-mail.outlook.com").expect("outlook");
        // Cross-provider and foreign hosts are refused, naming the provider.
        for (scope, host) in [
            (google, "outlook.office365.com"),
            (google, "imap.evilgmail.com"),
            (google, "imap.example.com"),
            (google, "127.0.0.1"),
            (microsoft, "imap.gmail.com"),
            (microsoft, "outlook.office365.com.evil.example"),
            (microsoft, "10.0.2.2"),
        ] {
            let err = check_bearer_host(Some(scope), host).expect_err(host);
            assert_eq!(
                err,
                TransportPolicyError::OAuthHostMismatch {
                    provider: Some(scope.provider),
                    host: host.into()
                }
            );
            let text = err.to_string();
            assert!(text.contains(host), "{text}");
            assert!(
                text.contains(mail_domains(scope.provider)[0]),
                "the allowed domains are named: {text}"
            );
        }
        let text = check_bearer_host(Some(google), "imap.example.com")
            .unwrap_err()
            .to_string();
        assert!(text.contains("Google"), "{text}");
        let text = check_bearer_host(Some(microsoft), "imap.example.com")
            .unwrap_err()
            .to_string();
        assert!(text.contains("Microsoft"), "{text}");
    }

    #[test]
    fn dev_idp_scope_also_accepts_local_hosts_only() {
        let dev = BearerScope {
            provider: Provider::Google,
            dev_idp: true,
        };
        for h in [
            "127.0.0.1",
            "::1",
            "localhost",
            "10.0.2.2",
            "192.168.0.9",
            "mail.sealbox.test",
        ] {
            check_bearer_host(Some(dev), h).expect(h);
        }
        check_bearer_host(Some(dev), "imap.gmail.com").expect("own provider still fine");
        for h in ["imap.example.com", "outlook.office365.com", "8.8.8.8"] {
            assert!(check_bearer_host(Some(dev), h).is_err(), "{h}");
        }
    }

    #[test]
    fn scope_follows_the_endpoints() {
        let real = OAuthEndpoints::for_provider(Provider::Google);
        assert!(!BearerScope::for_endpoints(Provider::Google, &real).dev_idp);
        let mock = OAuthEndpoints {
            auth_url: "http://127.0.0.1:4711/auth".into(),
            token_url: "http://localhost:4711/token".into(),
        };
        assert!(BearerScope::for_endpoints(Provider::Google, &mock).dev_idp);
        // An override that is not loopback (or only half loopback) is not a dev IdP.
        let remote = OAuthEndpoints {
            auth_url: "https://idp.example.com/auth".into(),
            token_url: "https://idp.example.com/token".into(),
        };
        assert!(!BearerScope::for_endpoints(Provider::Google, &remote).dev_idp);
        let half = OAuthEndpoints {
            auth_url: "http://127.0.0.1:1/auth".into(),
            token_url: "https://idp.example.com/token".into(),
        };
        assert!(!BearerScope::for_endpoints(Provider::Microsoft, &half).dev_idp);
    }

    #[test]
    fn unscoped_bearer_goes_only_to_known_provider_hosts() {
        check_bearer_host(None, "imap.gmail.com").expect("google host");
        check_bearer_host(None, "outlook.office365.com").expect("microsoft host");
        for h in ["127.0.0.1", "imap.example.com", "imap.evilgmail.com"] {
            let err = check_bearer_host(None, h).expect_err(h);
            assert_eq!(
                err,
                TransportPolicyError::OAuthHostMismatch {
                    provider: None,
                    host: h.into()
                }
            );
            assert!(err.to_string().contains("unknown"), "{err}");
        }
    }
}
