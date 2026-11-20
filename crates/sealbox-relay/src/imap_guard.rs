//! IMAP destination policy: the relay's guard against request forgery through `imap.host`
//! (threat-model R9).
//!
//! The client that registers chooses the IMAP host and port. Without a policy a token holder
//! could make the relay open TCP connections to anything it can reach (the cloud metadata
//! service, an admin port on loopback, a database in the private network), send a TLS
//! ClientHello or read a banner there, and learn the outcome from `state` / `last_error`. The
//! guard runs twice:
//!
//! 1. **At registration** ([`ImapGuard::check`], from `api::register`), before anything is
//!    stored.
//! 2. **At every (re)connect** of the worker: the host is resolved and checked again, and the
//!    worker connects only to the addresses that passed
//!    (`sealbox_mail::imap::ImapClient::connect_pinned`). A DNS answer that changes after the
//!    registration (rebinding) cannot redirect the session: check and connect use one and the
//!    same answer. TLS still verifies the certificate for the registered name.
//!
//! The rules, in order:
//!
//! 1. **Allow-list** (`--imap-allow-hosts`, when set): exact host names, `.suffix` entries
//!    (`.example.com` admits every name under `example.com`, not `example.com` itself) and IP
//!    literals (matched exactly). Case-insensitive, one trailing dot ignored, decided without
//!    DNS. The allow-list restricts further: an allow-listed host still has to pass 2 and 3.
//! 2. **Resolution**: a name is resolved with the relay's resolver, with the webhook guard's
//!    timeout ([`RESOLVE_TIMEOUT`]); an IP literal is taken as it is.
//! 3. **Addresses**: every address must be public, judged by the same table as webhook
//!    destinations ([`host_class::classify`]): loopback, RFC 1918, link-local (including
//!    `169.254.169.254`), unique-local, carrier-grade NAT, multicast, unspecified and reserved
//!    addresses are refused, and IPv4-mapped, NAT64 and 6to4 addresses are judged by the IPv4
//!    address they carry. `--imap-allow-private` (development and tests: a local GreenMail)
//!    accepts them.
//!
//! Refusal messages ([`ImapRefusal`]) describe the rule only, never the host, an address or the
//! port.

use std::{net::IpAddr, sync::Arc, time::Duration};

use crate::{
    host_class,
    webhook_guard::{self, NameResolver, SystemResolver, RESOLVE_TIMEOUT},
};

/// Why an IMAP destination was refused. The `Display` texts are the API's 400 reasons
/// verbatim; at connect time the worker records them as `IMAP destination refused: <reason>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ImapRefusal {
    #[error("imap.host is not on this relay's IMAP allow-list")]
    NotAllowListed,
    #[error("imap.host could not be resolved")]
    Unresolvable,
    #[error(
        "imap.host resolves to a non-public address (loopback, private, link-local, \
         unique-local, shared, multicast, unspecified or reserved), which this relay does not \
         connect to"
    )]
    NonPublic,
}

/// `host` as the allow-list compares it and the resolver gets it: trimmed, ASCII lower case,
/// one trailing dot removed.
fn normalize(host: &str) -> String {
    let host = host.trim().to_ascii_lowercase();
    match host.strip_suffix('.') {
        Some(stripped) => stripped.to_owned(),
        None => host,
    }
}

/// Labels of 1–63 characters from `[a-z0-9_-]`, at most 253 bytes in all.
fn is_host_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

/// `--imap-allow-hosts`: when configured, the only IMAP hosts the relay accepts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImapAllowHosts {
    /// Exact names, normalised.
    names: Vec<String>,
    /// `.suffix` entries, normalised, with their leading dot.
    suffixes: Vec<String>,
    /// IP literals, matched exactly.
    ips: Vec<IpAddr>,
}

impl ImapAllowHosts {
    /// Parse entries such as `imap.gmail.com`, `.office365.com`, `203.0.113.7`, `2001:db8::1`.
    /// Blank entries are skipped; `Ok(None)` means no allow-list. Wildcards, ports, schemes and
    /// paths are refused (the binary exits with status 2).
    pub fn parse<I, S>(entries: I) -> Result<Option<Self>, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut list = Self::default();
        for raw in entries {
            let entry = raw.as_ref().trim();
            if entry.is_empty() {
                continue;
            }
            if let Some(ip) = host_class::ip_literal(entry) {
                list.ips.push(ip);
                continue;
            }
            if entry.contains('*') {
                return Err(format!(
                    "--imap-allow-hosts: {entry:?}: write a suffix entry (.example.com admits \
                     every name under example.com) instead of a wildcard"
                ));
            }
            let normalized = normalize(entry);
            match normalized.strip_prefix('.') {
                Some(rest) if is_host_name(rest) => list.suffixes.push(normalized),
                None if is_host_name(&normalized) => list.names.push(normalized),
                _ => {
                    return Err(format!(
                        "--imap-allow-hosts: {entry:?} is not a host name, a .suffix entry or an \
                         IP address (no ports, schemes or paths)"
                    ))
                }
            }
        }
        let empty = list.names.is_empty() && list.suffixes.is_empty() && list.ips.is_empty();
        Ok((!empty).then_some(list))
    }

    /// Does the registered `host` match an entry?
    pub fn matches(&self, host: &str) -> bool {
        if let Some(ip) = host_class::ip_literal(host.trim()) {
            return self.ips.contains(&ip);
        }
        let host = normalize(host);
        self.names.contains(&host)
            || self.suffixes.iter().any(|suffix| {
                host.strip_suffix(suffix.as_str())
                    .is_some_and(|prefix| !prefix.is_empty() && !prefix.ends_with('.'))
            })
    }

    /// The entries, for the startup log.
    pub fn entries(&self) -> Vec<String> {
        self.names
            .iter()
            .chain(&self.suffixes)
            .cloned()
            .chain(self.ips.iter().map(IpAddr::to_string))
            .collect()
    }
}

/// Which IMAP destinations the relay accepts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImapPolicy {
    /// Development and tests: accept loopback, private, link-local … destinations.
    pub allow_private: bool,
    /// When set, the only hosts accepted (checked in addition to the address rule).
    pub allow_hosts: Option<ImapAllowHosts>,
}

impl ImapPolicy {
    /// May the relay connect to `ip`?
    pub fn check_addr(&self, ip: IpAddr) -> Result<(), ImapRefusal> {
        if self.allow_private || host_class::classify(ip).is_public() {
            Ok(())
        } else {
            Err(ImapRefusal::NonPublic)
        }
    }

    /// Every address must pass; an empty answer is unresolvable.
    pub fn check_addrs(&self, addrs: &[IpAddr]) -> Result<(), ImapRefusal> {
        if addrs.is_empty() {
            return Err(ImapRefusal::Unresolvable);
        }
        addrs.iter().try_for_each(|ip| self.check_addr(*ip))
    }
}

/// The policy plus the resolver it checks answers from.
#[derive(Debug)]
pub struct ImapGuard {
    policy: ImapPolicy,
    resolver: Arc<dyn NameResolver>,
    timeout: Duration,
}

impl ImapGuard {
    pub fn new(policy: ImapPolicy) -> Self {
        Self::with_resolver(policy, Arc::new(SystemResolver), RESOLVE_TIMEOUT)
    }

    pub fn with_resolver(
        policy: ImapPolicy,
        resolver: Arc<dyn NameResolver>,
        timeout: Duration,
    ) -> Self {
        Self {
            policy,
            resolver,
            timeout,
        }
    }

    pub fn policy(&self) -> &ImapPolicy {
        &self.policy
    }

    /// Check `host` and return the addresses a connection may use: the registration-time
    /// check, and the worker's check before every connect, which then dials exactly these
    /// addresses.
    pub async fn check(&self, host: &str) -> Result<Vec<IpAddr>, ImapRefusal> {
        let host = host.trim();
        if let Some(allow) = &self.policy.allow_hosts {
            if !allow.matches(host) {
                return Err(ImapRefusal::NotAllowListed);
            }
        }
        let addrs = match host_class::ip_literal(host) {
            Some(ip) => vec![ip],
            None => webhook_guard::lookup(self.resolver.as_ref(), &normalize(host), self.timeout)
                .await
                .ok_or(ImapRefusal::Unresolvable)?,
        };
        self.policy.check_addrs(&addrs)?;
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhook_guard::test_dns::FakeDns;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    fn guard(policy: ImapPolicy, dns: FakeDns) -> (ImapGuard, Arc<FakeDns>) {
        let dns = Arc::new(dns);
        let g = ImapGuard::with_resolver(policy, dns.clone(), Duration::from_millis(300));
        (g, dns)
    }

    #[test]
    fn allow_list_parses_normalises_and_matches_exactly_or_below_a_suffix() {
        let list = ImapAllowHosts::parse([
            " IMAP.Gmail.COM. ",
            "",
            ".Office365.com",
            "203.0.113.7",
            "[2001:db8::1]",
        ])
        .expect("valid")
        .expect("non-empty");
        assert_eq!(
            list.entries(),
            [
                "imap.gmail.com",
                ".office365.com",
                "203.0.113.7",
                "2001:db8::1"
            ]
        );
        for ok in [
            "imap.gmail.com",
            "IMAP.GMAIL.COM.",
            " imap.gmail.com ",
            "outlook.office365.com",
            "a.b.office365.com",
            "203.0.113.7",
            "2001:db8::1",
            "[2001:db8::1]",
        ] {
            assert!(list.matches(ok), "{ok}");
        }
        for no in [
            // An exact entry admits neither its parent nor its subdomains.
            "gmail.com",
            "smtp.gmail.com",
            "x.imap.gmail.com",
            "imap.gmail.com.evil.net",
            // A suffix entry admits names below it only, on a label boundary.
            "office365.com",
            "evil-office365.com",
            "xoffice365.com",
            "a..office365.com",
            "office365.com.evil.net",
            "203.0.113.8",
            "::ffff:203.0.113.7",
            "2001:db8::2",
        ] {
            assert!(!list.matches(no), "{no}");
        }

        assert_eq!(ImapAllowHosts::parse(["", "  "]), Ok(None));
        for bad in [
            "*.gmail.com",
            "imap.gmail.com:993",
            "imaps://imap.gmail.com",
            "imap.gmail.com/x",
            "user@imap.gmail.com",
            "a..b",
            ".",
            "..",
            "bad host",
            "imap.gmail.com\u{1}",
        ] {
            assert!(ImapAllowHosts::parse([bad]).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn every_non_public_address_class_is_refused_and_public_ones_pass() {
        let (g, dns) = guard(ImapPolicy::default(), FakeDns::new());
        for host in [
            "127.0.0.1",
            "::1",
            "[::1]",
            "10.0.0.1",
            "10.0.2.2",
            "172.16.0.1",
            "192.168.1.10",
            "169.254.169.254",
            "fe80::1",
            "fd00::25",
            "100.64.0.1",
            "100.100.100.200",
            "224.0.0.1",
            "ff02::1",
            "0.0.0.0",
            "::",
            "192.0.2.1",
            "240.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "2002:c0a8:0101::1",
        ] {
            assert_eq!(g.check(host).await, Err(ImapRefusal::NonPublic), "{host}");
        }
        for host in ["8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"] {
            assert_eq!(g.check(host).await, Ok(vec![ip(host)]), "{host}");
        }
        assert_eq!(dns.lookups(), 0, "IP literals need no DNS");
    }

    #[tokio::test]
    async fn names_are_resolved_and_every_address_must_be_public() {
        let dns = FakeDns::new()
            .answer("imap.example", &["93.184.216.34", "2606:4700::6810:84e5"])
            .answer("metadata.example", &["169.254.169.254"])
            .answer("mixed.example", &["93.184.216.34", "10.0.0.7"])
            .answer("mapped.example", &["::ffff:127.0.0.1"])
            .answer("nat64.example", &["64:ff9b::7f00:1"])
            .answer("empty.example", &[]);
        let (g, _) = guard(ImapPolicy::default(), dns);
        assert_eq!(
            g.check("imap.example").await,
            Ok(vec![ip("93.184.216.34"), ip("2606:4700::6810:84e5")])
        );
        // Case and a trailing dot do not change the name that is resolved.
        assert!(g.check("IMAP.Example.").await.is_ok());
        for (host, want) in [
            ("metadata.example", ImapRefusal::NonPublic),
            ("mixed.example", ImapRefusal::NonPublic),
            ("mapped.example", ImapRefusal::NonPublic),
            ("nat64.example", ImapRefusal::NonPublic),
            ("empty.example", ImapRefusal::Unresolvable),
            ("nxdomain.example", ImapRefusal::Unresolvable),
            // Not a strict IP literal: a name, which this resolver does not know.
            ("127.1", ImapRefusal::Unresolvable),
        ] {
            assert_eq!(g.check(host).await, Err(want), "{host}");
        }
    }

    #[tokio::test]
    async fn allow_private_accepts_local_destinations() {
        let dns = FakeDns::new().answer("greenmail.example", &["10.0.0.5"]);
        let policy = ImapPolicy {
            allow_private: true,
            ..ImapPolicy::default()
        };
        let (g, _) = guard(policy, dns);
        assert_eq!(g.check("127.0.0.1").await, Ok(vec![ip("127.0.0.1")]));
        assert_eq!(g.check("greenmail.example").await, Ok(vec![ip("10.0.0.5")]));
        assert_eq!(
            g.check("missing.example").await,
            Err(ImapRefusal::Unresolvable)
        );
    }

    #[tokio::test]
    async fn the_allow_list_is_decided_before_any_lookup_and_does_not_waive_the_address_rule() {
        let dns = FakeDns::new()
            .answer("imap.example.org", &["93.184.216.34"])
            .answer("internal.example.org", &["10.1.2.3"]);
        let policy = ImapPolicy {
            allow_hosts: ImapAllowHosts::parse([".example.org"]).expect("valid"),
            ..ImapPolicy::default()
        };
        let (g, dns) = guard(policy, dns);
        for host in [
            "imap.evil.example",
            "example.org",
            "93.184.216.34",
            "127.0.0.1",
        ] {
            assert_eq!(
                g.check(host).await,
                Err(ImapRefusal::NotAllowListed),
                "{host}"
            );
        }
        assert_eq!(dns.lookups(), 0, "the allow-list is decided without DNS");
        assert!(g.check("imap.example.org").await.is_ok());
        assert_eq!(
            g.check("internal.example.org").await,
            Err(ImapRefusal::NonPublic)
        );
    }

    #[tokio::test]
    async fn a_slow_resolver_times_out_as_unresolvable() {
        let dns = FakeDns::slow(Duration::from_secs(5)).answer("slow.example", &["93.184.216.34"]);
        let (g, _) = guard(ImapPolicy::default(), dns);
        let started = std::time::Instant::now();
        assert_eq!(
            g.check("slow.example").await,
            Err(ImapRefusal::Unresolvable)
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn system_resolver_refuses_localhost() {
        let g = ImapGuard::new(ImapPolicy::default());
        assert_eq!(g.check("localhost").await, Err(ImapRefusal::NonPublic));
    }
}
