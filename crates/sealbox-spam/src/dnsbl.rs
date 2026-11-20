//! Optional DNS block-list lookups: Spamhaus ZEN for the last external relay IP and
//! Spamhaus DBL for the domains linked from the body.
//!
//! **Privacy:** every query tells the configured DNS resolver (and, through it, the
//! block-list operator) which IP addresses and domains appear in the user's incoming mail.
//! That is why `SpamSettings.dnsbl_enabled` defaults to `false`. Nothing here is ever
//! required for a verdict; lookups that fail or time out simply contribute no reason.
//!
//! The resolver is a trait so tests (and the Flutter bridge, should it want to route DNS
//! differently) can plug in their own.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::time::Duration;

use crate::features::Features;
use crate::rules::RuleHit;
use crate::util::is_public_ip;

/// A-record lookup. Return an empty vector for NXDOMAIN, errors and timeouts.
pub trait Resolver: Send + Sync {
    fn lookup_a<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Ipv4Addr>> + Send + 'a>>;
}

/// Lookup zones and limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsblConfig {
    /// Per-query timeout.
    pub timeout: Duration,
    /// Overall budget for one message.
    pub total_timeout: Duration,
    pub zen_zone: String,
    pub dbl_zone: String,
    /// At most this many distinct URL domains are queried.
    pub max_domains: usize,
}

impl Default for DnsblConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            total_timeout: Duration::from_secs(5),
            zen_zone: "zen.spamhaus.org".into(),
            dbl_zone: "dbl.spamhaus.org".into(),
            max_domains: 5,
        }
    }
}

pub const W_ZEN_SBL: f64 = 3.0;
pub const W_ZEN_XBL: f64 = 3.0;
pub const W_ZEN_PBL: f64 = 1.0;
pub const W_DBL_LISTED: f64 = 3.0;
pub const W_DBL_ABUSED_LEGIT: f64 = 1.0;

/// `1.2.3.4` → `4.3.2.1.zen.spamhaus.org`.
pub fn zen_query(ip: Ipv4Addr, zone: &str) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.{zone}", o[3], o[2], o[1], o[0])
}

/// `example.com` → `example.com.dbl.spamhaus.org`.
pub fn dbl_query(domain: &str, zone: &str) -> String {
    format!("{}.{zone}", domain.trim_end_matches('.'))
}

/// Interpret ZEN return codes (<https://www.spamhaus.org/zen/>).
pub fn interpret_zen(answers: &[Ipv4Addr]) -> Option<(&'static str, f64, String)> {
    let mut best: Option<(&'static str, f64, String)> = None;
    for a in answers {
        let o = a.octets();
        if o[0] != 127 {
            continue;
        }
        if o[1] == 255 {
            // 127.255.255.x: query refused (public resolver / rate limit) — no information.
            return None;
        }
        let hit = match (o[2], o[3]) {
            (0, 2) => (
                "dnsbl_zen_sbl",
                W_ZEN_SBL,
                "relay IP is on the Spamhaus SBL (spam source)",
            ),
            (0, 3) => (
                "dnsbl_zen_css",
                W_ZEN_SBL,
                "relay IP is on the Spamhaus CSS (snowshoe spam)",
            ),
            (0, 4..=7) => (
                "dnsbl_zen_xbl",
                W_ZEN_XBL,
                "relay IP is on the Spamhaus XBL (compromised host)",
            ),
            (0, 10 | 11) => (
                "dnsbl_zen_pbl",
                W_ZEN_PBL,
                "relay IP is on the Spamhaus PBL (should not send mail directly)",
            ),
            _ => ("dnsbl_zen", W_ZEN_PBL, "relay IP is listed by Spamhaus ZEN"),
        };
        if best.as_ref().is_none_or(|b| hit.1 > b.1) {
            best = Some((hit.0, hit.1, hit.2.to_string()));
        }
    }
    best
}

/// Interpret DBL return codes (<https://www.spamhaus.org/dbl/>).
pub fn interpret_dbl(domain: &str, answers: &[Ipv4Addr]) -> Option<(&'static str, f64, String)> {
    let mut best: Option<(&'static str, f64, String)> = None;
    for a in answers {
        let o = a.octets();
        if o[0] != 127 || o[1] != 0 || o[2] != 1 {
            if o[0] == 127 && o[1] == 255 {
                return None;
            }
            continue;
        }
        let hit = match o[3] {
            2 => (
                "dnsbl_dbl_spam",
                W_DBL_LISTED,
                format!("{domain} is a Spamhaus DBL spam domain"),
            ),
            4 => (
                "dnsbl_dbl_phish",
                W_DBL_LISTED,
                format!("{domain} is a Spamhaus DBL phishing domain"),
            ),
            5 => (
                "dnsbl_dbl_malware",
                W_DBL_LISTED,
                format!("{domain} is a Spamhaus DBL malware domain"),
            ),
            6 => (
                "dnsbl_dbl_botnet",
                W_DBL_LISTED,
                format!("{domain} is a Spamhaus DBL botnet C&C domain"),
            ),
            102..=106 => (
                "dnsbl_dbl_abused",
                W_DBL_ABUSED_LEGIT,
                format!("{domain} is a legitimate domain abused by spammers (DBL)"),
            ),
            255 => return None, // IP queries prohibited
            _ => (
                "dnsbl_dbl",
                W_DBL_ABUSED_LEGIT,
                format!("{domain} is listed by Spamhaus DBL"),
            ),
        };
        if best.as_ref().is_none_or(|b| hit.1 > b.1) {
            best = Some(hit);
        }
    }
    best
}

/// Query ZEN for the last external relay and DBL for the linked domains (plus the sender's
/// domain). Never fails; returns whatever could be learned within the budget.
pub async fn check(f: &Features, resolver: &dyn Resolver, cfg: &DnsblConfig) -> Vec<RuleHit> {
    let run = async {
        let mut hits = Vec::new();
        if let Some(IpAddr::V4(ip)) = f.last_external_ip {
            if is_public_ip(IpAddr::V4(ip)) {
                let q = zen_query(ip, &cfg.zen_zone);
                let answers = timed(cfg.timeout, resolver.lookup_a(&q)).await;
                if let Some((code, w, detail)) = interpret_zen(&answers) {
                    hits.push(RuleHit::new(code, w, format!("{detail} ({ip})")));
                }
            }
        }
        let mut domains: Vec<String> = Vec::new();
        for u in &f.urls {
            if !u.raw_ip && !domains.contains(&u.domain) {
                domains.push(u.domain.clone());
            }
        }
        if let Some(d) = &f.from_domain {
            let d = crate::util::registrable_domain(d);
            if d.parse::<IpAddr>().is_err() && !domains.contains(&d) {
                domains.push(d);
            }
        }
        for d in domains.into_iter().take(cfg.max_domains) {
            let q = dbl_query(&d, &cfg.dbl_zone);
            let answers = timed(cfg.timeout, resolver.lookup_a(&q)).await;
            if let Some((code, w, detail)) = interpret_dbl(&d, &answers) {
                hits.push(RuleHit::new(code, w, detail));
            }
        }
        hits
    };
    match tokio::time::timeout(cfg.total_timeout, run).await {
        Ok(h) => h,
        Err(_) => {
            tracing::debug!("DNSBL check exceeded its budget; ignoring");
            Vec::new()
        }
    }
}

async fn timed<F: Future<Output = Vec<Ipv4Addr>>>(t: Duration, fut: F) -> Vec<Ipv4Addr> {
    tokio::time::timeout(t, fut).await.unwrap_or_default()
}

/// The production resolver (system DNS via hickory).
pub struct HickoryResolver {
    inner: hickory_resolver::TokioResolver,
}

impl std::fmt::Debug for HickoryResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HickoryResolver")
    }
}

impl HickoryResolver {
    /// Build from the system configuration (`/etc/resolv.conf` on Unix). Must be called on a
    /// tokio runtime.
    pub fn new(timeout: Duration) -> std::result::Result<Self, String> {
        let mut builder =
            hickory_resolver::TokioResolver::builder_tokio().map_err(|e| e.to_string())?;
        let opts = builder.options_mut();
        opts.timeout = timeout
            .max(Duration::from_millis(200))
            .min(Duration::from_secs(10));
        opts.attempts = 1;
        Ok(Self {
            inner: builder.build().map_err(|e| e.to_string())?,
        })
    }
}

impl Resolver for HickoryResolver {
    fn lookup_a<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Ipv4Addr>> + Send + 'a>> {
        Box::pin(async move {
            use hickory_resolver::proto::rr::RData;
            match self.inner.ipv4_lookup(name).await {
                Ok(lookup) => lookup
                    .answers()
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::A(a) => Some(a.0),
                        _ => None,
                    })
                    .collect(),
                Err(_) => Vec::new(),
            }
        })
    }
}

/// Canned answers, for tests.
#[derive(Clone, Debug, Default)]
pub struct StaticResolver {
    pub answers: HashMap<String, Vec<Ipv4Addr>>,
}

impl Resolver for StaticResolver {
    fn lookup_a<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Ipv4Addr>> + Send + 'a>> {
        let v = self.answers.get(name).cloned().unwrap_or_default();
        Box::pin(async move { v })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::extract;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn query_names_and_codes() {
        assert_eq!(
            zen_query(ip("1.2.3.4"), "zen.spamhaus.org"),
            "4.3.2.1.zen.spamhaus.org"
        );
        assert_eq!(
            dbl_query("example.com.", "dbl.spamhaus.org"),
            "example.com.dbl.spamhaus.org"
        );
        assert_eq!(
            interpret_zen(&[ip("127.0.0.2")]).map(|h| h.0),
            Some("dnsbl_zen_sbl")
        );
        assert_eq!(
            interpret_zen(&[ip("127.0.0.11"), ip("127.0.0.4")]).map(|h| h.0),
            Some("dnsbl_zen_xbl")
        );
        assert_eq!(
            interpret_zen(&[ip("127.255.255.254")]),
            None,
            "refused queries carry no information"
        );
        assert_eq!(interpret_zen(&[]), None);
        assert_eq!(
            interpret_dbl("x.com", &[ip("127.0.1.4")]).map(|h| h.0),
            Some("dnsbl_dbl_phish")
        );
        assert_eq!(
            interpret_dbl("x.com", &[ip("127.0.1.103")]).map(|h| h.1),
            Some(W_DBL_ABUSED_LEGIT)
        );
        assert_eq!(interpret_dbl("x.com", &[ip("127.0.1.255")]), None);
    }

    #[tokio::test]
    async fn check_uses_last_external_ip_and_url_domains() {
        let raw = "Received: from mx (mx [10.0.0.1]) by me\r\nReceived: from spammer (spammer [185.199.108.153]) by mx\r\nFrom: a@sender.example\r\nSubject: x\r\n\r\nvisit http://bad.example/x and http://good.example/\r\n";
        let f = extract(raw.as_bytes()).unwrap();
        assert_eq!(
            f.last_external_ip,
            Some("185.199.108.153".parse::<IpAddr>().unwrap())
        );
        let mut r = StaticResolver::default();
        r.answers
            .insert("153.108.199.185.zen.test".into(), vec![ip("127.0.0.3")]);
        r.answers
            .insert("bad.example.dbl.test".into(), vec![ip("127.0.1.2")]);
        let cfg = DnsblConfig {
            zen_zone: "zen.test".into(),
            dbl_zone: "dbl.test".into(),
            ..Default::default()
        };
        let hits = check(&f, &r, &cfg).await;
        let codes: Vec<&str> = hits.iter().map(|h| h.code.as_str()).collect();
        assert_eq!(codes, vec!["dnsbl_zen_css", "dnsbl_dbl_spam"]);
        assert!(hits[1].detail.contains("bad.example"));
        // Nothing listed → nothing reported.
        let hits = check(&f, &StaticResolver::default(), &cfg).await;
        assert!(hits.is_empty());
    }
}
