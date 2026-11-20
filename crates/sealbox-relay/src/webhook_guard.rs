//! Webhook destination policy: the relay's guard against server-side request forgery (R9).
//!
//! The client that registers chooses the webhook URL. Without a policy it could make the relay
//! POST to anything the relay can reach: the cloud metadata service (`169.254.169.254`), an
//! admin port on loopback, a database in the private network. The guard runs twice:
//!
//! 1. **At registration** ([`WebhookGuard::check`]): the URL must be `https`, its host must be
//!    on the allow-list when one is configured, and every address the host resolves to must be
//!    public. Plain `http` is accepted only for a non-public destination on a relay started
//!    with `--webhook-allow-http-private`, and a non-public destination only with
//!    `--webhook-allow-private`. Both are development and test escape hatches.
//! 2. **At every delivery**: the webhook clients built by [`Webhooks`] resolve names through
//!    [`WebhookGuard::resolve_checked`] (installed as reqwest's DNS resolver), so the name is
//!    resolved again and the connection is opened only to addresses that passed the same check.
//!    A DNS answer that changed after the registration (rebinding) cannot redirect a push:
//!    check and connect use one and the same answer. Only the socket address comes from the
//!    resolver; reqwest still takes the `Host` header, the TLS SNI and the certificate name from
//!    the URL. IP-literal URLs never reach a resolver, so the transport re-checks the literal
//!    before each send. Proxies are disabled for these clients (a proxy would resolve the name
//!    itself), and redirects are not followed (a redirect to an IP literal would bypass the
//!    resolver).
//!
//! Refusal messages ([`Refusal`]) describe the rule only, never the URL, the host or an address.

use std::{
    collections::HashSet,
    fmt, io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use reqwest::{
    dns::{Addrs, Name, Resolve, Resolving},
    Url,
};

use crate::{
    host_class,
    push::{BoxFuture, WebhookTransport},
    secret::Secret,
};

/// How long one DNS lookup for a webhook host may take, at registration and at delivery.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a webhook URL, or one delivery, was refused. The `Display` texts are the API's 400
/// reasons verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("transport.url host is not on this relay's webhook allow-list")]
    NotAllowListed,
    #[error(
        "transport.url must use https (plain http is accepted only for a private destination, \
         on a relay started with --webhook-allow-http-private)"
    )]
    HttpsRequired,
    #[error("transport.url host could not be resolved")]
    Unresolvable,
    #[error(
        "transport.url resolves to a non-public address (loopback, private, link-local, \
         unique-local, shared, multicast, unspecified or reserved), which this relay does not \
         push to"
    )]
    NonPublic,
}

/// The first [`Refusal`] in `err`'s source chain: how a delivery-time refusal from the
/// resolver is recognised inside a reqwest error.
pub fn refusal_in(err: &(dyn std::error::Error + 'static)) -> Option<Refusal> {
    let mut current = Some(err);
    while let Some(e) = current {
        if let Some(r) = e.downcast_ref::<Refusal>() {
            return Some(*r);
        }
        current = e.source();
    }
    None
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn of(url: &Url) -> Option<Self> {
        match url.scheme() {
            "https" => Some(Self::Https),
            "http" => Some(Self::Http),
            _ => None,
        }
    }
}

/// A webhook URL's host as the guard sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebhookHost {
    /// A DNS name, exactly as it appears in the URL (and as reqwest will resolve it).
    Name(String),
    Ip(IpAddr),
}

impl WebhookHost {
    /// `Url` has already normalised the host: IDNA to punycode, ASCII lowercase, and every
    /// IPv4 spelling (`0x7f.1`, `2130706433` …) to dotted decimal, so a numeric trick cannot
    /// pass as a name.
    pub fn of(url: &Url) -> Option<Self> {
        let host = url.host_str()?;
        Some(match host_class::ip_literal(host) {
            Some(ip) => Self::Ip(ip),
            None => Self::Name(host.to_owned()),
        })
    }
}

/// `--webhook-allow-hosts`: when configured, the only webhook hosts the relay accepts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AllowHosts {
    /// Normalised names; each also admits its subdomains (domain-boundary match).
    names: Vec<String>,
    /// IP literals, matched exactly.
    ips: Vec<IpAddr>,
}

impl AllowHosts {
    /// Parse entries such as `push.example.com`, `example.org`, `203.0.113.7`, `2001:db8::1`.
    /// Names are normalised the way URL hosts are (lowercase, punycode, no trailing dot).
    /// Blank entries are skipped; `Ok(None)` means no allow-list.
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
                    "--webhook-allow-hosts: {entry:?}: list the domain itself (a name already \
                     admits its subdomains), without a wildcard"
                ));
            }
            let parsed = Url::parse(&format!("https://{entry}/")).ok().filter(|u| {
                u.port().is_none()
                    && u.path() == "/"
                    && u.username().is_empty()
                    && u.password().is_none()
                    && u.query().is_none()
                    && u.fragment().is_none()
            });
            match parsed.as_ref().and_then(WebhookHost::of) {
                Some(WebhookHost::Ip(ip)) => list.ips.push(ip),
                Some(WebhookHost::Name(name)) => {
                    let name = name.strip_suffix('.').unwrap_or(&name).to_owned();
                    if name.is_empty() || name.split('.').any(str::is_empty) {
                        return Err(format!(
                            "--webhook-allow-hosts: {entry:?} is not a host name"
                        ));
                    }
                    list.names.push(name);
                }
                None => {
                    return Err(format!(
                        "--webhook-allow-hosts: {entry:?} is not a host name or IP address"
                    ))
                }
            }
        }
        Ok((!list.names.is_empty() || !list.ips.is_empty()).then_some(list))
    }

    pub fn matches(&self, host: &WebhookHost) -> bool {
        match host {
            WebhookHost::Ip(ip) => self.ips.contains(ip),
            WebhookHost::Name(name) => {
                let name = name.strip_suffix('.').unwrap_or(name);
                self.names.iter().any(|allowed| {
                    name == allowed
                        || (name.len() > allowed.len()
                            && name.ends_with(allowed.as_str())
                            && name.as_bytes()[name.len() - allowed.len() - 1] == b'.')
                })
            }
        }
    }

    /// The entries, for the startup log.
    pub fn entries(&self) -> Vec<String> {
        self.names
            .iter()
            .cloned()
            .chain(self.ips.iter().map(IpAddr::to_string))
            .collect()
    }
}

/// Which webhook destinations the relay accepts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WebhookPolicy {
    /// Development and tests: accept loopback, private, link-local … destinations.
    pub allow_private: bool,
    /// Development: accept `http://` for a non-public destination (needs `allow_private`).
    pub allow_http_private: bool,
    /// When set, the only hosts accepted (checked in addition to everything else).
    pub allow_hosts: Option<AllowHosts>,
}

impl WebhookPolicy {
    /// May a webhook with `scheme` connect to `ip`?
    pub fn check_addr(&self, scheme: Scheme, ip: IpAddr) -> Result<(), Refusal> {
        let public = host_class::classify(ip).is_public();
        match scheme {
            Scheme::Https if public || self.allow_private => Ok(()),
            Scheme::Https => Err(Refusal::NonPublic),
            // Plain http only ever to a non-public destination, and only in development.
            Scheme::Http if public || !self.allow_http_private => Err(Refusal::HttpsRequired),
            Scheme::Http if !self.allow_private => Err(Refusal::NonPublic),
            Scheme::Http => Ok(()),
        }
    }

    /// Every address must pass; an empty answer is unresolvable.
    pub fn check_addrs(&self, scheme: Scheme, addrs: &[IpAddr]) -> Result<(), Refusal> {
        if addrs.is_empty() {
            return Err(Refusal::Unresolvable);
        }
        addrs.iter().try_for_each(|ip| self.check_addr(scheme, *ip))
    }
}

/// Name → addresses. [`SystemResolver`] in production; tests substitute their own answers.
pub trait NameResolver: Send + Sync + fmt::Debug {
    fn lookup<'a>(&'a self, name: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>>;
}

/// The operating system's resolver (`tokio::net::lookup_host`, i.e. `getaddrinfo`).
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl NameResolver for SystemResolver {
    fn lookup<'a>(&'a self, name: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((name, 0)).await?;
            Ok(addrs.map(|a| a.ip()).collect())
        })
    }
}

/// The policy plus the resolver it checks answers from.
#[derive(Debug)]
pub struct WebhookGuard {
    policy: WebhookPolicy,
    resolver: Arc<dyn NameResolver>,
    timeout: Duration,
}

impl WebhookGuard {
    pub fn new(policy: WebhookPolicy) -> Self {
        Self::with_resolver(policy, Arc::new(SystemResolver), RESOLVE_TIMEOUT)
    }

    pub fn with_resolver(
        policy: WebhookPolicy,
        resolver: Arc<dyn NameResolver>,
        timeout: Duration,
    ) -> Self {
        Self {
            policy,
            resolver,
            timeout,
        }
    }

    pub fn policy(&self) -> &WebhookPolicy {
        &self.policy
    }

    /// The registration-time check of a parsed webhook URL.
    pub async fn check(&self, url: &Url) -> Result<(), Refusal> {
        let scheme = Scheme::of(url).ok_or(Refusal::HttpsRequired)?;
        let host = WebhookHost::of(url).ok_or(Refusal::Unresolvable)?;
        if let Some(allow) = &self.policy.allow_hosts {
            if !allow.matches(&host) {
                return Err(Refusal::NotAllowListed);
            }
        }
        if scheme == Scheme::Http && !self.policy.allow_http_private {
            return Err(Refusal::HttpsRequired);
        }
        match host {
            WebhookHost::Ip(ip) => self.policy.check_addr(scheme, ip),
            WebhookHost::Name(name) => self.resolve_checked(scheme, &name).await.map(drop),
        }
    }

    /// Resolve `name` now and return its addresses only if every one of them passes the policy
    /// for `scheme`. This is the delivery-time check: the webhook clients connect to exactly
    /// these addresses.
    pub async fn resolve_checked(
        &self,
        scheme: Scheme,
        name: &str,
    ) -> Result<Vec<IpAddr>, Refusal> {
        let addrs = lookup(self.resolver.as_ref(), name, self.timeout)
            .await
            .ok_or(Refusal::Unresolvable)?;
        self.policy.check_addrs(scheme, &addrs)?;
        Ok(addrs)
    }
}

/// Resolve `name` with `resolver` within `timeout`, without duplicates (first occurrence
/// kept). `None` when the lookup failed or timed out. Shared by the webhook guard and the IMAP
/// guard ([`crate::imap_guard`]).
pub(crate) async fn lookup(
    resolver: &dyn NameResolver,
    name: &str,
    timeout: Duration,
) -> Option<Vec<IpAddr>> {
    let addrs = match tokio::time::timeout(timeout, resolver.lookup(name)).await {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(_)) | Err(_) => return None,
    };
    let mut seen = HashSet::new();
    Some(addrs.into_iter().filter(|a| seen.insert(*a)).collect())
}

/// reqwest DNS hook: every connection a webhook client opens to a name.
struct GuardedResolver {
    guard: Arc<WebhookGuard>,
    scheme: Scheme,
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let guard = self.guard.clone();
        let scheme = self.scheme;
        let name = name.as_str().to_owned();
        Box::pin(async move {
            let addrs = guard
                .resolve_checked(scheme, &name)
                .await
                .map_err(|refusal| Box::new(refusal) as Box<dyn std::error::Error + Send + Sync>)?;
            // Port 0: reqwest fills in the URL's port (or the scheme default).
            let addrs: Addrs = Box::new(
                addrs
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, 0))
                    .collect::<Vec<_>>()
                    .into_iter(),
            );
            Ok(addrs)
        })
    }
}

/// The guard plus one guarded HTTP client per scheme; builds the webhook transports.
#[derive(Clone, Debug)]
pub struct Webhooks {
    guard: Arc<WebhookGuard>,
    https: reqwest::Client,
    http: reqwest::Client,
}

impl Webhooks {
    pub fn new(guard: WebhookGuard) -> Result<Self, reqwest::Error> {
        let guard = Arc::new(guard);
        Ok(Self {
            https: guarded_client(&guard, Scheme::Https)?,
            http: guarded_client(&guard, Scheme::Http)?,
            guard,
        })
    }

    pub fn guard(&self) -> &WebhookGuard {
        &self.guard
    }

    /// The registration-time check ([`WebhookGuard::check`]).
    pub async fn check(&self, url: &Url) -> Result<(), Refusal> {
        self.guard.check(url).await
    }

    /// A transport for an `http(s)` URL that already passed [`Webhooks::check`]. Its client
    /// re-checks the destination of every delivery.
    pub fn transport(&self, url: &Url, bearer: Option<Secret>) -> WebhookTransport {
        let scheme = Scheme::of(url).unwrap_or(Scheme::Https);
        let client = match scheme {
            Scheme::Https => self.https.clone(),
            Scheme::Http => self.http.clone(),
        };
        let literal = match WebhookHost::of(url) {
            Some(WebhookHost::Ip(ip)) => Some(ip),
            _ => None,
        };
        WebhookTransport::new(client, url.to_string(), bearer).guarded(
            self.guard.clone(),
            scheme,
            literal,
        )
    }
}

fn guarded_client(
    guard: &Arc<WebhookGuard>,
    scheme: Scheme,
) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(WebhookTransport::TIMEOUT)
        // A redirect could carry the bearer to a third host, and a redirect to an IP literal
        // would skip the resolver check; receivers answer 2xx directly.
        .redirect(reqwest::redirect::Policy::none())
        // A proxy would resolve the name itself, out of the guard's reach.
        .no_proxy()
        .user_agent(concat!("sealbox-relay/", env!("CARGO_PKG_VERSION")))
        .dns_resolver(Arc::new(GuardedResolver {
            guard: guard.clone(),
            scheme,
        }))
        .build()
}

/// A scripted resolver for tests: per name, a queue of answers (the last one repeats).
#[cfg(test)]
pub(crate) mod test_dns {
    use std::{
        collections::{HashMap, VecDeque},
        io,
        net::IpAddr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
        time::Duration,
    };

    use super::NameResolver;
    use crate::push::BoxFuture;

    #[derive(Debug, Default)]
    pub(crate) struct FakeDns {
        answers: Mutex<HashMap<String, VecDeque<Vec<IpAddr>>>>,
        delay: Option<Duration>,
        lookups: AtomicUsize,
    }

    impl FakeDns {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        /// Every lookup sleeps `delay` first (to exercise the timeout).
        pub(crate) fn slow(delay: Duration) -> Self {
            Self {
                delay: Some(delay),
                ..Self::default()
            }
        }

        /// Queue `ips` as the next answer for `name`.
        pub(crate) fn answer(self, name: &str, ips: &[&str]) -> Self {
            let ips = ips.iter().map(|ip| ip.parse().expect("ip")).collect();
            self.answers
                .lock()
                .expect("lock")
                .entry(name.to_owned())
                .or_default()
                .push_back(ips);
            self
        }

        pub(crate) fn lookups(&self) -> usize {
            self.lookups.load(Ordering::SeqCst)
        }
    }

    impl NameResolver for FakeDns {
        fn lookup<'a>(&'a self, name: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
            Box::pin(async move {
                self.lookups.fetch_add(1, Ordering::SeqCst);
                if let Some(d) = self.delay {
                    tokio::time::sleep(d).await;
                }
                let mut answers = self.answers.lock().expect("lock");
                let queue = answers
                    .get_mut(name)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "NXDOMAIN"))?;
                let ips = if queue.len() > 1 {
                    queue.pop_front().unwrap_or_default()
                } else {
                    queue.front().cloned().unwrap_or_default()
                };
                Ok(ips)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{test_dns::FakeDns, *};
    use crate::{error::PushError, push::PushEvent, push::PushTransport};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn url(s: &str) -> Url {
        Url::parse(s).expect("url")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    fn policy(allow_private: bool, allow_http_private: bool) -> WebhookPolicy {
        WebhookPolicy {
            allow_private,
            allow_http_private,
            allow_hosts: None,
        }
    }

    fn guard(policy: WebhookPolicy, dns: FakeDns) -> (WebhookGuard, Arc<FakeDns>) {
        let dns = Arc::new(dns);
        let g = WebhookGuard::with_resolver(policy, dns.clone(), Duration::from_millis(300));
        (g, dns)
    }

    #[test]
    fn address_policy_matrix() {
        use Refusal::*;
        use Scheme::*;
        let public = ip("93.184.216.34");
        let loopback = ip("127.0.0.1");
        let metadata = ip("169.254.169.254");
        let cases = [
            // (allow_private, allow_http_private, scheme, address, expected)
            (false, false, Https, public, Ok(())),
            (false, false, Https, loopback, Err(NonPublic)),
            (false, false, Https, metadata, Err(NonPublic)),
            (false, false, Http, public, Err(HttpsRequired)),
            (false, false, Http, loopback, Err(HttpsRequired)),
            (true, false, Https, loopback, Ok(())),
            (true, false, Http, loopback, Err(HttpsRequired)),
            (false, true, Http, loopback, Err(NonPublic)),
            (false, true, Http, public, Err(HttpsRequired)),
            (true, true, Http, loopback, Ok(())),
            (true, true, Http, metadata, Ok(())),
            (true, true, Http, public, Err(HttpsRequired)),
            (true, true, Https, public, Ok(())),
        ];
        for (private, http_private, scheme, addr, want) in cases {
            assert_eq!(
                policy(private, http_private).check_addr(scheme, addr),
                want,
                "{private} {http_private} {scheme:?} {addr}"
            );
        }
        // Every address must pass, and an empty answer is not an answer.
        let p = policy(false, false);
        assert_eq!(p.check_addrs(Https, &[public, loopback]), Err(NonPublic));
        assert_eq!(p.check_addrs(Https, &[]), Err(Unresolvable));
        assert_eq!(p.check_addrs(Https, &[public, ip("2606:4700::1")]), Ok(()));
    }

    #[test]
    fn allow_list_parses_normalises_and_matches_on_a_domain_boundary() {
        let list = AllowHosts::parse([
            " Push.Example.COM ",
            "",
            "hooks.example.org.",
            "203.0.113.7",
            "2001:db8::1",
            "[2001:db8::2]",
            "bücher.example",
        ])
        .expect("valid")
        .expect("non-empty");
        assert_eq!(
            list.entries(),
            [
                "push.example.com",
                "hooks.example.org",
                "xn--bcher-kva.example",
                "203.0.113.7",
                "2001:db8::1",
                "2001:db8::2"
            ]
        );
        let host = |u: &str| WebhookHost::of(&url(u)).expect("host");
        for ok in [
            "https://push.example.com/h",
            "https://PUSH.example.com./h",
            "https://eu.push.example.com/h",
            "https://a.b.hooks.example.org/x",
            "https://203.0.113.7/h",
            "https://[2001:db8::1]/h",
            "https://[2001:db8::2]:8443/h",
            "https://bücher.example/h",
            // 0xcb007107 is 203.0.113.7: `Url` normalises the spelling before matching.
            "https://0xcb007107/h",
        ] {
            assert!(list.matches(&host(ok)), "{ok}");
        }
        for no in [
            "https://evilpush.example.com/h",
            "https://push.example.com.evil.net/h",
            "https://example.com/h",
            "https://203.0.113.8/h",
            "https://[2001:db8::3]/h",
        ] {
            assert!(!list.matches(&host(no)), "{no}");
        }

        assert_eq!(AllowHosts::parse(["", "  "]), Ok(None));
        for bad in [
            "*.example.com",
            "push.example.com:8443",
            "https://push.example.com",
            "push.example.com/path",
            "user@push.example.com",
            "a..b",
        ] {
            assert!(AllowHosts::parse([bad]).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn registration_check_resolves_and_refuses_non_public_answers() {
        let dns = FakeDns::new()
            .answer("push.example", &["93.184.216.34", "2606:4700::6810:84e5"])
            .answer("metadata.example", &["169.254.169.254"])
            .answer("mixed.example", &["93.184.216.34", "10.0.0.7"])
            .answer("mapped.example", &["::ffff:127.0.0.1"])
            .answer("empty.example", &[]);
        let (g, _) = guard(WebhookPolicy::default(), dns);
        assert_eq!(
            g.check(&url("https://push.example/hook?cap=x")).await,
            Ok(())
        );
        for (u, want) in [
            ("https://metadata.example/latest", Refusal::NonPublic),
            ("https://mixed.example/h", Refusal::NonPublic),
            ("https://mapped.example/h", Refusal::NonPublic),
            ("https://empty.example/h", Refusal::Unresolvable),
            ("https://nxdomain.example/h", Refusal::Unresolvable),
            ("http://push.example/h", Refusal::HttpsRequired),
            // IP literals need no DNS; `Url` turns numeric spellings into dotted decimal.
            ("https://127.0.0.1:8080/h", Refusal::NonPublic),
            (
                "https://169.254.169.254/latest/meta-data/",
                Refusal::NonPublic,
            ),
            ("https://0x7f000001/h", Refusal::NonPublic),
            ("https://2130706433/h", Refusal::NonPublic),
            ("https://[::1]/h", Refusal::NonPublic),
            ("https://[::ffff:a9fe:a9fe]/h", Refusal::NonPublic),
            ("https://[fd00::1]/h", Refusal::NonPublic),
            ("https://0.0.0.0/h", Refusal::NonPublic),
            ("https://[::]/h", Refusal::NonPublic),
            ("http://8.8.8.8/h", Refusal::HttpsRequired),
        ] {
            assert_eq!(g.check(&url(u)).await, Err(want), "{u}");
        }
        assert_eq!(g.check(&url("https://93.184.216.34/h")).await, Ok(()));
    }

    #[tokio::test]
    async fn allow_list_is_checked_before_any_lookup_and_does_not_waive_the_address_check() {
        let dns = FakeDns::new()
            .answer("push.example", &["93.184.216.34"])
            .answer("eu.push.example", &["93.184.216.35"])
            .answer("internal.push.example", &["10.1.2.3"]);
        let policy = WebhookPolicy {
            allow_hosts: AllowHosts::parse(["push.example"]).expect("valid"),
            ..WebhookPolicy::default()
        };
        let (g, dns) = guard(policy, dns);
        for u in [
            "https://evilpush.example/h",
            "https://push.example.evil.net/h",
            "https://93.184.216.34/h",
        ] {
            assert_eq!(g.check(&url(u)).await, Err(Refusal::NotAllowListed), "{u}");
        }
        assert_eq!(dns.lookups(), 0, "the allow-list is decided without DNS");
        assert_eq!(g.check(&url("https://push.example/h")).await, Ok(()));
        assert_eq!(g.check(&url("https://eu.push.example/h")).await, Ok(()));
        assert_eq!(
            g.check(&url("https://internal.push.example/h")).await,
            Err(Refusal::NonPublic)
        );
        assert_eq!(
            g.check(&url("http://push.example/h")).await,
            Err(Refusal::HttpsRequired)
        );
    }

    #[tokio::test]
    async fn a_slow_resolver_times_out_as_unresolvable() {
        let dns = FakeDns::slow(Duration::from_secs(5)).answer("slow.example", &["93.184.216.34"]);
        let (g, _) = guard(WebhookPolicy::default(), dns);
        let started = std::time::Instant::now();
        assert_eq!(
            g.check(&url("https://slow.example/h")).await,
            Err(Refusal::Unresolvable)
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn system_resolver_refuses_localhost() {
        let g = WebhookGuard::new(WebhookPolicy::default());
        assert_eq!(
            g.check(&url("https://localhost:9/h")).await,
            Err(Refusal::NonPublic)
        );
    }

    /// A raw TCP listener that counts connections (and answers HTTP 204 to each request).
    async fn counting_server() -> (u16, Arc<AtomicUsize>, Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let requests: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        tokio::spawn({
            let (accepted, requests) = (accepted.clone(), requests.clone());
            async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    accepted.fetch_add(1, Ordering::SeqCst);
                    let requests = requests.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 8192];
                        let mut got = Vec::new();
                        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                            match sock.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => got.extend_from_slice(&buf[..n]),
                            }
                        }
                        requests
                            .lock()
                            .expect("lock")
                            .push(String::from_utf8_lossy(&got).into_owned());
                        let _ = sock
                            .write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n")
                            .await;
                    });
                }
            }
        });
        (port, accepted, requests)
    }

    #[tokio::test]
    async fn delivery_connects_to_the_checked_address_and_keeps_the_host_header() {
        let (port, accepted, requests) = counting_server().await;
        let dns = FakeDns::new().answer("hook.example", &["127.0.0.1"]);
        let (g, dns) = guard(policy(true, true), dns);
        let hooks = Webhooks::new(g).expect("clients");
        let u = url(&format!("http://hook.example:{port}/hook?cap=c4p"));
        hooks
            .check(&u)
            .await
            .expect("dev policy accepts a loopback hook");
        let t = hooks.transport(&u, None);
        assert!(t.is_guarded());
        t.send(&PushEvent::new_mail("reg-1", "INBOX"))
            .await
            .expect("push to the pinned address");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        let req = requests.lock().expect("lock")[0].to_ascii_lowercase();
        assert!(req.starts_with("post /hook?cap=c4p http/1.1"), "{req}");
        assert!(
            req.contains(&format!("\r\nhost: hook.example:{port}\r\n")),
            "the Host header keeps the original name: {req}"
        );
        // Registration and delivery each resolved the name.
        assert_eq!(dns.lookups(), 2);
    }

    #[tokio::test]
    async fn a_name_that_rebinds_to_loopback_after_registration_is_refused_at_delivery() {
        let (port, accepted, _) = counting_server().await;
        // First answer public (registration), every later one loopback (delivery).
        let dns = FakeDns::new()
            .answer("rebind.example", &["93.184.216.34"])
            .answer("rebind.example", &["127.0.0.1"]);
        let (g, _) = guard(WebhookPolicy::default(), dns);
        let hooks = Webhooks::new(g).expect("clients");
        let u = url(&format!("https://rebind.example:{port}/hook?cap=c4p"));
        hooks.check(&u).await.expect("public at registration time");
        let t = hooks.transport(&u, Some(Secret::new("bearer-1")));
        let err = t
            .send(&PushEvent::new_mail("reg-1", "INBOX"))
            .await
            .expect_err("loopback at delivery time must be refused");
        assert!(
            matches!(err, PushError::Refused(Refusal::NonPublic)),
            "{err:?}"
        );
        let text = err.to_string();
        assert!(
            !text.contains("rebind.example") && !text.contains("c4p"),
            "{text}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 0, "no connection was made");
    }

    #[tokio::test]
    async fn ip_literal_destinations_are_rechecked_before_every_send() {
        let (port, accepted, _) = counting_server().await;
        let (g, _) = guard(WebhookPolicy::default(), FakeDns::new());
        let hooks = Webhooks::new(g).expect("clients");
        // Built without `check` (as if the policy had been looser at registration).
        let t = hooks.transport(&url(&format!("https://127.0.0.1:{port}/h")), None);
        let err = t
            .send(&PushEvent::new_mail("reg-1", "INBOX"))
            .await
            .expect_err("refused");
        assert!(
            matches!(err, PushError::Refused(Refusal::NonPublic)),
            "{err:?}"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn refusal_is_found_in_an_error_chain() {
        #[derive(Debug)]
        struct Outer(Box<dyn std::error::Error + Send + Sync>);
        impl fmt::Display for Outer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("outer")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(self.0.as_ref())
            }
        }
        let e = Outer(Box::new(Refusal::NonPublic));
        assert_eq!(refusal_in(&e), Some(Refusal::NonPublic));
        let plain = io::Error::other("nope");
        assert_eq!(refusal_in(&plain), None);
    }
}
