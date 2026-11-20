//! Registration rate limit per client address (R9): by default 30 `POST /v1/push/register`
//! per minute, answered with **429** and `Retry-After` beyond that.
//!
//! The algorithm is GCRA (the "virtual scheduling" form of a token bucket): one timestamp per
//! client, the theoretical arrival time `tat`. A client may send `limit` requests back to back,
//! then one every `window / limit`, which is exactly a bucket of `limit` tokens refilled at
//! `limit` per `window`. Every authenticated registration attempt counts, whatever its outcome:
//! a refused one has cost a DNS lookup too.
//!
//! Clients are keyed by IPv4 address, by IPv6 `/64` (one subscriber usually holds a whole
//! `/64`) and by the canonical IPv4 address for IPv4-mapped IPv6. The table holds at most
//! `max_clients` entries. Entries that have fully refilled are dropped when it is full, and if
//! it is still full a *new* client is refused (fail closed) rather than tracked.
//!
//! Behind a reverse proxy every client shares the proxy's address, so the limit becomes
//! relay-wide. `X-Forwarded-For` is deliberately not trusted (any client could set it).

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

/// Default `--register-rate-limit`: registrations per client per [`DEFAULT_WINDOW`].
pub const DEFAULT_LIMIT: u32 = 30;
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);
/// Default bound on the number of clients tracked at once.
pub const DEFAULT_MAX_CLIENTS: usize = 65_536;
/// A full table is swept for refilled entries at most this often.
const SWEEP_EVERY: Duration = Duration::from_secs(1);

/// Who is counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClientKey {
    V4(Ipv4Addr),
    /// The first 64 bits of an IPv6 address.
    V6Net([u16; 4]),
    /// No peer address was available (the router was served without connect info).
    Unknown,
}

impl ClientKey {
    pub fn of(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => {
                let s = v6.segments();
                Self::V6Net([s[0], s[1], s[2], s[3]])
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Limited { retry_after: Duration },
}

impl Decision {
    /// `Retry-After` in whole seconds, rounded up, at least 1.
    pub fn retry_after_secs(retry_after: Duration) -> u64 {
        let secs = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
        secs.max(1)
    }
}

struct Table {
    tat: HashMap<ClientKey, Instant>,
    last_sweep: Option<Instant>,
}

/// The limiter. `limit == 0` disables it.
pub struct RateLimiter {
    limit: u32,
    window: Duration,
    max_clients: usize,
    table: Mutex<Table>,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("limit", &self.limit)
            .field("window", &self.window)
            .field("max_clients", &self.max_clients)
            .finish()
    }
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration, max_clients: usize) -> Self {
        Self {
            limit,
            window,
            max_clients: max_clients.max(1),
            table: Mutex::new(Table {
                tat: HashMap::new(),
                last_sweep: None,
            }),
        }
    }

    pub fn limit(&self) -> u32 {
        self.limit
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Count one request from `key` now.
    pub fn check(&self, key: ClientKey) -> Decision {
        self.check_at(key, Instant::now())
    }

    /// Count one request from `key` at `now` (monotonic; tests pass their own clock).
    pub fn check_at(&self, key: ClientKey, now: Instant) -> Decision {
        if self.limit == 0 || self.window.is_zero() {
            return Decision::Allowed;
        }
        // Emission interval and burst tolerance: `limit` back-to-back requests, then one per
        // interval.
        let interval = self.window / self.limit;
        let tolerance = self.window.saturating_sub(interval);
        let mut table = self.table();
        if !table.tat.contains_key(&key) && table.tat.len() >= self.max_clients {
            let due = table
                .last_sweep
                .is_none_or(|t| now.saturating_duration_since(t) >= SWEEP_EVERY);
            if due {
                table.tat.retain(|_, tat| *tat > now);
                table.last_sweep = Some(now);
            }
            if table.tat.len() >= self.max_clients {
                return Decision::Limited {
                    retry_after: self.window,
                };
            }
        }
        let tat = table.tat.get(&key).map_or(now, |t| (*t).max(now));
        let ahead = tat.saturating_duration_since(now);
        if ahead > tolerance {
            return Decision::Limited {
                retry_after: ahead - tolerance,
            };
        }
        table.tat.insert(key, tat + interval);
        Decision::Allowed
    }

    /// Clients currently tracked.
    pub fn tracked(&self) -> usize {
        self.table().tat.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> ClientKey {
        ClientKey::of(s.parse().expect("ip"))
    }

    fn limited(d: Decision) -> Duration {
        match d {
            Decision::Limited { retry_after } => retry_after,
            Decision::Allowed => panic!("expected a 429"),
        }
    }

    #[test]
    fn thirty_per_minute_then_one_every_two_seconds() {
        let rl = RateLimiter::new(30, Duration::from_secs(60), 100);
        let t0 = Instant::now();
        let a = v4("198.51.100.7");
        for i in 0..30 {
            assert_eq!(rl.check_at(a, t0), Decision::Allowed, "request {i}");
        }
        let wait = limited(rl.check_at(a, t0));
        assert_eq!(wait, Duration::from_secs(2));
        assert_eq!(Decision::retry_after_secs(wait), 2);
        // Still limited just before the next token, allowed once it is there, then limited.
        assert!(matches!(
            rl.check_at(a, t0 + Duration::from_millis(1999)),
            Decision::Limited { .. }
        ));
        assert_eq!(
            rl.check_at(a, t0 + Duration::from_secs(2)),
            Decision::Allowed
        );
        assert!(matches!(
            rl.check_at(a, t0 + Duration::from_secs(2)),
            Decision::Limited { .. }
        ));
        // A full minute of silence refills the whole burst.
        let later = t0 + Duration::from_secs(62);
        for i in 0..30 {
            assert_eq!(rl.check_at(a, later), Decision::Allowed, "refilled {i}");
        }
        assert!(matches!(rl.check_at(a, later), Decision::Limited { .. }));
    }

    #[test]
    fn clients_are_independent_and_ipv6_counts_per_64() {
        let rl = RateLimiter::new(2, Duration::from_secs(60), 100);
        let t0 = Instant::now();
        let a = v4("192.0.2.1");
        let b = v4("192.0.2.2");
        assert_eq!(rl.check_at(a, t0), Decision::Allowed);
        assert_eq!(rl.check_at(a, t0), Decision::Allowed);
        assert!(matches!(rl.check_at(a, t0), Decision::Limited { .. }));
        assert_eq!(rl.check_at(b, t0), Decision::Allowed);

        // Two addresses in one /64 share a budget; another /64 does not.
        let x1 = ClientKey::of("2001:db8:1:2::1".parse().expect("ip"));
        let x2 = ClientKey::of("2001:db8:1:2:ffff::9".parse().expect("ip"));
        let y = ClientKey::of("2001:db8:1:3::1".parse().expect("ip"));
        assert_eq!(x1, x2);
        assert_ne!(x1, y);
        assert_eq!(rl.check_at(x1, t0), Decision::Allowed);
        assert_eq!(rl.check_at(x2, t0), Decision::Allowed);
        assert!(matches!(rl.check_at(x1, t0), Decision::Limited { .. }));
        assert_eq!(rl.check_at(y, t0), Decision::Allowed);

        // IPv4-mapped IPv6 is the IPv4 client.
        assert_eq!(
            ClientKey::of("::ffff:192.0.2.1".parse().expect("ip")),
            v4("192.0.2.1")
        );
    }

    #[test]
    fn full_table_drops_refilled_clients_then_fails_closed() {
        let rl = RateLimiter::new(1, Duration::from_secs(10), 2);
        let t0 = Instant::now();
        assert_eq!(rl.check_at(v4("192.0.2.1"), t0), Decision::Allowed);
        assert_eq!(rl.check_at(v4("192.0.2.2"), t0), Decision::Allowed);
        // Full, nobody has refilled yet: a third client is refused, not tracked.
        let wait = limited(rl.check_at(v4("192.0.2.3"), t0));
        assert_eq!(wait, Duration::from_secs(10));
        assert_eq!(rl.tracked(), 2);
        // Known clients are still counted normally.
        assert!(matches!(
            rl.check_at(v4("192.0.2.1"), t0),
            Decision::Limited { .. }
        ));
        // Once both have refilled, the sweep makes room.
        let later = t0 + Duration::from_secs(11);
        assert_eq!(rl.check_at(v4("192.0.2.3"), later), Decision::Allowed);
        assert_eq!(rl.tracked(), 1);
    }

    #[test]
    fn zero_disables() {
        let rl = RateLimiter::new(0, Duration::from_secs(60), 1);
        let t0 = Instant::now();
        for _ in 0..1000 {
            assert_eq!(rl.check_at(ClientKey::Unknown, t0), Decision::Allowed);
        }
        assert_eq!(rl.tracked(), 0);
    }

    #[test]
    fn retry_after_rounds_up() {
        assert_eq!(Decision::retry_after_secs(Duration::from_millis(1)), 1);
        assert_eq!(Decision::retry_after_secs(Duration::from_millis(2001)), 3);
        assert_eq!(Decision::retry_after_secs(Duration::ZERO), 1);
        assert_eq!(Decision::retry_after_secs(Duration::from_secs(60)), 60);
    }
}
