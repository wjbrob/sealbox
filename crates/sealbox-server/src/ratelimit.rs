//! A tiny in-memory sliding-window rate limiter keyed by (scope, client).
//!
//! Good enough for one process; swap for a shared store if the server is ever replicated.

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Default)]
struct Inner {
    buckets: HashMap<(&'static str, String), VecDeque<Instant>>,
    checks_since_gc: u32,
}

/// Sliding-window limiter: at most `limit` events per `window` for each (scope, key).
#[derive(Default)]
pub struct RateLimiter {
    inner: Mutex<Inner>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one event for `(scope, key)`; returns `true` if it is within the limit.
    pub fn check(&self, scope: &'static str, key: &str, limit: u32, window: Duration) -> bool {
        self.check_at(scope, key, limit, window, Instant::now())
    }

    fn check_at(
        &self,
        scope: &'static str,
        key: &str,
        limit: u32,
        window: Duration,
        now: Instant,
    ) -> bool {
        // A poisoned lock only means another thread panicked mid-update; the map is still usable.
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.checks_since_gc += 1;
        if inner.checks_since_gc >= 1024 {
            inner.checks_since_gc = 0;
            let cutoff = now.checked_sub(window).unwrap_or(now);
            inner.buckets.retain(|_, q| {
                while q.front().is_some_and(|t| *t <= cutoff) {
                    q.pop_front();
                }
                !q.is_empty()
            });
        }
        let bucket = inner.buckets.entry((scope, key.to_owned())).or_default();
        while bucket
            .front()
            .is_some_and(|t| now.duration_since(*t) >= window)
        {
            bucket.pop_front();
        }
        if bucket.len() as u64 >= u64::from(limit) {
            return false;
        }
        bucket.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_then_recovers_after_window() {
        let rl = RateLimiter::new();
        let t0 = Instant::now();
        let w = Duration::from_secs(60);
        for _ in 0..3 {
            assert!(rl.check_at("s", "1.2.3.4", 3, w, t0));
        }
        assert!(!rl.check_at("s", "1.2.3.4", 3, w, t0));
        // other key / other scope unaffected
        assert!(rl.check_at("s", "5.6.7.8", 3, w, t0));
        assert!(rl.check_at("other", "1.2.3.4", 3, w, t0));
        // after the window passes the client is allowed again
        assert!(rl.check_at("s", "1.2.3.4", 3, w, t0 + w));
    }
}
