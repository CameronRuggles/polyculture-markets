//! Per-account request throttle + login-failure delay (spec §7, §20).
//! Login failures add delay per username — never a lockout, because a
//! lockout lets an attacker freeze a stranger's account.

use std::collections::HashMap;
use std::sync::Mutex;
use time::{Duration, OffsetDateTime};

pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: OffsetDateTime,
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_per_min: f64, now: OffsetDateTime) -> Self {
        TokenBucket {
            capacity,
            tokens: capacity,
            refill_per_sec: refill_per_min / 60.0,
            last: now,
        }
    }
    pub fn allow(&mut self, now: OffsetDateTime) -> bool {
        let elapsed = (now - self.last).as_seconds_f64().max(0.0);
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct Throttles {
    buckets: Mutex<HashMap<i64, TokenBucket>>,
    login_failures: Mutex<HashMap<String, u32>>,
}

impl Throttles {
    pub fn new() -> Self {
        Throttles {
            buckets: Mutex::new(HashMap::new()),
            login_failures: Mutex::new(HashMap::new()),
        }
    }

    /// Default per-account budget: burst 60, refill 60/min (spec §20's
    /// per-account throttle spirit; deployment-tunable).
    pub fn allow_request(&self, account_id: i64, now: OffsetDateTime) -> bool {
        let mut map = self.buckets.lock().unwrap();
        map.entry(account_id)
            .or_insert_with(|| TokenBucket::new(60.0, 60.0, now))
            .allow(now)
    }

    /// Exponential login delay: failure n -> min(2^n, 300) seconds.
    pub fn record_login_failure(&self, username_folded: &str) -> Duration {
        let mut map = self.login_failures.lock().unwrap();
        let n = map.entry(username_folded.to_string()).or_insert(0);
        *n += 1;
        let secs = (1u64 << (*n).min(8)).min(300);
        Duration::seconds(secs as i64)
    }

    pub fn clear_login_failures(&self, username_folded: &str) {
        self.login_failures.lock().unwrap().remove(username_folded);
    }
}

impl Default for Throttles {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_limits_and_refills() {
        let t0 = OffsetDateTime::from_unix_timestamp(1_760_000_000).unwrap();
        let th = Throttles::new();
        for _ in 0..60 {
            assert!(th.allow_request(1, t0));
        }
        assert!(!th.allow_request(1, t0)); // burst exhausted
        assert!(th.allow_request(1, t0 + Duration::seconds(2))); // refilled
        assert!(th.allow_request(2, t0)); // other accounts unaffected
    }

    #[test]
    fn login_delay_grows_never_locks() {
        let th = Throttles::new();
        assert_eq!(th.record_login_failure("alice"), Duration::seconds(2));
        assert_eq!(th.record_login_failure("alice"), Duration::seconds(4));
        assert_eq!(th.record_login_failure("alice"), Duration::seconds(8));
        th.clear_login_failures("alice");
        assert_eq!(th.record_login_failure("alice"), Duration::seconds(2));
    }
}
