//! Per-account request throttle + login-failure delay (spec §7, §20).
//! Login failures add delay per username — never a hard lockout of
//! the account, because a lockout lets an attacker freeze a stranger's
//! account; the delay is paired with a per-username attempt BUDGET
//! (audit AM1, 2026-10-18): after LOGIN_FAILURE_BUDGET failures inside
//! the window, further attempts are refused BEFORE any password
//! hashing happens, so a guessing loop pays nothing and gains nothing
//! until the window ages out.
//!
//! The failure map is capped and aged (audit AM2): it is keyed by
//! attacker-supplied username strings, so entries older than the
//! window are swept and the map never exceeds MAX_FAILURE_ENTRIES —
//! the oldest entries are evicted first when flooded.

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

/// Failed-login state for one folded username.
struct FailureEntry {
    count: u32,
    last_failure: OffsetDateTime,
}

/// Failures inside the window that exhaust a username's login budget.
pub const LOGIN_FAILURE_BUDGET: u32 = 10;
/// The budget window: failures older than this no longer count.
pub const LOGIN_FAILURE_WINDOW: Duration = Duration::hours(1);
/// Hard cap on tracked usernames; the oldest entries go first.
pub const MAX_FAILURE_ENTRIES: usize = 4096;
/// Hard cap on per-account request buckets.
const MAX_BUCKET_ENTRIES: usize = 100_000;

pub struct Throttles {
    buckets: Mutex<HashMap<i64, TokenBucket>>,
    login_failures: Mutex<HashMap<String, FailureEntry>>,
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
        if map.len() > MAX_BUCKET_ENTRIES {
            // Age out buckets idle for over an hour (a live bucket's
            // `last` moves on every request, so this only reaps the
            // abandoned ones).
            let cutoff = now - Duration::hours(1);
            map.retain(|_, b| b.last > cutoff);
        }
        map.entry(account_id)
            .or_insert_with(|| TokenBucket::new(60.0, 60.0, now))
            .allow(now)
    }

    /// Exponential login delay: failure n -> min(2^n, 300) seconds.
    pub fn record_login_failure(&self, username_folded: &str) -> Duration {
        let now = OffsetDateTime::now_utc();
        let mut map = self.login_failures.lock().unwrap();
        sweep_failures(&mut map, now);
        let n = {
            let e = map
                .entry(username_folded.to_string())
                .or_insert(FailureEntry { count: 0, last_failure: now });
            // A failure after the window has fully passed starts a
            // fresh count (the old failures aged out of the budget).
            if now - e.last_failure > LOGIN_FAILURE_WINDOW {
                e.count = 0;
            }
            e.count += 1;
            e.last_failure = now;
            e.count
        };
        if map.len() > MAX_FAILURE_ENTRIES {
            evict_oldest_failures(&mut map, MAX_FAILURE_ENTRIES);
        }
        let secs = (1u64 << n.min(8)).min(300);
        Duration::seconds(secs as i64)
    }

    /// True when this username has exhausted its attempt budget —
    /// checked by the login handler BEFORE any hashing (AM1).
    pub fn login_budget_exceeded(&self, username_folded: &str) -> bool {
        let now = OffsetDateTime::now_utc();
        let map = self.login_failures.lock().unwrap();
        match map.get(username_folded) {
            Some(e) => {
                e.count >= LOGIN_FAILURE_BUDGET
                    && now - e.last_failure <= LOGIN_FAILURE_WINDOW
            }
            None => false,
        }
    }

    pub fn clear_login_failures(&self, username_folded: &str) {
        self.login_failures.lock().unwrap().remove(username_folded);
    }

    /// Number of usernames with tracked failures (ops/tests).
    pub fn login_failure_entry_count(&self) -> usize {
        self.login_failures.lock().unwrap().len()
    }
}

/// Drop entries whose last failure is beyond the budget window.
fn sweep_failures(map: &mut HashMap<String, FailureEntry>, now: OffsetDateTime) {
    map.retain(|_, e| now - e.last_failure <= LOGIN_FAILURE_WINDOW);
}

/// Evict by oldest last-failure until the map is at `target` entries.
fn evict_oldest_failures(map: &mut HashMap<String, FailureEntry>, target: usize) {
    if map.len() <= target {
        return;
    }
    let mut stamps: Vec<(OffsetDateTime, String)> = map
        .iter()
        .map(|(k, e)| (e.last_failure, k.clone()))
        .collect();
    stamps.sort();
    let remove = map.len() - target;
    for (_, k) in stamps.into_iter().take(remove) {
        map.remove(&k);
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

    #[test]
    fn budget_trips_at_the_limit_and_is_per_user() {
        let th = Throttles::new();
        for _ in 0..LOGIN_FAILURE_BUDGET - 1 {
            th.record_login_failure("victim");
        }
        assert!(!th.login_budget_exceeded("victim"));
        th.record_login_failure("victim");
        assert!(th.login_budget_exceeded("victim"));
        assert!(!th.login_budget_exceeded("bystander"));
    }

    #[test]
    fn failure_map_is_capped_and_ages_out() {
        let th = Throttles::new();
        for i in 0..(MAX_FAILURE_ENTRIES + 500) {
            th.record_login_failure(&format!("flood{i}"));
        }
        assert!(th.login_failure_entry_count() <= MAX_FAILURE_ENTRIES);
        // Age every entry past the window by hand (module-internal),
        // then one fresh failure sweeps them all.
        {
            let mut map = th.login_failures.lock().unwrap();
            let old = OffsetDateTime::now_utc() - LOGIN_FAILURE_WINDOW - Duration::minutes(5);
            for e in map.values_mut() {
                e.last_failure = old;
            }
        }
        th.record_login_failure("fresh");
        assert_eq!(th.login_failure_entry_count(), 1);
        assert!(!th.login_budget_exceeded("flood0"), "aged failures no longer count");
    }
}
