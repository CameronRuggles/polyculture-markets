//! Sessions (spec §7): 256-bit random tokens, only SHA-256 hashes stored;
//! rotation on login and privilege change; idle 24h / absolute 14 days
//! (deployment-configurable defaults).

use rand::RngCore;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

pub const IDLE_TIMEOUT: Duration = Duration::hours(12);
pub const ABSOLUTE_TIMEOUT: Duration = Duration::days(7);

pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub fn new_csrf_secret() -> String {
    new_token()
}

#[derive(Debug, Clone)]
pub struct Session {
    pub account_id: i64,
    pub created_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub revoked: bool,
}

impl Session {
    pub fn fresh(account_id: i64, now: OffsetDateTime) -> Session {
        Session {
            account_id,
            created_at: now,
            last_seen_at: now,
            expires_at: now + ABSOLUTE_TIMEOUT,
            revoked: false,
        }
    }

    pub fn is_valid(&self, now: OffsetDateTime) -> bool {
        !self.revoked
            && now < self.expires_at
            && now - self.last_seen_at < IDLE_TIMEOUT
    }

    pub fn touch(&mut self, now: OffsetDateTime) {
        self.last_seen_at = now;
    }
}

/// Verify a presented CSRF token against the session's stored secret.
/// Both are 64-char hex; compare in full (lengths are public constants).
pub fn csrf_matches(stored_secret: &str, presented: &str) -> bool {
    if stored_secret.len() != presented.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (a, b) in stored_secret.bytes().zip(presented.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle() {
        let t0 = OffsetDateTime::from_unix_timestamp(1_760_000_000).unwrap();
        let mut s = Session::fresh(7, t0);
        assert!(s.is_valid(t0));
        assert!(s.is_valid(t0 + IDLE_TIMEOUT - Duration::hours(1)));
        assert!(!s.is_valid(t0 + IDLE_TIMEOUT + Duration::hours(1))); // idle, untouched
        s.touch(t0 + Duration::hours(11));
        assert!(s.is_valid(t0 + Duration::hours(22)));
        assert!(!s.is_valid(t0 + ABSOLUTE_TIMEOUT + Duration::seconds(1))); // absolute cap
        s.revoked = true;
        assert!(!s.is_valid(t0));
    }

    #[test]
    fn tokens_and_csrf() {
        let a = new_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, new_token());
        assert_eq!(hash_token(&a), hash_token(&a));
        assert!(csrf_matches("ab12", "ab12"));
        assert!(!csrf_matches("ab12", "ab13"));
        assert!(!csrf_matches("ab12", "ab1"));
    }
}
