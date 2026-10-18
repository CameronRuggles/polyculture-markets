//! Argon2id password hashing behind a global semaphore (spec §3.13, §7).
//! If the semaphore is full, callers return 503 — unbounded Argon2 queueing
//! is a memory-exhaustion DoS.

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use std::sync::Arc;
use tokio::sync::Semaphore;

pub fn argon2_params() -> Params {
    // OWASP-aligned starting point; benchmark + tune on target hardware at
    // deployment (docs/unverified.md #9).
    Params::new(64 * 1024, 3, 1, Some(32)).expect("valid params")
}

#[derive(Clone)]
pub struct HashGuard {
    sem: Arc<Semaphore>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HashError {
    /// Semaphore full — the web layer maps this to HTTP 503.
    Busy,
    Invalid,
}

impl HashGuard {
    pub fn new(permits: usize) -> Self {
        HashGuard {
            sem: Arc::new(Semaphore::new(permits)),
        }
    }

    pub async fn hash(&self, password: &str) -> Result<String, HashError> {
        let _permit = self.sem.try_acquire().map_err(|_| HashError::Busy)?;
        let pw = password.to_owned();
        tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params());
            a.hash_password(pw.as_bytes(), &salt)
                .map(|h| h.to_string())
                .map_err(|_| HashError::Invalid)
        })
        .await
        .map_err(|_| HashError::Invalid)?
    }

    pub async fn verify(&self, password: &str, stored: &str) -> Result<bool, HashError> {
        let _permit = self.sem.try_acquire().map_err(|_| HashError::Busy)?;
        let pw = password.to_owned();
        let stored = stored.to_owned();
        tokio::task::spawn_blocking(move || {
            let parsed = PasswordHash::new(&stored).map_err(|_| HashError::Invalid)?;
            Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params())
                .verify_password(pw.as_bytes(), &parsed)
                .is_ok())
        })
        .await
        .map_err(|_| HashError::Invalid)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hash_verify_roundtrip() {
        let g = HashGuard::new(2);
        let h = g.hash("correct horse battery staple").await.unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(g.verify("correct horse battery staple", &h).await.unwrap());
        assert!(!g.verify("wrong", &h).await.unwrap());
    }
}

/// Starter slice of the bundled common-passphrase list (spec §7: checked
/// offline against common passwords; the production list is a larger
/// bundled data file, deployment concern).
const COMMON: &[&str] = &[
    // Canonical top entries of every standard common-password corpus.
    "123456", "123456789", "12345", "12345678", "1234567", "qwerty", "abc123",
    "password", "111111", "123123", "admin", "letmein", "welcome", "monkey",
    "dragon", "football", "baseball", "iloveyou", "trustno1", "sunshine",
    "master", "shadow", "ashley", "michael", "ninja", "mustang", "charlie",
    // Longer forms carried over from the starter slice.
    "password1", "password123", "123456789012", "qwertyuiop12",
    "letmeinletmein", "iloveyouilove", "adminadminadmin", "welcome12345",
    "monkeymonkey1", "dragon123456", "football1234", "sunshine1234",
    "princess1234", "shadow123456", "superman1234", "michael12345",
    "correcthorsebatterystaple",
];

pub fn is_common_password(pw: &str) -> bool {
    COMMON.contains(&pw.to_lowercase().as_str())
}
