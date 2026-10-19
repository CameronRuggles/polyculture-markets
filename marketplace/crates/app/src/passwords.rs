//! Argon2id password hashing behind a global semaphore (spec §3.13, §7).
//! If the semaphore is full, callers return 503 — unbounded Argon2 queueing
//! is a memory-exhaustion DoS.
//!
//! Account Security Audit AM1/AM2 (2026-10-18): hashing is also
//! serialized PER SCOPE (a folded username at the login gate, an
//! account scope at step-up) via `hash_scoped`/`verify_scoped` — at
//! most one Argon2 run per username at a time, so parallel guesses
//! against one account cannot fill the pool and starve every other
//! login. The unscoped `hash`/`verify` keep their original contract
//! (global semaphore only) for the callers that predate scopes.

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, Semaphore};

pub fn argon2_params() -> Params {
    // OWASP-aligned starting point; benchmark + tune on target hardware at
    // deployment (docs/unverified.md #9).
    Params::new(64 * 1024, 3, 1, Some(32)).expect("valid params")
}

#[derive(Clone)]
pub struct HashGuard {
    sem: Arc<Semaphore>,
    /// One async mutex per scope; an entry exists while its scope has
    /// been used at least once and not yet been swept. Bounded by
    /// opportunistic sweeping in `scope_lock`.
    scopes: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HashError {
    /// Semaphore full — the web layer maps this to HTTP 503.
    Busy,
    Invalid,
}

/// Above this many remembered scopes, idle ones (held only by the
/// map) are dropped on the next scoped call.
const SCOPE_SWEEP_THRESHOLD: usize = 8192;

impl HashGuard {
    pub fn new(permits: usize) -> Self {
        HashGuard {
            sem: Arc::new(Semaphore::new(permits)),
            scopes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The lock serializing all hashing for one scope. The returned
    /// guard must be held across the hash/verify call.
    async fn scope_lock(&self, scope: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut map = self.scopes.lock().unwrap();
            if map.len() > SCOPE_SWEEP_THRESHOLD {
                // Drop scopes nobody holds or waits on (strong count 1
                // = only this map). A scope with a live guard or a
                // queued waiter has count >= 2 and survives.
                map.retain(|_, v| Arc::strong_count(v) > 1);
            }
            map.entry(scope.to_string())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }

    pub async fn hash(&self, password: &str) -> Result<String, HashError> {
        let _permit = self.sem.try_acquire().map_err(|_| HashError::Busy)?;
        hash_inner(password).await
    }

    pub async fn verify(&self, password: &str, stored: &str) -> Result<bool, HashError> {
        let _permit = self.sem.try_acquire().map_err(|_| HashError::Busy)?;
        verify_inner(password, stored).await
    }

    /// `hash` under the per-scope serialization (AM2): attempts for
    /// one scope run one at a time; other scopes proceed in parallel
    /// up to the global semaphore.
    pub async fn hash_scoped(&self, scope: &str, password: &str) -> Result<String, HashError> {
        let _scope = self.scope_lock(scope).await;
        self.hash(password).await
    }

    /// `verify` under the per-scope serialization (AM1/AM2).
    pub async fn verify_scoped(
        &self,
        scope: &str,
        password: &str,
        stored: &str,
    ) -> Result<bool, HashError> {
        let _scope = self.scope_lock(scope).await;
        self.verify(password, stored).await
    }
}

async fn hash_inner(password: &str) -> Result<String, HashError> {
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

async fn verify_inner(password: &str, stored: &str) -> Result<bool, HashError> {
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

    #[tokio::test]
    async fn scoped_variants_roundtrip() {
        let g = HashGuard::new(2);
        let h = g.hash_scoped("alice", "correct horse battery staple").await.unwrap();
        assert!(g.verify_scoped("alice", "correct horse battery staple", &h).await.unwrap());
        assert!(!g.verify_scoped("alice", "wrong", &h).await.unwrap());
        assert!(!g.verify_scoped("bob", "wrong", &h).await.unwrap());
    }
}

/// The bundled common-password corpus (spec §7; audit AM1): the
/// NCSC/HIBP 100,000 most common passwords as mirrored by SecLists
/// (99,839 entries as fetched — see the data file's header for full
/// provenance). Checked offline; membership is case-folded on the
/// candidate, matching the starter slice's semantics.
const COMMON_PASSWORDS_TEXT: &str = include_str!("../data/common-passwords-ncsc-100k.txt");

fn common_passwords() -> &'static std::collections::HashSet<String> {
    use std::sync::OnceLock;
    static SET: OnceLock<std::collections::HashSet<String>> = OnceLock::new();
    SET.get_or_init(|| {
        // The data file opens with a comment header; only the
        // LEADING comment block is skipped — real passwords can
        // start with '#' further down the list.
        let mut in_header = true;
        COMMON_PASSWORDS_TEXT
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                if in_header && l.starts_with('#') {
                    return None;
                }
                in_header = false;
                if l.is_empty() {
                    None
                } else {
                    Some(l.to_lowercase())
                }
            })
            .collect()
    })
}

/// How many distinct (case-folded) entries the bundled list carries.
pub fn common_password_list_len() -> usize {
    common_passwords().len()
}

pub fn is_common_password(pw: &str) -> bool {
    common_passwords().contains(&pw.to_lowercase())
}
