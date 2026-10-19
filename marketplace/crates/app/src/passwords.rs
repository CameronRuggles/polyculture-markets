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
//!
//! Modules Audit BM1 (2026-10-19): registration does NOT use the
//! shared pool at all. Registration is anonymous and unbounded in
//! principle, and it hashed BEFORE checking anything — four
//! in-flight registrations (e.g. resubmitting a taken username,
//! which costs a full hash and creates nothing) filled the shared
//! pool and 503'd every login. `hash_registration` runs on a
//! dedicated ONE-slot semaphore, so registrations can never take a
//! slot a login, step-up or recovery needs; the handler additionally
//! checks the username and the per-instance registration budget
//! BEFORE hashing. And the login path (`verify_guarded_wait`) may
//! WAIT briefly for a slot instead of failing at once: a momentary
//! burst of legitimate verifications should not 503 a correct login.

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

/// How long the login path may wait for a hashing slot before
/// answering Busy (BM1). One Argon2 run at the shipped parameters
/// takes well under a second on the target hardware class, so
/// five seconds covers several queued runs without turning the
/// wait into an unbounded queue (the DoS the semaphore exists to
/// stop) — a waiting login holds only its request task.
const LOGIN_SLOT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone)]
pub struct HashGuard {
    sem: Arc<Semaphore>,
    /// BM1: registration's own one-slot pool. Registrations are
    /// serialized against each other and can NEVER occupy a slot of
    /// the shared pool that logins, step-ups and recoveries use.
    reg_sem: Arc<Semaphore>,
    /// One async mutex per scope; an entry exists while its scope has
    /// been used at least once and not yet been swept. Bounded by
    /// opportunistic sweeping in `scope_lock`.
    scopes: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
    /// Total Argon2 runs performed (hashes + verifications). An ops
    /// counter: it makes the login budget's "refused BEFORE hashing"
    /// property observable (verification-fix V1's acceptance test
    /// counts hashes across a parallel guessing burst).
    hash_ops: Arc<std::sync::atomic::AtomicU64>,
}

/// A held per-scope lock (see `HashGuard::scope_guard`). While a
/// caller holds this, no other scoped hash for the same scope runs —
/// the login handler holds it across its budget re-check, the
/// password verification, and the failure recording, so the three
/// are atomic against parallel attempts on the same username
/// (verification-fix V1: checking the budget before queueing on the
/// lock let a burst through, because every queued request had
/// already passed the check).
pub struct ScopeGuard {
    _guard: OwnedMutexGuard<()>,
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
            reg_sem: Arc::new(Semaphore::new(1)),
            scopes: Arc::new(Mutex::new(HashMap::new())),
            hash_ops: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Total Argon2 runs performed through this guard so far.
    pub fn hash_op_count(&self) -> u64 {
        self.hash_ops.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Take the per-scope lock and HOLD it (the caller decides when
    /// it drops). Pair with `verify_guarded` for the verification
    /// itself.
    pub async fn scope_guard(&self, scope: &str) -> ScopeGuard {
        ScopeGuard { _guard: self.scope_lock(scope).await }
    }

    /// `verify` while the caller holds the scope's `ScopeGuard`:
    /// the global semaphore still applies; the per-scope
    /// serialization is the caller's held guard, not re-acquired.
    pub async fn verify_guarded(
        &self,
        _guard: &ScopeGuard,
        password: &str,
        stored: &str,
    ) -> Result<bool, HashError> {
        self.verify(password, stored).await
    }

    /// The login path's verification (BM1): like `verify_guarded`,
    /// but waits up to `LOGIN_SLOT_WAIT` for a shared-pool slot
    /// before answering Busy. Only the login handler uses this —
    /// it is the one path a momentary burst must never lock out.
    pub async fn verify_guarded_wait(
        &self,
        _guard: &ScopeGuard,
        password: &str,
        stored: &str,
    ) -> Result<bool, HashError> {
        let _permit = match tokio::time::timeout(
            LOGIN_SLOT_WAIT,
            self.sem.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(p)) => p,
            _ => return Err(HashError::Busy),
        };
        self.hash_ops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        verify_inner(password, stored).await
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
        self.hash_ops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        hash_inner(password).await
    }

    /// Registration's hash (BM1): runs on the dedicated one-slot
    /// registration semaphore, never the shared pool. A second
    /// concurrent registration gets Busy at once rather than
    /// queueing — registration is not latency-critical, and an
    /// instant refusal is the cheapest possible answer to a flood.
    pub async fn hash_registration(&self, password: &str) -> Result<String, HashError> {
        let _permit = self.reg_sem.try_acquire().map_err(|_| HashError::Busy)?;
        self.hash_ops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        hash_inner(password).await
    }

    pub async fn verify(&self, password: &str, stored: &str) -> Result<bool, HashError> {
        let _permit = self.sem.try_acquire().map_err(|_| HashError::Busy)?;
        self.hash_ops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
    async fn scope_guard_and_op_counter() {
        let g = HashGuard::new(2);
        let h = g.hash("correct horse battery staple").await.unwrap();
        assert_eq!(g.hash_op_count(), 1);
        let guard = g.scope_guard("alice").await;
        assert!(g.verify_guarded(&guard, "correct horse battery staple", &h).await.unwrap());
        assert_eq!(g.hash_op_count(), 2, "guarded verifies count as hash ops");
        drop(guard);
        // A second guard for the same scope is available after the drop.
        let _g2 = g.scope_guard("alice").await;
    }

    #[tokio::test]
    async fn registration_pool_is_separate_from_login_pool() {
        // BM1: four registrations' worth of demand can never touch
        // the shared pool. Registration has ONE slot: a second
        // concurrent registration is Busy at once, and the shared
        // pool stays free for logins throughout.
        let g = HashGuard::new(4);
        let reg = {
            let g = g.clone();
            tokio::spawn(async move { g.hash_registration("registration-passphrase-1").await })
        };
        // Wait until the spawned registration has actually taken
        // the slot (it counts its hash op when it starts hashing).
        for _ in 0..100 {
            if g.hash_op_count() >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(g.hash_op_count() >= 1, "registration started hashing");
        assert_eq!(
            g.hash_registration("registration-passphrase-2").await,
            Err(HashError::Busy),
            "registration pool has exactly one slot"
        );
        // The login pool is untouched: a normal hash/verify pair
        // proceeds immediately while the registration is in flight.
        let h = g.hash("correct horse battery staple").await.unwrap();
        assert!(g.verify("correct horse battery staple", &h).await.unwrap());
        let reg_hash = reg.await.unwrap().unwrap();
        assert!(reg_hash.starts_with("$argon2id$"));
        assert!(g.verify("registration-passphrase-1", &reg_hash).await.unwrap());
    }

    #[tokio::test]
    async fn login_verify_waits_for_a_slot() {
        // BM1: the login path waits briefly for a slot instead of
        // failing at once. Hold both permits with verifies against
        // a half-cost stored hash (the PHC string carries its own
        // parameters, so verifies run at half the production cost
        // — fast enough for a unit test, slow enough to overlap),
        // start a waiting verify, and confirm it completes once a
        // slot frees rather than returning Busy.
        let salt = SaltString::generate(&mut OsRng);
        let cheap = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(32 * 1024, 3, 1, Some(32)).unwrap(),
        );
        let h = cheap
            .hash_password(b"correct horse battery staple", &salt)
            .unwrap()
            .to_string();
        let g = HashGuard::new(2);
        let hold = |g: HashGuard, h: String| {
            tokio::spawn(async move { g.verify("correct horse battery staple", &h).await })
        };
        let a = hold(g.clone(), h.clone());
        let b = hold(g.clone(), h.clone());
        // Wait until both holders are actually hashing (2 ops).
        for _ in 0..200 {
            if g.hash_op_count() >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(g.hash_op_count() >= 2, "both holders are hashing");
        // Both slots are held: the waiting variant must still
        // succeed by waiting for a holder to finish.
        let guard = g.scope_guard("alice").await;
        let waited = g
            .verify_guarded_wait(&guard, "correct horse battery staple", &h)
            .await
            .unwrap();
        assert!(waited, "waiting verify succeeds once a slot frees");
        let _ = a.await;
        let _ = b.await;
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
