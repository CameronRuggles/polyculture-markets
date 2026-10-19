//! Fix Verification (accounts + messaging) — acceptance tests for
//! the V1–V9 fix brief (2026-10-19). One test per brief task:
//!
//! 1. (V1) Login budget: re-check under the per-username lock,
//!    lowest-count eviction that never evicts a tripped budget,
//!    signed device-cookie exemption, inbox notice on trip.
//! 2. (V2) Passphrase change and recovery-code issuance require the
//!    full step-up (passphrase + TOTP code when enrolled).
//! 3. (V6) Step-up passphrase failures are counted; the fifth
//!    revokes the session and posts a notice; one generic error.
//! 4. (V5) TOTP counters and the replay claim are atomic.
//! 5. (V3, owner decision 2026-10-19) A recovery code also clears
//!    TOTP, posts a notice, and starts the 72-hour payment pause.
//! 6. (V4) Disclosures name a message from the order's conversation;
//!    "verified" needs the signature within 24h before its arrival.
//! 7. (V7) Certificate refresh merges into the stored certificate —
//!    a stale copy can no longer drop a revocation.
//! 8. (V8) Nothing but whitespace may precede the armor BEGIN line.
//! 9. (V9) Global message-storage ceiling, free-disk floor, smaller
//!    budget for new accounts, env-settable registration cap.
//! 11. (decisions 9 + 11) Enrollment confirm consumes its step; the
//!    detached-signature disclosure API is retired.
//!
//! DB tests require DATABASE_URL (skipped silently when unset, the
//! pattern of the neighbouring suites). Tests in this file that
//! touch message sending serialize on MSG_LOCK: the task-9 limits
//! are env-configured process-wide (the production pattern — the
//! limits read the environment at send time).

use app::config::InstanceConfig;
use app::keyfile::KeyFile;
use app::media::MediaPipeline;
use app::moderation::{self, ModError};
use app::passwords::HashGuard;
use app::throttle::Throttles;
use app::totp;
use app::web::{router, AppState};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PW: &str = "verifix-correct-passphrase-1";
const PW2: &str = "verifix-rotated-passphrase-2";
const CSRF: &str = "verifix-csrf";

// Stagenet payment fixtures shared with the neighbouring suites.
const PRIMARY_A: &str = "55b6gZhKJ2b6EzvernZJBcPXiZym13w1CfbpDU6sR8aSGpaRbAmU4EMSH3XYXu5U1cSac7B49WRSSBbwQK9by3c7H9AdnFB";
const PRIMARY_B: &str = "57AaCDLE3GeBsgrK513QiUFePcBbSp5QYhn2Q2S1P9DsceUmeVkvBMJBQDFTfS9f21LfhXJSWNGN16mvXQmffGsA7KCVBxh";

// GPG fixtures (app/tests/fixtures/gpg; public certs + ciphertexts).
const CERT_ALICE: &str = include_str!("fixtures/gpg/cert-alice.asc");
const CERT_BOB: &str = include_str!("fixtures/gpg/cert-bob.asc");
const CERT_CAROL_V1: &str = include_str!("fixtures/gpg/cert-carol-v1.asc");
const CERT_CAROL_V2: &str = include_str!("fixtures/gpg/cert-carol-v2-revoked-subkey.asc");
const MSG_TO_CAROL_SUBKEY1: &str = include_str!("fixtures/gpg/msg-to-carol-subkey1.asc");
const UNWRAP_BOB_SIGNED: &str = include_str!("fixtures/gpg/unwrap-bob-signed.asc");
const UNWRAP_BOB_UNSIGNED: &str = include_str!("fixtures/gpg/unwrap-bob-unsigned.asc");
const MSG_300_UNSIGNED: &str = include_str!("fixtures/gpg/msg-300-unsigned.asc");
const DISCLOSE_PLAINTEXT: &str =
    "Bob here: your widget shipped today, tracking is in the next message.";

/// Serializes this file's message-sending tests (task 9's limits
/// are process-wide environment by design).
static MSG_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
fn msg_lock() -> &'static tokio::sync::Mutex<()> {
    MSG_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .ok()
}

fn uniq() -> String {
    app::sessions::new_token()[..16].to_string()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The TOTP code for `secret` at `offset` seconds from now.
fn code(secret: &[u8], offset: i64) -> String {
    let t = (now_secs() as i64 + offset).max(0) as u64;
    totp::code_at(secret, t)
}

fn wrong_code(secret: &[u8]) -> String {
    let valid: Vec<String> = [-30i64, 0, 30]
        .iter()
        .map(|o| code(secret, *o))
        .collect();
    for n in 0..1_000_000u32 {
        let cand = format!("{n:06}");
        if !valid.contains(&cand) {
            return cand;
        }
    }
    unreachable!()
}

/// Create an account with a REAL Argon2id hash of `password`.
async fn make_account(pool: &PgPool, role: &str, password: &str) -> (i64, String) {
    let hash = HashGuard::new(2).hash(password).await.unwrap();
    let public_id = app::db::public_id("acct_");
    let username = format!("vfix{}", uniq());
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO accounts (public_id, username, password_hash, role)
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(&public_id)
    .bind(&username)
    .bind(&hash)
    .bind(role)
    .fetch_one(pool)
    .await
    .unwrap();
    (id, username)
}

/// Enroll an account in TOTP at the library layer; returns the
/// secret. Confirmation presents the PREVIOUS step's code: the
/// brief's task 11 makes confirmation consume its step, and a
/// previous-step code is inside the verify window yet never the
/// step later gates are tested with — the same construction the
/// neighbouring suites' helpers were moved to.
async fn enroll(pool: &PgPool, kf: &KeyFile, account_id: i64) -> Vec<u8> {
    let b32 = moderation::totp_begin(pool, kf, account_id).await.unwrap();
    let secret = totp::base32_decode(&b32).unwrap();
    let c = code(&secret, -30);
    moderation::totp_confirm(pool, kf, account_id, &c).await.unwrap();
    assert!(moderation::totp_enrolled(pool, account_id).await.unwrap());
    secret
}

async fn session_for(pool: &PgPool, account_id: i64) -> String {
    let token = app::sessions::new_token();
    let now = time::OffsetDateTime::now_utc();
    let sess = app::sessions::Session::fresh(account_id, now);
    app::db::create_session(pool, &token, CSRF, &sess).await.unwrap();
    token
}

/// Install a real certificate as the account's current key.
async fn install_cert(pool: &PgPool, account_id: i64, cert: &str) {
    let info = app::keys::validate_cert(cert.as_bytes()).unwrap();
    app::keys::install_key(pool, account_id, cert.as_bytes(), &info, None)
        .await
        .unwrap();
}

async fn cleanup(pool: &PgPool, accounts: &[i64]) {
    for id in accounts {
        for q in [
            "DELETE FROM payment_review_flags WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM payment_declarations WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM payment_reports WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM payment_proofs WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM disclosures WHERE dispute_id IN (SELECT d.id FROM disputes d JOIN orders o ON o.id = d.order_id WHERE o.buyer_id = $1 OR o.seller_id = $1)",
            "DELETE FROM disputes WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM reviews WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM payment_attestations WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM encrypted_messages WHERE conversation_id IN (SELECT id FROM conversations WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1))",
            "DELETE FROM conversation_key_sightings WHERE conversation_id IN (SELECT id FROM conversations WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1))",
            "DELETE FROM conversation_participants WHERE conversation_id IN (SELECT id FROM conversations WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1))",
            "DELETE FROM conversations WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM encrypted_messages WHERE sender_id = $1 OR recipient_id = $1",
            "DELETE FROM conversation_key_sightings WHERE account_id = $1 OR shown_to = $1",
            "DELETE FROM conversations WHERE id IN (SELECT conversation_id FROM conversation_participants WHERE account_id = $1)",
            "DELETE FROM conversation_blocks WHERE blocker_id = $1 OR blocked_id = $1",
            "DELETE FROM payment_pool_entries WHERE seller_id = $1",
            "DELETE FROM payment_batches WHERE seller_id = $1",
            "DELETE FROM payment_identities WHERE seller_id = $1",
            "DELETE FROM destinations WHERE seller_id = $1",
            "DELETE FROM moderation_actions WHERE actor_id = $1 OR target_account_id = $1",
            "DELETE FROM admission_records WHERE account_id = $1",
            "DELETE FROM totp_stepup_grants WHERE account_id = $1",
            "DELETE FROM notifications WHERE account_id = $1",
            "DELETE FROM orders WHERE buyer_id = $1 OR seller_id = $1",
            "DELETE FROM listings WHERE seller_id = $1",
            "DELETE FROM identity_keys WHERE account_id = $1",
            "DELETE FROM session_csrf WHERE token_hash IN (SELECT token_hash FROM sessions WHERE account_id = $1)",
            "DELETE FROM sessions WHERE account_id = $1",
            "DELETE FROM recovery_codes WHERE account_id = $1",
            "DELETE FROM accounts WHERE id = $1",
        ] {
            sqlx::query(q).bind(id).execute(pool).await.unwrap();
        }
        // Conversations whose participant rows were deleted above.
        let _ = sqlx::query(
            "DELETE FROM conversation_participants WHERE conversation_id IN \
             (SELECT id FROM conversations WHERE order_id IS NULL AND id NOT IN \
             (SELECT conversation_id FROM conversation_participants))",
        )
        .execute(pool)
        .await;
    }
}

// ---------------------------------------------------------------------------
// HTTP test server (the account_security pattern, with the hash
// guard and throttles retained so tests can observe them)
// ---------------------------------------------------------------------------

struct TestServer {
    addr: std::net::SocketAddr,
    keyfile: Arc<KeyFile>,
    hash_guard: HashGuard,
    throttles: Arc<Throttles>,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}

async fn test_server(pool: &PgPool) -> TestServer {
    test_server_with_cap(pool, None).await
}

async fn test_server_with_cap(pool: &PgPool, account_cap: Option<u64>) -> TestServer {
    let mut dir = std::env::temp_dir();
    dir.push(format!("verifix-http-{}-{}", std::process::id(), uniq()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("test.key");
    let media = MediaPipeline {
        worker_path: dir.join("no-worker"),
        media_dir: dir.clone(),
        tmp_dir: dir.join("tmp"),
    };
    let instance = InstanceConfig::resolve(&|_| None).expect("empty env resolves");
    let marketplace_id = instance.marketplace_id.clone();
    let payments = app::payments::PaymentConfig::from_env(&marketplace_id, instance.network);
    let keyfile = Arc::new(KeyFile::load_or_generate(&key_path).expect("key file"));
    let hash_guard = HashGuard::new(4);
    let throttles = Arc::new(Throttles::new());
    let state = AppState {
        pool: pool.clone(),
        hash_guard: hash_guard.clone(),
        throttles: throttles.clone(),
        registrations_open: true,
        account_cap,
        dev_cookies: true,
        media,
        marketplace_id,
        payments,
        keyfile: keyfile.clone(),
        stage9: app::reputation::Stage9Config::from_env(),
        instance,
        retention: app::retention::RetentionConfig::defaults(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    TestServer { addr, keyfile, hash_guard, throttles, handle, dir }
}

impl TestServer {
    fn stop(self) {
        self.handle.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct HttpResult {
    status: u16,
    headers: String,
    body: String,
}

async fn http_raw(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    cookie_header: Option<&str>,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> HttpResult {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n");
    if let Some(c) = cookie_header {
        req.push_str(&format!("Cookie: {c}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!(
            "Content-Type: {}\r\nContent-Length: {}\r\n",
            content_type.unwrap_or("application/x-www-form-urlencoded"),
            b.len()
        ));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    if let Some(b) = body {
        s.write_all(b).await.unwrap();
    }
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .expect("status line parses");
    let (headers, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h.to_string(), b.to_string()),
        None => (text.clone(), String::new()),
    };
    HttpResult { status, headers, body }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn form_body(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

async fn post_form(
    addr: std::net::SocketAddr,
    path: &str,
    cookie_header: Option<&str>,
    fields: &[(&str, &str)],
) -> HttpResult {
    let body = form_body(fields);
    http_raw(addr, "POST", path, cookie_header, None, Some(body.as_bytes())).await
}

async fn get_page(
    addr: std::net::SocketAddr,
    path: &str,
    cookie_header: Option<&str>,
) -> HttpResult {
    http_raw(addr, "GET", path, cookie_header, None, None).await
}

/// GET an anonymous form page (login/recover): returns the CSRF
/// cookie value, which is also the form's hidden csrf field value.
async fn anon_csrf(addr: std::net::SocketAddr, path: &str) -> String {
    let r = http_raw(addr, "GET", path, None, None, None).await;
    assert_eq!(r.status, 200, "GET {path}");
    let marker = "csrf=";
    let start = r.headers.to_lowercase().find(marker).expect("csrf cookie set") + marker.len();
    let rest = &r.headers[start..];
    rest.split(';').next().unwrap().trim().to_string()
}

/// One login attempt. `extra_cookie` carries e.g. a device cookie
/// (`device=...`) alongside the anonymous CSRF cookie.
async fn login_attempt(
    addr: std::net::SocketAddr,
    username: &str,
    password: &str,
    totp_code: Option<&str>,
    extra_cookie: Option<&str>,
) -> HttpResult {
    let csrf = anon_csrf(addr, "/login").await;
    let mut fields = vec![
        ("csrf", csrf.as_str()),
        ("username", username),
        ("password", password),
    ];
    if let Some(c) = totp_code {
        fields.push(("totp", c));
    }
    let cookie = match extra_cookie {
        Some(x) => format!("csrf={csrf}; {x}"),
        None => format!("csrf={csrf}"),
    };
    post_form(addr, "/login", Some(&cookie), &fields).await
}

fn set_cookie_value(r: &HttpResult, name: &str) -> Option<String> {
    for line in r.headers.lines() {
        let l = line.to_lowercase();
        if l.starts_with("set-cookie:") {
            let v = line.splitn(2, ':').nth(1)?.trim();
            if let Some(rest) = v.strip_prefix(&format!("{name}=")) {
                let tok = rest.split(';').next()?.trim();
                if !tok.is_empty() {
                    return Some(tok.to_string());
                }
            }
        }
    }
    None
}

fn session_cookie_of(r: &HttpResult) -> Option<String> {
    set_cookie_value(r, "session")
}

fn location_of(r: &HttpResult) -> String {
    for line in r.headers.lines() {
        if line.to_lowercase().starts_with("location:") {
            return line.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
        }
    }
    String::new()
}

/// The security page's status line (where step_up errors render).
fn status_text(body: &str) -> String {
    let start = body.find("<p role=\"status\">").expect("status line present") + "<p role=\"status\">".len();
    let end = body[start..].find("</p>").expect("status line closes") + start;
    body[start..end].to_string()
}

async fn stored_hash(pool: &PgPool, account_id: i64) -> String {
    sqlx::query_scalar::<_, String>("SELECT password_hash FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn has_event(pool: &PgPool, account_id: i64, event_type: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM notifications WHERE account_id = $1 AND event_type = $2)",
    )
    .bind(account_id)
    .bind(event_type)
    .fetch_one(pool)
    .await
    .unwrap()
}

// ---------------------------------------------------------------------------
// Task 1 (V1): the login budget — burst-proof, flood-proof, and the
// owner is not locked out of a browser that has logged in before.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_budget_burst_flood_and_device_cookie() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (id, username) = make_account(&pool, "buyer", PW).await;

    // A first successful login sets the device cookie for this browser.
    let r = login_attempt(srv.addr, &username, PW, None, None).await;
    assert!(session_cookie_of(&r).is_some(), "initial login succeeds");
    let device = set_cookie_value(&r, "device").expect("login sets a device cookie");
    let device_cookie = format!("device={device}");

    // BURST: 150 parallel wrong passphrases for the one username.
    // However they interleave, at most LOGIN_FAILURE_BUDGET hashes
    // may run in the window: the budget is re-checked while holding
    // the per-username lock, and each failure is recorded before
    // the lock is released.
    let before = srv.hash_guard.hash_op_count();
    let mut burst = Vec::new();
    for _ in 0..150 {
        let addr = srv.addr;
        let user = username.clone();
        burst.push(tokio::spawn(async move {
            login_attempt(addr, &user, "wrong-passphrase-guess", None, None).await
        }));
    }
    for h in burst {
        let r = h.await.unwrap();
        assert!(session_cookie_of(&r).is_none(), "a wrong passphrase never logs in");
    }
    let hashes = srv.hash_guard.hash_op_count() - before;
    assert!(
        hashes <= app::throttle::LOGIN_FAILURE_BUDGET as u64,
        "a 150-way parallel burst ran {hashes} hashes; the budget allows at most {}",
        app::throttle::LOGIN_FAILURE_BUDGET
    );
    assert!(hashes >= 1, "the burst really reached the verifier");

    // The budget is spent: a stranger with the RIGHT passphrase is
    // refused, with no hash performed at all.
    let before = srv.hash_guard.hash_op_count();
    let r = login_attempt(srv.addr, &username, PW, None, None).await;
    assert!(session_cookie_of(&r).is_none(), "budget spent: stranger refused even with the right passphrase");
    assert!(r.body.contains("Invalid username or passphrase."), "generic error, no oracle");
    assert_eq!(
        srv.hash_guard.hash_op_count() - before,
        0,
        "a budget refusal performs no hash"
    );
    // The trip posted an inbox notice to the account.
    assert!(
        has_event(&pool, id, "login_budget_tripped").await,
        "the budget trip notifies the account"
    );

    // FLOOD: 5,000 failures on non-existent usernames (the exact
    // recording call the login handler makes for unknown names)
    // must not evict the victim's tripped budget.
    for i in 0..5_000 {
        srv.throttles.record_login_failure_counted(&format!("vfixflood{i}"));
    }
    assert!(
        srv.throttles.login_budget_exceeded(&username),
        "the victim's count survives a flood of fake usernames"
    );
    let r = login_attempt(srv.addr, &username, PW, None, None).await;
    assert!(session_cookie_of(&r).is_none(), "still refused after the flood");

    // A FORGED device cookie exempts nobody.
    let mut forged = device.clone();
    forged.replace_range(..1, if device.starts_with('a') { "b" } else { "a" });
    let r = login_attempt(srv.addr, &username, PW, None, Some(&format!("device={forged}"))).await;
    assert!(session_cookie_of(&r).is_none(), "a forged device cookie does not exempt");

    // The owner's own browser — the one that logged in before —
    // still gets in with the right passphrase while the budget is
    // spent. (Success clears the failure count, as before.)
    let r = login_attempt(srv.addr, &username, PW, None, Some(&device_cookie)).await;
    assert!(
        session_cookie_of(&r).is_some(),
        "the device-cookie browser logs in despite the spent budget"
    );
    assert!(!srv.throttles.login_budget_exceeded(&username), "success cleared the failures");

    cleanup(&pool, &[id]).await;
    srv.stop();
}

// ---------------------------------------------------------------------------
// Task 2 (V2): passphrase change and recovery-code issuance take
// the full step-up — on an enrolled account the right passphrase
// with NO code changes nothing and issues no code.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn passphrase_change_and_recovery_issue_require_full_stepup() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (id, _username) = make_account(&pool, "buyer", PW).await;
    let secret = enroll(&pool, &srv.keyfile, id).await;
    let token = session_for(&pool, id).await;
    let cookie = format!("session={token}");
    let stored_before = stored_hash(&pool, id).await;

    // Right passphrase, NO code: the passphrase does not change.
    let r = post_form(
        srv.addr,
        "/account/passphrase",
        Some(&cookie),
        &[("csrf", CSRF), ("current_password", PW), ("new_password", PW2)],
    )
    .await;
    assert_eq!(r.status, 200);
    assert!(
        r.body.contains("Step-up verification failed"),
        "no code on an enrolled account must refuse the change: {}",
        r.body
    );
    assert_eq!(stored_hash(&pool, id).await, stored_before, "passphrase unchanged without a code");

    // Right passphrase, NO code: no recovery code is issued.
    let r = post_form(
        srv.addr,
        "/account/recovery-codes",
        Some(&cookie),
        &[("csrf", CSRF), ("password", PW)],
    )
    .await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("Step-up verification failed"), "issuance refused without a code");
    let unconsumed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_codes WHERE account_id = $1 AND consumed_at IS NULL",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unconsumed, 0, "no recovery code was issued");

    // With a code, the passphrase change goes through (and the new
    // passphrase verifies against the stored hash).
    let r = post_form(
        srv.addr,
        "/account/passphrase",
        Some(&cookie),
        &[
            ("csrf", CSRF),
            ("current_password", PW),
            ("new_password", PW2),
            ("totp", &code(&secret, 0)),
        ],
    )
    .await;
    assert!(r.body.contains("Passphrase changed."), "change with a code succeeds: {}", r.body);
    let stored_after = stored_hash(&pool, id).await;
    assert_ne!(stored_after, stored_before);
    let guard = HashGuard::new(2);
    assert!(guard.verify(PW2, &stored_after).await.unwrap(), "new passphrase verifies");
    assert!(!guard.verify(PW, &stored_after).await.unwrap(), "old passphrase is gone");

    // With a code, a recovery code is issued (exactly one live code).
    let r = post_form(
        srv.addr,
        "/account/recovery-codes",
        Some(&cookie),
        &[("csrf", CSRF), ("password", PW2), ("totp", &code(&secret, 30))],
    )
    .await;
    assert_eq!(r.status, 200);
    let unconsumed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_codes WHERE account_id = $1 AND consumed_at IS NULL",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unconsumed, 1, "one live recovery code after issuance with a code");

    cleanup(&pool, &[id]).await;
    srv.stop();
}

// ---------------------------------------------------------------------------
// Task 3 (V6): wrong step-up passphrases are counted; the fifth
// revokes the session and posts a notice; the error is one generic
// text for a wrong passphrase and a wrong code alike.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stepup_failures_counted_session_revoked_generic_error() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (id, _username) = make_account(&pool, "buyer", PW).await;
    let secret = enroll(&pool, &srv.keyfile, id).await;
    let token = session_for(&pool, id).await;
    let cookie = format!("session={token}");
    let attempt = |current: &str, code: Option<String>| {
        let addr = srv.addr;
        let cookie = cookie.clone();
        let current = current.to_string();
        async move {
            let mut fields = vec![
                ("csrf", CSRF),
                ("current_password", current.as_str()),
                ("new_password", PW2),
            ];
            if let Some(c) = &code {
                fields.push(("totp", c.as_str()));
            }
            post_form(addr, "/account/passphrase", Some(&cookie), &fields).await
        }
    };

    // Wrong passphrase: generic error (failure #1).
    let r = attempt("not-the-passphrase", None).await;
    assert_eq!(r.status, 200);
    let err_wrong_pw = status_text(&r.body);
    assert_eq!(err_wrong_pw, "Step-up verification failed.");

    // Right passphrase, WRONG code: the IDENTICAL error text — the
    // response must not reveal which factor failed. (A code failure
    // is the gate's business and does not move this counter.)
    let r = attempt(PW, Some(wrong_code(&secret))).await;
    assert_eq!(r.status, 200);
    let err_wrong_code = status_text(&r.body);
    assert_eq!(
        err_wrong_pw, err_wrong_code,
        "wrong passphrase and wrong code must read identically"
    );
    let count: i32 = sqlx::query_scalar("SELECT stepup_fail_count FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "only the wrong passphrase counted");

    // Four more wrong passphrases bring the count to five: the
    // fifth revokes the session and notifies the account.
    for _ in 0..4 {
        let r = attempt("not-the-passphrase", None).await;
        assert_eq!(r.status, 200, "attempts before the limit still render the form");
    }
    assert!(
        has_event(&pool, id, "stepup_session_revoked").await,
        "the account is told its session was revoked"
    );
    let count: i32 = sqlx::query_scalar("SELECT stepup_fail_count FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "the counter restarts after the revocation episode");

    // The sixth attempt rides the revoked session: it never reaches
    // the form — the session is gone, so it is a login redirect.
    let r = attempt(PW, Some(code(&secret, 0))).await;
    assert!(
        matches!(r.status, 302 | 303) && location_of(&r) == "/login",
        "sixth attempt is redirected to login, got {} {}",
        r.status,
        location_of(&r)
    );

    cleanup(&pool, &[id]).await;
    srv.stop();
}

// ---------------------------------------------------------------------------
// Task 4 (V5): the TOTP gate's counter and replay claim are atomic.
// ---------------------------------------------------------------------------

fn library_keyfile() -> (KeyFile, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("verifix-kf-{}-{}", std::process::id(), uniq()));
    std::fs::create_dir_all(&dir).unwrap();
    let kf = KeyFile::load_or_generate(&dir.join("keyfile")).unwrap();
    (kf, dir)
}

#[tokio::test]
async fn totp_gate_counters_and_replay_are_atomic() {
    let Some(pool) = pool().await else { return };
    let (kf, kf_dir) = library_keyfile();

    // -- 60 concurrent wrong codes trip the lock (exactly once). --
    let (id, _u) = make_account(&pool, "buyer", PW).await;
    let secret = enroll(&pool, &kf, id).await;
    let wrong = wrong_code(&secret);
    let barrier = Arc::new(tokio::sync::Barrier::new(60));
    let mut burst = Vec::new();
    for _ in 0..60 {
        let (p, k, b, w) = (pool.clone(), kf.clone(), barrier.clone(), wrong.clone());
        burst.push(tokio::spawn(async move {
            b.wait().await;
            moderation::verify_totp_gate(&p, &k, id, &w).await
        }));
    }
    let mut invalid = 0;
    for h in burst {
        match h.await.unwrap() {
            Err(ModError::TotpInvalid) => invalid += 1,
            Err(ModError::TotpLocked) => {}
            other => panic!("a wrong code in a burst must be Invalid or Locked, got {other:?}"),
        }
    }
    assert!(invalid >= 1, "at least the counting failures report Invalid");
    // The lock is on: even the CORRECT code is now refused as locked.
    let err = moderation::verify_totp_gate(&pool, &kf, id, &code(&secret, 0))
        .await
        .expect_err("a correct code is refused while locked");
    assert!(matches!(err, ModError::TotpLocked), "got {err:?}");
    // Exactly one lockout notice for the whole burst episode.
    let notices: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notifications WHERE account_id = $1 AND event_type = 'totp_locked'",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(notices, 1, "one notice per lockout episode, however the burst interleaved");
    let count: i32 = sqlx::query_scalar("SELECT totp_fail_count FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "the counter reset when the lock tripped, burst tail included");

    // -- Two concurrent presentations of the SAME valid code:
    //    exactly one succeeds; the other is a replay. --
    let (id2, _u2) = make_account(&pool, "buyer", PW).await;
    let secret2 = enroll(&pool, &kf, id2).await;
    let good = code(&secret2, 0);
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut pair = Vec::new();
    for _ in 0..2 {
        let (p, k, b, g) = (pool.clone(), kf.clone(), barrier.clone(), good.clone());
        pair.push(tokio::spawn(async move {
            b.wait().await;
            moderation::verify_totp_gate(&p, &k, id2, &g).await
        }));
    }
    let mut oks = 0;
    let mut replays = 0;
    for h in pair {
        match h.await.unwrap() {
            Ok(()) => oks += 1,
            Err(ModError::TotpReplayed) => replays += 1,
            other => panic!("the same-code race resolves as Ok or Replayed, got {other:?}"),
        }
    }
    assert_eq!((oks, replays), (1, 1), "exactly one of the two racers may consume the step");
    // And a sequential third presentation is a replay too.
    let err = moderation::verify_totp_gate(&pool, &kf, id2, &good)
        .await
        .expect_err("the consumed code stays consumed");
    assert!(matches!(err, ModError::TotpReplayed), "got {err:?}");

    cleanup(&pool, &[id, id2]).await;
    let _ = std::fs::remove_dir_all(&kf_dir);
}

// ---------------------------------------------------------------------------
// Task 5 (V3, owner decision 2026-10-19): a recovery code also
// clears TOTP; the account is notified; payment changes pause for
// 72 hours after the recovery.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recovery_clears_totp_and_pauses_payment_changes() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let pay_cfg = app::payments::PaymentConfig::from_env("vespiary-market", modules_api::Network::Stagenet);
    let (seller, username) = make_account(&pool, "seller", PW).await;
    let _secret1 = enroll(&pool, &srv.keyfile, seller).await;
    app::payments::set_primary_address(&pool, seller, PRIMARY_A, &pay_cfg)
        .await
        .unwrap();
    const RECOVERY_CODE: &str = "VFIX-RECOVERY-CODE-0001";
    app::db::store_recovery_code(&pool, seller, RECOVERY_CODE).await.unwrap();

    // Recover over HTTP: passphrase reset with the code.
    let csrf = anon_csrf(srv.addr, "/account/recover").await;
    let r = post_form(
        srv.addr,
        "/account/recover",
        Some(&format!("csrf={csrf}")),
        &[
            ("csrf", csrf.as_str()),
            ("username", username.as_str()),
            ("code", RECOVERY_CODE),
            ("password", PW2),
        ],
    )
    .await;
    assert_eq!(r.status, 200, "recovery renders: {}", r.body);
    assert!(r.body.contains("Passphrase reset"), "recovery succeeded");
    assert!(
        r.body.contains("Two-factor authentication was turned"),
        "the recovery page says TOTP was turned off"
    );

    // TOTP is OFF: the security state says so, and login needs no code.
    assert!(
        !moderation::totp_enrolled(&pool, seller).await.unwrap(),
        "recovery cleared the TOTP enrollment"
    );
    let r = login_attempt(srv.addr, &username, PW2, None, None).await;
    assert!(
        session_cookie_of(&r).is_some(),
        "after recovery, login needs no TOTP code"
    );
    // The inbox notice exists.
    assert!(
        has_event(&pool, seller, "security_recovery_totp_cleared").await,
        "the recovery posted a TOTP-cleared notice"
    );

    // Re-enroll (sellers need TOTP for payment changes), then try
    // to change the payment address inside the 72-hour pause.
    let secret2 = enroll(&pool, &srv.keyfile, seller).await;
    let token = session_for(&pool, seller).await;
    let cookie = format!("session={token}");
    let change = |addr: &str, code_s: String| {
        let http = srv.addr;
        let cookie = cookie.clone();
        let addr = addr.to_string();
        async move {
            post_form(
                http,
                "/seller/payment-identity",
                Some(&cookie),
                &[
                    ("csrf", CSRF),
                    ("primary_address", addr.as_str()),
                    ("password", PW2),
                    ("totp", code_s.as_str()),
                ],
            )
            .await
        }
    };
    let r = change(PRIMARY_B, code(&secret2, 0)).await;
    assert!(
        location_of(&r).contains("pmsg=recovery_pause"),
        "a change inside 72h of recovery is refused: {}",
        location_of(&r)
    );
    let identity = app::payments::get_identity(&pool, seller).await.unwrap().unwrap();
    assert_eq!(identity.primary_address, PRIMARY_A, "the address did not change during the pause");

    // Once the pause has run (recovered_at backdated past 72h),
    // the same change goes through.
    sqlx::query("UPDATE accounts SET recovered_at = now() - interval '73 hours' WHERE id = $1")
        .bind(seller)
        .execute(&pool)
        .await
        .unwrap();
    let r = change(PRIMARY_B, code(&secret2, 30)).await;
    assert!(
        location_of(&r).contains("pmsg=identity_saved"),
        "after 72h the change is allowed: {}",
        location_of(&r)
    );
    let identity = app::payments::get_identity(&pool, seller).await.unwrap().unwrap();
    assert_eq!(identity.primary_address, PRIMARY_B);

    cleanup(&pool, &[seller]).await;
    srv.stop();
}
