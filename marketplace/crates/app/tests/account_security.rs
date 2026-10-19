//! Account Security Audit fix brief — acceptance tests (2026-10-18).
//!
//! One test per brief task (some tasks get two), written against the
//! brief's own acceptance criteria:
//!
//! 1. TOTP at login for enrolled accounts; enrollment mandatory for
//!    moderators (all moderator powers were already code-gated; the
//!    disclosure view and seller approval join them in task 3) and for
//!    sellers before they can set a payment identity.
//! 2. Step-up (current passphrase, plus a TOTP code when enrolled) for
//!    payment address change, batch upload, key upload/rotation, and
//!    TOTP enrollment — with an inbox notice for each.
//! 3. Moderator gaps: fresh code to view dispute disclosures and to
//!    approve sellers; failed-code counting with a lockout after 10.
//! 4. Login limits: per-username budget checked BEFORE hashing; at
//!    most one hash per username at a time; capped/aged failure map;
//!    bundled 100k common-password list.
//! 5. The per-account request throttle wired into signed-in POSTs.
//! 6. Fail closed outside development: no key file / no DATABASE_URL
//!    means no start; key files are created 0600.
//! 7. TOTP tidy-ups: no code reuse within its window; no confirm
//!    while TOTP is already active.
//! 8. Passphrase change from a session (ends other sessions) and a
//!    route to issue a new recovery code.
//!
//! DB tests require DATABASE_URL (skipped silently when unset, the
//! pattern of the neighbouring suites).

use app::config::InstanceConfig;
use app::keyfile::KeyFile;
use app::media::MediaPipeline;
use app::moderation::{self, ModError};
use app::passwords::{is_common_password, HashGuard};
use app::totp;
use app::web::{router, AppState};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Fixtures + helpers
// ---------------------------------------------------------------------------

// Stagenet payment fixtures shared with the neighbouring suites.
const PRIMARY_A: &str = "55b6gZhKJ2b6EzvernZJBcPXiZym13w1CfbpDU6sR8aSGpaRbAmU4EMSH3XYXu5U1cSac7B49WRSSBbwQK9by3c7H9AdnFB";
const SIG: &str =
    "SigV2abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuv";
const SUBS: &[&str] = &[
    "75ecAyh9QuvfaDyaPRTVnwgc2QxjTByx2GM2haFsn8wrEu2vSVn7QctGiKQdpP5vNPeB2Fzbg8Sb78mqA22Qc2GaHdYhWsY",
    "758HazrgczGbQ4rmrAuws3CcFLEa5zGRE9abUNcVeSP3KYGuoC9mGFHcX2R4HS7qxJCmFHrPAzDDNSshrwHAQLUyUDch7xW",
    "73qWemDitUJbTzxfNhSEGi7YcTi1UYFrM1u3Ck2iL2qxhT3tY45KLk262yx58CKL81YjbyndXBjXSMXAczboytxUEvu4y7o",
    "75wgnqJyVbk2Yts13syYbzT3NLFYYFRhdU7FnD31WiKWdTtWVsRYMC9VojzbvuKSX6hzApqPqyVTbQRW61PqcJsU7Xu3hq6",
    "73AAUrVGHN7N8EksdD624URJb8Eq4bamVXETdXDcTwn92vLRNy7Rzn7hpfk4gPTDa3KgJR3psiQb8R2Y6abeZzbTEQAoD7w",
    "792YPQqaKeZ4fzqXucMjrueF6pSto5Fb7TRqT4mTDAZzEpALCQwVP7yfLRpMh2Qk9PS3Hvw2u2fzMUCZccGARTnzMq9mATA",
];

// The fixture addresses are a shared, globally-unique pool (an
// address may sit in only one seller's pool): tests in this file
// that touch payment state serialize on this lock and purge the
// fixture addresses first — the neighbouring suites' convention.
// Slices are disjoint per test: step-up uses SUBS[0..2], the
// moderator test uses SUBS[3..6].
static FIXTURE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

fn fixture_lock() -> &'static tokio::sync::Mutex<()> {
    FIXTURE_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn purge_fixture_addresses(pool: &PgPool) {
    let owned: Vec<String> = SUBS.iter().map(|s| s.to_string()).collect();
    for q in [
        "DELETE FROM payment_declarations WHERE pool_entry_id IN (SELECT id FROM payment_pool_entries WHERE address = ANY($1))",
        "DELETE FROM payment_review_flags WHERE order_id IN (SELECT order_id FROM payment_pool_entries WHERE address = ANY($1) AND order_id IS NOT NULL)",
        "DELETE FROM payment_reports WHERE order_id IN (SELECT order_id FROM payment_pool_entries WHERE address = ANY($1) AND order_id IS NOT NULL)",
        "DELETE FROM payment_proofs WHERE pool_entry_id IN (SELECT id FROM payment_pool_entries WHERE address = ANY($1))",
        "DELETE FROM payment_attestations WHERE pool_entry_id IN (SELECT id FROM payment_pool_entries WHERE address = ANY($1))",
        "DELETE FROM payment_pool_entries WHERE address = ANY($1)",
        "DELETE FROM destinations WHERE address = ANY($1)",
    ] {
        sqlx::query(q).bind(&owned).execute(pool).await.expect("purge fixture addresses");
    }
}

/// A dummy current identity key (orders pin the seller's fingerprint
/// at creation; the neighbouring suites' helper).
async fn install_key(pool: &PgPool, account_id: i64) {
    let fpr = format!("{:040X}", rand::random::<u128>() % (1u128 << 127));
    sqlx::query(
        "INSERT INTO identity_keys (account_id, certificate, fingerprint, version, status)
         VALUES ($1, $2, $3, 1, 'current')",
    )
    .bind(account_id)
    .bind(b"acctsec-test-dummy-cert".to_vec())
    .bind(&fpr)
    .execute(pool)
    .await
    .unwrap();
}

const PW: &str = "acctsec-correct-passphrase-1";
const PW2: &str = "acctsec-rotated-passphrase-2";
const CSRF: &str = "acctsec-csrf";

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

/// The current TOTP code for `secret` at `offset` seconds from now.
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
    let username = format!("asec{}", uniq());
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

/// Enroll an account in TOTP at the library layer (the keyfile must be
/// the server's, so the web layer can decrypt). Returns the secret.
/// NOTE: enrollment confirmation must NOT consume the current step —
/// the locked Stage 9 suite confirms and then presents the same code
/// at the step-up gate.
async fn enroll(pool: &PgPool, kf: &KeyFile, account_id: i64) -> Vec<u8> {
    let b32 = moderation::totp_begin(pool, kf, account_id).await.unwrap();
    let secret = totp::base32_decode(&b32).unwrap();
    let c = code(&secret, 0);
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
    }
}

// ---------------------------------------------------------------------------
// HTTP test server (the tx_proof_flow pattern, keyfile exposed)
// ---------------------------------------------------------------------------

struct TestServer {
    addr: std::net::SocketAddr,
    keyfile: Arc<KeyFile>,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}

async fn test_server(pool: &PgPool) -> TestServer {
    let mut dir = std::env::temp_dir();
    dir.push(format!("acctsec-http-{}-{}", std::process::id(), uniq()));
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
    let state = AppState {
        pool: pool.clone(),
        hash_guard: HashGuard::new(4),
        throttles: Arc::new(app::throttle::Throttles::new()),
        registrations_open: true,
        account_cap: None,
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
    TestServer { addr, keyfile, handle, dir }
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

/// GET an anonymous form page (login/recover): returns the CSRF cookie
/// value, which is also the form's hidden csrf field value.
async fn anon_csrf(addr: std::net::SocketAddr, path: &str) -> String {
    let r = http_raw(addr, "GET", path, None, None, None).await;
    assert_eq!(r.status, 200, "GET {path}");
    let marker = "csrf=";
    let start = r.headers.to_lowercase().find(marker).expect("csrf cookie set") + marker.len();
    let rest = &r.headers[start..];
    rest.split(';').next().unwrap().trim().to_string()
}

/// Attempt a login; returns the raw result. Success = 302/303 to
/// /account with a session Set-Cookie.
async fn login_attempt(
    addr: std::net::SocketAddr,
    username: &str,
    password: &str,
    totp_code: Option<&str>,
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
    post_form(addr, "/login", Some(&format!("csrf={csrf}")), &fields).await
}

fn session_cookie_of(r: &HttpResult) -> Option<String> {
    // dev_cookies shape: "session=<token>; Path=/; ..."
    for line in r.headers.lines() {
        let l = line.to_lowercase();
        if l.starts_with("set-cookie:") {
            let v = line.splitn(2, ':').nth(1)?.trim();
            if let Some(rest) = v.strip_prefix("session=") {
                let tok = rest.split(';').next()?.trim();
                if !tok.is_empty() {
                    return Some(tok.to_string());
                }
            }
        }
    }
    None
}

fn location_of(r: &HttpResult) -> String {
    for line in r.headers.lines() {
        if line.to_lowercase().starts_with("location:") {
            return line.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
        }
    }
    String::new()
}

async fn session_count(pool: &PgPool, account_id: i64) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE account_id = $1 AND revoked_at IS NULL")
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
// Task 4 (list): the bundled common-password corpus
// ---------------------------------------------------------------------------

#[test]
fn bundled_common_password_list_covers_the_full_corpus() {
    // The canonical head of every corpus, pinned by blind_stage1 too.
    assert!(is_common_password("123456"));
    assert!(is_common_password("password"));
    assert!(is_common_password("qwerty"));
    // The TAIL of the bundled NCSC 100k list: present only if the
    // whole corpus shipped, not a starter slice.
    assert!(
        is_common_password("crossroad"),
        "the last entry of the NCSC 100k list must be bundled"
    );
    assert!(is_common_password("ganja123"));
    // Membership is case-folded on the candidate (existing semantics).
    assert!(is_common_password("PASSWORD"));
    // A string no corpus contains stays allowed.
    assert!(!is_common_password("zqxjkvb-uncommon-passphrase-987654"));
    // The bundled list really is the ~100k corpus (99,839 published
    // entries; ~97.7k distinct after the case-folding the membership
    // check applies).
    assert!(
        app::passwords::common_password_list_len() >= 97_000,
        "bundled list must carry the full corpus, got {}",
        app::passwords::common_password_list_len()
    );
}

// ---------------------------------------------------------------------------
// Task 1: TOTP at login
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_requires_totp_once_enrolled() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (id, username) = make_account(&pool, "buyer", PW).await;

    // Before enrollment, passphrase alone logs in (control).
    let r = login_attempt(srv.addr, &username, PW, None).await;
    assert!(
        session_cookie_of(&r).is_some(),
        "unenrolled account logs in with the passphrase alone: {} {}",
        r.status,
        r.body
    );

    // Enroll, then the passphrase alone must NOT open a session.
    let secret = enroll(&pool, &srv.keyfile, id).await;
    let before = session_count(&pool, id).await;
    let r = login_attempt(srv.addr, &username, PW, None).await;
    assert!(
        session_cookie_of(&r).is_none(),
        "enrolled account with the right passphrase but NO code gets no session"
    );
    let r = login_attempt(srv.addr, &username, PW, Some(&wrong_code(&secret))).await;
    assert!(
        session_cookie_of(&r).is_none(),
        "enrolled account with a wrong code gets no session"
    );
    assert_eq!(
        session_count(&pool, id).await,
        before,
        "no session row may be created by a code-less/wrong-code login"
    );

    // Passphrase + the current code opens the session.
    let r = login_attempt(srv.addr, &username, PW, Some(&code(&secret, 0))).await;
    assert!(
        session_cookie_of(&r).is_some(),
        "passphrase + current code logs in: {} {}",
        r.status,
        r.body
    );

    srv.stop();
    cleanup(&pool, &[id]).await;
}

// ---------------------------------------------------------------------------
// Task 7 (login half): a code is single-use at the login gate too
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_code_cannot_be_replayed() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (id, username) = make_account(&pool, "buyer", PW).await;
    let secret = enroll(&pool, &srv.keyfile, id).await;

    let c = code(&secret, 0);
    let r = login_attempt(srv.addr, &username, PW, Some(&c)).await;
    let tok = session_cookie_of(&r).expect("first use of the code logs in");
    // Log that session out again. The login-created session carries
    // its own random CSRF secret — scrape it from the account page's
    // logout form (the session_for helper's fixed secret does not
    // apply here).
    let page = http_raw(srv.addr, "GET", "/account", Some(&format!("session={tok}")), None, None).await;
    assert_eq!(page.status, 200);
    let marker = "name=\"csrf\" value=\"";
    let start = page.body.find(marker).expect("account page carries a csrf field") + marker.len();
    let real_csrf = &page.body[start..page.body[start..].find('"').unwrap() + start];
    let out = post_form(
        srv.addr,
        "/logout",
        Some(&format!("session={tok}")),
        &[("csrf", real_csrf)],
    )
    .await;
    assert!(matches!(out.status, 302 | 303), "logout must redirect, got {}", out.status);

    // The SAME code a second time (same validity window) is a replay.
    let r = login_attempt(srv.addr, &username, PW, Some(&c)).await;
    assert!(
        session_cookie_of(&r).is_none(),
        "the same code twice in one window must fail the second time"
    );

    srv.stop();
    cleanup(&pool, &[id]).await;
}

// ---------------------------------------------------------------------------
// Task 7 (library half): replay at the step-up gate + confirm-while-active
// ---------------------------------------------------------------------------

#[tokio::test]
async fn totp_gate_replay_and_confirm_while_active() {
    let Some(pool) = pool().await else { return };
    let dir = std::env::temp_dir().join(format!("acctsec-kf-{}-{}", std::process::id(), uniq()));
    std::fs::create_dir_all(&dir).unwrap();
    let kf = KeyFile::load_or_generate(&dir.join("k")).unwrap();
    let (id, _u) = make_account(&pool, "moderator", PW).await;
    let secret = enroll(&pool, &kf, id).await;

    // First presentation of the current code passes the gate...
    let c = code(&secret, 0);
    moderation::require_totp(&pool, &kf, id, &c).await.unwrap();
    // ...and the identical code again is a replay and is refused.
    let err = moderation::require_totp(&pool, &kf, id, &c)
        .await
        .expect_err("a replayed code must be refused");
    assert!(
        matches!(err, ModError::TotpReplayed | ModError::TotpInvalid),
        "replay must be refused, got {err:?}"
    );

    // Confirm while TOTP is already active is refused, and the active
    // secret is untouched by the attempt.
    let enc_before: Vec<u8> =
        sqlx::query_scalar("SELECT totp_secret_enc FROM accounts WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    moderation::totp_begin(&pool, &kf, id).await.unwrap();
    let pending_b32 = moderation::totp_pending(&pool, &kf, id).await.unwrap().unwrap();
    let pending_secret = totp::base32_decode(&pending_b32).unwrap();
    let err = moderation::totp_confirm(&pool, &kf, id, &code(&pending_secret, 0))
        .await
        .expect_err("confirm while TOTP is active must be refused");
    assert!(
        matches!(err, ModError::TotpAlreadyActive),
        "got {err:?}"
    );
    let enc_after: Vec<u8> =
        sqlx::query_scalar("SELECT totp_secret_enc FROM accounts WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(enc_before, enc_after, "the active secret must not be replaced");

    let _ = std::fs::remove_dir_all(&dir);
    cleanup(&pool, &[id]).await;
}

// ---------------------------------------------------------------------------
// Task 3 (library half): failed-code counting, lockout, notice, cool-down
// ---------------------------------------------------------------------------

#[tokio::test]
async fn moderator_codes_lock_after_ten_failures() {
    let Some(pool) = pool().await else { return };
    let dir = std::env::temp_dir().join(format!("acctsec-kf-{}-{}", std::process::id(), uniq()));
    std::fs::create_dir_all(&dir).unwrap();
    let kf = KeyFile::load_or_generate(&dir.join("k")).unwrap();
    let (id, _u) = make_account(&pool, "moderator", PW).await;
    let secret = enroll(&pool, &kf, id).await;

    // Nine wrong codes: refused as invalid, no lock yet.
    for i in 0..9 {
        let err = moderation::require_totp(&pool, &kf, id, &wrong_code(&secret))
            .await
            .expect_err("wrong code refused");
        assert!(matches!(err, ModError::TotpInvalid), "failure {i}: got {err:?}");
    }
    // The tenth failure trips the lock.
    let err = moderation::require_totp(&pool, &kf, id, &wrong_code(&secret))
        .await
        .expect_err("wrong code refused");
    assert!(matches!(err, ModError::TotpInvalid), "tenth failure: got {err:?}");
    // While locked, even the CORRECT code is refused.
    let err = moderation::require_totp(&pool, &kf, id, &code(&secret, 0))
        .await
        .expect_err("a locked account refuses even the correct code");
    assert!(matches!(err, ModError::TotpLocked), "got {err:?}");
    // The account got an inbox notice about the lockout.
    assert!(
        has_event(&pool, id, "totp_locked").await,
        "the lockout must leave an inbox notice for the account"
    );
    // After the cool-down, a successful code clears the lock.
    sqlx::query("UPDATE accounts SET totp_locked_until = now() - interval '1 second' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    moderation::require_totp(&pool, &kf, id, &code(&secret, 30))
        .await
        .expect("after the cool-down the next-step code passes and clears the lock");
    let still_locked: bool = sqlx::query_scalar(
        "SELECT totp_locked_until IS NOT NULL AND totp_locked_until > now() FROM accounts WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!still_locked, "a successful code clears the lock");

    let _ = std::fs::remove_dir_all(&dir);
    cleanup(&pool, &[id]).await;
}

// ---------------------------------------------------------------------------
// Tasks 1+2: seller payment identity needs enrollment AND step-up;
// step-up also guards batch upload, key upload/rotation, TOTP enrollment
// ---------------------------------------------------------------------------

fn batch_json(seller_pub: &str, subs: &[&str]) -> String {
    let cfg = app::payments::PaymentConfig::defaults("vespiary-market");
    let seller_id = app::payments::payment_seller_id(seller_pub).unwrap();
    let entries: Vec<serde_json::Value> = subs
        .iter()
        .map(|s| {
            serde_json::json!({
                "subaddress": s,
                "message": app::payments::canonical_message(&cfg.marketplace_id, cfg.network, &seller_id, PRIMARY_A, s),
                "signature": SIG,
            })
        })
        .collect();
    serde_json::json!({
        "format": "xmr-direct-batch-v1",
        "marketplace_id": cfg.marketplace_id,
        "network": "stagenet",
        "seller_id": seller_id,
        "primary_address": PRIMARY_A,
        "entries": entries,
    })
    .to_string()
}

fn multipart(fields: &[(&str, &str)]) -> (String, Vec<u8>) {
    let boundary = format!("----acctsec{}", uniq());
    let mut out = Vec::new();
    for (k, v) in fields {
        out.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n")
                .as_bytes(),
        );
    }
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), out)
}

#[tokio::test]
async fn stepup_required_for_payment_identity_batch_key_and_enrollment() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let srv = test_server(&pool).await;
    let cfg = app::payments::PaymentConfig::defaults("vespiary-market");
    let (seller, _su) = make_account(&pool, "seller", PW).await;
    let seller_pub = app::db::public_id_of(&pool, seller).await.unwrap().unwrap();
    let seller_cookie = format!("session={}", session_for(&pool, seller).await);

    // (a) Not enrolled in TOTP: setting a payment identity is refused
    // outright (task 1: enrollment is mandatory for sellers first).
    let r = post_form(
        srv.addr,
        "/seller/payment-identity",
        Some(&seller_cookie),
        &[("csrf", CSRF), ("primary_address", PRIMARY_A), ("password", PW)],
    )
    .await;
    assert!(
        location_of(&r).contains("TOTP"),
        "unenrolled seller must be told to enroll first, got location {:?}",
        location_of(&r)
    );
    assert!(
        app::payments::get_identity(&pool, seller).await.unwrap().is_none(),
        "no identity may be stored for an unenrolled seller"
    );

    // Enroll (library), then step-up applies.
    let secret = enroll(&pool, &srv.keyfile, seller).await;

    // (b) Passphrase but no code: refused, nothing stored.
    let r = post_form(
        srv.addr,
        "/seller/payment-identity",
        Some(&seller_cookie),
        &[("csrf", CSRF), ("primary_address", PRIMARY_A), ("password", PW)],
    )
    .await;
    assert!(
        location_of(&r).contains("Step-up"),
        "missing code must fail the step-up, got {:?}",
        location_of(&r)
    );
    assert!(app::payments::get_identity(&pool, seller).await.unwrap().is_none());

    // (c) Code but wrong passphrase: refused, nothing stored.
    let r = post_form(
        srv.addr,
        "/seller/payment-identity",
        Some(&seller_cookie),
        &[
            ("csrf", CSRF),
            ("primary_address", PRIMARY_A),
            ("password", "not-the-passphrase"),
            ("totp", &code(&secret, 0)),
        ],
    )
    .await;
    assert!(location_of(&r).contains("Step-up"), "wrong passphrase must fail the step-up");
    assert!(app::payments::get_identity(&pool, seller).await.unwrap().is_none());

    // (d) Passphrase + fresh code: stored, and an inbox notice lands.
    let r = post_form(
        srv.addr,
        "/seller/payment-identity",
        Some(&seller_cookie),
        &[
            ("csrf", CSRF),
            ("primary_address", PRIMARY_A),
            ("password", PW),
            ("totp", &code(&secret, 0)),
        ],
    )
    .await;
    assert!(
        location_of(&r).contains("saved"),
        "valid step-up must save the identity, got {:?}",
        location_of(&r)
    );
    let identity = app::payments::get_identity(&pool, seller).await.unwrap().unwrap();
    assert_eq!(identity.primary_address, PRIMARY_A);
    assert!(
        has_event(&pool, seller, "stepup_payment_identity").await,
        "a payment-identity step-up must leave an inbox notice"
    );

    // (e) Batch upload without step-up fields: refused, pool unchanged.
    let batch = batch_json(&seller_pub, &SUBS[0..2]);
    let (ct, body) = multipart(&[("csrf", CSRF), ("batch_json", &batch)]);
    let r = http_raw(
        srv.addr,
        "POST",
        "/seller/payment-batches",
        Some(&seller_cookie),
        Some(&ct),
        Some(&body),
    )
    .await;
    assert!(
        location_of(&r).contains("Step-up"),
        "batch upload without step-up must be refused, got {:?}",
        location_of(&r)
    );
    assert_eq!(
        app::payments::unused_count(&pool, seller).await.unwrap(),
        0,
        "no pool entries may land without step-up"
    );

    // (f) Batch upload with passphrase + the NEXT step's code: accepted.
    let (ct, body) = multipart(&[
        ("csrf", CSRF),
        ("batch_json", &batch),
        ("password", PW),
        ("totp", &code(&secret, 30)),
    ]);
    let r = http_raw(
        srv.addr,
        "POST",
        "/seller/payment-batches",
        Some(&seller_cookie),
        Some(&ct),
        Some(&body),
    )
    .await;
    assert!(
        location_of(&r).contains("accepted"),
        "valid step-up must accept the batch, got {:?}",
        location_of(&r)
    );
    assert_eq!(app::payments::unused_count(&pool, seller).await.unwrap(), 2);
    assert!(has_event(&pool, seller, "stepup_payment_batch").await);
    let _ = cfg;

    // (g) Key upload: session alone is not enough; passphrase+code is.
    let (kid, _ku) = make_account(&pool, "buyer", PW).await;
    let ksecret = enroll(&pool, &srv.keyfile, kid).await;
    let k_cookie = format!("session={}", session_for(&pool, kid).await);
    let cert_a = include_str!("fixtures/key-a.asc");
    let r = post_form(
        srv.addr,
        "/account/keys",
        Some(&k_cookie),
        &[("csrf", CSRF), ("cert", cert_a)],
    )
    .await;
    assert!(
        r.body.contains("Step-up"),
        "key upload without step-up must be refused: {}",
        r.body
    );
    assert!(app::keys::current_key(&pool, kid).await.unwrap().is_none());
    let r = post_form(
        srv.addr,
        "/account/keys",
        Some(&k_cookie),
        &[
            ("csrf", CSRF),
            ("cert", cert_a),
            ("password", PW),
            ("totp", &code(&ksecret, 0)),
        ],
    )
    .await;
    assert!(
        app::keys::current_key(&pool, kid).await.unwrap().is_some(),
        "key upload with step-up must register the key: {}",
        r.body
    );
    assert!(has_event(&pool, kid, "stepup_key_upload").await);

    // (h) Key rotation: refused without step-up before anything moves.
    let fpr_before = app::keys::current_key(&pool, kid).await.unwrap().unwrap().0;
    let cert_b = include_str!("fixtures/key-b.asc");
    let r = post_form(
        srv.addr,
        "/account/keys/rotate",
        Some(&k_cookie),
        &[
            ("csrf", CSRF),
            ("new_cert", cert_b),
            ("statement", ""),
            ("sig_old", ""),
            ("sig_new", ""),
        ],
    )
    .await;
    assert!(r.body.contains("Step-up"), "rotation without step-up must be refused");
    let fpr_after = app::keys::current_key(&pool, kid).await.unwrap().unwrap().0;
    assert_eq!(fpr_before, fpr_after, "the key must not move without step-up");

    // (i) TOTP enrollment itself needs the passphrase: a bare session
    // cannot start enrollment; the passphrase can.
    let (eid, _eu) = make_account(&pool, "buyer", PW).await;
    let e_cookie = format!("session={}", session_for(&pool, eid).await);
    let r = post_form(srv.addr, "/account/totp/begin", Some(&e_cookie), &[("csrf", CSRF)]).await;
    assert!(r.body.contains("Step-up"), "enrollment without passphrase must be refused");
    assert!(
        moderation::totp_pending(&pool, &srv.keyfile, eid).await.unwrap().is_none(),
        "no pending secret may be created without step-up"
    );
    let r = post_form(
        srv.addr,
        "/account/totp/begin",
        Some(&e_cookie),
        &[("csrf", CSRF), ("password", PW)],
    )
    .await;
    assert!(
        moderation::totp_pending(&pool, &srv.keyfile, eid).await.unwrap().is_some(),
        "enrollment with the passphrase must start: {}",
        r.body
    );
    assert!(has_event(&pool, eid, "stepup_totp_enrollment").await);

    srv.stop();
    cleanup(&pool, &[seller, kid, eid]).await;
}

// ---------------------------------------------------------------------------
// Task 3 (HTTP half): disclosures + seller approval need a fresh code
// ---------------------------------------------------------------------------

#[tokio::test]
async fn moderator_disclosures_and_seller_approval_need_fresh_code() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let srv = test_server(&pool).await;
    let cfg = app::payments::PaymentConfig::defaults("vespiary-market");

    // A shop, an order, a manual payment report (the dispute gate for
    // assignment-carrying orders), and a dispute with a disclosure.
    let (seller, _su) = make_account(&pool, "seller", PW).await;
    install_key(&pool, seller).await;
    let seller_pub = app::db::public_id_of(&pool, seller).await.unwrap().unwrap();
    app::payments::set_primary_address(&pool, seller, PRIMARY_A, &cfg).await.unwrap();
    app::payments::upload_batch(&pool, seller, &batch_json(&seller_pub, &SUBS[3..6]), &cfg)
        .await
        .unwrap();
    let (buyer, _bu) = make_account(&pool, "buyer", PW).await;
    let listing_id = app::db::public_id("lst_");
    sqlx::query(
        "INSERT INTO listings (public_id, seller_id, title, description, price_atomic,
            pricing_module, destination_module, auto_invoice, status, category)
         VALUES ($1, $2, 'Gate Widget', 'A widget.', 1250000000000, 'xmr-only',
                 'signed-address-pool', false, 'published', 'general')",
    )
    .bind(&listing_id)
    .bind(seller)
    .execute(&pool)
    .await
    .unwrap();
    let (order, _) =
        app::orders::create_order_with_config(&pool, "vespiary-market", buyer, &listing_id, 1, &uniq(), &cfg)
            .await
            .unwrap();
    app::orders::apply_action(&pool, &order, "accept", seller).await.unwrap();
    let order = app::orders::order_by_public_id(&pool, &order.public_id).await.unwrap();
    app::payments::submit_manual_report(&pool, &order, buyer).await.unwrap();
    // Re-fetch: apply_action judges the snapshot it is handed, and the
    // manual report just raised the stored evidence level (the same
    // pattern as tx_proof_flow.rs's dispute tests).
    let order = app::orders::order_by_public_id(&pool, &order.public_id).await.unwrap();
    app::orders::apply_action(&pool, &order, "dispute", buyer).await.unwrap();
    let dispute = app::disputes::dispute_for_order(&pool, order.id).await.unwrap().unwrap();
    const MARKER: &str = "ACCTSEC-DISCLOSURE-MARKER-7f3";
    app::disputes::submit_disclosure(
        &pool,
        &srv.keyfile,
        dispute.id,
        buyer,
        &format!("the seller said: {MARKER}"),
        "detached-signature-placeholder",
    )
    .await
    .unwrap();

    // A moderator (enrolled) looks at the dispute: the disclosure is
    // NOT rendered until a fresh code unlocks it for this session.
    let (moderator, _mu) = make_account(&pool, "moderator", PW).await;
    let mod_secret = enroll(&pool, &srv.keyfile, moderator).await;
    let mod_cookie = format!("session={}", session_for(&pool, moderator).await);
    let path = format!("/disputes/{}", dispute.id);
    let r = http_raw(srv.addr, "GET", &path, Some(&mod_cookie), None, None).await;
    assert_eq!(r.status, 200);
    assert!(
        !r.body.contains(MARKER),
        "no disclosure may render for a moderator without a fresh code"
    );
    assert!(
        r.body.contains(&format!("/disputes/{}/unlock", dispute.id)),
        "the locked view must offer the unlock form"
    );

    // A wrong code does not unlock.
    let r = post_form(
        srv.addr,
        &format!("/disputes/{}/unlock", dispute.id),
        Some(&mod_cookie),
        &[("csrf", CSRF), ("totp", &wrong_code(&mod_secret))],
    )
    .await;
    assert!(matches!(r.status, 302 | 303), "unlock attempt redirects back");
    let r = http_raw(srv.addr, "GET", &path, Some(&mod_cookie), None, None).await;
    assert!(!r.body.contains(MARKER), "a wrong code must not unlock disclosures");

    // The fresh code unlocks; the disclosure now renders.
    let r = post_form(
        srv.addr,
        &format!("/disputes/{}/unlock", dispute.id),
        Some(&mod_cookie),
        &[("csrf", CSRF), ("totp", &code(&mod_secret, 0))],
    )
    .await;
    assert!(matches!(r.status, 302 | 303));
    let r = http_raw(srv.addr, "GET", &path, Some(&mod_cookie), None, None).await;
    assert!(r.body.contains(MARKER), "after a fresh code the disclosure renders");

    // The buyer (a party) sees their own disclosure without any code.
    let buyer_cookie = format!("session={}", session_for(&pool, buyer).await);
    let r = http_raw(srv.addr, "GET", &path, Some(&buyer_cookie), None, None).await;
    assert!(r.body.contains(MARKER), "parties keep their existing view");

    // Seller approval: without a code the application stays pending;
    // with a fresh code it is approved.
    let (applicant, _au) = make_account(&pool, "buyer", PW).await;
    app::listings::apply_for_seller(&pool, applicant).await.unwrap();
    let decide_path = format!("/moderation/sellers/{applicant}");
    let r = post_form(
        srv.addr,
        &decide_path,
        Some(&mod_cookie),
        &[("csrf", CSRF), ("decision", "approve")],
    )
    .await;
    // The refusal is a 200 render of the applications page carrying
    // the refusal message (moderation_decide's pattern, like the
    // security page's step-up refusals) — not a redirect. The
    // substantive checks are the message and the unchanged role.
    assert_eq!(r.status, 200, "refusal renders the applications page");
    assert!(
        r.body.contains("Decision refused"),
        "the refusal must say why: {}",
        r.body
    );
    assert_eq!(
        app::db::role_of(&pool, applicant).await.unwrap().as_deref(),
        Some("buyer"),
        "approval without a code must not take effect"
    );
    let r = post_form(
        srv.addr,
        &decide_path,
        Some(&mod_cookie),
        &[("csrf", CSRF), ("decision", "approve"), ("totp", &code(&mod_secret, 30))],
    )
    .await;
    assert!(matches!(r.status, 302 | 303));
    assert_eq!(
        app::db::role_of(&pool, applicant).await.unwrap().as_deref(),
        Some("seller"),
        "approval with a fresh code takes effect"
    );

    srv.stop();
    cleanup(&pool, &[seller, buyer, moderator, applicant]).await;
}

// ---------------------------------------------------------------------------
// Task 4: login budget (checked before hashing) + per-username hash
// serialization + failure-map hygiene
// ---------------------------------------------------------------------------

#[test]
fn login_failure_budget_and_map_hygiene() {
    use app::throttle::Throttles;
    let th = Throttles::new();
    assert!(!th.login_budget_exceeded("victim"));
    for _ in 0..10 {
        th.record_login_failure("victim");
    }
    assert!(th.login_budget_exceeded("victim"), "10 failures exhaust the budget");
    assert!(!th.login_budget_exceeded("someoneelse"), "the budget is per-username");
    th.clear_login_failures("victim");
    assert!(!th.login_budget_exceeded("victim"), "a success clears the budget");

    // The failure map is capped: flooding distinct usernames cannot
    // grow it without bound.
    let th2 = Throttles::new();
    for i in 0..20_000 {
        th2.record_login_failure(&format!("flood{i}"));
    }
    assert!(
        th2.login_failure_entry_count() <= 4096,
        "failure map must be capped, got {}",
        th2.login_failure_entry_count()
    );
}

#[tokio::test]
async fn hash_scoped_serializes_per_username_only() {
    let guard = HashGuard::new(8);
    let stored = guard.hash("the-real-passphrase").await.unwrap();
    let one = || async {
        let t = std::time::Instant::now();
        let _ = guard.verify_scoped("scope-probe", "wrong-passphrase", &stored).await;
        t.elapsed()
    };
    // Baseline: the fastest of three single verifications.
    let mut d = one().await;
    for _ in 0..2 {
        d = d.min(one().await);
    }
    // Four concurrent verifications for the SAME scope serialize.
    let t = std::time::Instant::now();
    let mut hs = Vec::new();
    for _ in 0..4 {
        let g = guard.clone();
        let s = stored.clone();
        hs.push(tokio::spawn(async move {
            let _ = g.verify_scoped("same-user", "wrong-passphrase", &s).await;
        }));
    }
    for h in hs {
        h.await.unwrap();
    }
    let same = t.elapsed();
    // Four concurrent verifications for DIFFERENT scopes run in
    // parallel (subject only to the global guard + CPU).
    let t = std::time::Instant::now();
    let mut hs = Vec::new();
    for i in 0..4 {
        let g = guard.clone();
        let s = stored.clone();
        hs.push(tokio::spawn(async move {
            let _ = g
                .verify_scoped(&format!("user-{i}"), "wrong-passphrase", &s)
                .await;
        }));
    }
    for h in hs {
        h.await.unwrap();
    }
    let distinct = t.elapsed();
    assert!(
        same >= d * 3,
        "same-username hashes must serialize: 4 concurrent took {same:?}, one takes {d:?}"
    );
    assert!(
        distinct < same,
        "other usernames must not be serialized behind one user: distinct {distinct:?} vs same {same:?}"
    );
}

#[tokio::test]
async fn login_budget_refuses_before_hashing() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (victim, vname) = make_account(&pool, "buyer", PW).await;
    let (other, oname) = make_account(&pool, "buyer", PW).await;

    // Ten parallel wrong-password logins exhaust the victim's budget
    // (they also serialize on the victim's hash scope).
    let mut hs = Vec::new();
    for _ in 0..10 {
        let addr = srv.addr;
        let u = vname.clone();
        hs.push(tokio::spawn(async move {
            login_attempt(addr, &u, "wrong-passphrase", None).await
        }));
    }
    for h in hs {
        let r = h.await.unwrap();
        assert!(session_cookie_of(&r).is_none(), "wrong password never logs in");
    }

    // The 11th attempt — even with the CORRECT passphrase — is refused
    // by the budget, fast (no Argon2 work happens for it).
    let t = std::time::Instant::now();
    let r = login_attempt(srv.addr, &vname, PW, None).await;
    let refused_in = t.elapsed();
    assert!(session_cookie_of(&r).is_none(), "budget-exhausted login is refused");
    assert!(
        r.body.contains("Invalid username or passphrase."),
        "the refusal is the generic error (no oracle): {}",
        r.body
    );

    // A correct login for another user works and shows what a hashed
    // attempt costs; the budget refusal must be far cheaper.
    let t = std::time::Instant::now();
    let r = login_attempt(srv.addr, &oname, PW, None).await;
    let hashed_in = t.elapsed();
    assert!(session_cookie_of(&r).is_some(), "another username still logs in");
    assert!(
        refused_in < hashed_in / 2,
        "budget refusal ({refused_in:?}) must not pay the hash cost ({hashed_in:?})"
    );

    srv.stop();
    cleanup(&pool, &[victim, other]).await;
}

// ---------------------------------------------------------------------------
// Task 5: the request throttle is wired into signed-in POSTs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn signed_in_posts_are_throttled_at_sixty() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (id, _u) = make_account(&pool, "buyer", PW).await;
    let cookie = format!("session={}", session_for(&pool, id).await);

    // 61 rapid POSTs from one account: the burst budget is 60, so the
    // 61st is a 429 (the brief's acceptance shape).
    let mut statuses = Vec::new();
    for _ in 0..61 {
        let r = post_form(srv.addr, "/inbox/read-all", Some(&cookie), &[("csrf", CSRF)]).await;
        statuses.push(r.status);
    }
    assert!(
        statuses[..60].iter().all(|s| *s != 429),
        "the first 60 posts pass: {statuses:?}"
    );
    assert_eq!(statuses[60], 429, "the 61st post in the burst is throttled");

    // Another account is unaffected.
    let (id2, _u2) = make_account(&pool, "buyer", PW).await;
    let cookie2 = format!("session={}", session_for(&pool, id2).await);
    let r = post_form(srv.addr, "/inbox/read-all", Some(&cookie2), &[("csrf", CSRF)]).await;
    assert_ne!(r.status, 429, "the throttle is per-account");

    srv.stop();
    cleanup(&pool, &[id, id2]).await;
}

// ---------------------------------------------------------------------------
// Task 6: fail closed outside development
// ---------------------------------------------------------------------------

#[test]
fn keyfile_load_existing_and_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("acctsec-kf6-{}-{}", std::process::id(), uniq()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("k.key");

    // load_existing refuses a missing file and creates nothing.
    assert!(KeyFile::load_existing(&path).is_err(), "missing key file must refuse");
    assert!(!path.exists(), "a refused load must not create the file");

    // load_or_generate creates it 0600 from creation.
    let kf = KeyFile::load_or_generate(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "new key files are 0600, got {mode:o}");
    // And load_existing now loads the same key.
    let kf2 = KeyFile::load_existing(&path).unwrap();
    assert_eq!(kf.buyer_token(1, 2), kf2.buyer_token(1, 2));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn production_profile_fails_closed() {
    let Ok(db_url) = std::env::var("DATABASE_URL") else { return };
    let bin = env!("CARGO_BIN_EXE_marketplace-app");
    let dir = std::env::temp_dir().join(format!("acctsec-bin-{}-{}", std::process::id(), uniq()));
    std::fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("missing.key");

    let base = |cmd: &mut std::process::Command| {
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("DEPLOY_PROFILE", "production")
            .env("KEY_FILE_PATH", &key_path)
            .env("BIND_ADDR", "127.0.0.1:0");
    };

    // Production + no DATABASE_URL: refuse to start (exit 2), and do
    // not fall back to the development database.
    let out = {
        let mut c = std::process::Command::new(bin);
        base(&mut c);
        c.output().unwrap()
    };
    assert_eq!(
        out.status.code(),
        Some(2),
        "production without DATABASE_URL must exit 2: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!key_path.exists(), "no key file may be created on a refused start");

    // Production + DATABASE_URL + missing key file: refuse (exit 2),
    // create nothing.
    let out = {
        let mut c = std::process::Command::new(bin);
        base(&mut c);
        c.env("DATABASE_URL", &db_url);
        c.output().unwrap()
    };
    assert_eq!(
        out.status.code(),
        Some(2),
        "production without a key file must exit 2: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!key_path.exists(), "production must never silently mint a key file");

    // Development control: the same missing key file is generated and
    // the server starts.
    let mut child = {
        let mut c = std::process::Command::new(bin);
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("DATABASE_URL", &db_url)
            .env("KEY_FILE_PATH", &key_path)
            .env("BIND_ADDR", "127.0.0.1:0")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        c.spawn().unwrap()
    };
    std::thread::sleep(std::time::Duration::from_millis(900));
    let running = child.try_wait().unwrap().is_none();
    let created = key_path.exists();
    let _ = child.kill();
    let _ = child.wait();
    assert!(running, "the development profile must start");
    assert!(created, "development generates the key file as before");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Task 8: passphrase change + new recovery code
// ---------------------------------------------------------------------------

#[tokio::test]
async fn passphrase_change_and_recovery_code_issue() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (id, username) = make_account(&pool, "buyer", PW).await;
    let old_code = app::recovery::new_recovery_code();
    app::db::store_recovery_code(&pool, id, &old_code).await.unwrap();
    let tok1 = session_for(&pool, id).await;
    let tok2 = session_for(&pool, id).await;
    let c1 = format!("session={tok1}");
    let c2 = format!("session={tok2}");

    // Wrong current passphrase: refused, nothing changes.
    let r = post_form(
        srv.addr,
        "/account/passphrase",
        Some(&c1),
        &[("csrf", CSRF), ("current_password", "not-the-passphrase"), ("new_password", PW2)],
    )
    .await;
    assert!(!r.body.contains("Passphrase changed"), "wrong current passphrase must be refused");
    let r = login_attempt(srv.addr, &username, PW, None).await;
    assert!(session_cookie_of(&r).is_some(), "the old passphrase still works after a refused change");

    // Correct current passphrase: changed; other sessions end; this
    // session survives; an inbox notice lands.
    let r = post_form(
        srv.addr,
        "/account/passphrase",
        Some(&c1),
        &[("csrf", CSRF), ("current_password", PW), ("new_password", PW2)],
    )
    .await;
    assert!(r.body.contains("Passphrase changed"), "change must confirm: {}", r.body);
    let r = http_raw(srv.addr, "GET", "/account", Some(&c2), None, None).await;
    assert!(
        matches!(r.status, 302 | 303) && location_of(&r) == "/login",
        "the OTHER session must be revoked by a passphrase change"
    );
    let r = http_raw(srv.addr, "GET", "/account", Some(&c1), None, None).await;
    assert_eq!(r.status, 200, "the current session survives its own change");
    assert!(has_event(&pool, id, "security_passphrase_changed").await);
    let r = login_attempt(srv.addr, &username, PW, None).await;
    assert!(session_cookie_of(&r).is_none(), "the old passphrase now fails");
    let r = login_attempt(srv.addr, &username, PW2, None).await;
    assert!(session_cookie_of(&r).is_some(), "the new passphrase works");

    // Issue a new recovery code (passphrase step-up): the response
    // shows the new code once; the old code is dead.
    let r = post_form(
        srv.addr,
        "/account/recovery-codes",
        Some(&c1),
        &[("csrf", CSRF), ("password", PW2)],
    )
    .await;
    assert_eq!(r.status, 200, "issuing a recovery code renders the account page");
    let marker = "Your recovery code (shown once): ";
    let start = r.body.find(marker).expect("the new code is shown once") + marker.len();
    let new_code: String = r.body[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
        .collect();
    assert_eq!(new_code.len(), 23, "recovery code shape (5x4 + dashes): {new_code:?}");
    assert_ne!(new_code, old_code, "a NEW code is issued");

    // The old code no longer recovers; the new one does.
    let csrf = anon_csrf(srv.addr, "/account/recover").await;
    let r = post_form(
        srv.addr,
        "/account/recover",
        Some(&format!("csrf={csrf}")),
        &[
            ("csrf", csrf.as_str()),
            ("username", &username),
            ("code", &old_code),
            ("password", "acctsec-third-passphrase-3"),
        ],
    )
    .await;
    assert!(r.body.contains("Recovery failed."), "the superseded code must be dead");
    let csrf = anon_csrf(srv.addr, "/account/recover").await;
    let r = post_form(
        srv.addr,
        "/account/recover",
        Some(&format!("csrf={csrf}")),
        &[
            ("csrf", csrf.as_str()),
            ("username", &username),
            ("code", &new_code),
            ("password", "acctsec-third-passphrase-3"),
        ],
    )
    .await;
    assert!(r.body.contains("Passphrase reset"), "the new code recovers the account: {}", r.body);

    srv.stop();
    cleanup(&pool, &[id]).await;
}
