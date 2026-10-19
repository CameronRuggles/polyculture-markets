//! Modules, Statements, Fuzzing and Routes Audit (2026-10-19) —
//! acceptance tests for the BM/BL fix brief:
//!
//! 1. (BM1) Registration runs on its own one-slot hashing pool
//!    and checks the username + the per-instance registration
//!    budget BEFORE hashing; logins wait briefly for a slot.
//! 2. (BM2) Recovery hashes the new passphrase first and only then
//!    spends the recovery code, in a single transaction — a busy
//!    pool can no longer burn a user's only code.
//!
//! DB tests require DATABASE_URL (skipped silently when unset, the
//! pattern of the neighbouring suites).

use app::config::InstanceConfig;
use app::keyfile::KeyFile;
use app::media::MediaPipeline;
use app::passwords::HashGuard;
use app::throttle::Throttles;
use app::web::{router, AppState};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PW: &str = "bmbl-correct-passphrase-1";

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

async fn make_account(pool: &PgPool, role: &str, password: &str) -> (i64, String) {
    let hash = HashGuard::new(2).hash(password).await.unwrap();
    let public_id = app::db::public_id("acct_");
    let username = format!("bmbl{}", uniq());
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

// ---------------------------------------------------------------------------
// HTTP test server (the account_security / verification_fixes
// pattern, with the hash guard and throttles retained so tests can
// observe them)
// ---------------------------------------------------------------------------

struct TestServer {
    addr: std::net::SocketAddr,
    hash_guard: HashGuard,
    throttles: Arc<Throttles>,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}

async fn test_server(pool: &PgPool) -> TestServer {
    let mut dir = std::env::temp_dir();
    dir.push(format!("bmbl-http-{}-{}", std::process::id(), uniq()));
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
        account_cap: None,
        dev_cookies: true,
        media,
        marketplace_id,
        payments,
        keyfile,
        stage9: app::reputation::Stage9Config::from_env(),
        instance,
        retention: app::retention::RetentionConfig::defaults(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    TestServer { addr, hash_guard, throttles, handle, dir }
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

/// GET an anonymous form page (register/login/recover): returns the
/// CSRF cookie value, which is also the form's hidden csrf field.
async fn anon_csrf(addr: std::net::SocketAddr, path: &str) -> String {
    let r = http_raw(addr, "GET", path, None, None, None).await;
    assert_eq!(r.status, 200, "GET {path}");
    let marker = "csrf=";
    let start = r.headers.to_lowercase().find(marker).expect("csrf cookie set") + marker.len();
    let rest = &r.headers[start..];
    rest.split(';').next().unwrap().trim().to_string()
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

async fn register_attempt(
    addr: std::net::SocketAddr,
    username: &str,
    password: &str,
) -> HttpResult {
    let csrf = anon_csrf(addr, "/register").await;
    let cookie = format!("csrf={csrf}");
    post_form(
        addr,
        "/register",
        Some(&cookie),
        &[("csrf", &csrf), ("username", username), ("password", password)],
    )
    .await
}

async fn login_attempt(
    addr: std::net::SocketAddr,
    username: &str,
    password: &str,
) -> HttpResult {
    let csrf = anon_csrf(addr, "/login").await;
    let cookie = format!("csrf={csrf}");
    post_form(
        addr,
        "/login",
        Some(&cookie),
        &[("csrf", &csrf), ("username", username), ("password", password)],
    )
    .await
}

async fn recover_attempt(
    addr: std::net::SocketAddr,
    username: &str,
    code: &str,
    password: &str,
) -> HttpResult {
    let csrf = anon_csrf(addr, "/recover").await;
    let cookie = format!("csrf={csrf}");
    post_form(
        addr,
        "/recover",
        Some(&cookie),
        &[
            ("csrf", &csrf),
            ("username", username),
            ("code", code),
            ("password", password),
        ],
    )
    .await
}

// ---------------------------------------------------------------------------
// Task 1 (BM1): registration never touches the login pool, and a
// taken username is refused before any hashing.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registrations_in_flight_do_not_block_login() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (_id, username) = make_account(&pool, "buyer", PW).await;

    // Four registration requests held in flight at once. On the
    // pre-fix code these four Argon2 runs occupy the ENTIRE shared
    // hashing pool and the login below is refused Busy; with BM1
    // they contend only for registration's own one-slot pool.
    let mut regs = Vec::new();
    for i in 0..4 {
        let addr = srv.addr;
        let name = format!("bmblreg{}{}", i, uniq());
        regs.push(tokio::spawn(async move {
            register_attempt(addr, &name, "bmbl-new-account-passphrase").await
        }));
    }
    // Let the registrations get underway (the first is hashing,
    // the rest are being refused/queued at the registration slot).
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let r = login_attempt(srv.addr, &username, PW).await;
    assert!(
        set_cookie_value(&r, "session").is_some(),
        "a correct login succeeds while four registrations are in flight (status {})",
        r.status
    );

    for h in regs {
        let _ = h.await.unwrap();
    }
    srv.stop();
}

#[tokio::test]
async fn taken_username_registration_refused_without_hashing() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (_id, username) = make_account(&pool, "buyer", PW).await;

    // Re-registering a taken username is refused with the taken
    // message and — the BM1 point — performs NO Argon2 run at all:
    // the check happens before hashing.
    let before = srv.hash_guard.hash_op_count();
    let r = register_attempt(srv.addr, &username, "bmbl-other-passphrase-1").await;
    assert!(
        r.body.contains("That username is taken."),
        "taken username gets the taken message, got status {} body snippet: {}",
        r.status,
        &r.body[..r.body.len().min(200)]
    );
    assert_eq!(
        srv.hash_guard.hash_op_count(),
        before,
        "a taken-username registration must not run a single hash"
    );
    srv.stop();
}

#[tokio::test]
async fn registration_budget_refuses_before_hashing() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;

    // Spend the whole per-instance registration budget directly,
    // then confirm a fresh registration is refused (503) before
    // any hashing happens.
    let now = time::OffsetDateTime::now_utc();
    for _ in 0..app::throttle::REGISTRATION_BUDGET {
        srv.throttles.record_registration(now);
    }
    assert!(srv.throttles.registration_budget_exceeded(now));
    let before = srv.hash_guard.hash_op_count();
    let name = format!("bmblcap{}", uniq());
    let r = register_attempt(srv.addr, &name, "bmbl-new-account-passphrase").await;
    assert_eq!(r.status, 503, "over-budget registration is refused");
    assert_eq!(
        srv.hash_guard.hash_op_count(),
        before,
        "an over-budget registration must not run a hash"
    );
    srv.stop();
}
