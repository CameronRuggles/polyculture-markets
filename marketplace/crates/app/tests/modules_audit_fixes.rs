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
    let csrf = anon_csrf(addr, "/account/recover").await;
    let cookie = format!("csrf={csrf}");
    post_form(
        addr,
        "/account/recover",
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

// ---------------------------------------------------------------------------
// Task 3 (BL1): publishing requires a payment identity and an
// unused pool address; every authorization rule names a served
// route (modulo the dead rules the locked blind_stage1 suite
// pins — see the report).
// ---------------------------------------------------------------------------

fn location_of(r: &HttpResult) -> String {
    for line in r.headers.lines() {
        if line.to_lowercase().starts_with("location:") {
            return line.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
        }
    }
    String::new()
}

/// The session CSRF secret, as embedded in the seller page's forms.
async fn session_csrf(addr: std::net::SocketAddr, session_cookie: &str) -> String {
    let r = http_raw(addr, "GET", "/seller", Some(session_cookie), None, None).await;
    assert_eq!(r.status, 200, "seller page loads for a seller");
    let marker = "name=\"csrf\" value=\"";
    let start = r.body.find(marker).expect("seller page carries csrf fields") + marker.len();
    r.body[start..].split('"').next().unwrap().to_string()
}

async fn listing_status_of(pool: &PgPool, public_id: &str) -> String {
    sqlx::query_scalar::<_, String>("SELECT status FROM listings WHERE public_id = $1")
        .bind(public_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn publish_requires_payment_identity_and_unused_pool() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (seller, _name) = make_account(&pool, "seller", PW).await;
    let r = login_attempt(srv.addr, &_name, PW).await;
    let session = set_cookie_value(&r, "session").expect("seller login succeeds");
    let cookie = format!("session={session}");
    let pub_id = app::listings::create_listing(
        &pool,
        seller,
        "BL1 widget",
        "a widget",
        1_250_000_000_000,
        "general",
        "signed-address-pool",
        false,
    )
    .await
    .unwrap();
    assert_eq!(listing_status_of(&pool, &pub_id).await, "draft");

    // No payment identity, no pool: publishing is refused and the
    // listing stays a draft.
    let csrf = session_csrf(srv.addr, &cookie).await;
    let r = post_form(
        srv.addr,
        &format!("/seller/listings/{pub_id}/status"),
        Some(&cookie),
        &[("csrf", &csrf), ("status", "published")],
    )
    .await;
    assert!(
        location_of(&r).contains("pmsg=payment_setup_required"),
        "publish without payment setup is refused, got location {:?}",
        location_of(&r)
    );
    assert_eq!(listing_status_of(&pool, &pub_id).await, "draft");

    // Identity alone is not enough — an unused pool address is
    // also required.
    sqlx::query(
        "INSERT INTO payment_identities (seller_id, primary_address, network)
         VALUES ($1, $2, 'stagenet')",
    )
    .bind(seller)
    .bind(PRIMARY)
    .execute(&pool)
    .await
    .unwrap();
    let csrf = session_csrf(srv.addr, &cookie).await;
    let r = post_form(
        srv.addr,
        &format!("/seller/listings/{pub_id}/status"),
        Some(&cookie),
        &[("csrf", &csrf), ("status", "published")],
    )
    .await;
    assert!(
        location_of(&r).contains("pmsg=payment_setup_required"),
        "publish with identity but no unused pool address is refused"
    );
    assert_eq!(listing_status_of(&pool, &pub_id).await, "draft");

    // Identity + one unused pool entry: publishing succeeds.
    // (The destination address is unique per run: the destinations
    // table enforces global no-reuse, so a fixed fixture address
    // would collide with this test's own earlier runs.)
    let subaddr = format!("bmbl-sub-{}", uniq());
    let (batch_id,): (i64,) = sqlx::query_as(
        "INSERT INTO payment_batches (seller_id, marketplace_id, network, entry_count)
         VALUES ($1, 'vespiary-market', 'stagenet', 1) RETURNING id",
    )
    .bind(seller)
    .fetch_one(&pool)
    .await
    .unwrap();
    let (dest_id,): (i64,) = sqlx::query_as(
        "INSERT INTO destinations (address, seller_id, source)
         VALUES ($1, $2, 'pool') RETURNING id",
    )
    .bind(&subaddr)
    .bind(seller)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO payment_pool_entries (batch_id, seller_id, destination_id, address, message, signature)
         VALUES ($1, $2, $3, $4, 'msg', 'sig')",
    )
    .bind(batch_id)
    .bind(seller)
    .bind(dest_id)
    .bind(&subaddr)
    .execute(&pool)
    .await
    .unwrap();
    let csrf = session_csrf(srv.addr, &cookie).await;
    let r = post_form(
        srv.addr,
        &format!("/seller/listings/{pub_id}/status"),
        Some(&cookie),
        &[("csrf", &csrf), ("status", "published")],
    )
    .await;
    assert_eq!(location_of(&r), "/seller", "publish succeeds once the seller can be paid");
    assert_eq!(listing_status_of(&pool, &pub_id).await, "published");
    srv.stop();
}

/// The dead rules the LOCKED blind_stage1 suite pins: its expected
/// authorize() table names each of these, so authorize() must keep
/// answering Allow for them even though the router serves no such
/// route. They cannot be removed without amending that locked
/// suite (not authorized — see the batch report). This test pins
/// the set: a NEW dead rule fails here, and if a pinned rule ever
/// gains a route (or the locked suite is amended), the entry must
/// be deliberately removed.
const PINNED_DEAD_RULES: &[(&str, &str)] = &[
    ("GET", "/invoices/{id}"),
    ("GET", "/invoices/{id}/qr.png"),
    ("GET", "/invoices/{id}/statement.txt"),
    ("GET", "/invoices/{id}/statement.txt.asc"),
    ("POST", "/invoices/{id}/signature"),
    ("POST", "/invoices/{id}/evidence/{module}"),
    ("GET", "/pools/{id}/statement.txt"),
    ("GET", "/pools/{id}/statement.txt.asc"),
    ("GET", "/seller/pools"),
    ("POST", "/seller/pools"),
    ("POST", "/seller/pools/{id}/signature"),
    ("GET", "/messages/{id}/download"),
    ("GET", "/security"),
];

#[tokio::test]
async fn every_authz_rule_names_a_served_route() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let mut checked = 0usize;
    let mut seen_dead: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::HashSet<(&str, &str)> = std::collections::HashSet::new();
    for rule in app::authz::ROUTES {
        if !seen.insert((rule.method, rule.path)) {
            continue;
        }
        checked += 1;
        let path = rule
            .path
            .replace("{id}", "x")
            .replace("{module}", "x")
            .replace("{ref}", "x");
        // Anonymous probe: a served route answers with a page, a
        // redirect, a refusal, or a handler 404 WITH a body; a
        // route the router does not serve answers axum's bare 404
        // with an empty body.
        let r = http_raw(
            srv.addr,
            rule.method,
            &path,
            None,
            Some("application/x-www-form-urlencoded"),
            if rule.method == "POST" { Some(b"") } else { None },
        )
        .await;
        let unserved = r.status == 404 && r.body.trim().is_empty();
        if unserved {
            seen_dead.push((rule.method.to_string(), rule.path.to_string()));
        }
    }
    let mut expected_dead: Vec<(String, String)> = PINNED_DEAD_RULES
        .iter()
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .collect();
    seen_dead.sort();
    expected_dead.sort();
    assert_eq!(
        seen_dead, expected_dead,
        "the set of authorization rules naming unserved routes changed \
         ({checked} rules probed): only the blind_stage1-pinned dead \
         rules may be unserved"
    );
    srv.stop();
}

const PRIMARY: &str = "55b6gZhKJ2b6EzvernZJBcPXiZym13w1CfbpDU6sR8aSGpaRbAmU4EMSH3XYXu5U1cSac7B49WRSSBbwQK9by3c7H9AdnFB";

// ---------------------------------------------------------------------------
// Task 5 (BL3): Unicode format characters (category Cf) are
// refused in seller text.
// ---------------------------------------------------------------------------

#[test]
fn format_chars_refused_in_listing_text_and_terms() {
    use app::listings::{validate_listing, validate_listing_terms, ListingError};
    // The brief's two named cases.
    assert_eq!(
        validate_listing("Wi\u{200B}dget", "fine", 1_000_000, "general", "signed-address-pool", false),
        Err(ListingError::Title),
        "a title containing U+200B (zero-width space) is refused"
    );
    assert_eq!(
        validate_listing("Widget", "ships \u{202E}fast", 1_000_000, "general", "signed-address-pool", false),
        Err(ListingError::Description),
        "a description containing U+202E (right-to-left override) is refused"
    );
    // Ordinary non-ASCII text is NOT format characters: accents and
    // combining marks stay allowed.
    assert_eq!(
        validate_listing("Café widget", "Très bien — Cafe\u{301}", 1_000_000, "general", "signed-address-pool", false),
        Ok(())
    );
    // Delivery / refund terms: same rule.
    assert_eq!(validate_listing_terms("ships in 2 days", "no refunds"), Ok(()));
    assert_eq!(
        validate_listing_terms("ships \u{2066}in 2 days", "no refunds"),
        Err(ListingError::Terms)
    );
    assert_eq!(
        validate_listing_terms("ships in 2 days", "refund\u{FEFF} policy"),
        Err(ListingError::Terms)
    );
}

#[test]
fn normalize_form_lines_rejects_all_of_category_cf() {
    use modules_api::{contains_format_chars, normalize_form_lines, FormInputError};
    for (input, name) in [
        ("a\u{202E}b", "U+202E right-to-left override"),
        ("a\u{200B}b", "U+200B zero-width space"),
        ("a\u{2060}b", "U+2060 word joiner"),
        ("a\u{00AD}b", "U+00AD soft hyphen"),
        ("a\u{E0001}b", "U+E0001 language tag"),
        ("a\u{061C}b", "U+061C arabic letter mark"),
        ("a\u{180E}b", "U+180E mongolian vowel separator"),
    ] {
        assert_eq!(
            normalize_form_lines(input),
            Err(FormInputError::InvisibleCharacters),
            "{name} must be rejected"
        );
        assert!(contains_format_chars(input), "{name} is category Cf");
    }
    assert_eq!(
        normalize_form_lines("plain address line"),
        Ok(vec!["plain address line".to_string()])
    );
    assert!(!contains_format_chars("Café — naïve"));
}

#[tokio::test]
async fn review_and_profile_text_refuse_format_chars() {
    let Some(pool) = pool().await else { return };
    let (buyer, _b) = make_account(&pool, "buyer", PW).await;
    let (seller, _s) = make_account(&pool, "seller", PW).await;
    let listing_pub = app::listings::create_listing(
        &pool,
        seller,
        "BL3 review widget",
        "a widget",
        1_000_000,
        "general",
        "signed-address-pool",
        false,
    )
    .await
    .unwrap();
    let (listing_id,): (i64,) =
        sqlx::query_as("SELECT id FROM listings WHERE public_id = $1")
            .bind(&listing_pub)
            .fetch_one(&pool)
            .await
            .unwrap();
    let order_pub = app::db::public_id("ord_");
    sqlx::query(
        "INSERT INTO orders (public_id, buyer_id, seller_id, listing_id, state, settlement,
                             seller_fpr_pinned, terms_bytes, terms_sha256, total_atomic,
                             module_pins, evidence_level, idempotency_key)
         VALUES ($1, $2, $3, $4, 'Completed', 'direct', 'AABBCCDDEEFF00112233445566778899AABBCCDD',
                 'terms'::bytea, 'deadbeef', 1000000, '{}'::jsonb, 'None', $5)",
    )
    .bind(&order_pub)
    .bind(buyer)
    .bind(seller)
    .bind(listing_id)
    .bind(format!("idem-{}", uniq()))
    .execute(&pool)
    .await
    .unwrap();

    let dir = std::env::temp_dir().join(format!("bmbl-kf-{}", uniq()));
    std::fs::create_dir_all(&dir).unwrap();
    let kf = app::keyfile::KeyFile::load_or_generate(&dir.join("k")).unwrap();
    let cfg = app::reputation::Stage9Config::from_env();

    // Review text carrying a direction override is refused and
    // nothing is stored.
    let r = app::reviews::submit_review(
        &pool,
        &kf,
        &cfg,
        &order_pub,
        buyer,
        5,
        "great seller \u{202E}beware",
    )
    .await;
    assert_eq!(r, Err(app::reviews::ReviewError::FormatChars));
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE order_id = (SELECT id FROM orders WHERE public_id = $1)")
        .bind(&order_pub)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "no review stored");

    // A clean review lands; the seller's reply gets the same rule.
    app::reviews::submit_review(&pool, &kf, &cfg, &order_pub, buyer, 5, "great seller")
        .await
        .unwrap();
    let r = app::reviews::seller_reply(&pool, &cfg, &order_pub, seller, "thanks \u{200B}buyer").await;
    assert_eq!(r, Err(app::reviews::ReviewError::FormatChars));

    // Profile text over HTTP: refused, and the stored text is
    // unchanged; clean text is accepted.
    let srv = test_server(&pool).await;
    let (_bid, bname) = make_account(&pool, "buyer", PW).await;
    let lr = login_attempt(srv.addr, &bname, PW).await;
    let session = set_cookie_value(&lr, "session").expect("login succeeds");
    let cookie = format!("session={session}");
    let page = http_raw(srv.addr, "GET", "/account/security", Some(&cookie), None, None).await;
    assert_eq!(page.status, 200);
    let marker = "name=\"csrf\" value=\"";
    let start = page.body.find(marker).expect("security page carries csrf") + marker.len();
    let csrf = page.body[start..].split('"').next().unwrap().to_string();
    let r = post_form(
        srv.addr,
        "/account/profile",
        Some(&cookie),
        &[("csrf", &csrf), ("profile_text", "hello \u{202E} world")],
    )
    .await;
    assert_eq!(r.status, 400, "profile text with U+202E is refused");
    let stored: Option<String> =
        sqlx::query_scalar("SELECT profile_text FROM accounts WHERE id = $1")
            .bind(_bid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(stored.as_deref().unwrap_or("").is_empty(), "refused text was not stored");
    let r = post_form(
        srv.addr,
        "/account/profile",
        Some(&cookie),
        &[("csrf", &csrf), ("profile_text", "hello world")],
    )
    .await;
    assert_eq!(r.status, 303, "clean profile text is accepted (redirect)");
    assert_eq!(location_of(&r), "/account/security");
    srv.stop();
}

// ---------------------------------------------------------------------------
// Task 2 (BM2): a busy hashing pool must not burn a recovery code.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn busy_pool_recovery_attempt_leaves_the_code_valid() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (id, username) = make_account(&pool, "buyer", PW).await;
    let code = "BM2TK-AAAAA-BBBBB-CCCCC";
    app::db::store_recovery_code(&pool, id, code).await.unwrap();
    let stored: String = sqlx::query_scalar("SELECT password_hash FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // Fill the shared hashing pool: four verifies held in flight.
    let before = srv.hash_guard.hash_op_count();
    let mut holds = Vec::new();
    for _ in 0..4 {
        let g = srv.hash_guard.clone();
        let s = stored.clone();
        holds.push(tokio::spawn(async move { g.verify(PW, &s).await }));
    }
    for _ in 0..200 {
        if srv.hash_guard.hash_op_count() >= before + 4 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        srv.hash_guard.hash_op_count() >= before + 4,
        "all four verifies are hashing"
    );

    // The recovery attempt cannot hash, so it is refused Busy —
    // and, the BM2 point, the code is NOT spent: on the pre-fix
    // order (consume first, hash second) this same attempt burned
    // the code and the retry below answered "Recovery failed."
    let r = recover_attempt(srv.addr, &username, code, "bmbl-recovered-passphrase-1").await;
    assert_eq!(r.status, 503, "recovery with a full pool answers Busy");

    for h in holds {
        let _ = h.await.unwrap();
    }

    // Once the pool frees, the SAME code works.
    let r = recover_attempt(srv.addr, &username, code, "bmbl-recovered-passphrase-1").await;
    assert_eq!(r.status, 200, "the same code recovers once the pool frees");
    assert!(
        r.body.contains("Passphrase reset"),
        "recovery completes: {}",
        &r.body[..r.body.len().min(200)]
    );

    // And the new passphrase is live.
    let r = login_attempt(srv.addr, &username, "bmbl-recovered-passphrase-1").await;
    assert!(
        set_cookie_value(&r, "session").is_some(),
        "login with the recovered passphrase succeeds"
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
