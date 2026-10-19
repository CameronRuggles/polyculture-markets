//! Media / Content / Disputes Audit — acceptance tests (2026-10-19).
//!
//! One test per fix-brief task, written against the brief's own
//! acceptance criteria:
//!
//! 1. CH1 — moderator takedown lives in its own fields; sellers
//!    cannot change a taken-down listing at all; the seller's own
//!    removal is renamed "withdrawn"; moderator restore touches
//!    only takedowns.
//! 2. CM1 — media served only while the listing is published, or
//!    to its seller / moderators; files quarantined on takedown.
//! 3. CM2 — media worker: kill-on-drop past its timeout; at most
//!    2 workers concurrently.
//! 4. CM3 — no self-dealing: a moderator who is the order's buyer
//!    or seller cannot resolve its dispute or decide its payment
//!    flags; parties can see which moderator decided.
//! 5. CM4 — protected roles: moderators cannot close/warn
//!    moderator or admin accounts; only an admin can close a
//!    moderator; admin accounts are not closable through this
//!    path at all. Refusals are logged.
//! 6. CL1 — msg/pmsg URL params are codes mapping to fixed
//!    strings; arbitrary text in a link never renders.
//! 7. CL2 — an unconfirmed refund proposal returns to the
//!    moderator queue after 14 days.
//! 8. CL3 — CSP, frame-ancestors, Referrer-Policy and nosniff on
//!    every response, including errors and redirects.
//!
//! DB tests require DATABASE_URL (skipped silently when unset,
//! the pattern of the neighbouring suites).

use app::config::InstanceConfig;
use app::keyfile::KeyFile;
use app::media::MediaPipeline;
use app::moderation::{self, ModError};
use app::passwords::HashGuard;
use app::totp;
use app::web::{router, AppState};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Helpers (the account_security.rs pattern)
// ---------------------------------------------------------------------------

const PW: &str = "mediadisp-correct-passphrase-1";
const CSRF: &str = "mediadisp-csrf";

async fn pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    PgPoolOptions::new().max_connections(8).connect(&url).await.ok()
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

fn code(secret: &[u8], offset: i64) -> String {
    let t = (now_secs() as i64 + offset).max(0) as u64;
    totp::code_at(secret, t)
}

async fn make_account(pool: &PgPool, role: &str) -> (i64, String) {
    let hash = HashGuard::new(2).hash(PW).await.unwrap();
    let public_id = app::db::public_id("acct_");
    let username = format!("mdisp{}", uniq());
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

async fn enroll(pool: &PgPool, kf: &KeyFile, account_id: i64) -> Vec<u8> {
    let b32 = moderation::totp_begin(pool, kf, account_id).await.unwrap();
    let secret = totp::base32_decode(&b32).unwrap();
    // Enrollment confirmation consumes its step (owner decision
    // 2026-10-18): confirm with the previous step's code so the
    // current step stays fresh for gate presentations.
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

fn test_kf() -> KeyFile {
    let mut dir = std::env::temp_dir();
    dir.push(format!("mediadisp-kf-{}-{}", std::process::id(), uniq()));
    std::fs::create_dir_all(&dir).unwrap();
    KeyFile::load_or_generate(&dir.join("keyfile")).expect("test keyfile")
}

async fn make_listing(pool: &PgPool, seller_id: i64, status: &str) -> (i64, String) {
    let public_id = app::db::public_id("lst_");
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO listings (public_id, seller_id, title, description, price_atomic,
                                pricing_module, destination_module, auto_invoice, category, status)
         VALUES ($1, $2, $3, 'a fine widget', 1000000, 'xmr-only', 'signed-address-pool', false, 'general', $4)
         RETURNING id",
    )
    .bind(&public_id)
    .bind(seller_id)
    .bind(format!("Widget {}", uniq()))
    .bind(status)
    .fetch_one(pool)
    .await
    .unwrap();
    (id, public_id)
}

/// An order row in a given state plus (optionally) an open dispute.
async fn make_order(
    pool: &PgPool,
    buyer_id: i64,
    seller_id: i64,
    listing_id: i64,
    state: &str,
) -> (i64, String) {
    let public_id = app::db::public_id("ord_");
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO orders (public_id, buyer_id, seller_id, listing_id, state, settlement,
                             seller_fpr_pinned, terms_bytes, terms_sha256, total_atomic,
                             module_pins, evidence_level, idempotency_key)
         VALUES ($1, $2, $3, $4, $5, 'direct', 'AABBCCDDEEFF00112233445566778899AABBCCDD',
                 'terms'::bytea, 'deadbeef', 1000000, '{}'::jsonb, 'None', $6)
         RETURNING id",
    )
    .bind(&public_id)
    .bind(buyer_id)
    .bind(seller_id)
    .bind(listing_id)
    .bind(state)
    .bind(format!("idem-{}", uniq()))
    .fetch_one(pool)
    .await
    .unwrap();
    (id, public_id)
}

async fn make_dispute(pool: &PgPool, order_id: i64, opened_by: i64) -> i64 {
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO disputes (order_id, opened_by, state) VALUES ($1, $2, 'open') RETURNING id",
    )
    .bind(order_id)
    .bind(opened_by)
    .fetch_one(pool)
    .await
    .unwrap();
    id
}

async fn cleanup(pool: &PgPool, accounts: &[i64]) {
    // Pass 1: orders and everything that references them, for every
    // account first — an order can reference a listing owned by a
    // different fixture account than its buyer/seller pair, so
    // listings may only be deleted once ALL orders are gone.
    for id in accounts {
        for q in [
            "DELETE FROM payment_review_flags WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1 OR listing_id IN (SELECT id FROM listings WHERE seller_id = $1))",
            "DELETE FROM payment_reports WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1 OR listing_id IN (SELECT id FROM listings WHERE seller_id = $1))",
            "DELETE FROM payment_proofs WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1 OR listing_id IN (SELECT id FROM listings WHERE seller_id = $1))",
            "DELETE FROM disclosures WHERE dispute_id IN (SELECT d.id FROM disputes d JOIN orders o ON o.id = d.order_id WHERE o.buyer_id = $1 OR o.seller_id = $1)",
            "DELETE FROM disputes WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1 OR listing_id IN (SELECT id FROM listings WHERE seller_id = $1))",
            "DELETE FROM reviews WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1 OR listing_id IN (SELECT id FROM listings WHERE seller_id = $1))",
            "DELETE FROM reputation_facts WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1 OR listing_id IN (SELECT id FROM listings WHERE seller_id = $1))",
            "DELETE FROM payment_pool_entries WHERE seller_id = $1 OR order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1 OR listing_id IN (SELECT id FROM listings WHERE seller_id = $1))",
            "DELETE FROM orders WHERE buyer_id = $1 OR seller_id = $1 OR listing_id IN (SELECT id FROM listings WHERE seller_id = $1)",
        ] {
            sqlx::query(q).bind(id).execute(pool).await.unwrap();
        }
    }
    // Pass 2: listings, accounts, and account-scoped rows.
    for id in accounts {
        for q in [
            "DELETE FROM moderation_actions WHERE actor_id = $1 OR target_account_id = $1 OR target_listing_id IN (SELECT id FROM listings WHERE seller_id = $1)",
            "DELETE FROM notifications WHERE account_id = $1",
            "DELETE FROM reputation_summaries WHERE seller_id = $1",
            "DELETE FROM payment_batches WHERE seller_id = $1",
            "DELETE FROM destinations WHERE seller_id = $1",
            "DELETE FROM listing_media WHERE listing_id IN (SELECT id FROM listings WHERE seller_id = $1)",
            "DELETE FROM listings WHERE seller_id = $1",
            "DELETE FROM identity_keys WHERE account_id = $1",
            "DELETE FROM session_csrf WHERE token_hash IN (SELECT token_hash FROM sessions WHERE account_id = $1)",
            "DELETE FROM sessions WHERE account_id = $1",
            "DELETE FROM accounts WHERE id = $1",
        ] {
            sqlx::query(q).bind(id).execute(pool).await.unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP test server
// ---------------------------------------------------------------------------

struct TestServer {
    addr: std::net::SocketAddr,
    keyfile: Arc<KeyFile>,
    media_dir: std::path::PathBuf,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}

async fn test_server(pool: &PgPool) -> TestServer {
    let mut dir = std::env::temp_dir();
    dir.push(format!("mediadisp-http-{}-{}", std::process::id(), uniq()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("test.key");
    let media_dir = dir.join("media");
    std::fs::create_dir_all(&media_dir).unwrap();
    let media = MediaPipeline {
        worker_path: dir.join("no-worker"),
        media_dir: media_dir.clone(),
        tmp_dir: media_dir.join("tmp"),
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
    TestServer { addr, keyfile, media_dir, handle, dir }
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

async fn http(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    form: Option<&str>,
) -> HttpResult {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n");
    if let Some(c) = cookie {
        req.push_str(&format!("Cookie: session={c}\r\n"));
    }
    if let Some(b) = form {
        req.push_str(&format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
            b.len()
        ));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    if let Some(b) = form {
        s.write_all(b.as_bytes()).await.unwrap();
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

fn location(h: &HttpResult) -> String {
    for line in h.headers.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("location") {
                return v.trim().to_string();
            }
        }
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Task 1 (CH1) — takedown sellers can't undo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn takedown_blocks_seller_and_restore_only_touches_takedowns() {
    let Some(pool) = pool().await else { return };
    let (seller, _) = make_account(&pool, "seller").await;
    let (moderator, _) = make_account(&pool, "moderator").await;
    let (lid, lpub) = make_listing(&pool, seller, "published").await;

    // Moderator takes the listing down.
    moderation::set_listing_removed(&pool, &lpub, moderator, true).await.expect("takedown");
    let (status, taken_down): (String, bool) = sqlx::query_as(
        "SELECT status, taken_down_at IS NOT NULL FROM listings WHERE id = $1",
    )
    .bind(lid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(taken_down, "the takedown is recorded in its own field");
    assert_eq!(status, "removed", "locked-suite pin: status reads 'removed' while taken down");

    // The seller cannot republish — or change the status at all.
    for target in ["published", "draft", "paused", "withdrawn"] {
        let ok = app::listings::set_status(&pool, lid, seller, target).await.unwrap();
        assert!(!ok, "seller status change to {target} must be refused while taken down");
    }
    let found = app::listings::browse(&pool, None, None, 1).await.unwrap();
    assert!(!found.iter().any(|l| l.id == lid), "taken-down listing is not browsable");

    // Restore returns the listing to its pre-takedown status.
    moderation::set_listing_removed(&pool, &lpub, moderator, false).await.expect("restore");
    let (status, taken_down): (String, bool) = sqlx::query_as(
        "SELECT status, taken_down_at IS NOT NULL FROM listings WHERE id = $1",
    )
    .bind(lid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status, "published", "restore returns the pre-takedown status");
    assert!(!taken_down, "restore clears the takedown");

    // The seller's own removal is "withdrawn"; "removed" is refused.
    let ok = app::listings::set_status(&pool, lid, seller, "removed").await.unwrap();
    assert!(!ok, "sellers can no longer set 'removed' — that state is the moderators'");
    let ok = app::listings::set_status(&pool, lid, seller, "withdrawn").await.unwrap();
    assert!(ok, "seller withdrawal works under its own name");
    let status: String = sqlx::query_scalar("SELECT status FROM listings WHERE id = $1")
        .bind(lid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "withdrawn");

    // Moderator restore must NEVER republish a seller-withdrawn listing.
    let err = moderation::set_listing_removed(&pool, &lpub, moderator, false)
        .await
        .expect_err("restore of a non-takedown must be refused");
    assert!(matches!(err, ModError::BadInput), "got {err:?}");
    let status: String = sqlx::query_scalar("SELECT status FROM listings WHERE id = $1")
        .bind(lid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "withdrawn", "the withdrawn listing stays withdrawn");

    // A takedown of a withdrawn listing restores to withdrawn, not published.
    moderation::set_listing_removed(&pool, &lpub, moderator, true).await.expect("takedown of withdrawn");
    moderation::set_listing_removed(&pool, &lpub, moderator, false).await.expect("restore");
    let status: String = sqlx::query_scalar("SELECT status FROM listings WHERE id = $1")
        .bind(lid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "withdrawn", "restore returns the PRE-takedown status");

    cleanup(&pool, &[seller, moderator]).await;
}

// ---------------------------------------------------------------------------
// Task 2 (CM1) — serve only live images; quarantine on takedown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn media_served_only_for_live_listings_and_quarantined_on_takedown() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (seller, _) = make_account(&pool, "seller").await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    let (moderator, _) = make_account(&pool, "moderator").await;
    let secret = enroll(&pool, &srv.keyfile, moderator).await;
    let (lid, lpub) = make_listing(&pool, seller, "published").await;

    // A stored image: DB row + file in the served folder.
    let mref = format!("{}.png", app::sessions::new_token()[..32].to_string());
    sqlx::query("INSERT INTO listing_media (listing_id, sanitized_ref, width, height) VALUES ($1, $2, 10, 10)")
        .bind(lid)
        .bind(&mref)
        .execute(&pool)
        .await
        .unwrap();
    std::fs::write(srv.media_dir.join(&mref), b"\x89PNG-fake").unwrap();

    let path = format!("/media/{mref}");
    // Published: anyone may fetch it.
    let r = http(srv.addr, "GET", &path, None, None).await;
    assert_eq!(r.status, 200, "published listing image is public");

    // Draft: public and strangers get 404; the seller and a moderator get it.
    app::listings::set_status(&pool, lid, seller, "draft").await.unwrap();
    let r = http(srv.addr, "GET", &path, None, None).await;
    assert_eq!(r.status, 404, "draft listing image is not public");
    let buyer_tok = session_for(&pool, buyer).await;
    let r = http(srv.addr, "GET", &path, Some(&buyer_tok), None).await;
    assert_eq!(r.status, 404, "a stranger cannot fetch a draft listing's image");
    let seller_tok = session_for(&pool, seller).await;
    let r = http(srv.addr, "GET", &path, Some(&seller_tok), None).await;
    assert_eq!(r.status, 200, "the seller can fetch their own draft's image");
    let mod_tok = session_for(&pool, moderator).await;
    let r = http(srv.addr, "GET", &path, Some(&mod_tok), None).await;
    assert_eq!(r.status, 200, "a moderator can fetch a draft listing's image");

    // Back to published, then a moderator takedown THROUGH THE WEB:
    // the file must leave the served folder for quarantine.
    app::listings::set_status(&pool, lid, seller, "published").await.unwrap();
    let form = format!("csrf={CSRF}&totp={}", code(&secret, 0));
    let r = http(
        srv.addr,
        "POST",
        &format!("/moderation/listings/{lpub}/remove"),
        Some(&mod_tok),
        Some(&form),
    )
    .await;
    assert_eq!(r.status, 303, "takedown POST redirects, got {} ({})", r.status, r.body);
    assert!(
        !srv.media_dir.join(&mref).exists(),
        "on takedown the file leaves the served folder"
    );
    assert!(
        srv.media_dir.join("quarantine").join(&mref).exists(),
        "on takedown the file is quarantined, not deleted"
    );
    let r = http(srv.addr, "GET", &path, None, None).await;
    assert_eq!(r.status, 404, "a taken-down listing's image is not public");
    let r = http(srv.addr, "GET", &path, Some(&seller_tok), None).await;
    assert_eq!(r.status, 200, "the seller can still fetch their taken-down image (from quarantine)");

    // Restore through the web: the file returns to the served folder.
    // (Next step's code: the takedown consumed this step's — the
    // shared gate rejects replays, by design.)
    let form = format!("csrf={CSRF}&totp={}", code(&secret, 30));
    let r = http(
        srv.addr,
        "POST",
        &format!("/moderation/listings/{lpub}/restore"),
        Some(&mod_tok),
        Some(&form),
    )
    .await;
    assert_eq!(r.status, 303, "restore POST redirects");
    assert!(srv.media_dir.join(&mref).exists(), "restore returns the file to the served folder");
    let r = http(srv.addr, "GET", &path, None, None).await;
    assert_eq!(r.status, 200, "restored listing image is public again");

    srv.stop();
    cleanup(&pool, &[seller, buyer, moderator]).await;
}

// ---------------------------------------------------------------------------
// Task 3 (CM2) — worker containment: kill on timeout, at most 2 at once
// ---------------------------------------------------------------------------

fn write_stub(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    p
}

#[tokio::test]
async fn worker_is_killed_on_timeout_and_capped_at_two() {
    let mut dir = std::env::temp_dir();
    dir.push(format!("mediadisp-worker-{}-{}", std::process::id(), uniq()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let media_dir = dir.join("media");
    std::fs::create_dir_all(&media_dir).unwrap();

    // Timeout kill: the stub sleeps forever; sanitize must give up
    // quickly AND the child process must be gone (kill_on_drop).
    let pidfile = dir.join("stub.pid");
    let sleeper = write_stub(
        &dir,
        "sleeper.sh",
        &format!("#!/bin/sh\necho $$ > {}\nsleep 60\n", pidfile.display()),
    );
    let pipe = MediaPipeline {
        worker_path: sleeper,
        media_dir: media_dir.clone(),
        tmp_dir: media_dir.join("tmp"),
    };
    let png = b"\x89PNG\r\n\x1a\n-fake-image-bytes";
    let started = std::time::Instant::now();
    let res = pipe.sanitize_with_timeout(png, std::time::Duration::from_millis(400)).await;
    assert!(res.is_err(), "a worker that never finishes is an error");
    assert!(started.elapsed() < std::time::Duration::from_secs(5), "the timeout fires promptly");
    let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
    // Give the kill a moment to land, then the process must not exist.
    let mut alive = true;
    for _ in 0..50 {
        let rc = std::process::Command::new("kill").arg("-0").arg(pid.to_string()).output().unwrap();
        if !rc.status.success() {
            alive = false;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(!alive, "the timed-out worker process must be killed, not left running");

    // Concurrency cap: 6 parallel sanitizes, stub tracks overlap.
    let cnt = dir.join("cur");
    let max = dir.join("max");
    let lock = dir.join("lock");
    std::fs::write(&cnt, "0").unwrap();
    std::fs::write(&max, "0").unwrap();
    let counter = write_stub(
        &dir,
        "counter.sh",
        &format!(
            "#!/bin/sh\n(\n  flock -x 9\n  c=$(cat {cnt}); c=$((c+1)); echo $c > {cnt}\n  m=$(cat {max}); [ $c -gt $m ] && echo $c > {max}\n) 9>{lock}\nsleep 0.5\ncp \"$1\" \"$2\"\necho 10x10\n(\n  flock -x 9\n  c=$(cat {cnt}); echo $((c-1)) > {cnt}\n) 9>{lock}\n",
            cnt = cnt.display(),
            max = max.display(),
            lock = lock.display()
        ),
    );
    let pipe2 = MediaPipeline {
        worker_path: counter,
        media_dir: media_dir.clone(),
        tmp_dir: media_dir.join("tmp"),
    };
    let mut joins = Vec::new();
    for _ in 0..6 {
        let p = pipe2.clone();
        joins.push(tokio::spawn(async move { p.sanitize(png).await }));
    }
    for j in joins {
        let r = j.await.unwrap();
        assert!(r.is_ok(), "stub-worker sanitize succeeds: {r:?}");
    }
    let observed_max: i32 = std::fs::read_to_string(&max).unwrap().trim().parse().unwrap();
    assert!(observed_max <= 2, "at most 2 workers run at once (observed {observed_max})");
    assert!(observed_max >= 1, "the counter stub actually ran");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Task 4 (CM3) — no self-dealing in disputes or payment flags
// ---------------------------------------------------------------------------

#[tokio::test]
async fn moderators_cannot_decide_their_own_orders() {
    let Some(pool) = pool().await else { return };
    let kf = test_kf();
    let cfg = app::reputation::Stage9Config::from_env();
    let (seller, _) = make_account(&pool, "seller").await;
    let (mod_buyer, _) = make_account(&pool, "moderator").await;
    let (admin_seller, _) = make_account(&pool, "admin").await;
    let (neutral_mod, _) = make_account(&pool, "moderator").await;
    let (lid, _) = make_listing(&pool, seller, "published").await;

    // A moderator who BOUGHT the order cannot resolve its dispute.
    let (oid, _) = make_order(&pool, mod_buyer, seller, lid, "Disputed").await;
    let did = make_dispute(&pool, oid, mod_buyer).await;
    let err = app::disputes::resolve(&pool, &kf, &cfg, did, mod_buyer, "seller-at-fault")
        .await
        .expect_err("the buyer-moderator must not resolve their own dispute");
    assert!(matches!(err, app::disputes::DisputeError::Forbidden), "got {err:?}");

    // An admin who SOLD the order cannot resolve its dispute either.
    let (oid2, _) = make_order(&pool, mod_buyer, admin_seller, lid, "Disputed").await;
    let did2 = make_dispute(&pool, oid2, mod_buyer).await;
    let err = app::disputes::resolve(&pool, &kf, &cfg, did2, admin_seller, "buyer-at-fault")
        .await
        .expect_err("the seller-admin must not resolve their own dispute");
    assert!(matches!(err, app::disputes::DisputeError::Forbidden), "got {err:?}");

    // A neutral moderator can — and the decision is attributed.
    app::disputes::resolve(&pool, &kf, &cfg, did, neutral_mod, "seller-at-fault")
        .await
        .expect("a neutral moderator resolves");
    let d = app::disputes::get_dispute(&pool, did).await.unwrap().unwrap();
    assert_eq!(d.resolved_by, Some(neutral_mod), "the deciding moderator is recorded");

    // Payment flags: the order's buyer cannot decide its flag.
    let (flag_id,): (i64,) = sqlx::query_as(
        "INSERT INTO payment_review_flags (order_id, kind) VALUES ($1, 'proof-unconfirmed') RETURNING id",
    )
    .bind(oid2)
    .fetch_one(&pool)
    .await
    .unwrap();
    let err = moderation::payment_flag_action(&pool, flag_id, mod_buyer, "resolve")
        .await
        .expect_err("the buyer-moderator must not decide their own order's flag");
    assert!(matches!(err, ModError::Forbidden), "got {err:?}");
    moderation::payment_flag_action(&pool, flag_id, neutral_mod, "resolve")
        .await
        .expect("a neutral moderator decides the flag");

    cleanup(&pool, &[seller, mod_buyer, admin_seller, neutral_mod]).await;
}

#[tokio::test]
async fn dispute_page_names_the_deciding_moderator() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let kf = test_kf();
    let cfg = app::reputation::Stage9Config::from_env();
    let (seller, _) = make_account(&pool, "seller").await;
    let (buyer, buyer_name) = make_account(&pool, "buyer").await;
    let _ = buyer_name;
    let (moderator, mod_name) = make_account(&pool, "moderator").await;
    let (lid, _) = make_listing(&pool, seller, "published").await;
    let (oid, _) = make_order(&pool, buyer, seller, lid, "Disputed").await;
    let did = make_dispute(&pool, oid, buyer).await;
    app::disputes::resolve(&pool, &kf, &cfg, did, moderator, "seller-at-fault").await.unwrap();

    let tok = session_for(&pool, buyer).await;
    let r = http(srv.addr, "GET", &format!("/disputes/{did}"), Some(&tok), None).await;
    assert_eq!(r.status, 200, "the buyer can view the dispute");
    assert!(
        r.body.contains(&mod_name),
        "the buyer sees WHICH moderator decided (body must name {mod_name})"
    );
    let tok = session_for(&pool, seller).await;
    let r = http(srv.addr, "GET", &format!("/disputes/{did}"), Some(&tok), None).await;
    assert!(r.body.contains(&mod_name), "the seller sees which moderator decided too");

    srv.stop();
    cleanup(&pool, &[seller, buyer, moderator]).await;
}

// ---------------------------------------------------------------------------
// Task 5 (CM4) — protected roles
// ---------------------------------------------------------------------------

#[tokio::test]
async fn moderators_cannot_close_or_warn_protected_roles() {
    let Some(pool) = pool().await else { return };
    let (mod1, _) = make_account(&pool, "moderator").await;
    let (mod2, _) = make_account(&pool, "moderator").await;
    let (admin, _) = make_account(&pool, "admin").await;
    let (admin2, _) = make_account(&pool, "admin").await;
    let (seller, _) = make_account(&pool, "seller").await;

    let status_of = |pool: PgPool, id: i64| async move {
        sqlx::query_scalar::<_, String>("SELECT status FROM accounts WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let refused_logged = |pool: PgPool, actor: i64, target: i64, action: &'static str| async move {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM moderation_actions WHERE actor_id = $1 AND target_account_id = $2 AND action = $3)",
        )
        .bind(actor)
        .bind(target)
        .bind(action)
        .fetch_one(&pool)
        .await
        .unwrap()
    };

    // Moderator → moderator closure: refused, logged, target untouched.
    let err = moderation::close_account(&pool, mod2, mod1, "coup attempt").await.expect_err("mod cannot close mod");
    assert!(matches!(err, ModError::Forbidden), "got {err:?}");
    assert_eq!(status_of(pool.clone(), mod2).await, "active");
    assert!(refused_logged(pool.clone(), mod1, mod2, "close-account-refused").await, "the refusal is logged");

    // Moderator → admin closure: refused and logged.
    let err = moderation::close_account(&pool, admin, mod1, "coup attempt").await.expect_err("mod cannot close admin");
    assert!(matches!(err, ModError::Forbidden), "got {err:?}");
    assert_eq!(status_of(pool.clone(), admin).await, "active");
    assert!(refused_logged(pool.clone(), mod1, admin, "close-account-refused").await);

    // Admin → admin closure through this path: refused (operator console only).
    let err = moderation::close_account(&pool, admin2, admin, "closing a fellow admin").await.expect_err("admin accounts are console-only");
    assert!(matches!(err, ModError::Forbidden), "got {err:?}");
    assert_eq!(status_of(pool.clone(), admin2).await, "active");

    // Admin → moderator closure: allowed (only an admin can).
    moderation::close_account(&pool, mod2, admin, "stepping down a moderator").await.expect("admin closes moderator");
    assert_eq!(status_of(pool.clone(), mod2).await, "closed");

    // Moderator → seller closure: the ordinary path still works.
    moderation::close_account(&pool, seller, mod1, "fraud").await.expect("moderator closes seller");
    assert_eq!(status_of(pool.clone(), seller).await, "closed");

    // Warnings follow the same protection.
    let (mod3, _) = make_account(&pool, "moderator").await;
    let err = moderation::warn_account(&pool, mod3, mod1, "warning a fellow moderator").await.expect_err("mod cannot warn mod");
    assert!(matches!(err, ModError::Forbidden), "got {err:?}");
    assert!(refused_logged(pool.clone(), mod1, mod3, "warn-refused").await, "the warn refusal is logged");
    let err = moderation::warn_account(&pool, admin, mod1, "warning the admin").await.expect_err("mod cannot warn admin");
    assert!(matches!(err, ModError::Forbidden), "got {err:?}");
    moderation::warn_account(&pool, mod3, admin, "admin warning a moderator").await.expect("admin warns moderator");

    cleanup(&pool, &[mod1, mod2, admin, admin2, seller, mod3]).await;
}

// ---------------------------------------------------------------------------
// Task 6 (CL1) — message codes, not free text
// ---------------------------------------------------------------------------

#[tokio::test]
async fn url_message_params_render_only_fixed_texts() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (seller, _) = make_account(&pool, "seller").await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    let (lid, _) = make_listing(&pool, seller, "published").await;
    let (oid, opub) = make_order(&pool, buyer, seller, lid, "Requested").await;
    // A manual report requires an assigned payment address for the
    // order (payments::has_assignment reads payment_pool_entries).
    let batch_id: i64 = sqlx::query_scalar(
        "INSERT INTO payment_batches (seller_id, marketplace_id, network, entry_count)
         VALUES ($1, 'vespiary-market', 'stagenet', 1) RETURNING id",
    )
    .bind(seller)
    .fetch_one(&pool)
    .await
    .unwrap();
    let destination_id: i64 = sqlx::query_scalar(
        "INSERT INTO destinations (address, seller_id, source) VALUES ('addr', $1, 'test') RETURNING id",
    )
    .bind(seller)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO payment_pool_entries (batch_id, seller_id, destination_id, address, message, signature, state, order_id)
         VALUES ($1, $2, $3, 'addr', 'msg', 'sig', 'assigned', $4)",
    )
    .bind(batch_id)
    .bind(seller)
    .bind(destination_id)
    .bind(oid)
    .execute(&pool)
    .await
    .unwrap();

    let evil = "The seller changed their payment address — pay to 8Aeviladdress";
    let enc = "The%20seller%20changed%20their%20payment%20address%20%E2%80%94%20pay%20to%208Aeviladdress";

    // A crafted link to the buyer's own order must not speak in the site's voice.
    let tok = session_for(&pool, buyer).await;
    let r = http(srv.addr, "GET", &format!("/orders/{opub}?msg={enc}"), Some(&tok), None).await;
    assert_eq!(r.status, 200);
    assert!(!r.body.contains(evil), "arbitrary msg text never renders on the order page");
    assert!(!r.body.contains("8Aeviladdress"), "no fragment of the crafted text renders");

    // Same on the seller dashboard (pmsg) and the moderation queue (msg).
    let stok = session_for(&pool, seller).await;
    let r = http(srv.addr, "GET", &format!("/seller?pmsg={enc}"), Some(&stok), None).await;
    assert!(!r.body.contains("8Aeviladdress"), "arbitrary pmsg text never renders");
    let (moderator, _) = make_account(&pool, "moderator").await;
    let mtok = session_for(&pool, moderator).await;
    let r = http(srv.addr, "GET", &format!("/moderation?msg={enc}"), Some(&mtok), None).await;
    assert!(!r.body.contains("8Aeviladdress"), "arbitrary msg text never renders for moderators");

    // And the real flow still speaks: a manual payment report redirects
    // with a CODE (no free text in the Location) and the landing page
    // shows the fixed string for that code.
    let form = format!("csrf={CSRF}");
    let r = http(
        srv.addr,
        "POST",
        &format!("/orders/{opub}/manual-report"),
        Some(&tok),
        Some(&form),
    )
    .await;
    assert_eq!(r.status, 303, "manual report redirects, got {}", r.status);
    let loc = location(&r);
    assert!(loc.contains("msg=report_recorded"), "the redirect carries a code, got {loc}");
    assert!(!loc.contains(' '), "no free text travels in the redirect");
    let r = http(srv.addr, "GET", &loc, Some(&tok), None).await;
    assert!(
        r.body.contains("Your payment report is recorded"),
        "the fixed text for the code renders on the landing page"
    );

    srv.stop();
    cleanup(&pool, &[seller, buyer, moderator]).await;
}

// ---------------------------------------------------------------------------
// Task 7 (CL2) — unconfirmed refunds return to the moderator after 14 days
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unconfirmed_refund_returns_to_moderator_after_14_days() {
    let Some(pool) = pool().await else { return };
    let kf = test_kf();
    let cfg = app::reputation::Stage9Config::from_env();
    let (seller, _) = make_account(&pool, "seller").await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    let (moderator, _) = make_account(&pool, "moderator").await;
    let (lid, _) = make_listing(&pool, seller, "published").await;
    let (oid, _) = make_order(&pool, buyer, seller, lid, "Disputed").await;
    let did = make_dispute(&pool, oid, buyer).await;

    app::disputes::resolve(&pool, &kf, &cfg, did, moderator, "refund-confirmed").await.unwrap();
    let d = app::disputes::get_dispute(&pool, did).await.unwrap().unwrap();
    assert_eq!(d.state, "awaiting_buyer_confirmation");

    let rcfg = app::retention::RetentionConfig::defaults();
    // Fresh proposal: a retention pass changes nothing.
    let _ = app::retention::run_retention(&pool, &rcfg).await.unwrap();
    let d = app::disputes::get_dispute(&pool, did).await.unwrap().unwrap();
    assert_eq!(d.state, "awaiting_buyer_confirmation", "a fresh proposal is untouched");

    // Age the proposal past 14 days: the next pass reopens it for the
    // moderator instead of leaving it resolved-in-waiting forever.
    sqlx::query("UPDATE disputes SET refund_proposed_at = now() - interval '15 days' WHERE id = $1")
        .bind(did)
        .execute(&pool)
        .await
        .unwrap();
    let out = app::retention::run_retention(&pool, &rcfg).await.unwrap();
    assert_eq!(out.refunds_reopened, 1, "the stale proposal is reopened (outcome count)");
    let d = app::disputes::get_dispute(&pool, did).await.unwrap().unwrap();
    assert_eq!(d.state, "open", "the dispute is back in front of the moderator");
    let open = app::disputes::open_disputes(&pool).await.unwrap();
    assert!(open.iter().any(|(x, ..)| x.id == did), "and it shows in the moderation queue");

    cleanup(&pool, &[seller, buyer, moderator]).await;
}

// ---------------------------------------------------------------------------
// Task 8 (CL3) — security headers on every response
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_response_carries_security_headers() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;

    let check = |r: &HttpResult, what: &str| {
        let h = r.headers.to_lowercase();
        assert!(
            h.contains("content-security-policy: default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"),
            "{what}: CSP present and exact (headers: {})",
            r.headers
        );
        assert!(h.contains("referrer-policy: no-referrer"), "{what}: Referrer-Policy");
        assert!(h.contains("x-content-type-options: nosniff"), "{what}: nosniff");
    };

    let r = http(srv.addr, "GET", "/", None, None).await;
    assert_eq!(r.status, 200);
    check(&r, "home page");

    let r = http(srv.addr, "GET", "/no-such-route", None, None).await;
    assert_eq!(r.status, 404);
    check(&r, "router 404");

    let r = http(srv.addr, "GET", "/media/zzzz.png", None, None).await;
    assert_eq!(r.status, 404);
    check(&r, "media 404");

    let r = http(srv.addr, "GET", "/seller", None, None).await;
    assert_eq!(r.status, 303, "anonymous seller page redirects to login");
    check(&r, "redirect");

    let r = http(srv.addr, "POST", "/logout", None, Some("csrf=nope")).await;
    check(&r, "POST response");

    srv.stop();
}
