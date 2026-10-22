//! Regression test for the dispute-page signed-signature gap
//! (DISPUTE-SIGNATURE-GAP-2026-10-18.md).
//!
//! The dispute handler already fetched the payment assignment's
//! signature and primary address, but the template rendered neither,
//! so moderators and dispute participants could not verify the
//! seller's payment-address ownership from the dispute page. This
//! test requests the dispute page for an order that has a payment
//! assignment and asserts the signature and the primary address
//! appear in the rendered page.
//!
//! DB tests require DATABASE_URL (skipped silently when unset,
//! the pattern of the neighbouring suites).

use app::config::InstanceConfig;
use app::keyfile::KeyFile;
use app::media::MediaPipeline;
use app::passwords::HashGuard;
use app::web::{router, AppState};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PW: &str = "dispsig-correct-passphrase-1";
const CSRF: &str = "dispsig-csrf";

async fn pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Some(PgPoolOptions::new().max_connections(8).connect(&url).await.expect("DATABASE_URL is set but the database is unreachable"))
}

fn uniq() -> String {
    app::sessions::new_token()[..16].to_string()
}

async fn make_account(pool: &PgPool, role: &str) -> (i64, String) {
    let hash = HashGuard::new(2).hash(PW).await.unwrap();
    let public_id = app::db::public_id("acct_");
    let username = format!("dsig{}", uniq());
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

async fn session_for(pool: &PgPool, account_id: i64) -> String {
    let token = app::sessions::new_token();
    let now = time::OffsetDateTime::now_utc();
    let sess = app::sessions::Session::fresh(account_id, now);
    app::db::create_session(pool, &token, CSRF, &sess).await.unwrap();
    token
}

async fn make_listing(pool: &PgPool, seller_id: i64) -> i64 {
    let public_id = app::db::public_id("lst_");
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO listings (public_id, seller_id, title, description, price_atomic,
                                pricing_module, destination_module, auto_invoice, category, status)
         VALUES ($1, $2, $3, 'a fine widget', 1000000, 'xmr-only', 'signed-address-pool', false, 'general', 'published')
         RETURNING id",
    )
    .bind(&public_id)
    .bind(seller_id)
    .bind(format!("Widget {}", uniq()))
    .fetch_one(pool)
    .await
    .unwrap();
    id
}

async fn make_order(pool: &PgPool, buyer_id: i64, seller_id: i64, listing_id: i64) -> i64 {
    let public_id = app::db::public_id("ord_");
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO orders (public_id, buyer_id, seller_id, listing_id, state, settlement,
                             seller_fpr_pinned, terms_bytes, terms_sha256, total_atomic,
                             module_pins, evidence_level, idempotency_key)
         VALUES ($1, $2, $3, $4, 'Disputed', 'direct', 'AABBCCDDEEFF00112233445566778899AABBCCDD',
                 'terms'::bytea, 'deadbeef', 1000000, '{}'::jsonb, 'None', $5)
         RETURNING id",
    )
    .bind(&public_id)
    .bind(buyer_id)
    .bind(seller_id)
    .bind(listing_id)
    .bind(format!("idem-{}", uniq()))
    .fetch_one(pool)
    .await
    .unwrap();
    id
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
    for id in accounts {
        for q in [
            "DELETE FROM disclosures WHERE dispute_id IN (SELECT d.id FROM disputes d JOIN orders o ON o.id = d.order_id WHERE o.buyer_id = $1 OR o.seller_id = $1)",
            "DELETE FROM disputes WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM payment_pool_entries WHERE seller_id = $1",
            "DELETE FROM payment_batches WHERE seller_id = $1",
            "DELETE FROM payment_identities WHERE seller_id = $1",
            "DELETE FROM destinations WHERE seller_id = $1",
            "DELETE FROM orders WHERE buyer_id = $1 OR seller_id = $1",
            "DELETE FROM listings WHERE seller_id = $1",
            "DELETE FROM sessions WHERE account_id = $1",
            "DELETE FROM accounts WHERE id = $1",
        ] {
            sqlx::query(q).bind(id).execute(pool).await.unwrap();
        }
    }
}

struct TestServer {
    addr: std::net::SocketAddr,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}

async fn test_server(pool: &PgPool) -> TestServer {
    let mut dir = std::env::temp_dir();
    dir.push(format!("dispsig-http-{}-{}", std::process::id(), uniq()));
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
    TestServer { addr, handle, dir }
}

impl TestServer {
    fn stop(self) {
        self.handle.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct HttpResult {
    status: u16,
    body: String,
}

async fn http(addr: std::net::SocketAddr, path: &str, cookie: Option<&str>) -> HttpResult {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n");
    if let Some(c) = cookie {
        req.push_str(&format!("Cookie: session={c}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .expect("status line parses");
    let body = match text.split_once("\r\n\r\n") {
        Some((_, b)) => b.to_string(),
        None => String::new(),
    };
    HttpResult { status, body }
}

#[tokio::test]
async fn dispute_page_renders_signature_and_primary_address() {
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool).await;
    let (seller, _) = make_account(&pool, "seller").await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    let lid = make_listing(&pool, seller).await;
    let oid = make_order(&pool, buyer, seller, lid).await;
    let did = make_dispute(&pool, oid, buyer).await;

    // A payment assignment for the order, with distinctive primary
    // address and signature values that appear nowhere else.
    let primary = format!("9DisputePrimary{}", uniq());
    let subaddress = format!("8DisputeSubaddr{}", uniq());
    let signature = format!("DisputeSignature{}Value", uniq());
    let message = format!(
        "xmr-direct-v1|vespiary-market|stagenet|seller-1|{primary}|{subaddress}"
    );
    sqlx::query(
        "INSERT INTO payment_identities (seller_id, primary_address, network)
         VALUES ($1, $2, 'stagenet')",
    )
    .bind(seller)
    .bind(&primary)
    .execute(&pool)
    .await
    .unwrap();
    let batch_id: i64 = sqlx::query_scalar(
        "INSERT INTO payment_batches (seller_id, marketplace_id, network, entry_count)
         VALUES ($1, 'vespiary-market', 'stagenet', 1) RETURNING id",
    )
    .bind(seller)
    .fetch_one(&pool)
    .await
    .unwrap();
    let destination_id: i64 = sqlx::query_scalar(
        "INSERT INTO destinations (address, seller_id, source) VALUES ($1, $2, 'pool') RETURNING id",
    )
    .bind(&subaddress)
    .bind(seller)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO payment_pool_entries (batch_id, seller_id, destination_id, address, message, signature, state, order_id)
         VALUES ($1, $2, $3, $4, $5, $6, 'assigned', $7)",
    )
    .bind(batch_id)
    .bind(seller)
    .bind(destination_id)
    .bind(&subaddress)
    .bind(&message)
    .bind(&signature)
    .bind(oid)
    .execute(&pool)
    .await
    .unwrap();

    // The buyer (a dispute participant) sees the full verification
    // trio on the dispute page: primary address and signature, not
    // just the signed message.
    let tok = session_for(&pool, buyer).await;
    let r = http(srv.addr, &format!("/disputes/{did}"), Some(&tok)).await;
    assert_eq!(r.status, 200, "the buyer can view the dispute");
    assert!(
        r.body.contains(&signature),
        "the dispute page renders the seller's signature so it can be verified"
    );
    assert!(
        r.body.contains(&primary),
        "the dispute page renders the seller's primary address the signature is verified against"
    );
    assert!(
        r.body.contains(&message),
        "the dispute page still renders the signed message"
    );

    // The seller's view carries the same public payment evidence.
    let tok = session_for(&pool, seller).await;
    let r = http(srv.addr, &format!("/disputes/{did}"), Some(&tok)).await;
    assert_eq!(r.status, 200, "the seller can view the dispute");
    assert!(r.body.contains(&signature), "the seller sees the signature too");
    assert!(r.body.contains(&primary), "the seller sees the primary address too");

    srv.stop();
    cleanup(&pool, &[seller, buyer]).await;
}
