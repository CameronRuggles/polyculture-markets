//! Acceptance tests for the 2026-10-18 payment-path audit fix brief,
//! tasks 5-8 (the tasks that do not depend on owner decisions):
//!   task 5 (M2) — pay.html names the spend key and Feather's limit.
//!   task 6 (M4) — the drain-defence caps hold under simultaneous
//!                 order creations by one buyer.
//!   task 7 (L1) — the unused-pool cap is re-checked inside the
//!                 upload transaction, so simultaneous uploads cannot
//!                 overfill the pool. (The signature-shape half of L1
//!                 is NOT implemented: the locked blind_direct_v1
//!                 contract, assumption A7, pins "no signature-format
//!                 check" for upload_batch — see the fix report.)
//!   task 8 (L2) — the startup network guard refuses an instance
//!                 whose stored payment state is on another network.
//!
//! DB tests require DATABASE_URL (skipped silently when unset, the
//! pattern of the neighbouring suites). Task 8 uses its own scratch
//! database so its whole-database counts cannot be poisoned by other
//! suites' leftovers.

use app::orders::{create_order_with_config, OrderError};
use app::payments::{
    canonical_message, ensure_network_consistency, payment_seller_id, set_primary_address,
    unused_count, upload_batch, PaymentConfig, PaymentError,
};
use modules_api::Network;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;

// Real stagenet fixtures: the POOL200 fixture-wallet set shared with
// the locked suites, split into disjoint slices for this file:
// SUBS = indices 0..10, SUBS60 = indices 10..70, EXTRA = 110..170.
const PRIMARY_A: &str = "55b6gZhKJ2b6EzvernZJBcPXiZym13w1CfbpDU6sR8aSGpaRbAmU4EMSH3XYXu5U1cSac7B49WRSSBbwQK9by3c7H9AdnFB";
const SIG: &str = "SigV2abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuv";
const SUBS: &[&str] = &[
    "7B2BSyZukau1TerLFtd6UtDvgz7YZVKGmV9xNowvh74biBFvjXTcWAu8EMJ1ot7sCHHCXrg6QRTHgNfoGsQRRj3xRqNnPFd",
    "77cfgTU2rrsVSKhJzJohXzJBkx4cnJTPHDWK6sRxNT9U2cksSvg5mnTMV78PbMuA1mhvm5RaFgUV7DFc4ze9yq5jTwTPPpc",
    "7BMUYtFiouid14Qret4pFbe26a5pUri7mifsd3hAW8CX5mV3N42AcsyAE5csiFgdFe6xZyet1PgVQ7g864RLMXdZ5raBeQ4",
    "72zUPzmAyxP9LCJo6Kdg9wGsM4e3H3mKXSr2mYuTAz9rcDcFNseejEENQu75wgzEtD7HgUWL2GWXe5sdWH2hGsEXHvR8thM",
    "77igFNto2xnREKwpur11dBUUcCshQVjNZH31BNbZNbJccE3S39RfqHVTA4eNc832v66bCSfvMcwX5fyT1oMYZ2WXFtCcJNh",
    "72bvDCpnxUCaxeEhGX7CLQZvriyks7nAE71Fr8H5m4dSLCtTx1k2zbkNratUJfvnR6RqiThBoc6KqPt96b3VznVaLKLbrkK",
    "755behWV1epaqDGdUYqGkqa5yEc2KceXLJ2VZBqKhJAXM4n6CMFCdbQMVVCF6bSCQxHtC3Jj6XRXHHaAD2n9rPYSN2vXhpC",
    "75iLCeUEX4m8Pn7fSRv9vYEr7iFLbGQngaxA5yn8d9Q3GgU1juihAVW9U4ErsvvyeD3o7np233yxoMmegtZyZuWdBQbMnbs",
    "7AcYxXXxeNU9xrfjKdKCFPGPv5S8CgkXD1bcrL7bPdHiLzemA8tfUYs4JpcTUvRvyyHq5zfkM9YBK99F3F27oNKiG1vUAsE",
    "72GeiPtUwSSSsbBtk7SgYGebrQYiDZZYvGa7Y5Z5AAi2M5Cpp38sCU8DjQtcCVJPTxUjua8ekmSuRhzNSz6gFcfFErM7Jqm",
];
const SUBS60: &[&str] = &[
    "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",
];
const EXTRA: &[&str] = &[
    "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",
];

async fn pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    PgPoolOptions::new()
        .max_connections(24)
        .connect(&url)
        .await
        .ok()
}

fn cfg() -> PaymentConfig {
    PaymentConfig::defaults("vespiary-market")
}

fn uniq() -> String {
    app::sessions::new_token()[..16].to_string()
}

async fn make_account(pool: &PgPool, role: &str) -> (i64, String) {
    let public_id = app::db::public_id("acct_");
    let username = format!("fix{}", uniq());
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO accounts (public_id, username, password_hash, role, created_at)
         VALUES ($1, $2, 'x', $3, now() - interval '72 hours') RETURNING id",
    )
    .bind(&public_id)
    .bind(&username)
    .bind(role)
    .fetch_one(pool)
    .await
    .unwrap();
    (id, public_id)
}

async fn install_key(pool: &PgPool, account_id: i64) {
    let fpr = format!("{:040X}", rand::random::<u128>() % (1u128 << 127));
    sqlx::query(
        "INSERT INTO identity_keys (account_id, certificate, fingerprint, version, status)
         VALUES ($1, $2, $3, 1, 'current')",
    )
    .bind(account_id)
    .bind(b"payments-test-dummy-cert".to_vec())
    .bind(&fpr)
    .execute(pool)
    .await
    .unwrap();
}

async fn make_listing(pool: &PgPool, seller_id: i64) -> String {
    let public_id = app::db::public_id("lst_");
    sqlx::query(
        "INSERT INTO listings (public_id, seller_id, title, description, price_atomic,
            pricing_module, destination_module, auto_invoice, status, category)
         VALUES ($1, $2, 'Fix Widget', 'A widget.', 1250000000000, 'xmr-only',
                 'signed-address-pool', false, 'published', 'general')",
    )
    .bind(&public_id)
    .bind(seller_id)
    .execute(pool)
    .await
    .unwrap();
    public_id
}

fn batch_json(cfg: &PaymentConfig, seller_pub: &str, primary: &str, subs: &[&str]) -> String {
    let seller_id = payment_seller_id(seller_pub).unwrap();
    let entries: Vec<serde_json::Value> = subs
        .iter()
        .map(|s| {
            serde_json::json!({
                "subaddress": s,
                "message": canonical_message(&cfg.marketplace_id, cfg.network, &seller_id, primary, s),
                "signature": SIG,
            })
        })
        .collect();
    serde_json::json!({
        "format": "xmr-direct-batch-v1",
        "marketplace_id": cfg.marketplace_id,
        "network": "stagenet",
        "seller_id": seller_id,
        "primary_address": primary,
        "entries": entries,
    })
    .to_string()
}

async fn cleanup(pool: &PgPool, accounts: &[i64]) {
    for id in accounts {
        for q in [
            "DELETE FROM payment_attestations WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM payment_pool_entries WHERE seller_id = $1",
            "DELETE FROM payment_batches WHERE seller_id = $1",
            "DELETE FROM payment_identities WHERE seller_id = $1",
            "DELETE FROM destinations WHERE seller_id = $1",
            "DELETE FROM notifications WHERE account_id = $1",
            "DELETE FROM orders WHERE buyer_id = $1 OR seller_id = $1",
            "DELETE FROM listings WHERE seller_id = $1",
            "DELETE FROM identity_keys WHERE account_id = $1",
            "DELETE FROM accounts WHERE id = $1",
        ] {
            sqlx::query(q).bind(id).execute(pool).await.unwrap();
        }
    }
}

/// The fixture addresses are shared with other suites through the
/// global `destinations` table; purge stale rows for every address
/// this file uses before each test (the neighbouring suites' own
/// pre-clean discipline), and serialize this file's fixture tests.
static FIXTURE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

fn fixture_lock() -> &'static tokio::sync::Mutex<()> {
    FIXTURE_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn all_fixture_addrs() -> Vec<String> {
    SUBS.iter()
        .chain(SUBS60.iter())
        .chain(EXTRA.iter())
        .map(|s| s.to_string())
        .collect()
}

async fn purge_fixture_addresses(pool: &PgPool) {
    let owned = all_fixture_addrs();
    sqlx::query(
        "DELETE FROM payment_attestations WHERE pool_entry_id IN \
         (SELECT id FROM payment_pool_entries WHERE address = ANY($1))",
    )
    .bind(&owned)
    .execute(pool)
    .await
    .expect("purge attestations");
    sqlx::query("DELETE FROM payment_pool_entries WHERE address = ANY($1)")
        .bind(&owned)
        .execute(pool)
        .await
        .expect("purge entries");
    sqlx::query("DELETE FROM destinations WHERE address = ANY($1)")
        .bind(&owned)
        .execute(pool)
        .await
        .expect("purge destinations");
}

// ---------------------------------------------------------------------------
// Task 5 (M2): pay-page wording.

#[test]
fn pay_template_requires_spend_key_signature_and_warns_about_feather() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/templates/pay.html");
    let raw = std::fs::read_to_string(path).expect("read pay.html template");
    assert!(
        raw.contains("made with the spend key"),
        "pay page step 2 must say the wallet must report a signature made with the spend key"
    );
    assert!(
        raw.contains("Feather"),
        "pay page must name Feather in the key-type warning"
    );
    assert!(
        raw.contains("which key signed") || raw.contains("which key made it"),
        "pay page must warn that Feather cannot show which key signed"
    );
}

// ---------------------------------------------------------------------------
// Task 6 (M4): 20 simultaneous creations by one buyer, cap is 3.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_creations_by_one_buyer_stop_at_the_open_unpaid_cap() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    assert_eq!(c.open_unpaid_cap, 3, "fixture assumes the default cap");

    // Seller with identity, key, listing and a pool of 25.
    let (seller_id, seller_pub) = make_account(&pool, "seller").await;
    install_key(&pool, seller_id).await;
    let listing = make_listing(&pool, seller_id).await;
    set_primary_address(&pool, seller_id, PRIMARY_A, &c)
        .await
        .unwrap();
    let mut subs: Vec<&str> = SUBS.to_vec();
    subs.extend_from_slice(&SUBS60[..15]);
    upload_batch(&pool, seller_id, &batch_json(&c, &seller_pub, PRIMARY_A, &subs), &c)
        .await
        .unwrap();
    assert_eq!(unused_count(&pool, seller_id).await.unwrap(), 25);

    let (buyer, _) = make_account(&pool, "buyer").await;

    // Release all 20 creations at once: no sleeps; the barrier is the
    // only synchronization, so any pass over the cap is a real race in
    // the counting, not a scheduling artefact of the test.
    let barrier = Arc::new(tokio::sync::Barrier::new(20));
    let mut handles = Vec::new();
    for i in 0..20 {
        let p = pool.clone();
        let l = listing.clone();
        let cc = c.clone();
        let b = barrier.clone();
        handles.push(tokio::spawn(async move {
            b.wait().await;
            create_order_with_config(
                &p,
                "vespiary-market",
                buyer,
                &l,
                1,
                &format!("t6-burst-{i}"),
                &cc,
            )
            .await
        }));
    }
    let mut ok = 0usize;
    let mut capped = 0usize;
    for h in handles {
        match h.await.unwrap() {
            Ok((_order, created)) => {
                assert!(created);
                ok += 1;
            }
            Err(OrderError::TooManyOpenUnpaid) => capped += 1,
            Err(e) => panic!("burst creation failed with an unexpected error: {e:?}"),
        }
    }
    assert_eq!(ok, 3, "exactly the open-unpaid cap may be created");
    assert_eq!(capped, 17, "every further simultaneous creation must hit the cap");
    let orders: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM orders WHERE buyer_id = $1")
        .bind(buyer)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(orders, 3);
    assert_eq!(unused_count(&pool, seller_id).await.unwrap(), 22);
    cleanup(&pool, &[seller_id, buyer]).await;
}

// ---------------------------------------------------------------------------
// Task 7 (L1): two simultaneous 60-entry uploads against a 100 cap.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_uploads_cannot_overfill_the_pool() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    assert_eq!(c.max_unused_pool, 100, "fixture assumes the default pool cap");
    assert_eq!(c.max_batch, 100, "fixture assumes the default batch cap");

    let (seller_id, seller_pub) = make_account(&pool, "seller").await;
    set_primary_address(&pool, seller_id, PRIMARY_A, &c)
        .await
        .unwrap();

    let mut subs_a: Vec<&str> = SUBS.to_vec();
    subs_a.extend_from_slice(&SUBS60[..50]);
    assert_eq!(subs_a.len(), 60);
    let subs_b: Vec<&str> = EXTRA.to_vec();
    assert_eq!(subs_b.len(), 60);
    let batch_a = batch_json(&c, &seller_pub, PRIMARY_A, &subs_a);
    let batch_b = batch_json(&c, &seller_pub, PRIMARY_A, &subs_b);

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let (p1, p2) = (pool.clone(), pool.clone());
    let (c1, c2) = (c.clone(), c.clone());
    let b1 = barrier.clone();
    let h1 = tokio::spawn(async move {
        b1.wait().await;
        upload_batch(&p1, seller_id, &batch_a, &c1).await
    });
    let b2 = barrier.clone();
    let h2 = tokio::spawn(async move {
        b2.wait().await;
        upload_batch(&p2, seller_id, &batch_b, &c2).await
    });
    let r1 = h1.await.unwrap();
    let r2 = h2.await.unwrap();
    let oks = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        oks, 1,
        "exactly one of the two 60-entry uploads may land against the 100 cap: {r1:?} / {r2:?}"
    );
    for r in [&r1, &r2] {
        if let Err(e) = r {
            assert_eq!(
                *e,
                PaymentError::PoolFull,
                "the losing upload must fail on the pool cap, not on anything else"
            );
        }
    }
    assert_eq!(unused_count(&pool, seller_id).await.unwrap(), 60);
    cleanup(&pool, &[seller_id]).await;
}

// ---------------------------------------------------------------------------
// Task 8 (L2): startup network guard, in a scratch database so the
// whole-database counts are exactly this test's own state.

async fn guard_pool() -> Option<PgPool> {
    let base = std::env::var("DATABASE_URL").ok()?;
    let root = base.rsplit_once('/').map(|(r, _)| r).unwrap_or(&base);
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(&format!("{root}/postgres"))
        .await
        .ok()?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = 'marketplace_fix_guard')",
    )
    .fetch_one(&admin)
    .await
    .ok()?;
    if !exists {
        sqlx::query("CREATE DATABASE marketplace_fix_guard")
            .execute(&admin)
            .await
            .ok()?;
    }
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&format!("{root}/marketplace_fix_guard"))
        .await
        .ok()?;
    // The three tables the guard reads, with the migration-0008
    // columns it touches.
    for ddl in [
        "CREATE TABLE IF NOT EXISTS payment_identities (
            seller_id BIGINT PRIMARY KEY,
            primary_address TEXT NOT NULL,
            network TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            changed_at TIMESTAMPTZ
        )",
        "CREATE TABLE IF NOT EXISTS payment_batches (
            id BIGSERIAL PRIMARY KEY,
            seller_id BIGINT NOT NULL,
            marketplace_id TEXT NOT NULL,
            network TEXT NOT NULL,
            entry_count INTEGER NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )",
        "CREATE TABLE IF NOT EXISTS payment_pool_entries (
            id BIGSERIAL PRIMARY KEY,
            batch_id BIGINT NOT NULL,
            seller_id BIGINT NOT NULL,
            destination_id BIGINT,
            address TEXT NOT NULL,
            message TEXT NOT NULL DEFAULT '',
            signature TEXT NOT NULL DEFAULT '',
            state TEXT NOT NULL DEFAULT 'unused',
            order_id BIGINT,
            assigned_at TIMESTAMPTZ,
            retired_at TIMESTAMPTZ
        )",
        "DELETE FROM payment_pool_entries",
        "DELETE FROM payment_batches",
        "DELETE FROM payment_identities",
    ] {
        sqlx::query(ddl).execute(&pool).await.ok()?;
    }
    Some(pool)
}

#[tokio::test]
async fn network_guard_refuses_mismatched_stored_state() {
    let Some(pool) = guard_pool().await else { return };
    let mut mainnet = cfg();
    mainnet.network = Network::Mainnet;
    let stagenet = cfg();

    // No stored state: either network may start.
    ensure_network_consistency(&pool, &mainnet).await.unwrap();
    ensure_network_consistency(&pool, &stagenet).await.unwrap();

    // A stagenet identity alone already refuses a mainnet start.
    sqlx::query(
        "INSERT INTO payment_identities (seller_id, primary_address, network)
         VALUES (1, $1, 'stagenet')",
    )
    .bind(PRIMARY_A)
    .execute(&pool)
    .await
    .unwrap();
    ensure_network_consistency(&pool, &stagenet).await.unwrap();
    let err = ensure_network_consistency(&pool, &mainnet)
        .await
        .expect_err("stagenet identity + mainnet config must refuse to start");
    assert_eq!(
        err,
        PaymentError::NetworkMismatch {
            identities: 1,
            unused_entries: 0
        }
    );

    // An unused stagenet pool entry is counted too.
    sqlx::query(
        "INSERT INTO payment_batches (id, seller_id, marketplace_id, network, entry_count)
         VALUES (1, 1, 'vespiary-market', 'stagenet', 1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO payment_pool_entries (batch_id, seller_id, address, state)
         VALUES (1, 1, $1, 'unused')",
    )
    .bind(SUBS[0])
    .execute(&pool)
    .await
    .unwrap();
    let err = ensure_network_consistency(&pool, &mainnet)
        .await
        .expect_err("stagenet pool + mainnet config must refuse to start");
    assert_eq!(
        err,
        PaymentError::NetworkMismatch {
            identities: 1,
            unused_entries: 1
        }
    );
    ensure_network_consistency(&pool, &stagenet).await.unwrap();

    // Once the stored state matches the instance network, it starts.
    sqlx::query("UPDATE payment_identities SET network = 'mainnet'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE payment_batches SET network = 'mainnet'")
        .execute(&pool)
        .await
        .unwrap();
    ensure_network_consistency(&pool, &mainnet).await.unwrap();
}
