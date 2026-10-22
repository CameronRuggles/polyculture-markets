//! Buyer-evidence payment flow (owner decision 2026-10-18; audit fix
//! brief task 1 expanded + task 4 closed states).
//!
//! A buyer who paid the order's assigned subaddress submits the
//! Monero transaction proof (txid + proof string). The server carries
//! it UNVERIFIED (it never checks proofs, never labels them
//! "verified"); the submission is the timestamped payment report the
//! dispute gate, the expiry sweep, and the seller-cancel guard key
//! on, and it marks the order Paid through the core.
//!
//! VISIBILITY (owner-directed): the proof, the txid, and the source
//! of a Paid state are visible ONLY to the submitting buyer and to
//! moderators inside the dispute view. The seller sees only the
//! order state — a proof-driven Paid is indistinguishable from an
//! attestation-driven Paid on every seller-facing surface, including
//! notifications.
//!
//! DB tests require DATABASE_URL (skipped silently when unset, the
//! pattern of the neighbouring suites).

use app::orders::{apply_action, create_order_with_config, order_by_public_id, OrderError};
use app::payments::{
    assignment_for_order, canonical_message, confirm_payment, declare_not_received,
    expire_unpaid_orders, has_payment_report, mark_paid, open_payment_flags,
    payment_flags_for_order, payment_proof_for_order, payment_report_for_order, payment_seller_id,
    set_primary_address, submit_manual_report, submit_payment_proof, upload_batch, PaymentConfig,
    PaymentError,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

// Real stagenet fixtures: the POOL200 set shared with the locked
// suites; this file uses master indices 110..122 (the neighbouring
// files' EXTRA range), disjoint from payments_db's slices.
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
    "7ASpAtZh9rE4fdoB4z6ZfmG9K2TceDsQUQX4YAvNHtim3pHJnByTwXTYhiuhGqKMTWTvXtJ6CcQy6RksLmGLzYG4MsQdeB1",
    "77b3CaQrYFFWSGYzaiPib8by3P52VMjz4DZ6jBgy3K8hZdrLuKAxhAFhkMmukXAuZd7p6E3YQVZhQLbmQkVSbbqs79nXNRe",
    "766PMTwHFaKgmtrmPjHHfbRDzoPpgx6QWY1HjDWyKZEdNexTHqPBZge3yvu3isxoUriZgMgF71v6bVJCmsS2KVkHJpFV8Ug",
    "72wdPGhKzDWD8Z1GndB3uEPZFPr7h7KnUd91aZMCHxwLDg8Suv8LfrBEpVqJ2Ck8ja1QyjRFka8grhZHoxnneLL4Coc6xhS",
    "76w2GwjMXDuUhqBEd4bmuD79tNsabeBasSAijAVYCHPaXWia3Myd5ifSuXFGKF6QAYKETPUGDjmneM2C4xRjP2BjTFZgo59",
    "7AzQkETYG1CWgYY5HMUaGcJFpScdHyPjCZwcjdYyFH2Ygx3RxgbMuq3AADT5PPdsnCCArQHbSZwmRe6KfetPfKnL5zQyG7U",
];

const TXID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TXID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PROOF_A: &str = "OutProofV2PROOFAteststring0000000000000000000000000000000000000000";
const PROOF_B: &str = "OutProofV2PROOFBteststring1111111111111111111111111111111111111111";

async fn pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Some(
        PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .expect("DATABASE_URL is set but the database is unreachable"),
    )
}

fn cfg() -> PaymentConfig {
    PaymentConfig::defaults("vespiary-market")
}

fn uniq() -> String {
    app::sessions::new_token()[..16].to_string()
}

async fn make_account(pool: &PgPool, role: &str) -> (i64, String) {
    let public_id = app::db::public_id("acct_");
    let username = format!("txp{}", uniq());
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
         VALUES ($1, $2, 'Proof Widget', 'A widget.', 1250000000000, 'xmr-only',
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

/// A seller with key, listing, payment identity, and an uploaded pool.
async fn shop_with_pool(pool: &PgPool, subs: &[&str]) -> (i64, String, String) {
    let (seller_id, seller_pub) = make_account(pool, "seller").await;
    install_key(pool, seller_id).await;
    let listing = make_listing(pool, seller_id).await;
    let c = cfg();
    set_primary_address(pool, seller_id, PRIMARY_A, &c)
        .await
        .unwrap();
    upload_batch(
        pool,
        seller_id,
        &batch_json(&c, &seller_pub, PRIMARY_A, subs),
        &c,
    )
    .await
    .unwrap();
    (seller_id, seller_pub, listing)
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
            "DELETE FROM payment_attestations WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM payment_pool_entries WHERE seller_id = $1",
            "DELETE FROM payment_batches WHERE seller_id = $1",
            "DELETE FROM payment_identities WHERE seller_id = $1",
            "DELETE FROM destinations WHERE seller_id = $1",
            "DELETE FROM notifications WHERE account_id = $1",
            "DELETE FROM orders WHERE buyer_id = $1 OR seller_id = $1",
            "DELETE FROM listings WHERE seller_id = $1",
            "DELETE FROM identity_keys WHERE account_id = $1",
            "DELETE FROM sessions WHERE account_id = $1",
            "DELETE FROM accounts WHERE id = $1",
        ] {
            sqlx::query(q).bind(id).execute(pool).await.unwrap();
        }
    }
}

/// The fixture addresses are shared with other suites through the
/// global `destinations` table; purge stale rows for this file's
/// addresses before each test and serialize this file's tests (the
/// neighbouring suites' discipline).
static FIXTURE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

fn fixture_lock() -> &'static tokio::sync::Mutex<()> {
    FIXTURE_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn purge_fixture_addresses(pool: &PgPool) {
    let owned: Vec<String> = SUBS.iter().map(|s| s.to_string()).collect();
    sqlx::query(
        "DELETE FROM payment_declarations WHERE pool_entry_id IN \
         (SELECT id FROM payment_pool_entries WHERE address = ANY($1))",
    )
    .bind(&owned)
    .execute(pool)
    .await
    .expect("purge declarations");
    sqlx::query(
        "DELETE FROM payment_review_flags WHERE order_id IN \
         (SELECT order_id FROM payment_pool_entries WHERE address = ANY($1) AND order_id IS NOT NULL)",
    )
    .bind(&owned)
    .execute(pool)
    .await
    .expect("purge flags");
    sqlx::query(
        "DELETE FROM payment_reports WHERE order_id IN \
         (SELECT order_id FROM payment_pool_entries WHERE address = ANY($1) AND order_id IS NOT NULL)",
    )
    .bind(&owned)
    .execute(pool)
    .await
    .expect("purge reports");
    sqlx::query(
        "DELETE FROM payment_proofs WHERE pool_entry_id IN \
         (SELECT id FROM payment_pool_entries WHERE address = ANY($1))",
    )
    .bind(&owned)
    .execute(pool)
    .await
    .expect("purge proofs");
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

async fn order_state(pool: &PgPool, order_id: i64) -> (String, String) {
    sqlx::query_as("SELECT state, evidence_level FROM orders WHERE id = $1")
        .bind(order_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn backdate(pool: &PgPool, order_id: i64, hours: i64) {
    sqlx::query("UPDATE orders SET created_at = now() - ($2 || ' hours')::interval WHERE id = $1")
        .bind(order_id)
        .bind(hours.to_string())
        .execute(pool)
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Task 1 (expanded): the acceptance flow. Buyer pays, submits
// report+proof, seller stays silent, the sweep runs: the order is NOT
// cancelled and the buyer's dispute opens.

#[tokio::test]
async fn proof_submission_marks_paid_survives_sweep_and_opens_dispute() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[0..4]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;

    let (order, created) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    assert!(created);
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    assert_eq!(order.state, "AwaitingPayment");

    // Before any report, the buyer cannot dispute a direct order from
    // AwaitingPayment (the report is the gate).
    let err = apply_action(&pool, &order, "dispute", buyer).await;
    assert_eq!(err, Err(OrderError::TransitionDenied));

    // Buyer pays off-server and submits the proof.
    let state = submit_payment_proof(&pool, &order, buyer, TXID_A, PROOF_A, &c)
        .await
        .unwrap();
    assert_eq!(format!("{state:?}"), "Paid");
    let (st, ev) = order_state(&pool, order.id).await;
    assert_eq!(st, "Paid");
    assert_eq!(ev, "BuyerProofSubmitted");
    assert!(has_payment_report(&pool, order.id).await.unwrap());
    let stored = payment_proof_for_order(&pool, order.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.txid, TXID_A);
    assert_eq!(stored.proof, PROOF_A);
    assert_eq!(stored.submitted_by, buyer);

    // Notification parity: the buyer sees the same order_paid event an
    // attestation produces; the seller receives nothing that reveals
    // a proof (in fact nothing about the payment at all).
    let buyer_notes: Vec<(String,)> =
        sqlx::query_as("SELECT event_type FROM notifications WHERE account_id = $1")
            .bind(buyer)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(
        buyer_notes.iter().any(|(t,)| t == "order_paid"),
        "buyer must see the same order_paid event as an attestation produces: {buyer_notes:?}"
    );
    let seller_notes: Vec<(String,)> =
        sqlx::query_as("SELECT event_type FROM notifications WHERE account_id = $1")
            .bind(seller_id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(
        seller_notes
            .iter()
            .all(|(t,)| !t.contains("proof") && t != "order_paid"),
        "no seller notification may reveal or accompany the proof submission: {seller_notes:?}"
    );

    // Age the order well past the 48h expiry and run the sweep: a
    // reported order is never eaten by it.
    backdate(&pool, order.id, 72).await;
    expire_unpaid_orders(&pool, &c).await.unwrap();
    let (st, _) = order_state(&pool, order.id).await;
    assert_eq!(st, "Paid", "the sweep must skip proof-submitted orders");

    // The buyer's dispute opens.
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    let state = apply_action(&pool, &order, "dispute", buyer).await.unwrap();
    assert_eq!(format!("{state:?}"), "Disputed");
    let d = app::disputes::dispute_for_order(&pool, order.id)
        .await
        .unwrap()
        .expect("opening the dispute creates its row");
    assert_eq!(d.state, "open");

    cleanup(&pool, &[seller_id, buyer]).await;
}

// ---------------------------------------------------------------------------
// Submission from Requested (buyer paid before the seller accepted):
// the core advances the order to Paid; the seller can then neither
// cancel nor decline it — their remedy is a dispute or shipping.

#[tokio::test]
async fn proof_from_requested_advances_and_seller_cannot_cancel_or_decline() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[0..4]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;

    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    assert_eq!(order.state, "Requested");
    submit_payment_proof(&pool, &order, buyer, TXID_A, PROOF_A, &c)
        .await
        .unwrap();
    let (st, _) = order_state(&pool, order.id).await;
    assert_eq!(st, "Paid");

    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    let err = apply_action(&pool, &order, "cancel", seller_id).await;
    assert_eq!(
        err,
        Err(OrderError::TransitionDenied),
        "seller cannot cancel a reported order"
    );
    let err = apply_action(&pool, &order, "decline", seller_id).await;
    assert_eq!(err, Err(OrderError::TransitionDenied));

    // Parity: an attestation-paid order refuses seller cancel in
    // exactly the same way.
    let (order2, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order2, "accept", seller_id)
        .await
        .unwrap();
    let order2 = order_by_public_id(&pool, &order2.public_id).await.unwrap();
    mark_paid(&pool, &order2, seller_id, &c).await.unwrap();
    let order2 = order_by_public_id(&pool, &order2.public_id).await.unwrap();
    let err = apply_action(&pool, &order2, "cancel", seller_id).await;
    assert_eq!(err, Err(OrderError::TransitionDenied));

    cleanup(&pool, &[seller_id, buyer]).await;
}

// ---------------------------------------------------------------------------
// The unreported path is unchanged: no dispute without a report, and
// the sweep still cancels a stale unreported direct order.

#[tokio::test]
async fn unreported_direct_order_cannot_dispute_and_still_expires() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[4..8]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;

    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();

    // A buyer who never paid (never reported) cannot dispute.
    let err = apply_action(&pool, &order, "dispute", buyer).await;
    assert_eq!(err, Err(OrderError::TransitionDenied));

    backdate(&pool, order.id, 49).await;
    expire_unpaid_orders(&pool, &c).await.unwrap();
    let (st, _) = order_state(&pool, order.id).await;
    assert_eq!(st, "Cancelled", "an unreported stale order still expires");

    cleanup(&pool, &[seller_id, buyer]).await;
}

// ---------------------------------------------------------------------------
// Late submission (owner design point): the buyer may submit at any
// point while the order is open — including after the seller has
// already attested, and after fulfilment when a problem appears. The
// proof is recorded; a state the seller set is left exactly as it
// was (evidence never downgrades).

#[tokio::test]
async fn late_proof_submission_records_without_disturbing_state() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[4..8]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;

    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    mark_paid(&pool, &order, seller_id, &c).await.unwrap();

    // Submission while Paid (attested): recorded, nothing else moves.
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    let state = submit_payment_proof(&pool, &order, buyer, TXID_A, PROOF_A, &c)
        .await
        .unwrap();
    assert_eq!(format!("{state:?}"), "Paid");
    let (st, ev) = order_state(&pool, order.id).await;
    assert_eq!(st, "Paid");
    assert_eq!(
        ev, "SellerAttested",
        "an attestation is never rewritten by a later proof"
    );

    // Seller ships; the buyer then has a problem and their proof is
    // already on file for the dispute.
    apply_action(&pool, &order, "fulfil", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    let state = apply_action(&pool, &order, "dispute", buyer).await.unwrap();
    assert_eq!(format!("{state:?}"), "Disputed");

    cleanup(&pool, &[seller_id, buyer]).await;
}

// ---------------------------------------------------------------------------
// Authorization + input hygiene + closed orders.

#[tokio::test]
async fn proof_submission_rejects_non_buyer_bad_input_and_closed_orders() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[8..12]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    let (stranger, _) = make_account(&pool, "buyer").await;

    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();

    // Only the buyer may submit.
    assert_eq!(
        submit_payment_proof(&pool, &order, seller_id, TXID_A, PROOF_A, &c).await,
        Err(PaymentError::NotBuyer)
    );
    assert_eq!(
        submit_payment_proof(&pool, &order, stranger, TXID_A, PROOF_A, &c).await,
        Err(PaymentError::NotBuyer)
    );
    // Txid must be exactly 64 hex chars; the proof must be non-empty.
    assert_eq!(
        submit_payment_proof(&pool, &order, buyer, "abc123", PROOF_A, &c).await,
        Err(PaymentError::BadTxid)
    );
    assert_eq!(
        submit_payment_proof(&pool, &order, buyer, &"z".repeat(64), PROOF_A, &c).await,
        Err(PaymentError::BadTxid)
    );
    assert_eq!(
        submit_payment_proof(&pool, &order, buyer, TXID_A, "   ", &c).await,
        Err(PaymentError::BadProof)
    );
    assert!(!has_payment_report(&pool, order.id).await.unwrap());

    // Buyer cancels their own unpaid order (unchanged rule); a closed
    // order then accepts no proof.
    apply_action(&pool, &order, "cancel", buyer).await.unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    assert_eq!(
        submit_payment_proof(&pool, &order, buyer, TXID_A, PROOF_A, &c).await,
        Err(PaymentError::OrderClosed)
    );

    cleanup(&pool, &[seller_id, buyer, stranger]).await;
}

// ---------------------------------------------------------------------------
// Re-submission while open revises the stored proof; the report's
// first-submission timestamp stands.

#[tokio::test]
async fn proof_resubmission_revises_evidence_and_keeps_first_timestamp() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[8..12]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;

    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    submit_payment_proof(&pool, &order, buyer, TXID_A, PROOF_A, &c)
        .await
        .unwrap();
    let first = payment_proof_for_order(&pool, order.id)
        .await
        .unwrap()
        .unwrap();

    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    submit_payment_proof(&pool, &order, buyer, TXID_B, PROOF_B, &c)
        .await
        .unwrap();
    let second = payment_proof_for_order(&pool, order.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.txid, TXID_B);
    assert_eq!(second.proof, PROOF_B);
    assert_eq!(
        second.created_at, first.created_at,
        "the report timestamp is the FIRST submission"
    );
    assert!(second.updated_at >= first.updated_at);
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_proofs WHERE order_id = $1")
        .bind(order.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 1, "one proof row per order");

    cleanup(&pool, &[seller_id, buyer]).await;
}

// ---------------------------------------------------------------------------
// HTTP: workstream B (closed states) + the visibility rule end to end.

use app::config::InstanceConfig;
use app::media::MediaPipeline;
use app::web::{router, AppState};
use std::io::Write as _;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct TestServer {
    addr: std::net::SocketAddr,
    pool: PgPool,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}

async fn test_server(pool: &PgPool) -> TestServer {
    let mut dir = std::env::temp_dir();
    dir.push(format!("txproof-http-{}-{}", std::process::id(), uniq()));
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
    let keyfile = app::keyfile::KeyFile::load_or_generate(&key_path).expect("key file");
    let state = AppState {
        pool: pool.clone(),
        hash_guard: app::passwords::HashGuard::new(2),
        throttles: Arc::new(app::throttle::Throttles::new()),
        registrations_open: true,
        account_cap: None,
        dev_cookies: true,
        media,
        marketplace_id,
        payments,
        keyfile: Arc::new(keyfile),
        stage9: app::reputation::Stage9Config::from_env(),
        instance,
        retention: app::retention::RetentionConfig::defaults(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    TestServer {
        addr,
        pool: pool.clone(),
        handle,
        dir,
    }
}

async fn session_for(pool: &PgPool, account_id: i64) -> String {
    let token = app::sessions::new_token();
    let now = time::OffsetDateTime::now_utc();
    let sess = app::sessions::Session::fresh(account_id, now);
    app::db::create_session(pool, &token, "test-csrf-secret", &sess)
        .await
        .unwrap();
    token
}

async fn http(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n");
    if let Some(c) = cookie {
        req.push_str(&format!("Cookie: session={c}\r\n"));
    }
    if let Some(b) = body {
        req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .expect("status line parses");
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
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

fn csrf_from(html: &str) -> String {
    // Every POST form on the page embeds the same session CSRF token.
    let marker = "name=\"csrf\" value=\"";
    let start = html.find(marker).expect("page carries a csrf field") + marker.len();
    let end = html[start..].find('"').unwrap() + start;
    html[start..end].to_string()
}

#[tokio::test]
async fn buyer_submits_proof_over_http_and_order_turns_paid() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[0..4]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();

    let srv = test_server(&pool).await;
    let buyer_cookie = session_for(&pool, buyer).await;
    let (status, page_html) = http(
        srv.addr,
        "GET",
        &format!("/orders/{}", order.public_id),
        Some(&buyer_cookie),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        page_html.contains("submit-proof"),
        "the buyer order page must offer the proof submission form"
    );
    let csrf = csrf_from(&page_html);
    let form = format!(
        "csrf={}&txid={}&proof={}",
        urlencode(&csrf),
        urlencode(TXID_A),
        urlencode(PROOF_A)
    );
    let (status, _) = http(
        srv.addr,
        "POST",
        &format!("/orders/{}/submit-proof", order.public_id),
        Some(&buyer_cookie),
        Some(&form),
    )
    .await;
    assert_eq!(status, 303, "submission redirects back to the order");
    let (st, ev) = order_state(&pool, order.id).await;
    assert_eq!(st, "Paid");
    assert_eq!(ev, "BuyerProofSubmitted");

    srv.handle.abort();
    let _ = std::fs::remove_dir_all(&srv.dir);
    cleanup(&pool, &[seller_id, buyer]).await;
}

#[tokio::test]
async fn pay_page_closed_states_show_no_address_and_qr_404s() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[0..6]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    let srv = test_server(&pool).await;
    let buyer_cookie = session_for(&pool, buyer).await;

    // Control: an open (AwaitingPayment) order shows its address.
    let (open, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &open, "accept", seller_id)
        .await
        .unwrap();
    let open_addr = assignment_for_order(&pool, open.id, &c)
        .await
        .unwrap()
        .unwrap()
        .address;
    let (status, body) = http(
        srv.addr,
        "GET",
        &format!("/orders/{}/pay", open.public_id),
        Some(&buyer_cookie),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        body.contains(&open_addr),
        "open orders keep the payable address"
    );
    assert!(body.contains("Pay exactly"));
    let (status, _) = http(
        srv.addr,
        "GET",
        &format!("/orders/{}/pay/qr.png", open.public_id),
        Some(&buyer_cookie),
        None,
    )
    .await;
    assert_eq!(status, 200, "open orders keep the QR route");

    // Cancelled.
    let (cancelled, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    let cancelled_addr = assignment_for_order(&pool, cancelled.id, &c)
        .await
        .unwrap()
        .unwrap()
        .address;
    apply_action(&pool, &cancelled, "cancel", buyer)
        .await
        .unwrap();

    // Declined.
    let (declined, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    let declined_addr = assignment_for_order(&pool, declined.id, &c)
        .await
        .unwrap()
        .unwrap()
        .address;
    apply_action(&pool, &declined, "decline", seller_id)
        .await
        .unwrap();

    // Completed (full happy path).
    let (done, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    let done_addr = assignment_for_order(&pool, done.id, &c)
        .await
        .unwrap()
        .unwrap()
        .address;
    apply_action(&pool, &done, "accept", seller_id)
        .await
        .unwrap();
    let done = order_by_public_id(&pool, &done.public_id).await.unwrap();
    mark_paid(&pool, &done, seller_id, &c).await.unwrap();
    let done = order_by_public_id(&pool, &done.public_id).await.unwrap();
    apply_action(&pool, &done, "fulfil", seller_id)
        .await
        .unwrap();
    let done = order_by_public_id(&pool, &done.public_id).await.unwrap();
    apply_action(&pool, &done, "complete", buyer).await.unwrap();

    for (ord, addr, label) in [
        (&cancelled, &cancelled_addr, "cancelled"),
        (&declined, &declined_addr, "declined"),
        (&done, &done_addr, "completed"),
    ] {
        let (status, body) = http(
            srv.addr,
            "GET",
            &format!("/orders/{}/pay", ord.public_id),
            Some(&buyer_cookie),
            None,
        )
        .await;
        assert_eq!(status, 200, "{label}: the pay page itself still renders");
        assert!(
            body.contains("This order is closed. Do not pay."),
            "{label}: closed orders must say so plainly"
        );
        assert!(
            !body.contains(addr.as_str()),
            "{label}: a closed order must not present a payable address"
        );
        assert!(
            !body.contains("Pay exactly"),
            "{label}: a closed order must not invite payment"
        );
        let (status, _) = http(
            srv.addr,
            "GET",
            &format!("/orders/{}/pay/qr.png", ord.public_id),
            Some(&buyer_cookie),
            None,
        )
        .await;
        assert_eq!(status, 404, "{label}: the QR route 404s on closed orders");
    }

    srv.handle.abort();
    let _ = std::fs::remove_dir_all(&srv.dir);
    cleanup(&pool, &[seller_id, buyer]).await;
}

#[tokio::test]
async fn proof_visibility_seller_blind_buyer_and_moderator_see() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[0..4]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    let (moderator, _) = make_account(&pool, "moderator").await;

    // A proof-paid order, driven through the real submission path.
    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    submit_payment_proof(&pool, &order, buyer, TXID_A, PROOF_A, &c)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    apply_action(&pool, &order, "dispute", buyer).await.unwrap();
    let dispute = app::disputes::dispute_for_order(&pool, order.id)
        .await
        .unwrap()
        .unwrap();

    // An attestation-paid order as the indistinguishability control.
    let (order2, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order2, "accept", seller_id)
        .await
        .unwrap();
    let order2 = order_by_public_id(&pool, &order2.public_id).await.unwrap();
    mark_paid(&pool, &order2, seller_id, &c).await.unwrap();

    let srv = test_server(&pool).await;
    let seller_cookie = session_for(&pool, seller_id).await;
    let buyer_cookie = session_for(&pool, buyer).await;
    let mod_cookie = session_for(&pool, moderator).await;

    // Seller's order page for the proof-paid order: state only. No
    // txid, no proof, no source marker — and the same payment-evidence
    // line as the attestation-paid order.
    let (status, seller_view) = http(
        srv.addr,
        "GET",
        &format!("/orders/{}", order.public_id),
        Some(&seller_cookie),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        seller_view.contains("Disputed"),
        "seller sees the order state (here: disputed)"
    );
    for forbidden in [TXID_A, PROOF_A, "BuyerProofSubmitted", "payment proof"] {
        assert!(
            !seller_view.contains(forbidden),
            "seller order page must not contain {forbidden:?}"
        );
    }
    let (status, seller_view2) = http(
        srv.addr,
        "GET",
        &format!("/orders/{}", order2.public_id),
        Some(&seller_cookie),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        seller_view.contains("Seller confirmed payment")
            && seller_view2.contains("Seller confirmed payment"),
        "proof-paid and attestation-paid must read identically to the seller"
    );

    // The buyer sees their own proof on their order page.
    let (status, buyer_view) = http(
        srv.addr,
        "GET",
        &format!("/orders/{}", order.public_id),
        Some(&buyer_cookie),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        buyer_view.contains(TXID_A),
        "buyer sees their submitted txid"
    );
    assert!(
        buyer_view.contains(PROOF_A),
        "buyer sees their submitted proof"
    );
    assert!(
        buyer_view.to_lowercase().contains("unverified"),
        "the buyer's proof is labelled unverified"
    );

    // Moderator dispute view shows the proof as evidence to check.
    let (status, mod_view) = http(
        srv.addr,
        "GET",
        &format!("/disputes/{}", dispute.id),
        Some(&mod_cookie),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        mod_view.contains(TXID_A),
        "moderator dispute view shows the txid"
    );
    assert!(
        mod_view.contains(PROOF_A),
        "moderator dispute view shows the proof"
    );

    // The seller in the SAME dispute view sees neither.
    let (status, seller_dispute) = http(
        srv.addr,
        "GET",
        &format!("/disputes/{}", dispute.id),
        Some(&seller_cookie),
        None,
    )
    .await;
    assert_eq!(status, 200);
    for forbidden in [TXID_A, PROOF_A, "BuyerProofSubmitted"] {
        assert!(
            !seller_dispute.contains(forbidden),
            "seller dispute view must not contain {forbidden:?}"
        );
    }

    srv.handle.abort();
    let _ = std::fs::remove_dir_all(&srv.dir);
    cleanup(&pool, &[seller_id, buyer, moderator]).await;
}

// ---------------------------------------------------------------------------
// Owner design update #2 (2026-10-18): per-order confirmation bound to
// the subaddress, the manual-confirm fallback (BuyerReported), the
// auto-review flags, and the seller not-received declaration.

// Confirmation is per-order and bound to that order's subaddress:
// confirming one order writes its attestation against that order's
// pool entry and leaves the seller's other orders untouched. There
// is no bulk or account-level attestation path.

#[tokio::test]
async fn seller_confirmation_binds_order_and_subaddress() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[0..6]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;

    let (o1, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    let (o2, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &o1, "accept", seller_id).await.unwrap();
    apply_action(&pool, &o2, "accept", seller_id).await.unwrap();
    let o1 = order_by_public_id(&pool, &o1.public_id).await.unwrap();
    let o2 = order_by_public_id(&pool, &o2.public_id).await.unwrap();
    let entry1 = assignment_for_order(&pool, o1.id, &c)
        .await
        .unwrap()
        .unwrap()
        .entry_id;
    let entry2 = assignment_for_order(&pool, o2.id, &c)
        .await
        .unwrap()
        .unwrap()
        .entry_id;
    assert_ne!(entry1, entry2, "each order draws its own subaddress");

    // Only the seller confirms.
    assert_eq!(
        confirm_payment(&pool, &o1, buyer, &c).await,
        Err(PaymentError::NotSeller)
    );

    let state = confirm_payment(&pool, &o1, seller_id, &c).await.unwrap();
    assert_eq!(format!("{state:?}"), "Paid");
    // The attestation row names order 1's pool entry — the subaddress
    // being confirmed — and order 2 has none.
    let att1: Option<i64> =
        sqlx::query_scalar("SELECT pool_entry_id FROM payment_attestations WHERE order_id = $1")
            .bind(o1.id)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert_eq!(
        att1,
        Some(entry1),
        "confirmation binds the order's own subaddress"
    );
    let att2: Option<i64> =
        sqlx::query_scalar("SELECT pool_entry_id FROM payment_attestations WHERE order_id = $1")
            .bind(o2.id)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert_eq!(att2, None, "no bulk attestation: order 2 is untouched");
    let (st2, _) = order_state(&pool, o2.id).await;
    assert_eq!(st2, "AwaitingPayment");

    // Confirming order 2 afterwards works independently, and
    // re-confirming a confirmed order is an idempotent no-op.
    confirm_payment(&pool, &o2, seller_id, &c).await.unwrap();
    let o1 = order_by_public_id(&pool, &o1.public_id).await.unwrap();
    let state = confirm_payment(&pool, &o1, seller_id, &c).await.unwrap();
    assert_eq!(format!("{state:?}"), "Paid");

    cleanup(&pool, &[seller_id, buyer]).await;
}

// The manual fallback: a buyer who cannot produce a proof confirms
// "I paid" in words alone. That records BuyerReported — NOT the
// proof-backed level — and the order does not advance; but the report
// exists, and with it the buyer's dispute path.

#[tokio::test]
async fn manual_report_records_buyer_reported_and_opens_dispute() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[0..4]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;

    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();

    // Only the buyer reports.
    assert_eq!(
        submit_manual_report(&pool, &order, seller_id).await,
        Err(PaymentError::NotBuyer)
    );

    let state = submit_manual_report(&pool, &order, buyer).await.unwrap();
    assert_eq!(
        format!("{state:?}"),
        "AwaitingPayment",
        "a manual confirm never marks Paid"
    );
    let (st, ev) = order_state(&pool, order.id).await;
    assert_eq!(st, "AwaitingPayment");
    assert_eq!(
        ev, "BuyerReported",
        "the manual fallback is the weaker evidence level"
    );
    assert!(has_payment_report(&pool, order.id).await.unwrap());
    let report = payment_report_for_order(&pool, order.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.kind, "manual");
    assert!(
        payment_proof_for_order(&pool, order.id)
            .await
            .unwrap()
            .is_none(),
        "a manual report stores no proof"
    );

    // With a report on file the buyer's dispute opens.
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    let state = apply_action(&pool, &order, "dispute", buyer).await.unwrap();
    assert_eq!(format!("{state:?}"), "Disputed");

    cleanup(&pool, &[seller_id, buyer]).await;
}

// A manual report is weaker protection in exactly one way: it does
// not stop the expiry sweep (design update #2.4 coordinates the sweep
// and the seller declaration to agree — both close an unproofed order
// as unpaid; the proof is what stops them).

#[tokio::test]
async fn manual_report_does_not_block_sweep() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[4..8]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;

    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    submit_manual_report(&pool, &order, buyer).await.unwrap();

    backdate(&pool, order.id, 49).await;
    expire_unpaid_orders(&pool, &c).await.unwrap();
    let (st, _) = order_state(&pool, order.id).await;
    assert_eq!(st, "Cancelled", "a manual report alone never blocks expiry");

    cleanup(&pool, &[seller_id, buyer]).await;
}

// Flag lifecycle (3a): a proof on file with no seller confirmation
// raises a proof-unconfirmed flag in the moderation queue the moment
// it is submitted; the seller's per-order confirmation clears it.

#[tokio::test]
async fn flag_raised_on_proof_and_cleared_on_confirmation() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[0..4]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;

    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    assert!(payment_flags_for_order(&pool, order.id)
        .await
        .unwrap()
        .is_empty());

    submit_payment_proof(&pool, &order, buyer, TXID_A, PROOF_A, &c)
        .await
        .unwrap();
    let flags = payment_flags_for_order(&pool, order.id).await.unwrap();
    assert_eq!(flags.len(), 1);
    assert_eq!(flags[0].kind, "proof-unconfirmed");
    assert_eq!(flags[0].state, "open");
    assert!(
        open_payment_flags(&pool)
            .await
            .unwrap()
            .iter()
            .any(|f| f.order_id == order.id && f.kind == "proof-unconfirmed"),
        "the flag is in the moderators' open queue"
    );

    // The seller confirms this order (per-order confirmation on an
    // already-Paid order): the attestation lands, the evidence level
    // records the seller's own confirmation, and the flag clears.
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    let state = confirm_payment(&pool, &order, seller_id, &c).await.unwrap();
    assert_eq!(format!("{state:?}"), "Paid");
    let (_, ev) = order_state(&pool, order.id).await;
    assert_eq!(
        ev, "SellerAttested",
        "the seller has now confirmed in their own name"
    );
    let att: Option<i64> =
        sqlx::query_scalar("SELECT pool_entry_id FROM payment_attestations WHERE order_id = $1")
            .bind(order.id)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(
        att.is_some(),
        "confirmation writes the per-order attestation"
    );
    let flags = payment_flags_for_order(&pool, order.id).await.unwrap();
    assert_eq!(flags.len(), 1, "the flag row is retained as a record");
    assert_eq!(
        flags[0].state, "cleared",
        "confirmation clears the flag automatically"
    );
    assert!(
        !open_payment_flags(&pool)
            .await
            .unwrap()
            .iter()
            .any(|f| f.order_id == order.id),
        "a cleared flag leaves the open queue"
    );

    cleanup(&pool, &[seller_id, buyer]).await;
}

// The declaration (4): refused before the 48h horizon.

#[tokio::test]
async fn declaration_refused_before_48h() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[0..4]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;

    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();

    // Only the seller declares, and only after the horizon.
    assert_eq!(
        declare_not_received(&pool, &order, buyer, &c).await,
        Err(PaymentError::NotSeller)
    );
    assert_eq!(
        declare_not_received(&pool, &order, seller_id, &c).await,
        Err(PaymentError::DeclarationTooEarly)
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM payment_declarations WHERE order_id = $1")
            .bind(order.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 0);

    cleanup(&pool, &[seller_id, buyer]).await;
}

// The declaration (4) on an unproofed order after 48h closes it as
// unpaid — the same end state the sweep produces (entry retired,
// buyer told), with the declaration itself on the record.

#[tokio::test]
async fn declaration_closes_unproofed_order_after_48h() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[4..8]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;

    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();

    backdate(&pool, order.id, 49).await;
    let state = declare_not_received(&pool, &order, seller_id, &c)
        .await
        .unwrap();
    assert_eq!(format!("{state:?}"), "Cancelled");
    let (st, _) = order_state(&pool, order.id).await;
    assert_eq!(st, "Cancelled");
    let entry_state: String =
        sqlx::query_scalar("SELECT state FROM payment_pool_entries WHERE order_id = $1")
            .bind(order.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        entry_state, "retired",
        "closing as unpaid retires the assigned address, as the sweep does"
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM payment_declarations WHERE order_id = $1")
            .bind(order.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 1, "the declaration itself is on the record");
    let buyer_notes: Vec<(String,)> =
        sqlx::query_as("SELECT event_type FROM notifications WHERE account_id = $1")
            .bind(buyer)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(
        buyer_notes.iter().any(|(t,)| t == "order_not_received"),
        "the buyer is told the seller declared non-receipt: {buyer_notes:?}"
    );

    // One declaration per order.
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    assert_eq!(
        declare_not_received(&pool, &order, seller_id, &c).await,
        Err(PaymentError::AlreadyDeclared)
    );

    cleanup(&pool, &[seller_id, buyer]).await;
}

// The declaration (4) with only a manual report on file: the
// declaration still closes the order as unpaid (a manual report does
// not block it), the report stays on the record, and the buyer keeps
// their dispute path against the declaration — the dispute reopens
// the order.

#[tokio::test]
async fn declaration_with_manual_report_closes_and_buyer_can_dispute() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[8..12]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;

    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    submit_manual_report(&pool, &order, buyer).await.unwrap();

    backdate(&pool, order.id, 49).await;
    let state = declare_not_received(&pool, &order, seller_id, &c)
        .await
        .unwrap();
    assert_eq!(
        format!("{state:?}"),
        "Cancelled",
        "a manual report does not block closure"
    );
    assert!(
        has_payment_report(&pool, order.id).await.unwrap(),
        "the manual report remains on the record after closure"
    );

    // The buyer's dispute path against the declaration is intact.
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    let state = apply_action(&pool, &order, "dispute", buyer).await.unwrap();
    assert_eq!(format!("{state:?}"), "Disputed");
    let d = app::disputes::dispute_for_order(&pool, order.id)
        .await
        .unwrap()
        .expect("the reopened dispute has its row");
    assert_eq!(d.state, "open");

    cleanup(&pool, &[seller_id, buyer]).await;
}

// Flag (3b) + declaration (4) with a proof on file: the declaration
// is recorded, the contradiction flag goes up immediately, and the
// order does NOT close on the declaration alone.

#[tokio::test]
async fn declaration_with_proof_flags_contradiction_and_does_not_close() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[0..4]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;

    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    submit_payment_proof(&pool, &order, buyer, TXID_A, PROOF_A, &c)
        .await
        .unwrap();

    backdate(&pool, order.id, 49).await;
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    let state = declare_not_received(&pool, &order, seller_id, &c)
        .await
        .unwrap();
    assert_eq!(
        format!("{state:?}"),
        "Paid",
        "a proof-backed order never closes on a declaration"
    );
    let (st, _) = order_state(&pool, order.id).await;
    assert_eq!(st, "Paid");
    let flags = payment_flags_for_order(&pool, order.id).await.unwrap();
    assert!(
        flags
            .iter()
            .any(|f| f.kind == "proof-contradiction" && f.state == "open"),
        "proof + not-received declaration is a direct contradiction, flagged at once: {flags:?}"
    );

    cleanup(&pool, &[seller_id, buyer]).await;
}

// A seller who already attested cannot turn around and declare
// non-receipt for the same order.

#[tokio::test]
async fn declaration_on_attested_paid_order_refused() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[4..8]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;

    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    mark_paid(&pool, &order, seller_id, &c).await.unwrap();

    backdate(&pool, order.id, 49).await;
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    assert_eq!(
        declare_not_received(&pool, &order, seller_id, &c).await,
        Err(PaymentError::OrderClosed)
    );

    cleanup(&pool, &[seller_id, buyer]).await;
}

// ---------------------------------------------------------------------------
// HTTP: the confirmation names its order + subaddress; the buyer's
// payment panel leads with the proof (how-to included) and keeps the
// manual confirm behind it as the weaker fallback.

#[tokio::test]
async fn confirm_and_manual_ui_over_http() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[0..4]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let addr = assignment_for_order(&pool, order.id, &c)
        .await
        .unwrap()
        .unwrap()
        .address;

    let srv = test_server(&pool).await;
    let seller_cookie = session_for(&pool, seller_id).await;
    let buyer_cookie = session_for(&pool, buyer).await;

    // Seller side: the confirmation names the order and the exact
    // subaddress being confirmed (design update #2.1).
    let (status, seller_view) = http(
        srv.addr,
        "GET",
        &format!("/orders/{}", order.public_id),
        Some(&seller_cookie),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        seller_view.contains("Confirm payment received"),
        "confirm action is offered"
    );
    assert!(
        seller_view.contains(&order.public_id),
        "confirmation names the order"
    );
    assert!(
        seller_view.contains(&addr),
        "confirmation names the subaddress"
    );

    // Buyer side: proof first, with the wallet how-to; the manual
    // confirm is present behind it, worded as weaker protection.
    let (status, buyer_view) = http(
        srv.addr,
        "GET",
        &format!("/orders/{}", order.public_id),
        Some(&buyer_cookie),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        buyer_view.contains("submit-proof"),
        "proof form is the primary path"
    );
    assert!(
        buyer_view.contains("get_tx_proof"),
        "the how-to names the CLI proof command"
    );
    assert!(buyer_view.contains("Feather"), "the how-to covers Feather");
    assert!(
        buyer_view.contains("manual-report"),
        "the manual fallback exists"
    );
    assert!(
        buyer_view.to_lowercase().contains("weaker"),
        "the manual fallback is worded as the weaker protection"
    );

    // The manual fallback works over HTTP and records BuyerReported.
    let csrf = csrf_from(&buyer_view);
    let (status, _) = http(
        srv.addr,
        "POST",
        &format!("/orders/{}/manual-report", order.public_id),
        Some(&buyer_cookie),
        Some(&format!("csrf={}", urlencode(&csrf))),
    )
    .await;
    assert_eq!(status, 303);
    let (_, ev) = order_state(&pool, order.id).await;
    assert_eq!(ev, "BuyerReported");

    // And the named confirmation works over HTTP too.
    let (status, seller_view) = http(
        srv.addr,
        "GET",
        &format!("/orders/{}", order.public_id),
        Some(&seller_cookie),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let csrf = csrf_from(&seller_view);
    let (status, _) = http(
        srv.addr,
        "POST",
        &format!("/orders/{}/confirm-payment", order.public_id),
        Some(&seller_cookie),
        Some(&format!("csrf={}", urlencode(&csrf))),
    )
    .await;
    assert_eq!(status, 303);
    let (st, _) = order_state(&pool, order.id).await;
    assert_eq!(st, "Paid");

    srv.handle.abort();
    let _ = std::fs::remove_dir_all(&srv.dir);
    cleanup(&pool, &[seller_id, buyer]).await;
}

// HTTP: the auto-review flag reaches the moderation queue, and the
// moderator's flag page shows the proof (the seller cannot open it).

#[tokio::test]
async fn moderation_queue_lists_flag_and_flag_page_shows_proof() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _spub, listing) = shop_with_pool(&pool, &SUBS[0..4]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    let (moderator, _) = make_account(&pool, "moderator").await;

    let (order, _) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();
    apply_action(&pool, &order, "accept", seller_id)
        .await
        .unwrap();
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
    submit_payment_proof(&pool, &order, buyer, TXID_A, PROOF_A, &c)
        .await
        .unwrap();
    let flag = payment_flags_for_order(&pool, order.id)
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("submission raised the flag");

    let srv = test_server(&pool).await;
    let mod_cookie = session_for(&pool, moderator).await;
    let seller_cookie = session_for(&pool, seller_id).await;

    let (status, queue) = http(srv.addr, "GET", "/moderation", Some(&mod_cookie), None).await;
    assert_eq!(status, 200);
    assert!(
        queue.contains(&order.public_id),
        "the open flag appears in the moderation queue"
    );

    let (status, flag_page) = http(
        srv.addr,
        "GET",
        &format!("/moderation/flags/{}", flag.id),
        Some(&mod_cookie),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        flag_page.contains(TXID_A),
        "moderators working the flag see the txid"
    );
    assert!(
        flag_page.contains(PROOF_A),
        "moderators working the flag see the proof"
    );

    let (status, _) = http(
        srv.addr,
        "GET",
        &format!("/moderation/flags/{}", flag.id),
        Some(&seller_cookie),
        None,
    )
    .await;
    assert_ne!(status, 200, "the flag page is moderator-only");

    srv.handle.abort();
    let _ = std::fs::remove_dir_all(&srv.dir);
    cleanup(&pool, &[seller_id, buyer, moderator]).await;
}
