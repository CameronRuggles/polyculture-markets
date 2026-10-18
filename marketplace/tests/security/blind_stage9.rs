//! Blind security suite — Stage 9: reviews, reputation, disputes,
//! disclosures, moderation, TOTP, account closure (spec §24 stage 9).
//!
//! AUTHORSHIP: written ONLY from spec §9/§13/§16/§20/§22/§24,
//! SPEC-V2-AMENDMENTS.md (incl. Direct Payments v1), migration
//! 0009_stage9.sql (schema = contract), modules-api public types, the
//! API contract supplied with the authoring task, prior locked suites
//! (fixture conventions only), and the rendered-surface templates named
//! in the contract. The Stage 9 implementation files were NOT read.
//!
//! OWNER RULING (2026-10-16) applied throughout: there is NO ban or
//! suspension tool and NO re-entry blocklist. The account-level action
//! is CLOSE ACCOUNT. This suite tests closure semantics only and never
//! asserts any suspension/ban behaviour.
//!
//! CONTRACT AMBIGUITIES (conservative readings taken):
//!  A1. crates/app/tests/fixtures/key-*.asc contain PUBLIC keys only, so
//!      no signature can be produced from them. Disclosure fixtures
//!      therefore generate fresh ed25519 keypairs at runtime with GnuPG
//!      (the blind_stage3 helper pattern) and register the generated
//!      certs as the parties' identity keys via app::keys.
//!  A2. `reviews_for_seller` / `summary_row` etc. return shapes are
//!      taken exactly as printed in the contract; where a field beyond
//!      the pinned ones is asserted (ReviewView score/text/reply), it is
//!      the natural reading of "ReviewView" for a review.
//!  A3. The refund-proposed step is asserted to record NO reputation
//!      fact for the order (contract: "no final fact outcome yet").
//!  A4. Raw-panel `account_age_days` for a 72h-old fixture account is
//!      asserted as a small range (2..=4) because the contract does not
//!      pin floor-vs-calendar-day rounding.

use app::disputes::{self, DisputeError};
use app::keyfile::KeyFile;
use app::moderation::{self, ModError};
use app::orders::{apply_action, create_order, inbox, order_by_public_id, orders_for};
use app::reputation::{self, Stage9Config};
use app::reviews::{self, ReviewError};
use app::totp;
use modules_api::{ReputationFact, ReputationModel};
use sqlx::{PgPool, Row};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const DB_URL_DEFAULT: &str = "postgres://postgres:dev@localhost/marketplace_dev";
const MARKETPLACE_ID: &str = "mkt_0123456789abcdef0123456789abcdef";

fn db_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| DB_URL_DEFAULT.to_string())
}
async fn pool() -> PgPool {
    PgPool::connect(&db_url()).await.expect("connect to marketplace_dev")
}
fn cfg() -> Stage9Config {
    Stage9Config::defaults()
}

// ---------------------------------------------------------------------
// Fixture helpers (constructions mirrored from blind_stage4/direct_v1)
// ---------------------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(1);
fn uniq128() -> u128 {
    let c = COUNTER.fetch_add(1, Ordering::SeqCst) as u128;
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    t ^ (c << 100) ^ ((std::process::id() as u128) << 64)
}
fn uniq_name() -> String {
    format!("u{:016x}", (uniq128() & 0xffff_ffff_ffff_ffff) as u64)
}
fn acct_public_id() -> String {
    format!("acct_{:032x}", uniq128())
}
fn listing_public_id() -> String {
    format!("lst_{:032x}", uniq128())
}
fn fingerprint(seed: u128) -> String {
    format!("{:040X}", seed & 0xffff_ffff_ffff_ffff_ffffu128)
}
fn idem() -> String {
    format!("idem-{:032x}", uniq128())
}

/// (internal id, public id)
async fn make_account(pool: &PgPool, role: &str, age_hours: i64) -> (i64, String) {
    let username = uniq_name();
    let public_id = acct_public_id();
    let created = time::OffsetDateTime::now_utc() - time::Duration::hours(age_hours);
    let row = sqlx::query(
        "INSERT INTO accounts (public_id, username, password_hash, role, created_at) \
         VALUES ($1, $2, 'blind-suite-fixture-hash', $3, $4) RETURNING id",
    )
    .bind(&public_id)
    .bind(&username)
    .bind(role)
    .bind(created)
    .fetch_one(pool)
    .await
    .expect("insert account fixture");
    (row.get::<i64, _>("id"), public_id)
}

async fn install_dummy_key(pool: &PgPool, account_id: i64, fpr: &str) {
    sqlx::query(
        "INSERT INTO identity_keys (account_id, certificate, fingerprint, version, status, created_at) \
         VALUES ($1, $2, $3, 1, 'current', now())",
    )
    .bind(account_id)
    .bind(b"blind-suite-dummy-certificate".to_vec())
    .bind(fpr)
    .execute(pool)
    .await
    .expect("insert identity key fixture");
}

struct ListingFixture {
    public_id: String,
    internal_id: i64,
}
async fn make_listing(pool: &PgPool, seller_id: i64, title: &str) -> ListingFixture {
    let public_id = listing_public_id();
    let row = sqlx::query(
        "INSERT INTO listings (public_id, seller_id, title, description, price_atomic, \
                               pricing_module, destination_module, auto_invoice, status, \
                               delivery_terms, refund_terms) \
         VALUES ($1, $2, $3, $4, 1000000, 'xmr-only', 'signed-address-pool', false, 'published', $5, $6) \
         RETURNING id",
    )
    .bind(&public_id)
    .bind(seller_id)
    .bind(title)
    .bind("A widget described plainly.")
    .bind("Delivery within 3 days.")
    .bind("Refunds within 7 days.")
    .fetch_one(pool)
    .await
    .expect("insert listing fixture");
    ListingFixture { public_id, internal_id: row.get::<i64, _>("id") }
}

struct Shop {
    seller_id: i64,
    seller_pub: String,
    listing: ListingFixture,
}
async fn make_shop(pool: &PgPool) -> Shop {
    let (seller_id, seller_pub) = make_account(pool, "seller", 72).await;
    install_dummy_key(pool, seller_id, &fingerprint(uniq128())).await;
    let listing = make_listing(pool, seller_id, "Blind Suite Widget").await;
    Shop { seller_id, seller_pub, listing }
}
async fn make_buyer(pool: &PgPool) -> i64 {
    make_account(pool, "buyer", 72).await.0
}
async fn make_moderator(pool: &PgPool) -> i64 {
    make_account(pool, "moderator", 72).await.0
}

fn test_keyfile() -> KeyFile {
    let dir = std::env::temp_dir().join(format!("blind9-kf-{}-{:x}", std::process::id(), uniq128()));
    std::fs::create_dir_all(&dir).expect("create keyfile dir");
    KeyFile::load_or_generate(&dir.join("keyfile")).expect("load_or_generate keyfile")
}

async fn fresh_order(pool: &PgPool, shop: &Shop, buyer_id: i64) -> app::orders::Order {
    let (order, created) = create_order(pool, MARKETPLACE_ID, buyer_id, &shop.listing.public_id, 1, &idem())
        .await
        .expect("create order");
    assert!(created);
    order
}

/// Fixture construction only: force state/evidence/terminal stamp at the
/// DB level (the Stage 4 suites' force_order_state pattern).
async fn force_order(pool: &PgPool, order_id: i64, state: &str, evidence: &str) {
    sqlx::query(
        "UPDATE orders SET state = $1, evidence_level = $2, \
         terminal_at = CASE WHEN $1 IN ('Completed','Resolved','Cancelled','Declined') THEN now() ELSE terminal_at END \
         WHERE id = $3",
    )
    .bind(state)
    .bind(evidence)
    .bind(order_id)
    .execute(pool)
    .await
    .expect("force order state fixture");
}

async fn completed_order(pool: &PgPool, shop: &Shop, buyer_id: i64) -> app::orders::Order {
    let order = fresh_order(pool, shop, buyer_id).await;
    force_order(pool, order.id, "Completed", "SellerAttested").await;
    order_by_public_id(pool, &order.public_id).await.unwrap()
}

async fn has_event(pool: &PgPool, account_id: i64, event_type: &str) -> bool {
    inbox(pool, account_id).await.iter().any(|e| e.1 == event_type)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn fact(token: u8, bucket: u8, evidence: u8, score: u8, month: &str) -> ReputationFact {
    ReputationFact {
        seller_id: "seller-fixture".to_string(),
        buyer_token: [token; 32],
        maturity_bucket: bucket,
        evidence_level: evidence,
        outcome: 0,
        score: Some(score),
        month: month.to_string(),
    }
}
fn approx(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

// =====================================================================
// Config, KeyFile, TOTP (pure)
// =====================================================================

#[test]
fn config_defaults_match_contract() {
    let c = cfg();
    assert_eq!(c.model, "weighted-reviews-v1");
    assert_eq!(c.maturity_min_age_days, 30);
    assert_eq!(c.maturity_min_orders, 3);
    assert_eq!(c.maturity_min_sellers, 2);
    assert!(approx(c.mature_weight, 1.0));
    assert!(approx(c.immature_weight, 0.3));
    assert!(approx(c.evidence_verified_weight, 1.0));
    assert!(approx(c.evidence_unverified_weight, 0.6));
    assert_eq!(c.repeat_window_days, 90);
    assert!(approx(c.min_total_weight, 5.0));
    assert_eq!(c.review_edit_window_days, 7);
    assert_eq!(c.review_max_chars, 1000);
    assert_eq!(c.disclosure_retention_days, 180);
}

#[test]
fn keyfile_buyer_token_deterministic_pair_specific_32_bytes() {
    let kf = test_keyfile();
    let t1 = kf.buyer_token(11, 22);
    assert_eq!(t1.len(), 32);
    assert_eq!(t1, kf.buyer_token(11, 22), "same (seller,buyer) pair must give the same token");
    assert_ne!(t1, kf.buyer_token(99, 22), "same buyer, different seller must give a different token");
    assert_ne!(t1, kf.buyer_token(11, 23), "different buyer must give a different token");
}

#[test]
fn keyfile_encrypt_decrypt_roundtrip_and_reload_keeps_token() {
    let dir = std::env::temp_dir().join(format!("blind9-kf2-{}-{:x}", std::process::id(), uniq128()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("keyfile");
    let kf = KeyFile::load_or_generate(&path).expect("generate");
    assert!(path.exists(), "load_or_generate must create the key file");
    let msg = b"blind stage9 disclosure plaintext fixture";
    let ct = kf.encrypt(msg);
    assert!(!contains(&ct, msg), "ciphertext must not contain the plaintext");
    assert_eq!(kf.decrypt(&ct).as_deref(), Some(&msg[..]));
    let kf2 = KeyFile::load_or_generate(&path).expect("reload");
    assert_eq!(kf2.buyer_token(5, 6), kf.buyer_token(5, 6), "reloading the same key file must keep tokens stable");
    assert_eq!(kf2.decrypt(&ct).as_deref(), Some(&msg[..]));
}

#[test]
fn totp_rfc6238_sha1_vectors() {
    let seed: [u8; 20] = *b"12345678901234567890";
    assert_eq!(totp::code_at(&seed, 59), "287082");
    assert_eq!(totp::code_at(&seed, 1111111109), "081804");
    assert_eq!(totp::code_at(&seed, 1234567890), "005924");
}

#[test]
fn totp_verify_window_is_plus_minus_one_step() {
    let seed: [u8; 20] = *b"12345678901234567890";
    let t: u64 = 1234567890;
    let code = totp::code_at(&seed, t);
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert!(totp::verify(&seed, &code, t));
    assert!(totp::verify(&seed, &code, t + 30), "one step late must still verify");
    assert!(totp::verify(&seed, &code, t - 30), "one step early must still verify");
    assert!(!totp::verify(&seed, &code, t + 60), "two steps away must fail");
    assert!(!totp::verify(&seed, &code, t - 60), "two steps away must fail");
}

#[test]
fn totp_base32_roundtrip() {
    let secret = totp::generate_secret();
    assert_eq!(secret.len(), 20);
    let enc = totp::base32_encode(&secret);
    assert_eq!(enc.len(), 32, "20 bytes base32-encode to 32 chars");
    let dec = totp::base32_decode(&enc).expect("decode own encoding");
    assert_eq!(dec, secret.to_vec());
}

// =====================================================================
// Weight math (pure, constructed ReputationFact values)
// =====================================================================

#[test]
fn weight_single_mature_verified_fact() {
    let m = app::reputation::WeightedReviewsV1 { cfg: cfg() };
    let s = m.summarize(&[fact(1, 1, 3, 5, "2026-05")]);
    assert!(approx(s.total_weight, 1.0), "mature x verified = 1.0, got {}", s.total_weight);
    assert_eq!(s.established_buyers, 1);
    assert!(s.weighted_score.is_none(), "weight 1.0 is below the 5.0 threshold");
    // WalletObserved (level 4) is also verified-tier.
    let s = m.summarize(&[fact(1, 1, 4, 5, "2026-05")]);
    assert!(approx(s.total_weight, 1.0));
}

#[test]
fn weight_maturity_and_evidence_factors() {
    let m = app::reputation::WeightedReviewsV1 { cfg: cfg() };
    // Immature x verified = 0.3
    let s = m.summarize(&[fact(1, 0, 3, 5, "2026-05")]);
    assert!(approx(s.total_weight, 0.3), "got {}", s.total_weight);
    assert_eq!(s.established_buyers, 0);
    // Mature x SellerAttested (level 2, unverified tier) = 0.6
    let s = m.summarize(&[fact(1, 1, 2, 5, "2026-05")]);
    assert!(approx(s.total_weight, 0.6), "got {}", s.total_weight);
    // Immature x attested = 0.18
    let s = m.summarize(&[fact(1, 0, 2, 5, "2026-05")]);
    assert!(approx(s.total_weight, 0.18), "got {}", s.total_weight);
    // Unscored facts contribute nothing.
    let mut f = fact(1, 1, 3, 5, "2026-05");
    f.score = None;
    let s = m.summarize(&[f]);
    assert!(approx(s.total_weight, 0.0));
    assert_eq!(s.established_buyers, 0);
}

#[test]
fn weight_repeat_same_month_is_one_over_k() {
    let m = app::reputation::WeightedReviewsV1 { cfg: cfg() };
    let facts = vec![
        fact(7, 1, 3, 5, "2026-05"),
        fact(7, 1, 3, 3, "2026-05"),
        fact(7, 1, 3, 4, "2026-05"),
    ];
    let s = m.summarize(&facts);
    let expected = 1.0 + 1.0 / 2.0 + 1.0 / 3.0;
    assert!(approx(s.total_weight, expected), "repeat weights 1, 1/2, 1/3: got {}", s.total_weight);
    assert_eq!(s.established_buyers, 1, "one distinct established token");
}

#[test]
fn weight_repeat_window_two_months_counts_three_does_not() {
    let m = app::reputation::WeightedReviewsV1 { cfg: cfg() };
    // Jan -> Mar: the earlier fact is within the two preceding calendar
    // months of March, so k=2 for the second fact.
    let s = m.summarize(&[fact(7, 1, 3, 5, "2026-01"), fact(7, 1, 3, 5, "2026-03")]);
    assert!(approx(s.total_weight, 1.5), "Jan+Mar must total 1.5, got {}", s.total_weight);
    // Jan -> Apr: three months apart, outside the window, k=1 again.
    // (Inserted in reverse order: processing is in (month, insertion)
    // order, so the result must be the same.)
    let s = m.summarize(&[fact(7, 1, 3, 5, "2026-04"), fact(7, 1, 3, 5, "2026-01")]);
    assert!(approx(s.total_weight, 2.0), "Jan+Apr must total 2.0, got {}", s.total_weight);
    // Same month always counts even across a year boundary backwards:
    // Dec 2025 -> Feb 2026 is within two preceding months.
    let s = m.summarize(&[fact(7, 1, 3, 5, "2025-12"), fact(7, 1, 3, 5, "2026-02")]);
    assert!(approx(s.total_weight, 1.5), "Dec+Feb must total 1.5, got {}", s.total_weight);
}

#[test]
fn weight_threshold_4_8_is_none_5_0_is_some_with_weighted_mean() {
    let m = app::reputation::WeightedReviewsV1 { cfg: cfg() };
    // 8 distinct mature attested buyers: 8 x 0.6 = 4.8 < 5.0.
    let facts: Vec<_> = (0..8u8).map(|i| fact(10 + i, 1, 2, 4, "2026-05")).collect();
    let s = m.summarize(&facts);
    assert!(approx(s.total_weight, 4.8), "got {}", s.total_weight);
    assert!(s.weighted_score.is_none(), "total weight 4.8 must show Not enough history");
    // 5 distinct mature verified buyers: total 5.0, mean (5+4+5+3+5)/5 = 4.4
    let facts: Vec<_> = [5u8, 4, 5, 3, 5]
        .iter()
        .enumerate()
        .map(|(i, sc)| fact(30 + i as u8, 1, 3, *sc, "2026-05"))
        .collect();
    let s = m.summarize(&facts);
    assert!(approx(s.total_weight, 5.0), "got {}", s.total_weight);
    let score = s.weighted_score.expect("total weight 5.0 must yield a score");
    assert!(approx(score, 4.4), "weighted mean must be 4.4, got {score}");
    assert_eq!(s.established_buyers, 5);
}

#[test]
fn raw_counts_model_returns_no_score_and_zero_weight() {
    let m = app::reputation::RawCounts;
    let s = m.summarize(&[fact(1, 1, 3, 5, "2026-05"), fact(2, 1, 4, 1, "2026-05")]);
    assert!(s.weighted_score.is_none());
    assert!(approx(s.total_weight, 0.0));
}

// =====================================================================
// Facts pipeline
// =====================================================================

#[tokio::test]
async fn fact_minimization_token_equality_and_schema() {
    let pool = pool().await;
    let kf = test_keyfile();
    let shop = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let order = completed_order(&pool, &shop, buyer).await;
    reviews::submit_review(&pool, &kf, &cfg(), &order.public_id, buyer, 5, "Exactly as described.")
        .await
        .expect("review on completed order");

    // A review on a terminal order already yields the order's fact
    // (its score must mirror the review), so record_fact_for_order is
    // the idempotent second call here: it writes nothing, returns
    // false, and the single fact below is the one under test.
    let wrote = reputation::record_fact_for_order(&pool, &kf, &cfg(), order.id).await.expect("record fact");
    assert!(!wrote, "the reviewed order's fact already exists; recording must be idempotent");
    let facts = reputation::facts_for_seller(&pool, shop.seller_id).await.expect("facts_for_seller");
    assert_eq!(facts.len(), 1);
    let f = &facts[0];
    let expected_token = kf.buyer_token(shop.seller_id, buyer);
    assert_eq!(f.buyer_token, expected_token, "stored token must equal KeyFile::buyer_token(seller, buyer)");
    assert_eq!(f.buyer_token.len(), 32);
    assert_eq!(f.evidence_level, 2, "under Direct Payments v1 evidence is SellerAttested (2)");
    assert_eq!(f.outcome, 0, "completed outcome code 0");
    assert_eq!(f.score, Some(5), "score mirrors the order's review");
    let month: String = sqlx::query_scalar("SELECT to_char(now() AT TIME ZONE 'UTC','YYYY-MM')")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(f.month, month, "month is the order's terminal month, YYYY-MM");
    // The token is not any plain encoding of the buyer id alone.
    let mut be = [0u8; 32];
    be[..8].copy_from_slice(&buyer.to_be_bytes());
    let mut le = [0u8; 32];
    le[..8].copy_from_slice(&buyer.to_le_bytes());
    assert_ne!(f.buyer_token, be);
    assert_ne!(f.buyer_token, le);
    // Schema (contract): reputation_facts has NO buyer-identifying column.
    let buyer_id_cols: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns \
         WHERE table_name = 'reputation_facts' AND column_name IN ('buyer_id','buyer','buyer_public_id')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(buyer_id_cols, 0, "reputation_facts must carry no buyer-identifying column");
    let row_token: Vec<u8> = sqlx::query_scalar("SELECT buyer_token FROM reputation_facts WHERE order_id = $1")
        .bind(order.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row_token, expected_token.to_vec());
}

#[tokio::test]
async fn fact_token_unlinkable_across_sellers_same_for_same_pair() {
    let pool = pool().await;
    let kf = test_keyfile();
    let shop_a = make_shop(&pool).await;
    let shop_b = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let o1 = completed_order(&pool, &shop_a, buyer).await;
    let o2 = completed_order(&pool, &shop_b, buyer).await;
    let o3 = completed_order(&pool, &shop_a, buyer).await;
    for o in [&o1, &o2, &o3] {
        assert!(reputation::record_fact_for_order(&pool, &kf, &cfg(), o.id).await.unwrap());
    }
    let fa = reputation::facts_for_seller(&pool, shop_a.seller_id).await.expect("facts_for_seller");
    let fb = reputation::facts_for_seller(&pool, shop_b.seller_id).await.expect("facts_for_seller");
    assert_eq!(fa.len(), 2);
    assert_eq!(fb.len(), 1);
    assert_eq!(fa[0].buyer_token, fa[1].buyer_token, "same (seller,buyer) pair must reuse the token (repeat counting)");
    assert_ne!(fa[0].buyer_token, fb[0].buyer_token, "same buyer must be unlinkable across sellers");
    assert_eq!(fb[0].buyer_token, kf.buyer_token(shop_b.seller_id, buyer));
}

#[tokio::test]
async fn fact_record_is_idempotent_and_nonterminal_orders_have_none() {
    let pool = pool().await;
    let kf = test_keyfile();
    let shop = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let open = fresh_order(&pool, &shop, buyer).await;
    let wrote = reputation::record_fact_for_order(&pool, &kf, &cfg(), open.id).await.unwrap();
    assert!(!wrote, "a non-terminal order must produce no fact");
    assert_eq!(reputation::facts_for_seller(&pool, shop.seller_id).await.expect("facts_for_seller").len(), 0);

    let done = completed_order(&pool, &shop, buyer).await;
    assert!(reputation::record_fact_for_order(&pool, &kf, &cfg(), done.id).await.unwrap());
    let again = reputation::record_fact_for_order(&pool, &kf, &cfg(), done.id).await.unwrap();
    assert!(!again, "second recording must write nothing and return false");
    assert_eq!(reputation::facts_for_seller(&pool, shop.seller_id).await.expect("facts_for_seller").len(), 1);
}

/// Build priors + a target order and return the target fact's bucket.
async fn maturity_bucket(pool: &PgPool, buyer_age_days: i64, priors: &[(usize, bool)]) -> u8 {
    // priors: (order count, unused) grouped per distinct prior seller
    let kf = test_keyfile();
    let (buyer, _) = make_account(pool, "buyer", buyer_age_days * 24).await;
    for (count, _) in priors {
        let shop = make_shop(pool).await;
        for _ in 0..*count {
            let o = fresh_order(pool, &shop, buyer).await;
            sqlx::query("UPDATE orders SET state='Completed', evidence_level='SellerAttested', terminal_at=now()-interval '2 days', created_at=now()-interval '2 days' WHERE id=$1")
                .bind(o.id).execute(pool).await.unwrap();
        }
    }
    let target = make_shop(pool).await;
    let order = completed_order(pool, &target, buyer).await;
    assert!(reputation::record_fact_for_order(pool, &kf, &cfg(), order.id).await.unwrap());
    let facts = reputation::facts_for_seller(pool, target.seller_id).await.expect("facts_for_seller");
    assert_eq!(facts.len(), 1);
    facts[0].maturity_bucket
}

#[tokio::test]
async fn maturity_young_buyer_is_bucket_zero_even_with_many_orders() {
    let pool = pool().await;
    // 10 days old, 4 prior completed orders across 2 sellers.
    let b = maturity_bucket(&pool, 10, &[(2, false), (2, false)]).await;
    assert_eq!(b, 0, "account <30 days old at order time is never mature");
}

#[tokio::test]
async fn maturity_needs_at_least_three_prior_completed_orders() {
    let pool = pool().await;
    // 60 days old, only 2 prior completed orders across 2 sellers.
    let b = maturity_bucket(&pool, 60, &[(1, false), (1, false)]).await;
    assert_eq!(b, 0);
}

#[tokio::test]
async fn maturity_needs_priors_from_at_least_two_sellers() {
    let pool = pool().await;
    // 60 days old, 3 prior completed orders all from ONE seller.
    let b = maturity_bucket(&pool, 60, &[(3, false)]).await;
    assert_eq!(b, 0);
}

#[tokio::test]
async fn maturity_mature_buyer_is_bucket_one() {
    let pool = pool().await;
    // 60 days old, 3 prior completed orders across 2 sellers.
    let b = maturity_bucket(&pool, 60, &[(2, false), (1, false)]).await;
    assert_eq!(b, 1);
}

#[tokio::test]
async fn raw_panel_counts_only_the_completed_outcome_set() {
    let pool = pool().await;
    let kf = test_keyfile();
    let shop = make_shop(&pool).await;
    let b1 = make_buyer(&pool).await;
    let b2 = make_buyer(&pool).await;
    // Two completed (distinct buyers), one cancelled, one declined.
    let o1 = completed_order(&pool, &shop, b1).await;
    let o2 = completed_order(&pool, &shop, b2).await;
    let oc = fresh_order(&pool, &shop, b1).await;
    apply_action(&pool, &oc, "cancel", b1).await.expect("buyer cancels Requested");
    let od = fresh_order(&pool, &shop, b2).await;
    apply_action(&pool, &od, "decline", shop.seller_id).await.expect("seller declines Requested");
    for o in [&o1, &o2, &oc, &od] {
        reputation::record_fact_for_order(&pool, &kf, &cfg(), o.id).await.unwrap();
    }
    let raw = reputation::raw_facts(&pool, shop.seller_id).await.expect("raw_facts");
    assert_eq!(raw.completed_orders, 2, "cancelled/declined facts must not count as completed");
    assert_eq!(raw.distinct_buyers, 2);
    assert_eq!(raw.seller_confirmed_payments, 2, "both completed facts are SellerAttested");
    assert_eq!(raw.verified_payments, 0, "no payment is verified under v1");
    assert_eq!(raw.disputes_opened, 0);
    assert_eq!(raw.disputes_against_seller, 0);
    assert!(raw.first_sale_month.is_some(), "a completed sale sets first_sale_month");
    assert!((2..=4).contains(&raw.account_age_days), "72h-old seller: age days in 2..=4, got {}", raw.account_age_days);
    assert_eq!(raw.member_since_month.len(), 7, "member_since_month is YYYY-MM");
}

#[tokio::test]
async fn sync_facts_stores_summary_with_model_id() {
    let pool = pool().await;
    let kf = test_keyfile();
    let shop = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let order = completed_order(&pool, &shop, buyer).await;
    reviews::submit_review(&pool, &kf, &cfg(), &order.public_id, buyer, 5, "Scored for the summary.")
        .await
        .unwrap();
    reputation::sync_facts_for_seller(&pool, &kf, &cfg(), shop.seller_id).await.expect("sync facts");
    let row = reputation::summary_row(&pool, shop.seller_id)
        .await
        .expect("summary_row").expect("a stored summary must exist after sync");
    assert_eq!(row.model_id, "weighted-reviews-v1");
    assert!(row.weighted_score.is_none(), "one attested immature fact is far below the threshold");
    assert!(approx(row.total_weight, 0.18), "one immature attested scored fact weighs 0.3 x 0.6 = 0.18, got {}", row.total_weight);
}

// =====================================================================
// Reviews
// =====================================================================

#[tokio::test]
async fn review_before_completion_is_bad_state_and_nonbuyers_forbidden() {
    let pool = pool().await;
    let kf = test_keyfile();
    let shop = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let stranger = make_buyer(&pool).await;
    let order = fresh_order(&pool, &shop, buyer).await; // Requested
    let err = reviews::submit_review(&pool, &kf, &cfg(), &order.public_id, buyer, 5, "Too soon.")
        .await
        .expect_err("review before completion must be refused");
    assert!(matches!(err, ReviewError::BadState), "got {err:?}");
    let done = completed_order(&pool, &shop, buyer).await;
    for actor in [shop.seller_id, stranger] {
        let err = reviews::submit_review(&pool, &kf, &cfg(), &done.public_id, actor, 5, "Not mine.")
            .await
            .expect_err("only the order's buyer may review");
        assert!(matches!(err, ReviewError::Forbidden), "actor {actor}: got {err:?}");
    }
    let err = reviews::submit_review(&pool, &kf, &cfg(), "ord_00000000000000000000000000000000", buyer, 5, "Ghost.")
        .await
        .expect_err("unknown order must be refused");
    assert!(matches!(err, ReviewError::NotFound), "got {err:?}");
}

#[tokio::test]
async fn review_score_bounds_length_and_empty() {
    let pool = pool().await;
    let kf = test_keyfile();
    let shop = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let order = completed_order(&pool, &shop, buyer).await;
    for bad in [0, 6, -1] {
        let err = reviews::submit_review(&pool, &kf, &cfg(), &order.public_id, buyer, bad, "Fine text.")
            .await
            .expect_err("score outside 1..=5 must be refused");
        assert!(matches!(err, ReviewError::BadScore), "score {bad}: got {err:?}");
    }
    let long = "x".repeat(1001);
    let err = reviews::submit_review(&pool, &kf, &cfg(), &order.public_id, buyer, 5, &long)
        .await
        .expect_err("1001 chars must be refused");
    assert!(matches!(err, ReviewError::TooLong), "got {err:?}");
    let err = reviews::submit_review(&pool, &kf, &cfg(), &order.public_id, buyer, 5, "")
        .await
        .expect_err("empty review must be refused");
    assert!(matches!(err, ReviewError::Empty), "got {err:?}");
    // Exactly 1000 chars succeeds.
    let max = "y".repeat(1000);
    reviews::submit_review(&pool, &kf, &cfg(), &order.public_id, buyer, 4, &max)
        .await
        .expect("1000 chars is the bound and must succeed");
}

#[tokio::test]
async fn review_resubmit_within_window_edits_the_single_row() {
    let pool = pool().await;
    let kf = test_keyfile();
    let shop = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let order = completed_order(&pool, &shop, buyer).await;
    reviews::submit_review(&pool, &kf, &cfg(), &order.public_id, buyer, 5, "First take.")
        .await
        .unwrap();
    reviews::submit_review(&pool, &kf, &cfg(), &order.public_id, buyer, 2, "Second thoughts.")
        .await
        .expect("re-submitting within 7 days edits the review");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE order_id = $1")
        .bind(order.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "an edit must not create a second review row");
    let view = reviews::review_for_order(&pool, &cfg(), order.id).await.expect("review_for_order").expect("review view");
    assert_eq!(view.score, 2);
    assert_eq!(view.text, "Second thoughts.");
}

#[tokio::test]
async fn review_edit_after_seven_days_is_closed() {
    let pool = pool().await;
    let kf = test_keyfile();
    let shop = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let order = completed_order(&pool, &shop, buyer).await;
    reviews::submit_review(&pool, &kf, &cfg(), &order.public_id, buyer, 4, "Original.")
        .await
        .unwrap();
    sqlx::query("UPDATE reviews SET created_at = now() - interval '8 days', updated_at = now() - interval '8 days' WHERE order_id = $1")
        .bind(order.id)
        .execute(&pool)
        .await
        .unwrap();
    let err = reviews::submit_review(&pool, &kf, &cfg(), &order.public_id, buyer, 1, "Too late.")
        .await
        .expect_err("editing after 7 days must be refused");
    assert!(matches!(err, ReviewError::EditWindowClosed), "got {err:?}");
}

#[tokio::test]
async fn seller_reply_once_only_by_seller_and_needs_a_review() {
    let pool = pool().await;
    let kf = test_keyfile();
    let shop = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let unreviewed = completed_order(&pool, &shop, buyer).await;
    let err = reviews::seller_reply(&pool, &cfg(), &unreviewed.public_id, shop.seller_id, "Thanks!")
        .await
        .expect_err("reply with no review must be refused");
    assert!(matches!(err, ReviewError::NoReview), "got {err:?}");

    let order = completed_order(&pool, &shop, buyer).await;
    reviews::submit_review(&pool, &kf, &cfg(), &order.public_id, buyer, 5, "Great.")
        .await
        .unwrap();
    let err = reviews::seller_reply(&pool, &cfg(), &order.public_id, buyer, "I reply to myself?")
        .await
        .expect_err("the buyer may not post the seller reply");
    assert!(matches!(err, ReviewError::Forbidden), "got {err:?}");
    reviews::seller_reply(&pool, &cfg(), &order.public_id, shop.seller_id, "Thank you!")
        .await
        .expect("seller reply must succeed");
    let err = reviews::seller_reply(&pool, &cfg(), &order.public_id, shop.seller_id, "Again.")
        .await
        .expect_err("exactly one seller reply");
    assert!(matches!(err, ReviewError::AlreadyReplied), "got {err:?}");
    let view = reviews::review_for_order(&pool, &cfg(), order.id).await.expect("review_for_order").expect("review exists");
    assert_eq!(view.seller_reply.as_deref(), Some("Thank you!"));
    let listed = reviews::reviews_for_seller(&pool, &cfg(), shop.seller_id).await.expect("reviews_for_seller");
    assert!(listed.iter().any(|r| r.text == "Great."), "seller review list must include the review");
}

#[tokio::test]
async fn review_badge_is_false_under_seller_attested_v1() {
    let pool = pool().await;
    let kf = test_keyfile();
    let shop = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let order = completed_order(&pool, &shop, buyer).await; // evidence SellerAttested
    reviews::submit_review(&pool, &kf, &cfg(), &order.public_id, buyer, 5, "Paid and delivered.")
        .await
        .unwrap();
    reputation::record_fact_for_order(&pool, &kf, &cfg(), order.id).await.unwrap();
    let view = reviews::review_for_order(&pool, &cfg(), order.id).await.expect("review_for_order").expect("review exists");
    assert!(
        !view.payment_verified_badge,
        "SellerAttested evidence must never render a payment-verified badge"
    );
    let listed = reviews::reviews_for_seller(&pool, &cfg(), shop.seller_id).await.expect("reviews_for_seller");
    assert!(listed.iter().all(|r| !r.payment_verified_badge));
}

// =====================================================================
// Disputes
// =====================================================================

async fn disputed_order(pool: &PgPool, shop: &Shop, buyer: i64) -> (app::orders::Order, i64) {
    let order = fresh_order(pool, shop, buyer).await;
    force_order(pool, order.id, "Paid", "SellerAttested").await;
    let order = order_by_public_id(pool, &order.public_id).await.unwrap();
    apply_action(pool, &order, "dispute", buyer).await.expect("buyer disputes a Paid order");
    let d = disputes::dispute_for_order(pool, order.id)
        .await
        .expect("dispute_for_order").expect("opening a dispute must create a disputes row atomically");
    assert_eq!(d.state, "open");
    assert_eq!(d.opened_by, buyer);
    (order_by_public_id(pool, &order.public_id).await.unwrap(), d.id)
}

#[tokio::test]
async fn dispute_seller_at_fault_finalizes_with_fact_and_notices() {
    let pool = pool().await;
    let kf = test_keyfile();
    let shop = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let moderator = make_moderator(&pool).await;
    let (order, dispute_id) = disputed_order(&pool, &shop, buyer).await;
    disputes::resolve(&pool, &kf, &cfg(), dispute_id, moderator, "seller-at-fault")
        .await
        .expect("moderator resolves seller-at-fault");
    let d = disputes::get_dispute(&pool, dispute_id).await.expect("get_dispute").expect("dispute exists");
    assert_eq!(d.state, "resolved");
    assert_eq!(d.outcome.as_deref(), Some("seller-at-fault"));
    assert_eq!(d.outcome_state, "final");
    assert_eq!(d.resolved_by, Some(moderator));
    assert_eq!(order_by_public_id(&pool, &order.public_id).await.unwrap().state, "Resolved");
    let facts = reputation::facts_for_seller(&pool, shop.seller_id).await.expect("facts_for_seller");
    assert!(
        facts.iter().any(|f| f.outcome == 3),
        "seller-at-fault resolution must record a fact with outcome code 3, got {:?}",
        facts.iter().map(|f| f.outcome).collect::<Vec<_>>()
    );
    let raw = reputation::raw_facts(&pool, shop.seller_id).await.expect("raw_facts");
    assert_eq!(raw.disputes_against_seller, 1);
    assert_eq!(raw.disputes_opened, 1);
    assert!(has_event(&pool, buyer, "dispute_resolved").await, "buyer must be notified");
    assert!(has_event(&pool, shop.seller_id, "dispute_resolved").await, "seller must be notified");
}

#[tokio::test]
async fn dispute_resolve_rejects_bad_outcome_and_closed_disputes() {
    let pool = pool().await;
    let kf = test_keyfile();
    let shop = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let moderator = make_moderator(&pool).await;
    let (order, dispute_id) = disputed_order(&pool, &shop, buyer).await;
    let err = disputes::resolve(&pool, &kf, &cfg(), dispute_id, moderator, "banana")
        .await
        .expect_err("an outcome outside the closed set must be refused");
    assert!(matches!(err, DisputeError::BadOutcome), "got {err:?}");
    assert_eq!(disputes::get_dispute(&pool, dispute_id).await.expect("get_dispute").expect("dispute exists").state, "open");
    // Buyer withdraws: completing from Disputed closes the dispute.
    let disputed = order_by_public_id(&pool, &order.public_id).await.unwrap();
    apply_action(&pool, &disputed, "complete", buyer).await.expect("buyer withdraws the dispute");
    let d = disputes::get_dispute(&pool, dispute_id).await.expect("get_dispute").expect("dispute exists");
    assert_eq!(d.state, "closed");
    assert_eq!(d.outcome.as_deref(), Some("withdrawn"));
    let err = disputes::resolve(&pool, &kf, &cfg(), dispute_id, moderator, "unresolved")
        .await
        .expect_err("resolving a withdrawn/closed dispute must be refused");
    assert!(matches!(err, DisputeError::BadState), "got {err:?}");
}

#[tokio::test]
async fn dispute_refund_confirmed_is_a_two_step_outcome() {
    let pool = pool().await;
    let kf = test_keyfile();
    let shop = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let moderator = make_moderator(&pool).await;
    let (order, dispute_id) = disputed_order(&pool, &shop, buyer).await;
    disputes::resolve(&pool, &kf, &cfg(), dispute_id, moderator, "refund-confirmed")
        .await
        .expect("moderator proposes refund-confirmed");
    let d = disputes::get_dispute(&pool, dispute_id).await.expect("get_dispute").expect("dispute exists");
    assert_eq!(d.state, "awaiting_buyer_confirmation");
    assert_eq!(d.outcome_state, "proposed");
    assert_eq!(
        order_by_public_id(&pool, &order.public_id).await.unwrap().state,
        "Disputed",
        "a proposed refund must not finalize the order"
    );
    let fact_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reputation_facts WHERE order_id = $1")
        .bind(order.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(fact_rows, 0, "no final fact outcome exists before buyer confirmation (A3)");
    assert!(has_event(&pool, buyer, "dispute_refund_proposed").await, "buyer must be told a refund was proposed");
    // Only the buyer can confirm.
    let err = disputes::confirm_refund(&pool, &kf, &cfg(), dispute_id, shop.seller_id)
        .await
        .expect_err("the seller cannot confirm the buyer's refund");
    assert!(matches!(err, DisputeError::Forbidden), "got {err:?}");
    disputes::confirm_refund(&pool, &kf, &cfg(), dispute_id, buyer)
        .await
        .expect("buyer confirms the refund");
    let d = disputes::get_dispute(&pool, dispute_id).await.expect("get_dispute").expect("dispute exists");
    assert_eq!(d.state, "resolved");
    assert_eq!(d.outcome_state, "final");
    assert_eq!(order_by_public_id(&pool, &order.public_id).await.unwrap().state, "Resolved");
    let facts = reputation::facts_for_seller(&pool, shop.seller_id).await.expect("facts_for_seller");
    assert!(
        facts.iter().any(|f| f.outcome == 2),
        "confirmed refund must record a fact with outcome code 2"
    );
    // Confirming again is a bad state.
    let err = disputes::confirm_refund(&pool, &kf, &cfg(), dispute_id, buyer)
        .await
        .expect_err("double confirmation must be refused");
    assert!(matches!(err, DisputeError::BadState), "got {err:?}");
}

#[tokio::test]
async fn dispute_other_outcomes_finalize_immediately() {
    let pool = pool().await;
    let kf = test_keyfile();
    let moderator = make_moderator(&pool).await;
    for (outcome, code) in [
        ("delivered-confirmed", 1u8),
        ("buyer-at-fault", 4u8),
        ("unresolved", 5u8),
    ] {
        let shop = make_shop(&pool).await;
        let buyer = make_buyer(&pool).await;
        let (order, dispute_id) = disputed_order(&pool, &shop, buyer).await;
        disputes::resolve(&pool, &kf, &cfg(), dispute_id, moderator, outcome)
            .await
            .unwrap_or_else(|e| panic!("resolve {outcome}: {e:?}"));
        assert_eq!(disputes::get_dispute(&pool, dispute_id).await.expect("get_dispute").expect("dispute exists").state, "resolved");
        assert_eq!(order_by_public_id(&pool, &order.public_id).await.unwrap().state, "Resolved");
        let facts = reputation::facts_for_seller(&pool, shop.seller_id).await.expect("facts_for_seller");
        assert!(
            facts.iter().any(|f| f.outcome == code),
            "outcome {outcome} must record fact code {code}"
        );
    }
}

// =====================================================================
// Disclosures (GnuPG fixtures generated at runtime — see A1)
// =====================================================================

struct GpgHome {
    dir: PathBuf,
}
impl GpgHome {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("blind9-gpg-{}-{}-{:x}", tag, std::process::id(), uniq128()));
        std::fs::create_dir_all(&dir).expect("create GNUPGHOME");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        GpgHome { dir }
    }
    fn run(&self, args: &[&str]) -> String {
        let out = Command::new("gpg")
            .args(["--batch", "--yes", "--pinentry-mode", "loopback"])
            .args(args)
            .env("GNUPGHOME", &self.dir)
            .output()
            .expect("run gpg");
        assert!(out.status.success(), "gpg {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
    fn gen_key(&self, uid: &str) -> String {
        let params = format!(
            "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\nKey-Usage: sign\nName-Real: {uid}\nExpire-Date: 0\nSubkey-Type: ecdh\nSubkey-Curve: cv25519\nSubkey-Usage: encrypt\n%commit\n"
        );
        let pf = self.dir.join("params.txt");
        std::fs::write(&pf, params).unwrap();
        self.run(&["--gen-key", pf.to_str().unwrap()]);
        let listing = self.run(&["--with-colons", "--list-keys"]);
        for line in listing.lines() {
            if line.starts_with("fpr:") {
                return line.split(':').nth(9).expect("fpr field").to_string();
            }
        }
        panic!("no fingerprint in gpg listing");
    }
    fn export_armored(&self, fpr: &str) -> Vec<u8> {
        let out = Command::new("gpg")
            .args(["--batch", "--yes", "--pinentry-mode", "loopback", "--armor", "--export", fpr])
            .env("GNUPGHOME", &self.dir)
            .output()
            .expect("export cert");
        assert!(out.status.success());
        out.stdout
    }
    fn sign_detached(&self, fpr: &str, message: &[u8]) -> String {
        let mf = self.dir.join(format!("msg-{:x}.bin", uniq128()));
        std::fs::write(&mf, message).unwrap();
        let sf = self.dir.join(format!("msg-{:x}.asc", uniq128()));
        self.run(&[
            "--armor",
            "--detach-sign",
            "--local-user",
            fpr,
            "--output",
            sf.to_str().unwrap(),
            mf.to_str().unwrap(),
        ]);
        std::fs::read_to_string(&sf).unwrap()
    }
}
impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn register_key(pool: &PgPool, account_id: i64, home: &GpgHome, fpr: &str) {
    let cert = home.export_armored(fpr);
    let info = app::keys::validate_cert(&cert).expect("generated cert must validate");
    assert_eq!(info.fingerprint, *fpr);
    app::keys::install_key(pool, account_id, &cert, &info, None)
        .await
        .expect("register generated cert as identity key");
}

struct DisclosureFixture {
    shop: Shop,
    buyer: i64,
    buyer_home: GpgHome,
    buyer_fpr: String,
    seller_home: GpgHome,
    seller_fpr: String,
    order: app::orders::Order,
    dispute_id: i64,
}
async fn disclosure_fixture(pool: &PgPool) -> DisclosureFixture {
    let (seller_id, seller_pub) = make_account(pool, "seller", 72).await;
    let seller_home = GpgHome::new("seller");
    let seller_fpr = seller_home.gen_key("blind9 seller");
    register_key(pool, seller_id, &seller_home, &seller_fpr).await;
    let listing = make_listing(pool, seller_id, "Blind Suite Widget").await;
    let shop = Shop { seller_id, seller_pub, listing };
    let (buyer, _) = make_account(pool, "buyer", 72).await;
    let buyer_home = GpgHome::new("buyer");
    let buyer_fpr = buyer_home.gen_key("blind9 buyer");
    register_key(pool, buyer, &buyer_home, &buyer_fpr).await;
    let (order, dispute_id) = disputed_order(pool, &shop, buyer).await;
    DisclosureFixture { shop, buyer, buyer_home, buyer_fpr, seller_home, seller_fpr, order, dispute_id }
}

#[tokio::test]
async fn disclosure_signed_by_other_party_is_verified_and_stored_encrypted() {
    let pool = pool().await;
    let kf = test_keyfile();
    let fx = disclosure_fixture(&pool).await;
    assert_eq!(fx.order.seller_fpr_pinned, fx.seller_fpr, "order pins the seller's registered key");
    let message = format!("Seller said delivery ships Friday, tracking follows. ref {:x}", uniq128());
    // The BUYER discloses a message signed by the SELLER (the other party).
    let sig = fx.seller_home.sign_detached(&fx.seller_fpr, message.as_bytes());
    let status = disputes::submit_disclosure(&pool, &kf, fx.dispute_id, fx.buyer, &message, &sig)
        .await
        .expect("disclosure submission must succeed");
    assert_eq!(status, "verified", "a genuine other-party signature must classify verified");
    let views = disputes::disclosures_for(&pool, &kf, fx.dispute_id).await.expect("disclosures_for");
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].submitted_by, fx.buyer);
    assert_eq!(views[0].signature_status, "verified");
    assert_eq!(views[0].message, message, "disclosures_for must decrypt for display");
    // Stored content is encrypted: the plaintext must not appear verbatim.
    let enc: Vec<u8> = sqlx::query_scalar("SELECT content_enc FROM disclosures WHERE dispute_id = $1")
        .bind(fx.dispute_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!contains(&enc, message.as_bytes()), "content_enc must not contain the plaintext message");
}

#[tokio::test]
async fn disclosure_self_signed_or_garbage_is_an_unverified_claim() {
    let pool = pool().await;
    let kf = test_keyfile();
    let fx = disclosure_fixture(&pool).await;
    let message = format!("I definitely said this, trust me. ref {:x}", uniq128());
    // Signed by the SUBMITTER's own key: never evidence.
    let own_sig = fx.buyer_home.sign_detached(&fx.buyer_fpr, message.as_bytes());
    let status = disputes::submit_disclosure(&pool, &kf, fx.dispute_id, fx.buyer, &message, &own_sig)
        .await
        .expect("self-signed disclosure is stored as a claim, not an error");
    assert_eq!(status, "unverified_claim");
    // Garbage signature from the seller as submitter.
    let status = disputes::submit_disclosure(
        &pool,
        &kf,
        fx.dispute_id,
        fx.shop.seller_id,
        "Seller note about the order.",
        "-----BEGIN PGP SIGNATURE-----\n\nnot-a-real-signature\n-----END PGP SIGNATURE-----",
    )
    .await
    .expect("garbage signature is stored as a claim, not an error");
    assert_eq!(status, "unverified_claim");
    let views = disputes::disclosures_for(&pool, &kf, fx.dispute_id).await.expect("disclosures_for");
    assert_eq!(views.len(), 2);
    assert!(views.iter().all(|v| v.signature_status == "unverified_claim"));
}

#[tokio::test]
async fn disclosure_nonparticipant_forbidden_and_resolved_dispute_bad_state() {
    let pool = pool().await;
    let kf = test_keyfile();
    let fx = disclosure_fixture(&pool).await;
    let stranger = make_buyer(&pool).await;
    let message = "A message from nobody involved.";
    let sig = fx.seller_home.sign_detached(&fx.seller_fpr, message.as_bytes());
    let err = disputes::submit_disclosure(&pool, &kf, fx.dispute_id, stranger, message, &sig)
        .await
        .expect_err("only dispute participants may disclose");
    assert!(matches!(err, DisputeError::Forbidden), "got {err:?}");
    // Resolve the dispute; further disclosures are a bad state.
    let moderator = make_moderator(&pool).await;
    disputes::resolve(&pool, &kf, &cfg(), fx.dispute_id, moderator, "delivered-confirmed")
        .await
        .unwrap();
    let err = disputes::submit_disclosure(&pool, &kf, fx.dispute_id, fx.buyer, message, &sig)
        .await
        .expect_err("disclosure is only allowed while the dispute is open");
    assert!(matches!(err, DisputeError::BadState), "got {err:?}");
}

// =====================================================================
// Reports and the moderation queue
// =====================================================================

#[tokio::test]
async fn reports_create_for_listing_profile_and_review_targets() {
    let pool = pool().await;
    let kf = test_keyfile();
    let reporter = make_buyer(&pool).await;
    let shop = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let order = completed_order(&pool, &shop, buyer).await;
    reviews::submit_review(&pool, &kf, &cfg(), &order.public_id, buyer, 3, "Middling.")
        .await
        .unwrap();
    let id_listing = moderation::create_report(&pool, reporter, "listing", &shop.listing.public_id, "fraud", "Looks like a scam listing.")
        .await
        .expect("report a listing");
    let id_profile = moderation::create_report(&pool, reporter, "profile", &shop.seller_pub, "abuse", "Abusive profile text.")
        .await
        .expect("report a profile");
    let id_review = moderation::create_report(&pool, reporter, "review", &order.public_id, "other", "Review seems planted.")
        .await
        .expect("report a review");
    let open = moderation::open_reports(&pool).await.expect("open_reports");
    for (id, target) in [
        (id_listing, format!("listing:{}", shop.listing.public_id)),
        (id_profile, format!("profile:{}", shop.seller_pub)),
        (id_review, format!("review:{}", order.public_id)),
    ] {
        let r = open.iter().find(|r| r.id == id).unwrap_or_else(|| panic!("report {id} must be in the open queue"));
        assert_eq!(r.target, target, "stored target is kind:id");
        assert_eq!(r.state, "open");
    }
}

#[tokio::test]
async fn reports_bad_category_missing_target_and_action_transitions() {
    let pool = pool().await;
    let reporter = make_buyer(&pool).await;
    let moderator = make_moderator(&pool).await;
    let shop = make_shop(&pool).await;
    let err = moderation::create_report(&pool, reporter, "listing", &shop.listing.public_id, "rudeness", "Not a category.")
        .await
        .expect_err("category outside the closed set must be refused");
    assert!(matches!(err, ModError::BadInput), "got {err:?}");
    let err = moderation::create_report(&pool, reporter, "listing", &listing_public_id(), "fraud", "Ghost listing.")
        .await
        .expect_err("a nonexistent target must be refused");
    assert!(matches!(err, ModError::NotFound), "got {err:?}");
    let err = moderation::create_report(&pool, reporter, "listing", &shop.listing.public_id, "fraud", "")
        .await
        .expect_err("an empty reason must be refused");
    assert!(matches!(err, ModError::BadInput), "got {err:?}");

    let id = moderation::create_report(&pool, reporter, "listing", &shop.listing.public_id, "fraud", "Please look.")
        .await
        .unwrap();
    let err = moderation::report_action(&pool, id, moderator, "explode")
        .await
        .expect_err("unknown queue action must be refused");
    assert!(matches!(err, ModError::BadInput), "got {err:?}");
    moderation::report_action(&pool, id, moderator, "dismiss").await.expect("dismiss");
    let state: String = sqlx::query_scalar("SELECT state FROM reports WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "dismissed");
    assert!(
        !moderation::open_reports(&pool).await.expect("open_reports").iter().any(|r| r.id == id),
        "a dismissed report leaves the open queue"
    );
    let id2 = moderation::create_report(&pool, reporter, "profile", &shop.seller_pub, "other", "Second look.")
        .await
        .unwrap();
    moderation::report_action(&pool, id2, moderator, "resolve").await.expect("resolve");
    let state: String = sqlx::query_scalar("SELECT state FROM reports WHERE id = $1")
        .bind(id2)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "resolved");
}

// =====================================================================
// TOTP enrollment and the moderator step-up gate
// =====================================================================

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn wrong_code(secret: &[u8]) -> String {
    let t = now_secs();
    let valid: Vec<String> = [t - 30, t, t + 30].iter().map(|x| totp::code_at(secret, *x)).collect();
    for n in 0..1_000_000u32 {
        let cand = format!("{n:06}");
        if !valid.contains(&cand) {
            return cand;
        }
    }
    unreachable!()
}

#[tokio::test]
async fn totp_enrollment_flow_require_totp_and_encrypted_storage() {
    let pool = pool().await;
    let kf = test_keyfile();
    let (mod_id, _) = make_account(&pool, "moderator", 72).await;
    assert!(!moderation::totp_enrolled(&pool, mod_id).await.expect("totp_enrolled"));
    let err = moderation::require_totp(&pool, &kf, mod_id, "123456")
        .await
        .expect_err("an unenrolled moderator must be told TOTP is required");
    assert!(matches!(err, ModError::TotpRequired), "got {err:?}");

    let secret_b32 = moderation::totp_begin(&pool, &kf, mod_id).await.expect("begin enrollment");
    let secret = totp::base32_decode(&secret_b32).expect("begin returns a base32 secret");
    assert_eq!(secret.len(), 20);
    // Wrong code cannot confirm enrollment.
    let err = moderation::totp_confirm(&pool, &kf, mod_id, &wrong_code(&secret))
        .await
        .expect_err("a wrong code must not confirm enrollment");
    assert!(matches!(err, ModError::TotpInvalid), "got {err:?}");
    assert!(!moderation::totp_enrolled(&pool, mod_id).await.expect("totp_enrolled"));
    // Correct current code confirms.
    let code = totp::code_at(&secret, now_secs());
    moderation::totp_confirm(&pool, &kf, mod_id, &code).await.expect("confirm with the current code");
    assert!(moderation::totp_enrolled(&pool, mod_id).await.expect("totp_enrolled"));
    // require_totp: wrong code invalid, right code ok.
    let err = moderation::require_totp(&pool, &kf, mod_id, &wrong_code(&secret))
        .await
        .expect_err("wrong step-up code must be refused");
    assert!(matches!(err, ModError::TotpInvalid), "got {err:?}");
    let code = totp::code_at(&secret, now_secs());
    moderation::require_totp(&pool, &kf, mod_id, &code).await.expect("current code passes the gate");
    // Stored secret is encrypted: neither the base32 text nor the raw
    // secret bytes appear in accounts.totp_secret_enc.
    let enc: Vec<u8> = sqlx::query_scalar("SELECT totp_secret_enc FROM accounts WHERE id = $1")
        .bind(mod_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!enc.is_empty());
    assert!(!contains(&enc, secret_b32.as_bytes()), "totp_secret_enc must not contain the base32 secret");
    assert!(!contains(&enc, &secret), "totp_secret_enc must not contain the raw secret bytes");
}

// =====================================================================
// Warn, listing removal, account closure
// =====================================================================

#[tokio::test]
async fn warn_sets_timestamp_audit_and_notice_but_account_stays_active() {
    let pool = pool().await;
    let moderator = make_moderator(&pool).await;
    let (target, _) = make_account(&pool, "seller", 72).await;
    let err = moderation::warn_account(&pool, target, moderator, "")
        .await
        .expect_err("an empty warning reason must be refused");
    assert!(matches!(err, ModError::BadInput), "got {err:?}");
    moderation::warn_account(&pool, target, moderator, "First warning: misleading titles.")
        .await
        .expect("warn must succeed");
    let row = sqlx::query("SELECT status, warned_at IS NOT NULL AS w FROM accounts WHERE id = $1")
        .bind(target)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("status"), "active", "a warned account functions normally");
    assert!(row.get::<bool, _>("w"), "warned_at must be set");
    let action: String = sqlx::query_scalar(
        "SELECT action FROM moderation_actions WHERE target_account_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(target)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(action, "warn");
    assert!(has_event(&pool, target, "moderator_warning").await, "the target must get an inbox warning");
}

#[tokio::test]
async fn listing_removal_hides_from_browse_and_restore_returns_it() {
    let pool = pool().await;
    let moderator = make_moderator(&pool).await;
    let (seller_id, _) = make_account(&pool, "seller", 72).await;
    install_dummy_key(&pool, seller_id, &fingerprint(uniq128())).await;
    let title = format!("Blind9Remove{:x}", uniq128());
    let listing = make_listing(&pool, seller_id, &title).await;
    let found = app::listings::browse(&pool, Some(&title), None, 1).await.unwrap();
    assert!(found.iter().any(|l| l.public_id == listing.public_id), "published listing is browsable");
    moderation::set_listing_removed(&pool, &listing.public_id, moderator, true)
        .await
        .expect("remove listing");
    let status: String = sqlx::query_scalar("SELECT status FROM listings WHERE id = $1")
        .bind(listing.internal_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "removed");
    let found = app::listings::browse(&pool, Some(&title), None, 1).await.unwrap();
    assert!(!found.iter().any(|l| l.public_id == listing.public_id), "a removed listing is absent from browse");
    assert!(has_event(&pool, seller_id, "listing_removed").await, "the seller must be notified");
    let err = moderation::set_listing_removed(&pool, &listing.public_id, moderator, true)
        .await
        .expect_err("removing an already-removed listing must be refused");
    assert!(matches!(err, ModError::BadInput), "got {err:?}");
    moderation::set_listing_removed(&pool, &listing.public_id, moderator, false)
        .await
        .expect("restore listing");
    let found = app::listings::browse(&pool, Some(&title), None, 1).await.unwrap();
    assert!(found.iter().any(|l| l.public_id == listing.public_id), "a restored listing returns to browse");
}

/// Insert a live session and one unused payment-pool entry for `seller`.
async fn closure_extras(pool: &PgPool, seller_id: i64) {
    let mut token = vec![0u8; 32];
    for (i, b) in token.iter_mut().enumerate() {
        *b = ((uniq128() >> (i % 16)) & 0xff) as u8 ^ (i as u8);
    }
    sqlx::query("INSERT INTO sessions (token_hash, account_id, expires_at) VALUES ($1, $2, now() + interval '1 day')")
        .bind(token)
        .bind(seller_id)
        .execute(pool)
        .await
        .unwrap();
    let address = format!("blind9-pool-{:x}", uniq128());
    let dest: i64 = sqlx::query_scalar(
        "INSERT INTO destinations (address, seller_id, source) VALUES ($1, $2, 'pool') RETURNING id",
    )
    .bind(&address)
    .bind(seller_id)
    .fetch_one(pool)
    .await
    .unwrap();
    let batch: i64 = sqlx::query_scalar(
        "INSERT INTO payment_batches (seller_id, marketplace_id, network, entry_count) VALUES ($1, 'vespiary-market', 'stagenet', 1) RETURNING id",
    )
    .bind(seller_id)
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO payment_pool_entries (batch_id, seller_id, destination_id, address, message, signature, state) \
         VALUES ($1, $2, $3, $4, 'm', 's', 'unused')",
    )
    .bind(batch)
    .bind(seller_id)
    .bind(dest)
    .bind(&address)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn close_account_full_closure_semantics() {
    let pool = pool().await;
    let kf = test_keyfile();
    let moderator = make_moderator(&pool).await;
    let shop = make_shop(&pool).await;
    closure_extras(&pool, shop.seller_id).await;
    let buyer = make_buyer(&pool).await;
    // An open (non-terminal) order with the target, and a terminal order
    // with a review + fact recorded BEFORE closure.
    let open_order = fresh_order(&pool, &shop, buyer).await;
    let done_order = completed_order(&pool, &shop, buyer).await;
    reviews::submit_review(&pool, &kf, &cfg(), &done_order.public_id, buyer, 5, "Was great.")
        .await
        .unwrap();
    // The review above already yields this order's fact (score
    // mirroring); recording again is idempotent. What closure must
    // preserve is the fact itself, asserted by count below.
    let _ = reputation::record_fact_for_order(&pool, &kf, &cfg(), done_order.id).await.unwrap();
    // A third order, still open at closure, which terminates only after.
    let late_order = fresh_order(&pool, &shop, buyer).await;

    moderation::close_account(&pool, shop.seller_id, moderator, "Fraud investigation complete.")
        .await
        .expect("moderator closes the account");

    let row = sqlx::query("SELECT status, closed_at IS NOT NULL AS c FROM accounts WHERE id = $1")
        .bind(shop.seller_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("status"), "closed");
    assert!(row.get::<bool, _>("c"), "closed_at must be set");
    let revoked: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE account_id = $1 AND revoked_at IS NOT NULL")
        .bind(shop.seller_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(revoked, 1, "all sessions must be revoked at closure");
    let lstatus: String = sqlx::query_scalar("SELECT status FROM listings WHERE id = $1")
        .bind(shop.listing.internal_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(lstatus, "paused", "published listings become paused at closure");
    let found = app::listings::browse(&pool, Some("Blind Suite Widget"), None, 1).await.unwrap();
    assert!(!found.iter().any(|l| l.public_id == shop.listing.public_id), "a closed seller's listings leave the catalogue");
    let pool_state: String = sqlx::query_scalar("SELECT state FROM payment_pool_entries WHERE seller_id = $1")
        .bind(shop.seller_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pool_state, "retired", "unused pool entries are retired at closure");
    assert!(has_event(&pool, buyer, "account_closed").await, "counterparties with open orders get an account_closed notice");
    let action: String = sqlx::query_scalar(
        "SELECT action FROM moderation_actions WHERE target_account_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(shop.seller_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(action, "close-account");
    // History is retained and still visible to the counterparty.
    let mine = orders_for(&pool, buyer).await;
    assert!(mine.iter().any(|o| o.id == open_order.id), "open order history retained");
    assert!(mine.iter().any(|o| o.id == done_order.id), "terminal order history retained");
    let review_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE order_id = $1")
        .bind(done_order.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(review_rows, 1, "reviews are retained at closure");
    assert!(reviews::review_for_order(&pool, &cfg(), done_order.id).await.expect("review_for_order").is_some());
    // The pre-closure fact remains; an order terminating AFTER closure
    // accrues no fact.
    force_order(&pool, late_order.id, "Completed", "SellerAttested").await;
    let wrote = reputation::record_fact_for_order(&pool, &kf, &cfg(), late_order.id).await.unwrap();
    assert!(!wrote, "no fact accrues for an order terminating after closure");
    let fact_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reputation_facts WHERE seller_id = $1")
        .bind(shop.seller_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(fact_rows, 1, "only the pre-closure fact remains");
    // A second close is refused, and no account anywhere in this
    // fixture's outcomes carries a suspension status (no such tool).
    let err = moderation::close_account(&pool, shop.seller_id, moderator, "Again.")
        .await
        .expect_err("closing an already-closed account must be refused");
    assert!(matches!(err, ModError::AlreadyClosed), "got {err:?}");
    let suspended: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE status = 'suspended'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(suspended, 0, "there is no suspended status: closure is the only account-level action");
}

#[tokio::test]
async fn self_close_has_the_same_effects_with_self_audit_action() {
    let pool = pool().await;
    let shop = make_shop(&pool).await;
    closure_extras(&pool, shop.seller_id).await;
    let buyer = make_buyer(&pool).await;
    let _open = fresh_order(&pool, &shop, buyer).await;
    moderation::close_account(&pool, shop.seller_id, shop.seller_id, "Closing my own account.")
        .await
        .expect("self-service closure uses the same path");
    let status: String = sqlx::query_scalar("SELECT status FROM accounts WHERE id = $1")
        .bind(shop.seller_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "closed");
    let lstatus: String = sqlx::query_scalar("SELECT status FROM listings WHERE id = $1")
        .bind(shop.listing.internal_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(lstatus, "paused");
    let revoked: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE account_id = $1 AND revoked_at IS NOT NULL")
        .bind(shop.seller_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(revoked, 1);
    let action: String = sqlx::query_scalar(
        "SELECT action FROM moderation_actions WHERE target_account_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(shop.seller_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(action, "close-account-self", "actor == target records the self-close audit action");
    assert!(has_event(&pool, buyer, "account_closed").await);
}

// =====================================================================
// Honesty of the rendered surfaces (grep-style, templates only)
// =====================================================================

#[test]
fn templates_sockpuppet_honesty_and_no_verified_payment_claim() {
    let profile = include_str!("../../crates/app/templates/seller_profile.html");
    assert!(
        profile.contains("sock-puppet accounts") && profile.contains("farm reputation"),
        "the profile must plainly admit reputation can be farmed with sock-puppet accounts"
    );
    assert!(
        profile.contains("does not verify payments on-chain"),
        "the profile must not claim on-chain payment verification under v1; it counts fact evidence only"
    );
    let order = include_str!("../../crates/app/templates/order.html");
    assert!(
        !order.contains("payment verified") || order.contains("payment_verified_badge"),
        "order page may only show a verified claim via the badge condition"
    );
}

#[test]
fn templates_no_suspension_power_and_closure_wording_is_honest() {
    let queue = include_str!("../../crates/app/templates/moderation_queue.html");
    assert!(
        !queue.contains("suspend"),
        "moderation copy must not offer a suspend power (closure replaces it)"
    );
    assert!(queue.contains("close accounts"), "the queue names closing accounts as the account-level power");
    let dispute = include_str!("../../crates/app/templates/dispute.html");
    assert!(!dispute.contains("suspend"), "dispute copy must not offer a suspend power");
    let profile = include_str!("../../crates/app/templates/seller_profile.html");
    assert!(profile.contains("Account closed"), "closed profiles show a closure banner");
    assert!(
        profile.contains("does not stop anyone from registering a new account"),
        "closure copy must never claim the person cannot return"
    );
    assert!(profile.contains("cannot log in or trade"), "the banner states the identity has ended");
}
