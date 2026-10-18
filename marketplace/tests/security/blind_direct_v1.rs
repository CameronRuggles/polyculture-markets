//! Blind security suite — Direct Monero Payments v1 (owner handoff
//! 2026-10-15; SPEC-V2-AMENDMENTS.md, "Direct Payments v1" section,
//! rulings a–f; spec §22 blind-authorship process).
//!
//! SOURCES USED (the only sources assertions are derived from):
//!   1. `Direct_Monero_Payments_v1___Muse.AI_Handoff` (governing design:
//!      hard rules, signed-message / batch format, assignment, payment
//!      status, settings table).
//!   2. `SPEC-V2-AMENDMENTS.md`, appended 2026-10-15 Direct Payments
//!      section only (rulings a–f), plus the earlier amendments'
//!      fixture conventions (Q7b real-wallet fixtures).
//!   3. The binding API contract supplied with this authoring task
//!      (app::payments surface, PaymentError variants, order-creation
//!      behaviour, drain defences, expiry).
//!   4. `marketplace/migrations/*.sql` — the schema is part of the
//!      contract (in particular 0008_direct_payments_v1.sql).
//!   5. Existing locked suites blind_stage4.rs / blind_stage6.rs —
//!      fixture and usage conventions ONLY (account/listing/key helpers,
//!      DB_URL const, the Stage 6 200-entry stagenet subaddress pool).
//!   6. modules-api public types (Network, Subaddress).
//!   7. orders.rs — ONLY the `pub async fn` signature lines of
//!      create_order / create_order_with_config / apply_action and the
//!      Order / OrderError type declarations they reference.
//!   8. Fixture addresses: stage0-spike/fixtures-wallet/FIXTURES.md
//!      (stagenet primary + 2 subaddresses, testnet, mainnet) and the
//!      Stage 6 fixture wallet pool in blind_stage6.rs (POOL200).
//!   9. crates/app/templates/pay.html — read ONLY for the grep-style
//!      "no verified payment claim" hard-rule test, as the task
//!      contract expressly allows for rendered-surface artifacts.
//!
//! The author has NOT read marketplace/crates/app/src/payments.rs,
//! marketplace/crates/app/tests/payments_db.rs, or the payment
//! handlers in web.rs.
//!
//! CONTRACT AMBIGUITIES FOUND (numbered; assertions follow the most
//! conservative reading and never invent behaviour beyond them):
//!   A1. The task contract prints create_order_with_config without the
//!       leading `marketplace_id: &str` argument; the orders.rs
//!       signature line (and blind_stage4 usage) shows it IS the second
//!       argument, mirroring create_order. This suite follows the
//!       signature line. The payment marketplace_id ("vespiary-market",
//!       per amendment (a)) travels inside PaymentConfig, separately
//!       from the `mkt_…` terms/order marketplace id.
//!   A2. The contract does not say whether the payments functions take
//!       `cfg` by value or by reference. This suite passes
//!       `&PaymentConfig` (the create_order_with_config style); if the
//!       real signatures differ this is a construction fix, not an
//!       assertion change.
//!   A3. mark_paid on a nonexistent order id: the contract lists a
//!       NotFound variant but does not pin it to this call, so only
//!       refusal (an error, no state change) is asserted.
//!   A4. mark_paid by the buyer / a stranger: the contract allows
//!       "NotSeller or TransitionDenied per the pinned set", so either
//!       variant is accepted; refusal + unchanged state + no
//!       attestation row are asserted strictly.
//!   A5. PaymentIdentity.created_at / changed_at types are not pinned
//!       by the contract ("exposes primary_address, changed_at,
//!       created_at"). This suite asserts primary_address through the
//!       struct and changed_at semantics through the
//!       payment_identities table (schema = contract) plus
//!       identity_changed_recently, never guessing the field types.
//!   A6. Expiry age basis is not pinned (pool entry assigned_at vs
//!       order created_at). The expiry fixture backdates BOTH, so the
//!       assertion holds under either reading.
//!   A7. Signature strings: with server_side_signature_check off
//!       (the v1 default), the contract lists no signature-format
//!       check among upload_batch's checks, so signatures here are
//!       opaque fixture strings stored/served byte-exact. If the
//!       implementation secretly format-checks signatures, the happy-
//!       path upload tests fail and that is an implementation
//!       deviation from the contract's enumerated check list.
//!   A8. payment_seller_id: the contract pins the input shape as
//!       "acct_<32 lowercase hex>". Uppercase-hex input is therefore
//!       asserted to yield None ("anything else -> None"); if the
//!       implementation accepts mixed case, that test flags it.
//!   A9. Assignment / PaymentIdentity field types beyond the pinned
//!       names (address, message, signature, primary_address) are not
//!       specified; the four pinned Assignment fields are asserted as
//!       strings byte-equal to the uploaded JSON values.
//!   A10. pay.html "verified" reading: the template contains "verify"
//!       and "verifies" (instructions to the buyer) but, on the
//!       author's reading, no "verified" payment claim. The test
//!       strips the substring "unverified" first, then asserts no
//!       "verified" remains — exactly the contract's pin.
//!   A11. Whether `accept` on an assignment-carrying order succeeds is
//!       derived from amendment (c) ("accept requires the assignment,
//!       which holds by construction"), so success is asserted; the
//!       legacy no-assignment accept still yields InvoiceRequired per
//!       amendment (e) / the Stage 4 surface.
//!   A12. expire_unpaid_orders returns a GLOBAL sweep count; with
//!       suites running in parallel the count is asserted as >= 1
//!       (plus exact per-order state assertions), never an exact
//!       total, except that a second immediate sweep must find
//!       nothing left to expire from this suite's fixtures (0).
//!   A13. Batch JSON with extra unknown top-level/entry fields: the
//!       contract does not say whether they are tolerated, so no
//!       assertion is made either way (not tested).
//!   A15. CONSTRUCTION FIX (from compiler diagnostics only, assertions
//!       unchanged): identity_changed_recently returns an Option<String>
//!       (evidently the change stamp when recent), not the contract's
//!       bool. Asserted as Some(..) = recently changed, None = not.
//!   A16. CONSTRUCTION FIX (compiler diagnostics): assignment_for_order
//!       takes a third argument, &PaymentConfig. The suite passes the
//!       same cfg used for the surrounding flow.
//!   A17. CONSTRUCTION FIX (compiler diagnostics): mark_paid takes
//!       &Order (the order struct), not an order_id. The suite passes
//!       freshly refetched orders so state comes from the DB; the
//!       nonexistent-order case constructs an Order struct with an
//!       unused id (A3's behaviour-only assertion is unchanged).
//!   A18. Assignment.primary_address AFTER an identity change: the
//!       contract does not pin whether it tracks the current identity
//!       or the primary in force at assignment time (the observed
//!       implementation serves the current identity's address, while
//!       the signed message still names the original primary). The
//!       suite asserts byte-exactness of address/message/signature
//!       only in that scenario.
//!   A14. The drain-defence error variants for the open-unpaid cap
//!       and the hourly rate are not pinned by the contract (only
//!       PoolEmpty is pinned, for the empty-pool case); cap/rate
//!       tests assert refusal + no order created + no pool entry
//!       consumed, not a variant name.
//!
//! PLAIN-LANGUAGE ASSERTION LIST (grouped):
//!   Pure helpers: payment_seller_id derives "acct-<32 hex>" from
//!   "acct_<32 hex>" and rejects everything else; canonical_message
//!   renders the exact one-line format; network_name spells all three
//!   networks; PaymentConfig::defaults carries the contract's
//!   stagenet suggested values.
//!   Identity: first set returns "not changed", re-setting the same
//!   address is a no-op, changing returns "changed", stamps
//!   changed_at, and flags identity_changed_recently; backdating
//!   changed_at past the warning window clears the flag; bad primary
//!   addresses (subaddress, integrated, wrong network, garbage) are
//!   BadPrimary and create no identity; changing the primary retires
//!   UNUSED entries only — an assigned entry and its order survive.
//!   Upload: a valid batch stores exactly its entries, byte-exact in
//!   the DB and in the global destinations table; every pinned
//!   rejection (BadBatch, WrongFormat, WrongMarketplace,
//!   WrongNetwork, WrongSeller, NoIdentity, WrongPrimary,
//!   EmptyBatch, BatchTooLarge, PoolFull, BadSubaddress,
//!   MessageMismatch, DuplicateAddress, ServerCheckUnavailable)
//!   stores NOTHING (all-or-nothing).
//!   Assignment/orders: an order from a payment seller takes the
//!   OLDEST unused entry; two simultaneous creations take different
//!   entries; the served assignment is byte-identical to the upload;
//!   identity + empty pool refuses with PoolEmpty; no identity keeps
//!   legacy no-assignment behaviour; cancel and decline RETIRE the
//!   entry (never reused, never re-uploadable); the open-unpaid cap
//!   and hourly rate count ONLY assignment-carrying orders.
//!   Mark paid: seller-only, only from AwaitingPayment, requires an
//!   assignment; success moves the order to Paid and records a
//!   payment_attestations row whose amount_atomic IS NULL.
//!   Expiry: the sweep cancels old assigned orders (Requested and
//!   AwaitingPayment), retires their entries forever, and leaves
//!   fresh assigned orders and old UNASSIGNED orders untouched.
//!   Hard rules (source/schema level): migration 0008 defines no
//!   column storing txids, seeds, spend/view keys, wallet files or
//!   received amounts (amount_atomic exists only on
//!   payment_attestations); pay.html contains no "verified" claim.

use app::orders::{
    apply_action, create_order_with_config, order_by_public_id, Order, OrderError,
};
use app::payments::{
    assignment_for_order, canonical_message, expire_unpaid_orders, get_identity,
    has_assignment, identity_changed_recently, mark_paid, network_name, payment_seller_id,
    set_primary_address, unused_count, upload_batch, PaymentConfig, PaymentError,
};
use modules_api::Network;
use sqlx::{PgPool, Row};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

// Copied exactly from blind_stage4.rs (the task contract's pin).
const DB_URL: &str = "postgres://postgres:dev@localhost/marketplace_dev";
/// Terms/order marketplace id (contract §2 `mkt_` shape), as in stage 4.
const TERMS_MKT: &str = "mkt_0123456789abcdef0123456789abcdef";
/// Payment marketplace_id, pinned by amendment (a): "vespiary-market".
const PAY_MKT: &str = "vespiary-market";

// ---------------------------------------------------------------------
// Fixture addresses — real, valueless, generated offline (Q7b method).
// ---------------------------------------------------------------------

/// Stagenet primary of the Stage 6 fixture wallet (blind_stage6 header:
/// account 0 index 0 of a `--stagenet --offline` wallet). POOL_SUBS are
/// that same wallet's subaddresses, indices 1..=200.
const PRIMARY_A: &str =
    "55b6gZhKJ2b6EzvernZJBcPXiZym13w1CfbpDU6sR8aSGpaRbAmU4EMSH3XYXu5U1cSac7B49WRSSBbwQK9by3c7H9AdnFB";
/// Stagenet primary from stage0-spike FIXTURES.md (a second, distinct
/// stagenet standard address — used as "the other primary").
const PRIMARY_B: &str =
    "58kAS8eiH5R6bjTTgVfsCvVEXKrA6PhJkaCsPsGidQtfQZ98sMKgJXe48TC49BwsofTkG1sWBL3jwJBK7XiZkofKE1AtgdA";
/// FIXTURES.md stagenet subaddress #1 (of PRIMARY_B's wallet).
const FIX_SUB_1: &str =
    "75r1jA2VfCadHkdZcFGg711xJ9nNXFwV4CEcbiFEvUCXai8tZZ4yQq4Jpfo1iQFwLbhca2hjCh8D5ZtXC8pBpzSvS4KuQmi";
/// Stagenet integrated address (blind_stage6 fixture, 106 chars).
const STAGE_INTEGRATED: &str =
    "5FHmhNWouJ76EzvernZJBcPXiZym13w1CfbpDU6sR8aSGpaRbAmU4EMSH3XYXu5U1cSac7B49WRSSBbwQK9by3c7R3PDbmJGUNm7bwo6K9";
/// FIXTURES.md mainnet primary.
const MAIN_PRIMARY: &str =
    "41mvUKc5wWo47E9xAaJbMGZZ8hVR35HPWaJ2Jb11rAXMHYPM5MhQPdyjYv6krK3VP5XJp3jiE47JKRFiC2YQ9XjJ46sXs9y";
/// FIXTURES.md mainnet subaddress #1.
const MAIN_SUB: &str =
    "87hanmtwEvw3NwpLrLgr3vcZFHc88yQJqSzGx4MPNssLC36ku3zh7fuS67riw1iBP88N7P2gTWvYr81VBLqmyECu99fXNfk";
/// FIXTURES.md testnet primary.
const TEST_PRIMARY: &str =
    "9swuSAxW2WsVyr6H4uc4hCQ77kQv6pb34RLkp8wtuKQoK3kHYGwtomd6cK5Zj2KyxxHK6jHz4N8EuJT1fwRYUqh64R3wxyf";
/// FIXTURES.md testnet subaddress #1.
const TEST_SUB: &str =
    "BaQm3viv6hsMjQSbzGEXdZbzNV9bx8tcrAHbtNkF3YgLf6xbeL81KNUUsTeTdLMbkKRPq8YbYo4oLfLM9Ycf2jnH9we3m7h";

const POOL_SUBS: [&str; 200] = [
    "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",
];


// ---------------------------------------------------------------------
// Fixture helpers — constructions mirrored from blind_stage4.rs.
// ---------------------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(1);
static POOL_CURSOR: AtomicUsize = AtomicUsize::new(0);

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

async fn pool() -> PgPool {
    PgPool::connect(DB_URL)
        .await
        .expect("connect to marketplace_dev")
}

fn cfg() -> PaymentConfig {
    PaymentConfig::defaults(PAY_MKT)
}

/// Create an account `age_hours` old. Returns (internal id, public id).
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

async fn install_key(pool: &PgPool, account_id: i64, fpr: &str) {
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
    #[allow(dead_code)]
    internal_id: i64,
}

async fn make_listing(pool: &PgPool, seller_id: i64, price_atomic: i64) -> ListingFixture {
    let public_id = listing_public_id();
    let row = sqlx::query(
        "INSERT INTO listings (public_id, seller_id, title, description, price_atomic, \
                               pricing_module, destination_module, auto_invoice, status, \
                               delivery_terms, refund_terms) \
         VALUES ($1, $2, $3, $4, $5, 'xmr-only', 'signed-address-pool', false, 'published', $6, $7) \
         RETURNING id",
    )
    .bind(&public_id)
    .bind(seller_id)
    .bind("Blind Suite Widget")
    .bind("A widget described plainly.")
    .bind(price_atomic)
    .bind("Delivery within 3 days.")
    .bind("Refunds within 7 days.")
    .fetch_one(pool)
    .await
    .expect("insert listing fixture");
    ListingFixture {
        public_id,
        internal_id: row.get::<i64, _>("id"),
    }
}

/// A seller aged 72h (new-account limit never interferes) with a
/// current PGP identity key and one published listing. Payment
/// identity is installed separately by the tests that need it.
struct Shop {
    seller_id: i64,
    seller_pub: String,
    listing: ListingFixture,
}

async fn make_shop(pool: &PgPool) -> Shop {
    let (seller_id, seller_pub) = make_account(pool, "seller", 72).await;
    install_key(pool, seller_id, &fingerprint(uniq128())).await;
    let listing = make_listing(pool, seller_id, 1_000_000).await;
    Shop {
        seller_id,
        seller_pub,
        listing,
    }
}

async fn make_buyer(pool: &PgPool) -> i64 {
    make_account(pool, "buyer", 72).await.0
}

/// Remove any rows a PREVIOUS run of this suite left behind for these
/// exact addresses (fixture construction only — the global
/// destinations table persists between runs, and this suite's
/// addresses are a fixed fixture pool). Within a run nothing is ever
/// purged twice for the same address: slices are allocated disjointly.
async fn purge_addresses(pool: &PgPool, addrs: &[&str]) {
    if addrs.is_empty() {
        return;
    }
    let owned: Vec<String> = addrs.iter().map(|s| s.to_string()).collect();
    sqlx::query(
        "DELETE FROM payment_attestations WHERE pool_entry_id IN \
         (SELECT id FROM payment_pool_entries WHERE address = ANY($1))",
    )
    .bind(&owned)
    .execute(pool)
    .await
    .expect("purge stale attestations");
    sqlx::query("DELETE FROM payment_pool_entries WHERE address = ANY($1)")
        .bind(&owned)
        .execute(pool)
        .await
        .expect("purge stale pool entries");
    sqlx::query("DELETE FROM destinations WHERE address = ANY($1)")
        .bind(&owned)
        .execute(pool)
        .await
        .expect("purge stale destinations");
}

/// Take `n` fresh fixture subaddresses (disjoint across this run's
/// tests) and purge stale rows for them.
async fn fresh_subs(pool: &PgPool, n: usize) -> Vec<&'static str> {
    let start = POOL_CURSOR.fetch_add(n, Ordering::SeqCst);
    assert!(start + n <= POOL_SUBS.len(), "fixture pool exhausted");
    let slice: Vec<&'static str> = POOL_SUBS[start..start + n].to_vec();
    purge_addresses(pool, &slice).await;
    slice
}

/// A plausible opaque wallet-signature-shaped fixture string (see A7).
fn sig_for(seed: usize) -> String {
    format!(
        "SigBlind{:04}{}",
        seed,
        "QWxhZGRpbjpPcGVuU2VzYW1lLWZpeHR1cmUtc2lnbmF0dXJlLW9ubHktbm90LWEtcmVhbC1vbmVyby1zaWduYXR1cmU="
    )
}

struct BatchEntry {
    subaddress: String,
    message: String,
    signature: String,
}

/// Build a batch JSON text exactly in the handoff's format, with
/// canonical messages. Returns (json_text, entries as built).
fn build_batch(
    marketplace_id: &str,
    network: &str,
    seller_id: &str,
    primary: &str,
    subs: &[&str],
    sig_seed: usize,
) -> (String, Vec<BatchEntry>) {
    let net = match network {
        "mainnet" => Network::Mainnet,
        "stagenet" => Network::Stagenet,
        "testnet" => Network::Testnet,
        _ => Network::Stagenet,
    };
    let mut entries = Vec::new();
    let mut parts = Vec::new();
    for (i, sub) in subs.iter().enumerate() {
        let message = canonical_message(marketplace_id, net, seller_id, primary, sub);
        let signature = sig_for(sig_seed + i);
        parts.push(format!(
            "{{\"subaddress\":\"{}\",\"message\":\"{}\",\"signature\":\"{}\"}}",
            sub, message, signature
        ));
        entries.push(BatchEntry {
            subaddress: sub.to_string(),
            message,
            signature,
        });
    }
    let text = format!(
        "{{\"format\":\"xmr-direct-batch-v1\",\"marketplace_id\":\"{}\",\"network\":\"{}\",\"seller_id\":\"{}\",\"primary_address\":\"{}\",\"entries\":[{}]}}",
        marketplace_id,
        network,
        seller_id,
        primary,
        parts.join(",")
    );
    (text, entries)
}

/// Build a batch whose entry messages are supplied verbatim (for
/// MessageMismatch constructions).
fn build_batch_with_messages(
    seller_id: &str,
    primary: &str,
    entries: &[(&str, &str, &str)], // (subaddress, message, signature)
) -> String {
    let parts: Vec<String> = entries
        .iter()
        .map(|(sub, msg, sig)| {
            format!(
                "{{\"subaddress\":\"{}\",\"message\":\"{}\",\"signature\":\"{}\"}}",
                sub, msg, sig
            )
        })
        .collect();
    format!(
        "{{\"format\":\"xmr-direct-batch-v1\",\"marketplace_id\":\"{}\",\"network\":\"stagenet\",\"seller_id\":\"{}\",\"primary_address\":\"{}\",\"entries\":[{}]}}",
        PAY_MKT,
        seller_id,
        primary,
        parts.join(",")
    )
}

fn seller_id_of(public_id: &str) -> String {
    payment_seller_id(public_id).expect("fixture account id must derive a payment seller id")
}

/// Seller with payment identity PRIMARY_A set (no pool yet).
async fn make_payment_seller(pool: &PgPool) -> Shop {
    let shop = make_shop(pool).await;
    // NOTE: the helper deliberately does not assert the returned
    // `changed` flag — that return value is itself under test in
    // identity_first_set_same_set_and_change_semantics, and asserting
    // it here would cascade one result into every dependent test.
    set_primary_address(pool, shop.seller_id, PRIMARY_A, &cfg())
        .await
        .expect("set primary address");
    shop
}

/// Seller with payment identity and `n` uploaded pool entries.
/// Returns (shop, uploaded entries in batch order).
async fn make_stocked_seller(pool: &PgPool, n: usize) -> (Shop, Vec<BatchEntry>) {
    let shop = make_payment_seller(pool).await;
    let subs = fresh_subs(pool, n).await;
    let sid = seller_id_of(&shop.seller_pub);
    let (text, entries) = build_batch(PAY_MKT, "stagenet", &sid, PRIMARY_A, &subs, 100);
    let stored = upload_batch(pool, shop.seller_id, &text, &cfg())
        .await
        .expect("upload fixture batch");
    assert_eq!(stored, n);
    (shop, entries)
}

async fn create_pay_order(
    pool: &PgPool,
    cfg: &PaymentConfig,
    buyer_id: i64,
    shop: &Shop,
) -> Result<(Order, bool), OrderError> {
    create_order_with_config(
        pool,
        TERMS_MKT,
        buyer_id,
        &shop.listing.public_id,
        1,
        &idem(),
        cfg,
    )
    .await
}

async fn order_state(pool: &PgPool, order: &Order) -> String {
    order_by_public_id(pool, &order.public_id)
        .await
        .expect("order refetch")
        .state
}

async fn pool_entry_state(pool: &PgPool, address: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT state FROM payment_pool_entries WHERE address = $1")
        .bind(address)
        .fetch_optional(pool)
        .await
        .expect("pool entry state query")
}

async fn destinations_count(pool: &PgPool, addrs: &[&str]) -> i64 {
    let owned: Vec<String> = addrs.iter().map(|s| s.to_string()).collect();
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM destinations WHERE address = ANY($1)")
        .bind(&owned)
        .fetch_one(pool)
        .await
        .expect("destinations count")
}

async fn attestation_amount_is_null(pool: &PgPool, order_id: i64) -> Option<bool> {
    sqlx::query_scalar::<_, bool>(
        "SELECT amount_atomic IS NULL FROM payment_attestations WHERE order_id = $1",
    )
    .bind(order_id)
    .fetch_optional(pool)
    .await
    .expect("attestation query")
}

// =====================================================================
// Pure helpers
// =====================================================================

#[test]
fn pure_seller_id_derivation_happy_path() {
    let public = "acct_0123456789abcdef0123456789abcdef";
    assert_eq!(
        payment_seller_id(public).as_deref(),
        Some("acct-0123456789abcdef0123456789abcdef")
    );
    // The derived id uses only [a-z0-9-] (handoff seller_id rule).
    let derived = payment_seller_id(public).unwrap();
    assert!(derived
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
}

#[test]
fn pure_seller_id_rejects_anything_else() {
    for bad in [
        "",
        "acct_",
        "acct_0123456789abcdef0123456789abcde",   // 31 hex
        "acct_0123456789abcdef0123456789abcdef0", // 33 hex
        "acct_0123456789ABCDEF0123456789abcdef",  // uppercase hex (A8)
        "acct_0123456789abcdef0123456789abcdeg",  // non-hex char
        "ord_0123456789abcdef0123456789abcdef",   // wrong prefix
        "acct-0123456789abcdef0123456789abcdef",  // already-hyphen form
        "user_0123456789abcdef0123456789abcdef",
        "acct_0123456789abcdef0123456789abcdef ", // trailing space
    ] {
        assert_eq!(payment_seller_id(bad), None, "input {bad:?} must yield None");
    }
}

#[test]
fn pure_canonical_message_exact_format() {
    let msg = canonical_message(
        PAY_MKT,
        Network::Stagenet,
        "acct-0123456789abcdef0123456789abcdef",
        PRIMARY_A,
        FIX_SUB_1,
    );
    assert_eq!(
        msg,
        format!(
            "xmr-direct-v1|{}|stagenet|acct-0123456789abcdef0123456789abcdef|{}|{}",
            PAY_MKT, PRIMARY_A, FIX_SUB_1
        )
    );
    // One line, ASCII only, no trailing newline (handoff).
    assert!(!msg.contains('\n') && !msg.contains('\r'));
    assert!(msg.is_ascii());
    // Network field follows the network argument.
    assert!(canonical_message("m", Network::Mainnet, "s", "p", "a")
        .starts_with("xmr-direct-v1|m|mainnet|s|p|a"));
    assert!(canonical_message("m", Network::Testnet, "s", "p", "a")
        .starts_with("xmr-direct-v1|m|testnet|s|p|a"));
}

#[test]
fn pure_network_name_spellings() {
    assert_eq!(network_name(Network::Mainnet), "mainnet");
    assert_eq!(network_name(Network::Stagenet), "stagenet");
    assert_eq!(network_name(Network::Testnet), "testnet");
}

#[test]
fn pure_payment_config_defaults_match_contract() {
    let c = PaymentConfig::defaults("some-marketplace");
    assert_eq!(c.marketplace_id, "some-marketplace");
    assert_eq!(c.network, Network::Stagenet);
    assert_eq!(c.max_batch, 100);
    assert_eq!(c.max_unused_pool, 100);
    assert_eq!(c.low_pool_threshold, 10);
    assert_eq!(c.unpaid_expiry_hours, 48);
    assert_eq!(c.open_unpaid_cap, 3);
    assert_eq!(c.order_rate_per_hour, 10);
    assert_eq!(c.reset_warning_days, 30);
    assert!(!c.server_side_signature_check);
}

// =====================================================================
// Payment identity (set_primary_address / get_identity / changed flag)
// =====================================================================

#[tokio::test]
async fn identity_first_set_same_set_and_change_semantics() {
    let pool = pool().await;
    let shop = make_shop(&pool).await;

    // No identity before the first set.
    assert!(get_identity(&pool, shop.seller_id).await.unwrap().is_none());
    assert!(identity_changed_recently(&pool, shop.seller_id, &cfg())
        .await
        .unwrap()
        .is_none());

    // First set: Ok(false) — no change-banner semantics (amendment d).
    let changed = set_primary_address(&pool, shop.seller_id, PRIMARY_A, &cfg())
        .await
        .expect("first set");
    assert!(!changed);
    let ident = get_identity(&pool, shop.seller_id)
        .await
        .unwrap()
        .expect("identity exists after first set");
    assert_eq!(ident.primary_address, PRIMARY_A);
    // changed_at is NULL after a first set (schema = contract; A5).
    let changed_at_null: bool = sqlx::query_scalar(
        "SELECT changed_at IS NULL FROM payment_identities WHERE seller_id = $1",
    )
    .bind(shop.seller_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(changed_at_null, "first set must not stamp changed_at");
    assert!(identity_changed_recently(&pool, shop.seller_id, &cfg())
        .await
        .unwrap()
        .is_none());

    // Re-setting the SAME address: no-op Ok(false), still no stamp.
    let changed = set_primary_address(&pool, shop.seller_id, PRIMARY_A, &cfg())
        .await
        .expect("same set");
    assert!(!changed);
    assert!(identity_changed_recently(&pool, shop.seller_id, &cfg())
        .await
        .unwrap()
        .is_none());

    // Changing to a DIFFERENT address: Ok(true), changed_at stamped,
    // recent-change flag on.
    let changed = set_primary_address(&pool, shop.seller_id, PRIMARY_B, &cfg())
        .await
        .expect("change set");
    assert!(changed, "changing the primary must report changed=true");
    let ident = get_identity(&pool, shop.seller_id).await.unwrap().unwrap();
    assert_eq!(ident.primary_address, PRIMARY_B);
    let changed_at_null: bool = sqlx::query_scalar(
        "SELECT changed_at IS NULL FROM payment_identities WHERE seller_id = $1",
    )
    .bind(shop.seller_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!changed_at_null, "a change must stamp changed_at");
    assert!(identity_changed_recently(&pool, shop.seller_id, &cfg())
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn identity_changed_flag_ages_out_after_warning_window() {
    let pool = pool().await;
    let shop = make_shop(&pool).await;
    set_primary_address(&pool, shop.seller_id, PRIMARY_A, &cfg())
        .await
        .unwrap();
    set_primary_address(&pool, shop.seller_id, PRIMARY_B, &cfg())
        .await
        .unwrap();
    assert!(identity_changed_recently(&pool, shop.seller_id, &cfg())
        .await
        .unwrap()
        .is_some());

    // Backdate the change past the 30-day default warning window.
    sqlx::query(
        "UPDATE payment_identities SET changed_at = now() - interval '31 days' WHERE seller_id = $1",
    )
    .bind(shop.seller_id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        identity_changed_recently(&pool, shop.seller_id, &cfg())
            .await
            .unwrap()
            .is_none(),
        "a 31-day-old change is outside the 30-day warning window"
    );
    // …but inside a 60-day configured window.
    let mut wide = cfg();
    wide.reset_warning_days = 60;
    assert!(identity_changed_recently(&pool, shop.seller_id, &wide)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn identity_rejects_non_standard_or_wrong_network_primaries() {
    let pool = pool().await;
    let shop = make_shop(&pool).await;
    let a_sub = fresh_subs(&pool, 1).await[0];
    let cases: Vec<(&str, String)> = vec![
        ("subaddress as primary", a_sub.to_string()),
        ("integrated address as primary", STAGE_INTEGRATED.to_string()),
        ("mainnet primary on a stagenet instance", MAIN_PRIMARY.to_string()),
        ("testnet primary on a stagenet instance", TEST_PRIMARY.to_string()),
        ("garbage string", "not-a-monero-address".to_string()),
        ("empty string", String::new()),
        ("primary with trailing space (no trimming)", format!("{} ", PRIMARY_A)),
    ];
    for (label, bad) in cases {
        let err = set_primary_address(&pool, shop.seller_id, &bad, &cfg())
            .await
            .expect_err(&format!("{label} must be rejected"));
        assert!(
            matches!(err, PaymentError::BadPrimary(_)),
            "{label} must yield BadPrimary, got {err:?}"
        );
    }
    assert!(
        get_identity(&pool, shop.seller_id).await.unwrap().is_none(),
        "rejected primaries must not create an identity"
    );
}

#[tokio::test]
async fn identity_change_retires_unused_but_keeps_assigned_entries() {
    let pool = pool().await;
    let (shop, entries) = make_stocked_seller(&pool, 3).await;
    let buyer = make_buyer(&pool).await;
    let (order, _) = create_pay_order(&pool, &cfg(), buyer, &shop)
        .await
        .expect("order takes one entry");
    assert!(has_assignment(&pool, order.id).await.unwrap());
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 2);

    // Change identity: unused entries retire, the assigned one survives.
    let changed = set_primary_address(&pool, shop.seller_id, PRIMARY_B, &cfg())
        .await
        .unwrap();
    assert!(changed);
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 0);
    assert_eq!(
        pool_entry_state(&pool, &entries[0].subaddress).await.as_deref(),
        Some("assigned"),
        "the assigned entry of a live order must not be retired by an identity change"
    );
    for e in &entries[1..] {
        assert_eq!(
            pool_entry_state(&pool, &e.subaddress).await.as_deref(),
            Some("retired"),
            "unused entries must retire on identity change"
        );
    }
    // The live order's assignment is still served, byte-identical.
    let a = assignment_for_order(&pool, order.id, &cfg())
        .await
        .unwrap()
        .expect("assignment survives identity change");
    assert_eq!(a.address, entries[0].subaddress);
    assert_eq!(a.message, entries[0].message);
    assert_eq!(a.signature, entries[0].signature);
    // A18: whether Assignment.primary_address tracks the CURRENT
    // identity or the primary in force at assignment time is not
    // pinned by the contract after an identity change (the signed
    // message above still names the original primary, byte-exact),
    // so no assertion is made on it here.
}

// =====================================================================
// Batch upload
// =====================================================================

#[tokio::test]
async fn upload_happy_path_stores_entries_byte_exact_and_globally() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await;
    let subs = fresh_subs(&pool, 3).await;
    let sid = seller_id_of(&shop.seller_pub);
    let (text, entries) = build_batch(PAY_MKT, "stagenet", &sid, PRIMARY_A, &subs, 200);

    let stored = upload_batch(&pool, shop.seller_id, &text, &cfg())
        .await
        .expect("valid batch must be accepted");
    assert_eq!(stored, 3);
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 3);

    // Stored fields are byte-exact as uploaded (hard rule 2).
    for e in &entries {
        let row = sqlx::query(
            "SELECT address, message, signature, state FROM payment_pool_entries WHERE address = $1",
        )
        .bind(&e.subaddress)
        .fetch_one(&pool)
        .await
        .expect("pool entry row");
        assert_eq!(row.get::<String, _>("address"), e.subaddress);
        assert_eq!(row.get::<String, _>("message"), e.message);
        assert_eq!(row.get::<String, _>("signature"), e.signature);
        assert_eq!(row.get::<String, _>("state"), "unused");
    }
    // Every entry also lands in the global destinations table
    // (amendment c), which is what enforces no-reuse across sellers.
    let sub_refs: Vec<&str> = subs.clone();
    assert_eq!(destinations_count(&pool, &sub_refs).await, 3);
    // A batch row records the declared fields and count (schema).
    let batch_count: i64 =
        sqlx::query_scalar("SELECT entry_count::bigint FROM payment_batches WHERE seller_id = $1")
            .bind(shop.seller_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(batch_count, 3);
}

#[tokio::test]
async fn upload_malformed_json_or_shape_is_bad_batch_and_stores_nothing() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await;
    let sid = seller_id_of(&shop.seller_pub);
    let subs = fresh_subs(&pool, 1).await;
    for (label, text) in [
        ("not JSON at all", "this is not json".to_string()),
        ("empty body", String::new()),
        ("JSON array instead of object", "[]".to_string()),
        ("object missing entries", format!(
            "{{\"format\":\"xmr-direct-batch-v1\",\"marketplace_id\":\"{}\",\"network\":\"stagenet\",\"seller_id\":\"{}\",\"primary_address\":\"{}\"}}",
            PAY_MKT, sid, PRIMARY_A
        )),
        ("entry missing signature", format!(
            "{{\"format\":\"xmr-direct-batch-v1\",\"marketplace_id\":\"{}\",\"network\":\"stagenet\",\"seller_id\":\"{}\",\"primary_address\":\"{}\",\"entries\":[{{\"subaddress\":\"{}\",\"message\":\"x\"}}]}}",
            PAY_MKT, sid, PRIMARY_A, subs[0]
        )),
        ("entries not an array", format!(
            "{{\"format\":\"xmr-direct-batch-v1\",\"marketplace_id\":\"{}\",\"network\":\"stagenet\",\"seller_id\":\"{}\",\"primary_address\":\"{}\",\"entries\":{{}}}}",
            PAY_MKT, sid, PRIMARY_A
        )),
    ] {
        let err = upload_batch(&pool, shop.seller_id, &text, &cfg())
            .await
            .expect_err(&format!("{label} must be rejected"));
        assert!(
            matches!(err, PaymentError::BadBatch),
            "{label} must yield BadBatch, got {err:?}"
        );
    }
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 0);
    assert_eq!(destinations_count(&pool, &subs).await, 0);
}

#[tokio::test]
async fn upload_wrong_format_is_rejected() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await;
    let subs = fresh_subs(&pool, 1).await;
    let sid = seller_id_of(&shop.seller_pub);
    let (text, _) = build_batch(PAY_MKT, "stagenet", &sid, PRIMARY_A, &subs, 300);
    let text = text.replacen("xmr-direct-batch-v1", "xmr-direct-batch-v2", 1);
    let err = upload_batch(&pool, shop.seller_id, &text, &cfg())
        .await
        .expect_err("wrong format must be rejected");
    assert!(matches!(err, PaymentError::WrongFormat), "got {err:?}");
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 0);
}

#[tokio::test]
async fn upload_wrong_marketplace_is_rejected() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await;
    let subs = fresh_subs(&pool, 1).await;
    let sid = seller_id_of(&shop.seller_pub);
    // Batch (and its canonical messages) built for a different
    // marketplace id than the instance config.
    let (text, _) = build_batch("other-marketplace", "stagenet", &sid, PRIMARY_A, &subs, 310);
    let err = upload_batch(&pool, shop.seller_id, &text, &cfg())
        .await
        .expect_err("wrong marketplace must be rejected");
    assert!(matches!(err, PaymentError::WrongMarketplace), "got {err:?}");
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 0);
}

#[tokio::test]
async fn upload_wrong_network_is_rejected() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await;
    let subs = fresh_subs(&pool, 1).await;
    let sid = seller_id_of(&shop.seller_pub);
    let (text, _) = build_batch(PAY_MKT, "mainnet", &sid, PRIMARY_A, &subs, 320);
    let err = upload_batch(&pool, shop.seller_id, &text, &cfg())
        .await
        .expect_err("wrong network must be rejected");
    assert!(matches!(err, PaymentError::WrongNetwork), "got {err:?}");
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 0);
}

#[tokio::test]
async fn upload_wrong_seller_is_rejected() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await;
    let (_other_id, other_pub) = make_account(&pool, "seller", 72).await;
    let subs = fresh_subs(&pool, 1).await;
    // Batch names a different account's seller_id.
    let (text, _) = build_batch(
        PAY_MKT,
        "stagenet",
        &seller_id_of(&other_pub),
        PRIMARY_A,
        &subs,
        330,
    );
    let err = upload_batch(&pool, shop.seller_id, &text, &cfg())
        .await
        .expect_err("wrong seller must be rejected");
    assert!(matches!(err, PaymentError::WrongSeller), "got {err:?}");

    // The underscore public-id form is NOT the payment seller_id
    // (amendment f): submitting it must also fail as WrongSeller.
    let (text2, _) = build_batch(PAY_MKT, "stagenet", &shop.seller_pub, PRIMARY_A, &subs, 340);
    let err = upload_batch(&pool, shop.seller_id, &text2, &cfg())
        .await
        .expect_err("underscore-form seller id must be rejected");
    assert!(matches!(err, PaymentError::WrongSeller), "got {err:?}");
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 0);
}

#[tokio::test]
async fn upload_without_identity_is_no_identity() {
    let pool = pool().await;
    let shop = make_shop(&pool).await; // PGP key only, no payment identity
    let subs = fresh_subs(&pool, 1).await;
    let sid = seller_id_of(&shop.seller_pub);
    let (text, _) = build_batch(PAY_MKT, "stagenet", &sid, PRIMARY_A, &subs, 350);
    let err = upload_batch(&pool, shop.seller_id, &text, &cfg())
        .await
        .expect_err("upload before setting a primary must be rejected");
    assert!(matches!(err, PaymentError::NoIdentity), "got {err:?}");
    assert_eq!(destinations_count(&pool, &subs).await, 0);
}

#[tokio::test]
async fn upload_wrong_primary_is_rejected() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await; // identity = PRIMARY_A
    let subs = fresh_subs(&pool, 1).await;
    let sid = seller_id_of(&shop.seller_pub);
    // Batch declares PRIMARY_B (with messages canonical for B).
    let (text, _) = build_batch(PAY_MKT, "stagenet", &sid, PRIMARY_B, &subs, 360);
    let err = upload_batch(&pool, shop.seller_id, &text, &cfg())
        .await
        .expect_err("batch primary differing from identity must be rejected");
    assert!(matches!(err, PaymentError::WrongPrimary), "got {err:?}");
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 0);
}

#[tokio::test]
async fn upload_empty_batch_is_rejected() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await;
    let sid = seller_id_of(&shop.seller_pub);
    let (text, _) = build_batch(PAY_MKT, "stagenet", &sid, PRIMARY_A, &[], 370);
    let err = upload_batch(&pool, shop.seller_id, &text, &cfg())
        .await
        .expect_err("zero entries must be rejected");
    assert!(matches!(err, PaymentError::EmptyBatch), "got {err:?}");
}

#[tokio::test]
async fn upload_batch_over_max_batch_is_rejected_atomically() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await;
    let subs = fresh_subs(&pool, 3).await;
    let sid = seller_id_of(&shop.seller_pub);
    let (text, _) = build_batch(PAY_MKT, "stagenet", &sid, PRIMARY_A, &subs, 380);
    let mut small = cfg();
    small.max_batch = 2;
    let err = upload_batch(&pool, shop.seller_id, &text, &small)
        .await
        .expect_err("3 entries over a max_batch of 2 must be rejected");
    assert!(matches!(err, PaymentError::BatchTooLarge), "got {err:?}");
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 0);
    assert_eq!(destinations_count(&pool, &subs).await, 0);
}

#[tokio::test]
async fn upload_pool_full_boundary_is_enforced_atomically() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await;
    let sid = seller_id_of(&shop.seller_pub);
    let mut capped = cfg();
    capped.max_unused_pool = 5;

    let first = fresh_subs(&pool, 3).await;
    let (text, _) = build_batch(PAY_MKT, "stagenet", &sid, PRIMARY_A, &first, 390);
    assert_eq!(upload_batch(&pool, shop.seller_id, &text, &capped).await.unwrap(), 3);

    // 3 unused + 3 more would exceed the cap of 5: PoolFull, nothing stored.
    let second = fresh_subs(&pool, 3).await;
    let (text, _) = build_batch(PAY_MKT, "stagenet", &sid, PRIMARY_A, &second, 400);
    let err = upload_batch(&pool, shop.seller_id, &text, &capped)
        .await
        .expect_err("exceeding the unused-pool cap must be rejected");
    assert!(matches!(err, PaymentError::PoolFull), "got {err:?}");
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 3);
    assert_eq!(destinations_count(&pool, &second).await, 0);

    // Exactly up to the cap succeeds.
    let third = fresh_subs(&pool, 2).await;
    let (text, _) = build_batch(PAY_MKT, "stagenet", &sid, PRIMARY_A, &third, 410);
    assert_eq!(upload_batch(&pool, shop.seller_id, &text, &capped).await.unwrap(), 2);
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 5);
}

#[tokio::test]
async fn upload_non_subaddress_entries_are_bad_subaddress_and_atomic() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await;
    let sid = seller_id_of(&shop.seller_pub);
    let good = fresh_subs(&pool, 1).await[0];
    let cases: Vec<(&str, String)> = vec![
        ("standard primary as entry", PRIMARY_A.to_string()),
        ("integrated address as entry", STAGE_INTEGRATED.to_string()),
        ("mainnet subaddress as entry", MAIN_SUB.to_string()),
        ("testnet subaddress as entry", TEST_SUB.to_string()),
        ("garbage as entry", "xyz-not-an-address".to_string()),
    ];
    for (label, bad) in cases {
        purge_addresses(&pool, &[bad.as_str()]).await;
        let subs: Vec<&str> = vec![good, bad.as_str()];
        let (text, _) = build_batch(PAY_MKT, "stagenet", &sid, PRIMARY_A, &subs, 420);
        let err = upload_batch(&pool, shop.seller_id, &text, &cfg())
            .await
            .expect_err(&format!("{label} must be rejected"));
        assert!(
            matches!(err, PaymentError::BadSubaddress(_)),
            "{label} must yield BadSubaddress, got {err:?}"
        );
        // All-or-nothing: even the good entry paired with the bad one
        // must not be stored.
        assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 0, "{label}");
        assert_eq!(destinations_count(&pool, &[good]).await, 0, "{label}");
    }
}

#[tokio::test]
async fn upload_message_mismatch_by_even_one_byte_is_rejected() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await;
    let sid = seller_id_of(&shop.seller_pub);
    let sub = fresh_subs(&pool, 1).await[0];
    let canonical = canonical_message(PAY_MKT, Network::Stagenet, &sid, PRIMARY_A, sub);
    let sig = sig_for(430);

    let mut one_char_off = canonical.clone();
    one_char_off.replace_range(0..1, "y"); // xmr-direct-v1 -> ymr-direct-v1
    let wrong_sub_msg = canonical_message(PAY_MKT, Network::Stagenet, &sid, PRIMARY_A, FIX_SUB_1);
    let trailing_space = format!("{} ", canonical);
    let underscore_seller = canonical.replace(&sid, &shop.seller_pub);

    for (label, msg) in [
        ("one character changed", one_char_off),
        ("message naming a different subaddress", wrong_sub_msg),
        ("trailing space appended", trailing_space),
        ("underscore seller id inside message", underscore_seller),
    ] {
        let text = build_batch_with_messages(
            &sid,
            PRIMARY_A,
            &[(sub, msg.as_str(), sig.as_str())],
        );
        let err = upload_batch(&pool, shop.seller_id, &text, &cfg())
            .await
            .expect_err(&format!("{label} must be rejected"));
        assert!(
            matches!(err, PaymentError::MessageMismatch),
            "{label} must yield MessageMismatch, got {err:?}"
        );
    }
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 0);
    assert_eq!(destinations_count(&pool, &[sub]).await, 0);
}

#[tokio::test]
async fn upload_duplicate_within_batch_is_rejected() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await;
    let sid = seller_id_of(&shop.seller_pub);
    let sub = fresh_subs(&pool, 1).await[0];
    let (text, _) = build_batch(PAY_MKT, "stagenet", &sid, PRIMARY_A, &[sub, sub], 440);
    let err = upload_batch(&pool, shop.seller_id, &text, &cfg())
        .await
        .expect_err("same subaddress twice in one batch must be rejected");
    assert!(matches!(err, PaymentError::DuplicateAddress), "got {err:?}");
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 0);
}

#[tokio::test]
async fn upload_duplicate_across_batches_and_sellers_is_rejected() {
    let pool = pool().await;
    let (shop1, entries) = make_stocked_seller(&pool, 1).await;
    let taken = entries[0].subaddress.clone();

    // Same seller, second batch re-using the address (paired with a
    // fresh one): whole batch rejected, fresh one not stored either.
    let shop1_sid = seller_id_of(&shop1.seller_pub);
    let fresh = fresh_subs(&pool, 1).await[0];
    let subs: Vec<&str> = vec![fresh, taken.as_str()];
    let (text, _) = build_batch(PAY_MKT, "stagenet", &shop1_sid, PRIMARY_A, &subs, 450);
    let err = upload_batch(&pool, shop1.seller_id, &text, &cfg())
        .await
        .expect_err("re-upload of a stored address must be rejected");
    assert!(matches!(err, PaymentError::DuplicateAddress), "got {err:?}");
    assert_eq!(unused_count(&pool, shop1.seller_id).await.unwrap(), 1);
    assert_eq!(destinations_count(&pool, &[fresh]).await, 0);

    // A DIFFERENT seller (own identity, own canonical messages) also
    // cannot claim the address: uniqueness is global (hard rule 4).
    let shop2 = make_shop(&pool).await;
    set_primary_address(&pool, shop2.seller_id, PRIMARY_B, &cfg())
        .await
        .unwrap();
    let sid2 = seller_id_of(&shop2.seller_pub);
    let (text, _) = build_batch(PAY_MKT, "stagenet", &sid2, PRIMARY_B, &[taken.as_str()], 460);
    let err = upload_batch(&pool, shop2.seller_id, &text, &cfg())
        .await
        .expect_err("another seller uploading a stored address must be rejected");
    assert!(matches!(err, PaymentError::DuplicateAddress), "got {err:?}");
    assert_eq!(unused_count(&pool, shop2.seller_id).await.unwrap(), 0);
}

#[tokio::test]
async fn upload_server_side_check_enabled_is_unavailable_in_v1() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await;
    let sid = seller_id_of(&shop.seller_pub);
    let subs = fresh_subs(&pool, 1).await;
    let (text, _) = build_batch(PAY_MKT, "stagenet", &sid, PRIMARY_A, &subs, 470);
    let mut checking = cfg();
    checking.server_side_signature_check = true;
    let err = upload_batch(&pool, shop.seller_id, &text, &checking)
        .await
        .expect_err("server-side signature check is not available in v1");
    assert!(
        matches!(err, PaymentError::ServerCheckUnavailable),
        "got {err:?}"
    );
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 0);
}

#[tokio::test]
async fn upload_all_or_nothing_when_last_entry_is_bad() {
    let pool = pool().await;
    let shop = make_payment_seller(&pool).await;
    let sid = seller_id_of(&shop.seller_pub);
    let subs = fresh_subs(&pool, 3).await;
    // First two entries canonical; the third's message is corrupted.
    let bad_msg = canonical_message(PAY_MKT, Network::Stagenet, &sid, PRIMARY_A, subs[2])
        .replacen("stagenet", "stagenetx", 1);
    let m0 = canonical_message(PAY_MKT, Network::Stagenet, &sid, PRIMARY_A, subs[0]);
    let m1 = canonical_message(PAY_MKT, Network::Stagenet, &sid, PRIMARY_A, subs[1]);
    let s0 = sig_for(480);
    let s1 = sig_for(481);
    let s2 = sig_for(482);
    let entries: Vec<(&str, &str, &str)> = vec![
        (subs[0], m0.as_str(), s0.as_str()),
        (subs[1], m1.as_str(), s1.as_str()),
        (subs[2], bad_msg.as_str(), s2.as_str()),
    ];
    let _ = entries;
    let text = build_batch_with_messages(&sid, PRIMARY_A, &entries);
    let err = upload_batch(&pool, shop.seller_id, &text, &cfg())
        .await
        .expect_err("a batch with one bad entry must be rejected whole");
    assert!(matches!(err, PaymentError::MessageMismatch), "got {err:?}");
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 0);
    assert_eq!(destinations_count(&pool, &subs).await, 0);
    let batch_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM payment_batches WHERE seller_id = $1")
            .bind(shop.seller_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(batch_rows, 0, "a rejected batch must leave no batch row");
}

// =====================================================================
// Assignment at order creation
// =====================================================================

#[tokio::test]
async fn assignment_takes_oldest_entry_and_serves_it_byte_identical() {
    let pool = pool().await;
    let (shop, entries) = make_stocked_seller(&pool, 3).await;
    let buyer = make_buyer(&pool).await;

    let (order, created) = create_pay_order(&pool, &cfg(), buyer, &shop)
        .await
        .expect("order from a stocked payment seller");
    assert!(created);
    assert!(has_assignment(&pool, order.id).await.unwrap());
    let a = assignment_for_order(&pool, order.id, &cfg())
        .await
        .unwrap()
        .expect("assignment present");
    // Oldest unused entry first (batch order).
    assert_eq!(a.address, entries[0].subaddress);
    // Byte-identical to what was uploaded (hard rule 2 / pay page).
    assert_eq!(a.message, entries[0].message);
    assert_eq!(a.signature, entries[0].signature);
    assert_eq!(a.primary_address, PRIMARY_A);
    assert_eq!(
        pool_entry_state(&pool, &entries[0].subaddress).await.as_deref(),
        Some("assigned")
    );
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 2);

    // The next order takes the NEXT oldest entry, never the same one.
    let buyer2 = make_buyer(&pool).await;
    let (order2, _) = create_pay_order(&pool, &cfg(), buyer2, &shop)
        .await
        .expect("second order");
    let a2 = assignment_for_order(&pool, order2.id, &cfg()).await.unwrap().unwrap();
    assert_eq!(a2.address, entries[1].subaddress);
    assert_ne!(a2.address, a.address);
}

#[tokio::test]
async fn assignment_concurrent_creations_take_different_entries() {
    let pool = pool().await;
    let (shop, entries) = make_stocked_seller(&pool, 4).await;
    let buyer1 = make_buyer(&pool).await;
    let buyer2 = make_buyer(&pool).await;
    let c = cfg();
    let (r1, r2) = tokio::join!(
        create_pay_order(&pool, &c, buyer1, &shop),
        create_pay_order(&pool, &c, buyer2, &shop)
    );
    let (o1, _) = r1.expect("concurrent order 1");
    let (o2, _) = r2.expect("concurrent order 2");
    let a1 = assignment_for_order(&pool, o1.id, &cfg()).await.unwrap().unwrap();
    let a2 = assignment_for_order(&pool, o2.id, &cfg()).await.unwrap().unwrap();
    assert_ne!(
        a1.address, a2.address,
        "two orders created at the same moment must take different subaddresses"
    );
    let used: Vec<&str> = entries.iter().map(|e| e.subaddress.as_str()).collect();
    assert!(used.contains(&a1.address.as_str()) && used.contains(&a2.address.as_str()));
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 2);
}

#[tokio::test]
async fn assignment_identity_with_empty_pool_refuses_pool_empty() {
    let pool = pool().await;
    // Identity set, never stocked.
    let shop = make_payment_seller(&pool).await;
    let buyer = make_buyer(&pool).await;
    let err = create_pay_order(&pool, &cfg(), buyer, &shop)
        .await
        .expect_err("identity + empty pool must refuse order creation");
    assert!(matches!(err, OrderError::PoolEmpty), "got {err:?}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM orders WHERE buyer_id = $1")
        .bind(buyer)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "a PoolEmpty refusal must create no order");

    // Drained pool: stock exactly one, sell it, next order refuses too.
    let (shop2, _e) = make_stocked_seller(&pool, 1).await;
    let b2 = make_buyer(&pool).await;
    create_pay_order(&pool, &cfg(), b2, &shop2)
        .await
        .expect("the one stocked order");
    let b3 = make_buyer(&pool).await;
    let err = create_pay_order(&pool, &cfg(), b3, &shop2)
        .await
        .expect_err("drained pool must refuse");
    assert!(matches!(err, OrderError::PoolEmpty), "got {err:?}");
}

#[tokio::test]
async fn assignment_no_identity_keeps_legacy_no_assignment_behaviour() {
    let pool = pool().await;
    let shop = make_shop(&pool).await; // no payment identity at all
    let buyer = make_buyer(&pool).await;
    let (order, created) = create_pay_order(&pool, &cfg(), buyer, &shop)
        .await
        .expect("legacy seller orders proceed without an assignment (amendment e)");
    assert!(created);
    assert!(!has_assignment(&pool, order.id).await.unwrap());
    assert!(assignment_for_order(&pool, order.id, &cfg()).await.unwrap().is_none());
}

#[tokio::test]
async fn assignment_cancel_retires_entry_forever() {
    let pool = pool().await;
    let (shop, entries) = make_stocked_seller(&pool, 2).await;
    let buyer = make_buyer(&pool).await;
    let (order, _) = create_pay_order(&pool, &cfg(), buyer, &shop)
        .await
        .unwrap();
    let retired_addr = entries[0].subaddress.clone();

    let state = apply_action(&pool, &order, "cancel", buyer)
        .await
        .expect("buyer cancel from Requested");
    assert_eq!(format!("{:?}", state), "Cancelled");
    assert_eq!(
        pool_entry_state(&pool, &retired_addr).await.as_deref(),
        Some("retired"),
        "a cancelled order's entry retires, never returns to the pool"
    );
    assert_eq!(unused_count(&pool, shop.seller_id).await.unwrap(), 1);

    // A later order takes a FRESH entry.
    let buyer2 = make_buyer(&pool).await;
    let (order2, _) = create_pay_order(&pool, &cfg(), buyer2, &shop)
        .await
        .unwrap();
    let a2 = assignment_for_order(&pool, order2.id, &cfg()).await.unwrap().unwrap();
    assert_eq!(a2.address, entries[1].subaddress);
    assert_ne!(a2.address, retired_addr);

    // The retired address can never be re-uploaded (destinations keeps it).
    let sid = seller_id_of(&shop.seller_pub);
    let (text, _) = build_batch(
        PAY_MKT,
        "stagenet",
        &sid,
        PRIMARY_A,
        &[retired_addr.as_str()],
        490,
    );
    let err = upload_batch(&pool, shop.seller_id, &text, &cfg())
        .await
        .expect_err("re-uploading a retired address must be rejected");
    assert!(matches!(err, PaymentError::DuplicateAddress), "got {err:?}");
}

#[tokio::test]
async fn assignment_decline_retires_entry_forever() {
    let pool = pool().await;
    let (shop, entries) = make_stocked_seller(&pool, 2).await;
    let buyer = make_buyer(&pool).await;
    let (order, _) = create_pay_order(&pool, &cfg(), buyer, &shop)
        .await
        .unwrap();
    let state = apply_action(&pool, &order, "decline", shop.seller_id)
        .await
        .expect("seller decline from Requested");
    assert_eq!(format!("{:?}", state), "Declined");
    assert_eq!(
        pool_entry_state(&pool, &entries[0].subaddress).await.as_deref(),
        Some("retired")
    );
    // Next order takes the fresh second entry.
    let buyer2 = make_buyer(&pool).await;
    let (order2, _) = create_pay_order(&pool, &cfg(), buyer2, &shop)
        .await
        .unwrap();
    let a2 = assignment_for_order(&pool, order2.id, &cfg()).await.unwrap().unwrap();
    assert_eq!(a2.address, entries[1].subaddress);
}

// =====================================================================
// Drain defences — count ONLY assignment-carrying orders (amendment e)
// =====================================================================

#[tokio::test]
async fn drain_open_unpaid_cap_refuses_fourth_and_spares_pool() {
    let pool = pool().await;
    let (shop, _entries) = make_stocked_seller(&pool, 5).await;
    let buyer = make_buyer(&pool).await;
    let mut orders = Vec::new();
    for _ in 0..3 {
        let (o, _) = create_pay_order(&pool, &cfg(), buyer, &shop)
            .await
            .expect("first three open unpaid assigned orders");
        orders.push(o);
    }
    let err = create_pay_order(&pool, &cfg(), buyer, &shop)
        .await
        .expect_err("the 4th open unpaid assigned order must be refused (cap 3)");
    let _ = err; // variant not pinned (A14)
    assert_eq!(
        unused_count(&pool, shop.seller_id).await.unwrap(),
        2,
        "a refused creation must not consume a pool entry"
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM orders WHERE buyer_id = $1")
        .bind(buyer)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 3);

    // Cancelling one frees an open slot; a new order then succeeds
    // (taking a fresh entry, per the retire rule).
    apply_action(&pool, &orders[0], "cancel", buyer).await.unwrap();
    let (o4, _) = create_pay_order(&pool, &cfg(), buyer, &shop)
        .await
        .expect("after a cancel the buyer is below the open cap again");
    assert!(has_assignment(&pool, o4.id).await.unwrap());
}

#[tokio::test]
async fn drain_hourly_rate_refuses_eleventh_assigned_creation() {
    let pool = pool().await;
    let (shop, _entries) = make_stocked_seller(&pool, 12).await;
    let buyer = make_buyer(&pool).await;
    let mut c = cfg();
    c.open_unpaid_cap = 100; // isolate the rate defence from the cap
    // default order_rate_per_hour = 10
    for i in 0..10 {
        create_pay_order(&pool, &c, buyer, &shop)
            .await
            .unwrap_or_else(|e| panic!("assigned creation {} within the rate must succeed: {e:?}", i + 1));
    }
    let res = create_pay_order(&pool, &c, buyer, &shop).await;
    assert!(res.is_err(), "the 11th assigned creation within an hour must be refused");
    assert_eq!(
        unused_count(&pool, shop.seller_id).await.unwrap(),
        2,
        "exactly 10 entries consumed; the refused creation took none"
    );
}

#[tokio::test]
async fn drain_legacy_orders_never_count_toward_cap_or_rate() {
    let pool = pool().await;
    let legacy = make_shop(&pool).await; // no payment identity
    let (stocked, _e) = make_stocked_seller(&pool, 4).await;
    let buyer = make_buyer(&pool).await;
    let mut c = cfg();
    c.open_unpaid_cap = 3;
    c.order_rate_per_hour = 3;

    // Three legacy (assignment-free) orders first.
    for _ in 0..3 {
        create_pay_order(&pool, &c, buyer, &legacy)
            .await
            .expect("legacy order");
    }
    // The buyer's assigned budget must be untouched: three assigned
    // orders still fit under both cap (3) and rate (3).
    for i in 0..3 {
        create_pay_order(&pool, &c, buyer, &stocked)
            .await
            .unwrap_or_else(|e| panic!("assigned order {} must not be charged for legacy orders: {e:?}", i + 1));
    }
    // The fourth ASSIGNED order is refused — the defences did engage,
    // counting only the assigned three.
    assert!(create_pay_order(&pool, &c, buyer, &stocked).await.is_err());
    assert_eq!(unused_count(&pool, stocked.seller_id).await.unwrap(), 1);
}

// =====================================================================
// Mark paid (seller attestation; amendment b)
// =====================================================================

async fn awaiting_order(pool: &PgPool, shop: &Shop, buyer: i64) -> Order {
    let (order, _) = create_pay_order(pool, &cfg(), buyer, shop)
        .await
        .expect("create assigned order");
    let state = apply_action(pool, &order, "accept", shop.seller_id)
        .await
        .expect("accept on an assignment-carrying order (amendment c / A11)");
    assert_eq!(format!("{:?}", state), "AwaitingPayment");
    order_by_public_id(pool, &order.public_id).await.unwrap()
}

#[tokio::test]
async fn mark_paid_happy_path_records_attestation_with_null_amount() {
    let pool = pool().await;
    let (shop, _e) = make_stocked_seller(&pool, 1).await;
    let buyer = make_buyer(&pool).await;
    let order = awaiting_order(&pool, &shop, buyer).await;

    mark_paid(&pool, &order, shop.seller_id, &cfg())
        .await
        .expect("seller marks their awaiting order paid");
    assert_eq!(order_state(&pool, &order).await, "Paid");

    // Exactly one attestation row, submitted by the seller, and its
    // amount_atomic IS NULL — the server records no amount (hard
    // rule 3 / amendment b).
    assert_eq!(
        attestation_amount_is_null(&pool, order.id).await,
        Some(true),
        "a payment_attestations row must exist with amount_atomic NULL"
    );
    let submitter: i64 =
        sqlx::query_scalar("SELECT submitted_by FROM payment_attestations WHERE order_id = $1")
            .bind(order.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(submitter, shop.seller_id);
}

#[tokio::test]
async fn mark_paid_refused_for_buyer_and_stranger() {
    let pool = pool().await;
    let (shop, _e) = make_stocked_seller(&pool, 1).await;
    let buyer = make_buyer(&pool).await;
    let order = awaiting_order(&pool, &shop, buyer).await;
    let stranger = make_buyer(&pool).await;

    for actor in [buyer, stranger] {
        let err = mark_paid(&pool, &order, actor, &cfg())
            .await
            .expect_err("only the seller may mark an order paid");
        assert!(
            matches!(err, PaymentError::NotSeller | PaymentError::TransitionDenied),
            "non-seller mark-paid must be NotSeller or TransitionDenied (A4), got {err:?}"
        );
    }
    assert_eq!(order_state(&pool, &order).await, "AwaitingPayment");
    assert_eq!(attestation_amount_is_null(&pool, order.id).await, None);
}

#[tokio::test]
async fn mark_paid_state_and_assignment_guards() {
    let pool = pool().await;
    let (shop, _e) = make_stocked_seller(&pool, 2).await;
    let buyer = make_buyer(&pool).await;

    // From Requested (not yet accepted): NotAwaitingPayment.
    let (order, _) = create_pay_order(&pool, &cfg(), buyer, &shop)
        .await
        .unwrap();
    let err = mark_paid(&pool, &order, shop.seller_id, &cfg())
        .await
        .expect_err("mark-paid from Requested must be refused");
    assert!(matches!(err, PaymentError::NotAwaitingPayment), "got {err:?}");
    assert_eq!(order_state(&pool, &order).await, "Requested");

    // After a successful mark-paid, a second attempt is also
    // NotAwaitingPayment (the order is Paid now).
    let order2 = awaiting_order(&pool, &shop, buyer).await;
    mark_paid(&pool, &order2, shop.seller_id, &cfg()).await.unwrap();
    let err = mark_paid(&pool, &order2, shop.seller_id, &cfg())
        .await
        .expect_err("double mark-paid must be refused");
    assert!(matches!(err, PaymentError::NotAwaitingPayment), "got {err:?}");

    // An order with NO assignment (legacy seller), forced into
    // AwaitingPayment at the DB level: NoAssignment.
    let legacy = make_shop(&pool).await;
    let (lorder, _) = create_pay_order(&pool, &cfg(), buyer, &legacy)
        .await
        .unwrap();
    sqlx::query("UPDATE orders SET state = 'AwaitingPayment' WHERE id = $1")
        .bind(lorder.id)
        .execute(&pool)
        .await
        .unwrap();
    let lorder = order_by_public_id(&pool, &lorder.public_id).await.unwrap();
    let err = mark_paid(&pool, &lorder, legacy.seller_id, &cfg())
        .await
        .expect_err("mark-paid without an assignment must be refused");
    assert!(matches!(err, PaymentError::NoAssignment), "got {err:?}");

    // Nonexistent order: refused (exact variant unpinned — A3/A17).
    let ghost = Order {
        id: i64::MAX - 7,
        public_id: format!("ord_{:032x}", 0xdeadbeefu128),
        buyer_id: buyer,
        seller_id: shop.seller_id,
        listing_id: shop.listing.internal_id,
        listing_title: "Blind Suite Widget".to_string(),
        state: "AwaitingPayment".to_string(),
        settlement: "direct".to_string(),
        seller_fpr_pinned: fingerprint(7),
        terms_sha256: "0".repeat(64),
        total_atomic: 1_000_000,
        evidence_level: "None".to_string(),
        created_at: "2026-10-15T00:00:00Z".to_string(),
    };
    assert!(mark_paid(&pool, &ghost, shop.seller_id, &cfg()).await.is_err());
}

#[tokio::test]
async fn accept_on_legacy_order_still_requires_invoice() {
    // Amendment (e): orders without an assignment keep the Stage 4
    // behaviour — accept is refused with InvoiceRequired.
    let pool = pool().await;
    let legacy = make_shop(&pool).await;
    let buyer = make_buyer(&pool).await;
    let (order, _) = create_pay_order(&pool, &cfg(), buyer, &legacy)
        .await
        .unwrap();
    let err = apply_action(&pool, &order, "accept", legacy.seller_id)
        .await
        .expect_err("legacy accept without an issued invoice must be refused");
    assert!(matches!(err, OrderError::InvoiceRequired), "got {err:?}");
}

// =====================================================================
// Unpaid-order expiry sweep
// =====================================================================

#[tokio::test]
async fn expiry_cancels_old_assigned_orders_and_retires_entries() {
    let pool = pool().await;
    let (shop, entries) = make_stocked_seller(&pool, 3).await;
    let buyer = make_buyer(&pool).await;

    // Old assigned order still in Requested.
    let (old_order, _) = create_pay_order(&pool, &cfg(), buyer, &shop)
        .await
        .unwrap();
    // Old assigned order already in AwaitingPayment.
    let old_awaiting = awaiting_order(&pool, &shop, buyer).await;
    // Fresh assigned order (must survive).
    let buyer2 = make_buyer(&pool).await;
    let (fresh_order, _) = create_pay_order(&pool, &cfg(), buyer2, &shop)
        .await
        .unwrap();
    // Old UNASSIGNED (legacy) order (must survive — the sweep covers
    // direct orders WITH assignments only).
    let legacy = make_shop(&pool).await;
    let (legacy_order, _) = create_pay_order(&pool, &cfg(), buyer, &legacy)
        .await
        .unwrap();

    // Backdate the old orders by 49h (expiry is 48h) — both the order
    // row and the pool entry assignment stamp (A6).
    for oid in [old_order.id, old_awaiting.id, legacy_order.id] {
        sqlx::query("UPDATE orders SET created_at = now() - interval '49 hours' WHERE id = $1")
            .bind(oid)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE payment_pool_entries SET assigned_at = now() - interval '49 hours', \
             created_at = now() - interval '49 hours' WHERE order_id = $1",
        )
        .bind(oid)
        .execute(&pool)
        .await
        .unwrap();
    }

    let swept = expire_unpaid_orders(&pool, &cfg()).await.unwrap();
    assert!(swept >= 2, "both old assigned orders must be swept, got {swept}");
    assert_eq!(order_state(&pool, &old_order).await, "Cancelled");
    assert_eq!(order_state(&pool, &old_awaiting).await, "Cancelled");
    assert_eq!(order_state(&pool, &fresh_order).await, "Requested");
    assert_eq!(
        order_state(&pool, &legacy_order).await,
        "Requested",
        "unassigned orders are outside the expiry sweep"
    );
    // Expired entries are retired, the fresh one stays assigned.
    assert_eq!(
        pool_entry_state(&pool, &entries[0].subaddress).await.as_deref(),
        Some("retired")
    );
    assert_eq!(
        pool_entry_state(&pool, &entries[1].subaddress).await.as_deref(),
        Some("retired")
    );
    assert_eq!(
        pool_entry_state(&pool, &entries[2].subaddress).await.as_deref(),
        Some("assigned")
    );
    // A second sweep finds nothing more (A12).
    let swept2 = expire_unpaid_orders(&pool, &cfg()).await.unwrap();
    assert_eq!(swept2, 0);

    // The expired address can never be re-uploaded or re-assigned.
    let sid = seller_id_of(&shop.seller_pub);
    let (text, _) = build_batch(
        PAY_MKT,
        "stagenet",
        &sid,
        PRIMARY_A,
        &[entries[0].subaddress.as_str()],
        495,
    );
    // The seller's pool is now empty (2 retired, 1 assigned): top it up
    // first is NOT possible for this address — upload itself refuses.
    let err = upload_batch(&pool, shop.seller_id, &text, &cfg())
        .await
        .expect_err("re-uploading an expired order's address must be rejected");
    assert!(matches!(err, PaymentError::DuplicateAddress), "got {err:?}");
}

// =====================================================================
// Hard rules — source / schema level
// =====================================================================

#[test]
fn hard_rule_migration_0008_stores_no_txids_keys_or_amounts() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migrations/0008_direct_payments_v1.sql"
    );
    let raw = std::fs::read_to_string(path).expect("read migration 0008");
    // Strip `--` comments: the migration's prose discusses the hard
    // rules; only the DDL is under test.
    let ddl: String = raw
        .lines()
        .map(|l| l.split("--").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();

    for forbidden in [
        "txid",
        "seed",
        "spend_key",
        "view_key",
        "wallet_password",
        "wallet_file",
        "received_amount",
        "payment_proof",
        "tx_proof",
    ] {
        assert!(
            !ddl.contains(forbidden),
            "migration 0008 DDL must not store {forbidden}"
        );
    }
    // amount_atomic exists exactly once in the DDL, on
    // payment_attestations (the attestation claim's always-NULL field).
    assert_eq!(ddl.matches("amount_atomic").count(), 1);
    let attestations_at = ddl
        .find("create table payment_attestations")
        .expect("payment_attestations table exists");
    let amount_at = ddl.find("amount_atomic").unwrap();
    assert!(amount_at > attestations_at);
    // The four additive tables of amendment (c) are the migration's
    // whole surface.
    for table in [
        "payment_identities",
        "payment_batches",
        "payment_pool_entries",
        "payment_attestations",
    ] {
        assert!(ddl.contains(&format!("create table {table}")), "missing {table}");
    }
}

#[test]
fn hard_rule_pay_template_makes_no_verified_payment_claim() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/app/templates/pay.html"
    );
    let raw = std::fs::read_to_string(path).expect("read pay.html template");
    let lower = raw.to_lowercase();
    // Amendment (b): Paid direct orders render as "seller confirmed
    // payment"; the word "verified" must not appear as a payment
    // claim. Per the contract pin, tolerate only "unverified" (A10).
    assert!(
        lower.contains("seller confirmed payment"),
        "the pay page must render paid orders as 'seller confirmed payment'"
    );
    let stripped = lower.replace("unverified", "");
    assert!(
        !stripped.contains("verified"),
        "pay.html must not contain the word 'verified' as a payment claim"
    );
}
