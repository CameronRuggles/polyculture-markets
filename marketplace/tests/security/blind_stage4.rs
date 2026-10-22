//! Blind security suite — Stage 4: orders, terms files, inbox.
//!
//! AUTHORSHIP NOTE: This suite was written by a blind test author working
//! ONLY from three documents: Spec v2 (especially §7, §9, §10, §15, §16,
//! §17), `SPEC-V2-AMENDMENTS.md` (amendments win over spec text; in
//! particular the §9 orders entries and the 2026-10-14 §17 ruling that
//! `GET /orders` IS a declared route), and `marketplace/docs/api-contract.md`
//! (§2 ID/integer rules, §7 authorization semantics, §10 order/invoice state
//! machines, §11 Stage 4 surface). The author has NOT seen any implementation
//! code, migrations, stage reports, decision logs, or earlier test suites.
//! Where the documents do not print a signature, the construction is guessed
//! from the contract's style and marked `// GUESS:`; assertions are never
//! guessed — where the documents genuinely do not determine an expected
//! behaviour, the test is `#[ignore]`d with a `DERIVATION-UNCERTAIN:` note.
//!
//! ASSERTIONS, grouped by area (plain language):
//!
//! A. Order state machine, pure domain table (contract §10 / spec §9):
//!    - Requested -> AwaitingPayment is allowed for the core (System) and
//!      the seller, refused for the buyer.
//!    - Requested -> Declined is seller-only; Requested -> Cancelled is
//!      buyer-only.
//!    - AwaitingPayment -> Paid is core-only, and only on evidence
//!      SellerAttested, ProofVerified, or WalletObserved; it is refused on
//!      evidence None and on BuyerReported, and refused for buyer and seller
//!      actors at EVERY evidence level (a buyer's report never yields Paid).
//!    - AwaitingPayment -> Cancelled is allowed for buyer and seller only
//!      when the evidence level is None; any recorded evidence (even
//!      BuyerReported) refuses it, for both actors.
//!    - AwaitingPayment -> Disputed is buyer-only and requires a buyer
//!      report on record (evidence BuyerReported); with no report it is
//!      refused. (The 72-hour wait itself is an app-layer guard; see C.)
//!    - Paid -> Fulfilled is seller-only. Paid -> Disputed is allowed for
//!      buyer and seller, refused for the core.
//!    - Fulfilled -> Completed is allowed for the buyer and the core,
//!      refused for the seller. Fulfilled -> Disputed is buyer-only.
//!    - Disputed -> Resolved is core-side only (contract §10's `Actor` has
//!      no separate Moderator variant; the moderator acts through the
//!      core/System side of the table — see the final report). Buyer and
//!      seller are refused. Disputed -> Completed is buyer-only (dispute
//!      withdrawal).
//!    - Terminal states (Declined, Cancelled, Completed, Resolved) accept
//!      NO further transition: every target state, every actor, every
//!      evidence level is refused.
//!    - Non-table jumps are refused (e.g. Requested -> Paid, Requested ->
//!      Fulfilled, Paid -> Cancelled, Paid -> Completed, Fulfilled ->
//!      Paid, Disputed -> Paid).
//!
//! B. Invoice state machine (contract §10 / spec §9):
//!    - Issued may go to Settled, Expired, Superseded, or Cancelled.
//!    - Settled, Expired, Superseded, and Cancelled accept no transitions,
//!      and no non-Issued state may transition anywhere (including back
//!      to Issued).
//!
//! C. App-layer actions (contract §11 `apply_action`):
//!    - A non-participant (stranger) gets TransitionDenied for every one of
//!      the six action strings.
//!    - `accept` by the seller on a Requested order with no issued invoice
//!      yields InvoiceRequired. `accept` by the buyer is an error.
//!      AMENDMENT (owner decision 2026-10-19 — BL1 completion,
//!      task-2 remainder): the InvoiceRequired clause above is
//!      SUPERSEDED — it is kept verbatim for the record. The owner
//!      delegated the BL1 completion decision to Muse ("do
//!      whatever you think is best", 2026-10-19), who authorized
//!      the BL1 amendment pass and its extension to this file and
//!      blind_direct_v1.rs. The §9 invoice gate in `apply_action`
//!      was removed: the invoice system is retired, nothing issues
//!      invoices, and the gate made assignment-less orders
//!      unacceptable forever. The test
//!      `c_accept_without_issued_invoice_yields_invoice_required`
//!      below is kept visible in its original form, followed by
//!      its replacement asserting the new behaviour (seller accept
//!      succeeds into AwaitingPayment; buyer accept remains an
//!      error). See BL1-TASK2-AMENDMENT-REPORT-2026-10-19.md.
//!    - `decline`: seller moves Requested -> Declined and the new state is
//!      persisted; buyer is refused with TransitionDenied.
//!    - `cancel`: buyer cancels from Requested; seller cancelling from
//!      Requested is refused; from AwaitingPayment, buyer and seller can
//!      cancel while evidence is None, and cancel is refused once any
//!      payment evidence exists.
//!    - `fulfil`: seller moves Paid -> Fulfilled; buyer is refused.
//!    - `complete`: buyer moves Fulfilled -> Completed; seller is refused.
//!    - `dispute`: buyer and seller can dispute from Paid; buyer can
//!      dispute from Fulfilled; seller disputing from Fulfilled is
//!      refused; dispute from AwaitingPayment with no buyer report on
//!      record is refused (72-hour guard unsatisfied); dispute from
//!      Requested is refused.
//!    - Every action attempted on an order already in a terminal state is
//!      refused with TransitionDenied, for buyer, seller, and stranger.
//!    - An unknown action string is refused with TransitionDenied.
//!
//! D. Creation rules (contract §11 / spec §9):
//!    - Only a published listing can be ordered: draft, removed, and
//!      unknown listings are all ListingNotAvailable.
//!    - Buyer == seller is OwnListing.
//!    - A seller with no current identity key is NoSellerKey.
//!    - Quantity 0 is BadQuantity; quantity above the 10,000 bound is
//!      BadQuantity; quantity 10,000 succeeds.
//!    - total_atomic equals unit price x quantity exactly.
//!    - A price x quantity that overflows u64 is an error and creates no
//!      order (never a wrapped total).
//!    - The seller's current key fingerprint is pinned at creation; after
//!      the seller rotates keys, new orders pin the new fingerprint and
//!      existing orders keep the fingerprint pinned at their creation.
//!
//! E. Idempotency (spec §9 / contract §11):
//!    - Same buyer + same idempotency key submitted twice creates one
//!      order; the second result reports not-created and returns the
//!      original (same public id, same terms digest).
//!    - Same buyer + a different key creates a second order.
//!    - A different buyer using the same key string gets an independent
//!      order.
//!    - Replaying an earlier key does not consume new-account quota
//!      (a replay after 3 creations still returns the original; a 4th
//!      distinct key then hits the limit — see F).
//!
//! F. New-account limit (spec §7 via contract §11):
//!    - An account younger than 24 hours may hold at most 3 orders: the
//!      4th creation fails with NewAccountLimit and creates nothing.
//!    - An account older than 24 hours is not limited: a 4th (and 5th)
//!      creation succeeds.
//!
//! G. Terms files (spec §10 / contract §11):
//!    - `build_terms` output begins with the exact header fields in the
//!      exact order (statement-format, marketplace-id, order-id,
//!      listing-id, buyer-account, seller-account,
//!      seller-key-fingerprint, quantity, total-atomic, pricing-module,
//!      created-at), followed by exactly one blank line, then the Title,
//!      Description, Delivery terms, and Refund terms sections in that
//!      order, each label preceding its content.
//!    - CRLF and CR line endings in the free-text inputs normalize to the
//!      same bytes as LF inputs; the output contains no CR byte.
//!    - Non-NFC input normalizes: decomposed and precomposed spellings of
//!      the same text produce identical bytes, in NFC form.
//!    - The terms bytes stored at order creation hash (SHA-256) to the
//!      order's recorded terms_sha256 digest (lowercase hex, 64 chars).
//!    - After the seller edits the listing's title, description, and
//!      terms, the order's stored terms bytes and digest are
//!      byte-identical to before (terms are never regenerated).
//!
//! H. Routes (spec §17 as amended 2026-10-14 / contract §7, §11):
//!    - For every order route — POST /orders, GET /orders,
//!      GET /orders/{id}, GET /orders/{id}/terms.txt, and the six action
//!      POSTs — anonymous actors get LoginRequired and every signed-in
//!      role (Buyer, Seller, Moderator, Admin) gets Allow at the route
//!      layer. GET /orders is asserted explicitly: it IS declared.
//!    - Undeclared methods/paths are Deny for every actor, including
//!      Admin and including anonymous: wrong method on an action path,
//!      DELETE/PUT on order paths, an undeclared action name, and an
//!      unknown path.
//!    - Every order POST route requires CSRF; no order GET route does.
//!
//! I. Object-level access (contract §11 / spec §17):
//!    - `orders_for` returns only orders where the account is the buyer
//!      or the seller; a third account sees none of them, and an account
//!      with no orders sees an empty list.
//!
//! J. Inbox (spec §15 / contract §11):
//!    - Order creation notifies the seller (order requested) and does
//!      not notify the buyer.
//!    - Decline notifies the buyer, not the seller; cancel notifies the
//!      seller, not the buyer; fulfil notifies the buyer, not the
//!      seller; complete notifies the seller, not the buyer; dispute
//!      notifies the counterparty, not the actor.
//!    - Notifications carry only event type, object reference, and time
//!      (the printed tuple shape), the object reference is the order's
//!      public id, and the inbox lists newest first.
//!    - `unread_count` reflects unread entries; `mark_all_read` zeroes
//!      it without deleting entries (the inbox keeps its length and all
//!      entries read back as read).
//!    - `notify` round-trips: an event stored through it appears in the
//!      recipient's inbox, unread, and in no one else's.
//!
//! K. IDs and settlement (contract §2, §11 / amendment §1):
//!    - Created orders carry `ord_`-prefixed public ids of exactly 32
//!      lowercase hex characters after the prefix.
//!    - Created orders have settlement "direct", evidence level "None",
//!      state "Requested", and a canonical (RFC 3339 UTC, `Z`) created_at
//!      timestamp.

use app::orders::{
    apply_action, build_terms, create_order, inbox, mark_all_read, notify, order_by_public_id,
    orders_for, terms_bytes, unread_count, OrderError,
};
// CONSTRUCTION FIX (Stage 4 gate): unread_count added to the import
// list (contract §11 names it in the orders module). No assertion
// affected.
use app::authz::{authorize, route_requires_csrf, Decision, Role};
// CONSTRUCTION FIX (Stage 4 gate): the four authorization names above
// live in app::authz, not the domain crate; the import was re-pointed.
// No assertion affected.
use domain::{
    order_can_transition, invoice_can_transition,
    validate_canonical_timestamp, Actor, EvidenceLevel, InvoiceState, OrderState,
};
use sqlx::{PgPool, Row};
use std::sync::atomic::{AtomicU64, Ordering};

const DB_URL: &str = "postgres://postgres:dev@localhost/marketplace_dev";
// GUESS: the marketplace-id value's format is pinned by contract §2
// (`mkt_` + 32 lowercase hex); the concrete value is a fixture choice.
const MARKETPLACE_ID: &str = "mkt_0123456789abcdef0123456789abcdef";

// ---------------------------------------------------------------------
// Fixture helpers. Constructions only; the implementer may adapt these
// without touching assertions.
//
// Fixtures are inserted with SQL against the table/column names printed
// in spec §16, because the contract prints no account/listing/key
// creation functions for Stages 1–3 — and because two Stage 4 behaviours
// under test (account age for the §7 limit, seller key rotation) are
// only expressible by controlling `accounts.created_at` and the
// `identity_keys` rows directly.
// GUESS: column `id` (internal i64 key) on accounts/listings;
// GUESS: listings columns `public_id`, `delivery_terms`, `refund_terms`
//        (§16 lists only "key fields" for listings; the terms builder in
//        contract §11 takes delivery/refund terms, which must be sourced
//        from the listing at order creation);
// GUESS: listings.status values "published" / "draft" / "removed"
//        (spec §9/§8 prose: published listings can be ordered; unpublished
//        or removed listings are invisible to non-sellers);
// GUESS: identity_keys.certificate is bytea and its contents are never
//        re-validated by the Stage 4 surface (key validation is Stage 3);
// GUESS: identity_keys.status value "current" is grounded in contract §9
//        ("the new key becomes the single `current` row"); "retired" is
//        the guessed counterpart;
// GUESS: accounts.role values are the lowercase Role names from
//        contract §7.
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
    // GUESS: listing public-id prefix is not pinned by contract §2 (its
    // prefix list covers mkt/inv/ord/pool/acct only); `lst_` mirrors the
    // style. Only uniqueness matters to the assertions.
    format!("lst_{:032x}", uniq128())
}

fn fingerprint(seed: u128) -> String {
    // 40 uppercase hex chars — a valid fingerprint shape per spec §10.
    format!("{:040X}", seed & 0xffff_ffff_ffff_ffff_ffffu128)
}

async fn pool() -> PgPool {
    PgPool::connect(DB_URL)
        .await
        .expect("connect to marketplace_dev")
}

/// Create an account `age_hours` old. Returns (internal id, username).
async fn make_account(pool: &PgPool, role: &str, age_hours: i64) -> (i64, String) {
    let username = uniq_name();
    let created = time::OffsetDateTime::now_utc() - time::Duration::hours(age_hours);
    let row = sqlx::query(
        "INSERT INTO accounts (public_id, username, password_hash, role, created_at) \
         VALUES ($1, $2, 'blind-suite-fixture-hash', $3, $4) RETURNING id",
    )
    .bind(acct_public_id())
    .bind(&username)
    .bind(role)
    .bind(created)
    .fetch_one(pool)
    .await
    .expect("insert account fixture");
    (row.get::<i64, _>("id"), username)
}

/// Give `account_id` a current identity key with `fpr`. Returns nothing.
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

/// Retire the account's current key and install `new_fpr` as current,
/// mirroring the storage contract in contract §9 (old row retired, new
/// row becomes the single current row with the next version).
async fn rotate_key(pool: &PgPool, account_id: i64, new_fpr: &str) {
    sqlx::query(
        "UPDATE identity_keys SET status = 'retired', retired_at = now() \
         WHERE account_id = $1 AND status = 'current'",
    )
    .bind(account_id)
    .execute(pool)
    .await
    .expect("retire key fixture");
    sqlx::query(
        "INSERT INTO identity_keys (account_id, certificate, fingerprint, version, status, created_at) \
         VALUES ($1, $2, $3, \
                 (SELECT COALESCE(MAX(version), 0) + 1 FROM identity_keys WHERE account_id = $1), \
                 'current', now())",
    )
    .bind(account_id)
    .bind(b"blind-suite-dummy-certificate-2".to_vec())
    .bind(new_fpr)
    .execute(pool)
    .await
    .expect("insert rotated key fixture");
}

struct ListingFixture {
    public_id: String,
    internal_id: i64,
}

/// Insert a listing for `seller_id`. Returns its public id + internal id.
async fn make_listing(
    pool: &PgPool,
    seller_id: i64,
    price_atomic: i64,
    status: &str,
    title: &str,
    description: &str,
    delivery_terms: &str,
    refund_terms: &str,
) -> ListingFixture {
    let public_id = listing_public_id();
    let row = sqlx::query(
        "INSERT INTO listings (public_id, seller_id, title, description, price_atomic, \
                               pricing_module, destination_module, auto_invoice, status, \
                               delivery_terms, refund_terms) \
         VALUES ($1, $2, $3, $4, $5, 'xmr-only', 'signed-address-pool', false, $6, $7, $8) \
         RETURNING id",
    )
    .bind(&public_id)
    .bind(seller_id)
    .bind(title)
    .bind(description)
    .bind(price_atomic)
    .bind(status)
    .bind(delivery_terms)
    .bind(refund_terms)
    .fetch_one(pool)
    .await
    .expect("insert listing fixture");
    ListingFixture {
        public_id,
        internal_id: row.get::<i64, _>("id"),
    }
}

/// A seller (aged 72h, so the §7 new-account limit never interferes)
/// with a current identity key, plus one published listing.
struct ShopFixture {
    seller_id: i64,
    seller_fpr: String,
    listing: ListingFixture,
}

async fn make_shop(pool: &PgPool, price_atomic: i64) -> ShopFixture {
    let (seller_id, _) = make_account(pool, "seller", 72).await;
    let fpr = fingerprint(uniq128());
    install_key(pool, seller_id, &fpr).await;
    let listing = make_listing(
        pool,
        seller_id,
        price_atomic,
        "published",
        "Blind Suite Widget",
        "A widget described plainly.",
        "Delivery within 3 days.",
        "Refunds within 7 days.",
    )
    .await;
    ShopFixture {
        seller_id,
        seller_fpr: fpr,
        listing,
    }
}

/// Force an order into a state/evidence combination the Stage 4 action
/// surface cannot reach on its own (Paid/Fulfilled require the payment
/// stages; evidence is raised by Stage 8). Columns are spec §16's
/// `orders.state` / `orders.evidence_level`.
async fn force_order_state(pool: &PgPool, order_id: i64, state: &str, evidence: &str) {
    sqlx::query("UPDATE orders SET state = $1, evidence_level = $2 WHERE id = $3")
        .bind(state)
        .bind(evidence)
        .bind(order_id)
        .execute(pool)
        .await
        .expect("force order state fixture");
}

async fn order_count_for_buyer(pool: &PgPool, buyer_id: i64) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM orders WHERE buyer_id = $1")
        .bind(buyer_id)
        .fetch_one(pool)
        .await
        .expect("count orders")
}

async fn sha256_hex(pool: &PgPool, bytes: &[u8]) -> String {
    // PostgreSQL's built-in sha256(bytea) — no extra crate needed.
    sqlx::query_scalar::<_, String>("SELECT encode(sha256($1), 'hex')")
        .bind(bytes)
        .fetch_one(pool)
        .await
        .expect("sha256 via postgres")
}

/// Create one order through the real surface and return it. Buyer is
/// aged 72h unless the caller builds its own.
async fn fresh_order(pool: &PgPool, shop: &ShopFixture, buyer_id: i64) -> app::orders::Order {
    let (order, created) = create_order(
        pool,
        MARKETPLACE_ID,
        buyer_id,
        &shop.listing.public_id,
        1,
        &format!("idem-{:032x}", uniq128()),
    )
    .await
    .expect("create order");
    assert!(created, "fresh order must report newly created");
    order
}

// =====================================================================
// A. Order state machine — pure domain table (contract §10 / spec §9)
// =====================================================================

fn can(from: OrderState, to: OrderState, actor: Actor, ev: EvidenceLevel) -> bool {
    order_can_transition(from, to, actor, ev)
}

#[test]
fn a_requested_to_awaiting_payment_is_core_or_seller() {
    for ev in [EvidenceLevel::None, EvidenceLevel::BuyerReported, EvidenceLevel::SellerAttested, EvidenceLevel::ProofVerified, EvidenceLevel::WalletObserved] {
        assert!(can(OrderState::Requested, OrderState::AwaitingPayment, Actor::Core, ev));
        assert!(can(OrderState::Requested, OrderState::AwaitingPayment, Actor::Seller, ev));
        assert!(!can(OrderState::Requested, OrderState::AwaitingPayment, Actor::Buyer, ev));
    }
}

#[test]
fn a_requested_to_declined_is_seller_only() {
    assert!(can(OrderState::Requested, OrderState::Declined, Actor::Seller, EvidenceLevel::None));
    assert!(!can(OrderState::Requested, OrderState::Declined, Actor::Buyer, EvidenceLevel::None));
    assert!(!can(OrderState::Requested, OrderState::Declined, Actor::Core, EvidenceLevel::None));
}

#[test]
fn a_requested_to_cancelled_is_buyer_only() {
    assert!(can(OrderState::Requested, OrderState::Cancelled, Actor::Buyer, EvidenceLevel::None));
    assert!(!can(OrderState::Requested, OrderState::Cancelled, Actor::Seller, EvidenceLevel::None));
    assert!(!can(OrderState::Requested, OrderState::Cancelled, Actor::Core, EvidenceLevel::None));
}

#[test]
fn a_awaiting_payment_to_paid_is_core_only_on_sufficient_evidence_level() {
    // Sufficient levels: EvidenceLevel::SellerAttested, or EvidenceLevel::ProofVerified / EvidenceLevel::WalletObserved
    // (amount and confirmation guards sit above the pure table, which
    // sees only the level — contract §10's signature takes EvidenceLevel).
    for ev in [EvidenceLevel::SellerAttested, EvidenceLevel::ProofVerified, EvidenceLevel::WalletObserved] {
        assert!(
            can(OrderState::AwaitingPayment, OrderState::Paid, Actor::Core, ev),
            "core must reach Paid on {ev:?}"
        );
    }
    // Below EvidenceLevel::SellerAttested the core must refuse.
    for ev in [EvidenceLevel::None, EvidenceLevel::BuyerReported] {
        assert!(
            !can(OrderState::AwaitingPayment, OrderState::Paid, Actor::Core, ev),
            "core must not reach Paid on {ev:?}"
        );
    }
}

#[test]
fn a_buyers_report_never_produces_paid_for_any_actor() {
    // Spec §3 invariant 11 / §9: a buyer's report alone never reaches
    // Paid — and no non-core actor reaches Paid at any evidence level.
    for actor in [Actor::Buyer, Actor::Seller] {
        for ev in [EvidenceLevel::None, EvidenceLevel::BuyerReported, EvidenceLevel::SellerAttested, EvidenceLevel::ProofVerified, EvidenceLevel::WalletObserved] {
            assert!(
                !can(OrderState::AwaitingPayment, OrderState::Paid, actor, ev),
                "{actor:?} must never move an order to Paid (evidence {ev:?})"
            );
        }
    }
    assert!(!can(
        OrderState::AwaitingPayment,
        OrderState::Paid,
        Actor::Core,
        EvidenceLevel::BuyerReported
    ));
}

#[test]
fn a_awaiting_payment_to_cancelled_requires_no_payment_evidence() {
    for actor in [Actor::Buyer, Actor::Seller] {
        assert!(can(OrderState::AwaitingPayment, OrderState::Cancelled, actor, EvidenceLevel::None));
        for ev in [EvidenceLevel::BuyerReported, EvidenceLevel::SellerAttested, EvidenceLevel::ProofVerified, EvidenceLevel::WalletObserved] {
            assert!(
                !can(OrderState::AwaitingPayment, OrderState::Cancelled, actor, ev),
                "cancel must be refused once evidence {ev:?} exists"
            );
        }
    }
    assert!(!can(OrderState::AwaitingPayment, OrderState::Cancelled, Actor::Core, EvidenceLevel::None));
}

#[test]
fn a_awaiting_payment_to_disputed_is_buyer_with_a_report_on_record() {
    assert!(can(OrderState::AwaitingPayment, OrderState::Disputed, Actor::Buyer, EvidenceLevel::BuyerReported));
    // No report yet -> the §9 guard cannot be satisfied.
    assert!(!can(OrderState::AwaitingPayment, OrderState::Disputed, Actor::Buyer, EvidenceLevel::None));
    // Seller cannot open this dispute row at all.
    assert!(!can(OrderState::AwaitingPayment, OrderState::Disputed, Actor::Seller, EvidenceLevel::BuyerReported));
    assert!(!can(OrderState::AwaitingPayment, OrderState::Disputed, Actor::Core, EvidenceLevel::BuyerReported));
}

#[test]
fn a_paid_to_fulfilled_is_seller_only() {
    assert!(can(OrderState::Paid, OrderState::Fulfilled, Actor::Seller, EvidenceLevel::SellerAttested));
    assert!(!can(OrderState::Paid, OrderState::Fulfilled, Actor::Buyer, EvidenceLevel::SellerAttested));
    assert!(!can(OrderState::Paid, OrderState::Fulfilled, Actor::Core, EvidenceLevel::SellerAttested));
}

#[test]
fn a_paid_to_disputed_is_buyer_or_seller() {
    assert!(can(OrderState::Paid, OrderState::Disputed, Actor::Buyer, EvidenceLevel::SellerAttested));
    assert!(can(OrderState::Paid, OrderState::Disputed, Actor::Seller, EvidenceLevel::SellerAttested));
    assert!(!can(OrderState::Paid, OrderState::Disputed, Actor::Core, EvidenceLevel::SellerAttested));
}

#[test]
fn a_fulfilled_to_completed_is_buyer_or_core() {
    assert!(can(OrderState::Fulfilled, OrderState::Completed, Actor::Buyer, EvidenceLevel::SellerAttested));
    assert!(can(OrderState::Fulfilled, OrderState::Completed, Actor::Core, EvidenceLevel::SellerAttested));
    assert!(!can(OrderState::Fulfilled, OrderState::Completed, Actor::Seller, EvidenceLevel::SellerAttested));
}

#[test]
fn a_fulfilled_to_disputed_is_buyer_only() {
    assert!(can(OrderState::Fulfilled, OrderState::Disputed, Actor::Buyer, EvidenceLevel::SellerAttested));
    assert!(!can(OrderState::Fulfilled, OrderState::Disputed, Actor::Seller, EvidenceLevel::SellerAttested));
    assert!(!can(OrderState::Fulfilled, OrderState::Disputed, Actor::Core, EvidenceLevel::SellerAttested));
}

#[test]
fn a_disputed_to_resolved_is_core_side_only() {
    // Spec §9 names the Moderator. Contract §10 prints
    // `Actor { Buyer, Seller, System }` with no Moderator variant, so the
    // moderator's decision is expressed through the core/System side of
    // the printed table; buyer and seller must be refused either way.
    // CONSTRUCTION FIX (Stage 4 gate): the author's `Actor::Core`
    // glossed both core-side actors of the contract sketch; spec §9
    // names the Moderator for this transition and the domain enum
    // separates Core from Moderator, so this cell maps to Moderator.
    // The asserted expectation (the resolving actor is allowed) is
    // the author's, unchanged.
    assert!(can(OrderState::Disputed, OrderState::Resolved, Actor::Moderator, EvidenceLevel::SellerAttested));
    assert!(!can(OrderState::Disputed, OrderState::Resolved, Actor::Buyer, EvidenceLevel::SellerAttested));
    assert!(!can(OrderState::Disputed, OrderState::Resolved, Actor::Seller, EvidenceLevel::SellerAttested));
}

#[test]
fn a_disputed_to_completed_is_buyer_withdrawal_only() {
    assert!(can(OrderState::Disputed, OrderState::Completed, Actor::Buyer, EvidenceLevel::SellerAttested));
    assert!(!can(OrderState::Disputed, OrderState::Completed, Actor::Seller, EvidenceLevel::SellerAttested));
    assert!(!can(OrderState::Disputed, OrderState::Completed, Actor::Core, EvidenceLevel::SellerAttested));
}

#[test]
fn a_terminal_states_accept_no_further_transitions() {
    let terminals = [
        OrderState::Declined,
        OrderState::Cancelled,
        OrderState::Completed,
        OrderState::Resolved,
    ];
    let targets = [
        OrderState::Requested,
        OrderState::AwaitingPayment,
        OrderState::Paid,
        OrderState::Fulfilled,
        OrderState::Disputed,
        OrderState::Declined,
        OrderState::Cancelled,
        OrderState::Completed,
        OrderState::Resolved,
    ];
    let actors = [Actor::Buyer, Actor::Seller, Actor::Core];
    let evidences = [EvidenceLevel::None, EvidenceLevel::BuyerReported, EvidenceLevel::SellerAttested, EvidenceLevel::ProofVerified, EvidenceLevel::WalletObserved];
    for from in terminals {
        for to in targets {
            for actor in actors {
                for ev in evidences {
                    assert!(
                        !can(from, to, actor, ev),
                        "terminal {from:?} must not transition to {to:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_non_table_jumps_are_refused() {
    let cases: &[(OrderState, OrderState)] = &[
        (OrderState::Requested, OrderState::Paid),
        (OrderState::Requested, OrderState::Fulfilled),
        (OrderState::Requested, OrderState::Disputed),
        (OrderState::Requested, OrderState::Completed),
        (OrderState::Requested, OrderState::Resolved),
        (OrderState::AwaitingPayment, OrderState::Fulfilled),
        (OrderState::AwaitingPayment, OrderState::Completed),
        (OrderState::AwaitingPayment, OrderState::Declined),
        (OrderState::AwaitingPayment, OrderState::Resolved),
        (OrderState::Paid, OrderState::Cancelled),
        (OrderState::Paid, OrderState::Completed),
        (OrderState::Paid, OrderState::Declined),
        (OrderState::Paid, OrderState::AwaitingPayment),
        (OrderState::Fulfilled, OrderState::Paid),
        (OrderState::Fulfilled, OrderState::Cancelled),
        (OrderState::Fulfilled, OrderState::Declined),
        (OrderState::Disputed, OrderState::Paid),
        (OrderState::Disputed, OrderState::Fulfilled),
        (OrderState::Disputed, OrderState::Cancelled),
    ];
    for (from, to) in cases {
        for actor in [Actor::Buyer, Actor::Seller, Actor::Core] {
            for ev in [EvidenceLevel::None, EvidenceLevel::BuyerReported, EvidenceLevel::SellerAttested, EvidenceLevel::ProofVerified, EvidenceLevel::WalletObserved] {
                assert!(!can(*from, *to, actor, ev), "{from:?} -> {to:?} is not in the §9 table");
            }
        }
    }
}

// =====================================================================
// B. Invoice state machine (contract §10 / spec §9)
// GUESS: InvoiceState variant names are the state names in spec §9's
// invoice prose (Issued, Settled, Expired, Superseded, Cancelled); the
// contract prints the type name but elides its variants.
// =====================================================================

#[test]
fn b_issued_invoice_may_settle_expire_be_superseded_or_cancel() {
    assert!(invoice_can_transition(InvoiceState::Issued, InvoiceState::Settled));
    assert!(invoice_can_transition(InvoiceState::Issued, InvoiceState::Expired));
    assert!(invoice_can_transition(InvoiceState::Issued, InvoiceState::Superseded));
    assert!(invoice_can_transition(InvoiceState::Issued, InvoiceState::Cancelled));
}

#[test]
fn b_non_issued_invoice_states_are_terminal() {
    let all = [
        InvoiceState::Issued,
        InvoiceState::Settled,
        InvoiceState::Expired,
        InvoiceState::Superseded,
        InvoiceState::Cancelled,
    ];
    for from in [
        InvoiceState::Settled,
        InvoiceState::Expired,
        InvoiceState::Superseded,
        InvoiceState::Cancelled,
    ] {
        for to in all {
            assert!(
                !invoice_can_transition(from, to),
                "{from:?} is terminal for invoices and must not reach {to:?}"
            );
        }
    }
    // No self-transition on Issued either.
    assert!(!invoice_can_transition(InvoiceState::Issued, InvoiceState::Issued));
}

// =====================================================================
// D. Creation rules (contract §11 / spec §9)
// =====================================================================

#[tokio::test]
async fn d_only_published_listings_can_be_ordered() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;

    for status in ["draft", "removed"] {
        let listing = make_listing(
            &pool,
            shop.seller_id,
            1_000_000,
            status,
            "Hidden Widget",
            "Not for sale yet.",
            "Delivery within 3 days.",
            "Refunds within 7 days.",
        )
        .await;
        let err = create_order(
            &pool,
            MARKETPLACE_ID,
            buyer_id,
            &listing.public_id,
            1,
            &format!("idem-{:032x}", uniq128()),
        )
        .await
        .expect_err("non-published listing must be rejected");
        assert!(
            matches!(err, OrderError::ListingNotAvailable),
            "{status} listing must yield ListingNotAvailable, got {err:?}"
        );
    }

    // Unknown listing id: indistinguishable from not-published.
    let err = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_id,
        &listing_public_id(),
        1,
        &format!("idem-{:032x}", uniq128()),
    )
    .await
    .expect_err("unknown listing must be rejected");
    assert!(matches!(err, OrderError::ListingNotAvailable));
}

#[tokio::test]
async fn d_buyer_cannot_order_own_listing() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let err = create_order(
        &pool,
        MARKETPLACE_ID,
        shop.seller_id, // buyer == seller
        &shop.listing.public_id,
        1,
        &format!("idem-{:032x}", uniq128()),
    )
    .await
    .expect_err("buyer == seller must be rejected");
    assert!(matches!(err, OrderError::OwnListing), "got {err:?}");
}

#[tokio::test]
async fn d_seller_without_current_key_cannot_be_ordered_from() {
    let pool = pool().await;
    let (seller_id, _) = make_account(&pool, "seller", 72).await;
    // Deliberately no identity key installed.
    let listing = make_listing(
        &pool,
        seller_id,
        1_000_000,
        "published",
        "Keyless Widget",
        "Seller never registered a key.",
        "Delivery within 3 days.",
        "Refunds within 7 days.",
    )
    .await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let err = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_id,
        &listing.public_id,
        1,
        &format!("idem-{:032x}", uniq128()),
    )
    .await
    .expect_err("seller with no current key must be rejected");
    assert!(matches!(err, OrderError::NoSellerKey), "got {err:?}");
}

#[tokio::test]
async fn d_quantity_zero_and_above_bound_are_bad_quantity() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;

    let err = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_id,
        &shop.listing.public_id,
        0,
        &format!("idem-{:032x}", uniq128()),
    )
    .await
    .expect_err("quantity 0 must be rejected");
    assert!(matches!(err, OrderError::BadQuantity), "got {err:?}");

    // Contract §11 pins the implementation bound at 10,000.
    let err = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_id,
        &shop.listing.public_id,
        10_001,
        &format!("idem-{:032x}", uniq128()),
    )
    .await
    .expect_err("quantity above the bound must be rejected");
    assert!(matches!(err, OrderError::BadQuantity), "got {err:?}");

    // The bound itself succeeds.
    let (order, created) = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_id,
        &shop.listing.public_id,
        10_000,
        &format!("idem-{:032x}", uniq128()),
    )
    .await
    .expect("quantity at the bound must succeed");
    assert!(created);
    assert_eq!(order.total_atomic, 1_000 * 10_000);
}

#[tokio::test]
async fn d_total_is_unit_price_times_quantity_exactly() {
    let pool = pool().await;
    // 2.5 XMR in atomic units.
    let shop = make_shop(&pool, 2_500_000_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let (order, _) = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_id,
        &shop.listing.public_id,
        3,
        &format!("idem-{:032x}", uniq128()),
    )
    .await
    .expect("create order");
    assert_eq!(order.total_atomic, 7_500_000_000_000i64);
}

#[tokio::test]
async fn d_total_overflow_is_an_error_never_a_wrap() {
    let pool = pool().await;
    // Largest price the listing fixture can carry; x3 overflows u64
    // (3 * i64::MAX > u64::MAX), so checked arithmetic must fail.
    let shop = make_shop(&pool, i64::MAX).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let before = order_count_for_buyer(&pool, buyer_id).await;
    let res = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_id,
        &shop.listing.public_id,
        3,
        &format!("idem-{:032x}", uniq128()),
    )
    .await;
    assert!(res.is_err(), "overflowing total must be an error, never a wrapped order");
    assert_eq!(
        order_count_for_buyer(&pool, buyer_id).await,
        before,
        "an overflowing creation must not persist any (wrapped) order"
    );
}

#[tokio::test]
async fn d_seller_key_fingerprint_is_pinned_at_creation_and_survives_rotation() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;

    let first = fresh_order(&pool, &shop, buyer_id).await;
    assert_eq!(first.seller_fpr_pinned, shop.seller_fpr);

    // Seller rotates to a new current key.
    let new_fpr = fingerprint(uniq128());
    rotate_key(&pool, shop.seller_id, &new_fpr).await;

    // New orders pin the NEW fingerprint...
    let second = fresh_order(&pool, &shop, buyer_id).await;
    assert_eq!(second.seller_fpr_pinned, new_fpr);

    // ...and the existing order's pin is unchanged (spec §8: every order
    // pins the seller's fingerprint at creation).
    let refetched = order_by_public_id(&pool, &first.public_id)
        .await
        .expect("first order still exists");
    assert_eq!(refetched.seller_fpr_pinned, shop.seller_fpr);
}

// =====================================================================
// K. IDs and settlement (contract §2, §11 / amendment §1)
// =====================================================================

#[tokio::test]
async fn k_created_orders_carry_ord_prefixed_ids_direct_settlement_requested_state() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let order = fresh_order(&pool, &shop, buyer_id).await;

    // Contract §2 pattern: ^ord_[0-9a-f]{32}$
    assert!(order.public_id.starts_with("ord_"), "id was {}", order.public_id);
    assert_eq!(order.public_id.len(), 4 + 32);
    assert!(
        order.public_id[4..]
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "id suffix must be 32 lowercase hex chars: {}",
        order.public_id
    );

    assert_eq!(order.settlement, "direct");
    assert_eq!(order.state, "Requested");
    assert_eq!(order.evidence_level, "None");
    assert_eq!(order.buyer_id, buyer_id);
    assert_eq!(order.seller_id, shop.seller_id);
    assert!(
        validate_canonical_timestamp(&order.created_at),
        "created_at must be a canonical RFC 3339 UTC timestamp: {}",
        order.created_at
    );
}

// =====================================================================
// E. Idempotency (spec §9 / contract §11)
// =====================================================================

#[tokio::test]
async fn e_same_buyer_same_key_returns_original_without_creating() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let key = format!("idem-{:032x}", uniq128());

    let (first, created1) = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_id,
        &shop.listing.public_id,
        2,
        &key,
    )
    .await
    .expect("first submission");
    assert!(created1);

    let (second, created2) = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_id,
        &shop.listing.public_id,
        2,
        &key,
    )
    .await
    .expect("replay must return the original result, not an error");
    assert!(!created2, "replay must report not-created");
    assert_eq!(second.public_id, first.public_id);
    assert_eq!(second.id, first.id);
    assert_eq!(second.terms_sha256, first.terms_sha256);
    assert_eq!(second.total_atomic, first.total_atomic);
    assert_eq!(order_count_for_buyer(&pool, buyer_id).await, 1);
}

#[tokio::test]
async fn e_same_buyer_different_key_is_a_second_order() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;

    let (first, c1) = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_id,
        &shop.listing.public_id,
        1,
        &format!("idem-{:032x}", uniq128()),
    )
    .await
    .expect("first order");
    let (second, c2) = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_id,
        &shop.listing.public_id,
        1,
        &format!("idem-{:032x}", uniq128()),
    )
    .await
    .expect("second order with a different key");
    assert!(c1 && c2);
    assert_ne!(second.public_id, first.public_id);
    assert_eq!(order_count_for_buyer(&pool, buyer_id).await, 2);
}

#[tokio::test]
async fn e_different_buyer_same_key_string_is_independent() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_a, _) = make_account(&pool, "buyer", 72).await;
    let (buyer_b, _) = make_account(&pool, "buyer", 72).await;
    let shared_key = format!("idem-{:032x}", uniq128());

    let (order_a, ca) = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_a,
        &shop.listing.public_id,
        1,
        &shared_key,
    )
    .await
    .expect("buyer A order");
    let (order_b, cb) = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_b,
        &shop.listing.public_id,
        1,
        &shared_key,
    )
    .await
    .expect("buyer B order with the same key string");
    assert!(ca && cb, "the key is scoped per buyer (spec §16 unique (buyer_id, idempotency_key))");
    assert_ne!(order_a.public_id, order_b.public_id);
}

// =====================================================================
// F. New-account limit (spec §7 via contract §11)
// Account age is expressed by backdating `accounts.created_at`
// (spec §16) in the fixture — the only printed surface that carries it.
// =====================================================================

#[tokio::test]
async fn f_young_account_holds_at_most_three_orders() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    // One hour old: inside the first-24-hours window.
    let (buyer_id, _) = make_account(&pool, "buyer", 1).await;

    for _ in 0..3 {
        let (_, created) = create_order(
            &pool,
            MARKETPLACE_ID,
            buyer_id,
            &shop.listing.public_id,
            1,
            &format!("idem-{:032x}", uniq128()),
        )
        .await
        .expect("first three orders of a young account must succeed");
        assert!(created);
    }

    let err = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_id,
        &shop.listing.public_id,
        1,
        &format!("idem-{:032x}", uniq128()),
    )
    .await
    .expect_err("the 4th order of a young account must fail");
    assert!(matches!(err, OrderError::NewAccountLimit), "got {err:?}");
    assert_eq!(order_count_for_buyer(&pool, buyer_id).await, 3);
}

#[tokio::test]
async fn f_account_older_than_24_hours_is_not_limited() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    // 48 hours old: outside the window.
    let (buyer_id, _) = make_account(&pool, "buyer", 48).await;

    for i in 0..5 {
        let (_, created) = create_order(
            &pool,
            MARKETPLACE_ID,
            buyer_id,
            &shop.listing.public_id,
            1,
            &format!("idem-{:032x}", uniq128()),
        )
        .await
        .unwrap_or_else(|e| panic!("order {} of an aged account must succeed: {e:?}", i + 1));
        assert!(created);
    }
    assert_eq!(order_count_for_buyer(&pool, buyer_id).await, 5);
}

#[tokio::test]
async fn f_replay_does_not_consume_new_account_quota() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 1).await;
    let first_key = format!("idem-{:032x}", uniq128());

    let (first, _) = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_id,
        &shop.listing.public_id,
        1,
        &first_key,
    )
    .await
    .expect("order 1");
    for _ in 0..2 {
        create_order(
            &pool,
            MARKETPLACE_ID,
            buyer_id,
            &shop.listing.public_id,
            1,
            &format!("idem-{:032x}", uniq128()),
        )
        .await
        .expect("orders 2 and 3");
    }

    // At the limit (3 held). Replaying the first key creates nothing,
    // so it must still return the original rather than the limit error.
    let (replay, created) = create_order(
        &pool,
        MARKETPLACE_ID,
        buyer_id,
        &shop.listing.public_id,
        1,
        &first_key,
    )
    .await
    .expect("replay at the limit must return the original order");
    assert!(!created);
    assert_eq!(replay.public_id, first.public_id);
    assert_eq!(order_count_for_buyer(&pool, buyer_id).await, 3);
}

#[tokio::test]
#[ignore = "DERIVATION-UNCERTAIN: exact 24h boundary"]
async fn f_exact_24h_boundary() {
    // DERIVATION-UNCERTAIN: spec §7 says "for the first 24 hours an
    // account may open at most 3 orders" and contract §11 says accounts
    // "< 24 h old" are limited, which together imply an account exactly
    // 24h old is NOT limited — but no printed surface lets a test set
    // created_at with a defined relationship to the clock the check
    // reads (the amendments flag the clock source itself as a Stage 10
    // open item), so an exact-boundary assertion would race the
    // implementation's clock. The 1h (limited) and 48h (unlimited)
    // points are asserted actively above.
    todo!("exact-boundary account age is not expressible race-free from the printed surface")
}

#[tokio::test]
#[ignore = "DERIVATION-UNCERTAIN: seller-side counting under the §7 limit"]
async fn f_seller_side_holdings_and_the_limit() {
    // DERIVATION-UNCERTAIN: §7 says an account may "hold at most 3
    // orders" / "open at most 3 orders". Whether orders where the young
    // account is the SELLER count toward its own creation limit is not
    // determined by the documents (contract §11 phrases the limit on
    // creation, which is a buyer-side act). Only the buyer-side limit is
    // asserted actively in this suite.
    todo!("documents do not determine whether seller-side orders count toward the holder's limit")
}

// =====================================================================
// C. App-layer actions (contract §11 `apply_action`)
// The actor is derived from the caller's relation to the order.
// =====================================================================

const ACTIONS: [&str; 6] = ["accept", "decline", "cancel", "fulfil", "complete", "dispute"];

#[tokio::test]
async fn c_non_participant_gets_transition_denied_for_every_action() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let (stranger_id, _) = make_account(&pool, "buyer", 72).await;
    let order = fresh_order(&pool, &shop, buyer_id).await;

    for action in ACTIONS {
        let err = apply_action(&pool, &order, action, stranger_id)
            .await
            .expect_err("a non-participant must be refused");
        assert!(
            matches!(err, OrderError::TransitionDenied),
            "stranger action {action} must be TransitionDenied, got {err:?}"
        );
    }
    // And the order is untouched.
    let after = order_by_public_id(&pool, &order.public_id).await.unwrap();
    assert_eq!(after.state, "Requested");
}

// AMENDED 2026-10-19 (BL1 completion, task-2 remainder — owner
// decision chain: the owner delegated the BL1 completion decision
// to Muse with "do whatever you think is best", 2026-10-19; the
// amendment pass authorized on that delegation was extended to
// this file and blind_direct_v1.rs). The original test is kept
// visible, commented out in place; its replacement follows.
//
// #[tokio::test]
// async fn c_accept_without_issued_invoice_yields_invoice_required() {
//     let pool = pool().await;
//     let shop = make_shop(&pool, 1_000_000).await;
//     let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
//     let order = fresh_order(&pool, &shop, buyer_id).await;
//
//     // No invoice exists (invoice issuance is Stage 6/7 surface), so the
//     // seller's accept must be refused with InvoiceRequired, per
//     // contract §11: "until the payment stages, accept is always refused
//     // with that reason".
//     let err = apply_action(&pool, &order, "accept", shop.seller_id)
//         .await
//         .expect_err("accept without an issued invoice must be refused");
//     assert!(matches!(err, OrderError::InvoiceRequired), "got {err:?}");
//
//     // The buyer attempting accept is an error too (wrong actor for the
//     // Requested -> AwaitingPayment seller row). The documents do not pin
//     // whether the actor check or the invoice guard fires first for a
//     // wrong actor, so only the error itself is asserted here.
//     assert!(apply_action(&pool, &order, "accept", buyer_id).await.is_err());
//
//     let after = order_by_public_id(&pool, &order.public_id).await.unwrap();
//     assert_eq!(after.state, "Requested");
// }

#[tokio::test]
async fn c_accept_without_issued_invoice_succeeds_since_bl1_amendment() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let order = fresh_order(&pool, &shop, buyer_id).await;

    // Replacement for the test above (BL1 amendment, 2026-10-19):
    // no invoice exists (nothing issues invoices since Direct
    // Payments retired the invoice system), and with the §9 invoice
    // gate removed from apply_action the seller's accept succeeds
    // and the order moves to AwaitingPayment.
    let state = apply_action(&pool, &order, "accept", shop.seller_id)
        .await
        .expect("seller accept must succeed since the BL1 amendment");
    assert!(matches!(state, OrderState::AwaitingPayment));

    // The buyer attempting accept is an error too (wrong actor for
    // the Requested -> AwaitingPayment seller row).
    assert!(apply_action(&pool, &order, "accept", buyer_id).await.is_err());

    let after = order_by_public_id(&pool, &order.public_id).await.unwrap();
    assert_eq!(after.state, "AwaitingPayment");
}

#[tokio::test]
async fn c_decline_is_seller_only_and_persists() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let order = fresh_order(&pool, &shop, buyer_id).await;

    let err = apply_action(&pool, &order, "decline", buyer_id)
        .await
        .expect_err("buyer cannot decline");
    assert!(matches!(err, OrderError::TransitionDenied), "got {err:?}");

    let state = apply_action(&pool, &order, "decline", shop.seller_id)
        .await
        .expect("seller decline must succeed");
    assert!(matches!(state, OrderState::Declined));
    let after = order_by_public_id(&pool, &order.public_id).await.unwrap();
    assert_eq!(after.state, "Declined");
}

#[tokio::test]
async fn c_cancel_from_requested_is_buyer_only() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let order = fresh_order(&pool, &shop, buyer_id).await;

    let err = apply_action(&pool, &order, "cancel", shop.seller_id)
        .await
        .expect_err("seller cannot cancel a Requested order");
    assert!(matches!(err, OrderError::TransitionDenied), "got {err:?}");

    let state = apply_action(&pool, &order, "cancel", buyer_id)
        .await
        .expect("buyer cancel from Requested must succeed");
    assert!(matches!(state, OrderState::Cancelled));
}

#[tokio::test]
async fn c_cancel_from_awaiting_payment_needs_no_evidence() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;

    // Buyer cancels with no evidence: allowed.
    let o1 = fresh_order(&pool, &shop, buyer_id).await;
    force_order_state(&pool, o1.id, "AwaitingPayment", "None").await;
    let o1 = order_by_public_id(&pool, &o1.public_id).await.unwrap();
    let state = apply_action(&pool, &o1, "cancel", buyer_id)
        .await
        .expect("buyer cancel from AwaitingPayment with no evidence");
    assert!(matches!(state, OrderState::Cancelled));

    // Seller cancels with no evidence: allowed.
    let o2 = fresh_order(&pool, &shop, buyer_id).await;
    force_order_state(&pool, o2.id, "AwaitingPayment", "None").await;
    let o2 = order_by_public_id(&pool, &o2.public_id).await.unwrap();
    let state = apply_action(&pool, &o2, "cancel", shop.seller_id)
        .await
        .expect("seller cancel from AwaitingPayment with no evidence");
    assert!(matches!(state, OrderState::Cancelled));

    // Any payment evidence on record refuses cancel, for both actors.
    for ev in ["BuyerReported", "SellerAttested", "ProofVerified", "WalletObserved"] {
        let o = fresh_order(&pool, &shop, buyer_id).await;
        force_order_state(&pool, o.id, "AwaitingPayment", ev).await;
        let o = order_by_public_id(&pool, &o.public_id).await.unwrap();
        for actor in [buyer_id, shop.seller_id] {
            let err = apply_action(&pool, &o, "cancel", actor)
                .await
                .expect_err("cancel must be refused once payment evidence exists");
            assert!(
                matches!(err, OrderError::TransitionDenied),
                "cancel with evidence {ev} must be TransitionDenied, got {err:?}"
            );
        }
    }
}

#[tokio::test]
async fn c_fulfil_is_seller_only_from_paid() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let order = fresh_order(&pool, &shop, buyer_id).await;
    force_order_state(&pool, order.id, "Paid", "SellerAttested").await;
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();

    let err = apply_action(&pool, &order, "fulfil", buyer_id)
        .await
        .expect_err("buyer cannot fulfil");
    assert!(matches!(err, OrderError::TransitionDenied), "got {err:?}");

    let state = apply_action(&pool, &order, "fulfil", shop.seller_id)
        .await
        .expect("seller fulfil from Paid must succeed");
    assert!(matches!(state, OrderState::Fulfilled));
    let after = order_by_public_id(&pool, &order.public_id).await.unwrap();
    assert_eq!(after.state, "Fulfilled");
}

#[tokio::test]
async fn c_complete_is_buyer_only_from_fulfilled() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let order = fresh_order(&pool, &shop, buyer_id).await;
    force_order_state(&pool, order.id, "Fulfilled", "SellerAttested").await;
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();

    let err = apply_action(&pool, &order, "complete", shop.seller_id)
        .await
        .expect_err("seller cannot complete (buyer or core only)");
    assert!(matches!(err, OrderError::TransitionDenied), "got {err:?}");

    let state = apply_action(&pool, &order, "complete", buyer_id)
        .await
        .expect("buyer complete from Fulfilled must succeed");
    assert!(matches!(state, OrderState::Completed));
}

#[tokio::test]
async fn c_dispute_rows_by_actor_and_state() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;

    // From Paid: buyer may dispute.
    let o = fresh_order(&pool, &shop, buyer_id).await;
    force_order_state(&pool, o.id, "Paid", "SellerAttested").await;
    let o = order_by_public_id(&pool, &o.public_id).await.unwrap();
    let state = apply_action(&pool, &o, "dispute", buyer_id)
        .await
        .expect("buyer dispute from Paid");
    assert!(matches!(state, OrderState::Disputed));

    // From Paid: seller may dispute.
    let o = fresh_order(&pool, &shop, buyer_id).await;
    force_order_state(&pool, o.id, "Paid", "SellerAttested").await;
    let o = order_by_public_id(&pool, &o.public_id).await.unwrap();
    let state = apply_action(&pool, &o, "dispute", shop.seller_id)
        .await
        .expect("seller dispute from Paid");
    assert!(matches!(state, OrderState::Disputed));

    // From Fulfilled: buyer may dispute; seller may not.
    let o = fresh_order(&pool, &shop, buyer_id).await;
    force_order_state(&pool, o.id, "Fulfilled", "SellerAttested").await;
    let o = order_by_public_id(&pool, &o.public_id).await.unwrap();
    let err = apply_action(&pool, &o, "dispute", shop.seller_id)
        .await
        .expect_err("seller cannot dispute from Fulfilled");
    assert!(matches!(err, OrderError::TransitionDenied), "got {err:?}");
    let state = apply_action(&pool, &o, "dispute", buyer_id)
        .await
        .expect("buyer dispute from Fulfilled");
    assert!(matches!(state, OrderState::Disputed));

    // From Requested: nobody may dispute.
    let o = fresh_order(&pool, &shop, buyer_id).await;
    for actor in [buyer_id, shop.seller_id] {
        let err = apply_action(&pool, &o, "dispute", actor)
            .await
            .expect_err("dispute from Requested is not in the table");
        assert!(matches!(err, OrderError::TransitionDenied), "got {err:?}");
    }
}

#[tokio::test]
async fn c_dispute_from_awaiting_payment_without_report_is_refused() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let order = fresh_order(&pool, &shop, buyer_id).await;
    // AwaitingPayment with NO buyer report on record: the §9 guard
    // ("buyer reported payment 72 hours ago") cannot be satisfied.
    force_order_state(&pool, order.id, "AwaitingPayment", "None").await;
    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();

    let err = apply_action(&pool, &order, "dispute", buyer_id)
        .await
        .expect_err("dispute from AwaitingPayment without a buyer report must be refused");
    assert!(matches!(err, OrderError::TransitionDenied), "got {err:?}");

    let err = apply_action(&pool, &order, "dispute", shop.seller_id)
        .await
        .expect_err("seller cannot dispute from AwaitingPayment at all");
    assert!(matches!(err, OrderError::TransitionDenied), "got {err:?}");
}

#[tokio::test]
#[ignore = "DERIVATION-UNCERTAIN: 72h guard inputs not reachable through the printed surface"]
async fn c_dispute_from_awaiting_payment_after_72h_report() {
    // DERIVATION-UNCERTAIN: the satisfied side of the 72-hour guard
    // needs a buyer payment report recorded 72+ hours ago. The printed
    // Stage 4 surface has no function that records a buyer report
    // (evidence submission is Stage 8 surface, and a report attaches to
    // an invoice, which is Stage 6/7 surface), and §16's
    // payment_evidence table keys reports by invoice_id — so the
    // guard's inputs cannot be constructed from the documents alone.
    // The unsatisfied side IS asserted actively (no report -> refused).
    todo!("a 72h-old buyer report cannot be constructed through the printed Stage 4 surface")
}

#[tokio::test]
async fn c_terminal_orders_refuse_every_action_for_everyone() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let (stranger_id, _) = make_account(&pool, "buyer", 72).await;

    for terminal in ["Declined", "Cancelled", "Completed", "Resolved"] {
        let order = fresh_order(&pool, &shop, buyer_id).await;
        force_order_state(&pool, order.id, terminal, "SellerAttested").await;
        let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
        for action in ACTIONS {
            for actor in [buyer_id, shop.seller_id, stranger_id] {
                let err = apply_action(&pool, &order, action, actor)
                    .await
                    .expect_err("terminal orders accept no transitions");
                assert!(
                    matches!(err, OrderError::TransitionDenied),
                    "{terminal} + {action} must be TransitionDenied, got {err:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn c_unknown_action_string_is_refused() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let order = fresh_order(&pool, &shop, buyer_id).await;
    for bogus in ["refund", "pay", "", "Accept"] {
        let err = apply_action(&pool, &order, bogus, shop.seller_id)
            .await
            .expect_err("unknown action must be refused");
        assert!(
            matches!(err, OrderError::TransitionDenied),
            "unknown action {bogus:?} must be TransitionDenied, got {err:?}"
        );
    }
}

#[tokio::test]
#[ignore = "DERIVATION-UNCERTAIN: core auto-complete not expressible via apply_action"]
async fn c_core_auto_complete_via_apply_action() {
    // DERIVATION-UNCERTAIN: Fulfilled -> Completed by "core after the
    // auto-complete window" (spec §9) is asserted in the pure table
    // (Actor::Core). Through `apply_action` the actor is derived from
    // an account's relation to the order (contract §11), and the core
    // is not an account, so the app-layer auto-complete path has no
    // printed construction.
    todo!("core auto-complete has no apply_action construction in the printed surface")
}

// =====================================================================
// I. Object-level access (contract §11 / spec §17)
// =====================================================================

#[tokio::test]
async fn i_orders_for_returns_only_buyer_or_seller_orders() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let (third_id, _) = make_account(&pool, "buyer", 72).await;

    let o1 = fresh_order(&pool, &shop, buyer_id).await;
    let o2 = fresh_order(&pool, &shop, buyer_id).await;

    let buyer_view = orders_for(&pool, buyer_id).await;
    let buyer_ids: Vec<&str> = buyer_view.iter().map(|o| o.public_id.as_str()).collect();
    assert!(buyer_ids.contains(&o1.public_id.as_str()));
    assert!(buyer_ids.contains(&o2.public_id.as_str()));

    let seller_view = orders_for(&pool, shop.seller_id).await;
    let seller_ids: Vec<&str> = seller_view.iter().map(|o| o.public_id.as_str()).collect();
    assert!(seller_ids.contains(&o1.public_id.as_str()));
    assert!(seller_ids.contains(&o2.public_id.as_str()));

    // A third account sees none of them.
    let third_view = orders_for(&pool, third_id).await;
    assert!(
        third_view
            .iter()
            .all(|o| o.public_id != o1.public_id && o.public_id != o2.public_id),
        "a non-participant must not see the order in orders_for"
    );
    assert!(
        third_view.is_empty(),
        "the third account placed/received no orders, so its list is empty"
    );
}

#[tokio::test]
#[ignore = "DERIVATION-UNCERTAIN: detail/terms indistinguishability needs an actor the surface does not take"]
async fn i_nonparticipant_detail_and_terms_indistinguishable_from_nonexistent() {
    // DERIVATION-UNCERTAIN: contract §11 requires a non-participant's
    // view of an order (or its terms) to be indistinguishable from
    // nonexistent — but the printed lookup functions take no actor:
    // `order_by_public_id(pool, public_id)` and `terms_bytes(pool,
    // order_id)`. The indistinguishability therefore lives at the web
    // layer, which this surface cannot express; the expressible half
    // (`orders_for` filtering) is asserted actively above.
    todo!("printed lookups take no actor parameter; web-layer indistinguishability is not expressible here")
}

// =====================================================================
// H. Routes and authorization (spec §17 as amended / contract §7, §11)
// =====================================================================

fn sample_order_path(suffix: &str) -> String {
    format!("/orders/ord_00000000000000000000000000000000{suffix}")
}

#[test]
fn h_order_routes_anonymous_login_required_every_role_allowed() {
    let routes: Vec<(&str, String)> = vec![
        ("POST", "/orders".to_string()),
        ("GET", "/orders".to_string()),
        ("GET", sample_order_path("")),
        ("GET", sample_order_path("/terms.txt")),
        ("POST", sample_order_path("/accept")),
        ("POST", sample_order_path("/decline")),
        ("POST", sample_order_path("/cancel")),
        ("POST", sample_order_path("/fulfil")),
        ("POST", sample_order_path("/complete")),
        ("POST", sample_order_path("/dispute")),
    ];
    for (method, path) in &routes {
        assert!(
            matches!(authorize(method, path, None), Decision::LoginRequired),
            "anonymous {method} {path} must be LoginRequired"
        );
        for role in [Role::Buyer, Role::Seller, Role::Moderator, Role::Admin] {
            let label = format!("{role:?}");
            assert!(
                matches!(authorize(method, path, Some(role)), Decision::Allow),
                "{label} {method} {path} must be Allow at the route layer \
                 (any-authenticated; object-level rules apply after)"
            );
        }
    }
}

#[test]
fn h_get_orders_collection_is_a_declared_route() {
    // Amendment 2026-10-14 (§17): GET /orders IS declared — the orders
    // collection page. It must not fall into the deny-by-default bucket.
    assert!(matches!(authorize("GET", "/orders", None), Decision::LoginRequired));
    for role in [Role::Buyer, Role::Seller, Role::Moderator, Role::Admin] {
        assert!(matches!(authorize("GET", "/orders", Some(role)), Decision::Allow));
    }
}

#[test]
fn h_undeclared_methods_and_paths_are_denied_for_everyone() {
    let undeclared: Vec<(&str, String)> = vec![
        ("DELETE", "/orders".to_string()),
        ("PUT", "/orders".to_string()),
        ("DELETE", sample_order_path("")),
        ("PUT", sample_order_path("")),
        // Wrong method on known paths: actions are POST-only; the
        // detail and terms routes are GET-only.
        ("GET", sample_order_path("/accept")),
        ("GET", sample_order_path("/cancel")),
        ("POST", sample_order_path("")),
        ("POST", sample_order_path("/terms.txt")),
        // Undeclared action name.
        ("POST", sample_order_path("/refund")),
        ("POST", sample_order_path("/pay")),
        // Unknown paths entirely.
        ("GET", "/orders-unknown".to_string()),
        ("POST", "/orderz".to_string()),
    ];
    for (method, path) in &undeclared {
        for role in [None, Some(Role::Buyer), Some(Role::Seller), Some(Role::Moderator), Some(Role::Admin)] {
            let label = format!("{role:?}");
            assert!(
                matches!(authorize(method, path, role), Decision::Deny),
                "undeclared {method} {path} must be Deny for {label} (deny-by-default, Admin included)"
            );
        }
    }
}

#[test]
fn h_every_order_post_requires_csrf_and_no_get_does() {
    // Every declared order POST requires CSRF (contract §7: every
    // state-changing route requires CSRF; no GET does).
    assert!(route_requires_csrf("POST", "/orders"));
    for suffix in ["/accept", "/decline", "/cancel", "/fulfil", "/complete", "/dispute"] {
        assert!(
            route_requires_csrf("POST", &sample_order_path(suffix)),
            "POST {suffix} must require CSRF"
        );
    }
    assert!(!route_requires_csrf("GET", "/orders"));
    assert!(!route_requires_csrf("GET", &sample_order_path("")));
    assert!(!route_requires_csrf("GET", &sample_order_path("/terms.txt")));
}

// =====================================================================
// G. Terms files (spec §10 / contract §11)
// =====================================================================

// GUESS: `build_terms` argument types follow the printed order in
// contract §11 — string fields as &str, quantity as u32 (matching
// create_order), total_atomic as u64 (spec §9: amounts are u64 atomic;
// the Order struct's i64 is the storage-side representation).
fn sample_terms(
    title: &str,
    description: &str,
    delivery: &str,
    refund: &str,
) -> Vec<u8> {
    build_terms(
        MARKETPLACE_ID,
        "ord_11111111111111111111111111111111",
        "lst_22222222222222222222222222222222",
        "buyeracct",
        "selleracct",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        2,
        5_000_000_000_000,
        "xmr-only",
        "2026-10-14T12:00:00Z",
        title,
        description,
        delivery,
        refund,
    )
}

#[test]
fn g_build_terms_header_is_exact_and_in_order_then_one_blank_line() {
    let bytes = sample_terms(
        "TITLE-SENTINEL",
        "DESC-SENTINEL",
        "DELIVERY-SENTINEL",
        "REFUND-SENTINEL",
    );
    let text = String::from_utf8(bytes).expect("terms file is UTF-8");

    let expected_header: [&str; 11] = [
        "statement-format: marketplace-terms-v1",
        "marketplace-id: mkt_0123456789abcdef0123456789abcdef",
        "order-id: ord_11111111111111111111111111111111",
        "listing-id: lst_22222222222222222222222222222222",
        "buyer-account: buyeracct",
        "seller-account: selleracct",
        "seller-key-fingerprint: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "quantity: 2",
        "total-atomic: 5000000000000",
        "pricing-module: xmr-only",
        "created-at: 2026-10-14T12:00:00Z",
    ];
    let lines: Vec<&str> = text.split('\n').collect();
    assert!(
        lines.len() > expected_header.len() + 1,
        "terms file must have a body after the header"
    );
    for (i, expected) in expected_header.iter().enumerate() {
        assert_eq!(lines[i], *expected, "header line {} must be exact", i + 1);
    }
    // Exactly one blank line separates header and body.
    assert_eq!(lines[expected_header.len()], "", "one blank line after the header");
    assert_ne!(
        lines[expected_header.len() + 1],
        "",
        "exactly one blank line, not two"
    );
    // No CR anywhere (LF endings only).
    assert!(!text.contains('\r'), "terms bytes must be LF-only");
}

#[test]
fn g_build_terms_sections_appear_in_order_label_before_content() {
    let bytes = sample_terms(
        "TITLE-SENTINEL",
        "DESC-SENTINEL",
        "DELIVERY-SENTINEL",
        "REFUND-SENTINEL",
    );
    let text = String::from_utf8(bytes).expect("terms file is UTF-8");
    // Contract §11 names the sections Title / Description / Delivery
    // terms / Refund terms, in that order. The exact label punctuation
    // is not printed in any document (see the ignored test below), so
    // this asserts the section words and contents in strict order.
    let pos = |needle: &str| {
        text.find(needle)
            .unwrap_or_else(|| panic!("terms file must contain {needle:?}"))
    };
    let order = [
        pos("Title"),
        pos("TITLE-SENTINEL"),
        pos("Description"),
        pos("DESC-SENTINEL"),
        pos("Delivery"),
        pos("DELIVERY-SENTINEL"),
        pos("Refund"),
        pos("REFUND-SENTINEL"),
    ];
    for w in order.windows(2) {
        assert!(w[0] < w[1], "sections and contents must appear in §11 order");
    }
}

#[test]
fn g_build_terms_normalizes_crlf_and_cr_to_lf() {
    let lf = sample_terms(
        "Title line",
        "first line\nsecond line",
        "deliver\nfast",
        "refund\npolicy",
    );
    let crlf = sample_terms(
        "Title line",
        "first line\r\nsecond line",
        "deliver\r\nfast",
        "refund\r\npolicy",
    );
    let cr = sample_terms(
        "Title line",
        "first line\rsecond line",
        "deliver\rfast",
        "refund\rpolicy",
    );
    assert_eq!(lf, crlf, "CRLF input must normalize to the LF bytes");
    assert_eq!(lf, cr, "CR input must normalize to the LF bytes");
}

#[test]
fn g_build_terms_normalizes_non_nfc_input() {
    // "Café" decomposed (e + U+0301) vs precomposed (U+00E9).
    let decomposed = sample_terms("Cafe\u{301}", "desc", "delivery", "refund");
    let precomposed = sample_terms("Caf\u{e9}", "desc", "delivery", "refund");
    assert_eq!(
        decomposed, precomposed,
        "non-NFC input must normalize to the NFC bytes (spec §10: UTF-8 in NFC)"
    );
    let text = String::from_utf8(decomposed).unwrap();
    assert!(text.contains("Caf\u{e9}"), "output must be in NFC form");
    assert!(
        !text.contains("Cafe\u{301}"),
        "output must not retain the decomposed sequence"
    );
}

#[test]
#[ignore = "DERIVATION-UNCERTAIN: exact section label bytes are not printed in any document"]
// CONSTRUCTION FIX (Stage 4 gate): `async` removed — the body is a
// single todo!() with no awaits, and a plain #[test] cannot be async.
// The test remains #[ignore]d as the author designed.
fn g_build_terms_exact_section_labels() {
    // DERIVATION-UNCERTAIN: spec §10 says the body is "labelled
    // plain-text sections" and contract §11 names them (Title /
    // Description / Delivery terms / Refund terms), but neither prints
    // the exact label lines (e.g. whether a label is `Title:`, a
    // heading, or something else), and spec §10 additionally lists a
    // "selected options" section that contract §11's four-section list
    // and the build_terms parameter list omit. The active tests assert
    // header exactness, section order, and label-before-content; the
    // exact label bytes are left unpinned here.
    todo!("exact terms section label format is not determined by the documents")
}

#[tokio::test]
async fn g_stored_terms_hash_to_the_orders_recorded_digest() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let order = fresh_order(&pool, &shop, buyer_id).await;

    // Digest shape: 64 lowercase hex (spec §10 digest rule).
    assert_eq!(order.terms_sha256.len(), 64);
    assert!(
        order.terms_sha256
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "terms_sha256 must be lowercase hex: {}",
        order.terms_sha256
    );

    let stored = terms_bytes(&pool, order.id)
        .await
        .expect("stored terms bytes must exist for a created order");
    assert_eq!(
        sha256_hex(&pool, &stored).await,
        order.terms_sha256,
        "SHA-256 of the stored bytes must equal the recorded digest"
    );

    // The stored header binds this order, this listing, the pinned
    // fingerprint, and this marketplace.
    let text = String::from_utf8(stored).expect("stored terms are UTF-8");
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("statement-format: marketplace-terms-v1"));
    assert_eq!(
        lines.next(),
        Some(format!("marketplace-id: {MARKETPLACE_ID}").as_str())
    );
    assert_eq!(
        lines.next(),
        Some(format!("order-id: {}", order.public_id).as_str())
    );
    assert_eq!(
        lines.next(),
        Some(format!("listing-id: {}", shop.listing.public_id).as_str())
    );
    // Lines 5 and 6 are the buyer/seller account fields (values are the
    // implementation's account identifiers; keys and order are pinned).
    let l5 = lines.next().expect("buyer-account line");
    assert!(l5.starts_with("buyer-account: ") && l5.len() > "buyer-account: ".len());
    let l6 = lines.next().expect("seller-account line");
    assert!(l6.starts_with("seller-account: ") && l6.len() > "seller-account: ".len());
    assert_eq!(
        lines.next(),
        Some(format!("seller-key-fingerprint: {}", shop.seller_fpr).as_str())
    );
    assert_eq!(lines.next(), Some("quantity: 1"));
    assert_eq!(lines.next(), Some("total-atomic: 1000000"));
}

#[tokio::test]
async fn g_listing_edits_never_touch_existing_terms() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let order = fresh_order(&pool, &shop, buyer_id).await;

    let before = terms_bytes(&pool, order.id).await.expect("terms before edit");
    let digest_before = order.terms_sha256.clone();

    // Seller edits everything the terms were built from.
    sqlx::query(
        "UPDATE listings SET title = 'Completely Different Title', \
                             description = 'A rewritten description.', \
                             delivery_terms = 'Delivery whenever.', \
                             refund_terms = 'No refunds ever.' \
         WHERE id = $1",
    )
    .bind(shop.listing.internal_id)
    .execute(&pool)
    .await
    .expect("edit listing fixture");

    let after = terms_bytes(&pool, order.id).await.expect("terms after edit");
    assert_eq!(before, after, "stored terms bytes must never be regenerated");

    let refetched = order_by_public_id(&pool, &order.public_id).await.unwrap();
    assert_eq!(refetched.terms_sha256, digest_before);
    assert_eq!(sha256_hex(&pool, &after).await, digest_before);
}

// =====================================================================
// J. Inbox (spec §15 / contract §11)
// Event-type SPELLINGS are not pinned by the documents (§15 names the
// events in prose), so flow tests assert recipients, counts, object
// references, ordering, and read state — and the notify() round-trip
// test pins that whatever string is stored comes back verbatim.
// =====================================================================

type InboxEntry = (i64, String, String, String, bool); // (id, event, ref, time, read)

fn refs_of(entries: &[InboxEntry]) -> Vec<&str> {
    entries.iter().map(|e| e.2.as_str()).collect()
}

#[tokio::test]
async fn j_notify_round_trips_and_is_recipient_only() {
    let pool = pool().await;
    let (alice, _) = make_account(&pool, "buyer", 72).await;
    let (bob, _) = make_account(&pool, "buyer", 72).await;
    let object_ref = format!("ord_{:032x}", uniq128());

    notify(&pool, alice, "order_requested", &object_ref).await;

    let alice_inbox = inbox(&pool, alice).await;
    assert_eq!(alice_inbox.len(), 1);
    let (_id, event, obj_ref, when, read) = alice_inbox[0].clone();
    assert_eq!(event, "order_requested", "the stored event type round-trips verbatim");
    assert_eq!(obj_ref, object_ref, "only the object reference is carried");
    assert!(!when.is_empty(), "a time is carried");
    assert!(!read, "a fresh notification is unread");
    assert_eq!(unread_count(&pool, alice).await, 1);

    assert!(inbox(&pool, bob).await.is_empty(), "no one else sees it");
    assert_eq!(unread_count(&pool, bob).await, 0);
}

#[tokio::test]
async fn j_order_creation_notifies_seller_not_buyer() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;

    let seller_before = inbox(&pool, shop.seller_id).await.len();
    let buyer_before = inbox(&pool, buyer_id).await.len();

    let order = fresh_order(&pool, &shop, buyer_id).await;

    let seller_inbox = inbox(&pool, shop.seller_id).await;
    assert_eq!(seller_inbox.len(), seller_before + 1, "seller is notified of the request");
    assert_eq!(
        seller_inbox[0].2, order.public_id,
        "the newest seller notification references the new order"
    );
    assert!(!seller_inbox[0].4, "the notification is unread");
    assert_eq!(unread_count(&pool, shop.seller_id).await as usize, seller_inbox.len());

    assert_eq!(
        inbox(&pool, buyer_id).await.len(),
        buyer_before,
        "the buyer (actor) is not notified of their own order request"
    );
}

/// CONSTRUCTION FIX (Stage 4 gate): helper replacing the author's
/// `async move` closure (see the note inside
/// `j_counterparty_notifications_for_each_action`).
async fn inbox_counts(pool: &PgPool, b: i64, s: i64) -> (usize, usize) {
    (inbox(pool, b).await.len(), inbox(pool, s).await.len())
}

#[tokio::test]
async fn j_counterparty_notifications_for_each_action() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
    let seller = shop.seller_id;

    // CONSTRUCTION FIX (Stage 4 gate): the author's `async move`
    // closure moved `pool` on first use; replaced by the equivalent
    // `inbox_counts` helper below (same values, same call order).
    // Assertions unchanged.
    let counts = |b: i64, s: i64| inbox_counts(&pool, b, s);

    // Decline (seller acts) -> buyer notified, seller not.
    let o = fresh_order(&pool, &shop, buyer_id).await;
    let (b0, s0) = counts(buyer_id, seller).await;
    apply_action(&pool, &o, "decline", seller).await.unwrap();
    let (b1, s1) = counts(buyer_id, seller).await;
    assert_eq!(b1, b0 + 1, "decline notifies the buyer");
    assert_eq!(s1, s0, "decline does not notify the acting seller");
    assert_eq!(inbox(&pool, buyer_id).await[0].2, o.public_id);

    // Cancel (buyer acts) -> seller notified, buyer not.
    let o = fresh_order(&pool, &shop, buyer_id).await;
    let (b0, s0) = counts(buyer_id, seller).await;
    apply_action(&pool, &o, "cancel", buyer_id).await.unwrap();
    let (b1, s1) = counts(buyer_id, seller).await;
    assert_eq!(s1, s0 + 1, "cancel notifies the seller");
    assert_eq!(b1, b0, "cancel does not notify the acting buyer");
    assert_eq!(inbox(&pool, seller).await[0].2, o.public_id);

    // Fulfil (seller acts, from Paid) -> buyer notified, seller not.
    let o = fresh_order(&pool, &shop, buyer_id).await;
    force_order_state(&pool, o.id, "Paid", "SellerAttested").await;
    let o = order_by_public_id(&pool, &o.public_id).await.unwrap();
    let (b0, s0) = counts(buyer_id, seller).await;
    apply_action(&pool, &o, "fulfil", seller).await.unwrap();
    let (b1, s1) = counts(buyer_id, seller).await;
    assert_eq!(b1, b0 + 1, "fulfil notifies the buyer");
    assert_eq!(s1, s0, "fulfil does not notify the acting seller");

    // Complete (buyer acts, from Fulfilled) -> seller notified, buyer not.
    let o = order_by_public_id(&pool, &o.public_id).await.unwrap();
    let (b0, s0) = counts(buyer_id, seller).await;
    apply_action(&pool, &o, "complete", buyer_id).await.unwrap();
    let (b1, s1) = counts(buyer_id, seller).await;
    assert_eq!(s1, s0 + 1, "complete notifies the seller");
    assert_eq!(b1, b0, "complete does not notify the acting buyer");

    // Dispute (buyer acts, from Paid) -> seller notified, buyer not.
    let o = fresh_order(&pool, &shop, buyer_id).await;
    force_order_state(&pool, o.id, "Paid", "SellerAttested").await;
    let o = order_by_public_id(&pool, &o.public_id).await.unwrap();
    let (b0, s0) = counts(buyer_id, seller).await;
    apply_action(&pool, &o, "dispute", buyer_id).await.unwrap();
    let (b1, s1) = counts(buyer_id, seller).await;
    assert_eq!(s1, s0 + 1, "dispute notifies the seller (counterparty)");
    assert_eq!(b1, b0, "dispute does not notify the acting buyer");
    assert_eq!(inbox(&pool, seller).await[0].2, o.public_id);

    // Dispute (seller acts, from Paid) -> buyer notified, seller not.
    let o = fresh_order(&pool, &shop, buyer_id).await;
    force_order_state(&pool, o.id, "Paid", "SellerAttested").await;
    let o = order_by_public_id(&pool, &o.public_id).await.unwrap();
    let (b0, s0) = counts(buyer_id, seller).await;
    apply_action(&pool, &o, "dispute", seller).await.unwrap();
    let (b1, s1) = counts(buyer_id, seller).await;
    assert_eq!(b1, b0 + 1, "seller-opened dispute notifies the buyer");
    assert_eq!(s1, s0, "seller-opened dispute does not notify the acting seller");
}

#[tokio::test]
async fn j_inbox_is_newest_first() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;

    let o1 = fresh_order(&pool, &shop, buyer_id).await;
    let o2 = fresh_order(&pool, &shop, buyer_id).await;
    let o3 = fresh_order(&pool, &shop, buyer_id).await;

    let seller_inbox = inbox(&pool, shop.seller_id).await;
    let refs = refs_of(&seller_inbox);
    assert_eq!(
        refs,
        vec![
            o3.public_id.as_str(),
            o2.public_id.as_str(),
            o1.public_id.as_str()
        ],
        "inbox must list newest first"
    );
    // Ids and times agree with that ordering.
    for w in seller_inbox.windows(2) {
        assert!(w[0].0 > w[1].0, "entry ids descend in a newest-first inbox");
        assert!(w[0].3 >= w[1].3, "entry times are non-increasing in a newest-first inbox");
    }
}

#[tokio::test]
async fn j_unread_count_and_mark_all_read() {
    let pool = pool().await;
    let shop = make_shop(&pool, 1_000_000).await;
    let (buyer_id, _) = make_account(&pool, "buyer", 72).await;

    fresh_order(&pool, &shop, buyer_id).await;
    fresh_order(&pool, &shop, buyer_id).await;

    assert_eq!(unread_count(&pool, shop.seller_id).await, 2);
    let len_before = inbox(&pool, shop.seller_id).await.len();
    assert_eq!(len_before, 2);

    mark_all_read(&pool, shop.seller_id).await;

    assert_eq!(unread_count(&pool, shop.seller_id).await, 0, "mark_all_read zeroes the count");
    let after = inbox(&pool, shop.seller_id).await;
    assert_eq!(after.len(), len_before, "mark_all_read must not delete entries");
    assert!(after.iter().all(|e| e.4), "every entry reads back as read");

    // Marking read again is harmless, and other accounts are unaffected.
    mark_all_read(&pool, shop.seller_id).await;
    assert_eq!(unread_count(&pool, shop.seller_id).await, 0);
    assert_eq!(unread_count(&pool, buyer_id).await, 0);
}
