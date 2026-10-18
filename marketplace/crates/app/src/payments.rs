//! Direct Monero Payments v1 (owner handoff 2026-10-15; plan:
//! DIRECT-PAYMENTS-V1-PLAN.md). Buyers pay sellers directly, wallet to
//! wallet. The server stores seller primary addresses and pre-signed
//! subaddresses, assigns exactly one unused subaddress per order at
//! creation, and records only the seller's attestation when they mark
//! an order paid.
//!
//! HARD RULES (handoff, non-negotiable):
//! - Never accept or store seeds, spend/view keys, wallet passwords or
//!   wallet files. Never store txids, received amounts, or proofs.
//! - Store and serve every uploaded address, message, and signature
//!   BYTE-EXACT as received (JSON string values are taken verbatim —
//!   no trimming, no re-encoding anywhere in this module).
//! - One subaddress per order, never reused — not even after a cancel
//!   or expiry (the entry retires instead of returning to the pool).
//! - No server-side signature verification in v1: the setting exists
//!   (`PAYMENTS_SERVER_SIGNATURE_CHECK`, default off); the buyer's own
//!   wallet is the real check.
//! - No escrow, no tx-proof, no fees. Address validation goes through
//!   modules-api (the vetted `monero` crate) — no hand-rolled Monero
//!   cryptography.
//! - UI copy for a paid direct order is "seller confirmed payment";
//!   the word "verified" is never used as a payment claim here.

use domain::{order_can_transition, Actor, EvidenceLevel, OrderState};
use modules_api::{
    validate_standard_address, DestinationError, EvidenceClaim, EvidenceCx, FormInput,
    Module, ModuleError, ModuleId, PaymentEvidenceProvider, Subaddress,
};
use modules_api::{DestinationProvider, AllocateCx, DestinationProposal, Capability, Network};
use sqlx::PgPool;

// ---------------------------------------------------------------------------
// Settings (handoff "Settings the owner must choose" — config, not
// constants; env names documented per field).

#[derive(Debug, Clone)]
pub struct PaymentConfig {
    /// MARKETPLACE_ID (read in main; the payment config carries the same
    /// value). Baked into every signed message; "vespiary-market".
    pub marketplace_id: String,
    /// INSTANCE_NETWORK: "mainnet" | "stagenet" | "testnet".
    /// Payments accept only the instance network. Default: stagenet.
    pub network: Network,
    /// PAYMENTS_MAX_BATCH — max subaddresses per upload. Default 100.
    pub max_batch: usize,
    /// PAYMENTS_MAX_UNUSED_POOL — max unused entries stored per seller.
    /// Default 100.
    pub max_unused_pool: i64,
    /// PAYMENTS_LOW_POOL_THRESHOLD — notify the seller below this many
    /// unused entries. Default 10.
    pub low_pool_threshold: i64,
    /// PAYMENTS_UNPAID_EXPIRY_HOURS — unpaid direct orders expire after
    /// this. Default 48.
    pub unpaid_expiry_hours: i64,
    /// PAYMENTS_OPEN_UNPAID_CAP — max open unpaid (assignment-carrying)
    /// orders per buyer. Default 3.
    pub open_unpaid_cap: i64,
    /// PAYMENTS_ORDER_RATE_PER_HOUR — assignment-carrying order
    /// creations per buyer per hour. Default 10.
    pub order_rate_per_hour: i64,
    /// PAYMENTS_RESET_WARNING_DAYS — how long the "payment identity
    /// changed" banner shows after a primary-address change. Default 30.
    pub reset_warning_days: i64,
    /// PAYMENTS_SERVER_SIGNATURE_CHECK — server-side signature checking
    /// of uploads. Default off in v1 (no verifier exists; turning it on
    /// rejects uploads rather than pretending to check).
    pub server_side_signature_check: bool,
    /// PAYMENTS_SWEEP_INTERVAL_SECS — expiry sweep interval.
    /// Default 900 (15 min).
    pub sweep_interval_secs: u64,
}

impl PaymentConfig {
    pub fn defaults(marketplace_id: &str) -> PaymentConfig {
        PaymentConfig {
            marketplace_id: marketplace_id.to_string(),
            network: Network::Stagenet,
            max_batch: 100,
            max_unused_pool: 100,
            low_pool_threshold: 10,
            unpaid_expiry_hours: 48,
            open_unpaid_cap: 3,
            order_rate_per_hour: 10,
            reset_warning_days: 30,
            server_side_signature_check: false,
            sweep_interval_secs: 900,
        }
    }

    /// Stage 10: the network is resolved ONCE by
    /// `config::InstanceConfig` (strict, fail-closed: mainnet needs
    /// the production profile + the exact confirmation sentence) and
    /// handed in here. This function must never read INSTANCE_NETWORK
    /// itself — the pre-Stage-10 version silently mapped any
    /// unrecognised value to stagenet and accepted "mainnet" with no
    /// friction, which is exactly the failure mode the profile
    /// resolver exists to close.
    pub fn from_env(marketplace_id: &str, network: Network) -> PaymentConfig {
        let mut cfg = PaymentConfig::defaults(marketplace_id);
        cfg.network = network;
        let num = |name: &str, slot: &mut i64| {
            if let Ok(v) = std::env::var(name) {
                if let Ok(n) = v.parse() {
                    *slot = n;
                }
            }
        };
        if let Ok(v) = std::env::var("PAYMENTS_MAX_BATCH") {
            if let Ok(n) = v.parse() {
                cfg.max_batch = n;
            }
        }
        num("PAYMENTS_MAX_UNUSED_POOL", &mut cfg.max_unused_pool);
        num("PAYMENTS_LOW_POOL_THRESHOLD", &mut cfg.low_pool_threshold);
        num("PAYMENTS_UNPAID_EXPIRY_HOURS", &mut cfg.unpaid_expiry_hours);
        num("PAYMENTS_OPEN_UNPAID_CAP", &mut cfg.open_unpaid_cap);
        num("PAYMENTS_ORDER_RATE_PER_HOUR", &mut cfg.order_rate_per_hour);
        num("PAYMENTS_RESET_WARNING_DAYS", &mut cfg.reset_warning_days);
        if let Ok(v) = std::env::var("PAYMENTS_SWEEP_INTERVAL_SECS") {
            if let Ok(n) = v.parse() {
                cfg.sweep_interval_secs = n;
            }
        }
        cfg.server_side_signature_check =
            std::env::var("PAYMENTS_SERVER_SIGNATURE_CHECK").is_ok_and(|v| v == "1" || v == "true");
        cfg
    }
}

/// The network spelling used inside signed messages and batch files
/// (handoff: `mainnet` or `stagenet`; testnet kept for completeness).
pub fn network_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Stagenet => "stagenet",
        Network::Testnet => "testnet",
    }
}

/// THE payment seller_id derivation (single place, per coordinator
/// decision): `accounts.public_id` is `acct_<32 lowercase hex>`; the
/// handoff requires `[a-z0-9-]` in signed messages, so the payment
/// seller_id is `"acct-" + the 32 hex chars`. Used by the dashboard
/// display, batch validation, and the canonical message rebuild —
/// nowhere else may construct this string.
pub fn payment_seller_id(account_public_id: &str) -> Option<String> {
    let hex = account_public_id.strip_prefix("acct_")?;
    if hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Some(format!("acct-{hex}"))
    } else {
        None
    }
}

/// The canonical signed message (handoff format, one line, ASCII, no
/// trailing newline):
/// `xmr-direct-v1|<marketplace_id>|<network>|<seller_id>|<primary_address>|<subaddress>`
pub fn canonical_message(
    marketplace_id: &str,
    network: Network,
    seller_id: &str,
    primary_address: &str,
    subaddress: &str,
) -> String {
    format!(
        "xmr-direct-v1|{}|{}|{}|{}|{}",
        marketplace_id,
        network_name(network),
        seller_id,
        primary_address,
        subaddress
    )
}

// ---------------------------------------------------------------------------
// The compiled-in direct-v1 module (modules-api traits, Q9 seam).
// Modules propose; the core verifies, records, renders. Allocation is
// core DB work (the trait context carries no store handle), so
// `allocate` proposes nothing — the core's allocation in `orders`
// is the mechanism, and this module owns the evidence claim.

pub struct DirectV1;

impl Module for DirectV1 {
    fn id(&self) -> ModuleId {
        ModuleId("direct-v1")
    }
    fn version(&self) -> semver::Version {
        semver::Version::new(1, 0, 0)
    }
    fn capabilities(&self) -> &[Capability] {
        &[]
    }
}

impl DestinationProvider for DirectV1 {
    fn allocate(&self, _cx: &AllocateCx) -> Result<DestinationProposal, ModuleError> {
        // Allocation takes a row-locked pool entry inside the core's
        // order-creation transaction; a module without a store handle
        // cannot propose one. The core performs it (see orders.rs).
        Err(ModuleError(
            "direct-v1 allocation is performed by the core from the signed pool".into(),
        ))
    }
}

impl PaymentEvidenceProvider for DirectV1 {
    fn claim(&self, _cx: &EvidenceCx, _input: &FormInput) -> Result<EvidenceClaim, ModuleError> {
        // The seller's mark-paid IS the attestation. The amount is None:
        // the handoff forbids recording amounts received.
        Ok(EvidenceClaim::SellerAttestation { amount_atomic: None })
    }
}

// ---------------------------------------------------------------------------
// Errors

#[derive(Debug, PartialEq, Eq)]
pub enum PaymentError {
    /// Batch body is not the expected JSON shape.
    BadBatch,
    WrongFormat,
    WrongMarketplace,
    WrongNetwork,
    WrongSeller,
    NoIdentity,
    WrongPrimary,
    BadPrimary(DestinationError),
    BadSubaddress(DestinationError),
    MessageMismatch,
    DuplicateAddress,
    BatchTooLarge,
    PoolFull,
    EmptyBatch,
    /// PAYMENTS_SERVER_SIGNATURE_CHECK is on but v1 has no verifier.
    ServerCheckUnavailable,
    NotSeller,
    NotAwaitingPayment,
    NoAssignment,
    TransitionDenied,
    NotFound,
    Db,
}

impl From<sqlx::Error> for PaymentError {
    fn from(_: sqlx::Error) -> Self {
        PaymentError::Db
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .map(|d| d.code().as_deref() == Some("23505"))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Seller identity

#[derive(Debug, Clone)]
pub struct PaymentIdentity {
    pub seller_id: i64,
    pub primary_address: String,
    /// Canonical timestamp of the first set ("unchanged since").
    pub created_at: String,
    /// Canonical timestamp of the last change, if any.
    pub changed_at: Option<String>,
}

const TS: &str = "to_char(%COL% AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')";

fn ts_col(col: &str) -> String {
    TS.replace("%COL%", col)
}

pub async fn get_identity(pool: &PgPool, seller_id: i64) -> Result<Option<PaymentIdentity>, PaymentError> {
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(&format!(
        "SELECT primary_address, {}, {} FROM payment_identities WHERE seller_id = $1",
        ts_col("created_at"),
        ts_col("changed_at")
    ))
    .bind(seller_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(primary_address, created_at, changed_at)| PaymentIdentity {
        seller_id,
        primary_address,
        created_at,
        changed_at,
    }))
}

/// Whether the identity was changed recently enough that the
/// "payment identity changed" banner must show (config days window).
/// First set has no banner (changed_at is NULL).
pub async fn identity_changed_recently(
    pool: &PgPool,
    seller_id: i64,
    cfg: &PaymentConfig,
) -> Result<Option<String>, PaymentError> {
    let row: Option<(String,)> = sqlx::query_as(&format!(
        "SELECT {} FROM payment_identities
          WHERE seller_id = $1 AND changed_at IS NOT NULL
            AND changed_at > now() - ($2 || ' days')::interval",
        ts_col("changed_at")
    ))
    .bind(seller_id)
    .bind(cfg.reset_warning_days.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0))
}

/// Validate a primary address for the instance network (standard kind
/// only, via modules-api). Returns the canonical re-encoding.
pub fn validate_primary(input: &str, cfg: &PaymentConfig) -> Result<String, PaymentError> {
    validate_standard_address(input, cfg.network).map_err(PaymentError::BadPrimary)
}

/// Set or change the seller's primary address. First set: creates the
/// identity, no banner. Change to a different address: stamps
/// changed_at and retires every unused pool entry in the same
/// transaction (presentation reset — order/review history is never
/// erased). Setting the same address again is a no-op.
pub async fn set_primary_address(
    pool: &PgPool,
    seller_id: i64,
    primary_address: &str,
    cfg: &PaymentConfig,
) -> Result<bool, PaymentError> {
    let canonical = validate_primary(primary_address, cfg)?;
    let mut tx = pool.begin().await?;
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT primary_address FROM payment_identities WHERE seller_id = $1 FOR UPDATE")
            .bind(seller_id)
            .fetch_optional(&mut *tx)
            .await?;
    match existing {
        None => {
            sqlx::query(
                "INSERT INTO payment_identities (seller_id, primary_address, network)
                 VALUES ($1, $2, $3)",
            )
            .bind(seller_id)
            .bind(&canonical)
            .bind(network_name(cfg.network))
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            // First set is not a *change*: the returned bool means "an
            // existing identity's address changed" (pinned by the locked
            // blind_direct_v1 contract; the change banner is driven by
            // changed_at, which stays NULL on first set).
            Ok(false)
        }
        Some((current,)) if current == canonical => {
            tx.commit().await?;
            Ok(false)
        }
        Some(_) => {
            sqlx::query(
                "UPDATE payment_identities SET primary_address = $2, network = $3, changed_at = now()
                  WHERE seller_id = $1",
            )
            .bind(seller_id)
            .bind(&canonical)
            .bind(network_name(cfg.network))
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE payment_pool_entries SET state = 'retired', retired_at = now()
                  WHERE seller_id = $1 AND state = 'unused'",
            )
            .bind(seller_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(true)
        }
    }
}

pub async fn unused_count(pool: &PgPool, seller_id: i64) -> Result<i64, PaymentError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_pool_entries WHERE seller_id = $1 AND state = 'unused'",
    )
    .bind(seller_id)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

// ---------------------------------------------------------------------------
// Batch upload (all-or-nothing, one transaction)

#[derive(Debug, serde::Deserialize)]
struct BatchFile {
    format: String,
    marketplace_id: String,
    network: String,
    seller_id: String,
    primary_address: String,
    entries: Vec<BatchEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct BatchEntry {
    subaddress: String,
    message: String,
    signature: String,
}

/// Validate and store one uploaded batch. Every check runs before any
/// insert, and the inserts share one transaction: any failure rejects
/// the WHOLE batch. Entry fields are taken from the parsed JSON
/// verbatim — never trimmed or re-encoded (hard rule 2).
pub async fn upload_batch(
    pool: &PgPool,
    seller_id: i64,
    batch_text: &str,
    cfg: &PaymentConfig,
) -> Result<usize, PaymentError> {
    if cfg.server_side_signature_check {
        // v1 ships no verifier; refuse rather than pretend to check.
        return Err(PaymentError::ServerCheckUnavailable);
    }
    let batch: BatchFile = serde_json::from_str(batch_text).map_err(|_| PaymentError::BadBatch)?;
    if batch.format != "xmr-direct-batch-v1" {
        return Err(PaymentError::WrongFormat);
    }
    if batch.marketplace_id != cfg.marketplace_id {
        return Err(PaymentError::WrongMarketplace);
    }
    if batch.network != network_name(cfg.network) {
        return Err(PaymentError::WrongNetwork);
    }
    let seller_pub = crate::db::public_id_of(pool, seller_id)
        .await?
        .ok_or(PaymentError::NotFound)?;
    let want_seller = payment_seller_id(&seller_pub).ok_or(PaymentError::WrongSeller)?;
    if batch.seller_id != want_seller {
        return Err(PaymentError::WrongSeller);
    }
    let identity = get_identity(pool, seller_id).await?.ok_or(PaymentError::NoIdentity)?;
    if batch.primary_address != identity.primary_address {
        return Err(PaymentError::WrongPrimary);
    }
    if batch.entries.is_empty() {
        return Err(PaymentError::EmptyBatch);
    }
    if batch.entries.len() > cfg.max_batch {
        return Err(PaymentError::BatchTooLarge);
    }
    let unused = unused_count(pool, seller_id).await?;
    if unused + batch.entries.len() as i64 > cfg.max_unused_pool {
        return Err(PaymentError::PoolFull);
    }
    // Per-entry checks: subaddress kind/network via modules-api, and
    // the message must equal the canonical rebuild byte-for-byte.
    let mut seen = std::collections::HashSet::new();
    for e in &batch.entries {
        Subaddress::validate(&e.subaddress, cfg.network).map_err(PaymentError::BadSubaddress)?;
        let want = canonical_message(
            &cfg.marketplace_id,
            cfg.network,
            &want_seller,
            &identity.primary_address,
            &e.subaddress,
        );
        if e.message != want {
            return Err(PaymentError::MessageMismatch);
        }
        if !seen.insert(e.subaddress.clone()) {
            return Err(PaymentError::DuplicateAddress);
        }
    }
    // Pre-check the global no-reuse guarantee (the destinations UNIQUE
    // constraint is the enforcement; this gives the clean error).
    for e in &batch.entries {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM destinations WHERE address = $1)")
                .bind(&e.subaddress)
                .fetch_one(pool)
                .await?;
        if exists {
            return Err(PaymentError::DuplicateAddress);
        }
    }
    // All-or-nothing insert.
    let mut tx = pool.begin().await?;
    let (batch_id,): (i64,) = sqlx::query_as(
        "INSERT INTO payment_batches (seller_id, marketplace_id, network, entry_count)
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(seller_id)
    .bind(&batch.marketplace_id)
    .bind(&batch.network)
    .bind(batch.entries.len() as i32)
    .fetch_one(&mut *tx)
    .await?;
    for e in &batch.entries {
        let dest = sqlx::query_as::<_, (i64,)>(
            "INSERT INTO destinations (address, seller_id, source) VALUES ($1, $2, 'pool') RETURNING id",
        )
        .bind(&e.subaddress)
        .bind(seller_id)
        .fetch_one(&mut *tx)
        .await;
        let (destination_id,) = match dest {
            Ok(r) => r,
            Err(e) if is_unique_violation(&e) => {
                tx.rollback().await.ok();
                return Err(PaymentError::DuplicateAddress);
            }
            Err(e) => return Err(e.into()),
        };
        sqlx::query(
            "INSERT INTO payment_pool_entries
                (batch_id, seller_id, destination_id, address, message, signature)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(batch_id)
        .bind(seller_id)
        .bind(destination_id)
        .bind(&e.subaddress)
        .bind(&e.message)
        .bind(&e.signature)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(batch.entries.len())
}

// ---------------------------------------------------------------------------
// Assignment

#[derive(Debug, Clone)]
pub struct Assignment {
    pub entry_id: i64,
    pub address: String,
    pub message: String,
    pub signature: String,
    pub primary_address: String,
    /// Identity first-set timestamp ("unchanged since").
    pub identity_created_at: String,
    /// Identity change timestamp when inside the warning window.
    pub identity_changed_at: Option<String>,
}

pub async fn has_assignment(pool: &PgPool, order_id: i64) -> Result<bool, PaymentError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM payment_pool_entries WHERE order_id = $1)",
    )
    .bind(order_id)
    .fetch_one(pool)
    .await?;
    Ok(exists)
}

pub async fn assignment_for_order(
    pool: &PgPool,
    order_id: i64,
    cfg: &PaymentConfig,
) -> Result<Option<Assignment>, PaymentError> {
    let row: Option<(i64, String, String, String, i64)> = sqlx::query_as(
        "SELECT id, address, message, signature, seller_id
           FROM payment_pool_entries WHERE order_id = $1",
    )
    .bind(order_id)
    .fetch_optional(pool)
    .await?;
    let Some((entry_id, address, message, signature, seller_id)) = row else {
        return Ok(None);
    };
    let identity = get_identity(pool, seller_id).await?.ok_or(PaymentError::NotFound)?;
    let changed = identity_changed_recently(pool, seller_id, cfg).await?;
    // The primary served with an assignment is the one bound in the
    // entry's signed message (field 5 of xmr-direct-v1|...), NOT the
    // seller's current identity: if the seller changed address after
    // this order was assigned, the buyer must still be shown the
    // address whose key made the signature, or wallet verification
    // against the pasted address fails. The message was validated
    // byte-for-byte at upload, so the field always exists; fall back
    // to the identity defensively.
    let message_primary = message
        .split('|')
        .nth(4)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    Ok(Some(Assignment {
        entry_id,
        address,
        message,
        signature,
        primary_address: message_primary.unwrap_or(identity.primary_address),
        identity_created_at: identity.created_at,
        identity_changed_at: changed,
    }))
}

/// Retire an order's pool entry (cancel / decline / expiry). The entry
/// is NEVER returned to the pool: a buyer may still pay late, and the
/// address must never be handed to another order.
pub async fn retire_entry_for_order(
    pool: &PgPool,
    order_id: i64,
) -> Result<(), PaymentError> {
    sqlx::query(
        "UPDATE payment_pool_entries SET state = 'retired', retired_at = now()
          WHERE order_id = $1 AND state = 'assigned'",
    )
    .bind(order_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Mark-paid (seller attestation through the module seam)

/// Seller marks an order paid. The DirectV1 module proposes a
/// `SellerAttestation { amount_atomic: None }` claim; the CORE performs
/// the AwaitingPayment → Paid transition through the domain table
/// (the seller actor alone can never perform it). Only the seller,
/// only from AwaitingPayment, only on an order with an assignment.
pub async fn mark_paid(
    pool: &PgPool,
    order: &crate::orders::Order,
    actor_id: i64,
    cfg: &PaymentConfig,
) -> Result<OrderState, PaymentError> {
    if actor_id != order.seller_id {
        return Err(PaymentError::NotSeller);
    }
    if order.state != "AwaitingPayment" {
        return Err(PaymentError::NotAwaitingPayment);
    }
    let assignment = assignment_for_order(pool, order.id, cfg)
        .await?
        .ok_or(PaymentError::NoAssignment)?;
    let module = DirectV1;
    let cx = EvidenceCx {
        invoice_id: String::new(),
        order_id: order.public_id.clone(),
    };
    let claim = module
        .claim(&cx, &FormInput { fields: vec![] })
        .map_err(|_| PaymentError::TransitionDenied)?;
    let EvidenceClaim::SellerAttestation { amount_atomic } = claim else {
        return Err(PaymentError::TransitionDenied);
    };
    debug_assert!(amount_atomic.is_none(), "direct-v1 never records amounts");
    if !order_can_transition(
        OrderState::AwaitingPayment,
        OrderState::Paid,
        Actor::Core,
        EvidenceLevel::SellerAttested,
    ) {
        return Err(PaymentError::TransitionDenied);
    }
    let mut tx = pool.begin().await?;
    let r = sqlx::query(
        "UPDATE orders SET state = 'Paid', evidence_level = 'SellerAttested'
          WHERE id = $1 AND state = 'AwaitingPayment'",
    )
    .bind(order.id)
    .execute(&mut *tx)
    .await?;
    if r.rows_affected() != 1 {
        tx.rollback().await?;
        return Err(PaymentError::NotAwaitingPayment);
    }
    // The attestation record: no amount, no txid (payment_evidence
    // cannot hold it — its invoice_id is NOT NULL and direct orders
    // have no invoice — so it lands in payment_attestations).
    sqlx::query(
        "INSERT INTO payment_attestations (order_id, pool_entry_id, submitted_by, claim_kind, amount_atomic)
         VALUES ($1, $2, $3, 'seller-attestation', NULL)",
    )
    .bind(order.id)
    .bind(assignment.entry_id)
    .bind(actor_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let _ = crate::orders::notify(pool, order.buyer_id, "order_paid", &order.public_id).await;
    Ok(OrderState::Paid)
}

// ---------------------------------------------------------------------------
// Expiry sweep (minimal in-process form; the general scheduler is
// Stage 10). Cancels unpaid direct orders WITH an assignment whose
// created_at is older than the configured expiry; their entries retire.

pub async fn expire_unpaid_orders(pool: &PgPool, cfg: &PaymentConfig) -> Result<u64, PaymentError> {
    let stale: Vec<(i64, String, i64, i64)> = sqlx::query_as(
        "SELECT o.id, o.public_id, o.buyer_id, o.seller_id FROM orders o
          WHERE o.settlement = 'direct'
            AND o.state IN ('Requested', 'AwaitingPayment')
            AND o.created_at < now() - ($1 || ' hours')::interval
            AND EXISTS (SELECT 1 FROM payment_pool_entries p WHERE p.order_id = o.id)",
    )
    .bind(cfg.unpaid_expiry_hours.to_string())
    .fetch_all(pool)
    .await?;
    let mut count = 0u64;
    for (order_id, public_id, buyer_id, seller_id) in stale {
        let mut tx = pool.begin().await?;
        let r = sqlx::query(
            "UPDATE orders SET state = 'Cancelled', terminal_at = now() WHERE id = $1 AND state IN ('Requested', 'AwaitingPayment')",
        )
        .bind(order_id)
        .execute(&mut *tx)
        .await?;
        if r.rows_affected() == 1 {
            sqlx::query(
                "UPDATE payment_pool_entries SET state = 'retired', retired_at = now()
                  WHERE order_id = $1 AND state = 'assigned'",
            )
            .bind(order_id)
            .execute(&mut *tx)
            .await?;
            count += 1;
        }
        tx.commit().await?;
        let _ = crate::orders::notify(pool, buyer_id, "order_expired", &public_id).await;
        let _ = crate::orders::notify(pool, seller_id, "order_expired", &public_id).await;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seller_id_derivation_is_single_and_strict() {
        assert_eq!(
            payment_seller_id("acct_0123456789abcdef0123456789abcdef").as_deref(),
            Some("acct-0123456789abcdef0123456789abcdef")
        );
        assert_eq!(payment_seller_id("acct_0123"), None);
        assert_eq!(payment_seller_id("acct_0123456789ABCDEF0123456789abcdef"), None);
        assert_eq!(payment_seller_id("ord_0123456789abcdef0123456789abcdef"), None);
    }

    #[test]
    fn canonical_message_shape() {
        let m = canonical_message(
            "vespiary-market",
            Network::Stagenet,
            "acct-0123456789abcdef0123456789abcdef",
            "55b6PRIMARY",
            "7BnSUB",
        );
        assert_eq!(
            m,
            "xmr-direct-v1|vespiary-market|stagenet|acct-0123456789abcdef0123456789abcdef|55b6PRIMARY|7BnSUB"
        );
        assert!(!m.ends_with('\n') && !m.contains('\n'));
    }

    #[test]
    fn direct_module_claim_is_amountless_attestation() {
        let cx = EvidenceCx { invoice_id: String::new(), order_id: "ord_x".into() };
        match DirectV1.claim(&cx, &FormInput { fields: vec![] }).unwrap() {
            EvidenceClaim::SellerAttestation { amount_atomic } => assert_eq!(amount_atomic, None),
            _ => panic!("direct-v1 must claim seller attestation"),
        }
        assert_eq!(DirectV1.id(), ModuleId("direct-v1"));
    }

    #[test]
    fn config_defaults_match_handoff_stagenet_values() {
        let cfg = PaymentConfig::defaults("vespiary-market");
        assert_eq!(cfg.network, Network::Stagenet);
        assert_eq!(cfg.max_batch, 100);
        assert_eq!(cfg.max_unused_pool, 100);
        assert_eq!(cfg.low_pool_threshold, 10);
        assert_eq!(cfg.unpaid_expiry_hours, 48);
        assert_eq!(cfg.open_unpaid_cap, 3);
        assert_eq!(cfg.order_rate_per_hour, 10);
        assert_eq!(cfg.reset_warning_days, 30);
        assert!(!cfg.server_side_signature_check);
    }
}
