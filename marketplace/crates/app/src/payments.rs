//! Direct Monero Payments v1 (owner handoff 2026-10-15; plan:
//! DIRECT-PAYMENTS-V1-PLAN.md). Buyers pay sellers directly, wallet to
//! wallet. The server stores seller primary addresses and pre-signed
//! subaddresses, assigns exactly one unused subaddress per order at
//! creation, and records only the seller's attestation when they mark
//! an order paid.
//!
//! HARD RULES (handoff, non-negotiable):
//! - Never accept or store seeds, spend/view keys, wallet passwords or
//!   wallet files. Never store received amounts.
//! - AMENDED 2026-10-18 (owner decision; migration 0010): buyer-
//!   submitted transaction proofs for direct orders ARE stored —
//!   txid + proof string, carried UNVERIFIED (this module never checks
//!   them and nothing labels them "verified"), visible only to the
//!   submitting buyer and to moderators inside a dispute. The original
//!   rule ("never store txids or proofs") stands for every other path.
//! - Store and serve every uploaded address, message, and signature
//!   BYTE-EXACT as received (JSON string values are taken verbatim —
//!   no trimming, no re-encoding anywhere in this module).
//! - One subaddress per order, never reused — not even after a cancel
//!   or expiry (the entry retires instead of returning to the pool).
//! - No server-side signature verification in v1: the setting exists
//!   (`PAYMENTS_SERVER_SIGNATURE_CHECK`, default off); the buyer's own
//!   wallet is the real check.
//! - No escrow, no fees. Tx proofs exist only as buyer-submitted
//!   evidence per the amendment above. Address validation goes
//!   through modules-api (the vetted `monero` crate) — no hand-rolled
//!   Monero cryptography.
//! - UI copy for a paid direct order is "seller confirmed payment";
//!   the word "verified" is never used as a payment claim here.

use domain::{order_can_transition, Actor, EvidenceLevel, OrderState};
use modules_api::{
    validate_standard_address, DestinationError, EvidenceClaim, EvidenceCx, FormInput, Module,
    ModuleError, ModuleId, PaymentEvidenceProvider, Subaddress,
};
use modules_api::{AllocateCx, Capability, DestinationProposal, DestinationProvider, Network};
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
    if hex.len() == 32
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
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
        Ok(EvidenceClaim::SellerAttestation {
            amount_atomic: None,
        })
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
    /// Startup network guard (L2): stored payment state belongs to a
    /// different network than the instance is configured for.
    NetworkMismatch {
        /// payment_identities rows on another network.
        identities: i64,
        /// Unused pool entries (via their batch) on another network.
        unused_entries: i64,
    },
    NotSeller,
    NotAwaitingPayment,
    NoAssignment,
    TransitionDenied,
    NotFound,
    Db,
    /// Tx-proof flow (2026-10-18): the actor is not the order's buyer.
    NotBuyer,
    /// Submitted txid is not exactly 64 hex characters.
    BadTxid,
    /// Submitted proof is empty or over the storage bound.
    BadProof,
    /// The order's state accepts no such action (closed, or payment
    /// already settled on the record by the seller's own attestation).
    OrderClosed,
    /// Not-received declaration before the unpaid-expiry horizon.
    DeclarationTooEarly,
    /// A not-received declaration already exists for the order.
    AlreadyDeclared,
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

pub async fn get_identity(
    pool: &PgPool,
    seller_id: i64,
) -> Result<Option<PaymentIdentity>, PaymentError> {
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(&format!(
        "SELECT primary_address, {}, {} FROM payment_identities WHERE seller_id = $1",
        ts_col("created_at"),
        ts_col("changed_at")
    ))
    .bind(seller_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(primary_address, created_at, changed_at)| PaymentIdentity {
            seller_id,
            primary_address,
            created_at,
            changed_at,
        },
    ))
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
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT primary_address FROM payment_identities WHERE seller_id = $1 FOR UPDATE",
    )
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

/// Startup network guard (audit L2). Address assignment takes the
/// oldest unused pool entry with no network filter, and identities /
/// batches record the network that was configured when they were
/// created — so flipping an instance from stagenet to mainnet on the
/// same database would leave the old network's entries live for
/// assignment (buyers' wallets would refuse them: fail-safe but
/// confusing, and the orders burn pool entries). Refuse to start
/// instead: if any stored payment identity, or any unused pool entry
/// (through its batch), belongs to a different network than the
/// instance configuration, startup fails with the counts.
pub async fn ensure_network_consistency(
    pool: &PgPool,
    cfg: &PaymentConfig,
) -> Result<(), PaymentError> {
    let want = network_name(cfg.network);
    let identities: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM payment_identities WHERE network <> $1")
            .bind(want)
            .fetch_one(pool)
            .await?;
    let unused_entries: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_pool_entries e
           JOIN payment_batches b ON b.id = e.batch_id
          WHERE e.state = 'unused' AND b.network <> $1",
    )
    .bind(want)
    .fetch_one(pool)
    .await?;
    if identities > 0 || unused_entries > 0 {
        return Err(PaymentError::NetworkMismatch {
            identities,
            unused_entries,
        });
    }
    Ok(())
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
pub struct BatchFile {
    pub format: String,
    pub marketplace_id: String,
    pub network: String,
    pub seller_id: String,
    pub primary_address: String,
    pub entries: Vec<BatchEntry>,
}

#[derive(Debug, serde::Deserialize)]
pub struct BatchEntry {
    pub subaddress: String,
    pub message: String,
    pub signature: String,
}

/// The pure front end of batch upload (Modules Audit BL2): JSON
/// parsing plus the header checks that need no database — format
/// tag, marketplace id, network. `upload_batch` runs this first;
/// it is a separate function so the fuzz targets exercise the
/// exact parser the upload path uses, not a copy.
pub fn parse_batch_header(batch_text: &str, cfg: &PaymentConfig) -> Result<BatchFile, PaymentError> {
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
    Ok(batch)
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
    let batch = parse_batch_header(batch_text, cfg)?;
    let seller_pub = crate::db::public_id_of(pool, seller_id)
        .await?
        .ok_or(PaymentError::NotFound)?;
    let want_seller = payment_seller_id(&seller_pub).ok_or(PaymentError::WrongSeller)?;
    if batch.seller_id != want_seller {
        return Err(PaymentError::WrongSeller);
    }
    let identity = get_identity(pool, seller_id)
        .await?
        .ok_or(PaymentError::NoIdentity)?;
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
    // Audit L1: the cap check above raced with simultaneous uploads —
    // both could read the same unused count, both pass, and the pool
    // overfilled. Re-check inside the transaction, serialized per
    // seller on the identity row (the same lock order creation and
    // address changes already take): a concurrent upload waits for
    // this transaction to commit, then its in-transaction count sees
    // the entries landed here.
    let identity_row: Option<(i64,)> =
        sqlx::query_as("SELECT seller_id FROM payment_identities WHERE seller_id = $1 FOR UPDATE")
            .bind(seller_id)
            .fetch_optional(&mut *tx)
            .await?;
    if identity_row.is_none() {
        tx.rollback().await.ok();
        return Err(PaymentError::NoIdentity);
    }
    let unused_now: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_pool_entries WHERE seller_id = $1 AND state = 'unused'",
    )
    .bind(seller_id)
    .fetch_one(&mut *tx)
    .await?;
    if unused_now + batch.entries.len() as i64 > cfg.max_unused_pool {
        tx.rollback().await.ok();
        return Err(PaymentError::PoolFull);
    }
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
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM payment_pool_entries WHERE order_id = $1)")
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
    let identity = get_identity(pool, seller_id)
        .await?
        .ok_or(PaymentError::NotFound)?;
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
pub async fn retire_entry_for_order(pool: &PgPool, order_id: i64) -> Result<(), PaymentError> {
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
    // An attestation settles any outstanding proof-unconfirmed
    // flag (design update #2.3a). The clearing used to happen in
    // confirm_payment's already-Paid branch, because a proof made
    // the order Paid before the seller confirmed; since the
    // 2026-10-23 ruling the seller normally confirms from
    // AwaitingPayment through this function, so it happens here.
    // A no-op for orders with no proof on file.
    clear_unconfirmed_flags(&mut tx, order.id).await?;
    tx.commit().await?;
    let _ = crate::orders::notify(pool, order.buyer_id, "order_paid", &order.public_id).await;
    Ok(OrderState::Paid)
}

// ---------------------------------------------------------------------------
// Buyer payment reports + tx proofs, seller confirmation, not-received
// declarations, auto-review flags (owner decisions 2026-10-18 — the
// tx-proof flow; audit fix-brief task 1 expanded + design updates #1
// and #2; migration 0010).
//
// VISIBILITY (owner-directed): a proof, its txid, and its existence
// are visible ONLY to the submitting buyer and to moderators
// (dispute view + flag page). Nothing in this section ever notifies
// the seller about a submission, and a submission sends no
// notification to anyone: since the owner ruling of 2026-10-23
// (Audit 2 H1) a proof does not move the order at all, so there is
// no event to announce. The buyer's own `order_paid` notification
// is sent by the seller's attestation (mark_paid), never by a
// proof.

/// A stored buyer-submitted tx proof (migration 0010). Carried
/// unverified; the server never checks it.
#[derive(Debug, Clone)]
pub struct PaymentProof {
    pub txid: String,
    pub proof: String,
    pub submitted_by: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// A buyer's payment report row: kind 'proof' (a PaymentProof exists)
/// or 'manual' (the "I paid" fallback, evidence BuyerReported).
#[derive(Debug, Clone)]
pub struct PaymentReport {
    pub kind: String,
    pub submitted_by: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// An auto-review flag for the Stage 9 moderation queue.
#[derive(Debug, Clone)]
pub struct PaymentFlag {
    pub id: i64,
    pub order_id: i64,
    pub order_public_id: String,
    pub kind: String,
    pub state: String,
    pub created_at: String,
    pub closed_at: Option<String>,
}

fn stored_state(s: &str) -> OrderState {
    match s {
        "Requested" => OrderState::Requested,
        "AwaitingPayment" => OrderState::AwaitingPayment,
        "Paid" => OrderState::Paid,
        "Fulfilled" => OrderState::Fulfilled,
        "Completed" => OrderState::Completed,
        "Disputed" => OrderState::Disputed,
        "Declined" => OrderState::Declined,
        "Cancelled" => OrderState::Cancelled,
        "Resolved" => OrderState::Resolved,
        _ => OrderState::Requested,
    }
}

/// Does any buyer payment report (proof or manual) exist for the
/// order? This is the report-existence key the dispute gate uses.
pub async fn has_payment_report(pool: &PgPool, order_id: i64) -> Result<bool, PaymentError> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM payment_reports WHERE order_id = $1)")
            .bind(order_id)
            .fetch_one(pool)
            .await?;
    Ok(exists)
}

pub async fn payment_proof_for_order(
    pool: &PgPool,
    order_id: i64,
) -> Result<Option<PaymentProof>, PaymentError> {
    let row: Option<(String, String, i64, String, String)> = sqlx::query_as(&format!(
        "SELECT txid, proof, submitted_by, {}, {} FROM payment_proofs WHERE order_id = $1",
        ts_col("created_at"),
        ts_col("updated_at")
    ))
    .bind(order_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(txid, proof, submitted_by, created_at, updated_at)| PaymentProof {
        txid,
        proof,
        submitted_by,
        created_at,
        updated_at,
    }))
}

pub async fn payment_report_for_order(
    pool: &PgPool,
    order_id: i64,
) -> Result<Option<PaymentReport>, PaymentError> {
    let row: Option<(String, i64, String, String)> = sqlx::query_as(&format!(
        "SELECT kind, submitted_by, {}, {} FROM payment_reports WHERE order_id = $1",
        ts_col("created_at"),
        ts_col("updated_at")
    ))
    .bind(order_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(kind, submitted_by, created_at, updated_at)| PaymentReport {
        kind,
        submitted_by,
        created_at,
        updated_at,
    }))
}

pub async fn payment_flags_for_order(
    pool: &PgPool,
    order_id: i64,
) -> Result<Vec<PaymentFlag>, PaymentError> {
    let rows: Vec<(i64, i64, String, String, String, String, Option<String>)> =
        sqlx::query_as(&format!(
            "SELECT f.id, f.order_id, o.public_id, f.kind, f.state, {}, {}
               FROM payment_review_flags f JOIN orders o ON o.id = f.order_id
              WHERE f.order_id = $1 ORDER BY f.id",
            ts_col("f.created_at"),
            ts_col("f.closed_at")
        ))
        .bind(order_id)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(id, oid, pub_id, kind, state, created_at, closed_at)| PaymentFlag {
            id,
            order_id: oid,
            order_public_id: pub_id,
            kind,
            state,
            created_at,
            closed_at,
        })
        .collect())
}

/// All open flags, oldest first — the moderation queue's feed.
pub async fn open_payment_flags(pool: &PgPool) -> Result<Vec<PaymentFlag>, PaymentError> {
    let rows: Vec<(i64, i64, String, String, String, String, Option<String>)> =
        sqlx::query_as(&format!(
            "SELECT f.id, f.order_id, o.public_id, f.kind, f.state, {}, {}
               FROM payment_review_flags f JOIN orders o ON o.id = f.order_id
              WHERE f.state = 'open' ORDER BY f.created_at",
            ts_col("f.created_at"),
            ts_col("f.closed_at")
        ))
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(id, oid, pub_id, kind, state, created_at, closed_at)| PaymentFlag {
            id,
            order_id: oid,
            order_public_id: pub_id,
            kind,
            state,
            created_at,
            closed_at,
        })
        .collect())
}

/// Raise an open flag unless one of the same kind is already open
/// (the partial unique index backs this up).
async fn raise_flag(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    order_id: i64,
    kind: &str,
) -> Result<(), PaymentError> {
    let open: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM payment_review_flags WHERE order_id = $1 AND kind = $2 AND state = 'open')",
    )
    .bind(order_id)
    .bind(kind)
    .fetch_one(&mut **tx)
    .await?;
    if !open {
        sqlx::query("INSERT INTO payment_review_flags (order_id, kind) VALUES ($1, $2)")
            .bind(order_id)
            .bind(kind)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// Clear open proof-unconfirmed flags for an order (the seller has
/// confirmed; design update #2.3a). Contradiction flags are NOT
/// auto-cleared — moderators judge those.
async fn clear_unconfirmed_flags(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    order_id: i64,
) -> Result<(), PaymentError> {
    sqlx::query(
        "UPDATE payment_review_flags SET state = 'cleared', closed_at = now()
          WHERE order_id = $1 AND kind = 'proof-unconfirmed' AND state = 'open'",
    )
    .bind(order_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Buyer submits a transaction proof for a direct order (the "I've
/// paid" report with evidence attached). The proof is stored
/// byte-exact apart from outer-whitespace trimming and txid case
/// normalisation, and is NEVER verified here.
///
/// OWNER RULING 2026-10-23 (Code Audit 2, finding H1; amendment
/// record AUDIT2-H1-OWNER-DECISION-2026-10-23.md): a proof no
/// longer advances the order to Paid. The order HOLDS at
/// AwaitingPayment — from Requested it moves to AwaitingPayment,
/// exactly as a normal order does, and no further. Only the
/// seller's own attestation (mark_paid) makes an order Paid. The
/// submission still records the proof + report, raises the
/// evidence level to BuyerProofSubmitted on an open order (the
/// dispute gate and the sweep exemption key on them), and raises
/// the proof-unconfirmed moderator flag when no attestation
/// exists. In Paid / Fulfilled the proof is recorded alongside and
/// the state is left exactly as it was (late submission is part
/// of the design: protection status is never observable in
/// advance, and evidence never downgrades).
pub async fn submit_payment_proof(
    pool: &PgPool,
    order: &crate::orders::Order,
    actor_id: i64,
    txid: &str,
    proof: &str,
    cfg: &PaymentConfig,
) -> Result<OrderState, PaymentError> {
    if actor_id != order.buyer_id {
        return Err(PaymentError::NotBuyer);
    }
    let txid = txid.trim().to_ascii_lowercase();
    if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PaymentError::BadTxid);
    }
    let proof = proof.trim();
    if proof.is_empty() || proof.chars().count() > 16_384 {
        return Err(PaymentError::BadProof);
    }
    let assignment = assignment_for_order(pool, order.id, cfg)
        .await?
        .ok_or(PaymentError::NoAssignment)?;
    let from = stored_state(&order.state);
    let open = matches!(from, OrderState::Requested | OrderState::AwaitingPayment);
    if !open && !matches!(from, OrderState::Paid | OrderState::Fulfilled) {
        // Disputed and terminal orders take no new submissions (a
        // disputed order's proof is already on file — submission is
        // what opened the path here).
        return Err(PaymentError::OrderClosed);
    }
    if from == OrderState::Requested
        && !order_can_transition(
            OrderState::Requested,
            OrderState::AwaitingPayment,
            Actor::Core,
            EvidenceLevel::BuyerProofSubmitted,
        )
    {
        return Err(PaymentError::TransitionDenied);
    }
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO payment_proofs (order_id, pool_entry_id, submitted_by, txid, proof)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (order_id) DO UPDATE
            SET txid = EXCLUDED.txid, proof = EXCLUDED.proof, updated_at = now()",
    )
    .bind(order.id)
    .bind(assignment.entry_id)
    .bind(actor_id)
    .bind(&txid)
    .bind(proof)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO payment_reports (order_id, submitted_by, kind) VALUES ($1, $2, 'proof')
         ON CONFLICT (order_id) DO UPDATE SET kind = 'proof', updated_at = now()",
    )
    .bind(order.id)
    .bind(actor_id)
    .execute(&mut *tx)
    .await?;
    if open {
        if from == OrderState::Requested {
            let r = sqlx::query(
                "UPDATE orders SET state = 'AwaitingPayment' WHERE id = $1 AND state = 'Requested'",
            )
            .bind(order.id)
            .execute(&mut *tx)
            .await?;
            if r.rows_affected() != 1 {
                tx.rollback().await?;
                return Err(PaymentError::TransitionDenied);
            }
        }
        // The evidence level rises on the open order (the dispute
        // gate reads it, and the buyer sees the truthful unverified
        // label). The guard mirrors the manual-report rule — never
        // over an existing level — and an open order carries no
        // attestation to protect. The seller-facing label maps this
        // level to the same line as no evidence at all (visibility
        // rule), so the rise is invisible to the seller. The state
        // itself does not move: Paid is the seller's word, never
        // the proof's (ruling 2026-10-23).
        sqlx::query(
            "UPDATE orders SET evidence_level = 'BuyerProofSubmitted'
              WHERE id = $1 AND evidence_level IN ('None', 'BuyerReported')",
        )
        .bind(order.id)
        .execute(&mut *tx)
        .await?;
    }
    // Design update #2.3a: a proof with no seller confirmation yet is
    // flagged for review the moment it lands. If the seller already
    // attested, they have confirmed — no flag.
    let attested: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM payment_attestations WHERE order_id = $1)",
    )
    .bind(order.id)
    .fetch_one(&mut *tx)
    .await?;
    if !attested {
        raise_flag(&mut tx, order.id, "proof-unconfirmed").await?;
    }
    tx.commit().await?;
    // No notification to anyone: a proof changes nothing either
    // party must act on (ruling 2026-10-23). The seller's prompt
    // is the standing Confirm-payment form every unpaid order
    // carries; the buyer's `order_paid` event is produced by the
    // seller's attestation alone.
    if from == OrderState::Requested {
        Ok(OrderState::AwaitingPayment)
    } else {
        Ok(from)
    }
}

/// Buyer fallback (design update #2.2): a manual "I paid" confirm for
/// buyers who cannot produce a proof. Records the weaker
/// BuyerReported evidence level and a manual report row: the dispute
/// path opens, but the order does NOT advance, and neither the sweep
/// nor a seller declaration is blocked by it.
pub async fn submit_manual_report(
    pool: &PgPool,
    order: &crate::orders::Order,
    actor_id: i64,
) -> Result<OrderState, PaymentError> {
    if actor_id != order.buyer_id {
        return Err(PaymentError::NotBuyer);
    }
    let from = stored_state(&order.state);
    if !matches!(from, OrderState::Requested | OrderState::AwaitingPayment) {
        return Err(PaymentError::OrderClosed);
    }
    if !has_assignment(pool, order.id).await? {
        return Err(PaymentError::NoAssignment);
    }
    if let Some(report) = payment_report_for_order(pool, order.id).await? {
        // A report is already on file (a proof outranks this fallback;
        // a manual report is already recorded). Idempotent.
        let _ = report;
        return Ok(from);
    }
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO payment_reports (order_id, submitted_by, kind) VALUES ($1, $2, 'manual')
         ON CONFLICT (order_id) DO NOTHING",
    )
    .bind(order.id)
    .bind(actor_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE orders SET evidence_level = 'BuyerReported' WHERE id = $1 AND evidence_level = 'None'",
    )
    .bind(order.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(from)
}

/// Seller confirmation (design update #2.1): per-order, bound to the
/// order's assigned subaddress. From AwaitingPayment this IS
/// mark_paid (the v1 attestation). On a LEGACY order already Paid
/// on a buyer-submitted proof (the pre-2026-10-23 behaviour; since
/// the Audit 2 H1 ruling a proof no longer makes an order Paid) it
/// records the seller's own attestation alongside, raises the
/// evidence level to SellerAttested, and clears the
/// proof-unconfirmed flag.
pub async fn confirm_payment(
    pool: &PgPool,
    order: &crate::orders::Order,
    actor_id: i64,
    cfg: &PaymentConfig,
) -> Result<OrderState, PaymentError> {
    if actor_id != order.seller_id {
        return Err(PaymentError::NotSeller);
    }
    let from = stored_state(&order.state);
    if from == OrderState::AwaitingPayment {
        return mark_paid(pool, order, actor_id, cfg).await;
    }
    if !matches!(from, OrderState::Paid | OrderState::Fulfilled | OrderState::Disputed) {
        return Err(PaymentError::OrderClosed);
    }
    let assignment = assignment_for_order(pool, order.id, cfg)
        .await?
        .ok_or(PaymentError::NoAssignment)?;
    let attested: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM payment_attestations WHERE order_id = $1)",
    )
    .bind(order.id)
    .fetch_one(pool)
    .await?;
    if attested {
        return Ok(from); // already confirmed for this order; idempotent
    }
    if order.evidence_level != "BuyerProofSubmitted" {
        // Nothing buyer-submitted to confirm against (defensive: a
        // Paid direct order's record is attestation or proof).
        return Err(PaymentError::OrderClosed);
    }
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO payment_attestations (order_id, pool_entry_id, submitted_by, claim_kind, amount_atomic)
         VALUES ($1, $2, $3, 'seller-attestation', NULL)
         ON CONFLICT (order_id) DO NOTHING",
    )
    .bind(order.id)
    .bind(assignment.entry_id)
    .bind(actor_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE orders SET evidence_level = 'SellerAttested'
          WHERE id = $1 AND evidence_level = 'BuyerProofSubmitted'",
    )
    .bind(order.id)
    .execute(&mut *tx)
    .await?;
    clear_unconfirmed_flags(&mut tx, order.id).await?;
    tx.commit().await?;
    Ok(from)
}

/// Seller not-received declaration (design update #2.4), for one
/// specific order + its assigned subaddress, available once the order
/// is older than the unpaid-expiry horizon. With a proof on file the
/// declaration only records the statement and raises the
/// proof-contradiction flag — the order does NOT close. Without a
/// proof it closes the order as unpaid, the same end state the expiry
/// sweep produces (entry retired, buyer notified). Since the
/// 2026-10-23 ruling, a proof-backed order sits at AwaitingPayment
/// (it is no longer Paid on the proof), so the with-proof branch
/// covers AwaitingPayment as well as Paid — the #2.4 intent follows
/// the proof, not the old state name.
pub async fn declare_not_received(
    pool: &PgPool,
    order: &crate::orders::Order,
    actor_id: i64,
    cfg: &PaymentConfig,
) -> Result<OrderState, PaymentError> {
    if actor_id != order.seller_id {
        return Err(PaymentError::NotSeller);
    }
    let already: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM payment_declarations WHERE order_id = $1)",
    )
    .bind(order.id)
    .fetch_one(pool)
    .await?;
    if already {
        return Err(PaymentError::AlreadyDeclared);
    }
    let old_enough: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM orders WHERE id = $1
            AND created_at <= now() - ($2 || ' hours')::interval)",
    )
    .bind(order.id)
    .bind(cfg.unpaid_expiry_hours.to_string())
    .fetch_one(pool)
    .await?;
    if !old_enough {
        return Err(PaymentError::DeclarationTooEarly);
    }
    let assignment = assignment_for_order(pool, order.id, cfg)
        .await?
        .ok_or(PaymentError::NoAssignment)?;
    let has_proof: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM payment_proofs WHERE order_id = $1)")
            .bind(order.id)
            .fetch_one(pool)
            .await?;
    let from = stored_state(&order.state);
    if has_proof {
        if !matches!(from, OrderState::Paid | OrderState::AwaitingPayment) {
            // Post-shipment or terminal states: a declaration is
            // incoherent there; the dispute path is the remedy.
            return Err(PaymentError::OrderClosed);
        }
        let mut tx = pool.begin().await?;
        sqlx::query(
            "INSERT INTO payment_declarations (order_id, pool_entry_id, declared_by)
             VALUES ($1, $2, $3)",
        )
        .bind(order.id)
        .bind(assignment.entry_id)
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;
        raise_flag(&mut tx, order.id, "proof-contradiction").await?;
        tx.commit().await?;
        return Ok(from);
    }
    if !matches!(from, OrderState::Requested | OrderState::AwaitingPayment) {
        return Err(PaymentError::OrderClosed);
    }
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO payment_declarations (order_id, pool_entry_id, declared_by)
         VALUES ($1, $2, $3)",
    )
    .bind(order.id)
    .bind(assignment.entry_id)
    .bind(actor_id)
    .execute(&mut *tx)
    .await?;
    let r = sqlx::query(
        "UPDATE orders SET state = 'Cancelled', terminal_at = now()
          WHERE id = $1 AND state IN ('Requested', 'AwaitingPayment')",
    )
    .bind(order.id)
    .execute(&mut *tx)
    .await?;
    if r.rows_affected() != 1 {
        tx.rollback().await?;
        return Err(PaymentError::TransitionDenied);
    }
    sqlx::query(
        "UPDATE payment_pool_entries SET state = 'retired', retired_at = now()
          WHERE order_id = $1 AND state = 'assigned'",
    )
    .bind(order.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let _ = crate::orders::notify(pool, order.buyer_id, "order_not_received", &order.public_id).await;
    Ok(OrderState::Cancelled)
}

/// Whether the seller may declare not-received for this order right
/// now (declaration preconditions, minus the assignment check the
/// declaration itself performs). Drives the order-page form.
pub async fn declaration_available(
    pool: &PgPool,
    order: &crate::orders::Order,
    cfg: &PaymentConfig,
) -> Result<bool, PaymentError> {
    let already: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM payment_declarations WHERE order_id = $1)",
    )
    .bind(order.id)
    .fetch_one(pool)
    .await?;
    if already {
        return Ok(false);
    }
    let old_enough: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM orders WHERE id = $1
            AND created_at <= now() - ($2 || ' hours')::interval)",
    )
    .bind(order.id)
    .bind(cfg.unpaid_expiry_hours.to_string())
    .fetch_one(pool)
    .await?;
    if !old_enough {
        return Ok(false);
    }
    let has_proof: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM payment_proofs WHERE order_id = $1)")
            .bind(order.id)
            .fetch_one(pool)
            .await?;
    Ok(if has_proof {
        order.state == "Paid"
    } else {
        matches!(order.state.as_str(), "Requested" | "AwaitingPayment")
    })
}

pub async fn payment_flag_by_id(
    pool: &PgPool,
    flag_id: i64,
) -> Result<Option<PaymentFlag>, PaymentError> {
    let row: Option<(i64, i64, String, String, String, String, Option<String>)> =
        sqlx::query_as(&format!(
            "SELECT f.id, f.order_id, o.public_id, f.kind, f.state, {}, {}
               FROM payment_review_flags f JOIN orders o ON o.id = f.order_id
              WHERE f.id = $1",
            ts_col("f.created_at"),
            ts_col("f.closed_at")
        ))
        .bind(flag_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(id, oid, pub_id, kind, state, created_at, closed_at)| PaymentFlag {
        id,
        order_id: oid,
        order_public_id: pub_id,
        kind,
        state,
        created_at,
        closed_at,
    }))
}

/// The declaration-dispute exception (design update #2.4): an order
/// closed by a seller declaration while a buyer MANUAL report was on
/// file keeps the buyer's dispute path — the report stays on the
/// record and the dispute reopens the order. Proof-closed orders
/// cannot exist (a declaration never closes over a proof), so this
/// keys on the manual row.
pub async fn declaration_dispute_reopenable(
    pool: &PgPool,
    order_id: i64,
) -> Result<bool, PaymentError> {
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM payment_declarations WHERE order_id = $1)
            AND EXISTS(SELECT 1 FROM payment_reports WHERE order_id = $1 AND kind = 'manual')",
    )
    .bind(order_id)
    .fetch_one(pool)
    .await?;
    Ok(ok)
}

// ---------------------------------------------------------------------------
// Expiry sweep (minimal in-process form; the general scheduler is
// Stage 10). Cancels unpaid direct orders WITH an assignment whose
// created_at is older than the configured expiry; their entries retire.

pub async fn expire_unpaid_orders(
    pool: &PgPool,
    cfg: &PaymentConfig,
    kf: &crate::keyfile::KeyFile,
    rep: &crate::reputation::Stage9Config,
) -> Result<u64, PaymentError> {
    let stale: Vec<(i64, String, i64, i64)> = sqlx::query_as(
        "SELECT o.id, o.public_id, o.buyer_id, o.seller_id FROM orders o
          WHERE o.settlement = 'direct'
            AND o.state IN ('Requested', 'AwaitingPayment')
            AND o.created_at < now() - ($1 || ' hours')::interval
            AND EXISTS (SELECT 1 FROM payment_pool_entries p WHERE p.order_id = o.id)
            -- Owner decision 2026-10-18: a proof-submitted order is
            -- never eaten by the sweep. A manual report alone does
            -- not exempt an order (design update #2.4 coordinates the
            -- sweep and the seller declaration to agree).
            AND NOT EXISTS (SELECT 1 FROM payment_proofs p WHERE p.order_id = o.id)",
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
        let cancelled = r.rows_affected() == 1;
        if cancelled {
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
        if cancelled {
            // Audit 2 item 7 (L3): the fact is produced HERE, on the
            // terminal transition — never lazily on a profile read.
            let _ = crate::reputation::record_fact_for_order(pool, kf, rep, order_id).await;
        }
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
        assert_eq!(
            payment_seller_id("acct_0123456789ABCDEF0123456789abcdef"),
            None
        );
        assert_eq!(
            payment_seller_id("ord_0123456789abcdef0123456789abcdef"),
            None
        );
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
        let cx = EvidenceCx {
            invoice_id: String::new(),
            order_id: "ord_x".into(),
        };
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
