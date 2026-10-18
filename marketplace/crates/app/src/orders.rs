//! Orders (spec §9): creation writes the byte-exact terms file, pins the
//! seller's key, snapshots module pins, and is idempotent per buyer.
//! State changes go through the domain transition table — this module is
//! the only writer of orders.state.

use domain::{order_can_transition, Actor, EvidenceLevel, OrderState};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone)]
 pub struct Order {
    pub id: i64,
    pub public_id: String,
    pub buyer_id: i64,
    pub seller_id: i64,
    pub listing_id: i64,
    pub listing_title: String,
    pub state: String,
    pub settlement: String,
    pub seller_fpr_pinned: String,
    pub terms_sha256: String,
    pub total_atomic: i64,
    pub evidence_level: String,
    pub created_at: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OrderError {
    ListingNotAvailable,
    OwnListing,
    NoSellerKey,
    BadQuantity,
    NewAccountLimit,
    NotFound,
    TransitionDenied,
    InvoiceRequired,
    /// Direct Payments v1: the seller has a payment identity but no
    /// unused subaddresses left — the listing cannot take orders until
    /// they add payment addresses.
    PoolEmpty,
    /// Direct Payments v1 drain defence: buyer already holds the
    /// configured maximum of open unpaid assignment-carrying orders.
    TooManyOpenUnpaid,
    /// Direct Payments v1 drain defence: buyer exceeded the per-hour
    /// assignment-carrying order-creation rate.
    OrderRateLimited,
}

fn canonical_ts(now: OffsetDateTime) -> String {
    let f = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    now.format(&f).unwrap_or_default()
}

fn terms_text(s: &str) -> String {
    // §10: terms files are UTF-8 NFC with LF endings.
    s.replace("\r\n", "\n").replace('\r', "\n").nfc().collect()
}

/// Build the terms file bytes exactly as they will be stored (§10).
pub fn build_terms(
    marketplace_id: &str,
    order_id: &str,
    listing_public_id: &str,
    buyer_public_id: &str,
    seller_public_id: &str,
    seller_fpr: &str,
    quantity: u32,
    total_atomic: u64,
    pricing_module: &str,
    created_at: &str,
    title: &str,
    description: &str,
    delivery_terms: &str,
    refund_terms: &str,
) -> Vec<u8> {
    let empty = "Not specified by the seller.";
    let mut out = String::new();
    out.push_str("statement-format: marketplace-terms-v1\n");
    out.push_str(&format!("marketplace-id: {marketplace_id}\n"));
    out.push_str(&format!("order-id: {order_id}\n"));
    out.push_str(&format!("listing-id: {listing_public_id}\n"));
    out.push_str(&format!("buyer-account: {buyer_public_id}\n"));
    out.push_str(&format!("seller-account: {seller_public_id}\n"));
    out.push_str(&format!("seller-key-fingerprint: {seller_fpr}\n"));
    out.push_str(&format!("quantity: {quantity}\n"));
    out.push_str(&format!("total-atomic: {total_atomic}\n"));
    out.push_str(&format!("pricing-module: {pricing_module}\n"));
    out.push_str(&format!("created-at: {created_at}\n"));
    out.push('\n');
    out.push_str("Title\n");
    out.push_str(&terms_text(title));
    out.push_str("\n\nDescription\n");
    out.push_str(&terms_text(description));
    out.push_str("\n\nDelivery terms\n");
    out.push_str(&terms_text(if delivery_terms.trim().is_empty() { empty } else { delivery_terms }));
    out.push_str("\n\nRefund terms\n");
    out.push_str(&terms_text(if refund_terms.trim().is_empty() { empty } else { refund_terms }));
    out.push('\n');
    out.into_bytes()
}

pub async fn notify(pool: &PgPool, account_id: i64, event_type: &str, object_ref: &str) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO notifications (account_id, event_type, object_ref) VALUES ($1, $2, $3)")
        .bind(account_id)
        .bind(event_type)
        .bind(object_ref)
        .execute(pool)
        .await?;
    Ok(())
}

/// Create an order with the default Direct Payments v1 settings.
/// Kept as the stable entry point (locked suites call this signature);
/// the web layer calls [`create_order_with_config`] with the instance
/// configuration.
pub async fn create_order(
    pool: &PgPool,
    marketplace_id: &str,
    buyer_id: i64,
    listing_public_id: &str,
    quantity: u32,
    idempotency_key: &str,
) -> Result<(Order, bool), OrderError> {
    let cfg = crate::payments::PaymentConfig::defaults(marketplace_id);
    create_order_with_config(pool, marketplace_id, buyer_id, listing_public_id, quantity, idempotency_key, &cfg).await
}

pub async fn create_order_with_config(
    pool: &PgPool,
    marketplace_id: &str,
    buyer_id: i64,
    listing_public_id: &str,
    quantity: u32,
    idempotency_key: &str,
    pay_cfg: &crate::payments::PaymentConfig,
) -> Result<(Order, bool), OrderError> {
    if quantity == 0 || quantity > 10_000 {
        return Err(OrderError::BadQuantity);
    }
    // Idempotent replay: same buyer + key returns the original order.
    if let Some(existing) = order_by_idempotency(pool, buyer_id, idempotency_key).await {
        return Ok((existing, false));
    }
    let listing: Option<(i64, i64, String, String, String, i64, String, String, String)> = sqlx::query_as(
        "SELECT id, seller_id, title, description, delivery_terms, price_atomic, status, destination_module, public_id
         FROM listings WHERE public_id = $1",
    )
    .bind(listing_public_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| OrderError::NotFound)?;
    let (listing_id, seller_id, title, description, delivery_terms, unit_price, status, dest_module, listing_pub) =
        listing.ok_or(OrderError::ListingNotAvailable)?;
    if status != "published" {
        return Err(OrderError::ListingNotAvailable);
    }
    if seller_id == buyer_id {
        return Err(OrderError::OwnListing);
    }
    let refund_terms: String = sqlx::query_scalar("SELECT refund_terms FROM listings WHERE id = $1")
        .bind(listing_id)
        .fetch_one(pool)
        .await
        .map_err(|_| OrderError::NotFound)?;
    // Pin the seller's current key (§8/§9). No key, no orders.
    let seller_key = crate::keys::current_key(pool, seller_id)
        .await
        .map_err(|_| OrderError::NotFound)?
        .ok_or(OrderError::NoSellerKey)?;
    // New-account limit (§7): <24h old accounts may hold at most 3 orders.
    let (age_hours, order_count): (f64, i64) = sqlx::query_as(
        "SELECT EXTRACT(EPOCH FROM (now() - created_at))::float8 / 3600.0,
                (SELECT COUNT(*) FROM orders WHERE buyer_id = $1)
         FROM accounts WHERE id = $1",
    )
    .bind(buyer_id)
    .fetch_one(pool)
    .await
    .map_err(|_| OrderError::NotFound)?;
    if age_hours < 24.0 && order_count >= 3 {
        return Err(OrderError::NewAccountLimit);
    }
    let total = domain::xmr_only_total(unit_price as u64, quantity as u64)
        .ok_or(OrderError::BadQuantity)?;
    let order_public_id = crate::db::public_id("ord_");
    let buyer_pub = crate::db::public_id_of(pool, buyer_id).await.map_err(|_| OrderError::NotFound)?.ok_or(OrderError::NotFound)?;
    let seller_pub = crate::db::public_id_of(pool, seller_id).await.map_err(|_| OrderError::NotFound)?.ok_or(OrderError::NotFound)?;
    let now = OffsetDateTime::now_utc();
    let terms = build_terms(
        marketplace_id,
        &order_public_id,
        &listing_pub,
        &buyer_pub,
        &seller_pub,
        &seller_key.0,
        quantity,
        total,
        "xmr-only",
        &canonical_ts(now),
        &title,
        &description,
        &delivery_terms,
        &refund_terms,
    );
    let digest = hex::encode(Sha256::digest(&terms));
    let pins = serde_json::json!({
        "destination": dest_module,
        "pricing": "xmr-only",
        "evidence": ["seller-attestation", "tx-proof"],
        "reputation": "weighted-reviews-v1",
        "settlement": "direct"
    });
    // --- Direct Payments v1: allocation at creation -------------------
    // Compatibility rule (SPEC-V2-AMENDMENTS 2026-10-15): allocation is
    // attempted ONLY when the seller has a payment identity.
    // - Identity + empty pool => creation is refused (PoolEmpty).
    // - No identity => the order proceeds exactly as before this
    //   release (pre-payment behaviour; the Stage 4 locked suites
    //   exercise this path), with no assignment and no payment page.
    let has_identity: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM payment_identities WHERE seller_id = $1)",
    )
    .bind(seller_id)
    .fetch_one(pool)
    .await
    .map_err(|_| OrderError::NotFound)?;
    if !has_identity {
        let inserted: Option<(i64,)> = sqlx::query_as(
            "INSERT INTO orders (public_id, buyer_id, seller_id, listing_id, state, settlement,
                seller_fpr_pinned, terms_bytes, terms_sha256, total_atomic, module_pins,
                evidence_level, idempotency_key)
             VALUES ($1,$2,$3,$4,'Requested','direct',$5,$6,$7,$8,$9,'None',$10)
             ON CONFLICT (buyer_id, idempotency_key) DO NOTHING RETURNING id",
        )
        .bind(&order_public_id)
        .bind(buyer_id)
        .bind(seller_id)
        .bind(listing_id)
        .bind(&seller_key.0)
        .bind(&terms)
        .bind(&digest)
        .bind(total as i64)
        .bind(&pins)
        .bind(idempotency_key)
        .fetch_optional(pool)
        .await
        .map_err(|_| OrderError::NotFound)?;
        if inserted.is_none() {
            // Lost a race with a duplicate submission: return the original.
            let existing = order_by_idempotency(pool, buyer_id, idempotency_key)
                .await
                .ok_or(OrderError::NotFound)?;
            return Ok((existing, false));
        }
        let order = order_by_public_id(pool, &order_public_id).await.ok_or(OrderError::NotFound)?;
        let _ = notify(pool, seller_id, "order_requested", &order_public_id).await;
        return Ok((order, true));
    }
    // Drain defences — scoped to assignment-carrying orders only (their
    // purpose is pool protection): per-buyer open-unpaid cap and
    // per-hour creation rate. The <24h-account cap above is unchanged
    // and applies to all orders.
    let open_unpaid: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM orders o
          WHERE o.buyer_id = $1 AND o.state IN ('Requested', 'AwaitingPayment')
            AND EXISTS (SELECT 1 FROM payment_pool_entries p WHERE p.order_id = o.id)",
    )
    .bind(buyer_id)
    .fetch_one(pool)
    .await
    .map_err(|_| OrderError::NotFound)?;
    if open_unpaid >= pay_cfg.open_unpaid_cap {
        return Err(OrderError::TooManyOpenUnpaid);
    }
    let created_last_hour: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM orders o
          WHERE o.buyer_id = $1 AND o.created_at > now() - interval '1 hour'
            AND EXISTS (SELECT 1 FROM payment_pool_entries p WHERE p.order_id = o.id)",
    )
    .bind(buyer_id)
    .fetch_one(pool)
    .await
    .map_err(|_| OrderError::NotFound)?;
    if created_last_hour >= pay_cfg.order_rate_per_hour {
        return Err(OrderError::OrderRateLimited);
    }
    // Order insert + allocation in ONE transaction. The seller's
    // identity row is locked FOR UPDATE, serializing allocations per
    // seller; the entry take is oldest-first with FOR UPDATE SKIP
    // LOCKED. Two simultaneous creations therefore always take two
    // different entries.
    let mut tx = pool.begin().await.map_err(|_| OrderError::NotFound)?;
    sqlx::query("SELECT 1 FROM payment_identities WHERE seller_id = $1 FOR UPDATE")
        .bind(seller_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| OrderError::NotFound)?;
    let inserted: Option<(i64,)> = sqlx::query_as(
        "INSERT INTO orders (public_id, buyer_id, seller_id, listing_id, state, settlement,
            seller_fpr_pinned, terms_bytes, terms_sha256, total_atomic, module_pins,
            evidence_level, idempotency_key)
         VALUES ($1,$2,$3,$4,'Requested','direct',$5,$6,$7,$8,$9,'None',$10)
         ON CONFLICT (buyer_id, idempotency_key) DO NOTHING RETURNING id",
    )
    .bind(&order_public_id)
    .bind(buyer_id)
    .bind(seller_id)
    .bind(listing_id)
    .bind(&seller_key.0)
    .bind(&terms)
    .bind(&digest)
    .bind(total as i64)
    .bind(&pins)
    .bind(idempotency_key)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| OrderError::NotFound)?;
    let Some((new_order_id,)) = inserted else {
        // Duplicate submission won the race: roll back (nothing was
        // allocated) and return the original order.
        tx.rollback().await.map_err(|_| OrderError::NotFound)?;
        let existing = order_by_idempotency(pool, buyer_id, idempotency_key)
            .await
            .ok_or(OrderError::NotFound)?;
        return Ok((existing, false));
    };
    let entry: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM payment_pool_entries
          WHERE seller_id = $1 AND state = 'unused'
          ORDER BY id ASC LIMIT 1 FOR UPDATE SKIP LOCKED",
    )
    .bind(seller_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| OrderError::NotFound)?;
    let Some((entry_id,)) = entry else {
        // Identity but empty pool: refuse creation; the order insert
        // rolls back with the transaction.
        tx.rollback().await.map_err(|_| OrderError::NotFound)?;
        return Err(OrderError::PoolEmpty);
    };
    sqlx::query(
        "UPDATE payment_pool_entries SET state = 'assigned', order_id = $2, assigned_at = now()
          WHERE id = $1",
    )
    .bind(entry_id)
    .bind(new_order_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| OrderError::NotFound)?;
    tx.commit().await.map_err(|_| OrderError::NotFound)?;
    let order = order_by_public_id(pool, &order_public_id).await.ok_or(OrderError::NotFound)?;
    let _ = notify(pool, seller_id, "order_requested", &order_public_id).await;
    // Low-pool alert: notify only when crossing the threshold, or when
    // no unread low-pool notice is already waiting (never spam).
    if let Ok(unused) = crate::payments::unused_count(pool, seller_id).await {
        if unused < pay_cfg.low_pool_threshold {
            let already: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM notifications
                  WHERE account_id = $1 AND event_type = 'payment_pool_low' AND read_at IS NULL)",
            )
            .bind(seller_id)
            .fetch_one(pool)
            .await
            .unwrap_or(true);
            let crossed = unused + 1 >= pay_cfg.low_pool_threshold;
            if crossed || !already {
                let _ = notify(pool, seller_id, "payment_pool_low", &order_public_id).await;
            }
        }
    }
    Ok((order, true))
}

const ORDER_COLS: &str = "o.id, o.public_id, o.buyer_id, o.seller_id, o.listing_id, l.title,
    o.state, o.settlement, o.seller_fpr_pinned, o.terms_sha256, o.total_atomic, o.evidence_level,
    to_char(o.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')";

type OrderRow = (i64, String, i64, i64, i64, String, String, String, String, String, i64, String, String);

fn row(o: OrderRow) -> Order {
    Order {
        id: o.0,
        public_id: o.1,
        buyer_id: o.2,
        seller_id: o.3,
        listing_id: o.4,
        listing_title: o.5,
        state: o.6,
        settlement: o.7,
        seller_fpr_pinned: o.8,
        terms_sha256: o.9,
        total_atomic: o.10,
        evidence_level: o.11,
        created_at: o.12,
    }
}

/// Stage 9: disputes reference orders by internal id.
pub async fn order_by_internal_id(pool: &PgPool, id: i64) -> Option<Order> {
    let r: Option<OrderRow> = sqlx::query_as(&format!(
        "SELECT {ORDER_COLS} FROM orders o JOIN listings l ON l.id = o.listing_id WHERE o.id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
    .ok()?;
    r.map(row)
}

pub async fn order_by_public_id(pool: &PgPool, public_id: &str) -> Option<Order> {
    let r: Option<OrderRow> = sqlx::query_as(&format!(
        "SELECT {ORDER_COLS} FROM orders o JOIN listings l ON l.id = o.listing_id WHERE o.public_id = $1"
    ))
    .bind(public_id)
    .fetch_optional(pool)
    .await
    .ok()?;
    r.map(row)
}

async fn order_by_idempotency(pool: &PgPool, buyer_id: i64, key: &str) -> Option<Order> {
    let r: Option<OrderRow> = sqlx::query_as(&format!(
        "SELECT {ORDER_COLS} FROM orders o JOIN listings l ON l.id = o.listing_id
         WHERE o.buyer_id = $1 AND o.idempotency_key = $2"
    ))
    .bind(buyer_id)
    .bind(key)
    .fetch_optional(pool)
    .await
    .ok()?;
    r.map(row)
}

pub async fn orders_for(pool: &PgPool, account_id: i64) -> Vec<Order> {
    let rows: Vec<OrderRow> = sqlx::query_as(&format!(
        "SELECT {ORDER_COLS} FROM orders o JOIN listings l ON l.id = o.listing_id
         WHERE o.buyer_id = $1 OR o.seller_id = $1 ORDER BY o.created_at DESC"
    ))
    .bind(account_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    rows.into_iter().map(row).collect()
}

pub async fn terms_bytes(pool: &PgPool, order_id: i64) -> Option<Vec<u8>> {
    sqlx::query_scalar("SELECT terms_bytes FROM orders WHERE id = $1")
        .bind(order_id)
        .fetch_optional(pool)
        .await
        .ok()?
}

fn state_of(s: &str) -> Option<OrderState> {
    use OrderState::*;
    Some(match s {
        "Requested" => Requested,
        "AwaitingPayment" => AwaitingPayment,
        "Paid" => Paid,
        "Fulfilled" => Fulfilled,
        "Completed" => Completed,
        "Disputed" => Disputed,
        "Declined" => Declined,
        "Cancelled" => Cancelled,
        "Resolved" => Resolved,
        _ => return None,
    })
}

fn evidence_of(s: &str) -> EvidenceLevel {
    match s {
        "BuyerReported" => EvidenceLevel::BuyerReported,
        "SellerAttested" => EvidenceLevel::SellerAttested,
        "ProofVerified" => EvidenceLevel::ProofVerified,
        "WalletObserved" => EvidenceLevel::WalletObserved,
        _ => EvidenceLevel::None,
    }
}

/// Apply one user-facing action. The domain table decides; handlers map
/// the acting account to an Actor by their relation to the order.
pub async fn apply_action(
    pool: &PgPool,
    order: &Order,
    action: &str,
    actor_id: i64,
) -> Result<OrderState, OrderError> {
    let (actor, to) = match (action, order.buyer_id == actor_id, order.seller_id == actor_id) {
        ("accept", false, true) => (Actor::Seller, OrderState::AwaitingPayment),
        ("decline", false, true) => (Actor::Seller, OrderState::Declined),
        ("cancel", true, false) => (Actor::Buyer, OrderState::Cancelled),
        ("cancel", false, true) => (Actor::Seller, OrderState::Cancelled),
        ("fulfil", false, true) => (Actor::Seller, OrderState::Fulfilled),
        ("complete", true, false) => (Actor::Buyer, OrderState::Completed),
        ("dispute", true, false) => (Actor::Buyer, OrderState::Disputed),
        ("dispute", false, true) => (Actor::Seller, OrderState::Disputed),
        _ => return Err(OrderError::TransitionDenied),
    };
    let from = state_of(&order.state).ok_or(OrderError::NotFound)?;
    let evidence = evidence_of(&order.evidence_level);
    if !order_can_transition(from, to, actor, evidence) {
        return Err(OrderError::TransitionDenied);
    }
    if action == "accept" {
        // §9: Requested -> AwaitingPayment requires an issued invoice.
        // Direct Payments v1 disposition: for direct orders the gate is
        // assignment-exists instead (which holds by construction for
        // payment-enabled sellers, since allocation happens at
        // creation). Orders without an assignment keep the original
        // invoice behaviour exactly (Stage 4 locked suite).
        let assigned = crate::payments::has_assignment(pool, order.id)
            .await
            .map_err(|_| OrderError::NotFound)?;
        if !assigned {
            let issued: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM invoices WHERE order_id = $1 AND state = 'Issued')",
            )
            .bind(order.id)
            .fetch_one(pool)
            .await
            .map_err(|_| OrderError::NotFound)?;
            if !issued {
                return Err(OrderError::InvoiceRequired);
            }
        }
    }
    if action == "dispute" && from == OrderState::AwaitingPayment {
        // §9 guard: buyer reported payment >= 72h ago, no seller response.
        let old_enough: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM payment_evidence
              WHERE invoice_id IN (SELECT id FROM invoices WHERE order_id = $1)
                AND claim_kind = 'buyer-report' AND created_at < now() - interval '72 hours')",
        )
        .bind(order.id)
        .fetch_one(pool)
        .await
        .map_err(|_| OrderError::NotFound)?;
        if !old_enough {
            return Err(OrderError::TransitionDenied);
        }
    }
    let to_s = format!("{to:?}");
    sqlx::query("UPDATE orders SET state = $2 WHERE id = $1 AND state = $3")
        .bind(order.id)
        .bind(&to_s)
        .bind(&order.state)
        .execute(pool)
        .await
        .map_err(|_| OrderError::NotFound)?;
    if matches!(to, OrderState::Completed | OrderState::Cancelled | OrderState::Declined | OrderState::Resolved) {
        // Stage 9: the terminal moment (facts + closure accrual rule).
        let _ = sqlx::query("UPDATE orders SET terminal_at = now() WHERE id = $1 AND terminal_at IS NULL")
            .bind(order.id)
            .execute(pool)
            .await;
    }
    if action == "dispute" {
        // Stage 9: opening a dispute creates its row atomically with
        // the state change (one open dispute per order at a time).
        let _ = sqlx::query(
            "INSERT INTO disputes (order_id, opened_by)
             SELECT $1, $2 WHERE NOT EXISTS (
                 SELECT 1 FROM disputes WHERE order_id = $1
                   AND state IN ('open', 'awaiting_buyer_confirmation'))",
        )
        .bind(order.id)
        .bind(actor_id)
        .execute(pool)
        .await;
    }
    if action == "complete" && from == OrderState::Disputed {
        // §9: the buyer withdrawing a dispute closes it as withdrawn.
        let _ = sqlx::query(
            "UPDATE disputes SET state = 'closed', outcome = 'withdrawn',
                    outcome_state = 'final', resolved_at = now()
              WHERE order_id = $1 AND state = 'open'",
        )
        .bind(order.id)
        .execute(pool)
        .await;
    }
    if matches!(action, "cancel" | "decline") {
        // Direct Payments v1: a cancelled/declined order's subaddress
        // retires — it is never returned to the pool, because a buyer
        // may still pay it late.
        let _ = crate::payments::retire_entry_for_order(pool, order.id).await;
    }
    let counterparty = if actor_id == order.buyer_id { order.seller_id } else { order.buyer_id };
    let event = match action {
        "accept" => "invoice_issued",
        "decline" => "order_declined",
        "cancel" => "order_cancelled",
        "fulfil" => "order_fulfilled",
        "complete" => "order_completed",
        "dispute" => "dispute_opened",
        _ => "order_updated",
    };
    let _ = notify(pool, counterparty, event, &order.public_id).await;
    Ok(to)
}

// -- inbox (§15) ---------------------------------------------------------------

pub async fn inbox(pool: &PgPool, account_id: i64) -> Vec<(i64, String, String, String, bool)> {
    sqlx::query_as(
        "SELECT id, event_type, object_ref, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), read_at IS NOT NULL
         FROM notifications WHERE account_id = $1 ORDER BY created_at DESC LIMIT 100",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
}

pub async fn unread_count(pool: &PgPool, account_id: i64) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM notifications WHERE account_id = $1 AND read_at IS NULL")
        .bind(account_id)
        .fetch_one(pool)
        .await
        .unwrap_or(0)
}

pub async fn mark_all_read(pool: &PgPool, account_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE notifications SET read_at = now() WHERE account_id = $1 AND read_at IS NULL")
        .bind(account_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terms_are_byte_exact_and_deterministic() {
        let a = build_terms(
            "mkt_00", "ord_1", "lst_1", "acct_b", "acct_s", "AB12", 2, 700_000_000_000,
            "xmr-only", "2026-10-13T16:00:00Z", "Pipe", "A\r\npipe", "", "",
        );
        let b = build_terms(
            "mkt_00", "ord_1", "lst_1", "acct_b", "acct_s", "AB12", 2, 700_000_000_000,
            "xmr-only", "2026-10-13T16:00:00Z", "Pipe", "A\npipe", "", "",
        );
        assert_eq!(a, b, "CRLF must normalize to LF");
        let text = String::from_utf8(a).unwrap();
        assert!(text.starts_with("statement-format: marketplace-terms-v1\nmarketplace-id: mkt_00\n"));
        assert!(text.contains("\n\nTitle\nPipe\n\nDescription\n"));
        assert!(text.contains("Delivery terms\nNot specified by the seller."));
        assert_eq!(hex::encode(Sha256::digest(&text)), hex::encode(Sha256::digest(text.as_bytes())));
    }
}
