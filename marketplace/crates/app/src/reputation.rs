//! Reputation (spec §13): the facts pipeline, the raw-facts panel, and
//! the two reputation models behind the `modules-api` ReputationModel
//! trait (`weighted-reviews-v1` default, `raw-counts`).
//!
//! The core produces ONE minimized fact per terminal order. Facts are
//! the ONLY input a reputation model ever receives: seller id, outcome,
//! review score if any, month (YYYY-MM), the buyer token (HMAC from the
//! key file), the buyer's maturity bucket at order time, and the payment
//! evidence level. No buyer id, no amounts, no timestamps finer than a
//! month ever reach a model or the facts table.
//!
//! Direct Payments v1 honesty rule (amendments 2026-10-15): every fact
//! in v1 carries SellerAttested evidence. Nothing here ever labels a
//! payment "verified": the panel separates seller-confirmed payments
//! from on-chain verified payments, and the latter count is genuinely
//! computed from facts (ProofVerified / WalletObserved) — it is 0 until
//! an evidence module that can verify exists.

use crate::keyfile::KeyFile;
use modules_api::{Capability, Module, ModuleId, ReputationFact, ReputationModel, ReputationSummary};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};

// -- evidence levels (modules-api fact encoding) ------------------------------
pub const EV_NONE: u8 = 0;
pub const EV_BUYER_REPORTED: u8 = 1;
pub const EV_SELLER_ATTESTED: u8 = 2;
pub const EV_PROOF_VERIFIED: u8 = 3;
pub const EV_WALLET_OBSERVED: u8 = 4;

pub fn evidence_u8(s: &str) -> u8 {
    match s {
        "BuyerReported" => EV_BUYER_REPORTED,
        // Buyer-submitted proof (2026-10-18) is buyer-side evidence:
        // it never counts as an attested/verified class for weighting.
        "BuyerProofSubmitted" => EV_BUYER_REPORTED,
        "SellerAttested" => EV_SELLER_ATTESTED,
        "ProofVerified" => EV_PROOF_VERIFIED,
        "WalletObserved" => EV_WALLET_OBSERVED,
        _ => EV_NONE,
    }
}

// -- outcomes (modules-api fact encoding) --------------------------------------
pub const OUT_COMPLETED: u8 = 0;
pub const OUT_RESOLVED_DELIVERED: u8 = 1;
pub const OUT_RESOLVED_REFUND: u8 = 2;
pub const OUT_RESOLVED_SELLER_FAULT: u8 = 3;
pub const OUT_RESOLVED_BUYER_FAULT: u8 = 4;
pub const OUT_RESOLVED_UNRESOLVED: u8 = 5;
pub const OUT_CANCELLED: u8 = 6;
pub const OUT_DECLINED: u8 = 7;

pub fn outcome_str(code: u8) -> &'static str {
    match code {
        OUT_COMPLETED => "completed",
        OUT_RESOLVED_DELIVERED => "resolved-delivered-confirmed",
        OUT_RESOLVED_REFUND => "resolved-refund-confirmed",
        OUT_RESOLVED_SELLER_FAULT => "resolved-seller-at-fault",
        OUT_RESOLVED_BUYER_FAULT => "resolved-buyer-at-fault",
        OUT_RESOLVED_UNRESOLVED => "resolved-unresolved",
        OUT_CANCELLED => "cancelled",
        OUT_DECLINED => "declined",
        _ => "completed",
    }
}

fn outcome_code(state: &str, dispute_outcome: Option<&str>) -> u8 {
    match state {
        "Completed" => OUT_COMPLETED,
        "Cancelled" => OUT_CANCELLED,
        "Declined" => OUT_DECLINED,
        "Resolved" => match dispute_outcome {
            Some("delivered-confirmed") => OUT_RESOLVED_DELIVERED,
            Some("refund-confirmed") => OUT_RESOLVED_REFUND,
            Some("seller-at-fault") => OUT_RESOLVED_SELLER_FAULT,
            Some("buyer-at-fault") => OUT_RESOLVED_BUYER_FAULT,
            _ => OUT_RESOLVED_UNRESOLVED,
        },
        _ => OUT_COMPLETED,
    }
}

/// Outcomes that count as a completed sale for the raw-facts panel
/// (a sale happened, whatever was later disputed about it).
fn is_sale_outcome(s: &str) -> bool {
    matches!(
        s,
        "completed"
            | "resolved-delivered-confirmed"
            | "resolved-refund-confirmed"
            | "resolved-seller-at-fault"
            | "resolved-unresolved"
    )
}

pub fn is_terminal(state: &str) -> bool {
    matches!(state, "Completed" | "Resolved" | "Cancelled" | "Declined")
}

// -- configuration --------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Stage9Config {
    /// Reputation model id: "weighted-reviews-v1" | "raw-counts".
    pub model: String,
    pub maturity_min_age_days: i64,
    pub maturity_min_orders: i64,
    pub maturity_min_sellers: i64,
    pub mature_weight: f64,
    pub immature_weight: f64,
    pub evidence_verified_weight: f64,
    pub evidence_unverified_weight: f64,
    pub repeat_window_days: i64,
    pub min_total_weight: f64,
    pub review_edit_window_days: i64,
    pub review_max_chars: usize,
    /// Shown to users before disclosing; deletion itself is Stage 10.
    pub disclosure_retention_days: i64,
}

impl Stage9Config {
    pub fn defaults() -> Stage9Config {
        Stage9Config {
            model: "weighted-reviews-v1".into(),
            maturity_min_age_days: 30,
            maturity_min_orders: 3,
            maturity_min_sellers: 2,
            mature_weight: 1.0,
            immature_weight: 0.3,
            evidence_verified_weight: 1.0,
            evidence_unverified_weight: 0.6,
            repeat_window_days: 90,
            min_total_weight: 5.0,
            review_edit_window_days: 7,
            review_max_chars: 1000,
            disclosure_retention_days: 180,
        }
    }

    pub fn from_env() -> Stage9Config {
        let mut c = Stage9Config::defaults();
        let env = |k: &str| std::env::var(k).ok();
        if let Some(v) = env("REPUTATION_MODEL") {
            if v == "raw-counts" || v == "weighted-reviews-v1" {
                c.model = v;
            }
        }
        if let Some(v) = env("REPUTATION_MATURITY_MIN_AGE_DAYS").and_then(|s| s.parse().ok()) {
            c.maturity_min_age_days = v;
        }
        if let Some(v) = env("REPUTATION_MATURITY_MIN_ORDERS").and_then(|s| s.parse().ok()) {
            c.maturity_min_orders = v;
        }
        if let Some(v) = env("REPUTATION_MATURITY_MIN_SELLERS").and_then(|s| s.parse().ok()) {
            c.maturity_min_sellers = v;
        }
        if let Some(v) = env("REPUTATION_MIN_TOTAL_WEIGHT").and_then(|s| s.parse().ok()) {
            c.min_total_weight = v;
        }
        if let Some(v) = env("REVIEW_EDIT_WINDOW_DAYS").and_then(|s| s.parse().ok()) {
            c.review_edit_window_days = v;
        }
        if let Some(v) = env("DISCLOSURE_RETENTION_DAYS").and_then(|s| s.parse().ok()) {
            c.disclosure_retention_days = v;
        }
        c
    }
}

// -- facts pipeline ---------------------------------------------------------------

fn month_of(t: OffsetDateTime) -> String {
    format!("{:04}-{:02}", t.year(), u8::from(t.month()))
}

fn month_index(month: &str) -> i64 {
    let (y, m) = month.split_once('-').unwrap_or(("0", "0"));
    y.parse::<i64>().unwrap_or(0) * 12 + m.parse::<i64>().unwrap_or(0)
}

/// Buyer maturity at order time (spec §13): bucket 1 when the buyer's
/// account was already at least `maturity_min_age_days` old at order
/// creation AND the buyer already had at least `maturity_min_orders`
/// completed/resolved orders from at least `maturity_min_sellers`
/// distinct sellers before this order. Evaluated from stored rows, so
/// it is reproducible whenever the fact is (re)computed.
async fn maturity_bucket(
    pool: &PgPool,
    cfg: &Stage9Config,
    buyer_id: i64,
    order_id: i64,
    order_created: OffsetDateTime,
) -> Result<i16, sqlx::Error> {
    let buyer_created: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT created_at FROM accounts WHERE id = $1")
            .bind(buyer_id)
            .fetch_optional(pool)
            .await?
            .flatten();
    let Some(buyer_created) = buyer_created else {
        return Ok(0);
    };
    if buyer_created + Duration::days(cfg.maturity_min_age_days) > order_created {
        return Ok(0);
    }
    let (count, sellers): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(DISTINCT seller_id) FROM orders
          WHERE buyer_id = $1 AND id <> $2 AND created_at < $3
            AND state IN ('Completed', 'Resolved')",
    )
    .bind(buyer_id)
    .bind(order_id)
    .bind(order_created)
    .fetch_one(pool)
    .await?;
    Ok(if count >= cfg.maturity_min_orders && sellers >= cfg.maturity_min_sellers {
        1
    } else {
        0
    })
}

/// Record the one minimized fact for a terminal order. Idempotent
/// (UNIQUE(order_id) + ON CONFLICT DO NOTHING). Returns true when a new
/// fact was written. A closed seller accrues no new facts for orders
/// that terminated after the closure (owner ruling 2026-10-16: the
/// identity ended; its history stands, but stops growing).
pub async fn record_fact_for_order(
    pool: &PgPool,
    kf: &KeyFile,
    cfg: &Stage9Config,
    order_id: i64,
) -> Result<bool, sqlx::Error> {
    let row: Option<(i64, i64, String, String, OffsetDateTime, Option<OffsetDateTime>)> =
        sqlx::query_as(
            "SELECT buyer_id, seller_id, state, evidence_level, created_at, terminal_at
               FROM orders WHERE id = $1",
        )
        .bind(order_id)
        .fetch_optional(pool)
        .await?;
    let Some((buyer_id, seller_id, state, evidence, created_at, terminal_at)) = row else {
        return Ok(false);
    };
    if !is_terminal(&state) {
        return Ok(false);
    }
    let closed_at: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT closed_at FROM accounts WHERE id = $1")
            .bind(seller_id)
            .fetch_one(pool)
            .await?;
    if let Some(ca) = closed_at {
        match terminal_at {
            Some(t) if t <= ca => {}
            _ => return Ok(false), // terminated after closure: no accrual
        }
    }
    let dispute_outcome: Option<String> = sqlx::query_scalar(
        "SELECT outcome FROM disputes WHERE order_id = $1 AND state = 'resolved'
          ORDER BY resolved_at DESC NULLS LAST LIMIT 1",
    )
    .bind(order_id)
    .fetch_optional(pool)
    .await?
    .flatten();
    let outcome = outcome_str(outcome_code(&state, dispute_outcome.as_deref()));
    let bucket = maturity_bucket(pool, cfg, buyer_id, order_id, created_at).await?;
    let score: Option<i32> = sqlx::query_scalar("SELECT score FROM reviews WHERE order_id = $1")
        .bind(order_id)
        .fetch_optional(pool)
        .await?
        .flatten();
    let month = month_of(terminal_at.unwrap_or(created_at));
    let inserted = sqlx::query(
        "INSERT INTO reputation_facts
            (seller_id, buyer_token, maturity_bucket, evidence_level, outcome, score, month, order_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (order_id) DO NOTHING",
    )
    .bind(seller_id)
    .bind(kf.buyer_token(seller_id, buyer_id).as_slice())
    .bind(bucket)
    .bind(&evidence)
    .bind(outcome)
    .bind(score)
    .bind(&month)
    .bind(order_id)
    .execute(pool)
    .await?;
    if inserted.rows_affected() > 0 {
        recompute_summary(pool, cfg, seller_id).await?;
        return Ok(true);
    }
    Ok(false)
}

/// Bring one seller's facts up to date (every terminal order has its
/// fact) and ensure a stored summary exists. Called on profile render
/// and after Stage 9 writes, so facts exist whichever code path
/// terminated the order (core actions, the payments expiry sweep, or
/// dispute resolution) — order-module signatures stay untouched.
pub async fn sync_facts_for_seller(
    pool: &PgPool,
    kf: &KeyFile,
    cfg: &Stage9Config,
    seller_id: i64,
) -> Result<(), sqlx::Error> {
    let missing: Vec<i64> = sqlx::query_scalar(
        "SELECT o.id FROM orders o
          WHERE o.seller_id = $1
            AND o.state IN ('Completed', 'Resolved', 'Cancelled', 'Declined')
            AND NOT EXISTS (SELECT 1 FROM reputation_facts f WHERE f.order_id = o.id)",
    )
    .bind(seller_id)
    .fetch_all(pool)
    .await?;
    let mut changed = false;
    for oid in missing {
        changed |= record_fact_for_order(pool, kf, cfg, oid).await?;
    }
    if changed || summary_row(pool, seller_id).await?.is_none() {
        recompute_summary(pool, cfg, seller_id).await?;
    }
    Ok(())
}

/// Startup backfill: facts for every terminal order that lacks one.
pub async fn backfill_all(pool: &PgPool, kf: &KeyFile, cfg: &Stage9Config) -> Result<u64, sqlx::Error> {
    let sellers: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT seller_id FROM orders
          WHERE state IN ('Completed', 'Resolved', 'Cancelled', 'Declined')",
    )
    .fetch_all(pool)
    .await?;
    let mut n = 0u64;
    for s in sellers {
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reputation_facts WHERE seller_id = $1")
            .bind(s)
            .fetch_one(pool)
            .await?;
        sync_facts_for_seller(pool, kf, cfg, s).await?;
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reputation_facts WHERE seller_id = $1")
            .bind(s)
            .fetch_one(pool)
            .await?;
        n += (after - before).max(0) as u64;
    }
    Ok(n)
}

/// Attach (or update) the review score on an order's fact, then refresh
/// the seller's summary. Called by the review writer.
pub async fn set_fact_score(
    pool: &PgPool,
    cfg: &Stage9Config,
    order_id: i64,
    score: i32,
) -> Result<(), sqlx::Error> {
    let seller_id: Option<i64> =
        sqlx::query_scalar("SELECT seller_id FROM reputation_facts WHERE order_id = $1")
            .bind(order_id)
            .fetch_optional(pool)
            .await?
            .flatten();
    if let Some(sid) = seller_id {
        sqlx::query("UPDATE reputation_facts SET score = $2 WHERE order_id = $1")
            .bind(order_id)
            .bind(score)
            .execute(pool)
            .await?;
        recompute_summary(pool, cfg, sid).await?;
    }
    Ok(())
}

// -- model input ------------------------------------------------------------------

pub async fn facts_for_seller(pool: &PgPool, seller_id: i64) -> Result<Vec<ReputationFact>, sqlx::Error> {
    let seller_pub = crate::db::public_id_of(pool, seller_id)
        .await?
        .unwrap_or_default();
    let rows: Vec<(Vec<u8>, i16, String, String, Option<i32>, String)> = sqlx::query_as(
        "SELECT buyer_token, maturity_bucket, evidence_level, outcome, score, month
           FROM reputation_facts WHERE seller_id = $1 ORDER BY month, id",
    )
    .bind(seller_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(token, bucket, evidence, outcome, score, month)| {
            let mut t = [0u8; 32];
            if token.len() == 32 {
                t.copy_from_slice(&token);
            }
            ReputationFact {
                seller_id: seller_pub.clone(),
                buyer_token: t,
                maturity_bucket: bucket as u8,
                evidence_level: evidence_u8(&evidence),
                outcome: outcome_code_from_str(&outcome),
                score: score.map(|s| s as u8),
                month,
            }
        })
        .collect())
}

fn outcome_code_from_str(s: &str) -> u8 {
    match s {
        "resolved-delivered-confirmed" => OUT_RESOLVED_DELIVERED,
        "resolved-refund-confirmed" => OUT_RESOLVED_REFUND,
        "resolved-seller-at-fault" => OUT_RESOLVED_SELLER_FAULT,
        "resolved-buyer-at-fault" => OUT_RESOLVED_BUYER_FAULT,
        "resolved-unresolved" => OUT_RESOLVED_UNRESOLVED,
        "cancelled" => OUT_CANCELLED,
        "declined" => OUT_DECLINED,
        _ => OUT_COMPLETED,
    }
}

// -- summaries ----------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct StoredSummary {
    pub model_id: String,
    pub model_version: String,
    pub weighted_score: Option<f64>,
    pub review_count: i32,
    pub established_buyers: i64,
    pub total_weight: f64,
}

pub async fn summary_row(pool: &PgPool, seller_id: i64) -> Result<Option<StoredSummary>, sqlx::Error> {
    let row: Option<(String, String, Option<f64>, i32, i64, f64)> = sqlx::query_as(
        "SELECT model_id, model_version, weighted_score, review_count, established_buyers, total_weight
           FROM reputation_summaries WHERE seller_id = $1",
    )
    .bind(seller_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(model_id, model_version, weighted_score, review_count, established_buyers, total_weight)| {
        StoredSummary { model_id, model_version, weighted_score, review_count, established_buyers, total_weight }
    }))
}

pub async fn recompute_summary(
    pool: &PgPool,
    cfg: &Stage9Config,
    seller_id: i64,
) -> Result<(), sqlx::Error> {
    let facts = facts_for_seller(pool, seller_id).await?;
    let review_count = facts.iter().filter(|f| f.score.is_some()).count() as i32;
    let (summary, model_id, model_version) = if cfg.model == "raw-counts" {
        let m = RawCounts;
        (m.summarize(&facts), m.id().0.to_string(), m.version().to_string())
    } else {
        let m = WeightedReviewsV1 { cfg: cfg.clone() };
        (m.summarize(&facts), m.id().0.to_string(), m.version().to_string())
    };
    sqlx::query(
        "INSERT INTO reputation_summaries
            (seller_id, model_id, model_version, weighted_score, review_count, established_buyers, total_weight, computed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now())
         ON CONFLICT (seller_id) DO UPDATE SET
            model_id = EXCLUDED.model_id, model_version = EXCLUDED.model_version,
            weighted_score = EXCLUDED.weighted_score, review_count = EXCLUDED.review_count,
            established_buyers = EXCLUDED.established_buyers, total_weight = EXCLUDED.total_weight,
            computed_at = now()",
    )
    .bind(seller_id)
    .bind(&model_id)
    .bind(&model_version)
    .bind(summary.weighted_score)
    .bind(review_count)
    .bind(summary.established_buyers as i64)
    .bind(summary.total_weight)
    .execute(pool)
    .await?;
    Ok(())
}

// -- raw-facts panel (core-rendered under every model) --------------------------------

#[derive(Debug, Clone, Default)]
pub struct RawFacts {
    pub member_since_month: String,
    pub account_age_days: i64,
    pub first_sale_month: Option<String>,
    pub completed_orders: i64,
    pub distinct_buyers: i64,
    pub seller_confirmed_payments: i64,
    pub verified_payments: i64,
    pub disputes_opened: i64,
    pub disputes_against_seller: i64,
    pub rotations_certified: i64,
    pub rotations_uncertified: i64,
}

pub async fn raw_facts(pool: &PgPool, seller_id: i64) -> Result<RawFacts, sqlx::Error> {
    let (created_at,): (OffsetDateTime,) =
        sqlx::query_as("SELECT created_at FROM accounts WHERE id = $1")
            .bind(seller_id)
            .fetch_one(pool)
            .await?;
    let facts: Vec<(String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT outcome, evidence_level, buyer_token FROM reputation_facts WHERE seller_id = $1",
    )
    .bind(seller_id)
    .fetch_all(pool)
    .await?;
    let mut completed = 0i64;
    let mut buyers = std::collections::HashSet::new();
    let mut first_sale: Option<String> = None;
    let mut confirmed = 0i64;
    let mut verified = 0i64;
    for (outcome, evidence, token) in &facts {
        if is_sale_outcome(outcome) {
            completed += 1;
            buyers.insert(token.clone());
            match evidence.as_str() {
                "SellerAttested" => confirmed += 1,
                "ProofVerified" | "WalletObserved" => verified += 1,
                _ => {}
            }
        }
    }
    // First sale month from facts with sale outcomes (month precision).
    let sale_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT outcome, month FROM reputation_facts WHERE seller_id = $1 ORDER BY month",
    )
    .bind(seller_id)
    .fetch_all(pool)
    .await?;
    for (outcome, month) in sale_rows {
        if is_sale_outcome(&outcome) {
            first_sale = Some(month);
            break;
        }
    }
    let disputes_opened: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM disputes d JOIN orders o ON o.id = d.order_id WHERE o.seller_id = $1",
    )
    .bind(seller_id)
    .fetch_one(pool)
    .await?;
    let disputes_against: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM disputes d JOIN orders o ON o.id = d.order_id
          WHERE o.seller_id = $1 AND d.state = 'resolved' AND d.outcome = 'seller-at-fault'",
    )
    .bind(seller_id)
    .fetch_one(pool)
    .await?;
    let (cert, uncert): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE certified), COUNT(*) FILTER (WHERE NOT certified)
           FROM key_rotations WHERE account_id = $1",
    )
    .bind(seller_id)
    .fetch_one(pool)
    .await?;
    Ok(RawFacts {
        member_since_month: month_of(created_at),
        account_age_days: (OffsetDateTime::now_utc() - created_at).whole_days(),
        first_sale_month: first_sale,
        completed_orders: completed,
        distinct_buyers: buyers.len() as i64,
        seller_confirmed_payments: confirmed,
        verified_payments: verified,
        disputes_opened,
        disputes_against_seller: disputes_against,
        rotations_certified: cert,
        rotations_uncertified: uncert,
    })
}

// -- the models -----------------------------------------------------------------------

/// weighted-reviews-v1: weight = maturity × evidence × repeat.
/// - maturity: cfg.mature_weight (1.0) for bucket 1, else cfg.immature_weight (0.3).
/// - evidence: cfg.evidence_verified_weight (1.0) for ProofVerified /
///   WalletObserved; every other level takes the unverified tier
///   cfg.evidence_unverified_weight (0.6) — under Direct Payments v1
///   that is SellerAttested, the only level that occurs.
/// - repeat: the k-th scored fact from the same buyer token within the
///   repeat window counts 1/k. Facts carry month precision only (the
///   spec's own storage rule), so the 90-day window is evaluated on
///   calendar months: a fact counts toward k when it falls in the same
///   month or the two preceding months, in month order.
pub struct WeightedReviewsV1 {
    pub cfg: Stage9Config,
}

impl WeightedReviewsV1 {
    fn weight_for(&self, fact: &ReputationFact, k: u32) -> f64 {
        let maturity = if fact.maturity_bucket >= 1 {
            self.cfg.mature_weight
        } else {
            self.cfg.immature_weight
        };
        let evidence = if matches!(fact.evidence_level, EV_PROOF_VERIFIED | EV_WALLET_OBSERVED) {
            self.cfg.evidence_verified_weight
        } else {
            self.cfg.evidence_unverified_weight
        };
        maturity * evidence * (1.0 / k.max(1) as f64)
    }
}

impl Module for WeightedReviewsV1 {
    fn id(&self) -> ModuleId {
        ModuleId("weighted-reviews-v1")
    }
    fn version(&self) -> semver::Version {
        semver::Version::new(1, 0, 0)
    }
    fn capabilities(&self) -> &[Capability] {
        &[]
    }
}

impl ReputationModel for WeightedReviewsV1 {
    fn summarize(&self, facts: &[ReputationFact]) -> ReputationSummary {
        // Scored facts in (month, input) order — input arrives ordered
        // by month then insertion, from facts_for_seller.
        let scored: Vec<&ReputationFact> = facts.iter().filter(|f| f.score.is_some()).collect();
        let window_months = (self.cfg.repeat_window_days / 30).max(0);
        let mut total_weight = 0.0f64;
        let mut weighted_sum = 0.0f64;
        let mut established: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for (i, f) in scored.iter().enumerate() {
            // k = 1 + number of earlier scored facts from the same
            // token inside the window ending at this fact's month.
            let mut k: u32 = 1;
            for g in scored.iter().take(i) {
                if g.buyer_token == f.buyer_token {
                    let diff = month_index(&f.month) - month_index(&g.month);
                    if (0..=window_months).contains(&diff) {
                        k += 1;
                    }
                }
            }
            let w = self.weight_for(f, k);
            total_weight += w;
            weighted_sum += w * f.score.unwrap_or(0) as f64;
            if f.maturity_bucket >= 1 {
                established.insert(f.buyer_token);
            }
        }
        let weighted_score = if total_weight >= self.cfg.min_total_weight && total_weight > 0.0 {
            Some(weighted_sum / total_weight)
        } else {
            None
        };
        ReputationSummary {
            weighted_score,
            established_buyers: established.len() as u64,
            total_weight,
        }
    }
}

/// raw-counts: no score at all — the profile shows only the raw-facts
/// panel. The core still stores facts (they are core data, and the
/// panel is core-rendered); the model itself computes nothing.
pub struct RawCounts;

impl Module for RawCounts {
    fn id(&self) -> ModuleId {
        ModuleId("raw-counts")
    }
    fn version(&self) -> semver::Version {
        semver::Version::new(1, 0, 0)
    }
    fn capabilities(&self) -> &[Capability] {
        &[]
    }
}

impl ReputationModel for RawCounts {
    fn summarize(&self, _facts: &[ReputationFact]) -> ReputationSummary {
        ReputationSummary { weighted_score: None, established_buyers: 0, total_weight: 0.0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(token: u8, bucket: u8, ev: u8, score: Option<u8>, month: &str) -> ReputationFact {
        ReputationFact {
            seller_id: "acct_x".into(),
            buyer_token: [token; 32],
            maturity_bucket: bucket,
            evidence_level: ev,
            outcome: OUT_COMPLETED,
            score,
            month: month.into(),
        }
    }

    fn model() -> WeightedReviewsV1 {
        WeightedReviewsV1 { cfg: Stage9Config::defaults() }
    }

    #[test]
    fn weight_math_maturity_evidence_repeat() {
        let m = model();
        // One mature, attested review: weight 1*0.6*1 = 0.6 < 5 → no score.
        let s = m.summarize(&[fact(1, 1, EV_SELLER_ATTESTED, Some(5), "2026-10")]);
        assert_eq!(s.total_weight, 0.6);
        assert_eq!(s.weighted_score, None);
        assert_eq!(s.established_buyers, 1);
        // Immature, attested: 0.3*0.6 = 0.18.
        let s = m.summarize(&[fact(1, 0, EV_SELLER_ATTESTED, Some(5), "2026-10")]);
        assert!((s.total_weight - 0.18).abs() < 1e-9);
        assert_eq!(s.established_buyers, 0);
        // Verified evidence: 1*1 = 1.0.
        let s = m.summarize(&[fact(1, 1, EV_PROOF_VERIFIED, Some(4), "2026-10")]);
        assert_eq!(s.total_weight, 1.0);
    }

    #[test]
    fn repeat_decay_within_window_only() {
        let m = model();
        // Same token, same month: k = 1, 2, 3 → weights 1, 1/2, 1/3 (verified evidence, mature).
        let facts = vec![
            fact(9, 1, EV_PROOF_VERIFIED, Some(5), "2026-10"),
            fact(9, 1, EV_PROOF_VERIFIED, Some(5), "2026-10"),
            fact(9, 1, EV_PROOF_VERIFIED, Some(1), "2026-10"),
        ];
        let s = m.summarize(&facts);
        let expected = 1.0 + 0.5 + 1.0 / 3.0;
        assert!((s.total_weight - expected).abs() < 1e-9);
        // Four months later the window has passed: k resets to 1.
        let facts = vec![
            fact(9, 1, EV_PROOF_VERIFIED, Some(5), "2026-06"),
            fact(9, 1, EV_PROOF_VERIFIED, Some(5), "2026-10"),
        ];
        let s = m.summarize(&facts);
        assert!((s.total_weight - 2.0).abs() < 1e-9);
    }

    #[test]
    fn headline_threshold_and_mean() {
        let m = model();
        // 9 mature verified reviews of 4 → weight 9 ≥ 5, mean 4.
        let facts: Vec<_> = (0..9).map(|i| fact(i as u8 + 1, 1, EV_PROOF_VERIFIED, Some(4), "2026-10")).collect();
        let s = m.summarize(&facts);
        assert_eq!(s.weighted_score, Some(4.0));
        assert_eq!(s.established_buyers, 9);
        // Just below the threshold: 8 attested mature reviews → 4.8 < 5 → None.
        let facts: Vec<_> = (0..8).map(|i| fact(i as u8 + 1, 1, EV_SELLER_ATTESTED, Some(4), "2026-10")).collect();
        let s = m.summarize(&facts);
        assert!((s.total_weight - 4.8).abs() < 1e-9);
        assert_eq!(s.weighted_score, None);
    }

    #[test]
    fn evidence_and_outcome_mappings_are_exact() {
        assert_eq!(evidence_u8("None"), EV_NONE);
        assert_eq!(evidence_u8("BuyerReported"), EV_BUYER_REPORTED);
        assert_eq!(evidence_u8("SellerAttested"), EV_SELLER_ATTESTED);
        assert_eq!(evidence_u8("ProofVerified"), EV_PROOF_VERIFIED);
        assert_eq!(evidence_u8("WalletObserved"), EV_WALLET_OBSERVED);
        assert_eq!(evidence_u8("garbage"), EV_NONE);
        assert_eq!(outcome_str(OUT_COMPLETED), "completed");
        assert_eq!(outcome_str(OUT_RESOLVED_DELIVERED), "resolved-delivered-confirmed");
        assert_eq!(outcome_str(OUT_RESOLVED_REFUND), "resolved-refund-confirmed");
        assert_eq!(outcome_str(OUT_RESOLVED_SELLER_FAULT), "resolved-seller-at-fault");
        assert_eq!(outcome_str(OUT_RESOLVED_BUYER_FAULT), "resolved-buyer-at-fault");
        assert_eq!(outcome_str(OUT_RESOLVED_UNRESOLVED), "resolved-unresolved");
        assert_eq!(outcome_str(OUT_CANCELLED), "cancelled");
        assert_eq!(outcome_str(OUT_DECLINED), "declined");
        // Round trip through the string form used by facts_for_seller.
        for code in 0u8..=7 {
            assert_eq!(outcome_code_from_str(outcome_str(code)), code);
        }
        assert_eq!(outcome_code("Completed", None), OUT_COMPLETED);
        assert_eq!(outcome_code("Cancelled", None), OUT_CANCELLED);
        assert_eq!(outcome_code("Declined", None), OUT_DECLINED);
        assert_eq!(outcome_code("Resolved", Some("delivered-confirmed")), OUT_RESOLVED_DELIVERED);
        assert_eq!(outcome_code("Resolved", Some("refund-confirmed")), OUT_RESOLVED_REFUND);
        assert_eq!(outcome_code("Resolved", Some("seller-at-fault")), OUT_RESOLVED_SELLER_FAULT);
        assert_eq!(outcome_code("Resolved", Some("buyer-at-fault")), OUT_RESOLVED_BUYER_FAULT);
        assert_eq!(outcome_code("Resolved", Some("unresolved")), OUT_RESOLVED_UNRESOLVED);
        assert_eq!(outcome_code("Resolved", None), OUT_RESOLVED_UNRESOLVED);
        assert_eq!(outcome_code("Resolved", Some("withdrawn")), OUT_RESOLVED_UNRESOLVED);
    }

    #[test]
    fn sale_and_terminal_sets_are_exact() {
        for s in ["completed", "resolved-delivered-confirmed", "resolved-refund-confirmed", "resolved-seller-at-fault", "resolved-unresolved"] {
            assert!(is_sale_outcome(s), "{s} is a sale");
        }
        for s in ["cancelled", "declined", "resolved-buyer-at-fault"] {
            assert!(!is_sale_outcome(s), "{s} is not a sale");
        }
        for s in ["Completed", "Resolved", "Cancelled", "Declined"] {
            assert!(is_terminal(s), "{s} is terminal");
        }
        for s in ["Requested", "AwaitingPayment", "Paid", "Fulfilled", "Disputed"] {
            assert!(!is_terminal(s), "{s} is not terminal");
        }
    }

    #[test]
    fn month_index_arithmetic() {
        assert_eq!(month_index("2026-10") - month_index("2026-08"), 2);
        assert_eq!(month_index("2027-01") - month_index("2026-12"), 1);
        assert_eq!(month_index("2026-10") - month_index("2026-10"), 0);
        assert_eq!(month_of(time::macros::datetime!(2026-03-05 00:00 UTC)), "2026-03");
    }

    #[test]
    fn unscored_facts_do_not_count() {
        let m = model();
        let s = m.summarize(&[fact(1, 1, EV_SELLER_ATTESTED, None, "2026-10")]);
        assert_eq!(s.total_weight, 0.0);
        assert_eq!(s.weighted_score, None);
    }
}
