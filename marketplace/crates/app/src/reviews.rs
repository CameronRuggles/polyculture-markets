//! Reviews (spec §13): one per order, by the buyer, only after the
//! order is Completed or Resolved. Score 1–5, up to 1,000 characters
//! of plain text (stored raw, rendered escaped — never markup). The
//! buyer may edit for 7 days; the seller may post exactly one public
//! reply. A review's score is mirrored onto the order's reputation
//! fact; the "payment verified on-chain" badge is shown only when the
//! fact's evidence is ProofVerified or WalletObserved (never under
//! Direct Payments v1, where all evidence is SellerAttested).

use crate::keyfile::KeyFile;
use crate::reputation::{self, Stage9Config, EV_PROOF_VERIFIED, EV_WALLET_OBSERVED};
use sqlx::PgPool;
use time::OffsetDateTime;

#[derive(Debug, PartialEq, Eq)]
pub enum ReviewError {
    NotFound,
    Forbidden,
    BadState,
    BadScore,
    TooLong,
    Empty,
    FormatChars,
    EditWindowClosed,
    AlreadyReplied,
    NoReview,
}

#[derive(Debug, Clone)]
pub struct ReviewView {
    pub order_public_id: String,
    pub buyer_public_id: String,
    pub score: i32,
    pub text: String,
    pub seller_reply: Option<String>,
    pub created_at: String,
    /// True only with ProofVerified / WalletObserved fact evidence.
    pub payment_verified_badge: bool,
    pub editable_until: Option<String>,
}

fn fmt_ts(t: OffsetDateTime) -> String {
    let f = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    t.format(&f).unwrap_or_default()
}

/// Submit a new review, or edit the buyer's existing one inside the
/// edit window. The order's fact is synced first so the score lands on
/// it (and on the seller's summary) in the same request.
pub async fn submit_review(
    pool: &PgPool,
    kf: &KeyFile,
    cfg: &Stage9Config,
    order_public_id: &str,
    buyer_id: i64,
    score: i32,
    text: &str,
) -> Result<(), ReviewError> {
    let order = crate::orders::order_by_public_id(pool, order_public_id)
        .await
        .ok_or(ReviewError::NotFound)?;
    if order.buyer_id != buyer_id {
        return Err(ReviewError::Forbidden);
    }
    if !matches!(order.state.as_str(), "Completed" | "Resolved") {
        return Err(ReviewError::BadState);
    }
    if !(1..=5).contains(&score) {
        return Err(ReviewError::BadScore);
    }
    let text = text.trim();
    if text.is_empty() {
        return Err(ReviewError::Empty);
    }
    if text.chars().count() > cfg.review_max_chars {
        return Err(ReviewError::TooLong);
    }
    // BL3: no Unicode format characters (category Cf) in review
    // text — it is displayed to other users verbatim.
    if modules_api::contains_format_chars(text) {
        return Err(ReviewError::FormatChars);
    }
    let existing: Option<(i64, OffsetDateTime)> =
        sqlx::query_as("SELECT id, created_at FROM reviews WHERE order_id = $1")
            .bind(order.id)
            .fetch_optional(pool)
            .await
            .map_err(|_| ReviewError::NotFound)?;
    let now = OffsetDateTime::now_utc();
    match existing {
        Some((rid, created)) => {
            if now - created > time::Duration::days(cfg.review_edit_window_days) {
                return Err(ReviewError::EditWindowClosed);
            }
            sqlx::query("UPDATE reviews SET score = $2, text = $3, updated_at = now() WHERE id = $1")
                .bind(rid)
                .bind(score)
                .bind(text)
                .execute(pool)
                .await
                .map_err(|_| ReviewError::NotFound)?;
        }
        None => {
            sqlx::query("INSERT INTO reviews (order_id, score, text) VALUES ($1, $2, $3)")
                .bind(order.id)
                .bind(score)
                .bind(text)
                .execute(pool)
                .await
                .map_err(|_| ReviewError::NotFound)?;
        }
    }
    // Mirror the score onto the fact + refresh the seller summary.
    let _ = reputation::record_fact_for_order(pool, kf, cfg, order.id).await;
    reputation::set_fact_score(pool, cfg, order.id, score)
        .await
        .map_err(|_| ReviewError::NotFound)?;
    Ok(())
}

/// The seller's single public reply to the review on their order.
pub async fn seller_reply(
    pool: &PgPool,
    cfg: &Stage9Config,
    order_public_id: &str,
    seller_id: i64,
    text: &str,
) -> Result<(), ReviewError> {
    let order = crate::orders::order_by_public_id(pool, order_public_id)
        .await
        .ok_or(ReviewError::NotFound)?;
    if order.seller_id != seller_id {
        return Err(ReviewError::Forbidden);
    }
    let text = text.trim();
    if text.is_empty() {
        return Err(ReviewError::Empty);
    }
    if text.chars().count() > cfg.review_max_chars {
        return Err(ReviewError::TooLong);
    }
    // BL3: the seller's reply is displayed verbatim too.
    if modules_api::contains_format_chars(text) {
        return Err(ReviewError::FormatChars);
    }
    let row: Option<(i64, Option<String>)> =
        sqlx::query_as("SELECT id, seller_reply FROM reviews WHERE order_id = $1")
            .bind(order.id)
            .fetch_optional(pool)
            .await
            .map_err(|_| ReviewError::NotFound)?;
    let Some((rid, existing_reply)) = row else {
        return Err(ReviewError::NoReview);
    };
    if existing_reply.is_some() {
        return Err(ReviewError::AlreadyReplied);
    }
    sqlx::query("UPDATE reviews SET seller_reply = $2, seller_reply_at = now() WHERE id = $1")
        .bind(rid)
        .bind(text)
        .execute(pool)
        .await
        .map_err(|_| ReviewError::NotFound)?;
    Ok(())
}

type ReviewRow = (String, String, i32, String, Option<String>, OffsetDateTime, String);

fn view(row: ReviewRow, cfg: &Stage9Config) -> ReviewView {
    let (order_public_id, buyer_public_id, score, text, seller_reply, created_at, evidence) = row;
    let badge = matches!(
        reputation::evidence_u8(&evidence),
        EV_PROOF_VERIFIED | EV_WALLET_OBSERVED
    );
    let editable_until = created_at + time::Duration::days(cfg.review_edit_window_days);
    ReviewView {
        order_public_id,
        buyer_public_id,
        score,
        text,
        seller_reply,
        created_at: fmt_ts(created_at),
        payment_verified_badge: badge,
        editable_until: Some(fmt_ts(editable_until)),
    }
}

const REVIEW_COLS: &str = "o.public_id, ba.public_id, r.score, r.text, r.seller_reply, r.created_at,
    COALESCE(f.evidence_level, o.evidence_level)";

pub async fn review_for_order(
    pool: &PgPool,
    cfg: &Stage9Config,
    order_id: i64,
) -> Result<Option<ReviewView>, sqlx::Error> {
    let row: Option<ReviewRow> = sqlx::query_as(&format!(
        "SELECT {REVIEW_COLS}
           FROM reviews r
           JOIN orders o ON o.id = r.order_id
           JOIN accounts ba ON ba.id = o.buyer_id
           LEFT JOIN reputation_facts f ON f.order_id = o.id
          WHERE r.order_id = $1"
    ))
    .bind(order_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| view(r, cfg)))
}

pub async fn reviews_for_seller(
    pool: &PgPool,
    cfg: &Stage9Config,
    seller_id: i64,
) -> Result<Vec<ReviewView>, sqlx::Error> {
    let rows: Vec<ReviewRow> = sqlx::query_as(&format!(
        "SELECT {REVIEW_COLS}
           FROM reviews r
           JOIN orders o ON o.id = r.order_id
           JOIN accounts ba ON ba.id = o.buyer_id
           LEFT JOIN reputation_facts f ON f.order_id = o.id
          WHERE o.seller_id = $1
          ORDER BY r.created_at DESC LIMIT 100"
    ))
    .bind(seller_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| view(r, cfg)).collect())
}
