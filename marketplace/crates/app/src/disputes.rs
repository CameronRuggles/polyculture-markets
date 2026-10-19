//! Disputes (spec §13 on top of §9): outcome workflow, voluntary
//! disclosures, and resolution. Opening happens inside the order
//! transition (orders.rs creates the row atomically with the state
//! change); this module owns everything after that.
//!
//! Moderators see the public order record (terms hash, listing, total,
//! evidence level, and — under Direct Payments v1 — the assigned
//! subaddress with its wallet-signed message and the seller's
//! attestation). Private messages reach moderators ONLY by voluntary
//! disclosure: a party decrypts locally and pastes the plaintext plus
//! its detached signature. The signature is verified against the OTHER
//! party's pinned key — the seller's order-pinned fingerprint, or the
//! buyer's key that was current when the order was created. Only a
//! message that verifies counts as evidence; everything else is
//! stored and shown as an "unverified claim". Moderators have no
//! conversation-browsing interface, here or anywhere.
//!
//! Disclosure content is stored encrypted with the key file and kept
//! until 180 days after resolution (deletion is the Stage 10 job; the
//! period is shown to the user before they disclose).

use crate::keyfile::KeyFile;
use crate::reputation::{self, Stage9Config};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;

pub const OUTCOMES: [&str; 5] = [
    "delivered-confirmed",
    "refund-confirmed",
    "seller-at-fault",
    "buyer-at-fault",
    "unresolved",
];

#[derive(Debug, PartialEq, Eq)]
pub enum DisputeError {
    NotFound,
    Forbidden,
    BadState,
    BadOutcome,
    BadInput,
    Db,
}

#[derive(Debug, Clone)]
pub struct Dispute {
    pub id: i64,
    pub order_id: i64,
    pub opened_by: i64,
    pub state: String,
    pub outcome: Option<String>,
    pub outcome_state: String,
    pub resolved_by: Option<i64>,
    pub created_at: OffsetDateTime,
    pub resolved_at: Option<OffsetDateTime>,
}

type DisputeRow = (i64, i64, i64, String, Option<String>, String, Option<i64>, OffsetDateTime, Option<OffsetDateTime>);

fn row(r: DisputeRow) -> Dispute {
    Dispute {
        id: r.0,
        order_id: r.1,
        opened_by: r.2,
        state: r.3,
        outcome: r.4,
        outcome_state: r.5,
        resolved_by: r.6,
        created_at: r.7,
        resolved_at: r.8,
    }
}

const DISPUTE_COLS: &str =
    "id, order_id, opened_by, state, outcome, outcome_state, resolved_by, created_at, resolved_at";

pub async fn get_dispute(pool: &PgPool, id: i64) -> Result<Option<Dispute>, DisputeError> {
    let r: Option<DisputeRow> = sqlx::query_as(&format!("SELECT {DISPUTE_COLS} FROM disputes WHERE id = $1"))
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|_| DisputeError::Db)?;
    Ok(r.map(row))
}

/// The live (or most recent) dispute for an order, for the order page.
pub async fn dispute_for_order(pool: &PgPool, order_id: i64) -> Result<Option<Dispute>, DisputeError> {
    let r: Option<DisputeRow> = sqlx::query_as(&format!(
        "SELECT {DISPUTE_COLS} FROM disputes WHERE order_id = $1 ORDER BY id DESC LIMIT 1"
    ))
    .bind(order_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| DisputeError::Db)?;
    Ok(r.map(row))
}

/// Open disputes for the moderation queue.
pub async fn open_disputes(pool: &PgPool) -> Result<Vec<(Dispute, String, String, String)>, DisputeError> {
    // This query was broken twice over and the queue page's
    // unwrap_or_default hid both: the shared DISPUTE_COLS list is
    // unqualified, which made `id`/`created_at` ambiguous across
    // this join, and the row type nested a tuple inside the row
    // tuple, which sqlx cannot decode (it reads column 0 as a
    // RECORD). The moderation queue therefore never actually
    // listed a dispute. Found by the CL2 acceptance test
    // (2026-10-19); the row is flat and fully qualified now.
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        i64,
        i64,
        i64,
        String,
        Option<String>,
        String,
        Option<i64>,
        OffsetDateTime,
        Option<OffsetDateTime>,
        String,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT d.id, d.order_id, d.opened_by, d.state, d.outcome, d.outcome_state,
                d.resolved_by, d.created_at, d.resolved_at, o.public_id, ba.username, sa.username
           FROM disputes d
           JOIN orders o ON o.id = d.order_id
           JOIN accounts ba ON ba.id = o.buyer_id
           JOIN accounts sa ON sa.id = o.seller_id
          WHERE d.state IN ('open', 'awaiting_buyer_confirmation')
          ORDER BY d.created_at",
    )
    .fetch_all(pool)
    .await
    .map_err(|_| DisputeError::Db)?;
    Ok(rows
        .into_iter()
        .map(|(a, b, c, d, e, f, g, h, i, oid, bu, su)| {
            (row((a, b, c, d, e, f, g, h, i)), oid, bu, su)
        })
        .collect())
}

// -- disclosures --------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct DisclosureContent {
    message: String,
    signature: String,
}

#[derive(Debug, Clone)]
pub struct DisclosureView {
    pub id: i64,
    pub submitted_by: i64,
    pub submitter_username: String,
    pub signature_status: String, // verified | unverified_claim
    pub message: String,
    pub created_at: String,
    /// Verification-fix V4: the two times the verification rule
    /// compared, shown next to the disclosure so anyone reading it
    /// can see WHY it carries its status — when the signature was
    /// created, and when the message it unwraps arrived. `None` for
    /// disclosures stored before they were tied to a message
    /// (migration 0015) and for unverified claims with no good
    /// signature.
    pub signature_created_at: Option<String>,
    pub message_received_at: Option<String>,
}

/// The cert a disclosed message must verify against: the OTHER party's
/// pinned key. For the seller that is the fingerprint pinned on the
/// order at creation (exact cert). For the buyer it is the key whose
/// validity interval covers the order's creation — the buyer-side pin.
async fn other_party_cert(
    pool: &PgPool,
    order_id: i64,
    submitter_id: i64,
) -> Result<Option<Vec<u8>>, DisputeError> {
    let r: Option<(i64, i64, String, OffsetDateTime)> = sqlx::query_as(
        "SELECT buyer_id, seller_id, seller_fpr_pinned, created_at FROM orders WHERE id = $1",
    )
    .bind(order_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| DisputeError::Db)?;
    let Some((buyer_id, seller_id, pinned_fpr, created_at)) = r else {
        return Ok(None);
    };
    let other = if submitter_id == buyer_id {
        seller_id
    } else if submitter_id == seller_id {
        buyer_id
    } else {
        return Ok(None);
    };
    let cert: Option<Vec<u8>> = if other == seller_id {
        sqlx::query_scalar("SELECT certificate FROM identity_keys WHERE fingerprint = $1")
            .bind(&pinned_fpr)
            .fetch_optional(pool)
            .await
            .map_err(|_| DisputeError::Db)?
    } else {
        sqlx::query_scalar(
            "SELECT certificate FROM identity_keys
              WHERE account_id = $1 AND created_at <= $2
                AND (retired_at IS NULL OR retired_at > $2)
              ORDER BY created_at DESC LIMIT 1",
        )
        .bind(other)
        .bind(created_at)
        .fetch_optional(pool)
        .await
        .map_err(|_| DisputeError::Db)?
    };
    Ok(cert)
}

/// Submit a voluntary disclosure. `message` and `signature` are
/// form-layer normalized (Q13) by the caller contract — this function
/// applies `normalize_form_lines` itself so the verified bytes, the
/// stored bytes, and the displayed bytes are the same bytes.
pub async fn submit_disclosure(
    pool: &PgPool,
    kf: &KeyFile,
    dispute_id: i64,
    submitter_id: i64,
    message_raw: &str,
    signature_raw: &str,
) -> Result<String, DisputeError> {
    let dispute = get_dispute(pool, dispute_id).await?.ok_or(DisputeError::NotFound)?;
    if dispute.state != "open" {
        return Err(DisputeError::BadState);
    }
    let order = crate::orders::order_by_public_id(pool, &order_public_id(pool, dispute.order_id).await?)
        .await
        .ok_or(DisputeError::NotFound)?;
    if submitter_id != order.buyer_id && submitter_id != order.seller_id {
        return Err(DisputeError::Forbidden);
    }
    let message = normalize(message_raw)?;
    let signature = normalize(signature_raw)?;
    if message.is_empty() || signature.is_empty() || message.len() > 65_536 || signature.len() > 16_384 {
        return Err(DisputeError::BadInput);
    }
    let cert = other_party_cert(pool, dispute.order_id, submitter_id).await?;
    let verified = cert
        .as_deref()
        .map(|c| crate::keys::verify_detached(c, message.as_bytes(), signature.as_bytes()))
        .unwrap_or(false);
    let status = if verified { "verified" } else { "unverified_claim" };
    let content = serde_json::to_vec(&DisclosureContent { message, signature })
        .map_err(|_| DisputeError::Db)?;
    let enc = kf.encrypt(&content);
    sqlx::query(
        "INSERT INTO disclosures (dispute_id, submitted_by, content_enc, signature_status)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(dispute_id)
    .bind(submitter_id)
    .bind(&enc)
    .bind(status)
    .execute(pool)
    .await
    .map_err(|_| DisputeError::Db)?;
    Ok(status.to_string())
}

/// Submit a disclosure as ONE paste: the output of
/// `gpg --unwrap --armor` on the original encrypted message
/// (messaging audit MM1). The pre-MM1 form asked for plaintext plus a
/// detached signature, but these messages are signed INLINE — no
/// detached signature ever exists, so the old form could never
/// verify anything. Here the server verifies the embedded signature
/// itself, with Sequoia, against the OTHER party's order-pinned
/// certificate, and extracts the plaintext. An unwrapped message
/// whose signature is absent, foreign, or bad is stored as an
/// unverified claim holding the extracted plaintext — parity with the
/// old form's treatment of an unverifiable signature.
///
/// The paste itself is stored as the disclosure's `signature` field
/// (the proof artifact a moderator re-checks offline); the extracted
/// plaintext is the displayed `message`. Returns the signature status
/// ("verified" / "unverified_claim").
///
/// Verification-fix V4 (2026-10-19): the submitter also NAMES the
/// conversation message being disclosed (`message_id`). Before this
/// fix the check proved only "someone signed this text" — a signed
/// message from another order, or one signed long before this
/// order's conversation, was stored as verified evidence OF THIS
/// DISPUTE. Now the named message must be in the disputed order's
/// own conversation and sent by the other party, and `verified`
/// additionally requires the signature to have been created within
/// the 24 hours before that message arrived (and not after it):
/// a party unwrapping a message they just received holds a fresh
/// signature. Both times are stored on the row and shown on the
/// dispute page.
pub async fn submit_disclosure_unwrapped(
    pool: &PgPool,
    kf: &KeyFile,
    dispute_id: i64,
    submitter_id: i64,
    message_id: i64,
    unwrapped_raw: &str,
) -> Result<String, DisputeError> {
    // Cap parity with the old pair (64 KiB message + 16 KiB
    // signature): one paste may carry both.
    if unwrapped_raw.is_empty() || unwrapped_raw.len() > 81_920 {
        return Err(DisputeError::BadInput);
    }
    // Browsers submit CRLF; normalize before parsing (MH1) so the
    // stored paste is byte-identical to what was verified.
    let pasted = unwrapped_raw.replace("\r\n", "\n").replace('\r', "\n");
    let dispute = get_dispute(pool, dispute_id)
        .await?
        .ok_or(DisputeError::NotFound)?;
    if dispute.state != "open" {
        return Err(DisputeError::BadState);
    }
    let order = crate::orders::order_by_public_id(pool, &order_public_id(pool, dispute.order_id).await?)
        .await
        .ok_or(DisputeError::NotFound)?;
    if submitter_id != order.buyer_id && submitter_id != order.seller_id {
        return Err(DisputeError::Forbidden);
    }
    let other = if submitter_id == order.buyer_id { order.seller_id } else { order.buyer_id };
    // V4: the named message must belong to THIS order's conversation
    // and have been sent by the other party — a disclosure unwraps a
    // message the submitter RECEIVED in this conversation.
    let named: Option<(i64, OffsetDateTime)> = sqlx::query_as(
        "SELECT m.sender_id, m.received_at FROM encrypted_messages m
           JOIN conversations c ON c.id = m.conversation_id
          WHERE m.id = $1 AND c.order_id = $2",
    )
    .bind(message_id)
    .bind(dispute.order_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| DisputeError::Db)?;
    let Some((sender_id, received_at)) = named else {
        return Err(DisputeError::BadInput);
    };
    if sender_id != other {
        return Err(DisputeError::BadInput);
    }
    let cert = other_party_cert(pool, dispute.order_id, submitter_id).await?;
    let Some(extracted) = cert
        .as_deref()
        .and_then(|c| crate::keys::extract_unwrapped_message(c, pasted.as_bytes()))
    else {
        // No pinned cert, or the paste is not a readable message.
        return Err(DisputeError::BadInput);
    };
    if extracted.plaintext.len() > 65_536 {
        return Err(DisputeError::BadInput);
    }
    // V4 timing rule on top of the signature check.
    let sig_created = extracted.signature_created_unix;
    let timing_ok = match sig_created {
        Some(created) => {
            let received = received_at.unix_timestamp();
            created <= received && created >= received - 24 * 60 * 60
        }
        None => false,
    };
    let status = if extracted.verified && timing_ok {
        "verified"
    } else {
        "unverified_claim"
    };
    let content = serde_json::to_vec(&DisclosureContent {
        message: extracted.plaintext,
        signature: pasted,
    })
    .map_err(|_| DisputeError::Db)?;
    let enc = kf.encrypt(&content);
    let sig_at = sig_created.and_then(|u| OffsetDateTime::from_unix_timestamp(u).ok());
    sqlx::query(
        "INSERT INTO disclosures (dispute_id, submitted_by, content_enc, signature_status,
                                  message_id, signature_created_at, message_received_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(dispute_id)
    .bind(submitter_id)
    .bind(&enc)
    .bind(status)
    .bind(message_id)
    .bind(sig_at)
    .bind(received_at)
    .execute(pool)
    .await
    .map_err(|_| DisputeError::Db)?;
    Ok(status.to_string())
}

fn normalize(raw: &str) -> Result<String, DisputeError> {
    let lines = modules_api::normalize_form_lines(raw).map_err(|_| DisputeError::BadInput)?;
    Ok(lines.join("\n"))
}

async fn order_public_id(pool: &PgPool, order_id: i64) -> Result<String, DisputeError> {
    sqlx::query_scalar("SELECT public_id FROM orders WHERE id = $1")
        .bind(order_id)
        .fetch_one(pool)
        .await
        .map_err(|_| DisputeError::Db)
}

pub async fn disclosures_for(
    pool: &PgPool,
    kf: &KeyFile,
    dispute_id: i64,
) -> Result<Vec<DisclosureView>, DisputeError> {
    let rows: Vec<(
        i64,
        i64,
        String,
        Vec<u8>,
        String,
        OffsetDateTime,
        Option<OffsetDateTime>,
        Option<OffsetDateTime>,
    )> = sqlx::query_as(
        "SELECT d.id, d.submitted_by, a.username, d.content_enc, d.signature_status, d.created_at,
                d.signature_created_at, d.message_received_at
           FROM disclosures d JOIN accounts a ON a.id = d.submitted_by
          WHERE d.dispute_id = $1 ORDER BY d.created_at",
    )
    .bind(dispute_id)
    .fetch_all(pool)
    .await
    .map_err(|_| DisputeError::Db)?;
    let f = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    Ok(rows
        .into_iter()
        .map(|(id, by, username, enc, status, created, sig_at, recv_at)| {
            let message = kf
                .decrypt(&enc)
                .and_then(|pt| serde_json::from_slice::<DisclosureContent>(&pt).ok())
                .map(|c| c.message)
                .unwrap_or_else(|| "(content could not be decrypted)".to_string());
            DisclosureView {
                id,
                submitted_by: by,
                submitter_username: username,
                signature_status: status,
                message,
                created_at: created.format(&f).unwrap_or_default(),
                signature_created_at: sig_at.map(|t| t.format(&f).unwrap_or_default()),
                message_received_at: recv_at.map(|t| t.format(&f).unwrap_or_default()),
            }
        })
        .collect())
}

// -- resolution -----------------------------------------------------------------

/// Moderator records an outcome. `refund-confirmed` is only PROPOSED
/// here: §9 requires the buyer's confirmation before the order can
/// resolve on a refund outcome — the dispute waits in
/// 'awaiting_buyer_confirmation' until `confirm_refund`.
pub async fn resolve(
    pool: &PgPool,
    kf: &KeyFile,
    cfg: &Stage9Config,
    dispute_id: i64,
    moderator_id: i64,
    outcome: &str,
) -> Result<(), DisputeError> {
    if !OUTCOMES.contains(&outcome) {
        return Err(DisputeError::BadOutcome);
    }
    let dispute = get_dispute(pool, dispute_id).await?.ok_or(DisputeError::NotFound)?;
    if dispute.state != "open" {
        return Err(DisputeError::BadState);
    }
    let order_pub = order_public_id(pool, dispute.order_id).await?;
    let order = crate::orders::order_by_public_id(pool, &order_pub)
        .await
        .ok_or(DisputeError::NotFound)?;
    if order.state != "Disputed" {
        return Err(DisputeError::BadState);
    }
    // CM3: no self-dealing. Moderators and admins can also buy and
    // sell; a moderator who is a party to this order may not decide
    // its dispute, in either direction.
    if moderator_id == order.buyer_id || moderator_id == order.seller_id {
        return Err(DisputeError::Forbidden);
    }
    if outcome == "refund-confirmed" {
        // CL2: the proposal moment starts the buyer's 14-day
        // confirmation deadline (retention.rs returns an
        // unconfirmed proposal to the moderator queue).
        sqlx::query(
            "UPDATE disputes SET outcome = $2, outcome_state = 'proposed',
                    state = 'awaiting_buyer_confirmation', resolved_by = $3,
                    refund_proposed_at = now()
              WHERE id = $1",
        )
        .bind(dispute_id)
        .bind(outcome)
        .bind(moderator_id)
        .execute(pool)
        .await
        .map_err(|_| DisputeError::Db)?;
        let _ = crate::orders::notify(pool, order.buyer_id, "dispute_refund_proposed", &order_pub).await;
        return Ok(());
    }
    finalize(pool, kf, cfg, &dispute, outcome, moderator_id).await
}

/// The buyer confirms a refund outcome; the moderator's recorded
/// outcome then resolves the order (Disputed → Resolved).
pub async fn confirm_refund(
    pool: &PgPool,
    kf: &KeyFile,
    cfg: &Stage9Config,
    dispute_id: i64,
    buyer_id: i64,
) -> Result<(), DisputeError> {
    let dispute = get_dispute(pool, dispute_id).await?.ok_or(DisputeError::NotFound)?;
    if dispute.state != "awaiting_buyer_confirmation" {
        return Err(DisputeError::BadState);
    }
    let order_pub = order_public_id(pool, dispute.order_id).await?;
    let order = crate::orders::order_by_public_id(pool, &order_pub)
        .await
        .ok_or(DisputeError::NotFound)?;
    if order.buyer_id != buyer_id {
        return Err(DisputeError::Forbidden);
    }
    let moderator = dispute.resolved_by.ok_or(DisputeError::Db)?;
    finalize(pool, kf, cfg, &dispute, "refund-confirmed", moderator).await
}

async fn finalize(
    pool: &PgPool,
    kf: &KeyFile,
    cfg: &Stage9Config,
    dispute: &Dispute,
    outcome: &str,
    moderator_id: i64,
) -> Result<(), DisputeError> {
    // Domain guard: Disputed → Resolved is a Moderator transition.
    if !domain::order_can_transition(
        domain::OrderState::Disputed,
        domain::OrderState::Resolved,
        domain::Actor::Moderator,
        domain::EvidenceLevel::None,
    ) {
        return Err(DisputeError::BadState);
    }
    let mut tx = pool.begin().await.map_err(|_| DisputeError::Db)?;
    let upd = sqlx::query(
        "UPDATE orders SET state = 'Resolved', terminal_at = now()
          WHERE id = $1 AND state = 'Disputed'",
    )
    .bind(dispute.order_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| DisputeError::Db)?;
    if upd.rows_affected() != 1 {
        return Err(DisputeError::BadState);
    }
    sqlx::query(
        "UPDATE disputes SET outcome = $2, outcome_state = 'final', state = 'resolved',
                resolved_at = now(), resolved_by = $3
          WHERE id = $1",
    )
    .bind(dispute.id)
    .bind(outcome)
    .bind(moderator_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| DisputeError::Db)?;
    sqlx::query(
        "INSERT INTO moderation_actions (actor_id, target_account_id, action, reason)
         VALUES ($1, NULL, 'dispute-resolve', $2)",
    )
    .bind(moderator_id)
    .bind(outcome)
    .execute(&mut *tx)
    .await
    .map_err(|_| DisputeError::Db)?;
    tx.commit().await.map_err(|_| DisputeError::Db)?;
    let order_pub = order_public_id(pool, dispute.order_id).await?;
    if let Some(o) = crate::orders::order_by_public_id(pool, &order_pub).await {
        let _ = crate::orders::notify(pool, o.buyer_id, "dispute_resolved", &order_pub).await;
        let _ = crate::orders::notify(pool, o.seller_id, "dispute_resolved", &order_pub).await;
    }
    let _ = reputation::record_fact_for_order(pool, kf, cfg, dispute.order_id).await;
    Ok(())
}
