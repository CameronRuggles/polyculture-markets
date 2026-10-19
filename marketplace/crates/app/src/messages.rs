//! Ciphertext messaging (spec §14, §15): conversations between two
//! accounts, optionally bound to an order. The server stores ciphertext
//! only; every submission passes the amended §14 envelope validator.
//! Key sightings (amendment, Q16) are recorded whenever a participant's
//! key is presented inside a conversation, and the validator's
//! RecipientKeyRetired decision is built from sightings + validity
//! overlap — never from key history alone.

use envelope::{EnvelopeContext, KeyRef};
use modules_api::EnvelopeError;
use sqlx::PgPool;

pub struct Conversation {
    pub id: i64,
    pub other_id: i64,
    pub other_name: String,
    pub order_public_id: Option<String>,
    pub unread: i64,
    pub last_at: String,
}

pub async fn record_sightings(pool: &PgPool, conversation_id: i64) -> Result<(), sqlx::Error> {
    // Present each participant's current key to the other (idempotent).
    let parts: Vec<(i64,)> = sqlx::query_as(
        "SELECT account_id FROM conversation_participants WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .fetch_all(pool)
    .await?;
    for (owner,) in &parts {
        if let Some((fpr, _cert, _v)) = crate::keys::current_key(pool, *owner).await? {
            // OpenPGP key ID = low 64 bits of the fingerprint (last 16 hex
            // chars) — the same derivation the locked blind_stage3 suite's
            // key_id_of() uses. Sightings go through the single canonical
            // writer (migration 0006 repair, Option A).
            let key_id = &fpr[fpr.len() - 16..];
            for (viewer,) in &parts {
                if viewer != owner {
                    crate::keys::record_key_sighting(
                        pool,
                        conversation_id,
                        *owner,
                        &fpr,
                        key_id,
                        *viewer,
                    )
                    .await?;
                }
            }
        }
    }
    Ok(())
}

pub async fn find_or_create_for_order(pool: &PgPool, order_id: i64, buyer_id: i64, seller_id: i64) -> Result<i64, sqlx::Error> {
    if let Some((id,)) = sqlx::query_as::<_, (i64,)>(
        "SELECT id FROM conversations WHERE order_id = $1",
    )
    .bind(order_id)
    .fetch_optional(pool)
    .await?
    {
        return Ok(id);
    }
    create(pool, Some(order_id), buyer_id, seller_id).await
}

pub async fn find_or_create_direct(pool: &PgPool, a: i64, b: i64) -> Result<i64, sqlx::Error> {
    let found: Option<(i64,)> = sqlx::query_as(
        "SELECT c.id FROM conversations c
         JOIN conversation_participants p1 ON p1.conversation_id = c.id AND p1.account_id = $1
         JOIN conversation_participants p2 ON p2.conversation_id = c.id AND p2.account_id = $2
         WHERE c.order_id IS NULL",
    )
    .bind(a)
    .bind(b)
    .fetch_optional(pool)
    .await?;
    if let Some((id,)) = found {
        return Ok(id);
    }
    create(pool, None, a, b).await
}

async fn create(pool: &PgPool, order_id: Option<i64>, a: i64, b: i64) -> Result<i64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO conversations (public_id, order_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(crate::db::public_id("conv_"))
    .bind(order_id)
    .fetch_one(&mut *tx)
    .await?;
    for p in [a, b] {
        sqlx::query("INSERT INTO conversation_participants (conversation_id, account_id) VALUES ($1, $2)")
            .bind(id)
            .bind(p)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    let _ = record_sightings(pool, id).await;
    Ok(id)
}

pub async fn is_participant(pool: &PgPool, conversation_id: i64, account_id: i64) -> Result<bool, sqlx::Error> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conversation_participants WHERE conversation_id = $1 AND account_id = $2",
    )
    .bind(conversation_id)
    .bind(account_id)
    .fetch_one(pool)
    .await?;
    Ok(n == 1)
}

pub async fn other_participant(pool: &PgPool, conversation_id: i64, account_id: i64) -> Result<Option<(i64, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.id, a.username FROM conversation_participants cp
         JOIN accounts a ON a.id = cp.account_id
         WHERE cp.conversation_id = $1 AND cp.account_id <> $2",
    )
    .bind(conversation_id)
    .bind(account_id)
    .fetch_optional(pool)
    .await
}

pub async fn list_for(pool: &PgPool, account_id: i64) -> Result<Vec<Conversation>, sqlx::Error> {
    let rows: Vec<(i64, i64, String, Option<String>, i64, String)> = sqlx::query_as(
        "SELECT c.id, other.id, other.username, o.public_id,
                (SELECT COUNT(*) FROM notifications n
                  WHERE n.account_id = $1 AND n.event_type = 'message_received'
                    AND n.object_ref = c.id::text AND n.read_at IS NULL),
                to_char(c.created_at, 'YYYY-MM-DD')
         FROM conversations c
         JOIN conversation_participants me ON me.conversation_id = c.id AND me.account_id = $1
         JOIN conversation_participants op ON op.conversation_id = c.id AND op.account_id <> $1
         JOIN accounts other ON other.id = op.account_id
         LEFT JOIN orders o ON o.id = c.order_id
         ORDER BY c.created_at DESC",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| Conversation {
            id: r.0,
            other_id: r.1,
            other_name: r.2,
            order_public_id: r.3,
            unread: r.4,
            last_at: r.5,
        })
        .collect())
}

/// Metadata only — ciphertext is never loaded for list rendering (§14:
/// ciphertext is never rendered inline; participants download it).
pub async fn messages_of(pool: &PgPool, conversation_id: i64) -> Result<Vec<(i64, i64, i32, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, sender_id, length, to_char(received_at, 'YYYY-MM-DD HH24:MI')
         FROM encrypted_messages WHERE conversation_id = $1 ORDER BY received_at",
    )
    .bind(conversation_id)
    .fetch_all(pool)
    .await
}

pub fn blob_dir() -> std::path::PathBuf {
    std::env::var("BLOB_DIR").map(Into::into).unwrap_or_else(|_| "blobs".into())
}

pub async fn message_blob(pool: &PgPool, conversation_id: i64, message_id: i64) -> Option<Vec<u8>> {
    let (ref_,): (String,) = sqlx::query_as(
        "SELECT blob_ref FROM encrypted_messages WHERE conversation_id = $1 AND id = $2",
    )
    .bind(conversation_id)
    .bind(message_id)
    .fetch_optional(pool)
    .await
    .ok()??;
    if !ref_.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    tokio::fs::read(blob_dir().join(format!("{ref_}.asc"))).await.ok()
}

pub async fn mark_read(pool: &PgPool, conversation_id: i64, reader_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE notifications SET read_at = now()
         WHERE account_id = $2 AND event_type = 'message_received'
           AND object_ref = $1::text AND read_at IS NULL",
    )
    .bind(conversation_id)
    .bind(reader_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// The recipient's retired keys the sender was shown in this conversation:
/// sightings of now-retired keys, plus keys whose validity interval
/// overlaps the conversation's start (they were current when it began).
async fn retired_shown(pool: &PgPool, conversation_id: i64, recipient_id: i64) -> Result<Vec<KeyRef>, sqlx::Error> {
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT DISTINCT ik.certificate FROM identity_keys ik
         WHERE ik.account_id = $2 AND ik.status = 'retired' AND (
            EXISTS (SELECT 1 FROM conversation_key_sightings s
                    WHERE s.conversation_id = $1 AND s.fingerprint = ik.fingerprint)
            OR ik.retired_at > (SELECT created_at FROM conversations WHERE id = $1)
         )",
    )
    .bind(conversation_id)
    .bind(recipient_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        // Retired-key recognition stays UNFILTERED (MM3): a retired
        // certificate may since have expired, or had a subkey revoked
        // by a refresh, and a message encrypted to it must still be
        // recognised as RecipientKeyRetired, not reclassified.
        .filter_map(|(cert,)| KeyRef::from_cert_unfiltered(cert))
        .collect())
}

/// Messaging abuse bounds (messaging audit MM4). Retention expires
/// message blobs at 90 days, but volume must also be bounded at write
/// time: without limits, any account could fill the disk with 64 KiB
/// ciphertexts. The checks are aggregate-before-insert, so a
/// determined racer can overshoot by a small factor — acceptable for
/// a disk-exhaustion bound. The per-account request throttle (wired
/// in the account-security batch) is a separate, coarser bound.
pub const MSG_RATE_PER_MINUTE: i64 = 60;
pub const MSG_DAILY_BUDGET_BYTES: i64 = 16 * 1024 * 1024;
pub const MSG_CONVERSATION_MAX_MESSAGES: i64 = 1_000;
pub const MSG_CONVERSATION_MAX_BYTES: i64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum SendError {
    NoKey,            // sender or recipient has no registered key
    Envelope(EnvelopeError),
    TooLarge,
    /// The recipient has blocked the sender's direct messages (MM4).
    Blocked,
    /// More than MSG_RATE_PER_MINUTE sends in the last minute (MM4).
    RateLimited,
    /// The sender's rolling 24-hour byte budget is spent (MM4).
    BudgetExceeded,
    /// The conversation reached its message/byte cap (MM4).
    ConversationFull,
    Db,
}

pub fn envelope_message(e: &EnvelopeError, key_id: Option<String>) -> String {
    match e {
        EnvelopeError::Empty => "The message was empty.".into(),
        EnvelopeError::NotEncrypted => {
            "That was not an encrypted message. Encrypt to both keys with your OpenPGP client and paste the armored result.".into()
        }
        EnvelopeError::Malformed => "The message could not be parsed as an OpenPGP message.".into(),
        EnvelopeError::UnsupportedPacket => {
            "The message uses packet forms this marketplace does not accept (see the encryption guide).".into()
        }
        EnvelopeError::HiddenRecipient => "Hidden recipients are not accepted: encrypt to the named keys.".into(),
        EnvelopeError::RecipientKeyRetired => {
            "This conversation's recipient rotated their key. Download their current key and re-encrypt.".into()
        }
        EnvelopeError::WrongRecipient => {
            "The message is not encrypted to the recipient's current key.".into()
        }
        EnvelopeError::ExtraRecipient => format!(
            "The message is encrypted to an extra key (ID {}). Messages may be encrypted only to the two participants.",
            key_id.unwrap_or_default()
        ),
    }
}

pub async fn send_message(
    pool: &PgPool,
    conversation_id: i64,
    sender_id: i64,
    ciphertext: &[u8],
) -> Result<(), SendError> {
    if ciphertext.len() > envelope::MAX_MESSAGE_BYTES {
        return Err(SendError::TooLarge);
    }
    let Some((recipient_id, _name)) = other_participant(pool, conversation_id, sender_id)
        .await
        .map_err(|_| SendError::Db)?
    else {
        return Err(SendError::Db);
    };
    let order_id: Option<i64> =
        sqlx::query_scalar("SELECT order_id FROM conversations WHERE id = $1")
            .bind(conversation_id)
            .fetch_one(pool)
            .await
            .map_err(|_| SendError::Db)?;
    if order_id.is_none() {
        // Direct conversations can be blocked (MM4); order
        // conversations never are — trading counterparties must stay
        // reachable for the life of the order.
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM conversation_blocks \
             WHERE blocker_id = $1 AND blocked_id = $2)",
        )
        .bind(recipient_id)
        .bind(sender_id)
        .fetch_one(pool)
        .await
        .map_err(|_| SendError::Db)?;
        if blocked {
            return Err(SendError::Blocked);
        }
    }
    // Abuse bounds (MM4): per-sender rate and rolling daily byte
    // budget, then the per-conversation volume cap.
    let (sent_last_minute, sent_last_day): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM encrypted_messages \
                  WHERE sender_id = $1 AND received_at > now() - interval '1 minute'), \
                (SELECT COALESCE(SUM(length), 0) FROM encrypted_messages \
                  WHERE sender_id = $1 AND received_at > now() - interval '24 hours')",
    )
    .bind(sender_id)
    .fetch_one(pool)
    .await
    .map_err(|_| SendError::Db)?;
    if sent_last_minute >= MSG_RATE_PER_MINUTE {
        return Err(SendError::RateLimited);
    }
    if sent_last_day + ciphertext.len() as i64 > MSG_DAILY_BUDGET_BYTES {
        return Err(SendError::BudgetExceeded);
    }
    let (conv_count, conv_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(length), 0) FROM encrypted_messages \
         WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .map_err(|_| SendError::Db)?;
    if conv_count >= MSG_CONVERSATION_MAX_MESSAGES
        || conv_bytes + ciphertext.len() as i64 > MSG_CONVERSATION_MAX_BYTES
    {
        return Err(SendError::ConversationFull);
    }
    let sender_key = crate::keys::current_key(pool, sender_id).await.map_err(|_| SendError::Db)?.ok_or(SendError::NoKey)?;
    let recipient_key = crate::keys::current_key(pool, recipient_id).await.map_err(|_| SendError::Db)?.ok_or(SendError::NoKey)?;
    let ctx = EnvelopeContext {
        sender: KeyRef::from_cert(&sender_key.1).ok_or(SendError::Db)?,
        recipient: KeyRef::from_cert(&recipient_key.1).ok_or(SendError::Db)?,
        recipient_retired_shown: retired_shown(pool, conversation_id, recipient_id).await.map_err(|_| SendError::Db)?,
    };
    if let Err(e) = envelope::validate_envelope(ciphertext, &ctx) {
        return Err(SendError::Envelope(e));
    }
    // Store the payload as a blob file; the row keeps minimal metadata
    // only (§14/§16). Expiry at insert: 90 days (inquiry default, §20);
    // the retention job refines order-conversation expiry at Stage 10.
    let dir = blob_dir();
    tokio::fs::create_dir_all(&dir).await.map_err(|_| SendError::Db)?;
    let blob_ref = crate::sessions::new_token();
    tokio::fs::write(dir.join(format!("{blob_ref}.asc")), ciphertext)
        .await
        .map_err(|_| SendError::Db)?;
    let recipient_key_id = {
        let f = recipient_key.0.clone();
        f[f.len().saturating_sub(16)..].to_string()
    };
    sqlx::query(
        "INSERT INTO encrypted_messages
            (conversation_id, sender_id, recipient_id, recipient_key_id, blob_ref, length, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, now() + interval '90 days')",
    )
    .bind(conversation_id)
    .bind(sender_id)
    .bind(recipient_id)
    .bind(recipient_key_id)
    .bind(blob_ref)
    .bind(ciphertext.len() as i32)
    .execute(pool)
    .await
    .map_err(|_| SendError::Db)?;
    let _ = crate::orders::notify(pool, recipient_id, "message_received", &conversation_id.to_string()).await;
    Ok(())
}

/// ML1: the fingerprint pinned for `other_id` by the order behind an
/// order conversation. Seller side: the order's `seller_fpr_pinned`.
/// Buyer side: the buyer's key whose validity interval covers the
/// order's creation — the same rule disputes use to find the buyer's
/// pinned certificate. Display and warning logic compare this against
/// the CURRENT key; nothing here consults key_rotations.
pub async fn order_pinned_fingerprint(
    pool: &PgPool,
    order_id: i64,
    other_id: i64,
) -> Option<String> {
    let order = crate::orders::order_by_internal_id(pool, order_id).await?;
    if other_id == order.seller_id {
        return Some(order.seller_fpr_pinned.clone());
    }
    if other_id == order.buyer_id {
        return sqlx::query_scalar(
            "SELECT fingerprint FROM identity_keys
             WHERE account_id = $1 AND created_at <= $2
               AND (retired_at IS NULL OR retired_at > $2)
             ORDER BY version DESC LIMIT 1",
        )
        .bind(order.buyer_id)
        .bind(order.created_at)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
    }
    None
}

// ---------------------------------------------------------------------------
// Direct-conversation blocks (MM4, migration 0012)
// ---------------------------------------------------------------------------

/// Record that `blocker` refuses direct conversations with
/// `blocked`. Idempotent. Blocks govern DIRECT conversations only:
/// order conversations stay reachable regardless (send_message
/// never consults this table for them).
pub async fn block_account(
    pool: &PgPool,
    blocker_id: i64,
    blocked_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO conversation_blocks (blocker_id, blocked_id) VALUES ($1, $2)
         ON CONFLICT (blocker_id, blocked_id) DO NOTHING",
    )
    .bind(blocker_id)
    .bind(blocked_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn unblock_account(
    pool: &PgPool,
    blocker_id: i64,
    blocked_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM conversation_blocks WHERE blocker_id = $1 AND blocked_id = $2")
        .bind(blocker_id)
        .bind(blocked_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// True when a block exists in either direction between the two
/// accounts (used when OPENING a direct conversation: a block by
/// either side closes the door both ways).
pub async fn block_exists_either_way(
    pool: &PgPool,
    a: i64,
    b: i64,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM conversation_blocks \
         WHERE (blocker_id = $1 AND blocked_id = $2) \
            OR (blocker_id = $2 AND blocked_id = $1))",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
}

/// The accounts `account_id` has blocked: (account_id, public_id,
/// username), newest first.
pub async fn blocked_accounts(
    pool: &PgPool,
    account_id: i64,
) -> Result<Vec<(i64, String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.id, a.public_id, a.username FROM conversation_blocks b
         JOIN accounts a ON a.id = b.blocked_id
         WHERE b.blocker_id = $1 ORDER BY b.created_at DESC",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
}
