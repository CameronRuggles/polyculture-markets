//! Moderation (spec §13 + owner ruling 2026-10-16).
//!
//! There is NO ban and NO suspension: repeat accounts are unprovable,
//! so exclusion is not a tool this marketplace pretends to have. The
//! account-level action is CLOSURE — it ends the identity, which is
//! the real asset here (PGP key history, account age, reputation
//! facts):
//!
//! - the account cannot log in (it no longer exists as an actor; this
//!   is a property of closure, not an exclusion claim — nothing stops
//!   a person registering again, and no page claims otherwise);
//! - its sessions are revoked, its published listings are unpublished
//!   (moved to `paused`), its unused payment-pool entries are retired;
//! - its profile is marked "account closed" with the date;
//! - its reputation stops accruing (facts for orders terminating
//!   after closure are not produced — see reputation.rs);
//! - order and review HISTORY IS RETAINED and stays visible to
//!   counterparties; counterparties with open orders are notified.
//!
//! Self-service closure runs the exact same code path with the
//! account itself as actor. Moderators can also warn an account and
//! remove/restore listings. Every moderator action requires a current
//! TOTP code (step-up per action, amendments §7) and is written to
//! `moderation_actions`. Moderators have no power over funds, ever,
//! and no interface to anyone's conversations.

use crate::keyfile::KeyFile;
use sqlx::PgPool;
use time::OffsetDateTime;

#[derive(Debug, PartialEq, Eq)]
pub enum ModError {
    NotFound,
    Forbidden,
    TotpRequired,
    TotpInvalid,
    BadInput,
    AlreadyClosed,
    Db,
}

// -- TOTP step-up ---------------------------------------------------------------

/// True when the account has an active TOTP enrollment.
pub async fn totp_enrolled(pool: &PgPool, account_id: i64) -> Result<bool, ModError> {
    let at: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT totp_enabled_at FROM accounts WHERE id = $1")
            .bind(account_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| ModError::Db)?
            .flatten();
    Ok(at.is_some())
}

/// Gate for every moderator action: enrolled TOTP + a currently valid
/// code. No enrollment → TotpRequired (the action is refused, never
/// silently allowed).
pub async fn require_totp(
    pool: &PgPool,
    kf: &KeyFile,
    account_id: i64,
    presented_code: &str,
) -> Result<(), ModError> {
    let row: Option<(Option<Vec<u8>>, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT totp_secret_enc, totp_enabled_at FROM accounts WHERE id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ModError::Db)?;
    let Some((secret_enc, enabled_at)) = row else {
        return Err(ModError::NotFound);
    };
    let (Some(enc), Some(_)) = (secret_enc, enabled_at) else {
        return Err(ModError::TotpRequired);
    };
    let secret = kf.decrypt(&enc).ok_or(ModError::Db)?;
    let now = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
    if crate::totp::verify(&secret, presented_code, now) {
        Ok(())
    } else {
        Err(ModError::TotpInvalid)
    }
}

// -- TOTP enrollment (any account; required for moderators) ------------------------

/// Begin (or restart) enrollment: generate a secret, keep it as
/// pending (encrypted), and return the base32 for authenticator setup.
/// The pending secret activates only when a code from it verifies.
pub async fn totp_begin(pool: &PgPool, kf: &KeyFile, account_id: i64) -> Result<String, ModError> {
    let secret = crate::totp::generate_secret();
    let enc = kf.encrypt(&secret);
    sqlx::query("UPDATE accounts SET totp_pending_enc = $2 WHERE id = $1")
        .bind(account_id)
        .bind(&enc)
        .execute(pool)
        .await
        .map_err(|_| ModError::Db)?;
    Ok(crate::totp::base32_encode(&secret))
}

/// Confirm enrollment with a code from the pending secret.
pub async fn totp_confirm(pool: &PgPool, kf: &KeyFile, account_id: i64, code: &str) -> Result<(), ModError> {
    let enc: Option<Vec<u8>> = sqlx::query_scalar("SELECT totp_pending_enc FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| ModError::Db)?
        .flatten();
    let Some(enc) = enc else {
        return Err(ModError::BadInput);
    };
    let secret = kf.decrypt(&enc).ok_or(ModError::Db)?;
    let now = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
    if !crate::totp::verify(&secret, code, now) {
        return Err(ModError::TotpInvalid);
    }
    sqlx::query(
        "UPDATE accounts SET totp_secret_enc = totp_pending_enc, totp_pending_enc = NULL,
                totp_enabled_at = now()
          WHERE id = $1",
    )
    .bind(account_id)
    .execute(pool)
    .await
    .map_err(|_| ModError::Db)?;
    Ok(())
}

/// Disable TOTP (requires a currently valid code). A moderator who
/// disables loses the ability to take moderator actions until they
/// re-enroll — there is no bypass.
pub async fn totp_disable(pool: &PgPool, kf: &KeyFile, account_id: i64, code: &str) -> Result<(), ModError> {
    require_totp(pool, kf, account_id, code).await?;
    sqlx::query(
        "UPDATE accounts SET totp_secret_enc = NULL, totp_pending_enc = NULL, totp_enabled_at = NULL
          WHERE id = $1",
    )
    .bind(account_id)
    .execute(pool)
    .await
    .map_err(|_| ModError::Db)?;
    Ok(())
}

/// The pending enrollment (base32 + URI) for display on the security
/// page, or None when no enrollment is in progress.
pub async fn totp_pending(pool: &PgPool, kf: &KeyFile, account_id: i64) -> Result<Option<String>, ModError> {
    let enc: Option<Vec<u8>> = sqlx::query_scalar("SELECT totp_pending_enc FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| ModError::Db)?
        .flatten();
    let Some(enc) = enc else {
        return Ok(None);
    };
    let secret = kf.decrypt(&enc).ok_or(ModError::Db)?;
    Ok(Some(crate::totp::base32_encode(&secret)))
}

// -- reports -----------------------------------------------------------------------

pub const REPORT_CATEGORIES: [&str; 4] = ["illegal-goods", "fraud", "abuse", "other"];

#[derive(Debug, Clone)]
pub struct Report {
    pub id: i64,
    pub reporter_id: i64,
    pub reporter_username: String,
    pub target: String,
    pub category: String,
    pub reason: String,
    pub state: String,
    pub created_at: String,
}

/// File a report on a listing, a profile, or a review (identified by
/// its order's public id). The target must exist; the stored target is
/// a typed reference (`listing:<public_id>`, `profile:<public_id>`,
/// `review:<order_public_id>`), not free text.
pub async fn create_report(
    pool: &PgPool,
    reporter_id: i64,
    target_kind: &str,
    target_id: &str,
    category: &str,
    reason: &str,
) -> Result<i64, ModError> {
    if !REPORT_CATEGORIES.contains(&category) {
        return Err(ModError::BadInput);
    }
    let reason = reason.trim();
    if reason.is_empty() || reason.chars().count() > 2000 {
        return Err(ModError::BadInput);
    }
    let exists: bool = match target_kind {
        "listing" => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM listings WHERE public_id = $1)")
            .bind(target_id)
            .fetch_one(pool)
            .await
            .map_err(|_| ModError::Db)?,
        "profile" => sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE public_id = $1)")
            .bind(target_id)
            .fetch_one(pool)
            .await
            .map_err(|_| ModError::Db)?,
        "review" => sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM reviews r JOIN orders o ON o.id = r.order_id WHERE o.public_id = $1)",
        )
        .bind(target_id)
        .fetch_one(pool)
        .await
        .map_err(|_| ModError::Db)?,
        _ => return Err(ModError::BadInput),
    };
    if !exists {
        return Err(ModError::NotFound);
    }
    let target = format!("{target_kind}:{target_id}");
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO reports (reporter_id, target, category, reason) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(reporter_id)
    .bind(&target)
    .bind(category)
    .bind(reason)
    .fetch_one(pool)
    .await
    .map_err(|_| ModError::Db)?;
    Ok(id)
}

pub async fn open_reports(pool: &PgPool) -> Result<Vec<Report>, ModError> {
    let rows: Vec<(i64, i64, String, String, String, String, String, OffsetDateTime)> =
        sqlx::query_as(
            "SELECT r.id, r.reporter_id, a.username, r.target, r.category, r.reason, r.state, r.created_at
               FROM reports r JOIN accounts a ON a.id = r.reporter_id
              WHERE r.state = 'open' ORDER BY r.created_at",
        )
        .fetch_all(pool)
        .await
        .map_err(|_| ModError::Db)?;
    let f = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    Ok(rows
        .into_iter()
        .map(|(id, rid, username, target, category, reason, state, created)| Report {
            id,
            reporter_id: rid,
            reporter_username: username,
            target,
            category,
            reason,
            state,
            created_at: created.format(&f).unwrap_or_default(),
        })
        .collect())
}

pub async fn report_action(
    pool: &PgPool,
    report_id: i64,
    moderator_id: i64,
    action: &str,
) -> Result<(), ModError> {
    let new_state = match action {
        "dismiss" => "dismissed",
        "resolve" => "resolved",
        _ => return Err(ModError::BadInput),
    };
    let upd = sqlx::query("UPDATE reports SET state = $2 WHERE id = $1 AND state = 'open'")
        .bind(report_id)
        .bind(new_state)
        .execute(pool)
        .await
        .map_err(|_| ModError::Db)?;
    if upd.rows_affected() != 1 {
        return Err(ModError::NotFound);
    }
    log_action(pool, moderator_id, None, None, &format!("report-{action}"), "")
        .await
        .map_err(|_| ModError::Db)?;
    Ok(())
}

// -- account actions: warn + close ---------------------------------------------------

async fn log_action(
    pool: &PgPool,
    actor_id: i64,
    target_account: Option<i64>,
    target_listing: Option<i64>,
    action: &str,
    reason: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO moderation_actions (actor_id, target_account_id, target_listing_id, action, reason)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(actor_id)
    .bind(target_account)
    .bind(target_listing)
    .bind(action)
    .bind(reason)
    .execute(pool)
    .await?;
    Ok(())
}

/// Warn an account: the warning is timestamped, audited, and shown to
/// the account (account page + inbox). A warned account functions
/// normally — warning is a record and a signal, not a restriction.
pub async fn warn_account(
    pool: &PgPool,
    target_id: i64,
    moderator_id: i64,
    reason: &str,
) -> Result<(), ModError> {
    let reason = reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 {
        return Err(ModError::BadInput);
    }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE id = $1)")
        .bind(target_id)
        .fetch_one(pool)
        .await
        .map_err(|_| ModError::Db)?;
    if !exists {
        return Err(ModError::NotFound);
    }
    sqlx::query("UPDATE accounts SET warned_at = now() WHERE id = $1")
        .bind(target_id)
        .execute(pool)
        .await
        .map_err(|_| ModError::Db)?;
    log_action(pool, moderator_id, Some(target_id), None, "warn", reason)
        .await
        .map_err(|_| ModError::Db)?;
    let short: String = reason.chars().take(200).collect();
    let _ = crate::orders::notify(pool, target_id, "moderator_warning", &short).await;
    Ok(())
}

/// CLOSE an account — the one account-level enforcement (owner ruling
/// 2026-10-16). Used identically by moderators and by self-service
/// closure (`actor_id == target_id`). Effects, in one transaction:
/// status → closed (+ timestamp), sessions revoked, published
/// listings unpublished (→ paused), unused pool entries retired, and
/// every counterparty with a non-terminal order notified. History is
/// never touched. Closing an already-closed account is AlreadyClosed.
pub async fn close_account(
    pool: &PgPool,
    target_id: i64,
    actor_id: i64,
    reason: &str,
) -> Result<(), ModError> {
    let mut tx = pool.begin().await.map_err(|_| ModError::Db)?;
    let status: Option<String> = sqlx::query_scalar("SELECT status FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(target_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ModError::Db)?;
    let Some(status) = status else {
        return Err(ModError::NotFound);
    };
    if status == "closed" {
        return Err(ModError::AlreadyClosed);
    }
    sqlx::query("UPDATE accounts SET status = 'closed', closed_at = now() WHERE id = $1")
        .bind(target_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ModError::Db)?;
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE account_id = $1 AND revoked_at IS NULL")
        .bind(target_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ModError::Db)?;
    sqlx::query("UPDATE listings SET status = 'paused' WHERE seller_id = $1 AND status = 'published'")
        .bind(target_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ModError::Db)?;
    sqlx::query("UPDATE payment_pool_entries SET state = 'retired' WHERE seller_id = $1 AND state = 'unused'")
        .bind(target_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ModError::Db)?;
    let action = if actor_id == target_id { "close-account-self" } else { "close-account" };
    sqlx::query(
        "INSERT INTO moderation_actions (actor_id, target_account_id, action, reason) VALUES ($1, $2, $3, $4)",
    )
    .bind(actor_id)
    .bind(target_id)
    .bind(action)
    .bind(reason)
    .execute(&mut *tx)
    .await
    .map_err(|_| ModError::Db)?;
    tx.commit().await.map_err(|_| ModError::Db)?;
    // Notify counterparties holding open (non-terminal) orders.
    let target_pub = crate::db::public_id_of(pool, target_id)
        .await
        .map_err(|_| ModError::Db)?
        .unwrap_or_default();
    let counterparties: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT CASE WHEN buyer_id = $1 THEN seller_id ELSE buyer_id END
           FROM orders
          WHERE (buyer_id = $1 OR seller_id = $1)
            AND state NOT IN ('Completed', 'Resolved', 'Cancelled', 'Declined')",
    )
    .bind(target_id)
    .fetch_all(pool)
    .await
    .map_err(|_| ModError::Db)?;
    for cp in counterparties {
        let _ = crate::orders::notify(pool, cp, "account_closed", &target_pub).await;
    }
    Ok(())
}

// -- listing actions -------------------------------------------------------------------

/// Remove a listing (it disappears from the catalogue; the seller is
/// notified). Restore republishes it.
pub async fn set_listing_removed(
    pool: &PgPool,
    listing_public_id: &str,
    moderator_id: i64,
    remove: bool,
) -> Result<(), ModError> {
    let row: Option<(i64, i64, String)> = sqlx::query_as(
        "SELECT id, seller_id, status FROM listings WHERE public_id = $1",
    )
    .bind(listing_public_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ModError::Db)?;
    let Some((listing_id, seller_id, status)) = row else {
        return Err(ModError::NotFound);
    };
    let (new_status, action) = if remove {
        if status == "removed" {
            return Err(ModError::BadInput);
        }
        ("removed", "remove-listing")
    } else {
        if status != "removed" {
            return Err(ModError::BadInput);
        }
        ("published", "restore-listing")
    };
    sqlx::query("UPDATE listings SET status = $2 WHERE id = $1")
        .bind(listing_id)
        .bind(new_status)
        .execute(pool)
        .await
        .map_err(|_| ModError::Db)?;
    log_action(pool, moderator_id, Some(seller_id), Some(listing_id), action, "")
        .await
        .map_err(|_| ModError::Db)?;
    let event = if remove { "listing_removed" } else { "listing_restored" };
    let _ = crate::orders::notify(pool, seller_id, event, listing_public_id).await;
    Ok(())
}

// -- queue support ------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AccountHit {
    pub id: i64,
    pub public_id: String,
    pub username: String,
    pub role: String,
    pub status: String,
    pub warned: bool,
}

pub async fn search_accounts(pool: &PgPool, q: &str) -> Result<Vec<AccountHit>, ModError> {
    let rows: Vec<(i64, String, String, String, String, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT id, public_id, username, role, status, warned_at FROM accounts
          WHERE username ILIKE $1 ORDER BY username LIMIT 25",
    )
    .bind(format!("%{}%", q.trim()))
    .fetch_all(pool)
    .await
    .map_err(|_| ModError::Db)?;
    Ok(rows
        .into_iter()
        .map(|(id, public_id, username, role, status, warned_at)| AccountHit {
            id,
            public_id,
            username,
            role,
            status,
            warned: warned_at.is_some(),
        })
        .collect())
}

/// Account lifecycle facts the web layer needs (login gate, profile
/// banner, account page).
pub async fn account_status(pool: &PgPool, account_id: i64) -> Result<(String, Option<OffsetDateTime>, Option<OffsetDateTime>), ModError> {
    let row: Option<(String, Option<OffsetDateTime>, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT status, closed_at, warned_at FROM accounts WHERE id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ModError::Db)?;
    row.ok_or(ModError::NotFound)
}
