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
    /// The code belongs to a time step that was already accepted for
    /// this account (audit AL3: codes are single-use per window).
    TotpReplayed,
    /// Too many failed codes: code verification is locked until the
    /// cool-down passes (audit AH1).
    TotpLocked,
    /// Enrollment confirmation attempted while TOTP is already on
    /// (audit AL3: confirm must not replace an active secret).
    TotpAlreadyActive,
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

/// Failed verifications at any TOTP gate that lock code checking
/// for the account (audit AH1: codes could be guessed freely).
pub const TOTP_FAILURE_LOCK_THRESHOLD: i32 = 10;
/// How long code checking stays locked once the threshold trips.
pub const TOTP_LOCK_MINUTES: i64 = 15;

/// The one TOTP verification gate (audit AH1 + AL3, 2026-10-18),
/// shared by moderator action step-up, the disclosure unlock, and
/// TOTP at login. On top of a plain code check it enforces:
///
/// - failure counting: a wrong code increments the account's
///   consecutive-failure counter; at TOTP_FAILURE_LOCK_THRESHOLD the
///   account's code checking locks for TOTP_LOCK_MINUTES and the
///   account gets ONE inbox notice per lockout episode;
/// - lockout: while locked, EVERY code — including a correct one —
///   is refused with TotpLocked, and attempts do not extend the lock;
/// - replay protection: the matched code's time step is recorded,
///   and a code from that step (or an older one) is never accepted
///   again for this account.
///
/// A successful verification clears the failure counter and any
/// expired lock. Replays are refused WITHOUT counting as failures (a
/// code observed once is useless to an attacker either way, and the
/// legitimate holder racing their own code must not lock themselves
/// out).
pub async fn verify_totp_gate(
    pool: &PgPool,
    kf: &KeyFile,
    account_id: i64,
    presented_code: &str,
) -> Result<(), ModError> {
    let row: Option<(
        Option<Vec<u8>>,
        Option<OffsetDateTime>,
        Option<i64>,
        i32,
        Option<OffsetDateTime>,
    )> = sqlx::query_as(
        "SELECT totp_secret_enc, totp_enabled_at, totp_last_step, totp_fail_count,
                totp_locked_until
           FROM accounts WHERE id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ModError::Db)?;
    let Some((secret_enc, enabled_at, last_step, fail_count, locked_until)) = row else {
        return Err(ModError::NotFound);
    };
    let (Some(enc), Some(_)) = (secret_enc, enabled_at) else {
        return Err(ModError::TotpRequired);
    };
    let now = OffsetDateTime::now_utc();
    if let Some(until) = locked_until {
        if until > now {
            return Err(ModError::TotpLocked);
        }
        // The lock has expired: close out the episode's bookkeeping so
        // a FUTURE lockout notifies again (one notice per episode —
        // without this, a second episode with no successful code in
        // between would silently skip its notice).
        let _ = sqlx::query(
            "UPDATE accounts SET totp_locked_until = NULL, totp_lock_notified_at = NULL
              WHERE id = $1",
        )
        .bind(account_id)
        .execute(pool)
        .await;
    }
    let secret = kf.decrypt(&enc).ok_or(ModError::Db)?;
    let now_secs = now.unix_timestamp().max(0) as u64;
    match crate::totp::verify_step(&secret, presented_code, now_secs) {
        Some(step) => {
            if let Some(last) = last_step {
                if (step as i64) <= last {
                    return Err(ModError::TotpReplayed);
                }
            }
            sqlx::query(
                "UPDATE accounts SET totp_last_step = $2, totp_fail_count = 0,
                        totp_locked_until = NULL, totp_lock_notified_at = NULL
                  WHERE id = $1",
            )
            .bind(account_id)
            .bind(step as i64)
            .execute(pool)
            .await
            .map_err(|_| ModError::Db)?;
            Ok(())
        }
        None => {
            let new_count = fail_count + 1;
            if new_count >= TOTP_FAILURE_LOCK_THRESHOLD {
                // Trip the lock; reset the counter so the NEXT
                // episode needs a fresh run of failures after the
                // cool-down. Notify once per episode.
                sqlx::query(
                    "UPDATE accounts SET totp_fail_count = 0,
                            totp_locked_until = now() + make_interval(mins => $2)
                      WHERE id = $1",
                )
                .bind(account_id)
                .bind(TOTP_LOCK_MINUTES as i32)
                .execute(pool)
                .await
                .map_err(|_| ModError::Db)?;
                let notified: Option<OffsetDateTime> =
                    sqlx::query_scalar("SELECT totp_lock_notified_at FROM accounts WHERE id = $1")
                        .bind(account_id)
                        .fetch_optional(pool)
                        .await
                        .map_err(|_| ModError::Db)?
                        .flatten();
                if notified.is_none() {
                    let _ = crate::orders::notify(
                        pool,
                        account_id,
                        "totp_locked",
                        "code checking locked for 15 minutes after 10 failed codes",
                    )
                    .await;
                    let _ = sqlx::query(
                        "UPDATE accounts SET totp_lock_notified_at = now() WHERE id = $1",
                    )
                    .bind(account_id)
                    .execute(pool)
                    .await;
                }
            } else {
                sqlx::query("UPDATE accounts SET totp_fail_count = $2 WHERE id = $1")
                    .bind(account_id)
                    .bind(new_count)
                    .execute(pool)
                    .await
                    .map_err(|_| ModError::Db)?;
            }
            Err(ModError::TotpInvalid)
        }
    }
}

/// Gate for every moderator action: enrolled TOTP + a currently valid
/// code. No enrollment → TotpRequired (the action is refused, never
/// silently allowed). Verification goes through `verify_totp_gate`
/// (counting, lockout, replay protection).
pub async fn require_totp(
    pool: &PgPool,
    kf: &KeyFile,
    account_id: i64,
    presented_code: &str,
) -> Result<(), ModError> {
    verify_totp_gate(pool, kf, account_id, presented_code).await
}

/// How long a disclosure unlock step-up lasts for one session.
pub const DISCLOSURE_UNLOCK_MINUTES: i64 = 10;

/// Record a step-up grant (purpose-bound, session-bound): the caller
/// has just passed `verify_totp_gate`; the grant lets that session
/// render dispute disclosures for a few minutes without re-entering
/// a code on every page load. The raw session token is never stored —
/// only its SHA-256, as everywhere else (sessions.rs).
pub async fn grant_stepup(
    pool: &PgPool,
    token_hash: &[u8],
    account_id: i64,
    purpose: &str,
) -> Result<(), ModError> {
    sqlx::query(
        "INSERT INTO totp_stepup_grants (token_hash, account_id, purpose, expires_at)
         VALUES ($1, $2, $3, now() + make_interval(mins => $4))
         ON CONFLICT (token_hash, purpose)
         DO UPDATE SET account_id = EXCLUDED.account_id, expires_at = EXCLUDED.expires_at",
    )
    .bind(token_hash)
    .bind(account_id)
    .bind(purpose)
    .bind(DISCLOSURE_UNLOCK_MINUTES as i32)
    .execute(pool)
    .await
    .map_err(|_| ModError::Db)?;
    Ok(())
}

/// True while a live step-up grant exists for this session+purpose.
pub async fn stepup_granted(
    pool: &PgPool,
    token_hash: &[u8],
    account_id: i64,
    purpose: &str,
) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM totp_stepup_grants
                        WHERE token_hash = $1 AND account_id = $2 AND purpose = $3
                          AND expires_at > now())",
    )
    .bind(token_hash)
    .bind(account_id)
    .bind(purpose)
    .fetch_one(pool)
    .await
    .unwrap_or(false)
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
///
/// Refused while TOTP is already active (audit AL3): confirming must
/// never silently replace a live secret — the only path off is
/// `totp_disable`, which demands a current code.
///
/// NOTE (locked-suite constraint): confirmation deliberately does
/// NOT record the accepted step in `totp_last_step`. The locked
/// Stage 9 gate suite confirms enrollment with the current code and
/// then presents the SAME code at the step-up gate; consuming the
/// step here would fail that suite. The gate is therefore the first
/// consumer of a step, and everything after enrollment (login,
/// step-up) is replay-protected. Flagged in the fix report for an
/// owner-decision amendment if stricter semantics are wanted.
pub async fn totp_confirm(pool: &PgPool, kf: &KeyFile, account_id: i64, code: &str) -> Result<(), ModError> {
    let row: Option<(Option<Vec<u8>>, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT totp_pending_enc, totp_enabled_at FROM accounts WHERE id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ModError::Db)?;
    let Some((enc, enabled_at)) = row else {
        return Err(ModError::NotFound);
    };
    if enabled_at.is_some() {
        return Err(ModError::TotpAlreadyActive);
    }
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
        "UPDATE accounts SET totp_secret_enc = NULL, totp_pending_enc = NULL, totp_enabled_at = NULL,
                totp_last_step = NULL, totp_fail_count = 0, totp_locked_until = NULL,
                totp_lock_notified_at = NULL
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

/// Act on an auto-review payment flag (tx-proof flow, 2026-10-18):
/// moderators resolve or dismiss flags from the moderation queue.
/// The 'cleared' state is reserved for the automatic clearing that
/// happens when a seller confirms payment (payments.rs).
///
/// CM3: a moderator who is the flagged order's buyer or seller may
/// not decide it — the same no-self-dealing rule as dispute
/// resolution (disputes::resolve).
pub async fn payment_flag_action(
    pool: &PgPool,
    flag_id: i64,
    moderator_id: i64,
    action: &str,
) -> Result<(), ModError> {
    let new_state = match action {
        "dismiss" => "dismissed",
        "resolve" => "resolved",
        _ => return Err(ModError::BadInput),
    };
    let parties: Option<(i64, i64)> = sqlx::query_as(
        "SELECT o.buyer_id, o.seller_id FROM payment_review_flags f
           JOIN orders o ON o.id = f.order_id WHERE f.id = $1",
    )
    .bind(flag_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ModError::Db)?;
    let Some((buyer_id, seller_id)) = parties else {
        return Err(ModError::NotFound);
    };
    if moderator_id == buyer_id || moderator_id == seller_id {
        return Err(ModError::Forbidden);
    }
    let upd = sqlx::query(
        "UPDATE payment_review_flags SET state = $2, closed_at = now() WHERE id = $1 AND state = 'open'",
    )
    .bind(flag_id)
    .bind(new_state)
    .execute(pool)
    .await
    .map_err(|_| ModError::Db)?;
    if upd.rows_affected() != 1 {
        return Err(ModError::NotFound);
    }
    log_action(pool, moderator_id, None, None, &format!("payment-flag-{action}"), "")
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

/// CM4 role protection for the account actions below. Admin
/// accounts are operator-console territory: no web-path action —
/// warn or close, by anyone, including another admin or the admin
/// themself — may touch them. Moderator accounts may only be acted
/// on by an admin. Returns true when the (actor, target) pair is
/// protected. Self-actions on non-admin accounts are not protected
/// here (self-closure is the owner's own act, ruled 2026-10-16).
async fn role_protected(pool: &PgPool, target_id: i64, actor_id: i64) -> Result<bool, ModError> {
    let target_role: Option<String> = sqlx::query_scalar("SELECT role FROM accounts WHERE id = $1")
        .bind(target_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| ModError::Db)?;
    let Some(target_role) = target_role else {
        return Ok(false);
    };
    Ok(match target_role.as_str() {
        "admin" => true,
        "moderator" => {
            if actor_id == target_id {
                false
            } else {
                let actor_role: Option<String> =
                    sqlx::query_scalar("SELECT role FROM accounts WHERE id = $1")
                        .bind(actor_id)
                        .fetch_optional(pool)
                        .await
                        .map_err(|_| ModError::Db)?;
                actor_role.as_deref() != Some("admin")
            }
        }
        _ => false,
    })
}

/// Warn an account: the warning is timestamped, audited, and shown to
/// the account (account page + inbox). A warned account functions
/// normally — warning is a record and a signal, not a restriction.
/// CM4: protected-role targets (see `role_protected`) are refused
/// and the refusal is logged.
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
    if role_protected(pool, target_id, moderator_id).await? {
        log_action(pool, moderator_id, Some(target_id), None, "warn-refused", reason)
            .await
            .map_err(|_| ModError::Db)?;
        return Err(ModError::Forbidden);
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
    // CM4: protected roles are refused before anything else happens
    // — a moderator cannot close another moderator or an admin, and
    // an admin account cannot be closed through this path at all
    // (operator console only). The refusal is rolled back, logged,
    // and returned as Forbidden.
    if role_protected(pool, target_id, actor_id).await? {
        tx.rollback().await.map_err(|_| ModError::Db)?;
        log_action(pool, actor_id, Some(target_id), None, "close-account-refused", reason)
            .await
            .map_err(|_| ModError::Db)?;
        return Err(ModError::Forbidden);
    }
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

/// Take a listing down (it disappears from the catalogue; the
/// seller is notified) or restore it.
///
/// CH1: the takedown lives in its own fields — `taken_down_at` /
/// `taken_down_by`, with the seller's own status preserved in
/// `pre_takedown_status`. While a takedown is in force the status
/// column reads 'removed', a state no seller action can produce or
/// clear (listings::set_status refuses every change and no longer
/// accepts 'removed' at all). Restore touches ONLY takedowns: it
/// clears the takedown fields and returns the listing to its
/// pre-takedown status — it can never republish a listing the
/// seller withdrew ('withdrawn'), because a withdrawn listing has
/// no takedown to clear and restoring it is refused (BadInput).
pub async fn set_listing_removed(
    pool: &PgPool,
    listing_public_id: &str,
    moderator_id: i64,
    remove: bool,
) -> Result<(), ModError> {
    let row: Option<(i64, i64, String, bool)> = sqlx::query_as(
        "SELECT id, seller_id, status, taken_down_at IS NOT NULL FROM listings WHERE public_id = $1",
    )
    .bind(listing_public_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ModError::Db)?;
    let Some((listing_id, seller_id, _status, taken_down)) = row else {
        return Err(ModError::NotFound);
    };
    let action = if remove {
        if taken_down {
            return Err(ModError::BadInput);
        }
        sqlx::query(
            "UPDATE listings
                SET pre_takedown_status = status, status = 'removed',
                    taken_down_at = now(), taken_down_by = $2
              WHERE id = $1",
        )
        .bind(listing_id)
        .bind(moderator_id)
        .execute(pool)
        .await
        .map_err(|_| ModError::Db)?;
        "remove-listing"
    } else {
        if !taken_down {
            return Err(ModError::BadInput);
        }
        sqlx::query(
            "UPDATE listings
                SET status = COALESCE(pre_takedown_status, 'published'),
                    pre_takedown_status = NULL,
                    taken_down_at = NULL, taken_down_by = NULL
              WHERE id = $1",
        )
        .bind(listing_id)
        .execute(pool)
        .await
        .map_err(|_| ModError::Db)?;
        "restore-listing"
    };
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
