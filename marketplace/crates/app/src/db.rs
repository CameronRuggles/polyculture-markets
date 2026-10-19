//! Core-owned persistence for Stage 1 (accounts, sessions, recovery codes).
//! Runtime SQLx queries; only token/code HASHES are stored (spec §7, §16).

use crate::sessions::{hash_token, Session};
use sqlx::PgPool;
use time::OffsetDateTime;

pub fn public_id(prefix: &str) -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    format!("{prefix}{}", hex::encode(b))
}

pub async fn count_accounts(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM accounts")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

pub async fn create_account(
    pool: &PgPool,
    username_folded: &str,
    password_hash: &str,
) -> Result<i64, sqlx::Error> {
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO accounts (public_id, username, password_hash) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(public_id("acct_"))
    .bind(username_folded)
    .bind(password_hash)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

pub async fn account_by_username(
    pool: &PgPool,
    username_folded: &str,
) -> Result<Option<(i64, String, String)>, sqlx::Error> {
    sqlx::query_as("SELECT id, password_hash, role FROM accounts WHERE username = $1")
        .bind(username_folded)
        .fetch_optional(pool)
        .await
}

pub async fn role_of(pool: &PgPool, account_id: i64) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as("SELECT role FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.0))
}

pub async fn create_session(
    pool: &PgPool,
    token: &str,
    csrf_secret: &str,
    s: &Session,
) -> Result<(), sqlx::Error> {
    // csrf_secret rides in a dedicated column added by migration 0002;
    // Stage 1 keeps it in the sessions row's token-adjacent storage via
    // a separate table to avoid altering 0001 retroactively.
    sqlx::query(
        "INSERT INTO sessions (token_hash, account_id, created_at, last_seen_at, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(hash_token(token).to_vec())
    .bind(s.account_id)
    .bind(s.created_at)
    .bind(s.last_seen_at)
    .bind(s.expires_at)
    .execute(pool)
    .await?;
    sqlx::query("INSERT INTO session_csrf (token_hash, csrf_secret) VALUES ($1, $2)")
        .bind(hash_token(token).to_vec())
        .bind(csrf_secret)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn session_by_token(
    pool: &PgPool,
    token: &str,
) -> Result<Option<(Session, String)>, sqlx::Error> {
    let row: Option<(i64, OffsetDateTime, OffsetDateTime, OffsetDateTime, Option<OffsetDateTime>, String)> =
        sqlx::query_as(
            "SELECT s.account_id, s.created_at, s.last_seen_at, s.expires_at, s.revoked_at, c.csrf_secret
             FROM sessions s JOIN session_csrf c ON c.token_hash = s.token_hash
             WHERE s.token_hash = $1",
        )
        .bind(hash_token(token).to_vec())
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(account_id, created_at, last_seen_at, expires_at, revoked_at, csrf)| {
        (
            Session {
                account_id,
                created_at,
                last_seen_at,
                expires_at,
                revoked: revoked_at.is_some(),
            },
            csrf,
        )
    }))
}

pub async fn touch_session(pool: &PgPool, token: &str, now: OffsetDateTime) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sessions SET last_seen_at = $2 WHERE token_hash = $1")
        .bind(hash_token(token).to_vec())
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn revoke_all_sessions(pool: &PgPool, account_id: i64) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE sessions SET revoked_at = now() WHERE account_id = $1 AND revoked_at IS NULL",
    )
    .bind(account_id)
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

/// Revoke every session of the account EXCEPT the one identified by
/// `keep_token` (account-security task 8: a passphrase change ends all
/// other sessions; the session performing the change survives).
pub async fn revoke_other_sessions(
    pool: &PgPool,
    account_id: i64,
    keep_token: &str,
) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE sessions SET revoked_at = now()
          WHERE account_id = $1 AND revoked_at IS NULL AND token_hash <> $2",
    )
    .bind(account_id)
    .bind(hash_token(keep_token).to_vec())
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

/// Replace the account's recovery code (task 8): every unconsumed code
/// is burned and the new code is stored — after issuance, only the
/// newest code can recover the account.
pub async fn replace_recovery_code(pool: &PgPool, account_id: i64, code: &str) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE recovery_codes SET consumed_at = now()
          WHERE account_id = $1 AND consumed_at IS NULL",
    )
    .bind(account_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO recovery_codes (account_id, code_hash) VALUES ($1, $2)")
        .bind(account_id)
        .bind(crate::recovery::hash_code(code).to_vec())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn store_recovery_code(pool: &PgPool, account_id: i64, code: &str) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO recovery_codes (account_id, code_hash) VALUES ($1, $2)")
        .bind(account_id)
        .bind(crate::recovery::hash_code(code).to_vec())
        .execute(pool)
        .await?;
    Ok(())
}

/// Consume a recovery code: on success the code is burned AND all sessions
/// are revoked AND the profile is marked recovered (spec §7, one operation).
pub async fn consume_recovery_code(
    pool: &PgPool,
    account_id: i64,
    code: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let r = sqlx::query(
        "UPDATE recovery_codes SET consumed_at = now()
         WHERE account_id = $1 AND code_hash = $2 AND consumed_at IS NULL",
    )
    .bind(account_id)
    .bind(crate::recovery::hash_code(code).to_vec())
    .execute(&mut *tx)
    .await?;
    if r.rows_affected() != 1 {
        tx.rollback().await?;
        return Ok(false);
    }
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE account_id = $1 AND revoked_at IS NULL")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE accounts SET recovered_at = now() WHERE id = $1")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

/// Modules Audit BM2 (2026-10-19): the full recovery, in ONE
/// transaction, called only AFTER the new passphrase has been
/// hashed. The pre-fix handler consumed the code first (via
/// `consume_recovery_code`) and hashed second — so a Busy hashing
/// pool, which BM1 could arrange on demand, burned the user's
/// only recovery code and left the account unrecoverable. Here
/// the code is spent in the same commit that sets the new hash,
/// revokes every session, marks the account recovered, applies
/// the V3 TOTP clear (owner decision 2026-10-19) and stores the
/// fresh code: any failure before the commit leaves the old code
/// valid. Returns `Ok(None)` when the code does not match (nothing
/// was changed), `Ok(Some(totp_was_on))` on success.
pub async fn complete_recovery(
    pool: &PgPool,
    account_id: i64,
    code: &str,
    new_password_hash: &str,
    new_code: &str,
) -> Result<Option<bool>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let r = sqlx::query(
        "UPDATE recovery_codes SET consumed_at = now()
         WHERE account_id = $1 AND code_hash = $2 AND consumed_at IS NULL",
    )
    .bind(account_id)
    .bind(crate::recovery::hash_code(code).to_vec())
    .execute(&mut *tx)
    .await?;
    if r.rows_affected() != 1 {
        tx.rollback().await?;
        return Ok(None);
    }
    let totp_was_on: bool = sqlx::query_scalar(
        "SELECT totp_enabled_at IS NOT NULL FROM accounts WHERE id = $1",
    )
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("UPDATE accounts SET password_hash = $2 WHERE id = $1")
        .bind(account_id)
        .bind(new_password_hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE account_id = $1 AND revoked_at IS NULL")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE accounts SET recovered_at = now() WHERE id = $1")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    if totp_was_on {
        // V3: recovery clears TOTP (same column set as
        // totp_disable); the handler posts the inbox notice after
        // the commit.
        sqlx::query(
            "UPDATE accounts SET totp_secret_enc = NULL, totp_pending_enc = NULL,
                    totp_enabled_at = NULL, totp_last_step = NULL, totp_fail_count = 0,
                    totp_locked_until = NULL, totp_lock_notified_at = NULL
              WHERE id = $1",
        )
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("INSERT INTO recovery_codes (account_id, code_hash) VALUES ($1, $2)")
        .bind(account_id)
        .bind(crate::recovery::hash_code(new_code).to_vec())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(totp_was_on))
}

pub async fn public_id_of(pool: &PgPool, account_id: i64) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as("SELECT public_id FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.0))
}

/// Stage 9: display helper (dispute pages show both parties).
pub async fn username_of_id(pool: &PgPool, account_id: i64) -> String {
    sqlx::query_scalar("SELECT username FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|_| "?".into())
}

pub async fn account_by_public_id(
    pool: &PgPool,
    public_id: &str,
) -> Result<Option<(i64, String, String, Option<time::OffsetDateTime>, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, username, role, recovered_at, profile_text FROM accounts WHERE public_id = $1",
    )
    .bind(public_id)
    .fetch_optional(pool)
    .await
}

pub async fn list_sessions(
    pool: &PgPool,
    account_id: i64,
) -> Result<Vec<(i64, String, String, bool)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, to_char(created_at, 'YYYY-MM-DD HH24:MI'), to_char(last_seen_at, 'YYYY-MM-DD HH24:MI'),
                revoked_at IS NOT NULL
         FROM sessions WHERE account_id = $1 ORDER BY created_at DESC LIMIT 20",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
}

pub async fn revoke_session_by_id(pool: &PgPool, session_id: i64, account_id: i64) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE sessions SET revoked_at = now() WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL",
    )
    .bind(session_id)
    .bind(account_id)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn set_profile_text(pool: &PgPool, account_id: i64, text: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE accounts SET profile_text = $2 WHERE id = $1")
        .bind(account_id)
        .bind(text)
        .execute(pool)
        .await?;
    Ok(())
}
