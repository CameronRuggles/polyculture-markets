//! Stage 1 integration tests against a real PostgreSQL (spec §24 Stage 1
//! exit tests: registration/login, lockout-abuse behaviour, recovery).
//! Requires DATABASE_URL; skipped silently when unset.

use app::passwords::HashGuard;
use app::{db, recovery, sessions};
use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;

async fn pool() -> Option<sqlx::PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()
}

#[tokio::test]
async fn register_session_recovery_flow() {
    let Some(pool) = pool().await else { return };
    let uname = format!("t{}", &sessions::new_token()[..12]);
    let guard = HashGuard::new(2);
    let hash = guard.hash("a long passphrase").await.unwrap();
    let id = db::create_account(&pool, &uname, &hash).await.unwrap();

    // Duplicate username violates the unique constraint.
    assert!(db::create_account(&pool, &uname, &hash).await.is_err());

    // Session round-trip.
    let token = sessions::new_token();
    let sess = sessions::Session::fresh(id, OffsetDateTime::now_utc());
    db::create_session(&pool, &token, "csrfsecret", &sess).await.unwrap();
    let (found, csrf) = db::session_by_token(&pool, &token).await.unwrap().unwrap();
    assert_eq!(found.account_id, id);
    assert_eq!(csrf, "csrfsecret");
    assert!(db::session_by_token(&pool, "deadbeef").await.unwrap().is_none());

    // Recovery: code works once, revokes sessions, second use fails.
    let code = recovery::new_recovery_code();
    db::store_recovery_code(&pool, id, &code).await.unwrap();
    assert!(db::consume_recovery_code(&pool, id, &code).await.unwrap());
    let (after, _) = db::session_by_token(&pool, &token).await.unwrap().unwrap();
    assert!(after.revoked, "recovery must revoke all sessions");
    assert!(!db::consume_recovery_code(&pool, id, &code).await.unwrap());
    assert!(!db::consume_recovery_code(&pool, id, "WRONG-CODE-XXXX-XXXX").await.unwrap());

    // Cleanup (children first — the schema deliberately has no cascades).
    for q in [
        "DELETE FROM session_csrf WHERE token_hash IN (SELECT token_hash FROM sessions WHERE account_id = $1)",
        "DELETE FROM sessions WHERE account_id = $1",
        "DELETE FROM recovery_codes WHERE account_id = $1",
        "DELETE FROM accounts WHERE id = $1",
    ] {
        sqlx::query(q).bind(id).execute(&pool).await.unwrap();
    }
}
