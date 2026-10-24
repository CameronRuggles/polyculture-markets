//! Code Audit 2, item 3 (M2/C1) — the 90-day message retention the
//! `expires_at` column has always promised.
//!
//! One end-to-end pass over `run_retention` against a real
//! database:
//!
//! - a message row past `expires_at` is deleted AND its blob file
//!   is unlinked;
//! - a live message row and its blob are untouched;
//! - an orphan blob file (no referencing row) older than the
//!   grace period is reconciled away;
//! - a YOUNG orphan is kept (a send writes its blob before its
//!   row — an in-flight insert must never lose its file);
//! - foreign names in the blob directory are never touched.
//!
//! DB tests require DATABASE_URL (skipped silently when unset,
//! the pattern of the neighbouring suites). Blob files are staged
//! in a per-process scratch BLOB_DIR (the messaging_audit pattern).

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::io::Write as _;

async fn pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Some(
        PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("DATABASE_URL is set but the database is unreachable"),
    )
}

fn uniq() -> String {
    app::sessions::new_token()[..16].to_string()
}

fn blob_root() -> std::path::PathBuf {
    static ONCE: std::sync::Once = std::sync::Once::new();
    let mut dir = std::env::temp_dir();
    dir.push(format!("retention-msg-{}", std::process::id()));
    let root = dir.clone();
    ONCE.call_once(|| {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("blobs")).unwrap();
        std::env::set_var("BLOB_DIR", dir.join("blobs"));
    });
    root
}

async fn make_account(pool: &PgPool) -> i64 {
    let hash = app::passwords::HashGuard::new(2).hash("retention-test-passphrase-1").await.unwrap();
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO accounts (public_id, username, password_hash, role)
         VALUES ($1, $2, $3, 'buyer') RETURNING id",
    )
    .bind(app::db::public_id("acct_"))
    .bind(format!("retmsg{}", uniq()))
    .bind(&hash)
    .fetch_one(pool)
    .await
    .unwrap();
    id
}

fn write_blob(dir: &std::path::Path, stem: &str, age_secs: u64) -> std::path::PathBuf {
    let path = dir.join(format!("{stem}.asc"));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(b"-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----\n").unwrap();
    if age_secs > 0 {
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(age_secs);
        f.set_modified(when).unwrap();
    }
    path
}

#[tokio::test]
async fn expired_messages_and_orphan_blobs_are_swept() {
    let Some(pool) = pool().await else { return };
    let root = blob_root();
    let dir = root.join("blobs");
    let sender = make_account(&pool).await;
    let recipient = make_account(&pool).await;
    let (conv,): (i64,) = sqlx::query_as(
        "INSERT INTO conversations (public_id) VALUES ($1) RETURNING id",
    )
    .bind(app::db::public_id("conv_"))
    .fetch_one(&pool)
    .await
    .unwrap();

    // Distinct all-hex stems per run (the blob guard only ever
    // acts on hex names) so a shared database/dir can never
    // collide with this test's files.
    let live_ref = format!("{}a11e", uniq());
    let dead_ref = format!("{}dead", uniq());
    let stale_orphan = format!("{}09f1", uniq());
    let fresh_orphan = format!("{}09f2", uniq());

    let insert = |blob_ref: &str, expires: &str| {
        let q = format!(
            "INSERT INTO encrypted_messages
                (conversation_id, sender_id, recipient_id, recipient_key_id, blob_ref, length, expires_at)
             VALUES ($1, $2, $3, 'keyid', $4, 10, {expires})"
        );
        let pool = pool.clone();
        let blob_ref = blob_ref.to_string();
        async move {
            sqlx::query(&q)
                .bind(conv)
                .bind(sender)
                .bind(recipient)
                .bind(blob_ref)
                .execute(&pool)
                .await
                .unwrap()
        }
    };
    insert(&live_ref, "now() + interval '90 days'").await;
    insert(&dead_ref, "now() - interval '1 day'").await;

    let live_blob = write_blob(&dir, &live_ref, 0);
    let dead_blob = write_blob(&dir, &dead_ref, 0);
    let stale_blob = write_blob(&dir, &stale_orphan, app::retention::ORPHAN_BLOB_GRACE_SECS + 60);
    let fresh_blob = write_blob(&dir, &fresh_orphan, 0);
    // Foreign files: never the sweep's business.
    let notes = dir.join("operator-notes.txt");
    std::fs::write(&notes, b"keep me").unwrap();
    let nonhex = write_blob(&dir, "not-a-blob-ref", app::retention::ORPHAN_BLOB_GRACE_SECS + 60);

    let out = app::retention::run_retention(&pool, &app::retention::RetentionConfig::defaults())
        .await
        .unwrap();

    assert_eq!(out.messages, 1, "exactly the expired row is deleted");
    assert_eq!(out.orphan_blobs, 1, "exactly the stale orphan is reconciled");

    let (remaining,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM encrypted_messages WHERE conversation_id = $1")
            .bind(conv)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 1, "the live row remains");
    assert!(!dead_blob.exists(), "the expired message's blob is unlinked");
    assert!(live_blob.exists(), "the live message's blob is untouched");
    assert!(!stale_blob.exists(), "the stale orphan blob is removed");
    assert!(fresh_blob.exists(), "a young orphan survives (possible in-flight insert)");
    assert!(notes.exists(), "foreign files are left alone");
    assert!(nonhex.exists(), "non-blob names are left alone");

    // Cleanup.
    sqlx::query("DELETE FROM encrypted_messages WHERE conversation_id = $1")
        .bind(conv)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM conversations WHERE id = $1").bind(conv).execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM accounts WHERE id = ANY($1)")
        .bind(vec![sender, recipient])
        .execute(&pool)
        .await
        .unwrap();
    for p in [live_blob, fresh_blob, notes, nonhex] {
        let _ = std::fs::remove_file(p);
    }
}
