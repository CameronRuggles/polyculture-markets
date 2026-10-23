//! HT H1 audit fix task 10 (finding F14 + owner decision Q5):
//! the §4 publish gate's side doors.
//!
//! 1. Moderator restore re-checks the gate: a taken-down listing
//!    whose pre-takedown status was 'published' but which has no
//!    current terms pin matching its text restores to 'paused',
//!    not back into the catalogue. A listing WITH a matching pin
//!    restores to 'published' as before.
//! 2. Migration 0017 auto-pauses listings published before H1
//!    (published with no pinned terms) until re-signed, and leaves
//!    terms-pinned published listings untouched.
//!
//! DB tests require DATABASE_URL; skipped silently when unset, and
//! the pool helper panics when it is set but unreachable (fix task
//! 3b). The migration test runs against its own scratch database so
//! it can apply the migration files itself.
//!
//! HT H2 first batch task 4 (re-verification finding N3) adds
//! section 3: the takedown coverage the Q3 blind_stage9 case swap
//! dropped — seller notification on takedown, and refusal of a
//! second takedown (the `pre_takedown_status` guard) — restored
//! here, in a NON-locked suite, until a blind-authored stage9
//! case re-locks it under Q3.

use app::moderation;
use domain::ht_statements as hs;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

const MKT: &str = "mkt_0123456789abcdef0123456789abcdef";

async fn pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Some(
        PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .expect("DATABASE_URL is set but the database is unreachable"),
    )
}

fn uniq() -> String {
    app::sessions::new_token()[..16].to_string()
}

async fn make_account(pool: &PgPool, role: &str) -> i64 {
    let public_id = app::db::public_id("acct_");
    let username = format!("htg{}{}", &role[..3], uniq());
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO accounts (public_id, username, password_hash, role, created_at)
         VALUES ($1, $2, 'ht-publish-gate-fixture-hash', $3, now()) RETURNING id",
    )
    .bind(&public_id)
    .bind(&username)
    .bind(role)
    .fetch_one(pool)
    .await
    .expect("insert account");
    id
}

async fn make_listing(pool: &PgPool, seller_id: i64, status: &str) -> (i64, String) {
    let public = format!("lst_{:032x}", {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        t ^ ((std::process::id() as u128) << 64) ^ (seller_id as u128)
    });
    let row = sqlx::query(
        "INSERT INTO listings (public_id, seller_id, title, description, price_atomic,
                               pricing_module, destination_module, auto_invoice, status,
                               delivery_terms, refund_terms)
         VALUES ($1, $2, 'Gate Widget', 'A widget.', 250000000000, 'xmr-only',
                 'signed-address-pool', false, $3, 'Ships in 3 days.',
                 'Refunds per the cap.') RETURNING id",
    )
    .bind(&public)
    .bind(seller_id)
    .bind(status)
    .fetch_one(pool)
    .await
    .expect("insert listing");
    (row.get("id"), public)
}

async fn status_of(pool: &PgPool, listing_id: i64) -> String {
    sqlx::query_scalar("SELECT status FROM listings WHERE id = $1")
        .bind(listing_id)
        .fetch_one(pool)
        .await
        .expect("status")
}

async fn cleanup(pool: &PgPool, seller_id: i64, listing_id: i64, moderator_id: i64) {
    // FK order: moderation actions reference both the listing and
    // the accounts, so they go first.
    let _ = sqlx::query(
        "DELETE FROM moderation_actions WHERE actor_id = $1 OR target_listing_id = $2",
    )
    .bind(moderator_id)
    .bind(listing_id)
    .execute(pool)
    .await;
    for q in [
        "DELETE FROM listing_terms_statements WHERE listing_id = $1",
        "DELETE FROM listings WHERE id = $1",
    ] {
        let _ = sqlx::query(q).bind(listing_id).execute(pool).await;
    }
    for (q, id) in [
        ("DELETE FROM notifications WHERE account_id = $1", seller_id),
        ("DELETE FROM identity_keys WHERE account_id = $1", seller_id),
        ("DELETE FROM accounts WHERE id = $1", seller_id),
        ("DELETE FROM accounts WHERE id = $1", moderator_id),
    ] {
        let _ = sqlx::query(q).bind(id).execute(pool).await;
    }
}

// ---------------------------------------------------------------------------
// 1. The restore gate.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restore_without_a_terms_pin_lands_on_paused() {
    let Some(pool) = pool().await else { return };
    let seller = make_account(&pool, "seller").await;
    let moderator = make_account(&pool, "moderator").await;
    let (lid, lpub) = make_listing(&pool, seller, "published").await;

    moderation::set_listing_removed(&pool, &lpub, moderator, true)
        .await
        .expect("takedown");
    assert_eq!(status_of(&pool, lid).await, "removed");
    moderation::set_listing_removed(&pool, &lpub, moderator, false)
        .await
        .expect("restore");
    assert_eq!(
        status_of(&pool, lid).await,
        "paused",
        "a taken-down listing with no terms pin must restore to paused, not published (F14)"
    );
    cleanup(&pool, seller, lid, moderator).await;
}

#[tokio::test]
async fn restore_with_a_matching_terms_pin_returns_to_published() {
    let Some(pool) = pool().await else { return };
    let seller = make_account(&pool, "seller").await;
    let moderator = make_account(&pool, "moderator").await;
    let (lid, lpub) = make_listing(&pool, seller, "published").await;

    // Install a real key and pin matching terms through the app
    // layer (the same path the seller page uses).
    let (secret, cert) = helper_core::keys::generate_test_cert("Gate Seller <gate@example.org>")
        .expect("seller key");
    let fpr = helper_core::keys::fingerprint_of(&cert).expect("fpr");
    let cert_text = String::from_utf8(cert).expect("cert text");
    let info = app::keys::validate_cert(cert_text.as_bytes()).expect("cert validates");
    assert_eq!(info.fingerprint, fpr);
    app::keys::install_key(&pool, seller, cert_text.as_bytes(), &info, None)
        .await
        .expect("install key");
    let listing = app::listings::listing_by_public_id(&pool, &lpub)
        .await
        .expect("load")
        .expect("listing");
    let text = app::listings::listing_terms_text_for(&pool, &listing)
        .await
        .expect("terms text");
    let stmt = hs::TermsStatement {
        marketplace_id: MKT.into(),
        listing_id: lpub.clone(),
        listing_version: 1,
        seller_key_fingerprint: fpr.clone(),
        terms_sha256: hs::sha256_hex(text.as_bytes()),
        risk: hs::RiskTerms {
            transit_risk: hs::TransitRisk::Seller,
            remedy_cap_pct: 25,
            payment_timing: hs::PaymentTiming::Prepay,
        },
    };
    let stmt_text = String::from_utf8(stmt.to_bytes()).expect("statement text");
    let sig = helper_core::keys::sign_detached(&secret, None, stmt_text.as_bytes())
        .expect("sign terms");
    app::listings::submit_terms(&pool, MKT, &listing, &stmt_text, &sig)
        .await
        .expect("pin terms");
    assert!(app::listings::terms_match_listing(&pool, &listing).await, "pin matches before takedown");

    moderation::set_listing_removed(&pool, &lpub, moderator, true)
        .await
        .expect("takedown");
    moderation::set_listing_removed(&pool, &lpub, moderator, false)
        .await
        .expect("restore");
    assert_eq!(
        status_of(&pool, lid).await,
        "published",
        "a taken-down listing whose terms pin matches restores to published"
    );
    cleanup(&pool, seller, lid, moderator).await;
}

// ---------------------------------------------------------------------------
// 2. The migration, on a scratch database.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_0017_pauses_unpinned_published_listings_only() {
    let Some(base) = std::env::var("DATABASE_URL").ok() else { return };
    let root = base.rsplit_once('/').map(|(r, _)| r).unwrap_or(&base).to_string();
    let scratch = "marketplace_ht10_scratch";
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(&format!("{root}/postgres"))
        .await
        .expect("DATABASE_URL is set but the database is unreachable");
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {scratch} WITH (FORCE)"))
        .execute(&admin)
        .await;
    sqlx::query(&format!("CREATE DATABASE {scratch}"))
        .execute(&admin)
        .await
        .expect("create scratch db");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&format!("{root}/{scratch}"))
        .await
        .expect("connect scratch");

    // Apply the pre-0017 baseline exactly as the gate does (file
    // order): migration files named STRICTLY BELOW 0017. (N9:
    // this used to apply "everything except 0017" behind an
    // exact file-count assertion, so the next migration would
    // have been applied here by accident AND broken the count.
    // The name filter states the baseline directly; the count is
    // not pinned. 0017 itself is still applied below via
    // include_str!, unchanged.)
    let mig_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations");
    let mut files: Vec<_> = std::fs::read_dir(mig_dir)
        .expect("read migrations dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .filter(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            name.len() >= 4 && name[..4].parse::<u32>().is_ok_and(|n| n < 17)
        })
        .collect();
    files.sort();
    for f in &files {
        let sql = std::fs::read_to_string(f).expect("read migration");
        sqlx::raw_sql(&sql).execute(&pool).await.unwrap_or_else(|e| {
            panic!("applying {} failed: {e}", f.display());
        });
    }

    // Fixtures: a bare published listing (pre-H1 shape), a pinned
    // published listing, a removed listing, a draft.
    let seller = make_account(&pool, "seller").await;
    let (unpinned, _) = make_listing(&pool, seller, "published").await;
    let (pinned, _) = make_listing(&pool, seller, "published").await;
    let (removed, _) = make_listing(&pool, seller, "removed").await;
    let (draft, _) = make_listing(&pool, seller, "draft").await;
    sqlx::query(
        "INSERT INTO listing_terms_statements
            (listing_id, version, statement, signature, statement_sha256, terms_sha256,
             transit_risk, remedy_cap_pct, payment_timing)
         VALUES ($1, 1, 'stmt', 'sig', 'ssha', 'tsha', 'seller', 25, 'prepay')",
    )
    .bind(pinned)
    .execute(&pool)
    .await
    .expect("insert pin");

    let sql_0017 = include_str!("../../../migrations/0017_ht_pause_unpinned_listings.sql");
    sqlx::raw_sql(sql_0017).execute(&pool).await.expect("apply 0017");

    assert_eq!(status_of(&pool, unpinned).await, "paused", "pre-H1 published listing is auto-paused");
    assert_eq!(status_of(&pool, pinned).await, "published", "terms-pinned listing is untouched");
    assert_eq!(status_of(&pool, removed).await, "removed", "taken-down listings are not the migration's business");
    assert_eq!(status_of(&pool, draft).await, "draft", "drafts are untouched");

    pool.close().await;
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {scratch} WITH (FORCE)"))
        .execute(&admin)
        .await;
}

// ---------------------------------------------------------------------------
// 3. Takedown coverage restored (re-verification N3; H2 first batch
// task 4). The pre-swap blind_stage9 case asserted these alongside
// the stored status; the swap kept only the stored status, leaving
// notification and the double-remove guard with no coverage
// anywhere. They live here (non-locked) until H2's Q3 re-authoring
// re-locks them.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn takedown_notifies_the_seller() {
    let Some(pool) = pool().await else { return };
    let seller = make_account(&pool, "seller").await;
    let moderator = make_account(&pool, "moderator").await;
    let (lid, lpub) = make_listing(&pool, seller, "published").await;

    moderation::set_listing_removed(&pool, &lpub, moderator, true)
        .await
        .expect("takedown");
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM notifications
          WHERE account_id = $1 AND event_type = 'listing_removed' AND object_ref = $2",
    )
    .bind(seller)
    .bind(&lpub)
    .fetch_one(&pool)
    .await
    .expect("count notifications");
    assert_eq!(count, 1, "a takedown notifies the seller with a listing_removed event");
    cleanup(&pool, seller, lid, moderator).await;
}

#[tokio::test]
async fn second_takedown_is_refused_and_pre_takedown_status_survives() {
    let Some(pool) = pool().await else { return };
    let seller = make_account(&pool, "seller").await;
    let moderator = make_account(&pool, "moderator").await;
    let (lid, lpub) = make_listing(&pool, seller, "published").await;

    moderation::set_listing_removed(&pool, &lpub, moderator, true)
        .await
        .expect("first takedown");
    let err = moderation::set_listing_removed(&pool, &lpub, moderator, true)
        .await
        .expect_err("a second takedown of an already-removed listing must be refused");
    assert!(
        matches!(err, moderation::ModError::BadInput),
        "the second takedown is refused with BadInput, got {err:?}"
    );
    let (status, pre): (String, Option<String>) = sqlx::query_as(
        "SELECT status, pre_takedown_status FROM listings WHERE id = $1",
    )
    .bind(lid)
    .fetch_one(&pool)
    .await
    .expect("listing row");
    assert_eq!(status, "removed");
    assert_eq!(
        pre.as_deref(),
        Some("published"),
        "the refused second takedown must not overwrite pre_takedown_status with 'removed'"
    );
    // The restore still reads the preserved status: 'published'
    // re-checks the §4 terms gate (F14) and, unpinned, lands on
    // 'paused'. Had pre_takedown_status been clobbered with
    // 'removed', the restore would have returned the listing to
    // 'removed' instead.
    moderation::set_listing_removed(&pool, &lpub, moderator, false)
        .await
        .expect("restore");
    assert_eq!(status_of(&pool, lid).await, "paused");
    cleanup(&pool, seller, lid, moderator).await;
}
