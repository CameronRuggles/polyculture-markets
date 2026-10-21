//! HT H1 audit fix task 13 (finding F8 + owner decision Q4,
//! 2026-10-21): guards for the invariants scope line.
//!
//! The Hidden Trades amendment rewrote (7)–(10), but Direct
//! Payments v1 still runs on this tree under the pre-amendment
//! rules, and (11) still speaks v1's language (orders, Paid). The
//! owner decided the amended wording stays, SCOPED: the amended
//! (7)–(10) govern Hidden Trades, v1 keeps the old (7)–(10) until
//! its removal in stage H6, and (11) is v1-scoped. The scope
//! paragraph in docs/invariants.md is what makes the document
//! true of the live tree — these tests pin both halves:
//!
//! * the document carries the scope line (and still carries the
//!   amended claims it scopes);
//! * the live tree really does run both systems — the v1 tables
//!   (`destinations`, `orders`, `invoices`) exist alongside the
//!   Hidden Trades terms table. If v1 is ever removed without
//!   updating the scope line (or the line is dropped while v1
//!   lives), this suite fails.
//!
//! Authorship note: this file is fix-batch scaffolding written
//! under the owner's reviewed fix brief (the blind_*.rs suites are
//! untouched); from here on it is locked like the rest of this
//! directory, and future locked suites follow the Q3 rule — a
//! separate blind author.
//!
//! DB tests require DATABASE_URL; skipped silently when unset, and
//! the pool helper panics when it is set but unreachable (fix task
//! 3b — a gate run must never pass without a database).

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

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

#[test]
fn invariants_doc_carries_the_q4_scope() {
    let doc = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/invariants.md"
    ))
    .expect("read docs/invariants.md");
    assert!(
        doc.contains("**Scope (owner decision Q4, 2026-10-21).**"),
        "the scope paragraph is present"
    );
    assert!(doc.contains("govern **Hidden Trades**"), "the amended (7)-(10) are scoped to Hidden Trades");
    assert!(
        doc.contains("one global `destinations`"),
        "the v1 half of the scope quotes the pre-amendment (8)"
    );
    assert!(
        doc.contains("Invariant (11) belongs to that v1 scope"),
        "(11) is marked v1-scoped, reconciling it with the amended (10)"
    );
    let squashed = doc.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        squashed.contains("keeps the pre-amendment (7)–(10) until v1's removal in build stage H6"),
        "v1 keeps the old rules until H6"
    );
    // The amended claims the scope line governs are still standing.
    assert!(doc.contains("The server stores no destinations."), "amended (9) stands");
    assert!(
        doc.contains("The server holds no order or trade state."),
        "amended (10) stands"
    );
}

#[tokio::test]
async fn live_tree_still_runs_both_systems() {
    let Some(pool) = pool().await else { return };
    for table in ["destinations", "orders", "invoices"] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables
              WHERE table_schema = 'public' AND table_name = $1)",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .expect("information_schema query");
        assert!(exists, "v1 table {table} exists — the v1 scope has a live system to govern");
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM information_schema.tables
          WHERE table_schema = 'public' AND table_name = 'listing_terms_statements')",
    )
    .fetch_one(&pool)
    .await
    .expect("information_schema query");
    assert!(exists, "the Hidden Trades terms table exists — the amended scope is live too");
}
