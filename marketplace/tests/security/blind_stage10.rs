//! Blind security suite — Stage 10: deployment profiles, instance
//! configuration, §15 layout pass, retention jobs, deploy tooling
//! (spec §24 stage 10: "Retention jobs, deployment profiles, backups,
//! operations docs — Minimum viable marketplace complete").
//!
//! AUTHORSHIP: written ONLY from STAGE10-BRIEF.md (the pinned contract
//! source), spec §15, §19, §20, §22 and §24, SPEC-V2-AMENDMENTS.md
//! (incl. Direct Payments v1), PRE-MAINNET-CONFIRMATION-SHEET.md (for
//! the env-template default values), docs/api-contract.md, prior locked
//! suites in this directory (fixture conventions ONLY), and migrations
//! 0001_initial.sql / 0009_stage9.sql (schema = contract, for the
//! retention fixtures). The deploy artifacts named in the brief
//! (marketplace/deploy/env.demo.template, marketplace-demo.service,
//! deploy-demo.sh, DEPLOY-DEMO-RUNBOOK.md) are treated as contract
//! surfaces and are read ONLY by the file-scan assertions below; at
//! authoring time they did not exist yet, so those scans fail until
//! they land — that is correct gate behaviour (§22). The Stage 10
//! implementation files (crates/app/src/config.rs, web.rs,
//! retention.rs, main.rs, payments.rs, crates/app/templates/*) were
//! NOT read.
//!
//! OWNER RULINGS applied throughout:
//!  - No mainnet by default, anywhere. Mainnet is reachable only in
//!    the Production profile AND only with the exact friction string;
//!    every near-miss fails. The demo is stagenet (owner decision
//!    2026-10-16); the deploy tooling is stagenet-only.
//!  - marketplace_id defaults to "vespiary-market" and must never
//!    drift (it is baked into signed payment messages).
//!  - Direct Payments v1 copy is honest: payments are "seller
//!    confirmed", never "verified", and there is NO escrow.
//!  - Closure-not-ban is Stage 9's ruling, not this stage's: this
//!    suite asserts nothing about moderation, bans, or closure.
//!
//! CONTRACT AMBIGUITIES (conservative readings taken; fixture
//! constructions only — no assertion was weakened silently):
//!  A1. The brief/task pin the AppState fields and the construction
//!      recipe field-by-field, and say the HTTP tests run "via the
//!      real router", but do not name the module path of AppState or
//!      the router function. Conservative reading: both live in
//!      `app::web` and the constructor is `app::web::router(state)`.
//!      If the implementation names them differently, compilation of
//!      this suite fails and that is a contract gap to resolve at the
//!      gate, not a reason to soften an assertion.
//!  A2. Positive shell checks (doctype) are applied case-insensitively:
//!      HTML doctypes are case-insensitive and the brief lists the
//!      forbidden-markup checks as case-insensitive; footer link texts
//!      and the Version marker are asserted as displayed (exact case).
//!      Payment-risks copy is checked on the lowercased body so
//!      sentence-initial capitalisation cannot decide the result.
//!  A3. Where two config rules are violated at once (e.g. mainnet in
//!      the Demo profile WITHOUT the confirm string), the brief does
//!      not pin which error wins (R3 vs R4 check order). This suite
//!      asserts a specific ConfigError variant only where exactly one
//!      rule is violated; the one combined case asserted is mainnet +
//!      exact confirm in a non-Production profile, which can only be
//!      NetworkProfileMismatch under any check order.
//!  A4. Retention outcome counts are asserted exactly, so the DB test
//!      first runs run_retention once to flush any pre-existing aged
//!      rows left by other suites, THEN inserts its fixtures and
//!      asserts the second run's outcome. Construction only.
//!  A5. Retention keys (spec §20 wording): notifications on read_at
//!      ("Read + 30 days", unread rows are never aged out by this
//!      job), sessions on expires_at ("Expiry + 7 days"), security
//!      events on created_at, disclosures on their dispute's
//!      resolved_at — and deleting a disclosure deletes the row while
//!      the dispute record itself (an order record) stays.
//!  A6. Present-but-empty values are not "unset": an empty
//!      DEPLOY_PROFILE / INSTANCE_NETWORK / REGISTRATIONS_OPEN value
//!      is asserted invalid, matching R1/R2/R7's "anything else"
//!      wording. REGISTRATIONS_OPEN accepts exactly 1/true/0/false;
//!      "TRUE", "yes", "on", "2" are InvalidValue.
//!  A7. R6 keys dev_cookies on the ABSENCE of PRODUCTION_HTTPS. The
//!      suite sets it to "1" (presence with the conventional value);
//!      the empty-string-presence corner is not pinned and not
//!      asserted.
//!  A8. The brief pins the site_name default ("Vespiary Market") and
//!      the SOURCE_URL env name, but no env name for overriding the
//!      site name; only the default is asserted. AMENDED 2026-10-17:
//!      the owner renamed the product (Polyculture Markets), and the
//!      pinned default was changed to "Polyculture Markets" through
//!      the Q10 review-pack gate (NAME-PIN-REVIEW-PACK-2026-10-17.md;
//!      independent fresh-context review APPROVED 2026-10-17). The
//!      original pin above is kept verbatim for the record;
//!      marketplace_id (R8) was not part of the amendment.
//!  A9. RetentionOutcome fields and RetentionConfig fields are read
//!      as integer counts / days / seconds, per the brief's struct
//!      sketch; assertions compare them against integer literals.
//!  A10. AppState construction (fixture construction only): the task
//!      recipe lists the AppState fields verbatim and is followed
//!      verbatim, with ONE addition revealed by the compiler (error
//!      E0063) when the in-progress implementation landed during
//!      authoring: AppState also carries a `retention` field. It is
//!      constructed as RetentionConfig::defaults() — the brief's own
//!      default retention configuration — so no assertion in this
//!      suite depends on a value the brief does not pin. Recorded
//!      here for the owner's sight per the Q7a pattern.
//!  A11. KNOWN SCAFFOLD DEFECT (reported, not worked around): in
//!      tests/security/Cargo.toml as scaffolded, the axum / tower /
//!      http-body-util dependency lines sit AFTER the [[test]]
//!      tables, so TOML parses them as keys of a [[test]] table and
//!      NOT as [dependencies]; the crates are therefore not linked
//!      to this test target and the HTTP section cannot compile
//!      until the coordinator moves those three lines under
//!      [dependencies]. This suite's author may edit no file but
//!      this one, so the defect is flagged here and in the delivery
//!      report instead of being fixed.

use app::config::{ConfigError, InstanceConfig, Profile, MAINNET_CONFIRM_VALUE};
use app::payments::PaymentConfig;
use app::retention::{run_retention, RetentionConfig};
use modules_api::Network;
use sqlx::{PgPool, Row};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------
// Shared helpers (fixture conventions mirrored from blind_stage9)
// ---------------------------------------------------------------------

const DB_URL_DEFAULT: &str = "postgres://postgres@localhost:5432/marketplace_dev";

fn db_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| DB_URL_DEFAULT.to_string())
}
async fn pool() -> PgPool {
    PgPool::connect(&db_url()).await.expect("connect to marketplace_dev")
}

static COUNTER: AtomicU64 = AtomicU64::new(1);
fn uniq128() -> u128 {
    let c = COUNTER.fetch_add(1, Ordering::SeqCst) as u128;
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    t ^ (c << 100) ^ ((std::process::id() as u128) << 64)
}
fn uniq_name() -> String {
    format!("u{:016x}", (uniq128() & 0xffff_ffff_ffff_ffff) as u64)
}
fn marker(tag: &str) -> String {
    format!("blind10-{tag}-{:032x}", uniq128())
}

// =====================================================================
// Instance configuration & deployment profiles (brief §1, rules R1–R9)
// =====================================================================

/// resolve() with an injected env map — never the process env, so
/// parallel tests cannot race each other (brief §5 gate text).
fn resolve(pairs: &[(&str, &str)]) -> Result<InstanceConfig, ConfigError> {
    InstanceConfig::resolve(&|key: &str| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| (*v).to_string())
    })
}
fn variant_name(e: &ConfigError) -> &'static str {
    match e {
        ConfigError::UnknownProfile(_) => "UnknownProfile",
        ConfigError::UnknownNetwork(_) => "UnknownNetwork",
        ConfigError::MainnetNotConfirmed => "MainnetNotConfirmed",
        ConfigError::NetworkProfileMismatch => "NetworkProfileMismatch",
        ConfigError::InvalidValue(_) => "InvalidValue",
    }
}
fn resolved(pairs: &[(&str, &str)]) -> InstanceConfig {
    match resolve(pairs) {
        Ok(c) => c,
        Err(e) => panic!("expected Ok config for {pairs:?}, got {}", variant_name(&e)),
    }
}
fn resolve_err(pairs: &[(&str, &str)]) -> ConfigError {
    match resolve(pairs) {
        Ok(_) => panic!("expected Err config for {pairs:?}, got Ok"),
        Err(e) => e,
    }
}

#[test]
fn config_mainnet_confirm_constant_is_exact() {
    assert_eq!(MAINNET_CONFIRM_VALUE, "I ACCEPT MAINNET REAL FUNDS");
}

#[test]
fn config_empty_env_defaults_to_development_stagenet_loopback() {
    let c = resolved(&[]);
    assert!(matches!(c.profile, Profile::Development), "unset DEPLOY_PROFILE is Development (R1)");
    assert_eq!(c.network, Network::Stagenet, "unset INSTANCE_NETWORK is Stagenet (R2)");
    assert_eq!(c.marketplace_id, "vespiary-market", "R8 default marketplace_id");
    assert_eq!(c.site_name, "Polyculture Markets", "brief default site name, as amended 2026-10-17");
    assert_eq!(c.bind_addr, "127.0.0.1:8080", "R5: loopback default in every profile");
    assert!(c.dev_cookies, "empty env is Development without PRODUCTION_HTTPS: dev_cookies true (R6)");
    assert!(c.registrations_open, "unset REGISTRATIONS_OPEN defaults to open (R7)");
    assert!(c.source_url.is_none(), "unset SOURCE_URL is None");
    assert!(!c.version.is_empty(), "version marker must be present");
}

#[test]
fn config_unknown_profile_values_are_rejected_fail_closed() {
    for bad in ["prod", "Production", "DEMO", "staging", " development", "development ", ""] {
        let e = resolve_err(&[("DEPLOY_PROFILE", bad)]);
        assert!(
            matches!(e, ConfigError::UnknownProfile(_)),
            "DEPLOY_PROFILE={bad:?} must be UnknownProfile (R1: exact values only, no silent fallback), got {}",
            variant_name(&e)
        );
    }
}

#[test]
fn config_demo_and_production_profiles_parse() {
    let demo = resolved(&[("DEPLOY_PROFILE", "demo")]);
    assert!(matches!(demo.profile, Profile::Demo));
    assert_eq!(demo.network, Network::Stagenet, "demo defaults to stagenet");
    let prod = resolved(&[("DEPLOY_PROFILE", "production")]);
    assert!(matches!(prod.profile, Profile::Production));
    let dev = resolved(&[("DEPLOY_PROFILE", "development")]);
    assert!(matches!(dev.profile, Profile::Development));
}

#[test]
fn config_unknown_network_values_are_rejected_not_silently_stagenet() {
    // Regression for the pre-Stage-10 payments.rs behaviour the brief
    // calls out: any unrecognised INSTANCE_NETWORK silently became
    // stagenet. Every value below must now be an error (R2).
    for bad in ["mainet", "bitcoin", "regtest", "STAGENET", "Stagenet", "monero-stagenet", "stagenet ", ""] {
        let e = resolve_err(&[("INSTANCE_NETWORK", bad)]);
        assert!(
            matches!(e, ConfigError::UnknownNetwork(_)),
            "INSTANCE_NETWORK={bad:?} must be UnknownNetwork (R2), got {}",
            variant_name(&e)
        );
    }
}

#[test]
fn config_testnet_parses_in_development_and_demo() {
    let dev = resolved(&[("INSTANCE_NETWORK", "testnet")]);
    assert_eq!(dev.network, Network::Testnet);
    let demo = resolved(&[("DEPLOY_PROFILE", "demo"), ("INSTANCE_NETWORK", "testnet")]);
    assert_eq!(demo.network, Network::Testnet, "only Production forbids testnet (R4)");
}

#[test]
fn config_mainnet_in_production_without_confirm_is_rejected() {
    let e = resolve_err(&[("DEPLOY_PROFILE", "production"), ("INSTANCE_NETWORK", "mainnet")]);
    assert!(
        matches!(e, ConfigError::MainnetNotConfirmed),
        "mainnet without MAINNET_CONFIRM must be MainnetNotConfirmed (R3), got {}",
        variant_name(&e)
    );
}

#[test]
fn config_mainnet_near_miss_confirms_are_all_rejected() {
    // Friction by design (R3): case-sensitive, no trimming, and no
    // boolean-ish shortcut may stand in for the exact string.
    for miss in [
        "yes",
        "true",
        "1",
        "mainnet",
        "i accept mainnet real funds",       // lowercase variant of the confirm string
        "I ACCEPT MAINNET REAL FUNDS ",      // trailing space
        " I ACCEPT MAINNET REAL FUNDS",      // leading space
        "I ACCEPT MAINNET REAL FUND",        // truncated
        "I accept mainnet real funds",       // title case
        "",
    ] {
        let e = resolve_err(&[
            ("DEPLOY_PROFILE", "production"),
            ("INSTANCE_NETWORK", "mainnet"),
            ("MAINNET_CONFIRM", miss),
        ]);
        assert!(
            matches!(e, ConfigError::MainnetNotConfirmed),
            "MAINNET_CONFIRM={miss:?} must be MainnetNotConfirmed (R3), got {}",
            variant_name(&e)
        );
    }
}

#[test]
fn config_mainnet_exact_confirm_in_production_is_accepted() {
    // The ONLY mainnet-accepting case in the whole contract: Production
    // profile + mainnet + the exact confirm string (R3 + R4).
    let c = resolved(&[
        ("DEPLOY_PROFILE", "production"),
        ("INSTANCE_NETWORK", "mainnet"),
        ("MAINNET_CONFIRM", MAINNET_CONFIRM_VALUE),
    ]);
    assert!(matches!(c.profile, Profile::Production));
    assert_eq!(c.network, Network::Mainnet);
    assert!(!c.dev_cookies, "a Production instance never uses dev cookies (R6)");
}

#[test]
fn config_mainnet_with_exact_confirm_in_development_or_demo_is_mismatch() {
    // Even a perfect confirm string cannot put Development or Demo on
    // mainnet (R4): the demo is stagenet by owner decision, and a dev
    // instance on mainnet is precisely the accident being engineered
    // out.
    for profile in ["development", "demo"] {
        let e = resolve_err(&[
            ("DEPLOY_PROFILE", profile),
            ("INSTANCE_NETWORK", "mainnet"),
            ("MAINNET_CONFIRM", MAINNET_CONFIRM_VALUE),
        ]);
        assert!(
            matches!(e, ConfigError::NetworkProfileMismatch),
            "mainnet in profile {profile} must be NetworkProfileMismatch (R4), got {}",
            variant_name(&e)
        );
    }
}

#[test]
fn config_testnet_is_forbidden_in_production() {
    let e = resolve_err(&[("DEPLOY_PROFILE", "production"), ("INSTANCE_NETWORK", "testnet")]);
    assert!(
        matches!(e, ConfigError::NetworkProfileMismatch),
        "testnet in Production must be NetworkProfileMismatch (R4), got {}",
        variant_name(&e)
    );
}

#[test]
fn config_production_with_stagenet_is_allowed() {
    // Production + stagenet is the safe direction and must not require
    // any confirm string (R4).
    let c = resolved(&[("DEPLOY_PROFILE", "production"), ("INSTANCE_NETWORK", "stagenet")]);
    assert!(matches!(c.profile, Profile::Production));
    assert_eq!(c.network, Network::Stagenet);
}

#[test]
fn config_bind_addr_defaults_to_loopback_in_every_profile() {
    for profile in ["development", "demo", "production"] {
        let c = resolved(&[("DEPLOY_PROFILE", profile)]);
        assert_eq!(
            c.bind_addr, "127.0.0.1:8080",
            "profile {profile} must default to loopback (R5: the app never binds a public interface by default)"
        );
    }
}

#[test]
fn config_bind_addr_override_is_respected() {
    let c = resolved(&[("DEPLOY_PROFILE", "demo"), ("BIND_ADDR", "127.0.0.1:9999")]);
    assert_eq!(c.bind_addr, "127.0.0.1:9999", "any profile may override BIND_ADDR (R5)");
}

#[test]
fn config_dev_cookies_true_only_for_development_without_production_https() {
    assert!(resolved(&[]).dev_cookies, "Development, no PRODUCTION_HTTPS: true");
    assert!(resolved(&[("DEPLOY_PROFILE", "development")]).dev_cookies);
    let with_https = resolved(&[("DEPLOY_PROFILE", "development"), ("PRODUCTION_HTTPS", "1")]);
    assert!(!with_https.dev_cookies, "PRODUCTION_HTTPS present in Development: dev_cookies false (R6)");
    assert!(!resolved(&[("DEPLOY_PROFILE", "demo")]).dev_cookies, "Demo: false (__Host- cookies)");
    assert!(!resolved(&[("DEPLOY_PROFILE", "production")]).dev_cookies, "Production: false");
}

#[test]
fn config_demo_on_stagenet_has_dev_cookies_false() {
    let c = resolved(&[("DEPLOY_PROFILE", "demo"), ("INSTANCE_NETWORK", "stagenet")]);
    assert_eq!(c.network, Network::Stagenet);
    assert!(!c.dev_cookies, "the hosted demo uses __Host- cookies, never dev cookies (R6)");
}

#[test]
fn config_registrations_open_strict_parse() {
    assert!(resolved(&[]).registrations_open, "unset defaults to open (R7)");
    assert!(resolved(&[("REGISTRATIONS_OPEN", "1")]).registrations_open);
    assert!(resolved(&[("REGISTRATIONS_OPEN", "true")]).registrations_open);
    assert!(!resolved(&[("REGISTRATIONS_OPEN", "0")]).registrations_open);
    assert!(!resolved(&[("REGISTRATIONS_OPEN", "false")]).registrations_open);
}

#[test]
fn config_registrations_open_garbage_is_invalid_value() {
    for bad in ["yes", "on", "2", "TRUE", "False", "closed", ""] {
        let e = resolve_err(&[("REGISTRATIONS_OPEN", bad)]);
        assert!(
            matches!(e, ConfigError::InvalidValue(_)),
            "REGISTRATIONS_OPEN={bad:?} must be InvalidValue (R7: anything else), got {}",
            variant_name(&e)
        );
    }
}

#[test]
fn config_marketplace_id_default_and_override_and_source_url() {
    assert_eq!(resolved(&[]).marketplace_id, "vespiary-market", "R8 default must never drift");
    let c = resolved(&[
        ("MARKETPLACE_ID", "other-market"),
        ("SOURCE_URL", "https://example.invalid/source.tar.gz"),
    ]);
    assert_eq!(c.marketplace_id, "other-market", "MARKETPLACE_ID override is honoured");
    assert_eq!(
        c.source_url.as_deref(),
        Some("https://example.invalid/source.tar.gz"),
        "SOURCE_URL populates source_url"
    );
}

#[test]
fn config_payment_config_defaults_stay_on_stagenet() {
    // Regression (brief R9 + Direct Payments v1): the locked-suites'
    // constructor PaymentConfig::defaults is unchanged and its network
    // is Stagenet — payments may never default to mainnet.
    let c = PaymentConfig::defaults("vespiary-market");
    assert_eq!(c.network, Network::Stagenet);
    assert_eq!(c.marketplace_id, "vespiary-market");
}

// =====================================================================
// Retention jobs (brief §3, spec §20)
// =====================================================================

#[test]
fn retention_config_defaults_match_spec_section20() {
    let c = RetentionConfig::defaults();
    assert_eq!(c.notifications_read_days, 30, "notifications: read + 30 days (§20)");
    assert_eq!(c.sessions_expired_days, 7, "sessions: expiry + 7 days (§20)");
    assert_eq!(c.security_events_days, 30, "security events: 30 days (§20)");
    assert_eq!(c.disclosures_resolved_days, 180, "dispute disclosures: resolution + 180 days (§20)");
    assert_eq!(c.interval_secs, 3600, "brief §3: RETENTION_INTERVAL_SECS default 3600");
}

async fn make_account(pool: &PgPool) -> i64 {
    let public_id = format!("acct_{:032x}", uniq128());
    let row = sqlx::query(
        "INSERT INTO accounts (public_id, username, password_hash, role, created_at) \
         VALUES ($1, $2, 'blind-suite-fixture-hash', 'buyer', now()) RETURNING id",
    )
    .bind(&public_id)
    .bind(uniq_name())
    .fetch_one(pool)
    .await
    .expect("insert retention fixture account");
    row.get::<i64, _>("id")
}

fn days_ago(days: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() - time::Duration::days(days)
}
fn days_ahead(days: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + time::Duration::days(days)
}
fn token_bytes(seed: u128) -> Vec<u8> {
    let mut t = [0u8; 32];
    t[..16].copy_from_slice(&seed.to_be_bytes());
    t[16..].copy_from_slice(&(seed ^ 0x9e37_79b9_7f4a_7c15_9e37_79b9_7f4a_7c15u128).to_be_bytes());
    t.to_vec()
}

#[tokio::test]
async fn retention_deletes_exactly_the_aged_rows() {
    let pool = pool().await;
    let cfg = RetentionConfig::defaults();

    // A4 (construction): flush any pre-existing aged rows left in the
    // shared dev DB by earlier suites, so the second run's outcome
    // counts describe exactly this test's fixtures.
    run_retention(&pool, &cfg).await.expect("flush run_retention");

    let account = make_account(&pool).await;
    let seller = make_account(&pool).await;

    // --- notifications: read 31d ago (delete) / read 1d ago (keep) /
    //     unread created 60d ago (keep: only READ notifications age) ---
    let (n_old, n_recent, n_unread) = (marker("n-old"), marker("n-new"), marker("n-unread"));
    sqlx::query(
        "INSERT INTO notifications (account_id, event_type, object_ref, created_at, read_at) \
         VALUES ($1, 'blind10', $2, $3, $4), ($1, 'blind10', $5, $6, $7), ($1, 'blind10', $8, $9, NULL)",
    )
    .bind(account)
    .bind(&n_old).bind(days_ago(40)).bind(days_ago(31))
    .bind(&n_recent).bind(days_ago(2)).bind(days_ago(1))
    .bind(&n_unread).bind(days_ago(60))
    .execute(&pool).await.expect("insert notification fixtures");

    // --- sessions (0001 shape: token_hash, account_id, created_at,
    //     last_seen_at, expires_at, revoked_at): expired 8d ago
    //     (delete) / expired 1d ago (keep) / still live (keep) ---
    let (s_old, s_recent, s_live) = (token_bytes(uniq128()), token_bytes(uniq128()), token_bytes(uniq128()));
    sqlx::query(
        "INSERT INTO sessions (token_hash, account_id, created_at, last_seen_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5), ($6, $2, $7, $8, $9), ($10, $2, $11, $12, $13)",
    )
    .bind(&s_old).bind(account).bind(days_ago(20)).bind(days_ago(9)).bind(days_ago(8))
    .bind(&s_recent).bind(days_ago(5)).bind(days_ago(2)).bind(days_ago(1))
    .bind(&s_live).bind(days_ago(1)).bind(time::OffsetDateTime::now_utc()).bind(days_ahead(6))
    .execute(&pool).await.expect("insert session fixtures");

    // --- security events: 31d old (delete) / 1d old (keep) ---
    let sec_marker = marker("sec");
    sqlx::query(
        "INSERT INTO security_events (actor_id, event_type, target, created_at) \
         VALUES ($1, $2, 'old', $3), ($1, $2, 'new', $4)",
    )
    .bind(account).bind(&sec_marker).bind(days_ago(31)).bind(days_ago(1))
    .execute(&pool).await.expect("insert security event fixtures");

    // --- disclosures: needs listing -> order -> dispute chains.
    //     Dispute resolved 181d ago (disclosure deleted, dispute row
    //     stays) / dispute still open (keep) / resolved 1d ago (keep).
    let listing_id: i64 = sqlx::query(
        "INSERT INTO listings (public_id, seller_id, title, description, price_atomic, \
                               pricing_module, destination_module, status) \
         VALUES ($1, $2, 'Blind10 Retention Widget', 'Fixture listing.', 1000000, \
                 'xmr-only', 'signed-address-pool', 'published') RETURNING id",
    )
    .bind(format!("lst_{:032x}", uniq128()))
    .bind(seller)
    .fetch_one(&pool).await.expect("insert retention listing").get("id");

    let mut dispute_ids: Vec<i64> = Vec::new();
    let mut order_ids: Vec<i64> = Vec::new();
    let mut disclosure_ids: Vec<i64> = Vec::new();
    for (state, resolved_at) in [
        ("resolved", Some(days_ago(181))),
        ("open", None),
        ("resolved", Some(days_ago(1))),
    ] {
        let order_id: i64 = sqlx::query(
            "INSERT INTO orders (public_id, buyer_id, seller_id, listing_id, state, settlement, \
                                 seller_fpr_pinned, terms_bytes, terms_sha256, total_atomic, \
                                 module_pins, evidence_level, idempotency_key, created_at, terminal_at) \
             VALUES ($1, $2, $3, $4, 'Resolved', 'direct', $5, $6, $7, 1000000, '{}'::jsonb, \
                     'SellerAttested', $8, now(), $9) RETURNING id",
        )
        .bind(format!("ord_{:032x}", uniq128()))
        .bind(account).bind(seller).bind(listing_id)
        .bind(format!("{:040X}", uniq128() & 0xffff_ffff_ffff_ffff_ffffu128))
        .bind(b"blind10 retention terms fixture".to_vec())
        .bind("a".repeat(64))
        .bind(format!("idem-{:032x}", uniq128()))
        .bind(resolved_at)
        .fetch_one(&pool).await.expect("insert retention order").get("id");
        order_ids.push(order_id);
        let dispute_id: i64 = sqlx::query(
            "INSERT INTO disputes (order_id, opened_by, state, outcome, created_at, resolved_at, outcome_state) \
             VALUES ($1, $2, $3, $4, now(), $5, 'final') RETURNING id",
        )
        .bind(order_id).bind(account).bind(state)
        .bind(if state == "resolved" { Some("seller-at-fault") } else { None })
        .bind(resolved_at)
        .fetch_one(&pool).await.expect("insert retention dispute").get("id");
        dispute_ids.push(dispute_id);
        let disclosure_id: i64 = sqlx::query(
            "INSERT INTO disclosures (dispute_id, submitted_by, content_enc, signature_status, created_at) \
             VALUES ($1, $2, $3, 'unverified_claim', now()) RETURNING id",
        )
        .bind(dispute_id).bind(account)
        .bind(b"blind10 encrypted disclosure fixture".to_vec())
        .fetch_one(&pool).await.expect("insert retention disclosure").get("id");
        disclosure_ids.push(disclosure_id);
    }

    // --- run the job under test ---
    let outcome = run_retention(&pool, &cfg).await.expect("run_retention on fixtures");

    // --- collect survival BEFORE asserting, so fixtures are cleaned
    //     up even when an assertion below fails ---
    let notif_left: Vec<String> = sqlx::query_scalar(
        "SELECT object_ref FROM notifications WHERE account_id = $1 AND event_type = 'blind10'",
    )
    .bind(account).fetch_all(&pool).await.unwrap();
    let sess_left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE account_id = $1")
        .bind(account).fetch_one(&pool).await.unwrap();
    let sess_old_left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE token_hash = $1")
        .bind(&s_old).fetch_one(&pool).await.unwrap();
    let sec_left: Vec<String> = sqlx::query_scalar(
        "SELECT target FROM security_events WHERE event_type = $1",
    )
    .bind(&sec_marker).fetch_all(&pool).await.unwrap();
    let disc_left: Vec<i64> = sqlx::query_scalar("SELECT id FROM disclosures WHERE id = ANY($1)")
        .bind(&disclosure_ids).fetch_all(&pool).await.unwrap();
    let disputes_left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM disputes WHERE id = ANY($1)")
        .bind(&dispute_ids).fetch_one(&pool).await.unwrap();

    // --- cleanup (FK order), whatever the assertions will say ---
    sqlx::query("DELETE FROM disclosures WHERE id = ANY($1)").bind(&disclosure_ids).execute(&pool).await.ok();
    sqlx::query("DELETE FROM disputes WHERE id = ANY($1)").bind(&dispute_ids).execute(&pool).await.ok();
    sqlx::query("DELETE FROM orders WHERE id = ANY($1)").bind(&order_ids).execute(&pool).await.ok();
    sqlx::query("DELETE FROM listings WHERE id = $1").bind(listing_id).execute(&pool).await.ok();
    sqlx::query("DELETE FROM notifications WHERE account_id = $1").bind(account).execute(&pool).await.ok();
    sqlx::query("DELETE FROM sessions WHERE account_id = $1").bind(account).execute(&pool).await.ok();
    sqlx::query("DELETE FROM security_events WHERE event_type = $1").bind(&sec_marker).execute(&pool).await.ok();
    sqlx::query("DELETE FROM accounts WHERE id IN ($1, $2)").bind(account).bind(seller).execute(&pool).await.ok();

    // --- assertions: exactly the aged rows are gone ---
    assert_eq!(outcome.notifications, 1, "exactly the notification read 31d ago is deleted");
    assert_eq!(outcome.sessions, 1, "exactly the session expired 8d ago is deleted");
    assert_eq!(outcome.security_events, 1, "exactly the 31d-old security event is deleted");
    assert_eq!(outcome.disclosures, 1, "exactly the disclosure of the dispute resolved 181d ago is deleted");

    assert!(!notif_left.contains(&n_old), "notification read 31d ago must be deleted");
    assert!(notif_left.contains(&n_recent), "notification read 1d ago must survive");
    assert!(notif_left.contains(&n_unread), "unread notification must survive however old it is");

    assert_eq!(sess_old_left, 0, "session expired 8d ago must be deleted");
    assert_eq!(sess_left, 2, "session expired 1d ago and the live session must survive");

    assert!(!sec_left.iter().any(|t| t == "old"), "31d-old security event must be deleted");
    assert!(sec_left.iter().any(|t| t == "new"), "1d-old security event must survive");

    assert_eq!(disc_left.len(), 2, "open-dispute and recently-resolved disclosures must survive");
    assert!(!disc_left.contains(&disclosure_ids[0]), "disclosure of the 181d-resolved dispute must be deleted");
    assert!(disc_left.contains(&disclosure_ids[1]), "open dispute's disclosure must survive");
    assert!(disc_left.contains(&disclosure_ids[2]), "recently-resolved dispute's disclosure must survive");
    assert_eq!(disputes_left, 3, "the dispute records themselves are order records and stay (brief §3)");
}

// =====================================================================
// §15 layout pass — HTTP over the real router (anonymous pages)
// =====================================================================

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn test_router() -> axum::Router {
    let dir = std::env::temp_dir().join(format!("blind10-kf-{}-{:x}", std::process::id(), uniq128()));
    std::fs::create_dir_all(&dir).expect("create keyfile dir");
    let kf_path = dir.join("keyfile");
    let state = app::web::AppState {
        pool: pool().await,
        hash_guard: app::passwords::HashGuard::new(4),
        throttles: std::sync::Arc::new(app::throttle::Throttles::new()),
        registrations_open: true,
        account_cap: None,
        dev_cookies: true,
        media: app::media::MediaPipeline::from_env(),
        marketplace_id: "vespiary-market".into(),
        payments: app::payments::PaymentConfig::defaults("vespiary-market"),
        keyfile: std::sync::Arc::new(
            app::keyfile::KeyFile::load_or_generate(&kf_path).expect("load_or_generate keyfile"),
        ),
        stage9: app::reputation::Stage9Config::defaults(),
        retention: RetentionConfig::defaults(),
        instance: InstanceConfig::resolve(&|_| None).unwrap(),
    };
    app::web::router(state)
}

/// (status, content-type, body)
async fn get(app: &axum::Router, path: &str) -> (u16, String, String) {
    let res = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).expect("request"))
        .await
        .expect("router oneshot");
    let status = res.status().as_u16();
    let ctype = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = res.into_body().collect().await.expect("collect body").to_bytes();
    (status, ctype, String::from_utf8_lossy(&bytes).into_owned())
}

const ANON_PAGES: &[&str] = &[
    "/", "/listings", "/login", "/register", "/limitations", "/policy",
    "/payment-risks", "/security-guide", "/help", "/source",
];

fn assert_shell(path: &str, body: &str) {
    let lower = body.to_lowercase();
    assert!(lower.contains("<!doctype html"), "{path}: body must carry the shell doctype");
    assert!(lower.contains("<style"), "{path}: CSS is the shell's one inline <style> block (L2)");
    assert!(lower.contains("viewport"), "{path}: shell <head> must carry the viewport meta (§15)");
    for text in ["Policy", "Limitations", "Payment risks", "Source", "Help"] {
        assert!(body.contains(text), "{path}: footer must contain the {text:?} link text (§15 footer)");
    }
    assert!(body.contains("Version"), "{path}: footer must contain the Version marker (§15 footer)");
    for bad in ["<script", "<link", "src=\"http", "href=\"http", "@import", "javascript:", "onclick", "onload"] {
        assert!(
            !lower.contains(bad),
            "{path}: body must not contain {bad:?} (L1: no JavaScript; L2: no external requests)"
        );
    }
}

#[tokio::test]
async fn http_anonymous_pages_all_carry_the_shell_and_no_forbidden_markup() {
    let app = test_router().await;
    for path in ANON_PAGES {
        let (status, ctype, body) = get(&app, path).await;
        assert_eq!(status, 200, "anonymous GET {path} must return 200");
        assert!(ctype.contains("text/html"), "GET {path} must be text/html, got {ctype:?}");
        assert_shell(path, &body);
    }
}

#[tokio::test]
async fn http_limitations_page_names_the_instance_network_stagenet() {
    let app = test_router().await;
    let (status, _ctype, body) = get(&app, "/limitations").await;
    assert_eq!(status, 200);
    assert!(
        body.contains("stagenet"),
        "/limitations must name this instance's actual network, stagenet (brief L4 / §15)"
    );
}

#[tokio::test]
async fn http_payment_risks_page_uses_honest_v1_copy_and_says_no_escrow() {
    let app = test_router().await;
    let (status, _ctype, body) = get(&app, "/payment-risks").await;
    assert_eq!(status, 200);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("seller confirmed payment") || lower.contains("sellers confirm"),
        "/payment-risks must tell the honest v1 story: sellers confirm payment themselves (brief L4)"
    );
    assert!(lower.contains("no escrow"), "/payment-risks must state plainly that there is no escrow (brief L4)");
}

#[tokio::test]
async fn http_source_page_in_default_config_has_no_external_links() {
    // The default test instance has no SOURCE_URL configured, so the
    // AGPL /source page must not emit any external href/src at all.
    let app = test_router().await;
    let (status, _ctype, body) = get(&app, "/source").await;
    assert_eq!(status, 200);
    let lower = body.to_lowercase();
    assert!(!lower.contains("href=\"http"), "/source must have no external href without SOURCE_URL");
    assert!(!lower.contains("href='http"), "/source must have no external href without SOURCE_URL");
    assert!(!lower.contains("src=\"http"), "/source must have no external src");
    assert!(!lower.contains("src='http"), "/source must have no external src");
}

// =====================================================================
// Deploy tooling — file scans (brief §4; paths relative to this
// package: ../../deploy/... and ../../crates/app/templates)
// =====================================================================

fn marketplace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn deploy_file(name: &str) -> PathBuf {
    marketplace_root().join("deploy").join(name)
}
fn read_contract_file(path: &PathBuf, what: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{what} must exist at {}: {e}", path.display()))
}
fn has_assignment(content: &str, key: &str, value: &str) -> bool {
    content
        .lines()
        .any(|l| l.trim() == format!("{key}={value}"))
}

#[test]
fn file_env_demo_template_is_stagenet_demo_with_sheet_defaults() {
    let path = deploy_file("env.demo.template");
    let content = read_contract_file(&path, "env.demo.template");
    assert!(
        has_assignment(&content, "INSTANCE_NETWORK", "stagenet"),
        "demo env template must select stagenet (owner decision: the demo is stagenet)"
    );
    assert!(
        !content.lines().any(|l| l.trim_start().starts_with("INSTANCE_NETWORK=mainnet")),
        "no line may set INSTANCE_NETWORK=mainnet (the word may appear in comments only)"
    );
    assert!(
        has_assignment(&content, "DEPLOY_PROFILE", "demo"),
        "demo env template must select the demo profile"
    );
    // PRE-MAINNET-CONFIRMATION-SHEET §2 defaults, pinned verbatim.
    for (k, v) in [
        ("PAYMENTS_MAX_BATCH", "100"),
        ("PAYMENTS_UNPAID_EXPIRY_HOURS", "48"),
        ("PAYMENTS_OPEN_UNPAID_CAP", "3"),
        ("PAYMENTS_ORDER_RATE_PER_HOUR", "10"),
    ] {
        assert!(has_assignment(&content, k, v), "env.demo.template must carry the sheet default {k}={v}");
    }
}

#[test]
fn file_env_demo_template_contains_no_real_secrets() {
    let path = deploy_file("env.demo.template");
    let content = read_contract_file(&path, "env.demo.template");
    // No 64-char hex string anywhere: no key, hash, or token material
    // may ship in a template.
    let mut run = 0usize;
    let mut longest = 0usize;
    for ch in content.chars() {
        if ch.is_ascii_hexdigit() {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    assert!(longest < 64, "env.demo.template must contain no 64-char hex string (found a run of {longest})");
    // Every secret-looking assignment is a CHANGE-ME-style placeholder.
    // KEY_FILE_PATH is a path, not a secret, and *_PATH values in
    // general are locations, not credentials.
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some(eq) = line.find('=') else { continue };
        let key = line[..eq].trim().to_ascii_uppercase();
        let value = line[eq + 1..].trim().trim_matches(|c| c == '"' || c == '\'');
        let secretish = (key.contains("PASSWORD") || key.contains("SECRET") || key.contains("TOKEN")
            || key.contains("KEY"))
            && !key.contains("PATH");
        if secretish {
            assert!(
                value.to_ascii_uppercase().contains("CHANGE"),
                "{key} in env.demo.template must be a CHANGE-ME-style placeholder, got {value:?}"
            );
        }
        if key.contains("PASSWORD") {
            assert!(
                value.to_ascii_uppercase().contains("CHANGE"),
                "any PASSWORD value must be a CHANGE-ME placeholder, got {value:?}"
            );
        }
    }
}

#[test]
fn file_deploy_demo_script_fails_fast_and_refuses_mainnet() {
    let path = deploy_file("deploy-demo.sh");
    let content = read_contract_file(&path, "deploy-demo.sh");
    assert!(content.contains("set -e"), "deploy-demo.sh must fail fast (set -e)");
    assert!(content.contains("INSTANCE_NETWORK"), "deploy-demo.sh must inspect INSTANCE_NETWORK");
    assert!(content.contains("stagenet"), "deploy-demo.sh is stagenet tooling (the demo is stagenet-only)");
    assert!(
        content.contains("mainnet"),
        "deploy-demo.sh must refuse to run when the env file selects mainnet (brief §4, defence in depth behind R3/R4)"
    );
}

#[test]
fn file_systemd_unit_loads_an_environment_file() {
    let path = deploy_file("marketplace-demo.service");
    let content = read_contract_file(&path, "marketplace-demo.service");
    assert!(content.contains("EnvironmentFile"), "the systemd unit must load its EnvironmentFile");
}

#[test]
fn file_deploy_runbook_covers_backup_and_restore() {
    let path = deploy_file("DEPLOY-DEMO-RUNBOOK.md");
    let content = read_contract_file(&path, "DEPLOY-DEMO-RUNBOOK.md").to_lowercase();
    assert!(content.contains("backup"), "the runbook must cover backup");
    assert!(content.contains("restore"), "the runbook must cover restore (tested restore, §19 operations)");
}

#[test]
fn file_templates_contain_no_scripts_external_assets_or_imports() {
    let dir = marketplace_root().join("crates/app/templates");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("templates dir must exist at {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "html").unwrap_or(false))
        .collect();
    files.sort();
    assert!(
        files.len() >= 18,
        "brief L5: all 18 existing templates are rendered through the shell; found only {} .html templates",
        files.len()
    );
    for f in &files {
        let lower = std::fs::read_to_string(f)
            .unwrap_or_else(|e| panic!("read template {}: {e}", f.display()))
            .to_lowercase();
        for bad in ["<script", "<link", "src=\"http", "href=\"http", "src='http", "href='http", "@import"] {
            assert!(
                !lower.contains(bad),
                "template {} must not contain {bad:?} (L1/L2; plain-text https in copy is data — only attribute contexts are scanned)",
                f.display()
            );
        }
    }
}
