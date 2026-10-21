//! HT H1 audit fix task 2 (finding F1): on a DEFAULT-configured
//! instance, signed terms must pin end to end through the real web
//! form.
//!
//! F1 was that the app had no `mkt_` marketplace id at all: the only
//! id it produced was the v1 slug (`vespiary-market`), which the HT
//! statement family's `mkt_` rule refuses, so every terms
//! submission on a default instance was rejected as Malformed and
//! the publish gate blocked all new publishing. The task-1 test
//! (ht_terms_web.rs) isolated the CRLF half by configuring its
//! AppState with a hand-written `mkt_` id; this test is the other
//! half. It builds its AppState exactly as main.rs does —
//! `InstanceConfig::resolve` with an empty environment, the v1 slug
//! flowing to the payments side untouched — and signs the terms
//! statement against whatever id resolution minted. No marketplace
//! id VALUE of either family appears as a literal anywhere in this
//! file: the ids under test come from the resolved config alone
//! (the family prefix appears once, in a shape assertion).
//!
//! Assertions, in order:
//! 1. The resolved HT id is shaped as the statement family demands
//!    (36 chars: prefix + 32 hex) and is NOT the v1 slug.
//! 2. A statement naming the v1 SLUG is refused by the POST route
//!    (terms_rejected, no row) — the handler no longer verifies HT
//!    statements against the slug.
//! 3. The same statement naming the resolved HT id, submitted with
//!    browser CRLF line endings, is accepted (terms_saved) and
//!    pins exactly one row, whose stored bytes name the HT id and
//!    parse under it — and do not parse under the slug.
//!
//! DB tests require DATABASE_URL; skipped silently when unset, and
//! the pool helper panics when it is set but unreachable (fix task
//! 3b — a gate run must never pass without a database).

use app::payments::PaymentConfig;
use app::web::{router, AppState};
use domain::ht_statements as hs;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::io::Write as _;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CSRF: &str = "htdefault-csrf";

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

// ---------------------------------------------------------------------------
// Throwaway OpenPGP cert + detached signing (Sequoia), mirroring
// ht_terms_web.rs: the seller's key must be a real key the app
// layer accepts and can verify against.
// ---------------------------------------------------------------------------

fn generate_test_cert(user_id: &str) -> (Vec<u8>, Vec<u8>) {
    use sequoia_openpgp::armor::Kind as ArmorKind;
    use sequoia_openpgp::cert::prelude::*;
    use sequoia_openpgp::serialize::Marshal;
    let (cert, _rev) = CertBuilder::new()
        .add_userid(user_id)
        .add_signing_subkey()
        .add_storage_encryption_subkey()
        .add_transport_encryption_subkey()
        .generate()
        .expect("generate test cert");
    fn armor(kind: ArmorKind, bytes: &[u8]) -> Vec<u8> {
        let mut w = sequoia_openpgp::armor::Writer::new(Vec::new(), kind).expect("armor writer");
        w.write_all(bytes).expect("armor write");
        w.finalize().expect("armor finalize")
    }
    let mut secret = Vec::new();
    cert.as_tsk().serialize(&mut secret).expect("serialize secret");
    let mut public = Vec::new();
    cert.serialize(&mut public).expect("serialize public");
    (
        armor(ArmorKind::SecretKey, &secret),
        armor(ArmorKind::PublicKey, &public),
    )
}

fn fingerprint_of(cert_bytes: &[u8]) -> String {
    use sequoia_openpgp::parse::Parse;
    let cert = sequoia_openpgp::Cert::from_bytes(cert_bytes).expect("parse cert");
    cert.fingerprint().to_hex()
}

fn sign_detached(secret_cert_bytes: &[u8], message: &[u8]) -> String {
    use sequoia_openpgp::armor::Kind as ArmorKind;
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::policy::StandardPolicy;
    use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer};
    let cert = sequoia_openpgp::Cert::from_bytes(secret_cert_bytes).expect("parse secret cert");
    assert!(cert.is_tsk(), "secret cert carries secret material");
    let policy = StandardPolicy::new();
    let mut keypair = None;
    for ka in cert.keys().with_policy(&policy, None).secret().for_signing() {
        let key = ka.key().clone();
        assert!(!key.secret().is_encrypted(), "test key is unencrypted");
        if let Ok(kp) = key.into_keypair() {
            keypair = Some(kp);
            break;
        }
    }
    let keypair = keypair.expect("usable signing key");
    let mut sink = Vec::new();
    {
        let message_writer = Message::new(&mut sink);
        let message_writer = Armorer::new(message_writer)
            .kind(ArmorKind::Signature)
            .build()
            .expect("armorer");
        let mut signer = Signer::new(message_writer, keypair)
            .expect("signer")
            .detached()
            .build()
            .expect("detached signer");
        signer.write_all(message).expect("sign write");
        signer.finalize().expect("sign finalize");
    }
    String::from_utf8(sink).expect("signature armor is UTF-8")
}

// ---------------------------------------------------------------------------
// Fixture: seller account + installed key + draft listing.
// ---------------------------------------------------------------------------

struct Fixture {
    seller_id: i64,
    listing_internal: i64,
    listing_public: String,
    seller_secret: Vec<u8>,
    seller_fpr: String,
}

async fn fixture(pool: &PgPool) -> Fixture {
    let (seller_secret, seller_cert) = generate_test_cert("HT Default Seller <default@example.org>");
    let seller_fpr = fingerprint_of(&seller_cert);
    let public_id = app::db::public_id("acct_");
    let username = format!("htd{}", uniq());
    let (seller_id,): (i64,) = sqlx::query_as(
        "INSERT INTO accounts (public_id, username, password_hash, role, created_at)
         VALUES ($1, $2, 'ht-terms-default-fixture-hash', 'seller', now()) RETURNING id",
    )
    .bind(&public_id)
    .bind(&username)
    .fetch_one(pool)
    .await
    .expect("insert account");
    let cert_text = String::from_utf8(seller_cert).expect("cert armor is UTF-8");
    let info = app::keys::validate_cert(cert_text.as_bytes()).expect("test cert must validate");
    assert_eq!(info.fingerprint, seller_fpr);
    app::keys::install_key(pool, seller_id, cert_text.as_bytes(), &info, None)
        .await
        .expect("install seller key");
    let listing_public = format!("lst_{:032x}", {
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
         VALUES ($1, $2, 'HT Default Widget', 'A widget.', 250000000000, 'xmr-only',
                 'signed-address-pool', false, 'draft', 'Ships in 3 days.',
                 'Refunds per the cap.') RETURNING id",
    )
    .bind(&listing_public)
    .bind(seller_id)
    .fetch_one(pool)
    .await
    .expect("insert listing");
    Fixture {
        seller_id,
        listing_internal: row.get("id"),
        listing_public,
        seller_secret,
        seller_fpr,
    }
}

impl Fixture {
    /// A valid v1 terms statement + detached signature over the
    /// fixture listing's current text, naming `marketplace_id`
    /// (supplied by the caller from the resolved config — never a
    /// literal in this file), LF line endings.
    async fn signed_terms(&self, pool: &PgPool, marketplace_id: &str) -> (String, String) {
        let listing = app::listings::listing_by_public_id(pool, &self.listing_public)
            .await
            .expect("load listing")
            .expect("listing exists");
        let row = sqlx::query("SELECT delivery_terms, refund_terms FROM listings WHERE id = $1")
            .bind(self.listing_internal)
            .fetch_one(pool)
            .await
            .expect("listing terms row");
        let delivery: String = row.get("delivery_terms");
        let refund: String = row.get("refund_terms");
        let text = hs::listing_terms_text(
            &listing.title,
            &listing.description,
            &delivery,
            &refund,
            listing.price_atomic as u64,
        );
        let stmt = hs::TermsStatement {
            marketplace_id: marketplace_id.into(),
            listing_id: self.listing_public.clone(),
            listing_version: 1,
            seller_key_fingerprint: self.seller_fpr.clone(),
            terms_sha256: hs::sha256_hex(text.as_bytes()),
            risk: hs::RiskTerms {
                transit_risk: hs::TransitRisk::Seller,
                remedy_cap_pct: 25,
                payment_timing: hs::PaymentTiming::Prepay,
            },
        };
        let bytes = stmt.to_bytes();
        let sig = sign_detached(&self.seller_secret, &bytes);
        (String::from_utf8(bytes).expect("statement is UTF-8"), sig)
    }
}

async fn session_for(pool: &PgPool, account_id: i64) -> String {
    let token = app::sessions::new_token();
    let now = time::OffsetDateTime::now_utc();
    let sess = app::sessions::Session::fresh(account_id, now);
    app::db::create_session(pool, &token, CSRF, &sess)
        .await
        .expect("create session");
    token
}

async fn cleanup(pool: &PgPool, fx: &Fixture) {
    for q in [
        "DELETE FROM listing_terms_statements WHERE listing_id = $1",
        "DELETE FROM listings WHERE id = $1",
    ] {
        let _ = sqlx::query(q).bind(fx.listing_internal).execute(pool).await;
    }
    for q in [
        "DELETE FROM session_csrf WHERE token_hash IN (SELECT token_hash FROM sessions WHERE account_id = $1)",
        "DELETE FROM sessions WHERE account_id = $1",
        "DELETE FROM identity_keys WHERE account_id = $1",
        "DELETE FROM accounts WHERE id = $1",
    ] {
        let _ = sqlx::query(q).bind(fx.seller_id).execute(pool).await;
    }
}

async fn pinned_count(pool: &PgPool, fx: &Fixture) -> i64 {
    let (count,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM listing_terms_statements WHERE listing_id = $1")
            .bind(fx.listing_internal)
            .fetch_one(pool)
            .await
            .expect("count pinned terms");
    count
}

// ---------------------------------------------------------------------------
// HTTP plumbing (the messaging_audit raw-socket pattern).
// ---------------------------------------------------------------------------

struct TestServer {
    addr: std::net::SocketAddr,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}

/// Build the server the way main.rs does: the instance is resolved
/// from an empty environment (all defaults), and the resolved slug
/// flows to the payments side untouched. Returns the server and the
/// resolved config, so the test can sign against the config's own
/// HT id.
async fn test_server(pool: &PgPool) -> (TestServer, app::config::InstanceConfig) {
    let mut dir = std::env::temp_dir();
    dir.push(format!("htdefault-http-{}-{}", std::process::id(), uniq()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("test.key");
    let instance = app::config::InstanceConfig::resolve(&|_| None).expect("empty env resolves");
    let state = AppState {
        pool: pool.clone(),
        hash_guard: app::passwords::HashGuard::new(4),
        throttles: Arc::new(app::throttle::Throttles::new()),
        registrations_open: true,
        account_cap: None,
        dev_cookies: true,
        media: app::media::MediaPipeline::from_env(),
        marketplace_id: instance.marketplace_id.clone(),
        payments: PaymentConfig::defaults(&instance.marketplace_id),
        keyfile: Arc::new(app::keyfile::KeyFile::load_or_generate(&key_path).expect("key file")),
        stage9: app::reputation::Stage9Config::defaults(),
        retention: app::retention::RetentionConfig::defaults(),
        instance: instance.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    (TestServer { addr, handle, dir }, instance)
}

impl TestServer {
    fn stop(self) {
        self.handle.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct HttpResult {
    status: u16,
    headers: String,
    body: String,
}

async fn http_post_form(
    addr: std::net::SocketAddr,
    path: &str,
    cookie_header: &str,
    fields: &[(&str, &str)],
) -> HttpResult {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\nCookie: {cookie_header}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    s.write_all(body.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .expect("status line parses");
    let (headers, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h.to_string(), b.to_string()),
        None => (text.clone(), String::new()),
    };
    HttpResult { status, headers, body }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn crlf(s: &str) -> String {
    s.replace('\n', "\r\n")
}

// ---------------------------------------------------------------------------
// The F1 acceptance test.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn terms_submit_on_default_instance_uses_the_minted_ht_id() {
    let Some(pool) = pool().await else { return };
    let fx = fixture(&pool).await;
    let (server, instance) = test_server(&pool).await;
    let ht_id = instance.ht_marketplace_id.clone();
    let slug = instance.marketplace_id.clone();

    // (1) The minted id has the statement family's shape and is a
    // different identity from the v1 slug.
    assert_eq!(ht_id.len(), 36, "an mkt_ id is prefix + 32 hex chars: {ht_id}");
    assert!(ht_id.starts_with("mkt_"), "the HT id uses the mkt_ family: {ht_id}");
    assert_ne!(ht_id, slug, "the HT identity is not the v1 slug");

    let token = session_for(&pool, fx.seller_id).await;
    let cookie = format!("session={token}");
    let path = format!("/listings/{}/terms", fx.listing_public);

    // (2) A statement naming the v1 slug — the only id a default
    // instance could produce before this fix — is refused, and
    // nothing is pinned.
    let (stmt, sig) = fx.signed_terms(&pool, &slug).await;
    let res = http_post_form(
        server.addr,
        &path,
        &cookie,
        &[("csrf", CSRF), ("statement", &crlf(&stmt)), ("signature", &crlf(&sig))],
    )
    .await;
    assert_eq!(res.status, 303, "expected the terms redirect, body: {}", res.body);
    assert!(
        res.headers.to_lowercase().contains("location: /seller?pmsg=terms_rejected"),
        "a slug-named statement must be rejected, headers: {}",
        res.headers
    );
    assert_eq!(pinned_count(&pool, &fx).await, 0, "a rejected submission pins nothing");

    // (3) The same statement naming the instance's minted HT id is
    // accepted and pins exactly one row.
    let (stmt, sig) = fx.signed_terms(&pool, &ht_id).await;
    let res = http_post_form(
        server.addr,
        &path,
        &cookie,
        &[("csrf", CSRF), ("statement", &crlf(&stmt)), ("signature", &crlf(&sig))],
    )
    .await;
    assert_eq!(res.status, 303, "expected the terms redirect, body: {}", res.body);
    assert!(
        res.headers.to_lowercase().contains("location: /seller?pmsg=terms_saved"),
        "expected the terms_saved redirect, headers: {}",
        res.headers
    );
    assert_eq!(pinned_count(&pool, &fx).await, 1, "exactly one pinned terms row");

    // The stored bytes name the HT id, parse under it, and do not
    // parse under the slug: the two identities are not
    // interchangeable anywhere on the path.
    let (stored,): (String,) =
        sqlx::query_as("SELECT statement FROM listing_terms_statements WHERE listing_id = $1")
            .bind(fx.listing_internal)
            .fetch_one(&pool)
            .await
            .expect("load pinned statement");
    assert_eq!(stored, stmt);
    assert!(hs::parse_terms_statement(&stored, &ht_id).is_some());
    assert!(hs::parse_terms_statement(&stored, &slug).is_none());

    server.stop();
    cleanup(&pool, &fx).await;
}
