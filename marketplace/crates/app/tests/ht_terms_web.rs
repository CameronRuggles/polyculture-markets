//! HT H1 audit fix task 1 (finding F2): the signed-terms web form
//! must accept what a browser actually submits.
//!
//! Browsers submit textarea content with CRLF line endings. The
//! terms statement parser admits LF only and verifies byte-exact, so
//! `terms_submit` normalises CRLF at the handler boundary (the MH1
//! pattern every other paste handler already followed). This test
//! drives the real route — POST /listings/{id}/terms through the
//! real router over a real socket — with a valid statement and
//! signature whose line endings are CRLF throughout, and asserts the
//! `terms_saved` redirect and exactly one pinned row.
//!
//! Scope note (audit F1): when this test was written, the
//! marketplace id a default-configured instance handed this
//! handler was still the v1 slug, which the statement family's
//! `mkt_` rule refuses. Fix task 2 has since given the instance a
//! real `mkt_` id of its own; this test pins its instance's HT id
//! to the same fixed id the fixture signs against (the id the
//! blind_ht1 router uses) so it continues to isolate the CRLF
//! behaviour alone. The default-instance path — resolution minting
//! the id, the handler using it — has its own test
//! (ht_terms_default_instance.rs).
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

const MKT: &str = "mkt_0123456789abcdef0123456789abcdef";
const CSRF: &str = "htterms-csrf";

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
// helper-core's test-key construction: the seller's key must be a
// real key the app layer accepts and can verify against.
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
// Fixture: seller account + installed key + draft listing, all through
// the app layer / the same row shapes the blind suite uses.
// ---------------------------------------------------------------------------

struct Fixture {
    seller_id: i64,
    listing_internal: i64,
    listing_public: String,
    seller_secret: Vec<u8>,
    seller_fpr: String,
}

async fn fixture(pool: &PgPool) -> Fixture {
    let (seller_secret, seller_cert) = generate_test_cert("HT Web Seller <web@example.org>");
    let seller_fpr = fingerprint_of(&seller_cert);
    let public_id = app::db::public_id("acct_");
    let username = format!("htw{}", uniq());
    let (seller_id,): (i64,) = sqlx::query_as(
        "INSERT INTO accounts (public_id, username, password_hash, role, created_at)
         VALUES ($1, $2, 'ht-terms-web-fixture-hash', 'seller', now()) RETURNING id",
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
         VALUES ($1, $2, 'HT Widget', 'A widget.', 250000000000, 'xmr-only',
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
    /// fixture listing's current text, LF line endings.
    async fn signed_terms(&self, pool: &PgPool) -> (String, String) {
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
            marketplace_id: MKT.into(),
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

// ---------------------------------------------------------------------------
// HTTP plumbing (the messaging_audit raw-socket pattern).
// ---------------------------------------------------------------------------

struct TestServer {
    addr: std::net::SocketAddr,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}

async fn test_server(pool: &PgPool) -> TestServer {
    let mut dir = std::env::temp_dir();
    dir.push(format!("htterms-http-{}-{}", std::process::id(), uniq()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("test.key");
    // Fix task 2: the handler verifies against the instance's HT
    // id; pin it to the fixture's id (see the scope note above).
    let mut instance = app::config::InstanceConfig::resolve(&|_| None).expect("empty env resolves");
    instance.ht_marketplace_id = MKT.into();
    let state = AppState {
        pool: pool.clone(),
        hash_guard: app::passwords::HashGuard::new(4),
        throttles: Arc::new(app::throttle::Throttles::new()),
        registrations_open: true,
        account_cap: None,
        dev_cookies: true,
        media: app::media::MediaPipeline::from_env(),
        marketplace_id: MKT.into(),
        payments: PaymentConfig::defaults(MKT),
        keyfile: Arc::new(app::keyfile::KeyFile::load_or_generate(&key_path).expect("key file")),
        stage9: app::reputation::Stage9Config::defaults(),
        retention: app::retention::RetentionConfig::defaults(),
        instance,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    TestServer { addr, handle, dir }
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
// The F2 regression test.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn terms_submit_accepts_browser_crlf() {
    let Some(pool) = pool().await else { return };
    let fx = fixture(&pool).await;
    let (statement, signature) = fx.signed_terms(&pool).await;
    let token = session_for(&pool, fx.seller_id).await;
    let server = test_server(&pool).await;

    // Exactly what a browser pastes: the same valid statement and
    // signature, every line ending CRLF.
    let res = http_post_form(
        server.addr,
        &format!("/listings/{}/terms", fx.listing_public),
        &format!("session={token}"),
        &[
            ("csrf", CSRF),
            ("statement", &crlf(&statement)),
            ("signature", &crlf(&signature)),
        ],
    )
    .await;
    assert_eq!(res.status, 303, "expected the terms redirect, body: {}", res.body);
    assert!(
        res.headers.to_lowercase().contains("location: /seller?pmsg=terms_saved"),
        "expected the terms_saved redirect, headers: {}",
        res.headers
    );

    let (count,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM listing_terms_statements WHERE listing_id = $1")
            .bind(fx.listing_internal)
            .fetch_one(&pool)
            .await
            .expect("count pinned terms");
    assert_eq!(count, 1, "exactly one pinned terms row");

    // What is stored is the normalised (LF) text — the exact bytes
    // that were verified.
    let (stored,): (String,) =
        sqlx::query_as("SELECT statement FROM listing_terms_statements WHERE listing_id = $1")
            .bind(fx.listing_internal)
            .fetch_one(&pool)
            .await
            .expect("load pinned statement");
    assert_eq!(stored, statement);
    assert!(!stored.contains('\r'));

    server.stop();
    cleanup(&pool, &fx).await;
}
