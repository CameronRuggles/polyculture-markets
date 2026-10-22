//! HT H1 audit fix task 5 (finding F7): the canonical terms text
//! the buyer's helper needs for §14 check 3 was served NOWHERE —
//! the one download carried the statement + signature but not the
//! text whose hash the statement binds, so check 3 could never
//! pass from what the site serves.
//!
//! The fix serves the three parts as three separate GET resources
//! (statement / signature / text), gated exactly like the combined
//! download. This test downloads all three for a published listing
//! and runs the buyer helper's REAL §14 verify
//! (`helper_core::verify::verify_assignment` — the function
//! `helper buyer verify` calls) against an assignment built on
//! exactly those downloaded files. The CLI-side half of the
//! acceptance (the binary accepting files of these shapes) is
//! covered by helper-cli/tests/cli_ht.rs; the §14 function is the
//! shared core of both.
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
const CSRF: &str = "htfiles-csrf";
const SUB: &str =
    "75VjEqDg5fp7hyErNLsyRK59sHRJjLX3fTvARvKvGodj5PPajrWjmyQ2mvuPWWMWi4HNS5jg4jvyYLREvx63KZe4HK7sbH8";

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

struct Fixture {
    seller_id: i64,
    listing_internal: i64,
    listing_public: String,
    seller_secret: Vec<u8>,
    seller_cert: Vec<u8>,
    seller_fpr: String,
}

async fn fixture(pool: &PgPool) -> Fixture {
    let (seller_secret, seller_cert) = generate_test_cert("HT Files Seller <files@example.org>");
    let seller_fpr = fingerprint_of(&seller_cert);
    let public_id = app::db::public_id("acct_");
    let username = format!("htf{}", uniq());
    let (seller_id,): (i64,) = sqlx::query_as(
        "INSERT INTO accounts (public_id, username, password_hash, role, created_at)
         VALUES ($1, $2, 'ht-terms-files-fixture-hash', 'seller', now()) RETURNING id",
    )
    .bind(&public_id)
    .bind(&username)
    .fetch_one(pool)
    .await
    .expect("insert account");
    let cert_text = String::from_utf8(seller_cert.clone()).expect("cert armor is UTF-8");
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
        t ^ ((std::process::id() as u128) << 64) ^ (seller_id as u128) ^ 0xF11E5u128
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
        seller_cert,
        seller_fpr,
    }
}

impl Fixture {
    async fn signed_terms(&self, pool: &PgPool) -> (String, String, String) {
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
        (String::from_utf8(bytes).expect("statement is UTF-8"), sig, text)
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

struct TestServer {
    addr: std::net::SocketAddr,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}

async fn test_server(pool: &PgPool) -> TestServer {
    let mut dir = std::env::temp_dir();
    dir.push(format!("htfiles-http-{}-{}", std::process::id(), uniq()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("test.key");
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

fn split_response(raw: Vec<u8>) -> HttpResult {
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

async fn http_get(addr: std::net::SocketAddr, path: &str, cookie: Option<&str>) -> HttpResult {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let cookie_line = cookie.map(|c| format!("Cookie: {c}\r\n")).unwrap_or_default();
    let req = format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n{cookie_line}\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    split_response(raw)
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
    split_response(raw)
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

// ---------------------------------------------------------------------------
// The F7 acceptance test.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn terms_files_download_and_buyer_verify_accepts_them() {
    let Some(pool) = pool().await else { return };
    let fx = fixture(&pool).await;
    let (statement, signature, text) = fx.signed_terms(&pool).await;
    let token = session_for(&pool, fx.seller_id).await;
    let server = test_server(&pool).await;
    let base = format!("/listings/{}/terms", fx.listing_public);

    // Pin the terms through the real route (listing still draft).
    let res = http_post_form(
        server.addr,
        &base,
        &format!("session={token}"),
        &[("csrf", CSRF), ("statement", &statement), ("signature", &signature)],
    )
    .await;
    assert_eq!(res.status, 303, "pin redirect expected, body: {}", res.body);
    assert!(
        res.headers.to_lowercase().contains("location: /seller?pmsg=terms_saved"),
        "headers: {}",
        res.headers
    );

    // Gating while draft: anonymous gets 404 on every part (and on
    // the combined download); the owner gets 200.
    for part in ["statement", "signature", "text"] {
        let res = http_get(server.addr, &format!("{base}/{part}"), None).await;
        assert_eq!(res.status, 404, "draft listing part {part} must 404 anonymously");
    }
    let res = http_get(server.addr, &base, None).await;
    assert_eq!(res.status, 404, "draft listing combined download must 404 anonymously");
    let owner_cookie = format!("session={token}");
    let res = http_get(server.addr, &format!("{base}/text"), Some(&owner_cookie)).await;
    assert_eq!(res.status, 200, "owner can read a draft listing's terms text");
    assert_eq!(res.body, text);

    // Publish (the download gate reads only the status column; the
    // publish-path gates are covered by their own suites).
    sqlx::query("UPDATE listings SET status = 'published' WHERE id = $1")
        .bind(fx.listing_internal)
        .execute(&pool)
        .await
        .expect("publish listing");

    // The three resources, anonymously, byte-exact.
    let stmt_dl = http_get(server.addr, &format!("{base}/statement"), None).await;
    assert_eq!(stmt_dl.status, 200, "statement: {}", stmt_dl.body);
    assert_eq!(stmt_dl.body, statement);
    let sig_dl = http_get(server.addr, &format!("{base}/signature"), None).await;
    assert_eq!(sig_dl.status, 200);
    assert_eq!(sig_dl.body, signature);
    let text_dl = http_get(server.addr, &format!("{base}/text"), None).await;
    assert_eq!(text_dl.status, 200);
    assert_eq!(text_dl.body, text);
    // The combined download still serves statement + signature.
    let combined = http_get(server.addr, &base, None).await;
    assert_eq!(combined.status, 200);
    assert_eq!(combined.body, format!("{statement}{signature}"));

    // The check-3 chain over the DOWNLOADED bytes: the statement
    // parses under the instance id, the text hashes to the digest
    // the statement binds, and the signature verifies against the
    // seller's key.
    let parsed = hs::parse_terms_statement(&stmt_dl.body, MKT).expect("downloaded statement parses");
    assert_eq!(hs::sha256_hex(text_dl.body.as_bytes()), parsed.terms_sha256);
    assert!(helper_core::keys::verify_detached(
        &fx.seller_cert,
        stmt_dl.body.as_bytes(),
        sig_dl.body.as_bytes(),
    ));

    // A §14 verify of an assignment built against exactly these
    // files — the buyer's real check, end to end.
    let (buyer_secret, buyer_cert) =
        helper_core::keys::generate_test_cert("HT Files Buyer <buyer@example.org>")
            .expect("buyer key");
    let _ = &buyer_secret;
    let buyer_fpr = helper_core::keys::fingerprint_of(&buyer_cert).expect("buyer fpr");
    let fmt = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    let expires_at = (time::OffsetDateTime::now_utc() + time::Duration::days(30))
        .format(&fmt)
        .expect("format expiry");
    let assignment = hs::AssignmentStatement {
        marketplace_id: MKT.into(),
        network: modules_api::Network::Stagenet,
        seller_key_fingerprint: fx.seller_fpr.clone(),
        buyer_key_fingerprint: buyer_fpr.clone(),
        terms_statement_sha256: hs::terms_statement_sha256(stmt_dl.body.as_bytes()),
        destination: modules_api::Subaddress::validate(SUB, modules_api::Network::Stagenet)
            .expect("fixture subaddress"),
        amount_atomic: 250_000_000_000,
        payment_timing: hs::PaymentTiming::Prepay,
        expires_at,
        nonce: "0123456789abcdef0123456789abcdef".into(),
    };
    let assignment_bytes = assignment.to_bytes();
    // Sign through helper-core so the verify below exercises the
    // shipped pair (sign in helper-core, verify in helper-core).
    let assignment_sig =
        helper_core::keys::sign_detached(&fx.seller_secret, None, &assignment_bytes)
            .expect("sign assignment");
    let verified = helper_core::verify::verify_assignment(&helper_core::verify::VerifyInputs {
        assignment: assignment_bytes.clone(),
        assignment_sig,
        seller_cert: fx.seller_cert.clone(),
        own_fingerprint: buyer_fpr,
        marketplace_id: MKT.into(),
        network: modules_api::Network::Stagenet,
        terms_statement: stmt_dl.body.clone().into_bytes(),
        terms_sig: sig_dl.body.clone(),
        terms_text: text_dl.body.clone(),
        now: helper_core::now_canonical(),
        ceiling: None,
    });
    let verified = verified.expect("§14 verify accepts an assignment against the downloaded files");
    assert_eq!(verified.trade_id, hs::trade_id(&assignment_bytes));

    server.stop();
    cleanup(&pool, &fx).await;
}

#[tokio::test]
async fn terms_files_404_without_pin_and_for_unknown_listing() {
    let Some(pool) = pool().await else { return };
    let fx = fixture(&pool).await;
    let server = test_server(&pool).await;
    // Published but never pinned: every part 404s.
    sqlx::query("UPDATE listings SET status = 'published' WHERE id = $1")
        .bind(fx.listing_internal)
        .execute(&pool)
        .await
        .expect("publish listing");
    for part in ["statement", "signature", "text"] {
        let res = http_get(
            server.addr,
            &format!("/listings/{}/terms/{part}", fx.listing_public),
            None,
        )
        .await;
        assert_eq!(res.status, 404, "unpinned listing part {part} must 404");
    }
    // Unknown listing: 404.
    let res = http_get(
        server.addr,
        "/listings/lst_00000000000000000000000000000099/terms/text",
        None,
    )
    .await;
    assert_eq!(res.status, 404, "unknown listing must 404");

    server.stop();
    cleanup(&pool, &fx).await;
}
