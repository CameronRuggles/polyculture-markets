//! Messaging Audit fix brief — acceptance tests (2026-10-19).
//!
//! Written against the brief's own acceptance criteria:
//!
//! 0. Real-client fixtures: messages produced by GnuPG 2.4.4 (see
//!    tests/fixtures/gpg/README.md), submitted through the HTTP form
//!    with CRLF line endings the way a browser sends them. Every
//!    fixture valid under the encryption guide must be accepted.
//! 1. CRLF→LF on every armored input (message, rotation statement,
//!    signatures, disclosure).
//! 2. Partial body lengths accepted on the final encrypted-data
//!    packet (the GnuPG fixtures above carry them); >64 KiB refused.
//! 3. Disclosure by `gpg --unwrap --armor` paste: the unwrapped
//!    signed message counts as evidence; an unsigned one is an
//!    unverified claim.
//! 4. The conversation page's example signs; the guide's size limit
//!    equals the code's.
//! 5. Recipient matching only against alive, encryption-capable
//!    subkeys (a message to a revoked subkey is WrongRecipient);
//!    same-fingerprint certificate refresh accepts new signatures
//!    only — no new key material, no different fingerprint.
//! 6. Message limits: 60 messages/minute per account, a daily byte
//!    budget, a per-conversation cap; direct-conversation blocking.
//! 7. Order conversations show the order's pinned fingerprint and
//!    warn when the current key differs (no rotation row needed).
//!
//! DB tests require DATABASE_URL (skipped silently when unset, the
//! pattern of the neighbouring suites).

use app::config::InstanceConfig;
use app::keyfile::KeyFile;
use app::media::MediaPipeline;
use app::orders::{apply_action, create_order_with_config, order_by_public_id};
use app::payments::{
    canonical_message, payment_seller_id, set_primary_address, submit_payment_proof,
    upload_batch, PaymentConfig,
};
use app::web::{router, AppState};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Real GnuPG fixtures (tests/fixtures/gpg/ — provenance in its README)
// ---------------------------------------------------------------------------

const CERT_ALICE: &str = include_str!("fixtures/gpg/cert-alice.asc");
const CERT_BOB: &str = include_str!("fixtures/gpg/cert-bob.asc");
const CERT_CAROL_V1: &str = include_str!("fixtures/gpg/cert-carol-v1.asc");
const CERT_CAROL_V2: &str = include_str!("fixtures/gpg/cert-carol-v2-revoked-subkey.asc");
const CERT_DAVE_SHORT: &str = include_str!("fixtures/gpg/cert-dave-short-expiry.asc");
const CERT_DAVE_EXTENDED: &str = include_str!("fixtures/gpg/cert-dave-extended.asc");
const CERT_DAVE_ADDED: &str = include_str!("fixtures/gpg/cert-dave-added-subkey.asc");

const ALICE_FPR: &str = "698C2CE6489C747F1458C2BF35C511FEAF38F328";
const BOB_FPR: &str = "54C8A581E49106123FB5CCBACED0A0143425A8E0";
const CAROL_FPR: &str = "346F063FB3DB1FB8EDB9F17D4065C0B2115BED30";
const DAVE_FPR: &str = "5A37E91C3A9C8A8BAAEB9503DD38B3DF073E742C";

const MSG_300_UNSIGNED: &str = include_str!("fixtures/gpg/msg-300-unsigned.asc");
const MSG_300_SIGNED: &str = include_str!("fixtures/gpg/msg-300-signed.asc");
const MSG_2K_UNSIGNED: &str = include_str!("fixtures/gpg/msg-2k-unsigned.asc");
const MSG_2K_SIGNED: &str = include_str!("fixtures/gpg/msg-2k-signed.asc");
const MSG_40K_UNSIGNED: &str = include_str!("fixtures/gpg/msg-40k-unsigned.asc");
const MSG_40K_SIGNED: &str = include_str!("fixtures/gpg/msg-40k-signed.asc");
const MSG_2K_SIGNED_BIN: &[u8] = include_bytes!("fixtures/gpg/msg-2k-signed.gpg");
const MSG_TO_CAROL_SUBKEY1: &str = include_str!("fixtures/gpg/msg-to-carol-subkey1.asc");
const UNWRAP_BOB_SIGNED: &str = include_str!("fixtures/gpg/unwrap-bob-signed.asc");
const UNWRAP_BOB_UNSIGNED: &str = include_str!("fixtures/gpg/unwrap-bob-unsigned.asc");
const DISCLOSE_PLAINTEXT: &str =
    "Bob here: your widget shipped today, tracking is in the next message.";

// Stagenet payment fixtures shared with the neighbouring suites (the
// tx_proof_flow slice of the POOL200 master set); tests in this file
// that touch payment state serialize on FIXTURE_LOCK and purge first.
const PRIMARY_A: &str = "55b6gZhKJ2b6EzvernZJBcPXiZym13w1CfbpDU6sR8aSGpaRbAmU4EMSH3XYXu5U1cSac7B49WRSSBbwQK9by3c7H9AdnFB";
const SIG: &str =
    "SigV2abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuv";
const SUBS: &[&str] = &[
    "75ecAyh9QuvfaDyaPRTVnwgc2QxjTByx2GM2haFsn8wrEu2vSVn7QctGiKQdpP5vNPeB2Fzbg8Sb78mqA22Qc2GaHdYhWsY",
    "758HazrgczGbQ4rmrAuws3CcFLEa5zGRE9abUNcVeSP3KYGuoC9mGFHcX2R4HS7qxJCmFHrPAzDDNSshrwHAQLUyUDch7xW",
    "73qWemDitUJbTzxfNhSEGi7YcTi1UYFrM1u3Ck2iL2qxhT3tY45KLk262yx58CKL81YjbyndXBjXSMXAczboytxUEvu4y7o",
    "75wgnqJyVbk2Yts13syYbzT3NLFYYFRhdU7FnD31WiKWdTtWVsRYMC9VojzbvuKSX6hzApqPqyVTbQRW61PqcJsU7Xu3hq6",
];

static FIXTURE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

fn fixture_lock() -> &'static tokio::sync::Mutex<()> {
    FIXTURE_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// The fixture certificates have globally-unique fingerprints
/// (identity_keys.fingerprint is UNIQUE), so every test in this file
/// serializes on the fixture lock and first purges any account still
/// holding a fixture key (residue from a failed earlier run).
async fn fixture_guard(pool: &PgPool) -> tokio::sync::MutexGuard<'static, ()> {
    let guard = fixture_lock().lock().await;
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT account_id FROM identity_keys WHERE fingerprint = ANY($1)",
    )
    .bind(vec![
        ALICE_FPR.to_string(),
        BOB_FPR.to_string(),
        CAROL_FPR.to_string(),
        DAVE_FPR.to_string(),
    ])
    .fetch_all(pool)
    .await
    .unwrap();
    if !ids.is_empty() {
        cleanup(pool, &ids).await;
    }
    guard
}

async fn purge_fixture_addresses(pool: &PgPool) {
    let owned: Vec<String> = SUBS.iter().map(|s| s.to_string()).collect();
    for q in [
        "DELETE FROM payment_declarations WHERE pool_entry_id IN (SELECT id FROM payment_pool_entries WHERE address = ANY($1))",
        "DELETE FROM payment_review_flags WHERE order_id IN (SELECT order_id FROM payment_pool_entries WHERE address = ANY($1) AND order_id IS NOT NULL)",
        "DELETE FROM payment_reports WHERE order_id IN (SELECT order_id FROM payment_pool_entries WHERE address = ANY($1) AND order_id IS NOT NULL)",
        "DELETE FROM payment_proofs WHERE pool_entry_id IN (SELECT id FROM payment_pool_entries WHERE address = ANY($1))",
        "DELETE FROM payment_attestations WHERE pool_entry_id IN (SELECT id FROM payment_pool_entries WHERE address = ANY($1))",
        "DELETE FROM payment_pool_entries WHERE address = ANY($1)",
        "DELETE FROM destinations WHERE address = ANY($1)",
    ] {
        sqlx::query(q).bind(&owned).execute(pool).await.expect("purge fixture addresses");
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PW: &str = "msgaudit-correct-passphrase-1";
const CSRF: &str = "msgaudit-csrf";

async fn pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Some(PgPoolOptions::new().max_connections(8).connect(&url).await.expect("DATABASE_URL is set but the database is unreachable"))
}

fn uniq() -> String {
    app::sessions::new_token()[..16].to_string()
}

fn cfg() -> PaymentConfig {
    PaymentConfig::defaults("vespiary-market")
}

/// An account with a REAL Argon2id hash of PW, backdated past the
/// new-account limits (the tx_proof_flow convention).
async fn make_account(pool: &PgPool, role: &str) -> (i64, String) {
    let hash = app::passwords::HashGuard::new(2).hash(PW).await.unwrap();
    let public_id = app::db::public_id("acct_");
    let username = format!("msg{}", uniq());
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO accounts (public_id, username, password_hash, role, created_at)
         VALUES ($1, $2, $3, $4, now() - interval '72 hours') RETURNING id",
    )
    .bind(&public_id)
    .bind(&username)
    .bind(&hash)
    .bind(role)
    .fetch_one(pool)
    .await
    .unwrap();
    (id, public_id)
}

/// Install a real certificate through the app layer (validate + store).
async fn install_cert(pool: &PgPool, account_id: i64, cert_text: &str) {
    let info = app::keys::validate_cert(cert_text.as_bytes()).expect("fixture cert must validate");
    app::keys::install_key(pool, account_id, cert_text.as_bytes(), &info, None)
        .await
        .expect("install fixture cert");
}

async fn session_for(pool: &PgPool, account_id: i64) -> String {
    let token = app::sessions::new_token();
    let now = time::OffsetDateTime::now_utc();
    let sess = app::sessions::Session::fresh(account_id, now);
    app::db::create_session(pool, &token, CSRF, &sess).await.unwrap();
    token
}

fn cookie(token: &str) -> String {
    format!("session={token}")
}

fn crlf(s: &str) -> String {
    s.replace('\n', "\r\n")
}

async fn cleanup(pool: &PgPool, accounts: &[i64]) {
    // Conversations first, torn down by id (both participants' rows),
    // so an order conversation never outlives its order below.
    let conv_ids: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT conversation_id FROM conversation_participants WHERE account_id = ANY($1)",
    )
    .bind(accounts)
    .fetch_all(pool)
    .await
    .unwrap();
    for cid in &conv_ids {
        for q in [
            "DELETE FROM encrypted_messages WHERE conversation_id = $1",
            "DELETE FROM conversation_key_sightings WHERE conversation_id = $1",
            "DELETE FROM conversation_participants WHERE conversation_id = $1",
            "DELETE FROM conversations WHERE id = $1",
        ] {
            sqlx::query(q).bind(cid).execute(pool).await.unwrap();
        }
    }
    for id in accounts {
        // conversation_blocks arrives with migration 0012 (task 6);
        // tolerate its absence so cleanup also works pre-migration.
        let _ = sqlx::query(
            "DELETE FROM conversation_blocks WHERE blocker_id = $1 OR blocked_id = $1",
        )
        .bind(id)
        .execute(pool)
        .await;
        for q in [
            "DELETE FROM payment_review_flags WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM payment_declarations WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM payment_reports WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM payment_proofs WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM disclosures WHERE dispute_id IN (SELECT d.id FROM disputes d JOIN orders o ON o.id = d.order_id WHERE o.buyer_id = $1 OR o.seller_id = $1)",
            "DELETE FROM disputes WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM payment_attestations WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM payment_pool_entries WHERE seller_id = $1",
            "DELETE FROM payment_batches WHERE seller_id = $1",
            "DELETE FROM payment_identities WHERE seller_id = $1",
            "DELETE FROM destinations WHERE seller_id = $1",
            "DELETE FROM notifications WHERE account_id = $1",
            "DELETE FROM orders WHERE buyer_id = $1 OR seller_id = $1",
            "DELETE FROM listings WHERE seller_id = $1",
            "DELETE FROM key_rotations WHERE account_id = $1",
            "DELETE FROM identity_keys WHERE account_id = $1",
            "DELETE FROM session_csrf WHERE token_hash IN (SELECT token_hash FROM sessions WHERE account_id = $1)",
            "DELETE FROM sessions WHERE account_id = $1",
            "DELETE FROM accounts WHERE id = $1",
        ] {
            sqlx::query(q).bind(id).execute(pool).await.unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP test server (the account_security / tx_proof_flow pattern)
// ---------------------------------------------------------------------------

struct TestServer {
    addr: std::net::SocketAddr,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}

async fn test_server(pool: &PgPool) -> TestServer {
    let mut dir = std::env::temp_dir();
    dir.push(format!("msgaudit-http-{}-{}", std::process::id(), uniq()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Message blobs land in one shared scratch dir for this test process.
    static BLOB_ONCE: std::sync::Once = std::sync::Once::new();
    let blob_root = dir.clone();
    BLOB_ONCE.call_once(|| {
        std::env::set_var("BLOB_DIR", blob_root.join("blobs"));
    });
    let key_path = dir.join("test.key");
    let media = MediaPipeline {
        worker_path: dir.join("no-worker"),
        media_dir: dir.clone(),
        tmp_dir: dir.join("tmp"),
    };
    let instance = InstanceConfig::resolve(&|_| None).expect("empty env resolves");
    let marketplace_id = instance.marketplace_id.clone();
    let payments = PaymentConfig::from_env(&marketplace_id, instance.network);
    let keyfile = Arc::new(KeyFile::load_or_generate(&key_path).expect("key file"));
    let state = AppState {
        pool: pool.clone(),
        hash_guard: app::passwords::HashGuard::new(4),
        throttles: Arc::new(app::throttle::Throttles::new()),
        registrations_open: true,
        account_cap: None,
        dev_cookies: true,
        media,
        marketplace_id,
        payments,
        keyfile,
        stage9: app::reputation::Stage9Config::from_env(),
        instance,
        retention: app::retention::RetentionConfig::defaults(),
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

async fn http_raw(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    cookie_header: Option<&str>,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> HttpResult {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n");
    if let Some(c) = cookie_header {
        req.push_str(&format!("Cookie: {c}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!(
            "Content-Type: {}\r\nContent-Length: {}\r\n",
            content_type.unwrap_or("application/x-www-form-urlencoded"),
            b.len()
        ));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    if let Some(b) = body {
        s.write_all(b).await.unwrap();
    }
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
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn form_body(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

async fn post_form(
    addr: std::net::SocketAddr,
    path: &str,
    cookie_header: Option<&str>,
    fields: &[(&str, &str)],
) -> HttpResult {
    let body = form_body(fields);
    http_raw(addr, "POST", path, cookie_header, None, Some(body.as_bytes())).await
}

async fn get_page(addr: std::net::SocketAddr, path: &str, token: &str) -> HttpResult {
    http_raw(addr, "GET", path, Some(&cookie(token)), None, None).await
}

fn location_of(r: &HttpResult) -> String {
    for line in r.headers.lines() {
        if line.to_lowercase().starts_with("location:") {
            return line.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
        }
    }
    String::new()
}

/// Paste a message into a conversation as the session's account.
async fn send_paste(
    addr: std::net::SocketAddr,
    token: &str,
    conv_id: i64,
    ciphertext: &str,
) -> HttpResult {
    post_form(
        addr,
        &format!("/conversations/{conv_id}/messages"),
        Some(&cookie(token)),
        &[("csrf", CSRF), ("ciphertext", ciphertext)],
    )
    .await
}

/// Upload a message file (multipart) into a conversation.
async fn send_file(
    addr: std::net::SocketAddr,
    token: &str,
    conv_id: i64,
    bytes: &[u8],
) -> HttpResult {
    let boundary = "msgaudit-boundary-7f3a";
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{CSRF}\r\n\
             --{boundary}\r\nContent-Disposition: form-data; name=\"ciphertext_file\"; filename=\"message.asc\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    http_raw(
        addr,
        "POST",
        &format!("/conversations/{conv_id}/messages/file"),
        Some(&cookie(token)),
        Some(&format!("multipart/form-data; boundary={boundary}")),
        Some(&body),
    )
    .await
}

fn is_redirect(r: &HttpResult) -> bool {
    r.status == 302 || r.status == 303
}

// ---------------------------------------------------------------------------
// Tasks 0–2: the GnuPG fixture set through the HTTP form, LF and CRLF.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gnupg_fixtures_accepted_through_http_forms() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_guard(&pool).await;
    let srv = test_server(&pool).await;
    let (alice, _ap) = make_account(&pool, "buyer").await;
    let (bob, _bp) = make_account(&pool, "seller").await;
    install_cert(&pool, alice, CERT_ALICE).await;
    install_cert(&pool, bob, CERT_BOB).await;
    let conv = app::messages::find_or_create_direct(&pool, alice, bob)
        .await
        .unwrap();
    let token = session_for(&pool, alice).await;

    let fixtures: &[(&str, &str)] = &[
        ("300B unsigned", MSG_300_UNSIGNED),
        ("300B signed", MSG_300_SIGNED),
        ("2KB unsigned", MSG_2K_UNSIGNED),
        ("2KB signed", MSG_2K_SIGNED),
        ("40KB unsigned", MSG_40K_UNSIGNED),
        ("40KB signed", MSG_40K_SIGNED),
    ];
    for (name, fixture) in fixtures {
        for (ending, text) in [("LF", fixture.to_string()), ("CRLF", crlf(fixture))] {
            let r = send_paste(srv.addr, &token, conv, &text).await;
            assert!(
                is_redirect(&r),
                "{name} with {ending} endings must be accepted; got {}: {}",
                r.status,
                r.body.chars().take(300).collect::<String>()
            );
        }
    }

    // The file path: a binary GnuPG message, and an armored message
    // whose bytes carry CRLF (a file saved from a browser).
    let r = send_file(srv.addr, &token, conv, MSG_2K_SIGNED_BIN).await;
    assert!(is_redirect(&r), "binary file upload: {} {}", r.status, r.body);
    let r = send_file(srv.addr, &token, conv, crlf(MSG_300_UNSIGNED).as_bytes()).await;
    assert!(is_redirect(&r), "CRLF armored file upload: {} {}", r.status, r.body);

    // Over the cap: a padded armor whose submission exceeds 64 KiB is
    // still refused.
    let mut padded = String::from("-----BEGIN PGP MESSAGE-----\nComment: ");
    padded.push_str(&"A".repeat(30_000));
    padded.push('\n');
    padded.push_str(MSG_40K_SIGNED.splitn(2, '\n').nth(1).unwrap());
    let r = send_paste(srv.addr, &token, conv, &padded).await;
    assert_eq!(r.status, 200, "oversize must be refused, not redirected");
    assert!(
        r.body.contains("64 KiB"),
        "oversize refusal names the cap: {}",
        r.body.chars().take(300).collect::<String>()
    );

    cleanup(&pool, &[alice, bob]).await;
    srv.stop();
}

// ---------------------------------------------------------------------------
// Task 1 (MH1): certified rotation from a browser — statement and
// signatures arrive with CRLF line endings.
// ---------------------------------------------------------------------------

/// A throwaway GnuPG home for runtime key generation (the
/// blind_stage9 pattern): private keys never leave the temp dir.
struct GpgHome {
    dir: std::path::PathBuf,
}

impl GpgHome {
    fn new() -> GpgHome {
        let mut dir = std::env::temp_dir();
        dir.push(format!("msgaudit-gpg-{}-{}", std::process::id(), uniq()));
        std::fs::create_dir_all(&dir).unwrap();
        std::process::Command::new("chmod")
            .arg("700")
            .arg(&dir)
            .output()
            .unwrap();
        GpgHome { dir }
    }

    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> (bool, Vec<u8>) {
        use std::io::Write;
        let mut cmd = std::process::Command::new("gpg");
        cmd.args([
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--trust-model",
            "always",
        ])
        .env("GNUPGHOME", &self.dir)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().expect("spawn gpg");
        if let Some(data) = stdin {
            child.stdin.take().unwrap().write_all(data).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        (out.status.success(), out.stdout)
    }

    fn gen_key(&self, name: &str) -> String {
        let params = format!(
            "Key-Type: eddsa\nKey-Curve: ed25519\nKey-Usage: sign\n\
             Subkey-Type: ecdh\nSubkey-Curve: cv25519\nSubkey-Usage: encrypt\n\
             Name-Real: {name}\nExpire-Date: 0\n%no-protection\n%commit\n"
        );
        let (ok, _) = self.run(&["--gen-key"], Some(params.as_bytes()));
        assert!(ok, "gpg --gen-key failed");
        let (_, out) = self.run(&["--with-colons", "--list-keys"], None);
        let text = String::from_utf8(out).unwrap();
        for line in text.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.first() == Some(&"fpr") {
                return fields[9].to_string();
            }
        }
        panic!("no fingerprint in key listing");
    }

    fn export(&self, fpr: &str) -> String {
        let (ok, out) = self.run(&["--armor", "--export", fpr], None);
        assert!(ok);
        String::from_utf8(out).unwrap()
    }

    fn sign_detached(&self, fpr: &str, data: &[u8]) -> String {
        let (ok, out) = self.run(
            &["--armor", "--detach-sign", "--local-user", fpr],
            Some(data),
        );
        assert!(ok, "gpg --detach-sign failed");
        String::from_utf8(out).unwrap()
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = std::process::Command::new("gpgconf")
            .arg("--kill")
            .arg("agent")
            .env("GNUPGHOME", &self.dir)
            .output();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn crlf_rotation_statement_verifies_as_certified() {
    if std::process::Command::new("gpg").arg("--version").output().is_err() {
        return; // no gpg in this environment
    }
    let Some(pool) = pool().await else { return };
    let old_home = GpgHome::new();
    let new_home = GpgHome::new();
    let old_fpr = old_home.gen_key("Rotate From");
    let new_fpr = new_home.gen_key("Rotate To");
    let old_cert = old_home.export(&old_fpr);
    let new_cert = new_home.export(&new_fpr);

    let srv = test_server(&pool).await;
    let (acct, acct_pub) = make_account(&pool, "seller").await;
    install_cert(&pool, acct, &old_cert).await;
    let token = session_for(&pool, acct).await;

    let statement = format!(
        "statement-format: marketplace-key-rotation-v1\n\
         marketplace-id: vespiary-market\n\
         account-id: {acct_pub}\n\
         old-fingerprint: {old_fpr}\n\
         new-fingerprint: {new_fpr}\n\
         rotated-at: 2026-10-19T00:00:00Z\n"
    );
    let sig_old = old_home.sign_detached(&old_fpr, statement.as_bytes());
    let sig_new = new_home.sign_detached(&new_fpr, statement.as_bytes());

    // Everything the browser submits arrives with CRLF endings.
    let r = post_form(
        srv.addr,
        "/account/keys/rotate",
        Some(&cookie(&token)),
        &[
            ("csrf", CSRF),
            ("new_cert", &crlf(&new_cert)),
            ("statement", &crlf(&statement)),
            ("sig_old", &crlf(&sig_old)),
            ("sig_new", &crlf(&sig_new)),
            ("password", PW),
        ],
    )
    .await;
    assert_eq!(r.status, 200, "rotation render: {}", r.status);
    assert!(
        r.body.contains("Key rotated (certified)"),
        "a browser-submitted certified rotation must verify; body: {}",
        r.body.chars().take(500).collect::<String>()
    );
    let (fpr,): (String,) =
        sqlx::query_as("SELECT fingerprint FROM identity_keys WHERE account_id = $1 AND status = 'current'")
            .bind(acct)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(fpr, new_fpr);

    cleanup(&pool, &[acct]).await;
    srv.stop();
}

// ---------------------------------------------------------------------------
// Order/dispute scaffolding on the real fixture keys.
// ---------------------------------------------------------------------------

async fn make_listing(pool: &PgPool, seller_id: i64) -> String {
    let public_id = app::db::public_id("lst_");
    sqlx::query(
        "INSERT INTO listings (public_id, seller_id, title, description, price_atomic,
            pricing_module, destination_module, auto_invoice, status, category)
         VALUES ($1, $2, 'Audit widget', 'desc', 1250000000000, 'xmr-only',
                 'signed-address-pool', false, 'published', 'general')",
    )
    .bind(&public_id)
    .bind(seller_id)
    .execute(pool)
    .await
    .unwrap();
    public_id
}

fn batch_json(cfg: &PaymentConfig, seller_pub: &str, primary: &str, subs: &[&str]) -> String {
    let seller_id = payment_seller_id(seller_pub).unwrap();
    let entries: Vec<serde_json::Value> = subs
        .iter()
        .map(|s| {
            serde_json::json!({
                "subaddress": s,
                "message": canonical_message(&cfg.marketplace_id, cfg.network, &seller_id, primary, s),
                "signature": SIG,
            })
        })
        .collect();
    serde_json::json!({
        "format": "xmr-direct-batch-v1",
        "marketplace_id": cfg.marketplace_id,
        "network": "stagenet",
        "seller_id": seller_id,
        "primary_address": primary,
        "entries": entries,
    })
    .to_string()
}

/// Seller = bob's real fixture cert; buyer = alice's. Returns
/// (seller_id, buyer_id, listing_public_id).
async fn shop(pool: &PgPool) -> (i64, i64, String) {
    let c = cfg();
    let (seller, seller_pub) = make_account(pool, "seller").await;
    install_cert(pool, seller, CERT_BOB).await;
    let listing = make_listing(pool, seller).await;
    set_primary_address(pool, seller, PRIMARY_A, &c).await.unwrap();
    upload_batch(pool, seller, &batch_json(&c, &seller_pub, PRIMARY_A, &SUBS[0..3]), &c)
        .await
        .unwrap();
    let (buyer, _bp) = make_account(pool, "buyer").await;
    install_cert(pool, buyer, CERT_ALICE).await;
    (seller, buyer, listing)
}

/// A Paid order (buyer proof submitted) opened into a dispute.
/// Returns (order_internal_id, order_public_id, dispute_id).
async fn disputed_order(pool: &PgPool, seller: i64, buyer: i64, listing: &str) -> (i64, String, i64) {
    let c = cfg();
    let (order, created) =
        create_order_with_config(pool, "vespiary-market", buyer, listing, 1, &uniq(), &c)
            .await
            .unwrap();
    assert!(created);
    apply_action(pool, &order, "accept", seller).await.unwrap();
    let order = order_by_public_id(pool, &order.public_id).await.unwrap();
    submit_payment_proof(pool, &order, buyer, "aa".repeat(32).as_str(), "proof text", &c)
        .await
        .unwrap();
    let order = order_by_public_id(pool, &order.public_id).await.unwrap();
    apply_action(pool, &order, "dispute", buyer).await.unwrap();
    let dispute = app::disputes::dispute_for_order(pool, order.id)
        .await
        .unwrap()
        .expect("dispute row exists");
    (order.id, order.public_id, dispute.id)
}

// ---------------------------------------------------------------------------
// Task 3 (MM1): disclosure by unwrap paste.
// ---------------------------------------------------------------------------

/// Verification-fix V4: a disclosure names the conversation
/// message it unwraps; plant one directly (blob file + row) with a
/// chosen arrival time and return its id.
async fn plant_disclosable_message(
    pool: &PgPool,
    conversation_id: i64,
    sender: i64,
    recipient: i64,
    bytes: &[u8],
    received_unix: i64,
) -> i64 {
    let dir = app::messages::blob_dir();
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let blob_ref = format!("test-{}", uniq());
    tokio::fs::write(dir.join(format!("{blob_ref}.asc")), bytes).await.unwrap();
    sqlx::query_scalar(
        "INSERT INTO encrypted_messages
            (conversation_id, sender_id, recipient_id, recipient_key_id, blob_ref, length, received_at, expires_at)
         VALUES ($1, $2, $3, 'A5C23E96999A1AF9', $4, $5, to_timestamp($6), to_timestamp($6) + interval '90 days')
         RETURNING id",
    )
    .bind(conversation_id)
    .bind(sender)
    .bind(recipient)
    .bind(blob_ref)
    .bind(bytes.len() as i32)
    .bind(received_unix as f64)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn disclosure_unwrap_verified_and_unsigned_is_claim() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_guard(&pool).await;
    purge_fixture_addresses(&pool).await;
    let srv = test_server(&pool).await;
    let (seller, buyer, listing) = shop(&pool).await;
    let (oid, _opub, dispute_id) = disputed_order(&pool, seller, buyer, &listing).await;
    let token = session_for(&pool, buyer).await;

    // V4: name the message being disclosed. Its arrival is planted
    // one hour after the fixture signature was created, so the pair
    // satisfies the 24h freshness rule deterministically.
    let conv = app::messages::find_or_create_for_order(&pool, oid, buyer, seller)
        .await
        .unwrap();
    let sig_unix = app::keys::extract_unwrapped_message(CERT_BOB.as_bytes(), UNWRAP_BOB_SIGNED.as_bytes())
        .and_then(|u| u.signature_created_unix)
        .expect("the signed fixture carries a signature creation time");
    let signed_mid = plant_disclosable_message(
        &pool,
        conv,
        seller,
        buyer,
        UNWRAP_BOB_SIGNED.as_bytes(),
        sig_unix + 3600,
    )
    .await;
    let signed_mid_s = signed_mid.to_string();

    // The unwrap output of bob's signed message, sent with CRLF the
    // way a browser submits it: verifies against bob's pinned key.
    let r = post_form(
        srv.addr,
        &format!("/disputes/{dispute_id}/disclosures"),
        Some(&cookie(&token)),
        &[("csrf", CSRF), ("unwrapped", &crlf(UNWRAP_BOB_SIGNED)), ("message_id", &signed_mid_s)],
    )
    .await;
    assert!(is_redirect(&r), "unwrap disclosure: {} {}", r.status, r.body);
    let loc = location_of(&r);
    assert!(
        loc.contains("signature verified"),
        "signed unwrap must record as verified evidence; location: {loc}"
    );
    assert!(!loc.contains("unverified"), "location: {loc}");

    // The dispute page shows the extracted plaintext and its status.
    let page = get_page(srv.addr, &format!("/disputes/{dispute_id}"), &token).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains(DISCLOSE_PLAINTEXT), "extracted plaintext shown");
    assert!(page.body.contains("Evidence — signature verified"), "verified label shown");

    // An unwrapped but UNSIGNED message: stored as an unverified claim.
    let unsigned_mid = plant_disclosable_message(
        &pool,
        conv,
        seller,
        buyer,
        UNWRAP_BOB_UNSIGNED.as_bytes(),
        sig_unix + 3600,
    )
    .await;
    let unsigned_mid_s = unsigned_mid.to_string();
    let r = post_form(
        srv.addr,
        &format!("/disputes/{dispute_id}/disclosures"),
        Some(&cookie(&token)),
        &[("csrf", CSRF), ("unwrapped", UNWRAP_BOB_UNSIGNED), ("message_id", &unsigned_mid_s)],
    )
    .await;
    assert!(is_redirect(&r), "unsigned unwrap: {} {}", r.status, r.body);
    let loc = location_of(&r);
    assert!(loc.contains("unverified claim"), "location: {loc}");
    let page = get_page(srv.addr, &format!("/disputes/{dispute_id}"), &token).await;
    assert!(page.body.contains("Unverified claim"), "claim label shown");

    // Garbage is not a disclosure at all.
    let r = post_form(
        srv.addr,
        &format!("/disputes/{dispute_id}/disclosures"),
        Some(&cookie(&token)),
        &[("csrf", CSRF), ("unwrapped", "this is not an unwrapped message"), ("message_id", &signed_mid_s)],
    )
    .await;
    assert!(is_redirect(&r), "garbage redirects with a message: {}", r.status);
    assert!(
        location_of(&r).contains("no readable message"),
        "location: {}",
        location_of(&r)
    );

    cleanup(&pool, &[seller, buyer]).await;
    srv.stop();
}

// ---------------------------------------------------------------------------
// Task 4 (MM2): the page's example signs; the guide's limits match code.
// ---------------------------------------------------------------------------

#[test]
fn page_and_guide_agree_on_signing_and_limits() {
    let page = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/templates/conversation.html"
    ))
    .unwrap();
    assert!(
        page.contains("--sign"),
        "the conversation page's example command must sign (MM2)"
    );
    assert!(page.contains("--encrypt"), "example still encrypts");
    let guide = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/encryption-guide.md"
    ))
    .unwrap();
    assert!(
        !guide.contains("10 MiB"),
        "the guide must not promise a 10 MiB allowance the code does not have"
    );
    assert!(
        guide.contains("64 KiB"),
        "the guide states the real 64 KiB per-message cap"
    );
}

// ---------------------------------------------------------------------------
// Task 5 (MM3): recipient matching against alive encryption subkeys;
// certificate refresh accepts signatures only.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoked_subkey_stops_matching() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_guard(&pool).await;
    let srv = test_server(&pool).await;
    let (alice, _ap) = make_account(&pool, "buyer").await;
    let (carol, _cp) = make_account(&pool, "seller").await;
    install_cert(&pool, alice, CERT_ALICE).await;
    install_cert(&pool, carol, CERT_CAROL_V1).await;
    let conv = app::messages::find_or_create_direct(&pool, alice, carol)
        .await
        .unwrap();
    let token = session_for(&pool, alice).await;

    // While subkey 1 is valid, a message encrypted to it alone is
    // accepted…
    let r = send_paste(srv.addr, &token, conv, MSG_TO_CAROL_SUBKEY1).await;
    assert!(is_redirect(&r), "before revocation: {} {}", r.status, r.body);

    // …carol refreshes her certificate: the refresh revokes subkey 1
    // (the stored certificate is exactly what the refresh endpoint
    // would store — the endpoint itself is exercised below).
    sqlx::query("UPDATE identity_keys SET certificate = $2 WHERE account_id = $1 AND status = 'current'")
        .bind(carol)
        .bind(CERT_CAROL_V2.as_bytes())
        .execute(&pool)
        .await
        .unwrap();

    // The same message is now refused: it is not encrypted to an
    // alive, encryption-capable subkey of the current certificate.
    let r = send_paste(srv.addr, &token, conv, MSG_TO_CAROL_SUBKEY1).await;
    assert_eq!(r.status, 200, "expected a refusal page, got {}", r.status);
    assert!(
        // (apostrophe is HTML-escaped in the rendered page)
        r.body.contains("not encrypted to the recipient"),
        "refusal is WrongRecipient: {}",
        r.body.chars().take(300).collect::<String>()
    );

    cleanup(&pool, &[alice, carol]).await;
    srv.stop();
}

#[tokio::test]
async fn cert_refresh_accepts_new_signatures_only() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_guard(&pool).await;
    let srv = test_server(&pool).await;
    let (dave, _dp) = make_account(&pool, "seller").await;
    install_cert(&pool, dave, CERT_DAVE_SHORT).await;
    let token = session_for(&pool, dave).await;

    let refresh = |cert: String, with_pw: bool| {
        let addr = srv.addr;
        let token = token.clone();
        async move {
            let mut fields: Vec<(&str, &str)> = vec![("csrf", CSRF), ("cert", Box::leak(cert.into_boxed_str()))];
            if with_pw {
                fields.push(("password", PW));
            }
            post_form(addr, "/account/keys/refresh", Some(&cookie(&token)), &fields).await
        }
    };

    // Signatures-only change (expiry extended): accepted.
    let r = refresh(CERT_DAVE_EXTENDED.to_string(), true).await;
    assert_eq!(r.status, 200, "refresh render: {}", r.status);
    assert!(
        r.body.contains("Certificate refreshed"),
        "expiry-extension refresh must succeed; body: {}",
        r.body.chars().take(400).collect::<String>()
    );
    let (stored,): (Vec<u8>,) =
        sqlx::query_as("SELECT certificate FROM identity_keys WHERE account_id = $1 AND status = 'current'")
            .bind(dave)
            .fetch_one(&pool)
            .await
            .unwrap();
    // AMENDED (verification-fix V7, 2026-10-19): the stored
    // certificate is the MERGE of the stored and submitted certs,
    // not byte-equal to the submission — the old replace semantics
    // let a stale export silently drop a revocation. What must
    // hold now: the stored cert is still dave's key, it PASSES the
    // upload policy (the short-expiry certificate on its own no
    // longer does — the extension took effect), and it is not the
    // pre-refresh bytes.
    let info = app::keys::validate_cert(&stored).expect("the stored merged certificate validates");
    assert_eq!(info.fingerprint, DAVE_FPR, "the refresh kept dave's key");
    assert_ne!(stored, CERT_DAVE_SHORT.as_bytes(), "the refresh changed the stored certificate");

    // New key material (an added subkey): refused, stored cert kept.
    let r = refresh(CERT_DAVE_ADDED.to_string(), true).await;
    assert!(
        r.body.contains("new key material") || r.body.contains("different set of keys"),
        "added-subkey refresh must be refused as new key material; body: {}",
        r.body.chars().take(400).collect::<String>()
    );
    let (stored2,): (Vec<u8>,) =
        sqlx::query_as("SELECT certificate FROM identity_keys WHERE account_id = $1 AND status = 'current'")
            .bind(dave)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored2, stored, "a refused refresh leaves the stored certificate untouched");

    // A different key entirely: refused.
    let r = refresh(CERT_BOB.to_string(), true).await;
    assert!(
        !r.body.contains("Certificate refreshed"),
        "a different fingerprint is a rotation, not a refresh"
    );

    // No step-up: refused even for a valid refresh.
    let r = refresh(CERT_DAVE_EXTENDED.to_string(), false).await;
    assert!(
        !r.body.contains("Certificate refreshed"),
        "refresh requires the passphrase step-up"
    );

    cleanup(&pool, &[dave]).await;
    srv.stop();
}

// ---------------------------------------------------------------------------
// Task 6 (MM4): message limits at the library seam + direct blocking.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn message_rate_budget_and_conversation_cap() {
    use app::messages::{send_message, SendError};
    let Some(pool) = pool().await else { return };
    let _guard = fixture_guard(&pool).await;

    // Fixture certificates have globally-unique fingerprints, so each
    // scenario pair uses two of the four fixture identities.

    // -- rate: 60 messages/minute per account -------------------------
    let (a1, _p) = make_account(&pool, "buyer").await;
    let (b1, _q) = make_account(&pool, "seller").await;
    install_cert(&pool, a1, CERT_ALICE).await;
    install_cert(&pool, b1, CERT_BOB).await;
    let conv = app::messages::find_or_create_direct(&pool, a1, b1).await.unwrap();
    for i in 0..60 {
        send_message(&pool, conv, a1, MSG_300_UNSIGNED.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("send {i} within the rate must pass: {e:?}"));
    }
    let err = send_message(&pool, conv, a1, MSG_300_UNSIGNED.as_bytes())
        .await
        .expect_err("61st message in a minute is refused");
    assert!(matches!(err, SendError::RateLimited), "got {err:?}");

    // -- daily byte budget, then the per-conversation cap ---------------
    let (a2, _p) = make_account(&pool, "buyer").await;
    let (b2, _q) = make_account(&pool, "seller").await;
    install_cert(&pool, a2, CERT_DAVE_SHORT).await;
    install_cert(&pool, b2, CERT_CAROL_V1).await;
    let conv2 = app::messages::find_or_create_direct(&pool, a2, b2).await.unwrap();
    // Seed the day with a full budget of ciphertext from a2 (two
    // hours old: inside the daily window, outside the rate window).
    sqlx::query(
        "INSERT INTO encrypted_messages
           (conversation_id, sender_id, recipient_id, recipient_key_id, blob_ref, length, received_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, now() - interval '2 hours', now() + interval '90 days')",
    )
    .bind(conv2)
    .bind(a2)
    .bind(b2)
    .bind(CAROL_FPR)
    .bind("ab".repeat(32))
    .bind(app::messages::MSG_DAILY_BUDGET_BYTES)
    .execute(&pool)
    .await
    .unwrap();
    // a2's next send would exceed the daily byte budget.
    let err = send_message(&pool, conv2, a2, MSG_300_UNSIGNED.as_bytes())
        .await
        .expect_err("the daily byte budget refuses the next send");
    assert!(matches!(err, SendError::BudgetExceeded), "got {err:?}");
    // The same stored volume fills the CONVERSATION for the other
    // party too (her own rate and budget are untouched): the cap is
    // on the conversation, not the sender.
    let err = send_message(&pool, conv2, b2, MSG_TO_CAROL_SUBKEY1.as_bytes())
        .await
        .expect_err("a full conversation refuses new messages");
    assert!(matches!(err, SendError::ConversationFull), "got {err:?}");

    cleanup(&pool, &[a1, b1, a2, b2]).await;
}

#[tokio::test]
async fn direct_conversation_blocking() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_guard(&pool).await;
    let srv = test_server(&pool).await;
    let (alice, _ap) = make_account(&pool, "buyer").await;
    let (carol, carol_pub) = make_account(&pool, "seller").await;
    install_cert(&pool, alice, CERT_ALICE).await;
    install_cert(&pool, carol, CERT_CAROL_V1).await;
    let atok = session_for(&pool, alice).await;
    let ctok = session_for(&pool, carol).await;

    // Control: alice can open a direct conversation and write.
    let r = post_form(
        srv.addr,
        &format!("/conversations/direct/{carol_pub}"),
        Some(&cookie(&atok)),
        &[("csrf", CSRF)],
    )
    .await;
    assert!(is_redirect(&r), "open direct: {} {}", r.status, r.body);
    let conv_path = location_of(&r);
    let conv_id: i64 = conv_path.trim_start_matches("/conversations/").parse().unwrap();
    let r = send_paste(srv.addr, &atok, conv_id, MSG_TO_CAROL_SUBKEY1).await;
    assert!(is_redirect(&r), "write before block: {} {}", r.status, r.body);

    // Carol blocks alice from the conversation page.
    let r = post_form(
        srv.addr,
        &format!("/conversations/{conv_id}/block"),
        Some(&cookie(&ctok)),
        &[("csrf", CSRF)],
    )
    .await;
    assert!(is_redirect(&r), "block: {} {}", r.status, r.body);

    // Alice can no longer write into it, nor re-open it.
    let r = send_paste(srv.addr, &atok, conv_id, MSG_TO_CAROL_SUBKEY1).await;
    assert_eq!(r.status, 200, "blocked send is refused: {}", r.status);
    assert!(
        r.body.contains("blocked"),
        "refusal says why: {}",
        r.body.chars().take(300).collect::<String>()
    );
    let r = post_form(
        srv.addr,
        &format!("/conversations/direct/{carol_pub}"),
        Some(&cookie(&atok)),
        &[("csrf", CSRF)],
    )
    .await;
    assert_eq!(r.status, 403, "blocked open is refused: {}", r.status);

    // Carol unblocks from her conversations page; alice can write again.
    let page = get_page(srv.addr, "/conversations", &ctok).await;
    assert!(page.body.contains("Blocked accounts"), "block list renders");
    let (alice_pub,): (String,) = sqlx::query_as("SELECT public_id FROM accounts WHERE id = $1")
        .bind(alice)
        .fetch_one(&pool)
        .await
        .unwrap();
    let r = post_form(
        srv.addr,
        &format!("/conversations/blocks/{alice_pub}"),
        Some(&cookie(&ctok)),
        &[("csrf", CSRF)],
    )
    .await;
    assert!(is_redirect(&r), "unblock: {} {}", r.status, r.body);
    let r = send_paste(srv.addr, &atok, conv_id, MSG_TO_CAROL_SUBKEY1).await;
    assert!(is_redirect(&r), "write after unblock: {} {}", r.status, r.body);

    cleanup(&pool, &[alice, carol]).await;
    srv.stop();
}

// ---------------------------------------------------------------------------
// Task 7 (ML1): order conversations show the pinned key.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn order_conversation_shows_pinned_key_and_warns_on_change() {
    let Some(pool) = pool().await else { return };
    let _guard = fixture_guard(&pool).await;
    purge_fixture_addresses(&pool).await;
    let srv = test_server(&pool).await;
    let (seller, buyer, listing) = shop(&pool).await;
    let c = cfg();
    let (order, _created) =
        create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, &uniq(), &c)
            .await
            .unwrap();

    let btok = session_for(&pool, buyer).await;
    let r = post_form(
        srv.addr,
        &format!("/conversations/for-order/{}", order.public_id),
        Some(&cookie(&btok)),
        &[("csrf", CSRF)],
    )
    .await;
    assert!(is_redirect(&r), "open order conversation: {} {}", r.status, r.body);
    let conv_path = location_of(&r);

    let page = get_page(srv.addr, &conv_path, &btok).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains(BOB_FPR), "the pinned fingerprint is shown");
    assert!(
        page.body.contains("pinned"),
        "the page says the key is pinned to the order"
    );
    assert!(
        !page.body.contains("differs from the key pinned"),
        "no warning while the keys agree"
    );

    // The seller's current key changes WITHOUT any key_rotations row
    // (database swap): the warning must still appear, because it is
    // computed from the order's pin, not from rotation bookkeeping.
    sqlx::query(
        "UPDATE identity_keys SET status = 'retired', retired_at = now()
         WHERE account_id = $1 AND status = 'current'",
    )
    .bind(seller)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO identity_keys (account_id, certificate, fingerprint, version, status)
         VALUES ($1, $2, $3, 2, 'current')",
    )
    .bind(seller)
    .bind(CERT_CAROL_V1.as_bytes())
    .bind(CAROL_FPR)
    .execute(&pool)
    .await
    .unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM key_rotations WHERE account_id = $1")
        .bind(seller)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0, "test premise: no rotation row exists");

    let page = get_page(srv.addr, &conv_path, &btok).await;
    assert!(page.body.contains(BOB_FPR), "the pin is still shown after the swap");
    assert!(
        page.body.contains("differs from the key pinned"),
        "the warning appears without any rotation row"
    );

    cleanup(&pool, &[seller, buyer]).await;
    srv.stop();
}

// Keep the CAROL_FPR/carol fixtures referenced when earlier tests are
// compiled out in a filtered run.
#[allow(dead_code)]
fn _fixtures_used() -> (&'static str, &'static str) {
    (CERT_CAROL_V1, CAROL_FPR)
}
