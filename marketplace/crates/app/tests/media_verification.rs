//! Media Fix Verification — acceptance tests (2026-10-19).
//!
//! One test per task of the media fix-verification brief:
//!
//! 1. CM2 (sandbox ships on) — with `MEDIA_WORKER_SANDBOX=bwrap`, a
//!    probe worker inside the sandbox can neither read a file outside
//!    it nor open a network connection, while the SAME probe succeeds
//!    at both without the sandbox (positive control); and the real
//!    media-worker still sanitizes a PNG inside the sandbox.
//! 2. CM2 (per-job scratch) — two workers running at once cannot see
//!    each other's files: each job's scratch directory holds only its
//!    own input.
//! 3. CM2 (bounded queue) — 30 parallel uploads: at most 6 are in the
//!    system (2 running + 4 queued), the rest are refused (HTTP 503)
//!    before their bodies are buffered or written to disk.
//! 4. N1 — a refused TOTP code at dispute resolution redirects back
//!    to the dispute page (not the nonexistent /moderation/{id}), and
//!    the page shows a refusal message covering wrong/reused/locked
//!    codes.
//!
//! Tests in this file are serialized behind one mutex: the media
//! pipeline's admission and worker semaphores are process-wide, and
//! the sandbox switch is a process-wide environment variable.
//!
//! DB tests require DATABASE_URL (skipped silently when unset, the
//! pattern of the neighbouring suites).

use app::config::InstanceConfig;
use app::keyfile::KeyFile;
use app::media::MediaPipeline;
use app::moderation;
use app::passwords::HashGuard;
use app::totp;
use app::web::{router, AppState};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const PW: &str = "mediaverif-correct-passphrase-1";
const CSRF: &str = "mediaverif-csrf";
/// A genuine 1x1 PNG (the standard transparent pixel), base64.
const PNG_1X1_B64: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n-fake-image-bytes";

async fn pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Some(PgPoolOptions::new().max_connections(8).connect(&url).await.expect("DATABASE_URL is set but the database is unreachable"))
}

fn uniq() -> String {
    app::sessions::new_token()[..16].to_string()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn code(secret: &[u8], offset: i64) -> String {
    let t = (now_secs() as i64 + offset).max(0) as u64;
    totp::code_at(secret, t)
}

async fn make_account(pool: &PgPool, role: &str) -> (i64, String) {
    let hash = HashGuard::new(2).hash(PW).await.unwrap();
    let public_id = app::db::public_id("acct_");
    let username = format!("mverif{}", uniq());
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO accounts (public_id, username, password_hash, role)
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(&public_id)
    .bind(&username)
    .bind(&hash)
    .bind(role)
    .fetch_one(pool)
    .await
    .unwrap();
    (id, username)
}

async fn session_for(pool: &PgPool, account_id: i64) -> String {
    let token = app::sessions::new_token();
    let now = time::OffsetDateTime::now_utc();
    let sess = app::sessions::Session::fresh(account_id, now);
    app::db::create_session(pool, &token, CSRF, &sess).await.unwrap();
    token
}

async fn cleanup(pool: &PgPool, accounts: &[i64]) {
    for id in accounts {
        for q in [
            "DELETE FROM disclosures WHERE dispute_id IN (SELECT d.id FROM disputes d JOIN orders o ON o.id = d.order_id WHERE o.buyer_id = $1 OR o.seller_id = $1)",
            "DELETE FROM disputes WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM orders WHERE buyer_id = $1 OR seller_id = $1",
            "DELETE FROM listing_media WHERE listing_id IN (SELECT id FROM listings WHERE seller_id = $1)",
            "DELETE FROM listings WHERE seller_id = $1",
            "DELETE FROM totp_stepup_grants WHERE account_id = $1",
            "DELETE FROM notifications WHERE account_id = $1",
            "DELETE FROM session_csrf WHERE token_hash IN (SELECT token_hash FROM sessions WHERE account_id = $1)",
            "DELETE FROM sessions WHERE account_id = $1",
            "DELETE FROM accounts WHERE id = $1",
        ] {
            let _ = sqlx::query(q).bind(id).execute(pool).await;
        }
    }
}

fn write_stub(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    p
}

fn count_files_recursively(dir: &std::path::Path) -> usize {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                n += count_files_recursively(&p);
            } else {
                n += 1;
            }
        }
    }
    n
}

fn b64_decode(s: &str) -> Vec<u8> {
    let mut vals = Vec::with_capacity(s.len());
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => continue,
        };
        vals.push(v);
    }
    let mut out = Vec::new();
    for chunk in vals.chunks(4) {
        if chunk.len() >= 2 {
            out.push((chunk[0] << 2) | (chunk[1] >> 4));
        }
        if chunk.len() >= 3 {
            out.push(((chunk[1] & 0xF) << 4) | (chunk[2] >> 2));
        }
        if chunk.len() >= 4 {
            out.push(((chunk[2] & 0x3) << 6) | chunk[3]);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Task 1 (CM2) — the sandbox confines the worker, and the real worker
// still works inside it.
// ---------------------------------------------------------------------------

/// Compile the probe worker: it tries to read a secret file outside
/// the sandbox and to open a TCP connection; it exits 0 (and produces
/// output) only when BOTH are blocked.
fn build_probe(dir: &std::path::Path, secret: &std::path::Path, addr: std::net::SocketAddr) -> std::path::PathBuf {
    let src = dir.join("probe.rs");
    let bin = dir.join("probe");
    let code = format!(
        r#"use std::io::Write;
fn main() {{
    let args: Vec<String> = std::env::args().collect();
    let key_blocked = std::fs::read({secret:?}).is_err();
    let net_blocked = std::net::TcpStream::connect({addr:?}).is_err();
    if key_blocked && net_blocked {{
        std::fs::write(&args[2], b"both-blocked").unwrap();
        println!("1x1");
    }} else {{
        let _ = writeln!(std::io::stderr(), "key_blocked={{key_blocked}} net_blocked={{net_blocked}}");
        std::process::exit(3);
    }}
}}
"#,
        secret = secret.display().to_string(),
        addr = addr.to_string(),
    );
    std::fs::write(&src, code).unwrap();
    let home = std::env::var("HOME").unwrap_or_default();
    let candidates = [
        "rustc".to_string(),
        format!("{home}/.cargo/bin/rustc"),
        "/root/.cargo/bin/rustc".to_string(),
    ];
    let mut last_err = String::new();
    for cand in &candidates {
        match std::process::Command::new(cand)
            .args(["-O", src.to_str().unwrap(), "-o", bin.to_str().unwrap()])
            .output()
        {
            Ok(o) if o.status.success() => return bin,
            Ok(o) => last_err = String::from_utf8_lossy(&o.stderr).to_string(),
            Err(e) => last_err = e.to_string(),
        }
    }
    panic!("could not compile the sandbox probe with rustc: {last_err}");
}

#[tokio::test]
async fn sandbox_blocks_key_read_and_network_but_not_the_work() {
    let _serial = SERIAL.lock().await;
    // The sandbox wrapper needs bubblewrap on the host. It is a
    // deployment dependency; where it genuinely does not exist this
    // test cannot run (the deploy script installs it — task 1).
    if std::process::Command::new("bwrap").arg("--version").output().is_err() {
        eprintln!("bwrap not available; skipping sandbox confinement test");
        return;
    }
    let mut dir = std::env::temp_dir();
    dir.push(format!("mediaverif-sbx-{}-{}", std::process::id(), uniq()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let media_dir = dir.join("media");
    std::fs::create_dir_all(&media_dir).unwrap();

    // A secret the worker must never read, and a listener it must
    // never reach. The listener stays bound for the whole test, so a
    // connect would complete (backlog) if the network were shared.
    let secret = dir.join("marketplace.key");
    std::fs::write(&secret, b"key-material-the-worker-must-not-read").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let probe = build_probe(&dir, &secret, addr);
    let pipe = MediaPipeline {
        worker_path: probe,
        media_dir: media_dir.clone(),
        tmp_dir: media_dir.join("tmp"),
    };

    // Positive control: WITHOUT the sandbox the probe reads the key
    // and connects, so it refuses to produce output (exit 3) and the
    // sanitize fails. This proves the probe really can do both bad
    // things when it is not confined.
    std::env::remove_var("MEDIA_WORKER_SANDBOX");
    let control = pipe.sanitize(PNG_MAGIC).await;
    assert!(
        control.is_err(),
        "control run: the unconfined probe must reach the key and the network: {control:?}"
    );

    // Sandboxed: the same probe now finds no key file and no network,
    // so it does its (harmless) job and the sanitize succeeds.
    std::env::set_var("MEDIA_WORKER_SANDBOX", "bwrap");
    let confined = pipe.sanitize(PNG_MAGIC).await;
    std::env::remove_var("MEDIA_WORKER_SANDBOX");
    let (stored_ref, w, h) = confined.expect("the confined probe's work succeeds");
    assert_eq!((w, h), (1, 1));
    let out = std::fs::read(media_dir.join(&stored_ref)).unwrap();
    assert_eq!(out, b"both-blocked", "both escapes were blocked inside the sandbox");

    drop(listener);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn sandboxed_real_worker_sanitizes_a_png() {
    let _serial = SERIAL.lock().await;
    if std::process::Command::new("bwrap").arg("--version").output().is_err() {
        eprintln!("bwrap not available; skipping real-worker sandbox test");
        return;
    }
    let worker = std::env::var("MEDIA_WORKER").unwrap_or_else(|_| "target/debug/media-worker".into());
    if !std::path::Path::new(&worker).exists() {
        eprintln!("real media-worker not built at {worker}; skipping");
        return;
    }
    let mut dir = std::env::temp_dir();
    dir.push(format!("mediaverif-real-{}-{}", std::process::id(), uniq()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let media_dir = dir.join("media");
    std::fs::create_dir_all(&media_dir).unwrap();
    let pipe = MediaPipeline {
        worker_path: worker.into(),
        media_dir: media_dir.clone(),
        tmp_dir: media_dir.join("tmp"),
    };
    let png = b64_decode(PNG_1X1_B64);
    std::env::set_var("MEDIA_WORKER_SANDBOX", "bwrap");
    let res = pipe.sanitize(&png).await;
    std::env::remove_var("MEDIA_WORKER_SANDBOX");
    let (stored_ref, w, h) = res.expect("the real worker sanitizes inside the sandbox");
    assert_eq!((w, h), (1, 1));
    assert!(media_dir.join(&stored_ref).exists(), "sanitized output is stored");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Task 2 (CM2) — one scratch folder per job.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_jobs_cannot_see_each_others_files() {
    let _serial = SERIAL.lock().await;
    let mut dir = std::env::temp_dir();
    dir.push(format!("mediaverif-scratch-{}-{}", std::process::id(), uniq()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let media_dir = dir.join("media");
    std::fs::create_dir_all(&media_dir).unwrap();
    // Rendezvous OUTSIDE any job scratch dir: both stubs register,
    // wait until both are in flight, then list their input's folder.
    let rendez = dir.join("rendez");
    std::fs::create_dir_all(&rendez).unwrap();
    // The listing is captured BEFORE the output file is created (a
    // plain `ls dir > "$2"` would list the just-created output too):
    // post-fix a job dir holds only its input at that moment; pre-fix
    // the shared tmp dir held both jobs' inputs, so this saw >= 2.
    let stub = write_stub(
        &dir,
        "lister.sh",
        &format!(
            "#!/bin/sh\ntouch \"{r}/job-$$\"\ni=0\nwhile [ \"$(ls {r} | wc -l)\" -lt 2 ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done\nlisting=$(ls \"$(dirname \"$1\")\")\nprintf '%s\\n' \"$listing\" > \"$2\"\necho 10x10\n",
            r = rendez.display()
        ),
    );
    let pipe = MediaPipeline {
        worker_path: stub,
        media_dir: media_dir.clone(),
        tmp_dir: media_dir.join("tmp"),
    };
    let p1 = pipe.clone();
    let p2 = pipe.clone();
    let (r1, r2) = tokio::join!(
        tokio::spawn(async move { p1.sanitize(PNG_MAGIC).await }),
        tokio::spawn(async move { p2.sanitize(PNG_MAGIC).await })
    );
    let (ref1, _, _) = r1.unwrap().expect("first job succeeds");
    let (ref2, _, _) = r2.unwrap().expect("second job succeeds");
    for r in [&ref1, &ref2] {
        let listing = std::fs::read_to_string(media_dir.join(r)).unwrap();
        let entries: Vec<&str> = listing.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(
            entries.len(),
            1,
            "a job's scratch dir holds only its own file, saw: {entries:?}"
        );
    }
    // And once both jobs are done, no scratch is left behind.
    assert_eq!(
        count_files_recursively(&media_dir.join("tmp")),
        0,
        "job scratch dirs are deleted after the job"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// HTTP test server (the media_disputes_audit.rs pattern)
// ---------------------------------------------------------------------------

struct TestServer {
    addr: std::net::SocketAddr,
    media: MediaPipeline,
    keyfile: Arc<KeyFile>,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}

async fn test_server(pool: &PgPool, worker_path: std::path::PathBuf) -> TestServer {
    let mut dir = std::env::temp_dir();
    dir.push(format!("mediaverif-http-{}-{}", std::process::id(), uniq()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("test.key");
    let media_dir = dir.join("media");
    std::fs::create_dir_all(&media_dir).unwrap();
    let media = MediaPipeline {
        worker_path,
        media_dir: media_dir.clone(),
        tmp_dir: media_dir.join("tmp"),
    };
    let instance = InstanceConfig::resolve(&|_| None).expect("empty env resolves");
    let marketplace_id = instance.marketplace_id.clone();
    let payments = app::payments::PaymentConfig::from_env(&marketplace_id, instance.network);
    let keyfile = Arc::new(KeyFile::load_or_generate(&key_path).expect("key file"));
    let state = AppState {
        pool: pool.clone(),
        hash_guard: HashGuard::new(4),
        throttles: Arc::new(app::throttle::Throttles::new()),
        registrations_open: true,
        account_cap: None,
        dev_cookies: true,
        media: media.clone(),
        marketplace_id,
        payments,
        keyfile: keyfile.clone(),
        stage9: app::reputation::Stage9Config::from_env(),
        instance,
        retention: app::retention::RetentionConfig::defaults(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    TestServer { addr, media, keyfile, handle, dir }
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

async fn http_raw(addr: std::net::SocketAddr, request: &[u8]) -> HttpResult {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(request).await.unwrap();
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

async fn http(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    form: Option<&str>,
) -> HttpResult {
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n");
    if let Some(c) = cookie {
        req.push_str(&format!("Cookie: session={c}\r\n"));
    }
    if let Some(b) = form {
        req.push_str(&format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
            b.len()
        ));
    }
    req.push_str("\r\n");
    let mut bytes = req.into_bytes();
    if let Some(b) = form {
        bytes.extend_from_slice(b.as_bytes());
    }
    http_raw(addr, &bytes).await
}

fn location(h: &HttpResult) -> String {
    for line in h.headers.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("location") {
                return v.trim().to_string();
            }
        }
    }
    String::new()
}

async fn make_listing(pool: &PgPool, seller_id: i64, status: &str) -> (i64, String) {
    let public_id = app::db::public_id("lst_");
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO listings (public_id, seller_id, title, description, price_atomic,
                                pricing_module, destination_module, auto_invoice, category, status)
         VALUES ($1, $2, $3, 'a fine widget', 1000000, 'xmr-only', 'signed-address-pool', false, 'general', $4)
         RETURNING id",
    )
    .bind(&public_id)
    .bind(seller_id)
    .bind(format!("Widget {}", uniq()))
    .bind(status)
    .fetch_one(pool)
    .await
    .unwrap();
    (id, public_id)
}

// ---------------------------------------------------------------------------
// Task 3 (CM2) — the upload queue is bounded; refusals are immediate
// and nothing of theirs touches the disk.
// ---------------------------------------------------------------------------

fn slow_stub(dir: &std::path::Path) -> std::path::PathBuf {
    write_stub(
        dir,
        "slow.sh",
        "#!/bin/sh\nsleep 0.6\ncp \"$1\" \"$2\"\necho 10x10\n",
    )
}

#[tokio::test]
async fn upload_burst_admits_at_most_six_and_refusals_write_nothing() {
    let _serial = SERIAL.lock().await;
    let mut dir = std::env::temp_dir();
    dir.push(format!("mediaverif-burst-{}-{}", std::process::id(), uniq()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let media_dir = dir.join("media");
    std::fs::create_dir_all(&media_dir).unwrap();
    let stub = slow_stub(&dir);
    let pipe = MediaPipeline {
        worker_path: stub,
        media_dir: media_dir.clone(),
        tmp_dir: media_dir.join("tmp"),
    };
    // 30 simultaneous uploads against a system that holds 2 running +
    // 4 queued: exactly 6 may enter, the other 24 are refused.
    let barrier = Arc::new(tokio::sync::Barrier::new(31));
    let mut joins = Vec::new();
    for _ in 0..30 {
        let p = pipe.clone();
        let b = barrier.clone();
        joins.push(tokio::spawn(async move {
            b.wait().await;
            p.sanitize(PNG_MAGIC).await
        }));
    }
    barrier.wait().await;
    let mut ok = 0;
    let mut refused = 0;
    for j in joins {
        match j.await.unwrap() {
            Ok(_) => ok += 1,
            Err(_) => refused += 1,
        }
    }
    assert_eq!(ok, 6, "at most 2 running + 4 queued uploads are admitted");
    assert_eq!(refused, 24, "the rest are refused at once");
    // Refused uploads never had their bodies written to disk, and the
    // admitted jobs cleaned their scratch up: no files remain in tmp.
    assert_eq!(
        count_files_recursively(&media_dir.join("tmp")),
        0,
        "no upload bodies or scratch files are left in the tmp dir"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn upload_burst_over_http_answers_503_to_the_excess() {
    let _serial = SERIAL.lock().await;
    let Some(pool) = pool().await else { return };
    let mut dir = std::env::temp_dir();
    dir.push(format!("mediaverif-bursthttp-{}-{}", std::process::id(), uniq()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let stub = slow_stub(&dir);
    let srv = test_server(&pool, stub).await;
    let (seller, _) = make_account(&pool, "seller").await;
    let (_lid, lpub) = make_listing(&pool, seller, "draft").await;
    let token = session_for(&pool, seller).await;

    let boundary = "----mediaverif-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{CSRF}\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"image\"; filename=\"x.png\"\r\nContent-Type: image/png\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(PNG_MAGIC);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let req_head = format!(
        "POST /seller/listings/{lpub}/media HTTP/1.1\r\nHost: test\r\nConnection: close\r\nCookie: session={token}\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut request = req_head.into_bytes();
    request.extend_from_slice(&body);

    let barrier = Arc::new(tokio::sync::Barrier::new(31));
    let mut joins = Vec::new();
    for _ in 0..30 {
        let addr = srv.addr;
        let req = request.clone();
        let b = barrier.clone();
        joins.push(tokio::spawn(async move {
            b.wait().await;
            http_raw(addr, &req).await
        }));
    }
    barrier.wait().await;
    let mut redirects = 0;
    let mut busy = 0;
    let mut other: Vec<u16> = Vec::new();
    for j in joins {
        let r = j.await.unwrap();
        match r.status {
            303 => redirects += 1,
            503 => busy += 1,
            s => other.push(s),
        }
    }
    assert!(other.is_empty(), "no unexpected statuses in the burst: {other:?}");
    assert_eq!(redirects, 6, "exactly the admitted uploads succeed");
    assert_eq!(busy, 24, "the excess uploads are answered 503 at once");
    assert_eq!(
        count_files_recursively(&srv.media.tmp_dir),
        0,
        "refused uploads wrote nothing to disk; admitted jobs cleaned up"
    );
    srv.stop();
    cleanup(&pool, &[seller]).await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Task 4 (N1) — a refused code at dispute resolution returns to the
// dispute page with a message that fits the refusal.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wrong_code_at_dispute_resolve_returns_to_the_dispute_page() {
    let _serial = SERIAL.lock().await;
    let Some(pool) = pool().await else { return };
    let srv = test_server(&pool, std::path::PathBuf::from("no-worker")).await;
    // Enrollment must use the SERVER's keyfile: require_totp decrypts
    // the stored secret with it when the resolve is attempted.
    let kf = srv.keyfile.clone();
    let (buyer, _) = make_account(&pool, "buyer").await;
    let (seller, _) = make_account(&pool, "seller").await;
    let (moderator, _) = make_account(&pool, "moderator").await;
    let (listing_id, _lpub) = make_listing(&pool, seller, "published").await;
    let order_public = app::db::public_id("ord_");
    let (order_id,): (i64,) = sqlx::query_as(
        "INSERT INTO orders (public_id, buyer_id, seller_id, listing_id, state, settlement,
                             seller_fpr_pinned, terms_bytes, terms_sha256, total_atomic,
                             module_pins, evidence_level, idempotency_key)
         VALUES ($1, $2, $3, $4, 'paid', 'direct', 'AABBCCDDEEFF00112233445566778899AABBCCDD',
                 'terms'::bytea, 'deadbeef', 1000000, '{}'::jsonb, 'None', $5)
         RETURNING id",
    )
    .bind(&order_public)
    .bind(buyer)
    .bind(seller)
    .bind(listing_id)
    .bind(format!("idem-{}", uniq()))
    .fetch_one(&pool)
    .await
    .unwrap();
    let (dispute_id,): (i64,) = sqlx::query_as(
        "INSERT INTO disputes (order_id, opened_by, state) VALUES ($1, $2, 'open') RETURNING id",
    )
    .bind(order_id)
    .bind(buyer)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Enroll the moderator in TOTP (library flow, as account_security).
    let b32 = moderation::totp_begin(&pool, &kf, moderator).await.unwrap();
    let secret = totp::base32_decode(&b32).unwrap();
    moderation::totp_confirm(&pool, &kf, moderator, &code(&secret, 0))
        .await
        .unwrap();
    // A wrong code: a well-formed code that is not valid at any step
    // in the acceptance window right now.
    let now = now_secs();
    let wrong = (0..10)
        .map(|d| format!("{d}{d}{d}{d}{d}{d}"))
        .find(|cand| totp::verify_step(&secret, cand, now).is_none())
        .expect("some repeated-digit code is wrong");

    let token = session_for(&pool, moderator).await;
    let form = format!("csrf={CSRF}&outcome=refund_buyer&totp={wrong}");
    let res = http(
        srv.addr,
        "POST",
        &format!("/disputes/{dispute_id}/resolve"),
        Some(&token),
        Some(&form),
    )
    .await;
    assert_eq!(res.status, 303, "a refused resolve redirects, got {}", res.status);
    assert_eq!(
        location(&res),
        format!("/disputes/{dispute_id}?msg=mod_action_refused"),
        "the redirect goes back to the dispute page (N1: /moderation/{{id}} does not exist)"
    );

    // Following the redirect shows the refusal, worded for a wrong,
    // reused or locked-out code — not "enroll first".
    let page = http(
        srv.addr,
        "GET",
        &format!("/disputes/{dispute_id}?msg=mod_action_refused"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(page.status, 200, "the dispute page renders for the moderator");
    assert!(
        page.body.contains("code was not accepted"),
        "the page shows the code-refusal message"
    );
    assert!(
        !page.body.contains("Enroll in TOTP on your security page first"),
        "the old enroll-first wording is gone"
    );

    // The dispute is untouched: still open.
    let state: String = sqlx::query_scalar("SELECT state FROM disputes WHERE id = $1")
        .bind(dispute_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "open");

    srv.stop();
    cleanup(&pool, &[buyer, seller, moderator]).await;
}
