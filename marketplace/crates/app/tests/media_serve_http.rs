//! Regression test (2026-10-17): a stored listing image must actually
//! be servable over HTTP. The media_serve ref validation ran its hex
//! check over the whole ref including the file extension, whose
//! letters are not hex digits, so GET /media/<ref> 404'd every real
//! image while upload, sanitize, and storage all worked. No test
//! requested /media/... before this one, which is why no stage gate
//! caught it (found by the Manioc Server recipe's full-stack drive;
//! see REBRAND-AND-FIXES-REPORT.md).
//!
//! End to end: real PNG bytes go through the real media-worker
//! (MEDIA_WORKER), land in a temp MEDIA_DIR, and are fetched back
//! through the real router over a real socket. Requires DATABASE_URL
//! (AppState carries a pool) and MEDIA_WORKER; skipped silently when
//! either is unset, per the stage1_db.rs convention.

use app::config::InstanceConfig;
use app::media::MediaPipeline;
use app::web::{router, AppState};
use sqlx::postgres::PgPoolOptions;
use std::io::Write as _;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The canonical 1x1 transparent PNG (68 bytes).
const PNG_1PX: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82";

async fn get(addr: std::net::SocketAddr, path: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a header/body split");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .expect("status line parses");
    let headers = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string())))
        .collect();
    (status, headers, raw[split + 4..].to_vec())
}

#[tokio::test]
async fn stored_image_is_served_end_to_end() {
    let Ok(url) = std::env::var("DATABASE_URL") else { return };
    let Ok(worker) = std::env::var("MEDIA_WORKER") else { return };
    let Ok(pool) = PgPoolOptions::new().max_connections(4).connect(&url).await else { return };

    // Unique temp media dir for this test run.
    let mut dir = std::env::temp_dir();
    dir.push(format!("media-serve-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut key_path = dir.clone();
    key_path.push("test.key");
    {
        // KeyFile::load_or_generate expects to create the file; give it
        // a path inside the temp dir.
        let mut f = std::fs::File::create(&key_path).unwrap();
        f.write_all(b"").unwrap();
        std::fs::remove_file(&key_path).unwrap();
    }

    let media = MediaPipeline {
        worker_path: worker.into(),
        media_dir: dir.clone(),
        tmp_dir: dir.join("tmp"),
    };

    // 1. Upload path: sanitize a real image through the real worker.
    let (stored_ref, w, h) = media
        .sanitize(PNG_1PX)
        .await
        .expect("media worker must accept a valid 1x1 PNG");
    assert_eq!((w, h), (1, 1), "worker reports the PNG's dimensions");
    assert!(stored_ref.ends_with(".png"), "stored ref carries the png extension: {stored_ref}");
    let (stem, _ext) = stored_ref.rsplit_once('.').unwrap();
    assert!(
        !stem.is_empty() && stem.chars().all(|c| c.is_ascii_hexdigit()),
        "stored ref stem is server-generated hex: {stored_ref}"
    );
    let stored_bytes = std::fs::read(dir.join(&stored_ref)).unwrap();
    assert!(!stored_bytes.is_empty(), "sanitized image is on disk");

    // 2. App state + router on an ephemeral port.
    let instance = InstanceConfig::resolve(&|_| None).expect("empty env resolves");
    let marketplace_id = instance.marketplace_id.clone();
    let payments = app::payments::PaymentConfig::from_env(&marketplace_id, instance.network);
    let keyfile = app::keyfile::KeyFile::load_or_generate(&key_path).expect("key file");
    let state = AppState {
        pool,
        hash_guard: app::passwords::HashGuard::new(2),
        throttles: Arc::new(app::throttle::Throttles::new()),
        registrations_open: true,
        account_cap: None,
        dev_cookies: true,
        media,
        marketplace_id,
        payments,
        keyfile: Arc::new(keyfile),
        stage9: app::reputation::Stage9Config::from_env(),
        instance,
        retention: app::retention::RetentionConfig::defaults(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });

    // 3. The fetch that shipped broken: the stored image must serve.
    let (status, headers, body) = get(addr, &format!("/media/{stored_ref}")).await;
    assert_eq!(status, 200, "GET /media/{stored_ref} must serve the stored image");
    assert!(
        headers.iter().any(|(k, v)| k == "content-type" && v == "image/png"),
        "served with the png content type: {headers:?}"
    );
    assert_eq!(body, stored_bytes, "served bytes are the stored bytes");

    // 4. The validation still refuses what it exists to refuse.
    let mut bad_stem = stem.to_string();
    bad_stem.replace_range(0..1, "z");
    let (status, _, _) = get(addr, &format!("/media/{bad_stem}.png")).await;
    assert_eq!(status, 404, "non-hex stem is refused");
    let (status, _, _) = get(addr, "/media/00000000000000000000000000000000.png").await;
    assert_eq!(status, 404, "well-formed but absent ref is 404");
    let (status, _, _) = get(addr, &format!("/media/{stem}.gif")).await;
    assert_eq!(status, 404, "non-image extension is refused");

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
