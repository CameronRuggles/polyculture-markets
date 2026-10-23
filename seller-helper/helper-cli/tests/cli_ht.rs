//! CLI integration tests for the Hidden Trades commands (HT H1
//! audit fix task 8; findings F9/F10/F13): `helper init`,
//! `helper seller terms`, `helper seller assign`,
//! `helper buyer pin`, `helper buyer verify`, and both status
//! commands, driven end-to-end through the real binary. Library
//! calls are used only to build fixtures (keys) and to fetch what
//! the seller's store saved (the terms files a buyer would receive
//! over the conversation) — every behaviour asserted here is the
//! binary's.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const MKT: &str = "mkt_0123456789abcdef0123456789abcdef";
const LISTING: &str = "lst_00000000000000000000000000000001";
const SUB: &str =
    "75VjEqDg5fp7hyErNLsyRK59sHRJjLX3fTvARvKvGodj5PPajrWjmyQ2mvuPWWMWi4HNS5jg4jvyYLREvx63KZe4HK7sbH8";

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_helper"))
        .args(args)
        .env("PCM_HELPER_PASSPHRASE", "")
        .stdin(Stdio::null())
        .output()
        .expect("run helper")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

struct Fixture {
    dir: PathBuf,
    seller_cfg: PathBuf,
    buyer_cfg: PathBuf,
    seller_store: PathBuf,
    buyer_store: PathBuf,
    seller_cert: PathBuf,
    seller_fpr: String,
    buyer_fpr: String,
}

fn fixture(tag: &str) -> Fixture {
    let dir = std::env::temp_dir().join(format!("pcm-cli-ht-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (seller_sec, seller_pub) =
        helper_core::keys::generate_test_cert("Seller <seller@example.com>").unwrap();
    let (buyer_sec, buyer_pub) =
        helper_core::keys::generate_test_cert("Buyer <buyer@example.com>").unwrap();
    let seller_key = dir.join("seller.key");
    let seller_cert = dir.join("seller.asc");
    let buyer_key = dir.join("buyer.key");
    let buyer_cert = dir.join("buyer.asc");
    std::fs::write(&seller_key, &seller_sec).unwrap();
    std::fs::write(&seller_cert, &seller_pub).unwrap();
    std::fs::write(&buyer_key, &buyer_sec).unwrap();
    std::fs::write(&buyer_cert, &buyer_pub).unwrap();
    let seller_fpr = helper_core::keys::fingerprint_of(&seller_pub).unwrap();
    let buyer_fpr = helper_core::keys::fingerprint_of(&buyer_pub).unwrap();
    let seller_cfg = dir.join("seller.json");
    let buyer_cfg = dir.join("buyer.json");
    let seller_store = dir.join("seller-store");
    let buyer_store = dir.join("buyer-store");
    for (cfg, key, cert, store) in [
        (&seller_cfg, &seller_key, &seller_cert, &seller_store),
        (&buyer_cfg, &buyer_key, &buyer_cert, &buyer_store),
    ] {
        let out = run(&[
            "init",
            "--core-config",
            cfg.to_str().unwrap(),
            "--marketplace-id",
            MKT,
            "--network",
            "monero-stagenet",
            "--key-file",
            key.to_str().unwrap(),
            "--cert-file",
            cert.to_str().unwrap(),
            "--store-dir",
            store.to_str().unwrap(),
        ]);
        assert!(out.status.success(), "init failed: {}", stderr(&out));
        assert!(stdout(&out).contains("Wrote helper config"), "{}", stdout(&out));
    }
    Fixture {
        dir,
        seller_cfg,
        buyer_cfg,
        seller_store,
        buyer_store,
        seller_cert,
        seller_fpr,
        buyer_fpr,
    }
}

/// Run `seller terms` + `seller assign` on the fixture; returns
/// the trade id. The assignment and terms files a buyer would
/// receive are written into `fx.dir` as assignment.txt/.sig,
/// terms-statement.txt/.sig, terms-text.txt.
fn seller_side_trade(fx: &Fixture) -> String {
    let out = run(&[
        "seller",
        "terms",
        "--core-config",
        fx.seller_cfg.to_str().unwrap(),
        "--listing",
        LISTING,
        "--title",
        "One careful widget",
        "--description",
        "A widget, carefully kept.",
        "--delivery-terms",
        "Ships within two days, tracked.",
        "--refund-terms",
        "Full refund if it arrives broken.",
        "--price",
        "0.25",
        "--transit-risk",
        "seller",
        "--remedy-cap-pct",
        "25",
        "--payment-timing",
        "prepay",
    ]);
    assert!(out.status.success(), "seller terms failed: {}", stderr(&out));
    assert!(stdout(&out).contains("marketplace-terms-v2"), "{}", stdout(&out));

    let batch = fx.dir.join("batch.json");
    std::fs::write(&batch, format!("{{\"entries\":[{{\"subaddress\":\"{SUB}\"}}]}}")).unwrap();
    let out = run(&[
        "seller",
        "assign",
        "--core-config",
        fx.seller_cfg.to_str().unwrap(),
        "--listing",
        LISTING,
        "--buyer",
        &fx.buyer_fpr,
        "--batch",
        batch.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "seller assign failed: {}", stderr(&out));
    assert!(stdout(&out).contains("Assignment for trade"), "{}", stdout(&out));

    // Fetch what the conversation would carry from the seller's
    // own records.
    let store = helper_core::store::EvidenceStore::open(fx.seller_store.clone()).unwrap();
    let ids = store.trade_ids().expect("readable store lists its trades");
    assert_eq!(ids.len(), 1, "exactly one trade in the seller store");
    let trade_id = ids[0].clone();
    let tdir = store.trade_dir(&trade_id);
    std::fs::copy(tdir.join("00-assignment.txt"), fx.dir.join("assignment.txt")).unwrap();
    std::fs::copy(tdir.join("00-assignment.sig"), fx.dir.join("assignment.txt.sig")).unwrap();
    let saved = helper_core::store::load_terms(&store, LISTING).expect("saved terms");
    std::fs::write(fx.dir.join("terms-statement.txt"), &saved.statement).unwrap();
    std::fs::write(fx.dir.join("terms-statement.txt.sig"), &saved.signature).unwrap();
    std::fs::write(fx.dir.join("terms-text.txt"), &saved.terms_text).unwrap();
    trade_id
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn terms_assign_pin_verify_and_status_end_to_end() {
    let fx = fixture("e2e");
    let trade_id = seller_side_trade(&fx);

    // buyer pin
    let out = run(&["buyer", "pin", p(&fx.seller_cert), "--core-config", p(&fx.buyer_cfg)]);
    assert!(out.status.success(), "buyer pin failed: {}", stderr(&out));
    assert!(stdout(&out).contains(&format!("Pinned {}", fx.seller_fpr)), "{}", stdout(&out));

    // buyer verify
    let out = run(&[
        "buyer",
        "verify",
        "--core-config",
        p(&fx.buyer_cfg),
        "--assignment",
        p(&fx.dir.join("assignment.txt")),
        "--terms",
        p(&fx.dir.join("terms-statement.txt")),
        "--terms-text",
        p(&fx.dir.join("terms-text.txt")),
    ]);
    assert!(out.status.success(), "buyer verify failed: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("Assignment checks passed (signature, terms, destination, amount, expiry)."),
        "{text}"
    );
    assert!(text.contains(&format!("Trade {trade_id}")), "{text}");
    assert!(text.contains(&format!("Pay 0.25 XMR to {SUB}")), "{text}");

    // both status commands fold the trade
    for (mode, cfg) in [("seller", &fx.seller_cfg), ("buyer", &fx.buyer_cfg)] {
        let out = run(&[mode, "status", "--core-config", p(cfg)]);
        assert!(out.status.success(), "{mode} status failed: {}", stderr(&out));
        let text = stdout(&out);
        assert!(text.contains(&trade_id), "{mode} status: {text}");
        assert!(text.contains("state=Assigned"), "{mode} status: {text}");
    }

    // F13 parse-back at the CLI: off-platform terms at version 1
    // are refused by `seller terms` itself; version 0 succeeds.
    let out = run(&[
        "seller",
        "terms",
        "--core-config",
        p(&fx.seller_cfg),
        "--listing",
        "off-platform",
        "--version",
        "1",
        "--title",
        "T",
        "--description",
        "D",
        "--delivery-terms",
        "X",
        "--refund-terms",
        "Y",
        "--price",
        "0.1",
        "--transit-risk",
        "seller",
        "--remedy-cap-pct",
        "25",
        "--payment-timing",
        "prepay",
    ]);
    assert!(!out.status.success(), "off-platform v1 must refuse: {}", stdout(&out));
    assert!(stderr(&out).contains("does not re-parse"), "{}", stderr(&out));
}

#[test]
fn refused_verify_with_wrong_seller_cert_leaves_no_pin() {
    let fx = fixture("tofu");
    let _trade_id = seller_side_trade(&fx);

    // A third party's certificate offered as the seller's: the
    // fingerprint cannot match, the verify must refuse, and —
    // F9 — NOTHING may be pinned by the attempt.
    let (third_sec, third_pub) =
        helper_core::keys::generate_test_cert("Third <third@example.com>").unwrap();
    let _ = third_sec;
    let third_cert = fx.dir.join("third.asc");
    std::fs::write(&third_cert, &third_pub).unwrap();

    let pins_dir = fx.buyer_store.join("pins");
    let pins_before: Vec<String> = std::fs::read_dir(&pins_dir)
        .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    assert!(pins_before.is_empty(), "fresh buyer store has no pins: {pins_before:?}");

    let out = run(&[
        "buyer",
        "verify",
        "--core-config",
        p(&fx.buyer_cfg),
        "--assignment",
        p(&fx.dir.join("assignment.txt")),
        "--terms",
        p(&fx.dir.join("terms-statement.txt")),
        "--terms-text",
        p(&fx.dir.join("terms-text.txt")),
        "--seller-cert",
        p(&third_cert),
    ]);
    assert!(!out.status.success(), "wrong-cert verify must refuse: {}", stdout(&out));
    assert!(stderr(&out).contains("not pinned"), "{}", stderr(&out));
    let pins_after: Vec<String> = std::fs::read_dir(&pins_dir)
        .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    assert!(pins_after.is_empty(), "a refused verify must leave no pin: {pins_after:?}");

    // The correct certificate pins on first use and verifies.
    let out = run(&[
        "buyer",
        "verify",
        "--core-config",
        p(&fx.buyer_cfg),
        "--assignment",
        p(&fx.dir.join("assignment.txt")),
        "--terms",
        p(&fx.dir.join("terms-statement.txt")),
        "--terms-text",
        p(&fx.dir.join("terms-text.txt")),
        "--seller-cert",
        p(&fx.seller_cert),
    ]);
    assert!(out.status.success(), "TOFU verify failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains("Assignment checks passed (signature, terms, destination, amount, expiry)."),
        "{}",
        stdout(&out)
    );
    let pin_file = pins_dir.join(format!("{}.asc", fx.seller_fpr));
    assert!(pin_file.exists(), "the matching certificate is pinned after a good verify");
}

#[test]
fn status_over_an_unreadable_store_prints_the_error_row_and_fails() {
    // E11 (audit 3): the `(evidence store) ERROR:` row exists at
    // the CLI since N8, but the command exited 0 — a script
    // checking the exit code was told the status succeeded while
    // looking at a broken store. A store-level error row now
    // comes with a non-zero exit; per-trade F10 rows keep exit 0
    // (the healthy statuses here and in the end-to-end test pin
    // the success side).
    let fx = fixture("status-error");
    let _trade_id = seller_side_trade(&fx);
    // Control: the healthy store's status succeeds.
    let out = run(&["seller", "status", "--core-config", p(&fx.seller_cfg)]);
    assert!(out.status.success(), "healthy seller status failed: {}", stderr(&out));
    assert!(stdout(&out).contains("state=Assigned"), "{}", stdout(&out));

    // Plant an entry whose type cannot be determined inside the
    // trades directory (a dangling symlink — E2's shape): the
    // enumeration fails, so status can only print the store row.
    std::os::unix::fs::symlink(
        fx.dir.join("no-such-target"),
        fx.seller_store.join("trades").join("trd_dangling"),
    )
    .unwrap();
    let out = run(&["seller", "status", "--core-config", p(&fx.seller_cfg)]);
    let text = stdout(&out);
    assert!(text.contains("(evidence store)  ERROR:"), "{text}");
    assert!(
        !out.status.success(),
        "a store-level ERROR row must exit non-zero, got {:?}: {text}",
        out.status.code()
    );

    // Buyer status is the same command over the buyer's own
    // store; that store is healthy, so it still succeeds — the
    // failure belongs to the store, not the mode.
    let out = run(&["buyer", "status", "--core-config", p(&fx.buyer_cfg)]);
    assert!(out.status.success(), "healthy buyer status failed: {}", stderr(&out));
}
