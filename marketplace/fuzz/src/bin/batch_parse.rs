//! Fuzz target (Modules Audit BL2, 2026-10-19): the payment-batch
//! parser — seller-helper batch JSON as parsed by
//! `app::payments::upload_batch`'s front end.
//!
//! Real entry points: `app::payments::parse_batch_header` (the exact
//! function upload_batch runs first: JSON parse + format /
//! marketplace / network header checks) and, for every entry of a
//! batch whose header parses, the per-entry pure checks upload_batch
//! performs before any database write: subaddress validation and the
//! canonical-message rebuild comparison.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let cfg = app::payments::PaymentConfig::defaults("vespiary-market");
    if let Ok(batch) = app::payments::parse_batch_header(text, &cfg) {
        for e in &batch.entries {
            let _ = modules_api::Subaddress::validate(&e.subaddress, cfg.network);
            let want = app::payments::canonical_message(
                &cfg.marketplace_id,
                cfg.network,
                &batch.seller_id,
                &batch.primary_address,
                &e.subaddress,
            );
            let _ = e.message == want;
        }
    }
});
