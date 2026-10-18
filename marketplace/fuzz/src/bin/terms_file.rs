//! Fuzz target (§22.5): the terms file.
//!
//! There is no terms-file *parser* in the codebase — §10 terms files
//! are generated, never parsed back: the real surface is the builder,
//! `app::orders::build_terms`, fed with seller-controlled title /
//! description / delivery / refund text (plus ids and totals), and the
//! statement parsers' `terms-sha256` field gate, which the
//! `statements` target already covers. This target fuzzes the builder
//! with the fuzzer's bytes distributed across its free-text fields and
//! asserts: no panic, deterministic output, and the fixed
//! `marketplace-terms-v1` header.
//!
//! (If a terms parser is ever written, it gets its own target and this
//! note must be updated.)
#![no_main]

use libfuzzer_sys::fuzz_target;

/// Split at the largest char boundary <= `idx`. (The first version of
/// this target used plain `split_at(len/4)`, which itself panicked on
/// multi-byte input — crash-4c1ebba7…, found and fixed 2026-10-17; the
/// bug was in this harness, not in `build_terms`.)
fn split_at_boundary(s: &str, mut idx: usize) -> (&str, &str) {
    if idx >= s.len() {
        return (s, "");
    }
    while !s.is_char_boundary(idx) {
        idx -= 1;
    }
    s.split_at(idx)
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Rotate the input through the four free-text fields by quarters so
    // mutations explore each field's normalisation (CRLF folding, NFC).
    let q = text.len() / 4;
    let (title, rest) = split_at_boundary(text, q);
    let (desc, rest) = split_at_boundary(rest, q);
    let (delivery, refund) = split_at_boundary(rest, rest.len() / 2);
    let build = |title: &str, desc: &str, delivery: &str, refund: &str| {
        app::orders::build_terms(
            "mkt_4f9c2a7e1b3d5f60718293a4b5c6d7e8",
            "ord_2b6a9e4d1c083f5a7c9e1b2d4f607182",
            "lst_00000000000000000000000000000000",
            "acct_00000000000000000000000000000000",
            "acct_11111111111111111111111111111111",
            "0123456789ABCDEF0123456789ABCDEF01234567",
            1,
            1_250_000_000_000,
            "xmr-only",
            "2026-10-17T00:00:00Z",
            title,
            desc,
            delivery,
            refund,
        )
    };
    let a = build(title, desc, delivery, refund);
    let b = build(title, desc, delivery, refund);
    assert_eq!(a, b, "terms builder must be deterministic");
    assert!(a.starts_with(b"statement-format: marketplace-terms-v1\n"));
});
