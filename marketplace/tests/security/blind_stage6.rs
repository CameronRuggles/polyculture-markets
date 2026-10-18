//! Blind security suite — Stage 6 CORE: canonical statement library,
//! payment URI / QR, and `xmr-only` pricing (spec §10, §11; api-contract §12).
//!
//! Authored from documents alone (spec §10/§11/§24, SPEC-V2-AMENDMENTS.md,
//! docs/api-contract.md) under §22 test-independence rules. The author has
//! not read any implementation code.
//!
//! =====================================================================
//! PLAIN-LANGUAGE ASSERTION LIST (owner-readable; grouped)
//! =====================================================================
//!
//! Valid statements:
//! - A correct invoice statement is accepted, and printing it back
//!   reproduces the submitted bytes exactly, byte for byte.
//! - A correct address-pool statement is accepted and likewise
//!   reproduces byte-for-byte, for pools of 1, 3, and 200 addresses.
//! - A pool claiming 201 addresses is refused.
//! - An invoice built in code (not parsed) prints as exactly the
//!   canonical text, and parsing that text gives back the same
//!   statement field by field; same for a pool built in code.
//! - Fingerprints of both allowed lengths (40 and 64 hex) are accepted.
//!
//! Byte-identity attacks (both invoice and pool parsers refuse each):
//! - Windows (CRLF) line endings; a missing final newline; two final
//!   newlines; a blank line in the middle; a trailing space on a line;
//!   two spaces after a colon; no space after a colon; a tab anywhere;
//!   a non-ASCII character; two neighbouring fields swapped; a field
//!   repeated; an extra unknown field; a wrong statement-format value;
//!   an invoice fed to the pool parser and a pool fed to the invoice
//!   parser.
//!
//! IDs:
//! - An ID with the wrong prefix for its field is refused; an ID with
//!   31 or 33 hex characters is refused; an ID with uppercase hex is
//!   refused; an ID with a non-hex character is refused.
//! - A statement naming a different marketplace than this instance is
//!   refused.
//!
//! Fingerprints and digests:
//! - A lowercase fingerprint is refused; fingerprints of length 39, 41,
//!   63, or 65 are refused.
//! - A terms digest with uppercase hex is refused; digests of length
//!   63 or 65 are refused.
//!
//! Networks and destinations:
//! - A network value outside the three allowed spellings is refused.
//! - A statement whose network differs from this instance's network is
//!   refused, in both directions.
//! - An invoice whose destination is a genuine subaddress of a
//!   DIFFERENT network than its own network line is refused; a pool
//!   containing even one different-network address among good ones is
//!   refused.
//! - A standard (primary) address or an integrated address used as an
//!   invoice destination or pool entry is refused; a garbage
//!   destination string is refused.
//!
//! Numbers:
//! - An amount with leading zeros, a plus sign, an internal space, an
//!   empty value, or a value too big for u64 is refused; an amount of
//!   zero is refused; an amount exactly at the configured maximum is
//!   accepted and one unit above it is refused.
//! - A pool address-count of 0 or 201 is refused; a count with leading
//!   zeros is refused; a count that disagrees with the number of
//!   address lines, in either direction, is refused.
//!
//! Timestamps:
//! - A leap second (:60), February 30, month 13, a +00:00 offset
//!   instead of Z, missing seconds, a space instead of the T, and a
//!   lowercase z are each refused; a genuine leap-day timestamp is
//!   accepted.
//!
//! Pool structure:
//! - Address lines that are not last are refused; the same address
//!   appearing twice in one pool is refused.
//!
//! No trimming (Q13 — the statement library never normalizes):
//! - Whitespace before or after the whole statement is refused; a
//!   space before a value is refused; the payment URI contains no
//!   whitespace and spells the destination exactly as the validated
//!   address type renders it.
//!
//! Payment URI:
//! - The URI for a known invoice is exactly "monero:" + destination +
//!   "?tx_amount=" + the amount in decimal XMR (1.25 XMR renders as
//!   1.25, a whole XMR amount renders with no decimal point, 1 atomic
//!   unit renders as 0.000000000001); it carries no other parameter;
//!   asking twice gives the identical string.
//!
//! QR code:
//! - The QR output starts with the PNG magic bytes; two calls give
//!   identical bytes; a different amount gives different bytes; the
//!   output is a real image, not a stub (over 200 bytes).
//!
//! Typing (Q17):
//! - A parsed statement's network is the closed Network type (not a
//!   string) and agrees with its destination's network; a pool's
//!   network agrees with every address it contains.
//!
//! Pricing:
//! - The pricing module id is exactly "xmr-only".
//! - Totals are exact products, including large values; a product
//!   that would overflow u64 yields "no total" instead of wrapping;
//!   a zero unit price yields a zero total (quantity rules live at
//!   the order layer, not in this helper).
//!
//! Supporting address/amount types (§1, §8):
//! - A genuine subaddress validates on its own network, reports that
//!   network as the enum, and re-renders as the identical string; a
//!   primary address, a different network, and a whitespace-wrapped
//!   address are each refused.
//! - Decimal XMR amounts format canonically (whole amounts have no
//!   decimal point) and parse back exactly.
//! =====================================================================
//!
//! Fixtures — real Monero addresses only (Q7b method). All fixtures are
//! valueless throwaway addresses generated OFFLINE on 2026-10-14 with
//! monero-wallet-cli / monero-wallet-rpc v0.18.4.3
//! (downloads/monero-x86_64-linux-gnu-v0.18.4.3), empty passwords,
//! wallets in /tmp:
//! - STAGE_PRIMARY: account-0 primary of a `--stagenet --offline`
//!   wallet ("Generated new wallet" output).
//! - STAGE_SUB_A/B/C and POOL200[..]: subaddresses of that same
//!   stagenet wallet, created via wallet RPC `create_address`
//!   (account 0, indices 1..=205).
//! - STAGE_INTEGRATED: that wallet's `make_integrated_address` output.
//! - MAIN_SUB: subaddress (account 0, index 1) of a mainnet `--offline`
//!   wallet. TEST_SUB: subaddress (account 0, index 1) of a
//!   `--testnet --offline` wallet.
//! Every fixture was verified with the wallet's own `validate_address`
//! RPC (any_net) against a wallet RPC server of its own network:
//! stagenet fixtures -> valid, nettype stagenet, subaddress flag true
//! for A/B/C, false + integrated true for the integrated address,
//! false/false for the primary; MAIN_SUB -> valid mainnet subaddress;
//! TEST_SUB -> valid testnet subaddress. No implementation code was
//! used to check any fixture.

use domain::statements::{
    parse_invoice_statement, parse_pool_statement, payment_qr_png, payment_uri,
    InvoiceStatement, PoolStatement,
};
use domain::{xmr_only_total, Atomic, PRICING_MODULE_XMR_ONLY};
use modules_api::{Network, Subaddress};

// ---------------------------------------------------------------------
// Fixtures (see header for generation + verification method)
// ---------------------------------------------------------------------

/// Stagenet standard (primary) address, account 0 index 0.
const STAGE_PRIMARY: &str =
    "55b6gZhKJ2b6EzvernZJBcPXiZym13w1CfbpDU6sR8aSGpaRbAmU4EMSH3XYXu5U1cSac7B49WRSSBbwQK9by3c7H9AdnFB";
/// Stagenet subaddress, account 0 index 1.
const STAGE_SUB_A: &str =
    "7B2BSyZukau1TerLFtd6UtDvgz7YZVKGmV9xNowvh74biBFvjXTcWAu8EMJ1ot7sCHHCXrg6QRTHgNfoGsQRRj3xRqNnPFd";
/// Stagenet subaddress, account 0 index 2.
const STAGE_SUB_B: &str =
    "77cfgTU2rrsVSKhJzJohXzJBkx4cnJTPHDWK6sRxNT9U2cksSvg5mnTMV78PbMuA1mhvm5RaFgUV7DFc4ze9yq5jTwTPPpc";
/// Stagenet subaddress, account 0 index 3.
const STAGE_SUB_C: &str =
    "7BMUYtFiouid14Qret4pFbe26a5pUri7mifsd3hAW8CX5mV3N42AcsyAE5csiFgdFe6xZyet1PgVQ7g864RLMXdZ5raBeQ4";
/// Stagenet integrated address (primary keys + payment id), 106 chars.
const STAGE_INTEGRATED: &str =
    "5FHmhNWouJ76EzvernZJBcPXiZym13w1CfbpDU6sR8aSGpaRbAmU4EMSH3XYXu5U1cSac7B49WRSSBbwQK9by3c7R3PDbmJGUNm7bwo6K9";
/// Mainnet subaddress, account 0 index 1 of a mainnet wallet.
const MAIN_SUB: &str =
    "8AH28DTbc3cYwUv6YZeq9ujTNWvrMyMxXaJaDt9yEpnTLiQpBfYssq4PNxMJywinEignsaB5jkfgNeSQFgsoyPn2CW7kmSL";
/// Testnet subaddress, account 0 index 1 of a testnet wallet.
const TEST_SUB: &str =
    "BeN6Lux9bLxFR89ts6frTFZtVEXjDgVm8ae4NmZLVvuk38xwtA4UqDjC9HyUtAzzx6hZ712k2tms6j8bAgU3KWYKUg7gc2Y";

/// Stagenet subaddress, account 0 index 201 (the 201st distinct entry,
/// used only by the over-maximum pool test).
const SUB201: &str = "79P6EcofPJEKRX3ErDWChmeGc6adA7kwPGxMvyJaVvBm9nHWpQK1RzWSw1Du5ur5E339Ai93awP9u6kxazUZxGmYQsUvZpz";

/// 200 distinct stagenet subaddresses (account 0, indices 1..=200 of the
/// fixture wallet), for the maximum-size pool boundary case.
const POOL200: [&str; 200] = [
    "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",
];

// ---------------------------------------------------------------------
// Canonical-text builders and shared constants
// ---------------------------------------------------------------------

const MKT: &str = "mkt_4f9c2a7e1b3d5f60718293a4b5c6d7e8";
const MKT_OTHER: &str = "mkt_00000000000000000000000000000000";
const INV: &str = "inv_8d1e5b0c3a7f2b4d6f8091a3b5c7d9e0";
const ORD: &str = "ord_2b6a9e4d1c083f5a7c9e1b2d4f607182";
const POOL: &str = "pool_6c0e3f9a5b7d9f1a2c4e6a8b0d2f4a6b";
const FPR40: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
const FPR64: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
const TERMS: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// Generous amount cap for tests that are not about the cap itself.
const MAX_BIG: u64 = 1_000_000_000_000_000;

fn invoice_text() -> String {
    format!(
        "statement-format: marketplace-invoice-v1\n\
         marketplace-id: {MKT}\n\
         invoice-id: {INV}\n\
         order-id: {ORD}\n\
         seller-key-fingerprint: {FPR40}\n\
         network: monero-stagenet\n\
         destination: {STAGE_SUB_A}\n\
         amount-atomic: 1250000000000\n\
         expires-at: 2026-10-16T17:00:00Z\n\
         terms-sha256: {TERMS}\n"
    )
}

fn mainnet_invoice_text() -> String {
    invoice_text()
        .replacen("network: monero-stagenet", "network: monero-mainnet", 1)
        .replacen(STAGE_SUB_A, MAIN_SUB, 1)
}

fn pool_text() -> String {
    format!(
        "statement-format: marketplace-address-pool-v1\n\
         marketplace-id: {MKT}\n\
         pool-id: {POOL}\n\
         seller-key-fingerprint: {FPR40}\n\
         network: monero-stagenet\n\
         created-at: 2026-10-13T16:00:00Z\n\
         address-count: 3\n\
         address: {STAGE_SUB_A}\n\
         address: {STAGE_SUB_B}\n\
         address: {STAGE_SUB_C}\n"
    )
}

fn pool_text_for(addrs: &[&str]) -> String {
    let mut s = format!(
        "statement-format: marketplace-address-pool-v1\n\
         marketplace-id: {MKT}\n\
         pool-id: {POOL}\n\
         seller-key-fingerprint: {FPR40}\n\
         network: monero-stagenet\n\
         created-at: 2026-10-13T16:00:00Z\n\
         address-count: {}\n",
        addrs.len()
    );
    for a in addrs {
        s.push_str(&format!("address: {a}\n"));
    }
    s
}

fn parse_inv(text: &str) -> Option<InvoiceStatement> {
    parse_invoice_statement(text, MKT, Network::Stagenet, MAX_BIG)
}

fn parse_pool(text: &str) -> Option<PoolStatement> {
    parse_pool_statement(text, MKT, Network::Stagenet)
}

/// Both parsers must refuse the (separately mutated) texts.
fn assert_both_reject(inv: String, pool: String, rule: &str) {
    assert!(parse_inv(&inv).is_none(), "invoice parser must reject: {rule}");
    assert!(parse_pool(&pool).is_none(), "pool parser must reject: {rule}");
}

// ---------------------------------------------------------------------
// Valid statements and round-trips
// ---------------------------------------------------------------------

#[test]
fn invoice_valid_parses_and_roundtrips() {
    let text = invoice_text();
    let inv = parse_inv(&text).expect("a correct invoice statement is accepted");
    assert_eq!(inv.marketplace_id, MKT, "marketplace-id field survives parsing");
    assert_eq!(inv.invoice_id, INV, "invoice-id field survives parsing");
    assert_eq!(inv.order_id, ORD, "order-id field survives parsing");
    assert_eq!(inv.seller_key_fingerprint, FPR40, "fingerprint field survives parsing");
    assert!(
        matches!(inv.network, Network::Stagenet),
        "network field is the Stagenet enum value"
    );
    assert_eq!(
        inv.destination.as_str(),
        STAGE_SUB_A,
        "destination re-renders as the exact submitted subaddress"
    );
    assert_eq!(inv.amount_atomic, 1_250_000_000_000, "amount field survives parsing");
    assert_eq!(inv.expires_at, "2026-10-16T17:00:00Z", "expiry field survives parsing");
    assert_eq!(inv.terms_sha256, TERMS, "terms digest field survives parsing");
    assert_eq!(
        inv.to_bytes(),
        text.as_bytes(),
        "to_bytes() reproduces the input byte-for-byte"
    );
}

#[test]
fn invoice_valid_mainnet_parses_on_mainnet_instance() {
    let text = mainnet_invoice_text();
    let inv = parse_invoice_statement(&text, MKT, Network::Mainnet, MAX_BIG)
        .expect("a correct mainnet invoice is accepted on a mainnet instance");
    assert!(matches!(inv.network, Network::Mainnet), "network is the Mainnet enum value");
    assert_eq!(inv.destination.as_str(), MAIN_SUB, "mainnet destination survives parsing");
    assert_eq!(inv.to_bytes(), text.as_bytes(), "mainnet invoice round-trips byte-for-byte");
}

#[test]
fn invoice_valid_testnet_parses_on_testnet_instance() {
    let text = invoice_text()
        .replacen("network: monero-stagenet", "network: monero-testnet", 1)
        .replacen(STAGE_SUB_A, TEST_SUB, 1);
    let inv = parse_invoice_statement(&text, MKT, Network::Testnet, MAX_BIG)
        .expect("a correct testnet invoice is accepted on a testnet instance");
    assert!(matches!(inv.network, Network::Testnet), "network is the Testnet enum value");
    assert_eq!(inv.to_bytes(), text.as_bytes(), "testnet invoice round-trips byte-for-byte");
}

#[test]
fn pool_valid_parses_and_roundtrips() {
    let text = pool_text();
    let pool = parse_pool(&text).expect("a correct pool statement is accepted");
    assert_eq!(pool.marketplace_id, MKT, "marketplace-id field survives parsing");
    assert_eq!(pool.pool_id, POOL, "pool-id field survives parsing");
    assert_eq!(pool.seller_key_fingerprint, FPR40, "fingerprint field survives parsing");
    assert!(matches!(pool.network, Network::Stagenet), "network is the Stagenet enum value");
    assert_eq!(pool.created_at, "2026-10-13T16:00:00Z", "created-at field survives parsing");
    assert_eq!(pool.addresses.len(), 3, "all three addresses are parsed");
    let rendered: Vec<String> = pool.addresses.iter().map(|a| a.as_str()).collect();
    assert_eq!(
        rendered,
        vec![STAGE_SUB_A.to_string(), STAGE_SUB_B.to_string(), STAGE_SUB_C.to_string()],
        "pool addresses re-render in order as the exact submitted strings"
    );
    assert_eq!(pool.to_bytes(), text.as_bytes(), "to_bytes() reproduces the input byte-for-byte");
}

#[test]
fn pool_valid_single_address_accepted() {
    let text = pool_text_for(&[STAGE_SUB_A]);
    let pool = parse_pool(&text).expect("address-count 1 (the minimum) is accepted");
    assert_eq!(pool.addresses.len(), 1, "single-entry pool holds one address");
    assert_eq!(pool.to_bytes(), text.as_bytes(), "single-entry pool round-trips byte-for-byte");
}

#[test]
fn pool_200_addresses_accepted() {
    let text = pool_text_for(&POOL200);
    let pool = parse_pool(&text).expect("a 200-address pool (the maximum) is accepted");
    assert_eq!(pool.addresses.len(), 200, "all 200 addresses are parsed");
    assert_eq!(pool.to_bytes(), text.as_bytes(), "200-address pool round-trips byte-for-byte");
}

#[test]
fn pool_201_addresses_rejected() {
    let mut addrs: Vec<&str> = POOL200.to_vec();
    addrs.push(SUB201);
    let text = pool_text_for(&addrs);
    assert!(
        text.contains("address-count: 201\n"),
        "fixture construction: the 201 case really claims 201"
    );
    assert!(parse_pool(&text).is_none(), "address-count above 200 is rejected");
}

#[test]
fn invoice_serializer_built_value_matches_canonical_text() {
    let dest = Subaddress::validate(STAGE_SUB_A, Network::Stagenet)
        .expect("fixture subaddress validates on stagenet");
    let inv = InvoiceStatement {
        marketplace_id: MKT.to_string(),
        invoice_id: INV.to_string(),
        order_id: ORD.to_string(),
        seller_key_fingerprint: FPR40.to_string(),
        network: Network::Stagenet,
        destination: dest,
        amount_atomic: 1_250_000_000_000,
        expires_at: "2026-10-16T17:00:00Z".to_string(),
        terms_sha256: TERMS.to_string(),
    };
    let bytes = inv.to_bytes();
    assert_eq!(
        bytes,
        invoice_text().as_bytes(),
        "a directly built invoice serializes to exactly the canonical text"
    );
    let back = parse_inv(std::str::from_utf8(&bytes).expect("serialized bytes are UTF-8"))
        .expect("serialized invoice parses back");
    assert_eq!(back.marketplace_id, inv.marketplace_id, "round-trip: marketplace-id equal");
    assert_eq!(back.invoice_id, inv.invoice_id, "round-trip: invoice-id equal");
    assert_eq!(back.order_id, inv.order_id, "round-trip: order-id equal");
    assert_eq!(
        back.seller_key_fingerprint, inv.seller_key_fingerprint,
        "round-trip: fingerprint equal"
    );
    assert!(matches!(back.network, Network::Stagenet), "round-trip: network equal");
    assert_eq!(
        back.destination.as_str(),
        inv.destination.as_str(),
        "round-trip: destination equal"
    );
    assert_eq!(back.amount_atomic, inv.amount_atomic, "round-trip: amount equal");
    assert_eq!(back.expires_at, inv.expires_at, "round-trip: expires-at equal");
    assert_eq!(back.terms_sha256, inv.terms_sha256, "round-trip: terms digest equal");
}

#[test]
fn pool_serializer_built_value_matches_canonical_text() {
    let mk = |s: &str| Subaddress::validate(s, Network::Stagenet).expect("fixture validates");
    let pool = PoolStatement {
        marketplace_id: MKT.to_string(),
        pool_id: POOL.to_string(),
        seller_key_fingerprint: FPR40.to_string(),
        network: Network::Stagenet,
        created_at: "2026-10-13T16:00:00Z".to_string(),
        addresses: vec![mk(STAGE_SUB_A), mk(STAGE_SUB_B), mk(STAGE_SUB_C)],
    };
    let bytes = pool.to_bytes();
    assert_eq!(
        bytes,
        pool_text().as_bytes(),
        "a directly built pool serializes to exactly the canonical text"
    );
    let back = parse_pool(std::str::from_utf8(&bytes).expect("serialized bytes are UTF-8"))
        .expect("serialized pool parses back");
    assert_eq!(back.pool_id, pool.pool_id, "round-trip: pool-id equal");
    assert_eq!(back.addresses.len(), 3, "round-trip: address count equal");
    for (a, b) in back.addresses.iter().zip(pool.addresses.iter()) {
        assert_eq!(a.as_str(), b.as_str(), "round-trip: each address equal");
    }
}

// ---------------------------------------------------------------------
// Byte-identity attacks (both parsers)
// ---------------------------------------------------------------------

#[test]
fn bytes_crlf_line_endings_rejected() {
    assert_both_reject(
        invoice_text().replace('\n', "\r\n"),
        pool_text().replace('\n', "\r\n"),
        "CRLF line endings are not canonical bytes",
    );
}

#[test]
fn bytes_missing_final_lf_rejected() {
    let mut i = invoice_text();
    i.pop();
    let mut p = pool_text();
    p.pop();
    assert_both_reject(i, p, "exactly one final LF is required");
}

#[test]
fn bytes_two_final_lfs_rejected() {
    assert_both_reject(
        format!("{}\n", invoice_text()),
        format!("{}\n", pool_text()),
        "a second final LF is a blank line and is rejected",
    );
}

#[test]
fn bytes_blank_line_rejected() {
    assert_both_reject(
        invoice_text().replacen("invoice-id:", "\ninvoice-id:", 1),
        pool_text().replacen("pool-id:", "\npool-id:", 1),
        "blank lines are forbidden",
    );
}

#[test]
fn bytes_trailing_space_on_line_rejected() {
    assert_both_reject(
        invoice_text().replacen("amount-atomic: 1250000000000\n", "amount-atomic: 1250000000000 \n", 1),
        pool_text().replacen("address-count: 3\n", "address-count: 3 \n", 1),
        "trailing spaces are forbidden",
    );
}

#[test]
fn bytes_two_spaces_after_colon_rejected() {
    assert_both_reject(
        invoice_text().replacen("invoice-id: ", "invoice-id:  ", 1),
        pool_text().replacen("pool-id: ", "pool-id:  ", 1),
        "exactly one space after the colon",
    );
}

#[test]
fn bytes_no_space_after_colon_rejected() {
    assert_both_reject(
        invoice_text().replacen("invoice-id: ", "invoice-id:", 1),
        pool_text().replacen("pool-id: ", "pool-id:", 1),
        "the single space after the colon is required",
    );
}

#[test]
fn bytes_tab_anywhere_rejected() {
    assert_both_reject(
        invoice_text().replacen("invoice-id: ", "invoice-id:\t", 1),
        pool_text().replacen("pool-id: ", "pool-id:\t", 1),
        "tabs are forbidden anywhere in a statement",
    );
}

#[test]
fn bytes_non_ascii_rejected() {
    assert_both_reject(
        invoice_text().replacen(TERMS, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde\u{e9}", 1),
        pool_text().replacen("2026-10-13", "2026-10-1\u{e9}", 1),
        "statements are printable ASCII plus LF only",
    );
}

#[test]
fn bytes_swapped_adjacent_fields_rejected() {
    let inv = invoice_text().replacen(
        &format!("invoice-id: {INV}\norder-id: {ORD}\n"),
        &format!("order-id: {ORD}\ninvoice-id: {INV}\n"),
        1,
    );
    let pool = pool_text().replacen(
        &format!("pool-id: {POOL}\nseller-key-fingerprint: {FPR40}\n"),
        &format!("seller-key-fingerprint: {FPR40}\npool-id: {POOL}\n"),
        1,
    );
    assert_both_reject(inv, pool, "field order is fixed by the layout");
}

#[test]
fn bytes_duplicated_field_rejected() {
    assert_both_reject(
        invoice_text().replacen(
            &format!("invoice-id: {INV}\n"),
            &format!("invoice-id: {INV}\ninvoice-id: {INV}\n"),
            1,
        ),
        pool_text().replacen(
            &format!("pool-id: {POOL}\n"),
            &format!("pool-id: {POOL}\npool-id: {POOL}\n"),
            1,
        ),
        "a field may not appear twice",
    );
}

#[test]
fn bytes_unknown_extra_field_rejected() {
    assert_both_reject(
        invoice_text().replacen(
            &format!("terms-sha256: {TERMS}\n"),
            &format!("terms-sha256: {TERMS}\nextra-field: x\n"),
            1,
        ),
        pool_text().replacen(
            "address-count: 3\n",
            "address-count: 3\nextra-field: x\n",
            1,
        ),
        "unknown fields are not part of the fixed layout",
    );
}

#[test]
fn bytes_wrong_statement_format_rejected() {
    assert_both_reject(
        invoice_text().replacen("marketplace-invoice-v1", "marketplace-invoice-v2", 1),
        pool_text().replacen("marketplace-address-pool-v1", "marketplace-pool-v1", 1),
        "statement-format must be the exact v1 value for the type",
    );
}

#[test]
fn bytes_cross_type_statement_rejected() {
    assert!(
        parse_pool(&invoice_text()).is_none(),
        "an invoice statement fed to the pool parser is rejected"
    );
    assert!(
        parse_inv(&pool_text()).is_none(),
        "a pool statement fed to the invoice parser is rejected"
    );
}

// ---------------------------------------------------------------------
// IDs
// ---------------------------------------------------------------------

#[test]
fn ids_wrong_prefix_for_field_rejected() {
    let inv = invoice_text().replacen(
        &format!("invoice-id: {INV}"),
        "invoice-id: ord_8d1e5b0c3a7f2b4d6f8091a3b5c7d9e0",
        1,
    );
    assert!(parse_inv(&inv).is_none(), "invoice-id must carry the inv_ prefix");
    let inv2 = invoice_text().replacen(
        &format!("order-id: {ORD}"),
        "order-id: inv_2b6a9e4d1c083f5a7c9e1b2d4f607182",
        1,
    );
    assert!(parse_inv(&inv2).is_none(), "order-id must carry the ord_ prefix");
    let pool = pool_text().replacen(
        &format!("pool-id: {POOL}"),
        "pool-id: inv_6c0e3f9a5b7d9f1a2c4e6a8b0d2f4a6b",
        1,
    );
    assert!(parse_pool(&pool).is_none(), "pool-id must carry the pool_ prefix");
}

#[test]
fn ids_31_and_33_hex_chars_rejected() {
    let inv31 = invoice_text().replacen(INV, "inv_8d1e5b0c3a7f2b4d6f8091a3b5c7d9e", 1);
    assert!(parse_inv(&inv31).is_none(), "a 31-hex-char invoice-id is rejected");
    let inv33 = invoice_text().replacen(INV, "inv_8d1e5b0c3a7f2b4d6f8091a3b5c7d9e0a", 1);
    assert!(parse_inv(&inv33).is_none(), "a 33-hex-char invoice-id is rejected");
    let pool31 = pool_text().replacen(POOL, "pool_6c0e3f9a5b7d9f1a2c4e6a8b0d2f4a6", 1);
    assert!(parse_pool(&pool31).is_none(), "a 31-hex-char pool-id is rejected");
    let pool33 = pool_text().replacen(POOL, "pool_6c0e3f9a5b7d9f1a2c4e6a8b0d2f4a6bb", 1);
    assert!(parse_pool(&pool33).is_none(), "a 33-hex-char pool-id is rejected");
}

#[test]
fn ids_uppercase_hex_rejected() {
    let inv = invoice_text().replacen(INV, "inv_8D1E5B0C3A7F2B4D6F8091A3B5C7D9E0", 1);
    assert!(parse_inv(&inv).is_none(), "public IDs are lowercase hex only");
    let pool = pool_text().replacen(POOL, "pool_6C0E3F9A5B7D9F1A2C4E6A8B0D2F4A6B", 1);
    assert!(parse_pool(&pool).is_none(), "public IDs are lowercase hex only (pool)");
}

#[test]
fn ids_non_hex_char_rejected() {
    let inv = invoice_text().replacen(INV, "inv_8d1e5b0c3a7f2b4d6f8091a3b5c7d9eg", 1);
    assert!(parse_inv(&inv).is_none(), "a non-hex character in an ID is rejected");
    let pool = pool_text().replacen(POOL, "pool_6c0e3f9a5b7d9f1a2c4e6a8b0d2f4a6g", 1);
    assert!(parse_pool(&pool).is_none(), "a non-hex character in a pool ID is rejected");
}

#[test]
fn ids_marketplace_mismatch_rejected() {
    assert!(
        parse_invoice_statement(&invoice_text(), MKT_OTHER, Network::Stagenet, MAX_BIG).is_none(),
        "invoice marketplace-id must equal the instance ID passed in"
    );
    assert!(
        parse_pool_statement(&pool_text(), MKT_OTHER, Network::Stagenet).is_none(),
        "pool marketplace-id must equal the instance ID passed in"
    );
}

#[test]
fn ids_marketplace_wrong_prefix_rejected() {
    // The passed-in instance ID is the very string in the statement, so
    // only the mkt_ prefix pattern can reject these.
    let bad = "inv_4f9c2a7e1b3d5f60718293a4b5c6d7e8";
    let inv = invoice_text().replacen(MKT, bad, 1);
    assert!(
        parse_invoice_statement(&inv, bad, Network::Stagenet, MAX_BIG).is_none(),
        "marketplace-id must match the mkt_ pattern even when it equals the argument"
    );
    let pool = pool_text().replacen(MKT, bad, 1);
    assert!(
        parse_pool_statement(&pool, bad, Network::Stagenet).is_none(),
        "pool marketplace-id must match the mkt_ pattern even when it equals the argument"
    );
}

// ---------------------------------------------------------------------
// Fingerprints and terms digest
// ---------------------------------------------------------------------

#[test]
fn fpr_lowercase_rejected() {
    assert_both_reject(
        invoice_text().replacen(FPR40, "0123456789abcdef0123456789abcdef01234567", 1),
        pool_text().replacen(FPR40, "0123456789abcdef0123456789abcdef01234567", 1),
        "fingerprints are uppercase hex",
    );
}

#[test]
fn fpr_lengths_39_41_63_65_rejected() {
    for bad in [
        "0123456789ABCDEF0123456789ABCDEF0123456", // 39
        "0123456789ABCDEF0123456789ABCDEF012345678", // 41
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE", // 63
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0", // 65
    ] {
        assert!(
            parse_inv(&invoice_text().replacen(FPR40, bad, 1)).is_none(),
            "fingerprint of length {} is rejected (invoice)",
            bad.len()
        );
        assert!(
            parse_pool(&pool_text().replacen(FPR40, bad, 1)).is_none(),
            "fingerprint of length {} is rejected (pool)",
            bad.len()
        );
    }
}

#[test]
fn fpr_40_and_64_accepted() {
    assert!(
        parse_inv(&invoice_text()).is_some(),
        "a 40-char uppercase fingerprint is accepted (invoice)"
    );
    assert!(
        parse_pool(&pool_text()).is_some(),
        "a 40-char uppercase fingerprint is accepted (pool)"
    );
    let inv64 = invoice_text().replacen(FPR40, FPR64, 1);
    let parsed = parse_inv(&inv64).expect("a 64-char uppercase fingerprint is accepted (invoice)");
    assert_eq!(parsed.seller_key_fingerprint, FPR64, "64-char fingerprint survives parsing");
    assert_eq!(parsed.to_bytes(), inv64.as_bytes(), "64-char fingerprint invoice round-trips");
    let pool64 = pool_text().replacen(FPR40, FPR64, 1);
    assert!(parse_pool(&pool64).is_some(), "a 64-char uppercase fingerprint is accepted (pool)");
}

#[test]
fn terms_uppercase_rejected() {
    let inv = invoice_text().replacen(TERMS, "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", 1);
    assert!(parse_inv(&inv).is_none(), "terms-sha256 is lowercase hex only");
}

#[test]
fn terms_lengths_63_and_65_rejected() {
    let t63 = invoice_text().replacen(TERMS, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", 1);
    assert!(parse_inv(&t63).is_none(), "a 63-char terms digest is rejected");
    let t65 = invoice_text().replacen(TERMS, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", 1);
    assert!(parse_inv(&t65).is_none(), "a 65-char terms digest is rejected");
}

// ---------------------------------------------------------------------
// Networks and destinations
// ---------------------------------------------------------------------

#[test]
fn net_value_outside_closed_set_rejected() {
    for bad in ["monero-regtest", "mainnet", "monero-mainnet2", "Monero-Stagenet"] {
        let inv = invoice_text().replacen("network: monero-stagenet", &format!("network: {bad}"), 1);
        assert!(parse_inv(&inv).is_none(), "network value {bad:?} is outside the closed set (invoice)");
        let pool = pool_text().replacen("network: monero-stagenet", &format!("network: {bad}"), 1);
        assert!(parse_pool(&pool).is_none(), "network value {bad:?} is outside the closed set (pool)");
    }
}

#[test]
fn net_statement_network_differs_from_instance_rejected() {
    assert!(
        parse_invoice_statement(&invoice_text(), MKT, Network::Mainnet, MAX_BIG).is_none(),
        "stagenet invoice on a mainnet instance is rejected"
    );
    assert!(
        parse_pool_statement(&pool_text(), MKT, Network::Mainnet).is_none(),
        "stagenet pool on a mainnet instance is rejected"
    );
    assert!(
        parse_invoice_statement(&mainnet_invoice_text(), MKT, Network::Stagenet, MAX_BIG).is_none(),
        "mainnet invoice on a stagenet instance is rejected"
    );
    let single_mainnet_pool = {
        let mut s = pool_text_for(&[MAIN_SUB]);
        s = s.replacen("network: monero-stagenet", "network: monero-mainnet", 1);
        s
    };
    assert!(
        parse_pool_statement(&single_mainnet_pool, MKT, Network::Stagenet).is_none(),
        "mainnet pool on a stagenet instance is rejected"
    );
    assert!(
        parse_pool_statement(&single_mainnet_pool, MKT, Network::Mainnet).is_some(),
        "the same mainnet pool is accepted on a mainnet instance (positive control)"
    );
}

#[test]
fn net_invoice_destination_other_network_rejected() {
    let inv = invoice_text().replacen(STAGE_SUB_A, MAIN_SUB, 1);
    assert!(
        parse_inv(&inv).is_none(),
        "a mainnet subaddress under a monero-stagenet network line is rejected"
    );
    let inv2 = mainnet_invoice_text().replacen(MAIN_SUB, STAGE_SUB_A, 1);
    assert!(
        parse_invoice_statement(&inv2, MKT, Network::Mainnet, MAX_BIG).is_none(),
        "a stagenet subaddress under a monero-mainnet network line is rejected"
    );
    let inv3 = invoice_text().replacen(STAGE_SUB_A, TEST_SUB, 1);
    assert!(
        parse_inv(&inv3).is_none(),
        "a testnet subaddress under a monero-stagenet network line is rejected"
    );
}

#[test]
fn net_pool_one_other_network_address_rejected() {
    let text = pool_text_for(&[STAGE_SUB_A, MAIN_SUB, STAGE_SUB_C]);
    assert!(
        parse_pool(&text).is_none(),
        "one different-network address among valid ones rejects the whole pool"
    );
}

#[test]
fn net_standard_address_as_destination_rejected() {
    let inv = invoice_text().replacen(STAGE_SUB_A, STAGE_PRIMARY, 1);
    assert!(parse_inv(&inv).is_none(), "a standard address is not a valid invoice destination");
    let pool = pool_text_for(&[STAGE_PRIMARY]);
    assert!(parse_pool(&pool).is_none(), "a standard address is not a valid pool entry");
}

#[test]
fn net_integrated_address_as_destination_rejected() {
    let inv = invoice_text().replacen(STAGE_SUB_A, STAGE_INTEGRATED, 1);
    assert!(parse_inv(&inv).is_none(), "an integrated address is not a valid invoice destination");
    let pool = pool_text_for(&[STAGE_INTEGRATED]);
    assert!(parse_pool(&pool).is_none(), "an integrated address is not a valid pool entry");
}

#[test]
fn net_garbage_destination_rejected() {
    let inv = invoice_text().replacen(STAGE_SUB_A, "notamoneroaddress", 1);
    assert!(parse_inv(&inv).is_none(), "a garbage destination string is rejected");
    let pool = pool_text_for(&["notamoneroaddress"]);
    assert!(parse_pool(&pool).is_none(), "a garbage pool address string is rejected");
}

// ---------------------------------------------------------------------
// Canonical integers
// ---------------------------------------------------------------------

#[test]
fn int_amount_leading_zeros_rejected() {
    let inv = invoice_text().replacen("amount-atomic: 1250000000000", "amount-atomic: 01250000000000", 1);
    assert!(parse_inv(&inv).is_none(), "amount with a leading zero is not canonical");
}

#[test]
fn int_amount_plus_sign_rejected() {
    let inv = invoice_text().replacen("amount-atomic: 1250000000000", "amount-atomic: +1250000000000", 1);
    assert!(parse_inv(&inv).is_none(), "amount with a + sign is not canonical");
}

#[test]
fn int_amount_internal_space_rejected() {
    let inv = invoice_text().replacen("amount-atomic: 1250000000000", "amount-atomic: 1250 000000000", 1);
    assert!(parse_inv(&inv).is_none(), "amount with an internal space is not canonical");
}

#[test]
fn int_amount_empty_rejected() {
    let inv = invoice_text().replacen("amount-atomic: 1250000000000\n", "amount-atomic: \n", 1);
    assert!(parse_inv(&inv).is_none(), "an empty amount value is rejected");
}

#[test]
fn int_amount_exceeding_u64_rejected() {
    let inv = invoice_text().replacen(
        "amount-atomic: 1250000000000",
        "amount-atomic: 18446744073709551616",
        1,
    );
    assert!(
        parse_invoice_statement(&inv, MKT, Network::Stagenet, u64::MAX).is_none(),
        "an amount exceeding u64 (2^64) is rejected even with a maximal cap"
    );
}

#[test]
fn int_amount_zero_rejected() {
    let inv = invoice_text().replacen("amount-atomic: 1250000000000", "amount-atomic: 0", 1);
    assert!(parse_inv(&inv).is_none(), "amount-atomic must be greater than zero");
}

#[test]
fn int_amount_at_max_accepted_and_above_max_rejected() {
    let at = invoice_text().replacen("amount-atomic: 1250000000000", "amount-atomic: 2000000000000", 1);
    assert!(
        parse_invoice_statement(&at, MKT, Network::Stagenet, 2_000_000_000_000).is_some(),
        "an amount exactly equal to max_amount_atomic is accepted"
    );
    let above = invoice_text().replacen("amount-atomic: 1250000000000", "amount-atomic: 2000000000001", 1);
    assert!(
        parse_invoice_statement(&above, MKT, Network::Stagenet, 2_000_000_000_000).is_none(),
        "an amount one unit above max_amount_atomic is rejected"
    );
}

#[test]
fn int_address_count_zero_rejected() {
    let mut text = pool_text_for(&[]);
    text = text.replacen("address-count: 0", "address-count: 0", 1);
    assert!(parse_pool(&text).is_none(), "address-count 0 is below the 1..=200 range");
}

#[test]
fn int_address_count_leading_zeros_rejected() {
    let text = pool_text().replacen("address-count: 3", "address-count: 03", 1);
    assert!(parse_pool(&text).is_none(), "address-count with a leading zero is not canonical");
}

#[test]
fn int_address_count_mismatch_rejected() {
    let fewer = pool_text().replacen("address-count: 3", "address-count: 2", 1);
    assert!(parse_pool(&fewer).is_none(), "count 2 with 3 address lines is rejected");
    let more = pool_text().replacen("address-count: 3", "address-count: 4", 1);
    assert!(parse_pool(&more).is_none(), "count 4 with 3 address lines is rejected");
}

// ---------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------

fn inv_with_expiry(ts: &str) -> String {
    invoice_text().replacen("expires-at: 2026-10-16T17:00:00Z", &format!("expires-at: {ts}"), 1)
}

fn pool_with_created(ts: &str) -> String {
    pool_text().replacen("created-at: 2026-10-13T16:00:00Z", &format!("created-at: {ts}"), 1)
}

#[test]
fn ts_leap_second_rejected() {
    assert_both_reject(
        inv_with_expiry("2026-10-16T17:00:60Z"),
        pool_with_created("2026-10-13T16:00:60Z"),
        "leap seconds (:60) are rejected",
    );
}

#[test]
fn ts_february_30_rejected() {
    assert_both_reject(
        inv_with_expiry("2026-02-30T17:00:00Z"),
        pool_with_created("2026-02-30T16:00:00Z"),
        "February 30 does not exist",
    );
}

#[test]
fn ts_month_13_rejected() {
    assert_both_reject(
        inv_with_expiry("2026-13-16T17:00:00Z"),
        pool_with_created("2026-13-13T16:00:00Z"),
        "month 13 does not exist",
    );
}

#[test]
fn ts_offset_form_rejected() {
    assert_both_reject(
        inv_with_expiry("2026-10-16T17:00:00+00:00"),
        pool_with_created("2026-10-13T16:00:00+00:00"),
        "the +00:00 offset form is not the canonical Z form",
    );
}

#[test]
fn ts_missing_seconds_rejected() {
    assert_both_reject(
        inv_with_expiry("2026-10-16T17:00Z"),
        pool_with_created("2026-10-13T16:00Z"),
        "timestamps carry seconds",
    );
}

#[test]
fn ts_space_instead_of_t_rejected() {
    assert_both_reject(
        inv_with_expiry("2026-10-16 17:00:00Z"),
        pool_with_created("2026-10-13 16:00:00Z"),
        "the T separator is required",
    );
}

#[test]
fn ts_lowercase_z_rejected() {
    assert_both_reject(
        inv_with_expiry("2026-10-16T17:00:00z"),
        pool_with_created("2026-10-13T16:00:00z"),
        "the zone designator is uppercase Z",
    );
}

#[test]
fn ts_valid_and_leap_day_accepted() {
    assert!(parse_inv(&inv_with_expiry("2026-10-16T17:00:00Z")).is_some(), "a canonical timestamp is accepted (invoice)");
    assert!(parse_pool(&pool_with_created("2026-10-13T16:00:00Z")).is_some(), "a canonical timestamp is accepted (pool)");
    assert!(
        parse_inv(&inv_with_expiry("2028-02-29T00:00:00Z")).is_some(),
        "February 29 in a leap year is a real date and is accepted"
    );
    assert!(
        parse_inv(&inv_with_expiry("2026-02-29T00:00:00Z")).is_none(),
        "February 29 in a non-leap year does not exist and is rejected"
    );
}

// ---------------------------------------------------------------------
// Pool structure
// ---------------------------------------------------------------------

#[test]
fn pool_address_lines_not_last_rejected() {
    let text = format!(
        "statement-format: marketplace-address-pool-v1\n\
         marketplace-id: {MKT}\n\
         pool-id: {POOL}\n\
         seller-key-fingerprint: {FPR40}\n\
         network: monero-stagenet\n\
         address: {STAGE_SUB_A}\n\
         created-at: 2026-10-13T16:00:00Z\n\
         address-count: 2\n\
         address: {STAGE_SUB_B}\n"
    );
    assert!(parse_pool(&text).is_none(), "address lines come last, after every other field");
}

#[test]
fn pool_duplicate_address_rejected() {
    let text = pool_text_for(&[STAGE_SUB_A, STAGE_SUB_B, STAGE_SUB_A]);
    assert!(
        parse_pool(&text).is_none(),
        "the same address twice in one pool is rejected (an entry index must identify one address)"
    );
}

// ---------------------------------------------------------------------
// No trimming (Q13)
// ---------------------------------------------------------------------

#[test]
fn notrim_surrounding_whitespace_rejected() {
    assert_both_reject(
        format!(" {}", invoice_text()),
        format!(" {}", pool_text()),
        "a leading space before the whole statement is never trimmed away",
    );
    assert_both_reject(
        format!("\n{}", invoice_text()),
        format!("\n{}", pool_text()),
        "a leading blank line before the whole statement is rejected",
    );
    assert_both_reject(
        format!("{} ", invoice_text()),
        format!("{} ", pool_text()),
        "a trailing space after the final LF is rejected",
    );
    assert_both_reject(
        format!("{}\t", invoice_text()),
        format!("{}\t", pool_text()),
        "a trailing tab after the final LF is rejected",
    );
}

#[test]
fn notrim_space_before_value_rejected() {
    // Two spaces after the colon == a space before the value; the parser
    // must not trim it into validity.
    assert_both_reject(
        invoice_text().replacen("destination: ", "destination:  ", 1),
        pool_text().replacen("address: ", "address:  ", 1),
        "a space before a value fails byte-identity (no trimming)",
    );
    // A space at the start of a line is likewise never trimmed.
    assert_both_reject(
        invoice_text().replacen("invoice-id:", " invoice-id:", 1),
        pool_text().replacen("pool-id:", " pool-id:", 1),
        "a leading space on a line fails byte-identity (no trimming)",
    );
}

// ---------------------------------------------------------------------
// Payment URI
// ---------------------------------------------------------------------

fn parsed_default_invoice() -> InvoiceStatement {
    parse_inv(&invoice_text()).expect("default invoice parses")
}

#[test]
fn uri_exact_for_known_invoice() {
    let inv = parsed_default_invoice();
    assert_eq!(
        payment_uri(&inv),
        format!("monero:{STAGE_SUB_A}?tx_amount=1.25"),
        "URI is monero: + destination + ?tx_amount= with 1.25 XMR rendered as 1.25"
    );
}

#[test]
fn uri_whole_xmr_has_no_decimal_point() {
    let text = invoice_text().replacen("amount-atomic: 1250000000000", "amount-atomic: 1000000000000", 1);
    let inv = parse_inv(&text).expect("1 XMR invoice parses");
    assert_eq!(
        payment_uri(&inv),
        format!("monero:{STAGE_SUB_A}?tx_amount=1"),
        "a whole-XMR amount renders without a decimal point"
    );
}

#[test]
fn uri_one_atomic_renders_full_precision() {
    let text = invoice_text().replacen("amount-atomic: 1250000000000", "amount-atomic: 1", 1);
    let inv = parse_inv(&text).expect("1-atomic invoice parses");
    assert_eq!(
        payment_uri(&inv),
        format!("monero:{STAGE_SUB_A}?tx_amount=0.000000000001"),
        "1 atomic unit renders as 0.000000000001"
    );
}

#[test]
fn uri_no_other_parameters() {
    let uri = payment_uri(&parsed_default_invoice());
    assert!(uri.starts_with("monero:"), "URI uses the monero: scheme");
    assert_eq!(uri.matches('?').count(), 1, "URI has exactly one query separator");
    assert!(!uri.contains('&'), "URI carries no second parameter");
    assert!(!uri.contains("tx_label"), "URI carries no label parameter");
    assert!(!uri.contains("tx_description"), "URI carries no description parameter");
    assert!(!uri.contains("recipient_name"), "URI carries no recipient-name parameter");
}

#[test]
fn uri_deterministic() {
    let inv = parsed_default_invoice();
    assert_eq!(payment_uri(&inv), payment_uri(&inv), "same statement, same URI, always");
}

#[test]
fn uri_uses_canonical_destination_and_no_whitespace() {
    let inv = parsed_default_invoice();
    let uri = payment_uri(&inv);
    assert!(
        !uri.chars().any(|c| c.is_whitespace()),
        "the payment URI contains no whitespace (single normalization path, Q13)"
    );
    assert!(
        uri.contains(&inv.destination.as_str()),
        "the URI spells the destination exactly as Subaddress::as_str renders it"
    );
    assert_eq!(
        inv.destination.as_str(),
        STAGE_SUB_A,
        "the canonical destination string is the submitted fixture string"
    );
}

// ---------------------------------------------------------------------
// QR PNG
// ---------------------------------------------------------------------

#[test]
fn qr_png_magic_bytes() {
    let png = payment_qr_png(&parsed_default_invoice());
    assert!(
        png.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        "QR output starts with the PNG magic bytes"
    );
}

#[test]
fn qr_deterministic_identical_bytes() {
    let inv = parsed_default_invoice();
    assert_eq!(
        payment_qr_png(&inv),
        payment_qr_png(&inv),
        "same statement produces identical PNG bytes"
    );
}

#[test]
fn qr_different_amount_different_bytes() {
    let a = parsed_default_invoice();
    let text = invoice_text().replacen("amount-atomic: 1250000000000", "amount-atomic: 1250000000001", 1);
    let b = parse_inv(&text).expect("altered-amount invoice parses");
    assert_ne!(
        payment_qr_png(&a),
        payment_qr_png(&b),
        "a different amount produces a different QR image"
    );
}

#[test]
fn qr_length_nontrivial() {
    let png = payment_qr_png(&parsed_default_invoice());
    assert!(png.len() > 200, "QR PNG is a real rendered image, not a stub (got {} bytes)", png.len());
}

// ---------------------------------------------------------------------
// Q17 typing
// ---------------------------------------------------------------------

#[test]
fn typing_invoice_network_is_enum_and_matches_destination() {
    let inv = parsed_default_invoice();
    assert!(
        matches!(inv.network, Network::Stagenet),
        "invoice network is the Network enum value, not a string"
    );
    assert!(
        matches!(inv.destination.network(), Network::Stagenet),
        "invoice destination reports the same network as the enum"
    );
}

#[test]
fn typing_pool_network_matches_every_address() {
    let pool = parse_pool(&pool_text()).expect("default pool parses");
    assert!(matches!(pool.network, Network::Stagenet), "pool network is the Network enum value");
    for a in &pool.addresses {
        assert!(
            matches!(a.network(), Network::Stagenet),
            "every pool address reports the pool's network"
        );
    }
}

// ---------------------------------------------------------------------
// Pricing (xmr-only)
// ---------------------------------------------------------------------

#[test]
fn pricing_module_id_is_xmr_only() {
    assert_eq!(PRICING_MODULE_XMR_ONLY, "xmr-only", "the sole v2 pricing module id is xmr-only");
}

#[test]
fn pricing_exact_products() {
    assert_eq!(
        xmr_only_total(1_250_000_000_000, 3),
        Some(3_750_000_000_000),
        "1.25 XMR x 3 totals exactly 3.75 XMR in atomic units"
    );
    assert_eq!(xmr_only_total(1, 1), Some(1), "1 atomic x 1 is 1 atomic");
    assert_eq!(
        xmr_only_total(999_999_999_999, 7),
        Some(6_999_999_999_993),
        "large exact product is computed without rounding"
    );
    assert_eq!(
        xmr_only_total(u64::MAX / 2, 2),
        Some(u64::MAX - 1),
        "the largest even product below u64::MAX is exact"
    );
}

#[test]
fn pricing_overflow_is_none() {
    assert_eq!(xmr_only_total(u64::MAX, 2), None, "an overflowing total is None, never a wrap");
    assert_eq!(
        xmr_only_total(u64::MAX / 2 + 1, 2),
        None,
        "a product one step past u64::MAX is None"
    );
    assert_eq!(xmr_only_total(u64::MAX, u64::MAX), None, "max x max is None");
}

#[test]
fn pricing_zero_unit_price_is_zero_total() {
    assert_eq!(xmr_only_total(0, 5), Some(0), "a zero unit price yields a zero total");
    assert_eq!(
        xmr_only_total(123, 0),
        Some(0),
        "the helper is pure checked arithmetic; quantity >= 1 is the order layer's rule, not this helper's"
    );
}

// ---------------------------------------------------------------------
// Supporting types: Subaddress (§1) and Atomic (§8)
// ---------------------------------------------------------------------

#[test]
fn subaddr_validate_ok_network_and_canonical_string() {
    let s = Subaddress::validate(STAGE_SUB_A, Network::Stagenet)
        .expect("a genuine stagenet subaddress validates on stagenet");
    assert!(matches!(s.network(), Network::Stagenet), "validated subaddress reports Stagenet as the enum");
    assert_eq!(s.as_str(), STAGE_SUB_A, "as_str re-renders the exact submitted string");
}

#[test]
fn subaddr_validate_rejects_wrong_inputs() {
    assert!(
        Subaddress::validate(STAGE_SUB_A, Network::Mainnet).is_err(),
        "a stagenet subaddress is refused on mainnet"
    );
    assert!(
        Subaddress::validate(STAGE_PRIMARY, Network::Stagenet).is_err(),
        "a primary (standard) address is refused as a subaddress"
    );
    assert!(
        Subaddress::validate(STAGE_INTEGRATED, Network::Stagenet).is_err(),
        "an integrated address is refused as a subaddress"
    );
    assert!(
        Subaddress::validate(&format!(" {STAGE_SUB_A}"), Network::Stagenet).is_err(),
        "validate never trims: a leading-space address is refused"
    );
    assert!(
        Subaddress::validate(&format!("{STAGE_SUB_A} "), Network::Stagenet).is_err(),
        "validate never trims: a trailing-space address is refused"
    );
    assert!(
        Subaddress::validate("notamoneroaddress", Network::Stagenet).is_err(),
        "a garbage string is refused"
    );
}

#[test]
fn atomic_format_decimal_canonical() {
    assert_eq!(Atomic(0).format_decimal(), "0", "zero renders as 0");
    assert_eq!(Atomic(1).format_decimal(), "0.000000000001", "1 atomic renders at full precision");
    assert_eq!(Atomic(1_000_000_000_000).format_decimal(), "1", "1 XMR renders with no decimal point");
    assert_eq!(Atomic(1_250_000_000_000).format_decimal(), "1.25", "1.25 XMR renders as 1.25");
    assert_eq!(Atomic(1_500_000_000_000).format_decimal(), "1.5", "trailing zeros are not rendered");
}

#[test]
fn atomic_parse_decimal_exact() {
    assert_eq!(
        Atomic::parse_decimal("1.25").map(|a| a.0),
        Some(1_250_000_000_000),
        "1.25 parses to exactly 1250000000000 atomic units"
    );
    assert_eq!(
        Atomic::parse_decimal("0.000000000001").map(|a| a.0),
        Some(1),
        "the smallest decimal parses to exactly 1 atomic unit"
    );
    assert_eq!(
        Atomic::parse_decimal("1").map(|a| a.0),
        Some(1_000_000_000_000),
        "a whole-XMR decimal parses exactly"
    );
}
