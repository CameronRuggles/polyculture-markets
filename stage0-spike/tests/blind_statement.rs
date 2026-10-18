// BLIND security tests — canonical invoice statements.
// Authored independently from spec v2 (section 10, plus s3 and s23) and
// the Stage 0 API contract ONLY. The author has not seen any
// implementation code.
//
// Spec clauses traced (all s10 unless noted):
//   - Bytes: printable ASCII (0x20-0x7E) and LF only; no CR, tabs, or other
//     bytes.
//   - One `key: value` per line, a single space after the colon; keys
//     lowercase, from a fixed list, in a fixed order; no blank lines, no
//     trailing spaces, exactly one final LF.
//   - Line 1 is `statement-format: marketplace-invoice-v1`; line 2 is
//     `marketplace-id: <id>`.
//   - Values match per-field patterns: timestamps RFC 3339 UTC with seconds
//     and `Z`; fingerprints uppercase hex (40 or 64); digests lowercase hex
//     (64).
//   - Signatures are detached; clearsigned and inline-signed statements
//     are rejected.
//   - Parsers re-serialize the parsed fields and reject any input that is
//     not byte-identical to the result (also stated in the API contract).
//   - s23 (Payments): "Tampered statements fail verification; clearsigned
//     and non-canonical statements are rejected."
//
// The sample values below are the spec s10 invoice example's own values
// (marketplace / invoice / order ids, amount, expiry), with the spec's
// placeholders replaced by concrete pattern-conforming values: a 40-hex
// uppercase fingerprint, a 64-hex lowercase digest, and, as the
// destination, a checksum-verified published mainnet subaddress (see
// blind_address.rs header for provenance).

use stage0_spike::statement::{parse_invoice, serialize_invoice, Invoice};

const MARKETPLACE_ID: &str = "mkt_4f9c2a7e";
const INVOICE_ID: &str = "inv_8d1e5b0c3a7f";
const ORDER_ID: &str = "ord_2b6a9e4d1c08";
/// 40 uppercase hex characters.
const FINGERPRINT_40: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
/// 64 uppercase hex characters.
const FINGERPRINT_64: &str =
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
/// Published, checksum-verified mainnet subaddress (prefix 42).
const DESTINATION: &str =
    "84EgZVjXKF4d1JkEhZSxm4LQQEx64AvqQEwkvWPtHEb5JMrB1Y86y1vCPSCiXsKzbfS9x8vCpx3gVgPaHCpobPYqQzANTnC";
const AMOUNT_ATOMIC: u64 = 1_250_000_000_000;
const EXPIRES_AT: &str = "2026-10-16T17:00:00Z";
/// 64 lowercase hex characters.
const TERMS_SHA256: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The canonical byte layout, written out literally and independently of
/// `sample_invoice()` so the serialization test compares two separate
/// transcriptions of the spec s10 example.
const CANONICAL: &str = concat!(
    "statement-format: marketplace-invoice-v1\n",
    "marketplace-id: mkt_4f9c2a7e\n",
    "invoice-id: inv_8d1e5b0c3a7f\n",
    "order-id: ord_2b6a9e4d1c08\n",
    "seller-key-fingerprint: 0123456789ABCDEF0123456789ABCDEF01234567\n",
    "network: monero-mainnet\n",
    "destination: 84EgZVjXKF4d1JkEhZSxm4LQQEx64AvqQEwkvWPtHEb5JMrB1Y86y1vCPSCiXsKzbfS9x8vCpx3gVgPaHCpobPYqQzANTnC\n",
    "amount-atomic: 1250000000000\n",
    "expires-at: 2026-10-16T17:00:00Z\n",
    "terms-sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
);

fn sample_invoice() -> Invoice {
    Invoice {
        marketplace_id: MARKETPLACE_ID.to_string(),
        invoice_id: INVOICE_ID.to_string(),
        order_id: ORDER_ID.to_string(),
        seller_fingerprint: FINGERPRINT_40.to_string(),
        network: "monero-mainnet".to_string(),
        destination: DESTINATION.to_string(),
        amount_atomic: AMOUNT_ATOMIC,
        expires_at: EXPIRES_AT.to_string(),
        terms_sha256: TERMS_SHA256.to_string(),
    }
}

fn canonical_string() -> String {
    CANONICAL.to_string()
}

fn assert_parse_rejected(bytes: &[u8], what: &str) {
    match parse_invoice(bytes) {
        Err(_) => {}
        Ok(_) => panic!("{what}: expected parse rejection but the input was ACCEPTED"),
    }
}

// ------------------------------------------------------------- happy path ---

#[test]
fn serialize_invoice_matches_spec_layout_byte_for_byte() {
    // s10 invoice example, byte-for-byte: key order, single space after
    // each colon, LF line endings, exactly one final LF, no CR anywhere.
    let out = serialize_invoice(&sample_invoice());
    assert_eq!(
        out,
        CANONICAL.as_bytes(),
        "serialized invoice differs from the spec s10 layout"
    );
    // Redundant, explicit guards on the two easiest properties to regress:
    assert!(out.ends_with(b"\n"), "must end with a final LF");
    assert!(!out.ends_with(b"\n\n"), "must not end with a blank line");
    assert!(!out.contains(&b'\r'), "must not contain CR");
    assert!(!out.contains(&b'\t'), "must not contain tab");
}

#[test]
fn parse_invoice_accepts_canonical_and_recovers_every_field() {
    let inv = parse_invoice(CANONICAL.as_bytes())
        .expect("the canonical spec-layout statement must parse");
    assert_eq!(inv.marketplace_id, MARKETPLACE_ID);
    assert_eq!(inv.invoice_id, INVOICE_ID);
    assert_eq!(inv.order_id, ORDER_ID);
    assert_eq!(inv.seller_fingerprint, FINGERPRINT_40);
    assert_eq!(inv.network, "monero-mainnet");
    assert_eq!(inv.destination, DESTINATION);
    assert_eq!(inv.amount_atomic, AMOUNT_ATOMIC);
    assert_eq!(inv.expires_at, EXPIRES_AT);
    assert_eq!(inv.terms_sha256, TERMS_SHA256);
}

#[test]
fn parse_then_serialize_is_byte_identical() {
    // s10 / contract: re-serialization of a parsed statement reproduces
    // the input exactly.
    let inv = parse_invoice(CANONICAL.as_bytes()).expect("canonical must parse");
    assert_eq!(serialize_invoice(&inv), CANONICAL.as_bytes());
}

#[test]
fn parse_invoice_accepts_64_hex_fingerprint() {
    // s10: fingerprints are "40 or 64 hex". The 64-hex form must be
    // accepted just as the 40-hex form is.
    let s = canonical_string().replacen(FINGERPRINT_40, FINGERPRINT_64, 1);
    let inv = parse_invoice(s.as_bytes()).expect("64-hex fingerprint must be accepted");
    assert_eq!(inv.seller_fingerprint, FINGERPRINT_64);
}

// --------------------------------------------------- rejected: whitespace ---

#[test]
fn rejects_crlf_line_endings() {
    let s = canonical_string().replace('\n', "\r\n");
    assert_parse_rejected(s.as_bytes(), "CRLF line endings");
}

#[test]
fn rejects_tab() {
    // A tab where the single space after the colon belongs.
    let s = canonical_string().replacen("invoice-id: ", "invoice-id:\t", 1);
    assert_parse_rejected(s.as_bytes(), "tab after colon");
}

#[test]
fn rejects_trailing_space_on_a_line() {
    let s = canonical_string().replacen(
        "invoice-id: inv_8d1e5b0c3a7f\n",
        "invoice-id: inv_8d1e5b0c3a7f \n",
        1,
    );
    assert_parse_rejected(s.as_bytes(), "trailing space");
}

#[test]
fn rejects_blank_line_in_the_middle() {
    let s = canonical_string().replacen("order-id:", "\norder-id:", 1);
    assert_parse_rejected(s.as_bytes(), "blank line in the middle");
}

#[test]
fn rejects_missing_final_lf() {
    let mut bytes = CANONICAL.as_bytes().to_vec();
    assert_eq!(bytes.last(), Some(&b'\n'));
    bytes.pop();
    assert_parse_rejected(&bytes, "missing final LF");
}

#[test]
fn rejects_extra_final_lf() {
    // A second final LF is a trailing blank line: not "exactly one".
    let s = format!("{CANONICAL}\n");
    assert_parse_rejected(s.as_bytes(), "extra final LF / trailing blank line");
}

#[test]
fn rejects_two_spaces_after_colon() {
    let s = canonical_string().replacen("marketplace-id: ", "marketplace-id:  ", 1);
    assert_parse_rejected(s.as_bytes(), "two spaces after colon");
}

// ------------------------------------------------------ rejected: content ---

#[test]
fn rejects_wrong_key_order() {
    // invoice-id and order-id lines swapped.
    let s = canonical_string().replacen(
        "invoice-id: inv_8d1e5b0c3a7f\norder-id: ord_2b6a9e4d1c08\n",
        "order-id: ord_2b6a9e4d1c08\ninvoice-id: inv_8d1e5b0c3a7f\n",
        1,
    );
    assert_ne!(s, canonical_string(), "test construction failed");
    assert_parse_rejected(s.as_bytes(), "wrong key order");
}

#[test]
fn rejects_lowercase_fingerprint() {
    // s10: fingerprints are UPPERCASE hex.
    let s = canonical_string().replacen(FINGERPRINT_40, &FINGERPRINT_40.to_lowercase(), 1);
    assert_parse_rejected(s.as_bytes(), "lowercase fingerprint");
}

#[test]
fn rejects_uppercase_digest() {
    // s10: digests are lowercase hex.
    let s = canonical_string().replacen(TERMS_SHA256, &TERMS_SHA256.to_uppercase(), 1);
    assert_parse_rejected(s.as_bytes(), "uppercase terms digest");
}

#[test]
fn rejects_extra_unknown_key() {
    // Keys come "from a fixed list": an extra key, however well-formed,
    // is not part of the format.
    let s = canonical_string().replacen("terms-sha256:", "comment: hello\nterms-sha256:", 1);
    assert_parse_rejected(s.as_bytes(), "extra unknown key");
}

#[test]
fn rejects_missing_key() {
    let s = canonical_string().replacen("order-id: ord_2b6a9e4d1c08\n", "", 1);
    assert_parse_rejected(s.as_bytes(), "missing order-id line");
}

#[test]
fn rejects_amount_with_leading_zero() {
    // Derivable from the contract: amount_atomic is a u64, so a parsed
    // "01250000000000" re-serializes as "1250000000000" and is therefore
    // not byte-identical to the input, which the parser MUST reject.
    let s = canonical_string()
        .replacen("amount-atomic: 1250000000000", "amount-atomic: 01250000000000", 1);
    assert_parse_rejected(s.as_bytes(), "amount with leading zero");
}

#[test]
fn rejects_non_ascii_bytes() {
    // s10: printable ASCII (0x20-0x7E) only. U+00E9 encodes as two bytes
    // >= 0x80 in UTF-8.
    let s = canonical_string().replacen("mkt_4f9c2a7e", "mkt_4f9c2a7\u{e9}", 1);
    assert_parse_rejected(s.as_bytes(), "non-ASCII byte in a value");
}

#[test]
fn rejects_clearsigned_style_input() {
    // s10: "Clearsigned and inline-signed statements are rejected."
    // A clearsigned document wraps the statement in PGP armor headers and
    // a signature block; none of that is the canonical statement format.
    let s = format!(
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n{CANONICAL}-----BEGIN PGP SIGNATURE-----\n\nx\n-----END PGP SIGNATURE-----\n"
    );
    assert_parse_rejected(s.as_bytes(), "clearsigned-style input");
}
