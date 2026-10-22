//! Blind gate suite — Hidden Trades stage H1 (Alpha build spec §16.1).
//!
//! Coverage, mapped to the H1 gate:
//!  - Accept AND reject fixtures for every §5 statement (terms,
//!    assignment, open, ack, shipped, issue, settle, refund-to,
//!    receipt, vouch, link), as literal canonical texts: a parser
//!    must accept the literal and re-serialise it byte-identically,
//!    and must refuse every mutation.
//!  - `trade-id` is the lowercase hex SHA-256 of the exact assignment
//!    bytes (expected digest computed independently of the code).
//!  - The §6 fold: all three payment timings (prepay / on_ship /
//!    on_receipt) through Paid/Shipped/Closed, the issue path with
//!    its 30-day window, settle (including the over-amount refusal),
//!    lapsed, and terminal states ignoring later statements.
//!  - Buyer `verify` (helper-core) refusing each of spec §14 checks
//!    1–6 INDEPENDENTLY; check 7 warns and never stops.
//!  - Terms v2 pinning in the app (spec §4, closes RM2): signature
//!    against the seller's pinned key, per-version pins, superseded
//!    versions kept, a listing-text edit invalidating the pin.
//!
//! The marketplace id follows the statement family's form
//! (`mkt_` + 32 lowercase hex, spec §5's `<mkt_ id>`; every existing
//! parser enforces it via the shared marketplace-id rule).
//!
//! Fixture addresses are real Monero addresses: the stagenet/mainnet
//! subaddresses and the stagenet standard address were constructed
//! with the `monero` crate from fixed keys; the stagenet integrated
//! address was confirmed against monero-wallet-rpc validate_address.

use domain::ht_fold::{fold_trade, PaymentRecord, TradeEvent, TradeState};
use domain::ht_statements as hs;
use modules_api::Network;
use std::sync::atomic::{AtomicU64, Ordering};

const MKT: &str = "mkt_0123456789abcdef0123456789abcdef";
const SELLER_FPR: &str = "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4";
const BUYER_FPR: &str = "0F1E2D3C4B5A69788796A5B4C3D2E1F0A9B8C7D6";
const TERMS_SHA: &str = "abababababababababababababababababababababababababababababababab";
const TEXT_SHA: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const STAGENET_SUB: &str =
    "75VjEqDg5fp7hyErNLsyRK59sHRJjLX3fTvARvKvGodj5PPajrWjmyQ2mvuPWWMWi4HNS5jg4jvyYLREvx63KZe4HK7sbH8";
const MAINNET_SUB: &str =
    "85hmKg8djGv7hyErNLsyRK59sHRJjLX3fTvARvKvGodj5PPajrWjmyQ2mvuPWWMWi4HNS5jg4jvyYLREvx63KZe4HMDtjgm";
const STAGENET_STD: &str =
    "54rFEm2hfRj9GXT5Qn7fUW2sZtnk1RBrQhhifxDRAUt5AVtMo1FtzAUehtkKuWCuaFduM6dopUmCfbaUTo58YgNq1xbZiZy";
const STAGENET_INTEGRATED: &str =
    "5FHmhNWouJ76EzvernZJBcPXiZym13w1CfbpDU6sR8aSGpaRbAmU4EMSH3XYXu5U1cSac7B49WRSSBbwQK9by3c7R3PDbmJGUNm7bwo6K9";
/// SHA-256 of the ASSIGNMENT literal below (computed independently).
const ASSIGNMENT_TRADE_ID: &str =
    "2b0c9a9fcd437374def302d767fb684e89399d137bcd45ac14bf5f734cad0109";
/// SHA-256 of the TERMS literal below (computed independently).
const TERMS_STMT_SHA: &str = "3787746cf0bf742a16a3a4d2db70e4fdc78a5b35e29940629b4573f34b50d2ab";

const TERMS: &str = "statement-format: marketplace-terms-v2\n\
marketplace-id: mkt_0123456789abcdef0123456789abcdef\n\
listing-id: lst_00000000000000000000000000000001\n\
listing-version: 3\n\
seller-key-fingerprint: A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4\n\
terms-sha256: cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\n\
transit-risk: seller\n\
remedy-cap-pct: 25\n\
payment-timing: on_ship\n";

const ASSIGNMENT: &str = "statement-format: marketplace-assignment-v1\n\
marketplace-id: mkt_0123456789abcdef0123456789abcdef\n\
network: monero-stagenet\n\
seller-key-fingerprint: A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4\n\
buyer-key-fingerprint: 0F1E2D3C4B5A69788796A5B4C3D2E1F0A9B8C7D6\n\
terms-statement-sha256: abababababababababababababababababababababababababababababababab\n\
destination: 75VjEqDg5fp7hyErNLsyRK59sHRJjLX3fTvARvKvGodj5PPajrWjmyQ2mvuPWWMWi4HNS5jg4jvyYLREvx63KZe4HK7sbH8\n\
amount-atomic: 250000000000\n\
payment-timing: prepay\n\
settlement: direct\n\
expires-at: 2026-12-01T00:00:00Z\n\
nonce: 0123456789abcdef0123456789abcdef\n";

const OPEN: &str = "statement-format: marketplace-open-v1\n\
marketplace-id: mkt_0123456789abcdef0123456789abcdef\n\
seller-key-fingerprint: A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4\n\
buyer-key-fingerprint: 0F1E2D3C4B5A69788796A5B4C3D2E1F0A9B8C7D6\n\
trade-id: 2b0c9a9fcd437374def302d767fb684e89399d137bcd45ac14bf5f734cad0109\n";

const ACK: &str = "statement-format: marketplace-ack-v1\n\
marketplace-id: mkt_0123456789abcdef0123456789abcdef\n\
trade-id: 2b0c9a9fcd437374def302d767fb684e89399d137bcd45ac14bf5f734cad0109\n\
acknowledged: paid\n\
date: 2026-10-21\n";

const SHIPPED: &str = "statement-format: marketplace-shipped-v1\n\
marketplace-id: mkt_0123456789abcdef0123456789abcdef\n\
trade-id: 2b0c9a9fcd437374def302d767fb684e89399d137bcd45ac14bf5f734cad0109\n\
direction: out\n\
date: 2026-10-22\n\
carrier-commit: efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef\n";

const ISSUE: &str = "statement-format: marketplace-issue-v1\n\
marketplace-id: mkt_0123456789abcdef0123456789abcdef\n\
trade-id: 2b0c9a9fcd437374def302d767fb684e89399d137bcd45ac14bf5f734cad0109\n\
kind: missing-part\n\
requested-refund-pct: 40\n\
date: 2026-11-01\n";

const SETTLE: &str = "statement-format: marketplace-settle-v1\n\
marketplace-id: mkt_0123456789abcdef0123456789abcdef\n\
trade-id: 2b0c9a9fcd437374def302d767fb684e89399d137bcd45ac14bf5f734cad0109\n\
refund-atomic: 100000000000\n\
return-required: yes\n\
month: 2026-11\n";

const REFUND_TO: &str = "statement-format: marketplace-refund-to-v1\n\
marketplace-id: mkt_0123456789abcdef0123456789abcdef\n\
trade-id: 2b0c9a9fcd437374def302d767fb684e89399d137bcd45ac14bf5f734cad0109\n\
refund-destination: 75VjEqDg5fp7hyErNLsyRK59sHRJjLX3fTvARvKvGodj5PPajrWjmyQ2mvuPWWMWi4HNS5jg4jvyYLREvx63KZe4HK7sbH8\n\
refund-atomic: 100000000000\n";

const RECEIPT: &str = "statement-format: marketplace-receipt-v1\n\
marketplace-id: mkt_0123456789abcdef0123456789abcdef\n\
trade-id: 2b0c9a9fcd437374def302d767fb684e89399d137bcd45ac14bf5f734cad0109\n\
seller-key-fingerprint: A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4\n\
buyer-key-fingerprint: 0F1E2D3C4B5A69788796A5B4C3D2E1F0A9B8C7D6\n\
month: 2026-11\n\
outcome: completed\n";

const VOUCH: &str = "statement-format: marketplace-vouch-v1\n\
marketplace-id: mkt_0123456789abcdef0123456789abcdef\n\
voucher-key-fingerprint: A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4\n\
newcomer-key-fingerprint: 0F1E2D3C4B5A69788796A5B4C3D2E1F0A9B8C7D6\n\
month: 2026-10\n";

const LINK: &str = "statement-format: marketplace-link-v1\n\
marketplace-id: mkt_0123456789abcdef0123456789abcdef\n\
account-key-fingerprint: A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4\n\
venue-name: Some Other Market\n\
venue-address: http://example.invalid/store\n";

// ---------------------------------------------------------------------
// Accept fixtures: parse the literal, check fields, byte-identical
// re-serialisation.
// ---------------------------------------------------------------------

#[test]
fn terms_v2_accepts_and_round_trips() {
    let s = hs::parse_terms_statement(TERMS, MKT).expect("terms literal must parse");
    assert_eq!(s.listing_id, "lst_00000000000000000000000000000001");
    assert_eq!(s.listing_version, 3);
    assert_eq!(s.seller_key_fingerprint, SELLER_FPR);
    assert_eq!(s.terms_sha256, TEXT_SHA);
    assert_eq!(s.risk.transit_risk, hs::TransitRisk::Seller);
    assert_eq!(s.risk.remedy_cap_pct, 25);
    assert_eq!(s.risk.payment_timing, hs::PaymentTiming::OnShip);
    assert_eq!(s.to_bytes(), TERMS.as_bytes(), "byte-identical round trip");
    assert_eq!(
        hs::terms_statement_sha256(TERMS.as_bytes()),
        TERMS_STMT_SHA,
        "terms-statement-sha256 is the SHA-256 of the exact bytes"
    );
}

#[test]
fn assignment_accepts_round_trips_and_names_the_trade() {
    let s =
        hs::parse_assignment_statement(ASSIGNMENT, MKT, Network::Stagenet).expect("must parse");
    assert_eq!(s.network, Network::Stagenet);
    assert_eq!(s.destination.as_str(), STAGENET_SUB);
    assert_eq!(s.amount_atomic, 250_000_000_000);
    assert_eq!(s.payment_timing, hs::PaymentTiming::Prepay);
    assert_eq!(s.expires_at, "2026-12-01T00:00:00Z");
    assert_eq!(s.to_bytes(), ASSIGNMENT.as_bytes());
    assert_eq!(
        hs::trade_id(ASSIGNMENT.as_bytes()),
        ASSIGNMENT_TRADE_ID,
        "trade-id = lowercase hex SHA-256 of the exact assignment bytes"
    );
    // The raw field parse (buyer verify's entry point) agrees.
    let f = hs::parse_assignment_fields(ASSIGNMENT).expect("fields must parse");
    assert_eq!(f.destination, STAGENET_SUB);
}

#[test]
fn open_ack_shipped_accept_and_round_trip() {
    let o = hs::parse_open_token(OPEN, MKT).expect("open must parse");
    assert_eq!(o.trade_id, ASSIGNMENT_TRADE_ID);
    assert_eq!(o.to_bytes(), OPEN.as_bytes());

    let a = hs::parse_ack_statement(ACK, MKT).expect("ack must parse");
    assert_eq!(a.date, "2026-10-21");
    assert_eq!(a.to_bytes(), ACK.as_bytes());

    let sh = hs::parse_shipped_statement(SHIPPED, MKT).expect("shipped must parse");
    assert_eq!(sh.direction, hs::ShippedDirection::Out);
    assert_eq!(sh.date, "2026-10-22");
    assert!(sh.carrier_commit.starts_with("ef"));
    assert_eq!(sh.to_bytes(), SHIPPED.as_bytes());

    // carrier-commit: `none` is the other legal value.
    let none_variant = SHIPPED.replace(
        "carrier-commit: efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
        "carrier-commit: none",
    );
    let sh2 = hs::parse_shipped_statement(&none_variant, MKT).expect("none commit must parse");
    assert_eq!(sh2.carrier_commit, "none");
    // The commitment construction: SHA-256 of carrier|tracking|salt.
    let commit = hs::carrier_commit("ParcelPost", "TRK-123", "0123456789abcdef0123456789abcdef")
        .expect("valid salt");
    assert_eq!(commit.len(), 64);
    assert!(hs::carrier_commit("P", "T", "XYZ").is_none(), "bad salt refuses");
}

#[test]
fn issue_settle_refund_to_accept_and_round_trip() {
    let i = hs::parse_issue_statement(ISSUE, MKT).expect("issue must parse");
    assert_eq!(i.kind, hs::IssueKind::MissingPart);
    assert_eq!(i.requested_refund_pct, 40);
    assert_eq!(i.to_bytes(), ISSUE.as_bytes());

    let st = hs::parse_settle_statement(SETTLE, MKT).expect("settle must parse");
    assert_eq!(st.refund_atomic, 100_000_000_000);
    assert!(st.return_required);
    assert_eq!(st.month, "2026-11");
    assert_eq!(st.to_bytes(), SETTLE.as_bytes());

    let rt =
        hs::parse_refund_to_statement(REFUND_TO, MKT, Network::Stagenet).expect("must parse");
    assert_eq!(rt.refund_destination, STAGENET_SUB);
    assert_eq!(rt.refund_atomic, 100_000_000_000);
    assert_eq!(rt.to_bytes(), REFUND_TO.as_bytes());
}

#[test]
fn receipt_vouch_link_accept_and_round_trip() {
    let r = hs::parse_receipt_statement(RECEIPT, MKT).expect("receipt must parse");
    assert_eq!(r.seller_key_fingerprint, SELLER_FPR);
    assert_eq!(r.buyer_key_fingerprint, BUYER_FPR);
    assert_eq!(r.month, "2026-11");
    assert_eq!(r.to_bytes(), RECEIPT.as_bytes());

    let v = hs::parse_vouch_statement(VOUCH, MKT).expect("vouch must parse");
    assert_eq!(v.newcomer_key_fingerprint, BUYER_FPR);
    assert_eq!(v.to_bytes(), VOUCH.as_bytes());

    let l = hs::parse_link_statement(LINK, MKT).expect("link must parse");
    assert_eq!(l.venue_name, "Some Other Market");
    assert_eq!(l.to_bytes(), LINK.as_bytes());
}

#[test]
fn tx_proof_messages_are_exact() {
    assert_eq!(
        hs::payment_proof_message(ASSIGNMENT_TRADE_ID),
        format!("marketplace-pay-v1|{ASSIGNMENT_TRADE_ID}")
    );
    assert_eq!(
        hs::refund_proof_message(ASSIGNMENT_TRADE_ID),
        format!("marketplace-refund-v1|{ASSIGNMENT_TRADE_ID}")
    );
    assert_eq!(
        hs::stake_proof_message(MKT, SELLER_FPR),
        format!("marketplace-stake-v1|{MKT}|{SELLER_FPR}")
    );
}

// ---------------------------------------------------------------------
// Reject fixtures: shared mutations must fail EVERY parser, and each
// statement's own value rules must bite.
// ---------------------------------------------------------------------

fn mutations(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    out.push(("missing final LF".into(), text.trim_end_matches('\n').to_string()));
    out.push(("extra blank line".into(), format!("{text}\n")));
    out.push(("extra field".into(), format!("{}x-extra: 1\n", text)));
    out.push((
        "wrong marketplace".into(),
        text.replace("marketplace-id: mkt_0123456789abcdef0123456789abcdef", "marketplace-id: other-market"),
    ));
    out.push((
        "double space after colon".into(),
        text.replacen(": ", ":  ", 1),
    ));
    out.push((
        "CRLF line ending".into(),
        text.replacen('\n', "\r\n", 1),
    ));
    out.push((
        "leading whitespace on a line".into(),
        text.replacen("\nmarketplace-id:", "\n marketplace-id:", 1),
    ));
    out
}

#[test]
fn every_statement_refuses_shared_mutations() {
    for (name, m) in mutations(TERMS) {
        assert!(hs::parse_terms_statement(&m, MKT).is_none(), "terms: {name}");
    }
    for (name, m) in mutations(ASSIGNMENT) {
        assert!(
            hs::parse_assignment_statement(&m, MKT, Network::Stagenet).is_none(),
            "assignment: {name}"
        );
        assert!(
            hs::parse_assignment_fields(&m).is_none(),
            "assignment fields: {name}"
        );
    }
    for (name, m) in mutations(OPEN) {
        assert!(hs::parse_open_token(&m, MKT).is_none(), "open: {name}");
    }
    for (name, m) in mutations(ACK) {
        assert!(hs::parse_ack_statement(&m, MKT).is_none(), "ack: {name}");
    }
    for (name, m) in mutations(SHIPPED) {
        assert!(hs::parse_shipped_statement(&m, MKT).is_none(), "shipped: {name}");
    }
    for (name, m) in mutations(ISSUE) {
        assert!(hs::parse_issue_statement(&m, MKT).is_none(), "issue: {name}");
    }
    for (name, m) in mutations(SETTLE) {
        assert!(hs::parse_settle_statement(&m, MKT).is_none(), "settle: {name}");
    }
    for (name, m) in mutations(REFUND_TO) {
        assert!(
            hs::parse_refund_to_statement(&m, MKT, Network::Stagenet).is_none(),
            "refund-to: {name}"
        );
    }
    for (name, m) in mutations(RECEIPT) {
        assert!(hs::parse_receipt_statement(&m, MKT).is_none(), "receipt: {name}");
    }
    for (name, m) in mutations(VOUCH) {
        assert!(hs::parse_vouch_statement(&m, MKT).is_none(), "vouch: {name}");
    }
    for (name, m) in mutations(LINK) {
        assert!(hs::parse_link_statement(&m, MKT).is_none(), "link: {name}");
    }
}

#[test]
fn statement_value_rules_bite() {
    // Terms: cap range, enums, fingerprint case, version zero.
    assert!(hs::parse_terms_statement(&TERMS.replace("remedy-cap-pct: 25", "remedy-cap-pct: 101"), MKT).is_none());
    assert!(hs::parse_terms_statement(&TERMS.replace("transit-risk: seller", "transit-risk: nobody"), MKT).is_none());
    assert!(hs::parse_terms_statement(&TERMS.replace("A1B2C3D4", "a1b2c3d4"), MKT).is_none(), "fingerprints are uppercase");
    assert!(hs::parse_terms_statement(&TERMS.replacen("cdcd", "CDCD", 1), MKT).is_none(), "digests are lowercase");
    // Off-platform terms: listing-id off-platform with version 0 is the
    // one legal zero (§4 rule 5).
    let off = TERMS
        .replace("listing-id: lst_00000000000000000000000000000001", "listing-id: off-platform")
        .replace("listing-version: 3", "listing-version: 0");
    assert!(hs::parse_terms_statement(&off, MKT).is_some(), "off-platform v0 parses");

    // Assignment: destination kinds and networks (invariant (7)).
    assert!(hs::parse_assignment_statement(&ASSIGNMENT.replace(STAGENET_SUB, STAGENET_STD), MKT, Network::Stagenet).is_none(), "standard address refuses");
    assert!(hs::parse_assignment_statement(&ASSIGNMENT.replace(STAGENET_SUB, STAGENET_INTEGRATED), MKT, Network::Stagenet).is_none(), "integrated refuses");
    assert!(hs::parse_assignment_statement(&ASSIGNMENT.replace(STAGENET_SUB, MAINNET_SUB), MKT, Network::Stagenet).is_none(), "mainnet destination on a stagenet instance refuses");
    assert!(hs::parse_assignment_statement(&ASSIGNMENT.replace("network: monero-stagenet", "network: monero-mainnet"), MKT, Network::Stagenet).is_none(), "statement network must match the instance");
    assert!(hs::parse_assignment_statement(&ASSIGNMENT.replace("settlement: direct", "settlement: multisig-2of3"), MKT, Network::Stagenet).is_none(), "only `direct` parses today");
    assert!(hs::parse_assignment_statement(&ASSIGNMENT.replace("nonce: 0123", "nonce: 012Z"), MKT, Network::Stagenet).is_none());
    assert!(hs::parse_assignment_statement(&ASSIGNMENT.replace("amount-atomic: 250000000000", "amount-atomic: 0250000000000"), MKT, Network::Stagenet).is_none(), "no leading zeros");
    assert!(hs::parse_assignment_statement(&ASSIGNMENT.replace("expires-at: 2026-12-01T00:00:00Z", "expires-at: 2026-12-01 00:00:00Z"), MKT, Network::Stagenet).is_none(), "timestamps are canonical");
    assert!(hs::parse_assignment_statement(&ASSIGNMENT.replace("expires-at: 2026-12-01T00:00:00Z", "expires-at: 2026-02-30T00:00:00Z"), MKT, Network::Stagenet).is_none(), "impossible dates refuse");

    // Shipped / issue / settle / refund-to / receipt / link values.
    assert!(hs::parse_shipped_statement(&SHIPPED.replace("direction: out", "direction: sideways"), MKT).is_none());
    assert!(hs::parse_shipped_statement(&SHIPPED.replace("efef", "EFEF"), MKT).is_none(), "commit digest is lowercase hex");
    assert!(hs::parse_shipped_statement(&SHIPPED.replace("date: 2026-10-22", "date: 2026-13-22"), MKT).is_none());
    assert!(hs::parse_issue_statement(&ISSUE.replace("requested-refund-pct: 40", "requested-refund-pct: 0"), MKT).is_none());
    assert!(hs::parse_issue_statement(&ISSUE.replace("requested-refund-pct: 40", "requested-refund-pct: 101"), MKT).is_none());
    assert!(hs::parse_issue_statement(&ISSUE.replace("kind: missing-part", "kind: vibes"), MKT).is_none());
    assert!(hs::parse_settle_statement(&SETTLE.replace("return-required: yes", "return-required: maybe"), MKT).is_none());
    assert!(hs::parse_settle_statement(&SETTLE.replace("month: 2026-11", "month: 2026-13"), MKT).is_none());
    assert!(hs::parse_refund_to_statement(&REFUND_TO.replace(STAGENET_SUB, STAGENET_INTEGRATED), MKT, Network::Stagenet).is_none(), "integrated refund destination refuses");
    assert!(hs::parse_receipt_statement(&RECEIPT.replace("outcome: completed", "outcome: refunded"), MKT).is_none());
    assert!(hs::parse_receipt_statement(&RECEIPT.replace("month: 2026-11\noutcome", "outcome: completed\nmonth: 2026-11\noutcome"), MKT).is_none(), "field order is fixed");
    let long_venue = LINK.replace("Some Other Market", &"x".repeat(65));
    assert!(hs::parse_link_statement(&long_venue, MKT).is_none(), "venue-name caps at 64 chars");
}

// §6 fold: all three timings, issue/settle, lapsed, terminals.
// ---------------------------------------------------------------------

fn assignment(timing: hs::PaymentTiming) -> hs::AssignmentStatement {
    hs::AssignmentStatement {
        marketplace_id: MKT.into(),
        network: Network::Stagenet,
        seller_key_fingerprint: SELLER_FPR.into(),
        buyer_key_fingerprint: BUYER_FPR.into(),
        terms_statement_sha256: TERMS_SHA.into(),
        destination: modules_api::Subaddress::validate(STAGENET_SUB, Network::Stagenet).unwrap(),
        amount_atomic: 250_000_000_000,
        payment_timing: timing,
        expires_at: "2026-12-01T00:00:00Z".into(),
        nonce: "0123456789abcdef0123456789abcdef".into(),
    }
}

fn ev_assignment(timing: hs::PaymentTiming) -> TradeEvent {
    TradeEvent::Assignment(assignment(timing))
}
fn ev_payment() -> TradeEvent {
    TradeEvent::Payment(PaymentRecord {
        txid: "f".repeat(64),
        proof: "OutProofV2fixture".into(),
    })
}
fn ev_ack() -> TradeEvent {
    TradeEvent::Ack(hs::AckStatement {
        marketplace_id: MKT.into(),
        trade_id: ASSIGNMENT_TRADE_ID.into(),
        date: "2026-10-21".into(),
    })
}
fn ev_shipped(date: &str) -> TradeEvent {
    TradeEvent::Shipped(hs::ShippedStatement {
        marketplace_id: MKT.into(),
        trade_id: ASSIGNMENT_TRADE_ID.into(),
        direction: hs::ShippedDirection::Out,
        date: date.into(),
        carrier_commit: "none".into(),
    })
}
fn ev_return() -> TradeEvent {
    TradeEvent::Shipped(hs::ShippedStatement {
        marketplace_id: MKT.into(),
        trade_id: ASSIGNMENT_TRADE_ID.into(),
        direction: hs::ShippedDirection::Return,
        date: "2026-11-05".into(),
        carrier_commit: "none".into(),
    })
}
fn ev_issue(date: &str) -> TradeEvent {
    TradeEvent::Issue(hs::IssueStatement {
        marketplace_id: MKT.into(),
        trade_id: ASSIGNMENT_TRADE_ID.into(),
        kind: hs::IssueKind::Item,
        requested_refund_pct: 50,
        date: date.into(),
    })
}
fn ev_settle(refund_atomic: u64) -> TradeEvent {
    TradeEvent::Settle(hs::SettleStatement {
        marketplace_id: MKT.into(),
        trade_id: ASSIGNMENT_TRADE_ID.into(),
        refund_atomic,
        return_required: false,
        month: "2026-11".into(),
    })
}
fn ev_receipt() -> TradeEvent {
    TradeEvent::Receipt(hs::ReceiptStatement {
        marketplace_id: MKT.into(),
        trade_id: ASSIGNMENT_TRADE_ID.into(),
        seller_key_fingerprint: SELLER_FPR.into(),
        buyer_key_fingerprint: BUYER_FPR.into(),
        month: "2026-11".into(),
    })
}
fn fold(events: &[TradeEvent], now: &str) -> domain::ht_fold::FoldedTrade {
    fold_trade(events, now).expect("an assignment is held")
}

#[test]
fn fold_prepay_path() {
    let a = ev_assignment(hs::PaymentTiming::Prepay);
    let f = fold(&[a.clone()], "2026-10-20T00:00:00Z");
    assert_eq!(f.state, TradeState::Assigned);
    let f = fold(&[a.clone(), ev_payment()], "2026-10-20T00:00:00Z");
    assert_eq!(f.state, TradeState::Paid, "payment record alone pays");
    let f = fold(&[a.clone(), ev_ack()], "2026-10-20T00:00:00Z");
    assert_eq!(f.state, TradeState::Paid, "seller ack alone pays (§6 rule 2)");
    let f = fold(
        &[a.clone(), ev_payment(), ev_shipped("2026-10-22")],
        "2026-10-23T00:00:00Z",
    );
    assert_eq!(f.state, TradeState::Shipped);
    let f = fold(
        &[a.clone(), ev_payment(), ev_shipped("2026-10-22"), ev_receipt()],
        "2026-10-25T00:00:00Z",
    );
    assert_eq!(f.state, TradeState::Closed);
    assert!(f.terminal);
}

#[test]
fn fold_on_ship_path() {
    let a = ev_assignment(hs::PaymentTiming::OnShip);
    let f = fold(&[a.clone(), ev_shipped("2026-10-22")], "2026-10-23T00:00:00Z");
    assert_eq!(f.state, TradeState::Shipped, "seller ships first");
    let f = fold(
        &[a.clone(), ev_shipped("2026-10-22"), ev_payment()],
        "2026-10-24T00:00:00Z",
    );
    assert_eq!(f.state, TradeState::Paid);
    assert!(f.paid && f.shipped);
    let f = fold(
        &[a.clone(), ev_shipped("2026-10-22"), ev_payment(), ev_receipt()],
        "2026-10-25T00:00:00Z",
    );
    assert_eq!(f.state, TradeState::Closed);
}

#[test]
fn fold_on_receipt_path() {
    let a = ev_assignment(hs::PaymentTiming::OnReceipt);
    let f = fold(&[a.clone(), ev_shipped("2026-10-22")], "2026-10-30T00:00:00Z");
    assert_eq!(f.state, TradeState::Shipped);
    let f = fold(
        &[a.clone(), ev_shipped("2026-10-22"), ev_payment()],
        "2026-11-15T00:00:00Z",
    );
    assert_eq!(f.state, TradeState::Paid);
    let f = fold(
        &[a.clone(), ev_shipped("2026-10-22"), ev_payment(), ev_receipt()],
        "2026-11-16T00:00:00Z",
    );
    assert_eq!(f.state, TradeState::Closed);
}

#[test]
fn fold_issue_window_and_settle() {
    let a = ev_assignment(hs::PaymentTiming::Prepay);
    // Issue before shipping does nothing.
    let f = fold(
        &[a.clone(), ev_payment(), ev_issue("2026-10-21")],
        "2026-10-21T00:00:00Z",
    );
    assert_eq!(f.state, TradeState::Paid);
    // Issue on the last day of the window (shipped + 30) raises.
    let f = fold(
        &[a.clone(), ev_payment(), ev_shipped("2026-10-22"), ev_issue("2026-11-21")],
        "2026-11-21T00:00:00Z",
    );
    assert_eq!(f.state, TradeState::IssueRaised);
    assert_eq!(f.issue_window_ends.as_deref(), Some("2026-11-21"));
    // One day later does not.
    let f = fold(
        &[a.clone(), ev_payment(), ev_shipped("2026-10-22"), ev_issue("2026-11-22")],
        "2026-11-22T00:00:00Z",
    );
    assert_eq!(f.state, TradeState::Shipped);
    // Settle closes with the refund recorded (§6).
    let f = fold(
        &[
            a.clone(),
            ev_payment(),
            ev_shipped("2026-10-22"),
            ev_issue("2026-11-01"),
            ev_settle(100_000_000_000),
        ],
        "2026-11-02T00:00:00Z",
    );
    assert_eq!(f.state, TradeState::Settled);
    assert_eq!(f.refund_atomic, Some(100_000_000_000));
    assert!(f.terminal);
    // A settle above the trade amount is not a settle.
    let f = fold(
        &[a.clone(), ev_payment(), ev_shipped("2026-10-22"), ev_settle(250_000_000_001)],
        "2026-11-02T00:00:00Z",
    );
    assert_eq!(f.state, TradeState::Shipped, "over-amount settle ignored");
    // A full-refund settle is legal.
    let f = fold(
        &[a.clone(), ev_payment(), ev_shipped("2026-10-22"), ev_settle(250_000_000_000)],
        "2026-11-02T00:00:00Z",
    );
    assert_eq!(f.state, TradeState::Settled);
}

#[test]
fn fold_lapsed_and_terminals_ignore_later_statements() {
    let a = ev_assignment(hs::PaymentTiming::OnReceipt);
    let f = fold(&[a.clone()], "2026-12-02T00:00:00Z");
    assert_eq!(f.state, TradeState::Lapsed, "expiry passed, nothing paid or shipped");
    let f = fold(&[a.clone(), ev_shipped("2026-11-30")], "2026-12-02T00:00:00Z");
    assert_eq!(f.state, TradeState::Shipped, "a shipped statement defeats lapse");
    let f = fold(&[a.clone(), ev_payment()], "2026-12-02T00:00:00Z");
    assert_eq!(f.state, TradeState::Paid, "payment defeats lapse");
    // Terminal precedence is decided by OUTCOME, not by held order
    // (§6 rule 4, as re-ruled by the owner 2026-10-21/22): one
    // complete terminal alone decides the trade; two DIFFERENT
    // complete terminals conflict, in either held order; a second
    // terminal identical in outcome is the same terminal, not a
    // conflict; and once a terminal state is reached, later
    // statements that are not complete terminals change nothing.
    //
    // Pin 1 — the receipt side.
    let f = fold(
        &[a.clone(), ev_payment(), ev_receipt()],
        "2026-11-02T00:00:00Z",
    );
    assert_eq!(f.state, TradeState::Closed, "a lone complete receipt closes");
    assert_eq!(f.refund_atomic, None);
    assert!(f.terminal);
    let f = fold(
        &[a.clone(), ev_payment(), ev_receipt(), ev_receipt()],
        "2026-11-02T00:00:00Z",
    );
    assert_eq!(
        f.state,
        TradeState::Closed,
        "a duplicated receipt is the same receipt, not a second terminal"
    );
    let f = fold(
        &[a.clone(), ev_payment(), ev_receipt(), ev_shipped("2026-10-22")],
        "2026-11-02T00:00:00Z",
    );
    assert_eq!(
        f.state,
        TradeState::Closed,
        "a later statement that is not a complete terminal changes nothing"
    );
    let f = fold(
        &[a.clone(), ev_payment(), ev_receipt(), ev_settle(1)],
        "2026-11-02T00:00:00Z",
    );
    assert_eq!(
        f.state,
        TradeState::Conflicted,
        "receipt held first, settle second: two different complete terminals conflict"
    );
    assert!(f.terminal);
    // Pin 2 — the settle side.
    let f = fold(
        &[a.clone(), ev_payment(), ev_settle(5)],
        "2026-11-02T00:00:00Z",
    );
    assert_eq!(f.state, TradeState::Settled, "a lone complete settle settles");
    assert_eq!(f.refund_atomic, Some(5), "on that settle's terms");
    assert!(f.terminal);
    // The same settle terms signed again in a later month — so,
    // different statement bytes — are the same settle outcome.
    let mut resigned = ev_settle(5);
    if let TradeEvent::Settle(s) = &mut resigned {
        s.month = "2026-12".into();
    }
    let f = fold(
        &[a.clone(), ev_payment(), ev_settle(5), resigned],
        "2026-11-02T00:00:00Z",
    );
    assert_eq!(
        f.state,
        TradeState::Settled,
        "identical settle terms re-signed are one settle, not a conflict"
    );
    assert_eq!(f.refund_atomic, Some(5));
    let f = fold(
        &[a.clone(), ev_payment(), ev_settle(5), ev_shipped("2026-10-22")],
        "2026-11-02T00:00:00Z",
    );
    assert_eq!(
        f.state,
        TradeState::Settled,
        "a later statement that is not a complete terminal changes nothing"
    );
    let f = fold(
        &[a.clone(), ev_payment(), ev_settle(5), ev_receipt()],
        "2026-11-02T00:00:00Z",
    );
    assert_eq!(
        f.state,
        TradeState::Conflicted,
        "settle held first, receipt second: two different complete terminals conflict"
    );
    assert!(f.terminal);
    // Two complete settles on DIFFERENT terms conflict as well —
    // whether the refund differs, or only the return term does.
    let f = fold(
        &[a.clone(), ev_payment(), ev_settle(5), ev_settle(10)],
        "2026-11-02T00:00:00Z",
    );
    assert_eq!(
        f.state,
        TradeState::Conflicted,
        "two settles with different refunds conflict"
    );
    let mut return_settle = ev_settle(5);
    if let TradeEvent::Settle(s) = &mut return_settle {
        s.return_required = true;
    }
    let f = fold(
        &[a.clone(), ev_payment(), ev_settle(5), return_settle],
        "2026-11-02T00:00:00Z",
    );
    assert_eq!(
        f.state,
        TradeState::Conflicted,
        "two settles differing only in return-required conflict"
    );
    // A return shipment is not the outbound shipment.
    let f = fold(&[a.clone(), ev_return()], "2026-11-06T00:00:00Z");
    assert_eq!(f.state, TradeState::Assigned);
    assert!(!f.shipped);
    // A receipt naming a different seller does not close.
    let mut wrong = ev_receipt();
    if let TradeEvent::Receipt(r) = &mut wrong {
        r.seller_key_fingerprint = BUYER_FPR.into();
    }
    let f = fold(&[a.clone(), ev_payment(), wrong], "2026-11-02T00:00:00Z");
    assert_ne!(f.state, TradeState::Closed);
    // No assignment held: no trade.
    assert!(fold_trade(&[ev_ack()], "2026-11-02T00:00:00Z").is_none());
}

// ---------------------------------------------------------------------
// §14 buyer verify: checks 1–6 refuse independently; 7 only warns.
// ---------------------------------------------------------------------

use helper_core::keys;
use helper_core::verify::{verify_assignment, VerifyError, VerifyInputs};

struct VerifyFixture {
    seller_secret: Vec<u8>,
    seller_cert: Vec<u8>,
    seller_fpr: String,
    buyer_secret: Vec<u8>,
    buyer_fpr: String,
    terms_text: String,
    terms_statement: Vec<u8>,
    terms_signature: String,
}

fn build_fixture() -> VerifyFixture {
    let (seller_secret, seller_cert) =
        keys::generate_test_cert("HT Seller <seller@example.org>").unwrap();
    let seller_fpr = keys::fingerprint_of(&seller_cert).unwrap();
    let (buyer_secret, buyer_cert) =
        keys::generate_test_cert("HT Buyer <buyer@example.org>").unwrap();
    let buyer_fpr = keys::fingerprint_of(&buyer_cert).unwrap();
    // Signed terms over a canonical text priced at the assignment
    // amount (0.25 XMR).
    let terms_text = hs::listing_terms_text(
        "HT Widget",
        "A widget.",
        "Ships in 3 days.",
        "Refunds per the cap.",
        250_000_000_000,
    );
    let terms_stmt = hs::TermsStatement {
        marketplace_id: MKT.into(),
        listing_id: "lst_00000000000000000000000000000002".into(),
        listing_version: 1,
        seller_key_fingerprint: seller_fpr.clone(),
        terms_sha256: hs::sha256_hex(terms_text.as_bytes()),
        risk: hs::RiskTerms {
            transit_risk: hs::TransitRisk::Seller,
            remedy_cap_pct: 25,
            payment_timing: hs::PaymentTiming::Prepay,
        },
    };
    let terms_statement = terms_stmt.to_bytes();
    let terms_signature = keys::sign_detached(&seller_secret, None, &terms_statement).unwrap();
    VerifyFixture {
        seller_secret,
        seller_cert,
        seller_fpr,
        buyer_secret,
        buyer_fpr,
        terms_text,
        terms_statement,
        terms_signature,
    }
}

/// Canonical `YYYY-MM-DDTHH:MM:SSZ` for 00:00 UTC, `days` from today
/// (civil-from-days; expiry checks measure from the signature's real
/// creation time, so fixtures must be relative to it).
fn timestamp_days_from_now(days: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let z = now.div_euclid(86_400) + days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    format!("{y:04}-{m:02}-{d:02}T00:00:00Z")
}

impl VerifyFixture {
    fn assignment_with(&self, edit: impl FnOnce(&mut hs::AssignmentStatement)) -> Vec<u8> {
        let mut a = hs::AssignmentStatement {
            marketplace_id: MKT.into(),
            network: Network::Stagenet,
            seller_key_fingerprint: self.seller_fpr.clone(),
            buyer_key_fingerprint: self.buyer_fpr.clone(),
            terms_statement_sha256: hs::terms_statement_sha256(&self.terms_statement),
            destination: modules_api::Subaddress::validate(STAGENET_SUB, Network::Stagenet)
                .unwrap(),
            amount_atomic: 250_000_000_000,
            payment_timing: hs::PaymentTiming::Prepay,
            expires_at: timestamp_days_from_now(30),
            nonce: "0123456789abcdef0123456789abcdef".into(),
        };
        edit(&mut a);
        a.to_bytes()
    }
    fn assignment_bytes(&self) -> Vec<u8> {
        self.assignment_with(|_| {})
    }
    /// An assignment whose destination was swapped in the text (the
    /// typed struct cannot hold a non-subaddress at all).
    fn assignment_with_destination(&self, dest: &str) -> Vec<u8> {
        let text = String::from_utf8(self.assignment_bytes()).unwrap();
        text.replace(STAGENET_SUB, dest).into_bytes()
    }
    fn inputs(&self, assignment: &[u8], sig: &str) -> VerifyInputs {
        VerifyInputs {
            assignment: assignment.to_vec(),
            assignment_sig: sig.to_string(),
            seller_cert: self.seller_cert.clone(),
            own_fingerprint: self.buyer_fpr.clone(),
            marketplace_id: MKT.into(),
            network: Network::Stagenet,
            terms_statement: self.terms_statement.clone(),
            terms_sig: self.terms_signature.clone(),
            terms_text: self.terms_text.clone(),
            now: timestamp_days_from_now(0),
            ceiling: None,
        }
    }
    fn run(
        &self,
        assignment: &[u8],
        sig: &str,
    ) -> Result<helper_core::verify::VerifiedAssignment, VerifyError> {
        verify_assignment(&self.inputs(assignment, sig))
    }
    fn sign(&self, bytes: &[u8]) -> String {
        keys::sign_detached(&self.seller_secret, None, bytes).unwrap()
    }
}

#[test]
fn verify_accepts_a_clean_assignment() {
    let fx = build_fixture();
    let bytes = fx.assignment_bytes();
    let sig = fx.sign(&bytes);
    let ok = fx.run(&bytes, &sig).expect("clean assignment verifies");
    assert_eq!(ok.assignment.destination.as_str(), STAGENET_SUB);
    assert_eq!(ok.assignment.amount_atomic, 250_000_000_000);
    assert!(ok.warnings.is_empty());
    assert_eq!(ok.trade_id, hs::trade_id(&bytes));
    assert_eq!(
        hs::payment_proof_message(&ok.trade_id),
        format!("marketplace-pay-v1|{}", ok.trade_id)
    );
}

#[test]
fn verify_check1_signature_stops() {
    let fx = build_fixture();
    let bytes = fx.assignment_bytes();
    // Signed by the buyer's key, not the pinned seller key.
    let bad_sig = keys::sign_detached(&fx.buyer_secret, None, &bytes).unwrap();
    assert!(matches!(fx.run(&bytes, &bad_sig), Err(VerifyError::Signature)));
    // The pinned key is not the key the assignment names (an
    // uncovered key change): stop, never prompt.
    let (_os, other_cert) = keys::generate_test_cert("Other <other@example.org>").unwrap();
    let sig = fx.sign(&bytes);
    let mut inputs = fx.inputs(&bytes, &sig);
    inputs.seller_cert = other_cert;
    assert!(matches!(
        verify_assignment(&inputs),
        Err(VerifyError::Signature)
    ));
}

#[test]
fn verify_check2_party_and_network_stop() {
    let fx = build_fixture();
    // Assignment names a different buyer.
    let bytes = fx.assignment_with(|a| a.buyer_key_fingerprint = fx.seller_fpr.clone());
    let sig = fx.sign(&bytes);
    assert!(matches!(fx.run(&bytes, &sig), Err(VerifyError::Party)));
    // Statement network is not the configured network.
    let bytes = fx.assignment_with(|a| a.network = Network::Testnet);
    let sig = fx.sign(&bytes);
    assert!(matches!(fx.run(&bytes, &sig), Err(VerifyError::Party)));
    // Wrong marketplace id.
    let bytes = fx.assignment_with(|a| a.marketplace_id = "mkt_ffffffffffffffffffffffffffffffff".into());
    let sig = fx.sign(&bytes);
    assert!(matches!(fx.run(&bytes, &sig), Err(VerifyError::Party)));
}

#[test]
fn verify_check3_terms_binding_stops() {
    let fx = build_fixture();
    // Assignment binds a different terms statement.
    let bytes = fx.assignment_with(|a| a.terms_statement_sha256 = "e".repeat(64));
    let sig = fx.sign(&bytes);
    assert!(matches!(fx.run(&bytes, &sig), Err(VerifyError::Terms)));
    // Saved terms statement signed by someone else.
    let bytes = fx.assignment_bytes();
    let sig = fx.sign(&bytes);
    let mut inputs = fx.inputs(&bytes, &sig);
    inputs.terms_sig = keys::sign_detached(&fx.buyer_secret, None, &fx.terms_statement).unwrap();
    assert!(matches!(verify_assignment(&inputs), Err(VerifyError::Terms)));
    // Terms text edited after signing (its hash no longer matches).
    let mut inputs = fx.inputs(&bytes, &sig);
    inputs.terms_text = inputs.terms_text.replace("0.25 XMR", "0.1 XMR");
    assert!(matches!(verify_assignment(&inputs), Err(VerifyError::Terms)));
}

#[test]
fn verify_check4_destination_stops() {
    let fx = build_fixture();
    for dest in [STAGENET_STD, STAGENET_INTEGRATED, MAINNET_SUB] {
        let bytes = fx.assignment_with_destination(dest);
        let sig = fx.sign(&bytes);
        assert!(
            matches!(fx.run(&bytes, &sig), Err(VerifyError::Destination)),
            "destination {dest} must stop at check 4"
        );
    }
}

#[test]
fn verify_check5_amount_stops() {
    let fx = build_fixture();
    let bytes = fx.assignment_with(|a| a.amount_atomic = 249_999_999_999);
    let sig = fx.sign(&bytes);
    assert!(matches!(fx.run(&bytes, &sig), Err(VerifyError::Amount)));
}

#[test]
fn verify_check6_expiry_stops() {
    let fx = build_fixture();
    // Already expired.
    let bytes = fx.assignment_with(|a| a.expires_at = "2020-01-01T00:00:00Z".into());
    let sig = fx.sign(&bytes);
    assert!(matches!(fx.run(&bytes, &sig), Err(VerifyError::Expiry)));
    // More than 60 days after the signature's creation.
    let bytes = fx.assignment_with(|a| a.expires_at = timestamp_days_from_now(90));
    let sig = fx.sign(&bytes);
    assert!(matches!(fx.run(&bytes, &sig), Err(VerifyError::Expiry)));
}

#[test]
fn verify_check7_warns_but_never_stops() {
    let fx = build_fixture();
    let bytes = fx.assignment_bytes();
    let sig = fx.sign(&bytes);
    let mut inputs = fx.inputs(&bytes, &sig);
    inputs.ceiling = Some((100_000_000_000, 0)); // below the 0.25 XMR amount
    let ok = verify_assignment(&inputs).expect("check 7 must not stop payment");
    assert_eq!(ok.warnings.len(), 1);
    assert!(ok.warnings[0].contains("ceiling"));
}

// ---------------------------------------------------------------------
// §4 terms v2 in the app: pinning against the seller's current key,
// per-version pins, superseded versions kept (§15.7).
// ---------------------------------------------------------------------

use sqlx::{PgPool, Row};

fn db_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:dev@localhost/marketplace_dev".to_string())
}
async fn pool() -> PgPool {
    PgPool::connect(&db_url()).await.expect("connect to marketplace_dev")
}

static COUNTER: AtomicU64 = AtomicU64::new(1);
fn uniq128() -> u128 {
    let c = COUNTER.fetch_add(1, Ordering::SeqCst) as u128;
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    t ^ (c << 100) ^ ((std::process::id() as u128) << 64)
}

struct TermsFixture {
    seller_id: i64,
    listing_internal: i64,
    listing_public: String,
    seller_secret: Vec<u8>,
    seller_fpr: String,
}

async fn terms_fixture(pool: &PgPool) -> TermsFixture {
    let (seller_secret, seller_cert) =
        keys::generate_test_cert("HT App Seller <appseller@example.org>").unwrap();
    let seller_fpr = keys::fingerprint_of(&seller_cert).unwrap();
    let public_id = format!("acct_{:032x}", uniq128());
    let row = sqlx::query(
        "INSERT INTO accounts (public_id, username, password_hash, role, created_at) \
         VALUES ($1, $2, 'blind-suite-fixture-hash', 'member', now()) RETURNING id",
    )
    .bind(&public_id)
    .bind(format!("u{:016x}", (uniq128() & 0xffff_ffff_ffff_ffff) as u64))
    .fetch_one(pool)
    .await
    .expect("insert account");
    let seller_id: i64 = row.get("id");
    sqlx::query(
        "INSERT INTO identity_keys (account_id, certificate, fingerprint, version, status, created_at) \
         VALUES ($1, $2, $3, 1, 'current', now())",
    )
    .bind(seller_id)
    .bind(seller_cert)
    .bind(&seller_fpr)
    .execute(pool)
    .await
    .expect("insert identity key");
    let listing_public = format!("lst_{:032x}", uniq128());
    let row = sqlx::query(
        "INSERT INTO listings (public_id, seller_id, title, description, price_atomic, \
                               pricing_module, destination_module, auto_invoice, status, \
                               delivery_terms, refund_terms) \
         VALUES ($1, $2, 'HT Widget', 'A widget.', 250000000000, 'xmr-only', \
                 'signed-address-pool', false, 'draft', 'Ships in 3 days.', \
                 'Refunds per the cap.') RETURNING id",
    )
    .bind(&listing_public)
    .bind(seller_id)
    .fetch_one(pool)
    .await
    .expect("insert listing");
    TermsFixture {
        seller_id,
        listing_internal: row.get("id"),
        listing_public,
        seller_secret,
        seller_fpr,
    }
}

impl TermsFixture {
    async fn listing(&self, pool: &PgPool) -> app::listings::Listing {
        app::listings::listing_by_public_id(pool, &self.listing_public)
            .await
            .unwrap()
            .unwrap()
    }
    async fn signed_terms(
        &self,
        pool: &PgPool,
        version: u64,
    ) -> (String, String) {
        let listing = app::listings::listing_by_public_id(pool, &self.listing_public)
            .await
            .unwrap()
            .unwrap();
        let row = sqlx::query(
            "SELECT delivery_terms, refund_terms FROM listings WHERE id = $1",
        )
        .bind(self.listing_internal)
        .fetch_one(pool)
        .await
        .unwrap();
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
            listing_version: version,
            seller_key_fingerprint: self.seller_fpr.clone(),
            terms_sha256: hs::sha256_hex(text.as_bytes()),
            risk: hs::RiskTerms {
                transit_risk: hs::TransitRisk::Seller,
                remedy_cap_pct: 25,
                payment_timing: hs::PaymentTiming::Prepay,
            },
        };
        let bytes = stmt.to_bytes();
        let sig = keys::sign_detached(&self.seller_secret, None, &bytes).unwrap();
        (String::from_utf8(bytes).unwrap(), sig)
    }
}

#[tokio::test]
async fn terms_v2_pins_per_version_and_survives_supersede() {
    let pool = pool().await;
    let fx = terms_fixture(&pool).await;
    // Nothing pinned yet: the publish gate predicate is false.
    assert!(!app::listings::terms_match_listing(&pool, &fx.listing(&pool).await).await);

    let (stmt, sig) = fx.signed_terms(&pool, 1).await;
    let v = app::listings::submit_terms(&pool, MKT, &fx.listing(&pool).await, &stmt, &sig)
        .await
        .expect("version 1 pins");
    assert_eq!(v.version, 1);
    assert!(app::listings::terms_match_listing(&pool, &fx.listing(&pool).await).await);
    let pinned = app::listings::current_terms(&pool, fx.listing_internal)
        .await
        .unwrap()
        .expect("a pin exists");
    assert_eq!(pinned.version, 1);
    let lines = app::listings::terms_risk_lines(
        &pinned.transit_risk,
        pinned.remedy_cap_pct as i64,
        &pinned.payment_timing,
    );
    assert_eq!(
        lines,
        [
            "If it's lost in the post, the seller refunds or reships.".to_string(),
            "Raise an issue within 30 days of shipping and the seller has promised a refund of up to 25%.".to_string(),
            "You pay before it ships.".to_string(),
        ],
        "the three risk fields render in §4's fixed wording"
    );

    // Re-submitting version 1 is a version error, not a silent no-op.
    let again = app::listings::submit_terms(&pool, MKT, &fx.listing(&pool).await, &stmt, &sig).await;
    assert!(matches!(again, Err(app::listings::TermsError::Version)));

    // Edit the listing text: the pin no longer matches (§4 rule 1 —
    // verification happens at every edit, so publish stays refused).
    sqlx::query("UPDATE listings SET delivery_terms = 'Ships in 9 days.' WHERE id = $1")
        .bind(fx.listing_internal)
        .execute(&pool)
        .await
        .unwrap();
    assert!(!app::listings::terms_match_listing(&pool, &fx.listing(&pool).await).await);

    // Pin version 2 over the edited text; version 1 stays on record
    // (§15.7: kept 12 months after supersede).
    let (stmt2, sig2) = fx.signed_terms(&pool, 2).await;
    let v = app::listings::submit_terms(&pool, MKT, &fx.listing(&pool).await, &stmt2, &sig2)
        .await
        .expect("version 2 pins");
    assert_eq!(v.version, 2);
    assert!(app::listings::terms_match_listing(&pool, &fx.listing(&pool).await).await);
    let count: i64 = sqlx::query(
        "SELECT COUNT(*) AS c FROM listing_terms_statements WHERE listing_id = $1",
    )
    .bind(fx.listing_internal)
    .fetch_one(&pool)
    .await
    .unwrap()
    .get("c");
    assert_eq!(count, 2, "superseded versions are kept");
}

#[tokio::test]
async fn terms_v2_refuses_bad_signature_wrong_key_and_wrong_listing() {
    let pool = pool().await;
    let fx = terms_fixture(&pool).await;
    let (stmt, _sig) = fx.signed_terms(&pool, 1).await;

    // Signature made by a different key.
    let (other_secret, _oc) =
        keys::generate_test_cert("Other <other2@example.org>").unwrap();
    let bad_sig = keys::sign_detached(&other_secret, None, stmt.as_bytes()).unwrap();
    let res = app::listings::submit_terms(&pool, MKT, &fx.listing(&pool).await, &stmt, &bad_sig).await;
    assert!(matches!(res, Err(app::listings::TermsError::BadSignature)));

    // Statement naming a key that is not the account's pinned key.
    let listing = fx.listing(&pool).await;
    let row = sqlx::query("SELECT delivery_terms, refund_terms FROM listings WHERE id = $1")
        .bind(fx.listing_internal)
        .fetch_one(&pool)
        .await
        .unwrap();
    let delivery: String = row.get("delivery_terms");
    let refund: String = row.get("refund_terms");
    let text = hs::listing_terms_text(
        &listing.title,
        &listing.description,
        &delivery,
        &refund,
        listing.price_atomic as u64,
    );
    let foreign = hs::TermsStatement {
        marketplace_id: MKT.into(),
        listing_id: fx.listing_public.clone(),
        listing_version: 1,
        seller_key_fingerprint: BUYER_FPR.into(),
        terms_sha256: hs::sha256_hex(text.as_bytes()),
        risk: hs::RiskTerms {
            transit_risk: hs::TransitRisk::Seller,
            remedy_cap_pct: 25,
            payment_timing: hs::PaymentTiming::Prepay,
        },
    };
    let foreign_bytes = foreign.to_bytes();
    let foreign_sig = keys::sign_detached(&fx.seller_secret, None, &foreign_bytes).unwrap();
    let res = app::listings::submit_terms(
        &pool,
        MKT,
        &fx.listing(&pool).await,
        std::str::from_utf8(&foreign_bytes).unwrap(),
        &foreign_sig,
    )
    .await;
    assert!(matches!(res, Err(app::listings::TermsError::KeyMismatch)));

    // Statement for a different listing.
    let (stmt3, sig3) = fx.signed_terms(&pool, 1).await;
    let stmt3 = stmt3.replace(&fx.listing_public, "lst_00000000000000000000000000000009");
    let res = app::listings::submit_terms(&pool, MKT, &fx.listing(&pool).await, &stmt3, &sig3).await;
    assert!(matches!(res, Err(app::listings::TermsError::WrongListing)));

    // A statement binding a DIFFERENT terms text than the listing's:
    // correctly signed, wrong digest — refused as a text mismatch.
    let foreign_text = hs::TermsStatement {
        marketplace_id: MKT.into(),
        listing_id: fx.listing_public.clone(),
        listing_version: 1,
        seller_key_fingerprint: fx.seller_fpr.clone(),
        terms_sha256: hs::sha256_hex(b"some other terms text"),
        risk: hs::RiskTerms {
            transit_risk: hs::TransitRisk::Seller,
            remedy_cap_pct: 25,
            payment_timing: hs::PaymentTiming::Prepay,
        },
    };
    let ft_bytes = foreign_text.to_bytes();
    let ft_sig = keys::sign_detached(&fx.seller_secret, None, &ft_bytes).unwrap();
    let res = app::listings::submit_terms(
        &pool,
        MKT,
        &fx.listing(&pool).await,
        std::str::from_utf8(&ft_bytes).unwrap(),
        &ft_sig,
    )
    .await;
    assert!(matches!(res, Err(app::listings::TermsError::TextMismatch)), "got {res:?}");
}

// ---------------------------------------------------------------------
// Terms download route: pinned terms are public on a published
// listing; an unpublished listing's terms stay owner-only (404 here,
// anonymously).
// ---------------------------------------------------------------------

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn test_router(pool: PgPool) -> axum::Router {
    let dir = std::env::temp_dir().join(format!("blind-ht1-kf-{}-{:x}", std::process::id(), uniq128()));
    std::fs::create_dir_all(&dir).expect("create keyfile dir");
    let kf_path = dir.join("keyfile");
    let state = app::web::AppState {
        pool,
        hash_guard: app::passwords::HashGuard::new(4),
        throttles: std::sync::Arc::new(app::throttle::Throttles::new()),
        registrations_open: true,
        account_cap: None,
        dev_cookies: true,
        media: app::media::MediaPipeline::from_env(),
        marketplace_id: "mkt_0123456789abcdef0123456789abcdef".into(),
        payments: app::payments::PaymentConfig::defaults("mkt_0123456789abcdef0123456789abcdef"),
        keyfile: std::sync::Arc::new(
            app::keyfile::KeyFile::load_or_generate(&kf_path).expect("load_or_generate keyfile"),
        ),
        stage9: app::reputation::Stage9Config::defaults(),
        retention: app::retention::RetentionConfig::defaults(),
        instance: app::config::InstanceConfig::resolve(&|_| None).unwrap(),
    };
    app::web::router(state)
}

#[tokio::test]
async fn terms_download_visibility() {
    let pool = pool().await;
    let fx = terms_fixture(&pool).await;
    let (stmt, sig) = fx.signed_terms(&pool, 1).await;
    app::listings::submit_terms(&pool, MKT, &fx.listing(&pool).await, &stmt, &sig)
        .await
        .expect("pin v1");
    let app = test_router(pool.clone()).await;
    let get = |app: axum::Router, path: String| async move {
        let res = app
            .oneshot(Request::builder().uri(path).body(Body::empty()).expect("request"))
            .await
            .expect("router oneshot");
        let status = res.status().as_u16();
        let bytes = res.into_body().collect().await.expect("collect").to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    };
    // Draft listing: anonymous download is refused.
    let (status, _) = get(app.clone(), format!("/listings/{}/terms", fx.listing_public)).await;
    assert_eq!(status, 404, "unpublished listing terms are not public");
    // Publish directly (the handler's gate is over the same library
    // predicate asserted above): now the statement is public.
    sqlx::query("UPDATE listings SET status = 'published' WHERE id = $1")
        .bind(fx.listing_internal)
        .execute(&pool)
        .await
        .unwrap();
    let (status, body) = get(app, format!("/listings/{}/terms", fx.listing_public)).await;
    assert_eq!(status, 200);
    assert!(body.contains("statement-format: marketplace-terms-v2"));
    assert!(body.contains("PGP SIGNATURE"), "the detached signature is served with it");
}
