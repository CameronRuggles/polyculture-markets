//! Hidden Trades statement family (Alpha build spec §5): the eleven
//! canonical statements of the hidden-trades design, in the same
//! canonical-statement family as [`crate::statements`] — printable
//! ASCII + LF only, `key: value` with exactly one space after the
//! colon, fixed key order, first line `statement-format: <name>`,
//! exactly one final LF, no trimming or normalising anywhere, and
//! acceptance requires byte-identical re-serialisation.
//!
//! This module parses, validates and serialises canonical bytes
//! only. It verifies no signatures and does no I/O; signature
//! verification lives with the key owners (the app's pinned keys on
//! the server, the helper's pins locally), exactly as for the v1
//! invoice/pool statements.

use modules_api::{
    parse_canonical_u64, validate_any_address, validate_public_id, Network, Subaddress,
};
use sha2::{Digest, Sha256};

use crate::statements::{byte_gate, expect_end, next_field, valid_fingerprint, valid_terms_sha256};
use crate::{validate_canonical_date, validate_canonical_month, validate_canonical_timestamp, Atomic};

// ---------------------------------------------------------------------------
// Closed value sets (§5).

/// Terms-statement `transit-risk` (§4): who carries a loss in the post.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitRisk {
    Seller,
    Buyer,
}

impl TransitRisk {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransitRisk::Seller => "seller",
            TransitRisk::Buyer => "buyer",
        }
    }
    pub fn from_statement(s: &str) -> Option<TransitRisk> {
        match s {
            "seller" => Some(TransitRisk::Seller),
            "buyer" => Some(TransitRisk::Buyer),
            _ => None,
        }
    }
}

/// `payment-timing` (§4/§5): when the buyer pays relative to
/// shipment. Reserved §19 values (`mad-2of2`, `multisig-2of3` are
/// settlement modes, NOT timings) never parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentTiming {
    Prepay,
    OnShip,
    OnReceipt,
}

impl PaymentTiming {
    pub fn as_str(&self) -> &'static str {
        match self {
            PaymentTiming::Prepay => "prepay",
            PaymentTiming::OnShip => "on_ship",
            PaymentTiming::OnReceipt => "on_receipt",
        }
    }
    pub fn from_statement(s: &str) -> Option<PaymentTiming> {
        match s {
            "prepay" => Some(PaymentTiming::Prepay),
            "on_ship" => Some(PaymentTiming::OnShip),
            "on_receipt" => Some(PaymentTiming::OnReceipt),
            _ => None,
        }
    }
}

/// Shipped-statement `direction` (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShippedDirection {
    Out,
    Return,
}

impl ShippedDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShippedDirection::Out => "out",
            ShippedDirection::Return => "return",
        }
    }
    pub fn from_statement(s: &str) -> Option<ShippedDirection> {
        match s {
            "out" => Some(ShippedDirection::Out),
            "return" => Some(ShippedDirection::Return),
            _ => None,
        }
    }
}

/// Issue-statement `kind` (§5/§9): what the buyer says went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueKind {
    Item,
    Quality,
    MissingPart,
}

impl IssueKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            IssueKind::Item => "item",
            IssueKind::Quality => "quality",
            IssueKind::MissingPart => "missing-part",
        }
    }
    pub fn from_statement(s: &str) -> Option<IssueKind> {
        match s {
            "item" => Some(IssueKind::Item),
            "quality" => Some(IssueKind::Quality),
            "missing-part" => Some(IssueKind::MissingPart),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Small shared readers / validators.

/// SHA-256 of `bytes`, lowercase hex (the digest shape of §5).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn valid_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A transaction id: 64 lowercase hex (§5/§7).
pub fn valid_txid(s: &str) -> bool {
    valid_lower_hex(s, 64)
}

/// An assignment nonce: 128 bits, 32 lowercase hex (§5).
fn valid_nonce(s: &str) -> bool {
    valid_lower_hex(s, 32)
}

fn check_format<'a, I>(lines: &mut I, name: &str) -> Option<()>
where
    I: Iterator<Item = &'a str>,
{
    let value = next_field(lines, "statement-format")?;
    (value == name).then_some(())
}

fn next_marketplace_id<'a, I>(lines: &mut I, marketplace_id: &str) -> Option<String>
where
    I: Iterator<Item = &'a str>,
{
    let value = next_field(lines, "marketplace-id")?;
    if value != marketplace_id || !validate_public_id(value, "mkt_") {
        return None;
    }
    Some(value.to_string())
}

fn next_fingerprint<'a, I>(lines: &mut I, key: &str) -> Option<String>
where
    I: Iterator<Item = &'a str>,
{
    let value = next_field(lines, key)?;
    if !valid_fingerprint(value) {
        return None;
    }
    Some(value.to_string())
}

fn next_digest<'a, I>(lines: &mut I, key: &str) -> Option<String>
where
    I: Iterator<Item = &'a str>,
{
    let value = next_field(lines, key)?;
    if !valid_terms_sha256(value) {
        return None;
    }
    Some(value.to_string())
}

fn next_u64<'a, I>(lines: &mut I, key: &str) -> Option<u64>
where
    I: Iterator<Item = &'a str>,
{
    parse_canonical_u64(next_field(lines, key)?)
}

fn next_listing_id<'a, I>(lines: &mut I) -> Option<String>
where
    I: Iterator<Item = &'a str>,
{
    let value = next_field(lines, "listing-id")?;
    if value == "off-platform" || validate_public_id(value, "lst_") {
        Some(value.to_string())
    } else {
        None
    }
}

fn next_trade_id<'a, I>(lines: &mut I) -> Option<String>
where
    I: Iterator<Item = &'a str>,
{
    let value = next_field(lines, "trade-id")?;
    if valid_terms_sha256(value) {
        Some(value.to_string())
    } else {
        None
    }
}

fn next_date<'a, I>(lines: &mut I) -> Option<String>
where
    I: Iterator<Item = &'a str>,
{
    let value = next_field(lines, "date")?;
    if validate_canonical_date(value) {
        Some(value.to_string())
    } else {
        None
    }
}

fn next_month<'a, I>(lines: &mut I) -> Option<String>
where
    I: Iterator<Item = &'a str>,
{
    let value = next_field(lines, "month")?;
    if validate_canonical_month(value) {
        Some(value.to_string())
    } else {
        None
    }
}

/// The fixed §4 risk fields are shared by the terms statement (input)
/// and its fixed-wording display; the statement stores them typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskTerms {
    pub transit_risk: TransitRisk,
    pub remedy_cap_pct: u64,
    pub payment_timing: PaymentTiming,
}

// ---------------------------------------------------------------------------
// Terms statement (§4/§5): marketplace-terms-v2. Signed by the
// seller; pinned per listing version by the server (H1) and saved by
// the buyer from the listing.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermsStatement {
    pub marketplace_id: String,
    pub listing_id: String,
    pub listing_version: u64,
    pub seller_key_fingerprint: String,
    pub terms_sha256: String,
    pub risk: RiskTerms,
}

impl TermsStatement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("statement-format: marketplace-terms-v2\n");
        out.push_str(&format!("marketplace-id: {}\n", self.marketplace_id));
        out.push_str(&format!("listing-id: {}\n", self.listing_id));
        out.push_str(&format!("listing-version: {}\n", self.listing_version));
        out.push_str(&format!(
            "seller-key-fingerprint: {}\n",
            self.seller_key_fingerprint
        ));
        out.push_str(&format!("terms-sha256: {}\n", self.terms_sha256));
        out.push_str(&format!("transit-risk: {}\n", self.risk.transit_risk.as_str()));
        out.push_str(&format!("remedy-cap-pct: {}\n", self.risk.remedy_cap_pct));
        out.push_str(&format!(
            "payment-timing: {}\n",
            self.risk.payment_timing.as_str()
        ));
        out.into_bytes()
    }
}

pub fn parse_terms_statement(text: &str, marketplace_id: &str) -> Option<TermsStatement> {
    if !byte_gate(text) {
        return None;
    }
    let mut lines = text.split('\n');
    check_format(&mut lines, "marketplace-terms-v2")?;
    let marketplace_id = next_marketplace_id(&mut lines, marketplace_id)?;
    let listing_id = next_listing_id(&mut lines)?;
    let listing_version = next_u64(&mut lines, "listing-version")?;
    let seller_key_fingerprint = next_fingerprint(&mut lines, "seller-key-fingerprint")?;
    let terms_sha256 = next_digest(&mut lines, "terms-sha256")?;
    let transit_risk = TransitRisk::from_statement(next_field(&mut lines, "transit-risk")?)?;
    let remedy_cap_pct = next_u64(&mut lines, "remedy-cap-pct")?;
    if remedy_cap_pct > 100 {
        return None;
    }
    let payment_timing =
        PaymentTiming::from_statement(next_field(&mut lines, "payment-timing")?)?;
    expect_end(&mut lines)?;
    let stmt = TermsStatement {
        marketplace_id,
        listing_id,
        listing_version,
        seller_key_fingerprint,
        terms_sha256,
        risk: RiskTerms {
            transit_risk,
            remedy_cap_pct,
            payment_timing,
        },
    };
    (stmt.to_bytes() == text.as_bytes()).then_some(stmt)
}

/// The canonical listing terms text whose SHA-256 a terms statement
/// binds (§4: the statement "wraps the existing terms text hash").
/// One definition for the whole build: the app hashes the listing's
/// stored text with this function when a terms statement is pinned,
/// and the helper hashes the seller's own copy with it when signing.
/// Sections mirror the v1 terms file's body (`orders::build_terms`);
/// a blank delivery/refund section renders the same fallback line;
/// a `Price` section closes the text so the statement also binds the
/// listing's price (the buyer's helper reads it back for §14 check
/// 5). CR characters are normalised to LF, as in the v1 body; no
/// other normalisation is applied.
pub fn listing_terms_text(
    title: &str,
    description: &str,
    delivery_terms: &str,
    refund_terms: &str,
    price_atomic: u64,
) -> String {
    fn section(text: &str) -> String {
        text.replace("\r\n", "\n").replace('\r', "\n")
    }
    fn or_unspecified(text: &str) -> String {
        if text.trim().is_empty() {
            "Not specified by the seller.".to_string()
        } else {
            section(text)
        }
    }
    format!(
        "Title\n{}\n\nDescription\n{}\n\nDelivery terms\n{}\n\nRefund terms\n{}\n\nPrice\n{} XMR\n",
        section(title),
        section(description),
        or_unspecified(delivery_terms),
        or_unspecified(refund_terms),
        Atomic(price_atomic).format_decimal(),
    )
}

/// The price bound into a canonical listing terms text (the exact
/// inverse of [`listing_terms_text`]'s final section). `None` for
/// anything that is not exactly that shape.
pub fn listing_terms_price(text: &str) -> Option<u64> {
    let body = text.strip_suffix('\n')?;
    let tail = body.rsplit("\n\n").next()?;
    let decimal = tail.strip_prefix("Price\n")?.strip_suffix(" XMR")?;
    Atomic::parse_decimal(decimal).map(|a| a.0)
}

// ---------------------------------------------------------------------------
// Assignment statement (§5): marketplace-assignment-v1. Signed by the
// seller; the trade-id is the SHA-256 of its exact bytes.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentStatement {
    pub marketplace_id: String,
    pub network: Network,
    pub seller_key_fingerprint: String,
    pub buyer_key_fingerprint: String,
    pub terms_statement_sha256: String,
    pub destination: Subaddress,
    pub amount_atomic: u64,
    pub payment_timing: PaymentTiming,
    pub expires_at: String,
    pub nonce: String,
}

impl AssignmentStatement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let destination = self.destination.as_str();
        assignment_bytes(
            &self.marketplace_id,
            self.network,
            &self.seller_key_fingerprint,
            &self.buyer_key_fingerprint,
            &self.terms_statement_sha256,
            &destination,
            self.amount_atomic,
            self.payment_timing,
            &self.expires_at,
            &self.nonce,
        )
    }
}

/// The assignment's fields as parsed WITHOUT the instance-binding
/// checks (marketplace / network equality) and WITHOUT destination
/// validation: every field is shape-validated, nothing is compared
/// against local configuration. The buyer's `verify` (§14) works on
/// this form so it can name the exact check that failed; the strict
/// parser below is this parse plus the binding + destination checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentFields {
    pub marketplace_id: String,
    pub network: Network,
    pub seller_key_fingerprint: String,
    pub buyer_key_fingerprint: String,
    pub terms_statement_sha256: String,
    pub destination: String,
    pub amount_atomic: u64,
    pub payment_timing: PaymentTiming,
    pub expires_at: String,
    pub nonce: String,
}

fn assignment_bytes(
    marketplace_id: &str,
    network: Network,
    seller_key_fingerprint: &str,
    buyer_key_fingerprint: &str,
    terms_statement_sha256: &str,
    destination: &str,
    amount_atomic: u64,
    payment_timing: PaymentTiming,
    expires_at: &str,
    nonce: &str,
) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("statement-format: marketplace-assignment-v1\n");
    out.push_str(&format!("marketplace-id: {marketplace_id}\n"));
    out.push_str(&format!("network: {}\n", network.statement_name()));
    out.push_str(&format!(
        "seller-key-fingerprint: {seller_key_fingerprint}\n"
    ));
    out.push_str(&format!(
        "buyer-key-fingerprint: {buyer_key_fingerprint}\n"
    ));
    out.push_str(&format!(
        "terms-statement-sha256: {terms_statement_sha256}\n"
    ));
    out.push_str(&format!("destination: {destination}\n"));
    out.push_str(&format!("amount-atomic: {amount_atomic}\n"));
    out.push_str(&format!(
        "payment-timing: {}\n",
        payment_timing.as_str()
    ));
    out.push_str(&format!("expires-at: {expires_at}\n"));
    out.push_str(&format!("nonce: {nonce}\n"));
    out.into_bytes()
}

pub fn parse_assignment_fields(text: &str) -> Option<AssignmentFields> {
    if !byte_gate(text) {
        return None;
    }
    let mut lines = text.split('\n');
    check_format(&mut lines, "marketplace-assignment-v1")?;
    let marketplace_id = next_field(&mut lines, "marketplace-id")?.to_string();
    if !validate_public_id(&marketplace_id, "mkt_") {
        return None;
    }
    let network = Network::from_statement_name(next_field(&mut lines, "network")?)?;
    let seller_key_fingerprint = next_fingerprint(&mut lines, "seller-key-fingerprint")?;
    let buyer_key_fingerprint = next_fingerprint(&mut lines, "buyer-key-fingerprint")?;
    let terms_statement_sha256 = next_digest(&mut lines, "terms-statement-sha256")?;
    let destination = next_field(&mut lines, "destination")?.to_string();
    let amount_atomic = next_u64(&mut lines, "amount-atomic")?;
    if amount_atomic == 0 {
        return None;
    }
    let payment_timing =
        PaymentTiming::from_statement(next_field(&mut lines, "payment-timing")?)?;
    let expires_at = next_field(&mut lines, "expires-at")?.to_string();
    if !validate_canonical_timestamp(&expires_at) {
        return None;
    }
    let nonce = next_field(&mut lines, "nonce")?.to_string();
    if !valid_nonce(&nonce) {
        return None;
    }
    expect_end(&mut lines)?;
    let fields = AssignmentFields {
        marketplace_id,
        network,
        seller_key_fingerprint,
        buyer_key_fingerprint,
        terms_statement_sha256,
        destination,
        amount_atomic,
        payment_timing,
        expires_at,
        nonce,
    };
    let bytes = assignment_bytes(
        &fields.marketplace_id,
        fields.network,
        &fields.seller_key_fingerprint,
        &fields.buyer_key_fingerprint,
        &fields.terms_statement_sha256,
        &fields.destination,
        fields.amount_atomic,
        fields.payment_timing,
        &fields.expires_at,
        &fields.nonce,
    );
    (bytes == text.as_bytes()).then_some(fields)
}

pub fn parse_assignment_statement(
    text: &str,
    marketplace_id: &str,
    instance_network: Network,
) -> Option<AssignmentStatement> {
    let fields = parse_assignment_fields(text)?;
    if fields.marketplace_id != marketplace_id || fields.network != instance_network {
        return None;
    }
    let destination = Subaddress::validate(&fields.destination, instance_network).ok()?;
    Some(AssignmentStatement {
        marketplace_id: fields.marketplace_id,
        network: fields.network,
        seller_key_fingerprint: fields.seller_key_fingerprint,
        buyer_key_fingerprint: fields.buyer_key_fingerprint,
        terms_statement_sha256: fields.terms_statement_sha256,
        destination,
        amount_atomic: fields.amount_atomic,
        payment_timing: fields.payment_timing,
        expires_at: fields.expires_at,
        nonce: fields.nonce,
    })
}

/// The trade-id of an assignment: SHA-256 of its exact bytes,
/// final LF included (§5). This is the trade's only name.
pub fn trade_id(assignment_bytes: &[u8]) -> String {
    sha256_hex(assignment_bytes)
}

/// The §5 terms-statement digest an assignment binds: SHA-256 of the
/// terms statement's exact bytes.
pub fn terms_statement_sha256(terms_bytes: &[u8]) -> String {
    sha256_hex(terms_bytes)
}

// ---------------------------------------------------------------------------
// Open token (§5): marketplace-open-v1. Signed by the seller; posted
// to open the trade's existence.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenToken {
    pub marketplace_id: String,
    pub trade_id: String,
    pub buyer_key_fingerprint: String,
    pub seller_key_fingerprint: String,
}

impl OpenToken {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("statement-format: marketplace-open-v1\n");
        out.push_str(&format!("marketplace-id: {}\n", self.marketplace_id));
        out.push_str(&format!("trade-id: {}\n", self.trade_id));
        out.push_str(&format!(
            "buyer-key-fingerprint: {}\n",
            self.buyer_key_fingerprint
        ));
        out.push_str(&format!(
            "seller-key-fingerprint: {}\n",
            self.seller_key_fingerprint
        ));
        out.into_bytes()
    }
}

pub fn parse_open_token(text: &str, marketplace_id: &str) -> Option<OpenToken> {
    if !byte_gate(text) {
        return None;
    }
    let mut lines = text.split('\n');
    check_format(&mut lines, "marketplace-open-v1")?;
    let marketplace_id = next_marketplace_id(&mut lines, marketplace_id)?;
    let trade_id = next_trade_id(&mut lines)?;
    let buyer_key_fingerprint = next_fingerprint(&mut lines, "buyer-key-fingerprint")?;
    let seller_key_fingerprint = next_fingerprint(&mut lines, "seller-key-fingerprint")?;
    expect_end(&mut lines)?;
    let stmt = OpenToken {
        marketplace_id,
        trade_id,
        buyer_key_fingerprint,
        seller_key_fingerprint,
    };
    (stmt.to_bytes() == text.as_bytes()).then_some(stmt)
}

// ---------------------------------------------------------------------------
// Ack (§5): marketplace-ack-v1. The seller's signed word that the
// buyer paid. `acknowledged` has exactly one value today: `paid`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckStatement {
    pub marketplace_id: String,
    pub trade_id: String,
    pub seller_key_fingerprint: String,
    pub date: String,
}

impl AckStatement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("statement-format: marketplace-ack-v1\n");
        out.push_str(&format!("marketplace-id: {}\n", self.marketplace_id));
        out.push_str(&format!("trade-id: {}\n", self.trade_id));
        out.push_str(&format!(
            "seller-key-fingerprint: {}\n",
            self.seller_key_fingerprint
        ));
        out.push_str("acknowledged: paid\n");
        out.push_str(&format!("date: {}\n", self.date));
        out.into_bytes()
    }
}

pub fn parse_ack_statement(text: &str, marketplace_id: &str) -> Option<AckStatement> {
    if !byte_gate(text) {
        return None;
    }
    let mut lines = text.split('\n');
    check_format(&mut lines, "marketplace-ack-v1")?;
    let marketplace_id = next_marketplace_id(&mut lines, marketplace_id)?;
    let trade_id = next_trade_id(&mut lines)?;
    let seller_key_fingerprint = next_fingerprint(&mut lines, "seller-key-fingerprint")?;
    if next_field(&mut lines, "acknowledged")? != "paid" {
        return None;
    }
    let date = next_date(&mut lines)?;
    expect_end(&mut lines)?;
    let stmt = AckStatement {
        marketplace_id,
        trade_id,
        seller_key_fingerprint,
        date,
    };
    (stmt.to_bytes() == text.as_bytes()).then_some(stmt)
}

// ---------------------------------------------------------------------------
// Shipped (§5): marketplace-shipped-v1. `carrier-commit` is the
// SHA-256 of `<carrier>|<tracking>|<salt hex>` or the literal `none`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShippedStatement {
    pub marketplace_id: String,
    pub trade_id: String,
    pub seller_key_fingerprint: String,
    pub direction: ShippedDirection,
    pub carrier_commit: String,
    pub date: String,
}

impl ShippedStatement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("statement-format: marketplace-shipped-v1\n");
        out.push_str(&format!("marketplace-id: {}\n", self.marketplace_id));
        out.push_str(&format!("trade-id: {}\n", self.trade_id));
        out.push_str(&format!(
            "seller-key-fingerprint: {}\n",
            self.seller_key_fingerprint
        ));
        out.push_str(&format!("direction: {}\n", self.direction.as_str()));
        out.push_str(&format!("carrier-commit: {}\n", self.carrier_commit));
        out.push_str(&format!("date: {}\n", self.date));
        out.into_bytes()
    }
}

pub fn parse_shipped_statement(text: &str, marketplace_id: &str) -> Option<ShippedStatement> {
    if !byte_gate(text) {
        return None;
    }
    let mut lines = text.split('\n');
    check_format(&mut lines, "marketplace-shipped-v1")?;
    let marketplace_id = next_marketplace_id(&mut lines, marketplace_id)?;
    let trade_id = next_trade_id(&mut lines)?;
    let seller_key_fingerprint = next_fingerprint(&mut lines, "seller-key-fingerprint")?;
    let direction = ShippedDirection::from_statement(next_field(&mut lines, "direction")?)?;
    let carrier_commit = next_field(&mut lines, "carrier-commit")?.to_string();
    if carrier_commit != "none" && !valid_terms_sha256(&carrier_commit) {
        return None;
    }
    let date = next_date(&mut lines)?;
    expect_end(&mut lines)?;
    let stmt = ShippedStatement {
        marketplace_id,
        trade_id,
        seller_key_fingerprint,
        direction,
        carrier_commit,
        date,
    };
    (stmt.to_bytes() == text.as_bytes()).then_some(stmt)
}

/// The §5 carrier commitment: SHA-256 of the exact string
/// `<carrier>|<tracking>|<salt hex>`, where the salt is 128 bits as
/// 32 lowercase hex.
pub fn carrier_commit(carrier: &str, tracking: &str, salt_hex: &str) -> Option<String> {
    if !valid_nonce(salt_hex) {
        return None;
    }
    Some(sha256_hex(format!("{carrier}|{tracking}|{salt_hex}").as_bytes()))
}

// ---------------------------------------------------------------------------
// Issue (§5): marketplace-issue-v1, signed by the buyer.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueStatement {
    pub marketplace_id: String,
    pub trade_id: String,
    pub buyer_key_fingerprint: String,
    pub kind: IssueKind,
    pub requested_refund_pct: u64,
    pub date: String,
}

impl IssueStatement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("statement-format: marketplace-issue-v1\n");
        out.push_str(&format!("marketplace-id: {}\n", self.marketplace_id));
        out.push_str(&format!("trade-id: {}\n", self.trade_id));
        out.push_str(&format!(
            "buyer-key-fingerprint: {}\n",
            self.buyer_key_fingerprint
        ));
        out.push_str(&format!("kind: {}\n", self.kind.as_str()));
        out.push_str(&format!(
            "requested-refund-pct: {}\n",
            self.requested_refund_pct
        ));
        out.push_str(&format!("date: {}\n", self.date));
        out.into_bytes()
    }
}

pub fn parse_issue_statement(text: &str, marketplace_id: &str) -> Option<IssueStatement> {
    if !byte_gate(text) {
        return None;
    }
    let mut lines = text.split('\n');
    check_format(&mut lines, "marketplace-issue-v1")?;
    let marketplace_id = next_marketplace_id(&mut lines, marketplace_id)?;
    let trade_id = next_trade_id(&mut lines)?;
    let buyer_key_fingerprint = next_fingerprint(&mut lines, "buyer-key-fingerprint")?;
    let kind = IssueKind::from_statement(next_field(&mut lines, "kind")?)?;
    let requested_refund_pct = next_u64(&mut lines, "requested-refund-pct")?;
    if requested_refund_pct == 0 || requested_refund_pct > 100 {
        return None;
    }
    let date = next_date(&mut lines)?;
    expect_end(&mut lines)?;
    let stmt = IssueStatement {
        marketplace_id,
        trade_id,
        buyer_key_fingerprint,
        kind,
        requested_refund_pct,
        date,
    };
    (stmt.to_bytes() == text.as_bytes()).then_some(stmt)
}

// ---------------------------------------------------------------------------
// Settle (§5): marketplace-settle-v1, signed by the seller. Closes a
// trade with an agreed refund; `settlement` accepts only `direct`
// today (§19: reserved values do not parse).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettleStatement {
    pub marketplace_id: String,
    pub trade_id: String,
    pub seller_key_fingerprint: String,
    pub refund_atomic: u64,
    pub refund_to: String,
    pub month: String,
}

impl SettleStatement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("statement-format: marketplace-settle-v1\n");
        out.push_str(&format!("marketplace-id: {}\n", self.marketplace_id));
        out.push_str(&format!("trade-id: {}\n", self.trade_id));
        out.push_str(&format!(
            "seller-key-fingerprint: {}\n",
            self.seller_key_fingerprint
        ));
        out.push_str(&format!("refund-atomic: {}\n", self.refund_atomic));
        out.push_str(&format!("refund-to: {}\n", self.refund_to));
        out.push_str(&format!("month: {}\n", self.month));
        out.push_str("settlement: direct\n");
        out.into_bytes()
    }
}

pub fn parse_settle_statement(
    text: &str,
    marketplace_id: &str,
    instance_network: Network,
) -> Option<SettleStatement> {
    if !byte_gate(text) {
        return None;
    }
    let mut lines = text.split('\n');
    check_format(&mut lines, "marketplace-settle-v1")?;
    let marketplace_id = next_marketplace_id(&mut lines, marketplace_id)?;
    let trade_id = next_trade_id(&mut lines)?;
    let seller_key_fingerprint = next_fingerprint(&mut lines, "seller-key-fingerprint")?;
    let refund_atomic = next_u64(&mut lines, "refund-atomic")?;
    let refund_to = validate_any_address(next_field(&mut lines, "refund-to")?, instance_network)
        .ok()?;
    let month = next_month(&mut lines)?;
    if next_field(&mut lines, "settlement")? != "direct" {
        return None;
    }
    expect_end(&mut lines)?;
    let stmt = SettleStatement {
        marketplace_id,
        trade_id,
        seller_key_fingerprint,
        refund_atomic,
        refund_to,
        month,
    };
    (stmt.to_bytes() == text.as_bytes()).then_some(stmt)
}

// ---------------------------------------------------------------------------
// Refund destination (§5): marketplace-refund-to-v1, signed by the
// buyer before any refund or close.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefundToStatement {
    pub marketplace_id: String,
    pub trade_id: String,
    pub buyer_key_fingerprint: String,
    pub refund_destination: String,
}

impl RefundToStatement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("statement-format: marketplace-refund-to-v1\n");
        out.push_str(&format!("marketplace-id: {}\n", self.marketplace_id));
        out.push_str(&format!("trade-id: {}\n", self.trade_id));
        out.push_str(&format!(
            "buyer-key-fingerprint: {}\n",
            self.buyer_key_fingerprint
        ));
        out.push_str(&format!(
            "refund-destination: {}\n",
            self.refund_destination
        ));
        out.into_bytes()
    }
}

pub fn parse_refund_to_statement(
    text: &str,
    marketplace_id: &str,
    instance_network: Network,
) -> Option<RefundToStatement> {
    if !byte_gate(text) {
        return None;
    }
    let mut lines = text.split('\n');
    check_format(&mut lines, "marketplace-refund-to-v1")?;
    let marketplace_id = next_marketplace_id(&mut lines, marketplace_id)?;
    let trade_id = next_trade_id(&mut lines)?;
    let buyer_key_fingerprint = next_fingerprint(&mut lines, "buyer-key-fingerprint")?;
    let refund_destination = validate_any_address(
        next_field(&mut lines, "refund-destination")?,
        instance_network,
    )
    .ok()?;
    expect_end(&mut lines)?;
    let stmt = RefundToStatement {
        marketplace_id,
        trade_id,
        buyer_key_fingerprint,
        refund_destination,
    };
    (stmt.to_bytes() == text.as_bytes()).then_some(stmt)
}

// ---------------------------------------------------------------------------
// Receipt (§5): marketplace-receipt-v1, signed by the buyer.
// `outcome` has exactly one value today: `completed`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptStatement {
    pub marketplace_id: String,
    pub trade_id: String,
    pub buyer_key_fingerprint: String,
    pub month: String,
}

impl ReceiptStatement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("statement-format: marketplace-receipt-v1\n");
        out.push_str(&format!("marketplace-id: {}\n", self.marketplace_id));
        out.push_str(&format!("trade-id: {}\n", self.trade_id));
        out.push_str(&format!(
            "buyer-key-fingerprint: {}\n",
            self.buyer_key_fingerprint
        ));
        out.push_str("outcome: completed\n");
        out.push_str(&format!("month: {}\n", self.month));
        out.into_bytes()
    }
}

pub fn parse_receipt_statement(text: &str, marketplace_id: &str) -> Option<ReceiptStatement> {
    if !byte_gate(text) {
        return None;
    }
    let mut lines = text.split('\n');
    check_format(&mut lines, "marketplace-receipt-v1")?;
    let marketplace_id = next_marketplace_id(&mut lines, marketplace_id)?;
    let trade_id = next_trade_id(&mut lines)?;
    let buyer_key_fingerprint = next_fingerprint(&mut lines, "buyer-key-fingerprint")?;
    if next_field(&mut lines, "outcome")? != "completed" {
        return None;
    }
    let month = next_month(&mut lines)?;
    expect_end(&mut lines)?;
    let stmt = ReceiptStatement {
        marketplace_id,
        trade_id,
        buyer_key_fingerprint,
        month,
    };
    (stmt.to_bytes() == text.as_bytes()).then_some(stmt)
}

// ---------------------------------------------------------------------------
// Vouch (§5): marketplace-vouch-v1. Display-only (H5 renders it).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VouchStatement {
    pub marketplace_id: String,
    pub voucher_key_fingerprint: String,
    pub newcomer_key_fingerprint: String,
    pub month: String,
}

impl VouchStatement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("statement-format: marketplace-vouch-v1\n");
        out.push_str(&format!("marketplace-id: {}\n", self.marketplace_id));
        out.push_str(&format!(
            "voucher-key-fingerprint: {}\n",
            self.voucher_key_fingerprint
        ));
        out.push_str(&format!(
            "newcomer-key-fingerprint: {}\n",
            self.newcomer_key_fingerprint
        ));
        out.push_str(&format!("month: {}\n", self.month));
        out.into_bytes()
    }
}

pub fn parse_vouch_statement(text: &str, marketplace_id: &str) -> Option<VouchStatement> {
    if !byte_gate(text) {
        return None;
    }
    let mut lines = text.split('\n');
    check_format(&mut lines, "marketplace-vouch-v1")?;
    let marketplace_id = next_marketplace_id(&mut lines, marketplace_id)?;
    let voucher_key_fingerprint = next_fingerprint(&mut lines, "voucher-key-fingerprint")?;
    let newcomer_key_fingerprint = next_fingerprint(&mut lines, "newcomer-key-fingerprint")?;
    let month = next_month(&mut lines)?;
    expect_end(&mut lines)?;
    let stmt = VouchStatement {
        marketplace_id,
        voucher_key_fingerprint,
        newcomer_key_fingerprint,
        month,
    };
    (stmt.to_bytes() == text.as_bytes()).then_some(stmt)
}

// ---------------------------------------------------------------------------
// Link (§5): marketplace-link-v1. Display-only (H5 renders it).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkStatement {
    pub marketplace_id: String,
    pub account_key_fingerprint: String,
    pub venue_name: String,
    pub venue_address: String,
    pub venue_account: String,
}

impl LinkStatement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("statement-format: marketplace-link-v1\n");
        out.push_str(&format!("marketplace-id: {}\n", self.marketplace_id));
        out.push_str(&format!(
            "account-key-fingerprint: {}\n",
            self.account_key_fingerprint
        ));
        out.push_str(&format!("venue-name: {}\n", self.venue_name));
        out.push_str(&format!("venue-address: {}\n", self.venue_address));
        out.push_str(&format!("venue-account: {}\n", self.venue_account));
        out.into_bytes()
    }
}

pub fn parse_link_statement(text: &str, marketplace_id: &str) -> Option<LinkStatement> {
    if !byte_gate(text) {
        return None;
    }
    let mut lines = text.split('\n');
    check_format(&mut lines, "marketplace-link-v1")?;
    let marketplace_id = next_marketplace_id(&mut lines, marketplace_id)?;
    let account_key_fingerprint = next_fingerprint(&mut lines, "account-key-fingerprint")?;
    let venue_name = next_field(&mut lines, "venue-name")?.to_string();
    if venue_name.is_empty() || venue_name.chars().count() > 64 {
        return None;
    }
    let venue_address = next_field(&mut lines, "venue-address")?.to_string();
    if venue_address.is_empty() || venue_address.chars().count() > 200 {
        return None;
    }
    let venue_account = next_field(&mut lines, "venue-account")?.to_string();
    if venue_account.is_empty() || venue_account.chars().count() > 200 {
        return None;
    }
    expect_end(&mut lines)?;
    let stmt = LinkStatement {
        marketplace_id,
        account_key_fingerprint,
        venue_name,
        venue_address,
        venue_account,
    };
    (stmt.to_bytes() == text.as_bytes()).then_some(stmt)
}

// ---------------------------------------------------------------------------
// Transaction-proof messages (§5): the exact strings a Monero
// transaction proof commits to. A proof over any other string proves
// nothing here.

/// The payment-proof message for a trade: `marketplace-pay-v1|<trade-id>`.
pub fn payment_proof_message(trade_id: &str) -> String {
    format!("marketplace-pay-v1|{trade_id}")
}

/// The refund-proof message for a trade: `marketplace-refund-v1|<trade-id>`.
pub fn refund_proof_message(trade_id: &str) -> String {
    format!("marketplace-refund-v1|{trade_id}")
}

/// The stake-proof message (§5): `marketplace-stake-v1|<marketplace-id>|<fingerprint>`.
pub fn stake_proof_message(marketplace_id: &str, fingerprint: &str) -> String {
    format!("marketplace-stake-v1|{marketplace_id}|{fingerprint}")
}

/// Which trade-bound proof a message belongs to (§14 form check:
/// "the message names this trade and no other").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofPurpose {
    Payment,
    Refund,
}

/// Exact-match check that `message` is the §5 proof message for
/// `purpose` and `trade_id` — no other message is accepted.
pub fn proof_message_matches(message: &str, purpose: ProofPurpose, trade_id: &str) -> bool {
    let expected = match purpose {
        ProofPurpose::Payment => payment_proof_message(trade_id),
        ProofPurpose::Refund => refund_proof_message(trade_id),
    };
    message == expected
}

/// Exact-match check that `message` is the §5 stake-proof message
/// for this marketplace and fingerprint.
pub fn stake_message_matches(message: &str, marketplace_id: &str, fingerprint: &str) -> bool {
    message == stake_proof_message(marketplace_id, fingerprint)
}
