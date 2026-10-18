//! Canonical statement library (spec §10; api-contract §12): the
//! seller-signed invoice and address-pool statements, plus the payment
//! URI / QR derived from a validated invoice. This module does no I/O
//! and verifies no signatures; it parses, validates, and serializes
//! canonical bytes only. Nothing here trims or normalizes (Q13) — a
//! parser returns `None` on ANY violation, and acceptance requires the
//! re-serialization to be byte-identical to the input.

use std::collections::HashSet;
use std::io::Cursor;

use modules_api::{parse_canonical_u64, validate_public_id, Network, Subaddress};

use crate::{validate_canonical_timestamp, Atomic};

// ---------------------------------------------------------------------------
// Statement types (Q17: network is the closed enum, destination is the
// validated newtype — never strings on success types).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceStatement {
    pub marketplace_id: String,
    pub invoice_id: String,
    pub order_id: String,
    pub seller_key_fingerprint: String,
    pub network: Network,
    pub destination: Subaddress,
    pub amount_atomic: u64,
    pub expires_at: String,
    pub terms_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolStatement {
    pub marketplace_id: String,
    pub pool_id: String,
    pub seller_key_fingerprint: String,
    pub network: Network,
    pub created_at: String,
    pub addresses: Vec<Subaddress>,
}

impl InvoiceStatement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("statement-format: marketplace-invoice-v1\n");
        out.push_str(&format!("marketplace-id: {}\n", self.marketplace_id));
        out.push_str(&format!("invoice-id: {}\n", self.invoice_id));
        out.push_str(&format!("order-id: {}\n", self.order_id));
        out.push_str(&format!(
            "seller-key-fingerprint: {}\n",
            self.seller_key_fingerprint
        ));
        out.push_str(&format!("network: {}\n", self.network.statement_name()));
        out.push_str(&format!("destination: {}\n", self.destination.as_str()));
        out.push_str(&format!("amount-atomic: {}\n", self.amount_atomic));
        out.push_str(&format!("expires-at: {}\n", self.expires_at));
        out.push_str(&format!("terms-sha256: {}\n", self.terms_sha256));
        out.into_bytes()
    }
}

impl PoolStatement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("statement-format: marketplace-address-pool-v1\n");
        out.push_str(&format!("marketplace-id: {}\n", self.marketplace_id));
        out.push_str(&format!("pool-id: {}\n", self.pool_id));
        out.push_str(&format!(
            "seller-key-fingerprint: {}\n",
            self.seller_key_fingerprint
        ));
        out.push_str(&format!("network: {}\n", self.network.statement_name()));
        out.push_str(&format!("created-at: {}\n", self.created_at));
        out.push_str(&format!("address-count: {}\n", self.addresses.len()));
        for address in &self.addresses {
            out.push_str(&format!("address: {}\n", address.as_str()));
        }
        out.into_bytes()
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers

/// §4 byte gate: printable ASCII (0x20–0x7E) or LF only.
fn byte_gate(text: &str) -> bool {
    text.bytes().all(|b| b == b'\n' || (0x20..=0x7e).contains(&b))
}

/// Fingerprints are uppercase hex, 40 or 64 chars (§4).
fn valid_fingerprint(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64)
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

/// Digests are exactly 64 lowercase hex chars (§4).
fn valid_terms_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Pull the next line from a `'\n'` split, requiring exactly `key: value`
/// (single space after the colon) with the expected key, in fixed order.
/// Any other shape — blank line, wrong key, missing space — is `None`.
fn next_field<'a, I>(lines: &mut I, want: &str) -> Option<&'a str>
where
    I: Iterator<Item = &'a str>,
{
    let line = lines.next()?;
    let (k, v) = line.split_once(": ")?;
    if k == want {
        Some(v)
    } else {
        None
    }
}

/// After the last field, the split must hold exactly the empty tail of
/// the single final LF and nothing else.
fn expect_end<'a, I>(lines: &mut I) -> Option<()>
where
    I: Iterator<Item = &'a str>,
{
    if lines.next() == Some("") && lines.next().is_none() {
        Some(())
    } else {
        None
    }
}

fn parse_marketplace_id<'a, I>(lines: &mut I, marketplace_id: &str) -> Option<String>
where
    I: Iterator<Item = &'a str>,
{
    let value = next_field(lines, "marketplace-id")?;
    if value != marketplace_id || !validate_public_id(value, "mkt_") {
        return None;
    }
    Some(value.to_string())
}

fn parse_fingerprint<'a, I>(lines: &mut I) -> Option<String>
where
    I: Iterator<Item = &'a str>,
{
    let value = next_field(lines, "seller-key-fingerprint")?;
    if !valid_fingerprint(value) {
        return None;
    }
    Some(value.to_string())
}

fn parse_network<'a, I>(lines: &mut I, instance_network: Network) -> Option<Network>
where
    I: Iterator<Item = &'a str>,
{
    let value = next_field(lines, "network")?;
    let network = Network::from_statement_name(value)?;
    if network != instance_network {
        return None;
    }
    Some(network)
}

// ---------------------------------------------------------------------------
// Parsers

pub fn parse_invoice_statement(
    text: &str,
    marketplace_id: &str,
    instance_network: Network,
    max_amount_atomic: u64,
) -> Option<InvoiceStatement> {
    if !byte_gate(text) {
        return None;
    }
    let mut lines = text.split('\n');
    if next_field(&mut lines, "statement-format")? != "marketplace-invoice-v1" {
        return None;
    }
    let marketplace_id_field = parse_marketplace_id(&mut lines, marketplace_id)?;
    let invoice_id = next_field(&mut lines, "invoice-id")?;
    if !validate_public_id(invoice_id, "inv_") {
        return None;
    }
    let order_id = next_field(&mut lines, "order-id")?;
    if !validate_public_id(order_id, "ord_") {
        return None;
    }
    let seller_key_fingerprint = parse_fingerprint(&mut lines)?;
    let network = parse_network(&mut lines, instance_network)?;
    let destination_raw = next_field(&mut lines, "destination")?;
    let destination = Subaddress::validate(destination_raw, network).ok()?;
    let amount_raw = next_field(&mut lines, "amount-atomic")?;
    let amount_atomic = parse_canonical_u64(amount_raw)?;
    if amount_atomic == 0 || amount_atomic > max_amount_atomic {
        return None;
    }
    let expires_at = next_field(&mut lines, "expires-at")?;
    if !validate_canonical_timestamp(expires_at) {
        return None;
    }
    let terms_sha256 = next_field(&mut lines, "terms-sha256")?;
    if !valid_terms_sha256(terms_sha256) {
        return None;
    }
    expect_end(&mut lines)?;
    let statement = InvoiceStatement {
        marketplace_id: marketplace_id_field,
        invoice_id: invoice_id.to_string(),
        order_id: order_id.to_string(),
        seller_key_fingerprint,
        network,
        destination,
        amount_atomic,
        expires_at: expires_at.to_string(),
        terms_sha256: terms_sha256.to_string(),
    };
    // §4: acceptance requires byte-identical re-serialization.
    if statement.to_bytes() != text.as_bytes() {
        return None;
    }
    Some(statement)
}

pub fn parse_pool_statement(
    text: &str,
    marketplace_id: &str,
    instance_network: Network,
) -> Option<PoolStatement> {
    if !byte_gate(text) {
        return None;
    }
    let mut lines = text.split('\n');
    if next_field(&mut lines, "statement-format")? != "marketplace-address-pool-v1" {
        return None;
    }
    let marketplace_id_field = parse_marketplace_id(&mut lines, marketplace_id)?;
    let pool_id = next_field(&mut lines, "pool-id")?;
    if !validate_public_id(pool_id, "pool_") {
        return None;
    }
    let seller_key_fingerprint = parse_fingerprint(&mut lines)?;
    let network = parse_network(&mut lines, instance_network)?;
    let created_at = next_field(&mut lines, "created-at")?;
    if !validate_canonical_timestamp(created_at) {
        return None;
    }
    let count_raw = next_field(&mut lines, "address-count")?;
    let count = parse_canonical_u64(count_raw)?;
    if !(1..=200).contains(&count) {
        return None;
    }
    let mut addresses: Vec<Subaddress> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for _ in 0..count {
        let raw = next_field(&mut lines, "address")?;
        let address = Subaddress::validate(raw, network).ok()?;
        // Duplicate address lines are rejected: an entry index must
        // identify one address (§11).
        if !seen.insert(address.as_str()) {
            return None;
        }
        addresses.push(address);
    }
    expect_end(&mut lines)?;
    let statement = PoolStatement {
        marketplace_id: marketplace_id_field,
        pool_id: pool_id.to_string(),
        seller_key_fingerprint,
        network,
        created_at: created_at.to_string(),
        addresses,
    };
    if statement.to_bytes() != text.as_bytes() {
        return None;
    }
    Some(statement)
}

// ---------------------------------------------------------------------------
// Payment URI / QR (§11)

pub fn payment_uri(invoice: &InvoiceStatement) -> String {
    payment_uri_for(&invoice.destination.as_str(), invoice.amount_atomic)
}

/// The §11 URI for an arbitrary already-validated destination + amount
/// (Direct Payments v1 payment page: the assigned subaddress and the
/// order total). Same format as [`payment_uri`], always.
pub fn payment_uri_for(address: &str, amount_atomic: u64) -> String {
    format!(
        "monero:{}?tx_amount={}",
        address,
        Atomic(amount_atomic).format_decimal()
    )
}

pub fn payment_qr_png(invoice: &InvoiceStatement) -> Vec<u8> {
    payment_qr_png_for(&invoice.destination.as_str(), invoice.amount_atomic)
}

/// QR PNG of [`payment_uri_for`] — same rendering rules as
/// [`payment_qr_png`] (black modules on white, 4-module quiet zone,
/// 8 px per module, deterministic bytes).
pub fn payment_qr_png_for(address: &str, amount_atomic: u64) -> Vec<u8> {
    let uri = payment_uri_for(address, amount_atomic);
    // QR-encode the URI bytes. Validated statements keep the URI well
    // within QR capacity; if the default construction ever failed, fall
    // back to the largest version at each error-correction level rather
    // than panicking, and finally to an empty image buffer.
    let code = qrcode::QrCode::new(uri.as_bytes()).ok().or_else(|| {
        use qrcode::Version;
        [qrcode::EcLevel::L, qrcode::EcLevel::M, qrcode::EcLevel::Q, qrcode::EcLevel::H]
            .into_iter()
            .find_map(|level| qrcode::QrCode::with_version(uri.as_bytes(), Version::Normal(40), level).ok())
    });
    let Some(code) = code else {
        return Vec::new();
    };
    let width = code.width();
    let colors = code.to_colors();
    // Render: black modules on white, 4-module quiet zone, 8 px/module.
    let scale = 8usize;
    let quiet = 4usize;
    let dim = ((width + quiet * 2) * scale) as u32;
    let mut img = image::GrayImage::from_pixel(dim, dim, image::Luma([255u8]));
    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == qrcode::Color::Dark {
                let px = ((x + quiet) * scale) as u32;
                let py = ((y + quiet) * scale) as u32;
                for dy in 0..scale as u32 {
                    for dx in 0..scale as u32 {
                        img.put_pixel(px + dx, py + dy, image::Luma([0u8]));
                    }
                }
            }
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(Cursor::new(&mut buf));
    if image::ImageEncoder::write_image(
        encoder,
        &img,
        dim,
        dim,
        image::ExtendedColorType::L8,
    )
    .is_err()
    {
        return Vec::new();
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    // Stagenet subaddresses from the wallet RPC docs / offline fixtures
    // (same family of fixtures the locked suite uses, distinct entries).
    const SUB_A: &str =
        "7BnERTpvL5MbCLtj5n9No7J5oE5hHiB3tVCK5cjSvCsYWD2WRJLFuWeKTLiXo5QJqt2ZwUaLy2Vh1Ad51K7FNgqcHgjW85o";
    const MKT: &str = "mkt_4f9c2a7e1b3d5f60718293a4b5c6d7e8";
    const FPR: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
    const TERMS: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const MAX: u64 = 1_000_000_000_000_000;

    fn invoice_text() -> String {
        format!(
            "statement-format: marketplace-invoice-v1\n\
             marketplace-id: {MKT}\n\
             invoice-id: inv_8d1e5b0c3a7f2b4d6f8091a3b5c7d9e0\n\
             order-id: ord_2b6a9e4d1c083f5a7c9e1b2d4f607182\n\
             seller-key-fingerprint: {FPR}\n\
             network: monero-stagenet\n\
             destination: {SUB_A}\n\
             amount-atomic: 1250000000000\n\
             expires-at: 2026-10-16T17:00:00Z\n\
             terms-sha256: {TERMS}\n"
        )
    }

    fn pool_text() -> String {
        format!(
            "statement-format: marketplace-address-pool-v1\n\
             marketplace-id: {MKT}\n\
             pool-id: pool_6c0e3f9a5b7d9f1a2c4e6a8b0d2f4a6b\n\
             seller-key-fingerprint: {FPR}\n\
             network: monero-stagenet\n\
             created-at: 2026-10-13T16:00:00Z\n\
             address-count: 1\n\
             address: {SUB_A}\n"
        )
    }

    #[test]
    fn invoice_round_trip() {
        let text = invoice_text();
        let inv = parse_invoice_statement(&text, MKT, Network::Stagenet, MAX)
            .expect("valid invoice parses");
        assert_eq!(inv.amount_atomic, 1_250_000_000_000);
        assert!(matches!(inv.network, Network::Stagenet));
        assert_eq!(inv.to_bytes(), text.as_bytes());
    }

    #[test]
    fn pool_round_trip() {
        let text = pool_text();
        let pool = parse_pool_statement(&text, MKT, Network::Stagenet)
            .expect("valid pool parses");
        assert_eq!(pool.addresses.len(), 1);
        assert_eq!(pool.to_bytes(), text.as_bytes());
    }

    #[test]
    fn rejections() {
        // CRLF, missing final LF, wrong instance network, amount above cap,
        // duplicate pool address, lowercase fingerprint.
        let text = invoice_text();
        assert!(parse_invoice_statement(&text.replace('\n', "\r\n"), MKT, Network::Stagenet, MAX).is_none());
        assert!(parse_invoice_statement(text.trim_end(), MKT, Network::Stagenet, MAX).is_none());
        assert!(parse_invoice_statement(&text, MKT, Network::Mainnet, MAX).is_none());
        assert!(parse_invoice_statement(&text, MKT, Network::Stagenet, 1).is_none());
        let dup = format!(
            "statement-format: marketplace-address-pool-v1\n\
             marketplace-id: {MKT}\n\
             pool-id: pool_6c0e3f9a5b7d9f1a2c4e6a8b0d2f4a6b\n\
             seller-key-fingerprint: {FPR}\n\
             network: monero-stagenet\n\
             created-at: 2026-10-13T16:00:00Z\n\
             address-count: 2\n\
             address: {SUB_A}\n\
             address: {SUB_A}\n"
        );
        assert!(parse_pool_statement(&dup, MKT, Network::Stagenet).is_none());
        assert!(parse_pool_statement(
            &pool_text().replacen(FPR, "0123456789abcdef0123456789abcdef01234567", 1),
            MKT,
            Network::Stagenet
        )
        .is_none());
    }

    #[test]
    fn uri_exact_and_qr_is_png() {
        let inv = parse_invoice_statement(&invoice_text(), MKT, Network::Stagenet, MAX).unwrap();
        assert_eq!(
            payment_uri(&inv),
            format!("monero:{SUB_A}?tx_amount=1.25")
        );
        let png = payment_qr_png(&inv);
        assert!(png.starts_with(&[0x89, 0x50, 0x4E, 0x47]));
        assert_eq!(png, payment_qr_png(&inv), "QR rendering is deterministic");
    }

    #[test]
    fn uri_for_matches_invoice_uri() {
        let inv = parse_invoice_statement(&invoice_text(), MKT, Network::Stagenet, MAX).unwrap();
        assert_eq!(
            payment_uri_for(SUB_A, 1_250_000_000_000),
            payment_uri(&inv),
            "the direct-v1 helpers must render the identical §11 URI"
        );
        assert_eq!(
            payment_qr_png_for(SUB_A, 1_250_000_000_000),
            payment_qr_png(&inv)
        );
    }

    #[test]
    fn qr_png_decodes_back_to_the_encoded_uri_modules() {
        // Closes the Stage 6 gate's named blind spot: 11 QR-geometry
        // mutants survived because no test ever looked at the rendered
        // modules. Decode the PNG and compare module-for-module against
        // the QR matrix of the same URI. (QR-DECODE-TEST-DRAFT-2026-10-14)
        let inv = parse_invoice_statement(&invoice_text(), MKT, Network::Stagenet, MAX)
            .expect("fixture invoice must parse");
        let png = payment_qr_png(&inv);
        assert!(!png.is_empty(), "QR render must produce a PNG");

        let img = image::load_from_memory(&png)
            .expect("rendered QR must be a decodable PNG")
            .to_luma8();

        let uri = payment_uri(&inv);
        let code = qrcode::QrCode::new(uri.as_bytes()).expect("URI must encode");
        let width = code.width();
        let colors = code.to_colors();

        // Pinned geometry: 4-module quiet zone, 8 px per module.
        let (scale, quiet) = (8usize, 4usize);
        let dim = ((width + quiet * 2) * scale) as u32;
        assert_eq!(
            img.dimensions(),
            (dim, dim),
            "PNG size must be (modules + 2*quiet) * scale in both axes"
        );

        // Quiet zone must be entirely white.
        for y in 0..dim {
            for x in 0..dim {
                let in_qr = x >= (quiet * scale) as u32
                    && x < ((quiet + width) * scale) as u32
                    && y >= (quiet * scale) as u32
                    && y < ((quiet + width) * scale) as u32;
                if !in_qr {
                    assert_eq!(
                        img.get_pixel(x, y).0[0],
                        255,
                        "quiet zone pixel ({x},{y}) must be white"
                    );
                }
            }
        }

        // Every module's centre pixel must match the encoded matrix.
        for my in 0..width {
            for mx in 0..width {
                let cx = ((mx + quiet) * scale + scale / 2) as u32;
                let cy = ((my + quiet) * scale + scale / 2) as u32;
                let dark = img.get_pixel(cx, cy).0[0] == 0;
                let expect_dark = colors[my * width + mx] == qrcode::Color::Dark;
                assert_eq!(
                    dark, expect_dark,
                    "module ({mx},{my}) rendered with the wrong colour"
                );
            }
        }
    }
}
