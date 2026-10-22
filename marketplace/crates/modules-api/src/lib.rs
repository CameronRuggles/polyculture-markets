//! modules-api — the only crate strategy modules depend on (spec §4).
//!
//! Stage 0 contents: the closed types every later stage builds on —
//! validated `Subaddress`, public-ID patterns, canonical integers, the
//! form-layer input normalizer (the ONLY place trimming happens), the
//! envelope error taxonomy, capability handles, and the module traits
//! with their closed evidence enums. Modules propose; the core verifies,
//! records, and renders. Nothing in this crate does I/O.

use std::fmt;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Networks, address kinds, and the Subaddress newtype (spec §3.7, §4; Q2/Q14/Q17)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Mainnet,
    Stagenet,
    Testnet,
}

impl Network {
    pub fn statement_name(&self) -> &'static str {
        match self {
            Network::Mainnet => "monero-mainnet",
            Network::Stagenet => "monero-stagenet",
            Network::Testnet => "monero-testnet",
        }
    }
    pub fn from_statement_name(s: &str) -> Option<Network> {
        match s {
            "monero-mainnet" => Some(Network::Mainnet),
            "monero-stagenet" => Some(Network::Stagenet),
            "monero-testnet" => Some(Network::Testnet),
            _ => None,
        }
    }
}

impl From<Network> for monero::Network {
    fn from(n: Network) -> Self {
        match n {
            Network::Mainnet => monero::Network::Mainnet,
            Network::Stagenet => monero::Network::Stagenet,
            Network::Testnet => monero::Network::Testnet,
        }
    }
}
impl From<monero::Network> for Network {
    fn from(n: monero::Network) -> Self {
        match n {
            monero::Network::Mainnet => Network::Mainnet,
            monero::Network::Stagenet => Network::Stagenet,
            monero::Network::Testnet => Network::Testnet,
        }
    }
}

/// Closed set of address kinds (Q17: kind exists only inside rejections).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    Standard,
    Integrated,
    Subaddress,
}

impl From<monero::AddressType> for AddressKind {
    fn from(t: monero::AddressType) -> Self {
        match t {
            monero::AddressType::Standard => AddressKind::Standard,
            monero::AddressType::Integrated(_) => AddressKind::Integrated,
            monero::AddressType::SubAddress => AddressKind::Subaddress,
        }
    }
}

/// Destination validation failures, in the pinned check order (Q2):
/// decode/checksum, then network, then kind, then key sanity (Q14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationError {
    Parse,
    WrongNetwork,
    WrongKind { found: AddressKind },
    /// A public key is the identity or has a torsion (small-order) component.
    SmallOrderKey,
}

/// A Monero subaddress that has passed full validation. Constructible only
/// through [`Subaddress::validate`] (Q4-S1): if you hold one, it is a
/// subaddress, on its stated network, with torsion-free keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subaddress {
    address: monero::Address,
    network: Network,
}

impl Subaddress {
    pub fn validate(input: &str, expected: Network) -> Result<Subaddress, DestinationError> {
        // 1. Decode + checksum + canonical point encoding (the `monero`
        //    crate's PublicKey::from_slice rejects non-canonical encodings;
        //    a locked fixture guards that behaviour against crate changes).
        let parsed = monero::Address::from_str(input).map_err(|_| DestinationError::Parse)?;
        // 2. Network.
        let network = Network::from(parsed.network);
        if network != expected {
            return Err(DestinationError::WrongNetwork);
        }
        // 3. Kind.
        if parsed.addr_type != monero::AddressType::SubAddress {
            return Err(DestinationError::WrongKind {
                found: AddressKind::from(parsed.addr_type),
            });
        }
        // 4. Torsion / identity (Q14): a small-order view key would make
        //    payments linkable and amounts decryptable to any observer.
        check_keys(&parsed)?;
        Ok(Subaddress {
            address: parsed,
            network,
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }
    pub fn as_str(&self) -> String {
        self.address.to_string()
    }
}

impl fmt::Display for Subaddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

/// Shared key-sanity check (Q14): both embedded public keys must be
/// torsion-free and not the identity. Used by every address validator in
/// this crate — the checks themselves come from the vetted `monero` /
/// `curve25519-dalek` crates; no Monero cryptography is hand-rolled here.
fn check_keys(parsed: &monero::Address) -> Result<(), DestinationError> {
    for key in [parsed.public_spend, parsed.public_view] {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(key.as_bytes());
        let compressed = curve25519_dalek::edwards::CompressedEdwardsY(bytes);
        let point = compressed.decompress().ok_or(DestinationError::Parse)?;
        if !point.is_torsion_free() || point == curve25519_dalek::edwards::EdwardsPoint::default() {
            return Err(DestinationError::SmallOrderKey);
        }
    }
    Ok(())
}

/// Validate a seller's primary (standard) address for the direct-payment
/// identity (Direct Payments v1): same pinned check order as
/// [`Subaddress::validate`] — decode/checksum → network → kind → key
/// sanity — but the required kind is Standard. Returns the canonical
/// re-encoding of the validated address. Never trims its input.
pub fn validate_standard_address(
    input: &str,
    expected: Network,
) -> Result<String, DestinationError> {
    let parsed = monero::Address::from_str(input).map_err(|_| DestinationError::Parse)?;
    let network = Network::from(parsed.network);
    if network != expected {
        return Err(DestinationError::WrongNetwork);
    }
    if parsed.addr_type != monero::AddressType::Standard {
        return Err(DestinationError::WrongKind {
            found: AddressKind::from(parsed.addr_type),
        });
    }
    check_keys(&parsed)?;
    Ok(parsed.to_string())
}

/// Validate an address a refund may be sent to (Alpha spec §5,
/// `marketplace-settle-v1` / `marketplace-refund-to-v1`): same pinned
/// check order as [`Subaddress::validate`] — decode/checksum →
/// network → kind → key sanity — but the accepted kinds are Standard
/// and Subaddress. Integrated addresses are refused: a baked-in
/// payment ID would silently change what a transaction proof proves.
/// Returns the canonical re-encoding of the validated address. Never
/// trims its input.
pub fn validate_any_address(input: &str, expected: Network) -> Result<String, DestinationError> {
    let parsed = monero::Address::from_str(input).map_err(|_| DestinationError::Parse)?;
    let network = Network::from(parsed.network);
    if network != expected {
        return Err(DestinationError::WrongNetwork);
    }
    if matches!(parsed.addr_type, monero::AddressType::Integrated(_)) {
        return Err(DestinationError::WrongKind {
            found: AddressKind::Integrated,
        });
    }
    check_keys(&parsed)?;
    Ok(parsed.to_string())
}

// ---------------------------------------------------------------------------
// Public IDs (Q15): prefix + 32 lowercase hex (128 bits, matching §16).

pub fn validate_public_id(s: &str, prefix: &str) -> bool {
    let Some(rest) = s.strip_prefix(prefix) else {
        return false;
    };
    rest.len() == 32
        && rest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------------------
// Canonical integers (Q3): digits only, no sign, no whitespace, no leading
// zeros, fits in u64. ("0" itself is allowed here; range rules live with
// each field's own validation.)

pub fn parse_canonical_u64(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse().ok()
}

// ---------------------------------------------------------------------------
// Form-layer input normalization (Q13). This is the ONLY trimming in the
// system. Nothing below the form layer trims: not Subaddress::validate,
// not the statement parsers, not the database, not URI/QR generation.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormInputError {
    /// Non-ASCII whitespace or invisible characters are never stripped
    /// silently — they get their own, specific error.
    InvisibleCharacters,
}

/// Split pasted multi-line input, strip ASCII whitespace (space, tab, CR,
/// LF) from both ends of each line, drop empty lines.
/// Unicode general category Cf (format characters), complete range
/// table for Unicode 15.0 — 170 code points. Includes the bidi
/// controls (U+202A–U+202E, U+2066–U+2069), zero-width characters
/// (U+200B–U+200F, U+2060, U+FEFF), soft hyphen (U+00AD), the
/// Arabic letter marks, tag characters (U+E0001, U+E0020–U+E007F)
/// and the rest. These characters are invisible or reorder the
/// text around them, so user-supplied text that other people will
/// READ — listing text, terms, reviews, profiles — must not carry
/// them: what the reader sees must be what the bytes say
/// (Modules Audit BL3, 2026-10-19).
pub const FORMAT_CHAR_RANGES: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

/// True iff `ch` is a Unicode format character (category Cf).
pub fn is_format_char(ch: char) -> bool {
    let cp = ch as u32;
    FORMAT_CHAR_RANGES.iter().any(|&(lo, hi)| cp >= lo && cp <= hi)
}

/// True iff `s` contains any Unicode format character (category Cf).
pub fn contains_format_chars(s: &str) -> bool {
    s.chars().any(is_format_char)
}

pub fn normalize_form_lines(input: &str) -> Result<Vec<String>, FormInputError> {
    // Reject invisibles up front: NBSP, zero-width space, BOM, etc. are any
    // non-ASCII whitespace or format characters (all of category Cf —
    // BL3 made this check match the claim; it previously named only
    // four format characters). Ordinary non-ASCII letters are left
    // for downstream validators to reject on their own terms.
    for ch in input.chars() {
        if (ch.is_whitespace() && !ch.is_ascii_whitespace()) || is_format_char(ch) {
            return Err(FormInputError::InvisibleCharacters);
        }
    }
    Ok(input
        .lines()
        .map(|l| l.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\r')))
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

// ---------------------------------------------------------------------------
// Envelope error taxonomy (Q16, as amended 2026-10-13). Ordered: the first
// failure in this list wins. There is deliberately no registered-vs-unknown
// recipient distinction (membership oracle).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Empty submission (caught at the form layer).
    Empty,
    /// Not an encrypted OpenPGP message at all. The plaintext is never
    /// echoed back into a form and never logged.
    NotEncrypted,
    /// OpenPGP, but structurally invalid.
    Malformed,
    /// SKESK, literal data, legacy SED, or an unknown packet tag.
    UnsupportedPacket,
    /// A wildcard (hidden) recipient key ID is present.
    HiddenRecipient,
    /// A PKESK matches a recipient key that was current in THIS
    /// conversation and has since rotated. Never returned for keys the
    /// sender was not already shown (leak fix, 2026-10-13) — that case is
    /// `WrongRecipient`.
    RecipientKeyRetired,
    /// No PKESK matches the recipient's current key.
    WrongRecipient,
    /// The recipient matched, but another PKESK belongs to neither party.
    /// The UI shows the offending key ID only, never an owner.
    ExtraRecipient,
}

// ---------------------------------------------------------------------------
// Module system (spec §4). Modules propose; the core verifies and commits.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModuleId(pub &'static str);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    MoneroVerifyRpc,
    // Future capabilities are added here, never as strings.
}

pub trait Module {
    fn id(&self) -> ModuleId;
    fn version(&self) -> semver::Version;
    fn capabilities(&self) -> &[Capability];
}

/// Closed, core-owned destination evidence (spec §4 rule 2).
pub enum DestinationEvidence {
    SignedInvoice {
        statement: Vec<u8>,
        signature: Vec<u8>,
    },
    SignedPoolEntry {
        pool_id: String,
        index: u32,
    },
}

pub struct DestinationProposal {
    pub address: Subaddress,
    pub evidence: DestinationEvidence,
}

pub trait DestinationProvider: Module {
    fn allocate(&self, cx: &AllocateCx) -> Result<DestinationProposal, ModuleError>;
}

pub struct AllocateCx {
    pub seller_id: String,
    pub network: Network,
}

/// Closed, core-owned payment evidence claims (spec §4).
pub enum EvidenceClaim {
    BuyerReport,
    SellerAttestation { amount_atomic: Option<u64> },
    TxProof { txid: [u8; 32], proof: String },
    /// The one claim the core cannot re-check; its module is off by default
    /// and needs operator enablement + seller opt-in (spec §5/§12).
    WalletObservation {
        amount_atomic: u64,
        confirmations: u64,
    },
}

pub trait PaymentEvidenceProvider: Module {
    fn claim(&self, cx: &EvidenceCx, input: &FormInput) -> Result<EvidenceClaim, ModuleError>;
}

pub struct EvidenceCx {
    pub invoice_id: String,
    pub order_id: String,
}

pub trait ReputationModel: Module {
    fn summarize(&self, facts: &[ReputationFact]) -> ReputationSummary;
}

/// The minimized facts the core produces per terminal order (spec §13).
/// The ONLY input a reputation model ever receives.
pub struct ReputationFact {
    pub seller_id: String,
    pub buyer_token: [u8; 32],
    pub maturity_bucket: u8,
    pub evidence_level: u8,
    pub outcome: u8,
    pub score: Option<u8>,
    pub month: String, // YYYY-MM
}

pub struct ReputationSummary {
    pub weighted_score: Option<f64>,
    pub established_buyers: u64,
    pub total_weight: f64,
}

pub trait PricingSource: Module {
    fn quote(&self, cx: &QuoteCx) -> Result<u64, ModuleError>; // atomic units
}

pub struct QuoteCx {
    pub listing_id: String,
    pub quantity: u32,
}

pub trait AdmissionPolicy: Module {
    fn admit(&self, cx: &AdmissionCx, input: &FormInput) -> Result<Admission, ModuleError>;
}

pub struct AdmissionCx {
    pub username: String,
    /// Core-supplied facts (the module decides; the core counts).
    pub registrations_open: bool,
    pub account_count: u64,
    pub account_cap: Option<u64>,
}

pub enum Admission {
    Admitted,
    PendingApproval,
    Rejected,
}

pub trait NotificationChannel: Module {
    fn deliver(&self, cx: &NotifyCx, n: &Notification) -> Result<(), ModuleError>;
}

pub struct NotifyCx {
    pub account_id: String,
}

pub struct Notification {
    pub event_type: String,
    pub object_ref: String,
}

/// Minimal opaque form input handed to modules (never raw request bodies,
/// session tokens, or message payloads — spec §3 invariant 17).
pub struct FormInput {
    pub fields: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct ModuleError(pub String);

impl fmt::Display for ModuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "module error: {}", self.0)
    }
}
impl std::error::Error for ModuleError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subaddress_newtype_enforces_rules() {
        // Docs fixture: stagenet subaddress from the official wallet RPC docs.
        let docs = "7BnERTpvL5MbCLtj5n9No7J5oE5hHiB3tVCK5cjSvCsYWD2WRJLFuWeKTLiXo5QJqt2ZwUaLy2Vh1Ad51K7FNgqcHgjW85o";
        assert!(Subaddress::validate(docs, Network::Stagenet).is_ok());
        assert_eq!(
            Subaddress::validate(docs, Network::Mainnet),
            Err(DestinationError::WrongNetwork)
        );
        assert_eq!(
            Subaddress::validate("garbage", Network::Mainnet),
            Err(DestinationError::Parse)
        );
    }

    #[test]
    fn network_statement_names_round_trip() {
        // Added in the stage-gate retrofit (2026-10-14): the first
        // cargo-mutants run found these conversions untested — every
        // mutant of statement_name/from_statement_name survived.
        for (network, name) in [
            (Network::Mainnet, "monero-mainnet"),
            (Network::Stagenet, "monero-stagenet"),
            (Network::Testnet, "monero-testnet"),
        ] {
            assert_eq!(network.statement_name(), name);
            assert_eq!(Network::from_statement_name(name), Some(network));
            // Q17: the name carried on a success type is exactly the
            // canonical statement name, never a free-form string.
            let converted: monero::Network = network.into();
            assert_eq!(Network::from(converted), network);
        }
        assert_eq!(Network::from_statement_name("monero-devnet"), None);
        assert_eq!(Network::from_statement_name(""), None);
    }

    #[test]
    fn subaddress_rendering_round_trips() {
        // Retrofit addition (2026-10-14): as_str/Display mutants survived
        // the first mutants run because nothing asserted the rendering.
        let docs = "7BnERTpvL5MbCLtj5n9No7J5oE5hHiB3tVCK5cjSvCsYWD2WRJLFuWeKTLiXo5QJqt2ZwUaLy2Vh1Ad51K7FNgqcHgjW85o";
        let addr = Subaddress::validate(docs, Network::Stagenet).unwrap();
        assert_eq!(addr.as_str(), docs);
        assert_eq!(format!("{addr}"), docs);
        assert_eq!(addr.network(), Network::Stagenet);
    }

    #[test]
    fn standard_address_validation_for_payment_identity() {
        // Stagenet primary + subaddress fixtures (wallet RPC docs family /
        // Stage 6 fixture wallet).
        let primary = "55b6gZhKJ2b6EzvernZJBcPXiZym13w1CfbpDU6sR8aSGpaRbAmU4EMSH3XYXu5U1cSac7B49WRSSBbwQK9by3c7H9AdnFB";
        let sub = "7B2BSyZukau1TerLFtd6UtDvgz7YZVKGmV9xNowvh74biBFvjXTcWAu8EMJ1ot7sCHHCXrg6QRTHgNfoGsQRRj3xRqNnPFd";
        let integrated = "5FHmhNWouJ76EzvernZJBcPXiZym13w1CfbpDU6sR8aSGpaRbAmU4EMSH3XYXu5U1cSac7B49WRSSBbwQK9by3c7R3PDbmJGUNm7bwo6K9";
        assert_eq!(
            validate_standard_address(primary, Network::Stagenet).unwrap(),
            primary
        );
        assert_eq!(
            validate_standard_address(primary, Network::Mainnet),
            Err(DestinationError::WrongNetwork)
        );
        assert_eq!(
            validate_standard_address(sub, Network::Stagenet),
            Err(DestinationError::WrongKind { found: AddressKind::Subaddress })
        );
        assert_eq!(
            validate_standard_address(integrated, Network::Stagenet),
            Err(DestinationError::WrongKind { found: AddressKind::Integrated })
        );
        assert_eq!(
            validate_standard_address("garbage", Network::Stagenet),
            Err(DestinationError::Parse)
        );
        // Never trims: whitespace-wrapped input is rejected.
        assert!(validate_standard_address(&format!(" {primary} "), Network::Stagenet).is_err());
    }

    #[test]
    fn module_error_display_carries_the_message() {
        // Retrofit addition (2026-10-14): Display mutant survived.
        assert_eq!(
            format!("{}", ModuleError("boom".to_string())),
            "module error: boom"
        );
    }

    #[test]
    fn public_id_patterns() {
        assert!(validate_public_id("inv_0123456789abcdef0123456789abcdef", "inv_"));
        assert!(!validate_public_id("inv_8d1e5b0c3a7f", "inv_")); // old 48-bit example
        assert!(!validate_public_id("inv_0123456789ABCDEF0123456789abcdef", "inv_"));
        assert!(!validate_public_id("ord_0123456789abcdef0123456789abcdef", "inv_"));
    }

    #[test]
    fn canonical_integers() {
        assert_eq!(parse_canonical_u64("0"), Some(0));
        assert_eq!(parse_canonical_u64("1250000000000"), Some(1250000000000));
        assert_eq!(parse_canonical_u64("007"), None);
        assert_eq!(parse_canonical_u64("+7"), None);
        assert_eq!(parse_canonical_u64(" 7"), None);
        assert_eq!(parse_canonical_u64(""), None);
        assert_eq!(parse_canonical_u64("99999999999999999999999999"), None);
    }

    #[test]
    fn form_lines_trim_once_and_reject_invisibles() {
        let out = normalize_form_lines("  abc \r\ndef\r\n\r\n ghi\t\n").unwrap();
        assert_eq!(out, vec!["abc", "def", "ghi"]);
        assert_eq!(
            normalize_form_lines("ab\u{200B}c"),
            Err(FormInputError::InvisibleCharacters)
        );
        assert_eq!(
            normalize_form_lines("a\u{00A0}b"),
            Err(FormInputError::InvisibleCharacters)
        );
    }
}
