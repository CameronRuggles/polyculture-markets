//! domain — state machines, money, and canonical statements (spec §9, §10).
//! Only the core changes v1 order/invoice state, and only through these
//! transition tables (spec §3 invariant 10, v1 scope). Hidden Trades state
//! is computed by the helpers from signed statements with the shared fold
//! in this crate (the amended invariant (10), scoped to Hidden Trades —
//! see docs/invariants.md, Scope paragraph, owner decision Q4 2026-10-21).

pub mod ht_fold;
pub mod ht_statements;
pub mod markup;
pub mod statements;

use modules_api::Network;

// ---------------------------------------------------------------------------
// Money: u64 atomic units only. No floating point anywhere (spec §9).

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Atomic(pub u64);

impl Atomic {
    /// Parse a decimal XMR string: at most 12 decimal places, digits and at
    /// most one '.', no sign/exponent — via integer arithmetic only.
    pub fn parse_decimal(s: &str) -> Option<Atomic> {
        if s.is_empty() || s.starts_with('.') || s.ends_with('.') {
            return None;
        }
        let (whole, frac) = match s.split_once('.') {
            Some((w, f)) => (w, f),
            None => (s, ""),
        };
        if whole.is_empty()
            || !whole.bytes().all(|b| b.is_ascii_digit())
            || !frac.bytes().all(|b| b.is_ascii_digit())
            || frac.len() > 12
        {
            return None;
        }
        let whole: u64 = whole.parse().ok()?;
        let mut frac_val: u64 = if frac.is_empty() { 0 } else { frac.parse().ok()? };
        for _ in frac.len()..12 {
            frac_val *= 10;
        }
        whole
            .checked_mul(1_000_000_000_000)?
            .checked_add(frac_val)
            .map(Atomic)
    }

    pub fn format_decimal(&self) -> String {
        let whole = self.0 / 1_000_000_000_000;
        let frac = self.0 % 1_000_000_000_000;
        if frac == 0 {
            format!("{whole}")
        } else {
            let mut f = format!("{frac:012}");
            while f.ends_with('0') {
                f.pop();
            }
            format!("{whole}.{f}")
        }
    }
}

// ---------------------------------------------------------------------------
// Pricing (spec §11): `xmr-only` is the sole pricing mode until Stage 11.
// The total is unit price × quantity in checked u64 arithmetic — None on
// overflow, never a wrap. (Quantity ≥ 1 is the order layer's rule.)

pub const PRICING_MODULE_XMR_ONLY: &str = "xmr-only";

pub fn xmr_only_total(unit_price_atomic: u64, quantity: u64) -> Option<u64> {
    unit_price_atomic.checked_mul(quantity)
}

// ---------------------------------------------------------------------------
// Order state machine (spec §9). Terminal: Declined, Cancelled, Completed,
// Resolved. `settlement` (Q9): always Direct in v2; the enum leaves room
// for a future escrow variant without rewriting the machine.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settlement {
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderState {
    Requested,
    AwaitingPayment,
    Paid,
    Fulfilled,
    Completed,
    Disputed,
    Declined,
    Cancelled,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    Buyer,
    Seller,
    Core,
    Moderator,
}

/// Payment evidence strength (spec §9/§12). Only the core raises it.
/// A buyer's bare report (BuyerReported) can never move an order to
/// Paid (invariant 11). A buyer-submitted transaction proof
/// (BuyerProofSubmitted) can — owner decision 2026-10-18: the proof is
/// evidence attached to the claim, carried by the server UNVERIFIED
/// (the server runs no wallet and never labels it verified); sellers
/// and moderators check it in their own wallets. SellerAttested,
/// ProofVerified, and WalletObserved retain their places above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceLevel {
    None,
    BuyerReported,
    BuyerProofSubmitted,
    SellerAttested,
    ProofVerified,
    WalletObserved,
}

pub fn order_can_transition(
    from: OrderState,
    to: OrderState,
    actor: Actor,
    evidence: EvidenceLevel,
) -> bool {
    use Actor::*;
    use OrderState::*;
    match (from, to) {
        (Requested, AwaitingPayment) => matches!(actor, Core | Seller),
        (Requested, Declined) => actor == Seller,
        (Requested, Cancelled) => actor == Buyer,
        // The Paid transition is the money-critical guard of the whole
        // design: Core only, and never on a buyer's word alone.
        (AwaitingPayment, Paid) => {
            actor == Core
                && matches!(
                    evidence,
                    EvidenceLevel::BuyerProofSubmitted
                        | EvidenceLevel::SellerAttested
                        | EvidenceLevel::ProofVerified
                        | EvidenceLevel::WalletObserved
                )
        }
        (AwaitingPayment, Cancelled) => {
            matches!(actor, Buyer | Seller) && evidence == EvidenceLevel::None
        }
        (AwaitingPayment, Disputed) => {
            // §9 guard: the buyer reported payment. The pure table can
            // enforce the report's existence via the evidence level; the
            // 72-hour timing is enforced at the app layer, which owns
            // the claim timestamps. (Stage 4 gate fix: the blind suite
            // showed this row ignored the evidence parameter entirely,
            // unlike the Paid and Cancelled rows.) For direct-v1 orders
            // a submitted tx proof (BuyerProofSubmitted, owner decision
            // 2026-10-18) stands in the same place: a report exists, so
            // the buyer may dispute; the app layer gates on the report
            // row itself.
            actor == Buyer
                && matches!(
                    evidence,
                    EvidenceLevel::BuyerReported | EvidenceLevel::BuyerProofSubmitted
                )
        }
        (Paid, Fulfilled) => actor == Seller,
        (Paid, Disputed) => matches!(actor, Buyer | Seller),
        (Fulfilled, Completed) => matches!(actor, Buyer | Core),
        (Fulfilled, Disputed) => actor == Buyer,
        (Disputed, Resolved) => actor == Moderator,
        (Disputed, Completed) => actor == Buyer,
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceState {
    Issued,
    Settled,
    Expired,
    Superseded,
    Cancelled,
}

pub fn invoice_can_transition(from: InvoiceState, to: InvoiceState) -> bool {
    use InvoiceState::*;
    matches!(
        (from, to),
        (Issued, Settled) | (Issued, Expired) | (Issued, Superseded) | (Issued, Cancelled)
    )
}

// ---------------------------------------------------------------------------
// Canonical timestamps (Q4-S3): parse with the `time` crate's RFC 3339
// parser, reject leap seconds, re-format canonically.

pub fn validate_canonical_timestamp(s: &str) -> bool {
    if s.len() != 20 || !s.ends_with('Z') || s.contains(":60") {
        return false; // shape + leap-second rejection before parsing
    }
    let Ok(dt) = time::OffsetDateTime::parse(
        s,
        &time::format_description::well_known::Rfc3339,
    ) else {
        return false;
    };
    let format = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
    );
    dt.format(&format).map(|out| out == s).unwrap_or(false)
}

/// Canonical calendar date `YYYY-MM-DD` (Alpha spec §5: the `date` /
/// `month` fields of the Hidden Trades statements): exactly 10 bytes,
/// a real calendar date, byte-identical on re-format. No trimming.
pub fn validate_canonical_date(s: &str) -> bool {
    parse_canonical_date(s).is_some()
}

/// The parsed form of [`validate_canonical_date`].
pub fn parse_canonical_date(s: &str) -> Option<time::Date> {
    if s.len() != 10 {
        return None;
    }
    let format = time::macros::format_description!("[year]-[month]-[day]");
    let d = time::Date::parse(s, &format).ok()?;
    (d.format(&format).ok()? == s).then_some(d)
}

/// `date + days`, re-rendered canonically; `None` when the input is
/// not a canonical date or the addition overflows the calendar.
pub fn date_add_days(s: &str, days: u32) -> Option<String> {
    let d = parse_canonical_date(s)?.checked_add(time::Duration::days(i64::from(days)))?;
    let format = time::macros::format_description!("[year]-[month]-[day]");
    d.format(&format).ok()
}

/// Canonical month `YYYY-MM` (Alpha spec §5: settle / receipt / vouch
/// statements): exactly 7 bytes, month 01–12, byte-identical on
/// re-format.
pub fn validate_canonical_month(s: &str) -> bool {
    if s.len() != 7 || s.as_bytes().get(4) != Some(&b'-') {
        return false;
    }
    let (year, month) = s.split_at(4);
    let month = &month[1..];
    if !year.bytes().all(|b| b.is_ascii_digit()) || !month.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Ok(month) = month.parse::<u8>() else {
        return false;
    };
    (1..=12).contains(&month)
}

// ---------------------------------------------------------------------------
// Statement network agreement (Q4-S4 + core rule): a statement's network
// must equal the instance's configured network.

pub fn statement_network_matches(statement_network: &str, instance: Network) -> bool {
    Network::from_statement_name(statement_network) == Some(instance)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn money_is_exact() {
        assert_eq!(Atomic::parse_decimal("1.25"), Some(Atomic(1_250_000_000_000)));
        assert_eq!(Atomic::parse_decimal("0.000000000001"), Some(Atomic(1)));
        assert_eq!(Atomic::parse_decimal("0.0000000000001"), None); // 13 dp
        assert_eq!(Atomic::parse_decimal("1."), None);
        assert_eq!(Atomic::parse_decimal(".5"), None);
        assert_eq!(Atomic::parse_decimal("-1"), None);
        assert_eq!(Atomic(1_250_000_000_000).format_decimal(), "1.25");
        assert_eq!(Atomic(1).format_decimal(), "0.000000000001");
        assert_eq!(Atomic(2_000_000_000_000).format_decimal(), "2");
    }

    #[test]
    fn xmr_only_pricing_is_checked() {
        assert_eq!(PRICING_MODULE_XMR_ONLY, "xmr-only");
        assert_eq!(xmr_only_total(1_250_000_000_000, 3), Some(3_750_000_000_000));
        assert_eq!(xmr_only_total(0, 5), Some(0));
        assert_eq!(xmr_only_total(123, 0), Some(0));
        assert_eq!(xmr_only_total(u64::MAX, 2), None); // overflow, never wraps
        assert_eq!(xmr_only_total(u64::MAX / 2, 2), Some(u64::MAX - 1));
    }

    #[test]
    fn buyer_report_never_reaches_paid() {
        use Actor::*;
        use OrderState::*;
        for ev in [EvidenceLevel::None, EvidenceLevel::BuyerReported] {
            assert!(!order_can_transition(AwaitingPayment, Paid, Core, ev));
            assert!(!order_can_transition(AwaitingPayment, Paid, Buyer, ev));
        }
        for ev in [
            EvidenceLevel::SellerAttested,
            EvidenceLevel::ProofVerified,
            EvidenceLevel::WalletObserved,
        ] {
            assert!(order_can_transition(AwaitingPayment, Paid, Core, ev));
            // Only the core performs the transition, even with good evidence.
            assert!(!order_can_transition(AwaitingPayment, Paid, Seller, ev));
        }
    }

    #[test]
    fn buyer_proof_submission_reaches_paid_via_core_only() {
        use Actor::*;
        use OrderState::*;
        // Owner decision 2026-10-18: a submitted tx proof is evidence,
        // not a bare report — the core may mark Paid on it; no other
        // actor may, and the level also satisfies the dispute row.
        assert!(order_can_transition(
            AwaitingPayment,
            Paid,
            Core,
            EvidenceLevel::BuyerProofSubmitted
        ));
        assert!(!order_can_transition(
            AwaitingPayment,
            Paid,
            Buyer,
            EvidenceLevel::BuyerProofSubmitted
        ));
        assert!(!order_can_transition(
            AwaitingPayment,
            Paid,
            Seller,
            EvidenceLevel::BuyerProofSubmitted
        ));
        assert!(order_can_transition(
            AwaitingPayment,
            Disputed,
            Buyer,
            EvidenceLevel::BuyerProofSubmitted
        ));
        // The ordering keeps a proof below an attestation.
        assert!(EvidenceLevel::BuyerReported < EvidenceLevel::BuyerProofSubmitted);
        assert!(EvidenceLevel::BuyerProofSubmitted < EvidenceLevel::SellerAttested);
    }

    #[test]
    fn state_table_spot_checks() {
        use Actor::*;
        use OrderState::*;
        assert!(order_can_transition(Requested, Declined, Seller, EvidenceLevel::None));
        assert!(!order_can_transition(Requested, Declined, Buyer, EvidenceLevel::None));
        assert!(order_can_transition(Disputed, Resolved, Moderator, EvidenceLevel::None));
        assert!(!order_can_transition(Completed, Disputed, Buyer, EvidenceLevel::None));
        assert!(!order_can_transition(Paid, Completed, Buyer, EvidenceLevel::None));
    }

    #[test]
    fn timestamps_semantic() {
        assert!(validate_canonical_timestamp("2026-10-16T17:00:00Z"));
        assert!(!validate_canonical_timestamp("2026-13-16T17:00:00Z")); // month 13
        assert!(!validate_canonical_timestamp("2026-02-30T17:00:00Z")); // Feb 30
        assert!(!validate_canonical_timestamp("2026-10-16T17:00:60Z")); // leap second
        assert!(!validate_canonical_timestamp("2026-10-16 17:00:00Z")); // space, not T
        assert!(!validate_canonical_timestamp("2026-10-16T17:00:00+00:00"));
    }
}
