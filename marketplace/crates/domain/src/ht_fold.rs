//! The trade fold (Alpha build spec §6): a trade's state is a pure
//! function of the statements the parties hold plus the buyer's
//! payment record — no server-side order record exists. This is the
//! ONE implementation of that function: the helper's seller and
//! buyer modes fold with it, and the moderator view (H3) will replay
//! disclosed statements through the same code.
//!
//! Rules (§6):
//! - The assignment opens the trade. The fold runs over the
//!   statements a party HOLDS for the trade (their evidence store);
//!   statements enter a store only after their signatures check
//!   against the pinned keys, so the fold itself does not re-check
//!   signers — with one structural exception: a receipt names both
//!   parties, and only a receipt naming the assignment's own buyer
//!   and seller closes the trade.
//! - Payment is shown by the buyer's payment record OR the seller's
//!   ack — either is enough (§6 rule 1).
//! - The issue path runs from Shipped, inside the 30-day issue
//!   window. The window is governed by RECEIPT time (owner decision
//!   Q2, 2026-10-21; audit F6): when the holder recorded when the
//!   counterparty's statement arrived in the conversation, that
//!   witnessed date — not the date the signer wrote into the
//!   statement — starts the window, and an issue counts only if
//!   its own receipt date falls inside it. A signer can backdate
//!   their own `date` field; they cannot backdate a receipt. Where
//!   no receipt time is recorded for a statement, the fold falls
//!   back to that statement's signed date (see `fold_trade_timed`).
//! - `Settled` and `Closed` are terminal: the fold ignores every
//!   later statement (rule 4).
//! - Two DIFFERENT complete settles are a conflict, not a race
//!   (owner rule, Cameron 2026-10-21; close-out delta D3): a
//!   settle is a jointly signed statement of final terms, and
//!   renegotiation can produce two incompatible ones. The rule
//!   is presence-based — if two or more distinct settles each
//!   pass `check_settle`, the trade is `Conflicted` (terminal,
//!   no agreed refund) whatever order they were held in. A
//!   duplicated identical settle is one settle; an over-amount
//!   settle is not complete and cannot create a conflict.
//! - `Lapsed` is derived, never signed: the assignment's expiry
//!   passes with neither payment nor a shipped statement held.
//! - `payment_overdue` is derived, never signed (audit F18): an
//!   on_receipt trade that has shipped and is still unpaid once
//!   the assignment's `expires-at` passes is flagged, so silent
//!   non-payment is visible in status instead of invisible.

use crate::date_add_days;
use crate::ht_statements::{
    AckStatement, AssignmentStatement, IssueStatement, PaymentTiming, ReceiptStatement,
    SettleStatement, ShippedDirection, ShippedStatement,
};

/// The buyer's payment record: the txid plus the OutProofV2 string
/// over `marketplace-pay-v1|<trade-id>` (§5/§6 rule 1). The fold
/// takes the record's presence as the payment leg; proof FORM is
/// checked by the helper when the record is made (§14), and proof
/// truth by whoever verifies it against a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentRecord {
    pub txid: String,
    pub proof: String,
}

/// One held input to the fold, in the order it was held (statements
/// travel in conversation order, so both parties fold the same
/// sequence; the moderator replays in disclosure order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TradeEvent {
    Assignment(AssignmentStatement),
    Ack(AckStatement),
    Shipped(ShippedStatement),
    Issue(IssueStatement),
    Settle(SettleStatement),
    Receipt(ReceiptStatement),
    Payment(PaymentRecord),
}

/// A held event plus the witnessed time it was RECEIVED in the
/// conversation, when the holder recorded one (owner decision Q2,
/// 2026-10-21; audit F6). `received_at` is a canonical timestamp
/// (`YYYY-MM-DDTHH:MM:SSZ`); only its date part governs the fold.
/// It is evidence the holder keeps next to the statement in the
/// trade folder — never part of the signed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedEvent {
    pub event: TradeEvent,
    pub received_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TradeState {
    Assigned,
    Paid,
    Shipped,
    IssueRaised,
    Settled,
    Closed,
    Lapsed,
    /// Two or more DIFFERENT complete settles are held for the
    /// trade: the parties signed incompatible final terms and
    /// the fold will not pick one by arrival order — the trade
    /// is in dispute (owner rule, Cameron 2026-10-21). Terminal:
    /// no held statement resolves it; only the parties, or a
    /// moderator replaying disclosed statements (§9), can.
    Conflicted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedTrade {
    pub state: TradeState,
    /// A terminal state (`Settled` / `Closed` / `Conflicted`)
    /// was reached; the outcome is final (rule 4).
    pub terminal: bool,
    pub paid: bool,
    pub shipped: bool,
    /// The agreed refund of the closing settle, when settled.
    pub refund_atomic: Option<u64>,
    /// Last day of the 30-day issue window, once shipped
    /// (`shipped date + 30 days`, §6). The shipped date is the
    /// receipt date when one was recorded, else the shipped
    /// statement's signed date.
    pub issue_window_ends: Option<String>,
    /// The trade's terms are pay-on-receipt, the goods shipped,
    /// no payment is held, and the assignment's `expires-at` has
    /// passed: the buyer's payment is overdue (audit F18, owner
    /// decision Q2). Derived, never signed; terminal states
    /// report `false` (their outcome supersedes the flag).
    pub payment_overdue: bool,
}

/// A settle closes a trade only when its refund does not exceed the
/// assignment's amount (§6: settle "closes the trade with an agreed
/// refund", possibly zero — never more than the price).
pub fn check_settle(assignment: &AssignmentStatement, settle: &SettleStatement) -> bool {
    settle.refund_atomic <= assignment.amount_atomic
}

/// The date a statement governs by: its RECEIPT date when the
/// holder recorded one (and it is a valid canonical timestamp),
/// else the date the signer wrote into the statement. Returns the
/// effective date and whether it came from a receipt record.
fn effective_date(received_at: Option<&str>, signer_date: &str) -> (String, bool) {
    if let Some(ts) = received_at {
        if let Some(date) = ts.get(..10) {
            if crate::validate_canonical_date(date) {
                return (date.to_string(), true);
            }
        }
    }
    (signer_date.to_string(), false)
}

/// Fold `events` (in held order) into the trade's state. `now` is a
/// canonical timestamp used only for the derived `Lapsed` state.
/// Returns `None` when no assignment is held — there is no trade.
///
/// This is the un-timed fold: no receipt times are recorded, so
/// every statement governs by its signed date. It delegates to
/// [`fold_trade_timed`] so the two can never disagree.
pub fn fold_trade(events: &[TradeEvent], now: &str) -> Option<FoldedTrade> {
    let timed: Vec<TimedEvent> = events
        .iter()
        .cloned()
        .map(|event| TimedEvent { event, received_at: None })
        .collect();
    fold_trade_timed(&timed, now)
}

/// Fold held events with their witnessed receipt times (owner
/// decision Q2, 2026-10-21).
///
/// The issue window runs from the shipped statement's EFFECTIVE
/// date (receipt date when recorded, else its signed date) for 30
/// days, and an issue counts only when its own effective date
/// falls inside. When BOTH the shipped and the issue carry receipt
/// times, the window also has a lower bound — an issue received
/// before the shipment was received cannot raise: both receipt
/// times are witnessed by the same conversation record, so their
/// order is evidence, unlike either party's signed dates. With a
/// receipt on only one side, no lower bound is applied (the two
/// clocks are not comparable) and the signed date stands in for
/// the un-witnessed side.
pub fn fold_trade_timed(events: &[TimedEvent], now: &str) -> Option<FoldedTrade> {
    let assignment = events.iter().find_map(|t| match &t.event {
        TradeEvent::Assignment(a) => Some(a),
        _ => None,
    })?;

    // Owner rule (Cameron, 2026-10-21; close-out delta D3): count
    // the DISTINCT complete settles in the whole held set before
    // the walk. Two or more means the parties signed incompatible
    // final terms — a conflict the fold surfaces identically in
    // either held order, never a winner picked by arrival order.
    // Identical duplicates count once; a settle failing
    // `check_settle` is not complete and cannot conflict.
    let mut distinct_settles: Vec<&SettleStatement> = Vec::new();
    for timed in events {
        if let TradeEvent::Settle(settle) = &timed.event {
            if check_settle(assignment, settle) && !distinct_settles.contains(&settle) {
                distinct_settles.push(settle);
            }
        }
    }
    let conflicted = distinct_settles.len() >= 2;

    let mut paid = false;
    let mut shipped = false;
    // The shipped statement's effective date, and whether it came
    // from a receipt record.
    let mut shipped_effective: Option<(String, bool)> = None;
    let mut last_milestone: Option<TradeState> = None;
    let mut issue_raised = false;
    let mut terminal: Option<(TradeState, Option<u64>)> = None;

    for timed in events {
        if terminal.is_some() {
            break; // Rule 4: terminal states end the fold.
        }
        let event = &timed.event;
        match event {
            TradeEvent::Assignment(_) => {}
            TradeEvent::Payment(_) => {
                if !paid {
                    paid = true;
                    last_milestone = Some(TradeState::Paid);
                }
            }
            TradeEvent::Ack(_ack) => {
                if !paid {
                    paid = true;
                    last_milestone = Some(TradeState::Paid);
                }
            }
            TradeEvent::Shipped(s) => {
                if s.direction == ShippedDirection::Out && !shipped {
                    shipped = true;
                    shipped_effective =
                        Some(effective_date(timed.received_at.as_deref(), &s.date));
                    last_milestone = Some(TradeState::Shipped);
                }
            }
            TradeEvent::Issue(issue) => {
                // The issue path runs from Shipped, inside the
                // window; a signed issue from anyone else, before
                // shipment, or after the window does not move the
                // fold (it remains the signer's statement, and a
                // dispute filed on it is the court's business, §9).
                if let Some((start, shipped_by_receipt)) = &shipped_effective {
                    let (issue_date, issue_by_receipt) =
                        effective_date(timed.received_at.as_deref(), &issue.date);
                    if let Some(end) = date_add_days(start, 30) {
                        // Lower bound only when both sides are
                        // receipt-witnessed (see fn docs).
                        let after_start = !(*shipped_by_receipt && issue_by_receipt)
                            || issue_date.as_str() >= start.as_str();
                        if after_start && issue_date.as_str() <= end.as_str() {
                            issue_raised = true;
                        }
                    }
                }
            }
            TradeEvent::Settle(settle) => {
                // A conflict suppresses every positional terminal
                // (here and in the receipt arm): the walk runs
                // over the full held set so `paid`, `shipped` and
                // the window describe all of it, and the conflict
                // outcome below is identical in either held order.
                if !conflicted && check_settle(assignment, settle) {
                    terminal = Some((TradeState::Settled, Some(settle.refund_atomic)));
                }
            }
            TradeEvent::Receipt(receipt) => {
                if !conflicted
                    && receipt.buyer_key_fingerprint == assignment.buyer_key_fingerprint
                    && receipt.seller_key_fingerprint == assignment.seller_key_fingerprint
                {
                    terminal = Some((TradeState::Closed, None));
                }
            }
        }
    }

    let issue_window_ends = shipped_effective
        .as_ref()
        .and_then(|(d, _)| date_add_days(d, 30));

    if conflicted {
        // No refund is named: the parties agreed two different
        // ones, which is exactly the dispute. Like every terminal
        // state, a conflict supersedes the overdue flag.
        return Some(FoldedTrade {
            state: TradeState::Conflicted,
            terminal: true,
            paid,
            shipped,
            refund_atomic: None,
            issue_window_ends,
            payment_overdue: false,
        });
    }

    if let Some((state, refund)) = terminal {
        return Some(FoldedTrade {
            state,
            terminal: true,
            paid,
            shipped,
            refund_atomic: refund,
            issue_window_ends,
            payment_overdue: false,
        });
    }

    let state = if issue_raised {
        TradeState::IssueRaised
    } else if paid && shipped {
        // Both legs held: the state is the later milestone.
        last_milestone.unwrap_or(TradeState::Shipped)
    } else if paid {
        TradeState::Paid
    } else if shipped {
        TradeState::Shipped
    } else if now > assignment.expires_at.as_str() {
        // Lapsed: expiry passed with neither payment nor shipment.
        TradeState::Lapsed
    } else {
        TradeState::Assigned
    };

    // F18/Q2: pay-on-receipt terms, goods shipped, still unpaid
    // once the assignment's payment date (expires-at) has passed —
    // flag it rather than letting non-payment stay invisible.
    let payment_overdue = assignment.payment_timing == PaymentTiming::OnReceipt
        && shipped
        && !paid
        && now > assignment.expires_at.as_str();

    Some(FoldedTrade {
        state,
        terminal: false,
        paid,
        shipped,
        refund_atomic: None,
        issue_window_ends,
        payment_overdue,
    })
}

// ---------------------------------------------------------------------------
// Tests (fix batch 2026-10-21; the blind_ht1 suite's fold cases are
// unaffected — they replay through `fold_trade`, which delegates here
// with no receipt times and must behave exactly as before).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ht_statements::IssueKind;
    use modules_api::Network;

    const MKT: &str = "mkt_0123456789abcdef0123456789abcdef";
    const SELLER: &str = "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4";
    const BUYER: &str = "0F1E2D3C4B5A69788796A5B4C3D2E1F0A9B8C7D6";
    const SUB: &str =
        "75VjEqDg5fp7hyErNLsyRK59sHRJjLX3fTvARvKvGodj5PPajrWjmyQ2mvuPWWMWi4HNS5jg4jvyYLREvx63KZe4HK7sbH8";
    const TID: &str = "2b0c9a9fcd437374def302d767fb684e89399d137bcd45ac14bf5f734cad0109";

    fn assignment(timing: PaymentTiming, expires_at: &str) -> AssignmentStatement {
        AssignmentStatement {
            marketplace_id: MKT.into(),
            network: Network::Stagenet,
            seller_key_fingerprint: SELLER.into(),
            buyer_key_fingerprint: BUYER.into(),
            terms_statement_sha256: "ab".repeat(32),
            destination: modules_api::Subaddress::validate(SUB, Network::Stagenet)
                .expect("fixture subaddress"),
            amount_atomic: 250_000_000_000,
            payment_timing: timing,
            expires_at: expires_at.into(),
            nonce: "0123456789abcdef0123456789abcdef".into(),
        }
    }

    fn shipped(date: &str) -> ShippedStatement {
        ShippedStatement {
            marketplace_id: MKT.into(),
            trade_id: TID.into(),
            direction: ShippedDirection::Out,
            date: date.into(),
            carrier_commit: "ef".repeat(32),
        }
    }

    fn issue(date: &str) -> IssueStatement {
        IssueStatement {
            marketplace_id: MKT.into(),
            trade_id: TID.into(),
            kind: IssueKind::MissingPart,
            requested_refund_pct: 40,
            date: date.into(),
        }
    }

    fn timed(event: TradeEvent, received_at: Option<&str>) -> TimedEvent {
        TimedEvent { event, received_at: received_at.map(str::to_string) }
    }

    const FAR_FUTURE_EXPIRY: &str = "2027-01-01T00:00:00Z";
    const NOW: &str = "2026-11-15T00:00:00Z";

    /// Q2: a backdated shipped statement (signed 2026-10-01) that
    /// the buyer actually RECEIVED on 2026-10-25 starts the window
    /// at receipt: an issue received 2026-11-20 raises, one received
    /// 2026-11-25 does not — although the issue's signed date would
    /// sit inside the signer-date window in both cases.
    #[test]
    fn receipt_time_governs_the_issue_window() {
        let base = [
            timed(TradeEvent::Assignment(assignment(PaymentTiming::Prepay, FAR_FUTURE_EXPIRY)), None),
            timed(TradeEvent::Shipped(shipped("2026-10-01")), Some("2026-10-25T09:00:00Z")),
        ];
        let mut inside = base.to_vec();
        inside.push(timed(TradeEvent::Issue(issue("2026-10-20")), Some("2026-11-20T09:00:00Z")));
        let folded = fold_trade_timed(&inside, NOW).expect("trade");
        assert_eq!(folded.state, TradeState::IssueRaised);
        assert_eq!(folded.issue_window_ends.as_deref(), Some("2026-11-24"));

        let mut late = base.to_vec();
        late.push(timed(TradeEvent::Issue(issue("2026-10-20")), Some("2026-11-25T09:00:00Z")));
        let folded = fold_trade_timed(&late, NOW).expect("trade");
        assert_eq!(folded.state, TradeState::Shipped, "received after the receipt window: no raise");
    }

    /// Q2 lower bound: an issue RECEIVED before the shipment was
    /// received cannot raise, even when both signed dates sit
    /// inside the signer-date window.
    #[test]
    fn issue_received_before_the_shipment_does_not_raise() {
        let events = vec![
            timed(TradeEvent::Assignment(assignment(PaymentTiming::Prepay, FAR_FUTURE_EXPIRY)), None),
            timed(TradeEvent::Shipped(shipped("2026-10-01")), Some("2026-10-25T09:00:00Z")),
            timed(TradeEvent::Issue(issue("2026-10-20")), Some("2026-10-24T09:00:00Z")),
        ];
        let folded = fold_trade_timed(&events, NOW).expect("trade");
        assert_eq!(folded.state, TradeState::Shipped);
    }

    /// With no receipt times recorded the fold is the pre-Q2 fold:
    /// signed dates govern (blind_ht1's cases replay this path).
    #[test]
    fn untimed_fold_uses_signed_dates() {
        let events = vec![
            TradeEvent::Assignment(assignment(PaymentTiming::Prepay, FAR_FUTURE_EXPIRY)),
            TradeEvent::Shipped(shipped("2026-10-22")),
            TradeEvent::Issue(issue("2026-11-21")),
        ];
        let folded = fold_trade(&events, NOW).expect("trade");
        assert_eq!(folded.state, TradeState::IssueRaised);
        assert_eq!(folded.issue_window_ends.as_deref(), Some("2026-11-21"));

        let events = vec![
            TradeEvent::Assignment(assignment(PaymentTiming::Prepay, FAR_FUTURE_EXPIRY)),
            TradeEvent::Shipped(shipped("2026-10-22")),
            TradeEvent::Issue(issue("2026-11-22")),
        ];
        assert_eq!(fold_trade(&events, NOW).expect("trade").state, TradeState::Shipped);
    }

    /// Mixed evidence: a receipt on the shipped leg only starts the
    /// window at receipt; the issue's signed date is compared
    /// against that window (no lower bound applies).
    #[test]
    fn receipt_on_one_side_still_starts_the_window() {
        let events = vec![
            timed(TradeEvent::Assignment(assignment(PaymentTiming::Prepay, FAR_FUTURE_EXPIRY)), None),
            timed(TradeEvent::Shipped(shipped("2026-10-01")), Some("2026-10-25T09:00:00Z")),
            timed(TradeEvent::Issue(issue("2026-11-10")), None),
        ];
        let folded = fold_trade_timed(&events, NOW).expect("trade");
        assert_eq!(folded.state, TradeState::IssueRaised);
        assert_eq!(folded.issue_window_ends.as_deref(), Some("2026-11-24"));
    }

    /// F18/Q2: on_receipt + shipped + unpaid + past the
    /// assignment's payment date ⇒ overdue; every other shape ⇒ no
    /// flag.
    #[test]
    fn on_receipt_overdue_flag() {
        let mk = |timing: PaymentTiming| {
            vec![
                TradeEvent::Assignment(assignment(timing, "2026-11-01T00:00:00Z")),
                TradeEvent::Shipped(shipped("2026-10-22")),
            ]
        };
        let folded = fold_trade(&mk(PaymentTiming::OnReceipt), "2026-11-02T00:00:00Z").expect("trade");
        assert!(folded.payment_overdue, "unpaid on_receipt past the payment date flags");
        assert_eq!(folded.state, TradeState::Shipped);

        // Not yet past the payment date.
        let folded = fold_trade(&mk(PaymentTiming::OnReceipt), "2026-10-31T00:00:00Z").expect("trade");
        assert!(!folded.payment_overdue);
        // Prepay terms never flag (their expiry path is Lapsed).
        let folded = fold_trade(&mk(PaymentTiming::Prepay), "2026-11-02T00:00:00Z").expect("trade");
        assert!(!folded.payment_overdue);
        // Paid: no flag.
        let mut ev = mk(PaymentTiming::OnReceipt);
        ev.push(TradeEvent::Payment(PaymentRecord { txid: "aa".into(), proof: "x".into() }));
        let folded = fold_trade(&ev, "2026-11-02T00:00:00Z").expect("trade");
        assert!(!folded.payment_overdue && folded.paid);
        // Not shipped: the trade lapses instead of flagging.
        let ev = vec![TradeEvent::Assignment(assignment(PaymentTiming::OnReceipt, "2026-11-01T00:00:00Z"))];
        let folded = fold_trade(&ev, "2026-11-02T00:00:00Z").expect("trade");
        assert!(!folded.payment_overdue);
        assert_eq!(folded.state, TradeState::Lapsed);
    }

    fn settle(refund_atomic: u64, return_required: bool) -> SettleStatement {
        SettleStatement {
            marketplace_id: MKT.into(),
            trade_id: TID.into(),
            refund_atomic,
            return_required,
            month: "2026-11".into(),
        }
    }

    /// D3 (owner rule, Cameron 2026-10-21): two DIFFERENT complete
    /// settles are a conflict in either held order — the auditor's
    /// probe made permanent. The whole folded outcome, not just
    /// the state, must be identical across orders (paid/shipped
    /// are computed over the full held set, not a prefix).
    #[test]
    fn two_distinct_complete_settles_conflict_in_either_order() {
        let a = settle(100_000_000_000, false);
        let b = settle(50_000_000_000, true);
        let mk = |first: SettleStatement, second: SettleStatement| {
            vec![
                TradeEvent::Assignment(assignment(PaymentTiming::Prepay, FAR_FUTURE_EXPIRY)),
                TradeEvent::Payment(PaymentRecord { txid: "aa".into(), proof: "x".into() }),
                TradeEvent::Shipped(shipped("2026-10-22")),
                TradeEvent::Settle(first),
                TradeEvent::Settle(second),
            ]
        };
        let ab = fold_trade(&mk(a.clone(), b.clone()), NOW).expect("trade");
        let ba = fold_trade(&mk(b, a), NOW).expect("trade");
        assert_eq!(ab, ba, "the folded outcome must not depend on held order");
        assert_eq!(ab.state, TradeState::Conflicted);
        assert!(ab.terminal);
        assert_eq!(ab.refund_atomic, None, "a conflict names no agreed refund");
        assert!(ab.paid && ab.shipped);
        assert_eq!(ab.issue_window_ends.as_deref(), Some("2026-11-21"));
    }

    /// D3: the same settle held twice is ONE settle (a duplicate
    /// travels when a statement is re-sent), never a conflict.
    #[test]
    fn a_duplicated_settle_still_settles() {
        let a = settle(100_000_000_000, false);
        let events = vec![
            TradeEvent::Assignment(assignment(PaymentTiming::Prepay, FAR_FUTURE_EXPIRY)),
            TradeEvent::Settle(a.clone()),
            TradeEvent::Settle(a),
        ];
        let folded = fold_trade(&events, NOW).expect("trade");
        assert_eq!(folded.state, TradeState::Settled);
        assert!(folded.terminal);
        assert_eq!(folded.refund_atomic, Some(100_000_000_000));
    }

    /// D3: an over-amount settle is not complete (§6 caps the
    /// refund at the price), so it cannot conflict with the one
    /// complete settle — in either order.
    #[test]
    fn one_complete_settle_and_one_over_amount_settle_settles() {
        let good = settle(100_000_000_000, false);
        let over = settle(250_000_000_001, false);
        for events in [
            vec![
                TradeEvent::Assignment(assignment(PaymentTiming::Prepay, FAR_FUTURE_EXPIRY)),
                TradeEvent::Settle(good.clone()),
                TradeEvent::Settle(over.clone()),
            ],
            vec![
                TradeEvent::Assignment(assignment(PaymentTiming::Prepay, FAR_FUTURE_EXPIRY)),
                TradeEvent::Settle(over),
                TradeEvent::Settle(good.clone()),
            ],
        ] {
            let folded = fold_trade(&events, NOW).expect("trade");
            assert_eq!(folded.state, TradeState::Settled);
            assert_eq!(folded.refund_atomic, Some(100_000_000_000));
        }
    }
}
