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
//!   window counted from the shipped statement's date.
//! - `Settled` and `Closed` are terminal: the fold ignores every
//!   later statement (rule 4).
//! - `Lapsed` is derived, never signed: the assignment's expiry
//!   passes with neither payment nor a shipped statement held.

use crate::date_add_days;
use crate::ht_statements::{
    AckStatement, AssignmentStatement, IssueStatement, ReceiptStatement, SettleStatement,
    ShippedDirection, ShippedStatement,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TradeState {
    Assigned,
    Paid,
    Shipped,
    IssueRaised,
    Settled,
    Closed,
    Lapsed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedTrade {
    pub state: TradeState,
    /// A terminal state (`Settled` / `Closed`) was reached; every
    /// later statement was ignored (rule 4).
    pub terminal: bool,
    pub paid: bool,
    pub shipped: bool,
    /// The agreed refund of the closing settle, when settled.
    pub refund_atomic: Option<u64>,
    /// Last day of the 30-day issue window, once shipped
    /// (`shipped date + 30 days`, §6).
    pub issue_window_ends: Option<String>,
}

/// A settle closes a trade only when its refund does not exceed the
/// assignment's amount (§6: settle "closes the trade with an agreed
/// refund", possibly zero — never more than the price).
pub fn check_settle(assignment: &AssignmentStatement, settle: &SettleStatement) -> bool {
    settle.refund_atomic <= assignment.amount_atomic
}

/// Fold `events` (in held order) into the trade's state. `now` is a
/// canonical timestamp used only for the derived `Lapsed` state.
/// Returns `None` when no assignment is held — there is no trade.
pub fn fold_trade(events: &[TradeEvent], now: &str) -> Option<FoldedTrade> {
    let assignment = events.iter().find_map(|e| match e {
        TradeEvent::Assignment(a) => Some(a),
        _ => None,
    })?;

    let mut paid = false;
    let mut shipped = false;
    let mut shipped_date: Option<String> = None;
    let mut last_milestone: Option<TradeState> = None;
    let mut issue_raised = false;
    let mut terminal: Option<(TradeState, Option<u64>)> = None;

    for event in events {
        if terminal.is_some() {
            break; // Rule 4: terminal states end the fold.
        }
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
                    shipped_date = Some(s.date.clone());
                    last_milestone = Some(TradeState::Shipped);
                }
            }
            TradeEvent::Issue(issue) => {
                // The issue path runs from Shipped, inside the
                // window; a signed issue from anyone else, before
                // shipment, or after the window does not move the
                // fold (it remains the signer's statement, and a
                // dispute filed on it is the court's business, §9).
                if shipped {
                    if let Some(end) =
                        shipped_date.as_deref().and_then(|d| date_add_days(d, 30))
                    {
                        if issue.date.as_str() <= end.as_str() {
                            issue_raised = true;
                        }
                    }
                }
            }
            TradeEvent::Settle(settle) => {
                if check_settle(assignment, settle) {
                    terminal = Some((TradeState::Settled, Some(settle.refund_atomic)));
                }
            }
            TradeEvent::Receipt(receipt) => {
                if receipt.buyer_key_fingerprint == assignment.buyer_key_fingerprint
                    && receipt.seller_key_fingerprint == assignment.seller_key_fingerprint
                {
                    terminal = Some((TradeState::Closed, None));
                }
            }
        }
    }

    let issue_window_ends = shipped_date
        .as_deref()
        .and_then(|d| date_add_days(d, 30));

    if let Some((state, refund)) = terminal {
        return Some(FoldedTrade {
            state,
            terminal: true,
            paid,
            shipped,
            refund_atomic: refund,
            issue_window_ends,
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

    Some(FoldedTrade {
        state,
        terminal: false,
        paid,
        shipped,
        refund_atomic: None,
        issue_window_ends,
    })
}
