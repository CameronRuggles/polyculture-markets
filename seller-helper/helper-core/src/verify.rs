//! The buyer's `verify` (§14): the assignment check that runs
//! before any money moves. The checks run IN ORDER; on any failure
//! payment stops. Checks 1–6 refuse; check 7 only warns.
//!
//! 1. The signature verifies against the seller's pinned key, and
//!    any key change is covered (verify against a *different* pinned
//!    key than the assignment names is a failure here, never a
//!    prompt).
//! 2. The assignment names this buyer (own fingerprint), this
//!    marketplace, this network.
//! 3. `terms-statement-sha256` matches the signed terms saved from
//!    the listing — and those terms themselves verify, bind the same
//!    seller, and hash the terms text the buyer actually read.
//! 4. The destination is a subaddress of this network, validated in
//!    the pinned order (decode/checksum → network → subaddress-only
//!    → torsion-free).
//! 5. The amount matches the terms price exactly (every listing in
//!    this build is XMR-priced — the pricing module's sole live
//!    mode — so the fiat branch of §14 check 5 has nothing to run
//!    on yet).
//! 6. `expires-at` is in the future and at most 60 days after the
//!    signature's creation time.
//! 7. Warning only: the amount against the seller's suggested
//!    ceiling less the buyer's open exposure on that seller.

use domain::ht_statements::{
    self, AssignmentFields, AssignmentStatement,
};
use modules_api::{Network, Subaddress};

/// The exact check that refused an assignment (§14's `verify`
/// refuses at the first failed check, and says which).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// The bytes do not parse as an assignment at all.
    Malformed,
    /// Check 1: the signature does not verify against the pinned
    /// seller key (or the pinned key is not the key the assignment
    /// names — an uncovered key change).
    Signature,
    /// Check 2: wrong buyer, marketplace, or network.
    Party,
    /// Check 3: the terms chain does not hold.
    Terms,
    /// Check 4: the destination is not a valid subaddress here.
    Destination,
    /// Check 5: the amount is not the terms price.
    Amount,
    /// Check 6: expired, or expires too far after signing.
    Expiry,
}

#[derive(Debug, Clone)]
pub struct VerifyInputs {
    /// The assignment statement, exact bytes as received.
    pub assignment: Vec<u8>,
    /// Its armored detached signature.
    pub assignment_sig: String,
    /// The seller's pinned certificate bytes.
    pub seller_cert: Vec<u8>,
    /// This buyer's own key fingerprint.
    pub own_fingerprint: String,
    pub marketplace_id: String,
    pub network: Network,
    /// The signed terms saved from the listing: statement bytes,
    /// its armored detached signature, and the terms text itself.
    pub terms_statement: Vec<u8>,
    pub terms_sig: String,
    pub terms_text: String,
    /// Canonical timestamp of "now" (check 6).
    pub now: String,
    /// Check 7 inputs, when known: the seller's suggested ceiling
    /// for this buyer and the buyer's open exposure on the seller.
    pub ceiling: Option<(u64, u64)>,
}

#[derive(Debug, Clone)]
pub struct VerifiedAssignment {
    pub assignment: AssignmentStatement,
    pub trade_id: String,
    /// Check 7 advisories; never a refusal.
    pub warnings: Vec<String>,
}

fn parse_ts(s: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(
        s,
        &time::format_description::well_known::Rfc3339,
    )
    .ok()
}

/// Run the §14 checks, in order.
pub fn verify_assignment(inputs: &VerifyInputs) -> Result<VerifiedAssignment, VerifyError> {
    let assignment_text = std::str::from_utf8(&inputs.assignment).map_err(|_| VerifyError::Malformed)?;

    // Check 1 — signature against the pinned key, for exactly the
    // key the assignment names. An assignment naming a key other
    // than the pinned one is an uncovered change: stop.
    let fields = ht_statements::parse_assignment_fields(assignment_text)
        .ok_or(VerifyError::Malformed)?;
    let pinned_fpr = crate::keys::fingerprint_of(&inputs.seller_cert).map_err(|_| VerifyError::Signature)?;
    if fields.seller_key_fingerprint != pinned_fpr {
        return Err(VerifyError::Signature);
    }
    if !crate::keys::verify_detached(
        &inputs.seller_cert,
        &inputs.assignment,
        inputs.assignment_sig.as_bytes(),
    ) {
        return Err(VerifyError::Signature);
    }

    // Check 2 — right buyer, right marketplace, right network.
    if fields.buyer_key_fingerprint != inputs.own_fingerprint
        || fields.marketplace_id != inputs.marketplace_id
        || fields.network != inputs.network
    {
        return Err(VerifyError::Party);
    }

    // Check 3 — the terms chain: the assignment's digest is the
    // saved terms statement's hash; the terms verify against the
    // same pinned key and name the same seller; the terms text the
    // buyer read hashes to the statement's terms-sha256.
    let terms_text = std::str::from_utf8(&inputs.terms_statement).map_err(|_| VerifyError::Terms)?;
    if ht_statements::terms_statement_sha256(&inputs.terms_statement)
        != fields.terms_statement_sha256
    {
        return Err(VerifyError::Terms);
    }
    let terms = ht_statements::parse_terms_statement(terms_text, &inputs.marketplace_id)
        .ok_or(VerifyError::Terms)?;
    if terms.seller_key_fingerprint != fields.seller_key_fingerprint {
        return Err(VerifyError::Terms);
    }
    if !crate::keys::verify_detached(
        &inputs.seller_cert,
        &inputs.terms_statement,
        inputs.terms_sig.as_bytes(),
    ) {
        return Err(VerifyError::Terms);
    }
    if ht_statements::sha256_hex(inputs.terms_text.as_bytes()) != terms.terms_sha256 {
        return Err(VerifyError::Terms);
    }

    // Check 4 — destination, in the pinned order.
    Subaddress::validate(&fields.destination, inputs.network).map_err(|_| VerifyError::Destination)?;

    // Check 5 — amount is the terms price, exactly.
    let price = ht_statements::listing_terms_price(&inputs.terms_text).ok_or(VerifyError::Terms)?;
    if fields.amount_atomic != price {
        return Err(VerifyError::Amount);
    }

    // Check 6 — expiry: in the future, and at most 60 days after
    // the signature was made.
    let created_unix = crate::keys::signature_created(inputs.assignment_sig.as_bytes())
        .ok_or(VerifyError::Expiry)?;
    let created = time::OffsetDateTime::from_unix_timestamp(created_unix).map_err(|_| VerifyError::Expiry)?;
    let expires = parse_ts(&fields.expires_at).ok_or(VerifyError::Expiry)?;
    let now = parse_ts(&inputs.now).ok_or(VerifyError::Expiry)?;
    if expires <= now || expires > created + time::Duration::days(60) {
        return Err(VerifyError::Expiry);
    }

    // Check 7 — warn only.
    let mut warnings = Vec::new();
    if let Some((ceiling, open_exposure)) = inputs.ceiling {
        let headroom = ceiling.saturating_sub(open_exposure);
        if fields.amount_atomic > headroom {
            warnings.push(format!(
                "amount {} atomic exceeds the seller's suggested ceiling headroom ({} atomic): \
                 consider splitting the trade into tranches or asking for on_ship terms",
                fields.amount_atomic, headroom
            ));
        }
    }

    let assignment = ht_statements::parse_assignment_statement(
        assignment_text,
        &inputs.marketplace_id,
        inputs.network,
    )
    .ok_or(VerifyError::Malformed)?;
    Ok(VerifiedAssignment {
        trade_id: ht_statements::trade_id(&inputs.assignment),
        assignment,
        warnings,
    })
}

/// One row of [`trade_status`]: the trade id and its fold — or
/// the error its held set produced. An unreadable trade is a row
/// with an `Err`, never a missing row (audit F10).
pub type TradeStatusRow = (String, Result<Option<domain::ht_fold::FoldedTrade>, String>);

/// Fold every trade in the store (§6) — the data behind
/// `helper buyer status` / `helper seller status`. Each trade's
/// held set is re-verified at load (audit F4): the parties come
/// from the trade's own assignment, certificates resolve against
/// `own_cert` (the holder's key) and the pins. Enumerating the
/// store is the one failure that cannot become a per-trade row
/// (re-verification N8): if the trades directory cannot be read
/// this returns Err and the caller prints an ERROR row for the
/// store — "no trades" is a finding about a READABLE store,
/// never a fallback for an unreadable one.
pub fn trade_status(
    store: &crate::store::EvidenceStore,
    marketplace_id: &str,
    network: Network,
    now: &str,
    own_cert: Option<&std::path::Path>,
) -> Result<Vec<TradeStatusRow>, String> {
    let mut out = Vec::new();
    for trade_id in store.trade_ids()? {
        let row = (|| -> Result<Option<domain::ht_fold::FoldedTrade>, String> {
            let Some(assignment) = store.load_assignment(&trade_id, marketplace_id, network)?
            else {
                return Ok(None);
            };
            let expected = crate::store::ExpectedSigners {
                seller_fpr: assignment.seller_key_fingerprint.clone(),
                buyer_fpr: assignment.buyer_key_fingerprint.clone(),
            };
            let events = store.load_events(&trade_id, &expected, marketplace_id, network, own_cert)?;
            Ok(domain::ht_fold::fold_trade_timed(&events, now))
        })();
        out.push((trade_id, row));
    }
    Ok(out)
}

/// The fields-level view other checks share (kept public for the
/// CLI's diagnostics).
pub fn assignment_fields(text: &str) -> Option<AssignmentFields> {
    ht_statements::parse_assignment_fields(text)
}
