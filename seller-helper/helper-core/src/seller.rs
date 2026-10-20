//! Seller-side statement builders (§14 `seller terms`, `seller
//! assign`): compose canonical statements with the domain
//! serialisers, sign them with the seller's key, and keep the local
//! records (saved terms, pool ledger, evidence store) consistent.
//! Signing and storage happen here; the CLI only wires flags.

use domain::ht_statements::{
    self, AssignmentStatement, OpenToken, PaymentTiming, RiskTerms, TermsStatement, TransitRisk,
};
use modules_api::Network;

use crate::store::{EvidenceStore, PoolLedger, SavedTerms};

/// Everything `seller terms` needs to sign one terms version.
pub struct TermsInputs {
    pub marketplace_id: String,
    pub listing_id: String,
    pub listing_version: u64,
    pub seller_fingerprint: String,
    pub title: String,
    pub description: String,
    pub delivery_terms: String,
    pub refund_terms: String,
    pub price_atomic: u64,
    pub transit_risk: TransitRisk,
    pub remedy_cap_pct: u64,
    pub payment_timing: PaymentTiming,
}

pub struct SignedTerms {
    pub statement: TermsStatement,
    pub statement_text: String,
    pub signature: String,
    pub terms_text: String,
}

/// Compose and sign a terms statement. The terms text is the
/// domain's canonical assembly — the same bytes the server hashes
/// when the statement is pinned, and the same bytes the buyer's
/// helper hashes at verify.
pub fn create_terms(
    inputs: &TermsInputs,
    secret_key: &[u8],
    passphrase: Option<&str>,
) -> Result<SignedTerms, String> {
    let terms_text = ht_statements::listing_terms_text(
        &inputs.title,
        &inputs.description,
        &inputs.delivery_terms,
        &inputs.refund_terms,
        inputs.price_atomic,
    );
    let statement = TermsStatement {
        marketplace_id: inputs.marketplace_id.clone(),
        listing_id: inputs.listing_id.clone(),
        listing_version: inputs.listing_version,
        seller_key_fingerprint: inputs.seller_fingerprint.clone(),
        terms_sha256: ht_statements::sha256_hex(terms_text.as_bytes()),
        risk: RiskTerms {
            transit_risk: inputs.transit_risk,
            remedy_cap_pct: inputs.remedy_cap_pct,
            payment_timing: inputs.payment_timing,
        },
    };
    let statement_text = String::from_utf8(statement.to_bytes()).expect("statement is ASCII");
    let signature = crate::keys::sign_detached(secret_key, passphrase, statement_text.as_bytes())?;
    Ok(SignedTerms {
        statement,
        statement_text,
        signature,
        terms_text,
    })
}

/// Everything `seller assign` needs.
pub struct AssignInputs {
    pub marketplace_id: String,
    pub network: Network,
    pub seller_fingerprint: String,
    pub buyer_fingerprint: String,
    /// The terms statement being assigned under (its exact text).
    pub terms_statement_text: String,
    /// Payment timing for this buyer; defaults to the terms'.
    pub payment_timing: Option<PaymentTiming>,
    pub amount_atomic: u64,
    pub expires_at: String,
    /// 128-bit nonce, 32 lowercase hex. Supplied by the caller
    /// (tests pin it; the CLI generates it randomly).
    pub nonce: String,
}

pub struct SignedAssignment {
    pub assignment_text: String,
    pub assignment_sig: String,
    pub open_text: String,
    pub open_sig: String,
    pub trade_id: String,
    pub destination: String,
}

/// Compose, sign and store an assignment + its open token, drawing
/// the destination from the pool ledger. The address is marked used
/// (with the new trade-id) only after both signatures exist, and
/// the ledger is saved before the statements — a crash must never
/// leave a signed assignment whose address the ledger still calls
/// unused.
pub fn create_assignment(
    inputs: &AssignInputs,
    secret_key: &[u8],
    passphrase: Option<&str>,
    store: &EvidenceStore,
    pool: &mut PoolLedger,
    pool_path: &std::path::Path,
    destination_override: Option<&str>,
) -> Result<SignedAssignment, String> {
    let terms = ht_statements::parse_terms_statement(
        &inputs.terms_statement_text,
        &inputs.marketplace_id,
    )
    .ok_or("the terms statement does not parse")?;
    if terms.seller_key_fingerprint != inputs.seller_fingerprint {
        return Err("the terms statement names a different seller key".to_string());
    }
    // Destination: explicit one-off (added to the ledger first) or
    // the ledger's next unused address.
    let destination = match destination_override {
        Some(addr) => {
            pool.add(addr)?;
            addr.to_string()
        }
        None => pool
            .peek_unused()
            .map(str::to_string)
            .ok_or("the local pool is empty: seed it from a batch file or pass --destination")?,
    };
    let destination = modules_api::Subaddress::validate(&destination, inputs.network)
        .map_err(|e| format!("pool destination is not a valid subaddress here: {e:?}"))?;

    let assignment = AssignmentStatement {
        marketplace_id: inputs.marketplace_id.clone(),
        network: inputs.network,
        seller_key_fingerprint: inputs.seller_fingerprint.clone(),
        buyer_key_fingerprint: inputs.buyer_fingerprint.clone(),
        terms_statement_sha256: ht_statements::terms_statement_sha256(
            inputs.terms_statement_text.as_bytes(),
        ),
        destination,
        amount_atomic: inputs.amount_atomic,
        payment_timing: inputs.payment_timing.unwrap_or(terms.risk.payment_timing),
        expires_at: inputs.expires_at.clone(),
        nonce: inputs.nonce.clone(),
    };
    let assignment_text = String::from_utf8(assignment.to_bytes()).expect("statement is ASCII");
    let trade_id = ht_statements::trade_id(assignment_text.as_bytes());
    let assignment_sig =
        crate::keys::sign_detached(secret_key, passphrase, assignment_text.as_bytes())?;

    let open = OpenToken {
        marketplace_id: inputs.marketplace_id.clone(),
        trade_id: trade_id.clone(),
        buyer_key_fingerprint: inputs.buyer_fingerprint.clone(),
        seller_key_fingerprint: inputs.seller_fingerprint.clone(),
    };
    let open_text = String::from_utf8(open.to_bytes()).expect("statement is ASCII");
    let open_sig = crate::keys::sign_detached(secret_key, passphrase, open_text.as_bytes())?;

    // Mark + persist the ledger BEFORE the statements are stored.
    let destination_str = assignment.destination.as_str();
    pool.mark_used(&destination_str, &trade_id)?;
    pool.save(pool_path)?;

    store.save_statement(&trade_id, "assignment", assignment_text.as_bytes(), Some(&assignment_sig))?;
    store.save_statement(&trade_id, "open", open_text.as_bytes(), Some(&open_sig))?;

    Ok(SignedAssignment {
        destination: assignment.destination.as_str(),
        assignment_text,
        assignment_sig,
        open_text,
        open_sig,
        trade_id,
    })
}

/// The saved-terms record for a signed terms statement.
pub fn saved_terms(signed: &SignedTerms) -> SavedTerms {
    SavedTerms {
        statement: signed.statement_text.clone(),
        signature: signed.signature.clone(),
        terms_text: signed.terms_text.clone(),
    }
}
