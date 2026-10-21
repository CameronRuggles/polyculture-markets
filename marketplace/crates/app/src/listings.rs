//! Listings + catalogue (spec §9, §15) and seller admission (§5/§7).

use sqlx::PgPool;

pub const CATEGORIES: &[&str] = &[
    "general", "books", "art", "software", "services", "collectibles", "other",
];
pub const DESTINATION_MODULES: &[&str] = &["signed-address-pool", "signed-invoice"];

#[derive(Debug, Clone)]
pub struct Listing {
    pub id: i64,
    pub public_id: String,
    pub seller_id: i64,
    pub seller_name: String,
    pub seller_public_id: String,
    pub title: String,
    pub description: String,
    pub price_atomic: i64,
    pub category: String,
    pub destination_module: String,
    pub pricing_module: String,
    pub auto_invoice: bool,
    pub status: String,
    /// CH1: a moderator takedown is in force (migration 0013). While
    /// set, `status` reads 'removed' — a state only moderators can
    /// put a listing into or take it out of — and the seller cannot
    /// change the status at all. The seller's own removal is the
    /// separate status 'withdrawn'.
    pub taken_down: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ListingError {
    Title,
    Description,
    Price,
    Category,
    DestinationModule,
    AutoInvoiceNeedsPool,
    Terms,
}

/// Contract §8 signature: the price arrives already parsed to atomic units
/// (the caller parses the decimal form input via `Atomic::parse_decimal`;
/// an unparseable amount is a `Price` error at that layer).
pub fn validate_listing(
    title: &str,
    description: &str,
    price_atomic: u64,
    category: &str,
    destination_module: &str,
    auto_invoice: bool,
) -> Result<(), ListingError> {
    let t = title.trim();
    if t.is_empty() || t.chars().count() > 120 || t.contains(['<', '>', '\n']) {
        return Err(ListingError::Title);
    }
    // BL3: no Unicode format characters (category Cf — bidi
    // overrides, zero-width characters, tag characters) in seller
    // text: what the reader sees must be what the bytes say, in
    // the catalogue and in the signed terms file alike.
    if modules_api::contains_format_chars(t) {
        return Err(ListingError::Title);
    }
    if description.trim().is_empty() || description.chars().count() > 20_000 {
        return Err(ListingError::Description);
    }
    if modules_api::contains_format_chars(description) {
        return Err(ListingError::Description);
    }
    if price_atomic == 0 {
        return Err(ListingError::Price);
    }
    if !CATEGORIES.contains(&category) {
        return Err(ListingError::Category);
    }
    if !DESTINATION_MODULES.contains(&destination_module) {
        return Err(ListingError::DestinationModule);
    }
    // §9: auto-invoice is available only with the address-pool module.
    if auto_invoice && destination_module != "signed-address-pool" {
        return Err(ListingError::AutoInvoiceNeedsPool);
    }
    Ok(())
}

const LISTING_COLS: &str = "l.id, l.public_id, l.seller_id, a.username, a.public_id, l.title, l.description,
    l.price_atomic, l.category, l.destination_module, l.pricing_module, l.auto_invoice, l.status,
    l.taken_down_at IS NOT NULL";

fn row_to_listing(r: ListingRow) -> Listing {
    Listing {
        id: r.0,
        public_id: r.1,
        seller_id: r.2,
        seller_name: r.3,
        seller_public_id: r.4,
        title: r.5,
        description: r.6,
        price_atomic: r.7,
        category: r.8,
        destination_module: r.9,
        pricing_module: r.10,
        auto_invoice: r.11,
        status: r.12,
        taken_down: r.13,
    }
}

type ListingRow = (i64, String, i64, String, String, String, String, i64, String, String, String, bool, String, bool);

/// BL3: the per-listing delivery/refund terms get the same
/// format-character rule as the title and description — they are
/// bound into the buyer's terms file verbatim. (No current form
/// writes these columns; the check runs where the terms are
/// consumed, in order creation, so no path can carry Cf text
/// into a terms file.)
pub fn validate_listing_terms(delivery_terms: &str, refund_terms: &str) -> Result<(), ListingError> {
    if modules_api::contains_format_chars(delivery_terms)
        || modules_api::contains_format_chars(refund_terms)
    {
        return Err(ListingError::Terms);
    }
    Ok(())
}

pub async fn create_listing(
    pool: &PgPool,
    seller_id: i64,
    title: &str,
    description: &str,
    price_atomic: i64,
    category: &str,
    destination_module: &str,
    auto_invoice: bool,
) -> Result<String, sqlx::Error> {
    let public_id = crate::db::public_id("lst_");
    sqlx::query(
        "INSERT INTO listings (public_id, seller_id, title, description, price_atomic,
            pricing_module, destination_module, auto_invoice, category)
         VALUES ($1,$2,$3,$4,$5,'xmr-only',$6,$7,$8)",
    )
    .bind(&public_id)
    .bind(seller_id)
    .bind(title.trim())
    .bind(description)
    .bind(price_atomic)
    .bind(destination_module)
    .bind(auto_invoice)
    .bind(category)
    .execute(pool)
    .await?;
    Ok(public_id)
}

pub async fn listing_by_public_id(pool: &PgPool, public_id: &str) -> Result<Option<Listing>, sqlx::Error> {
    let row: Option<ListingRow> = sqlx::query_as(&format!(
        "SELECT {LISTING_COLS} FROM listings l JOIN accounts a ON a.id = l.seller_id
         WHERE l.public_id = $1"
    ))
    .bind(public_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(row_to_listing))
}

pub async fn listings_of_seller(pool: &PgPool, seller_id: i64) -> Result<Vec<Listing>, sqlx::Error> {
    let rows: Vec<ListingRow> = sqlx::query_as(&format!(
        "SELECT {LISTING_COLS} FROM listings l JOIN accounts a ON a.id = l.seller_id
         WHERE l.seller_id = $1 ORDER BY l.created_at DESC"
    ))
    .bind(seller_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(row_to_listing).collect())
}

/// Published catalogue: optional full-text-ish search + category filter,
/// newest first, 20 per page.
pub async fn browse(
    pool: &PgPool,
    q: Option<&str>,
    category: Option<&str>,
    page: i64,
) -> Result<Vec<Listing>, sqlx::Error> {
    let rows: Vec<ListingRow> = sqlx::query_as(&format!(
        "SELECT {LISTING_COLS} FROM listings l JOIN accounts a ON a.id = l.seller_id
         WHERE l.status = 'published' AND l.taken_down_at IS NULL
           AND ($1::text IS NULL OR (l.title ILIKE '%'||$1||'%' OR l.description ILIKE '%'||$1||'%'))
           AND ($2::text IS NULL OR l.category = $2)
         ORDER BY l.created_at DESC LIMIT 20 OFFSET $3"
    ))
    .bind(q)
    .bind(category)
    .bind((page.max(1) - 1) * 20)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(row_to_listing).collect())
}

/// Seller-controlled status changes. The seller's vocabulary is
/// draft / published / paused / withdrawn — 'removed' is NOT in it:
/// that state belongs to moderator takedowns (CH1). While a
/// takedown is in force (`taken_down_at` set), EVERY seller status
/// change is refused, so a takedown cannot be undone from the
/// seller dashboard.
pub async fn set_status(
    pool: &PgPool,
    listing_id: i64,
    seller_id: i64,
    status: &str,
) -> Result<bool, sqlx::Error> {
    if !["draft", "published", "paused", "withdrawn"].contains(&status) {
        return Ok(false);
    }
    let r = sqlx::query(
        "UPDATE listings SET status = $3
          WHERE id = $1 AND seller_id = $2 AND taken_down_at IS NULL",
    )
    .bind(listing_id)
    .bind(seller_id)
    .bind(status)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn add_media(
    pool: &PgPool,
    listing_id: i64,
    sanitized_ref: &str,
    width: i32,
    height: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO listing_media (listing_id, sanitized_ref, width, height) VALUES ($1,$2,$3,$4)",
    )
    .bind(listing_id)
    .bind(sanitized_ref)
    .bind(width)
    .bind(height)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn media_of(pool: &PgPool, listing_id: i64) -> Result<Vec<(String, i32, i32)>, sqlx::Error> {
    sqlx::query_as("SELECT sanitized_ref, width, height FROM listing_media WHERE listing_id = $1 ORDER BY id")
        .bind(listing_id)
        .fetch_all(pool)
        .await
}

// -- seller admission (default module: admin-approval, spec §5) -------------

pub async fn apply_for_seller(pool: &PgPool, account_id: i64) -> Result<(), sqlx::Error> {
    // Contract §8: re-applying while an application is pending is
    // idempotent — a second pending row would also break the decision
    // update below, which expects exactly one pending record.
    sqlx::query(
        "INSERT INTO admission_records (account_id, module, outcome)
         SELECT $1, 'admin-approval', 'pending'
         WHERE NOT EXISTS (
             SELECT 1 FROM admission_records
             WHERE account_id = $1 AND module = 'admin-approval' AND outcome = 'pending'
         )",
    )
    .bind(account_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn pending_seller_applications(pool: &PgPool) -> Result<Vec<(i64, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT r.account_id, a.username FROM admission_records r JOIN accounts a ON a.id = r.account_id
         WHERE r.module = 'admin-approval' AND r.outcome = 'pending' ORDER BY r.created_at",
    )
    .fetch_all(pool)
    .await
}

/// Failure modes of a seller-admission decision. An unauthorized
/// decision attempt is an error, not a silent no-op (contract §8: "a
/// non-privileged actor cannot decide any application").
#[derive(Debug)]
pub enum AdmissionError {
    Unauthorized,
    Db(sqlx::Error),
}

impl From<sqlx::Error> for AdmissionError {
    fn from(e: sqlx::Error) -> Self {
        AdmissionError::Db(e)
    }
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmissionError::Unauthorized => write!(f, "decider is not a moderator or admin"),
            AdmissionError::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl std::error::Error for AdmissionError {}

pub async fn decide_seller_application(
    pool: &PgPool,
    decider_id: i64,
    account_id: i64,
    approve: bool,
) -> Result<bool, AdmissionError> {
    let mut tx = pool.begin().await?;
    // Contract §8 invariant: only a moderator/admin may decide an
    // application — enforced here, not only at the route layer, so no
    // caller can grant seller status without a privileged actor. A
    // non-privileged decider (including the applicant) changes nothing
    // and the attempt fails.
    let decider_role: Option<String> =
        sqlx::query_scalar("SELECT role FROM accounts WHERE id = $1")
            .bind(decider_id)
            .fetch_optional(&mut *tx)
            .await?;
    if !matches!(decider_role.as_deref(), Some("moderator") | Some("admin")) {
        tx.rollback().await?;
        return Err(AdmissionError::Unauthorized);
    }
    let r = sqlx::query(
        "UPDATE admission_records SET outcome = $2
         WHERE account_id = $1 AND module = 'admin-approval' AND outcome = 'pending'",
    )
    .bind(account_id)
    .bind(if approve { "approved" } else { "rejected" })
    .execute(&mut *tx)
    .await?;
    if r.rows_affected() != 1 {
        tx.rollback().await?;
        return Ok(false);
    }
    if approve {
        sqlx::query("UPDATE accounts SET role = 'seller' WHERE id = $1 AND role = 'buyer'")
            .bind(account_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(true)
}

pub async fn seller_application_state(pool: &PgPool, account_id: i64) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT outcome FROM admission_records WHERE account_id = $1 AND module = 'admin-approval'
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rules() {
        assert_eq!(
            validate_listing("A book", "Nice", 1_500_000_000_000, "books", "signed-invoice", false),
            Ok(())
        );
        assert_eq!(
            validate_listing("A book", "Nice", 1_500_000_000_000, "books", "signed-invoice", true),
            Err(ListingError::AutoInvoiceNeedsPool)
        );
        assert_eq!(
            validate_listing("<b>x</b>", "Nice", 1_500_000_000_000, "books", "signed-invoice", false),
            Err(ListingError::Title)
        );
        assert_eq!(
            validate_listing("Ok", "Nice", 0, "books", "signed-invoice", false),
            Err(ListingError::Price)
        );
        assert_eq!(
            validate_listing("Ok", "Nice", 1_500_000_000_000, "nope", "signed-invoice", false),
            Err(ListingError::Category)
        );
    }
}

// ---------------------------------------------------------------------------
// Signed listing terms v2 (Alpha spec §4; migration 0016): the
// seller's helper produces a `marketplace-terms-v2` statement over
// the listing's canonical terms text; the server verifies it against
// the seller's pinned key and pins it per version. A listing cannot
// be published without a current pinned version whose hash matches
// the listing's current text (enforced at the publish path in web).

/// One pinned terms version of a listing.
#[derive(Debug, Clone)]
pub struct TermsPin {
    pub version: i64,
    pub statement: String,
    pub signature: String,
    pub statement_sha256: String,
    pub terms_sha256: String,
    pub transit_risk: String,
    pub remedy_cap_pct: i32,
    pub payment_timing: String,
}

#[derive(Debug)]
pub enum TermsError {
    /// The statement does not parse as marketplace-terms-v2 for this
    /// marketplace.
    Malformed,
    /// The statement names a different listing.
    WrongListing,
    /// The statement's version is not the next version for the
    /// listing (versions pin in order, starting at 1).
    Version,
    /// The seller has no pinned key.
    NoKey,
    /// The statement's fingerprint is not the seller's current
    /// pinned key.
    KeyMismatch,
    /// The statement does not bind the listing's current terms text.
    TextMismatch,
    /// The detached signature does not verify against the pinned key.
    BadSignature,
    Db(sqlx::Error),
}

impl From<sqlx::Error> for TermsError {
    fn from(e: sqlx::Error) -> Self {
        TermsError::Db(e)
    }
}

type TermsRow = (i64, String, String, String, String, String, i32, String);

fn row_to_terms(r: TermsRow) -> TermsPin {
    TermsPin {
        version: r.0,
        statement: r.1,
        signature: r.2,
        statement_sha256: r.3,
        terms_sha256: r.4,
        transit_risk: r.5,
        remedy_cap_pct: r.6,
        payment_timing: r.7,
    }
}

const TERMS_COLS: &str = "version, statement, signature, statement_sha256, terms_sha256,
    transit_risk, remedy_cap_pct, payment_timing";

/// The listing's current (un-superseded) pinned terms, if any.
pub async fn current_terms(pool: &PgPool, listing_id: i64) -> Result<Option<TermsPin>, sqlx::Error> {
    let row: Option<TermsRow> = sqlx::query_as(&format!(
        "SELECT {TERMS_COLS} FROM listing_terms_statements
          WHERE listing_id = $1 AND superseded_at IS NULL"
    ))
    .bind(listing_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(row_to_terms))
}

/// The listing's canonical terms text (domain's one definition),
/// from the listing's stored fields — the exact bytes whose
/// SHA-256 the pinned terms statement binds, and the bytes the
/// buyer's helper hashes at verify (§13/§14 check 3). Served to
/// buyers as its own resource (audit F7: without it, no buyer
/// could ever satisfy check 3 from what the site serves).
pub async fn listing_terms_text_for(
    pool: &PgPool,
    listing: &Listing,
) -> Result<String, sqlx::Error> {
    let (delivery_terms, refund_terms): (String, String) = sqlx::query_as(
        "SELECT delivery_terms, refund_terms FROM listings WHERE id = $1",
    )
    .bind(listing.id)
    .fetch_one(pool)
    .await?;
    Ok(domain::ht_statements::listing_terms_text(
        &listing.title,
        &listing.description,
        &delivery_terms,
        &refund_terms,
        listing.price_atomic as u64,
    ))
}

/// The listing's canonical terms text's SHA-256.
async fn listing_terms_digest(pool: &PgPool, listing: &Listing) -> Result<String, sqlx::Error> {
    let text = listing_terms_text_for(pool, listing).await?;
    Ok(domain::ht_statements::sha256_hex(text.as_bytes()))
}

/// Verify and pin a seller-submitted terms statement for `listing`
/// (§4 rule 1: verified against the seller's pinned key, here and at
/// every later version). On success the previous current version is
/// superseded in the same transaction (it stays readable for 12
/// months, §15.7).
pub async fn submit_terms(
    pool: &PgPool,
    marketplace_id: &str,
    listing: &Listing,
    statement_text: &str,
    signature_armored: &str,
) -> Result<TermsPin, TermsError> {
    let stmt = domain::ht_statements::parse_terms_statement(statement_text, marketplace_id)
        .ok_or(TermsError::Malformed)?;
    if stmt.listing_id != listing.public_id {
        return Err(TermsError::WrongListing);
    }
    let (fpr, cert, _v) = crate::keys::current_key(pool, listing.seller_id)
        .await?
        .ok_or(TermsError::NoKey)?;
    if stmt.seller_key_fingerprint != fpr {
        return Err(TermsError::KeyMismatch);
    }
    if stmt.terms_sha256 != listing_terms_digest(pool, listing).await? {
        return Err(TermsError::TextMismatch);
    }
    if !crate::keys::verify_detached(&cert, statement_text.as_bytes(), signature_armored.as_bytes()) {
        return Err(TermsError::BadSignature);
    }
    let current = current_terms(pool, listing.id).await?;
    let next = current.as_ref().map(|c| c.version + 1).unwrap_or(1);
    if stmt.listing_version != next as u64 {
        return Err(TermsError::Version);
    }
    let pin = TermsPin {
        version: next,
        statement: statement_text.to_string(),
        signature: signature_armored.to_string(),
        statement_sha256: domain::ht_statements::terms_statement_sha256(statement_text.as_bytes()),
        terms_sha256: stmt.terms_sha256.clone(),
        transit_risk: stmt.risk.transit_risk.as_str().to_string(),
        remedy_cap_pct: stmt.risk.remedy_cap_pct as i32,
        payment_timing: stmt.risk.payment_timing.as_str().to_string(),
    };
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE listing_terms_statements SET superseded_at = now()
          WHERE listing_id = $1 AND superseded_at IS NULL",
    )
    .bind(listing.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO listing_terms_statements
            (listing_id, version, statement, signature, statement_sha256, terms_sha256,
             transit_risk, remedy_cap_pct, payment_timing)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(listing.id)
    .bind(pin.version)
    .bind(&pin.statement)
    .bind(&pin.signature)
    .bind(&pin.statement_sha256)
    .bind(&pin.terms_sha256)
    .bind(&pin.transit_risk)
    .bind(pin.remedy_cap_pct)
    .bind(&pin.payment_timing)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(pin)
}

/// True when the listing has a current pinned terms version whose
/// hash still matches the listing's current text — the publish gate
/// (§4: verified at publish and at every edit; any text change
/// without a re-signed statement fails this check).
pub async fn terms_match_listing(pool: &PgPool, listing: &Listing) -> bool {
    let (Ok(Some(pin)), Ok(digest)) = (
        current_terms(pool, listing.id).await,
        listing_terms_digest(pool, listing).await,
    ) else {
        return false;
    };
    pin.terms_sha256 == digest
}

/// The three risk fields in the spec's fixed display wording (§4),
/// rendered beside the price wherever terms are pinned. The wording
/// is the spec's exactly; only the cap number is substituted.
pub fn terms_risk_lines(transit_risk: &str, remedy_cap_pct: i64, payment_timing: &str) -> [String; 3] {
    let transit = match transit_risk {
        "seller" => "If it's lost in the post, the seller refunds or reships.".to_string(),
        "buyer" => "Once the seller signs that it shipped, loss in the post is yours.".to_string(),
        _ => String::new(),
    };
    let remedy = if remedy_cap_pct == 0 {
        "Sold as-is. No refund for quality or wrong-item complaints unless the listing itself is contradicted.".to_string()
    } else {
        format!("Raise an issue within 30 days of shipping and the seller has promised a refund of up to {remedy_cap_pct}%.")
    };
    let timing = match payment_timing {
        "prepay" => "You pay before it ships.".to_string(),
        "on_ship" => "You pay once the seller signs that it shipped.".to_string(),
        "on_receipt" => "The seller ships first; you pay by the date in your assignment.".to_string(),
        _ => String::new(),
    };
    [transit, remedy, timing]
}
