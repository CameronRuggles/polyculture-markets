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
    if description.trim().is_empty() || description.chars().count() > 20_000 {
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
