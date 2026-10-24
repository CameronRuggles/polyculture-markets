//! Retention jobs (spec §20; Stage 10). The database is effectively
//! a buyer–seller graph with timestamps, so it keeps as little
//! history as the marketplace needs to function.
//!
//! This stage automates only the §20 rows whose semantics are
//! unambiguous and touch no counterparty history:
//!
//! - notifications read more than `notifications_read_days` ago are
//!   deleted (unread notifications are never deleted — they are the
//!   attention system, §15);
//! - sessions that expired more than `sessions_expired_days` ago
//!   are deleted;
//! - security events older than `security_events_days` are deleted;
//! - disclosures belonging to disputes resolved more than
//!   `disclosures_resolved_days` ago are deleted (the row and its
//!   encrypted payload; the dispute record itself is part of the
//!   order record and stays). This is the deletion job Stage 9
//!   disclosed to users in advance ("kept until 180 days after this
//!   dispute is resolved, then deleted").
//! - message payloads past their per-row `expires_at` (written at
//!   insert as received + 90 days, §20) are deleted together with
//!   their blob files, and blob files no live row references are
//!   reconciled away (Code Audit 2, M2/C1). This is the 90-day
//!   message window ONLY.
//!
//! NOT automated here, deliberately: order/invoice/terms purge at
//! terminal + 180 days with tombstones, and report windows. Those
//! interact with reputation facts and counterparty records; they
//! are recorded as not-yet-built in docs/unverified.md rather than
//! shipped unreviewed.
//!
//! One non-deletion category rides the same scheduler (CL2): a
//! dispute whose moderator-proposed refund outcome has waited
//! longer than `refund_proposal_days` for the buyer's confirmation
//! is returned to the moderator queue (state back to 'open',
//! outcome cleared to 'expired'). An unconfirmed refund is never
//! silently resolved: the buyer may simply have disappeared, and
//! the order stays Disputed until a moderator decides again.
//!
//! Periods are configuration (env-overridable) and the Limitations
//! page shows the instance's actual values (§15/§20).

use sqlx::PgPool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionConfig {
    /// NOTIFICATIONS_READ_RETENTION_DAYS. Default 30 (§20).
    pub notifications_read_days: i64,
    /// SESSIONS_EXPIRED_RETENTION_DAYS. Default 7 (§20: expiry + 7d).
    pub sessions_expired_days: i64,
    /// SECURITY_EVENTS_RETENTION_DAYS. Default 30 (§20).
    pub security_events_days: i64,
    /// DISCLOSURES_RESOLVED_RETENTION_DAYS. Default 180 (§20).
    pub disclosures_resolved_days: i64,
    /// REFUND_PROPOSAL_EXPIRY_DAYS — CL2: days a proposed refund
    /// outcome may wait for the buyer's confirmation before the
    /// dispute returns to the moderator queue. Default 14.
    pub refund_proposal_days: i64,
    /// RETENTION_INTERVAL_SECS — scheduler period. Default 3600.
    pub interval_secs: u64,
}

impl RetentionConfig {
    pub fn defaults() -> RetentionConfig {
        RetentionConfig {
            notifications_read_days: 30,
            sessions_expired_days: 7,
            security_events_days: 30,
            disclosures_resolved_days: 180,
            refund_proposal_days: 14,
            interval_secs: 3600,
        }
    }

    pub fn from_env() -> RetentionConfig {
        let mut cfg = RetentionConfig::defaults();
        let num = |name: &str, slot: &mut i64| {
            if let Ok(v) = std::env::var(name) {
                if let Ok(n) = v.parse() {
                    *slot = n;
                }
            }
        };
        num("NOTIFICATIONS_READ_RETENTION_DAYS", &mut cfg.notifications_read_days);
        num("SESSIONS_EXPIRED_RETENTION_DAYS", &mut cfg.sessions_expired_days);
        num("SECURITY_EVENTS_RETENTION_DAYS", &mut cfg.security_events_days);
        num("DISCLOSURES_RESOLVED_RETENTION_DAYS", &mut cfg.disclosures_resolved_days);
        num("REFUND_PROPOSAL_EXPIRY_DAYS", &mut cfg.refund_proposal_days);
        if let Ok(v) = std::env::var("RETENTION_INTERVAL_SECS") {
            if let Ok(n) = v.parse() {
                cfg.interval_secs = n;
            }
        }
        cfg
    }
}

/// Rows deleted by one retention pass, per category.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionOutcome {
    pub notifications: u64,
    pub sessions: u64,
    pub security_events: u64,
    pub disclosures: u64,
    /// Message rows deleted past their `expires_at`, with their
    /// blob files unlinked (Code Audit 2, M2/C1).
    pub messages: u64,
    /// Orphan blob FILES unlinked by the reconciliation sweep
    /// (files, not rows — kept out of `total()`).
    pub orphan_blobs: u64,
    /// CL2: refund proposals that waited past the confirmation
    /// deadline and were returned to the moderator queue (state
    /// change, not a deletion — kept out of `total()`).
    pub refunds_reopened: u64,
}

impl RetentionOutcome {
    pub fn total(&self) -> u64 {
        self.notifications + self.sessions + self.security_events + self.disclosures + self.messages
    }
}

/// Grace period for the orphan-blob reconciliation (Code Audit 2,
/// M2/C1). A send writes its blob file BEFORE inserting the row, so
/// a file with no referencing row may belong to an insert still in
/// flight; only files older than this are treated as orphans. One
/// hour is far beyond any real write→insert gap while still
/// reclaiming leaked files (failed inserts, failed unlinks from
/// the expiry sweep above) on the next pass but one.
pub const ORPHAN_BLOB_GRACE_SECS: u64 = 3600;

/// Run one retention pass. Each deletion category is a single
/// DELETE with the cutoff computed by the database
/// (`now() - interval`), so clock handling matches the stored
/// timestamptz columns exactly. A category that errors aborts the
/// pass (the scheduler logs it and the next pass retries);
/// categories already deleted stay deleted — deletion is the goal,
/// so partial progress is safe. The CL2 refund reopening at the end
/// follows the same per-row guarded-update pattern.
pub async fn run_retention(
    pool: &PgPool,
    cfg: &RetentionConfig,
) -> Result<RetentionOutcome, sqlx::Error> {
    let mut out = RetentionOutcome::default();

    let r = sqlx::query(
        "DELETE FROM notifications \
         WHERE read_at IS NOT NULL \
           AND read_at < now() - ($1 || ' days')::interval",
    )
    .bind(cfg.notifications_read_days.to_string())
    .execute(pool)
    .await?;
    out.notifications = r.rows_affected();

    let r = sqlx::query(
        "DELETE FROM sessions \
         WHERE expires_at < now() - ($1 || ' days')::interval",
    )
    .bind(cfg.sessions_expired_days.to_string())
    .execute(pool)
    .await?;
    out.sessions = r.rows_affected();

    let r = sqlx::query(
        "DELETE FROM security_events \
         WHERE created_at < now() - ($1 || ' days')::interval",
    )
    .bind(cfg.security_events_days.to_string())
    .execute(pool)
    .await?;
    out.security_events = r.rows_affected();

    let r = sqlx::query(
        "DELETE FROM disclosures d \
         USING disputes dp \
         WHERE d.dispute_id = dp.id \
           AND dp.resolved_at IS NOT NULL \
           AND dp.resolved_at < now() - ($1 || ' days')::interval",
    )
    .bind(cfg.disclosures_resolved_days.to_string())
    .execute(pool)
    .await?;
    out.disclosures = r.rows_affected();

    // Message payloads past their expires_at (Code Audit 2, M2/C1).
    // The DELETE … RETURNING captures exactly the refs of the rows
    // this pass removed, so the unlink set can never name a blob a
    // live row still references. Unlinks are best-effort: a file
    // that cannot be removed is picked up by the orphan
    // reconciliation below (or the next pass) once it ages past the
    // grace period.
    let expired: Vec<(String,)> =
        sqlx::query_as("DELETE FROM encrypted_messages WHERE expires_at < now() RETURNING blob_ref")
            .fetch_all(pool)
            .await?;
    out.messages = expired.len() as u64;
    let blob_dir = crate::messages::blob_dir();
    for (blob_ref,) in &expired {
        unlink_blob(&blob_dir, blob_ref);
    }
    out.orphan_blobs = reconcile_orphan_blobs(pool, &blob_dir).await?;

    // CL2: refund proposals that outlived the buyer's confirmation
    // deadline go back to the moderator. The dispute reopens (the
    // order itself stays Disputed — it never resolved), the
    // proposal is cleared, and buyer, seller and the proposing
    // moderator are notified. The reopened dispute reappears in
    // disputes::open_disputes, so any moderator can decide it
    // afresh.
    let stale: Vec<(i64, String, i64, i64, Option<i64>)> = sqlx::query_as(
        "SELECT d.id, o.public_id, o.buyer_id, o.seller_id, d.resolved_by
           FROM disputes d JOIN orders o ON o.id = d.order_id
          WHERE d.state = 'awaiting_buyer_confirmation'
            AND d.refund_proposed_at IS NOT NULL
            AND d.refund_proposed_at < now() - ($1 || ' days')::interval",
    )
    .bind(cfg.refund_proposal_days.to_string())
    .fetch_all(pool)
    .await?;
    for (dispute_id, order_pub, buyer_id, seller_id, proposer) in stale {
        let r = sqlx::query(
            "UPDATE disputes
                SET state = 'open', outcome = NULL, outcome_state = 'expired',
                    refund_proposed_at = NULL
              WHERE id = $1 AND state = 'awaiting_buyer_confirmation'",
        )
        .bind(dispute_id)
        .execute(pool)
        .await?;
        if r.rows_affected() == 1 {
            out.refunds_reopened += 1;
            let _ = crate::orders::notify(pool, buyer_id, "dispute_refund_expired", &order_pub).await;
            let _ = crate::orders::notify(pool, seller_id, "dispute_refund_expired", &order_pub).await;
            if let Some(m) = proposer {
                let _ = crate::orders::notify(pool, m, "dispute_refund_expired", &order_pub).await;
            }
        }
    }

    Ok(out)
}

/// True for a genuine blob stem: blob refs are session tokens
/// (non-empty ASCII hex), the same guard `messages::message_blob`
/// applies before it builds a path from a stored ref. A name that
/// fails this can never be turned into a path by the sweep, so a
/// corrupt or hostile ref cannot escape the blob directory.
fn is_blob_stem(stem: &str) -> bool {
    !stem.is_empty() && stem.chars().all(|c| c.is_ascii_hexdigit())
}

/// Unlink `<dir>/<blob_ref>.asc`, best-effort. Only hex refs are
/// ever turned into paths (see `is_blob_stem`).
fn unlink_blob(dir: &std::path::Path, blob_ref: &str) {
    if is_blob_stem(blob_ref) {
        let _ = std::fs::remove_file(dir.join(format!("{blob_ref}.asc")));
    }
}

/// Reconcile orphan blob files: `<stem>.asc` files in the blob
/// directory that no live `encrypted_messages` row references.
/// Orphans arise when a send's INSERT failed after its file write,
/// or when an expiry unlink failed. Two guards make this safe:
///
/// - only well-formed blob names are considered — anything else in
///   the directory (operator files, foreign names) is left alone;
/// - a file younger than `ORPHAN_BLOB_GRACE_SECS` is never
///   unlinked, because a send writes its blob BEFORE inserting the
///   row: a young unreferenced file may be an insert in flight.
///
/// Filesystem trouble is non-fatal (a missing directory simply has
/// no orphans); the sweep returns how many files it removed.
async fn reconcile_orphan_blobs(pool: &PgPool, dir: &std::path::Path) -> Result<u64, sqlx::Error> {
    let live: std::collections::HashSet<String> =
        sqlx::query_as::<_, (String,)>("SELECT blob_ref FROM encrypted_messages")
            .fetch_all(pool)
            .await?
            .into_iter()
            .map(|(r,)| r)
            .collect();
    let mut removed = 0u64;
    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(_) => return Ok(0),
    };
    let now = std::time::SystemTime::now();
    loop {
        let entry = match rd.next_entry().await {
            Ok(Some(e)) => e,
            _ => break,
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".asc") else { continue };
        if !is_blob_stem(stem) || live.contains(stem) {
            continue;
        }
        let Ok(md) = entry.metadata().await else { continue };
        let Ok(mtime) = md.modified() else { continue };
        // Skip young files (possible in-flight insert) and any
        // timestamp the clock reports as in the future.
        match now.duration_since(mtime) {
            Ok(age) if age.as_secs() >= ORPHAN_BLOB_GRACE_SECS => {}
            _ => continue,
        }
        if tokio::fs::remove_file(entry.path()).await.is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec_section_20() {
        let c = RetentionConfig::defaults();
        assert_eq!(c.notifications_read_days, 30);
        assert_eq!(c.sessions_expired_days, 7);
        assert_eq!(c.security_events_days, 30);
        assert_eq!(c.disclosures_resolved_days, 180);
        assert_eq!(c.interval_secs, 3600);
    }

    #[test]
    fn outcome_total() {
        let o = RetentionOutcome {
            notifications: 1,
            sessions: 2,
            security_events: 3,
            disclosures: 4,
            messages: 5,
            orphan_blobs: 6,
            refunds_reopened: 0,
        };
        // Rows only: orphan_blobs counts files, refunds_reopened is
        // a state change — both stay out of the total.
        assert_eq!(o.total(), 15);
    }

    #[test]
    fn blob_stem_guard() {
        assert!(is_blob_stem("0123456789abcdef"));
        assert!(!is_blob_stem(""));
        assert!(!is_blob_stem("../escape"));
        assert!(!is_blob_stem("not-hex"));
        assert!(!is_blob_stem("dead beef"));
    }
}
