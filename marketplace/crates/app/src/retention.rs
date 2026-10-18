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
//!
//! NOT automated here, deliberately: order/invoice/terms purge at
//! terminal + 180 days with tombstones, message-payload windows,
//! and report windows. Those interact with reputation facts and
//! counterparty records; they are recorded as not-yet-built in
//! docs/unverified.md rather than shipped unreviewed.
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
}

impl RetentionOutcome {
    pub fn total(&self) -> u64 {
        self.notifications + self.sessions + self.security_events + self.disclosures
    }
}

/// Run one retention pass. Each category is a single DELETE with the
/// cutoff computed by the database (`now() - interval`), so clock
/// handling matches the stored timestamptz columns exactly. A
/// category that errors aborts the pass (the scheduler logs it and
/// the next pass retries); categories already deleted stay deleted —
/// deletion is the goal, so partial progress is safe.
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

    Ok(out)
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
        let o = RetentionOutcome { notifications: 1, sessions: 2, security_events: 3, disclosures: 4 };
        assert_eq!(o.total(), 10);
    }
}
