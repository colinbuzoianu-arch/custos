//! The dashboard's Overview page: today's decision counts, the blocked
//! percentage, the top blocked agents/tools today, and per-gateway health.
//! Composes `audit` (for the aggregates) and `gateways` (for health) rather
//! than duplicating either.

use crate::gateways::{self, Gateway, GatewaysError};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum OverviewError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Gateways(#[from] GatewaysError),
}

#[derive(Debug, Default, Serialize)]
pub struct DecisionCounts {
    pub allow: i64,
    pub block: i64,
    pub hold: i64,
}

impl DecisionCounts {
    fn total(&self) -> i64 {
        self.allow + self.block + self.hold
    }

    /// `0.0` rather than `NaN` when nothing has happened yet today - a
    /// dashboard showing "0%" is more honest than one showing nothing.
    fn blocked_percent(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            0.0
        } else {
            (self.block as f64 / total as f64) * 100.0
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CountedName {
    pub name: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct Overview {
    pub decisions_today: DecisionCounts,
    pub blocked_percent: f64,
    pub top_blocked_agents: Vec<CountedName>,
    pub top_blocked_tools: Vec<CountedName>,
    pub gateways: Vec<Gateway>,
}

const TOP_N: i64 = 5;

pub async fn get_overview(pool: &PgPool, tenant_id: Uuid) -> Result<Overview, OverviewError> {
    let verdict_counts: Vec<(Option<String>, i64)> = sqlx::query_as(
        "select verdict, count(*) from audit_records
         where tenant_id = $1 and ingested_at >= date_trunc('day', now())
         group by verdict",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    let mut decisions_today = DecisionCounts::default();
    for (verdict, count) in verdict_counts {
        match verdict.as_deref() {
            Some("ALLOW") => decisions_today.allow = count,
            Some("BLOCK") => decisions_today.block = count,
            Some("HOLD") => decisions_today.hold = count,
            // Null or unrecognized verdict - not counted toward any bucket,
            // same as the search API's best-effort extraction elsewhere.
            _ => {}
        }
    }
    let blocked_percent = decisions_today.blocked_percent();

    let top_blocked_agents = top_blocked(pool, tenant_id, "agent").await?;
    let top_blocked_tools = top_blocked(pool, tenant_id, "tool").await?;
    let gateways = gateways::list_gateways(pool, tenant_id).await?;

    Ok(Overview {
        decisions_today,
        blocked_percent,
        top_blocked_agents,
        top_blocked_tools,
        gateways,
    })
}

/// `column` is never user input - always the literal `"agent"` or
/// `"tool"` from this file, never interpolated from a request.
async fn top_blocked(
    pool: &PgPool,
    tenant_id: Uuid,
    column: &'static str,
) -> Result<Vec<CountedName>, sqlx::Error> {
    let sql = format!(
        "select {column} as name, count(*) as n from audit_records
         where tenant_id = $1 and verdict = 'BLOCK' and {column} is not null
           and ingested_at >= date_trunc('day', now())
         group by {column}
         order by n desc
         limit {TOP_N}"
    );
    let rows: Vec<(String, i64)> = sqlx::query_as(&sql).bind(tenant_id).fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|(name, count)| CountedName { name, count })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_percent_is_zero_with_no_decisions() {
        assert_eq!(DecisionCounts::default().blocked_percent(), 0.0);
    }

    #[test]
    fn blocked_percent_is_computed_correctly() {
        let counts = DecisionCounts {
            allow: 3,
            block: 1,
            hold: 0,
        };
        assert_eq!(counts.blocked_percent(), 25.0);
    }
}
