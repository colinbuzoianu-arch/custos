//! Ingesting a gateway's audit records: idempotent by `(gateway_id, seq)`,
//! schema-tolerant (stores whatever JSON shape a record has, never rejects
//! a batch over an unrecognized field), and flags chain gaps/breaks per
//! gateway without re-deriving the gateway's own SHA-256 hash chain.

use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("gateway not found")]
    GatewayNotFound,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct IngestOutcome {
    pub inserted: usize,
    pub duplicates: usize,
    pub skipped: usize,
}

/// Ingests one batch of raw audit-log lines (each exactly what the gateway
/// wrote to its JSONL file, any schema version). Records are processed in
/// `seq` order regardless of the order they arrived in, so an out-of-order
/// batch still gets the same chain-continuity result as an in-order one.
pub async fn ingest_batch(
    pool: &PgPool,
    tenant_id: Uuid,
    gateway_id: Uuid,
    records: &[Value],
) -> Result<IngestOutcome, AuditError> {
    let mut sorted: Vec<&Value> = records.iter().collect();
    sorted.sort_by_key(|r| r.get("seq").and_then(Value::as_u64).unwrap_or(0));

    let current: Option<(Option<i64>, Option<String>)> =
        sqlx::query_as("select last_ingested_seq, last_ingested_hash from gateways where id = $1")
            .bind(gateway_id)
            .fetch_optional(pool)
            .await?;
    let Some((mut last_seq, mut last_hash)) = current else {
        return Err(AuditError::GatewayNotFound);
    };
    let mut chain_status = "ok".to_string();
    let mut chain_issue: Option<String> = None;

    let mut outcome = IngestOutcome::default();

    for record in sorted {
        let Some(seq) = record
            .get("seq")
            .and_then(Value::as_u64)
            .and_then(|s| i64::try_from(s).ok())
        else {
            // Can't dedupe or chain-check a record with no usable seq - not
            // something our own gateway ever writes, but a hostile or
            // buggy client shouldn't be able to corrupt chain tracking with
            // one.
            outcome.skipped += 1;
            continue;
        };
        let ts = record
            .get("ts")
            .and_then(Value::as_str)
            .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok());
        let agent = record.get("agent").and_then(Value::as_str);
        let owner = record.get("owner").and_then(Value::as_str);
        let tool = record.get("tool").and_then(Value::as_str);
        let verdict = record
            .get("decision")
            .and_then(|d| d.get("verdict"))
            .and_then(Value::as_str);
        let policy_version = record.get("policy_version").and_then(Value::as_str);
        let findings = record.get("findings");
        let prev_hash = record.get("prev_hash").and_then(Value::as_str);
        let hash = record.get("hash").and_then(Value::as_str);

        let result = sqlx::query(
            "insert into audit_records
                (tenant_id, gateway_id, seq, ts, agent, owner, tool, verdict, policy_version, findings, record)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             on conflict (gateway_id, seq) do nothing",
        )
        .bind(tenant_id)
        .bind(gateway_id)
        .bind(seq)
        .bind(ts)
        .bind(agent)
        .bind(owner)
        .bind(tool)
        .bind(verdict)
        .bind(policy_version)
        .bind(findings)
        .bind(record)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            outcome.duplicates += 1;
            continue;
        }
        outcome.inserted += 1;

        if let (Some(prev_seq), Some(prev_h)) = (last_seq, last_hash.as_deref()) {
            if seq != prev_seq + 1 {
                chain_status = "gap".to_string();
                chain_issue = Some(format!("expected seq {}, got {seq}", prev_seq + 1));
            } else if prev_hash != Some(prev_h) {
                chain_status = "broken".to_string();
                chain_issue = Some(format!(
                    "seq {seq}: prev_hash does not match the last ingested record's hash"
                ));
            }
        }
        last_seq = Some(seq);
        last_hash = hash.map(str::to_string);
    }

    sqlx::query(
        "update gateways
         set last_ingested_seq = $2, last_ingested_hash = $3, chain_status = $4, chain_issue = $5
         where id = $1",
    )
    .bind(gateway_id)
    .bind(last_seq)
    .bind(&last_hash)
    .bind(&chain_status)
    .bind(&chain_issue)
    .execute(pool)
    .await?;

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_is_read_from_the_nested_decision_object() {
        let record = serde_json::json!({
            "seq": 1,
            "decision": { "verdict": "BLOCK", "reason": "no policy permits this call" }
        });
        let verdict = record
            .get("decision")
            .and_then(|d| d.get("verdict"))
            .and_then(Value::as_str);
        assert_eq!(verdict, Some("BLOCK"));
    }
}
