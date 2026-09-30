//! Ingesting a gateway's audit records: idempotent by `(gateway_id, seq)`,
//! schema-tolerant (stores whatever JSON shape a record has, never rejects
//! a batch over an unrecognized field), and flags chain gaps/breaks per
//! gateway without re-deriving the gateway's own SHA-256 hash chain.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
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
    #[error("invalid cursor: {0}")]
    Cursor(String),
}

/// One ingested (or already-known) audit record, exactly as the search API
/// and the live SSE stream both return it.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecordSummary {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub gateway_id: Uuid,
    pub seq: i64,
    #[serde(with = "time::serde::rfc3339::option")]
    pub ts: Option<OffsetDateTime>,
    pub agent: Option<String>,
    pub owner: Option<String>,
    pub tool: Option<String>,
    pub verdict: Option<String>,
    pub policy_version: Option<String>,
    pub findings: Option<Value>,
    /// The exact JSON the gateway wrote — everything above is extracted
    /// from this for filtering/display convenience.
    pub record: Value,
    #[serde(with = "time::serde::rfc3339")]
    pub ingested_at: OffsetDateTime,
}

type RecordRow = (
    Uuid,
    Uuid,
    Uuid,
    i64,
    Option<OffsetDateTime>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Value>,
    Value,
    OffsetDateTime,
);

fn row_to_summary(row: RecordRow) -> AuditRecordSummary {
    let (
        id,
        tenant_id,
        gateway_id,
        seq,
        ts,
        agent,
        owner,
        tool,
        verdict,
        policy_version,
        findings,
        record,
        ingested_at,
    ) = row;
    AuditRecordSummary {
        id,
        tenant_id,
        gateway_id,
        seq,
        ts,
        agent,
        owner,
        tool,
        verdict,
        policy_version,
        findings,
        record,
        ingested_at,
    }
}

const RECORD_COLUMNS: &str = "id, tenant_id, gateway_id, seq, ts, agent, owner, tool, verdict, policy_version, findings, record, ingested_at";

#[derive(Debug, Default, serde::Serialize)]
pub struct IngestOutcome {
    pub inserted: usize,
    pub duplicates: usize,
    pub skipped: usize,
    /// Newly inserted records only (never duplicates) — what the caller
    /// broadcasts to any live SSE subscribers.
    #[serde(skip)]
    pub inserted_records: Vec<AuditRecordSummary>,
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

        let sql = format!(
            "insert into audit_records
                (tenant_id, gateway_id, seq, ts, agent, owner, tool, verdict, policy_version, findings, record)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             on conflict (gateway_id, seq) do nothing
             returning {RECORD_COLUMNS}"
        );
        let inserted: Option<RecordRow> = sqlx::query_as(&sql)
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
            .fetch_optional(pool)
            .await?;

        let Some(row) = inserted else {
            outcome.duplicates += 1;
            continue;
        };
        outcome.inserted += 1;
        outcome.inserted_records.push(row_to_summary(row));

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

/// Encodes a keyset-pagination cursor from the last row of a page — opaque
/// to callers, just base64 so it's a safe query-string value.
fn encode_cursor(ingested_at: OffsetDateTime, id: Uuid) -> Result<String, AuditError> {
    let ts = ingested_at
        .format(&Rfc3339)
        .map_err(|e| AuditError::Cursor(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(format!("{ts},{id}")))
}

fn decode_cursor(cursor: &str) -> Result<(OffsetDateTime, Uuid), AuditError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|e| AuditError::Cursor(e.to_string()))?;
    let text = String::from_utf8(bytes).map_err(|e| AuditError::Cursor(e.to_string()))?;
    let (ts_str, id_str) = text
        .split_once(',')
        .ok_or_else(|| AuditError::Cursor("malformed cursor".into()))?;
    let ts =
        OffsetDateTime::parse(ts_str, &Rfc3339).map_err(|e| AuditError::Cursor(e.to_string()))?;
    let id = Uuid::parse_str(id_str).map_err(|e| AuditError::Cursor(e.to_string()))?;
    Ok((ts, id))
}

/// Search filters — every field optional except `limit`, which the caller
/// (the HTTP handler) has already clamped to a sane range.
#[derive(Debug, Default)]
pub struct SearchFilters {
    pub agent: Option<String>,
    pub tool: Option<String>,
    pub verdict: Option<String>,
    pub policy_version: Option<String>,
    pub from: Option<OffsetDateTime>,
    pub to: Option<OffsetDateTime>,
    pub cursor: Option<String>,
    pub limit: i64,
}

#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub records: Vec<AuditRecordSummary>,
    /// `Some` only when there may be more results — pass it back as
    /// `cursor` to fetch the next page. Its absence doesn't guarantee
    /// there's nothing more as of a split second later, only that there
    /// wasn't when this page was read.
    pub next_cursor: Option<String>,
}

/// Filters by agent/tool/verdict/policy_version (exact match) and a
/// `ts` range, ordered newest-ingested-first with keyset pagination on
/// `(ingested_at, id)` — not `ts`, since `ts` can be null for a malformed
/// record and a stable sort key can't be.
pub async fn search(
    pool: &PgPool,
    tenant_id: Uuid,
    filters: SearchFilters,
) -> Result<SearchResult, AuditError> {
    let (cursor_ts, cursor_id) = match &filters.cursor {
        Some(c) => {
            let (ts, id) = decode_cursor(c)?;
            (Some(ts), Some(id))
        }
        None => (None, None),
    };

    let sql = format!(
        "select {RECORD_COLUMNS} from audit_records
         where tenant_id = $1
           and ($2::text is null or agent = $2)
           and ($3::text is null or tool = $3)
           and ($4::text is null or verdict = $4)
           and ($5::text is null or policy_version = $5)
           and ($6::timestamptz is null or ts >= $6)
           and ($7::timestamptz is null or ts <= $7)
           and ($8::timestamptz is null or $9::uuid is null or (ingested_at, id) < ($8, $9))
         order by ingested_at desc, id desc
         limit $10"
    );
    let rows: Vec<RecordRow> = sqlx::query_as(&sql)
        .bind(tenant_id)
        .bind(&filters.agent)
        .bind(&filters.tool)
        .bind(&filters.verdict)
        .bind(&filters.policy_version)
        .bind(filters.from)
        .bind(filters.to)
        .bind(cursor_ts)
        .bind(cursor_id)
        .bind(filters.limit)
        .fetch_all(pool)
        .await?;

    let has_more = rows.len() as i64 == filters.limit;
    let records: Vec<AuditRecordSummary> = rows.into_iter().map(row_to_summary).collect();
    let next_cursor = if has_more {
        match records.last() {
            Some(last) => Some(encode_cursor(last.ingested_at, last.id)?),
            None => None,
        }
    } else {
        None
    };

    Ok(SearchResult {
        records,
        next_cursor,
    })
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

    #[test]
    fn cursor_round_trips() {
        let ts = OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap_or_else(|_| panic!("fixed timestamp must be valid"));
        let id = Uuid::new_v4();
        let cursor = match encode_cursor(ts, id) {
            Ok(c) => c,
            Err(e) => panic!("{e}"),
        };
        let (decoded_ts, decoded_id) = match decode_cursor(&cursor) {
            Ok(v) => v,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(decoded_ts, ts);
        assert_eq!(decoded_id, id);
    }

    #[test]
    fn a_malformed_cursor_is_rejected_not_panicked_on() {
        for bad in ["not-base64!!", "", "aGVsbG8"] {
            assert!(decode_cursor(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
