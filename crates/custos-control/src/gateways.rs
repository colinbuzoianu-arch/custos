//! Gateways: enrollment (a one-time token exchanged for a permanent
//! credential), authenticating a gateway's own requests, and heartbeats.
//!
//! A gateway is Control's mirror image of an agent: an agent holds a token
//! *the gateway* verifies by hash; a gateway holds a credential *Control*
//! verifies by hash. Same convention (see `agents::hash_token`), roles
//! reversed.

use crate::AppState;
use crate::agents;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use serde::Serialize;
use sqlx::PgPool;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum GatewaysError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("enrollment token is invalid, expired, or already used")]
    InvalidEnrollToken,
    #[error("a gateway named {0:?} already exists")]
    NameTaken(String),
    #[error("gateway not found")]
    NotFound,
}

const UNIQUE_VIOLATION: &str = "23505";

/// Issues a one-time enrollment token for `tenant_id`, valid for `ttl`.
/// Returns the plaintext once — only its hash is stored, same as an agent
/// token.
pub async fn create_enroll_token(
    pool: &PgPool,
    tenant_id: Uuid,
    created_by_user_id: Uuid,
    ttl: time::Duration,
) -> Result<String, GatewaysError> {
    let token = agents::generate_token();
    let hash = agents::hash_token(&token);
    let expires_at = OffsetDateTime::now_utc() + ttl;
    sqlx::query(
        "insert into gateway_enroll_tokens (tenant_id, token_sha256, created_by_user_id, expires_at)
         values ($1, $2, $3, $4)",
    )
    .bind(tenant_id)
    .bind(&hash)
    .bind(created_by_user_id)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(token)
}

/// What a gateway gets back from a successful enrollment: its id, which
/// tenant it belongs to, and its permanent credential — shown here once and
/// never retrievable again (Control only ever stores its hash from this
/// point on).
pub struct Enrolled {
    pub gateway_id: Uuid,
    pub tenant_id: Uuid,
    pub credential: String,
}

/// Consumes a one-time enrollment token and creates a new gateway. The
/// token check and its `used_at` update happen in the same transaction as
/// the insert, so two concurrent enrollments racing on the same token can't
/// both succeed.
pub async fn enroll(
    pool: &PgPool,
    raw_token: &str,
    gateway_name: &str,
) -> Result<Enrolled, GatewaysError> {
    let hash = agents::hash_token(raw_token);
    let mut tx = pool.begin().await?;

    let row: Option<(Uuid, Uuid)> = sqlx::query_as(
        "select id, tenant_id from gateway_enroll_tokens
         where token_sha256 = $1 and used_at is null and expires_at > now()
         for update",
    )
    .bind(&hash)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((enroll_token_id, tenant_id)) = row else {
        return Err(GatewaysError::InvalidEnrollToken);
    };

    sqlx::query("update gateway_enroll_tokens set used_at = now() where id = $1")
        .bind(enroll_token_id)
        .execute(&mut *tx)
        .await?;

    let credential = agents::generate_token();
    let credential_hash = agents::hash_token(&credential);
    let inserted: Result<(Uuid,), sqlx::Error> = sqlx::query_as(
        "insert into gateways (tenant_id, name, credential_sha256) values ($1, $2, $3) returning id",
    )
    .bind(tenant_id)
    .bind(gateway_name)
    .bind(&credential_hash)
    .fetch_one(&mut *tx)
    .await;
    let gateway_id = match inserted {
        Ok((id,)) => id,
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some(UNIQUE_VIOLATION) => {
            return Err(GatewaysError::NameTaken(gateway_name.to_string()));
        }
        Err(e) => return Err(GatewaysError::Db(e)),
    };

    tx.commit().await?;
    Ok(Enrolled {
        gateway_id,
        tenant_id,
        credential,
    })
}

/// Whoever a gateway's own bearer credential identifies — the gateway-side
/// equivalent of [`crate::sessions::CurrentUser`], checked the same way
/// (extract, hash, look up) but against `gateways.credential_sha256`
/// instead of a session cookie.
pub struct GatewayAuth {
    pub gateway_id: Uuid,
    pub tenant_id: Uuid,
}

impl FromRequestParts<Arc<AppState>> for GatewayAuth {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let credential = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let hash = agents::hash_token(credential);

        let row: Option<(Uuid, Uuid)> =
            sqlx::query_as("select id, tenant_id from gateways where credential_sha256 = $1")
                .bind(&hash)
                .fetch_optional(&state.db)
                .await
                .map_err(|_| StatusCode::UNAUTHORIZED)?;

        let (gateway_id, tenant_id) = row.ok_or(StatusCode::UNAUTHORIZED)?;
        Ok(GatewayAuth {
            gateway_id,
            tenant_id,
        })
    }
}

/// One gateway as the admin API lists it — never its credential hash.
#[derive(Debug, Serialize)]
pub struct Gateway {
    pub id: Uuid,
    pub name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub enrolled_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_heartbeat_at: Option<OffsetDateTime>,
    pub last_version: Option<String>,
    pub last_policy_version: Option<String>,
    pub decisions_allowed: i64,
    pub decisions_blocked: i64,
    pub last_ingested_seq: Option<i64>,
    /// `"ok"`, `"gap"`, or `"broken"` — see `audit::ingest_batch`. Once a
    /// gap or break is flagged, later good records never quietly clear it.
    pub chain_status: String,
    pub chain_issue: Option<String>,
}

type GatewayRow = (
    Uuid,
    String,
    OffsetDateTime,
    Option<OffsetDateTime>,
    Option<String>,
    Option<String>,
    i64,
    i64,
    Option<i64>,
    String,
    Option<String>,
);

fn row_to_gateway(row: GatewayRow) -> Gateway {
    let (
        id,
        name,
        enrolled_at,
        last_heartbeat_at,
        last_version,
        last_policy_version,
        decisions_allowed,
        decisions_blocked,
        last_ingested_seq,
        chain_status,
        chain_issue,
    ) = row;
    Gateway {
        id,
        name,
        enrolled_at,
        last_heartbeat_at,
        last_version,
        last_policy_version,
        decisions_allowed,
        decisions_blocked,
        last_ingested_seq,
        chain_status,
        chain_issue,
    }
}

const GATEWAY_COLUMNS: &str = "id, name, enrolled_at, last_heartbeat_at, last_version, last_policy_version, decisions_allowed, decisions_blocked, last_ingested_seq, chain_status, chain_issue";

pub async fn list_gateways(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<Gateway>, GatewaysError> {
    let sql = format!(
        "select {GATEWAY_COLUMNS} from gateways where tenant_id = $1 order by enrolled_at desc"
    );
    let rows: Vec<GatewayRow> = sqlx::query_as(&sql).bind(tenant_id).fetch_all(pool).await?;
    Ok(rows.into_iter().map(row_to_gateway).collect())
}

pub async fn get_gateway(
    pool: &PgPool,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Gateway, GatewaysError> {
    let sql = format!("select {GATEWAY_COLUMNS} from gateways where tenant_id = $1 and id = $2");
    let row: Option<GatewayRow> = sqlx::query_as(&sql)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await?;
    row.map(row_to_gateway).ok_or(GatewaysError::NotFound)
}

/// Records a heartbeat: the gateway's binary version, the local hash of the
/// policy it's currently enforcing, and its cumulative decision counts
/// (since the gateway started, not since the last heartbeat).
pub async fn record_heartbeat(
    pool: &PgPool,
    gateway_id: Uuid,
    version: &str,
    policy_version: Option<&str>,
    decisions_allowed: i64,
    decisions_blocked: i64,
) -> Result<(), GatewaysError> {
    let result = sqlx::query(
        "update gateways
         set last_heartbeat_at = now(), last_version = $2, last_policy_version = $3,
             decisions_allowed = $4, decisions_blocked = $5
         where id = $1",
    )
    .bind(gateway_id)
    .bind(version)
    .bind(policy_version)
    .bind(decisions_allowed)
    .bind(decisions_blocked)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(GatewaysError::NotFound);
    }
    Ok(())
}
