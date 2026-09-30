//! Agents: CRUD, token issue/rotate, and the admin audit trail every change
//! writes to. Builds on `users`/`sessions` (session 9).

use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AgentsError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("agent not found")]
    NotFound,
    #[error("an agent named {0:?} already exists")]
    NameTaken(String),
}

/// Postgres' code for a unique-constraint violation.
const UNIQUE_VIOLATION: &str = "23505";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Active,
    Disabled,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Active => "active",
            Status::Disabled => "disabled",
        }
    }
}

impl std::str::FromStr for Status {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Status::Active),
            "disabled" => Ok(Status::Disabled),
            other => Err(format!("unknown status {other:?}")),
        }
    }
}

/// What the API returns for an agent. Deliberately has no `token_sha256`
/// field — that's never exposed again after the issue/rotate response that
/// showed the plaintext once.
#[derive(Debug, Serialize)]
pub struct Agent {
    pub id: Uuid,
    pub name: String,
    pub owner_user_id: Option<Uuid>,
    pub description: Option<String>,
    pub status: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expiry_date: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

type AgentRow = (
    Uuid,
    String,
    Option<Uuid>,
    Option<String>,
    String,
    Option<OffsetDateTime>,
    OffsetDateTime,
    OffsetDateTime,
);

fn row_to_agent(row: AgentRow) -> Agent {
    let (id, name, owner_user_id, description, status, expiry_date, created_at, updated_at) = row;
    Agent {
        id,
        name,
        owner_user_id,
        description,
        status,
        expiry_date,
        created_at,
        updated_at,
    }
}

const AGENT_COLUMNS: &str =
    "id, name, owner_user_id, description, status, expiry_date, created_at, updated_at";

pub async fn create_agent(
    pool: &PgPool,
    tenant_id: Uuid,
    name: &str,
    owner_user_id: Option<Uuid>,
    description: Option<&str>,
    expiry_date: Option<OffsetDateTime>,
) -> Result<Agent, AgentsError> {
    let sql = format!(
        "insert into agents (tenant_id, name, owner_user_id, description, expiry_date)
         values ($1, $2, $3, $4, $5) returning {AGENT_COLUMNS}"
    );
    let result: Result<AgentRow, sqlx::Error> = sqlx::query_as(&sql)
        .bind(tenant_id)
        .bind(name)
        .bind(owner_user_id)
        .bind(description)
        .bind(expiry_date)
        .fetch_one(pool)
        .await;
    match result {
        Ok(row) => Ok(row_to_agent(row)),
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some(UNIQUE_VIOLATION) => {
            Err(AgentsError::NameTaken(name.to_string()))
        }
        Err(e) => Err(AgentsError::Db(e)),
    }
}

pub async fn list_agents(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<Agent>, AgentsError> {
    let sql =
        format!("select {AGENT_COLUMNS} from agents where tenant_id = $1 order by created_at desc");
    let rows: Vec<AgentRow> = sqlx::query_as(&sql).bind(tenant_id).fetch_all(pool).await?;
    Ok(rows.into_iter().map(row_to_agent).collect())
}

pub async fn get_agent(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<Agent, AgentsError> {
    let sql = format!("select {AGENT_COLUMNS} from agents where tenant_id = $1 and id = $2");
    let row: Option<AgentRow> = sqlx::query_as(&sql)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await?;
    row.map(row_to_agent).ok_or(AgentsError::NotFound)
}

/// A PATCH: only the fields present get changed. There's no way in this
/// first cut to *clear* `owner_user_id`/`description`/`expiry_date` back to
/// null via PATCH, only to set a new value — a deliberate v0 simplification
/// (a `null` in the JSON body and "field not sent" would need to be told
/// apart, e.g. `Option<Option<T>>`, which isn't worth the complexity yet).
#[derive(Debug, Default)]
pub struct AgentPatch {
    pub name: Option<String>,
    pub owner_user_id: Option<Uuid>,
    pub description: Option<String>,
    pub status: Option<Status>,
    pub expiry_date: Option<OffsetDateTime>,
}

pub async fn update_agent(
    pool: &PgPool,
    tenant_id: Uuid,
    id: Uuid,
    patch: AgentPatch,
) -> Result<Agent, AgentsError> {
    let sql = format!(
        "update agents set
            name = coalesce($3, name),
            owner_user_id = coalesce($4, owner_user_id),
            description = coalesce($5, description),
            status = coalesce($6, status),
            expiry_date = coalesce($7, expiry_date),
            updated_at = now()
         where tenant_id = $1 and id = $2
         returning {AGENT_COLUMNS}"
    );
    let name_for_error = patch.name.clone();
    let result: Result<AgentRow, sqlx::Error> = sqlx::query_as(&sql)
        .bind(tenant_id)
        .bind(id)
        .bind(patch.name)
        .bind(patch.owner_user_id)
        .bind(patch.description)
        .bind(patch.status.map(Status::as_str))
        .bind(patch.expiry_date)
        .fetch_one(pool)
        .await;
    match result {
        Ok(row) => Ok(row_to_agent(row)),
        Err(sqlx::Error::RowNotFound) => Err(AgentsError::NotFound),
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some(UNIQUE_VIOLATION) => {
            Err(AgentsError::NameTaken(name_for_error.unwrap_or_default()))
        }
        Err(e) => Err(AgentsError::Db(e)),
    }
}

pub async fn delete_agent(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<(), AgentsError> {
    let result = sqlx::query("delete from agents where tenant_id = $1 and id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AgentsError::NotFound);
    }
    Ok(())
}

/// A fresh, unguessable token: two random UUID v4s concatenated (244 bits
/// of randomness between them) rather than pulling in a CSPRNG crate
/// directly for this alone.
pub(crate) fn generate_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// SHA-256 hex — the exact same convention as the gateway's own
/// `custos hash-token`, so a token issued here is checked the same way
/// there.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Issues a new token for the agent, replacing any previous one (this is
/// also how rotation works — there's only ever one live token). Returns
/// the plaintext, which the caller must show now: it is never retrievable
/// again, only its hash is stored.
pub async fn issue_token(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<String, AgentsError> {
    let token = generate_token();
    let hash = hash_token(&token);
    let result = sqlx::query(
        "update agents set token_sha256 = $3, updated_at = now() where tenant_id = $1 and id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(&hash)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AgentsError::NotFound);
    }
    Ok(token)
}

/// Records one admin-gated change. Never carries a token value or hash,
/// even for token-related actions — `detail` is for things like the old
/// and new field values on an update, not secrets.
pub async fn record_admin_audit(
    pool: &PgPool,
    tenant_id: Uuid,
    actor_user_id: Uuid,
    action: &str,
    target_type: &str,
    target_id: Option<Uuid>,
    detail: Option<serde_json::Value>,
) {
    let result = sqlx::query(
        "insert into admin_audit (tenant_id, actor_user_id, action, target_type, target_id, detail)
         values ($1, $2, $3, $4, $5, $6)",
    )
    .bind(tenant_id)
    .bind(actor_user_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(detail)
    .execute(pool)
    .await;
    if let Err(e) = result {
        tracing::error!(error = %e, action, target_type, "failed to write admin_audit");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_through_its_string_form() {
        for status in [Status::Active, Status::Disabled] {
            let s = status.as_str();
            let parsed: Status = s.parse().unwrap_or_else(|_| panic!("{s} must parse back"));
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn unknown_status_string_is_rejected() {
        assert!("pending".parse::<Status>().is_err());
    }

    #[test]
    fn generated_tokens_are_unique_and_long() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
        assert!(a.len() >= 32);
    }

    #[test]
    fn token_hash_matches_the_gateway_convention() {
        // custos_gateway::hash_token(t) == hex::encode(Sha256::digest(t)) -
        // this must compute the exact same thing without depending on the
        // gateway crate (control has no reason to link against it).
        let expected = hex::encode(Sha256::digest(b"a-test-token"));
        assert_eq!(hash_token("a-test-token"), expected);
    }
}
