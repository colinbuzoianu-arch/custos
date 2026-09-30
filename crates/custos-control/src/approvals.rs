//! Human approval for held tool calls. A gateway creates one of these when
//! a Cedar `@hold` policy fires, then polls its status ([`get`]) until it
//! leaves `pending` or the gateway's own timeout elapses — see
//! `docs/decisions/0008-hold-and-approval.md` for why that's plain polling
//! rather than a true server-side long-poll. An `approver`/`admin` user
//! resolves it via [`resolve`], which enforces `four_eyes` before anything
//! else can.

use serde::Serialize;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ApprovalsError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("approval not found")]
    NotFound,
    #[error("this approval was already resolved")]
    AlreadyResolved,
    #[error("the agent's own owner cannot resolve a four-eyes hold")]
    FourEyesViolation,
}

#[derive(Debug, Serialize)]
pub struct Approval {
    pub id: Uuid,
    pub gateway_id: Uuid,
    pub agent: String,
    pub tool: String,
    pub findings: Option<serde_json::Value>,
    pub reason: String,
    pub four_eyes: bool,
    pub status: String,
    pub comment: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

type ApprovalRow = (
    Uuid,
    Uuid,
    String,
    String,
    Option<serde_json::Value>,
    String,
    bool,
    String,
    Option<String>,
    OffsetDateTime,
);

fn row_to_approval(row: ApprovalRow) -> Approval {
    let (id, gateway_id, agent, tool, findings, reason, four_eyes, status, comment, created_at) =
        row;
    Approval {
        id,
        gateway_id,
        agent,
        tool,
        findings,
        reason,
        four_eyes,
        status,
        comment,
        created_at,
    }
}

const APPROVAL_COLUMNS: &str =
    "id, gateway_id, agent, tool, findings, reason, four_eyes, status, comment, created_at";

/// What a gateway sends to open a new approval — bundled into one struct
/// rather than passed field by field, since [`create`] would otherwise
/// need eight separate arguments.
pub struct NewApproval<'a> {
    pub gateway_id: Uuid,
    pub agent: &'a str,
    pub tool: &'a str,
    pub findings: Option<&'a serde_json::Value>,
    pub reason: &'a str,
    pub four_eyes: bool,
}

/// Creates a new pending approval. Called once per held call, by the
/// gateway that held it.
pub async fn create(
    pool: &PgPool,
    tenant_id: Uuid,
    new: NewApproval<'_>,
) -> Result<Approval, ApprovalsError> {
    let sql = format!(
        "insert into approvals (tenant_id, gateway_id, agent, tool, findings, reason, four_eyes)
         values ($1, $2, $3, $4, $5, $6, $7)
         returning {APPROVAL_COLUMNS}"
    );
    let row: ApprovalRow = sqlx::query_as(&sql)
        .bind(tenant_id)
        .bind(new.gateway_id)
        .bind(new.agent)
        .bind(new.tool)
        .bind(new.findings)
        .bind(new.reason)
        .bind(new.four_eyes)
        .fetch_one(pool)
        .await?;
    Ok(row_to_approval(row))
}

/// The gateway-facing poll: scoped to the exact gateway that created it,
/// so one gateway can never read another's pending approval even within
/// the same tenant.
pub async fn get_for_gateway(
    pool: &PgPool,
    tenant_id: Uuid,
    gateway_id: Uuid,
    id: Uuid,
) -> Result<Approval, ApprovalsError> {
    let sql = format!(
        "select {APPROVAL_COLUMNS} from approvals where tenant_id = $1 and gateway_id = $2 and id = $3"
    );
    let row: Option<ApprovalRow> = sqlx::query_as(&sql)
        .bind(tenant_id)
        .bind(gateway_id)
        .bind(id)
        .fetch_optional(pool)
        .await?;
    row.map(row_to_approval).ok_or(ApprovalsError::NotFound)
}

/// The human-facing read: any approval in the tenant, not scoped to a
/// gateway - an approver isn't tied to one.
pub async fn get(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<Approval, ApprovalsError> {
    let sql = format!("select {APPROVAL_COLUMNS} from approvals where tenant_id = $1 and id = $2");
    let row: Option<ApprovalRow> = sqlx::query_as(&sql)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await?;
    row.map(row_to_approval).ok_or(ApprovalsError::NotFound)
}

pub async fn list_pending(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<Approval>, ApprovalsError> {
    let sql = format!(
        "select {APPROVAL_COLUMNS} from approvals
         where tenant_id = $1 and status = 'pending'
         order by created_at asc"
    );
    let rows: Vec<ApprovalRow> = sqlx::query_as(&sql).bind(tenant_id).fetch_all(pool).await?;
    Ok(rows.into_iter().map(row_to_approval).collect())
}

/// Resolves a pending approval. `Err(FourEyesViolation)` if the approval
/// requires four eyes and `approver_user_id` is the agent's own owner —
/// checked by name against the `agents` table, since that's the only
/// identity a gateway's `ToolCall.agent` string maps to on this side.
/// Nothing is written when this check fails: the approval stays pending,
/// exactly as if nobody had acted on it.
pub async fn resolve(
    pool: &PgPool,
    tenant_id: Uuid,
    id: Uuid,
    approver_user_id: Uuid,
    approve: bool,
    comment: Option<&str>,
) -> Result<Approval, ApprovalsError> {
    let approval = get(pool, tenant_id, id).await?;
    if approval.status != "pending" {
        return Err(ApprovalsError::AlreadyResolved);
    }

    if approval.four_eyes {
        let owner: Option<(Option<Uuid>,)> =
            sqlx::query_as("select owner_user_id from agents where tenant_id = $1 and name = $2")
                .bind(tenant_id)
                .bind(&approval.agent)
                .fetch_optional(pool)
                .await?;
        if owner.and_then(|(o,)| o) == Some(approver_user_id) {
            return Err(ApprovalsError::FourEyesViolation);
        }
    }

    let status = if approve { "approved" } else { "rejected" };
    let sql = format!(
        "update approvals
         set status = $3, approver_user_id = $4, comment = $5, resolved_at = now()
         where tenant_id = $1 and id = $2 and status = 'pending'
         returning {APPROVAL_COLUMNS}"
    );
    let row: Option<ApprovalRow> = sqlx::query_as(&sql)
        .bind(tenant_id)
        .bind(id)
        .bind(status)
        .bind(approver_user_id)
        .bind(comment)
        .fetch_optional(pool)
        .await?;
    // `status = 'pending'` in the WHERE clause makes this update
    // itself the race-safe check: if two approvers resolve the same
    // approval at once, only the first one's UPDATE matches a row.
    row.map(row_to_approval)
        .ok_or(ApprovalsError::AlreadyResolved)
}
