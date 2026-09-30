//! Custos Control: multi-gateway management, audit search, approvals.
//!
//! Session 9 (this file, for now): the skeleton — a Postgres pool, embedded
//! migrations, and `/healthz`. Users, sessions, and login all follow in the
//! same session's later commits. See `docs/decisions/0002-control-plane.md`
//! for why this exists and how it's meant to be deployed, and `NOTICE.md`
//! for why this crate — unlike the rest of the workspace — isn't Apache-2.0.

pub mod agents;
pub mod approvals;
pub mod audit;
pub mod config;
pub mod gateways;
pub mod overview;
pub mod policies;
pub mod sessions;
pub mod users;

use agents::{AgentPatch, AgentsError, Status};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::{
    Json, Router,
    routing::{get, post},
};
use axum_extra::extract::cookie::CookieJar;
use ed25519_dalek::SigningKey;
use gateways::{GatewayAuth, GatewaysError};
use policies::PoliciesError;
use serde::Deserialize;
use sessions::{AdminUser, ApproverUser, CurrentUser, LoginError, RateLimiter};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::Arc;
use uuid::Uuid;

pub struct AppState {
    pub db: PgPool,
    pub login_attempts: RateLimiter,
    /// Signs every policy bundle on publish. See
    /// `docs/decisions/0003-policy-bundle.md`.
    pub policy_signing_key: SigningKey,
    /// Fans out every newly ingested audit record to `/audit/stream`
    /// subscribers. A `send` with no subscribers is the normal case (no
    /// dashboard open) and isn't an error.
    pub audit_events: tokio::sync::broadcast::Sender<audit::AuditRecordSummary>,
}

/// How many audit events a lagging SSE subscriber can fall behind before
/// old ones are dropped for it (it still gets a `Lagged` notice, handled as
/// "skip ahead," never a hard disconnect).
pub const AUDIT_EVENTS_CAPACITY: usize = 1024;

/// Connects to Postgres, failing fast if it's unreachable rather than
/// starting up unable to do anything.
pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
}

/// Applies every migration in `migrations/` that hasn't run yet. Safe to
/// call on every startup — already-applied migrations are skipped.
pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

/// Everything but `/healthz`, kept separate so it can be nested under
/// `/api` — the dashboard is a single-page app whose own client-side
/// routes live at paths like `/agents`, which would otherwise collide with
/// this API's routes of the same name once both are served from one origin.
fn api_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/login", post(login_handler))
        .route("/logout", post(logout_handler))
        .route("/me", get(me_handler))
        .route("/admin/ping", get(|_admin: AdminUser| async { "ok" }))
        .route(
            "/agents",
            post(create_agent_handler).get(list_agents_handler),
        )
        .route(
            "/agents/{id}",
            get(get_agent_handler)
                .patch(update_agent_handler)
                .delete(delete_agent_handler),
        )
        .route("/agents/{id}/token", post(issue_token_handler))
        .route(
            "/policies",
            post(save_policy_draft_handler).get(list_policy_versions_handler),
        )
        .route("/policies/diff", get(diff_policy_versions_handler))
        .route("/policies/validate", post(validate_policy_handler))
        .route("/policies/{version}", get(get_policy_version_handler))
        .route(
            "/policies/{version}/publish",
            post(publish_policy_version_handler),
        )
        .route("/enroll", post(enroll_handler))
        .route("/gateways/enroll-tokens", post(create_enroll_token_handler))
        .route("/gateways", get(list_gateways_handler))
        .route("/gateways/bundle", get(gateway_bundle_handler))
        .route("/gateways/heartbeat", post(heartbeat_handler))
        .route("/gateways/audit/batch", post(ingest_audit_batch_handler))
        .route("/gateways/approvals", post(create_approval_handler))
        .route(
            "/gateways/approvals/{id}",
            get(get_approval_for_gateway_handler),
        )
        .route("/approvals", get(list_pending_approvals_handler))
        .route("/approvals/{id}/approve", post(approve_handler))
        .route("/approvals/{id}/reject", post(reject_handler))
        .route("/audit", get(search_audit_handler))
        .route("/audit/stream", get(audit_stream_handler))
        .route("/overview", get(overview_handler))
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .nest("/api", api_router())
        .with_state(state)
}

#[derive(Deserialize)]
struct LoginRequest {
    tenant: String,
    email: String,
    password: String,
}

async fn login_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let result = sessions::login(
        &state.db,
        &state.login_attempts,
        &req.tenant,
        &req.email,
        &req.password,
    )
    .await;

    match result {
        Ok(logged_in) => {
            let jar = jar.add(sessions::session_cookie(logged_in.session_id));
            (
                StatusCode::OK,
                jar,
                Json(serde_json::json!({ "csrf_token": logged_in.csrf_token, "role": logged_in.role.as_str() })),
            )
                .into_response()
        }
        Err(LoginError::LockedOut) => StatusCode::TOO_MANY_REQUESTS.into_response(),
        Err(LoginError::InvalidCredentials) => StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "login failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn logout_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    user: CurrentUser,
) -> impl IntoResponse {
    if let Err(status) = user.check_csrf(&headers) {
        return status.into_response();
    }
    match sessions::logout(&state.db, user.session_id).await {
        Ok(()) => {
            let jar = jar.add(sessions::clear_session_cookie());
            (StatusCode::OK, jar).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "logout failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Lets the dashboard recover "am I logged in, and as what role" after a
/// page refresh — the HttpOnly session cookie survives one, but anything
/// the page only held in memory (role, CSRF token) doesn't. `401` via
/// `CurrentUser`'s own extractor is exactly "not logged in."
async fn me_handler(user: CurrentUser) -> impl IntoResponse {
    Json(serde_json::json!({
        "role": user.role.as_str(),
        "csrf_token": user.csrf_token(),
    }))
}

#[derive(Deserialize)]
struct CreateAgentRequest {
    name: String,
    owner_user_id: Option<Uuid>,
    description: Option<String>,
    expiry_date: Option<String>,
}

/// Parses an optional RFC3339 timestamp from a request body, `Bad Request`
/// on anything malformed rather than silently dropping it.
fn parse_expiry(s: &Option<String>) -> Result<Option<time::OffsetDateTime>, StatusCode> {
    match s {
        None => Ok(None),
        Some(s) => time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .map(Some)
            .map_err(|_| StatusCode::BAD_REQUEST),
    }
}

fn agents_error_response(e: AgentsError) -> axum::response::Response {
    match e {
        AgentsError::NotFound => StatusCode::NOT_FOUND.into_response(),
        AgentsError::NameTaken(_) => StatusCode::CONFLICT.into_response(),
        AgentsError::Db(e) => {
            tracing::error!(error = %e, "agents db error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn create_agent_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(user): AdminUser,
    headers: HeaderMap,
    Json(req): Json<CreateAgentRequest>,
) -> impl IntoResponse {
    if let Err(status) = user.check_csrf(&headers) {
        return status.into_response();
    }
    let expiry_date = match parse_expiry(&req.expiry_date) {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };
    match agents::create_agent(
        &state.db,
        user.tenant_id,
        &req.name,
        req.owner_user_id,
        req.description.as_deref(),
        expiry_date,
    )
    .await
    {
        Ok(agent) => {
            agents::record_admin_audit(
                &state.db,
                user.tenant_id,
                user.user_id,
                "create",
                "agent",
                Some(agent.id),
                None,
            )
            .await;
            (StatusCode::CREATED, Json(agent)).into_response()
        }
        Err(e) => agents_error_response(e),
    }
}

async fn list_agents_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(user): AdminUser,
) -> impl IntoResponse {
    match agents::list_agents(&state.db, user.tenant_id).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => agents_error_response(e),
    }
}

async fn get_agent_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(user): AdminUser,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match agents::get_agent(&state.db, user.tenant_id, id).await {
        Ok(agent) => Json(agent).into_response(),
        Err(e) => agents_error_response(e),
    }
}

#[derive(Deserialize, Default)]
struct UpdateAgentRequest {
    name: Option<String>,
    owner_user_id: Option<Uuid>,
    description: Option<String>,
    status: Option<String>,
    expiry_date: Option<String>,
}

async fn update_agent_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(user): AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateAgentRequest>,
) -> impl IntoResponse {
    if let Err(status) = user.check_csrf(&headers) {
        return status.into_response();
    }
    let expiry_date = match parse_expiry(&req.expiry_date) {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };
    let status_val: Option<Status> = match req.status.as_deref().map(str::parse) {
        Some(Ok(s)) => Some(s),
        Some(Err(_)) => return StatusCode::BAD_REQUEST.into_response(),
        None => None,
    };
    let patch = AgentPatch {
        name: req.name,
        owner_user_id: req.owner_user_id,
        description: req.description,
        status: status_val,
        expiry_date,
    };
    match agents::update_agent(&state.db, user.tenant_id, id, patch).await {
        Ok(agent) => {
            agents::record_admin_audit(
                &state.db,
                user.tenant_id,
                user.user_id,
                "update",
                "agent",
                Some(agent.id),
                None,
            )
            .await;
            Json(agent).into_response()
        }
        Err(e) => agents_error_response(e),
    }
}

async fn delete_agent_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(user): AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if let Err(status) = user.check_csrf(&headers) {
        return status.into_response();
    }
    match agents::delete_agent(&state.db, user.tenant_id, id).await {
        Ok(()) => {
            agents::record_admin_audit(
                &state.db,
                user.tenant_id,
                user.user_id,
                "delete",
                "agent",
                Some(id),
                None,
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => agents_error_response(e),
    }
}

async fn issue_token_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(user): AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if let Err(status) = user.check_csrf(&headers) {
        return status.into_response();
    }
    match agents::issue_token(&state.db, user.tenant_id, id).await {
        Ok(token) => {
            agents::record_admin_audit(
                &state.db,
                user.tenant_id,
                user.user_id,
                "issue_token",
                "agent",
                Some(id),
                None,
            )
            .await;
            Json(serde_json::json!({ "token": token })).into_response()
        }
        Err(e) => agents_error_response(e),
    }
}

fn policies_error_response(e: PoliciesError) -> axum::response::Response {
    match e {
        PoliciesError::NotFound => StatusCode::NOT_FOUND.into_response(),
        PoliciesError::Invalid(reason) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": reason })),
        )
            .into_response(),
        PoliciesError::Db(e) => {
            tracing::error!(error = %e, "policies db error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        PoliciesError::Bundle(e) => {
            tracing::error!(error = %e, "failed to build policy bundle");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct SavePolicyDraftRequest {
    policy_text: String,
    schema_text: Option<String>,
    message: Option<String>,
}

async fn save_policy_draft_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(user): AdminUser,
    headers: HeaderMap,
    Json(req): Json<SavePolicyDraftRequest>,
) -> impl IntoResponse {
    if let Err(status) = user.check_csrf(&headers) {
        return status.into_response();
    }
    match policies::save_draft(
        &state.db,
        user.tenant_id,
        user.user_id,
        &req.policy_text,
        req.schema_text.as_deref(),
        req.message.as_deref(),
    )
    .await
    {
        Ok(version) => {
            agents::record_admin_audit(
                &state.db,
                user.tenant_id,
                user.user_id,
                "save_draft",
                "policy_version",
                Some(version.id),
                None,
            )
            .await;
            (StatusCode::CREATED, Json(version)).into_response()
        }
        Err(e) => policies_error_response(e),
    }
}

#[derive(Deserialize)]
struct ValidatePolicyRequest {
    policy_text: String,
    schema_text: Option<String>,
}

/// Checks Cedar source without saving anything — "validate as you type" in
/// the dashboard would otherwise mean one new `policy_versions` row per
/// keystroke if it called `save_draft` directly.
async fn validate_policy_handler(
    AdminUser(user): AdminUser,
    headers: HeaderMap,
    Json(req): Json<ValidatePolicyRequest>,
) -> impl IntoResponse {
    if let Err(status) = user.check_csrf(&headers) {
        return status.into_response();
    }
    let validation_error = policies::validate(&req.policy_text, req.schema_text.as_deref());
    Json(serde_json::json!({
        "valid": validation_error.is_none(),
        "validation_error": validation_error,
    }))
    .into_response()
}

async fn list_policy_versions_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(user): AdminUser,
) -> impl IntoResponse {
    match policies::list_versions(&state.db, user.tenant_id).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => policies_error_response(e),
    }
}

async fn get_policy_version_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(user): AdminUser,
    Path(version): Path<i32>,
) -> impl IntoResponse {
    match policies::get_version(&state.db, user.tenant_id, version).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => policies_error_response(e),
    }
}

#[derive(Deserialize)]
struct DiffQuery {
    from: i32,
    to: i32,
}

async fn diff_policy_versions_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(user): AdminUser,
    Query(q): Query<DiffQuery>,
) -> impl IntoResponse {
    match policies::diff_versions(&state.db, user.tenant_id, q.from, q.to).await {
        Ok(diff) => diff.into_response(),
        Err(e) => policies_error_response(e),
    }
}

async fn publish_policy_version_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(user): AdminUser,
    headers: HeaderMap,
    Path(version): Path<i32>,
) -> impl IntoResponse {
    if let Err(status) = user.check_csrf(&headers) {
        return status.into_response();
    }
    match policies::publish(
        &state.db,
        user.tenant_id,
        version,
        &state.policy_signing_key,
    )
    .await
    {
        Ok((updated, signed)) => {
            agents::record_admin_audit(
                &state.db,
                user.tenant_id,
                user.user_id,
                "publish",
                "policy_version",
                Some(updated.id),
                None,
            )
            .await;
            Json(signed).into_response()
        }
        Err(e) => policies_error_response(e),
    }
}

fn gateways_error_response(e: GatewaysError) -> axum::response::Response {
    match e {
        GatewaysError::NotFound => StatusCode::NOT_FOUND.into_response(),
        GatewaysError::InvalidEnrollToken => StatusCode::UNAUTHORIZED.into_response(),
        GatewaysError::NameTaken(_) => StatusCode::CONFLICT.into_response(),
        GatewaysError::Db(e) => {
            tracing::error!(error = %e, "gateways db error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// How long a `custos enroll` token stays usable before it must be reissued.
const ENROLL_TOKEN_TTL: time::Duration = time::Duration::hours(1);

async fn create_enroll_token_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(user): AdminUser,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = user.check_csrf(&headers) {
        return status.into_response();
    }
    match gateways::create_enroll_token(&state.db, user.tenant_id, user.user_id, ENROLL_TOKEN_TTL)
        .await
    {
        Ok(token) => {
            agents::record_admin_audit(
                &state.db,
                user.tenant_id,
                user.user_id,
                "create_enroll_token",
                "gateway",
                None,
                None,
            )
            .await;
            Json(serde_json::json!({ "token": token })).into_response()
        }
        Err(e) => gateways_error_response(e),
    }
}

#[derive(Deserialize)]
struct EnrollRequest {
    token: String,
    name: String,
}

async fn enroll_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollRequest>,
) -> impl IntoResponse {
    match gateways::enroll(&state.db, &req.token, &req.name).await {
        Ok(enrolled) => {
            let control_public_key =
                hex::encode(state.policy_signing_key.verifying_key().to_bytes());
            Json(serde_json::json!({
                "gateway_id": enrolled.gateway_id,
                "credential": enrolled.credential,
                "control_public_key": control_public_key,
            }))
            .into_response()
        }
        Err(e) => gateways_error_response(e),
    }
}

async fn list_gateways_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(user): AdminUser,
) -> impl IntoResponse {
    match gateways::list_gateways(&state.db, user.tenant_id).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => gateways_error_response(e),
    }
}

async fn gateway_bundle_handler(
    State(state): State<Arc<AppState>>,
    auth: GatewayAuth,
    headers: HeaderMap,
) -> impl IntoResponse {
    match policies::latest_published_bundle(&state.db, auth.tenant_id).await {
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Ok(Some((version, signed))) => {
            let etag = version.to_string();
            let if_none_match = headers
                .get(header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok());
            if if_none_match == Some(etag.as_str()) {
                return StatusCode::NOT_MODIFIED.into_response();
            }
            (StatusCode::OK, [(header::ETAG, etag)], Json(signed)).into_response()
        }
        Err(e) => policies_error_response(e),
    }
}

#[derive(Deserialize)]
struct HeartbeatRequest {
    version: String,
    policy_version: Option<String>,
    decisions_allowed: i64,
    decisions_blocked: i64,
}

async fn heartbeat_handler(
    State(state): State<Arc<AppState>>,
    auth: GatewayAuth,
    Json(req): Json<HeartbeatRequest>,
) -> impl IntoResponse {
    match gateways::record_heartbeat(
        &state.db,
        auth.gateway_id,
        &req.version,
        req.policy_version.as_deref(),
        req.decisions_allowed,
        req.decisions_blocked,
    )
    .await
    {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => gateways_error_response(e),
    }
}

fn audit_error_response(e: audit::AuditError) -> axum::response::Response {
    match e {
        audit::AuditError::GatewayNotFound => StatusCode::NOT_FOUND.into_response(),
        audit::AuditError::Cursor(_) => StatusCode::BAD_REQUEST.into_response(),
        audit::AuditError::Db(e) => {
            tracing::error!(error = %e, "audit db error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn ingest_audit_batch_handler(
    State(state): State<Arc<AppState>>,
    auth: GatewayAuth,
    Json(records): Json<Vec<serde_json::Value>>,
) -> impl IntoResponse {
    match audit::ingest_batch(&state.db, auth.tenant_id, auth.gateway_id, &records).await {
        Ok(outcome) => {
            for record in &outcome.inserted_records {
                // No subscribers is the common case (no dashboard open) and
                // not an error - `send` only fails when nobody's listening.
                let _ = state.audit_events.send(record.clone());
            }
            (StatusCode::OK, Json(outcome)).into_response()
        }
        Err(e) => audit_error_response(e),
    }
}

fn approvals_error_response(e: approvals::ApprovalsError) -> axum::response::Response {
    match e {
        approvals::ApprovalsError::NotFound => StatusCode::NOT_FOUND.into_response(),
        approvals::ApprovalsError::AlreadyResolved => StatusCode::CONFLICT.into_response(),
        approvals::ApprovalsError::FourEyesViolation => StatusCode::FORBIDDEN.into_response(),
        approvals::ApprovalsError::Db(e) => {
            tracing::error!(error = %e, "approvals db error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct CreateApprovalRequest {
    agent: String,
    tool: String,
    findings: Option<serde_json::Value>,
    reason: String,
    #[serde(default)]
    four_eyes: bool,
}

async fn create_approval_handler(
    State(state): State<Arc<AppState>>,
    auth: GatewayAuth,
    Json(req): Json<CreateApprovalRequest>,
) -> impl IntoResponse {
    match approvals::create(
        &state.db,
        auth.tenant_id,
        approvals::NewApproval {
            gateway_id: auth.gateway_id,
            agent: &req.agent,
            tool: &req.tool,
            findings: req.findings.as_ref(),
            reason: &req.reason,
            four_eyes: req.four_eyes,
        },
    )
    .await
    {
        Ok(approval) => (StatusCode::CREATED, Json(approval)).into_response(),
        Err(e) => approvals_error_response(e),
    }
}

async fn get_approval_for_gateway_handler(
    State(state): State<Arc<AppState>>,
    auth: GatewayAuth,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match approvals::get_for_gateway(&state.db, auth.tenant_id, auth.gateway_id, id).await {
        Ok(approval) => Json(approval).into_response(),
        Err(e) => approvals_error_response(e),
    }
}

async fn list_pending_approvals_handler(
    State(state): State<Arc<AppState>>,
    ApproverUser(user): ApproverUser,
) -> impl IntoResponse {
    match approvals::list_pending(&state.db, user.tenant_id).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => approvals_error_response(e),
    }
}

#[derive(Deserialize, Default)]
struct ResolveApprovalRequest {
    comment: Option<String>,
}

async fn resolve_approval(
    state: &Arc<AppState>,
    user: &CurrentUser,
    id: Uuid,
    approve: bool,
    comment: Option<&str>,
) -> axum::response::Response {
    match approvals::resolve(
        &state.db,
        user.tenant_id,
        id,
        user.user_id,
        approve,
        comment,
    )
    .await
    {
        Ok(approval) => {
            agents::record_admin_audit(
                &state.db,
                user.tenant_id,
                user.user_id,
                if approve { "approve" } else { "reject" },
                "approval",
                Some(approval.id),
                comment.map(|c| serde_json::json!({ "comment": c })),
            )
            .await;
            Json(approval).into_response()
        }
        Err(e) => approvals_error_response(e),
    }
}

async fn approve_handler(
    State(state): State<Arc<AppState>>,
    ApproverUser(user): ApproverUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ResolveApprovalRequest>,
) -> impl IntoResponse {
    if let Err(status) = user.check_csrf(&headers) {
        return status.into_response();
    }
    resolve_approval(&state, &user, id, true, req.comment.as_deref()).await
}

async fn reject_handler(
    State(state): State<Arc<AppState>>,
    ApproverUser(user): ApproverUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ResolveApprovalRequest>,
) -> impl IntoResponse {
    if let Err(status) = user.check_csrf(&headers) {
        return status.into_response();
    }
    resolve_approval(&state, &user, id, false, req.comment.as_deref()).await
}

#[derive(Deserialize)]
struct AuditSearchQuery {
    agent: Option<String>,
    tool: Option<String>,
    verdict: Option<String>,
    policy_version: Option<String>,
    from: Option<String>,
    to: Option<String>,
    cursor: Option<String>,
    limit: Option<i64>,
}

/// Parses an optional RFC3339 timestamp from a query parameter, `Bad
/// Request` on anything malformed.
fn parse_query_timestamp(s: &Option<String>) -> Result<Option<time::OffsetDateTime>, StatusCode> {
    match s {
        None => Ok(None),
        Some(s) => time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .map(Some)
            .map_err(|_| StatusCode::BAD_REQUEST),
    }
}

async fn search_audit_handler(
    State(state): State<Arc<AppState>>,
    user: CurrentUser,
    Query(q): Query<AuditSearchQuery>,
) -> impl IntoResponse {
    let from = match parse_query_timestamp(&q.from) {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };
    let to = match parse_query_timestamp(&q.to) {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };
    let filters = audit::SearchFilters {
        agent: q.agent,
        tool: q.tool,
        verdict: q.verdict,
        policy_version: q.policy_version,
        from,
        to,
        cursor: q.cursor,
        limit: q.limit.unwrap_or(50).clamp(1, 200),
    };
    match audit::search(&state.db, user.tenant_id, filters).await {
        Ok(result) => Json(result).into_response(),
        Err(e) => audit_error_response(e),
    }
}

/// Turns a broadcast receiver into an SSE event stream scoped to one
/// tenant: a record for a different tenant is silently skipped (never
/// yielded), a lagging subscriber just skips ahead rather than
/// disconnecting, and the stream only ends if the sender itself is gone.
fn audit_event_stream(
    rx: tokio::sync::broadcast::Receiver<audit::AuditRecordSummary>,
    tenant_id: Uuid,
) -> impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>
{
    futures_util::stream::unfold((rx, tenant_id), |(mut rx, tenant_id)| async move {
        loop {
            match rx.recv().await {
                Ok(record) if record.tenant_id == tenant_id => {
                    let event = match axum::response::sse::Event::default().json_data(&record) {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    return Some((Ok(event), (rx, tenant_id)));
                }
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}

async fn audit_stream_handler(
    State(state): State<Arc<AppState>>,
    user: CurrentUser,
) -> axum::response::sse::Sse<
    impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
> {
    let stream = audit_event_stream(state.audit_events.subscribe(), user.tenant_id);
    axum::response::sse::Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

async fn overview_handler(
    State(state): State<Arc<AppState>>,
    user: CurrentUser,
) -> impl IntoResponse {
    match overview::get_overview(&state.db, user.tenant_id).await {
        Ok(overview) => Json(overview).into_response(),
        Err(overview::OverviewError::Db(e)) => {
            tracing::error!(error = %e, "overview db error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(overview::OverviewError::Gateways(e)) => gateways_error_response(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    /// `connect_lazy` parses the URL and builds a pool without dialing
    /// Postgres — fine here since `/healthz` never touches `state.db`, and
    /// it means this test runs without a live database.
    fn lazy_state() -> Arc<AppState> {
        let db = match PgPoolOptions::new()
            .connect_lazy("postgres://user:pass@localhost/custos_control")
        {
            Ok(pool) => pool,
            Err(e) => panic!("connect_lazy must not need a real connection: {e}"),
        };
        Arc::new(AppState {
            db,
            login_attempts: Default::default(),
            policy_signing_key: SigningKey::from_bytes(&[1u8; 32]),
            audit_events: tokio::sync::broadcast::channel(AUDIT_EVENTS_CAPACITY).0,
        })
    }

    #[tokio::test]
    async fn healthz_is_ok_without_a_database() {
        let request = match Request::builder().uri("/healthz").body(Body::empty()) {
            Ok(r) => r,
            Err(e) => panic!("{e}"),
        };
        let response = match app(lazy_state()).oneshot(request).await {
            Ok(r) => r,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(response.status(), StatusCode::OK);
    }

    fn sample_summary(tenant_id: Uuid) -> audit::AuditRecordSummary {
        audit::AuditRecordSummary {
            id: Uuid::new_v4(),
            tenant_id,
            gateway_id: Uuid::new_v4(),
            seq: 1,
            ts: None,
            agent: None,
            owner: None,
            tool: None,
            verdict: None,
            policy_version: None,
            findings: None,
            record: serde_json::json!({}),
            ingested_at: time::OffsetDateTime::now_utc(),
        }
    }

    #[tokio::test]
    async fn audit_stream_yields_only_records_for_its_own_tenant() {
        use futures_util::StreamExt;

        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let my_tenant = Uuid::new_v4();
        let other_tenant = Uuid::new_v4();
        let mut stream = std::pin::pin!(audit_event_stream(rx, my_tenant));

        // Sent before anyone polls the stream, so both are already queued
        // when we start reading: the other tenant's record must never
        // surface, the matching one must.
        if tx.send(sample_summary(other_tenant)).is_err() {
            panic!("send must succeed with a live receiver");
        }
        if tx.send(sample_summary(my_tenant)).is_err() {
            panic!("send must succeed with a live receiver");
        }

        let next = match stream.next().await {
            Some(item) => item,
            None => panic!("stream ended before yielding the matching record"),
        };
        assert!(next.is_ok());
    }

    #[tokio::test]
    async fn audit_stream_ends_when_the_sender_is_dropped() {
        use futures_util::StreamExt;

        let (tx, rx) = tokio::sync::broadcast::channel::<audit::AuditRecordSummary>(16);
        let mut stream = std::pin::pin!(audit_event_stream(rx, Uuid::new_v4()));
        drop(tx);
        assert!(stream.next().await.is_none());
    }
}
