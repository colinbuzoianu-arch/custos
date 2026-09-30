//! Custos Control: multi-gateway management, audit search, approvals.
//!
//! Session 9 (this file, for now): the skeleton — a Postgres pool, embedded
//! migrations, and `/healthz`. Users, sessions, and login all follow in the
//! same session's later commits. See `docs/decisions/0002-control-plane.md`
//! for why this exists and how it's meant to be deployed, and `NOTICE.md`
//! for why this crate — unlike the rest of the workspace — isn't Apache-2.0.

pub mod agents;
pub mod config;
pub mod policies;
pub mod sessions;
pub mod users;

use agents::{AgentPatch, AgentsError, Status};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{
    Json, Router,
    routing::{get, post},
};
use axum_extra::extract::cookie::CookieJar;
use ed25519_dalek::SigningKey;
use policies::PoliciesError;
use serde::Deserialize;
use sessions::{AdminUser, CurrentUser, LoginError, RateLimiter};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::Arc;
use uuid::Uuid;

pub struct AppState {
    pub db: PgPool,
    pub login_attempts: RateLimiter,
    /// Signs every policy bundle on publish. See
    /// `docs/decisions/0003-policy-bundle.md`.
    pub policy_signing_key: SigningKey,
}

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

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/login", post(login_handler))
        .route("/logout", post(logout_handler))
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
        .route("/policies/{version}", get(get_policy_version_handler))
        .route(
            "/policies/{version}/publish",
            post(publish_policy_version_handler),
        )
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
        PoliciesError::Serialize(e) => {
            tracing::error!(error = %e, "failed to serialize policy bundle");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        PoliciesError::MalformedBundle(_) | PoliciesError::BadSignature => {
            // Only reachable via `verify_bundle`, which this crate's own
            // handlers never call on a bundle they just produced themselves.
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
}
