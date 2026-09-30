//! Custos Control: multi-gateway management, audit search, approvals.
//!
//! Session 9 (this file, for now): the skeleton — a Postgres pool, embedded
//! migrations, and `/healthz`. Users, sessions, and login all follow in the
//! same session's later commits. See `docs/decisions/0002-control-plane.md`
//! for why this exists and how it's meant to be deployed, and `NOTICE.md`
//! for why this crate — unlike the rest of the workspace — isn't Apache-2.0.

pub mod config;
pub mod sessions;
pub mod users;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{Json, Router, routing::get, routing::post};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use sessions::{AdminUser, CurrentUser, LoginError, RateLimiter};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::Arc;

pub struct AppState {
    pub db: PgPool,
    pub login_attempts: RateLimiter,
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
        // Throwaway route proving the role gate actually rejects
        // non-admins - a real admin-only endpoint arrives in session 10.
        .route("/admin/ping", get(|_admin: AdminUser| async { "ok" }))
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
