//! Custos Control: multi-gateway management, audit search, approvals.
//!
//! Session 9 (this file, for now): the skeleton — a Postgres pool, embedded
//! migrations, and `/healthz`. Users, sessions, and login all follow in the
//! same session's later commits. See `docs/decisions/0002-control-plane.md`
//! for why this exists and how it's meant to be deployed, and `NOTICE.md`
//! for why this crate — unlike the rest of the workspace — isn't Apache-2.0.

pub mod config;
pub mod users;

use axum::{Router, routing::get};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::Arc;

pub struct AppState {
    pub db: PgPool,
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
        .with_state(state)
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
        Arc::new(AppState { db })
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
