//! DB-touching tests. `#[ignore]`d because there's no Postgres available in
//! the environment these were written in. To run them for real:
//!
//!   docker compose -f docker-compose.control.yml up -d postgres
//!   DATABASE_URL=postgres://custos:custos@localhost/custos_control \
//!     cargo test -p custos-control -- --ignored

use axum::body::Body;
use axum::http::{Request, StatusCode};
use custos_control::sessions::{self, RateLimiter, SESSION_COOKIE};
use custos_control::users::{self, Role};
use custos_control::{AppState, app};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

async fn pool() -> PgPool {
    let url = match std::env::var("DATABASE_URL") {
        Ok(u) => u,
        Err(_) => panic!("DATABASE_URL must be set to run these tests (see module docs)"),
    };
    let pool = match custos_control::connect(&url).await {
        Ok(p) => p,
        Err(e) => panic!("{e}"),
    };
    if let Err(e) = custos_control::migrate(&pool).await {
        panic!("{e}");
    }
    pool
}

/// A fresh tenant + user for one test, so tests never collide with each
/// other or with real data in the same database.
struct Fixture {
    db: PgPool,
    tenant_slug: String,
    email: String,
    password: &'static str,
}

async fn fixture(role: Role) -> Fixture {
    let db = pool().await;
    let tenant_slug = format!("test-{}", Uuid::new_v4());
    let email = format!("{}@example.com", Uuid::new_v4());
    let password = "correct horse battery staple";

    let tenant_id = match users::create_tenant(&db, &tenant_slug, &tenant_slug).await {
        Ok(id) => id,
        Err(e) => panic!("{e}"),
    };
    let hash = match users::hash_password(password) {
        Ok(h) => h,
        Err(e) => panic!("{e}"),
    };
    if let Err(e) = users::create_user(&db, tenant_id, &email, &hash, role).await {
        panic!("{e}");
    }

    Fixture {
        db,
        tenant_slug,
        email,
        password,
    }
}

#[tokio::test]
#[ignore]
async fn login_succeeds_with_correct_credentials() {
    let f = fixture(Role::Viewer).await;
    let limiter = RateLimiter::default();
    let result = sessions::login(&f.db, &limiter, &f.tenant_slug, &f.email, f.password).await;
    assert!(result.is_ok(), "{:?}", result.err().map(|e| e.to_string()));
}

#[tokio::test]
#[ignore]
async fn login_fails_with_wrong_password() {
    let f = fixture(Role::Viewer).await;
    let limiter = RateLimiter::default();
    let result = sessions::login(&f.db, &limiter, &f.tenant_slug, &f.email, "wrong password").await;
    assert!(result.is_err());
}

#[tokio::test]
#[ignore]
async fn lockout_after_max_failures() {
    let f = fixture(Role::Viewer).await;
    let limiter = RateLimiter::default();
    // The exact count matches sessions::MAX_FAILURES (5); this only checks
    // the observable behavior, not the private constant.
    for _ in 0..5 {
        let _ = sessions::login(&f.db, &limiter, &f.tenant_slug, &f.email, "wrong").await;
    }
    let result = sessions::login(&f.db, &limiter, &f.tenant_slug, &f.email, f.password).await;
    assert!(
        matches!(result, Err(sessions::LoginError::LockedOut)),
        "correct password should still be locked out after too many failures"
    );
}

#[tokio::test]
#[ignore]
async fn viewer_cannot_call_admin_endpoint() {
    let f = fixture(Role::Viewer).await;
    let limiter = RateLimiter::default();
    let logged_in =
        match sessions::login(&f.db, &limiter, &f.tenant_slug, &f.email, f.password).await {
            Ok(l) => l,
            Err(e) => panic!("{e}"),
        };

    let state = Arc::new(AppState {
        db: f.db,
        login_attempts: RateLimiter::default(),
    });
    let request = match Request::builder()
        .uri("/admin/ping")
        .header(
            "cookie",
            format!("{SESSION_COOKIE}={}", logged_in.session_id),
        )
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let response = match app(state).oneshot(request).await {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore]
async fn admin_can_call_admin_endpoint() {
    let f = fixture(Role::Admin).await;
    let limiter = RateLimiter::default();
    let logged_in =
        match sessions::login(&f.db, &limiter, &f.tenant_slug, &f.email, f.password).await {
            Ok(l) => l,
            Err(e) => panic!("{e}"),
        };

    let state = Arc::new(AppState {
        db: f.db,
        login_attempts: RateLimiter::default(),
    });
    let request = match Request::builder()
        .uri("/admin/ping")
        .header(
            "cookie",
            format!("{SESSION_COOKIE}={}", logged_in.session_id),
        )
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let response = match app(state).oneshot(request).await {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn logout_without_csrf_token_is_rejected() {
    let f = fixture(Role::Viewer).await;
    let limiter = RateLimiter::default();
    let logged_in =
        match sessions::login(&f.db, &limiter, &f.tenant_slug, &f.email, f.password).await {
            Ok(l) => l,
            Err(e) => panic!("{e}"),
        };

    let state = Arc::new(AppState {
        db: f.db,
        login_attempts: RateLimiter::default(),
    });
    let request = match Request::builder()
        .method("POST")
        .uri("/logout")
        .header(
            "cookie",
            format!("{SESSION_COOKIE}={}", logged_in.session_id),
        )
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let response = match app(state).oneshot(request).await {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
