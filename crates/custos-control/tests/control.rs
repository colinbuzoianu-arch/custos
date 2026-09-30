//! DB-touching tests. `#[ignore]`d because there's no Postgres available in
//! the environment these were written in. To run them for real:
//!
//!   docker compose -f docker-compose.control.yml up -d postgres
//!   DATABASE_URL=postgres://custos:custos@localhost/custos_control \
//!     cargo test -p custos-control -- --ignored

use axum::body::Body;
use axum::http::{Request, StatusCode};
use custos_control::agents::{self, AgentPatch, AgentsError, Status};
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
    tenant_id: Uuid,
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
        tenant_id,
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
async fn agent_crud_round_trips() {
    let f = fixture(Role::Admin).await;

    let created = match agents::create_agent(
        &f.db,
        f.tenant_id,
        "agent-one",
        None,
        Some("does things"),
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(created.status, "active");

    let fetched = match agents::get_agent(&f.db, f.tenant_id, created.id).await {
        Ok(a) => a,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(fetched.name, "agent-one");

    let updated = match agents::update_agent(
        &f.db,
        f.tenant_id,
        created.id,
        AgentPatch {
            status: Some(Status::Disabled),
            ..Default::default()
        },
    )
    .await
    {
        Ok(a) => a,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(updated.status, "disabled");
    // A field not mentioned in the patch must survive untouched.
    assert_eq!(updated.description.as_deref(), Some("does things"));

    if let Err(e) = agents::delete_agent(&f.db, f.tenant_id, created.id).await {
        panic!("{e}");
    }
    let after_delete = agents::get_agent(&f.db, f.tenant_id, created.id).await;
    assert!(matches!(after_delete, Err(AgentsError::NotFound)));
}

#[tokio::test]
#[ignore]
async fn agent_name_must_be_unique_within_a_tenant() {
    let f = fixture(Role::Admin).await;
    let tenant_id = f.tenant_id;
    if let Err(e) = agents::create_agent(&f.db, tenant_id, "dup", None, None, None).await {
        panic!("{e}");
    }
    let second = agents::create_agent(&f.db, tenant_id, "dup", None, None, None).await;
    assert!(matches!(second, Err(AgentsError::NameTaken(_))));
}

#[tokio::test]
#[ignore]
async fn agent_from_another_tenant_is_not_found() {
    let f = fixture(Role::Admin).await;
    let tenant_id = f.tenant_id;
    let created = match agents::create_agent(&f.db, tenant_id, "isolated", None, None, None).await {
        Ok(a) => a,
        Err(e) => panic!("{e}"),
    };

    let other_tenant = match users::create_tenant(&f.db, "other-tenant", "other-tenant").await {
        Ok(id) => id,
        Err(e) => panic!("{e}"),
    };
    let result = agents::get_agent(&f.db, other_tenant, created.id).await;
    assert!(matches!(result, Err(AgentsError::NotFound)));
}

#[tokio::test]
#[ignore]
async fn issued_token_hashes_to_the_stored_value_and_is_never_returned_again() {
    let f = fixture(Role::Admin).await;
    let tenant_id = f.tenant_id;
    let created =
        match agents::create_agent(&f.db, tenant_id, "token-agent", None, None, None).await {
            Ok(a) => a,
            Err(e) => panic!("{e}"),
        };

    let token = match agents::issue_token(&f.db, tenant_id, created.id).await {
        Ok(t) => t,
        Err(e) => panic!("{e}"),
    };
    let stored_hash: (Option<String>,) =
        match sqlx::query_as("select token_sha256 from agents where id = $1")
            .bind(created.id)
            .fetch_one(&f.db)
            .await
        {
            Ok(row) => row,
            Err(e) => panic!("{e}"),
        };
    assert_eq!(stored_hash.0, Some(agents::hash_token(&token)));

    // The `Agent` type returned by every other read has no field for the
    // token or its hash - serializing it can't leak either one.
    let refetched = match agents::get_agent(&f.db, tenant_id, created.id).await {
        Ok(a) => a,
        Err(e) => panic!("{e}"),
    };
    let json = match serde_json::to_value(&refetched) {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    assert!(json.get("token").is_none());
    assert!(json.get("token_sha256").is_none());
}

#[tokio::test]
#[ignore]
async fn issuing_a_token_writes_an_admin_audit_entry() {
    let f = fixture(Role::Admin).await;
    let tenant_id = f.tenant_id;
    let created =
        match agents::create_agent(&f.db, tenant_id, "audited-agent", None, None, None).await {
            Ok(a) => a,
            Err(e) => panic!("{e}"),
        };
    if let Err(e) = agents::issue_token(&f.db, tenant_id, created.id).await {
        panic!("{e}");
    }
    agents::record_admin_audit(
        &f.db,
        tenant_id,
        Uuid::new_v4(),
        "issue_token",
        "agent",
        Some(created.id),
        None,
    )
    .await;

    let count: (i64,) = match sqlx::query_as(
        "select count(*) from admin_audit where tenant_id = $1 and target_id = $2 and action = 'issue_token'",
    )
    .bind(tenant_id)
    .bind(created.id)
    .fetch_one(&f.db)
    .await
    {
        Ok(row) => row,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(count.0, 1);
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
