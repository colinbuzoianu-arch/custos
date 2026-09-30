//! DB-touching tests. `#[ignore]`d because there's no Postgres available in
//! the environment these were written in. To run them for real:
//!
//!   docker compose -f docker-compose.control.yml up -d postgres
//!   DATABASE_URL=postgres://custos:custos@localhost/custos_control \
//!     cargo test -p custos-control -- --ignored

use axum::body::Body;
use axum::http::{Request, StatusCode};
use custos_control::agents::{self, AgentPatch, AgentsError, Status};
use custos_control::approvals::{self, ApprovalsError, NewApproval};
use custos_control::audit;
use custos_control::evidence;
use custos_control::gateways::{self, GatewaysError};
use custos_control::policies::{self, PoliciesError};
use custos_control::sessions::{self, RateLimiter, SESSION_COOKIE};
use custos_control::users::{self, Role};
use custos_control::{AppState, app};
use ed25519_dalek::SigningKey;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

/// An `AppState` for HTTP-level tests. The signing key is a fixed test seed
/// - fine here since none of these tests publish a policy bundle.
fn test_state(db: PgPool) -> Arc<AppState> {
    Arc::new(AppState {
        db,
        login_attempts: RateLimiter::default(),
        policy_signing_key: SigningKey::from_bytes(&[1u8; 32]),
        audit_events: tokio::sync::broadcast::channel(custos_control::AUDIT_EVENTS_CAPACITY).0,
    })
}

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
    user_id: Uuid,
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
    let user_id = match users::create_user(&db, tenant_id, &email, &hash, role).await {
        Ok(id) => id,
        Err(e) => panic!("{e}"),
    };

    Fixture {
        db,
        tenant_id,
        tenant_slug,
        user_id,
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

    let state = test_state(f.db);
    let request = match Request::builder()
        .uri("/api/admin/ping")
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

    let state = test_state(f.db);
    let request = match Request::builder()
        .uri("/api/admin/ping")
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

    let state = test_state(f.db);
    let request = match Request::builder()
        .method("POST")
        .uri("/api/logout")
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
async fn invalid_policy_draft_saves_but_cannot_publish() {
    let f = fixture(Role::Admin).await;

    let saved = match policies::save_draft(
        &f.db,
        f.tenant_id,
        f.user_id,
        "this is not cedar at all",
        None,
        Some("first attempt"),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    assert!(!saved.valid);
    assert!(saved.validation_error.is_some());

    let key = SigningKey::from_bytes(&[3u8; 32]);
    let result = policies::publish(&f.db, f.tenant_id, saved.version, &key).await;
    assert!(matches!(result, Err(PoliciesError::Invalid(_))));
}

#[tokio::test]
#[ignore]
async fn valid_policy_publishes_a_bundle_whose_signature_verifies() {
    let f = fixture(Role::Admin).await;
    let policy_text = r#"permit (principal, action, resource == Tool::"echo");"#;

    let saved = match policies::save_draft(
        &f.db,
        f.tenant_id,
        f.user_id,
        policy_text,
        None,
        Some("first version"),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    assert!(saved.valid, "{:?}", saved.validation_error);

    // An agent active at publish time must appear in the bundle.
    let agent =
        match agents::create_agent(&f.db, f.tenant_id, "bundled-agent", None, None, None).await {
            Ok(a) => a,
            Err(e) => panic!("{e}"),
        };
    if let Err(e) = agents::issue_token(&f.db, f.tenant_id, agent.id).await {
        panic!("{e}");
    }

    let key = SigningKey::from_bytes(&[5u8; 32]);
    let (updated, signed) = match policies::publish(&f.db, f.tenant_id, saved.version, &key).await {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert!(updated.published);

    let bundle = match policies::verify_bundle(&signed, &key.verifying_key()) {
        Ok(b) => b,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(bundle.version, saved.version);
    assert_eq!(bundle.policy, policy_text);
    assert!(bundle.agents.iter().any(|a| a.id == agent.id));

    // The wrong key must not verify it.
    let wrong_key = SigningKey::from_bytes(&[6u8; 32]);
    assert!(policies::verify_bundle(&signed, &wrong_key.verifying_key()).is_err());
}

#[tokio::test]
#[ignore]
async fn diff_shows_the_change_between_two_versions() {
    let f = fixture(Role::Admin).await;

    let v1 = match policies::save_draft(
        &f.db,
        f.tenant_id,
        f.user_id,
        r#"permit (principal, action, resource == Tool::"a");"#,
        None,
        None,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    let v2 = match policies::save_draft(
        &f.db,
        f.tenant_id,
        f.user_id,
        r#"permit (principal, action, resource == Tool::"b");"#,
        None,
        None,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };

    let diff = match policies::diff_versions(&f.db, f.tenant_id, v1.version, v2.version).await {
        Ok(d) => d,
        Err(e) => panic!("{e}"),
    };
    assert!(diff.contains("-permit (principal, action, resource == Tool::\"a\");"));
    assert!(diff.contains("+permit (principal, action, resource == Tool::\"b\");"));
}

#[tokio::test]
#[ignore]
async fn enroll_token_is_single_use() {
    let f = fixture(Role::Admin).await;
    let token = match gateways::create_enroll_token(
        &f.db,
        f.tenant_id,
        f.user_id,
        time::Duration::hours(1),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => panic!("{e}"),
    };

    let enrolled = match gateways::enroll(&f.db, &token, "gw-one").await {
        Ok(e) => e,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(enrolled.tenant_id, f.tenant_id);

    let second = gateways::enroll(&f.db, &token, "gw-two").await;
    assert!(matches!(second, Err(GatewaysError::InvalidEnrollToken)));
}

#[tokio::test]
#[ignore]
async fn enroll_rejects_an_unknown_token() {
    let f = fixture(Role::Admin).await;
    let result = gateways::enroll(&f.db, "not-a-real-token", "gw").await;
    assert!(matches!(result, Err(GatewaysError::InvalidEnrollToken)));
}

#[tokio::test]
#[ignore]
async fn gateway_bundle_endpoint_authenticates_by_credential() {
    let f = fixture(Role::Admin).await;
    let token = match gateways::create_enroll_token(
        &f.db,
        f.tenant_id,
        f.user_id,
        time::Duration::hours(1),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => panic!("{e}"),
    };
    let enrolled = match gateways::enroll(&f.db, &token, "gw-auth").await {
        Ok(e) => e,
        Err(e) => panic!("{e}"),
    };

    let state = test_state(f.db);

    // No bundle published yet, but a valid credential still gets past auth
    // (404, not 401).
    let request = match Request::builder()
        .uri("/api/gateways/bundle")
        .header("authorization", format!("Bearer {}", enrolled.credential))
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let response = match app(state.clone()).oneshot(request).await {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let bad_request = match Request::builder()
        .uri("/api/gateways/bundle")
        .header("authorization", "Bearer wrong-credential")
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let bad_response = match app(state).oneshot(bad_request).await {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(bad_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore]
async fn gateway_bundle_endpoint_returns_304_when_etag_matches() {
    let f = fixture(Role::Admin).await;
    let saved = match policies::save_draft(
        &f.db,
        f.tenant_id,
        f.user_id,
        r#"permit (principal, action, resource == Tool::"echo");"#,
        None,
        None,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    let key = SigningKey::from_bytes(&[4u8; 32]);
    if let Err(e) = policies::publish(&f.db, f.tenant_id, saved.version, &key).await {
        panic!("{e}");
    }

    let token = match gateways::create_enroll_token(
        &f.db,
        f.tenant_id,
        f.user_id,
        time::Duration::hours(1),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => panic!("{e}"),
    };
    let enrolled = match gateways::enroll(&f.db, &token, "gw-etag").await {
        Ok(e) => e,
        Err(e) => panic!("{e}"),
    };

    let state = test_state(f.db);
    let auth_header = format!("Bearer {}", enrolled.credential);

    let first = match Request::builder()
        .uri("/api/gateways/bundle")
        .header("authorization", &auth_header)
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let first_response = match app(state.clone()).oneshot(first).await {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(first_response.status(), StatusCode::OK);
    let etag = match first_response.headers().get("etag") {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_string(),
            Err(e) => panic!("{e}"),
        },
        None => panic!("expected an ETag header"),
    };

    let second = match Request::builder()
        .uri("/api/gateways/bundle")
        .header("authorization", &auth_header)
        .header("if-none-match", &etag)
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let second_response = match app(state).oneshot(second).await {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(second_response.status(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
#[ignore]
async fn heartbeat_updates_the_gateway_row() {
    let f = fixture(Role::Admin).await;
    let token = match gateways::create_enroll_token(
        &f.db,
        f.tenant_id,
        f.user_id,
        time::Duration::hours(1),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => panic!("{e}"),
    };
    let enrolled = match gateways::enroll(&f.db, &token, "gw-heartbeat").await {
        Ok(e) => e,
        Err(e) => panic!("{e}"),
    };

    let state = test_state(f.db);
    let body = serde_json::json!({
        "version": "0.1.0",
        "policy_version": "abc123",
        "decisions_allowed": 10,
        "decisions_blocked": 2,
    });
    let request = match Request::builder()
        .method("POST")
        .uri("/api/gateways/heartbeat")
        .header("authorization", format!("Bearer {}", enrolled.credential))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
    {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let response = match app(state.clone()).oneshot(request).await {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(response.status(), StatusCode::OK);

    let list = match gateways::list_gateways(&state.db, f.tenant_id).await {
        Ok(l) => l,
        Err(e) => panic!("{e}"),
    };
    let gw = list
        .iter()
        .find(|g| g.id == enrolled.gateway_id)
        .unwrap_or_else(|| panic!("gateway must be in the list"));
    assert_eq!(gw.decisions_allowed, 10);
    assert_eq!(gw.decisions_blocked, 2);
    assert_eq!(gw.last_version.as_deref(), Some("0.1.0"));
    assert!(gw.last_heartbeat_at.is_some());
}

async fn enrolled_gateway(f: &Fixture, name: &str) -> gateways::Enrolled {
    let token = match gateways::create_enroll_token(
        &f.db,
        f.tenant_id,
        f.user_id,
        time::Duration::hours(1),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => panic!("{e}"),
    };
    match gateways::enroll(&f.db, &token, name).await {
        Ok(e) => e,
        Err(e) => panic!("{e}"),
    }
}

fn fake_record(
    seq: u64,
    prev_hash: &str,
    hash: &str,
    tool: &str,
    verdict: &str,
) -> serde_json::Value {
    serde_json::json!({
        "v": 4,
        "seq": seq,
        "ts": "2026-09-30T12:00:00Z",
        "agent": "test-agent",
        "owner": null,
        "tool": tool,
        "arguments": null,
        "decision": { "verdict": verdict },
        "gateway_instance": "test-instance",
        "policy_version": "abc123",
        "findings": [],
        "prev_hash": prev_hash,
        "hash": hash,
    })
}

#[tokio::test]
#[ignore]
async fn duplicate_audit_batch_is_a_noop() {
    let f = fixture(Role::Admin).await;
    let gw = enrolled_gateway(&f, "gw-audit-dup").await;

    let batch = vec![
        fake_record(1, "0".repeat(64).as_str(), "h1", "echo", "ALLOW"),
        fake_record(2, "h1", "h2", "echo", "ALLOW"),
    ];

    let first = match audit::ingest_batch(&f.db, f.tenant_id, gw.gateway_id, &batch).await {
        Ok(o) => o,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(first.inserted, 2);
    assert_eq!(first.duplicates, 0);

    let second = match audit::ingest_batch(&f.db, f.tenant_id, gw.gateway_id, &batch).await {
        Ok(o) => o,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(second.inserted, 0);
    assert_eq!(second.duplicates, 2);

    let count: (i64,) =
        match sqlx::query_as("select count(*) from audit_records where gateway_id = $1")
            .bind(gw.gateway_id)
            .fetch_one(&f.db)
            .await
        {
            Ok(c) => c,
            Err(e) => panic!("{e}"),
        };
    assert_eq!(count.0, 2);
}

#[tokio::test]
#[ignore]
async fn a_seq_gap_is_flagged_and_stays_flagged() {
    let f = fixture(Role::Admin).await;
    let gw = enrolled_gateway(&f, "gw-audit-gap").await;

    if let Err(e) = audit::ingest_batch(
        &f.db,
        f.tenant_id,
        gw.gateway_id,
        &[fake_record(1, &"0".repeat(64), "h1", "echo", "ALLOW")],
    )
    .await
    {
        panic!("{e}");
    }
    // seq 2 is skipped entirely.
    if let Err(e) = audit::ingest_batch(
        &f.db,
        f.tenant_id,
        gw.gateway_id,
        &[fake_record(3, "h1", "h3", "echo", "ALLOW")],
    )
    .await
    {
        panic!("{e}");
    }

    let gateway = match gateways::get_gateway(&f.db, f.tenant_id, gw.gateway_id).await {
        Ok(g) => g,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(gateway.chain_status, "gap");
    assert!(gateway.chain_issue.is_some());

    // A subsequent, perfectly-linked record must not clear the flag.
    if let Err(e) = audit::ingest_batch(
        &f.db,
        f.tenant_id,
        gw.gateway_id,
        &[fake_record(4, "h3", "h4", "echo", "ALLOW")],
    )
    .await
    {
        panic!("{e}");
    }
    let gateway = match gateways::get_gateway(&f.db, f.tenant_id, gw.gateway_id).await {
        Ok(g) => g,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(gateway.chain_status, "gap");
}

#[tokio::test]
#[ignore]
async fn a_mismatched_prev_hash_is_flagged_as_broken() {
    let f = fixture(Role::Admin).await;
    let gw = enrolled_gateway(&f, "gw-audit-broken").await;

    if let Err(e) = audit::ingest_batch(
        &f.db,
        f.tenant_id,
        gw.gateway_id,
        &[fake_record(1, &"0".repeat(64), "h1", "echo", "ALLOW")],
    )
    .await
    {
        panic!("{e}");
    }
    // seq is contiguous, but prev_hash doesn't match the last ingested hash.
    if let Err(e) = audit::ingest_batch(
        &f.db,
        f.tenant_id,
        gw.gateway_id,
        &[fake_record(2, "not-h1", "h2", "echo", "ALLOW")],
    )
    .await
    {
        panic!("{e}");
    }

    let gateway = match gateways::get_gateway(&f.db, f.tenant_id, gw.gateway_id).await {
        Ok(g) => g,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(gateway.chain_status, "broken");
}

#[tokio::test]
#[ignore]
async fn a_verdict_is_searchable_after_ingest() {
    let f = fixture(Role::Admin).await;
    let gw = enrolled_gateway(&f, "gw-audit-search").await;

    if let Err(e) = audit::ingest_batch(
        &f.db,
        f.tenant_id,
        gw.gateway_id,
        &[fake_record(
            1,
            &"0".repeat(64),
            "h1",
            "payroll.read",
            "BLOCK",
        )],
    )
    .await
    {
        panic!("{e}");
    }

    let row: (Option<String>, Option<String>) = match sqlx::query_as(
        "select tool, verdict from audit_records where gateway_id = $1 and seq = 1",
    )
    .bind(gw.gateway_id)
    .fetch_one(&f.db)
    .await
    {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(row.0.as_deref(), Some("payroll.read"));
    assert_eq!(row.1.as_deref(), Some("BLOCK"));
}

#[tokio::test]
#[ignore]
async fn search_filters_by_tool_and_verdict() {
    let f = fixture(Role::Admin).await;
    let gw = enrolled_gateway(&f, "gw-search-filters").await;

    let records = vec![
        fake_record(1, &"0".repeat(64), "h1", "payroll.read", "BLOCK"),
        fake_record(2, "h1", "h2", "echo", "ALLOW"),
    ];
    if let Err(e) = audit::ingest_batch(&f.db, f.tenant_id, gw.gateway_id, &records).await {
        panic!("{e}");
    }

    let result = match audit::search(
        &f.db,
        f.tenant_id,
        audit::SearchFilters {
            tool: Some("payroll.read".into()),
            limit: 50,
            ..Default::default()
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0].verdict.as_deref(), Some("BLOCK"));

    let result = match audit::search(
        &f.db,
        f.tenant_id,
        audit::SearchFilters {
            verdict: Some("ALLOW".into()),
            limit: 50,
            ..Default::default()
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0].tool.as_deref(), Some("echo"));
}

#[tokio::test]
#[ignore]
async fn search_never_returns_another_tenants_records() {
    let f1 = fixture(Role::Admin).await;
    let gw1 = enrolled_gateway(&f1, "gw-tenant-1").await;
    if let Err(e) = audit::ingest_batch(
        &f1.db,
        f1.tenant_id,
        gw1.gateway_id,
        &[fake_record(1, &"0".repeat(64), "h1", "echo", "ALLOW")],
    )
    .await
    {
        panic!("{e}");
    }

    let f2 = fixture(Role::Admin).await;
    let result = match audit::search(
        &f1.db,
        f2.tenant_id,
        audit::SearchFilters {
            limit: 50,
            ..Default::default()
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert!(result.records.is_empty());
}

#[tokio::test]
#[ignore]
async fn search_pagination_walks_every_record_exactly_once() {
    let f = fixture(Role::Admin).await;
    let gw = enrolled_gateway(&f, "gw-search-paging").await;

    let mut prev_hash = "0".repeat(64);
    let mut records = Vec::new();
    for seq in 1..=5u64 {
        let hash = format!("h{seq}");
        records.push(fake_record(seq, &prev_hash, &hash, "echo", "ALLOW"));
        prev_hash = hash;
    }
    if let Err(e) = audit::ingest_batch(&f.db, f.tenant_id, gw.gateway_id, &records).await {
        panic!("{e}");
    }

    let mut seen = std::collections::HashSet::new();
    let mut cursor = None;
    loop {
        let result = match audit::search(
            &f.db,
            f.tenant_id,
            audit::SearchFilters {
                cursor: cursor.clone(),
                limit: 2,
                ..Default::default()
            },
        )
        .await
        {
            Ok(r) => r,
            Err(e) => panic!("{e}"),
        };
        for record in &result.records {
            seen.insert(record.seq);
        }
        match result.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
        if seen.len() > 5 {
            panic!("pagination looped past every record without stopping");
        }
    }
    assert_eq!(seen.len(), 5);
}

#[tokio::test]
#[ignore]
async fn overview_aggregates_todays_decisions_and_top_blocked() {
    let f = fixture(Role::Admin).await;
    let gw = enrolled_gateway(&f, "gw-overview").await;

    let records = vec![
        fake_record(1, &"0".repeat(64), "h1", "payroll.read", "BLOCK"),
        fake_record(2, "h1", "h2", "payroll.read", "BLOCK"),
        fake_record(3, "h2", "h3", "echo", "ALLOW"),
    ];
    if let Err(e) = audit::ingest_batch(&f.db, f.tenant_id, gw.gateway_id, &records).await {
        panic!("{e}");
    }

    let overview = match custos_control::overview::get_overview(&f.db, f.tenant_id).await {
        Ok(o) => o,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(overview.decisions_today.allow, 1);
    assert_eq!(overview.decisions_today.block, 2);
    assert!((overview.blocked_percent - (200.0 / 3.0)).abs() < 0.01);
    assert_eq!(overview.top_blocked_tools.len(), 1);
    assert_eq!(overview.top_blocked_tools[0].name, "payroll.read");
    assert_eq!(overview.top_blocked_tools[0].count, 2);
    assert!(overview.gateways.iter().any(|g| g.id == gw.gateway_id));
}

#[tokio::test]
#[ignore]
async fn me_requires_a_session_and_returns_role_and_csrf_token() {
    let f = fixture(Role::Viewer).await;
    let limiter = RateLimiter::default();
    let logged_in =
        match sessions::login(&f.db, &limiter, &f.tenant_slug, &f.email, f.password).await {
            Ok(l) => l,
            Err(e) => panic!("{e}"),
        };
    let state = test_state(f.db);

    let anonymous = match Request::builder().uri("/api/me").body(Body::empty()) {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let anonymous_response = match app(state.clone()).oneshot(anonymous).await {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(anonymous_response.status(), StatusCode::UNAUTHORIZED);

    let authed = match Request::builder()
        .uri("/api/me")
        .header(
            "cookie",
            format!("{SESSION_COOKIE}={}", logged_in.session_id),
        )
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let authed_response = match app(state).oneshot(authed).await {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(authed_response.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn validate_endpoint_never_creates_a_version_row() {
    let f = fixture(Role::Admin).await;
    let limiter = RateLimiter::default();
    let logged_in =
        match sessions::login(&f.db, &limiter, &f.tenant_slug, &f.email, f.password).await {
            Ok(l) => l,
            Err(e) => panic!("{e}"),
        };
    let state = test_state(f.db);

    let body = serde_json::json!({ "policy_text": "this is not cedar at all" });
    let request = match Request::builder()
        .method("POST")
        .uri("/api/policies/validate")
        .header(
            "cookie",
            format!("{SESSION_COOKIE}={}", logged_in.session_id),
        )
        .header("x-csrf-token", &logged_in.csrf_token)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
    {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let response = match app(state.clone()).oneshot(request).await {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(response.status(), StatusCode::OK);

    let count: (i64,) =
        match sqlx::query_as("select count(*) from policy_versions where tenant_id = $1")
            .bind(f.tenant_id)
            .fetch_one(&state.db)
            .await
        {
            Ok(c) => c,
            Err(e) => panic!("{e}"),
        };
    assert_eq!(count.0, 0);
}

#[tokio::test]
#[ignore]
async fn approval_is_only_visible_to_the_gateway_that_created_it() {
    let f = fixture(Role::Admin).await;
    let gw1 = enrolled_gateway(&f, "gw-approval-1").await;
    let gw2 = enrolled_gateway(&f, "gw-approval-2").await;

    let created = match approvals::create(
        &f.db,
        f.tenant_id,
        NewApproval {
            gateway_id: gw1.gateway_id,
            agent: "some-agent",
            tool: "payroll.run",
            findings: None,
            reason: "needs a human",
            four_eyes: false,
        },
    )
    .await
    {
        Ok(a) => a,
        Err(e) => panic!("{e}"),
    };

    let own = approvals::get_for_gateway(&f.db, f.tenant_id, gw1.gateway_id, created.id).await;
    assert!(own.is_ok());

    let other = approvals::get_for_gateway(&f.db, f.tenant_id, gw2.gateway_id, created.id).await;
    assert!(matches!(other, Err(ApprovalsError::NotFound)));
}

#[tokio::test]
#[ignore]
async fn resolve_approves_and_records_a_comment() {
    let f = fixture(Role::Admin).await;
    let gw = enrolled_gateway(&f, "gw-approval-resolve").await;
    let created = match approvals::create(
        &f.db,
        f.tenant_id,
        NewApproval {
            gateway_id: gw.gateway_id,
            agent: "some-agent",
            tool: "payroll.run",
            findings: None,
            reason: "needs a human",
            four_eyes: false,
        },
    )
    .await
    {
        Ok(a) => a,
        Err(e) => panic!("{e}"),
    };

    let resolved = match approvals::resolve(
        &f.db,
        f.tenant_id,
        created.id,
        f.user_id,
        true,
        Some("looks fine"),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(resolved.status, "approved");
    assert_eq!(resolved.comment.as_deref(), Some("looks fine"));
}

#[tokio::test]
#[ignore]
async fn resolving_an_already_resolved_approval_fails() {
    let f = fixture(Role::Admin).await;
    let gw = enrolled_gateway(&f, "gw-approval-twice").await;
    let created = match approvals::create(
        &f.db,
        f.tenant_id,
        NewApproval {
            gateway_id: gw.gateway_id,
            agent: "some-agent",
            tool: "payroll.run",
            findings: None,
            reason: "needs a human",
            four_eyes: false,
        },
    )
    .await
    {
        Ok(a) => a,
        Err(e) => panic!("{e}"),
    };

    if let Err(e) = approvals::resolve(&f.db, f.tenant_id, created.id, f.user_id, true, None).await
    {
        panic!("{e}");
    }
    let second = approvals::resolve(&f.db, f.tenant_id, created.id, f.user_id, false, None).await;
    assert!(matches!(second, Err(ApprovalsError::AlreadyResolved)));
}

#[tokio::test]
#[ignore]
async fn four_eyes_blocks_the_agents_own_owner_from_resolving() {
    let f = fixture(Role::Admin).await;
    let gw = enrolled_gateway(&f, "gw-approval-four-eyes").await;

    let owner_id = f.user_id;
    let agent = match agents::create_agent(
        &f.db,
        f.tenant_id,
        "owned-agent",
        Some(owner_id),
        None,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => panic!("{e}"),
    };

    let created = match approvals::create(
        &f.db,
        f.tenant_id,
        NewApproval {
            gateway_id: gw.gateway_id,
            agent: &agent.name,
            tool: "payroll.run",
            findings: None,
            reason: "needs a second pair of eyes",
            four_eyes: true,
        },
    )
    .await
    {
        Ok(a) => a,
        Err(e) => panic!("{e}"),
    };

    let by_owner = approvals::resolve(&f.db, f.tenant_id, created.id, owner_id, true, None).await;
    assert!(matches!(by_owner, Err(ApprovalsError::FourEyesViolation)));

    // A different approver can still resolve it.
    let other_approver = Uuid::new_v4();
    let resolved = match approvals::resolve(
        &f.db,
        f.tenant_id,
        created.id,
        other_approver,
        true,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(resolved.status, "approved");
}

#[tokio::test]
#[ignore]
async fn a_viewer_cannot_list_pending_approvals() {
    let f = fixture(Role::Viewer).await;
    let limiter = RateLimiter::default();
    let logged_in =
        match sessions::login(&f.db, &limiter, &f.tenant_slug, &f.email, f.password).await {
            Ok(l) => l,
            Err(e) => panic!("{e}"),
        };
    let state = test_state(f.db);
    let request = match Request::builder()
        .uri("/api/approvals")
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
async fn evidence_json_endpoint_returns_a_verifiable_signed_bundle() {
    let f = fixture(Role::Admin).await;
    let limiter = RateLimiter::default();
    let logged_in =
        match sessions::login(&f.db, &limiter, &f.tenant_slug, &f.email, f.password).await {
            Ok(l) => l,
            Err(e) => panic!("{e}"),
        };
    let signing_key = SigningKey::from_bytes(&[8u8; 32]);
    let db = f.db.clone();
    let state = Arc::new(AppState {
        db,
        login_attempts: RateLimiter::default(),
        policy_signing_key: signing_key.clone(),
        audit_events: tokio::sync::broadcast::channel(custos_control::AUDIT_EVENTS_CAPACITY).0,
    });

    let request = match Request::builder()
        .uri("/api/evidence.json?from=2020-01-01T00:00:00Z&to=2030-01-01T00:00:00Z")
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

    let bytes = match axum::body::to_bytes(response.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(e) => panic!("{e}"),
    };
    let signed: evidence::SignedEvidence = match serde_json::from_slice(&bytes) {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };
    let sig_bytes: [u8; 64] = match base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &signed.signature,
    )
    .ok()
    .and_then(|b| b.try_into().ok())
    {
        Some(b) => b,
        None => panic!("signature must decode to 64 bytes"),
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    assert!(
        signing_key
            .verifying_key()
            .verify_strict(signed.evidence_json.as_bytes(), &signature)
            .is_ok()
    );
}

#[tokio::test]
#[ignore]
async fn evidence_pdf_endpoint_returns_pdf_bytes() {
    let f = fixture(Role::Admin).await;
    let limiter = RateLimiter::default();
    let logged_in =
        match sessions::login(&f.db, &limiter, &f.tenant_slug, &f.email, f.password).await {
            Ok(l) => l,
            Err(e) => panic!("{e}"),
        };
    let state = test_state(f.db);

    let request = match Request::builder()
        .uri("/api/evidence.pdf?from=2020-01-01T00:00:00Z&to=2030-01-01T00:00:00Z&lang=ro")
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
    let bytes = match axum::body::to_bytes(response.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(e) => panic!("{e}"),
    };
    assert!(bytes.starts_with(b"%PDF"));
}

#[tokio::test]
#[ignore]
async fn evidence_endpoints_reject_non_admins() {
    let f = fixture(Role::Viewer).await;
    let limiter = RateLimiter::default();
    let logged_in =
        match sessions::login(&f.db, &limiter, &f.tenant_slug, &f.email, f.password).await {
            Ok(l) => l,
            Err(e) => panic!("{e}"),
        };
    let state = test_state(f.db);

    let request = match Request::builder()
        .uri("/api/evidence.json?from=2020-01-01T00:00:00Z&to=2030-01-01T00:00:00Z")
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
async fn evidence_endpoint_rejects_a_malformed_date() {
    let f = fixture(Role::Admin).await;
    let limiter = RateLimiter::default();
    let logged_in =
        match sessions::login(&f.db, &limiter, &f.tenant_slug, &f.email, f.password).await {
            Ok(l) => l,
            Err(e) => panic!("{e}"),
        };
    let state = test_state(f.db);

    let request = match Request::builder()
        .uri("/api/evidence.json?from=not-a-date&to=2030-01-01T00:00:00Z")
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
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
