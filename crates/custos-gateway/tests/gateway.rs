//! End-to-end: a fake upstream MCP server, the real gateway, a real HTTP client.

use axum::{
    Json, Router,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use custos_gateway::{AppState, BLOCKED_CODE, app, config, hash_token};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const TOKEN: &str = "test-token-invoice";
const TOKEN_A: &str = "test-token-agent-a";
const TOKEN_B: &str = "test-token-agent-b";

const POLICY: &str = r#"
@id("invoice-read")
permit (
    principal == Agent::"invoice-processor",
    action == Action::"call_tool",
    resource == Tool::"sap.read_invoice"
);
@id("no-payroll")
forbid (principal, action, resource == Tool::"payroll.read_salaries");
"#;

struct Harness {
    base: String,
    upstream_hits: Arc<AtomicUsize>,
    audit: std::path::PathBuf,
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

/// Like `start()`, but the caller supplies the upstream router directly —
/// used by the `tools/list` filtering tests, which need to control exactly
/// what upstream sends back (a specific content-type, a specific body).
async fn start_with_upstream(
    upstream: Router,
    upstream_hits: Arc<AtomicUsize>,
) -> anyhow::Result<Harness> {
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up.local_addr()?;
    tokio::spawn(async move { axum::serve(up, upstream).await });

    let dir = tempfile::tempdir()?;
    let policy_dir = dir.path().join("policies");
    std::fs::create_dir(&policy_dir)?;
    std::fs::write(policy_dir.join("test.cedar"), POLICY)?;
    let audit = dir.path().join("audit.jsonl");

    // These tests aren't about what the audit log records, just that the
    // gateway allows/blocks/forwards correctly — "full" mode needs no
    // signing key and keeps that out of scope. The GDPR-specific behaviour
    // (hash mode, redaction, the audit key) has its own tests below and in
    // `custos-audit`.
    let cfg = config::Config {
        listen: "127.0.0.1:0".parse()?,
        upstream: format!("http://{up_addr}/mcp"),
        upstream_authorization: None,
        policy_dir,
        audit_log: audit.clone(),
        audit_arguments: config::AuditArgsMode::Full,
        audit_key_id: None,
        instance_id: Some("test-instance".into()),
        session_idle_timeout_secs: 86_400,
        max_sessions: 10_000,
        auth: config::AuthMode::Static,
        signing_keys: vec![],
        agents: vec![config::AgentConfig {
            id: "invoice-processor".into(),
            owner: Some("finance".into()),
            token_sha256: hash_token(TOKEN),
        }],
    };
    let state = Arc::new(AppState::from_config(&cfg)?);
    let gw = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = gw.local_addr()?;
    let serve_state = state.clone();
    tokio::spawn(async move { axum::serve(gw, app(serve_state)).await });

    Ok(Harness {
        base: format!("http://{gw_addr}/mcp"),
        upstream_hits,
        audit,
        state,
        _dir: dir,
    })
}

async fn start() -> anyhow::Result<Harness> {
    // Fake upstream: counts hits, echoes the method back as a result.
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let upstream = Router::new().route(
        "/mcp",
        post(move |Json(msg): Json<Value>| {
            let h = h.clone();
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                Json(json!({"jsonrpc": "2.0", "id": msg["id"], "result": {"echo": msg["method"]}}))
            }
        }),
    );
    start_with_upstream(upstream, hits).await
}

fn tool_call(id: u64, tool: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {}}})
}

fn tool_call_with_args(id: u64, tool: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}})
}

async fn post_json(
    h: &Harness,
    token: Option<&str>,
    body: &Value,
) -> anyhow::Result<reqwest::Response> {
    let mut req = reqwest::Client::new().post(&h.base).json(body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    Ok(req.send().await?)
}

#[tokio::test]
async fn rejects_missing_or_unknown_token() -> anyhow::Result<()> {
    let h = start().await?;
    assert_eq!(
        post_json(&h, None, &tool_call(1, "sap.read_invoice"))
            .await?
            .status(),
        401
    );
    assert_eq!(
        post_json(&h, Some("wrong"), &tool_call(1, "sap.read_invoice"))
            .await?
            .status(),
        401
    );
    assert_eq!(h.upstream_hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn allowed_call_reaches_upstream() -> anyhow::Result<()> {
    let h = start().await?;
    let r: Value = post_json(&h, Some(TOKEN), &tool_call(7, "sap.read_invoice"))
        .await?
        .json()
        .await?;
    assert_eq!(r["id"], 7);
    assert_eq!(r["result"]["echo"], "tools/call");
    assert_eq!(h.upstream_hits.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn forbidden_call_is_blocked_and_never_forwarded() -> anyhow::Result<()> {
    let h = start().await?;
    let r: Value = post_json(&h, Some(TOKEN), &tool_call(8, "payroll.read_salaries"))
        .await?
        .json()
        .await?;
    assert_eq!(r["id"], 8);
    assert_eq!(r["error"]["code"], BLOCKED_CODE);
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("no-payroll")
    );
    assert_eq!(h.upstream_hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn non_tool_messages_pass_through() -> anyhow::Result<()> {
    let h = start().await?;
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let r: Value = post_json(&h, Some(TOKEN), &init).await?.json().await?;
    assert_eq!(r["result"]["echo"], "initialize");
    Ok(())
}

#[tokio::test]
async fn batches_and_garbage_are_rejected() -> anyhow::Result<()> {
    let h = start().await?;
    let batch = json!([tool_call(1, "payroll.read_salaries")]);
    assert_eq!(post_json(&h, Some(TOKEN), &batch).await?.status(), 400);
    let garbage = reqwest::Client::new()
        .post(&h.base)
        .bearer_auth(TOKEN)
        .body("not json")
        .send()
        .await?;
    assert_eq!(garbage.status(), 400);
    assert_eq!(h.upstream_hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn every_decision_is_audited_in_an_intact_chain() -> anyhow::Result<()> {
    let h = start().await?;
    post_json(&h, Some(TOKEN), &tool_call(1, "sap.read_invoice")).await?;
    post_json(&h, Some(TOKEN), &tool_call(2, "payroll.read_salaries")).await?;
    post_json(&h, Some(TOKEN), &tool_call(3, "sap.execute_payment")).await?;
    let (count, _) = custos_audit::verify(&h.audit)?;
    assert_eq!(count, 3);
    Ok(())
}

#[tokio::test]
async fn content_findings_are_recorded_on_the_audit_record() -> anyhow::Result<()> {
    let h = start().await?;
    let card = "4242424242424242"; // Stripe's published Luhn-valid test number
    post_json(
        &h,
        Some(TOKEN),
        &tool_call_with_args(1, "sap.read_invoice", json!({"card": card})),
    )
    .await?;

    let records: Vec<Value> = std::fs::read_to_string(&h.audit)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(records.len(), 1);
    let found_card = records[0]["findings"]
        .as_array()
        .is_some_and(|items| items.iter().any(|f| f["kind"] == "card"));
    assert!(found_card, "{:?}", records[0]);
    Ok(())
}

#[tokio::test]
async fn concurrent_tool_calls_are_all_audited_in_an_intact_chain() -> anyhow::Result<()> {
    let h = start().await?;
    const N: u64 = 20;
    let bodies: Vec<Value> = (1..=N)
        .map(|id| tool_call(id, "sap.read_invoice"))
        .collect();
    let calls = bodies.iter().map(|b| post_json(&h, Some(TOKEN), b));
    let results = futures_util::future::join_all(calls).await;
    for r in results {
        r?;
    }
    let (count, _) = custos_audit::verify(&h.audit)?;
    assert_eq!(count, N);
    Ok(())
}

#[tokio::test]
async fn hash_mode_without_key_id_fails_to_start() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let policy_dir = dir.path().join("policies");
    std::fs::create_dir(&policy_dir)?;
    std::fs::write(policy_dir.join("test.cedar"), POLICY)?;

    let cfg = config::Config {
        listen: "127.0.0.1:0".parse()?,
        upstream: "http://127.0.0.1:0/mcp".into(),
        upstream_authorization: None,
        policy_dir,
        audit_log: dir.path().join("audit.jsonl"),
        audit_arguments: config::AuditArgsMode::Hash,
        audit_key_id: None, // missing: "hash" mode must refuse to start
        instance_id: None,
        session_idle_timeout_secs: 86_400,
        max_sessions: 10_000,
        auth: config::AuthMode::Static,
        signing_keys: vec![],
        agents: vec![],
    };
    assert!(AppState::from_config(&cfg).is_err());
    Ok(())
}

#[tokio::test]
async fn reload_changes_the_policy_version_on_the_next_audit_record() -> anyhow::Result<()> {
    let h = start().await?;

    post_json(&h, Some(TOKEN), &tool_call(1, "sap.read_invoice")).await?;

    // Rewrite the policy the harness started with, then reload directly —
    // the same call SIGHUP and --watch-policies both make; this just skips
    // waiting on an OS signal or a filesystem debounce to prove it.
    let policy_dir = h.state.policy.dir().to_path_buf();
    std::fs::write(
        policy_dir.join("test.cedar"),
        r#"@id("no-invoices") forbid (principal, action, resource == Tool::"sap.read_invoice");"#,
    )?;
    let (old_version, new_version) = h.state.policy.reload()?;
    assert_ne!(old_version, new_version);

    // Same tool, now forbidden by the reloaded policy.
    let r: Value = post_json(&h, Some(TOKEN), &tool_call(2, "sap.read_invoice"))
        .await?
        .json()
        .await?;
    assert_eq!(r["error"]["code"], BLOCKED_CODE);

    let records: Vec<Value> = std::fs::read_to_string(&h.audit)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["policy_version"], old_version);
    assert_eq!(records[1]["policy_version"], new_version);
    Ok(())
}

// --- tools/list filtering -------------------------------------------------

fn tools_list(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}})
}

/// The three tools every fake `tools/list` fixture below offers: one the
/// test policy permits, one it explicitly forbids, one it never mentions
/// (blocked by default deny).
fn three_tools() -> Value {
    json!([
        {"name": "sap.read_invoice", "description": "allowed"},
        {"name": "payroll.read_salaries", "description": "explicitly forbidden"},
        {"name": "sap.execute_payment", "description": "unlisted, default-denied"},
    ])
}

/// Empty (rather than panicking) if `result.tools` is missing, not an array,
/// or a tool has no usable name — a mismatch there is a test bug, and an
/// empty `Vec` fails the `assert_eq!` just as loudly.
fn tool_names(list_response: &Value) -> Vec<&str> {
    list_response["result"]["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| t["name"].as_str())
        .collect()
}

/// Splits a raw SSE body into each event's parsed `data:` JSON, in order.
/// An event whose data isn't valid JSON is dropped rather than panicking.
fn sse_data_values(raw: &str) -> Vec<Value> {
    raw.split("\n\n")
        .filter(|event| !event.trim().is_empty())
        .filter_map(|event| event.lines().find_map(|l| l.strip_prefix("data:")))
        .filter_map(|d| serde_json::from_str(d.trim()).ok())
        .collect()
}

/// A fixed 200 response with a given content-type — used by the fake
/// upstreams below to hand back exactly the bytes a test wants to see
/// filtered (or not) by Custos.
fn fixed_response(content_type: &'static str, body: impl Into<axum::body::Body>) -> Response {
    let mut resp = Response::new(body.into());
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static(content_type),
    );
    resp
}

#[tokio::test]
async fn tools_list_json_hides_what_policy_would_block() -> anyhow::Result<()> {
    let upstream = Router::new().route(
        "/mcp",
        post(|Json(msg): Json<Value>| async move {
            Json(json!({"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": three_tools()}}))
        }),
    );
    let h = start_with_upstream(upstream, Arc::new(AtomicUsize::new(0))).await?;

    let r: Value = post_json(&h, Some(TOKEN), &tools_list(1))
        .await?
        .json()
        .await?;
    assert_eq!(tool_names(&r), vec!["sap.read_invoice"]);
    Ok(())
}

#[tokio::test]
async fn tools_list_sse_filters_the_response_and_leaves_notifications_alone() -> anyhow::Result<()>
{
    let upstream = Router::new().route(
        "/mcp",
        post(|Json(msg): Json<Value>| async move {
            let notification =
                json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"data": "working on it"}});
            let response = json!({"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": three_tools()}});
            let body = format!(
                "event: message\ndata: {notification}\n\nevent: message\ndata: {response}\n\n"
            );
            fixed_response("text/event-stream", body)
        }),
    );
    let h = start_with_upstream(upstream, Arc::new(AtomicUsize::new(0))).await?;

    let raw = post_json(&h, Some(TOKEN), &tools_list(2))
        .await?
        .text()
        .await?;
    let events = sse_data_values(&raw);
    assert_eq!(events.len(), 2);

    // The notification has no "id" at all, so it can never be our response
    // — it must pass through untouched, byte for byte.
    assert_eq!(events[0]["method"], "notifications/message");
    assert_eq!(events[0]["params"]["data"], "working on it");

    assert_eq!(tool_names(&events[1]), vec!["sap.read_invoice"]);
    Ok(())
}

#[tokio::test]
async fn tools_list_sse_event_with_different_id_is_not_rewritten() -> anyhow::Result<()> {
    let upstream = Router::new().route(
        "/mcp",
        post(|Json(msg): Json<Value>| async move {
            // Shaped exactly like a tools/list response, but for a
            // different in-flight request — must be left alone.
            let other =
                json!({"jsonrpc": "2.0", "id": 999_999, "result": {"tools": three_tools()}});
            let ours =
                json!({"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": three_tools()}});
            let body = format!("event: message\ndata: {other}\n\nevent: message\ndata: {ours}\n\n");
            fixed_response("text/event-stream", body)
        }),
    );
    let h = start_with_upstream(upstream, Arc::new(AtomicUsize::new(0))).await?;

    let raw = post_json(&h, Some(TOKEN), &tools_list(3))
        .await?
        .text()
        .await?;
    let events = sse_data_values(&raw);
    assert_eq!(events.len(), 2);

    assert_eq!(events[0]["id"], 999_999);
    assert_eq!(
        tool_names(&events[0]),
        vec![
            "sap.read_invoice",
            "payroll.read_salaries",
            "sap.execute_payment"
        ]
    );

    assert_eq!(events[1]["id"], 3);
    assert_eq!(tool_names(&events[1]), vec!["sap.read_invoice"]);
    Ok(())
}

#[tokio::test]
async fn tools_list_unknown_content_type_fails_closed() -> anyhow::Result<()> {
    let upstream =
        Router::new().route(
            "/mcp",
            post(|| async move {
                fixed_response("text/plain", "sap.read_invoice, payroll.read_salaries")
            }),
        );
    let h = start_with_upstream(upstream, Arc::new(AtomicUsize::new(0))).await?;

    let r: Value = post_json(&h, Some(TOKEN), &tools_list(4))
        .await?
        .json()
        .await?;
    assert_eq!(r["id"], 4);
    assert_eq!(r["error"]["code"], BLOCKED_CODE);
    Ok(())
}

// --- session binding -------------------------------------------------

/// A fake upstream that always tags its response with a fixed
/// `Mcp-Session-Id`, as if it had just created (or were continuing) that
/// session, and accepts `DELETE` (returning 200, no body).
fn upstream_with_session_header(session_id: &'static str, hits: Arc<AtomicUsize>) -> Router {
    let post_hits = hits.clone();
    Router::new().route(
        "/mcp",
        post(move |Json(msg): Json<Value>| {
            let hits = post_hits.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let mut resp = Json(
                    json!({"jsonrpc": "2.0", "id": msg["id"], "result": {"echo": msg["method"]}}),
                )
                .into_response();
                resp.headers_mut()
                    .insert("mcp-session-id", HeaderValue::from_static(session_id));
                resp
            }
        })
        .delete(move || {
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        }),
    )
}

/// Like `start_with_upstream`, but with two agents (`TOKEN_A`/`TOKEN_B`)
/// instead of one — needed for the session-binding tests, where a second
/// agent tries to reuse the first one's session.
async fn start_with_two_agents(
    upstream: Router,
    upstream_hits: Arc<AtomicUsize>,
) -> anyhow::Result<Harness> {
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up.local_addr()?;
    tokio::spawn(async move { axum::serve(up, upstream).await });

    let dir = tempfile::tempdir()?;
    let policy_dir = dir.path().join("policies");
    std::fs::create_dir(&policy_dir)?;
    std::fs::write(policy_dir.join("test.cedar"), POLICY)?;
    let audit = dir.path().join("audit.jsonl");

    let cfg = config::Config {
        listen: "127.0.0.1:0".parse()?,
        upstream: format!("http://{up_addr}/mcp"),
        upstream_authorization: None,
        policy_dir,
        audit_log: audit.clone(),
        audit_arguments: config::AuditArgsMode::Full,
        audit_key_id: None,
        instance_id: Some("test-instance".into()),
        session_idle_timeout_secs: 86_400,
        max_sessions: 10_000,
        auth: config::AuthMode::Static,
        signing_keys: vec![],
        agents: vec![
            config::AgentConfig {
                id: "agent-a".into(),
                owner: None,
                token_sha256: hash_token(TOKEN_A),
            },
            config::AgentConfig {
                id: "agent-b".into(),
                owner: None,
                token_sha256: hash_token(TOKEN_B),
            },
        ],
    };
    let state = Arc::new(AppState::from_config(&cfg)?);
    let gw = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = gw.local_addr()?;
    let serve_state = state.clone();
    tokio::spawn(async move { axum::serve(gw, app(serve_state)).await });

    Ok(Harness {
        base: format!("http://{gw_addr}/mcp"),
        upstream_hits,
        audit,
        state,
        _dir: dir,
    })
}

async fn post_with_session(
    h: &Harness,
    token: &str,
    session_id: &str,
    body: &Value,
) -> anyhow::Result<reqwest::Response> {
    Ok(reqwest::Client::new()
        .post(&h.base)
        .bearer_auth(token)
        .header("Mcp-Session-Id", session_id)
        .json(body)
        .send()
        .await?)
}

async fn delete_with_session(
    h: &Harness,
    token: &str,
    session_id: &str,
) -> anyhow::Result<reqwest::Response> {
    Ok(reqwest::Client::new()
        .delete(&h.base)
        .bearer_auth(token)
        .header("Mcp-Session-Id", session_id)
        .send()
        .await?)
}

#[tokio::test]
async fn session_reused_by_another_agent_is_forbidden_and_never_forwarded() -> anyhow::Result<()> {
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = upstream_with_session_header("shared-session", hits.clone());
    let h = start_with_two_agents(upstream, hits.clone()).await?;

    // Agent A's first request carries no session id yet — upstream's
    // response introduces one, which the gateway binds to agent A.
    post_json(
        &h,
        Some(TOKEN_A),
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
    )
    .await?;
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Agent B tries to use that same session.
    let r = post_with_session(
        &h,
        TOKEN_B,
        "shared-session",
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "x", "arguments": {}}}),
    )
    .await?;
    assert_eq!(r.status(), 403);
    // Never reached upstream: the hit count from agent A's call is unchanged.
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn unknown_session_is_rejected() -> anyhow::Result<()> {
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = upstream_with_session_header("irrelevant", hits.clone());
    let h = start_with_two_agents(upstream, hits.clone()).await?;

    let r = post_with_session(
        &h,
        TOKEN_A,
        "no-such-session",
        &json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
    )
    .await?;
    assert_eq!(r.status(), 404);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn deleted_session_is_rejected_afterward() -> anyhow::Result<()> {
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = upstream_with_session_header("to-delete", hits.clone());
    let h = start_with_two_agents(upstream, hits.clone()).await?;

    post_json(
        &h,
        Some(TOKEN_A),
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
    )
    .await?;

    let deleted = delete_with_session(&h, TOKEN_A, "to-delete").await?;
    assert!(deleted.status().is_success());

    let r = post_with_session(
        &h,
        TOKEN_A,
        "to-delete",
        &json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
    )
    .await?;
    assert_eq!(r.status(), 404);
    Ok(())
}

// --- signed tokens (auth = "signed") ----------------------------------

/// Like `start()`, but `auth = "signed"` with the given trusted keys instead
/// of a static token list.
async fn start_with_signed_auth(
    signing_keys: Vec<config::SigningKeyConfig>,
) -> anyhow::Result<Harness> {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let upstream = Router::new().route(
        "/mcp",
        post(move |Json(msg): Json<Value>| {
            let h = h.clone();
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                Json(json!({"jsonrpc": "2.0", "id": msg["id"], "result": {"echo": msg["method"]}}))
            }
        }),
    );
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up.local_addr()?;
    tokio::spawn(async move { axum::serve(up, upstream).await });

    let dir = tempfile::tempdir()?;
    let policy_dir = dir.path().join("policies");
    std::fs::create_dir(&policy_dir)?;
    std::fs::write(
        policy_dir.join("test.cedar"),
        r#"permit (principal, action, resource == Tool::"sap.read_invoice");"#,
    )?;
    let audit = dir.path().join("audit.jsonl");

    let cfg = config::Config {
        listen: "127.0.0.1:0".parse()?,
        upstream: format!("http://{up_addr}/mcp"),
        upstream_authorization: None,
        policy_dir,
        audit_log: audit.clone(),
        audit_arguments: config::AuditArgsMode::Full,
        audit_key_id: None,
        instance_id: Some("test-instance".into()),
        session_idle_timeout_secs: 86_400,
        max_sessions: 10_000,
        auth: config::AuthMode::Signed,
        signing_keys,
        agents: vec![],
    };
    let state = Arc::new(AppState::from_config(&cfg)?);
    let gw = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = gw.local_addr()?;
    let serve_state = state.clone();
    tokio::spawn(async move { axum::serve(gw, app(serve_state)).await });

    Ok(Harness {
        base: format!("http://{gw_addr}/mcp"),
        upstream_hits: hits,
        audit,
        state,
        _dir: dir,
    })
}

fn test_signing_key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn signing_key_config(key_id: &str, key: &ed25519_dalek::SigningKey) -> config::SigningKeyConfig {
    config::SigningKeyConfig {
        key_id: key_id.to_string(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
    }
}

#[tokio::test]
async fn valid_signed_token_authenticates() -> anyhow::Result<()> {
    let key = test_signing_key(1);
    let h = start_with_signed_auth(vec![signing_key_config("k1", &key)]).await?;
    let token = custos_tokens::issue(
        &key,
        "invoice-processor",
        custos_gateway::now_unix(),
        3600,
        "k1",
    );

    let r: Value = post_json(&h, Some(&token), &tool_call(1, "sap.read_invoice"))
        .await?
        .json()
        .await?;
    assert_eq!(r["result"]["echo"], "tools/call");
    assert_eq!(h.upstream_hits.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn expired_signed_token_is_rejected() -> anyhow::Result<()> {
    let key = test_signing_key(1);
    let h = start_with_signed_auth(vec![signing_key_config("k1", &key)]).await?;
    // Issued an hour ago with a 1-second TTL: already expired.
    let token = custos_tokens::issue(
        &key,
        "invoice-processor",
        custos_gateway::now_unix() - 3600,
        1,
        "k1",
    );

    let status = post_json(&h, Some(&token), &tool_call(1, "sap.read_invoice"))
        .await?
        .status();
    assert_eq!(status, 401);
    assert_eq!(h.upstream_hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn signed_token_from_an_untrusted_key_is_rejected() -> anyhow::Result<()> {
    let trusted = test_signing_key(1);
    let untrusted = test_signing_key(2);
    // The gateway only trusts "k1" -> trusted's public key; a token signed
    // by a different key, even under the same key_id, must not verify.
    let h = start_with_signed_auth(vec![signing_key_config("k1", &trusted)]).await?;
    let token = custos_tokens::issue(
        &untrusted,
        "invoice-processor",
        custos_gateway::now_unix(),
        3600,
        "k1",
    );

    let status = post_json(&h, Some(&token), &tool_call(1, "sap.read_invoice"))
        .await?
        .status();
    assert_eq!(status, 401);
    assert_eq!(h.upstream_hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn tampered_signed_token_is_rejected() -> anyhow::Result<()> {
    let key = test_signing_key(1);
    let h = start_with_signed_auth(vec![signing_key_config("k1", &key)]).await?;
    let token = custos_tokens::issue(
        &key,
        "invoice-processor",
        custos_gateway::now_unix(),
        3600,
        "k1",
    );
    let Some((payload_part, sig_part)) = token.split_once('.') else {
        panic!("token must have a payload and a signature segment");
    };
    // Flip one character in the (base64) payload segment — same shape,
    // different, unsigned content.
    let mut chars: Vec<char> = payload_part.chars().collect();
    if let Some(c) = chars.first_mut() {
        *c = if *c == 'a' { 'b' } else { 'a' };
    }
    let tampered = format!("{}.{sig_part}", chars.into_iter().collect::<String>());

    let status = post_json(&h, Some(&tampered), &tool_call(1, "sap.read_invoice"))
        .await?
        .status();
    assert_eq!(status, 401);
    assert_eq!(h.upstream_hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn key_rotation_accepts_tokens_from_either_key() -> anyhow::Result<()> {
    let old_key = test_signing_key(1);
    let new_key = test_signing_key(2);
    let h = start_with_signed_auth(vec![
        signing_key_config("old", &old_key),
        signing_key_config("new", &new_key),
    ])
    .await?;

    let old_token = custos_tokens::issue(
        &old_key,
        "invoice-processor",
        custos_gateway::now_unix(),
        3600,
        "old",
    );
    let new_token = custos_tokens::issue(
        &new_key,
        "invoice-processor",
        custos_gateway::now_unix(),
        3600,
        "new",
    );

    for token in [old_token, new_token] {
        let status = post_json(&h, Some(&token), &tool_call(1, "sap.read_invoice"))
            .await?
            .status();
        assert_eq!(status, 200);
    }
    assert_eq!(h.upstream_hits.load(Ordering::SeqCst), 2);
    Ok(())
}
