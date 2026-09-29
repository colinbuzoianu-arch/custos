//! End-to-end: a fake upstream MCP server, the real gateway, a real HTTP client.

use axum::{Json, Router, http::HeaderValue, response::Response, routing::post};
use custos_gateway::{AppState, BLOCKED_CODE, app, config, hash_token};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const TOKEN: &str = "test-token-invoice";

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
        agents: vec![config::AgentConfig {
            id: "invoice-processor".into(),
            owner: Some("finance".into()),
            token_sha256: hash_token(TOKEN),
        }],
    };
    let state = Arc::new(AppState::from_config(&cfg)?);
    let gw = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = gw.local_addr()?;
    tokio::spawn(async move { axum::serve(gw, app(state)).await });

    Ok(Harness {
        base: format!("http://{gw_addr}/mcp"),
        upstream_hits,
        audit,
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
        agents: vec![],
    };
    assert!(AppState::from_config(&cfg).is_err());
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
