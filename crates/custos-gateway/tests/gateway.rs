//! End-to-end: a fake upstream MCP server, the real gateway, a real HTTP client.

use axum::{Json, Router, routing::post};
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
        upstream_hits: hits,
        audit,
        _dir: dir,
    })
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
