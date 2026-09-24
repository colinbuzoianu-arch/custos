//! Custos gateway.
//!
//! Sits in front of one MCP server (streamable HTTP transport). Every request
//! must carry an agent's bearer token. Every `tools/call` is checked against
//! Cedar policy and written to the audit log *before* it is forwarded.
//! Anything the gateway cannot understand is rejected: fail closed.

pub mod config;

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use custos_audit::AuditLog;
use custos_core::{AgentId, Decision, ToolCall};
use custos_policy::PolicyEngine;
use futures_util::TryStreamExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// JSON-RPC error code returned when Custos blocks a call.
pub const BLOCKED_CODE: i64 = -32001;

/// Headers passed between agent and upstream. Everything else is dropped,
/// in particular the agent's own `Authorization`.
const FORWARD_REQUEST_HEADERS: &[&str] = &[
    "content-type",
    "accept",
    "mcp-session-id",
    "mcp-protocol-version",
    "last-event-id",
];
const FORWARD_RESPONSE_HEADERS: &[&str] = &["content-type", "mcp-session-id", "cache-control"];

pub struct AppState {
    pub policy: PolicyEngine,
    pub audit: Mutex<AuditLog>,
    /// sha256(token) hex → agent
    pub agents: HashMap<String, AgentId>,
    pub upstream: String,
    pub upstream_authorization: Option<String>,
    pub client: reqwest::Client,
}

impl AppState {
    pub fn from_config(cfg: &config::Config) -> anyhow::Result<Self> {
        let policy = PolicyEngine::from_dir(&cfg.policy_dir)?;
        let audit = AuditLog::open(&cfg.audit_log)?;
        let agents = cfg
            .agents
            .iter()
            .map(|a| (a.token_sha256.to_lowercase(), AgentId(a.id.clone())))
            .collect();
        Ok(Self {
            policy,
            audit: Mutex::new(audit),
            agents,
            upstream: cfg.upstream.clone(),
            upstream_authorization: cfg.upstream_authorization.clone(),
            client: reqwest::Client::new(),
        })
    }
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/mcp", any(handle))
        .route("/healthz", any(|| async { "ok" }))
        .with_state(state)
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> Option<AgentId> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        return None;
    }
    // Lookup is by hash, so the plain token is never compared or stored.
    state.agents.get(&hash_token(token)).cloned()
}

async fn handle(
    State(state): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(agent) = authenticate(&state, &headers) else {
        return (StatusCode::UNAUTHORIZED, "missing or unknown agent token").into_response();
    };

    if method == Method::POST {
        let msg: Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return (StatusCode::BAD_REQUEST, "body is not JSON").into_response(),
        };
        // MCP (2025-06-18+) has no JSON-RPC batching. Rejecting arrays means
        // a tool call can never hide inside a batch.
        if !msg.is_object() {
            return (
                StatusCode::BAD_REQUEST,
                "expected a single JSON-RPC message",
            )
                .into_response();
        }
        if msg.get("method").and_then(Value::as_str) == Some("tools/call")
            && let Some(blocked) = check_tool_call(&state, &agent, &msg)
        {
            return blocked;
        }
    } else if method != Method::GET && method != Method::DELETE {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    forward(&state, method, &headers, body).await
}

/// Returns `Some(response)` if the call must not be forwarded.
fn check_tool_call(state: &AppState, agent: &AgentId, msg: &Value) -> Option<Response> {
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let params = msg.get("params");
    let Some(tool) = params.and_then(|p| p.get("name")).and_then(Value::as_str) else {
        return Some(rpc_error(
            id,
            BLOCKED_CODE,
            "Blocked by Custos: tool name missing",
        ));
    };
    let call = ToolCall {
        agent: agent.clone(),
        tool: tool.to_string(),
        arguments: params
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or(Value::Null),
    };
    let decision = state.policy.decide(&call);

    // Record before acting. If the audit write fails, nothing goes through.
    let audited = match state.audit.lock() {
        Ok(mut log) => log.append(&call, &decision).is_ok(),
        Err(_) => false,
    };
    if !audited {
        tracing::error!(agent = %agent, tool, "audit write failed; blocking");
        return Some((StatusCode::SERVICE_UNAVAILABLE, "audit log unavailable").into_response());
    }

    tracing::info!(agent = %agent, tool, decision = ?decision, "tool call");
    match decision {
        Decision::Allow => None,
        Decision::Block { reason } | Decision::Hold { reason } => Some(rpc_error(
            id,
            BLOCKED_CODE,
            &format!("Blocked by Custos: {reason}"),
        )),
    }
}

fn rpc_error(id: Value, code: i64, message: &str) -> Response {
    let body = json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } });
    (StatusCode::OK, axum::Json(body)).into_response()
}

async fn forward(state: &AppState, method: Method, headers: &HeaderMap, body: Bytes) -> Response {
    let mut req = state.client.request(method.clone(), &state.upstream);
    for name in FORWARD_REQUEST_HEADERS {
        if let Some(v) = headers.get(*name) {
            req = req.header(*name, v);
        }
    }
    if let Some(auth) = &state.upstream_authorization {
        req = req.header(header::AUTHORIZATION, auth);
    }
    if method == Method::POST {
        req = req.body(body);
    }

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "upstream unreachable");
            return (StatusCode::BAD_GATEWAY, "upstream MCP server unreachable").into_response();
        }
    };

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut out = HeaderMap::new();
    for name in FORWARD_RESPONSE_HEADERS {
        if let Some(v) = upstream.headers().get(*name)
            && let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_bytes(v.as_bytes()),
            )
        {
            out.insert(n, v);
        }
    }
    // Stream the body so SSE responses pass through as they arrive.
    let stream = upstream.bytes_stream().map_err(std::io::Error::other);
    let mut resp = Response::new(Body::from_stream(stream));
    *resp.status_mut() = status;
    *resp.headers_mut() = out;
    resp
}
