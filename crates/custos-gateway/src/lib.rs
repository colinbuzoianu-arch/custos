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
use custos_policy::PolicyStore;
use futures_util::{Stream, StreamExt, TryStreamExt, stream::unfold};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::pin::Pin;
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
    pub policy: PolicyStore,
    pub audit: Mutex<AuditLog>,
    /// sha256(token) hex → agent
    pub agents: HashMap<String, AgentId>,
    /// agent → human owner, for the audit log. Looked up separately from
    /// `agents` so `authenticate` can keep returning a plain `AgentId`.
    pub owners: HashMap<AgentId, Option<String>>,
    pub upstream: String,
    pub upstream_authorization: Option<String>,
    pub client: reqwest::Client,
}

impl AppState {
    pub fn from_config(cfg: &config::Config) -> anyhow::Result<Self> {
        let policy = PolicyStore::open(cfg.policy_dir.clone())?;
        let args_policy = cfg.args_policy()?;
        let audit = AuditLog::open(&cfg.audit_log, args_policy, cfg.gateway_instance())?;
        let agents = cfg
            .agents
            .iter()
            .map(|a| (a.token_sha256.to_lowercase(), AgentId(a.id.clone())))
            .collect();
        let owners = cfg
            .agents
            .iter()
            .map(|a| (AgentId(a.id.clone()), a.owner.clone()))
            .collect();
        Ok(Self {
            policy,
            audit: Mutex::new(audit),
            agents,
            owners,
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

fn log_reload_result(result: Result<(String, String), custos_policy::PolicyError>) {
    match result {
        Ok((old, new)) => {
            tracing::info!(old_version = %old, new_version = %new, "policy reloaded");
        }
        Err(e) => {
            tracing::error!(error = %e, "policy reload failed; keeping the previous policy");
        }
    }
}

/// Starts every way the policy set can be reloaded without restarting the
/// gateway. On Unix, `SIGHUP` always triggers a reload. If `watch_policies`
/// is set, a debounced (~500ms) file watcher on the policy directory also
/// triggers one, on any platform. Both call the same `PolicyStore::reload`,
/// so both share its all-or-nothing, never-fall-back-to-no-policy guarantee.
///
/// The returned guard must be kept alive (bound to a variable, not
/// dropped) for as long as the file watcher should keep running; dropping it
/// stops the watch. `None` if `watch_policies` was false.
pub fn spawn_policy_reload_triggers(
    state: Arc<AppState>,
    watch_policies: bool,
) -> anyhow::Result<
    Option<notify_debouncer_mini::Debouncer<notify_debouncer_mini::notify::RecommendedWatcher>>,
> {
    #[cfg(unix)]
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sig = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "could not install SIGHUP handler");
                    return;
                }
            };
            loop {
                sig.recv().await;
                tracing::info!("SIGHUP received; reloading policy");
                log_reload_result(state.policy.reload());
            }
        });
    }

    if !watch_policies {
        return Ok(None);
    }

    let watch_state = Arc::clone(&state);
    let mut debouncer = notify_debouncer_mini::new_debouncer(
        std::time::Duration::from_millis(500),
        move |result: notify_debouncer_mini::DebounceEventResult| match result {
            Ok(events) if events.is_empty() => {}
            Ok(_) => {
                tracing::info!("policy directory changed; reloading policy");
                log_reload_result(watch_state.policy.reload());
            }
            Err(e) => tracing::warn!(error = %e, "policy directory watch error"),
        },
    )?;
    debouncer.watcher().watch(
        state.policy.dir(),
        notify_debouncer_mini::notify::RecursiveMode::NonRecursive,
    )?;
    Ok(Some(debouncer))
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

    // Set only for a `tools/list` request: the id whose response, once it
    // comes back from upstream, must be filtered down to what this agent may
    // call. Every other message (tools/call, initialize, notifications...)
    // leaves this `None` and passes through `forward` unmodified.
    let mut tools_list_id = None;

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
        match msg.get("method").and_then(Value::as_str) {
            Some("tools/call") => {
                if let Some(blocked) = check_tool_call(&state, &agent, &msg).await {
                    return blocked;
                }
            }
            Some("tools/list") => {
                tools_list_id = Some(msg.get("id").cloned().unwrap_or(Value::Null));
            }
            _ => {}
        }
    } else if method != Method::GET && method != Method::DELETE {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    forward(state, agent, method, &headers, body, tools_list_id).await
}

/// Returns `Some(response)` if the call must not be forwarded.
async fn check_tool_call(state: &Arc<AppState>, agent: &AgentId, msg: &Value) -> Option<Response> {
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
    // One snapshot for the whole call: the decision and the audit record's
    // policy_version both come from it, so this request is decided by (and
    // says it was decided by) the exact policy that was live when it
    // started, even if a reload replaces it before the write below finishes.
    let policy = state.policy.snapshot();
    let decision = policy.engine.decide(&call);

    // Record before acting. The write (and its fsync) run on a blocking
    // thread so they never stall the async reactor, but this still waits
    // right here for it to finish: if the audit write fails, nothing goes
    // through.
    let write_state = Arc::clone(state);
    let write_call = call.clone();
    let write_decision = decision.clone();
    let owner = state.owners.get(agent).cloned().flatten();
    let policy_version = policy.version.clone();
    let audited = tokio::task::spawn_blocking(move || match write_state.audit.lock() {
        Ok(mut log) => log
            .append(
                &write_call,
                &write_decision,
                owner.as_deref(),
                &policy_version,
            )
            .is_ok(),
        Err(_) => false,
    })
    .await
    .unwrap_or(false);
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

/// Forwards a request upstream. If `tools_list_id` is `Some`, this was a
/// `tools/list` request: the response is filtered down to the tools this
/// agent's policy allows before it reaches the agent. Otherwise the response
/// streams through untouched, exactly as before.
async fn forward(
    state: Arc<AppState>,
    agent: AgentId,
    method: Method,
    headers: &HeaderMap,
    body: Bytes,
    tools_list_id: Option<Value>,
) -> Response {
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

    let Some(want_id) = tools_list_id else {
        // Stream the body so SSE responses pass through as they arrive.
        let stream = upstream.bytes_stream().map_err(std::io::Error::other);
        let mut resp = Response::new(Body::from_stream(stream));
        *resp.status_mut() = status;
        *resp.headers_mut() = out;
        return resp;
    };

    let content_type = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();

    // One snapshot for the whole response, same reasoning as check_tool_call:
    // every tool in this one tools/list reply is judged by the same policy,
    // even if a reload lands while a slow SSE response is still streaming.
    let policy = state.policy.snapshot();

    if content_type.starts_with("application/json") {
        let bytes = match upstream.bytes().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "reading upstream tools/list response failed");
                return blocked_tools_list(want_id);
            }
        };
        return match filter_tools_list_json(&bytes, &want_id, &policy.engine, &agent) {
            Ok((filtered, hidden)) => {
                tracing::info!(agent = %agent, hidden, "tools/list filtered");
                let mut resp = axum::Json(filtered).into_response();
                *resp.status_mut() = status;
                for (name, value) in &out {
                    resp.headers_mut().insert(name.clone(), value.clone());
                }
                resp
            }
            Err(()) => blocked_tools_list(want_id),
        };
    }

    if content_type.starts_with("text/event-stream") {
        let stream = sse_filter_stream(upstream.bytes_stream(), want_id, policy, agent);
        let mut resp = Response::new(Body::from_stream(stream));
        *resp.status_mut() = status;
        *resp.headers_mut() = out;
        return resp;
    }

    tracing::warn!(
        content_type,
        "unexpected content-type for tools/list response"
    );
    blocked_tools_list(want_id)
}

fn blocked_tools_list(id: Value) -> Response {
    rpc_error(
        id,
        BLOCKED_CODE,
        "Blocked by Custos: tools/list response could not be filtered",
    )
}

/// True if `agent`'s policy would allow it to call `tool`. Arguments never
/// affect this (Cedar evaluates with no context), so an empty call is enough.
fn may_call(engine: &custos_policy::PolicyEngine, agent: &AgentId, tool: &str) -> bool {
    engine
        .decide(&ToolCall {
            agent: agent.clone(),
            tool: tool.to_string(),
            arguments: Value::Null,
        })
        .is_allowed()
}

/// Drops every tool from `msg["result"]["tools"]` that `agent` may not call,
/// including any tool object without a usable `name`. Returns how many were
/// hidden, or `Err` if `msg` isn't a `tools/list` result we understand.
fn filter_result_tools(
    msg: &mut Value,
    engine: &custos_policy::PolicyEngine,
    agent: &AgentId,
) -> Result<usize, ()> {
    let result = msg.get_mut("result").ok_or(())?;
    let tools = result.get_mut("tools").ok_or(())?;
    let arr = tools.as_array_mut().ok_or(())?;
    let before = arr.len();
    arr.retain(|tool| {
        tool.get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| may_call(engine, agent, name))
    });
    Ok(before - arr.len())
}

/// Parses a buffered `application/json` `tools/list` response and filters
/// it. `Err` means the shape wasn't one we recognise (wrong id, no
/// `result.tools` array, ...) — the caller must fail closed, never forward
/// `bytes` unfiltered.
fn filter_tools_list_json(
    bytes: &[u8],
    want_id: &Value,
    engine: &custos_policy::PolicyEngine,
    agent: &AgentId,
) -> Result<(Value, usize), ()> {
    let mut msg: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    if !msg.is_object() || msg.get("id") != Some(want_id) {
        return Err(());
    }
    // An upstream error for this call has nothing to filter and nothing to
    // leak; pass it through as-is.
    if msg.get("error").is_some() {
        return Ok((msg, 0));
    }
    let hidden = filter_result_tools(&mut msg, engine, agent)?;
    Ok((msg, hidden))
}

/// Finds the first complete SSE event in `buf` (up to and including its
/// blank-line terminator) and returns `(content_len, total_len)`: bytes
/// `[0, content_len)` are the event's fields, `[content_len, total_len)` is
/// the terminator itself. `None` means the buffer holds no full event yet.
fn find_sse_event(buf: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = find_subslice(buf, b"\n\n") {
        return Some((pos, pos + 2));
    }
    find_subslice(buf, b"\r\n\r\n").map(|pos| (pos, pos + 4))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Rewrites one SSE event if its `data:` field is the `tools/list` response
/// we're watching for (matching JSON-RPC id); every other event — a
/// notification, a different in-flight request, a heartbeat — passes through
/// byte-for-byte. Only the `data:` line(s) are ever touched; `event:`/`id:`
/// (the SSE transport id, unrelated to the JSON-RPC id inside `data:`) are
/// preserved exactly.
fn process_sse_event(
    content: &[u8],
    terminator: &[u8],
    want_id: &Value,
    engine: &custos_policy::PolicyEngine,
    agent: &AgentId,
) -> (Vec<u8>, Option<usize>) {
    let unchanged = || {
        let mut v = content.to_vec();
        v.extend_from_slice(terminator);
        v
    };

    let Ok(text) = std::str::from_utf8(content) else {
        return (unchanged(), None);
    };
    let data_lines: Vec<&str> = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim_start)
        .collect();
    if data_lines.is_empty() {
        return (unchanged(), None);
    }
    let Ok(mut msg) = serde_json::from_str::<Value>(&data_lines.join("\n")) else {
        return (unchanged(), None);
    };
    if msg.get("id") != Some(want_id) {
        return (unchanged(), None);
    }

    let (new_data, hidden) = match filter_result_tools(&mut msg, engine, agent) {
        Ok(hidden) => (serde_json::to_string(&msg).unwrap_or_default(), hidden),
        Err(()) => (blocked_tools_list_data(want_id), 0),
    };

    let mut out_lines: Vec<String> = Vec::new();
    let mut data_written = false;
    for line in text.split('\n') {
        let bare = line.strip_suffix('\r').unwrap_or(line);
        if bare.starts_with("data:") {
            if !data_written {
                out_lines.push(format!("data: {new_data}"));
                data_written = true;
            }
        } else {
            out_lines.push(bare.to_string());
        }
    }
    let mut out = out_lines.join("\n").into_bytes();
    out.extend_from_slice(terminator);
    (out, Some(hidden))
}

fn blocked_tools_list_data(id: &Value) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": BLOCKED_CODE,
            "message": "Blocked by Custos: tools/list response could not be filtered",
        }
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

struct SseFilterState {
    inner: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
    buf: Vec<u8>,
    upstream_done: bool,
    want_id: Value,
    policy: Arc<custos_policy::Versioned>,
    agent: AgentId,
    logged: bool,
}

/// Wraps an upstream SSE byte stream, rewriting only the one event that
/// carries our `tools/list` response as it arrives. Bytes are handed to the
/// agent event by event, not buffered in full: the wrapper holds only the
/// current incomplete tail of the stream, however long the connection stays
/// open.
fn sse_filter_stream(
    inner: impl Stream<Item = reqwest::Result<Bytes>> + Send + 'static,
    want_id: Value,
    policy: Arc<custos_policy::Versioned>,
    agent: AgentId,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> {
    let init = SseFilterState {
        inner: Box::pin(inner),
        buf: Vec::new(),
        upstream_done: false,
        want_id,
        policy,
        agent,
        logged: false,
    };
    unfold(init, |mut st| async move {
        loop {
            if let Some((content_len, total_len)) = find_sse_event(&st.buf) {
                let content = st.buf[..content_len].to_vec();
                let terminator = st.buf[content_len..total_len].to_vec();
                let (out, hidden) = process_sse_event(
                    &content,
                    &terminator,
                    &st.want_id,
                    &st.policy.engine,
                    &st.agent,
                );
                st.buf.drain(..total_len);
                if let Some(hidden) = hidden
                    && !st.logged
                {
                    st.logged = true;
                    tracing::info!(agent = %st.agent, hidden, "tools/list filtered");
                }
                return Some((Ok(Bytes::from(out)), st));
            }
            if st.upstream_done {
                if st.buf.is_empty() {
                    return None;
                }
                let out = std::mem::take(&mut st.buf);
                return Some((Ok(Bytes::from(out)), st));
            }
            match st.inner.next().await {
                Some(Ok(chunk)) => st.buf.extend_from_slice(&chunk),
                Some(Err(e)) => return Some((Err(std::io::Error::other(e)), st)),
                None => st.upstream_done = true,
            }
        }
    })
}
