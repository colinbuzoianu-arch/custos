//! Custos gateway.
//!
//! Sits in front of one MCP server (streamable HTTP transport). Every request
//! must carry an agent's bearer token. Every `tools/call` is checked against
//! Cedar policy and written to the audit log *before* it is forwarded.
//! Anything the gateway cannot understand is rejected: fail closed.

pub mod config;
pub mod control_sync;

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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// A pseudo-tool name used only to audit a session-binding violation — never
/// a real upstream tool, so it can't collide with one.
const SESSION_REUSE_TOOL: &str = "custos/session-reuse-attempt";

/// Which agent created an MCP session, and when it was last used — so agent
/// B can't reuse agent A's session, and idle sessions don't accumulate
/// forever.
struct SessionEntry {
    agent: AgentId,
    last_seen: Instant,
}

pub struct AppState {
    pub policy: PolicyStore,
    pub audit: Mutex<AuditLog>,
    pub auth: config::AuthMode,
    /// sha256(token) hex → agent. Only consulted when `auth = "static"`.
    pub agents: HashMap<String, AgentId>,
    /// key_id → public key. Only consulted when `auth = "signed"`.
    pub verifying_keys: HashMap<String, ed25519_dalek::VerifyingKey>,
    /// agent → human owner, for the audit log. Looked up separately from
    /// `agents` so `authenticate` can keep returning a plain `AgentId`.
    pub owners: HashMap<AgentId, Option<String>>,
    /// Agents most recently seen in a synced, verified policy bundle
    /// (session 12/18): token hash → agent id. Replaced wholesale on every
    /// successful sync, never merged with the previous contents — a
    /// rotated or removed agent's old token stops working the moment the
    /// next bundle is applied, rather than lingering until a restart.
    /// Only consulted when `auth = "static"`, alongside `agents` (the
    /// config-defined set, which this never touches).
    synced_agents: Mutex<HashMap<String, AgentId>>,
    /// `Mcp-Session-Id` → who created it.
    sessions: Mutex<HashMap<String, SessionEntry>>,
    session_idle_timeout: Duration,
    max_sessions: usize,
    pub upstream: String,
    pub upstream_authorization: Option<String>,
    pub client: reqwest::Client,
    /// Cumulative since this process started — reported in the
    /// heartbeat to Custos Control (session 12), never reset between
    /// heartbeats.
    pub decisions_allowed: AtomicU64,
    pub decisions_blocked: AtomicU64,
    /// `Some` only when `[control]` is configured and its enrollment state
    /// loaded successfully. `None` means every `@hold` fails closed to
    /// `Block` — there's no way to ask a human anything.
    pub control_approvals: Option<Arc<control_sync::ApprovalClient>>,
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
        let verifying_keys = cfg.verifying_keys()?;
        let control_approvals = cfg
            .control
            .as_ref()
            .and_then(control_sync::ApprovalClient::build)
            .map(Arc::new);
        Ok(Self {
            policy,
            audit: Mutex::new(audit),
            auth: cfg.auth,
            agents,
            verifying_keys,
            owners,
            synced_agents: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            session_idle_timeout: Duration::from_secs(cfg.session_idle_timeout_secs),
            max_sessions: cfg.max_sessions,
            upstream: cfg.upstream.clone(),
            upstream_authorization: cfg.upstream_authorization.clone(),
            client: reqwest::Client::new(),
            decisions_allowed: AtomicU64::new(0),
            decisions_blocked: AtomicU64::new(0),
            control_approvals,
        })
    }

    /// Replaces the set of agents trusted via a synced, verified policy
    /// bundle with exactly what that bundle currently lists — never merged
    /// with what was there before, so an agent a new bundle stops
    /// mentioning (token rotated, agent disabled or deleted in Control)
    /// loses access the moment this runs, not just eventually. Only
    /// consulted by [`authenticate`] when `auth = "static"`; never touches
    /// `agents`, the config-defined set.
    pub fn apply_synced_agents(&self, agents: &[custos_policy::bundle::BundleAgent]) {
        let mut map = HashMap::with_capacity(agents.len());
        for agent in agents {
            if let Some(hash) = &agent.token_sha256 {
                map.insert(hash.to_lowercase(), AgentId(agent.name.clone()));
            }
        }
        if let Ok(mut guard) = self.synced_agents.lock() {
            *guard = map;
        }
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

/// Periodically forgets MCP sessions nobody has used within
/// `session_idle_timeout` — otherwise a gateway that runs indefinitely would
/// accumulate one entry per session forever.
pub fn spawn_session_expiry_sweep(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        loop {
            tick.tick().await;
            let Ok(mut sessions) = state.sessions.lock() else {
                continue;
            };
            let before = sessions.len();
            let timeout = state.session_idle_timeout;
            sessions.retain(|_, entry| entry.last_seen.elapsed() < timeout);
            let expired = before - sessions.len();
            if expired > 0 {
                tracing::info!(expired, remaining = sessions.len(), "expired idle sessions");
            }
        }
    });
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> Option<AgentId> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        return None;
    }
    match state.auth {
        // Lookup is by hash, so the plain token is never compared or
        // stored. Config-defined agents take priority; a synced bundle is
        // only ever additional trust, never a way to shadow one.
        config::AuthMode::Static => {
            let hash = hash_token(token);
            state.agents.get(&hash).cloned().or_else(|| {
                let guard = state.synced_agents.lock().ok()?;
                guard.get(&hash).cloned()
            })
        }
        config::AuthMode::Signed => {
            let payload = custos_tokens::verify(token, &state.verifying_keys, now_unix()).ok()?;
            Some(AgentId(payload.agent))
        }
    }
}

/// Current Unix time in seconds. `0` if the clock is somehow before 1970
/// rather than panicking — `custos_tokens::verify` then just treats every
/// token as expired, which is the fail-closed outcome anyway.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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

    if let Some(blocked) = check_session(&state, &agent, &headers, &method).await {
        return blocked;
    }

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

    let resp = forward(
        state.clone(),
        agent.clone(),
        method,
        &headers,
        body,
        tools_list_id,
    )
    .await;

    // A response that introduces or confirms an Mcp-Session-Id binds it to
    // this agent — covers both a brand-new session (from `initialize`) and
    // refreshing an existing one's last-seen time.
    if let Some(session_id) = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
    {
        bind_session(&state, &agent, session_id);
    }

    resp
}

/// Checks an incoming `Mcp-Session-Id` against who created it. `None` means
/// either there's no session id on this request, or it's this agent's own —
/// either way, proceed to `forward`. `Some(response)` means the request must
/// never reach upstream: unknown session (404, the client should
/// re-initialize per the MCP spec) or a session owned by a different agent
/// (403, audited as a reuse attempt). A `DELETE` on an owned session removes
/// its binding immediately, before the request is forwarded.
async fn check_session(
    state: &Arc<AppState>,
    agent: &AgentId,
    headers: &HeaderMap,
    method: &Method,
) -> Option<Response> {
    let session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())?
        .to_string();

    let owner = match state.sessions.lock() {
        Ok(sessions) => sessions.get(&session_id).map(|e| e.agent.clone()),
        Err(_) => {
            return Some(
                (StatusCode::SERVICE_UNAVAILABLE, "session table unavailable").into_response(),
            );
        }
    };

    match owner {
        None => Some((StatusCode::NOT_FOUND, "unknown MCP session").into_response()),
        Some(owner) if &owner != agent => {
            audit_session_violation(state, agent, &session_id).await;
            Some(
                (
                    StatusCode::FORBIDDEN,
                    "session belongs to a different agent",
                )
                    .into_response(),
            )
        }
        Some(_) => {
            if let Ok(mut sessions) = state.sessions.lock() {
                if *method == Method::DELETE {
                    sessions.remove(&session_id);
                } else if let Some(entry) = sessions.get_mut(&session_id) {
                    entry.last_seen = Instant::now();
                }
            }
            None
        }
    }
}

/// Records a session-reuse attempt in the audit log — the same primitive
/// `check_tool_call` uses, with a synthetic tool name so it's never mistaken
/// for a real upstream tool.
async fn audit_session_violation(state: &Arc<AppState>, agent: &AgentId, session_id: &str) {
    let policy_version = state.policy.snapshot().version.clone();
    let call = ToolCall {
        agent: agent.clone(),
        tool: SESSION_REUSE_TOOL.to_string(),
        arguments: json!({ "session_id": session_id }),
    };
    let decision = Decision::Block {
        reason: "session belongs to another agent".into(),
    };
    let write_state = Arc::clone(state);
    let owner = state.owners.get(agent).cloned().flatten();
    let write_call = call.clone();
    let write_decision = decision.clone();
    let audited = tokio::task::spawn_blocking(move || match write_state.audit.lock() {
        Ok(mut log) => log
            .append(
                &write_call,
                &write_decision,
                owner.as_deref(),
                &policy_version,
                &custos_inspect::Findings::default(),
            )
            .is_ok(),
        Err(_) => false,
    })
    .await
    .unwrap_or(false);
    if !audited {
        tracing::error!(agent = %agent, session_id, "failed to audit a session reuse attempt");
    }
    state.decisions_blocked.fetch_add(1, Ordering::Relaxed);
    tracing::warn!(agent = %agent, session_id, "blocked: session belongs to another agent");
}

/// Binds `session_id` to `agent` (inserting or refreshing `last_seen`). If
/// this would add a session beyond `max_sessions`, the single
/// least-recently-seen entry is evicted first — memory can't grow forever,
/// and the request that triggered this never fails because of the cap.
fn bind_session(state: &AppState, agent: &AgentId, session_id: &str) {
    let Ok(mut sessions) = state.sessions.lock() else {
        return;
    };
    if !sessions.contains_key(session_id) && sessions.len() >= state.max_sessions {
        let oldest = sessions
            .iter()
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(id, _)| id.clone());
        if let Some(oldest) = oldest {
            sessions.remove(&oldest);
        }
    }
    sessions.insert(
        session_id.to_string(),
        SessionEntry {
            agent: agent.clone(),
            last_seen: Instant::now(),
        },
    );
}

/// Writes one decision to the audit log before anything acts on it,
/// waiting right here for the write (and its fsync) to finish on a
/// blocking thread so it never stalls the async reactor. `false` means the
/// write failed — the caller must block, never forward, on that alone.
async fn audit_decision(
    state: &Arc<AppState>,
    call: &ToolCall,
    decision: &Decision,
    findings: &custos_inspect::Findings,
    policy_version: &str,
) -> bool {
    let write_state = Arc::clone(state);
    let write_call = call.clone();
    let write_decision = decision.clone();
    let write_findings = findings.clone();
    let owner = state.owners.get(&call.agent).cloned().flatten();
    let policy_version = policy_version.to_string();
    tokio::task::spawn_blocking(move || match write_state.audit.lock() {
        Ok(mut log) => log
            .append(
                &write_call,
                &write_decision,
                owner.as_deref(),
                &policy_version,
                &write_findings,
            )
            .is_ok(),
        Err(_) => false,
    })
    .await
    .unwrap_or(false)
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
    // Never I/O, never fails: worst case is a truncated (never wrong) scan.
    let findings =
        custos_inspect::inspect(&call.arguments, &custos_inspect::InspectConfig::default());

    // One snapshot for the whole call: the decision and the audit record's
    // policy_version both come from it, so this request is decided by (and
    // says it was decided by) the exact policy that was live when it
    // started, even if a reload replaces it before the write below finishes.
    let policy = state.policy.snapshot();
    let decision = policy.engine.decide(&call, &findings);
    let policy_version = policy.version.clone();

    if !audit_decision(state, &call, &decision, &findings, &policy_version).await {
        tracing::error!(agent = %agent, tool, "audit write failed; blocking");
        return Some((StatusCode::SERVICE_UNAVAILABLE, "audit log unavailable").into_response());
    }

    // A hold isn't a final answer: ask Control, wait (bounded by
    // `approval_timeout_secs`), and treat whatever comes back — approved,
    // rejected, timed out, or Control unreachable — as a second decision
    // on the same call, audited the same way before it's acted on.
    let final_decision = match decision {
        Decision::Hold { reason, four_eyes } => {
            let resolved = match &state.control_approvals {
                Some(approval) => {
                    control_sync::resolve_hold(
                        approval, &agent.0, tool, &findings, reason, four_eyes,
                    )
                    .await
                }
                None => {
                    tracing::warn!(agent = %agent, tool, "hold policy fired but no Control configured; blocking");
                    Decision::Block {
                        reason: format!("hold requires Control, which isn't configured: {reason}"),
                    }
                }
            };
            if !audit_decision(state, &call, &resolved, &findings, &policy_version).await {
                tracing::error!(agent = %agent, tool, "audit write failed after hold resolution; blocking");
                return Some(
                    (StatusCode::SERVICE_UNAVAILABLE, "audit log unavailable").into_response(),
                );
            }
            resolved
        }
        other => other,
    };

    match &final_decision {
        Decision::Allow => state.decisions_allowed.fetch_add(1, Ordering::Relaxed),
        Decision::Block { .. } | Decision::Hold { .. } => {
            state.decisions_blocked.fetch_add(1, Ordering::Relaxed)
        }
    };
    tracing::info!(agent = %agent, tool, decision = ?final_decision, "tool call");
    match final_decision {
        Decision::Allow => None,
        Decision::Block { reason } | Decision::Hold { reason, .. } => Some(rpc_error(
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
    // No real arguments to inspect here — this is a visibility check for
    // tools/list, not a real call — so no findings.
    engine
        .decide(
            &ToolCall {
                agent: agent.clone(),
                tool: tool.to_string(),
                arguments: Value::Null,
            },
            &custos_inspect::Findings::default(),
        )
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
