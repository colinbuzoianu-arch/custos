//! Syncing with Custos Control: enrollment, polling for a new signed policy
//! bundle, applying it, and heartbeats. Entirely optional — a gateway with
//! no `[control]` section in its config never touches any of this and
//! behaves exactly as it always has.
//!
//! The core guarantee (see `docs/decisions/0003-policy-bundle.md` and
//! CLAUDE.md's fail-closed invariant): nothing here ever replaces a
//! last-good, already-enforced policy with something unverified. A bad
//! signature, a bundle that fails local validation, an unreachable Control,
//! or any I/O error along the way all end the same way — log it, change
//! nothing, keep enforcing whatever's already on disk.

use crate::AppState;
use crate::config::ControlConfig;
use custos_policy::bundle::{SignedBundle, verify_bundle};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("could not read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("control state is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("control's public key does not decode: {0}")]
    Key(String),
    #[error("enrollment request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("enrollment failed: Control returned HTTP {0}")]
    Rejected(reqwest::StatusCode),
}

/// One fixed file pair this gateway overwrites on every applied sync,
/// inside `policy_dir`. Any other `*.cedar` files placed there manually
/// would still be concatenated in alongside this one by
/// `PolicyStore::reload` — sync assumes `policy_dir` is otherwise empty.
const POLICY_BUNDLE_FILE: &str = "control-bundle.cedar";
const SCHEMA_FILE: &str = "custos.cedarschema";

/// What `custos enroll` writes to `state_path` and `run` reads back on
/// every start. `credential` is deliberately plaintext: it's this
/// gateway's own secret to present to Control, symmetric to how
/// `upstream_authorization` already holds a plaintext secret in config —
/// not an agent token, which is the thing this gateway verifies and must
/// never store unhashed.
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlState {
    pub gateway_id: Uuid,
    pub credential: String,
    pub control_public_key: String,
}

impl ControlState {
    pub fn load(path: &Path) -> Result<Self, ControlError> {
        let text = std::fs::read_to_string(path).map_err(|e| ControlError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(serde_json::from_str(&text)?)
    }

    fn save(&self, path: &Path) -> Result<(), ControlError> {
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(path, text).map_err(|e| ControlError::Io {
            path: path.display().to_string(),
            source: e,
        })
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, ControlError> {
        let bytes = custos_tokens::decode_key_32(&self.control_public_key)
            .map_err(|e| ControlError::Key(e.to_string()))?;
        VerifyingKey::from_bytes(&bytes).map_err(|e| ControlError::Key(e.to_string()))
    }
}

#[derive(Serialize)]
struct EnrollRequest<'a> {
    token: &'a str,
    name: &'a str,
}

#[derive(Deserialize)]
struct EnrollResponse {
    gateway_id: Uuid,
    credential: String,
    control_public_key: String,
}

/// Exchanges a one-time enrollment token for a permanent credential and
/// Control's public key, and writes them to `state_path`.
pub async fn enroll(
    client: &reqwest::Client,
    control_url: &str,
    token: &str,
    gateway_name: &str,
    state_path: &Path,
) -> Result<(), ControlError> {
    let resp = client
        .post(format!("{control_url}/enroll"))
        .json(&EnrollRequest {
            token,
            name: gateway_name,
        })
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ControlError::Rejected(status));
    }
    let body: EnrollResponse = resp.json().await?;
    ControlState {
        gateway_id: body.gateway_id,
        credential: body.credential,
        control_public_key: body.control_public_key,
    }
    .save(state_path)
}

/// Starts the background poll+heartbeat loop. Returns immediately;
/// `state_path` is read once, up front — if it can't be read or its
/// pinned public key doesn't decode, sync is skipped entirely (logged as
/// an error) rather than refusing to start the gateway over an optional
/// feature.
pub fn spawn(state: Arc<AppState>, control: ControlConfig) {
    tokio::spawn(async move {
        let control_state = match ControlState::load(&control.state_path) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "could not load control state; sync disabled - run `custos enroll` first");
                return;
            }
        };
        let verifying_key = match control_state.verifying_key() {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(error = %e, "control state's public key is invalid; sync disabled");
                return;
            }
        };
        let client = reqwest::Client::new();
        let mut etag: Option<String> = None;
        let mut tick = tokio::time::interval(Duration::from_secs(control.poll_interval_secs));
        loop {
            tick.tick().await;
            poll_once(
                &state,
                &client,
                &control,
                &control_state,
                &verifying_key,
                &mut etag,
            )
            .await;
            send_heartbeat(&state, &client, &control, &control_state).await;
        }
    });
}

async fn poll_once(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    control: &ControlConfig,
    control_state: &ControlState,
    verifying_key: &VerifyingKey,
    etag: &mut Option<String>,
) {
    let mut req = client
        .get(format!("{}/gateways/bundle", control.url))
        .bearer_auth(&control_state.credential);
    if let Some(tag) = etag.as_deref() {
        req = req.header(reqwest::header::IF_NONE_MATCH, tag);
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "could not reach Control; keeping current policy");
            return;
        }
    };
    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return;
    }
    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), "Control returned an error fetching the bundle; keeping current policy");
        return;
    }
    let new_etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let signed: SignedBundle = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "could not parse bundle response; keeping current policy");
            return;
        }
    };

    let bundle = match verify_bundle(&signed, verifying_key) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "bundle signature did not verify; discarding, keeping current policy");
            return;
        }
    };

    // Validate before touching disk — a signed-but-bad bundle (should never
    // happen if Control validated before publish, but a remote payload is
    // never trusted on that alone) must never overwrite the last-good files.
    if let Err(e) = custos_policy::validate_source(&bundle.policy, bundle.schema.as_deref()) {
        tracing::error!(error = %e, "published bundle failed local validation; discarding, keeping current policy");
        return;
    }

    let policy_path = state.policy.dir().join(POLICY_BUNDLE_FILE);
    let schema_path = state.policy.dir().join(SCHEMA_FILE);
    if let Err(e) = std::fs::write(&policy_path, &bundle.policy) {
        tracing::error!(error = %e, path = %policy_path.display(), "could not write synced policy; keeping current policy");
        return;
    }
    match &bundle.schema {
        Some(schema) => {
            if let Err(e) = std::fs::write(&schema_path, schema) {
                tracing::error!(error = %e, path = %schema_path.display(), "could not write synced schema; keeping current policy");
                return;
            }
        }
        // A version published with no schema: drop a stale one from an
        // earlier sync so it doesn't keep validating against rules this
        // version no longer ships with.
        None => {
            if schema_path.exists()
                && let Err(e) = std::fs::remove_file(&schema_path)
            {
                tracing::warn!(error = %e, path = %schema_path.display(), "could not remove stale synced schema");
            }
        }
    }

    match state.policy.reload() {
        Ok((old_version, new_version)) => {
            tracing::info!(
                old_version,
                new_version,
                control_version = bundle.version,
                "applied synced policy bundle"
            );
            *etag = new_etag;
        }
        Err(e) => {
            tracing::error!(error = %e, "synced bundle passed local validation but failed to reload; keeping previous policy");
        }
    }
}

async fn send_heartbeat(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    control: &ControlConfig,
    control_state: &ControlState,
) {
    let policy_version = state.policy.snapshot().version.clone();
    let body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "policy_version": policy_version,
        "decisions_allowed": state.decisions_allowed.load(Ordering::Relaxed),
        "decisions_blocked": state.decisions_blocked.load(Ordering::Relaxed),
    });
    let result = client
        .post(format!("{}/gateways/heartbeat", control.url))
        .bearer_auth(&control_state.credential)
        .json(&body)
        .send()
        .await;
    match result {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => tracing::warn!(status = %r.status(), "heartbeat rejected by Control"),
        Err(e) => tracing::warn!(error = %e, "could not send heartbeat to Control"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuditArgsMode, AuthMode, Config};
    use axum::Router;
    use axum::routing::get;
    use custos_policy::bundle::sign_bundle;
    use ed25519_dalek::SigningKey;

    fn state_with_policy(dir: &std::path::Path, initial_policy: &str) -> Arc<AppState> {
        if let Err(e) = std::fs::write(dir.join("initial.cedar"), initial_policy) {
            panic!("{e}");
        }
        let cfg = Config {
            listen: match "127.0.0.1:0".parse() {
                Ok(a) => a,
                Err(e) => panic!("{e}"),
            },
            upstream: "http://127.0.0.1:1/mcp".into(),
            upstream_authorization: None,
            policy_dir: dir.to_path_buf(),
            audit_log: dir.join("audit.jsonl"),
            audit_arguments: AuditArgsMode::Full,
            audit_key_id: None,
            instance_id: Some("test".into()),
            session_idle_timeout_secs: 86_400,
            max_sessions: 10,
            auth: AuthMode::Static,
            signing_keys: vec![],
            agents: vec![],
            control: None,
        };
        match AppState::from_config(&cfg) {
            Ok(s) => Arc::new(s),
            Err(e) => panic!("{e}"),
        }
    }

    fn allows(state: &AppState, tool: &str) -> bool {
        state
            .policy
            .snapshot()
            .engine
            .decide(
                &custos_core::ToolCall {
                    agent: custos_core::AgentId("x".into()),
                    tool: tool.into(),
                    arguments: serde_json::Value::Null,
                },
                &custos_inspect::Findings::default(),
            )
            .is_allowed()
    }

    /// Spawns a fake Control that always serves the given signed bundle at
    /// `/gateways/bundle`, with the given ETag.
    async fn fake_control(bundle_json: String, signature: String, version: i32) -> String {
        let router = Router::new().route(
            "/gateways/bundle",
            get(move || {
                let bundle_json = bundle_json.clone();
                let signature = signature.clone();
                async move {
                    (
                        axum::http::StatusCode::OK,
                        [("etag", version.to_string())],
                        axum::Json(serde_json::json!({
                            "bundle_json": bundle_json,
                            "signature": signature,
                        })),
                    )
                }
            }),
        );
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => panic!("{e}"),
        };
        let addr = match listener.local_addr() {
            Ok(a) => a,
            Err(e) => panic!("{e}"),
        };
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        format!("http://{addr}")
    }

    fn sample_control_config(url: String) -> ControlConfig {
        ControlConfig {
            url,
            state_path: "unused".into(),
            poll_interval_secs: 30,
        }
    }

    fn sample_control_state() -> ControlState {
        ControlState {
            gateway_id: Uuid::new_v4(),
            credential: "test-credential".into(),
            control_public_key: "00".repeat(32),
        }
    }

    #[tokio::test]
    async fn a_bundle_with_a_bad_signature_never_replaces_the_current_policy() {
        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(e) => panic!("{e}"),
        };
        let state = state_with_policy(
            dir.path(),
            r#"permit (principal, action, resource == Tool::"echo");"#,
        );
        assert!(allows(&state, "echo"));
        assert!(!allows(&state, "get-env"));

        // Signed by a different key than the one the gateway trusts - a
        // stand-in for a forged or corrupted bundle.
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let trusted_key = SigningKey::from_bytes(&[2u8; 32]);
        let bundle = custos_policy::bundle::PolicyBundle {
            tenant_id: Uuid::new_v4(),
            version: 1,
            policy: r#"permit (principal, action, resource == Tool::"get-env");"#.into(),
            schema: None,
            agents: vec![],
            published_at: time::OffsetDateTime::now_utc(),
        };
        let signed = match sign_bundle(&bundle, &signing_key) {
            Ok(s) => s,
            Err(e) => panic!("{e}"),
        };

        let url = fake_control(signed.bundle_json, signed.signature, 1).await;
        let control = sample_control_config(url);
        let control_state = sample_control_state();
        let client = reqwest::Client::new();
        let mut etag = None;

        poll_once(
            &state,
            &client,
            &control,
            &control_state,
            &trusted_key.verifying_key(),
            &mut etag,
        )
        .await;

        // Unchanged: the forged bundle's policy never took effect.
        assert!(allows(&state, "echo"));
        assert!(!allows(&state, "get-env"));
        assert!(etag.is_none());
    }

    #[tokio::test]
    async fn control_unreachable_leaves_enforcement_unchanged() {
        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(e) => panic!("{e}"),
        };
        let state = state_with_policy(
            dir.path(),
            r#"permit (principal, action, resource == Tool::"echo");"#,
        );

        // Reserve a port, then drop the listener so nothing answers there.
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => panic!("{e}"),
        };
        let addr = match listener.local_addr() {
            Ok(a) => a,
            Err(e) => panic!("{e}"),
        };
        drop(listener);

        let control = sample_control_config(format!("http://{addr}"));
        let control_state = sample_control_state();
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let client = reqwest::Client::new();
        let mut etag = None;

        poll_once(
            &state,
            &client,
            &control,
            &control_state,
            &key.verifying_key(),
            &mut etag,
        )
        .await;

        assert!(allows(&state, "echo"));
        assert!(!allows(&state, "get-env"));
    }
}
