use custos_audit::ArgsPolicy;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

/// How tool-call arguments are recorded in the audit log. See
/// `config/custos.example.toml` for what each mode means.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditArgsMode {
    #[default]
    Hash,
    Redacted,
    Full,
}

/// How agents authenticate. See `config/custos.example.toml`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// Bearer token compared as a SHA-256 hash against `[[agents]]`. Never
    /// expires; simplest to set up.
    #[default]
    Static,
    /// Bearer token is an Ed25519-signed, expiring token from `custos
    /// issue-token`, checked against `[[signing_keys]]`.
    Signed,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyConfig {
    pub key_id: String,
    /// Ed25519 public key, hex or base64. Only used when `auth = "signed"`.
    pub public_key: String,
}

/// Gateway configuration, loaded from TOML. See `config/custos.example.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the gateway listens on, e.g. `127.0.0.1:8787`.
    pub listen: SocketAddr,
    /// URL of the upstream MCP server's streamable-HTTP endpoint.
    pub upstream: String,
    /// Optional `Authorization` header value Custos sends to the upstream.
    /// Agents never see this credential.
    #[serde(default)]
    pub upstream_authorization: Option<String>,
    /// Directory with `*.cedar` policy files.
    pub policy_dir: PathBuf,
    /// JSON Lines audit log file.
    pub audit_log: PathBuf,
    /// How tool arguments are recorded in the audit log. Default `hash`.
    #[serde(default)]
    pub audit_arguments: AuditArgsMode,
    /// Identifies which secret `CUSTOS_AUDIT_KEY` holds. Required when
    /// `audit_arguments = "hash"`; the key itself is never in config.
    #[serde(default)]
    pub audit_key_id: Option<String>,
    /// Recorded on every audit entry. Defaults to the machine's hostname.
    #[serde(default)]
    pub instance_id: Option<String>,
    /// How long an MCP session may sit idle before the gateway forgets it.
    /// Default 24h.
    #[serde(default = "default_session_idle_timeout_secs")]
    pub session_idle_timeout_secs: u64,
    /// Upper bound on how many MCP sessions the gateway tracks at once; the
    /// least-recently-used one is evicted before this is exceeded. Default
    /// 10,000.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// How agents authenticate. Default `static`.
    #[serde(default)]
    pub auth: AuthMode,
    /// Public keys trusted to sign agent tokens, by key id. Only used when
    /// `auth = "signed"`; list both the old and new key while rotating.
    #[serde(default)]
    pub signing_keys: Vec<SigningKeyConfig>,
    #[serde(default)]
    pub agents: Vec<AgentConfig>,
}

fn default_session_idle_timeout_secs() -> u64 {
    24 * 60 * 60
}

fn default_max_sessions() -> usize {
    10_000
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub id: String,
    /// Human owner, shown in the audit log and dashboard later.
    #[serde(default)]
    pub owner: Option<String>,
    /// SHA-256 of the agent's bearer token, hex. Create with
    /// `custos hash-token <token>`. Plain tokens are never stored.
    pub token_sha256: String,
}

/// Environment variable holding the raw HMAC key for `audit_arguments =
/// "hash"`, hex- or base64-encoded. Never held in config, never logged.
pub const AUDIT_KEY_ENV: &str = "CUSTOS_AUDIT_KEY";

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text)?;
        Ok(cfg)
    }

    /// Builds the argument-recording policy this config asks for. In `hash`
    /// mode this reads and decodes [`AUDIT_KEY_ENV`] — `Err` (with a message
    /// safe to show, never the key itself) if `audit_key_id` is missing, the
    /// environment variable isn't set, or the key doesn't decode to at least
    /// [`custos_audit::MIN_KEY_LEN`] bytes. `full` mode logs a warning: it
    /// may store personal data.
    pub fn args_policy(&self) -> anyhow::Result<ArgsPolicy> {
        match self.audit_arguments {
            AuditArgsMode::Full => {
                tracing::warn!(
                    "audit_arguments = \"full\": tool call arguments will be stored \
                     as-is in the audit log; this may include personal data"
                );
                Ok(ArgsPolicy::Full)
            }
            AuditArgsMode::Redacted => Ok(ArgsPolicy::Redacted),
            AuditArgsMode::Hash => {
                let key_id = self.audit_key_id.clone().ok_or_else(|| {
                    anyhow::anyhow!("audit_arguments = \"hash\" requires audit_key_id in config")
                })?;
                let raw = std::env::var(AUDIT_KEY_ENV).map_err(|_| {
                    anyhow::anyhow!(
                        "{AUDIT_KEY_ENV} is not set; audit_arguments = \"hash\" needs a \
                         hex or base64 key of at least {} bytes",
                        custos_audit::MIN_KEY_LEN
                    )
                })?;
                let key = custos_audit::decode_key(&raw)?;
                Ok(ArgsPolicy::hash(key, key_id)?)
            }
        }
    }

    /// The value recorded as `gateway_instance` on every audit entry:
    /// `instance_id` if set, otherwise the machine's hostname, otherwise
    /// `"unknown"`.
    pub fn gateway_instance(&self) -> String {
        self.instance_id.clone().unwrap_or_else(|| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".into())
        })
    }

    /// Decodes every `[[signing_keys]]` entry into a verifying key, keyed by
    /// `key_id`. `Err` if `auth = "signed"` but the list is empty, or any
    /// entry doesn't decode to a valid Ed25519 public key — refusing to
    /// start beats starting up unable to authenticate anyone.
    pub fn verifying_keys(&self) -> anyhow::Result<HashMap<String, ed25519_dalek::VerifyingKey>> {
        if self.auth == AuthMode::Signed && self.signing_keys.is_empty() {
            anyhow::bail!("auth = \"signed\" requires at least one [[signing_keys]] entry");
        }
        self.signing_keys
            .iter()
            .map(|k| {
                let bytes = custos_tokens::decode_key_32(&k.public_key)?;
                let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                    .map_err(|e| anyhow::anyhow!("signing_keys[{}]: {e}", k.key_id))?;
                Ok((k.key_id.clone(), key))
            })
            .collect()
    }
}

/// Environment variable holding the raw Ed25519 signing seed for `custos
/// issue-token`, hex- or base64-encoded. Never held in config, never logged.
pub const SIGNING_KEY_ENV: &str = "CUSTOS_SIGNING_KEY";
