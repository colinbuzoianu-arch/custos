use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

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
    #[serde(default)]
    pub agents: Vec<AgentConfig>,
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

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text)?;
        Ok(cfg)
    }
}
