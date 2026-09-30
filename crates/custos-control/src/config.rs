use serde::Deserialize;
use std::net::SocketAddr;

/// Control configuration, loaded from TOML. See
/// `config/custos-control.example.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address Control listens on, e.g. `127.0.0.1:8788`.
    pub listen: SocketAddr,
    /// Postgres connection string, e.g.
    /// `postgres://user:pass@localhost/custos_control`. Not a secret worth
    /// hiding behind an env var the way agent/audit keys are — a DB
    /// connection string is routine deployment config — but never logged.
    pub database_url: String,
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text)?;
        Ok(cfg)
    }
}
