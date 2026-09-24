//! Shared types used by every Custos crate.
//!
//! Keep this crate small and dependency-light: it is the contract between
//! the gateway, the policy engine and the audit log.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable identifier of an AI agent, e.g. `invoice-processor`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(pub String);

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One attempt by an agent to call a tool through the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub agent: AgentId,
    /// Tool name as the MCP server exposes it, e.g. `sap.read_invoice`.
    pub tool: String,
    /// Raw tool arguments. Inspected, never trusted.
    #[serde(default)]
    pub arguments: serde_json::Value,
}

/// What the gateway does with a call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Block {
        reason: String,
    },
    /// Wait for a human. Not enforced yet (week 2).
    Hold {
        reason: String,
    },
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_serializes_with_verdict_tag() {
        let d = Decision::Block {
            reason: "outside scope".into(),
        };
        let json = serde_json::to_value(&d).unwrap_or_default();
        assert_eq!(json["verdict"], "BLOCK");
        assert_eq!(json["reason"], "outside scope");
    }
}
