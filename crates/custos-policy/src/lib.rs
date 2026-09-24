//! Policy evaluation with Cedar.
//!
//! Model (v0):
//! - principal: `Agent::"<agent id>"`
//! - action:    `Action::"call_tool"`
//! - resource:  `Tool::"<tool name>"`
//!
//! Default is deny: a call is allowed only if some `permit` matches and no
//! `forbid` matches. Every decision carries the ids of the policies that
//! decided it, so the audit log can say *why*.

use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, EntityUid, PolicySet, Request,
};
use custos_core::{Decision, ToolCall};
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("could not read policy file {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid Cedar policy: {0}")]
    Parse(String),
    #[error("invalid identifier: {0}")]
    Uid(String),
}

pub struct PolicyEngine {
    policies: PolicySet,
    authorizer: Authorizer,
}

impl PolicyEngine {
    /// Parse policies from Cedar source text.
    pub fn parse(src: &str) -> Result<Self, PolicyError> {
        let policies = PolicySet::from_str(src).map_err(|e| PolicyError::Parse(e.to_string()))?;
        Ok(Self {
            policies,
            authorizer: Authorizer::new(),
        })
    }

    /// Load every `*.cedar` file in a directory, in name order.
    pub fn from_dir(dir: &Path) -> Result<Self, PolicyError> {
        let io = |e| PolicyError::Io {
            path: dir.display().to_string(),
            source: e,
        };
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .map_err(io)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "cedar"))
            .collect();
        files.sort();
        let mut src = String::new();
        for f in files {
            let text = std::fs::read_to_string(&f).map_err(|e| PolicyError::Io {
                path: f.display().to_string(),
                source: e,
            })?;
            src.push_str(&text);
            src.push('\n');
        }
        Self::parse(&src)
    }

    /// Decide on one tool call. Never panics; any internal error blocks.
    pub fn decide(&self, call: &ToolCall) -> Decision {
        match self.try_decide(call) {
            Ok(d) => d,
            Err(e) => Decision::Block {
                reason: format!("policy error: {e}"),
            },
        }
    }

    fn try_decide(&self, call: &ToolCall) -> Result<Decision, PolicyError> {
        let principal = uid("Agent", &call.agent.0)?;
        let action = uid("Action", "call_tool")?;
        let resource = uid("Tool", &call.tool)?;
        let request = Request::new(principal, action, resource, Context::empty(), None)
            .map_err(|e| PolicyError::Uid(e.to_string()))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &Entities::empty());

        // Prefer the human-readable `@id("...")` annotation over Cedar's
        // generated ids (`policy0`, `policy1`, ...).
        let ids: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|pid| {
                self.policies
                    .policy(pid)
                    .and_then(|p| p.annotation("id"))
                    .map_or_else(|| pid.to_string(), str::to_string)
            })
            .collect();

        Ok(match response.decision() {
            CedarDecision::Allow => Decision::Allow,
            CedarDecision::Deny if ids.is_empty() => Decision::Block {
                reason: "no policy permits this call".into(),
            },
            CedarDecision::Deny => Decision::Block {
                reason: format!("forbidden by {}", ids.join(", ")),
            },
        })
    }
}

/// Build an entity uid safely: the id is JSON-escaped, so a tool name like
/// `a"; permit(...)` cannot inject Cedar syntax.
fn uid(kind: &str, id: &str) -> Result<EntityUid, PolicyError> {
    let quoted = serde_json::to_string(id).map_err(|e| PolicyError::Uid(e.to_string()))?;
    EntityUid::from_str(&format!("{kind}::{quoted}")).map_err(|e| PolicyError::Uid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use custos_core::AgentId;

    const POLICY: &str = r#"
        @id("invoice-read")
        permit (
            principal == Agent::"invoice-processor",
            action == Action::"call_tool",
            resource
        ) when {
            [Tool::"sap.read_invoice", Tool::"sap.create_payment_proposal"].contains(resource)
        };

        @id("no-payroll")
        forbid (principal, action, resource == Tool::"payroll.read_salaries");
    "#;

    fn call(agent: &str, tool: &str) -> ToolCall {
        ToolCall {
            agent: AgentId(agent.into()),
            tool: tool.into(),
            arguments: serde_json::Value::Null,
        }
    }

    fn engine() -> PolicyEngine {
        match PolicyEngine::parse(POLICY) {
            Ok(e) => e,
            Err(e) => panic!("test policy must parse: {e}"),
        }
    }

    #[test]
    fn permitted_call_is_allowed() {
        assert_eq!(
            engine().decide(&call("invoice-processor", "sap.read_invoice")),
            Decision::Allow
        );
    }

    #[test]
    fn unlisted_call_is_blocked_by_default() {
        let d = engine().decide(&call("invoice-processor", "sap.execute_payment"));
        assert!(!d.is_allowed());
    }

    #[test]
    fn forbid_names_the_policy() {
        let d = engine().decide(&call("invoice-processor", "payroll.read_salaries"));
        match d {
            Decision::Block { reason } => assert!(reason.contains("no-payroll"), "{reason}"),
            other => panic!("expected block, got {other:?}"),
        }
    }

    #[test]
    fn other_agent_is_blocked() {
        assert!(
            !engine()
                .decide(&call("support-agent", "sap.read_invoice"))
                .is_allowed()
        );
    }

    #[test]
    fn hostile_tool_name_cannot_inject() {
        let d = engine().decide(&call(
            "invoice-processor",
            r#"x"; permit(principal, action, resource); //"#,
        ));
        assert!(!d.is_allowed());
    }

    #[test]
    fn loads_policies_from_dir() {
        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(e) => panic!("{e}"),
        };
        if let Err(e) = std::fs::write(dir.path().join("a.cedar"), POLICY) {
            panic!("{e}");
        }
        let e = match PolicyEngine::from_dir(dir.path()) {
            Ok(e) => e,
            Err(e) => panic!("{e}"),
        };
        assert!(
            e.decide(&call("invoice-processor", "sap.read_invoice"))
                .is_allowed()
        );
    }
}
