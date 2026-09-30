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

pub mod bundle;

use arc_swap::ArcSwap;
use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, EntityUid, PolicySet, Request,
    RestrictedExpression,
};
use custos_core::{Decision, ToolCall};
use custos_inspect::Findings;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

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
    #[error("could not build policy context: {0}")]
    Context(String),
    #[error("invalid schema {path}: {detail}")]
    Schema { path: String, detail: String },
    #[error("invalid schema: {0}")]
    SchemaParse(String),
    #[error("policy does not match schema: {0}")]
    Validation(String),
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
        Self::parse(&concatenated_source(dir)?)
    }

    /// Decide on one tool call, given what [`custos_inspect::inspect`] found
    /// in its arguments. Never panics; any internal error blocks.
    pub fn decide(&self, call: &ToolCall, findings: &Findings) -> Decision {
        match self.try_decide(call, findings) {
            Ok(d) => d,
            Err(e) => Decision::Block {
                reason: format!("policy error: {e}"),
            },
        }
    }

    fn try_decide(&self, call: &ToolCall, findings: &Findings) -> Result<Decision, PolicyError> {
        let principal = uid("Agent", &call.agent.0)?;
        let action = uid("Action", "call_tool")?;
        let resource = uid("Tool", &call.tool)?;
        let context = build_context(findings)?;
        let request = Request::new(principal, action, resource, context, None)
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

/// A [`PolicyEngine`] paired with the identity of the exact source text it
/// was built from, so the audit log can record *which* policy decided each
/// call. `version` is the SHA-256 hex of that source text — any change to
/// the policies, even whitespace, is a different version.
pub struct Versioned {
    pub engine: PolicyEngine,
    pub version: String,
}

fn load_versioned(dir: &Path) -> Result<Versioned, PolicyError> {
    let src = concatenated_source(dir)?;
    let engine = PolicyEngine::parse(&src)?;
    if let Some(schema) = load_schema(dir)? {
        validate_against_schema(&engine.policies, &schema)?;
    }
    let version = hex::encode(Sha256::digest(src.as_bytes()));
    Ok(Versioned { engine, version })
}

/// `custos.cedarschema`, if `dir` has one. Schema validation is opt-in per
/// directory (no file, no validation) so existing setups and tests without
/// a schema keep working unchanged.
const SCHEMA_FILE_NAME: &str = "custos.cedarschema";

fn load_schema(dir: &Path) -> Result<Option<cedar_policy::Schema>, PolicyError> {
    let path = dir.join(SCHEMA_FILE_NAME);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| PolicyError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    parse_schema_str(&text)
        .map(Some)
        .map_err(|e| PolicyError::Schema {
            path: path.display().to_string(),
            detail: e.to_string(),
        })
}

/// Parses Cedar schema source text (the contents of a `.cedarschema` file),
/// with no file I/O — for callers (like Control) that keep schema text
/// somewhere other than a file, e.g. a database column.
pub fn parse_schema_str(src: &str) -> Result<cedar_policy::Schema, PolicyError> {
    let (schema, _warnings) = cedar_policy::Schema::from_cedarschema_str(src)
        .map_err(|e| PolicyError::SchemaParse(e.to_string()))?;
    Ok(schema)
}

/// Checks every policy in `policies` type-checks against `schema` in
/// [`cedar_policy::ValidationMode::Strict`] — an unknown context attribute,
/// or one used with the wrong type, is an error here, not a silent no-op at
/// decision time.
pub fn validate_against_schema(
    policies: &PolicySet,
    schema: &cedar_policy::Schema,
) -> Result<(), PolicyError> {
    let validator = cedar_policy::Validator::new(schema.clone());
    let result = validator.validate(policies, cedar_policy::ValidationMode::default());
    if result.validation_passed() {
        return Ok(());
    }
    let messages: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
    Err(PolicyError::Validation(messages.join("; ")))
}

/// Parses `policy_src` and, if `schema_src` is given, validates it against
/// that schema — for callers that keep Cedar source as text (e.g. one
/// column per policy version) rather than a directory of `.cedar` files.
pub fn validate_source(policy_src: &str, schema_src: Option<&str>) -> Result<(), PolicyError> {
    let policies =
        PolicySet::from_str(policy_src).map_err(|e| PolicyError::Parse(e.to_string()))?;
    if let Some(schema_src) = schema_src {
        let schema = parse_schema_str(schema_src)?;
        validate_against_schema(&policies, &schema)?;
    }
    Ok(())
}

/// Holds the live [`PolicyEngine`] and lets it be replaced — atomically,
/// without a lock a reader has to wait on — while the gateway keeps running.
///
/// Every read goes through [`snapshot`](Self::snapshot), which hands back an
/// owned `Arc<Versioned>`. That matters for one specific guarantee: a
/// request that snapshots the policy once at the start keeps using that
/// exact engine and version for its whole lifetime, even if [`reload`]
/// replaces what *new* snapshots see while this request is still in flight —
/// because the `Arc` keeps the old value alive for as long as anyone still
/// holds a clone of it.
pub struct PolicyStore {
    dir: PathBuf,
    current: ArcSwap<Versioned>,
}

impl PolicyStore {
    /// Loads and validates `dir`'s policies once, up front — same failure
    /// behaviour as `PolicyEngine::from_dir`, just wrapped for reloading.
    pub fn open(dir: PathBuf) -> Result<Self, PolicyError> {
        let versioned = load_versioned(&dir)?;
        Ok(Self {
            dir,
            current: ArcSwap::new(Arc::new(versioned)),
        })
    }

    /// The policy set and version in effect right now. Cheap and never
    /// blocks; call it once per request and reuse the result rather than
    /// calling it again mid-request.
    pub fn snapshot(&self) -> Arc<Versioned> {
        self.current.load_full()
    }

    /// The directory [`reload`](Self::reload) re-reads — e.g. to point a
    /// file watcher at it.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Loads and fully validates `dir` again. Only on success does it
    /// replace what [`snapshot`](Self::snapshot) returns for everyone else —
    /// on failure the old policy set keeps deciding calls, never falling
    /// back to "no policy." Returns `(old_version, new_version)` on success.
    pub fn reload(&self) -> Result<(String, String), PolicyError> {
        let new = load_versioned(&self.dir)?;
        let old_version = self.current.load().version.clone();
        let new_version = new.version.clone();
        self.current.store(Arc::new(new));
        Ok((old_version, new_version))
    }
}

/// Build an entity uid safely: the id is JSON-escaped, so a tool name like
/// `a"; permit(...)` cannot inject Cedar syntax.
fn uid(kind: &str, id: &str) -> Result<EntityUid, PolicyError> {
    let quoted = serde_json::to_string(id).map_err(|e| PolicyError::Uid(e.to_string()))?;
    EntityUid::from_str(&format!("{kind}::{quoted}")).map_err(|e| PolicyError::Uid(e.to_string()))
}

/// Turns what `custos-inspect` found into the Cedar context every decision
/// evaluates against: `findings` (the set of kinds present, deduplicated —
/// never the matched values themselves, `custos-inspect` never hands those
/// back), `args_bytes`, `array_max_len`, and `hour_utc`/`weekday` from the
/// clock at decision time, so policies can use `when { context.weekday < 5
/// }`-style conditions. See `policies/custos.cedarschema` for the shape this
/// must match.
fn build_context(findings: &Findings) -> Result<Context, PolicyError> {
    let now = time::OffsetDateTime::now_utc();
    let hour_utc = i64::from(now.hour());
    // Cedar has no day-of-week type; 0 = Monday .. 6 = Sunday.
    let weekday = i64::from(now.weekday().number_from_monday()) - 1;

    let mut kinds: Vec<String> = findings.items.iter().map(|f| kind_name(f.kind)).collect();
    kinds.sort_unstable();
    kinds.dedup();
    let findings_set =
        RestrictedExpression::new_set(kinds.into_iter().map(RestrictedExpression::new_string));

    let args_bytes = i64::try_from(findings.args_bytes).unwrap_or(i64::MAX);
    let array_max_len = i64::try_from(findings.array_max_len).unwrap_or(i64::MAX);

    Context::from_pairs([
        ("findings".to_string(), findings_set),
        (
            "args_bytes".to_string(),
            RestrictedExpression::new_long(args_bytes),
        ),
        (
            "array_max_len".to_string(),
            RestrictedExpression::new_long(array_max_len),
        ),
        (
            "hour_utc".to_string(),
            RestrictedExpression::new_long(hour_utc),
        ),
        (
            "weekday".to_string(),
            RestrictedExpression::new_long(weekday),
        ),
    ])
    .map_err(|e| PolicyError::Context(e.to_string()))
}

/// The Cedar-facing name for a finding kind — must match
/// `policies/custos.cedarschema`'s `findings` element type. Reuses
/// `Kind`'s own serde mapping so the two can't silently drift apart.
fn kind_name(kind: custos_inspect::Kind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Every `*.cedar` file in `dir`, in name order — the order that determines
/// both the concatenated source `from_dir` parses and the input to the
/// `policy_version` hash, so it must be stable.
fn sorted_cedar_files(dir: &Path) -> Result<Vec<std::path::PathBuf>, PolicyError> {
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
    Ok(files)
}

/// The exact text `from_dir` builds its `PolicySet` from: every `*.cedar`
/// file in `dir`, name-sorted, concatenated with a blank line between them.
pub fn concatenated_source(dir: &Path) -> Result<String, PolicyError> {
    let mut src = String::new();
    for f in sorted_cedar_files(dir)? {
        let text = std::fs::read_to_string(&f).map_err(|e| PolicyError::Io {
            path: f.display().to_string(),
            source: e,
        })?;
        src.push_str(&text);
        src.push('\n');
    }
    Ok(src)
}

/// One `.cedar` file's validation result, from [`check_dir`].
pub struct FileCheck {
    pub path: std::path::PathBuf,
    /// Number of policies in this file, or `0` if it failed to parse.
    pub policy_count: usize,
    /// Parse errors, each prefixed `line N: ` when Cedar reports a location.
    pub errors: Vec<String>,
    /// Cedar-generated ids (`policy0`, ...) of policies with no `@id`
    /// annotation — block reasons use `@id`, so these decide silently.
    pub missing_id: Vec<String>,
}

impl FileCheck {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validates every `*.cedar` file in `dir` **individually** (unlike
/// `from_dir`, which concatenates them into one `PolicySet` to build the
/// engine that actually decides calls) so a syntax error's line number and
/// the "no `@id`" warning are both attributable to one file. `Err` only for
/// a directory that can't be read at all, or (if present) whose
/// `custos.cedarschema` doesn't itself parse.
pub fn check_dir(dir: &Path) -> Result<Vec<FileCheck>, PolicyError> {
    let schema = load_schema(dir)?;
    sorted_cedar_files(dir)?
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).map_err(|e| PolicyError::Io {
                path: path.display().to_string(),
                source: e,
            })?;
            Ok(check_file(path, &text, schema.as_ref()))
        })
        .collect()
}

fn check_file(
    path: std::path::PathBuf,
    text: &str,
    schema: Option<&cedar_policy::Schema>,
) -> FileCheck {
    match PolicySet::from_str(text) {
        Ok(policies) => {
            let missing_id = policies
                .policies()
                .filter(|p| p.annotation("id").is_none())
                .map(|p| p.id().to_string())
                .collect();
            let mut errors = Vec::new();
            if let Some(schema) = schema
                && let Err(e) = validate_against_schema(&policies, schema)
            {
                errors.push(e.to_string());
            }
            FileCheck {
                path,
                policy_count: policies.policies().count(),
                errors,
                missing_id,
            }
        }
        Err(e) => FileCheck {
            path,
            policy_count: 0,
            errors: describe_parse_errors(&e, text),
            missing_id: Vec::new(),
        },
    }
}

/// Formats each underlying parse error, prefixed with its line number in
/// `text` when Cedar's diagnostics give us a byte offset to count lines up
/// to; otherwise just the message.
fn describe_parse_errors(errors: &cedar_policy::ParseErrors, text: &str) -> Vec<String> {
    use miette::Diagnostic;
    errors
        .iter()
        .map(|e| match e.labels().and_then(|mut ls| ls.next()) {
            Some(label) => {
                let offset = label.offset().min(text.len());
                let line = text[..offset].matches('\n').count() + 1;
                format!("line {line}: {e}")
            }
            None => e.to_string(),
        })
        .collect()
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

    fn no_findings() -> Findings {
        Findings::default()
    }

    #[test]
    fn permitted_call_is_allowed() {
        assert_eq!(
            engine().decide(
                &call("invoice-processor", "sap.read_invoice"),
                &no_findings()
            ),
            Decision::Allow
        );
    }

    #[test]
    fn unlisted_call_is_blocked_by_default() {
        let d = engine().decide(
            &call("invoice-processor", "sap.execute_payment"),
            &no_findings(),
        );
        assert!(!d.is_allowed());
    }

    #[test]
    fn forbid_names_the_policy() {
        let d = engine().decide(
            &call("invoice-processor", "payroll.read_salaries"),
            &no_findings(),
        );
        match d {
            Decision::Block { reason } => assert!(reason.contains("no-payroll"), "{reason}"),
            other => panic!("expected block, got {other:?}"),
        }
    }

    #[test]
    fn other_agent_is_blocked() {
        assert!(
            !engine()
                .decide(&call("support-agent", "sap.read_invoice"), &no_findings())
                .is_allowed()
        );
    }

    #[test]
    fn hostile_tool_name_cannot_inject() {
        let d = engine().decide(
            &call(
                "invoice-processor",
                r#"x"; permit(principal, action, resource); //"#,
            ),
            &no_findings(),
        );
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
            e.decide(
                &call("invoice-processor", "sap.read_invoice"),
                &no_findings()
            )
            .is_allowed()
        );
    }

    // --- check_dir ---------------------------------------------------

    fn write(dir: &tempfile::TempDir, name: &str, contents: &str) {
        if let Err(e) = std::fs::write(dir.path().join(name), contents) {
            panic!("{e}");
        }
    }

    #[test]
    fn check_dir_reports_a_valid_file() -> Result<(), PolicyError> {
        let dir = tempfile::tempdir().map_err(|e| PolicyError::Io {
            path: "<tempdir>".into(),
            source: e,
        })?;
        write(&dir, "a.cedar", POLICY);
        let reports = check_dir(dir.path())?;
        assert_eq!(reports.len(), 1);
        assert!(reports[0].is_valid());
        assert_eq!(reports[0].policy_count, 2);
        assert!(reports[0].missing_id.is_empty());
        Ok(())
    }

    #[test]
    fn check_dir_names_the_broken_file_and_a_line() -> Result<(), PolicyError> {
        let dir = tempfile::tempdir().map_err(|e| PolicyError::Io {
            path: "<tempdir>".into(),
            source: e,
        })?;
        write(&dir, "good.cedar", POLICY);
        write(
            &dir,
            "bad.cedar",
            "permit (\n    principal,\n    action,\n    resource\n);\nthis is not cedar",
        );
        let reports = check_dir(dir.path())?;
        assert_eq!(reports.len(), 2);

        let good = reports.iter().find(|r| r.path.ends_with("good.cedar"));
        assert!(good.is_some_and(FileCheck::is_valid));

        let bad = reports.iter().find(|r| r.path.ends_with("bad.cedar"));
        let Some(bad) = bad else {
            panic!("bad.cedar must be in the report");
        };
        assert!(!bad.is_valid());
        assert!(
            bad.errors.iter().any(|e| e.starts_with("line 6:")),
            "{:?}",
            bad.errors
        );
        Ok(())
    }

    #[test]
    fn check_dir_warns_about_missing_id() -> Result<(), PolicyError> {
        let dir = tempfile::tempdir().map_err(|e| PolicyError::Io {
            path: "<tempdir>".into(),
            source: e,
        })?;
        write(
            &dir,
            "no-id.cedar",
            r#"permit (principal, action, resource == Tool::"echo");"#,
        );
        let reports = check_dir(dir.path())?;
        assert_eq!(reports.len(), 1);
        assert!(reports[0].is_valid());
        assert_eq!(reports[0].policy_count, 1);
        assert_eq!(reports[0].missing_id.len(), 1);
        Ok(())
    }

    // --- PolicyStore / reload -----------------------------------------

    fn store_in(dir: &tempfile::TempDir) -> PolicyStore {
        match PolicyStore::open(dir.path().to_path_buf()) {
            Ok(s) => s,
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn valid_reload_changes_decisions_and_version() -> Result<(), PolicyError> {
        let dir = tempfile::tempdir().map_err(|e| PolicyError::Io {
            path: "<tempdir>".into(),
            source: e,
        })?;
        write(
            &dir,
            "a.cedar",
            r#"permit (principal, action, resource == Tool::"echo");"#,
        );
        let store = store_in(&dir);
        let before = store.snapshot();
        assert!(
            !before
                .engine
                .decide(&call("x", "get-env"), &no_findings())
                .is_allowed()
        );

        write(
            &dir,
            "a.cedar",
            r#"permit (principal, action, resource == Tool::"get-env");"#,
        );
        let (old_version, new_version) = store.reload()?;
        assert_eq!(old_version, before.version);
        assert_ne!(new_version, old_version);

        let after = store.snapshot();
        assert_eq!(after.version, new_version);
        assert!(
            after
                .engine
                .decide(&call("x", "get-env"), &no_findings())
                .is_allowed()
        );

        // The snapshot taken before the reload still decides exactly as it
        // did when it was taken — an in-flight request isn't affected by a
        // reload that happens after it already started.
        assert!(
            !before
                .engine
                .decide(&call("x", "get-env"), &no_findings())
                .is_allowed()
        );
        Ok(())
    }

    #[test]
    fn invalid_reload_keeps_the_old_policy_and_version() -> Result<(), PolicyError> {
        let dir = tempfile::tempdir().map_err(|e| PolicyError::Io {
            path: "<tempdir>".into(),
            source: e,
        })?;
        write(
            &dir,
            "a.cedar",
            r#"permit (principal, action, resource == Tool::"echo");"#,
        );
        let store = store_in(&dir);
        let before = store.snapshot();

        write(&dir, "a.cedar", "this is not cedar at all");
        assert!(store.reload().is_err());

        let after = store.snapshot();
        assert_eq!(after.version, before.version);
        assert!(
            after
                .engine
                .decide(&call("x", "echo"), &no_findings())
                .is_allowed()
        );
        Ok(())
    }

    // --- Cedar context: findings, args_bytes, array_max_len -------------

    const CONTEXT_SCHEMA: &str = r#"
        entity Agent;
        entity Tool;
        action call_tool appliesTo {
            principal: [Agent],
            resource: [Tool],
            context: {
                findings: Set<String>,
                args_bytes: Long,
                array_max_len: Long,
                hour_utc: Long,
                weekday: Long,
            }
        };
    "#;

    const CONTEXT_POLICY: &str = r#"
        @id("allow-echo")
        permit (principal, action, resource == Tool::"echo");

        @id("no-card-data")
        forbid (principal, action, resource) when {
            context.findings.contains("card")
        };

        @id("allow-export")
        permit (principal, action, resource == Tool::"crm.export");

        @id("no-bulk-export")
        forbid (principal, action, resource == Tool::"crm.export") when {
            context.array_max_len > 500
        };
    "#;

    fn context_engine() -> PolicyEngine {
        match PolicyEngine::parse(CONTEXT_POLICY) {
            Ok(e) => e,
            Err(e) => panic!("test policy must parse: {e}"),
        }
    }

    fn findings_with(items: Vec<custos_inspect::Finding>) -> Findings {
        Findings {
            items,
            ..Findings::default()
        }
    }

    fn card_finding() -> custos_inspect::Finding {
        custos_inspect::Finding {
            kind: custos_inspect::Kind::Card,
            path: "$.card".into(),
            count: 1,
        }
    }

    #[test]
    fn same_tool_allowed_without_findings_and_blocked_with_them() {
        let engine = context_engine();
        assert!(
            engine
                .decide(&call("x", "echo"), &no_findings())
                .is_allowed()
        );
        assert!(
            !engine
                .decide(&call("x", "echo"), &findings_with(vec![card_finding()]))
                .is_allowed()
        );
    }

    #[test]
    fn array_max_len_can_block_a_bulk_export() {
        let engine = context_engine();
        let small = Findings {
            array_max_len: 10,
            ..Findings::default()
        };
        let big = Findings {
            array_max_len: 600,
            ..Findings::default()
        };
        assert!(engine.decide(&call("x", "crm.export"), &small).is_allowed());
        assert!(!engine.decide(&call("x", "crm.export"), &big).is_allowed());
    }

    #[test]
    fn schema_accepts_the_context_policy() -> Result<(), PolicyError> {
        let dir = tempfile::tempdir().map_err(|e| PolicyError::Io {
            path: "<tempdir>".into(),
            source: e,
        })?;
        write(&dir, SCHEMA_FILE_NAME, CONTEXT_SCHEMA);
        write(&dir, "a.cedar", CONTEXT_POLICY);
        let reports = check_dir(dir.path())?;
        assert_eq!(reports.len(), 1);
        assert!(reports[0].is_valid(), "{:?}", reports[0].errors);
        // Also exercised through the actual load path (open/reload).
        assert!(PolicyStore::open(dir.path().to_path_buf()).is_ok());
        Ok(())
    }

    #[test]
    fn schema_catches_a_typo_in_a_context_attribute() -> Result<(), PolicyError> {
        let dir = tempfile::tempdir().map_err(|e| PolicyError::Io {
            path: "<tempdir>".into(),
            source: e,
        })?;
        write(&dir, SCHEMA_FILE_NAME, CONTEXT_SCHEMA);
        write(
            &dir,
            "bad.cedar",
            r#"
                @id("typo")
                forbid (principal, action, resource) when {
                    context.finding.contains("card")
                };
            "#,
        );
        let reports = check_dir(dir.path())?;
        assert_eq!(reports.len(), 1);
        assert!(!reports[0].is_valid());

        // The same typo also stops the policy set from loading at all.
        assert!(PolicyStore::open(dir.path().to_path_buf()).is_err());
        Ok(())
    }
}
