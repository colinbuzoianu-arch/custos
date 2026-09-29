//! Tamper-evident, GDPR-respecting audit log.
//!
//! Each line of the log is one JSON record. Every record contains the hash of
//! the previous record, so editing or deleting any line breaks the chain and
//! [`verify`] reports where. Records written by an older version of this
//! module — no `"v"` field at all, or `"v": 2` before `policy_version`
//! existed — are still read and verified with their original, unchanged
//! hashing rule; every new record is written as `"v": 3`. The ClickHouse sink
//! and signatures come later (see `docs/PLAN.md`).

use custos_core::{AgentId, Decision, ToolCall};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// An HMAC key must be at least this many bytes — short enough to brute-force
/// is not a secret.
pub const MIN_KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit record is not valid JSON at line {line}: {msg}")]
    Corrupt { line: usize, msg: String },
    #[error("hash chain broken at line {line}")]
    Broken { line: usize },
    #[error("unsupported audit record version {version} at line {line}")]
    UnsupportedVersion { line: usize, version: u64 },
    #[error("audit key must be at least {MIN_KEY_LEN} bytes, got {got}")]
    WeakAuditKey { got: usize },
    #[error("audit key must be hex or base64")]
    InvalidAuditKey,
}

/// How `ToolCall::arguments` are represented in the audit log. Default
/// (`Hash`) never stores the arguments themselves — only proof that specific
/// argument bytes were seen, which the key holder can confirm but a reader of
/// the log cannot reverse.
pub enum ArgsPolicy {
    /// `{"args_hmac", "args_bytes", "key_id"}` — the arguments themselves are
    /// never stored. `key` is the raw HMAC key; a policy can only be built
    /// with a key of at least [`MIN_KEY_LEN`] bytes, so "hash mode with a
    /// weak key" is not a state this type can represent.
    Hash { key: Vec<u8>, key_id: String },
    /// Same JSON shape and keys as the real arguments, every value replaced
    /// by its type and length, e.g. `{"iban": "<string:22>"}`.
    Redacted,
    /// Arguments stored exactly as received. May contain personal data.
    Full,
}

impl ArgsPolicy {
    /// Hash-mode policy. `Err` if `key` is shorter than [`MIN_KEY_LEN`]
    /// bytes — the only way this constructor can fail, by design, so a
    /// caller can never end up with a `Hash` policy backed by a weak key.
    pub fn hash(key: Vec<u8>, key_id: String) -> Result<Self, AuditError> {
        if key.len() < MIN_KEY_LEN {
            return Err(AuditError::WeakAuditKey { got: key.len() });
        }
        Ok(Self::Hash { key, key_id })
    }
}

/// Decodes an audit key from hex or, failing that, standard base64.
pub fn decode_key(raw: &str) -> Result<Vec<u8>, AuditError> {
    if let Ok(bytes) = hex::decode(raw.trim()) {
        return Ok(bytes);
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|_| AuditError::InvalidAuditKey)
}

/// Recursively sorts object keys so the same logical arguments always
/// serialize to the same bytes, regardless of the order an agent sent them
/// in. (`serde_json::Value` here preserves insertion order rather than
/// sorting automatically, since another dependency in this workspace enables
/// that behaviour — so this step is load-bearing, not defensive.)
fn canonicalize(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut sorted: std::collections::BTreeMap<&String, &Value> = Default::default();
            for (k, val) in map {
                sorted.insert(k, val);
            }
            let mut out = Map::new();
            for (k, val) in sorted {
                out.insert(k.clone(), canonicalize(val));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

/// Same JSON shape and keys, every leaf value replaced by its type and
/// length (strings) or just its type (everything else).
fn redact(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            Value::Object(map.iter().map(|(k, v)| (k.clone(), redact(v))).collect())
        }
        Value::Array(arr) => Value::Array(arr.iter().map(redact).collect()),
        Value::String(s) => Value::String(format!("<string:{}>", s.chars().count())),
        Value::Number(_) => Value::String("<number>".into()),
        Value::Bool(_) => Value::String("<bool>".into()),
        Value::Null => Value::String("<null>".into()),
    }
}

type HmacSha256 = Hmac<Sha256>;

fn represent_arguments(args: &Value, policy: &ArgsPolicy) -> Result<Value, AuditError> {
    match policy {
        ArgsPolicy::Full => Ok(args.clone()),
        ArgsPolicy::Redacted => Ok(redact(args)),
        ArgsPolicy::Hash { key, key_id } => {
            let canon = canonicalize(args);
            let bytes = serde_json::to_vec(&canon).map_err(|e| AuditError::Corrupt {
                line: 0,
                msg: e.to_string(),
            })?;
            let mut mac =
                HmacSha256::new_from_slice(key).map_err(|_| AuditError::InvalidAuditKey)?;
            mac.update(&bytes);
            let args_hmac = hex::encode(mac.finalize().into_bytes());
            Ok(json!({
                "args_hmac": args_hmac,
                "args_bytes": bytes.len(),
                "key_id": key_id,
            }))
        }
    }
}

/// One audit record as written today (`"v": 3`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub v: u8,
    pub seq: u64,
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    pub agent: AgentId,
    pub owner: Option<String>,
    pub tool: String,
    /// Shape depends on the [`ArgsPolicy`] active when this was written.
    pub arguments: Value,
    pub decision: Decision,
    pub gateway_instance: String,
    /// SHA-256 hex of the exact policy source text that made this decision
    /// (see `custos_policy::PolicyStore`) — proves which policy version
    /// decided this specific call.
    pub policy_version: String,
    pub prev_hash: String,
    pub hash: String,
}

/// Fields that are hashed. `hash` itself is excluded.
#[derive(Serialize)]
struct Hashed<'a> {
    v: u8,
    seq: u64,
    ts: &'a str,
    agent: &'a AgentId,
    owner: &'a Option<String>,
    tool: &'a str,
    arguments: &'a Value,
    decision: &'a Decision,
    gateway_instance: &'a str,
    policy_version: &'a str,
    prev_hash: &'a str,
}

fn hash_of(h: &Hashed<'_>) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(h)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// A record written before `policy_version` existed (`"v": 2`). Kept only so
/// [`verify`] can still walk a chain that includes one of these; never
/// written any more.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordV2 {
    v: u8,
    seq: u64,
    ts: String,
    agent: AgentId,
    owner: Option<String>,
    tool: String,
    arguments: Value,
    decision: Decision,
    gateway_instance: String,
    prev_hash: String,
    hash: String,
}

#[derive(Serialize)]
struct HashedV2<'a> {
    v: u8,
    seq: u64,
    ts: &'a str,
    agent: &'a AgentId,
    owner: &'a Option<String>,
    tool: &'a str,
    arguments: &'a Value,
    decision: &'a Decision,
    gateway_instance: &'a str,
    prev_hash: &'a str,
}

fn hash_of_v2(h: &HashedV2<'_>) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(h)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// A record written before `"v"` existed at all. Kept only so [`verify`] can
/// still walk a chain that starts with one of these; never written any more.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordV1 {
    seq: u64,
    ts: String,
    call: ToolCall,
    decision: Decision,
    prev_hash: String,
    hash: String,
}

#[derive(Serialize)]
struct HashedV1<'a> {
    seq: u64,
    ts: &'a str,
    call: &'a ToolCall,
    decision: &'a Decision,
    prev_hash: &'a str,
}

fn hash_of_v1(h: &HashedV1<'_>) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(h)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub struct AuditLog {
    path: PathBuf,
    file: File,
    seq: u64,
    last_hash: String,
    args_policy: ArgsPolicy,
    gateway_instance: String,
}

impl AuditLog {
    /// Open (or create) a log file. An existing file is verified first —
    /// including any older `v1` records at its start — and new records
    /// continue its chain.
    pub fn open(
        path: impl AsRef<Path>,
        args_policy: ArgsPolicy,
        gateway_instance: String,
    ) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        let (seq, last_hash) = if path.exists() {
            verify(&path)?
        } else {
            (0, GENESIS.to_string())
        };
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            file,
            seq,
            last_hash,
            args_policy,
            gateway_instance,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one decision and flush it to disk before returning.
    pub fn append(
        &mut self,
        call: &ToolCall,
        decision: &Decision,
        owner: Option<&str>,
        policy_version: &str,
    ) -> Result<Record, AuditError> {
        let ts = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let seq = self.seq + 1;
        let owner = owner.map(str::to_string);
        let arguments = represent_arguments(&call.arguments, &self.args_policy)?;
        let hash = hash_of(&Hashed {
            v: 3,
            seq,
            ts: &ts,
            agent: &call.agent,
            owner: &owner,
            tool: &call.tool,
            arguments: &arguments,
            decision,
            gateway_instance: &self.gateway_instance,
            policy_version,
            prev_hash: &self.last_hash,
        })
        .map_err(|e| AuditError::Corrupt {
            line: seq as usize,
            msg: e.to_string(),
        })?;
        let record = Record {
            v: 3,
            seq,
            ts,
            agent: call.agent.clone(),
            owner,
            tool: call.tool.clone(),
            arguments,
            decision: decision.clone(),
            gateway_instance: self.gateway_instance.clone(),
            policy_version: policy_version.to_string(),
            prev_hash: self.last_hash.clone(),
            hash: hash.clone(),
        };
        let mut line = serde_json::to_vec(&record).map_err(|e| AuditError::Corrupt {
            line: seq as usize,
            msg: e.to_string(),
        })?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.sync_data()?;
        self.seq = seq;
        self.last_hash = hash;
        Ok(record)
    }
}

/// Check the whole chain — `v1`, `v2` and `v3` records alike. Returns the
/// last sequence number and hash.
pub fn verify(path: impl AsRef<Path>) -> Result<(u64, String), AuditError> {
    let reader = BufReader::new(File::open(path)?);
    let mut prev = GENESIS.to_string();
    let mut seq = 0u64;
    for (i, line) in reader.lines().enumerate() {
        let n = i + 1;
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let raw: Value = serde_json::from_str(&line).map_err(|e| AuditError::Corrupt {
            line: n,
            msg: e.to_string(),
        })?;
        let corrupt = |e: serde_json::Error| AuditError::Corrupt {
            line: n,
            msg: e.to_string(),
        };
        let (r_seq, r_prev_hash, r_hash, expected) = match raw.get("v").and_then(Value::as_u64) {
            None => {
                let r: RecordV1 = serde_json::from_value(raw).map_err(corrupt)?;
                let expected = hash_of_v1(&HashedV1 {
                    seq: r.seq,
                    ts: &r.ts,
                    call: &r.call,
                    decision: &r.decision,
                    prev_hash: &r.prev_hash,
                })
                .map_err(corrupt)?;
                (r.seq, r.prev_hash, r.hash, expected)
            }
            Some(2) => {
                let r: RecordV2 = serde_json::from_value(raw).map_err(corrupt)?;
                let expected = hash_of_v2(&HashedV2 {
                    v: r.v,
                    seq: r.seq,
                    ts: &r.ts,
                    agent: &r.agent,
                    owner: &r.owner,
                    tool: &r.tool,
                    arguments: &r.arguments,
                    decision: &r.decision,
                    gateway_instance: &r.gateway_instance,
                    prev_hash: &r.prev_hash,
                })
                .map_err(corrupt)?;
                (r.seq, r.prev_hash, r.hash, expected)
            }
            Some(3) => {
                let r: Record = serde_json::from_value(raw).map_err(corrupt)?;
                let expected = hash_of(&Hashed {
                    v: r.v,
                    seq: r.seq,
                    ts: &r.ts,
                    agent: &r.agent,
                    owner: &r.owner,
                    tool: &r.tool,
                    arguments: &r.arguments,
                    decision: &r.decision,
                    gateway_instance: &r.gateway_instance,
                    policy_version: &r.policy_version,
                    prev_hash: &r.prev_hash,
                })
                .map_err(corrupt)?;
                (r.seq, r.prev_hash, r.hash, expected)
            }
            Some(v) => {
                return Err(AuditError::UnsupportedVersion {
                    line: n,
                    version: v,
                });
            }
        };
        if r_prev_hash != prev || r_hash != expected || r_seq != seq + 1 {
            return Err(AuditError::Broken { line: n });
        }
        prev = r_hash;
        seq = r_seq;
    }
    Ok((seq, prev))
}

#[cfg(test)]
mod tests {
    use super::*;
    use custos_core::AgentId;

    const KEY_A: &[u8] = b"01234567890123456789012345678901";
    const KEY_B: &[u8] = b"98765432109876543210987654321098";

    fn call(tool: &str, args: Value) -> ToolCall {
        ToolCall {
            agent: AgentId("a".into()),
            tool: tool.into(),
            arguments: args,
        }
    }

    fn log_in(dir: &tempfile::TempDir, policy: ArgsPolicy) -> (PathBuf, AuditLog) {
        let p = dir.path().join("audit.jsonl");
        match AuditLog::open(&p, policy, "test-instance".into()) {
            Ok(l) => (p, l),
            Err(e) => panic!("{e}"),
        }
    }

    fn hash_policy() -> ArgsPolicy {
        match ArgsPolicy::hash(KEY_A.to_vec(), "test-key".into()) {
            Ok(p) => p,
            Err(e) => panic!("{e}"),
        }
    }

    // --- key handling --------------------------------------------------

    #[test]
    fn short_key_is_rejected() {
        assert!(matches!(
            ArgsPolicy::hash(vec![0u8; 10], "id".into()),
            Err(AuditError::WeakAuditKey { got: 10 })
        ));
    }

    #[test]
    fn key_decodes_hex_or_base64() {
        let hex_key = "00".repeat(32);
        assert_eq!(decode_key(&hex_key).unwrap_or_default().len(), 32);

        let b64_key = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode([7u8; 32])
        };
        assert_eq!(decode_key(&b64_key).unwrap_or_default().len(), 32);

        assert!(decode_key("not hex or base64 at all!!").is_err());
    }

    // --- argument representation ----------------------------------------

    #[test]
    fn same_arguments_different_key_order_give_same_hmac() -> Result<(), AuditError> {
        let dir = tempfile::tempdir().map_err(AuditError::Io)?;
        let (_p, mut log) = log_in(&dir, hash_policy());
        let a = call(
            "t",
            json!({"iban": "RO49AAAA1B31007593840000", "amount": 10}),
        );
        let b = call(
            "t",
            json!({"amount": 10, "iban": "RO49AAAA1B31007593840000"}),
        );
        let ra = log.append(&a, &Decision::Allow, None, "policy-v1")?;
        let rb = log.append(&b, &Decision::Allow, None, "policy-v1")?;
        assert_eq!(ra.arguments["args_hmac"], rb.arguments["args_hmac"]);
        Ok(())
    }

    #[test]
    fn different_key_gives_different_hmac() -> Result<(), AuditError> {
        let dir = tempfile::tempdir().map_err(AuditError::Io)?;
        let args = json!({"iban": "RO49AAAA1B31007593840000"});

        let (_p1, mut log_a) = log_in(&dir, hash_policy());
        let ra = log_a.append(
            &call("t", args.clone()),
            &Decision::Allow,
            None,
            "policy-v1",
        )?;

        let dir_b = tempfile::tempdir().map_err(AuditError::Io)?;
        let policy_b = ArgsPolicy::hash(KEY_B.to_vec(), "other-key".into())?;
        let (_p2, mut log_b) = log_in(&dir_b, policy_b);
        let rb = log_b.append(&call("t", args), &Decision::Allow, None, "policy-v1")?;

        assert_ne!(ra.arguments["args_hmac"], rb.arguments["args_hmac"]);
        Ok(())
    }

    #[test]
    fn hash_mode_never_stores_the_raw_argument_value() -> Result<(), AuditError> {
        let dir = tempfile::tempdir().map_err(AuditError::Io)?;
        let (p, mut log) = log_in(&dir, hash_policy());
        log.append(
            &call("t", json!({"iban": "RO49AAAA1B31007593840000"})),
            &Decision::Allow,
            None,
            "policy-v1",
        )?;
        let raw = std::fs::read_to_string(&p).map_err(AuditError::Io)?;
        assert!(!raw.contains("RO49AAAA1B31007593840000"));
        Ok(())
    }

    #[test]
    fn redacted_mode_keeps_keys_hides_values() -> Result<(), AuditError> {
        let dir = tempfile::tempdir().map_err(AuditError::Io)?;
        let (_p, mut log) = log_in(&dir, ArgsPolicy::Redacted);
        let r = log.append(
            &call(
                "t",
                json!({"iban": "RO49AAAA1B31007593840000", "amount": 10}),
            ),
            &Decision::Allow,
            None,
            "policy-v1",
        )?;
        assert_eq!(r.arguments["iban"], "<string:24>");
        assert_eq!(r.arguments["amount"], "<number>");
        Ok(())
    }

    // --- chain integrity, v1/v2 compatibility ---------------------------

    #[test]
    fn v3_chain_verifies_and_resumes() -> Result<(), AuditError> {
        let dir = tempfile::tempdir().map_err(AuditError::Io)?;
        let (p, mut log) = log_in(&dir, hash_policy());
        log.append(
            &call("x", Value::Null),
            &Decision::Allow,
            Some("finance"),
            "policy-v1",
        )?;
        drop(log);
        let mut log = AuditLog::open(&p, hash_policy(), "test-instance".into())?;
        let r = log.append(&call("y", Value::Null), &Decision::Allow, None, "policy-v2")?;
        assert_eq!(r.seq, 2);
        assert_eq!(r.policy_version, "policy-v2");
        assert_eq!(verify(&p)?.0, 2);
        Ok(())
    }

    #[test]
    fn editing_args_hmac_breaks_the_chain() -> Result<(), AuditError> {
        let dir = tempfile::tempdir().map_err(AuditError::Io)?;
        let (p, mut log) = log_in(&dir, hash_policy());
        log.append(
            &call("t", json!({"iban": "RO49AAAA1B31007593840000"})),
            &Decision::Allow,
            None,
            "policy-v1",
        )?;
        drop(log);
        let text = std::fs::read_to_string(&p).map_err(AuditError::Io)?;
        let mut record: Value =
            serde_json::from_str(text.trim()).map_err(|e| AuditError::Corrupt {
                line: 1,
                msg: e.to_string(),
            })?;
        // Flip the recorded HMAC's first character to a different hex
        // digit — same shape, different value, no structural change.
        let hmac = record["arguments"]["args_hmac"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let mut chars: Vec<char> = hmac.chars().collect();
        if let Some(first) = chars.first_mut() {
            *first = if *first == '0' { '1' } else { '0' };
        }
        record["arguments"]["args_hmac"] = Value::String(chars.into_iter().collect());
        let mut tampered = serde_json::to_string(&record).map_err(|e| AuditError::Corrupt {
            line: 1,
            msg: e.to_string(),
        })?;
        tampered.push('\n');
        assert_ne!(text, tampered);
        std::fs::write(&p, tampered).map_err(AuditError::Io)?;
        assert!(matches!(verify(&p), Err(AuditError::Broken { line: 1 })));
        Ok(())
    }

    #[test]
    fn a_v1_log_still_verifies() -> Result<(), AuditError> {
        let dir = tempfile::tempdir().map_err(AuditError::Io)?;
        let p = dir.path().join("audit.jsonl");
        let v1 = HashedV1 {
            seq: 1,
            ts: "2026-01-01T00:00:00Z",
            call: &call("x", Value::Null),
            decision: &Decision::Allow,
            prev_hash: GENESIS,
        };
        let hash = hash_of_v1(&v1).map_err(|e| AuditError::Corrupt {
            line: 1,
            msg: e.to_string(),
        })?;
        let record = RecordV1 {
            seq: 1,
            ts: "2026-01-01T00:00:00Z".into(),
            call: call("x", Value::Null),
            decision: Decision::Allow,
            prev_hash: GENESIS.into(),
            hash,
        };
        let mut line = serde_json::to_vec(&record).map_err(|e| AuditError::Corrupt {
            line: 1,
            msg: e.to_string(),
        })?;
        line.push(b'\n');
        std::fs::write(&p, &line).map_err(AuditError::Io)?;

        let (seq, _) = verify(&p)?;
        assert_eq!(seq, 1);

        // A gateway can still resume (and append v3 records) after it.
        let mut log = AuditLog::open(&p, hash_policy(), "test-instance".into())?;
        let r = log.append(&call("y", Value::Null), &Decision::Allow, None, "policy-v1")?;
        assert_eq!(r.seq, 2);
        assert_eq!(r.v, 3);
        Ok(())
    }

    #[test]
    fn a_v2_log_still_verifies() -> Result<(), AuditError> {
        let dir = tempfile::tempdir().map_err(AuditError::Io)?;
        let p = dir.path().join("audit.jsonl");
        let v2 = HashedV2 {
            v: 2,
            seq: 1,
            ts: "2026-01-01T00:00:00Z",
            agent: &AgentId("a".into()),
            owner: &None,
            tool: "x",
            arguments: &Value::Null,
            decision: &Decision::Allow,
            gateway_instance: "gw-old",
            prev_hash: GENESIS,
        };
        let hash = hash_of_v2(&v2).map_err(|e| AuditError::Corrupt {
            line: 1,
            msg: e.to_string(),
        })?;
        let record = RecordV2 {
            v: 2,
            seq: 1,
            ts: "2026-01-01T00:00:00Z".into(),
            agent: AgentId("a".into()),
            owner: None,
            tool: "x".into(),
            arguments: Value::Null,
            decision: Decision::Allow,
            gateway_instance: "gw-old".into(),
            prev_hash: GENESIS.into(),
            hash,
        };
        let mut line = serde_json::to_vec(&record).map_err(|e| AuditError::Corrupt {
            line: 1,
            msg: e.to_string(),
        })?;
        line.push(b'\n');
        std::fs::write(&p, &line).map_err(AuditError::Io)?;

        let (seq, _) = verify(&p)?;
        assert_eq!(seq, 1);

        // A gateway can still resume (and append v3 records) after it.
        let mut log = AuditLog::open(&p, hash_policy(), "test-instance".into())?;
        let r = log.append(&call("y", Value::Null), &Decision::Allow, None, "policy-v1")?;
        assert_eq!(r.seq, 2);
        assert_eq!(r.v, 3);
        Ok(())
    }

    #[test]
    fn deleted_line_breaks_chain() -> Result<(), AuditError> {
        let dir = tempfile::tempdir().map_err(AuditError::Io)?;
        let (p, mut log) = log_in(&dir, ArgsPolicy::Full);
        for t in ["a", "b", "c"] {
            log.append(&call(t, Value::Null), &Decision::Allow, None, "policy-v1")?;
        }
        drop(log);
        let text = std::fs::read_to_string(&p).map_err(AuditError::Io)?;
        let kept: Vec<&str> = text
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        std::fs::write(&p, kept.join("\n")).map_err(AuditError::Io)?;
        assert!(matches!(verify(&p), Err(AuditError::Broken { line: 2 })));
        Ok(())
    }

    #[test]
    fn full_mode_stores_arguments_as_is() -> Result<(), AuditError> {
        let dir = tempfile::tempdir().map_err(AuditError::Io)?;
        let (_p, mut log) = log_in(&dir, ArgsPolicy::Full);
        let r = log.append(
            &call("t", json!({"amount": 10})),
            &Decision::Allow,
            None,
            "policy-v1",
        )?;
        assert_eq!(r.arguments, json!({"amount": 10}));
        Ok(())
    }
}
