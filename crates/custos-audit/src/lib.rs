//! Tamper-evident audit log.
//!
//! Each line of the log is one JSON record. Every record contains the hash of
//! the previous record, so editing or deleting any line breaks the chain and
//! [`verify`] reports where. v0 writes JSON Lines to a local file; the
//! ClickHouse sink and signatures come later (see docs/PLAN.md).

use custos_core::{Decision, ToolCall};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit record is not valid JSON at line {line}: {msg}")]
    Corrupt { line: usize, msg: String },
    #[error("hash chain broken at line {line}")]
    Broken { line: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub seq: u64,
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    pub call: ToolCall,
    pub decision: Decision,
    pub prev_hash: String,
    pub hash: String,
}

/// Fields that are hashed. `hash` itself is excluded.
#[derive(Serialize)]
struct Hashed<'a> {
    seq: u64,
    ts: &'a str,
    call: &'a ToolCall,
    decision: &'a Decision,
    prev_hash: &'a str,
}

fn hash_of(h: &Hashed<'_>) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(h)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub struct AuditLog {
    path: PathBuf,
    file: File,
    seq: u64,
    last_hash: String,
}

impl AuditLog {
    /// Open (or create) a log file. An existing file is verified first, and
    /// new records continue its chain.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
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
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one decision and flush it to disk before returning.
    pub fn append(&mut self, call: &ToolCall, decision: &Decision) -> Result<Record, AuditError> {
        let ts = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let seq = self.seq + 1;
        let hash = hash_of(&Hashed {
            seq,
            ts: &ts,
            call,
            decision,
            prev_hash: &self.last_hash,
        })
        .map_err(|e| AuditError::Corrupt {
            line: seq as usize,
            msg: e.to_string(),
        })?;
        let record = Record {
            seq,
            ts,
            call: call.clone(),
            decision: decision.clone(),
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

/// Check the whole chain. Returns the last sequence number and hash.
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
        let r: Record = serde_json::from_str(&line).map_err(|e| AuditError::Corrupt {
            line: n,
            msg: e.to_string(),
        })?;
        let expected = hash_of(&Hashed {
            seq: r.seq,
            ts: &r.ts,
            call: &r.call,
            decision: &r.decision,
            prev_hash: &r.prev_hash,
        })
        .map_err(|e| AuditError::Corrupt {
            line: n,
            msg: e.to_string(),
        })?;
        if r.prev_hash != prev || r.hash != expected || r.seq != seq + 1 {
            return Err(AuditError::Broken { line: n });
        }
        prev = r.hash;
        seq = r.seq;
    }
    Ok((seq, prev))
}

#[cfg(test)]
mod tests {
    use super::*;
    use custos_core::AgentId;

    fn call(tool: &str) -> ToolCall {
        ToolCall {
            agent: AgentId("a".into()),
            tool: tool.into(),
            arguments: serde_json::json!({"n": 1}),
        }
    }

    fn log_in(dir: &tempfile::TempDir) -> (PathBuf, AuditLog) {
        let p = dir.path().join("audit.jsonl");
        match AuditLog::open(&p) {
            Ok(l) => (p, l),
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn chain_verifies_and_resumes() -> Result<(), AuditError> {
        let dir = tempfile::tempdir()?;
        let (p, mut log) = log_in(&dir);
        log.append(&call("x"), &Decision::Allow)?;
        log.append(
            &call("y"),
            &Decision::Block {
                reason: "no".into(),
            },
        )?;
        drop(log);
        let mut log = AuditLog::open(&p)?;
        let r = log.append(&call("z"), &Decision::Allow)?;
        assert_eq!(r.seq, 3);
        assert_eq!(verify(&p)?.0, 3);
        Ok(())
    }

    #[test]
    fn edited_line_breaks_chain() -> Result<(), AuditError> {
        let dir = tempfile::tempdir()?;
        let (p, mut log) = log_in(&dir);
        log.append(
            &call("payroll.read_salaries"),
            &Decision::Block {
                reason: "forbidden".into(),
            },
        )?;
        log.append(&call("x"), &Decision::Allow)?;
        drop(log);
        // An attacker rewrites the block into an allow.
        let text = std::fs::read_to_string(&p)?;
        let tampered = text.replacen(
            r#""decision":{"verdict":"BLOCK","reason":"forbidden"}"#,
            r#""decision":{"verdict":"ALLOW"}"#,
            1,
        );
        assert_ne!(text, tampered);
        std::fs::write(&p, tampered)?;
        assert!(matches!(verify(&p), Err(AuditError::Broken { line: 1 })));
        Ok(())
    }

    #[test]
    fn deleted_line_breaks_chain() -> Result<(), AuditError> {
        let dir = tempfile::tempdir()?;
        let (p, mut log) = log_in(&dir);
        for t in ["a", "b", "c"] {
            log.append(&call(t), &Decision::Allow)?;
        }
        drop(log);
        let text = std::fs::read_to_string(&p)?;
        let kept: Vec<&str> = text
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        std::fs::write(&p, kept.join("\n"))?;
        assert!(matches!(verify(&p), Err(AuditError::Broken { line: 2 })));
        Ok(())
    }
}
