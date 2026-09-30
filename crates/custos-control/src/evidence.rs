//! Evidence packs: a signed JSON bundle of the underlying records for a
//! time range, plus a human-readable PDF report (EN/DE/RO) built from the
//! same data. Neither is a compliance certification — see
//! `docs/decisions/0009-evidence-export.md` and the report's own
//! disclaimer section.

use crate::overview::DecisionCounts;
use crate::{agents, gateways, policies};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Agents(#[from] agents::AgentsError),
    #[error(transparent)]
    Policies(#[from] policies::PoliciesError),
    #[error(transparent)]
    Gateways(#[from] gateways::GatewaysError),
    #[error("could not serialize the evidence bundle: {0}")]
    Json(#[from] serde_json::Error),
    #[error("could not render the PDF report: {0}")]
    Pdf(String),
    #[error("unsupported language {0:?}")]
    UnsupportedLanguage(String),
}

/// A resolved approval plus the approver's email, joined here rather than
/// looked up one at a time - this report can list many.
#[derive(Debug, Serialize)]
pub struct ResolvedApproval {
    pub id: Uuid,
    pub gateway_id: Uuid,
    pub agent: String,
    pub tool: String,
    pub findings: Option<serde_json::Value>,
    pub reason: String,
    pub four_eyes: bool,
    pub status: String,
    pub comment: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub approver_email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EvidenceReport {
    pub tenant_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub from: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub to: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub agents: Vec<agents::Agent>,
    /// Every published version — a version is rare and small enough that
    /// the whole history is more useful here than a range-filtered slice.
    pub published_policy_versions: Vec<policies::PolicyVersion>,
    pub decisions: DecisionCounts,
    pub resolved_approvals: Vec<ResolvedApproval>,
    pub gateways: Vec<gateways::Gateway>,
}

/// Gathers everything an evidence pack needs for `[from, to]`, scoped to
/// one tenant. Time-ranged: decisions and resolved approvals. Not
/// time-ranged (current state, not history): the agent inventory, gateway
/// health/chain status, and the published policy history.
pub async fn gather(
    pool: &PgPool,
    tenant_id: Uuid,
    from: OffsetDateTime,
    to: OffsetDateTime,
) -> Result<EvidenceReport, EvidenceError> {
    let agent_list = agents::list_agents(pool, tenant_id).await?;

    let published_policy_versions: Vec<policies::PolicyVersion> =
        policies::list_versions(pool, tenant_id)
            .await?
            .into_iter()
            .filter(|v| v.published)
            .collect();

    let gateway_list = gateways::list_gateways(pool, tenant_id).await?;

    let verdict_counts: Vec<(Option<String>, i64)> = sqlx::query_as(
        "select verdict, count(*) from audit_records
         where tenant_id = $1 and ingested_at >= $2 and ingested_at <= $3
         group by verdict",
    )
    .bind(tenant_id)
    .bind(from)
    .bind(to)
    .fetch_all(pool)
    .await?;
    let mut decisions = DecisionCounts::default();
    for (verdict, count) in verdict_counts {
        match verdict.as_deref() {
            Some("ALLOW") => decisions.allow = count,
            Some("BLOCK") => decisions.block = count,
            Some("HOLD") => decisions.hold = count,
            _ => {}
        }
    }

    type ApprovalRow = (
        Uuid,
        Uuid,
        String,
        String,
        Option<serde_json::Value>,
        String,
        bool,
        String,
        Option<String>,
        OffsetDateTime,
        Option<String>,
    );
    let approval_rows: Vec<ApprovalRow> = sqlx::query_as(
        "select a.id, a.gateway_id, a.agent, a.tool, a.findings, a.reason, a.four_eyes,
                a.status, a.comment, a.created_at, u.email
         from approvals a
         left join users u on u.id = a.approver_user_id
         where a.tenant_id = $1 and a.resolved_at is not null
           and a.resolved_at >= $2 and a.resolved_at <= $3
         order by a.resolved_at asc",
    )
    .bind(tenant_id)
    .bind(from)
    .bind(to)
    .fetch_all(pool)
    .await?;
    let resolved_approvals = approval_rows
        .into_iter()
        .map(
            |(
                id,
                gateway_id,
                agent,
                tool,
                findings,
                reason,
                four_eyes,
                status,
                comment,
                created_at,
                approver_email,
            )| {
                ResolvedApproval {
                    id,
                    gateway_id,
                    agent,
                    tool,
                    findings,
                    reason,
                    four_eyes,
                    status,
                    comment,
                    created_at,
                    approver_email,
                }
            },
        )
        .collect();

    Ok(EvidenceReport {
        tenant_id,
        from,
        to,
        generated_at: OffsetDateTime::now_utc(),
        agents: agent_list,
        published_policy_versions,
        decisions,
        resolved_approvals,
        gateways: gateway_list,
    })
}

/// The signed JSON artifact: the exact bytes signed, kept verbatim, plus
/// the signature over them — same wire-format reasoning as
/// `custos_policy::bundle::SignedBundle` (never re-serialize to verify).
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct SignedEvidence {
    pub evidence_json: String,
    pub signature: String,
}

pub fn sign(
    report: &EvidenceReport,
    signing_key: &SigningKey,
) -> Result<SignedEvidence, EvidenceError> {
    let evidence_json = serde_json::to_string(report)?;
    let signature = signing_key.sign(evidence_json.as_bytes());
    Ok(SignedEvidence {
        evidence_json,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

#[derive(Debug, Clone, Copy)]
pub enum Lang {
    En,
    De,
    Ro,
}

impl std::str::FromStr for Lang {
    type Err = EvidenceError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "en" => Ok(Lang::En),
            "de" => Ok(Lang::De),
            "ro" => Ok(Lang::Ro),
            other => Err(EvidenceError::UnsupportedLanguage(other.to_string())),
        }
    }
}

mod pdf;
pub use pdf::render_pdf;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> EvidenceReport {
        EvidenceReport {
            tenant_id: Uuid::new_v4(),
            from: OffsetDateTime::UNIX_EPOCH,
            to: OffsetDateTime::now_utc(),
            generated_at: OffsetDateTime::now_utc(),
            agents: vec![],
            published_policy_versions: vec![],
            decisions: DecisionCounts::default(),
            resolved_approvals: vec![],
            gateways: vec![],
        }
    }

    #[test]
    fn signed_evidence_round_trips_through_the_signing_key() {
        let key = SigningKey::from_bytes(&[4u8; 32]);
        let signed = match sign(&sample_report(), &key) {
            Ok(s) => s,
            Err(e) => panic!("{e}"),
        };
        let sig_bytes: [u8; 64] = match URL_SAFE_NO_PAD
            .decode(&signed.signature)
            .ok()
            .and_then(|b| b.try_into().ok())
        {
            Some(b) => b,
            None => panic!("signature must decode to 64 bytes"),
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(
            key.verifying_key()
                .verify_strict(signed.evidence_json.as_bytes(), &signature)
                .is_ok()
        );
    }

    #[test]
    fn lang_parses_known_codes_and_rejects_others() {
        assert!(matches!("en".parse::<Lang>(), Ok(Lang::En)));
        assert!(matches!("de".parse::<Lang>(), Ok(Lang::De)));
        assert!(matches!("ro".parse::<Lang>(), Ok(Lang::Ro)));
        assert!("fr".parse::<Lang>().is_err());
    }

    #[test]
    fn pdf_renders_for_every_supported_language() {
        for lang in [Lang::En, Lang::De, Lang::Ro] {
            let bytes = match render_pdf(&sample_report(), lang) {
                Ok(b) => b,
                Err(e) => panic!("{e}"),
            };
            assert!(bytes.starts_with(b"%PDF"), "output must be a real PDF");
        }
    }
}
