//! Policy sets: versioned Cedar source per tenant, validated with
//! [`custos_policy`] on every save, published as a signed bundle a gateway
//! can trust, and diffable between any two versions.
//!
//! See `docs/decisions/0003-policy-bundle.md` for why the bundle is shaped
//! and signed the way it is.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum PoliciesError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("version not found")]
    NotFound,
    #[error("this version failed validation and cannot be published: {0}")]
    Invalid(String),
    #[error("could not serialize the policy bundle: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("malformed signed bundle: {0}")]
    MalformedBundle(String),
    #[error("bundle signature does not verify")]
    BadSignature,
}

#[derive(Debug, Serialize)]
pub struct PolicyVersion {
    pub id: Uuid,
    pub version: i32,
    pub policy_text: String,
    pub schema_text: Option<String>,
    pub message: Option<String>,
    pub valid: bool,
    pub validation_error: Option<String>,
    pub published: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

type PolicyVersionRow = (
    Uuid,
    i32,
    String,
    Option<String>,
    Option<String>,
    bool,
    Option<String>,
    bool,
    OffsetDateTime,
);

fn row_to_version(row: PolicyVersionRow) -> PolicyVersion {
    let (
        id,
        version,
        policy_text,
        schema_text,
        message,
        valid,
        validation_error,
        published,
        created_at,
    ) = row;
    PolicyVersion {
        id,
        version,
        policy_text,
        schema_text,
        message,
        valid,
        validation_error,
        published,
        created_at,
    }
}

const VERSION_COLUMNS: &str = "id, version, policy_text, schema_text, message, valid, validation_error, published, created_at";

/// Validates `policy_text` (and, if given, `schema_text`) and saves it as
/// the next version for `tenant_id` — an invalid draft is still saved
/// (with `valid = false` and the reason recorded), it just can't be
/// [`publish`]ed. Version numbers are assigned by the insert itself
/// (`max(version) + 1` per tenant in the same statement); under concurrent
/// saves for the same tenant this can race onto a duplicate version number,
/// which the unique constraint turns into a retryable error rather than
/// silent data loss — acceptable for an admin-only, low-frequency action.
pub async fn save_draft(
    pool: &PgPool,
    tenant_id: Uuid,
    author_user_id: Uuid,
    policy_text: &str,
    schema_text: Option<&str>,
    message: Option<&str>,
) -> Result<PolicyVersion, PoliciesError> {
    let validation_error = custos_policy::validate_source(policy_text, schema_text)
        .err()
        .map(|e| e.to_string());
    let valid = validation_error.is_none();

    let sql = format!(
        "with next as (
            select coalesce(max(version), 0) + 1 as v from policy_versions where tenant_id = $1
        )
        insert into policy_versions
            (tenant_id, version, policy_text, schema_text, author_user_id, message, valid, validation_error)
        select $1, next.v, $2, $3, $4, $5, $6, $7 from next
        returning {VERSION_COLUMNS}"
    );
    let row: PolicyVersionRow = sqlx::query_as(&sql)
        .bind(tenant_id)
        .bind(policy_text)
        .bind(schema_text)
        .bind(author_user_id)
        .bind(message)
        .bind(valid)
        .bind(&validation_error)
        .fetch_one(pool)
        .await?;
    Ok(row_to_version(row))
}

pub async fn list_versions(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Vec<PolicyVersion>, PoliciesError> {
    let sql = format!(
        "select {VERSION_COLUMNS} from policy_versions where tenant_id = $1 order by version desc"
    );
    let rows: Vec<PolicyVersionRow> = sqlx::query_as(&sql).bind(tenant_id).fetch_all(pool).await?;
    Ok(rows.into_iter().map(row_to_version).collect())
}

pub async fn get_version(
    pool: &PgPool,
    tenant_id: Uuid,
    version: i32,
) -> Result<PolicyVersion, PoliciesError> {
    let sql = format!(
        "select {VERSION_COLUMNS} from policy_versions where tenant_id = $1 and version = $2"
    );
    let row: Option<PolicyVersionRow> = sqlx::query_as(&sql)
        .bind(tenant_id)
        .bind(version)
        .fetch_optional(pool)
        .await?;
    row.map(row_to_version).ok_or(PoliciesError::NotFound)
}

/// A unified text diff of the policy source between two versions of the
/// same tenant.
pub async fn diff_versions(
    pool: &PgPool,
    tenant_id: Uuid,
    from: i32,
    to: i32,
) -> Result<String, PoliciesError> {
    let from_v = get_version(pool, tenant_id, from).await?;
    let to_v = get_version(pool, tenant_id, to).await?;
    let from_label = format!("v{from}");
    let to_label = format!("v{to}");
    let text_diff = similar::TextDiff::from_lines(&from_v.policy_text, &to_v.policy_text);
    Ok(text_diff
        .unified_diff()
        .header(&from_label, &to_label)
        .to_string())
}

/// One agent's identity inside a published bundle: enough for a gateway to
/// recognize the agent and check its token, never anything else about it.
#[derive(Debug, Serialize, Deserialize)]
pub struct BundleAgent {
    pub id: Uuid,
    pub name: String,
    pub token_sha256: Option<String>,
}

/// What gets signed on publish: the exact policy and schema text of one
/// version, plus a snapshot of every active agent's identity and token
/// hash, so a gateway that applies this bundle knows both the rules and
/// who they apply to as of the moment it was published.
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub tenant_id: Uuid,
    pub version: i32,
    pub policy: String,
    pub schema: Option<String>,
    pub agents: Vec<BundleAgent>,
    #[serde(with = "time::serde::rfc3339")]
    pub published_at: OffsetDateTime,
}

/// The wire format: the exact bytes that were signed, kept verbatim as a
/// JSON string, plus the signature over those bytes. Verification never
/// re-serializes `bundle` to recover what was signed — `serde_json::Value`
/// doesn't preserve field order the same way twice, so re-encoding it could
/// produce different bytes than what was actually signed. Keeping the
/// signed bytes themselves avoids that trap entirely.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedBundle {
    pub bundle_json: String,
    pub signature: String,
}

/// Publishes `version`: it must already be valid (from [`save_draft`]'s
/// check), never re-validated here so publish can't silently pass something
/// that would fail if checked again with a since-changed schema. Builds the
/// bundle from that version's exact stored text plus the tenant's currently
/// active agents, signs it, and records the version as published.
pub async fn publish(
    pool: &PgPool,
    tenant_id: Uuid,
    version: i32,
    signing_key: &SigningKey,
) -> Result<(PolicyVersion, SignedBundle), PoliciesError> {
    let v = get_version(pool, tenant_id, version).await?;
    if !v.valid {
        return Err(PoliciesError::Invalid(
            v.validation_error.unwrap_or_else(|| "not validated".into()),
        ));
    }

    let agent_rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
        "select id, name, token_sha256 from agents
         where tenant_id = $1 and status = 'active'
         order by id",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    let agents = agent_rows
        .into_iter()
        .map(|(id, name, token_sha256)| BundleAgent {
            id,
            name,
            token_sha256,
        })
        .collect();

    let bundle = PolicyBundle {
        tenant_id,
        version,
        policy: v.policy_text.clone(),
        schema: v.schema_text.clone(),
        agents,
        published_at: OffsetDateTime::now_utc(),
    };
    let bundle_json = serde_json::to_string(&bundle)?;
    let signature = signing_key.sign(bundle_json.as_bytes());
    let signed = SignedBundle {
        bundle_json,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    };

    sqlx::query(
        "update policy_versions set published = true, published_at = now() where tenant_id = $1 and version = $2",
    )
    .bind(tenant_id)
    .bind(version)
    .execute(pool)
    .await?;

    let updated = get_version(pool, tenant_id, version).await?;
    Ok((updated, signed))
}

/// Verifies a [`SignedBundle`] against `verifying_key`, returning the
/// bundle it carries only once the signature over its exact bytes checks
/// out. A single flipped byte anywhere in `bundle_json` fails this, since
/// the signature covers that string byte-for-byte.
pub fn verify_bundle(
    signed: &SignedBundle,
    verifying_key: &VerifyingKey,
) -> Result<PolicyBundle, PoliciesError> {
    let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&signed.signature)
        .map_err(|e| PoliciesError::MalformedBundle(e.to_string()))?
        .try_into()
        .map_err(|_| PoliciesError::MalformedBundle("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(signed.bundle_json.as_bytes(), &signature)
        .map_err(|_| PoliciesError::BadSignature)?;
    let bundle: PolicyBundle = serde_json::from_str(&signed.bundle_json)?;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sample_bundle() -> PolicyBundle {
        PolicyBundle {
            tenant_id: Uuid::new_v4(),
            version: 1,
            policy: "permit(principal, action, resource);".into(),
            schema: None,
            agents: vec![BundleAgent {
                id: Uuid::new_v4(),
                name: "agent-a".into(),
                token_sha256: Some("abc123".into()),
            }],
            published_at: OffsetDateTime::now_utc(),
        }
    }

    fn sign(bundle: &PolicyBundle, key: &SigningKey) -> SignedBundle {
        let bundle_json = match serde_json::to_string(bundle) {
            Ok(s) => s,
            Err(e) => panic!("{e}"),
        };
        let signature = key.sign(bundle_json.as_bytes());
        SignedBundle {
            bundle_json,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }
    }

    #[test]
    fn a_correctly_signed_bundle_verifies() {
        let key = signing_key();
        let signed = sign(&sample_bundle(), &key);
        let verified = match verify_bundle(&signed, &key.verifying_key()) {
            Ok(b) => b,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(verified.version, 1);
        assert_eq!(verified.agents.len(), 1);
    }

    #[test]
    fn a_tampered_bundle_fails_verification() {
        let key = signing_key();
        let mut signed = sign(&sample_bundle(), &key);
        // Flip one character inside the signed JSON without re-signing -
        // simulates an attacker (or a bug) modifying the bundle in transit.
        signed.bundle_json = signed.bundle_json.replace("agent-a", "agent-b");
        let result = verify_bundle(&signed, &key.verifying_key());
        assert!(matches!(result, Err(PoliciesError::BadSignature)));
    }

    #[test]
    fn a_bundle_signed_by_a_different_key_fails_verification() {
        let key = signing_key();
        let other_key = SigningKey::from_bytes(&[9u8; 32]);
        let signed = sign(&sample_bundle(), &key);
        let result = verify_bundle(&signed, &other_key.verifying_key());
        assert!(matches!(result, Err(PoliciesError::BadSignature)));
    }

    #[test]
    fn diff_output_shows_added_and_removed_lines() {
        let from = "permit(principal, action, resource == Tool::\"a\");\n";
        let to = "permit(principal, action, resource == Tool::\"b\");\n";
        let text_diff = similar::TextDiff::from_lines(from, to);
        let output = text_diff.unified_diff().header("v1", "v2").to_string();
        assert!(output.contains("-permit(principal, action, resource == Tool::\"a\");"));
        assert!(output.contains("+permit(principal, action, resource == Tool::\"b\");"));
    }
}
