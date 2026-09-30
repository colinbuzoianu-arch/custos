//! Policy sets: versioned Cedar source per tenant, validated with
//! [`custos_policy`] on every save, published as a signed bundle a gateway
//! can trust, and diffable between any two versions.
//!
//! See `docs/decisions/0003-policy-bundle.md` for why the bundle is shaped
//! and signed the way it is.

pub use custos_policy::bundle::{BundleAgent, PolicyBundle, SignedBundle, verify_bundle};

use custos_policy::bundle::BundleError;
use ed25519_dalek::SigningKey;
use serde::Serialize;
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
    #[error(transparent)]
    Bundle(#[from] BundleError),
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
    let signed = custos_policy::bundle::sign_bundle(&bundle, signing_key)?;

    sqlx::query(
        "update policy_versions
         set published = true, published_at = now(), bundle_json = $3, bundle_signature = $4
         where tenant_id = $1 and version = $2",
    )
    .bind(tenant_id)
    .bind(version)
    .bind(&signed.bundle_json)
    .bind(&signed.signature)
    .execute(pool)
    .await?;

    let updated = get_version(pool, tenant_id, version).await?;
    Ok((updated, signed))
}

/// The most recently published version's frozen bundle, if the tenant has
/// published anything at all. Never regenerated — this is exactly the
/// bytes [`publish`] signed, byte for byte.
pub async fn latest_published_bundle(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Option<(i32, SignedBundle)>, PoliciesError> {
    let row: Option<(i32, String, String)> = sqlx::query_as(
        "select version, bundle_json, bundle_signature from policy_versions
         where tenant_id = $1 and published = true
         order by version desc
         limit 1",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(version, bundle_json, signature)| {
        (
            version,
            SignedBundle {
                bundle_json,
                signature,
            },
        )
    }))
}

#[cfg(test)]
mod tests {
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
