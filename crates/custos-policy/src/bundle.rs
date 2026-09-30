//! The policy bundle: what Control publishes and a gateway applies. Pure,
//! no I/O and no database — building one from stored policy versions and
//! serving it is Control's job; verifying and applying one is the
//! gateway's. Shared here so both sides work from the exact same types and
//! the exact same signing/verification logic, without the gateway needing
//! to depend on Control's Postgres-backed crate just to check a signature.
//!
//! See `docs/decisions/0003-policy-bundle.md` for why the wire format is
//! shaped this way.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("could not (de)serialize the policy bundle: {0}")]
    Json(#[from] serde_json::Error),
    #[error("malformed signed bundle: {0}")]
    Malformed(String),
    #[error("bundle signature does not verify")]
    BadSignature,
}

/// One agent's identity inside a published bundle: enough for a gateway to
/// recognize the agent and check its token, never anything else about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleAgent {
    pub id: Uuid,
    pub name: String,
    pub token_sha256: Option<String>,
}

/// What gets signed on publish: the exact policy and schema text of one
/// version, plus a snapshot of every active agent's identity and token
/// hash, so a gateway that applies this bundle knows both the rules and
/// who they apply to as of the moment it was published.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBundle {
    pub bundle_json: String,
    pub signature: String,
}

/// Serializes and signs `bundle`, producing the exact wire format
/// [`verify_bundle`] checks. `bundle_json` and `signature` must always
/// travel together unchanged — never re-derive one from the other.
pub fn sign_bundle(
    bundle: &PolicyBundle,
    signing_key: &SigningKey,
) -> Result<SignedBundle, BundleError> {
    let bundle_json = serde_json::to_string(bundle)?;
    let signature = signing_key.sign(bundle_json.as_bytes());
    Ok(SignedBundle {
        bundle_json,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

/// Verifies a [`SignedBundle`] against `verifying_key`, returning the
/// bundle it carries only once the signature over its exact bytes checks
/// out. A single flipped byte anywhere in `bundle_json` fails this, since
/// the signature covers that string byte-for-byte.
pub fn verify_bundle(
    signed: &SignedBundle,
    verifying_key: &VerifyingKey,
) -> Result<PolicyBundle, BundleError> {
    let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&signed.signature)
        .map_err(|e| BundleError::Malformed(e.to_string()))?
        .try_into()
        .map_err(|_| BundleError::Malformed("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(signed.bundle_json.as_bytes(), &signature)
        .map_err(|_| BundleError::BadSignature)?;
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

    #[test]
    fn a_correctly_signed_bundle_verifies() {
        let key = signing_key();
        let signed = match sign_bundle(&sample_bundle(), &key) {
            Ok(s) => s,
            Err(e) => panic!("{e}"),
        };
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
        let mut signed = match sign_bundle(&sample_bundle(), &key) {
            Ok(s) => s,
            Err(e) => panic!("{e}"),
        };
        // Flip one character inside the signed JSON without re-signing -
        // simulates an attacker (or a bug) modifying the bundle in transit.
        signed.bundle_json = signed.bundle_json.replace("agent-a", "agent-b");
        let result = verify_bundle(&signed, &key.verifying_key());
        assert!(matches!(result, Err(BundleError::BadSignature)));
    }

    #[test]
    fn a_bundle_signed_by_a_different_key_fails_verification() {
        let key = signing_key();
        let other_key = SigningKey::from_bytes(&[9u8; 32]);
        let signed = match sign_bundle(&sample_bundle(), &key) {
            Ok(s) => s,
            Err(e) => panic!("{e}"),
        };
        let result = verify_bundle(&signed, &other_key.verifying_key());
        assert!(matches!(result, Err(BundleError::BadSignature)));
    }

    #[test]
    fn malformed_signature_is_rejected_not_panicked_on() {
        let key = signing_key();
        let mut signed = match sign_bundle(&sample_bundle(), &key) {
            Ok(s) => s,
            Err(e) => panic!("{e}"),
        };
        signed.signature = "not-base64!!".into();
        let result = verify_bundle(&signed, &key.verifying_key());
        assert!(matches!(result, Err(BundleError::Malformed(_))));
    }
}
