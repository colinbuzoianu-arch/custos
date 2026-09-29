//! Short-lived, Ed25519-signed agent tokens — pure functions, no I/O.
//!
//! A token is `base64url(payload_json).base64url(signature)`. The payload
//! carries the agent id, issued-at, expiry, and the id of the key that
//! signed it — but none of that is trusted until [`verify`] checks the
//! signature against a key the caller configured. `key_id` inside the
//! payload is used only to pick *which* key to try, the same role a JWT's
//! `kid` header plays; a forged `key_id` still needs a forged signature to
//! be accepted.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("malformed token")]
    Malformed,
    #[error("unknown signing key {0}")]
    UnknownKeyId(String),
    #[error("bad signature")]
    BadSignature,
    #[error("token expired at {exp}, now is {now}")]
    Expired { exp: i64, now: i64 },
    #[error("key must be hex or base64")]
    InvalidKeyEncoding,
    #[error("key must be exactly {expected} bytes, got {got}")]
    WrongKeyLength { expected: usize, got: usize },
}

/// What a verified token proves. Only ever constructed by [`verify`] after
/// the signature checks out — there is no public way to build one that
/// skips verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenPayload {
    pub agent: String,
    /// Unix seconds.
    pub iat: i64,
    /// Unix seconds.
    pub exp: i64,
    pub key_id: String,
}

/// Decodes a 32-byte key (signing seed or public key) from hex or, failing
/// that, standard base64 — same rule as `custos_audit`'s audit key, so an
/// operator only has to remember one convention.
pub fn decode_key_32(raw: &str) -> Result<[u8; 32], TokenError> {
    let bytes = if let Ok(b) = hex::decode(raw.trim()) {
        b
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(raw.trim())
            .map_err(|_| TokenError::InvalidKeyEncoding)?
    };
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| TokenError::WrongKeyLength {
            expected: 32,
            got: b.len(),
        })
}

/// Signs a new token for `agent`, expiring `ttl_secs` seconds after `now`
/// (both Unix seconds — the caller supplies "now" so this stays a pure
/// function of its inputs, easy to test without touching the clock).
pub fn issue(
    signing_key: &SigningKey,
    agent: &str,
    now: i64,
    ttl_secs: i64,
    key_id: &str,
) -> String {
    let payload = TokenPayload {
        agent: agent.to_string(),
        iat: now,
        exp: now + ttl_secs,
        key_id: key_id.to_string(),
    };
    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let signature = signing_key.sign(&payload_bytes);
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&payload_bytes),
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

/// Verifies `token` against `keys` (looked up by the payload's `key_id`,
/// which is how key rotation works: list the old and new key together
/// during the overlap window) and checks it hasn't expired as of `now`.
pub fn verify(
    token: &str,
    keys: &HashMap<String, VerifyingKey>,
    now: i64,
) -> Result<TokenPayload, TokenError> {
    let (payload_b64, sig_b64) = token.split_once('.').ok_or(TokenError::Malformed)?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| TokenError::Malformed)?;
    let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| TokenError::Malformed)?
        .try_into()
        .map_err(|_| TokenError::Malformed)?;
    let payload: TokenPayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| TokenError::Malformed)?;

    let key = keys
        .get(&payload.key_id)
        .ok_or_else(|| TokenError::UnknownKeyId(payload.key_id.clone()))?;
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify(&payload_bytes, &signature)
        .map_err(|_| TokenError::BadSignature)?;

    if now >= payload.exp {
        return Err(TokenError::Expired {
            exp: payload.exp,
            now,
        });
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn keys(pairs: &[(&str, &SigningKey)]) -> HashMap<String, VerifyingKey> {
        pairs
            .iter()
            .map(|(id, k)| (id.to_string(), k.verifying_key()))
            .collect()
    }

    #[test]
    fn valid_token_verifies_and_carries_the_agent() {
        let key = signing_key(1);
        let token = issue(&key, "invoice-processor", 1000, 3600, "k1");
        let payload = match verify(&token, &keys(&[("k1", &key)]), 1500) {
            Ok(p) => p,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(payload.agent, "invoice-processor");
        assert_eq!(payload.key_id, "k1");
    }

    #[test]
    fn expired_token_is_rejected() {
        let key = signing_key(1);
        let token = issue(&key, "a", 1000, 3600, "k1");
        // now == exp counts as expired, not "still valid until".
        let result = verify(&token, &keys(&[("k1", &key)]), 1000 + 3600);
        assert!(matches!(result, Err(TokenError::Expired { .. })));
    }

    #[test]
    fn token_signed_by_a_different_key_is_rejected() {
        let signer = signing_key(1);
        let wrong = signing_key(2);
        let token = issue(&signer, "a", 1000, 3600, "k1");
        // Same key_id, but the gateway only trusts a *different* key under
        // that id — simulates a token forged with an untrusted key.
        let result = verify(&token, &keys(&[("k1", &wrong)]), 1500);
        assert!(matches!(result, Err(TokenError::BadSignature)));
    }

    #[test]
    fn unknown_key_id_is_rejected() {
        let key = signing_key(1);
        let token = issue(&key, "a", 1000, 3600, "k1");
        let result = verify(&token, &keys(&[("k2", &key)]), 1500);
        assert!(matches!(result, Err(TokenError::UnknownKeyId(id)) if id == "k1"));
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let key = signing_key(1);
        let token = issue(&key, "invoice-processor", 1000, 3600, "k1");
        let (payload_b64, sig_b64) = match token.split_once('.') {
            Some(parts) => parts,
            None => panic!("token must have two parts"),
        };
        let mut payload_bytes = match URL_SAFE_NO_PAD.decode(payload_b64) {
            Ok(b) => b,
            Err(e) => panic!("{e}"),
        };
        // Flip a byte inside the (still base64-valid) payload — e.g. try to
        // rename the agent without re-signing.
        if let Some(byte) = payload_bytes.first_mut() {
            *byte ^= 0xFF;
        }
        let tampered = format!("{}.{sig_b64}", URL_SAFE_NO_PAD.encode(&payload_bytes));
        let result = verify(&tampered, &keys(&[("k1", &key)]), 1500);
        assert!(matches!(
            result,
            Err(TokenError::BadSignature) | Err(TokenError::Malformed)
        ));
    }

    #[test]
    fn rotation_accepts_tokens_from_either_key() {
        let old_key = signing_key(1);
        let new_key = signing_key(2);
        let trusted = keys(&[("old", &old_key), ("new", &new_key)]);

        let old_token = issue(&old_key, "a", 1000, 3600, "old");
        let new_token = issue(&new_key, "a", 1000, 3600, "new");

        assert!(verify(&old_token, &trusted, 1500).is_ok());
        assert!(verify(&new_token, &trusted, 1500).is_ok());
    }

    #[test]
    fn malformed_tokens_are_rejected_not_panicked_on() {
        let key = signing_key(1);
        let trusted = keys(&[("k1", &key)]);
        for bad in ["", "not-a-token", "a.b", "onlyonepart"] {
            let result = verify(bad, &trusted, 1500);
            assert!(result.is_err(), "{bad:?} should not verify");
        }
    }

    #[test]
    fn key_decodes_hex_or_base64() {
        let hex_key = "00".repeat(32);
        assert!(decode_key_32(&hex_key).is_ok());

        let b64_key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert!(decode_key_32(&b64_key).is_ok());

        assert!(decode_key_32("too short").is_err());
    }
}
