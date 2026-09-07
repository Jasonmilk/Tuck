//! Session tokens (JWT HS256) — the CAPABILITY-13 mode-scope carrier.
//!
//! Implemented directly on HMAC-SHA256 (workspace deps), no heavy JWT
//! crate: the format is three base64url segments, the signature is a plain
//! HMAC. Claims are minimal: issuer, subject, mode scope, issued-at, expiry.
//!
//! Philosophy: Tuck judges strings, never meaning — a token is validated
//! as bytes (signature + clock), the scope is passed through to audit as an
//! opaque label. No semantic interpretation of the scope here.

use serde::{Deserialize, Serialize};

/// Parse + validate errors for a session token.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token is not three segments")]
    Malformed,
    #[error("header algorithm is not HS256")]
    UnsupportedAlg,
    #[error("signature mismatch")]
    BadSignature,
    #[error("token payload is not valid json")]
    BadJson,
    #[error("token has expired")]
    Expired,
    #[error("secret not configured")]
    NoSecret,
}

/// Minimal claims carried by a session token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// Issuer — fixed to the Tuck gateway identity.
    pub iss: String,
    /// Session subject (who the token was issued to).
    pub sub: String,
    /// Mode scope label (driving / partner / survival capability scopes).
    /// Passed to audit as-is; Tuck never interprets it semantically.
    pub scope: String,
    /// Issued-at (unix seconds).
    pub iat: u64,
    /// Expiry (unix seconds).
    pub exp: u64,
}

fn b64u_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn b64u_decode(seg: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seg.as_bytes())
        .ok()
}

fn sign(secret: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::Mac;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret).expect("hmac accepts any key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Verify a token against the shared secret. Returns the claims on success.
///
/// Deterministic: same token + secret → same result; expiry is the only
/// wall-clock input (injected via `now` for replayable tests).
pub fn verify(token: &str, secret: &[u8], now: u64) -> Result<Claims, TokenError> {
    if secret.is_empty() {
        return Err(TokenError::NoSecret);
    }
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(sig), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(TokenError::Malformed);
    };

    // Algorithm pin: HS256 only (no algorithm-confusion surface).
    let hdr_bytes = b64u_decode(header).ok_or(TokenError::Malformed)?;
    let hdr: serde_json::Value = serde_json::from_slice(&hdr_bytes).map_err(|_| TokenError::BadJson)?;
    if hdr.get("alg").and_then(serde_json::Value::as_str) != Some("HS256") {
        return Err(TokenError::UnsupportedAlg);
    }

    // Constant-time signature check over the unsigned part.
    let unsigned = format!("{header}.{payload}");
    let expect = b64u_encode(&sign(secret, unsigned.as_bytes()));
    if !constant_time_eq(&expect, sig) {
        return Err(TokenError::BadSignature);
    }

    let claim_bytes = b64u_decode(payload).ok_or(TokenError::Malformed)?;
    let claims: Claims = serde_json::from_slice(&claim_bytes).map_err(|_| TokenError::BadJson)?;
    if now >= claims.exp {
        return Err(TokenError::Expired);
    }
    Ok(claims)
}

/// Constant-time string comparison (no early exit on mismatch).
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Issue a token (used by tests and by the issuer side).
pub fn issue(secret: &[u8], claims: &Claims) -> String {
    let header = b64u_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = b64u_encode(&serde_json::to_vec(claims).expect("claims serialize"));
    let unsigned = format!("{header}.{payload}");
    let sig = b64u_encode(&sign(secret, unsigned.as_bytes()));
    format!("{unsigned}.{sig}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret-0123456789";

    fn claims(sub: &str, scope: &str, exp: u64) -> Claims {
        Claims {
            iss: "tuck".into(),
            sub: sub.into(),
            scope: scope.into(),
            iat: 1_700_000_000,
            exp,
        }
    }

    #[test]
    fn valid_token_round_trips() {
        let tok = issue(SECRET, &claims("s1", "partner", 1_800_000_000));
        let got = verify(&tok, SECRET, 1_700_000_100).unwrap();
        assert_eq!(got.sub, "s1");
        assert_eq!(got.scope, "partner");
    }

    #[test]
    fn expired_token_rejected() {
        let tok = issue(SECRET, &claims("s1", "partner", 1_700_000_050));
        assert!(matches!(verify(&tok, SECRET, 1_700_000_100), Err(TokenError::Expired)));
    }

    #[test]
    fn wrong_secret_rejected() {
        let tok = issue(SECRET, &claims("s1", "partner", 1_800_000_000));
        assert!(matches!(verify(&tok, b"other-secret", 1_700_000_100), Err(TokenError::BadSignature)));
    }

    #[test]
    fn tampered_payload_rejected() {
        let tok = issue(SECRET, &claims("s1", "partner", 1_800_000_000));
        let mut parts: Vec<&str> = tok.split('.').collect();
        // Flip a char in the payload segment.
        let p = parts[1].to_string();
        let flipped = if p.starts_with('e') { format!("f{}", &p[1..]) } else { format!("e{}", &p[1..]) };
        parts[1] = &flipped;
        let tampered = parts.join(".");
        assert!(matches!(verify(&tampered, SECRET, 1_700_000_100), Err(TokenError::BadSignature)));
    }

    #[test]
    fn missing_exp_is_always_expired() {
        // A zero exp can never be in the future — expired by construction.
        let tok = issue(SECRET, &claims("s1", "partner", 0));
        assert!(matches!(verify(&tok, SECRET, 1_700_000_100), Err(TokenError::Expired)));
    }

    #[test]
    fn algorithm_confusion_rejected() {
        // Craft header with alg=none, valid claims, empty signature.
        let header = b64u_encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = b64u_encode(
            &serde_json::to_vec(&claims("s1", "partner", 1_800_000_000)).unwrap(),
        );
        let tok = format!("{header}.{payload}.");
        assert!(matches!(verify(&tok, SECRET, 1_700_000_100), Err(TokenError::UnsupportedAlg)));
    }

    #[test]
    fn deterministic_issue_same_claims_same_token() {
        let a = issue(SECRET, &claims("s", "p", 1_800_000_000));
        let b = issue(SECRET, &claims("s", "p", 1_800_000_000));
        assert_eq!(a, b, "no random nonce — same input, same token");
    }
}
