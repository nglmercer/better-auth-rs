use better_auth_core::error::{AuthError, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

/// Upper bound on the number of keys accepted from one JWKS document. Providers
/// publish a handful of keys; a larger document is treated as hostile.
pub const MAX_JWKS_KEYS: usize = 32;

#[derive(Clone)]
pub struct OidcIdTokenValidator {
    issuer: String,
    /// Additional issuer spellings the provider is documented to use.
    alternate_issuers: Vec<String>,
    audience: String,
    keys: HashMap<String, (DecodingKey, Algorithm)>,
}

impl OidcIdTokenValidator {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            alternate_issuers: Vec::new(),
            audience: audience.into(),
            keys: HashMap::new(),
        }
    }

    /// Accepts a second `iss` spelling for the same issuer, such as Google's
    /// documented `accounts.google.com` form alongside `https://accounts.google.com`.
    pub fn with_alternate_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.alternate_issuers.push(issuer.into());
        self
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Whether a signing key with this `kid` is loaded.
    pub fn has_key(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Returns a copy of this validator (same issuer, audience and issuers)
    /// that trusts exactly the RSA keys in `jwks`. Keys that are not RSA are
    /// skipped; the document is refused when it is malformed, has no usable
    /// key, or exceeds [`MAX_JWKS_KEYS`].
    pub fn with_jwks(&self, jwks: &Value) -> Result<Self> {
        let keys = jwks
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| AuthError::InvalidRequest("OIDC JWKS has no keys array".into()))?;
        if keys.len() > MAX_JWKS_KEYS {
            return Err(AuthError::InvalidRequest(format!(
                "OIDC JWKS lists more than {MAX_JWKS_KEYS} keys"
            )));
        }
        let mut replacement = HashMap::new();
        for jwk in keys {
            if jwk.get("kty").and_then(Value::as_str) != Some("RSA") {
                continue;
            }
            let key_id = jwk
                .get("kid")
                .and_then(Value::as_str)
                .ok_or_else(|| AuthError::InvalidRequest("OIDC JWK has no kid".into()))?;
            let modulus = jwk
                .get("n")
                .and_then(Value::as_str)
                .ok_or_else(|| AuthError::InvalidRequest("OIDC RSA JWK has no n".into()))?;
            let exponent = jwk
                .get("e")
                .and_then(Value::as_str)
                .ok_or_else(|| AuthError::InvalidRequest("OIDC RSA JWK has no e".into()))?;
            let key = DecodingKey::from_rsa_components(modulus, exponent)
                .map_err(|error| AuthError::Crypto(format!("invalid OIDC RSA JWK: {error}")))?;
            replacement.insert(key_id.to_owned(), (key, Algorithm::RS256));
        }
        if replacement.is_empty() {
            return Err(AuthError::InvalidRequest(
                "OIDC JWKS has no supported RSA signing keys".into(),
            ));
        }
        Ok(Self {
            issuer: self.issuer.clone(),
            alternate_issuers: self.alternate_issuers.clone(),
            audience: self.audience.clone(),
            keys: replacement,
        })
    }

    pub fn add_rsa_key(mut self, key_id: impl Into<String>, pem: &[u8]) -> Result<Self> {
        let key = DecodingKey::from_rsa_pem(pem)
            .map_err(|error| AuthError::Crypto(format!("invalid OIDC RSA key: {error}")))?;
        self.keys.insert(key_id.into(), (key, Algorithm::RS256));
        Ok(self)
    }

    pub fn add_ec_key(mut self, key_id: impl Into<String>, pem: &[u8]) -> Result<Self> {
        let key = DecodingKey::from_ec_pem(pem)
            .map_err(|error| AuthError::Crypto(format!("invalid OIDC EC key: {error}")))?;
        self.keys.insert(key_id.into(), (key, Algorithm::ES256));
        Ok(self)
    }

    pub fn replace_from_jwks(&mut self, jwks: &Value) -> Result<usize> {
        let replacement = self.with_jwks(jwks)?;
        let count = replacement.keys.len();
        self.keys = replacement.keys;
        Ok(count)
    }

    /// Adds an HS256 key. Test builds and the `test-utils` feature only, because a
    /// shared secret must never be used as an ID-token signing key in production.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn add_test_hs_key(mut self, key_id: impl Into<String>, secret: &[u8]) -> Self {
        self.keys.insert(
            key_id.into(),
            (DecodingKey::from_secret(secret), Algorithm::HS256),
        );
        self
    }

    pub fn validate(&self, token: &str, expected_nonce: Option<&str>) -> Result<OidcClaims> {
        let header = decode_header(token).map_err(|_| AuthError::Unauthorized)?;
        let key_id = header.kid.ok_or(AuthError::Unauthorized)?;
        let (key, algorithm) = self.keys.get(&key_id).ok_or(AuthError::Unauthorized)?;
        if header.alg != *algorithm {
            return Err(AuthError::Unauthorized);
        }
        let mut validation = Validation::new(*algorithm);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.validate_aud = false;
        // No clock-skew allowance: a token is valid exactly until its `exp`.
        validation.leeway = 0;
        let token = decode::<OidcClaims>(token, key, &validation)
            .map_err(|_| AuthError::Unauthorized)?
            .claims;
        let issuer_ok = token.iss == self.issuer || self.alternate_issuers.contains(&token.iss);
        if !issuer_ok || !audience_contains(&token.aud, &self.audience) {
            return Err(AuthError::Unauthorized);
        }
        // OIDC Core: with several audiences the authorized party must be this
        // client. Requiring it here fails closed when `azp` is missing.
        if is_multi_audience(&token.aud) && token.azp.as_deref() != Some(self.audience.as_str()) {
            return Err(AuthError::Unauthorized);
        }
        if token.azp.as_deref().is_some_and(|azp| azp != self.audience) {
            return Err(AuthError::Unauthorized);
        }
        if let Some(expected_nonce) = expected_nonce {
            if token.nonce.as_deref() != Some(expected_nonce) {
                return Err(AuthError::Unauthorized);
            }
        }
        Ok(token)
    }
}

/// The `kid` from an unverified token header. It only selects which key to
/// try; the signature is still verified against that key before any claim is
/// trusted.
pub fn token_key_id(token: &str) -> Option<String> {
    decode_header(token).ok().and_then(|header| header.kid)
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct OidcClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Value,
    pub exp: usize,
    pub iat: usize,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub azp: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
}

fn is_multi_audience(audience: &Value) -> bool {
    matches!(audience, Value::Array(values) if values.len() > 1)
}

fn audience_contains(audience: &Value, expected: &str) -> bool {
    match audience {
        Value::String(value) => value == expected,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    #[test]
    fn id_token_validation_checks_signature_issuer_audience_and_nonce() {
        let secret = b"oidc-test-secret";
        let validator = OidcIdTokenValidator::new("https://issuer.example", "client-1")
            .add_test_hs_key("test", secret);
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test".into());
        let claims = json!({
            "iss": "https://issuer.example",
            "sub": "subject-1",
            "aud": ["client-1", "other-client"],
            "azp": "client-1",
            "exp": (now_seconds() + 60) as usize,
            "iat": now_seconds() as usize,
            "nonce": "nonce-1"
        });
        let token = encode(&header, &claims, &EncodingKey::from_secret(secret)).unwrap();
        assert_eq!(
            validator.validate(&token, Some("nonce-1")).unwrap().sub,
            "subject-1"
        );
        assert!(validator.validate(&token, Some("wrong")).is_err());
    }

    #[test]
    fn multi_audience_tokens_require_matching_authorized_party() {
        let secret = b"oidc-test-secret";
        let validator = OidcIdTokenValidator::new("https://issuer.example", "client-1")
            .add_test_hs_key("test", secret);
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test".into());
        let base = |azp: Option<&str>| {
            let mut claims = json!({
                "iss": "https://issuer.example",
                "sub": "subject-1",
                "aud": ["client-1", "other-client"],
                "exp": (now_seconds() + 60) as usize,
                "iat": now_seconds() as usize,
                "nonce": "nonce-1"
            });
            if let Some(azp) = azp {
                claims["azp"] = json!(azp);
            }
            encode(&header, &claims, &EncodingKey::from_secret(secret)).unwrap()
        };
        assert!(validator.validate(&base(None), Some("nonce-1")).is_err());
        assert!(validator
            .validate(&base(Some("other-client")), Some("nonce-1"))
            .is_err());
        assert!(validator
            .validate(&base(Some("client-1")), Some("nonce-1"))
            .is_ok());
    }

    #[test]
    fn jwks_rotation_rejects_unsupported_or_incomplete_keys() {
        let mut validator = OidcIdTokenValidator::new("https://issuer.example", "client-1");
        let result = validator.replace_from_jwks(&json!({
            "keys": [{
                "kty": "EC",
                "kid": "unsupported"
            }]
        }));
        assert!(result.is_err());
        assert!(validator
            .replace_from_jwks(&json!({"keys": [{"kty":"RSA","kid":"missing"}]}))
            .is_err());
    }

    #[test]
    fn documented_alternate_issuer_is_accepted_and_others_are_not() {
        let secret = b"oidc-test-secret";
        let validator = OidcIdTokenValidator::new("https://accounts.google.com", "client-1")
            .with_alternate_issuer("accounts.google.com")
            .add_test_hs_key("test", secret);
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test".into());
        let token = |issuer: &str| {
            let claims = json!({
                "iss": issuer,
                "sub": "subject-1",
                "aud": "client-1",
                "exp": (now_seconds() + 60) as usize,
                "iat": now_seconds() as usize,
            });
            encode(&header, &claims, &EncodingKey::from_secret(secret)).unwrap()
        };
        assert!(validator
            .validate(&token("accounts.google.com"), None)
            .is_ok());
        assert!(validator
            .validate(&token("https://accounts.google.com"), None)
            .is_ok());
        assert!(validator
            .validate(&token("accounts.google.com.evil.example"), None)
            .is_err());
    }

    fn now_seconds() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}
