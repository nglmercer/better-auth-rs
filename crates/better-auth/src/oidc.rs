use better_auth_core::error::{AuthError, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone)]
pub struct OidcIdTokenValidator {
    issuer: String,
    audience: String,
    keys: HashMap<String, (DecodingKey, Algorithm)>,
}

impl OidcIdTokenValidator {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            keys: HashMap::new(),
        }
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
        let keys = jwks
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| AuthError::InvalidRequest("OIDC JWKS has no keys array".into()))?;
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
        let count = replacement.len();
        self.keys = replacement;
        Ok(count)
    }

    #[cfg(test)]
    fn add_test_hs_key(mut self, key_id: impl Into<String>, secret: &[u8]) -> Self {
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
        let token = decode::<OidcClaims>(token, key, &validation)
            .map_err(|_| AuthError::Unauthorized)?
            .claims;
        if token.iss != self.issuer || !audience_contains(&token.aud, &self.audience) {
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

    fn now_seconds() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}
