//! Asymmetric JWTs (RS256) with a published key set (JWKS).
//!
//! The private key stays in this process. Only the public key is published, as a
//! JSON Web Key with a `kid`, so relying parties can verify tokens without any
//! shared secret. The public key is derived from the private key, so the two
//! cannot drift apart.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use better_auth_core::error::{AuthError, Result};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rsa::{pkcs8::DecodePrivateKey, traits::PublicKeyParts, RsaPrivateKey};
use serde_json::{json, Map, Value};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct JwtSigner {
    kid: String,
    issuer: String,
    audience: String,
    encoding: EncodingKey,
    modulus: String,
    exponent: String,
}

impl JwtSigner {
    /// Builds a signer from a PKCS#8 PEM RSA private key (at least 2048 bits).
    pub fn from_rsa_pem(
        kid: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        private_pem: &str,
    ) -> Result<Self> {
        let key = RsaPrivateKey::from_pkcs8_pem(private_pem)
            .map_err(|error| AuthError::Crypto(format!("invalid RSA private key: {error}")))?;
        if key.size() < 256 {
            return Err(AuthError::InvalidConfiguration(
                "JWT signing keys must be at least 2048 bits".into(),
            ));
        }
        let public = key.to_public_key();
        let encoding = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .map_err(|error| AuthError::Crypto(format!("invalid RSA private key: {error}")))?;
        Ok(Self {
            kid: kid.into(),
            issuer: issuer.into(),
            audience: audience.into(),
            encoding,
            modulus: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            exponent: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
        })
    }

    /// The public key set to publish at `/jwks`.
    pub fn jwks(&self) -> Value {
        json!({"keys": [{
            "kty": "RSA",
            "kid": self.kid,
            "alg": "RS256",
            "use": "sig",
            "n": self.modulus,
            "e": self.exponent,
        }]})
    }

    /// Issues a token for `subject` that lasts `ttl_seconds`, with `claims` added.
    pub fn issue(
        &self,
        subject: &str,
        claims: Map<String, Value>,
        ttl_seconds: u64,
    ) -> Result<String> {
        let now = now_seconds();
        let mut payload = claims;
        payload.insert("sub".into(), json!(subject));
        payload.insert("iss".into(), json!(self.issuer));
        payload.insert("aud".into(), json!(self.audience));
        payload.insert("iat".into(), json!(now));
        payload.insert("exp".into(), json!(now + ttl_seconds));
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        encode(&header, &payload, &self.encoding)
            .map_err(|error| AuthError::Crypto(format!("JWT signing failed: {error}")))
    }

    /// Verifies a token with the published key, the issuer, the audience and the expiry.
    pub fn verify(&self, token: &str) -> Result<Value> {
        let key = DecodingKey::from_rsa_components(&self.modulus, &self.exponent)
            .map_err(|error| AuthError::Crypto(format!("invalid public key: {error}")))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.validate_exp = true;
        // The library default is 60 seconds of leeway. Tokens are refused the
        // moment they expire here, and clock skew is the relying party's concern.
        validation.leeway = 0;
        decode::<Value>(token, &key, &validation)
            .map(|data| data.claims)
            .map_err(|_| AuthError::Unauthorized)
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = include_str!("../tests/fixtures/jwt_test_rsa_private.pem");

    fn signer() -> JwtSigner {
        JwtSigner::from_rsa_pem("test-key", "https://auth.example", "api.example", TEST_KEY)
            .unwrap()
    }

    #[test]
    fn tokens_verify_with_the_published_key_and_reject_wrong_audience_and_expiry() {
        let signer = signer();
        let token = signer.issue("user-1", Map::new(), 300).unwrap();
        let claims = signer.verify(&token).unwrap();
        assert_eq!(claims["sub"], "user-1");

        // A relying party that trusts the published JWK, and nothing else, gets the same answer.
        let jwk = &signer.jwks()["keys"][0];
        let key = DecodingKey::from_rsa_components(
            jwk["n"].as_str().unwrap(),
            jwk["e"].as_str().unwrap(),
        )
        .unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["api.example"]);
        validation.set_issuer(&["https://auth.example"]);
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.kid.as_deref(), Some("test-key"));
        assert!(decode::<Value>(&token, &key, &validation).is_ok());

        let other = JwtSigner::from_rsa_pem(
            "test-key",
            "https://auth.example",
            "other.example",
            TEST_KEY,
        )
        .unwrap();
        assert!(other.verify(&token).is_err(), "wrong audience is refused");
        let expired = signer.issue("user-1", Map::new(), 0).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(
            signer.verify(&expired).is_err(),
            "expired tokens are refused"
        );
    }

    #[test]
    fn short_keys_and_garbage_are_rejected() {
        assert!(JwtSigner::from_rsa_pem("k", "i", "a", "not a key").is_err());
    }
}
