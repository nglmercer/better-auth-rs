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

/// A public key as it is published in the key set.
#[derive(Clone)]
struct PublishedKey {
    kid: String,
    modulus: String,
    exponent: String,
}

impl PublishedKey {
    fn jwk(&self) -> Value {
        json!({
            "kty": "RSA",
            "kid": self.kid,
            "alg": "RS256",
            "use": "sig",
            "n": self.modulus,
            "e": self.exponent,
        })
    }
}

#[derive(Clone)]
pub struct JwtSigner {
    /// The key that signs new tokens.
    current: PublishedKey,
    /// Keys that were current before a rotation. They stay published, so tokens they signed
    /// keep verifying until they are retired.
    previous: Vec<PublishedKey>,
    issuer: String,
    audience: String,
    encoding: EncodingKey,
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
            current: PublishedKey {
                kid: kid.into(),
                modulus: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
                exponent: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
            },
            previous: Vec::new(),
            issuer: issuer.into(),
            audience: audience.into(),
            encoding,
        })
    }

    /// Starts signing with a new key. The key it replaces stays published, so tokens it signed
    /// keep verifying until `retire` removes it. The new `kid` must be unused.
    pub fn rotate(&self, kid: impl Into<String>, private_pem: &str) -> Result<Self> {
        let next =
            Self::from_rsa_pem(kid, self.issuer.clone(), self.audience.clone(), private_pem)?;
        let kid = next.current.kid.clone();
        if kid == self.current.kid || self.previous.iter().any(|key| key.kid == kid) {
            return Err(AuthError::InvalidConfiguration(
                "the new signing key needs a kid that is not already published".into(),
            ));
        }
        let mut previous = vec![self.current.clone()];
        previous.extend(self.previous.iter().cloned());
        Ok(Self { previous, ..next })
    }

    /// Stops publishing a previous key, so tokens it signed stop verifying. The current key
    /// cannot be retired: rotate first.
    pub fn retire(&self, kid: &str) -> Result<Self> {
        if kid == self.current.kid {
            return Err(AuthError::InvalidConfiguration(
                "the signing key cannot be retired; rotate to a new key first".into(),
            ));
        }
        let previous: Vec<PublishedKey> = self
            .previous
            .iter()
            .filter(|key| key.kid != kid)
            .cloned()
            .collect();
        if previous.len() == self.previous.len() {
            return Err(AuthError::NotFound);
        }
        Ok(Self {
            previous,
            ..self.clone()
        })
    }

    /// The public key set to publish at `/jwks`: the current key and any key still in its
    /// overlap period.
    pub fn jwks(&self) -> Value {
        let keys: Vec<Value> = std::iter::once(&self.current)
            .chain(self.previous.iter())
            .map(PublishedKey::jwk)
            .collect();
        json!({ "keys": keys })
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
        header.kid = Some(self.current.kid.clone());
        encode(&header, &payload, &self.encoding)
            .map_err(|error| AuthError::Crypto(format!("JWT signing failed: {error}")))
    }

    /// Verifies a token against the published key its `kid` names, plus the issuer, the audience
    /// and the expiry. A token without a known `kid` is refused.
    pub fn verify(&self, token: &str) -> Result<Value> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| AuthError::Unauthorized)?;
        let kid = header.kid.ok_or(AuthError::Unauthorized)?;
        let published = std::iter::once(&self.current)
            .chain(self.previous.iter())
            .find(|key| key.kid == kid)
            .ok_or(AuthError::Unauthorized)?;
        let key = DecodingKey::from_rsa_components(&published.modulus, &published.exponent)
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

    /// The kid that signs new tokens.
    pub fn current_kid(&self) -> &str {
        &self.current.kid
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

    /// A second, independent test key, so rotation is exercised with two distinct keys.
    const ROTATION_KEY: &str = include_str!("../tests/fixtures/jwt_test_rsa_rotation_private.pem");

    #[test]
    fn rotation_keeps_old_tokens_valid_until_the_old_key_is_retired() {
        let before = signer();
        let old_token = before.issue("user-1", Map::new(), 300).unwrap();
        let after = before.rotate("rotated-key", ROTATION_KEY).unwrap();

        // New tokens are signed by the new key. Old tokens still verify during the overlap.
        let new_token = after.issue("user-2", Map::new(), 300).unwrap();
        assert_eq!(
            jsonwebtoken::decode_header(&new_token)
                .unwrap()
                .kid
                .as_deref(),
            Some("rotated-key")
        );
        assert_eq!(after.verify(&new_token).unwrap()["sub"], "user-2");
        assert_eq!(after.verify(&old_token).unwrap()["sub"], "user-1");

        // Both keys are published while they overlap.
        let published = after.jwks();
        let kids: Vec<&str> = published["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key["kid"].as_str().unwrap())
            .collect();
        assert_eq!(kids, vec!["rotated-key", "test-key"]);

        // Retiring the old key ends the old tokens and leaves the new ones alone.
        let retired = after.retire("test-key").unwrap();
        assert!(
            retired.verify(&old_token).is_err(),
            "retired key's tokens are refused"
        );
        assert_eq!(retired.verify(&new_token).unwrap()["sub"], "user-2");
        assert_eq!(retired.jwks()["keys"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn the_current_key_cannot_be_retired_and_kids_are_not_reused() {
        let before = signer();
        let after = before.rotate("rotated-key", ROTATION_KEY).unwrap();
        assert!(
            after.retire("rotated-key").is_err(),
            "the signing key stays published"
        );
        assert!(after.retire("no-such-key").is_err());
        assert!(
            before.rotate("test-key", ROTATION_KEY).is_err(),
            "a kid that is in use is refused"
        );
    }

    #[test]
    fn tokens_without_a_known_kid_are_refused() {
        let signer = signer();
        let token = signer.issue("user-1", Map::new(), 300).unwrap();
        // The same token, with its header's kid changed to one nobody publishes.
        let parts: Vec<&str> = token.split('.').collect();
        let forged_header =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT","kid":"unknown"}"#);
        let forged = format!("{forged_header}.{}.{}", parts[1], parts[2]);
        assert!(signer.verify(&forged).is_err());
    }

    #[test]
    fn short_keys_and_garbage_are_rejected() {
        assert!(JwtSigner::from_rsa_pem("k", "i", "a", "not a key").is_err());
    }
}
