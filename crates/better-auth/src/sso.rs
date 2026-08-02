use better_auth_core::error::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Duration};
use url::Url;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SsoProtocol {
    #[default]
    Oidc,
    Saml,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamlValidationConfig {
    pub expected_issuer: String,
    pub expected_audience: String,
    pub assertion_consumer_service_url: Url,
    pub clock_skew: Duration,
}

impl SamlValidationConfig {
    pub fn new(
        expected_issuer: impl Into<String>,
        expected_audience: impl Into<String>,
        assertion_consumer_service_url: Url,
    ) -> Result<Self> {
        if assertion_consumer_service_url.scheme() != "https" {
            return Err(AuthError::InvalidConfiguration(
                "SAML ACS URL must use HTTPS".into(),
            ));
        }
        Ok(Self {
            expected_issuer: expected_issuer.into(),
            expected_audience: expected_audience.into(),
            assertion_consumer_service_url,
            clock_skew: Duration::from_secs(60),
        })
    }

    pub fn with_clock_skew(mut self, clock_skew: Duration) -> Self {
        self.clock_skew = clock_skew;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamlAssertion {
    pub issuer: String,
    pub subject: String,
    pub audiences: Vec<String>,
    pub not_before: Option<u64>,
    pub not_on_or_after: Option<u64>,
    pub recipient: Option<String>,
    pub in_response_to: Option<String>,
    pub session_index: Option<String>,
    pub attributes: BTreeMap<String, Vec<String>>,
    /// Canonicalized, signed assertion bytes produced by the SAML XML layer.
    pub signed_payload: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamlResponse {
    pub status_success: bool,
    pub assertion: SamlAssertion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamlIdentity {
    pub subject: String,
    pub session_index: Option<String>,
    pub attributes: BTreeMap<String, Vec<String>>,
}

pub trait SamlSignatureVerifier: Send + Sync {
    fn verify(&self, payload: &[u8], signature: &[u8], issuer: &str) -> Result<()>;
}

pub struct SamlAssertionValidator<V> {
    config: SamlValidationConfig,
    signature_verifier: V,
}

impl<V: SamlSignatureVerifier> SamlAssertionValidator<V> {
    pub fn new(config: SamlValidationConfig, signature_verifier: V) -> Self {
        Self {
            config,
            signature_verifier,
        }
    }

    pub fn validate(
        &self,
        response: SamlResponse,
        request_id: Option<&str>,
        now_seconds: u64,
    ) -> Result<SamlIdentity> {
        if !response.status_success {
            return Err(AuthError::Unauthorized);
        }
        let assertion = response.assertion;
        if assertion.issuer != self.config.expected_issuer
            || !assertion
                .audiences
                .iter()
                .any(|audience| audience == &self.config.expected_audience)
        {
            return Err(AuthError::Unauthorized);
        }
        if assertion.subject.trim().is_empty() {
            return Err(AuthError::Unauthorized);
        }
        if assertion.recipient.as_deref()
            != Some(self.config.assertion_consumer_service_url.as_str())
        {
            return Err(AuthError::Unauthorized);
        }
        if let Some(expected_request_id) = request_id {
            if assertion.in_response_to.as_deref() != Some(expected_request_id) {
                return Err(AuthError::Unauthorized);
            }
        }
        let skew = self.config.clock_skew.as_secs();
        if assertion
            .not_before
            .is_some_and(|not_before| now_seconds.saturating_add(skew) < not_before)
            || assertion
                .not_on_or_after
                .is_some_and(|expiry| now_seconds.saturating_sub(skew) >= expiry)
        {
            return Err(AuthError::Unauthorized);
        }
        if assertion.signed_payload.is_empty() || assertion.signature.is_empty() {
            return Err(AuthError::Unauthorized);
        }
        self.signature_verifier.verify(
            &assertion.signed_payload,
            &assertion.signature,
            &assertion.issuer,
        )?;
        Ok(SamlIdentity {
            subject: assertion.subject,
            session_index: assertion.session_index,
            attributes: assertion.attributes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamlAuthorizationRequest {
    pub request_id: String,
    pub redirect_url: Url,
    pub relay_state: Option<String>,
}

pub trait SamlProvider {
    fn authorization_request(
        &self,
        request_id: String,
        relay_state: Option<String>,
    ) -> Result<SamlAuthorizationRequest>;

    fn validate_response(
        &self,
        response: SamlResponse,
        request_id: Option<&str>,
        now_seconds: u64,
    ) -> Result<SamlIdentity>;
}

pub struct ValidatedSamlProvider<V> {
    redirect_url: Url,
    validator: SamlAssertionValidator<V>,
}

impl<V: SamlSignatureVerifier> ValidatedSamlProvider<V> {
    pub fn new(redirect_url: Url, validator: SamlAssertionValidator<V>) -> Result<Self> {
        if redirect_url.scheme() != "https" {
            return Err(AuthError::InvalidConfiguration(
                "SAML redirect URL must use HTTPS".into(),
            ));
        }
        Ok(Self {
            redirect_url,
            validator,
        })
    }
}

impl<V: SamlSignatureVerifier> SamlProvider for ValidatedSamlProvider<V> {
    fn authorization_request(
        &self,
        request_id: String,
        relay_state: Option<String>,
    ) -> Result<SamlAuthorizationRequest> {
        if request_id.trim().is_empty() {
            return Err(AuthError::InvalidRequest(
                "SAML request ID cannot be empty".into(),
            ));
        }
        Ok(SamlAuthorizationRequest {
            request_id,
            redirect_url: self.redirect_url.clone(),
            relay_state,
        })
    }

    fn validate_response(
        &self,
        response: SamlResponse,
        request_id: Option<&str>,
        now_seconds: u64,
    ) -> Result<SamlIdentity> {
        self.validator.validate(response, request_id, now_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVerifier;

    impl SamlSignatureVerifier for TestVerifier {
        fn verify(&self, payload: &[u8], signature: &[u8], issuer: &str) -> Result<()> {
            if payload == b"assertion" && signature == b"valid" && issuer == "https://idp.example" {
                Ok(())
            } else {
                Err(AuthError::Unauthorized)
            }
        }
    }

    fn assertion() -> SamlAssertion {
        SamlAssertion {
            issuer: "https://idp.example".into(),
            subject: "subject-1".into(),
            audiences: vec!["https://app.example/saml".into()],
            not_before: Some(90),
            not_on_or_after: Some(200),
            recipient: Some("https://app.example/auth/saml/callback".into()),
            in_response_to: Some("request-1".into()),
            session_index: Some("session-1".into()),
            attributes: BTreeMap::new(),
            signed_payload: b"assertion".to_vec(),
            signature: b"valid".to_vec(),
        }
    }

    #[test]
    fn validator_checks_signature_audience_recipient_time_and_request_binding() {
        let config = SamlValidationConfig::new(
            "https://idp.example",
            "https://app.example/saml",
            Url::parse("https://app.example/auth/saml/callback").unwrap(),
        )
        .unwrap()
        .with_clock_skew(Duration::from_secs(0));
        let validator = SamlAssertionValidator::new(config, TestVerifier);
        let identity = validator
            .validate(
                SamlResponse {
                    status_success: true,
                    assertion: assertion(),
                },
                Some("request-1"),
                100,
            )
            .unwrap();
        assert_eq!(identity.subject, "subject-1");
        assert!(validator
            .validate(
                SamlResponse {
                    status_success: true,
                    assertion: assertion(),
                },
                Some("wrong-request"),
                100,
            )
            .is_err());
    }
}
