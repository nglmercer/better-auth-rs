use better_auth_core::error::{AuthError, Result};
use saml_rs::{
    AcsEndpoint, AuthnRequestSigningPolicy, BrowserInput, CertificatePem, EntityId, FormField,
    IdpDescriptor, MetadataTrustPolicy, PendingAuthnRequest, RelayStateParam, ReplayCache,
    ReplayKey, ReplayPolicy, Saml, SamlError, SamlValidationContext, Sp, SpConfig,
    SpValidationPolicy, SsoResponse, StartSso,
};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use url::Url;

/// A concrete SAML 2.0 service-provider integration backed by saml-rs.
///
/// The dependency performs XML parsing, entity/audience/recipient checks,
/// signed-message verification, and response/assertion time validation. The
/// pending request snapshot can be persisted by the host between browser
/// requests.
pub struct SamlRsServiceProvider {
    inner: Saml<Sp>,
    replay_cache: Mutex<SamlReplayCache>,
}

pub struct SamlRsStarted {
    pub redirect_url: Url,
    pub pending: PendingAuthnRequest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamlRsIdentity {
    pub issuer: String,
    pub subject: String,
    pub attributes: HashMap<String, Vec<String>>,
}

#[derive(Default)]
struct SamlReplayCache {
    seen: HashMap<String, SystemTime>,
}

impl ReplayCache for SamlReplayCache {
    fn check_and_store(
        &mut self,
        key: ReplayKey,
        expires_at: SystemTime,
    ) -> std::result::Result<(), SamlError> {
        let now = SystemTime::now();
        self.seen.retain(|_, expiry| *expiry > now);
        let cache_key = key.cache_key();
        if self.seen.contains_key(&cache_key) {
            return Err(SamlError::ReplayDetected { key: cache_key });
        }
        self.seen.insert(cache_key, expires_at);
        Ok(())
    }
}

impl SamlRsServiceProvider {
    pub fn new(entity_id: &str, assertion_consumer_service_url: &str) -> Result<Self> {
        let entity_id = EntityId::try_new(entity_id).map_err(saml_error)?;
        let acs = AcsEndpoint::post(assertion_consumer_service_url).map_err(saml_error)?;
        let mut validation = SpValidationPolicy::strict();
        validation.authn_requests = AuthnRequestSigningPolicy::DoNotSignForCompatibility;
        let config = SpConfig::builder(entity_id)
            .acs_endpoint(acs)
            .validation(validation)
            .build()
            .map_err(saml_error)?;
        Ok(Self {
            inner: Saml::sp(config).map_err(saml_error)?,
            replay_cache: Mutex::new(SamlReplayCache::default()),
        })
    }

    pub fn metadata_xml(&self) -> &str {
        self.inner.metadata_xml()
    }

    pub fn parse_idp_metadata(
        &self,
        issuer: &str,
        metadata_xml: &str,
        trusted_certificates: &[String],
    ) -> Result<IdpDescriptor> {
        let issuer = EntityId::try_new(issuer).map_err(saml_error)?;
        if trusted_certificates.is_empty() {
            IdpDescriptor::from_metadata_xml_for(
                issuer,
                metadata_xml,
                MetadataTrustPolicy::UnsignedForCompatibility,
            )
            .map_err(saml_error)
        } else {
            let certificates = trusted_certificates
                .iter()
                .cloned()
                .map(CertificatePem::new)
                .collect::<Vec<_>>();
            IdpDescriptor::from_metadata_xml_for(
                issuer,
                metadata_xml,
                MetadataTrustPolicy::RequireSignature {
                    trusted_certificates: &certificates,
                },
            )
            .map_err(saml_error)
        }
    }

    pub fn start_sso(
        &self,
        idp: &IdpDescriptor,
        relay_state: Option<String>,
    ) -> Result<SamlRsStarted> {
        let relay_state = RelayStateParam::try_from_option(relay_state).map_err(saml_error)?;
        let started = self
            .inner
            .start_sso(idp, StartSso::redirect().relay_state(relay_state))
            .map_err(saml_error)?;
        let redirect_url = Url::parse(started.outbound.redirect_url().map_err(saml_error)?)
            .map_err(|error| {
                AuthError::InvalidRequest(format!("invalid SAML redirect: {error}"))
            })?;
        Ok(SamlRsStarted {
            redirect_url,
            pending: started.pending,
        })
    }

    pub fn finish_sso(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingAuthnRequest,
        form_fields: Vec<FormField>,
    ) -> Result<SamlRsIdentity> {
        let mut replay_cache = self
            .replay_cache
            .lock()
            .map_err(|_| AuthError::Adapter("SAML replay-cache lock poisoned".into()))?;
        let validation = SamlValidationContext::new(
            SystemTime::now(),
            ReplayPolicy::RequireCache(&mut *replay_cache),
        );
        let session = self
            .inner
            .finish_sso(
                idp,
                pending,
                BrowserInput::<SsoResponse>::post(form_fields),
                validation,
            )
            .map_err(saml_error)?;
        let attributes = session
            .attributes()
            .as_slice()
            .iter()
            .map(|attribute| {
                (
                    attribute.name().to_owned(),
                    attribute
                        .values()
                        .iter()
                        .map(|value| value.as_str().to_owned())
                        .collect(),
                )
            })
            .collect();
        Ok(SamlRsIdentity {
            issuer: session.issuer().as_str().to_owned(),
            subject: session.name_id().value().to_owned(),
            attributes,
        })
    }

    pub fn now_seconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default()
    }
}

fn saml_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::InvalidRequest(format!("SAML validation failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDP_METADATA: &str = r#"
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
            entityID="https://idp.example/metadata">
          <md:IDPSSODescriptor
              protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:SingleSignOnService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                Location="https://idp.example/sso"/>
          </md:IDPSSODescriptor>
        </md:EntityDescriptor>
    "#;

    #[test]
    fn concrete_saml_provider_parses_metadata_and_exposes_sp_metadata() {
        let provider =
            SamlRsServiceProvider::new("https://sp.example/metadata", "https://sp.example/acs")
                .unwrap();
        assert!(provider.metadata_xml().contains("EntityDescriptor"));
        let idp = provider
            .parse_idp_metadata("https://idp.example/metadata", IDP_METADATA, &[])
            .unwrap();
        assert_eq!(idp.entity_id().as_str(), "https://idp.example/metadata");
    }

    #[test]
    fn concrete_saml_provider_rejects_metadata_entity_mismatch() {
        let provider =
            SamlRsServiceProvider::new("https://sp.example/metadata", "https://sp.example/acs")
                .unwrap();
        assert!(provider
            .parse_idp_metadata("https://wrong.example/metadata", IDP_METADATA, &[])
            .is_err());
    }
}
