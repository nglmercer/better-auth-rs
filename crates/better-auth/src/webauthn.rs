use better_auth_core::error::{AuthError, Result};
use serde::Serialize;
use serde_json::Value;
use std::{collections::HashMap, sync::Mutex};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// A WebAuthn-backed passkey service. Challenge state is retained server-side
/// and the vetted webauthn-rs implementation performs attestation, origin,
/// RP-ID, signature, user-verification, and counter checks.
pub struct WebAuthnService {
    webauthn: Webauthn,
    registrations: Mutex<HashMap<String, PasskeyRegistration>>,
    authentications: Mutex<HashMap<String, PasskeyAuthentication>>,
}

impl WebAuthnService {
    pub fn new(rp_id: &str, rp_origin: Url, rp_name: &str) -> Result<Self> {
        let builder = WebauthnBuilder::new(rp_id, &rp_origin)
            .map_err(webauthn_error)?
            .rp_name(rp_name);
        let webauthn = builder.build().map_err(webauthn_error)?;
        Ok(Self {
            webauthn,
            registrations: Mutex::new(HashMap::new()),
            authentications: Mutex::new(HashMap::new()),
        })
    }

    pub fn start_registration(
        &self,
        user_id: Uuid,
        user_name: &str,
        display_name: &str,
        exclude_credentials: Vec<Passkey>,
    ) -> Result<(String, Value)> {
        let excluded = exclude_credentials
            .iter()
            .map(|credential| credential.cred_id().clone())
            .collect();
        let (challenge, state) = self
            .webauthn
            .start_passkey_registration(user_id, user_name, display_name, Some(excluded))
            .map_err(webauthn_error)?;
        let transaction_id = Uuid::new_v4().simple().to_string();
        self.registrations
            .lock()
            .map_err(|_| lock_error())?
            .insert(transaction_id.clone(), state);
        Ok((
            transaction_id,
            serde_json::to_value(challenge).map_err(json_error)?,
        ))
    }

    pub fn finish_registration(&self, transaction_id: &str, response: Value) -> Result<Passkey> {
        let state = self
            .registrations
            .lock()
            .map_err(|_| lock_error())?
            .remove(transaction_id)
            .ok_or(AuthError::Unauthorized)?;
        let response: RegisterPublicKeyCredential =
            serde_json::from_value(response).map_err(json_error)?;
        self.webauthn
            .finish_passkey_registration(&response, &state)
            .map_err(webauthn_error)
    }

    pub fn start_authentication(&self, credentials: &[Passkey]) -> Result<(String, Value)> {
        if credentials.is_empty() {
            return Err(AuthError::InvalidRequest(
                "no passkey credentials are registered".into(),
            ));
        }
        let (challenge, state) = self
            .webauthn
            .start_passkey_authentication(credentials)
            .map_err(webauthn_error)?;
        let transaction_id = Uuid::new_v4().simple().to_string();
        self.authentications
            .lock()
            .map_err(|_| lock_error())?
            .insert(transaction_id.clone(), state);
        Ok((
            transaction_id,
            serde_json::to_value(challenge).map_err(json_error)?,
        ))
    }

    pub fn finish_authentication(
        &self,
        transaction_id: &str,
        response: Value,
        credential: &mut Passkey,
    ) -> Result<WebAuthnAuthenticationResult> {
        let state = self
            .authentications
            .lock()
            .map_err(|_| lock_error())?
            .remove(transaction_id)
            .ok_or(AuthError::Unauthorized)?;
        let response: PublicKeyCredential = serde_json::from_value(response).map_err(json_error)?;
        let result = self
            .webauthn
            .finish_passkey_authentication(&response, &state)
            .map_err(webauthn_error)?;
        let updated = credential
            .update_credential(&result)
            .ok_or_else(|| AuthError::Unauthorized)?;
        Ok(WebAuthnAuthenticationResult {
            credential_id: format!("{:?}", result.cred_id()),
            counter: result.counter(),
            credential_updated: updated,
        })
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct WebAuthnAuthenticationResult {
    pub credential_id: String,
    pub counter: u32,
    pub credential_updated: bool,
}

fn webauthn_error(error: impl std::fmt::Debug) -> AuthError {
    AuthError::Crypto(format!("WebAuthn verification failed: {error:?}"))
}

fn json_error(error: serde_json::Error) -> AuthError {
    AuthError::InvalidRequest(format!("invalid WebAuthn JSON: {error}"))
}

fn lock_error() -> AuthError {
    AuthError::Adapter("WebAuthn state lock poisoned".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webauthn_service_builds_origin_bound_registration_challenges() {
        let service = WebAuthnService::new(
            "example.com",
            Url::parse("https://example.com").unwrap(),
            "Example",
        )
        .unwrap();
        let (_, challenge) = service
            .start_registration(Uuid::new_v4(), "user@example.com", "User", Vec::new())
            .unwrap();
        assert!(challenge.get("publicKey").is_some());
    }
}
