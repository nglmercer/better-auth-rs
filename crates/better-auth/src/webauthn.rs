use better_auth_core::{
    adapter::{DbAdapter, Query, SecondaryStorage, StorageValue},
    error::{AuthError, Result},
};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
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
    state_storage: Option<Arc<dyn SecondaryStorage>>,
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
            state_storage: None,
        })
    }

    pub fn with_state_storage(mut self, storage: Arc<dyn SecondaryStorage>) -> Self {
        self.state_storage = Some(storage);
        self
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

    pub async fn start_registration_persisted(
        &self,
        user_id: Uuid,
        user_name: &str,
        display_name: &str,
        exclude_credentials: Vec<Passkey>,
    ) -> Result<(String, Value)> {
        let storage = self.state_storage()?;
        let excluded = exclude_credentials
            .iter()
            .map(|credential| credential.cred_id().clone())
            .collect();
        let (challenge, state) = self
            .webauthn
            .start_passkey_registration(user_id, user_name, display_name, Some(excluded))
            .map_err(webauthn_error)?;
        let transaction_id = Uuid::new_v4().simple().to_string();
        storage
            .set(
                &registration_key(&transaction_id),
                StorageValue::with_ttl(
                    serde_json::to_value(state).map_err(json_error)?,
                    Duration::from_secs(5 * 60),
                ),
            )
            .await?;
        Ok((
            transaction_id,
            serde_json::to_value(challenge).map_err(json_error)?,
        ))
    }

    pub async fn finish_registration_persisted(
        &self,
        transaction_id: &str,
        response: Value,
    ) -> Result<Passkey> {
        let storage = self.state_storage()?;
        let state = storage
            .get_and_delete(&registration_key(transaction_id))
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let state: PasskeyRegistration = serde_json::from_value(state.value).map_err(json_error)?;
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

    pub async fn start_authentication_persisted(
        &self,
        credentials: &[Passkey],
    ) -> Result<(String, Value)> {
        if credentials.is_empty() {
            return Err(AuthError::InvalidRequest(
                "no passkey credentials are registered".into(),
            ));
        }
        let storage = self.state_storage()?;
        let (challenge, state) = self
            .webauthn
            .start_passkey_authentication(credentials)
            .map_err(webauthn_error)?;
        let transaction_id = Uuid::new_v4().simple().to_string();
        storage
            .set(
                &authentication_key(&transaction_id),
                StorageValue::with_ttl(
                    serde_json::to_value(state).map_err(json_error)?,
                    Duration::from_secs(5 * 60),
                ),
            )
            .await?;
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
        self.finish_authentication_with_state(state, response, credential)
    }

    pub async fn finish_authentication_persisted(
        &self,
        transaction_id: &str,
        response: Value,
        credential: &mut Passkey,
    ) -> Result<WebAuthnAuthenticationResult> {
        let storage = self.state_storage()?;
        let state = storage
            .get_and_delete(&authentication_key(transaction_id))
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let state: PasskeyAuthentication =
            serde_json::from_value(state.value).map_err(json_error)?;
        self.finish_authentication_with_state(state, response, credential)
    }

    fn finish_authentication_with_state(
        &self,
        state: PasskeyAuthentication,
        response: Value,
        credential: &mut Passkey,
    ) -> Result<WebAuthnAuthenticationResult> {
        let response: PublicKeyCredential = serde_json::from_value(response).map_err(json_error)?;
        let result = self
            .webauthn
            .finish_passkey_authentication(&response, &state)
            .map_err(webauthn_error)?;
        let updated = credential
            .update_credential(&result)
            .ok_or(AuthError::Unauthorized)?;
        Ok(WebAuthnAuthenticationResult {
            credential_id: format!("{:?}", result.cred_id()),
            counter: result.counter(),
            credential_updated: updated,
        })
    }

    fn state_storage(&self) -> Result<&Arc<dyn SecondaryStorage>> {
        self.state_storage.as_ref().ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "configure WebAuthn state storage for persisted ceremonies".into(),
            )
        })
    }
}

pub struct DbPasskeyStore {
    adapter: Arc<dyn DbAdapter>,
}

impl DbPasskeyStore {
    pub fn new(adapter: Arc<dyn DbAdapter>) -> Self {
        Self { adapter }
    }

    pub async fn load_for_user(&self, user_id: &str) -> Result<Vec<Passkey>> {
        self.adapter
            .find_many("passkey", Query::new().eq("user_id", user_id.to_owned()))
            .await?
            .into_iter()
            .map(|value| {
                serde_json::from_value(
                    value
                        .get("credential")
                        .cloned()
                        .ok_or_else(|| AuthError::Adapter("passkey has no credential".into()))?,
                )
                .map_err(json_error)
            })
            .collect()
    }

    pub async fn save(&self, user_id: &str, credential: &Passkey) -> Result<()> {
        let credential_id = format!("{:?}", credential.cred_id());
        let record = serde_json::json!({
            "user_id": user_id,
            "credential_id": credential_id.clone(),
            "credential": credential,
        });
        if self
            .adapter
            .find_one(
                "passkey",
                Query::new().eq("credential_id", credential_id.clone()),
            )
            .await?
            .is_some()
        {
            self.adapter
                .update_where(
                    "passkey",
                    Query::new().eq("credential_id", credential_id),
                    record,
                )
                .await?;
            Ok(())
        } else {
            let id = Uuid::new_v4().to_string();
            let mut record = record;
            record["id"] = id.into();
            self.adapter.insert_record("passkey", record).await?;
            Ok(())
        }
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

fn registration_key(transaction_id: &str) -> String {
    format!("webauthn:registration:{transaction_id}")
}

fn authentication_key(transaction_id: &str) -> String {
    format!("webauthn:authentication:{transaction_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::adapter::memory::MemorySecondaryStorage;

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

    #[tokio::test]
    async fn persisted_registration_state_is_serialized_and_single_use() {
        let storage = Arc::new(MemorySecondaryStorage::default());
        let service = WebAuthnService::new(
            "example.com",
            Url::parse("https://example.com").unwrap(),
            "Example",
        )
        .unwrap()
        .with_state_storage(storage.clone());
        let (transaction_id, challenge) = service
            .start_registration_persisted(Uuid::new_v4(), "user@example.com", "User", Vec::new())
            .await
            .unwrap();
        assert!(challenge.get("publicKey").is_some());
        assert!(storage
            .get(&registration_key(&transaction_id))
            .await
            .unwrap()
            .is_some());
        assert!(service
            .finish_registration_persisted(&transaction_id, Value::Null)
            .await
            .is_err());
        assert!(storage
            .get(&registration_key(&transaction_id))
            .await
            .unwrap()
            .is_none());
    }
}
