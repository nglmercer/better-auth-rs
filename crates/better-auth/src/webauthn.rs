use better_auth_core::{
    adapter::{DbAdapter, Query, SecondaryStorage, StorageValue},
    error::{AuthError, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// How long a registration or sign-in ceremony may take from challenge to response.
const CEREMONY_TTL: Duration = Duration::from_secs(5 * 60);

/// A WebAuthn-backed passkey service. Challenge state is retained server-side
/// and the vetted webauthn-rs implementation performs attestation, origin,
/// RP-ID, signature, user-verification, and counter checks.
pub struct WebAuthnService {
    webauthn: Webauthn,
    registrations: Mutex<HashMap<String, PasskeyRegistration>>,
    authentications: Mutex<HashMap<String, PasskeyAuthentication>>,
    state_storage: Option<Arc<dyn SecondaryStorage>>,
}

/// Registration state stored between the options and the response. The user
/// is recorded so a response can only complete the ceremony its user started.
#[derive(Serialize, Deserialize)]
struct PersistedRegistration {
    user_id: Uuid,
    state: PasskeyRegistration,
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
        let transaction_id = new_transaction_id();
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
            .map_err(verification_error)
    }

    /// Starts a registration whose state lives in secondary storage, so any node
    /// can finish it. `user_id` is the WebAuthn user handle and must stay stable.
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
        let transaction_id = new_transaction_id();
        let persisted = PersistedRegistration { user_id, state };
        storage
            .set(
                &registration_key(&transaction_id),
                StorageValue::with_ttl(
                    serde_json::to_value(persisted).map_err(json_error)?,
                    CEREMONY_TTL,
                ),
            )
            .await?;
        Ok((
            transaction_id,
            serde_json::to_value(challenge).map_err(json_error)?,
        ))
    }

    /// Completes a persisted registration. The transaction is consumed even when
    /// verification fails, and it only completes for the user who started it.
    pub async fn finish_registration_persisted(
        &self,
        transaction_id: &str,
        user_id: Uuid,
        response: Value,
    ) -> Result<Passkey> {
        let storage = self.state_storage()?;
        let stored = storage
            .get_and_delete(&registration_key(transaction_id))
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let persisted: PersistedRegistration =
            serde_json::from_value(stored.value).map_err(json_error)?;
        if persisted.user_id != user_id {
            return Err(AuthError::Unauthorized);
        }
        let response: RegisterPublicKeyCredential =
            serde_json::from_value(response).map_err(json_error)?;
        self.webauthn
            .finish_passkey_registration(&response, &persisted.state)
            .map_err(verification_error)
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
        let transaction_id = new_transaction_id();
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
        let transaction_id = new_transaction_id();
        storage
            .set(
                &authentication_key(&transaction_id),
                StorageValue::with_ttl(
                    serde_json::to_value(state).map_err(json_error)?,
                    CEREMONY_TTL,
                ),
            )
            .await?;
        Ok((
            transaction_id,
            serde_json::to_value(challenge).map_err(json_error)?,
        ))
    }

    /// Starts a sign-in that does not name the account first. The browser picks
    /// a credential, and the server finds it by ID, so the options reveal
    /// nothing about which accounts exist.
    pub async fn start_discoverable_persisted(&self) -> Result<(String, Value)> {
        let storage = self.state_storage()?;
        let (challenge, state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(webauthn_error)?;
        let transaction_id = new_transaction_id();
        storage
            .set(
                &discoverable_key(&transaction_id),
                StorageValue::with_ttl(
                    serde_json::to_value(state).map_err(json_error)?,
                    CEREMONY_TTL,
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

    /// Completes a discoverable sign-in for the one credential the caller looked
    /// up by ID. webauthn-rs rejects a response for any other credential.
    pub async fn finish_discoverable_persisted(
        &self,
        transaction_id: &str,
        response: Value,
        credential: &mut Passkey,
    ) -> Result<WebAuthnAuthenticationResult> {
        let storage = self.state_storage()?;
        let stored = storage
            .get_and_delete(&discoverable_key(transaction_id))
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let state: DiscoverableAuthentication =
            serde_json::from_value(stored.value).map_err(json_error)?;
        let response: PublicKeyCredential = serde_json::from_value(response).map_err(json_error)?;
        let result = self
            .webauthn
            .finish_discoverable_authentication(
                &response,
                state,
                &[DiscoverableKey::from(&*credential)],
            )
            .map_err(verification_error)?;
        let updated = credential
            .update_credential(&result)
            .ok_or(AuthError::Unauthorized)?;
        Ok(WebAuthnAuthenticationResult {
            credential_id: credential_key(result.cred_id())?,
            counter: result.counter(),
            credential_updated: updated,
        })
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
            .map_err(verification_error)?;
        let updated = credential
            .update_credential(&result)
            .ok_or(AuthError::Unauthorized)?;
        Ok(WebAuthnAuthenticationResult {
            credential_id: credential_key(result.cred_id())?,
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

/// Text form of a credential ID, used as the lookup key in storage. The same
/// encoding is used for stored IDs and for the `rawId` of a response, so the
/// two can be compared directly.
pub fn credential_key(credential_id: &CredentialID) -> Result<String> {
    encoded_key(credential_id)
}

/// The credential ID a sign-in response names, before any verification. The
/// caller looks up that credential, then verifies the full response against it.
pub fn credential_key_from_response(response: &Value) -> Result<String> {
    let response: PublicKeyCredential =
        serde_json::from_value(response.clone()).map_err(json_error)?;
    encoded_key(&response.raw_id)
}

fn encoded_key<T: Serialize>(value: &T) -> Result<String> {
    match serde_json::to_value(value).map_err(json_error)? {
        Value::String(text) => Ok(text),
        _ => Err(AuthError::Adapter(
            "credential ID did not encode as text".into(),
        )),
    }
}

/// A stored passkey with the columns that identify it. The credential holds the
/// public key and signature counter, which webauthn-rs needs for verification.
#[derive(Clone)]
pub struct StoredPasskey {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub credential_id: String,
    pub credential: Passkey,
}

impl StoredPasskey {
    /// The public view: never the credential, only what a user manages.
    pub fn view(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "credential_id": self.credential_id,
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
        Ok(self
            .list_for_user(user_id)
            .await?
            .into_iter()
            .map(|stored| stored.credential)
            .collect())
    }

    pub async fn list_for_user(&self, user_id: &str) -> Result<Vec<StoredPasskey>> {
        self.adapter
            .find_many("passkey", Query::new().eq("user_id", user_id.to_owned()))
            .await?
            .into_iter()
            .map(decode_row)
            .collect()
    }

    pub async fn find_by_credential(&self, credential_id: &str) -> Result<Option<StoredPasskey>> {
        self.adapter
            .find_one(
                "passkey",
                Query::new().eq("credential_id", credential_id.to_owned()),
            )
            .await?
            .map(decode_row)
            .transpose()
    }

    /// Stores a newly verified credential. A credential ID already in use, by
    /// anyone, is refused rather than moved to another account.
    pub async fn insert(
        &self,
        user_id: &str,
        name: Option<&str>,
        credential: &Passkey,
    ) -> Result<StoredPasskey> {
        let credential_id = credential_key(credential.cred_id())?;
        if self.find_by_credential(&credential_id).await?.is_some() {
            return Err(AuthError::InvalidRequest(
                "this passkey is already registered".into(),
            ));
        }
        let stored = StoredPasskey {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_owned(),
            name: name.map(str::to_owned),
            credential_id,
            credential: credential.clone(),
        };
        self.adapter
            .insert_record(
                "passkey",
                json!({
                    "id": stored.id,
                    "user_id": stored.user_id,
                    "name": stored.name,
                    "credential_id": stored.credential_id,
                    "credential": credential,
                }),
            )
            .await?;
        Ok(stored)
    }

    /// Writes the credential after a successful sign-in, so the signature
    /// counter that webauthn-rs advanced is the one that is kept.
    pub async fn update_credential(&self, id: &str, credential: &Passkey) -> Result<()> {
        let changed = self
            .adapter
            .update_where(
                "passkey",
                Query::new().eq("id", id.to_owned()),
                json!({"credential": credential}),
            )
            .await?;
        if changed == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    /// Renames a passkey the user owns. Returns false when it is not theirs.
    pub async fn rename(&self, user_id: &str, id: &str, name: &str) -> Result<bool> {
        let changed = self
            .adapter
            .update_where("passkey", owned_by(user_id, id), json!({"name": name}))
            .await?;
        Ok(changed > 0)
    }

    /// Deletes a passkey the user owns. Returns false when it is not theirs.
    pub async fn delete(&self, user_id: &str, id: &str) -> Result<bool> {
        let removed = self
            .adapter
            .delete_where("passkey", owned_by(user_id, id))
            .await?;
        Ok(removed > 0)
    }

    /// Stores a credential for `user_id`, creating the row or updating its
    /// credential. A credential that belongs to a different user is refused.
    pub async fn save(&self, user_id: &str, credential: &Passkey) -> Result<()> {
        let credential_id = credential_key(credential.cred_id())?;
        match self.find_by_credential(&credential_id).await? {
            Some(existing) if existing.user_id != user_id => Err(AuthError::Unauthorized),
            Some(existing) => self.update_credential(&existing.id, credential).await,
            None => self.insert(user_id, None, credential).await.map(|_| ()),
        }
    }
}

fn owned_by(user_id: &str, id: &str) -> Query {
    Query::new()
        .eq("id", id.to_owned())
        .eq("user_id", user_id.to_owned())
}

fn decode_row(row: Value) -> Result<StoredPasskey> {
    let text = |field: &str| {
        row.get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| AuthError::Adapter(format!("passkey row has no {field}")))
    };
    let credential = row
        .get("credential")
        .cloned()
        .ok_or_else(|| AuthError::Adapter("passkey has no credential".into()))?;
    Ok(StoredPasskey {
        id: text("id")?,
        user_id: text("user_id")?,
        name: row.get("name").and_then(Value::as_str).map(str::to_owned),
        credential_id: text("credential_id")?,
        credential: serde_json::from_value(credential).map_err(json_error)?,
    })
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct WebAuthnAuthenticationResult {
    pub credential_id: String,
    pub counter: u32,
    pub credential_updated: bool,
}

fn new_transaction_id() -> String {
    Uuid::new_v4().simple().to_string()
}

fn webauthn_error(error: impl std::fmt::Debug) -> AuthError {
    AuthError::Crypto(format!("WebAuthn verification failed: {error:?}"))
}

/// A response that fails WebAuthn verification is the client's fault, not a
/// server fault, so it is reported as an authentication failure. The detail is
/// logged without the response itself.
fn verification_error(error: impl std::fmt::Debug) -> AuthError {
    tracing::debug!(reason = ?error, "passkey verification failed");
    AuthError::Unauthorized
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

fn discoverable_key(transaction_id: &str) -> String {
    format!("webauthn:discoverable:{transaction_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::adapter::memory::MemorySecondaryStorage;

    fn service(storage: Arc<dyn SecondaryStorage>) -> WebAuthnService {
        WebAuthnService::new(
            "example.com",
            Url::parse("https://example.com").unwrap(),
            "Example",
        )
        .unwrap()
        .with_state_storage(storage)
    }

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
        let service = service(storage.clone());
        let user = Uuid::new_v4();
        let (transaction_id, challenge) = service
            .start_registration_persisted(user, "user@example.com", "User", Vec::new())
            .await
            .unwrap();
        assert!(challenge.get("publicKey").is_some());
        assert!(storage
            .get(&registration_key(&transaction_id))
            .await
            .unwrap()
            .is_some());
        assert!(service
            .finish_registration_persisted(&transaction_id, user, Value::Null)
            .await
            .is_err());
        assert!(storage
            .get(&registration_key(&transaction_id))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn registration_only_completes_for_the_user_who_started_it() {
        let storage = Arc::new(MemorySecondaryStorage::default());
        let service = service(storage.clone());
        let owner = Uuid::new_v4();
        let (transaction_id, _) = service
            .start_registration_persisted(owner, "owner@example.com", "Owner", Vec::new())
            .await
            .unwrap();
        // A different user is refused before any response is examined, and the
        // transaction is spent so it cannot be retried by the owner either.
        let other = Uuid::new_v4();
        assert!(matches!(
            service
                .finish_registration_persisted(&transaction_id, other, Value::Null)
                .await,
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            service
                .finish_registration_persisted(&transaction_id, owner, Value::Null)
                .await,
            Err(AuthError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn discoverable_sign_in_state_is_stored_under_its_own_key() {
        let storage = Arc::new(MemorySecondaryStorage::default());
        let service = service(storage.clone());
        let (transaction_id, challenge) = service.start_discoverable_persisted().await.unwrap();
        assert!(challenge.get("publicKey").is_some());
        assert!(storage
            .get(&discoverable_key(&transaction_id))
            .await
            .unwrap()
            .is_some());
    }

    #[test]
    fn credential_keys_match_between_stored_and_response_forms() {
        let response = json!({
            "id": "AQID",
            "rawId": "AQID",
            "type": "public-key",
            "response": {
                "clientDataJSON": "e30",
                "authenticatorData": "e30",
                "signature": "e30",
            },
        });
        let key = credential_key_from_response(&response).unwrap();
        assert_eq!(key, "AQID");
    }
}
