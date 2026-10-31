use super::shared::{endpoint, now_seconds, optional, random_challenge, required, serialize_error};
use better_auth_core::{
    adapter::{SecondaryStorage, StorageValue},
    error::{AuthError, Result},
    plugin::{Endpoint, EndpointAccess, Plugin},
    schema::{FieldType, SchemaExtension, TableSchema},
};
use http::Method;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

#[derive(Clone, Copy, Debug, Default)]
pub struct PasskeyPlugin;

impl Plugin for PasskeyPlugin {
    fn name(&self) -> &'static str {
        "passkey"
    }
    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::POST,
                "/passkey/generate-register-options",
                "Start passkey registration for the signed-in user",
            ),
            endpoint(
                Method::POST,
                "/passkey/verify-registration",
                "Finish passkey registration",
            ),
            endpoint(
                Method::POST,
                "/passkey/generate-authenticate-options",
                "Start a passkey sign-in",
            )
            .with_access(EndpointAccess::Public),
            endpoint(
                Method::POST,
                "/passkey/verify-authentication",
                "Finish a passkey sign-in and create a session",
            )
            .with_access(EndpointAccess::Public),
            endpoint(
                Method::GET,
                "/passkey/list-user-passkeys",
                "List the signed-in user's passkeys",
            ),
            endpoint(
                Method::POST,
                "/passkey/update-passkey",
                "Rename one of the signed-in user's passkeys",
            ),
            endpoint(
                Method::POST,
                "/passkey/delete-passkey",
                "Delete one of the signed-in user's passkeys",
            ),
        ]
    }
    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default().table(
            "passkey",
            TableSchema::default()
                .field("id", required(FieldType::String).unique())
                .field("user_id", required(FieldType::String))
                .field("name", optional(FieldType::String))
                .field("credential_id", required(FieldType::String).unique())
                // The whole webauthn-rs credential, including the public key and
                // signature counter that verification depends on.
                .field("credential", required(FieldType::Json)),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasskeyChallenge {
    pub challenge: String,
    pub user_id: Option<String>,
    pub rp_id: String,
    pub expires_at: u64,
}

#[derive(Clone)]
pub struct PasskeyService {
    storage: Arc<dyn SecondaryStorage>,
}

impl PasskeyService {
    pub fn new(storage: Arc<dyn SecondaryStorage>) -> Self {
        Self { storage }
    }

    pub async fn begin(
        &self,
        key: &str,
        user_id: Option<String>,
        rp_id: &str,
        ttl: Duration,
    ) -> Result<PasskeyChallenge> {
        let challenge = random_challenge();
        let state = PasskeyChallenge {
            challenge: challenge.clone(),
            user_id,
            rp_id: rp_id.to_owned(),
            expires_at: now_seconds() + ttl.as_secs(),
        };
        self.storage
            .set(
                &format!("passkey:challenge:{key}"),
                StorageValue::with_ttl(serde_json::to_value(&state).map_err(serialize_error)?, ttl),
            )
            .await?;
        Ok(state)
    }

    pub async fn consume(&self, key: &str, expected_challenge: &str) -> Result<PasskeyChallenge> {
        let value = self
            .storage
            .get_and_delete(&format!("passkey:challenge:{key}"))
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let state: PasskeyChallenge =
            serde_json::from_value(value.value).map_err(serialize_error)?;
        if state.challenge != expected_challenge || state.expires_at <= now_seconds() {
            return Err(AuthError::Unauthorized);
        }
        Ok(state)
    }
}
