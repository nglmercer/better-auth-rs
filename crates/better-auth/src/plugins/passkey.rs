use super::shared::{endpoint, now_seconds, optional, random_challenge, required, serialize_error};
use better_auth_core::{
    adapter::{SecondaryStorage, StorageValue},
    error::{AuthError, Result},
    plugin::{Endpoint, Plugin},
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
                "/passkey/generate-challenge",
                "Generate a WebAuthn challenge",
            ),
            endpoint(
                Method::POST,
                "/passkey/register",
                "Register a passkey credential",
            ),
            endpoint(
                Method::POST,
                "/passkey/authenticate",
                "Authenticate with a passkey",
            ),
        ]
    }
    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default().table(
            "passkey",
            TableSchema::default()
                .field("id", required(FieldType::String).unique())
                .field("user_id", required(FieldType::String))
                .field("credential_id", required(FieldType::String).unique())
                .field("public_key", required(FieldType::Bytes))
                .field("counter", required(FieldType::Integer))
                .field("credential", required(FieldType::Json))
                .field("transports", optional(FieldType::Json)),
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
