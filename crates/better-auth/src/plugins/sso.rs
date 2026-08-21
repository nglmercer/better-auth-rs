use super::shared::{endpoint, required, serialize_error};
use crate::sso::SsoProtocol;
use better_auth_core::{
    adapter::{DbAdapter, Query},
    error::{AuthError, Result},
    plugin::{Endpoint, Plugin},
    schema::{FieldType, SchemaExtension, TableSchema},
};
use http::Method;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SsoConnectionConfig {
    pub id: String,
    #[serde(default)]
    pub protocol: SsoProtocol,
    pub issuer: String,
    pub client_id: String,
    pub discovery_url: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SsoPlugin;

impl Plugin for SsoPlugin {
    fn name(&self) -> &'static str {
        "sso"
    }
    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::GET,
                "/sso/authorize",
                "Start an enterprise SSO flow",
            ),
            endpoint(Method::POST, "/sso/connections", "Create an SSO connection"),
            endpoint(
                Method::GET,
                "/sso/saml/authorize",
                "Start a SAML enterprise SSO flow",
            ),
            endpoint(
                Method::POST,
                "/sso/saml/callback",
                "Validate a SAML enterprise SSO response",
            ),
        ]
    }
    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default().table(
            "sso_connection",
            TableSchema::default()
                .field("id", required(FieldType::String).unique())
                .field("protocol", required(FieldType::String))
                .field("issuer", required(FieldType::String))
                .field("client_id", required(FieldType::String))
                .field("discovery_url", required(FieldType::String)),
        )
    }
}

impl SsoConnectionConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.issuer.starts_with("https://") || !self.discovery_url.starts_with("https://") {
            return Err(AuthError::InvalidConfiguration(
                "SSO endpoints must use HTTPS".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct SsoConnectionService {
    adapter: Arc<dyn DbAdapter>,
}

impl SsoConnectionService {
    pub fn new(adapter: Arc<dyn DbAdapter>) -> Self {
        Self { adapter }
    }

    pub async fn create(&self, connection: SsoConnectionConfig) -> Result<()> {
        connection.validate()?;
        self.adapter
            .insert_record(
                "sso_connection",
                serde_json::to_value(&connection).map_err(serialize_error)?,
            )
            .await?;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> Result<Option<SsoConnectionConfig>> {
        let Some(value) = self
            .adapter
            .find_one("sso_connection", Query::new().eq("id", id.to_owned()))
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(
            serde_json::from_value(value).map_err(serialize_error)?,
        ))
    }
}
