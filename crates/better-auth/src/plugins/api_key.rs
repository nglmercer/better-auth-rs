//! API-key plugin: schema for the `api_key` table and its routes.

use super::shared::{endpoint, optional, required};
use better_auth_core::{
    plugin::{Endpoint, Plugin},
    schema::{FieldType, SchemaExtension, TableSchema},
};
use http::Method;

pub const API_KEY_PLUGIN: &str = "api-key";

#[derive(Clone, Copy, Debug, Default)]
pub struct ApiKeyPlugin;

impl Plugin for ApiKeyPlugin {
    fn name(&self) -> &'static str {
        API_KEY_PLUGIN
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(Method::POST, "/api-key/create", "Create an API key"),
            endpoint(Method::GET, "/api-key/list", "List the caller's API keys"),
            endpoint(Method::POST, "/api-key/revoke", "Revoke an API key"),
            endpoint(
                Method::GET,
                "/api-key/verify",
                "Describe the API key in x-api-key",
            ),
        ]
    }

    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default().table(
            TABLE,
            TableSchema::default()
                .primary_key("id")
                .field("id", required(FieldType::String).unique())
                .field("user_id", required(FieldType::String))
                .field("name", required(FieldType::String))
                .field("prefix", required(FieldType::String).unique())
                .field("key_hash", required(FieldType::String))
                .field("scopes", required(FieldType::Json))
                .field("expires_at", required(FieldType::DateTime))
                .field("has_expiry", required(FieldType::Boolean))
                .field("revoked", required(FieldType::Boolean))
                .field("created_at", required(FieldType::DateTime))
                .field("last_used_at", optional(FieldType::DateTime)),
        )
    }
}

const TABLE: &str = "api_key";
