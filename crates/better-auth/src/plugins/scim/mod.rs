use super::shared::{endpoint, hash_secret, optional, required};
use better_auth_core::{
    plugin::{Endpoint, Plugin},
    schema::{FieldType, SchemaExtension, TableSchema},
};
use http::Method;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

mod filter;
mod helpers;
mod patch;
mod resources;
mod service;

pub use service::ScimService;

#[derive(Clone, Copy, Debug, Default)]
pub struct ScimPlugin;

impl Plugin for ScimPlugin {
    fn name(&self) -> &'static str {
        "scim"
    }
    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(Method::GET, "/scim/v2/Users", "List SCIM users"),
            endpoint(Method::POST, "/scim/v2/Users", "Create a SCIM user"),
            endpoint(Method::GET, "/scim/v2/Users/:id", "Get a SCIM user"),
            endpoint(Method::PATCH, "/scim/v2/Users/:id", "Update a SCIM user"),
            endpoint(Method::DELETE, "/scim/v2/Users/:id", "Delete a SCIM user"),
            endpoint(Method::GET, "/scim/v2/Groups", "List SCIM groups"),
            endpoint(Method::POST, "/scim/v2/Groups", "Create a SCIM group"),
            endpoint(Method::GET, "/scim/v2/Groups/:id", "Get a SCIM group"),
            endpoint(Method::PATCH, "/scim/v2/Groups/:id", "Update a SCIM group"),
            endpoint(Method::DELETE, "/scim/v2/Groups/:id", "Delete a SCIM group"),
            endpoint(Method::POST, "/scim/v2/Bulk", "Apply SCIM bulk operations"),
        ]
    }
    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default()
            .table(
                "scim_token",
                TableSchema::default()
                    .field("id", required(FieldType::String).unique())
                    .field("organization_id", required(FieldType::String))
                    .field("token_hash", required(FieldType::String).unique())
                    .field("expires_at", optional(FieldType::DateTime)),
            )
            .table(
                "scim_group",
                TableSchema::default()
                    .field("id", required(FieldType::String).unique())
                    .field("display_name", required(FieldType::String))
                    .field("organization_id", required(FieldType::String)),
            )
            .table(
                "scim_group_member",
                TableSchema::default()
                    .field("id", required(FieldType::String).unique())
                    .field("group_id", required(FieldType::String))
                    .field("user_id", required(FieldType::String)),
            )
    }
}

pub fn generate_scim_token() -> (String, String) {
    let token = format!("scim_{}", Uuid::new_v4().simple());
    (token.clone(), hash_secret(&token))
}

pub fn verify_scim_token(token: &str, expected_hash: &str) -> bool {
    hash_secret(token)
        .as_bytes()
        .ct_eq(expected_hash.as_bytes())
        .into()
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScimBulkOperation {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScimBulkResponse {
    pub method: String,
    pub path: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScimPatchOperation {
    pub op: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub value: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScimGroup {
    pub id: String,
    pub display_name: String,
    pub organization_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScimGroupMember {
    pub group_id: String,
    pub user_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScimTokenRecord {
    pub id: String,
    pub organization_id: String,
    pub token_hash: String,
    #[serde(default)]
    pub expires_at: Option<u64>,
}
