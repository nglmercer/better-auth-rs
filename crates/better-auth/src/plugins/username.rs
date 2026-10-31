//! Username plugin: schema for the normalized, unique username column and the
//! routes that set it and sign in with it.

use super::shared::endpoint;
use better_auth_core::{
    plugin::{Endpoint, Plugin},
    schema::{FieldSchema, FieldType, SchemaExtension, TableSchema},
};
use http::Method;

pub const USERNAME_PLUGIN: &str = "username";

#[derive(Clone, Copy, Debug, Default)]
pub struct UsernamePlugin;

impl Plugin for UsernamePlugin {
    fn name(&self) -> &'static str {
        USERNAME_PLUGIN
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::POST,
                "/username/set",
                "Set the signed-in user's username",
            ),
            endpoint(
                Method::POST,
                "/sign-in/username",
                "Sign in with username and password",
            ),
        ]
    }

    fn schema(&self) -> SchemaExtension {
        SchemaExtension::default().table(
            "user",
            TableSchema::default().field(
                "username",
                FieldSchema::optional(FieldType::String).unique(),
            ),
        )
    }
}
