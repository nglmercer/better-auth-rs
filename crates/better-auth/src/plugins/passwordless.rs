//! Declarations for the passwordless plugins. The routes themselves are
//! mounted by the router when the plugin is registered.

use super::shared::endpoint;
use better_auth_core::plugin::{Endpoint, Plugin};
use http::Method;

#[derive(Clone, Copy, Debug, Default)]
pub struct MagicLinkPlugin;

impl Plugin for MagicLinkPlugin {
    fn name(&self) -> &'static str {
        "magic-link"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::POST,
                "/sign-in/magic-link",
                "Email a single-use sign-in link",
            ),
            endpoint(
                Method::GET,
                "/magic-link/verify",
                "Show the sign-in confirmation page",
            ),
            endpoint(
                Method::POST,
                "/magic-link/verify",
                "Consume a sign-in link and sign in",
            ),
        ]
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EmailOtpPlugin;

impl Plugin for EmailOtpPlugin {
    fn name(&self) -> &'static str {
        "email-otp"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::POST,
                "/email-otp/send",
                "Email a one-time sign-in code",
            ),
            endpoint(
                Method::POST,
                "/email-otp/verify",
                "Verify a one-time sign-in code",
            ),
        ]
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OneTimeTokenPlugin;

impl Plugin for OneTimeTokenPlugin {
    fn name(&self) -> &'static str {
        "one-time-token"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::POST,
                "/one-time-token/generate",
                "Issue a one-time token",
            ),
            endpoint(
                Method::POST,
                "/one-time-token/verify",
                "Consume a one-time token",
            ),
            endpoint(
                Method::POST,
                "/one-time-token/revoke",
                "Revoke a one-time token",
            ),
        ]
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DeviceAuthorizationPlugin;

impl Plugin for DeviceAuthorizationPlugin {
    fn name(&self) -> &'static str {
        "device-authorization"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(Method::POST, "/device/code", "Start a device authorization"),
            endpoint(Method::GET, "/device", "Look up a user code"),
            endpoint(Method::POST, "/device/approve", "Approve a user code"),
            endpoint(Method::POST, "/device/deny", "Deny a user code"),
            endpoint(Method::POST, "/device/token", "Poll for the device grant"),
        ]
    }

    fn schema(&self) -> better_auth_core::schema::SchemaExtension {
        use better_auth_core::schema::{FieldSchema, FieldType, SchemaExtension, TableSchema};
        SchemaExtension::default().table(
            "device_code",
            TableSchema::default()
                .primary_key("id")
                .field("id", FieldSchema::required(FieldType::String).unique())
                .field(
                    "device_code_hash",
                    FieldSchema::required(FieldType::String).unique(),
                )
                .field(
                    "user_code",
                    FieldSchema::required(FieldType::String).unique(),
                )
                .field("client_id", FieldSchema::required(FieldType::String))
                .field("user_id", FieldSchema::required(FieldType::String))
                .field("status", FieldSchema::required(FieldType::String))
                .field("expires_at", FieldSchema::required(FieldType::DateTime))
                .field("last_poll_at", FieldSchema::required(FieldType::DateTime))
                .field("created_at", FieldSchema::required(FieldType::DateTime)),
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AnonymousPlugin;

impl Plugin for AnonymousPlugin {
    fn name(&self) -> &'static str {
        "anonymous"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(Method::POST, "/sign-in/anonymous", "Start a guest session"),
            endpoint(
                Method::POST,
                "/anonymous/upgrade",
                "Upgrade a guest to a credential account",
            ),
            endpoint(
                Method::POST,
                "/delete-anonymous-user",
                "Delete a guest account",
            ),
        ]
    }

    fn schema(&self) -> better_auth_core::schema::SchemaExtension {
        use better_auth_core::schema::{FieldSchema, FieldType, SchemaExtension, TableSchema};
        SchemaExtension::default().table(
            "user",
            TableSchema::default().field("is_anonymous", FieldSchema::optional(FieldType::Boolean)),
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OneTapPlugin;

impl Plugin for OneTapPlugin {
    fn name(&self) -> &'static str {
        "one-tap"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![endpoint(
            Method::POST,
            "/one-tap/callback",
            "Sign in with a Google One Tap credential",
        )]
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SiwePlugin;

impl Plugin for SiwePlugin {
    fn name(&self) -> &'static str {
        "siwe"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::POST,
                "/siwe/nonce",
                "Issue a Sign In With Ethereum nonce",
            ),
            endpoint(Method::POST, "/siwe/verify", "Verify a signed SIWE message"),
        ]
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MultiSessionPlugin;

impl Plugin for MultiSessionPlugin {
    fn name(&self) -> &'static str {
        "multi-session"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::GET,
                "/multi-session/list-device-sessions",
                "List signed-in accounts",
            ),
            endpoint(
                Method::POST,
                "/multi-session/set-active",
                "Switch the active account",
            ),
            endpoint(
                Method::POST,
                "/multi-session/revoke",
                "Revoke one account in this browser",
            ),
        ]
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LastLoginMethodPlugin;

impl Plugin for LastLoginMethodPlugin {
    fn name(&self) -> &'static str {
        "last-login-method"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![endpoint(
            Method::GET,
            "/last-login-method",
            "Read the last sign-in method",
        )]
    }

    fn schema(&self) -> better_auth_core::schema::SchemaExtension {
        use better_auth_core::schema::{FieldSchema, FieldType, SchemaExtension, TableSchema};
        SchemaExtension::default().table(
            "user",
            TableSchema::default().field(
                "last_login_method",
                FieldSchema::optional(FieldType::String),
            ),
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PhoneNumberPlugin;

impl Plugin for PhoneNumberPlugin {
    fn name(&self) -> &'static str {
        "phone-number"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            endpoint(
                Method::POST,
                "/phone-number/send-otp",
                "Send an SMS sign-in code",
            ),
            endpoint(
                Method::POST,
                "/phone-number/verify",
                "Verify an SMS sign-in code",
            ),
        ]
    }

    fn schema(&self) -> better_auth_core::schema::SchemaExtension {
        use better_auth_core::schema::{FieldSchema, FieldType, SchemaExtension, TableSchema};
        SchemaExtension::default().table(
            "user",
            TableSchema::default()
                .field(
                    "phone_number",
                    FieldSchema::optional(FieldType::String).unique(),
                )
                .field(
                    "phone_number_verified",
                    FieldSchema::optional(FieldType::Boolean),
                ),
        )
    }
}
