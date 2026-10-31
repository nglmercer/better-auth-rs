//! OpenAPI 3.1 description of the routes this crate mounts.
//!
//! The route table is checked against the router source by a test, so a route
//! cannot be removed or renamed without this description changing too. Request
//! and response bodies are described loosely (JSON objects). The precise shapes
//! live in the typed SDKs.

use serde_json::{json, Map, Value};

pub struct Route {
    pub method: &'static str,
    pub path: &'static str,
    pub tag: &'static str,
    pub session: bool,
}

/// Every route mounted by `AuthRouter::handle`. Keep in sync with `router.rs`.
pub const ROUTES: &[Route] = &[
    Route {
        method: "GET",
        path: "/.well-known/jwks.json",
        tag: ".well-known",
        session: false,
    },
    Route {
        method: "POST",
        path: "/admin/ban-user",
        tag: "admin",
        session: true,
    },
    Route {
        method: "POST",
        path: "/admin/list-user-sessions",
        tag: "admin",
        session: true,
    },
    Route {
        method: "POST",
        path: "/admin/remove-user",
        tag: "admin",
        session: true,
    },
    Route {
        method: "POST",
        path: "/admin/revoke-user-session",
        tag: "admin",
        session: true,
    },
    Route {
        method: "POST",
        path: "/admin/revoke-user-sessions",
        tag: "admin",
        session: true,
    },
    Route {
        method: "POST",
        path: "/admin/unban-user",
        tag: "admin",
        session: true,
    },
    Route {
        method: "GET",
        path: "/admin/list-users",
        tag: "admin",
        session: true,
    },
    Route {
        method: "POST",
        path: "/admin/revoke-sessions",
        tag: "admin",
        session: true,
    },
    Route {
        method: "POST",
        path: "/admin/set-role",
        tag: "admin",
        session: true,
    },
    Route {
        method: "POST",
        path: "/anonymous/upgrade",
        tag: "anonymous",
        session: true,
    },
    Route {
        method: "POST",
        path: "/api-key/create",
        tag: "api-key",
        session: true,
    },
    Route {
        method: "GET",
        path: "/api-key/list",
        tag: "api-key",
        session: true,
    },
    Route {
        method: "POST",
        path: "/api-key/revoke",
        tag: "api-key",
        session: true,
    },
    Route {
        method: "GET",
        path: "/api-key/verify",
        tag: "api-key",
        session: false,
    },
    Route {
        method: "POST",
        path: "/change-password",
        tag: "change-password",
        session: true,
    },
    Route {
        method: "POST",
        path: "/delete-anonymous-user",
        tag: "delete-anonymous-user",
        session: true,
    },
    Route {
        method: "POST",
        path: "/delete-user",
        tag: "delete-user",
        session: true,
    },
    Route {
        method: "GET",
        path: "/device",
        tag: "device",
        session: false,
    },
    Route {
        method: "POST",
        path: "/device/approve",
        tag: "device",
        session: true,
    },
    Route {
        method: "POST",
        path: "/device/code",
        tag: "device",
        session: false,
    },
    Route {
        method: "POST",
        path: "/device/deny",
        tag: "device",
        session: true,
    },
    Route {
        method: "POST",
        path: "/device/token",
        tag: "device",
        session: false,
    },
    Route {
        method: "POST",
        path: "/email-otp/send",
        tag: "email-otp",
        session: false,
    },
    Route {
        method: "POST",
        path: "/email-otp/verify",
        tag: "email-otp",
        session: false,
    },
    Route {
        method: "GET",
        path: "/get-session",
        tag: "get-session",
        session: false,
    },
    Route {
        method: "GET",
        path: "/health",
        tag: "health",
        session: false,
    },
    Route {
        method: "GET",
        path: "/jwks",
        tag: "jwks",
        session: false,
    },
    Route {
        method: "GET",
        path: "/last-login-method",
        tag: "last-login-method",
        session: true,
    },
    Route {
        method: "GET",
        path: "/list-accounts",
        tag: "list-accounts",
        session: true,
    },
    Route {
        method: "GET",
        path: "/list-sessions",
        tag: "list-sessions",
        session: true,
    },
    Route {
        method: "GET",
        path: "/magic-link/verify",
        tag: "magic-link",
        session: false,
    },
    Route {
        method: "GET",
        path: "/metrics",
        tag: "metrics",
        session: false,
    },
    Route {
        method: "POST",
        path: "/one-tap/callback",
        tag: "one-tap",
        session: false,
    },
    Route {
        method: "POST",
        path: "/one-time-token/generate",
        tag: "one-time-token",
        session: true,
    },
    Route {
        method: "POST",
        path: "/one-time-token/revoke",
        tag: "one-time-token",
        session: true,
    },
    Route {
        method: "POST",
        path: "/one-time-token/verify",
        tag: "one-time-token",
        session: false,
    },
    Route {
        method: "POST",
        path: "/organization/accept-invitation",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/create",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/invite-member",
        tag: "organization",
        session: true,
    },
    Route {
        method: "GET",
        path: "/organization/list",
        tag: "organization",
        session: true,
    },
    Route {
        method: "GET",
        path: "/organization/list-members",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/remove-member",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/update-member-role",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/passkey/delete-passkey",
        tag: "passkey",
        session: true,
    },
    Route {
        method: "POST",
        path: "/passkey/generate-authenticate-options",
        tag: "passkey",
        session: false,
    },
    Route {
        method: "POST",
        path: "/passkey/generate-register-options",
        tag: "passkey",
        session: true,
    },
    Route {
        method: "GET",
        path: "/passkey/list-user-passkeys",
        tag: "passkey",
        session: true,
    },
    Route {
        method: "POST",
        path: "/passkey/update-passkey",
        tag: "passkey",
        session: true,
    },
    Route {
        method: "POST",
        path: "/passkey/verify-authentication",
        tag: "passkey",
        session: false,
    },
    Route {
        method: "POST",
        path: "/passkey/verify-registration",
        tag: "passkey",
        session: true,
    },
    Route {
        method: "GET",
        path: "/ok",
        tag: "health",
        session: false,
    },
    Route {
        method: "POST",
        path: "/get-session",
        tag: "session",
        session: false,
    },
    Route {
        method: "POST",
        path: "/is-username-available",
        tag: "username",
        session: false,
    },
    Route {
        method: "POST",
        path: "/two-factor/generate-backup-codes",
        tag: "two-factor",
        session: true,
    },
    Route {
        method: "POST",
        path: "/two-factor/get-totp-uri",
        tag: "two-factor",
        session: true,
    },
    Route {
        method: "POST",
        path: "/unlink-account",
        tag: "account",
        session: true,
    },
    Route {
        method: "POST",
        path: "/verify-password",
        tag: "account",
        session: true,
    },
    Route {
        method: "GET",
        path: "/organization/get-organization",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/update",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/delete",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/leave",
        tag: "organization",
        session: true,
    },
    Route {
        method: "GET",
        path: "/organization/list-invitations",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/cancel-invitation",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/reject-invitation",
        tag: "organization",
        session: true,
    },
    Route {
        method: "GET",
        path: "/organization/list-user-invitations",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/check-slug",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/email-otp/send-verification-otp",
        tag: "email-otp",
        session: false,
    },
    Route {
        method: "POST",
        path: "/forget-password/email-otp",
        tag: "email-otp",
        session: false,
    },
    Route {
        method: "POST",
        path: "/email-otp/request-password-reset",
        tag: "email-otp",
        session: false,
    },
    Route {
        method: "POST",
        path: "/sign-in/email-otp",
        tag: "email-otp",
        session: false,
    },
    Route {
        method: "POST",
        path: "/email-otp/verify-email",
        tag: "email-otp",
        session: false,
    },
    Route {
        method: "POST",
        path: "/email-otp/reset-password",
        tag: "email-otp",
        session: false,
    },
    Route {
        method: "GET",
        path: "/organization/list-teams",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/create-team",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/update-team",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/remove-team",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/add-team-member",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/organization/remove-team-member",
        tag: "organization",
        session: true,
    },
    Route {
        method: "GET",
        path: "/organization/list-team-members",
        tag: "organization",
        session: true,
    },
    Route {
        method: "GET",
        path: "/organization/list-user-teams",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/sign-in/social",
        tag: "sign-in",
        session: false,
    },
    Route {
        method: "POST",
        path: "/organization/has-permission",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/admin/create-user",
        tag: "admin",
        session: true,
    },
    Route {
        method: "GET",
        path: "/admin/get-user",
        tag: "admin",
        session: true,
    },
    Route {
        method: "POST",
        path: "/admin/update-user",
        tag: "admin",
        session: true,
    },
    Route {
        method: "POST",
        path: "/admin/set-user-password",
        tag: "admin",
        session: true,
    },
    Route {
        method: "POST",
        path: "/admin/has-permission",
        tag: "admin",
        session: true,
    },
    Route {
        method: "GET",
        path: "/error",
        tag: "core",
        session: false,
    },
    Route {
        method: "POST",
        path: "/email-otp/request-email-change",
        tag: "email-otp",
        session: true,
    },
    Route {
        method: "POST",
        path: "/email-otp/change-email",
        tag: "email-otp",
        session: true,
    },
    Route {
        method: "POST",
        path: "/email-otp/check-verification-otp",
        tag: "email-otp",
        session: false,
    },
    Route {
        method: "GET",
        path: "/organization/get-full-organization",
        tag: "organization",
        session: true,
    },
    Route {
        method: "GET",
        path: "/organization/get-invitation",
        tag: "organization",
        session: true,
    },
    Route {
        method: "POST",
        path: "/phone-number/send-otp",
        tag: "phone-number",
        session: false,
    },
    Route {
        method: "POST",
        path: "/phone-number/verify",
        tag: "phone-number",
        session: false,
    },
    Route {
        method: "GET",
        path: "/ready",
        tag: "ready",
        session: false,
    },
    Route {
        method: "POST",
        path: "/request-password-reset",
        tag: "request-password-reset",
        session: false,
    },
    Route {
        method: "POST",
        path: "/reset-password",
        tag: "reset-password",
        session: false,
    },
    Route {
        method: "POST",
        path: "/revoke-other-sessions",
        tag: "revoke-other-sessions",
        session: true,
    },
    Route {
        method: "POST",
        path: "/revoke-session",
        tag: "revoke-session",
        session: true,
    },
    Route {
        method: "POST",
        path: "/revoke-sessions",
        tag: "revoke-sessions",
        session: true,
    },
    Route {
        method: "POST",
        path: "/send-verification-email",
        tag: "send-verification-email",
        session: true,
    },
    Route {
        method: "POST",
        path: "/sign-in/anonymous",
        tag: "sign-in",
        session: false,
    },
    Route {
        method: "POST",
        path: "/sign-in/email",
        tag: "sign-in",
        session: false,
    },
    Route {
        method: "POST",
        path: "/sign-in/magic-link",
        tag: "sign-in",
        session: false,
    },
    Route {
        method: "POST",
        path: "/sign-in/username",
        tag: "sign-in",
        session: false,
    },
    Route {
        method: "POST",
        path: "/sign-out",
        tag: "sign-out",
        session: false,
    },
    Route {
        method: "POST",
        path: "/sign-up/email",
        tag: "sign-up",
        session: false,
    },
    Route {
        method: "POST",
        path: "/siwe/nonce",
        tag: "siwe",
        session: false,
    },
    Route {
        method: "POST",
        path: "/siwe/verify",
        tag: "siwe",
        session: false,
    },
    Route {
        method: "GET",
        path: "/token",
        tag: "token",
        session: true,
    },
    Route {
        method: "POST",
        path: "/two-factor/confirm",
        tag: "two-factor",
        session: true,
    },
    Route {
        method: "POST",
        path: "/two-factor/disable",
        tag: "two-factor",
        session: true,
    },
    Route {
        method: "POST",
        path: "/two-factor/enable",
        tag: "two-factor",
        session: true,
    },
    Route {
        method: "POST",
        path: "/two-factor/verify",
        tag: "two-factor",
        session: false,
    },
    Route {
        method: "POST",
        path: "/update-user",
        tag: "update-user",
        session: true,
    },
    Route {
        method: "POST",
        path: "/username/set",
        tag: "username",
        session: true,
    },
    Route {
        method: "POST",
        path: "/verify-email",
        tag: "verify-email",
        session: false,
    },
    Route {
        method: "GET",
        path: "/openapi.json",
        tag: "openapi",
        session: false,
    },
    Route {
        method: "GET",
        path: "/sign-in/social/{provider}",
        tag: "social",
        session: false,
    },
    Route {
        method: "GET",
        path: "/callback/{provider}",
        tag: "social",
        session: false,
    },
];

/// Builds the OpenAPI document for this build's routes.
pub fn document(base_path: &str) -> Value {
    let mut paths = Map::new();
    for route in ROUTES {
        let mut operation = Map::new();
        operation.insert("operationId".into(), json!(operation_id(route)));
        operation.insert("tags".into(), json!([route.tag]));
        operation.insert("summary".into(), json!(summary(route)));
        if route.path.contains('{') {
            operation.insert("parameters".into(), json!(path_parameters(route.path)));
        }
        if route.session {
            operation.insert("security".into(), json!([{"sessionCookie": []}]));
        }
        operation.insert(
            "responses".into(),
            json!({
                "200": {"description": "Success", "content": {"application/json": {"schema": {"type": "object"}}}},
                "400": {"description": "Invalid request"},
                "401": {"description": "Unauthenticated or invalid credentials"},
                "403": {"description": "Forbidden by policy"},
                "429": {"description": "Rate limited"},
                "500": {"description": "Internal server error; see x-request-id"},
            }),
        );
        let entry = paths
            .entry(route.path.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(item) = entry {
            item.insert(route.method.to_ascii_lowercase(), Value::Object(operation));
        }
    }
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "better-auth-rs",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Framework-neutral authentication routes. Mounted under the base path below.",
        },
        "servers": [{"url": base_path}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "sessionCookie": {"type": "apiKey", "in": "cookie", "name": "better-auth.session_token"}
            }
        }
    })
}

fn operation_id(route: &Route) -> String {
    let mut out = route.method.to_ascii_lowercase();
    for part in route
        .path
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|p| !p.is_empty())
    {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out
}

fn summary(route: &Route) -> String {
    route
        .path
        .split('/')
        .filter(|p| !p.is_empty() && !p.starts_with('{'))
        .collect::<Vec<_>>()
        .join(" ")
        .replace('-', " ")
}

fn path_parameters(path: &str) -> Vec<Value> {
    path.split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .map(|name| json!({"name": name, "in": "path", "required": true, "schema": {"type": "string"}}))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTER_SOURCE: &str = include_str!("router.rs");

    #[test]
    fn every_documented_route_is_still_mounted() {
        for route in ROUTES {
            let mounted = if route.path.contains('{') {
                let prefix = route.path.split('{').next().unwrap();
                ROUTER_SOURCE.contains(&format!("path.starts_with(\"{prefix}\")"))
            } else {
                // An arm may share its line with another method, as in
                // `(Method::GET | Method::POST, "/get-session") => {`, or with a second
                // arm, as in `(Method::POST, "/a") | (Method::POST, "/b") => {`.
                let arm = format!("\"{}\")", route.path);
                let method = format!("Method::{}", route.method);
                ROUTER_SOURCE
                    .lines()
                    .any(|line| line.contains(&arm) && line.contains(&method))
            };
            assert!(
                mounted,
                "documented route {} {} is not in the router",
                route.method, route.path
            );
        }
    }

    #[test]
    fn document_describes_every_route_with_its_method() {
        let doc = document("https://example.com/api/auth");
        assert_eq!(doc["openapi"], "3.1.0");
        assert!(doc["paths"]["/sign-in/email"]["post"].is_object());
        assert!(doc["paths"]["/sign-in/social/{provider}"]["get"]["parameters"].is_array());
        assert!(doc["paths"]["/change-password"]["post"]["security"].is_array());
        let operations: usize = doc["paths"]
            .as_object()
            .unwrap()
            .values()
            .map(|item| item.as_object().unwrap().len())
            .sum();
        assert_eq!(operations, ROUTES.len());
    }
}
