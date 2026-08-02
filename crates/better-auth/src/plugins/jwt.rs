use super::shared::endpoint;
use better_auth_core::plugin::{Endpoint, Plugin};
use http::Method;

#[derive(Clone, Copy, Debug, Default)]
pub struct JwtPlugin;

impl Plugin for JwtPlugin {
    fn name(&self) -> &'static str {
        "jwt"
    }
    fn endpoints(&self) -> Vec<Endpoint> {
        vec![endpoint(
            Method::GET,
            "/token",
            "Issue a JWT for the current session",
        )]
    }
    fn error_codes(&self) -> std::collections::BTreeMap<String, String> {
        [("JWT_INVALID".into(), "JWT is invalid or expired".into())]
            .into_iter()
            .collect()
    }
}
