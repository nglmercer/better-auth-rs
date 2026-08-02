use crate::cookies::{CookieCacheClaims, CookieCacheCodec, SecretKeySet};
use better_auth_core::{error::Result, options::CookieCacheStrategy, AuthOptions};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct JwtService {
    codec: CookieCacheCodec,
}

impl JwtService {
    pub fn from_options(options: &AuthOptions) -> Result<Self> {
        Ok(Self {
            codec: CookieCacheCodec::new(SecretKeySet::from_options(options)?),
        })
    }

    pub fn issue(
        &self,
        subject: impl Into<String>,
        data: Value,
        expires_at: u64,
    ) -> Result<String> {
        self.codec.encode(
            CookieCacheStrategy::Jwt,
            subject,
            data,
            now_seconds(),
            expires_at,
        )
    }

    pub fn verify(&self, token: &str) -> Result<CookieCacheClaims> {
        self.codec
            .decode(CookieCacheStrategy::Jwt, token, now_seconds())
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::options::AuthOptions;

    #[test]
    fn jwt_service_issues_and_verifies_rotatable_tokens() {
        let options = AuthOptions {
            secret: "j".repeat(32),
            ..AuthOptions::default()
        };
        let service = JwtService::from_options(&options).unwrap();
        let token = service
            .issue(
                "user-1",
                serde_json::json!({"role": "admin"}),
                now_seconds() + 60,
            )
            .unwrap();
        let claims = service.verify(&token).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.data["role"], "admin");
    }
}
