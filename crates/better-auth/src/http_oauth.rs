use crate::{
    oauth::{OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserProfile},
    oidc::OidcIdTokenValidator,
};
use async_trait::async_trait;
use better_auth_core::error::{AuthError, Result};
use reqwest::Client;
use serde_json::Value;
use url::Url;

#[derive(Clone)]
pub struct HttpOAuthProvider {
    id: String,
    client_id: String,
    client_secret: String,
    token_endpoint: Url,
    userinfo_endpoint: Url,
    client: Client,
    id_token_validator: Option<OidcIdTokenValidator>,
}

impl HttpOAuthProvider {
    pub fn new(
        id: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        token_endpoint: Url,
        userinfo_endpoint: Url,
    ) -> Result<Self> {
        if token_endpoint.scheme() != "https" || userinfo_endpoint.scheme() != "https" {
            return Err(AuthError::InvalidConfiguration(
                "OAuth token and userinfo endpoints must use HTTPS".into(),
            ));
        }
        Ok(Self {
            id: id.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            token_endpoint,
            userinfo_endpoint,
            client: Client::new(),
            id_token_validator: None,
        })
    }

    pub fn with_oidc_validator(mut self, validator: OidcIdTokenValidator) -> Self {
        self.id_token_validator = Some(validator);
        self
    }

    pub async fn refresh_oidc_jwks(&mut self, jwks_url: Url) -> Result<usize> {
        if jwks_url.scheme() != "https" {
            return Err(AuthError::InvalidConfiguration(
                "OIDC JWKS endpoint must use HTTPS".into(),
            ));
        }
        let body: Value = self
            .client
            .get(jwks_url)
            .send()
            .await
            .map_err(network_error)?
            .error_for_status()
            .map_err(network_error)?
            .json()
            .await
            .map_err(network_error)?;
        self.id_token_validator
            .as_mut()
            .ok_or_else(|| {
                AuthError::InvalidConfiguration(
                    "configure an OIDC validator before refreshing JWKS".into(),
                )
            })?
            .replace_from_jwks(&body)
    }

    pub fn google(client_id: impl Into<String>, client_secret: impl Into<String>) -> Result<Self> {
        Self::new(
            "google",
            client_id,
            client_secret,
            Url::parse("https://oauth2.googleapis.com/token").unwrap(),
            Url::parse("https://openidconnect.googleapis.com/v1/userinfo").unwrap(),
        )
    }

    pub fn github(client_id: impl Into<String>, client_secret: impl Into<String>) -> Result<Self> {
        Self::new(
            "github",
            client_id,
            client_secret,
            Url::parse("https://github.com/login/oauth/access_token").unwrap(),
            Url::parse("https://api.github.com/user").unwrap(),
        )
    }

    pub fn config(&self) -> OAuthProviderConfig {
        let authorization_endpoint = match self.id.as_str() {
            "google" => Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap(),
            "github" => Url::parse("https://github.com/login/oauth/authorize").unwrap(),
            _ => self.token_endpoint.clone(),
        };
        let config = OAuthProviderConfig::new(&self.id, authorization_endpoint, &self.client_id)
            .expect("provider endpoints are HTTPS");
        match self.id.as_str() {
            "google" => config.scopes(["openid", "email", "profile"]),
            "github" => config.scopes(["read:user", "user:email"]),
            _ => config,
        }
    }
}

#[async_trait]
impl OAuthProvider for HttpOAuthProvider {
    fn id(&self) -> &str {
        &self.id
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<OAuthTokens> {
        let response = self
            .client
            .post(self.token_endpoint.clone())
            .header("Accept", "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
            .map_err(network_error)?;
        let status = response.status();
        let body: Value = response.json().await.map_err(network_error)?;
        if !status.is_success() {
            return Err(AuthError::Adapter(format!(
                "OAuth token exchange failed: {body}"
            )));
        }
        let access_token = body
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::Adapter("OAuth response has no access_token".into()))?;
        let expires_at = body
            .get("expires_in")
            .and_then(Value::as_u64)
            .map(|seconds| now_seconds() + seconds);
        Ok(OAuthTokens {
            access_token: access_token.to_owned(),
            refresh_token: body
                .get("refresh_token")
                .and_then(Value::as_str)
                .map(str::to_owned),
            expires_at,
            token_type: body
                .get("token_type")
                .and_then(Value::as_str)
                .unwrap_or("Bearer")
                .to_owned(),
            id_token: body
                .get("id_token")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }

    async fn profile(&self, tokens: &OAuthTokens) -> Result<OAuthUserProfile> {
        let response = self
            .client
            .get(self.userinfo_endpoint.clone())
            .bearer_auth(&tokens.access_token)
            .header("User-Agent", "better-auth-rust")
            .send()
            .await
            .map_err(network_error)?;
        let status = response.status();
        let body: Value = response.json().await.map_err(network_error)?;
        if !status.is_success() {
            return Err(AuthError::Adapter(format!(
                "OAuth profile lookup failed: {body}"
            )));
        }
        let account_id = if let Some(value) = body.get("sub").and_then(Value::as_str) {
            value.to_owned()
        } else if let Some(value) = body.get("id").and_then(Value::as_i64) {
            value.to_string()
        } else if let Some(value) = body.get("id").and_then(Value::as_str) {
            value.to_owned()
        } else {
            return Err(AuthError::Adapter(
                "OAuth profile has no provider account id".into(),
            ));
        };
        Ok(OAuthUserProfile {
            provider_account_id: account_id,
            email: body.get("email").and_then(Value::as_str).map(str::to_owned),
            name: body
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| body.get("login").and_then(Value::as_str))
                .map(str::to_owned),
            image: body
                .get("picture")
                .or_else(|| body.get("avatar_url"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            email_verified: body
                .get("email_verified")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        })
    }

    fn validate_tokens(&self, tokens: &OAuthTokens, expected_nonce: &str) -> Result<()> {
        if let Some(validator) = &self.id_token_validator {
            let id_token = tokens.id_token.as_deref().ok_or(AuthError::Unauthorized)?;
            validator.validate(id_token, Some(expected_nonce))?;
        }
        Ok(())
    }
}

fn network_error(error: reqwest::Error) -> AuthError {
    AuthError::Adapter(format!("OAuth network request failed: {error}"))
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}
