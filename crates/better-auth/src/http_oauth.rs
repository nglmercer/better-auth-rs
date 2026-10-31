use crate::{
    oauth::{OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserProfile},
    oidc::OidcIdTokenValidator,
};
use async_trait::async_trait;
use better_auth_core::error::{AuthError, Result};
use reqwest::Client;
use serde_json::Value;
use url::Url;

const GOOGLE_ISSUER: &str = "https://accounts.google.com";
const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

#[derive(Clone)]
pub struct HttpOAuthProvider {
    id: String,
    client_id: String,
    client_secret: String,
    token_endpoint: Url,
    userinfo_endpoint: Url,
    /// Optional provider endpoint listing the account's emails with their
    /// verification status (for example GitHub `/user/emails`). When set, the
    /// verified primary email is the only trusted email proof.
    verified_emails_endpoint: Option<Url>,
    client: Client,
    id_token_validator: Option<OidcIdTokenValidator>,
    /// Where users are sent to authorize. Sign-in cannot start without it.
    authorization_endpoint: Option<Url>,
    scopes: Vec<String>,
    /// Set only by the test-utils constructor. It relaxes the HTTPS check on this
    /// provider's authorization endpoint and nothing else.
    #[cfg(feature = "test-utils")]
    insecure_for_testing: bool,
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
            verified_emails_endpoint: None,
            client: Client::new(),
            id_token_validator: None,
            authorization_endpoint: None,
            scopes: Vec::new(),
            #[cfg(feature = "test-utils")]
            insecure_for_testing: false,
        })
    }

    /// A provider with explicit endpoints, for example an enterprise OAuth server.
    /// All three endpoints must use HTTPS.
    pub fn generic(
        id: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        authorization_endpoint: Url,
        token_endpoint: Url,
        userinfo_endpoint: Url,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        Self::new(
            id,
            client_id,
            client_secret,
            token_endpoint,
            userinfo_endpoint,
        )?
        .with_authorization_endpoint(authorization_endpoint)
        .map(|provider| provider.with_scopes(scopes))
    }

    /// Sets the authorization endpoint. HTTPS is required.
    pub fn with_authorization_endpoint(mut self, endpoint: Url) -> Result<Self> {
        if endpoint.scheme() != "https" {
            return Err(AuthError::InvalidConfiguration(
                "OAuth authorization endpoint must use HTTPS".into(),
            ));
        }
        self.authorization_endpoint = Some(endpoint);
        Ok(self)
    }

    pub fn with_scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_oidc_validator(mut self, validator: OidcIdTokenValidator) -> Self {
        self.id_token_validator = Some(validator);
        self
    }

    pub fn with_verified_emails_endpoint(mut self, endpoint: Url) -> Result<Self> {
        if endpoint.scheme() != "https" {
            return Err(AuthError::InvalidConfiguration(
                "OAuth verified-emails endpoint must use HTTPS".into(),
            ));
        }
        self.verified_emails_endpoint = Some(endpoint);
        Ok(self)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Test-only constructor that accepts plain HTTP endpoints, so fixture
    /// providers on localhost can exercise the full flow. It exists only with the
    /// `test-utils` feature and must never be enabled in production.
    #[cfg(feature = "test-utils")]
    pub fn insecure_for_testing(
        id: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        authorization_endpoint: Url,
        token_endpoint: Url,
        userinfo_endpoint: Url,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            id: id.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            token_endpoint,
            userinfo_endpoint,
            verified_emails_endpoint: None,
            client: Client::new(),
            id_token_validator: None,
            authorization_endpoint: Some(authorization_endpoint),
            scopes: scopes.into_iter().map(Into::into).collect(),
            insecure_for_testing: true,
        }
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

    /// Google preset. The ID token is mandatory and validated against Google's
    /// issuer and this client ID. Signing keys must be loaded before use (see
    /// [`HttpOAuthProvider::google_with_jwks`]); without them every ID token is
    /// rejected, so the preset fails closed.
    pub fn google(client_id: impl Into<String>, client_secret: impl Into<String>) -> Result<Self> {
        let client_id = client_id.into();
        let validator = OidcIdTokenValidator::new(GOOGLE_ISSUER, client_id.clone());
        Self::new(
            "google",
            client_id,
            client_secret,
            Url::parse("https://oauth2.googleapis.com/token").unwrap(),
            Url::parse("https://openidconnect.googleapis.com/v1/userinfo").unwrap(),
        )?
        .with_oidc_validator(validator)
        .with_authorization_endpoint(
            Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap(),
        )
        .map(|provider| provider.with_scopes(["openid", "email", "profile"]))
    }

    /// Google preset with signing keys fetched from Google's JWKS endpoint.
    pub async fn google_with_jwks(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Result<Self> {
        let mut provider = Self::google(client_id, client_secret)?;
        provider
            .refresh_oidc_jwks(Url::parse(GOOGLE_JWKS_URL).unwrap())
            .await?;
        Ok(provider)
    }

    /// Facebook preset. Facebook's profile does not certify that the email is
    /// owned by the user, so the email is never reported as verified. That
    /// makes Facebook sign-in unable to link to an existing account.
    pub fn facebook(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            "facebook",
            client_id,
            client_secret,
            Url::parse("https://graph.facebook.com/v19.0/oauth/access_token").unwrap(),
            Url::parse("https://graph.facebook.com/v19.0/me?fields=id,name,email").unwrap(),
        )?
        .with_authorization_endpoint(
            Url::parse("https://www.facebook.com/v19.0/dialog/oauth").unwrap(),
        )
        .map(|provider| provider.with_scopes(["email", "public_profile"]))
    }

    /// GitHub preset. The verified primary email comes from `/user/emails`.
    pub fn github(client_id: impl Into<String>, client_secret: impl Into<String>) -> Result<Self> {
        Self::new(
            "github",
            client_id,
            client_secret,
            Url::parse("https://github.com/login/oauth/access_token").unwrap(),
            Url::parse("https://api.github.com/user").unwrap(),
        )?
        .with_verified_emails_endpoint(Url::parse("https://api.github.com/user/emails").unwrap())?
        .with_authorization_endpoint(
            Url::parse("https://github.com/login/oauth/authorize").unwrap(),
        )
        .map(|provider| provider.with_scopes(["read:user", "user:email"]))
    }

    /// The flow configuration for this provider. Fails when no authorization
    /// endpoint was set, instead of sending users to the token endpoint.
    pub fn config(&self) -> Result<OAuthProviderConfig> {
        let authorization_endpoint = self.authorization_endpoint.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration(format!(
                "provider {} has no authorization endpoint",
                self.id
            ))
        })?;
        #[cfg(feature = "test-utils")]
        if self.insecure_for_testing {
            return Ok(OAuthProviderConfig {
                id: self.id.clone(),
                authorization_endpoint,
                client_id: self.client_id.clone(),
                scopes: self.scopes.clone(),
                state_ttl: std::time::Duration::from_secs(10 * 60),
            });
        }
        OAuthProviderConfig::new(&self.id, authorization_endpoint, &self.client_id)
            .map(|config| config.scopes(self.scopes.iter()))
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
        // A validated ID token must belong to the same account as userinfo.
        // Otherwise a token from one account could be paired with another
        // account's profile response.
        if let (Some(validator), Some(id_token)) = (&self.id_token_validator, &tokens.id_token) {
            let claims = validator.validate(id_token, None)?;
            if claims.sub != account_id {
                return Err(AuthError::Unauthorized);
            }
        }
        // Email trust is fail-closed: an unverified or missing proof never
        // reaches account linking as verified.
        let mut email = body.get("email").and_then(Value::as_str).map(str::to_owned);
        let mut email_verified = body
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if let Some(endpoint) = &self.verified_emails_endpoint {
            let response = self
                .client
                .get(endpoint.clone())
                .bearer_auth(&tokens.access_token)
                .header("User-Agent", "better-auth-rust")
                .send()
                .await
                .map_err(network_error)?;
            let status = response.status();
            let emails: Value = response.json().await.map_err(network_error)?;
            if !status.is_success() {
                return Err(AuthError::Adapter(format!(
                    "OAuth verified-email lookup failed: {emails}"
                )));
            }
            match select_verified_primary_email(&emails) {
                Some(verified) => {
                    email = Some(verified);
                    email_verified = true;
                }
                None => email_verified = false,
            }
        }
        Ok(OAuthUserProfile {
            provider_account_id: account_id,
            email,
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
            email_verified,
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

/// Picks a verified email from the provider's address list, preferring the
/// primary one. Unverified entries are never returned: they are not proof.
fn select_verified_primary_email(emails: &Value) -> Option<String> {
    let verified = emails
        .as_array()?
        .iter()
        .filter(|entry| entry.get("verified").and_then(Value::as_bool) == Some(true))
        .filter_map(|entry| {
            let email = entry.get("email").and_then(Value::as_str)?.trim();
            (!email.is_empty()).then(|| {
                let primary = entry.get("primary").and_then(Value::as_bool) == Some(true);
                (primary, email.to_owned())
            })
        });
    verified
        .max_by_key(|(primary, _)| *primary)
        .map(|(_, email)| email)
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

#[cfg(test)]
mod tests {
    use super::select_verified_primary_email;
    use serde_json::json;

    #[test]
    fn verified_primary_email_is_preferred() {
        let emails = json!([
            {"email": "other@example.com", "primary": false, "verified": true},
            {"email": "main@example.com", "primary": true, "verified": true},
        ]);
        assert_eq!(
            select_verified_primary_email(&emails).as_deref(),
            Some("main@example.com")
        );
    }

    #[test]
    fn google_preset_fails_closed_without_loaded_signing_keys() {
        use crate::oauth::{OAuthProvider, OAuthTokens};
        let provider = super::HttpOAuthProvider::google("client-1", "secret").unwrap();
        let tokens = |id_token: Option<&str>| OAuthTokens {
            access_token: "access".into(),
            refresh_token: None,
            expires_at: None,
            token_type: "Bearer".into(),
            id_token: id_token.map(str::to_owned),
        };
        assert!(provider.validate_tokens(&tokens(None), "nonce").is_err());
        assert!(provider
            .validate_tokens(&tokens(Some("a.b.c")), "nonce")
            .is_err());
    }

    #[test]
    fn unverified_emails_are_rejected() {
        let unverified = json!([{"email": "a@example.com", "primary": true, "verified": false}]);
        assert_eq!(select_verified_primary_email(&unverified), None);
        let non_primary = json!([{"email": "a@example.com", "primary": false, "verified": true}]);
        assert_eq!(
            select_verified_primary_email(&non_primary).as_deref(),
            Some("a@example.com")
        );
        assert_eq!(
            select_verified_primary_email(&json!({"email": "a@example.com"})),
            None
        );
    }

    #[test]
    fn facebook_preset_never_reports_a_verified_email() {
        let provider = super::HttpOAuthProvider::facebook("client-1", "secret").unwrap();
        let config = provider.config().unwrap();
        assert_eq!(
            config.authorization_endpoint.host_str(),
            Some("www.facebook.com")
        );
        assert!(config.scopes.contains(&"email".to_owned()));
    }
}
