//! Google One Tap: sign in with an ID token the browser received from Google.
//!
//! The ID token is verified against Google's keys, issuer and audience. It must
//! carry a verified email. Each token is accepted once: its `(sub, iat)` pair is
//! claimed atomically in secondary storage, so a copied token cannot be replayed.

use crate::{
    context::AuthContext, email_password::User, oidc::OidcIdTokenValidator,
    passwordless::PasswordlessService,
};
use better_auth_core::{
    adapter::SecondaryStorage,
    error::{AuthError, Result},
};
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub struct OneTapService {
    validator: OidcIdTokenValidator,
    storage: Arc<dyn SecondaryStorage>,
    passwordless: PasswordlessService,
}

impl OneTapService {
    pub fn new(context: AuthContext, validator: OidcIdTokenValidator) -> Result<Self> {
        let storage = context.secondary_storage.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration("one-tap requires secondary storage".into())
        })?;
        Ok(Self {
            validator,
            storage,
            passwordless: PasswordlessService::new(context)?,
        })
    }

    /// Verifies the credential and returns the signed-in user.
    pub async fn sign_in(&self, credential: &str) -> Result<User> {
        let claims = self.validator.validate(credential, None)?;
        if claims.email_verified != Some(true) {
            return Err(AuthError::Forbidden(
                "the Google account email is not verified".into(),
            ));
        }
        let email = claims
            .email
            .as_deref()
            .ok_or_else(|| AuthError::InvalidRequest("ID token has no email".into()))?
            .trim()
            .to_ascii_lowercase();
        let remaining = claims.exp as u64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let ttl = Duration::from_secs(remaining.saturating_sub(now).max(1) + 60);
        let claimed = self
            .storage
            .increment(&format!("one-tap:{}:{}", claims.sub, claims.iat), 1, ttl)
            .await?;
        if claimed != 1 {
            return Err(AuthError::Unauthorized);
        }
        self.passwordless.sign_in_verified_email(&email).await
    }
}
