use crate::context::AuthContext;
use crate::session::SessionService;
use better_auth_core::{
    adapter::{Query, SecondaryStorage},
    error::{AuthError, Result},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct StoredVerification {
    purpose: String,
    subject: String,
    expires_at: u64,
}

#[derive(Clone)]
pub struct VerificationService {
    storage: Arc<dyn SecondaryStorage>,
}

impl VerificationService {
    pub fn new(storage: Arc<dyn SecondaryStorage>) -> Self {
        Self { storage }
    }

    pub async fn issue(&self, purpose: &str, subject: &str, ttl: Duration) -> Result<String> {
        if purpose.trim().is_empty() || subject.trim().is_empty() || ttl.is_zero() {
            return Err(AuthError::InvalidRequest(
                "verification parameters are invalid".into(),
            ));
        }
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let record = StoredVerification {
            purpose: purpose.to_owned(),
            subject: subject.to_owned(),
            expires_at: now_seconds() + ttl.as_secs(),
        };
        self.storage
            .set(
                &verification_key(purpose, &token),
                better_auth_core::StorageValue::with_ttl(
                    serde_json::to_value(record).map_err(serialize_error)?,
                    ttl,
                ),
            )
            .await?;
        Ok(token)
    }

    pub async fn consume(&self, purpose: &str, token: &str) -> Result<Option<String>> {
        let Some(value) = self
            .storage
            .get_and_delete(&verification_key(purpose, token))
            .await?
        else {
            return Ok(None);
        };
        let record: StoredVerification =
            serde_json::from_value(value.value).map_err(serialize_error)?;
        if record.purpose != purpose || record.expires_at <= now_seconds() {
            return Ok(None);
        }
        Ok(Some(record.subject))
    }
}

#[derive(Clone)]
pub struct EmailVerificationService {
    context: AuthContext,
    verification: VerificationService,
}

impl EmailVerificationService {
    pub fn new(context: AuthContext, storage: Arc<dyn SecondaryStorage>) -> Self {
        Self {
            context,
            verification: VerificationService::new(storage),
        }
    }

    pub async fn issue(&self, user_id: &str, ttl: Duration) -> Result<String> {
        if self
            .context
            .adapter
            .find_one("user", Query::new().eq("id", user_id.to_owned()))
            .await?
            .is_none()
        {
            return Err(AuthError::NotFound);
        }
        self.verification
            .issue("email-verification", user_id, ttl)
            .await
    }

    pub async fn verify(&self, token: &str) -> Result<bool> {
        let Some(user_id) = self
            .verification
            .consume("email-verification", token)
            .await?
        else {
            return Ok(false);
        };
        let mut user = self
            .context
            .adapter
            .find_one("user", Query::new().eq("id", user_id.clone()))
            .await?
            .ok_or(AuthError::NotFound)?;
        user["email_verified"] = true.into();
        self.context
            .adapter
            .update_where("user", Query::new().eq("id", user_id), user)
            .await?;
        Ok(true)
    }
}

#[derive(Clone)]
pub struct PasswordResetService {
    context: AuthContext,
    verification: VerificationService,
    sessions: SessionService,
}

impl PasswordResetService {
    pub fn new(context: AuthContext, storage: Arc<dyn SecondaryStorage>) -> Result<Self> {
        Ok(Self {
            sessions: SessionService::new(context.clone())?,
            context,
            verification: VerificationService::new(storage),
        })
    }

    pub async fn issue(&self, email: &str, ttl: Duration) -> Result<Option<String>> {
        let email = email.trim().to_ascii_lowercase();
        let Some(user) = self
            .context
            .adapter
            .find_one("user", Query::new().eq("email", email))
            .await?
        else {
            return Ok(None);
        };
        let user_id = user
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AuthError::Adapter("user record has no id".into()))?;
        Ok(Some(
            self.verification
                .issue("password-reset", user_id, ttl)
                .await?,
        ))
    }

    pub async fn reset(&self, token: &str, new_password: &str) -> Result<bool> {
        if new_password.is_empty() {
            return Err(AuthError::InvalidRequest("password cannot be empty".into()));
        }
        let Some(user_id) = self.verification.consume("password-reset", token).await? else {
            return Ok(false);
        };
        let account_id = format!("{user_id}:credential");
        let Some(mut account) = self
            .context
            .adapter
            .find_one("account", Query::new().eq("id", account_id.clone()))
            .await?
        else {
            return Err(AuthError::NotFound);
        };
        account["password_hash"] = self
            .context
            .password_provider
            .hash(new_password)
            .await?
            .into();
        self.context
            .adapter
            .update_where("account", Query::new().eq("id", account_id), account)
            .await?;
        self.sessions.revoke_all_for_user(&user_id).await?;
        self.context.after_password_change(&user_id).await?;
        Ok(true)
    }
}

fn verification_key(purpose: &str, token: &str) -> String {
    format!("verification:{purpose}:{}", hash_token(token))
}

fn hash_token(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

fn serialize_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Adapter(format!("verification serialization failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email_password::{EmailPasswordService, SignUpInput};
    use better_auth_core::{
        adapter::memory::{MemoryDb, MemorySecondaryStorage},
        options::{AuthOptions, BaseUrl},
    };

    #[tokio::test]
    async fn verification_tokens_are_single_use_and_purpose_bound() {
        let service = VerificationService::new(Arc::new(MemorySecondaryStorage::default()));
        let token = service
            .issue("email", "user-1", Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(service.consume("password", &token).await.unwrap(), None);
        assert_eq!(
            service.consume("email", &token).await.unwrap(),
            Some("user-1".into())
        );
        assert_eq!(service.consume("email", &token).await.unwrap(), None);
    }

    #[tokio::test]
    async fn password_reset_revokes_existing_sessions() {
        let adapter = Arc::new(MemoryDb::default());
        let storage = Arc::new(MemorySecondaryStorage::default());
        let context = AuthContext::new(
            AuthOptions {
                secret: "p".repeat(32),
                base_url: Some(BaseUrl::Static("https://example.com".into())),
                ..AuthOptions::default()
            },
            adapter,
            Some(storage.clone()),
            Vec::new(),
        )
        .unwrap();
        let email = EmailPasswordService::new(context.clone()).unwrap();
        let result = email
            .sign_up(
                SignUpInput {
                    email: "reset@example.com".into(),
                    name: "Reset User".into(),
                    password: "old password".into(),
                },
                true,
            )
            .await
            .unwrap();
        let reset = PasswordResetService::new(context, storage).unwrap();
        let token = reset
            .issue("reset@example.com", Duration::from_secs(60))
            .await
            .unwrap()
            .unwrap();
        assert!(reset.reset(&token, "new password").await.unwrap());

        let mut headers = http::HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {}", result.session_token).parse().unwrap(),
        );
        assert!(email
            .sessions()
            .resolve_with_transport(&headers, true, crate::session::SessionTransport::Bearer)
            .await
            .unwrap()
            .is_none());
    }
}
