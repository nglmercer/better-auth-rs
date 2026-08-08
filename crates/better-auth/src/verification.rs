use crate::{context::AuthContext, hash_password_async};
use better_auth_core::{
    adapter::SecondaryStorage,
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
        if self.context.adapter.get("user", user_id).await?.is_none() {
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
            .get("user", &user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        user["email_verified"] = true.into();
        self.context.adapter.update("user", &user_id, user).await?;
        Ok(true)
    }
}

#[derive(Clone)]
pub struct PasswordResetService {
    context: AuthContext,
    verification: VerificationService,
}

impl PasswordResetService {
    pub fn new(context: AuthContext, storage: Arc<dyn SecondaryStorage>) -> Self {
        Self {
            context,
            verification: VerificationService::new(storage),
        }
    }

    pub async fn issue(&self, email: &str, ttl: Duration) -> Result<Option<String>> {
        let email = email.trim().to_ascii_lowercase();
        let Some((_, user)) = self
            .context
            .adapter
            .get_by_field("user", "email", &serde_json::Value::String(email))
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
        let Some(mut account) = self.context.adapter.get("account", &account_id).await? else {
            return Err(AuthError::NotFound);
        };
        account["password_hash"] =
            hash_password_async(new_password, &self.context.options.password_hash)
                .await?
                .into();
        self.context
            .adapter
            .update("account", &account_id, account)
            .await?;
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
    use better_auth_core::adapter::memory::MemorySecondaryStorage;

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
}
