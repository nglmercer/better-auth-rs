//! One-time tokens: short-lived, purpose-bound, single-use bearer values.
//!
//! The token is random and only its hash is stored. Verifying consumes it, so a
//! replay fails. The owner can revoke it earlier. Purposes are fixed by the
//! application (for example `"device-link"`), and a token for one purpose is
//! never accepted for another.

use crate::verification::VerificationService;
use better_auth_core::{
    adapter::SecondaryStorage,
    error::{AuthError, Result},
};
use std::{sync::Arc, time::Duration};

pub const MAX_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
pub struct OneTimeTokenService {
    verification: VerificationService,
}

impl OneTimeTokenService {
    pub fn new(storage: Arc<dyn SecondaryStorage>) -> Self {
        Self {
            verification: VerificationService::new(storage),
        }
    }

    /// Issues a token for `user_id`. The lifetime is capped at fifteen minutes.
    pub async fn generate(&self, user_id: &str, purpose: &str, ttl: Duration) -> Result<String> {
        validate_purpose(purpose)?;
        if ttl.is_zero() || ttl > MAX_TTL {
            return Err(AuthError::InvalidRequest(
                "token lifetime must be between 1 second and 15 minutes".into(),
            ));
        }
        self.verification
            .issue(&scoped(purpose), user_id, ttl)
            .await
    }

    /// Consumes the token and returns the user it was issued to.
    pub async fn verify(&self, purpose: &str, token: &str) -> Result<Option<String>> {
        validate_purpose(purpose)?;
        self.verification.consume(&scoped(purpose), token).await
    }

    /// Revokes a token the caller owns. Returns `false` for tokens that do not
    /// exist, have expired, or belong to someone else.
    pub async fn revoke(&self, user_id: &str, purpose: &str, token: &str) -> Result<bool> {
        validate_purpose(purpose)?;
        self.verification
            .revoke_for_subject(&scoped(purpose), token, user_id)
            .await
    }
}

fn scoped(purpose: &str) -> String {
    format!("one-time:{purpose}")
}

fn validate_purpose(purpose: &str) -> Result<()> {
    let valid = (1..=32).contains(&purpose.len())
        && purpose
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if valid {
        Ok(())
    } else {
        Err(AuthError::InvalidRequest(
            "purpose must be 1-32 lowercase letters, digits or '-'".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::adapter::memory::MemorySecondaryStorage;

    #[tokio::test]
    async fn one_time_tokens_are_single_use_owned_and_purpose_bound() {
        let service = OneTimeTokenService::new(Arc::new(MemorySecondaryStorage::default()));
        let ttl = Duration::from_secs(60);
        let token = service
            .generate("user-1", "device-link", ttl)
            .await
            .unwrap();
        assert_eq!(
            service.verify("other-purpose", &token).await.unwrap(),
            None,
            "a token is bound to its purpose"
        );
        assert!(!service
            .revoke("user-2", "device-link", &token)
            .await
            .unwrap());
        assert_eq!(
            service
                .verify("device-link", &token)
                .await
                .unwrap()
                .as_deref(),
            Some("user-1")
        );
        assert_eq!(service.verify("device-link", &token).await.unwrap(), None);

        let revoked = service
            .generate("user-1", "device-link", ttl)
            .await
            .unwrap();
        assert!(service
            .revoke("user-1", "device-link", &revoked)
            .await
            .unwrap());
        assert_eq!(service.verify("device-link", &revoked).await.unwrap(), None);
        assert!(service
            .generate("user-1", "device-link", MAX_TTL + ttl)
            .await
            .is_err());
        assert!(service
            .generate("user-1", "Bad Purpose", ttl)
            .await
            .is_err());
    }
}
