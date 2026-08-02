use better_auth_core::{
    adapter::SecondaryStorage,
    error::{AuthError, Result},
};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitPolicy {
    pub name: String,
    pub limit: i64,
    pub window: Duration,
}

impl RateLimitPolicy {
    pub fn new(name: impl Into<String>, limit: i64, window: Duration) -> Result<Self> {
        if limit <= 0 || window.is_zero() {
            return Err(AuthError::InvalidConfiguration(
                "rate-limit limit and window must be positive".into(),
            ));
        }
        Ok(Self {
            name: name.into(),
            limit,
            window,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub limit: i64,
    pub remaining: i64,
    pub retry_after_seconds: u64,
}

impl RateLimitDecision {
    pub fn headers(&self) -> [(String, String); 3] {
        [
            ("RateLimit-Limit".into(), self.limit.to_string()),
            ("RateLimit-Remaining".into(), self.remaining.to_string()),
            ("Retry-After".into(), self.retry_after_seconds.to_string()),
        ]
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    storage: Arc<dyn SecondaryStorage>,
    namespace: String,
}

impl RateLimiter {
    pub fn new(storage: Arc<dyn SecondaryStorage>, namespace: impl Into<String>) -> Self {
        Self {
            storage,
            namespace: namespace.into(),
        }
    }

    pub async fn check(
        &self,
        policy: &RateLimitPolicy,
        identity: &str,
    ) -> Result<RateLimitDecision> {
        let key = format!(
            "{}:{}:{}",
            self.namespace,
            policy.name,
            stable_identity(identity)
        );
        let count = self.storage.increment(&key, 1, policy.window).await?;
        let allowed = count <= policy.limit;
        Ok(RateLimitDecision {
            allowed,
            limit: policy.limit,
            remaining: (policy.limit - count).max(0),
            retry_after_seconds: policy.window.as_secs().max(1),
        })
    }

    pub async fn enforce(&self, policy: &RateLimitPolicy, identity: &str) -> Result<()> {
        let decision = self.check(policy, identity).await?;
        if decision.allowed {
            Ok(())
        } else {
            Err(AuthError::RateLimited {
                retry_after_seconds: decision.retry_after_seconds,
            })
        }
    }
}

fn stable_identity(identity: &str) -> String {
    Sha256::digest(identity.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::adapter::memory::MemorySecondaryStorage;

    #[tokio::test]
    async fn rate_limit_decision_tracks_remaining_capacity() {
        let limiter = RateLimiter::new(Arc::new(MemorySecondaryStorage::default()), "auth");
        let policy = RateLimitPolicy::new("sign-in", 2, Duration::from_secs(60)).unwrap();
        assert!(
            limiter
                .check(&policy, "user@example.com")
                .await
                .unwrap()
                .allowed
        );
        assert!(
            limiter
                .check(&policy, "user@example.com")
                .await
                .unwrap()
                .allowed
        );
        let decision = limiter.check(&policy, "user@example.com").await.unwrap();
        assert!(!decision.allowed);
        assert_eq!(decision.remaining, 0);
        assert!(limiter.enforce(&policy, "user@example.com").await.is_err());
    }
}
