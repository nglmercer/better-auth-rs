//! Self-refreshing JSON Web Key Set for OIDC ID-token verification.
//!
//! The cache keeps one verified snapshot of a provider's signing keys and
//! refreshes it when either:
//! - the snapshot is older than [`JwksRefreshPolicy::refresh_after`] (scheduled), or
//! - a token names a `kid` the snapshot does not contain (rotation).
//!
//! Failures never widen trust. A failed refresh keeps the last verified keys
//! only until [`JwksRefreshPolicy::max_stale`] has passed since they were
//! fetched; after that, and whenever no keys have ever been loaded, every token
//! is refused. Fetch attempts are rate limited, and concurrent refreshes share
//! one request, so a flood of tokens with random `kid` values cannot turn into
//! a flood of requests to the provider.

use crate::{oidc::OidcIdTokenValidator, security::validate_public_https_endpoint};
use better_auth_core::error::{AuthError, Result};
use reqwest::Client;
use serde_json::Value;
use std::{
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use url::Url;

/// Largest JWKS document accepted. Real provider sets are a few kilobytes.
const MAX_JWKS_BYTES: usize = 64 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// How long verified signing keys are trusted and how often they are refetched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JwksRefreshPolicy {
    /// Refetch the key set once the current snapshot is this old.
    pub refresh_after: Duration,
    /// Stop trusting a snapshot this long after it was fetched, even if
    /// refreshes keep failing. Must be at least `refresh_after`.
    pub max_stale: Duration,
    /// Minimum time between fetch attempts, successful or not.
    pub min_retry_interval: Duration,
}

impl Default for JwksRefreshPolicy {
    fn default() -> Self {
        Self {
            refresh_after: Duration::from_secs(60 * 60),
            max_stale: Duration::from_secs(24 * 60 * 60),
            min_retry_interval: Duration::from_secs(60),
        }
    }
}

impl JwksRefreshPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.refresh_after.is_zero() {
            return Err(AuthError::InvalidConfiguration(
                "JWKS refresh_after must be greater than zero".into(),
            ));
        }
        if self.max_stale < self.refresh_after {
            return Err(AuthError::InvalidConfiguration(
                "JWKS max_stale must be at least refresh_after".into(),
            ));
        }
        Ok(())
    }
}

struct Snapshot {
    validator: Arc<OidcIdTokenValidator>,
    fetched_at: u64,
}

#[derive(Default)]
struct State {
    snapshot: Option<Snapshot>,
    last_attempt: Option<u64>,
}

/// A JWKS endpoint with a verified, expiring cache of its keys.
pub(crate) struct JwksKeySource {
    /// Issuer and audience for the validators built from fetched keys. Holds no keys.
    template: OidcIdTokenValidator,
    url: Url,
    policy: JwksRefreshPolicy,
    client: Client,
    /// Plain HTTP is allowed only by the `test-utils` constructor. This flag
    /// is false in every production path.
    allow_plain_http: bool,
    state: RwLock<State>,
    refresh_gate: Mutex<()>,
}

impl JwksKeySource {
    pub(crate) fn new(
        template: OidcIdTokenValidator,
        url: Url,
        policy: JwksRefreshPolicy,
        client: Client,
        allow_plain_http: bool,
    ) -> Result<Self> {
        policy.validate()?;
        if !allow_plain_http {
            validate_public_https_endpoint(&url, "OIDC JWKS endpoint")?;
        }
        Ok(Self {
            template,
            url,
            policy,
            client,
            allow_plain_http,
            state: RwLock::new(State::default()),
            refresh_gate: Mutex::new(()),
        })
    }

    /// The same provider settings with a different endpoint or policy. The cache starts empty.
    pub(crate) fn rebuilt(&self, url: Url, policy: JwksRefreshPolicy) -> Result<Self> {
        Self::new(
            self.template.clone(),
            url,
            policy,
            self.client.clone(),
            self.allow_plain_http,
        )
    }

    pub(crate) fn url(&self) -> &Url {
        &self.url
    }

    /// Fetches the key set now, ignoring the schedule. Errors are returned to
    /// the caller. Used at startup, where an unreachable provider should fail loudly.
    pub(crate) async fn refresh_now(&self) -> Result<usize> {
        let _gate = self.refresh_gate.lock().await;
        let now = now_seconds();
        self.write_state().last_attempt = Some(now);
        let validator = self.fetch().await?;
        let count = validator.key_count();
        self.write_state().snapshot = Some(Snapshot {
            validator: Arc::new(validator),
            fetched_at: now,
        });
        Ok(count)
    }

    /// Refreshes the key set when the schedule or the token's `kid` requires it.
    /// A failed refresh is logged and not returned: the caller then verifies
    /// against whatever is still trusted, and [`Self::current`] decides whether that is allowed.
    pub(crate) async fn ensure(&self, key_id: Option<&str>) {
        if !self.needs_refresh(now_seconds(), key_id) {
            return;
        }
        let _gate = self.refresh_gate.lock().await;
        // Another request may have refreshed while this one waited for the gate.
        let now = now_seconds();
        if !self.needs_refresh(now, key_id) {
            return;
        }
        self.write_state().last_attempt = Some(now);
        match self.fetch().await {
            Ok(validator) => {
                self.write_state().snapshot = Some(Snapshot {
                    validator: Arc::new(validator),
                    fetched_at: now,
                });
            }
            Err(error) => {
                tracing::warn!(
                    target: "better_auth::oidc",
                    error = %error,
                    "OIDC JWKS refresh failed; verification uses only keys that are still within max_stale"
                );
            }
        }
    }

    /// The validator for the current snapshot. Fails closed when no keys have
    /// been loaded or the snapshot is older than `max_stale`.
    pub(crate) fn current(&self, now: u64) -> Result<Arc<OidcIdTokenValidator>> {
        let state = self.read_state();
        match &state.snapshot {
            Some(snapshot)
                if now.saturating_sub(snapshot.fetched_at) <= self.policy.max_stale.as_secs() =>
            {
                Ok(snapshot.validator.clone())
            }
            _ => {
                tracing::warn!(
                    target: "better_auth::oidc",
                    "OIDC signing keys are unavailable or expired; refusing ID token"
                );
                Err(AuthError::Adapter(
                    "OIDC signing keys are unavailable".into(),
                ))
            }
        }
    }

    fn needs_refresh(&self, now: u64, key_id: Option<&str>) -> bool {
        let state = self.read_state();
        let retry_allowed = state.last_attempt.is_none_or(|last| {
            now.saturating_sub(last) >= self.policy.min_retry_interval.as_secs()
        });
        if !retry_allowed {
            return false;
        }
        match &state.snapshot {
            None => true,
            Some(snapshot) => {
                now.saturating_sub(snapshot.fetched_at) >= self.policy.refresh_after.as_secs()
                    || key_id.is_some_and(|key_id| !snapshot.validator.has_key(key_id))
            }
        }
    }

    async fn fetch(&self) -> Result<OidcIdTokenValidator> {
        let response = self
            .client
            .get(self.url.clone())
            .header("Accept", "application/json")
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|_| AuthError::Adapter("OIDC JWKS request failed".into()))?;
        if !response.status().is_success() {
            return Err(AuthError::Adapter(format!(
                "OIDC JWKS endpoint returned status {}",
                response.status().as_u16()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
        {
            return Err(AuthError::Adapter("OIDC JWKS document is too large".into()));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| AuthError::Adapter("OIDC JWKS body could not be read".into()))?;
        if bytes.len() > MAX_JWKS_BYTES {
            return Err(AuthError::Adapter("OIDC JWKS document is too large".into()));
        }
        let body: Value = serde_json::from_slice(&bytes)
            .map_err(|_| AuthError::Adapter("OIDC JWKS is not valid JSON".into()))?;
        self.template.with_jwks(&body)
    }

    fn read_state(&self) -> RwLockReadGuard<'_, State> {
        // A panic while the lock was held cannot leave a partially written
        // snapshot behind, so a poisoned lock is safe to read.
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write_state(&self) -> RwLockWriteGuard<'_, State> {
        self.state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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

    fn source(policy: JwksRefreshPolicy) -> JwksKeySource {
        JwksKeySource::new(
            OidcIdTokenValidator::new("https://issuer.example", "client-1"),
            Url::parse("https://keys.example/jwks").unwrap(),
            policy,
            Client::new(),
            false,
        )
        .unwrap()
    }

    #[test]
    fn policy_rejects_stale_window_shorter_than_refresh_interval() {
        let policy = JwksRefreshPolicy {
            refresh_after: Duration::from_secs(600),
            max_stale: Duration::from_secs(60),
            min_retry_interval: Duration::from_secs(1),
        };
        assert!(policy.validate().is_err());
        assert!(JwksRefreshPolicy::default().validate().is_ok());
    }

    #[test]
    fn empty_cache_refuses_every_token() {
        let source = source(JwksRefreshPolicy::default());
        assert!(source.current(now_seconds()).is_err());
    }

    #[test]
    fn plain_http_endpoints_are_refused_outside_test_builds() {
        let result = JwksKeySource::new(
            OidcIdTokenValidator::new("https://issuer.example", "client-1"),
            Url::parse("http://127.0.0.1/jwks").unwrap(),
            JwksRefreshPolicy::default(),
            Client::new(),
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_fresh_empty_cache_may_fetch_but_a_recent_failure_blocks_retries() {
        let source = source(JwksRefreshPolicy::default());
        let now = now_seconds();
        assert!(source.needs_refresh(now, None));
        source.write_state().last_attempt = Some(now);
        assert!(!source.needs_refresh(now, None));
        assert!(source.needs_refresh(now + 61, None));
    }
}

/// Google's documented issuer spellings.
const GOOGLE_ISSUER: &str = "https://accounts.google.com";
const GOOGLE_ISSUER_ALTERNATE: &str = "accounts.google.com";
const GOOGLE_JWKS: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Verifies OIDC ID tokens against a JWKS endpoint. Keys refresh on schedule and when a
/// token names an unknown `kid`, under the same rules as [`HttpOAuthProvider`]. Use it for
/// flows that verify tokens outside the OAuth redirect, such as Google One Tap.
///
/// [`HttpOAuthProvider`]: crate::http_oauth::HttpOAuthProvider
#[derive(Clone)]
pub struct JwksIdTokenVerifier {
    source: Arc<JwksKeySource>,
}

impl JwksIdTokenVerifier {
    /// A verifier for `issuer` and `audience` whose keys come from `jwks_url`. The URL must
    /// be a public HTTPS endpoint.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_url: Url,
        policy: JwksRefreshPolicy,
    ) -> Result<Self> {
        let template = OidcIdTokenValidator::new(issuer, audience);
        let source = JwksKeySource::new(template, jwks_url, policy, Client::new(), false)?;
        Ok(Self {
            source: Arc::new(source),
        })
    }

    /// Google's issuer, JWKS endpoint and default policy, for one client ID.
    pub fn google(client_id: impl Into<String>) -> Result<Self> {
        let template = OidcIdTokenValidator::new(GOOGLE_ISSUER, client_id)
            .with_alternate_issuer(GOOGLE_ISSUER_ALTERNATE);
        let url = Url::parse(GOOGLE_JWKS).expect("constant URL is valid");
        let source = JwksKeySource::new(
            template,
            url,
            JwksRefreshPolicy::default(),
            Client::new(),
            false,
        )?;
        Ok(Self {
            source: Arc::new(source),
        })
    }

    /// The JWKS endpoint keys are fetched from.
    pub fn jwks_url(&self) -> &Url {
        self.source.url()
    }

    /// Fetches the keys now. Errors are returned, so a broken endpoint fails at startup.
    pub async fn load(&self) -> Result<usize> {
        self.source.refresh_now().await
    }

    /// Verifies one token. The signature, issuer, audience, expiry and nonce must all
    /// match. Keys are refreshed first if the schedule or the token's `kid` requires it.
    pub async fn validate(
        &self,
        token: &str,
        expected_nonce: Option<&str>,
    ) -> Result<crate::oidc::OidcClaims> {
        let key_id = crate::oidc::token_key_id(token);
        self.source.ensure(key_id.as_deref()).await;
        self.source
            .current(now_seconds())?
            .validate(token, expected_nonce)
    }

    /// Test-only: a verifier whose JWKS may be a plain-HTTP localhost endpoint.
    #[cfg(feature = "test-utils")]
    pub fn insecure_for_testing(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_url: Url,
        policy: JwksRefreshPolicy,
    ) -> Result<Self> {
        let source = JwksKeySource::new(
            OidcIdTokenValidator::new(issuer, audience),
            jwks_url,
            policy,
            Client::new(),
            true,
        )?;
        Ok(Self {
            source: Arc::new(source),
        })
    }
}
