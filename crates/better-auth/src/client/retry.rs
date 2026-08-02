use crate::router::HttpResponse;
use better_auth_core::error::{AuthError, Result};
use http::{header, StatusCode};
use std::time::Duration;

/// Retry settings for idempotent client requests.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub max_retries: usize,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 2,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(2),
        }
    }
}

impl RetryPolicy {
    pub fn new(max_retries: usize, base_delay: Duration, max_delay: Duration) -> Result<Self> {
        if base_delay.is_zero() || max_delay < base_delay {
            return Err(AuthError::InvalidConfiguration(
                "retry delays must be non-zero and max_delay must be >= base_delay".into(),
            ));
        }
        Ok(Self {
            max_retries,
            base_delay,
            max_delay,
        })
    }

    pub(super) fn delay_for(&self, retry_index: usize) -> Duration {
        let exponent = retry_index.min(u32::BITS as usize - 1) as u32;
        self.base_delay
            .checked_mul(1_u32 << exponent)
            .unwrap_or(self.max_delay)
            .min(self.max_delay)
    }
}

pub(super) fn retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_EARLY
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

pub(super) fn retry_after(response: &HttpResponse) -> Option<Duration> {
    response
        .headers
        .get(header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_policy_caps_exponential_backoff() {
        let policy =
            RetryPolicy::new(3, Duration::from_millis(10), Duration::from_millis(15)).unwrap();
        assert_eq!(policy.delay_for(0), Duration::from_millis(10));
        assert_eq!(policy.delay_for(1), Duration::from_millis(15));
        assert_eq!(policy.delay_for(2), Duration::from_millis(15));
    }
}
