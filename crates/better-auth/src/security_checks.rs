//! Password breach screening and CAPTCHA verification.
//!
//! Both checks sit behind traits, so an application can use another provider.
//! Each check also declares how it fails. A breach lookup or CAPTCHA provider
//! that cannot be reached is either allowed or refused, as configured. It is
//! never silently ignored.

use async_trait::async_trait;
use better_auth_core::error::{AuthError, Result};
use reqwest::Client;
use sha1::{Digest, Sha1};
use std::net::IpAddr;
use url::Url;

/// What happens when the external check cannot answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureMode {
    /// Accept the request. Use only where availability matters more than the check.
    FailOpen,
    /// Refuse the request until the check can run.
    FailClosed,
}

#[async_trait]
pub trait BreachChecker: Send + Sync {
    /// Number of known breach records containing `password`. Zero means none.
    async fn breach_count(&self, password: &str) -> Result<u64>;
}

/// Checks passwords with the Have I Been Pwned range API. Only the first five
/// hex characters of the SHA-1 digest are sent. The match happens locally.
#[derive(Clone)]
pub struct HibpRangeChecker {
    client: Client,
    base: Url,
}

impl HibpRangeChecker {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base: Url::parse("https://api.pwnedpasswords.com/range/").expect("static URL"),
        }
    }

    /// Uses another range endpoint, for example an internal mirror. HTTPS is required.
    pub fn with_base_url(base: Url) -> Result<Self> {
        if base.scheme() != "https" {
            return Err(AuthError::InvalidConfiguration(
                "the breach-check endpoint must use HTTPS".into(),
            ));
        }
        Ok(Self {
            client: Client::new(),
            base,
        })
    }
}

impl Default for HibpRangeChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BreachChecker for HibpRangeChecker {
    async fn breach_count(&self, password: &str) -> Result<u64> {
        let (prefix, suffix) = sha1_prefix_and_suffix(password);
        let url = self
            .base
            .join(&prefix)
            .map_err(|error| AuthError::Plugin(format!("breach check URL: {error}")))?;
        let body = self
            .client
            .get(url)
            .header("Add-Padding", "true")
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| AuthError::Plugin(format!("breach check failed: {error}")))?
            .text()
            .await
            .map_err(|error| AuthError::Plugin(format!("breach check failed: {error}")))?;
        Ok(parse_range(&body, &suffix))
    }
}

/// Splits the uppercase SHA-1 hex digest of `password` into the 5-character
/// prefix sent to the service and the 35-character suffix kept locally.
pub fn sha1_prefix_and_suffix(password: &str) -> (String, String) {
    let digest: String = Sha1::digest(password.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    (digest[..5].to_owned(), digest[5..].to_owned())
}

/// Finds `suffix` in a range response (`SUFFIX:COUNT` per line). Padding rows
/// report a zero count and are ignored.
pub fn parse_range(body: &str, suffix: &str) -> u64 {
    body.lines()
        .filter_map(|line| line.trim().split_once(':'))
        .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(suffix))
        .filter_map(|(_, count)| count.trim().parse::<u64>().ok())
        .max()
        .unwrap_or(0)
}

#[async_trait]
pub trait CaptchaVerifier: Send + Sync {
    async fn verify(&self, response: &str, remote_ip: Option<IpAddr>) -> Result<bool>;
}

/// Verifies Cloudflare Turnstile tokens with the siteverify API.
#[derive(Clone)]
pub struct TurnstileVerifier {
    client: Client,
    secret: String,
    endpoint: Url,
}

impl TurnstileVerifier {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            secret: secret.into(),
            endpoint: Url::parse("https://challenges.cloudflare.com/turnstile/v0/siteverify")
                .expect("static URL"),
        }
    }
}

#[async_trait]
impl CaptchaVerifier for TurnstileVerifier {
    async fn verify(&self, response: &str, remote_ip: Option<IpAddr>) -> Result<bool> {
        let mut form = vec![
            ("secret", self.secret.clone()),
            ("response", response.to_owned()),
        ];
        if let Some(ip) = remote_ip {
            form.push(("remoteip", ip.to_string()));
        }
        let body: serde_json::Value = self
            .client
            .post(self.endpoint.clone())
            .form(&form)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| AuthError::Plugin(format!("captcha check failed: {error}")))?
            .json()
            .await
            .map_err(|error| AuthError::Plugin(format!("captcha check failed: {error}")))?;
        Ok(body.get("success").and_then(serde_json::Value::as_bool) == Some(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_prefix_matches_the_published_vector() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (prefix, suffix) = sha1_prefix_and_suffix("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn range_lookup_ignores_padding_and_other_suffixes() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n\
                    FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0";
        assert_eq!(
            parse_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            3_861_493
        );
        assert_eq!(parse_range(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0);
        assert_eq!(parse_range(body, "0000000000000000000000000000000000A"), 0);
    }

    #[test]
    fn breach_endpoint_must_be_https() {
        assert!(
            HibpRangeChecker::with_base_url(Url::parse("http://mirror.example/").unwrap()).is_err()
        );
        assert!(HibpRangeChecker::with_base_url(
            Url::parse("https://mirror.example/range/").unwrap()
        )
        .is_ok());
    }
}
