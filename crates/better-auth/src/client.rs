use crate::{
    email_password::{SignInInput, SignUpInput, User},
    router::{HttpRequest, HttpResponse},
};
use better_auth_core::error::{AuthError, Result};
use http::{header, HeaderMap, Method, Uri};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::time::Duration;
use url::Url;

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

    fn delay_for(&self, retry_index: usize) -> Duration {
        let exponent = retry_index.min(u32::BITS as usize - 1) as u32;
        self.base_delay
            .checked_mul(1_u32 << exponent)
            .unwrap_or(self.max_delay)
            .min(self.max_delay)
    }
}

#[derive(Clone, Debug)]
pub struct AuthClient {
    base_url: Url,
}

impl AuthClient {
    pub fn new(base_url: Url) -> Result<Self> {
        if !matches!(base_url.scheme(), "http" | "https") || base_url.host_str().is_none() {
            return Err(AuthError::InvalidConfiguration(
                "client base URL must have an HTTP(S) host".into(),
            ));
        }
        Ok(Self { base_url })
    }

    pub fn sign_up_email(&self, input: SignUpInput) -> Result<HttpRequest> {
        self.json_request(Method::POST, "/sign-up/email", &input)
    }

    pub fn sign_in_email(&self, input: SignInInput) -> Result<HttpRequest> {
        self.json_request(Method::POST, "/sign-in/email", &input)
    }

    pub fn get_session(&self) -> Result<HttpRequest> {
        self.request(Method::GET, "/get-session", None)
    }

    pub fn sign_out(&self) -> Result<HttpRequest> {
        self.json_request(
            Method::POST,
            "/sign-out",
            &Value::Object(Default::default()),
        )
    }

    pub fn parse_json<T: DeserializeOwned>(&self, response: &HttpResponse) -> Result<T> {
        serde_json::from_slice(&response.body)
            .map_err(|error| AuthError::InvalidRequest(format!("invalid auth response: {error}")))
    }

    pub fn parse_session(
        &self,
        response: &HttpResponse,
    ) -> Result<Option<(User, crate::email_password::Session)>> {
        if response.body == b"null" {
            return Ok(None);
        }
        let value: Value = self.parse_json(response)?;
        let user = serde_json::from_value(
            value
                .get("user")
                .cloned()
                .ok_or_else(|| AuthError::InvalidRequest("session response has no user".into()))?,
        )
        .map_err(|error| AuthError::InvalidRequest(format!("invalid session user: {error}")))?;
        let session =
            serde_json::from_value(value.get("session").cloned().ok_or_else(|| {
                AuthError::InvalidRequest("session response has no session".into())
            })?)
            .map_err(|error| AuthError::InvalidRequest(format!("invalid session: {error}")))?;
        Ok(Some((user, session)))
    }

    pub fn http_client() -> Result<reqwest::Client> {
        reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .map_err(|error| AuthError::Adapter(format!("auth HTTP client setup failed: {error}")))
    }

    pub async fn execute(
        &self,
        client: &reqwest::Client,
        request: HttpRequest,
    ) -> Result<HttpResponse> {
        let mut builder = client.request(request.method, request.uri.to_string());
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let response =
            builder.body(request.body).send().await.map_err(|error| {
                AuthError::Adapter(format!("auth HTTP request failed: {error}"))
            })?;
        let status = http::StatusCode::from_u16(response.status().as_u16()).map_err(|error| {
            AuthError::Adapter(format!("invalid auth response status: {error}"))
        })?;
        let mut headers = HeaderMap::new();
        for (name, value) in response.headers() {
            headers.append(name, value.clone());
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| {
                AuthError::Adapter(format!("auth response body read failed: {error}"))
            })?
            .to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }

    pub async fn execute_with_retry(
        &self,
        client: &reqwest::Client,
        request: HttpRequest,
        policy: &RetryPolicy,
    ) -> Result<HttpResponse> {
        let retry_safe = matches!(request.method, Method::GET | Method::HEAD | Method::OPTIONS)
            || request.headers.contains_key("idempotency-key");
        let mut retry_index = 0;
        loop {
            let result = self.execute(client, request.clone()).await;
            let should_retry = match &result {
                Ok(response) => retry_safe && retryable_status(response.status),
                Err(_) => retry_safe,
            };
            if !should_retry || retry_index >= policy.max_retries {
                return result;
            }
            let retry_after = result.as_ref().ok().and_then(retry_after);
            let delay = retry_after
                .map(|delay| delay.min(policy.max_delay))
                .unwrap_or_else(|| policy.delay_for(retry_index));
            tokio::time::sleep(delay).await;
            retry_index += 1;
        }
    }

    fn json_request<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        value: &T,
    ) -> Result<HttpRequest> {
        let body = serde_json::to_vec(value)
            .map_err(|error| AuthError::InvalidRequest(error.to_string()))?;
        self.request(method, path, Some(body))
    }

    fn request(&self, method: Method, path: &str, body: Option<Vec<u8>>) -> Result<HttpRequest> {
        let mut url = self.base_url.clone();
        let base_path = url.path().trim_end_matches('/');
        url.set_path(&format!("{base_path}{path}"));
        let uri: Uri = url
            .as_str()
            .parse()
            .map_err(|error| AuthError::InvalidRequest(format!("invalid client URL: {error}")))?;
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());
        if let Some(ref body) = body {
            headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
            headers.insert(
                header::CONTENT_LENGTH,
                body.len().to_string().parse().unwrap(),
            );
        }
        if method != Method::GET {
            let origin = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
            headers.insert(header::ORIGIN, origin.parse().unwrap());
        }
        Ok(HttpRequest::new(
            method,
            uri,
            headers,
            body.unwrap_or_default(),
        ))
    }
}

fn retryable_status(status: http::StatusCode) -> bool {
    matches!(
        status,
        http::StatusCode::REQUEST_TIMEOUT
            | http::StatusCode::TOO_EARLY
            | http::StatusCode::TOO_MANY_REQUESTS
            | http::StatusCode::INTERNAL_SERVER_ERROR
            | http::StatusCode::BAD_GATEWAY
            | http::StatusCode::SERVICE_UNAVAILABLE
            | http::StatusCode::GATEWAY_TIMEOUT
    )
}

fn retry_after(response: &HttpResponse) -> Option<Duration> {
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
    use http::Method;

    #[test]
    fn client_builds_same_origin_json_requests() {
        let client = AuthClient::new(Url::parse("https://example.com/api/auth").unwrap()).unwrap();
        let request = client
            .sign_in_email(SignInInput {
                email: "a@b.com".into(),
                password: "password".into(),
            })
            .unwrap();
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.uri.path(), "/api/auth/sign-in/email");
        assert_eq!(
            request.headers.get(header::ORIGIN).unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn retry_policy_caps_exponential_backoff() {
        let policy =
            RetryPolicy::new(3, Duration::from_millis(10), Duration::from_millis(15)).unwrap();
        assert_eq!(policy.delay_for(0), Duration::from_millis(10));
        assert_eq!(policy.delay_for(1), Duration::from_millis(15));
        assert_eq!(policy.delay_for(2), Duration::from_millis(15));
    }
}
