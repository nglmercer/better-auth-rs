use super::{retry::retry_after, retry::retryable_status, AuthClient, RetryPolicy};
use crate::router::{HttpRequest, HttpResponse};
use better_auth_core::error::{AuthError, Result};
use http::{header::HeaderMap, Method, StatusCode};

impl AuthClient {
    /// Creates a cookie-aware reqwest client for browser-like session use.
    pub fn http_client() -> Result<reqwest::Client> {
        reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .map_err(|error| AuthError::Adapter(format!("auth HTTP client setup failed: {error}")))
    }

    /// Executes a prepared request using any reqwest client.
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
        let status = StatusCode::from_u16(response.status().as_u16()).map_err(|error| {
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

    /// Retries only safe methods, or requests explicitly marked idempotent.
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
}
