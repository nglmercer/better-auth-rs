use crate::{
    check_csrf,
    context::{AuthContext, RequestMetadata},
    email_password::{AuthResult, EmailPasswordService, SignInInput, SignUpInput},
    rate_limit::{RateLimitPolicy, RateLimiter},
};
use better_auth_core::error::{AuthError, Result};
use http::{header, HeaderMap, Method, StatusCode, Uri};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: Method, uri: Uri, headers: HeaderMap, body: impl Into<Vec<u8>>) -> Self {
        Self {
            method,
            uri,
            headers,
            body: body.into(),
        }
    }

    fn metadata(&self) -> RequestMetadata {
        RequestMetadata::new(self.method.clone(), self.uri.clone(), self.headers.clone())
    }
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json(status: StatusCode, value: impl Serialize) -> Self {
        let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"null".to_vec());
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        Self {
            status,
            headers,
            body,
        }
    }

    pub fn error(status: StatusCode, message: impl Into<String>) -> Self {
        Self::json(status, json!({ "error": message.into() }))
    }

    fn with_cookie(mut self, value: String) -> Self {
        if let Ok(value) = value.parse() {
            self.headers.append(header::SET_COOKIE, value);
        }
        self
    }
}

#[derive(Clone)]
pub struct AuthRouter {
    context: AuthContext,
    email_password: EmailPasswordService,
    rate_limiter: Option<RateLimiter>,
    sign_in_policy: Option<RateLimitPolicy>,
}

impl AuthRouter {
    pub fn new(context: AuthContext) -> Result<Self> {
        let email_password = EmailPasswordService::new(context.clone())?;
        Ok(Self {
            context,
            email_password,
            rate_limiter: None,
            sign_in_policy: None,
        })
    }

    pub fn with_sign_in_rate_limit(
        mut self,
        limiter: RateLimiter,
        policy: RateLimitPolicy,
    ) -> Self {
        self.rate_limiter = Some(limiter);
        self.sign_in_policy = Some(policy);
        self
    }

    pub async fn handle(&self, request: HttpRequest) -> HttpResponse {
        match self.handle_result(request).await {
            Ok(response) => response,
            Err(error) => error_response(error),
        }
    }

    async fn handle_result(&self, request: HttpRequest) -> Result<HttpResponse> {
        let request_context = self.context.resolve_request(&request.metadata())?;
        let path = request.uri.path();
        let base_path = self.context.options.base_path.trim_end_matches('/');
        let endpoint = path
            .strip_prefix(base_path)
            .unwrap_or(path)
            .trim_end_matches('/');
        let secure_cookie = request_context
            .base_url
            .as_ref()
            .is_some_and(|url| url.scheme() == "https");

        match (request.method.clone(), endpoint) {
            (Method::POST, "/sign-up/email") => {
                check_csrf(&request_context, &request.metadata())?;
                let input: SignUpInput = parse_json(&request.body)?;
                self.enforce_sign_in_limit(&request_context, &input.email)
                    .await?;
                let result = self.email_password.sign_up(input, secure_cookie).await?;
                Ok(auth_result_response(StatusCode::OK, result))
            }
            (Method::POST, "/sign-in/email") => {
                check_csrf(&request_context, &request.metadata())?;
                let input: SignInInput = parse_json(&request.body)?;
                self.enforce_sign_in_limit(&request_context, &input.email)
                    .await?;
                let result = self.email_password.sign_in(input, secure_cookie).await?;
                Ok(auth_result_response(StatusCode::OK, result))
            }
            (Method::GET, "/get-session") => {
                let result = self
                    .email_password
                    .session_from_cookie(&request.headers, secure_cookie)
                    .await?;
                let has_session = result.is_some();
                let mut response = match result {
                    Some((user, session)) => HttpResponse::json(
                        StatusCode::OK,
                        json!({"user": user, "session": session}),
                    ),
                    None => HttpResponse::json(StatusCode::OK, Value::Null),
                };
                if has_session {
                    if let Some(cookie) = self
                        .email_password
                        .refresh_session_cookie(&request.headers, secure_cookie)
                        .await?
                    {
                        response = response.with_cookie(cookie.to_set_cookie_header());
                    }
                }
                Ok(response)
            }
            (Method::POST, "/sign-out") => {
                check_csrf(&request_context, &request.metadata())?;
                let cookie = self
                    .email_password
                    .sign_out(&request.headers, secure_cookie)
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({}))
                    .with_cookie(cookie.to_set_cookie_header()))
            }
            _ if endpoint.starts_with('/') => Err(AuthError::NotFound),
            _ => Err(AuthError::NotFound),
        }
    }

    async fn enforce_sign_in_limit(
        &self,
        request_context: &crate::context::RequestContext,
        identity: &str,
    ) -> Result<()> {
        let (Some(limiter), Some(policy)) = (&self.rate_limiter, &self.sign_in_policy) else {
            return Ok(());
        };
        let identity = request_context
            .client_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| identity.trim().to_ascii_lowercase());
        limiter.enforce(policy, &identity).await
    }
}

fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body)
        .map_err(|error| AuthError::InvalidRequest(format!("invalid JSON body: {error}")))
}

fn auth_result_response(status: StatusCode, result: AuthResult) -> HttpResponse {
    HttpResponse::json(
        status,
        json!({"user": result.user, "session": result.session}),
    )
    .with_cookie(result.cookie.to_set_cookie_header())
}

fn error_response(error: AuthError) -> HttpResponse {
    match error {
        AuthError::InvalidRequest(message) => HttpResponse::error(StatusCode::BAD_REQUEST, message),
        AuthError::Unauthorized => HttpResponse::error(StatusCode::UNAUTHORIZED, "unauthorized"),
        AuthError::Forbidden(message) => HttpResponse::error(StatusCode::FORBIDDEN, message),
        AuthError::NotFound => HttpResponse::error(StatusCode::NOT_FOUND, "not found"),
        AuthError::RateLimited {
            retry_after_seconds,
        } => {
            let mut response = HttpResponse::error(StatusCode::TOO_MANY_REQUESTS, "rate limited");
            response.headers.insert(
                header::RETRY_AFTER,
                retry_after_seconds.to_string().parse().unwrap(),
            );
            response
        }
        AuthError::InvalidConfiguration(message)
        | AuthError::Adapter(message)
        | AuthError::Plugin(message)
        | AuthError::Crypto(message) => {
            HttpResponse::error(StatusCode::INTERNAL_SERVER_ERROR, message)
        }
    }
}

#[cfg(feature = "axum")]
pub mod axum_adapter {
    use super::{AuthRouter, HttpRequest, HttpResponse};
    use axum::{
        body::{to_bytes, Body},
        extract::State,
        response::IntoResponse,
    };
    use http::Request;
    use std::sync::Arc;

    pub async fn handler(
        State(router): State<Arc<AuthRouter>>,
        request: Request<Body>,
    ) -> impl IntoResponse {
        let (parts, body) = request.into_parts();
        let body = to_bytes(body, 2 * 1024 * 1024).await.unwrap_or_default();
        let response: HttpResponse = router
            .handle(HttpRequest::new(
                parts.method,
                parts.uri,
                parts.headers,
                body.to_vec(),
            ))
            .await;
        (response.status, response.headers, response.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::{adapter::memory::MemoryDb, options::AuthOptions};
    use std::sync::Arc;

    fn router() -> AuthRouter {
        AuthRouter::new(
            AuthContext::new(
                AuthOptions {
                    secret: "r".repeat(32),
                    base_url: Some(better_auth_core::options::BaseUrl::Static(
                        "https://example.com".into(),
                    )),
                    has_database: true,
                    ..AuthOptions::default()
                },
                Arc::new(MemoryDb::default()),
                None,
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn router_exposes_signup_and_session_endpoints() {
        let router = router();
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
        let response = router
            .handle(HttpRequest::new(
                Method::POST,
                "/api/auth/sign-up/email".parse().unwrap(),
                headers,
                br#"{"email":"router@example.com","name":"Router","password":"correct horse battery staple"}"#,
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.headers.contains_key(header::SET_COOKIE));
    }
}
