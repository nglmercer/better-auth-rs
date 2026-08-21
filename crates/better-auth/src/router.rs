use crate::{
    check_csrf,
    context::{AuthContext, RequestMetadata},
    email_password::{AuthResult, EmailPasswordService, SignInInput, SignUpInput},
    rate_limit::{RateLimitPolicy, RateLimiter},
    verification::{EmailVerificationService, PasswordResetService},
};
use better_auth_core::{
    error::{AuthError, Result},
    plugin::{EndpointRequest, HookRequest, HookResponse},
};
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
    email_verification: Option<EmailVerificationService>,
    password_reset: Option<PasswordResetService>,
}

impl AuthRouter {
    pub fn new(context: AuthContext) -> Result<Self> {
        let email_password = EmailPasswordService::new(context.clone())?;
        Ok(Self {
            context,
            email_password,
            rate_limiter: None,
            sign_in_policy: None,
            email_verification: None,
            password_reset: None,
        })
    }

    pub fn with_verification_services(mut self) -> Result<Self> {
        if let Some(storage) = self.context.secondary_storage.clone() {
            self.email_verification = Some(EmailVerificationService::new(
                self.context.clone(),
                storage.clone(),
            ));
            self.password_reset = Some(PasswordResetService::new(self.context.clone(), storage)?);
        }
        Ok(self)
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
        let hook_request = HookRequest {
            method: request.method.clone(),
            path: request.uri.path().to_owned(),
            headers: request.headers.clone(),
            body: serde_json::from_slice(&request.body).ok(),
        };
        for hook in self.context.plugins.hooks() {
            if let Err(error) = hook.on_request(&hook_request).await {
                return error_response(error);
            }
        }

        let mut response = match self.handle_result(request).await {
            Ok(response) => response,
            Err(error) => error_response(error),
        };
        let hook_response = HookResponse {
            status: response.status,
            headers: response.headers.clone(),
        };
        for hook in self.context.plugins.hooks() {
            if let Err(error) = hook.on_response(&hook_request, &hook_response).await {
                response = error_response(error);
                break;
            }
        }
        response
    }

    async fn handle_result(&self, request: HttpRequest) -> Result<HttpResponse> {
        let request_context = self.context.resolve_request(&request.metadata())?;
        let path = request.uri.path();
        let base_path = self.context.options.base_path.trim_end_matches('/');
        let endpoint_path_name = path
            .strip_prefix(base_path)
            .unwrap_or(path)
            .trim_end_matches('/');
        let secure_cookie = request_context
            .base_url
            .as_ref()
            .is_some_and(|url| url.scheme() == "https");

        if let Some(endpoint) = self
            .context
            .plugins
            .endpoint_handlers()
            .iter()
            .find(|registered| {
                registered.endpoint.method == request.method
                    && registered.endpoint.path == endpoint_path_name
            })
        {
            let response = endpoint
                .handler
                .handle(EndpointRequest {
                    method: request.method.clone(),
                    path: endpoint_path_name.to_owned(),
                    headers: request.headers.clone(),
                    body: request.body.clone(),
                })
                .await?;
            return Ok(HttpResponse {
                status: response.status,
                headers: response.headers,
                body: response.body,
            });
        }

        match (request.method.clone(), endpoint_path_name) {
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
            (Method::POST, "/verify-email") => {
                check_csrf(&request_context, &request.metadata())?;
                let input: TokenInput = parse_json(&request.body)?;
                let service = self.email_verification.as_ref().ok_or_else(|| {
                    AuthError::InvalidConfiguration("verification storage is not configured".into())
                })?;
                let verified = service.verify(&input.token).await?;
                Ok(HttpResponse::json(
                    StatusCode::OK,
                    json!({"verified": verified}),
                ))
            }
            (Method::POST, "/request-password-reset") => {
                check_csrf(&request_context, &request.metadata())?;
                let input: EmailInput = parse_json(&request.body)?;
                let service = self.password_reset.as_ref().ok_or_else(|| {
                    AuthError::InvalidConfiguration("verification storage is not configured".into())
                })?;
                let _ = service
                    .issue(&input.email, std::time::Duration::from_secs(15 * 60))
                    .await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({"sent": true})))
            }
            (Method::POST, "/reset-password") => {
                check_csrf(&request_context, &request.metadata())?;
                let input: PasswordResetInput = parse_json(&request.body)?;
                let service = self.password_reset.as_ref().ok_or_else(|| {
                    AuthError::InvalidConfiguration("verification storage is not configured".into())
                })?;
                let reset = service.reset(&input.token, &input.new_password).await?;
                Ok(HttpResponse::json(StatusCode::OK, json!({"reset": reset})))
            }
            _ if endpoint_path_name.starts_with('/') => Err(AuthError::NotFound),
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

#[derive(serde::Deserialize)]
struct TokenInput {
    token: String,
}

#[derive(serde::Deserialize)]
struct EmailInput {
    email: String,
}

#[derive(serde::Deserialize)]
struct PasswordResetInput {
    token: String,
    new_password: String,
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

    #[cfg(feature = "axum")]
    #[tokio::test]
    async fn axum_adapter_bridges_native_requests_and_responses() {
        use axum::{body::Body, extract::State, response::IntoResponse};
        use http::Request;

        let router = Arc::new(router());
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/auth/sign-up/email")
            .header(header::ORIGIN, "https://example.com")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"email":"axum@example.com","name":"Axum","password":"correct horse battery staple"}"#,
            ))
            .unwrap();
        let response = axum_adapter::handler(State(router), request)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::SET_COOKIE).is_some());
    }
}
