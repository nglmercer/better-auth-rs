//! Axum helpers for an application that mounts Better Auth next to its own routes.
//!
//! - [`auth_routes`] mounts the Better Auth endpoints at the configured base path
//!   (default `/api/auth`) and returns a router that can be merged into the application.
//! - [`AuthUser`] authenticates an application route with the browser session cookie.
//!   Unsafe methods pass the same CSRF policy as the Better Auth routes first.
//! - [`NativeAuthUser`] authenticates an application route with an explicit
//!   `Authorization: Bearer` token only. Cookies are never read there, so a cross-site
//!   browser request has no ambient credential to use.
//!
//! Each extractor needs the application state to implement `FromRef<AuthContext>`.
//! Choosing an extractor is the opt-in: a route that uses [`AuthUser`] ignores the
//! `Authorization` header, and a route that uses [`NativeAuthUser`] ignores cookies.

use crate::{
    context::{AuthContext, RequestMetadata},
    router::{axum_adapter, AuthRouter},
    security::check_csrf,
    session::{AuthPrincipal, SessionService, SessionTransport},
};
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use better_auth_core::error::AuthError;
use serde_json::json;
use std::sync::Arc;

/// Mounts the Better Auth routes. The returned router already holds its state, so it
/// merges into an application router that has any state type.
pub fn auth_routes(router: AuthRouter) -> Router {
    let base = router
        .context()
        .options
        .base_path
        .trim_end_matches('/')
        .to_owned();
    Router::new()
        .route(&format!("{base}/{{*path}}"), any(axum_adapter::handler))
        .with_state(Arc::new(router))
}

/// Why an application route refused a request. The body carries a fixed message and never
/// the underlying error.
#[derive(Debug)]
pub struct AuthRejection {
    status: StatusCode,
    message: &'static str,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

fn reject(error: AuthError) -> AuthRejection {
    let (status, message) = match error {
        AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
        AuthError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
        AuthError::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate limited"),
        AuthError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid request"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    AuthRejection { status, message }
}

fn is_unsafe(method: &Method) -> bool {
    !matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

async fn authenticate(
    context: &AuthContext,
    parts: &Parts,
    transport: SessionTransport,
) -> Result<AuthPrincipal, AuthRejection> {
    let metadata = RequestMetadata::new(
        parts.method.clone(),
        parts.uri.clone(),
        parts.headers.clone(),
    );
    if transport == SessionTransport::Cookie && is_unsafe(&parts.method) {
        let request_context = context.resolve_request(&metadata).map_err(reject)?;
        check_csrf(&request_context, &metadata).map_err(reject)?;
    }
    SessionService::new(context.clone())
        .map_err(reject)?
        .resolve_request_with_transport(&metadata, transport)
        .await
        .map_err(reject)?
        .ok_or(AuthRejection {
            status: StatusCode::UNAUTHORIZED,
            message: "unauthorized",
        })
}

/// Authenticated user through the browser session cookie.
#[derive(Debug, Clone)]
pub struct AuthUser(pub AuthPrincipal);

impl<S> FromRequestParts<S> for AuthUser
where
    AuthContext: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let context = AuthContext::from_ref(state);
        authenticate(&context, parts, SessionTransport::Cookie)
            .await
            .map(AuthUser)
    }
}

/// Authenticated user through an explicit `Authorization: Bearer` token. Intended for
/// native clients that hold their own session token.
#[derive(Debug, Clone)]
pub struct NativeAuthUser(pub AuthPrincipal);

impl<S> FromRequestParts<S> for NativeAuthUser
where
    AuthContext: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let context = AuthContext::from_ref(state);
        authenticate(&context, parts, SessionTransport::Bearer)
            .await
            .map(NativeAuthUser)
    }
}
