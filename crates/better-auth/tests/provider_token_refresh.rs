//! Refresh and revocation of provider tokens against a local token/revocation fixture.
//! The library keeps no refresh token itself; these tests call it with one the caller holds.

#![cfg(all(feature = "test-utils", feature = "axum"))]

use axum::{extract::Form, http::StatusCode, routing::post, Json, Router};
use better_auth::{http_oauth::HttpOAuthProvider, oauth::OAuthTokens};
use better_auth_core::error::AuthError;
use serde::Deserialize;
use serde_json::{json, Value};
use url::Url;

#[derive(Deserialize)]
struct TokenForm {
    grant_type: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct RevokeForm {
    token: String,
}

async fn token(Form(form): Form<TokenForm>) -> (StatusCode, Json<Value>) {
    match (form.grant_type.as_deref(), form.refresh_token.as_deref()) {
        (Some("refresh_token"), Some("refresh-valid")) => (
            StatusCode::OK,
            Json(json!({"access_token": "access-2", "expires_in": 3600, "token_type": "Bearer"})),
        ),
        (Some("refresh_token"), Some("refresh-revoked")) => (
            StatusCode::BAD_REQUEST,
            Json(
                json!({"error": "invalid_grant", "error_description": "Token has been expired or revoked."}),
            ),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "server_error", "detail": "provider-internal-detail"})),
        ),
    }
}

async fn revoke(Form(form): Form<RevokeForm>) -> (StatusCode, Json<Value>) {
    match form.token.as_str() {
        "refresh-valid" | "access-1" => (StatusCode::OK, Json(json!({}))),
        "already-gone" => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_token"})),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"detail": "provider-internal-detail"})),
        ),
    }
}

async fn start() -> String {
    let app = Router::new()
        .route("/token", post(token))
        .route("/revoke", post(revoke));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{address}")
}

fn provider(base: &str) -> HttpOAuthProvider {
    HttpOAuthProvider::insecure_for_testing(
        "google",
        "client-1",
        "client-secret",
        Url::parse(&format!("{base}/authorize")).unwrap(),
        Url::parse(&format!("{base}/token")).unwrap(),
        Url::parse(&format!("{base}/userinfo")).unwrap(),
        ["openid"],
    )
    .with_revocation_endpoint(Url::parse(&format!("{base}/revoke")).unwrap())
    .unwrap()
}

#[tokio::test]
async fn a_valid_refresh_token_yields_a_new_access_token() {
    let base = start().await;
    let refreshed: OAuthTokens = provider(&base)
        .refresh_access_token("refresh-valid")
        .await
        .unwrap();
    assert_eq!(refreshed.access_token, "access-2");
    assert!(refreshed.expires_at.is_some());
    assert_eq!(refreshed.token_type, "Bearer");
    assert!(
        refreshed.id_token.is_none(),
        "refresh never yields an ID token"
    );
}

#[tokio::test]
async fn an_expired_or_revoked_refresh_token_requires_sign_in_again() {
    let base = start().await;
    let error = provider(&base)
        .refresh_access_token("refresh-revoked")
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::Unauthorized));
}

#[tokio::test]
async fn provider_error_bodies_are_not_echoed_into_errors() {
    let base = start().await;
    let error = provider(&base)
        .refresh_access_token("some-other-refresh-token")
        .await
        .unwrap_err();
    let text = error.to_string();
    assert!(text.contains("500"));
    assert!(!text.contains("provider-internal-detail"));
    assert!(!text.contains("some-other-refresh-token"));
}

#[tokio::test]
async fn revocation_succeeds_and_is_idempotent() {
    let base = start().await;
    let provider = provider(&base);
    provider.revoke_token("refresh-valid").await.unwrap();
    provider.revoke_token("already-gone").await.unwrap();
}

#[tokio::test]
async fn a_failed_revocation_is_reported() {
    let base = start().await;
    let error = provider(&base).revoke_token("unknown").await.unwrap_err();
    assert!(error.to_string().contains("500"));
    assert!(!error.to_string().contains("provider-internal-detail"));
}

#[tokio::test]
async fn revocation_requires_a_configured_endpoint() {
    let base = start().await;
    let provider = HttpOAuthProvider::insecure_for_testing(
        "google",
        "client-1",
        "client-secret",
        Url::parse(&format!("{base}/authorize")).unwrap(),
        Url::parse(&format!("{base}/token")).unwrap(),
        Url::parse(&format!("{base}/userinfo")).unwrap(),
        ["openid"],
    );
    assert!(provider.revoke_token("refresh-valid").await.is_err());
}

#[test]
fn revocation_endpoint_must_be_public_https_outside_test_builds() {
    let provider = HttpOAuthProvider::google("client-1", "secret").unwrap();
    assert!(provider
        .with_revocation_endpoint(Url::parse("http://127.0.0.1/revoke").unwrap())
        .is_err());
}
