//! Full OAuth flows against fixture providers on localhost.
//!
//! The fixture runs a token endpoint and two userinfo endpoints, one reporting a
//! verified email and one not. The router performs the real begin and callback
//! steps, including the token exchange and the profile request. Only the
//! `test-utils` constructor allows the plain-HTTP localhost endpoints.

#![cfg(all(feature = "test-utils", feature = "axum"))]

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use better_auth::{
    context::AuthContext,
    http_oauth::HttpOAuthProvider,
    router::{AuthRouter, HttpRequest, HttpResponse},
};
use better_auth_core::{
    adapter::{memory::MemoryDb, memory::MemorySecondaryStorage, Query},
    options::{AuthOptions, BaseUrl},
};
use http::{header, HeaderMap as Headers, Method, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use url::Url;

const ACCESS_TOKEN: &str = "fixture-access-token";

async fn token() -> Json<Value> {
    Json(json!({"access_token": ACCESS_TOKEN, "token_type": "Bearer", "expires_in": 3600}))
}

async fn userinfo(
    State(_): State<()>,
    Path(variant): Path<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(&format!("Bearer {ACCESS_TOKEN}"));
    if !authorized {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid_token"})),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "sub": format!("fixture-{variant}-user"),
            "email": "fixture@example.com",
            "email_verified": variant == "verified",
            "name": "Fixture User",
        })),
    )
}

/// Starts the fixture on an ephemeral port and returns its base URL.
async fn start_fixture() -> String {
    let app = Router::new()
        .route("/token", post(token))
        .route("/userinfo/{variant}", get(userinfo))
        .with_state(());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{address}")
}

fn provider(base: &str, id: &str, variant: &str) -> HttpOAuthProvider {
    HttpOAuthProvider::insecure_for_testing(
        id,
        "client-1",
        "client-secret",
        Url::parse(&format!("{base}/authorize")).unwrap(),
        Url::parse(&format!("{base}/token")).unwrap(),
        Url::parse(&format!("{base}/userinfo/{variant}")).unwrap(),
        ["openid", "email"],
    )
}

async fn get_path(router: &AuthRouter, path: &str) -> HttpResponse {
    router
        .handle(HttpRequest::new(
            Method::GET,
            format!("/api/auth{path}").parse().unwrap(),
            Headers::new(),
            Vec::new(),
        ))
        .await
}

/// Starts a sign-in with `id` and returns the state the provider would echo back.
async fn begin(router: &AuthRouter, id: &str) -> String {
    let response = get_path(router, &format!("/sign-in/social/{id}")).await;
    assert_eq!(response.status, StatusCode::FOUND);
    let location = response
        .headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    let url = Url::parse(location).unwrap();
    url.query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("authorization URL carries a state")
}

#[tokio::test]
async fn social_login_completes_against_fixture_providers_and_links_safely() {
    let base = start_fixture().await;
    let context = AuthContext::new(
        AuthOptions {
            secret: "f".repeat(32),
            base_url: Some(BaseUrl::Static("https://example.com".into())),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        Vec::new(),
    )
    .unwrap();
    let adapter = context.adapter.clone();
    let router = AuthRouter::new(context)
        .unwrap()
        .with_social_providers(vec![
            provider(&base, "verified-idp", "verified"),
            provider(&base, "unverified-idp", "unverified"),
        ])
        .unwrap();

    // A verified provider creates the account and sets a session cookie.
    let state = begin(&router, "verified-idp").await;
    let callback = format!("/callback/verified-idp?code=auth-code&state={state}");
    let response = get_path(&router, &callback).await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert!(response.headers.get(header::SET_COOKIE).is_some());
    let users = adapter.find_many("user", Query::new()).await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["email"], "fixture@example.com");
    assert_eq!(users[0]["email_verified"], true);

    // The same state cannot be replayed.
    let replay = get_path(&router, &callback).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);

    // A second provider reporting an unverified email cannot take over the account.
    let state = begin(&router, "unverified-idp").await;
    let response = get_path(
        &router,
        &format!("/callback/unverified-idp?code=auth-code&state={state}"),
    )
    .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    let accounts = adapter.find_many("account", Query::new()).await.unwrap();
    assert_eq!(accounts.len(), 1, "only the verified identity is linked");

    // A repeat login through the verified provider reuses the same account.
    let state = begin(&router, "verified-idp").await;
    let response = get_path(
        &router,
        &format!("/callback/verified-idp?code=auth-code&state={state}"),
    )
    .await;
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(
        adapter.find_many("user", Query::new()).await.unwrap().len(),
        1
    );
}
