//! An independent-style Axum application that mounts Better Auth, registers Google,
//! and protects its own routes. The application is served on a local port and called
//! over HTTP, so the extractors, CSRF policy and routing are exercised as a client
//! would see them. No live provider is contacted.

#![cfg(feature = "axum")]

use axum::{
    extract::FromRef,
    routing::{get, post},
    Json, Router,
};
use better_auth::{
    axum_integration::{auth_routes, AuthUser, NativeAuthUser},
    context::AuthContext,
    email_password::{EmailPasswordService, SignUpInput},
    http_oauth::HttpOAuthProvider,
    router::AuthRouter,
};
use better_auth_core::{
    adapter::{memory::MemoryDb, memory::MemorySecondaryStorage},
    options::{AuthOptions, BaseUrl, PasswordHashOptions},
};
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;

const ORIGIN: &str = "https://app.example.test";
const EVIL: &str = "https://evil.example.test";
const GOOGLE_CLIENT_SECRET: &str = "google-secret-must-not-leak";

#[derive(Clone)]
struct AppState {
    auth: AuthContext,
}

impl FromRef<AppState> for AuthContext {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}

async fn me(AuthUser(principal): AuthUser) -> Json<Value> {
    Json(json!({ "user_id": principal.user.id, "email": principal.user.email }))
}

async fn native_me(NativeAuthUser(principal): NativeAuthUser) -> Json<Value> {
    Json(json!({ "user_id": principal.user.id }))
}

async fn create_note(AuthUser(principal): AuthUser) -> Json<Value> {
    Json(json!({ "created_by": principal.user.id }))
}

fn context() -> AuthContext {
    AuthContext::new(
        AuthOptions {
            secret: "x".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            password_hash: PasswordHashOptions {
                scrypt_log_n: 10,
                ..PasswordHashOptions::default()
            },
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        vec![],
    )
    .unwrap()
}

/// Starts the application and returns its base URL and the auth context it uses.
async fn start() -> (String, AuthContext) {
    let context = context();
    let google = HttpOAuthProvider::google("google-client-id", GOOGLE_CLIENT_SECRET).unwrap();
    let auth = AuthRouter::new(context.clone())
        .unwrap()
        .with_social_providers(vec![google])
        .unwrap();
    let state = AppState {
        auth: context.clone(),
    };
    let app = Router::new()
        .route("/api/me", get(me))
        .route("/api/native/me", get(native_me))
        .route("/api/notes", post(create_note))
        .with_state(state)
        .merge(auth_routes(auth));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), context)
}

struct Account {
    cookie: String,
    bearer: String,
    user_id: String,
}

/// Creates an account through the library service, so the test holds both the cookie
/// value and the bearer token that a native client would store. The HTTPS base URL means
/// the secure cookie name, so the cookie is minted with `secure_cookie = true`.
async fn account(context: &AuthContext) -> Account {
    let result = EmailPasswordService::new(context.clone())
        .unwrap()
        .sign_up(
            SignUpInput {
                email: "axum-user@example.test".into(),
                name: "Axum User".into(),
                password: "correct horse battery staple".into(),
            },
            true,
        )
        .await
        .unwrap();
    Account {
        cookie: format!("{}={}", result.cookie.name, result.cookie.value),
        bearer: result.session_token,
        user_id: result.user.id,
    }
}

fn client() -> Client {
    Client::builder().redirect(Policy::none()).build().unwrap()
}

#[tokio::test]
async fn protected_routes_require_a_session() {
    let (base, _) = start().await;
    let response = client().get(format!("{base}/api/me")).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body, json!({"error": "unauthorized"}));
}

#[tokio::test]
async fn cookie_session_authenticates_an_application_route() {
    let (base, context) = start().await;
    let user = account(&context).await;
    let response = client()
        .get(format!("{base}/api/me"))
        .header("Cookie", &user.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["user_id"], user.user_id);
}

#[tokio::test]
async fn cross_site_mutation_with_a_session_cookie_is_refused() {
    let (base, context) = start().await;
    let user = account(&context).await;
    let forged = client()
        .post(format!("{base}/api/notes"))
        .header("Cookie", &user.cookie)
        .header("Origin", EVIL)
        .header("Sec-Fetch-Site", "cross-site")
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), StatusCode::FORBIDDEN);

    let trusted = client()
        .post(format!("{base}/api/notes"))
        .header("Cookie", &user.cookie)
        .header("Origin", ORIGIN)
        .header("Sec-Fetch-Site", "same-origin")
        .send()
        .await
        .unwrap();
    assert_eq!(trusted.status(), StatusCode::OK);
}

#[tokio::test]
async fn native_bearer_session_authenticates_and_cookies_are_ignored() {
    let (base, context) = start().await;
    let user = account(&context).await;

    let cookie_only = client()
        .get(format!("{base}/api/native/me"))
        .header("Cookie", &user.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(cookie_only.status(), StatusCode::UNAUTHORIZED);

    // An explicit bearer token works, including from a request with a foreign Origin:
    // no browser attaches it automatically, so cross-site CSRF has nothing to ride on.
    let native = client()
        .get(format!("{base}/api/native/me"))
        .header("Authorization", format!("Bearer {}", user.bearer))
        .header("Origin", EVIL)
        .send()
        .await
        .unwrap();
    assert_eq!(native.status(), StatusCode::OK);
    let body: Value = native.json().await.unwrap();
    assert_eq!(body["user_id"], user.user_id);
}

#[tokio::test]
async fn cookie_route_ignores_a_bearer_token() {
    // A bearer token alone must not authenticate a cookie route: the opt-in is the extractor.
    let (base, context) = start().await;
    let user = account(&context).await;
    let response = client()
        .get(format!("{base}/api/me"))
        .header("Authorization", format!("Bearer {}", user.bearer))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sign_out_is_csrf_protected_and_revokes_the_cookie_session() {
    let (base, context) = start().await;
    let user = account(&context).await;

    let forged = client()
        .post(format!("{base}/api/auth/sign-out"))
        .header("Cookie", &user.cookie)
        .header("Origin", EVIL)
        .header("Sec-Fetch-Site", "cross-site")
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), StatusCode::FORBIDDEN);
    let still_valid = client()
        .get(format!("{base}/api/me"))
        .header("Cookie", &user.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(still_valid.status(), StatusCode::OK);

    let signed_out = client()
        .post(format!("{base}/api/auth/sign-out"))
        .header("Cookie", &user.cookie)
        .header("Origin", ORIGIN)
        .header("Sec-Fetch-Site", "same-origin")
        .send()
        .await
        .unwrap();
    assert!(signed_out.status().is_success());
    let after = client()
        .get(format!("{base}/api/me"))
        .header("Cookie", &user.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn google_sign_in_redirects_with_state_and_pkce_without_leaking_the_secret() {
    let (base, _) = start().await;
    let response = client()
        .get(format!("{base}/api/auth/sign-in/social/google"))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_redirection());
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(location.starts_with("https://accounts.google.com/"));
    assert!(location.contains("state="));
    assert!(location.contains("code_challenge="));
    assert!(!location.contains(GOOGLE_CLIENT_SECRET));
}

#[tokio::test]
async fn forged_google_callback_creates_no_session() {
    let (base, _) = start().await;
    let response = client()
        .get(format!(
            "{base}/api/auth/callback/google?code=attacker-code&state=forged-state"
        ))
        .send()
        .await
        .unwrap();
    assert!(!response.status().is_success());
    assert!(response.headers().get("set-cookie").is_none());
}
