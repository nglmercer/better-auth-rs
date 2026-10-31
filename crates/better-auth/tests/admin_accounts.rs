//! Administrator account operations over HTTP: creating, reading and updating users,
//! setting passwords, and permission checks that match what the role can do.

use better_auth::{
    context::AuthContext,
    email::CapturingEmailSender,
    plugins::{AdminPlugin, EmailOtpPlugin},
    router::{AuthRouter, HttpRequest, HttpResponse},
};
use better_auth_core::{
    adapter::{memory::MemoryDb, memory::MemorySecondaryStorage, DbAdapter, Query},
    options::{AuthOptions, BaseUrl},
};
use http::{header, HeaderMap, Method, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;

const ORIGIN: &str = "https://example.com";
const PASSWORD: &str = "correct horse battery staple";

fn router(db: Arc<MemoryDb>, sender: Arc<CapturingEmailSender>) -> AuthRouter {
    let context = AuthContext::new(
        AuthOptions {
            secret: "a".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        db,
        Some(Arc::new(MemorySecondaryStorage::default())),
        vec![Arc::new(AdminPlugin), Arc::new(EmailOtpPlugin)],
    )
    .unwrap();
    AuthRouter::new(context)
        .unwrap()
        .with_email_sender(sender)
        .unwrap()
        .with_verification_services()
        .unwrap()
}

async fn call(
    router: &AuthRouter,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    body: Value,
) -> HttpResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    if let Some(cookie) = cookie {
        headers.insert(header::COOKIE, cookie.parse().unwrap());
    }
    let payload = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    router
        .handle(HttpRequest::new(
            method,
            format!("/api/auth{path}").parse().unwrap(),
            headers,
            payload,
        ))
        .await
}

async fn call_json(
    router: &AuthRouter,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let response = call(router, method, path, cookie, body).await;
    let body = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    (response.status, body)
}

fn session_cookie(response: &HttpResponse) -> Option<String> {
    response
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.contains("session_token="))
        .map(|value| value.split(';').next().unwrap().to_owned())
}

async fn sign_up(router: &AuthRouter, email: &str) -> (String, String) {
    let response = call(
        router,
        Method::POST,
        "/sign-up/email",
        None,
        json!({"email": email, "name": "Person", "password": PASSWORD}),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    (
        session_cookie(&response).expect("sign-up sets a session"),
        body["user"]["id"].as_str().unwrap().to_owned(),
    )
}

/// An administrator, promoted directly in the store, the way an operator would.
async fn admin(router: &AuthRouter, db: &MemoryDb) -> String {
    let (cookie, id) = sign_up(router, "admin@example.com").await;
    db.update_where("user", Query::new().eq("id", id), json!({"role": "admin"}))
        .await
        .unwrap();
    cookie
}

#[tokio::test]
async fn administrators_create_read_and_update_users() {
    let db = Arc::new(MemoryDb::default());
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(db.clone(), sender);
    let admin = admin(&router, &db).await;
    let (member, member_id) = sign_up(&router, "member@example.com").await;

    // Only administrators create accounts.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/admin/create-user",
        Some(&member),
        json!({"email": "new@example.com", "name": "New", "password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Weak passwords are refused before any account is written.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/admin/create-user",
        Some(&admin),
        json!({"email": "new@example.com", "name": "New", "password": "short"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = call_json(
        &router,
        Method::POST,
        "/admin/create-user",
        Some(&admin),
        json!({"email": "New@Example.com", "name": "New", "password": PASSWORD, "role": "editor"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new_id = body["user"]["id"].as_str().unwrap().to_owned();
    assert_eq!(body["user"]["role"], "editor");
    assert_eq!(body["user"]["email"], "new@example.com");

    // The created account can sign in with the password the administrator chose.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/sign-in/email",
        None,
        json!({"email": "new@example.com", "password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call_json(
        &router,
        Method::GET,
        &format!("/admin/get-user?id={new_id}"),
        Some(&admin),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user"]["name"], "New");
    assert!(!body.to_string().contains("password"));

    // Names and roles can change. An administrator cannot change their own role.
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/admin/update-user",
        Some(&admin),
        json!({"user_id": new_id, "name": "Renamed", "role": "viewer"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user"]["name"], "Renamed");
    assert_eq!(body["user"]["role"], "viewer");
    let own_id = db
        .find_one(
            "user",
            Query::new().eq("email", "admin@example.com".to_owned()),
        )
        .await
        .unwrap()
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/admin/update-user",
        Some(&admin),
        json!({"user_id": own_id, "role": "member"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Members cannot read or change other accounts.
    let (status, _) = call_json(
        &router,
        Method::GET,
        &format!("/admin/get-user?id={new_id}"),
        Some(&member),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let _ = member_id;
}

#[tokio::test]
async fn administrators_set_a_password_and_that_ends_the_users_sessions() {
    let db = Arc::new(MemoryDb::default());
    let router = router(db.clone(), Arc::new(CapturingEmailSender::default()));
    let admin = admin(&router, &db).await;
    let (user_cookie, user_id) = sign_up(&router, "user@example.com").await;

    let (status, _) = call_json(
        &router,
        Method::POST,
        "/admin/set-user-password",
        Some(&admin),
        json!({"user_id": user_id, "password": "a brand new passphrase"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, session) = call_json(
        &router,
        Method::GET,
        "/get-session",
        Some(&user_cookie),
        Value::Null,
    )
    .await;
    assert!(session.is_null() || session["user"].is_null());
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/sign-in/email",
        None,
        json!({"email": "user@example.com", "password": "a brand new passphrase"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn permission_checks_grant_only_what_the_admin_role_does() {
    let db = Arc::new(MemoryDb::default());
    let router = router(db.clone(), Arc::new(CapturingEmailSender::default()));
    let admin = admin(&router, &db).await;
    let (member, _) = sign_up(&router, "member@example.com").await;

    let (_, body) = call_json(
        &router,
        Method::POST,
        "/admin/has-permission",
        Some(&admin),
        json!({"permission": {"user": ["ban", "set-password"], "session": ["revoke"]}}),
    )
    .await;
    assert_eq!(body["success"], true);
    // An action the server does not implement is not granted.
    let (_, body) = call_json(
        &router,
        Method::POST,
        "/admin/has-permission",
        Some(&admin),
        json!({"permission": {"user": ["impersonate"]}}),
    )
    .await;
    assert_eq!(body["success"], false);
    // A plain member gets no grants at all.
    let (_, body) = call_json(
        &router,
        Method::POST,
        "/admin/has-permission",
        Some(&member),
        json!({"permission": {"user": ["ban"]}}),
    )
    .await;
    assert_eq!(body["success"], false);
}
