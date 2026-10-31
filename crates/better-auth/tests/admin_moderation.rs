//! Administrator moderation over HTTP: bans, unbans, session listing and
//! revocation, and removal. A ban must end access immediately and keep it ended.

use better_auth::{
    context::AuthContext,
    plugins::AdminPlugin,
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

fn router(db: Arc<MemoryDb>) -> AuthRouter {
    let context = AuthContext::new(
        AuthOptions {
            secret: "m".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        db,
        Some(Arc::new(MemorySecondaryStorage::default())),
        vec![Arc::new(AdminPlugin)],
    )
    .unwrap();
    AuthRouter::new(context).unwrap()
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

async fn sign_in_status(router: &AuthRouter, email: &str) -> StatusCode {
    call(
        router,
        Method::POST,
        "/sign-in/email",
        None,
        json!({"email": email, "password": PASSWORD}),
    )
    .await
    .status
}

/// Whether the session cookie still resolves to a user.
async fn has_session(router: &AuthRouter, cookie: &str) -> bool {
    let (_, body) = call_json(
        router,
        Method::GET,
        "/get-session",
        Some(cookie),
        Value::Null,
    )
    .await;
    !body.is_null() && !body["user"].is_null()
}

#[tokio::test]
async fn bans_end_access_and_unbans_restore_it() {
    let db = Arc::new(MemoryDb::default());
    let router = router(db.clone());
    let (admin_cookie, admin_id) = sign_up(&router, "admin@example.com").await;
    db.update_where(
        "user",
        Query::new().eq("id", admin_id.clone()),
        json!({"role": "admin"}),
    )
    .await
    .unwrap();
    let (target_cookie, target_id) = sign_up(&router, "target@example.com").await;
    let (other_cookie, _) = sign_up(&router, "other@example.com").await;

    // Only administrators moderate accounts.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/admin/ban-user",
        Some(&other_cookie),
        json!({"user_id": target_id}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(has_session(&router, &target_cookie).await);

    // An administrator cannot ban themselves.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/admin/ban-user",
        Some(&admin_cookie),
        json!({"user_id": admin_id}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The ban ends the target's sessions, and sign-in is refused.
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/admin/ban-user",
        Some(&admin_cookie),
        json!({"user_id": target_id, "ban_reason": "spam"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user"]["banned"], true);
    assert_eq!(body["user"]["ban_reason"], "spam");
    assert!(!has_session(&router, &target_cookie).await);
    assert_eq!(
        sign_in_status(&router, "target@example.com").await,
        StatusCode::FORBIDDEN
    );

    // Unbanning restores sign-in.
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/admin/unban-user",
        Some(&admin_cookie),
        json!({"user_id": target_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user"]["banned"], false);
    assert_eq!(
        sign_in_status(&router, "target@example.com").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn expired_bans_no_longer_apply() {
    let db = Arc::new(MemoryDb::default());
    let router = router(db.clone());
    let (admin_cookie, admin_id) = sign_up(&router, "admin@example.com").await;
    db.update_where(
        "user",
        Query::new().eq("id", admin_id),
        json!({"role": "admin"}),
    )
    .await
    .unwrap();
    let (_, target_id) = sign_up(&router, "target@example.com").await;
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/admin/ban-user",
        Some(&admin_cookie),
        json!({"user_id": target_id, "ban_expires_in": 3600}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        sign_in_status(&router, "target@example.com").await,
        StatusCode::FORBIDDEN
    );

    // The record still says banned, but the expiry has passed.
    db.update_where(
        "user",
        Query::new().eq("id", target_id),
        json!({"ban_expires": 1}),
    )
    .await
    .unwrap();
    assert_eq!(
        sign_in_status(&router, "target@example.com").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn sessions_can_be_listed_and_revoked_one_at_a_time() {
    let db = Arc::new(MemoryDb::default());
    let router = router(db.clone());
    let (admin_cookie, admin_id) = sign_up(&router, "admin@example.com").await;
    db.update_where(
        "user",
        Query::new().eq("id", admin_id),
        json!({"role": "admin"}),
    )
    .await
    .unwrap();
    let (user_cookie, user_id) = sign_up(&router, "user@example.com").await;
    // A second sign-in gives the user a second session.
    let response = call(
        &router,
        Method::POST,
        "/sign-in/email",
        None,
        json!({"email": "user@example.com", "password": PASSWORD}),
    )
    .await;
    let second_cookie = session_cookie(&response).unwrap();

    let (status, listed) = call_json(
        &router,
        Method::POST,
        "/admin/list-user-sessions",
        Some(&admin_cookie),
        json!({"user_id": user_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let sessions = listed["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    // Session tokens are never listed.
    assert!(!listed.to_string().contains("token"));
    let first = sessions[0]["id"].as_str().unwrap().to_owned();

    let (status, body) = call_json(
        &router,
        Method::POST,
        "/admin/revoke-user-session",
        Some(&admin_cookie),
        json!({"id": first}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], 1);

    // Revoking every session uses the upstream path and ends the second one too.
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/admin/revoke-user-sessions",
        Some(&admin_cookie),
        json!({"user_id": user_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], 1);
    assert!(!has_session(&router, &second_cookie).await);
    assert!(!has_session(&router, &user_cookie).await);
}

#[tokio::test]
async fn removing_a_user_deletes_the_account_and_its_sessions() {
    let db = Arc::new(MemoryDb::default());
    let router = router(db.clone());
    let (admin_cookie, admin_id) = sign_up(&router, "admin@example.com").await;
    db.update_where(
        "user",
        Query::new().eq("id", admin_id.clone()),
        json!({"role": "admin"}),
    )
    .await
    .unwrap();
    let (_, target_id) = sign_up(&router, "target@example.com").await;

    let (status, _) = call_json(
        &router,
        Method::POST,
        "/admin/remove-user",
        Some(&admin_cookie),
        json!({"user_id": admin_id}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = call_json(
        &router,
        Method::POST,
        "/admin/remove-user",
        Some(&admin_cookie),
        json!({"user_id": target_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["removed"], true);
    assert_eq!(
        sign_in_status(&router, "target@example.com").await,
        StatusCode::UNAUTHORIZED
    );
    let (_, listed) = call_json(
        &router,
        Method::GET,
        "/admin/list-users",
        Some(&admin_cookie),
        Value::Null,
    )
    .await;
    let emails: Vec<&str> = listed["users"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|user| user["email"].as_str())
        .collect();
    assert_eq!(emails, vec!["admin@example.com"]);
}

#[tokio::test]
async fn a_ban_locks_a_live_session_even_if_its_sessions_were_not_deleted() {
    let db = Arc::new(MemoryDb::default());
    let router = router(db.clone());
    let (cookie, user_id) = sign_up(&router, "live@example.com").await;
    assert!(has_session(&router, &cookie).await);
    // Written straight to the record, so no session cleanup has run.
    db.update_where(
        "user",
        Query::new().eq("id", user_id),
        json!({"banned": true}),
    )
    .await
    .unwrap();
    assert!(!has_session(&router, &cookie).await);
}
