//! Account routes that match upstream paths: password re-verification, username
//! availability, two-factor URI and backup codes, unlinking, and `/ok`.

use better_auth::{
    context::AuthContext,
    plugins::{totp_code, TwoFactorPlugin, UsernamePlugin},
    router::{AuthRouter, HttpRequest, HttpResponse},
};
use better_auth_core::{
    adapter::{memory::MemoryDb, memory::MemorySecondaryStorage, DbAdapter},
    options::{AuthOptions, BaseUrl},
};
use http::{header, HeaderMap, Method, StatusCode};
use serde_json::{json, Value};
use std::{sync::Arc, time::SystemTime};

const ORIGIN: &str = "https://example.com";
const PASSWORD: &str = "correct horse battery staple";

fn router(db: Arc<MemoryDb>) -> AuthRouter {
    let context = AuthContext::new(
        AuthOptions {
            secret: "a".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        db,
        Some(Arc::new(MemorySecondaryStorage::default())),
        vec![Arc::new(TwoFactorPlugin), Arc::new(UsernamePlugin)],
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
    call_from(router, ORIGIN, method, path, cookie, body).await
}

async fn call_from(
    router: &AuthRouter,
    origin: &str,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    body: Value,
) -> HttpResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, origin.parse().unwrap());
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

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn ok_and_session_reads_are_public_but_post_checks_origin() {
    let db = Arc::new(MemoryDb::default());
    let router = router(db);
    let (status, body) = call_json(&router, Method::GET, "/ok", None, Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);

    let (cookie, user_id) = sign_up(&router, "reader@example.com").await;
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/get-session",
        Some(&cookie),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user"]["id"], user_id);

    // POST can refresh the session cookie, so a foreign origin is refused.
    let response = call_from(
        &router,
        "https://evil.example",
        Method::POST,
        "/get-session",
        Some(&cookie),
        Value::Null,
    )
    .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn password_is_reverified_for_the_signed_in_user() {
    let db = Arc::new(MemoryDb::default());
    let router = router(db);
    let (cookie, _) = sign_up(&router, "verify@example.com").await;
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/verify-password",
        Some(&cookie),
        json!({"password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], true);

    let (status, _) = call_json(
        &router,
        Method::POST,
        "/verify-password",
        Some(&cookie),
        json!({"password": "not the password"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = call_json(
        &router,
        Method::POST,
        "/verify-password",
        None,
        json!({"password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn username_availability_reflects_claimed_names_and_rejects_invalid_ones() {
    let db = Arc::new(MemoryDb::default());
    let router = router(db);
    let (cookie, _) = sign_up(&router, "claimer@example.com").await;
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/is-username-available",
        None,
        json!({"username": "Alice"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["available"], true);

    let (status, _) = call_json(
        &router,
        Method::POST,
        "/username/set",
        Some(&cookie),
        json!({"username": "alice"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Case does not matter: the stored name is normalized.
    let (_, body) = call_json(
        &router,
        Method::POST,
        "/is-username-available",
        None,
        json!({"username": "ALICE"}),
    )
    .await;
    assert_eq!(body["available"], false);

    let (status, _) = call_json(
        &router,
        Method::POST,
        "/is-username-available",
        None,
        json!({"username": "a"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn totp_uri_and_backup_codes_need_the_password_and_rotate_backup_codes() {
    let db = Arc::new(MemoryDb::default());
    let router = router(db);
    let (cookie, _) = sign_up(&router, "second@example.com").await;

    let (status, enrollment) = call_json(
        &router,
        Method::POST,
        "/two-factor/enable",
        Some(&cookie),
        json!({"password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let secret = enrollment["secret"].as_str().unwrap().to_owned();
    let enrolled_uri = enrollment["totp_uri"].as_str().unwrap().to_owned();
    let original_codes: Vec<String> = enrollment["backup_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap().to_owned())
        .collect();
    let code = totp_code(&secret, now_seconds(), 30, 6).unwrap();
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/two-factor/confirm",
        Some(&cookie),
        json!({"code": code}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The URI is only given to someone who re-enters the password.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/two-factor/get-totp-uri",
        Some(&cookie),
        json!({"password": "wrong password here"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let response = call(
        &router,
        Method::POST,
        "/two-factor/get-totp-uri",
        Some(&cookie),
        json!({"password": PASSWORD}),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.headers.get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["totp_uri"], enrolled_uri);

    // New backup codes replace the old ones. The old code no longer completes
    // a sign-in challenge, and a new one does.
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/two-factor/generate-backup-codes",
        Some(&cookie),
        json!({"password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let new_codes: Vec<String> = body["backup_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(new_codes.len(), original_codes.len());
    assert!(new_codes.iter().all(|code| !original_codes.contains(code)));

    let challenge = |code: String| {
        let router = &router;
        async move {
            let (_, body) = call_json(
                router,
                Method::POST,
                "/sign-in/email",
                None,
                json!({"email": "second@example.com", "password": PASSWORD}),
            )
            .await;
            let token = body["challenge_token"].as_str().unwrap().to_owned();
            call_json(
                router,
                Method::POST,
                "/two-factor/verify",
                None,
                json!({"challenge_token": token, "code": code}),
            )
            .await
            .0
        }
    };
    assert_eq!(
        challenge(original_codes[0].clone()).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(challenge(new_codes[0].clone()).await, StatusCode::OK);
}

#[tokio::test]
async fn linked_accounts_can_be_unlinked_but_the_last_sign_in_method_stays() {
    let db = Arc::new(MemoryDb::default());
    let router = router(db.clone());
    let (cookie, user_id) = sign_up(&router, "linked@example.com").await;
    db.insert_record(
        "account",
        json!({
            "id": "github-link",
            "user_id": user_id,
            "provider_id": "github",
            "account_id": "gh-1",
        }),
    )
    .await
    .unwrap();

    let (status, body) = call_json(
        &router,
        Method::POST,
        "/unlink-account",
        Some(&cookie),
        json!({"provider_id": "github"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], true);

    let (status, _) = call_json(
        &router,
        Method::POST,
        "/unlink-account",
        Some(&cookie),
        json!({"provider_id": "github"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The password is now the only sign-in method, so it cannot be removed.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/unlink-account",
        Some(&cookie),
        json!({"provider_id": "credential"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
