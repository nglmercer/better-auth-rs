//! Emailed codes by purpose: sign-in, email verification and password reset.
//! Each code works once, for the purpose it was issued for, and only a limited
//! number of wrong guesses are allowed.

use better_auth::{
    context::AuthContext,
    email::CapturingEmailSender,
    plugins::EmailOtpPlugin,
    router::{AuthRouter, HttpRequest, HttpResponse},
};
use better_auth_core::{
    adapter::{memory::MemoryDb, memory::MemorySecondaryStorage},
    options::{AuthOptions, BaseUrl},
};
use http::{header, HeaderMap, Method, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;

const ORIGIN: &str = "https://example.com";
const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "a fresh passphrase for reset";

fn router(sender: Arc<CapturingEmailSender>) -> AuthRouter {
    let context = AuthContext::new(
        AuthOptions {
            secret: "e".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        vec![Arc::new(EmailOtpPlugin)],
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

/// The six-digit code in the most recent email.
fn code_in_last_email(sender: &CapturingEmailSender) -> String {
    sender
        .last()
        .unwrap()
        .text
        .split(|character: char| !character.is_ascii_digit())
        .find(|word| word.len() == 6)
        .unwrap()
        .to_owned()
}

async fn sign_up(router: &AuthRouter, email: &str) {
    let response = call(
        router,
        Method::POST,
        "/sign-up/email",
        None,
        json!({"email": email, "name": "Person", "password": PASSWORD}),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
}

#[tokio::test]
async fn a_sign_in_code_signs_in_once() {
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(sender.clone());
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/send-verification-otp",
        None,
        json!({"email": "walker@example.com", "type": "sign-in"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let code = code_in_last_email(&sender);

    let response = call(
        &router,
        Method::POST,
        "/sign-in/email-otp",
        None,
        json!({"email": "walker@example.com", "otp": code}),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(session_cookie(&response).is_some());

    let replay = call(
        &router,
        Method::POST,
        "/sign-in/email-otp",
        None,
        json!({"email": "walker@example.com", "otp": code}),
    )
    .await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_verification_code_marks_the_address_verified_and_nothing_else_works_with_it() {
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(sender.clone());
    sign_up(&router, "verify@example.com").await;

    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/send-verification-otp",
        None,
        json!({"email": "verify@example.com", "type": "email-verification"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let code = code_in_last_email(&sender);

    // A verification code cannot sign anyone in.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/sign-in/email-otp",
        None,
        json!({"email": "verify@example.com", "otp": code}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = call_json(
        &router,
        Method::POST,
        "/email-otp/verify-email",
        None,
        json!({"email": "verify@example.com", "otp": code}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], true);
    let response = call(
        &router,
        Method::POST,
        "/sign-in/email",
        None,
        json!({"email": "verify@example.com", "password": PASSWORD}),
    )
    .await;
    let cookie = session_cookie(&response).expect("password sign-in still works");
    let (_, session) = call_json(
        &router,
        Method::GET,
        "/get-session",
        Some(&cookie),
        Value::Null,
    )
    .await;
    assert_eq!(session["user"]["email_verified"], true);
}

#[tokio::test]
async fn a_reset_code_sets_a_new_password_and_ends_old_sessions() {
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(sender.clone());
    sign_up(&router, "reset@example.com").await;
    let response = call(
        &router,
        Method::POST,
        "/sign-in/email",
        None,
        json!({"email": "reset@example.com", "password": PASSWORD}),
    )
    .await;
    let old_session = session_cookie(&response).unwrap();

    let (status, body) = call_json(
        &router,
        Method::POST,
        "/forget-password/email-otp",
        None,
        json!({"email": "reset@example.com"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["sent"], true);
    let code = code_in_last_email(&sender);

    // A weak password is refused without spending the code.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/reset-password",
        None,
        json!({"email": "reset@example.com", "otp": code, "password": "short"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/reset-password",
        None,
        json!({"email": "reset@example.com", "otp": code, "password": NEW_PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The code is spent, the old password and the old session stop working, and the new password works.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/reset-password",
        None,
        json!({"email": "reset@example.com", "otp": code, "password": "yet another passphrase"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, session) = call_json(
        &router,
        Method::GET,
        "/get-session",
        Some(&old_session),
        Value::Null,
    )
    .await;
    assert!(session.is_null() || session["user"].is_null());
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/sign-in/email",
        None,
        json!({"email": "reset@example.com", "password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/sign-in/email",
        None,
        json!({"email": "reset@example.com", "password": NEW_PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn reset_codes_are_not_sent_for_unknown_addresses_and_guesses_are_limited() {
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(sender.clone());
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/email-otp/request-password-reset",
        None,
        json!({"email": "nobody@example.com"}),
    )
    .await;
    // The answer is the same as for a known address, and nothing is sent.
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["sent"], true);
    assert!(sender.messages().is_empty());

    sign_up(&router, "limit@example.com").await;
    call_json(
        &router,
        Method::POST,
        "/email-otp/send-verification-otp",
        None,
        json!({"email": "limit@example.com", "type": "email-verification"}),
    )
    .await;
    let code = code_in_last_email(&sender);
    let wrong = if code == "000000" { "111111" } else { "000000" };
    for _ in 0..5 {
        call_json(
            &router,
            Method::POST,
            "/email-otp/verify-email",
            None,
            json!({"email": "limit@example.com", "otp": wrong}),
        )
        .await;
    }
    // After five wrong guesses the code is gone, even if it is now presented correctly.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/verify-email",
        None,
        json!({"email": "limit@example.com", "otp": code}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_purposes_are_refused() {
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(sender);
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/send-verification-otp",
        None,
        json!({"email": "x@example.com", "type": "something-else"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
