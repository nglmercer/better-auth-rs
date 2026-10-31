//! Email change by code, the non-consuming code check, the error page, and the
//! organization read routes.

use better_auth::{
    context::AuthContext,
    email::CapturingEmailSender,
    plugins::{EmailOtpPlugin, OrganizationPlugin},
    router::{AuthRouter, HttpRequest, HttpResponse},
};
use better_auth_core::{
    adapter::memory::{MemoryDb, MemorySecondaryStorage},
    options::{AuthOptions, BaseUrl},
};
use http::{header, HeaderMap, Method, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;

const ORIGIN: &str = "https://example.com";
const PASSWORD: &str = "correct horse battery staple";

fn router(sender: Arc<CapturingEmailSender>) -> AuthRouter {
    let context = AuthContext::new(
        AuthOptions {
            secret: "c".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        vec![Arc::new(EmailOtpPlugin), Arc::new(OrganizationPlugin)],
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

async fn sign_up(router: &AuthRouter, email: &str) -> String {
    let response = call(
        router,
        Method::POST,
        "/sign-up/email",
        None,
        json!({"email": email, "name": "Person", "password": PASSWORD}),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    session_cookie(&response).expect("sign-up sets a session")
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

#[tokio::test]
async fn an_email_change_needs_a_code_sent_to_the_new_address() {
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(sender.clone());
    let cookie = sign_up(&router, "old@example.com").await;
    let other = sign_up(&router, "taken@example.com").await;
    let _ = other;

    // Requests need a session, and a taken or current address is refused.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/request-email-change",
        None,
        json!({"new_email": "fresh@example.com"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/request-email-change",
        Some(&cookie),
        json!({"new_email": "taken@example.com"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/request-email-change",
        Some(&cookie),
        json!({"new_email": "old@example.com"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The code goes to the new address.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/request-email-change",
        Some(&cookie),
        json!({"new_email": "fresh@example.com"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sender.last().unwrap().to, "fresh@example.com");
    let code = code_in_last_email(&sender);

    // A wrong code is refused, and the right one changes the address.
    let wrong = if code == "000000" { "111111" } else { "000000" };
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/change-email",
        Some(&cookie),
        json!({"new_email": "fresh@example.com", "otp": wrong}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/change-email",
        Some(&cookie),
        json!({"new_email": "fresh@example.com", "otp": code}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The new address signs in with the same password, and the old one does not.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/sign-in/email",
        None,
        json!({"email": "fresh@example.com", "password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/sign-in/email",
        None,
        json!({"email": "old@example.com", "password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The public send route cannot start an email change.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/send-verification-otp",
        None,
        json!({"email": "taken@example.com", "type": "email-change"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_code_can_be_checked_without_being_spent() {
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(sender.clone());
    sign_up(&router, "check@example.com").await;
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/send-verification-otp",
        None,
        json!({"email": "check@example.com", "type": "email-verification"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let code = code_in_last_email(&sender);

    let (status, body) = call_json(
        &router,
        Method::POST,
        "/email-otp/check-verification-otp",
        None,
        json!({"email": "check@example.com", "type": "email-verification", "otp": code}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    // The check did not spend the code, so the verification still works.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/verify-email",
        None,
        json!({"email": "check@example.com", "otp": code}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Once consumed, the code no longer checks.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/email-otp/check-verification-otp",
        None,
        json!({"email": "check@example.com", "type": "email-verification", "otp": code}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_error_page_escapes_its_message() {
    let router = router(Arc::new(CapturingEmailSender::default()));
    let response = call(
        &router,
        Method::GET,
        "/error?error=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        None,
        Value::Null,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.headers.get(header::CONTENT_TYPE).unwrap(),
        "text/html; charset=utf-8"
    );
    let page = String::from_utf8(response.body).unwrap();
    assert!(!page.contains("<script>"));
    assert!(page.contains("&lt;script&gt;"));
}

#[tokio::test]
async fn organization_reads_show_more_to_managers_than_to_members() {
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(sender.clone());
    let owner = sign_up(&router, "owner@example.com").await;
    let (_, created) = call_json(
        &router,
        Method::POST,
        "/organization/create",
        Some(&owner),
        json!({"name": "Acme"}),
    )
    .await;
    let org = created["organization"]["id"].as_str().unwrap().to_owned();
    call_json(
        &router,
        Method::POST,
        "/organization/invite-member",
        Some(&owner),
        json!({"organization_id": org, "email": "member@example.com", "role": "member"}),
    )
    .await;
    let token = sender
        .last()
        .unwrap()
        .text
        .lines()
        .nth(1)
        .unwrap()
        .to_owned();
    let member = sign_up(&router, "member@example.com").await;
    call_json(
        &router,
        Method::POST,
        "/organization/accept-invitation",
        Some(&member),
        json!({"token": token}),
    )
    .await;
    call_json(
        &router,
        Method::POST,
        "/organization/invite-member",
        Some(&owner),
        json!({"organization_id": org, "email": "pending@example.com", "role": "member"}),
    )
    .await;

    let (status, full) = call_json(
        &router,
        Method::GET,
        &format!("/organization/get-full-organization?organization_id={org}"),
        Some(&owner),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(full["organization"]["name"], "Acme");
    assert_eq!(full["members"].as_array().unwrap().len(), 2);
    assert_eq!(full["invitations"].as_array().unwrap().len(), 1);
    let invitation_id = full["invitations"][0]["id"].as_str().unwrap().to_owned();

    // Members see the organization and its members, but not the pending invitations.
    let (status, full) = call_json(
        &router,
        Method::GET,
        &format!("/organization/get-full-organization?organization_id={org}"),
        Some(&member),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(full["invitations"].as_array().unwrap().is_empty());

    let (status, body) = call_json(
        &router,
        Method::GET,
        &format!(
            "/organization/get-invitation?organization_id={org}&invitation_id={invitation_id}"
        ),
        Some(&owner),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["invitation"]["email"], "pending@example.com");
    let (status, _) = call_json(
        &router,
        Method::GET,
        &format!(
            "/organization/get-invitation?organization_id={org}&invitation_id={invitation_id}"
        ),
        Some(&member),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
