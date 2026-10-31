//! Takeover by pre-registration. An attacker signs up with a victim's address and a password, and
//! the account is not yet verified. When the victim proves the mailbox with a code, the attacker's
//! password and sessions must stop working.

use better_auth::{
    context::AuthContext,
    email::CapturingEmailSender,
    plugins::EmailOtpPlugin,
    router::{AuthRouter, HttpRequest, HttpResponse},
};
use better_auth_core::{
    adapter::memory::{MemoryDb, MemorySecondaryStorage},
    options::{AuthOptions, BaseUrl, PasswordHashOptions},
};
use http::{header, HeaderMap, Method, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;

const ORIGIN: &str = "https://example.com";
const ATTACKER_PASSWORD: &str = "attacker chose this passphrase";

fn router(sender: Arc<CapturingEmailSender>) -> AuthRouter {
    let context = AuthContext::new(
        AuthOptions {
            secret: "t".repeat(32),
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
        vec![Arc::new(EmailOtpPlugin)],
    )
    .unwrap();
    AuthRouter::new(context)
        .unwrap()
        .with_email_sender(sender)
        .unwrap()
}

async fn send(
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
    router
        .handle(HttpRequest::new(
            method,
            format!("/api/auth{path}").parse().unwrap(),
            headers,
            body.to_string().into_bytes(),
        ))
        .await
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

#[tokio::test]
async fn a_password_registered_before_the_mailbox_is_proven_stops_working_when_it_is() {
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(sender.clone());
    let victim = "victim@example.com";

    // The attacker registers the victim's address with their own password.
    let attacker = send(
        &router,
        Method::POST,
        "/sign-up/email",
        None,
        json!({"email": victim, "name": "Attacker", "password": ATTACKER_PASSWORD}),
    )
    .await;
    assert_eq!(attacker.status, StatusCode::OK);
    let attacker_session = session_cookie(&attacker).unwrap();

    // The victim signs in with a code sent to their own mailbox. That proves the mailbox.
    assert_eq!(
        send(
            &router,
            Method::POST,
            "/email-otp/send",
            None,
            json!({"email": victim})
        )
        .await
        .status,
        StatusCode::OK
    );
    let code = sender
        .last()
        .unwrap()
        .text
        .split("code is ")
        .nth(1)
        .unwrap()
        .chars()
        .take(6)
        .collect::<String>();
    let proven = send(
        &router,
        Method::POST,
        "/email-otp/verify",
        None,
        json!({"email": victim, "code": code}),
    )
    .await;
    assert_eq!(proven.status, StatusCode::OK);

    // The attacker's password no longer signs in.
    let password_again = send(
        &router,
        Method::POST,
        "/sign-in/email",
        None,
        json!({"email": victim, "password": ATTACKER_PASSWORD}),
    )
    .await;
    assert_ne!(
        password_again.status,
        StatusCode::OK,
        "the pre-registered password is revoked"
    );

    // The attacker's session no longer opens the account.
    let old = send(
        &router,
        Method::GET,
        "/get-session",
        Some(&attacker_session),
        Value::Null,
    )
    .await;
    let body: Value = serde_json::from_slice(&old.body).unwrap();
    assert!(
        body.is_null() || body["user"].is_null(),
        "the attacker's session is revoked"
    );

    // The victim's own sign-in still works.
    let victim_session = session_cookie(&proven).unwrap();
    let body: Value = serde_json::from_slice(
        &send(
            &router,
            Method::GET,
            "/get-session",
            Some(&victim_session),
            Value::Null,
        )
        .await
        .body,
    )
    .unwrap();
    assert_eq!(body["user"]["email"], victim);
    assert_eq!(body["user"]["email_verified"], true);
}
