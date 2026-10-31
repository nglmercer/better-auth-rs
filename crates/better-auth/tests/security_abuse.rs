//! Abuse cases that must fail: session fixation, and client-address spoofing when no proxy is
//! trusted. Each test states the attacker's move and checks that the server refuses it.

use better_auth::{
    context::{AuthContext, RequestMetadata},
    router::{AuthRouter, HttpRequest, HttpResponse},
    security::extract_client_ip,
};
use better_auth_core::{
    adapter::memory::{MemoryDb, MemorySecondaryStorage},
    options::{AdvancedOptions, AuthOptions, BaseUrl, PasswordHashOptions},
};
use http::{header, HeaderMap, Method, StatusCode};
use serde_json::{json, Value};
use std::{net::IpAddr, sync::Arc};

const ORIGIN: &str = "https://example.com";
const PASSWORD: &str = "correct horse battery staple";

fn options() -> AuthOptions {
    AuthOptions {
        secret: "f".repeat(32),
        base_url: Some(BaseUrl::Static(ORIGIN.into())),
        has_database: true,
        password_hash: PasswordHashOptions {
            scrypt_log_n: 10,
            ..PasswordHashOptions::default()
        },
        ..AuthOptions::default()
    }
}

fn router() -> AuthRouter {
    let context = AuthContext::new(
        options(),
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        Vec::new(),
    )
    .unwrap();
    AuthRouter::new(context).unwrap()
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

/// The name and value of the session cookie a response sets, as `name=value`.
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
async fn a_session_planted_in_the_browser_is_not_adopted_at_sign_in() {
    let router = router();
    let response = send(
        &router,
        Method::POST,
        "/sign-up/email",
        None,
        json!({"email": "victim@example.com", "name": "Victim", "password": PASSWORD}),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    // The attacker plants a token they chose in the victim's browser, under the cookie name the
    // server uses, and the victim then signs in.
    let planted_name = session_cookie(&response)
        .unwrap()
        .split('=')
        .next()
        .unwrap()
        .to_owned();
    let planted = format!("{planted_name}=current.bm90LXNlc3Npb24.attackerchosen");
    let signed_in = send(
        &router,
        Method::POST,
        "/sign-in/email",
        Some(&planted),
        json!({"email": "victim@example.com", "password": PASSWORD}),
    )
    .await;
    assert_eq!(signed_in.status, StatusCode::OK);
    let fresh = session_cookie(&signed_in).expect("sign-in issues a session");
    assert_ne!(
        fresh, planted,
        "the session is a new token, not the planted one"
    );

    // The planted token opens nothing, and the new one opens the victim's account.
    let with_planted = send(
        &router,
        Method::GET,
        "/get-session",
        Some(&planted),
        Value::Null,
    )
    .await;
    let body: Value = serde_json::from_slice(&with_planted.body).unwrap();
    assert!(
        body.is_null() || body["user"].is_null(),
        "the planted token is not a session"
    );
    let with_fresh = send(
        &router,
        Method::GET,
        "/get-session",
        Some(&fresh),
        Value::Null,
    )
    .await;
    let body: Value = serde_json::from_slice(&with_fresh.body).unwrap();
    assert_eq!(body["user"]["email"], "victim@example.com");
}

#[test]
fn client_addresses_are_not_read_from_headers_unless_a_proxy_is_trusted() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
    headers.insert("x-real-ip", "203.0.113.10".parse().unwrap());
    let metadata = RequestMetadata::new(
        Method::POST,
        "/api/auth/sign-in/email".parse().unwrap(),
        headers,
    );

    // With no trusted proxy, a client that sends its own forwarding headers is not believed,
    // so it cannot pick the address its requests are counted against.
    let untrusted =
        AuthContext::new(options(), Arc::new(MemoryDb::default()), None, Vec::new()).unwrap();
    let request = untrusted.resolve_request(&metadata).unwrap();
    assert_eq!(extract_client_ip(&request, &metadata), None);

    // Behind a proxy the operator trusts, the header is read, and that address is the client.
    let mut trusted_options = options();
    trusted_options.advanced = AdvancedOptions {
        trusted_proxy_headers: true,
        trusted_ip_headers: vec!["x-forwarded-for".into()],
    };
    let trusted = AuthContext::new(
        trusted_options,
        Arc::new(MemoryDb::default()),
        None,
        Vec::new(),
    )
    .unwrap();
    let request = trusted.resolve_request(&metadata).unwrap();
    assert_eq!(
        extract_client_ip(&request, &metadata),
        Some("203.0.113.9".parse::<IpAddr>().unwrap())
    );
}
