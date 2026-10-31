//! Property checks on parameter parsing. A deterministic generator (a fixed seed, so a failure
//! reproduces exactly) builds hostile strings: control characters, quotes, percent escapes,
//! separators, multibyte text, and long values. Every public route must answer them with a client
//! error or a success, never with an internal error. A panic fails the test on its own.

use better_auth::{
    context::AuthContext,
    email::CapturingEmailSender,
    plugins::{EmailOtpPlugin, MagicLinkPlugin, OrganizationPlugin, ScimPlugin, UsernamePlugin},
    router::{AuthRouter, HttpRequest},
};
use better_auth_core::{
    adapter::memory::{MemoryDb, MemorySecondaryStorage},
    options::{AuthOptions, BaseUrl, PasswordHashOptions},
};
use http::{header, HeaderMap, Method, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;

const ORIGIN: &str = "https://example.com";
const ALPHABET: &[&str] = &[
    "a", "Z", "0", "9", "@", ".", "-", "_", " ", "\"", "'", "\\", "/", "?", "&", "=", "%", "#",
    "<", ">", "(", ")", "[", "]", "{", "}", ";", ":", ",", "*", "+", "~", "\t", "\n", "\r", "\0",
    "\u{7f}", "é", "ß", "漢", "🙂", "\u{202e}", "%00", "%2F", "%2e%2e", "../", "\u{fffd}",
];

/// A xorshift generator with a fixed seed. Its output is the same on every run.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A string of up to `max_parts` alphabet entries, sometimes padded to a long length.
    fn text(&mut self, max_parts: usize) -> String {
        let parts = (self.next() as usize) % (max_parts + 1);
        let mut out = String::new();
        for _ in 0..parts {
            out.push_str(ALPHABET[(self.next() as usize) % ALPHABET.len()]);
        }
        if self.next().is_multiple_of(16) {
            out.push_str(&"x".repeat(600));
        }
        out
    }
}

fn router() -> (AuthRouter, Arc<CapturingEmailSender>) {
    let sender = Arc::new(CapturingEmailSender::default());
    let context = AuthContext::new(
        AuthOptions {
            secret: "i".repeat(32),
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
        vec![
            Arc::new(UsernamePlugin),
            Arc::new(EmailOtpPlugin),
            Arc::new(MagicLinkPlugin),
            Arc::new(OrganizationPlugin),
            Arc::new(ScimPlugin),
        ],
    )
    .unwrap();
    let router = AuthRouter::new(context)
        .unwrap()
        .with_email_sender(sender.clone())
        .unwrap()
        .with_verification_services()
        .unwrap();
    (router, sender)
}

async fn call(
    router: &AuthRouter,
    method: Method,
    uri: &str,
    headers: HeaderMap,
    body: Vec<u8>,
) -> StatusCode {
    router
        .handle(HttpRequest::new(
            method,
            uri.parse().unwrap(),
            headers,
            body,
        ))
        .await
        .status
}

fn json_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    headers
}

/// Percent-encodes every byte, so any generated text is a single query value.
fn encode(value: &str) -> String {
    value.bytes().map(|byte| format!("%{byte:02X}")).collect()
}

#[tokio::test]
async fn json_bodies_never_cause_an_internal_error() {
    let (router, _) = router();
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let routes = [
        "/api/auth/sign-in/email",
        "/api/auth/sign-up/email",
        "/api/auth/sign-in/username",
        "/api/auth/is-username-available",
        "/api/auth/request-password-reset",
        "/api/auth/reset-password",
        "/api/auth/sign-in/magic-link",
        "/api/auth/email-otp/send-verification-otp",
        "/api/auth/email-otp/check-verification-otp",
        "/api/auth/email-otp/reset-password",
        "/api/auth/magic-link/verify",
        "/api/auth/organization/create",
        "/api/auth/username/set",
    ];
    for _ in 0..300 {
        for route in routes {
            let body = json!({
                "email": random.text(6),
                "name": random.text(4),
                "password": random.text(4),
                "username": random.text(4),
                "type": random.text(2),
                "otp": random.text(3),
                "token": random.text(4),
                "callbackURL": random.text(5),
                "new_password": random.text(4),
                "role": random.text(2),
            });
            let status = call(
                &router,
                Method::POST,
                route,
                json_headers(),
                body.to_string().into_bytes(),
            )
            .await;
            assert_ne!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{route} answered an internal error to {body}"
            );
        }
    }
}

#[tokio::test]
async fn query_values_never_cause_an_internal_error() {
    let (router, _) = router();
    let mut random = Random(0xdead_beef_cafe_f00d);
    for _ in 0..400 {
        let value = encode(&random.text(8));
        for uri in [
            format!("/api/auth/magic-link/verify?token={value}&callbackURL={value}"),
            format!("/api/auth/error?error={value}"),
            format!("/api/auth/organization/get-organization?organization_id={value}"),
            format!("/api/auth/organization/get-invitation?organization_id={value}&invitation_id={value}"),
            format!("/api/auth/scim/v2/Users?filter={value}&startIndex={value}&count={value}"),
        ] {
            let status = call(&router, Method::GET, &uri, HeaderMap::new(), Vec::new()).await;
            assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "{uri} answered an internal error");
        }
    }
}

#[tokio::test]
async fn scim_bodies_and_filters_never_cause_an_internal_error() {
    let (router, _) = router();
    // An organization and a token, so the SCIM parsers run past the authorization check.
    let mut headers = json_headers();
    let sign_up = router
        .handle(HttpRequest::new(
            Method::POST,
            "/api/auth/sign-up/email".parse().unwrap(),
            headers.clone(),
            json!({"email": "scim-owner@example.com", "name": "Owner", "password": "correct horse battery staple"}).to_string().into_bytes(),
        ))
        .await;
    let cookie = sign_up
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.contains("session_token="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    headers.insert(header::COOKIE, cookie.parse().unwrap());
    let org = router
        .handle(HttpRequest::new(
            Method::POST,
            "/api/auth/organization/create".parse().unwrap(),
            headers.clone(),
            json!({"name": "Fuzz"}).to_string().into_bytes(),
        ))
        .await;
    let org_id = serde_json::from_slice::<Value>(&org.body).unwrap()["organization"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let issued = router
        .handle(HttpRequest::new(
            Method::POST,
            "/api/auth/scim/generate-token".parse().unwrap(),
            headers.clone(),
            json!({"organization_id": org_id}).to_string().into_bytes(),
        ))
        .await;
    let token = serde_json::from_slice::<Value>(&issued.body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let mut bearer = HeaderMap::new();
    bearer.insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    bearer.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    let mut random = Random(0x0123_4567_89ab_cdef);
    for _ in 0..400 {
        let filter = encode(&random.text(10));
        let status = call(
            &router,
            Method::GET,
            &format!("/api/auth/scim/v2/Users?filter={filter}"),
            bearer.clone(),
            Vec::new(),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "SCIM filter {filter} answered an internal error"
        );
        let body = json!({"userName": random.text(4), "displayName": random.text(3), "active": random.text(1)});
        let status = call(
            &router,
            Method::POST,
            "/api/auth/scim/v2/Users",
            bearer.clone(),
            body.to_string().into_bytes(),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "SCIM create {body} answered an internal error"
        );
        let patch = json!({"displayName": random.text(3), "role": random.text(1), "emails": random.text(2)});
        let status = call(
            &router,
            Method::PATCH,
            "/api/auth/scim/v2/Users/nobody",
            bearer.clone(),
            patch.to_string().into_bytes(),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "SCIM patch {patch} answered an internal error"
        );
    }
}
