//! Organization permission checks, checked against what each role can really do,
//! and social sign-in started by POST, which returns the provider URL as JSON.

use better_auth::{
    context::AuthContext,
    email::CapturingEmailSender,
    http_oauth::HttpOAuthProvider,
    plugins::OrganizationPlugin,
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

fn router(sender: Arc<CapturingEmailSender>) -> AuthRouter {
    let context = AuthContext::new(
        AuthOptions {
            secret: "p".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        vec![Arc::new(OrganizationPlugin)],
    )
    .unwrap();
    AuthRouter::new(context)
        .unwrap()
        .with_email_sender(sender)
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
    response
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.contains("session_token="))
        .map(|value| value.split(';').next().unwrap().to_owned())
        .expect("sign-up sets a session")
}

#[tokio::test]
async fn permission_checks_agree_with_what_each_role_can_do() {
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

    // An admin, promoted by the owner.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/invite-member",
        Some(&owner),
        json!({"organization_id": org, "email": "admin@example.com", "role": "admin"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = sender
        .last()
        .unwrap()
        .text
        .lines()
        .nth(1)
        .unwrap()
        .to_owned();
    let admin = sign_up(&router, "admin@example.com").await;
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/accept-invitation",
        Some(&admin),
        json!({"token": token}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let check = |cookie: String, permission: Value| {
        let router = &router;
        let org = org.clone();
        async move {
            let (status, body) = call_json(
                router,
                Method::POST,
                "/organization/has-permission",
                Some(&cookie),
                json!({"organization_id": org, "permission": permission}),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            body["success"].as_bool().unwrap()
        }
    };

    // The matrix says an admin may create teams, and does so. It says an admin may not
    // delete the organization, and the delete is refused.
    assert!(check(admin.clone(), json!({"team": ["create"]})).await);
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/create-team",
        Some(&admin),
        json!({"organization_id": org, "name": "Core"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!check(admin.clone(), json!({"organization": ["delete"]})).await);
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/delete",
        Some(&admin),
        json!({"organization_id": org}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The owner has everything the matrix lists, including deleting the organization.
    assert!(
        check(
            owner.clone(),
            json!({"organization": ["delete"], "team": ["create", "update"]})
        )
        .await
    );

    // Every pair must be granted, not just some of them.
    assert!(
        !check(
            admin.clone(),
            json!({"team": ["create"], "organization": ["delete"]})
        )
        .await
    );
}

#[tokio::test]
async fn a_plain_member_has_no_organization_permissions_and_outsiders_get_not_found() {
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
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/invite-member",
        Some(&owner),
        json!({"organization_id": org, "email": "member@example.com", "role": "member"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
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

    let (_, body) = call_json(
        &router,
        Method::POST,
        "/organization/has-permission",
        Some(&member),
        json!({"organization_id": org, "permission": {"team": ["create"]}}),
    )
    .await;
    assert_eq!(body["success"], false);
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/has-permission",
        Some(&member),
        json!({"organization_id": org, "permission": {}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let stranger = sign_up(&router, "stranger@example.com").await;
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/has-permission",
        Some(&stranger),
        json!({"organization_id": org, "permission": {"team": ["create"]}}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn social_sign_in_can_start_by_post_and_returns_the_provider_url() {
    let context = AuthContext::new(
        AuthOptions {
            secret: "s".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        Vec::new(),
    )
    .unwrap();
    let router = AuthRouter::new(context)
        .unwrap()
        .with_social_providers(vec![
            HttpOAuthProvider::google("client-1", "secret").unwrap()
        ])
        .unwrap();

    let (status, body) = call_json(
        &router,
        Method::POST,
        "/sign-in/social",
        None,
        json!({"provider": "google"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["redirect"], false);
    let url = body["url"].as_str().unwrap();
    assert!(url.starts_with("https://accounts.google.com/"), "{url}");
    assert!(url.contains("client_id=client-1"));

    // Unknown providers are not found, and the GET redirect still works.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/sign-in/social",
        None,
        json!({"provider": "nope"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let response = router
        .handle(HttpRequest::new(
            Method::GET,
            "/api/auth/sign-in/social/google".parse().unwrap(),
            HeaderMap::new(),
            Vec::new(),
        ))
        .await;
    assert_eq!(response.status, StatusCode::FOUND);
}
