//! Organization management over HTTP: reading and updating an organization, slugs,
//! invitations (list, cancel, reject, accept), leaving, and deleting.

use better_auth::{
    context::AuthContext,
    email::CapturingEmailSender,
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
            secret: "o".repeat(32),
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

/// The invitation token is the second line of the email, which is the only
/// place it is delivered.
fn invitation_token(sender: &CapturingEmailSender) -> String {
    sender
        .last()
        .unwrap()
        .text
        .lines()
        .nth(1)
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn organizations_are_read_updated_and_deleted_by_their_roles() {
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(sender.clone());
    let owner = sign_up(&router, "owner@example.com").await;
    let stranger = sign_up(&router, "stranger@example.com").await;

    let (_, created) = call_json(
        &router,
        Method::POST,
        "/organization/create",
        Some(&owner),
        json!({"name": "Acme"}),
    )
    .await;
    let org = created["organization"]["id"].as_str().unwrap().to_owned();
    let path = format!("/organization/get-organization?organization_id={org}");

    // Members read it. Outsiders get no sign that it exists.
    let (status, body) = call_json(&router, Method::GET, &path, Some(&owner), Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["organization"]["slug"], "acme");
    let (status, _) = call_json(&router, Method::GET, &path, Some(&stranger), Value::Null).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Slugs are checked for form and for use.
    let (_, body) = call_json(
        &router,
        Method::POST,
        "/organization/check-slug",
        Some(&owner),
        json!({"slug": "acme"}),
    )
    .await;
    assert_eq!(body["available"], false);
    let (_, body) = call_json(
        &router,
        Method::POST,
        "/organization/check-slug",
        Some(&owner),
        json!({"slug": "newco"}),
    )
    .await;
    assert_eq!(body["available"], true);
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/check-slug",
        Some(&owner),
        json!({"slug": "Bad_Slug"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The owner renames the organization. The slug is kept until it is changed.
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/organization/update",
        Some(&owner),
        json!({"organization_id": org, "name": "Acme Corp"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["organization"]["name"], "Acme Corp");
    assert_eq!(body["organization"]["slug"], "acme");

    // A slug another organization uses is refused.
    let (_, other) = call_json(
        &router,
        Method::POST,
        "/organization/create",
        Some(&stranger),
        json!({"name": "Other"}),
    )
    .await;
    let other_slug = other["organization"]["slug"].as_str().unwrap().to_owned();
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/update",
        Some(&owner),
        json!({"organization_id": org, "slug": other_slug}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A stranger cannot update or delete it.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/update",
        Some(&stranger),
        json!({"organization_id": org, "name": "Hijacked"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/delete",
        Some(&stranger),
        json!({"organization_id": org}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Deleting removes the organization for everyone.
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/organization/delete",
        Some(&owner),
        json!({"organization_id": org}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted"], true);
    let (status, _) = call_json(&router, Method::GET, &path, Some(&owner), Value::Null).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invitations_can_be_listed_cancelled_rejected_and_accepted() {
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(sender.clone());
    let owner = sign_up(&router, "owner@example.com").await;
    let stranger = sign_up(&router, "stranger@example.com").await;
    let (_, created) = call_json(
        &router,
        Method::POST,
        "/organization/create",
        Some(&owner),
        json!({"name": "Acme"}),
    )
    .await;
    let org = created["organization"]["id"].as_str().unwrap().to_owned();

    // An invitation to a person who will decline it.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/invite-member",
        Some(&owner),
        json!({"organization_id": org, "email": "declines@example.com", "role": "member"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let declines = sign_up(&router, "declines@example.com").await;
    let (_, listed) = call_json(
        &router,
        Method::GET,
        "/organization/list-user-invitations",
        Some(&declines),
        Value::Null,
    )
    .await;
    let invitations = listed["invitations"].as_array().unwrap();
    assert_eq!(invitations.len(), 1);
    assert_eq!(invitations[0]["organization_id"], org);
    // The token hash is never part of an invitation.
    assert!(!listed.to_string().contains("token"));
    let invitation_id = invitations[0]["id"].as_str().unwrap().to_owned();

    // Only the addressee can decline, and declining takes the invitation away.
    let (_, body) = call_json(
        &router,
        Method::POST,
        "/organization/reject-invitation",
        Some(&stranger),
        json!({"invitation_id": invitation_id}),
    )
    .await;
    assert_eq!(body["rejected"], false);
    let (_, body) = call_json(
        &router,
        Method::POST,
        "/organization/reject-invitation",
        Some(&declines),
        json!({"invitation_id": invitation_id}),
    )
    .await;
    assert_eq!(body["rejected"], true);
    let (_, listed) = call_json(
        &router,
        Method::GET,
        "/organization/list-user-invitations",
        Some(&declines),
        Value::Null,
    )
    .await;
    assert!(listed["invitations"].as_array().unwrap().is_empty());

    // An invitation the owner withdraws.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/invite-member",
        Some(&owner),
        json!({"organization_id": org, "email": "withdrawn@example.com", "role": "member"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, listed) = call_json(
        &router,
        Method::GET,
        &format!("/organization/list-invitations?organization_id={org}"),
        Some(&owner),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let withdrawn_id = listed["invitations"][0]["id"].as_str().unwrap().to_owned();
    let (_, body) = call_json(
        &router,
        Method::POST,
        "/organization/cancel-invitation",
        Some(&owner),
        json!({"organization_id": org, "invitation_id": withdrawn_id}),
    )
    .await;
    assert_eq!(body["cancelled"], true);
    let (_, body) = call_json(
        &router,
        Method::POST,
        "/organization/cancel-invitation",
        Some(&owner),
        json!({"organization_id": org, "invitation_id": withdrawn_id}),
    )
    .await;
    assert_eq!(body["cancelled"], false);

    // Invitations are not listed to people outside the organization.
    let (status, _) = call_json(
        &router,
        Method::GET,
        &format!("/organization/list-invitations?organization_id={org}"),
        Some(&stranger),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn members_leave_and_the_last_owner_stays() {
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
    let token = invitation_token(&sender);
    let member = sign_up(&router, "member@example.com").await;
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/accept-invitation",
        Some(&member),
        json!({"token": token}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // A plain member cannot change the organization.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/update",
        Some(&member),
        json!({"organization_id": org, "name": "Renamed"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/delete",
        Some(&member),
        json!({"organization_id": org}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The last owner cannot leave. A member can.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/leave",
        Some(&owner),
        json!({"organization_id": org}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/organization/leave",
        Some(&member),
        json!({"organization_id": org}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["left"], true);
    let (status, _) = call_json(
        &router,
        Method::GET,
        &format!("/organization/get-organization?organization_id={org}"),
        Some(&member),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
