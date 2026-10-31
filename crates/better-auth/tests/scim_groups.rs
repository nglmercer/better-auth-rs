//! SCIM Groups over HTTP. A group belongs to one organization. Its members are that
//! organization's members, and another organization's token cannot see or change it.

use better_auth::{
    context::AuthContext,
    plugins::{OrganizationPlugin, ScimPlugin},
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

fn router() -> AuthRouter {
    let context = AuthContext::new(
        AuthOptions {
            secret: "g".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        vec![Arc::new(OrganizationPlugin), Arc::new(ScimPlugin)],
    )
    .unwrap();
    AuthRouter::new(context).unwrap()
}

async fn send(
    router: &AuthRouter,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    if let Some(cookie) = cookie {
        headers.insert(header::COOKIE, cookie.parse().unwrap());
    }
    if let Some(bearer) = bearer {
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {bearer}").parse().unwrap(),
        );
    }
    let payload = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    let response: HttpResponse = router
        .handle(HttpRequest::new(
            method,
            format!("/api/auth{path}").parse().unwrap(),
            headers,
            payload,
        ))
        .await;
    (
        response.status,
        serde_json::from_slice(&response.body).unwrap_or(Value::Null),
    )
}

async fn sign_up(router: &AuthRouter, email: &str) -> String {
    let (_, body) = send(
        router,
        Method::POST,
        "/sign-up/email",
        None,
        None,
        json!({"email": email, "name": "Person", "password": PASSWORD}),
    )
    .await;
    let _ = body;
    // Sign-up's cookie is read from the response headers below.
    let response = router
        .handle(HttpRequest::new(
            Method::POST,
            "/api/auth/sign-in/email".parse().unwrap(),
            {
                let mut headers = HeaderMap::new();
                headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
                headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
                headers
            },
            json!({"email": email, "password": PASSWORD})
                .to_string()
                .into_bytes(),
        ))
        .await;
    response
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.contains("session_token="))
        .map(|value| value.split(';').next().unwrap().to_owned())
        .expect("sign-in sets a session")
}

async fn organization_with_token(router: &AuthRouter, name: &str, email: &str) -> (String, String) {
    let cookie = sign_up(router, email).await;
    let (_, created) = send(
        router,
        Method::POST,
        "/organization/create",
        Some(&cookie),
        None,
        json!({"name": name}),
    )
    .await;
    let org = created["organization"]["id"].as_str().unwrap().to_owned();
    let (_, issued) = send(
        router,
        Method::POST,
        "/scim/generate-token",
        Some(&cookie),
        None,
        json!({"organization_id": org}),
    )
    .await;
    (org, issued["token"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn groups_hold_only_their_organizations_members_and_stay_inside_it() {
    let router = router();
    let (_, alpha_token) = organization_with_token(&router, "Alpha", "alpha@example.com").await;
    let (_, beta_token) = organization_with_token(&router, "Beta", "beta@example.com").await;
    let (status, alice) = send(
        &router,
        Method::POST,
        "/scim/v2/Users",
        None,
        Some(&alpha_token),
        json!({"userName": "alice@example.com"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let alice_id = alice["id"].as_str().unwrap().to_owned();
    let (_, bob) = send(
        &router,
        Method::POST,
        "/scim/v2/Users",
        None,
        Some(&beta_token),
        json!({"userName": "bob@example.com"}),
    )
    .await;
    let bob_id = bob["id"].as_str().unwrap().to_owned();

    // Alpha creates a group with Alice, and Bob cannot be added to it.
    let (status, group) = send(
        &router,
        Method::POST,
        "/scim/v2/Groups",
        None,
        Some(&alpha_token),
        json!({"displayName": "Operators", "members": [{"value": alice_id}]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{group}");
    let group_id = group["id"].as_str().unwrap().to_owned();
    assert_eq!(group["members"][0]["value"], alice_id);
    let (status, _) = send(
        &router,
        Method::PATCH,
        &format!("/scim/v2/Groups/{group_id}"),
        None,
        Some(&alpha_token),
        json!({"members": [{"value": bob_id}]}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a user of another organization cannot join"
    );

    // Beta cannot read, rename, or delete Alpha's group, and does not list it.
    let path = format!("/scim/v2/Groups/{group_id}");
    let (status, _) = send(
        &router,
        Method::GET,
        &path,
        None,
        Some(&beta_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(
        &router,
        Method::PATCH,
        &path,
        None,
        Some(&beta_token),
        json!({"displayName": "Taken"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(
        &router,
        Method::DELETE,
        &path,
        None,
        Some(&beta_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, listed) = send(
        &router,
        Method::GET,
        "/scim/v2/Groups",
        None,
        Some(&beta_token),
        Value::Null,
    )
    .await;
    assert_eq!(listed["totalResults"], 0);

    // Alpha renames its group, and the change is visible to Alpha.
    let (status, renamed) = send(
        &router,
        Method::PATCH,
        &path,
        None,
        Some(&alpha_token),
        json!({"displayName": "Operators East"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(renamed["displayName"], "Operators East");

    // Removing Alice from Alpha takes her out of the group, and she is not listed there any more.
    let (status, _) = send(
        &router,
        Method::DELETE,
        &format!("/scim/v2/Users/{alice_id}"),
        None,
        Some(&alpha_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, after) = send(
        &router,
        Method::GET,
        &path,
        None,
        Some(&alpha_token),
        Value::Null,
    )
    .await;
    assert_eq!(after["members"], json!([]));

    // Alpha deletes the group.
    let (status, _) = send(
        &router,
        Method::DELETE,
        &path,
        None,
        Some(&alpha_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, listed) = send(
        &router,
        Method::GET,
        "/scim/v2/Groups",
        None,
        Some(&alpha_token),
        Value::Null,
    )
    .await;
    assert_eq!(listed["totalResults"], 0);
}
