//! SCIM Users over HTTP. Each organization's bearer token sees and changes only its own
//! members, a shared user cannot be changed from one organization, and no SCIM request
//! can set a role.

use better_auth::{
    context::AuthContext,
    plugins::{OrganizationPlugin, ScimPlugin},
    router::{AuthRouter, HttpRequest, HttpResponse},
};
use better_auth_core::{
    adapter::{memory::MemoryDb, memory::MemorySecondaryStorage, DbAdapter},
    options::{AuthOptions, BaseUrl},
};
use http::{header, HeaderMap, Method, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;

const ORIGIN: &str = "https://example.com";
const PASSWORD: &str = "correct horse battery staple";

struct Fixture {
    router: AuthRouter,
    db: Arc<MemoryDb>,
}

fn fixture() -> Fixture {
    let db = Arc::new(MemoryDb::default());
    let context = AuthContext::new(
        AuthOptions {
            secret: "s".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        db.clone(),
        Some(Arc::new(MemorySecondaryStorage::default())),
        vec![Arc::new(OrganizationPlugin), Arc::new(ScimPlugin)],
    )
    .unwrap();
    Fixture {
        router: AuthRouter::new(context).unwrap(),
        db,
    }
}

async fn send(
    router: &AuthRouter,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
    body: Value,
) -> (StatusCode, Value, HeaderMap) {
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
    let value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    (response.status, value, response.headers)
}

async fn sign_up(router: &AuthRouter, email: &str) -> String {
    let (status, _, headers) = send(
        router,
        Method::POST,
        "/sign-up/email",
        None,
        None,
        json!({"email": email, "name": "Person", "password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.contains("session_token="))
        .map(|value| value.split(';').next().unwrap().to_owned())
        .expect("sign-up sets a session")
}

async fn create_org(router: &AuthRouter, cookie: &str, name: &str) -> String {
    let (_, body, _) = send(
        router,
        Method::POST,
        "/organization/create",
        Some(cookie),
        None,
        json!({"name": name}),
    )
    .await;
    body["organization"]["id"].as_str().unwrap().to_owned()
}

async fn token_for(router: &AuthRouter, cookie: &str, org: &str) -> String {
    let (status, body, _) = send(
        router,
        Method::POST,
        "/scim/generate-token",
        Some(cookie),
        None,
        json!({"organization_id": org}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn tokens_are_issued_to_organization_admins_and_required_for_every_request() {
    let f = fixture();
    let owner = sign_up(&f.router, "owner@example.com").await;
    let org = create_org(&f.router, &owner, "Acme").await;

    // A stranger cannot issue a token for an organization they do not manage.
    let stranger = sign_up(&f.router, "stranger@example.com").await;
    let (status, _, _) = send(
        &f.router,
        Method::POST,
        "/scim/generate-token",
        Some(&stranger),
        None,
        json!({"organization_id": org}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let token = token_for(&f.router, &owner, &org).await;
    // Requests without a valid bearer token are refused.
    let (status, _, _) = send(
        &f.router,
        Method::GET,
        "/scim/v2/Users",
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = send(
        &f.router,
        Method::GET,
        "/scim/v2/Users",
        None,
        Some("not-a-real-token"),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = send(
        &f.router,
        Method::GET,
        "/scim/v2/Users",
        None,
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // A token that has expired is refused.
    let (_, body, _) = send(
        &f.router,
        Method::POST,
        "/scim/generate-token",
        Some(&owner),
        None,
        json!({"organization_id": org, "expires_in": 0}),
    )
    .await;
    let expired = body["token"].as_str().unwrap().to_owned();
    let (status, _, _) = send(
        &f.router,
        Method::GET,
        "/scim/v2/Users",
        None,
        Some(&expired),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn scim_creates_members_and_refuses_to_take_over_an_existing_account() {
    let f = fixture();
    let owner = sign_up(&f.router, "owner@example.com").await;
    let org = create_org(&f.router, &owner, "Acme").await;
    let token = token_for(&f.router, &owner, &org).await;

    let (status, created, _) = send(
        &f.router,
        Method::POST,
        "/scim/v2/Users",
        None,
        Some(&token),
        json!({"userName": "New.Hire@Example.com", "displayName": "New Hire"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["userName"], "new.hire@example.com");
    let id = created["id"].as_str().unwrap().to_owned();

    // The new user appears in the organization's listing.
    let (_, page, _) = send(
        &f.router,
        Method::GET,
        "/scim/v2/Users",
        None,
        Some(&token),
        Value::Null,
    )
    .await;
    // The owner is a member of the organization too, so the listing has two users.
    assert_eq!(page["totalResults"], 2);
    let listed: Vec<&str> = page["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|user| user["id"].as_str())
        .collect();
    assert!(listed.contains(&id.as_str()));

    // An email that already has an account is refused, and the account is untouched.
    let (status, _, _) = send(
        &f.router,
        Method::POST,
        "/scim/v2/Users",
        None,
        Some(&token),
        json!({"userName": "owner@example.com"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = send(
        &f.router,
        Method::POST,
        "/sign-in/email",
        None,
        None,
        json!({"email": "owner@example.com", "password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn one_organizations_token_cannot_reach_another_organizations_users() {
    let f = fixture();
    let owner_a = sign_up(&f.router, "owner-a@example.com").await;
    let org_a = create_org(&f.router, &owner_a, "Alpha").await;
    let token_a = token_for(&f.router, &owner_a, &org_a).await;
    let owner_b = sign_up(&f.router, "owner-b@example.com").await;
    let org_b = create_org(&f.router, &owner_b, "Beta").await;
    let token_b = token_for(&f.router, &owner_b, &org_b).await;

    let (_, created_b, _) = send(
        &f.router,
        Method::POST,
        "/scim/v2/Users",
        None,
        Some(&token_b),
        json!({"userName": "beta-only@example.com"}),
    )
    .await;
    let beta_id = created_b["id"].as_str().unwrap().to_owned();

    // Alpha's token sees none of Beta's users and cannot read, change or remove them.
    let (_, page, _) = send(
        &f.router,
        Method::GET,
        "/scim/v2/Users",
        None,
        Some(&token_a),
        Value::Null,
    )
    .await;
    let listed: Vec<&str> = page["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|user| user["id"].as_str())
        .collect();
    assert!(
        !listed.contains(&beta_id.as_str()),
        "Beta's user is not listed to Alpha"
    );
    let path = format!("/scim/v2/Users/{beta_id}");
    let (status, _, _) = send(
        &f.router,
        Method::GET,
        &path,
        None,
        Some(&token_a),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = send(
        &f.router,
        Method::PATCH,
        &path,
        None,
        Some(&token_a),
        json!({"displayName": "Hijacked"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = send(
        &f.router,
        Method::DELETE,
        &path,
        None,
        Some(&token_a),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Beta still has the user, unchanged.
    let (status, body, _) = send(
        &f.router,
        Method::GET,
        &path,
        None,
        Some(&token_b),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["userName"], "beta-only@example.com");
}

#[tokio::test]
async fn scim_cannot_set_roles_and_a_shared_user_is_protected_across_organizations() {
    let f = fixture();
    let owner_a = sign_up(&f.router, "owner-a@example.com").await;
    let org_a = create_org(&f.router, &owner_a, "Alpha").await;
    let token_a = token_for(&f.router, &owner_a, &org_a).await;
    let owner_b = sign_up(&f.router, "owner-b@example.com").await;
    let org_b = create_org(&f.router, &owner_b, "Beta").await;

    let (_, created, _) = send(
        &f.router,
        Method::POST,
        "/scim/v2/Users",
        None,
        Some(&token_a),
        json!({"userName": "shared@example.com", "displayName": "Shared"}),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_owned();
    let path = format!("/scim/v2/Users/{id}");

    // Role changes are refused, in either patch form.
    let (status, _, _) = send(
        &f.router,
        Method::PATCH,
        &path,
        None,
        Some(&token_a),
        json!({"role": "admin"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = send(
        &f.router,
        Method::PATCH,
        &path,
        None,
        Some(&token_a),
        json!([{"op": "replace", "path": "role", "value": "admin"}]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The user is then also a member of Beta, through an ordinary membership record.
    f.db.insert_record("organization_member", json!({"id": format!("{org_b}:{id}"), "organization_id": org_b, "user_id": id, "role": "member"}))
        .await
        .unwrap();

    // Alpha can neither rename, deactivate, nor change the email of a shared user.
    let (status, _, _) = send(
        &f.router,
        Method::PATCH,
        &path,
        None,
        Some(&token_a),
        json!({"displayName": "Renamed"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = send(
        &f.router,
        Method::PATCH,
        &path,
        None,
        Some(&token_a),
        json!({"active": false}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Removing the user from Alpha leaves the account and Beta's membership in place.
    let (status, _, _) = send(
        &f.router,
        Method::DELETE,
        &path,
        None,
        Some(&token_a),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let owner_b_token = token_for(&f.router, &owner_b, &org_b).await;
    let (status, body, _) = send(
        &f.router,
        Method::GET,
        &path,
        None,
        Some(&owner_b_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["userName"], "shared@example.com");
}

#[tokio::test]
async fn filters_apply_within_the_organization_and_bulk_is_not_mounted() {
    let f = fixture();
    let owner = sign_up(&f.router, "owner@example.com").await;
    let org = create_org(&f.router, &owner, "Acme").await;
    let token = token_for(&f.router, &owner, &org).await;
    for name in ["ada@example.com", "grace@example.com"] {
        let (status, _, _) = send(
            &f.router,
            Method::POST,
            "/scim/v2/Users",
            None,
            Some(&token),
            json!({"userName": name}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let (_, page, _) = send(
        &f.router,
        Method::GET,
        "/scim/v2/Users?filter=userName%20eq%20%22grace%40example.com%22",
        None,
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(page["totalResults"], 1);
    assert_eq!(page["Resources"][0]["userName"], "grace@example.com");

    // Bulk is not available until it is scoped, so it is not mounted at all.
    let (status, _, _) = send(
        &f.router,
        Method::POST,
        "/scim/v2/Bulk",
        None,
        Some(&token),
        json!({"Operations": []}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
