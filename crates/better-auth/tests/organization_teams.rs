//! Organization teams over HTTP: creating and renaming teams, adding and removing
//! members, scoping by organization, and cleanup when someone leaves.

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
            secret: "t".repeat(32),
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

async fn call_json(
    router: &AuthRouter,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
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
    let response: HttpResponse = router
        .handle(HttpRequest::new(
            method,
            format!("/api/auth{path}").parse().unwrap(),
            headers,
            payload,
        ))
        .await;
    let body = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    (response.status, body)
}

async fn sign_up(router: &AuthRouter, email: &str) -> String {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    let body = json!({"email": email, "name": "Person", "password": PASSWORD}).to_string();
    let response = router
        .handle(HttpRequest::new(
            Method::POST,
            "/api/auth/sign-up/email".parse().unwrap(),
            headers,
            body.into_bytes(),
        ))
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

/// A member of `org` who joined through an invitation.
async fn join(
    router: &AuthRouter,
    sender: &CapturingEmailSender,
    owner: &str,
    org: &str,
    email: &str,
) -> (String, String) {
    let (status, _) = call_json(
        router,
        Method::POST,
        "/organization/invite-member",
        Some(owner),
        json!({"organization_id": org, "email": email, "role": "member"}),
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
    let cookie = sign_up(router, email).await;
    let (_, body) = call_json(
        router,
        Method::POST,
        "/organization/accept-invitation",
        Some(&cookie),
        json!({"token": token}),
    )
    .await;
    let user_id = body["member"]["user_id"].as_str().unwrap().to_owned();
    (cookie, user_id)
}

#[tokio::test]
async fn teams_are_managed_by_managers_and_only_hold_organization_members() {
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
    let (member, member_id) = join(&router, &sender, &owner, &org, "member@example.com").await;
    let stranger = sign_up(&router, "stranger@example.com").await;

    // Members cannot create teams.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/create-team",
        Some(&member),
        json!({"organization_id": org, "name": "Core"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = call_json(
        &router,
        Method::POST,
        "/organization/create-team",
        Some(&owner),
        json!({"organization_id": org, "name": "Core"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let team = body["team"]["id"].as_str().unwrap().to_owned();

    // Only organization members can be added to a team.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/add-team-member",
        Some(&owner),
        json!({"organization_id": org, "team_id": team, "user_id": "not-a-member"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/add-team-member",
        Some(&owner),
        json!({"organization_id": org, "team_id": team, "user_id": member_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Members see the team, its members, and their own teams.
    let (_, listed) = call_json(
        &router,
        Method::GET,
        &format!("/organization/list-team-members?organization_id={org}&team_id={team}"),
        Some(&member),
        Value::Null,
    )
    .await;
    assert_eq!(listed["members"], json!([member_id]));
    let (_, user_teams) = call_json(
        &router,
        Method::GET,
        "/organization/list-user-teams",
        Some(&member),
        Value::Null,
    )
    .await;
    assert_eq!(user_teams["teams"].as_array().unwrap().len(), 1);

    // Members cannot rename the team, and outsiders cannot see it at all.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/update-team",
        Some(&member),
        json!({"organization_id": org, "team_id": team, "name": "Renamed"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call_json(
        &router,
        Method::GET,
        &format!("/organization/list-team-members?organization_id={org}&team_id={team}"),
        Some(&stranger),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Owners rename a team and remove a member from it.
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/organization/update-team",
        Some(&owner),
        json!({"organization_id": org, "team_id": team, "name": "Core Team"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["team"]["name"], "Core Team");
    let (_, body) = call_json(
        &router,
        Method::POST,
        "/organization/remove-team-member",
        Some(&owner),
        json!({"organization_id": org, "team_id": team, "user_id": member_id}),
    )
    .await;
    assert_eq!(body["removed"], true);
    let (_, body) = call_json(
        &router,
        Method::POST,
        "/organization/remove-team-member",
        Some(&owner),
        json!({"organization_id": org, "team_id": team, "user_id": member_id}),
    )
    .await;
    assert_eq!(body["removed"], false);

    // A team is only reachable through its own organization.
    let (_, other) = call_json(
        &router,
        Method::POST,
        "/organization/create",
        Some(&stranger),
        json!({"name": "Other"}),
    )
    .await;
    let other_org = other["organization"]["id"].as_str().unwrap().to_owned();
    let (_, other_team) = call_json(
        &router,
        Method::POST,
        "/organization/create-team",
        Some(&stranger),
        json!({"organization_id": other_org, "name": "Theirs"}),
    )
    .await;
    let other_team_id = other_team["team"]["id"].as_str().unwrap().to_owned();
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/remove-team",
        Some(&owner),
        json!({"organization_id": org, "team_id": other_team_id}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Removing a team takes it away from the listing.
    let (status, body) = call_json(
        &router,
        Method::POST,
        "/organization/remove-team",
        Some(&owner),
        json!({"organization_id": org, "team_id": team}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["removed"], true);
    let (_, listed) = call_json(
        &router,
        Method::GET,
        &format!("/organization/list-teams?organization_id={org}"),
        Some(&owner),
        Value::Null,
    )
    .await;
    assert!(listed["teams"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn leaving_an_organization_or_deleting_it_clears_its_teams() {
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
    let (member, member_id) = join(&router, &sender, &owner, &org, "member@example.com").await;
    let (_, body) = call_json(
        &router,
        Method::POST,
        "/organization/create-team",
        Some(&owner),
        json!({"organization_id": org, "name": "Core"}),
    )
    .await;
    let team = body["team"]["id"].as_str().unwrap().to_owned();
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/add-team-member",
        Some(&owner),
        json!({"organization_id": org, "team_id": team, "user_id": member_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Leaving the organization also leaves its teams.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/leave",
        Some(&member),
        json!({"organization_id": org}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, user_teams) = call_json(
        &router,
        Method::GET,
        "/organization/list-user-teams",
        Some(&member),
        Value::Null,
    )
    .await;
    assert!(user_teams["teams"].as_array().unwrap().is_empty());

    // Deleting the organization deletes its teams, so nothing is left behind.
    let (status, _) = call_json(
        &router,
        Method::POST,
        "/organization/delete",
        Some(&owner),
        json!({"organization_id": org}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call_json(
        &router,
        Method::GET,
        &format!("/organization/list-teams?organization_id={org}"),
        Some(&owner),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
