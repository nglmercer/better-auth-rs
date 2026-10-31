//! The central access table: every documented route has a stated requirement, anonymous
//! callers are refused everywhere a session is required, and non-administrators are refused
//! on every admin route except the permission check.

use better_auth::{
    context::AuthContext,
    openapi::ROUTES,
    plugins::AdminPlugin,
    router::{route_access, AuthRouter, HttpRequest, HttpResponse, RouteAccess},
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

fn router(plugins: Vec<Arc<dyn better_auth::core::plugin::Plugin>>) -> AuthRouter {
    let context = AuthContext::new(
        AuthOptions {
            secret: "p".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        plugins,
    )
    .unwrap();
    AuthRouter::new(context).unwrap()
}

async fn send(
    router: &AuthRouter,
    method: &str,
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
            method.parse::<Method>().unwrap(),
            format!("/api/auth{path}").parse().unwrap(),
            headers,
            payload,
        ))
        .await
}

async fn sign_up(router: &AuthRouter, email: &str) -> String {
    let response = send(
        router,
        "POST",
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

#[test]
fn the_access_table_agrees_with_the_documented_routes() {
    for route in ROUTES {
        let access = route_access(&route.method.parse().unwrap(), route.path);
        let requires_session = matches!(access, RouteAccess::Session | RouteAccess::Admin);
        assert_eq!(
            requires_session, route.session,
            "{} {} is documented as session={} but the table says {:?}",
            route.method, route.path, route.session, access
        );
    }
}

#[test]
fn unknown_routes_fail_closed_and_scim_uses_bearer_tokens() {
    assert_eq!(
        route_access(&Method::GET, "/no-such-route"),
        RouteAccess::Session
    );
    assert_eq!(
        route_access(&Method::GET, "/scim/v2/Users/abc"),
        RouteAccess::Bearer
    );
    assert_eq!(
        route_access(&Method::POST, "/admin/has-permission"),
        RouteAccess::Session
    );
    assert_eq!(
        route_access(&Method::POST, "/admin/set-role"),
        RouteAccess::Admin
    );
}

#[tokio::test]
async fn anonymous_callers_are_refused_on_every_route_that_needs_a_session() {
    let router = router(Vec::new());
    for route in ROUTES.iter().filter(|route| route.session) {
        let response = send(&router, route.method, route.path, None, Value::Null).await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "anonymous {} {} must be refused before the handler runs",
            route.method,
            route.path
        );
    }
}

#[tokio::test]
async fn non_administrators_are_refused_on_admin_routes_except_the_permission_check() {
    let router = router(vec![Arc::new(AdminPlugin)]);
    let member = sign_up(&router, "member@example.com").await;
    for route in ROUTES
        .iter()
        .filter(|route| route.path.starts_with("/admin/"))
    {
        let response = send(
            &router,
            route.method,
            route.path,
            Some(&member),
            json!({"permission": {"user": ["ban"]}}),
        )
        .await;
        if route.path == "/admin/has-permission" {
            assert_eq!(response.status, StatusCode::OK);
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(
                body["success"], false,
                "a non-administrator is granted nothing"
            );
        } else {
            assert_eq!(
                response.status,
                StatusCode::FORBIDDEN,
                "{} {} must refuse a non-administrator",
                route.method,
                route.path
            );
        }
    }
}
