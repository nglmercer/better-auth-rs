//! The origin and Fetch Metadata policy for state-changing requests, case by case.

use better_auth::{
    context::AuthContext,
    router::{AuthRouter, HttpRequest},
};
use better_auth_core::{
    adapter::memory::{MemoryDb, MemorySecondaryStorage},
    options::{AuthOptions, BaseUrl},
};
use http::{header, HeaderMap, Method, StatusCode};
use std::sync::Arc;

const ORIGIN: &str = "https://example.com";

fn router() -> AuthRouter {
    let context = AuthContext::new(
        AuthOptions {
            secret: "c".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        Vec::new(),
    )
    .unwrap();
    AuthRouter::new(context).unwrap()
}

/// POST /sign-out is public and changes nothing when there is no session, so it isolates
/// the origin policy from every other check.
async fn post_with(router: &AuthRouter, headers: &[(&str, &str)]) -> StatusCode {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    router
        .handle(HttpRequest::new(
            Method::POST,
            "/api/auth/sign-out".parse().unwrap(),
            map,
            Vec::new(),
        ))
        .await
        .status
}

#[tokio::test]
async fn the_origin_and_fetch_metadata_policy_is_explicit() {
    let router = router();
    // Absent headers come from non-browser clients, which are accepted.
    assert_eq!(post_with(&router, &[]).await, StatusCode::OK);
    // A trusted origin, with or without a same-site fetch, is accepted.
    assert_eq!(
        post_with(&router, &[("origin", ORIGIN)]).await,
        StatusCode::OK
    );
    assert_eq!(
        post_with(
            &router,
            &[("origin", ORIGIN), ("sec-fetch-site", "same-origin")]
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        post_with(&router, &[("sec-fetch-site", "same-site")]).await,
        StatusCode::OK
    );
    assert_eq!(
        post_with(&router, &[("sec-fetch-site", "none")]).await,
        StatusCode::OK
    );

    // An opaque origin is never trusted, even though it is not an address anyone can host.
    assert_eq!(
        post_with(&router, &[("origin", "null")]).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post_with(&router, &[("origin", "https://evil.example")]).await,
        StatusCode::FORBIDDEN
    );
    // Cross-site and cross-origin fetches are refused.
    assert_eq!(
        post_with(&router, &[("sec-fetch-site", "cross-site")]).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post_with(&router, &[("sec-fetch-site", "cross-origin")]).await,
        StatusCode::FORBIDDEN
    );
    // A fetch-site value outside the allowlist is refused rather than assumed harmless.
    assert_eq!(
        post_with(&router, &[("sec-fetch-site", "banana")]).await,
        StatusCode::FORBIDDEN
    );
    // Conflicting signals: a trusted origin can not excuse a cross-site fetch, and a
    // foreign origin can not hide behind a same-origin fetch.
    assert_eq!(
        post_with(
            &router,
            &[("origin", ORIGIN), ("sec-fetch-site", "cross-site")]
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post_with(
            &router,
            &[
                ("origin", "https://evil.example"),
                ("sec-fetch-site", "same-origin")
            ]
        )
        .await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn safe_methods_are_never_checked() {
    let router = router();
    let mut map = HeaderMap::new();
    map.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
    map.insert("sec-fetch-site", "cross-site".parse().unwrap());
    let response = router
        .handle(HttpRequest::new(
            Method::GET,
            "/api/auth/ok".parse().unwrap(),
            map,
            Vec::new(),
        ))
        .await;
    assert_eq!(response.status, StatusCode::OK);
}
