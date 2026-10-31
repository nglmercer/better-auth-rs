//! Magic-link sign-in: the GET confirmation page changes nothing, the POST signs in
//! and redirects only to a path on this site, and foreign origins are refused.

use better_auth::{
    context::AuthContext,
    email::CapturingEmailSender,
    plugins::MagicLinkPlugin,
    router::{AuthRouter, HttpRequest, HttpResponse},
};
use better_auth_core::{
    adapter::memory::{MemoryDb, MemorySecondaryStorage},
    options::{AuthOptions, BaseUrl},
};
use http::{header, HeaderMap, Method, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;

const ORIGIN: &str = "https://example.com";

fn router(sender: Arc<CapturingEmailSender>) -> AuthRouter {
    let context = AuthContext::new(
        AuthOptions {
            secret: "m".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        vec![Arc::new(MagicLinkPlugin)],
    )
    .unwrap();
    AuthRouter::new(context)
        .unwrap()
        .with_email_sender(sender)
        .unwrap()
}

/// Sends one request. `form` posts an urlencoded body, `json` a JSON body.
async fn send(
    router: &AuthRouter,
    method: Method,
    path: &str,
    origin: &str,
    content_type: Option<&str>,
    body: Vec<u8>,
) -> HttpResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, origin.parse().unwrap());
    if let Some(content_type) = content_type {
        headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    }
    router
        .handle(HttpRequest::new(
            method,
            format!("/api/auth{path}").parse().unwrap(),
            headers,
            body,
        ))
        .await
}

async fn send_json(router: &AuthRouter, method: Method, path: &str, body: Value) -> HttpResponse {
    send(
        router,
        method,
        path,
        ORIGIN,
        Some("application/json"),
        body.to_string().into_bytes(),
    )
    .await
}

fn link_from(sender: &CapturingEmailSender) -> url::Url {
    let text = sender.last().unwrap().text;
    let start = text.find("https://").expect("the email contains a link");
    let end = text[start..]
        .find(char::is_whitespace)
        .map_or(text.len(), |i| start + i);
    url::Url::parse(&text[start..end]).unwrap()
}

fn token_of(link: &url::Url) -> String {
    link.query_pairs()
        .find(|(key, _)| key == "token")
        .map(|(_, value)| value.into_owned())
        .expect("the link carries a token")
}

fn session_cookie(response: &HttpResponse) -> Option<String> {
    response
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.contains("session_token="))
        .map(str::to_owned)
}

#[tokio::test]
async fn the_confirmation_page_changes_nothing_and_posting_signs_in_once() {
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(sender.clone());
    let response = send_json(
        &router,
        Method::POST,
        "/sign-in/magic-link",
        json!({"email": "reader@example.com"}),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    let link = link_from(&sender);
    let token = token_of(&link);

    // Opening the link, as a mail scanner would, shows a form and signs nothing in.
    let page = send(
        &router,
        Method::GET,
        &format!("/magic-link/verify?token={token}"),
        ORIGIN,
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(session_cookie(&page).is_none());
    assert_eq!(
        page.headers.get(header::CONTENT_SECURITY_POLICY).unwrap(),
        "default-src 'none'; form-action 'self'; style-src 'unsafe-inline'"
    );
    let html = String::from_utf8(page.body).unwrap();
    assert!(html.contains(&format!("value=\"{token}\"")));
    assert!(html.contains("method=\"post\""));

    // The button posts the token from the same origin, and the session is created.
    let form = format!("token={token}&callbackURL=%2Fdashboard");
    let signed_in = send(
        &router,
        Method::POST,
        "/magic-link/verify",
        ORIGIN,
        Some("application/x-www-form-urlencoded"),
        form.clone().into_bytes(),
    )
    .await;
    assert_eq!(signed_in.status, StatusCode::SEE_OTHER);
    assert_eq!(
        signed_in.headers.get(header::LOCATION).unwrap(),
        "/dashboard"
    );
    assert!(session_cookie(&signed_in).is_some());

    // The same link does not work again.
    let replay = send(
        &router,
        Method::POST,
        "/magic-link/verify",
        ORIGIN,
        Some("application/x-www-form-urlencoded"),
        form.into_bytes(),
    )
    .await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn callbacks_must_be_paths_on_this_site() {
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(sender.clone());

    // Off-site and protocol-relative callbacks are refused when the link is requested.
    for bad in [
        "https://evil.example/",
        "//evil.example/",
        "/\\evil.example",
    ] {
        let response = send_json(
            &router,
            Method::POST,
            "/sign-in/magic-link",
            json!({"email": "bad@example.com", "callbackURL": bad}),
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert!(sender.messages().is_empty());

    // A good callback is carried in the link and used after sign-in.
    let response = send_json(
        &router,
        Method::POST,
        "/sign-in/magic-link",
        json!({"email": "good@example.com", "callbackURL": "/welcome?step=1"}),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    let link = link_from(&sender);
    assert_eq!(
        link.query_pairs()
            .find(|(k, _)| k == "callbackURL")
            .unwrap()
            .1,
        "/welcome?step=1"
    );
    let token = token_of(&link);

    // A callback posted by a form that was tampered with falls back to "/".
    let form = format!("token={token}&callbackURL=https%3A%2F%2Fevil.example%2F");
    let signed_in = send(
        &router,
        Method::POST,
        "/magic-link/verify",
        ORIGIN,
        Some("application/x-www-form-urlencoded"),
        form.into_bytes(),
    )
    .await;
    assert_eq!(signed_in.status, StatusCode::SEE_OTHER);
    assert_eq!(signed_in.headers.get(header::LOCATION).unwrap(), "/");
}

#[tokio::test]
async fn a_post_from_another_site_is_refused_before_the_link_is_spent() {
    let sender = Arc::new(CapturingEmailSender::default());
    let router = router(sender.clone());
    send_json(
        &router,
        Method::POST,
        "/sign-in/magic-link",
        json!({"email": "victim@example.com"}),
    )
    .await;
    let token = token_of(&link_from(&sender));

    // A page on another site cannot make the browser sign in with this link.
    let forged = send(
        &router,
        Method::POST,
        "/magic-link/verify",
        "https://evil.example",
        Some("application/x-www-form-urlencoded"),
        format!("token={token}").into_bytes(),
    )
    .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);

    // The link still works for the person who received it.
    let genuine = send(
        &router,
        Method::POST,
        "/magic-link/verify",
        ORIGIN,
        Some("application/x-www-form-urlencoded"),
        format!("token={token}").into_bytes(),
    )
    .await;
    assert_eq!(genuine.status, StatusCode::SEE_OTHER);
}
