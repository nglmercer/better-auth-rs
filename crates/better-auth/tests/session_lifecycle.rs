//! Session revocation, expiry and renewal, including stale cookie-cache credentials and
//! several application instances that share one database.
//!
//! A revoked or expired session must not authenticate, even when the browser still
//! holds a valid cookie-cache value or a bearer token from before the revocation.

use better_auth::{
    context::AuthContext,
    email_password::{EmailPasswordService, SignUpInput},
    session::{SessionService, SessionTransport},
};
use better_auth_core::{
    adapter::{memory::MemoryDb, memory::MemorySecondaryStorage},
    options::{AuthOptions, BaseUrl, PasswordHashOptions},
};
use http::{header, HeaderMap};
use std::{sync::Arc, time::Duration};

const ORIGIN: &str = "https://app.example.test";

fn options(cache: bool, expires_in_seconds: u64) -> AuthOptions {
    let mut options = AuthOptions {
        secret: "s".repeat(32),
        base_url: Some(BaseUrl::Static(ORIGIN.into())),
        has_database: true,
        password_hash: PasswordHashOptions {
            scrypt_log_n: 10,
            ..PasswordHashOptions::default()
        },
        ..AuthOptions::default()
    };
    options.session.expires_in_seconds = expires_in_seconds;
    options.session.cookie_cache.enabled = cache;
    options.session.cookie_cache.max_age_seconds = 3600;
    options
}

/// Two contexts over one database and one secondary store: two application instances.
fn shared_instances(cache: bool, expires_in_seconds: u64) -> (AuthContext, AuthContext) {
    let db = Arc::new(MemoryDb::default());
    let storage = Arc::new(MemorySecondaryStorage::default());
    let make = || {
        AuthContext::new(
            options(cache, expires_in_seconds),
            db.clone(),
            Some(storage.clone()),
            vec![],
        )
        .unwrap()
    };
    (make(), make())
}

struct Login {
    user_id: String,
    token: String,
    cookie_header: HeaderMap,
    bearer_header: HeaderMap,
}

async fn sign_up(context: &AuthContext) -> Login {
    let result = EmailPasswordService::new(context.clone())
        .unwrap()
        .sign_up(
            SignUpInput {
                email: "session@example.test".into(),
                name: "Session User".into(),
                password: "correct horse battery staple".into(),
            },
            false,
        )
        .await
        .unwrap();
    let mut cookie_header = HeaderMap::new();
    cookie_header.insert(
        header::COOKIE,
        format!("{}={}", result.cookie.name, result.cookie.value)
            .parse()
            .unwrap(),
    );
    let mut bearer_header = HeaderMap::new();
    bearer_header.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", result.session_token).parse().unwrap(),
    );
    Login {
        user_id: result.user.id,
        token: result.session_token,
        cookie_header,
        bearer_header,
    }
}

async fn authenticates_cookie(context: &AuthContext, headers: &HeaderMap) -> bool {
    SessionService::new(context.clone())
        .unwrap()
        .resolve(headers, false)
        .await
        .unwrap()
        .is_some()
}

async fn authenticates_bearer(context: &AuthContext, headers: &HeaderMap) -> bool {
    SessionService::new(context.clone())
        .unwrap()
        .resolve_with_transport(headers, false, SessionTransport::Bearer)
        .await
        .unwrap()
        .is_some()
}

#[tokio::test]
async fn revoked_session_is_refused_even_with_a_cached_cookie() {
    for cache in [false, true] {
        let (context, _) = shared_instances(cache, 3600);
        let login = sign_up(&context).await;
        assert!(authenticates_cookie(&context, &login.cookie_header).await);

        SessionService::new(context.clone())
            .unwrap()
            .revoke_token(&login.token)
            .await
            .unwrap();
        assert!(
            !authenticates_cookie(&context, &login.cookie_header).await,
            "cache enabled: {cache}"
        );
    }
}

#[tokio::test]
async fn bearer_token_is_refused_once_revoked() {
    let (context, _) = shared_instances(true, 3600);
    let login = sign_up(&context).await;
    assert!(authenticates_bearer(&context, &login.bearer_header).await);

    SessionService::new(context.clone())
        .unwrap()
        .revoke_token(&login.token)
        .await
        .unwrap();
    assert!(!authenticates_bearer(&context, &login.bearer_header).await);
}

#[tokio::test]
async fn logout_all_devices_ends_every_session_of_the_user() {
    let (context, _) = shared_instances(true, 3600);
    let first = sign_up(&context).await;
    let second = EmailPasswordService::new(context.clone())
        .unwrap()
        .sign_in(
            better_auth::email_password::SignInInput {
                email: "session@example.test".into(),
                password: "correct horse battery staple".into(),
            },
            false,
        )
        .await
        .unwrap();
    let mut second_header = HeaderMap::new();
    second_header.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", second.session_token).parse().unwrap(),
    );
    assert!(authenticates_cookie(&context, &first.cookie_header).await);
    assert!(authenticates_bearer(&context, &second_header).await);

    let removed = SessionService::new(context.clone())
        .unwrap()
        .revoke_all_for_user(&first.user_id)
        .await
        .unwrap();
    assert!(removed >= 2);
    assert!(!authenticates_cookie(&context, &first.cookie_header).await);
    assert!(!authenticates_bearer(&context, &second_header).await);
}

#[tokio::test]
async fn refresh_does_not_resurrect_a_revoked_session() {
    let (context, _) = shared_instances(true, 3600);
    let login = sign_up(&context).await;
    let service = SessionService::new(context.clone()).unwrap();
    service.revoke_token(&login.token).await.unwrap();
    let refreshed = service.refresh(&login.cookie_header, false).await.unwrap();
    assert!(refreshed.is_none());
    assert!(!authenticates_cookie(&context, &login.cookie_header).await);
}

#[tokio::test]
async fn a_revocation_on_one_instance_is_seen_by_another() {
    let (node_a, node_b) = shared_instances(true, 3600);
    let login = sign_up(&node_a).await;
    assert!(authenticates_cookie(&node_b, &login.cookie_header).await);

    SessionService::new(node_b.clone())
        .unwrap()
        .revoke_token(&login.token)
        .await
        .unwrap();
    assert!(!authenticates_cookie(&node_a, &login.cookie_header).await);
    assert!(!authenticates_cookie(&node_b, &login.cookie_header).await);
}

#[tokio::test]
async fn expired_session_is_refused_even_with_a_cached_cookie() {
    let (context, _) = shared_instances(true, 1);
    let login = sign_up(&context).await;
    assert!(authenticates_cookie(&context, &login.cookie_header).await);

    tokio::time::sleep(Duration::from_millis(2_100)).await;
    assert!(!authenticates_cookie(&context, &login.cookie_header).await);
    assert!(!authenticates_bearer(&context, &login.bearer_header).await);
}

#[tokio::test]
async fn unknown_or_forged_tokens_do_not_authenticate() {
    let (context, _) = shared_instances(true, 3600);
    let _ = sign_up(&context).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        "Bearer 00000000-0000-0000-0000-000000000000"
            .parse()
            .unwrap(),
    );
    assert!(!authenticates_bearer(&context, &headers).await);
}
