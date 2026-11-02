//! Native (desktop) login, end to end and in its negative cases.
//!
//! The happy path runs the whole flow: a loopback callback receiver, a browser-style
//! HTTP request to the redirect URI, a backend-issued single-use handoff code, redemption
//! with the PKCE verifier, and an opt-in bearer session that authenticates. The negative
//! tests cover replay, interception, forged or wrong callbacks, wrong PKCE verifier,
//! client or redirect binding, expiry, parallel redemption, timeout and cancellation.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use better_auth::{
    context::AuthContext,
    desktop::{DesktopHandoffService, HandoffRequest, LoopbackCallbackReceiver, RedeemRequest},
    email_password::{EmailPasswordService, SignUpInput},
    session::{SessionService, SessionTransport},
};
use better_auth_core::{
    adapter::{memory::MemoryDb, memory::MemorySecondaryStorage},
    options::{AuthOptions, BaseUrl, PasswordHashOptions},
};
use http::{header, HeaderMap};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::oneshot,
};
use url::Url;

const ORIGIN: &str = "https://app.example.test";
const CLIENT_ID: &str = "desktop-client";
const STATE: &str = "desktop-state-0123456789";
const PASSWORD: &str = "correct horse battery staple";

fn context() -> AuthContext {
    AuthContext::new(
        AuthOptions {
            secret: "d".repeat(32),
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
        vec![],
    )
    .unwrap()
}

/// Returns a PKCE verifier and its S256 challenge.
fn pkce() -> (String, String) {
    let verifier = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

async fn signed_up_user(context: &AuthContext) -> (String, String) {
    let result = EmailPasswordService::new(context.clone())
        .unwrap()
        .sign_up(
            SignUpInput {
                email: "native@example.test".into(),
                name: "Native User".into(),
                password: PASSWORD.into(),
            },
            false,
        )
        .await
        .unwrap();
    (
        result.user.id,
        format!("{}={}", result.cookie.name, result.cookie.value),
    )
}

fn request(redirect_uri: &str, challenge: &str, ttl: Duration) -> HandoffRequest {
    HandoffRequest {
        client_id: CLIENT_ID.into(),
        redirect_uri: redirect_uri.into(),
        code_challenge: challenge.into(),
        ttl,
    }
}

fn redeem(code: &str, verifier: &str, redirect_uri: &str) -> RedeemRequest {
    RedeemRequest {
        code: code.into(),
        client_id: CLIENT_ID.into(),
        redirect_uri: redirect_uri.into(),
        code_verifier: verifier.into(),
    }
}

/// Sends a raw HTTP request to the loopback listener, as a browser would.
async fn browser_get(port: u16, target: &str, host: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let request = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

fn port_of(redirect_uri: &str) -> u16 {
    Url::parse(redirect_uri).unwrap().port().unwrap()
}

#[tokio::test]
async fn desktop_login_completes_through_loopback_callback_and_bearer_session() {
    let context = context();
    let (user_id, _cookie) = signed_up_user(&context).await;
    let handoff = DesktopHandoffService::new(context.clone()).unwrap();

    let receiver = LoopbackCallbackReceiver::bind("/callback", STATE)
        .await
        .unwrap();
    let redirect_uri = receiver.redirect_uri();
    let port = port_of(&redirect_uri);
    let (verifier, challenge) = pkce();
    let (_cancel_tx, cancel_rx) = oneshot::channel();
    let waiting = tokio::spawn(receiver.receive(Duration::from_secs(5), cancel_rx));

    // Backend, after the browser has signed the user in: issue and redirect.
    let code = handoff
        .issue(
            &user_id,
            &request(&redirect_uri, &challenge, Duration::from_secs(60)),
        )
        .await
        .unwrap();
    let callback = better_auth::loopback_callback_url(&redirect_uri, &code, STATE).unwrap();
    let target = callback
        .strip_prefix(&format!("http://127.0.0.1:{port}"))
        .unwrap();
    let browser_response = browser_get(port, target, &format!("127.0.0.1:{port}")).await;
    assert!(browser_response.starts_with("HTTP/1.1 200"));

    // Native client: receives the code, then redeems it with its verifier.
    let received = waiting.await.unwrap().unwrap();
    assert_eq!(received, code);
    let session = handoff
        .redeem(&redeem(&received, &verifier, &redirect_uri), false)
        .await
        .unwrap();

    // The opt-in bearer session authenticates the user.
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", session.session_token).parse().unwrap(),
    );
    let principal = SessionService::new(context.clone())
        .unwrap()
        .resolve_with_transport(&headers, false, SessionTransport::Bearer)
        .await
        .unwrap()
        .expect("bearer session authenticates");
    assert_eq!(principal.user.id, user_id);
}

#[tokio::test]
async fn handoff_code_is_single_use_and_replay_is_rejected() {
    let context = context();
    let (user_id, _) = signed_up_user(&context).await;
    let handoff = DesktopHandoffService::new(context).unwrap();
    let redirect = "http://127.0.0.1:50123/callback";
    let (verifier, challenge) = pkce();
    let code = handoff
        .issue(
            &user_id,
            &request(redirect, &challenge, Duration::from_secs(60)),
        )
        .await
        .unwrap();

    assert!(handoff
        .redeem(&redeem(&code, &verifier, redirect), false)
        .await
        .is_ok());
    assert!(
        handoff
            .redeem(&redeem(&code, &verifier, redirect), false)
            .await
            .is_err(),
        "a replayed code must not create a second session"
    );
}

#[tokio::test]
async fn intercepted_code_without_the_verifier_is_refused_and_burned() {
    let context = context();
    let (user_id, _) = signed_up_user(&context).await;
    let handoff = DesktopHandoffService::new(context).unwrap();
    let redirect = "http://127.0.0.1:50123/callback";
    let (verifier, challenge) = pkce();
    let code = handoff
        .issue(
            &user_id,
            &request(redirect, &challenge, Duration::from_secs(60)),
        )
        .await
        .unwrap();

    // An attacker who intercepted the code tries a guessed verifier.
    let (guessed, _) = pkce();
    assert!(handoff
        .redeem(&redeem(&code, &guessed, redirect), false)
        .await
        .is_err());
    // The code is consumed, so the legitimate client cannot redeem it either.
    assert!(handoff
        .redeem(&redeem(&code, &verifier, redirect), false)
        .await
        .is_err());
}

#[tokio::test]
async fn code_is_bound_to_client_and_redirect_uri() {
    let context = context();
    let (user_id, _) = signed_up_user(&context).await;
    let handoff = DesktopHandoffService::new(context).unwrap();
    let redirect = "http://127.0.0.1:50123/callback";
    let (verifier, challenge) = pkce();

    for (client, uri) in [
        ("other-client", redirect),
        (CLIENT_ID, "http://127.0.0.1:50124/callback"),
    ] {
        let code = handoff
            .issue(
                &user_id,
                &request(redirect, &challenge, Duration::from_secs(60)),
            )
            .await
            .unwrap();
        let mut attempt = redeem(&code, &verifier, uri);
        attempt.client_id = client.into();
        assert!(handoff.redeem(&attempt, false).await.is_err());
    }
}

#[tokio::test]
async fn expired_handoff_code_is_refused() {
    let context = context();
    let (user_id, _) = signed_up_user(&context).await;
    let handoff = DesktopHandoffService::new(context).unwrap();
    let redirect = "http://127.0.0.1:50123/callback";
    let (verifier, challenge) = pkce();
    let code = handoff
        .issue(
            &user_id,
            &request(redirect, &challenge, Duration::from_secs(1)),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    assert!(handoff
        .redeem(&redeem(&code, &verifier, redirect), false)
        .await
        .is_err());
}

#[tokio::test]
async fn parallel_redemptions_of_one_code_create_one_session() {
    let context = context();
    let (user_id, _) = signed_up_user(&context).await;
    let handoff = Arc::new(DesktopHandoffService::new(context).unwrap());
    let redirect = "http://127.0.0.1:50123/callback";
    let (verifier, challenge) = pkce();
    let code = handoff
        .issue(
            &user_id,
            &request(redirect, &challenge, Duration::from_secs(60)),
        )
        .await
        .unwrap();

    let mut tasks = Vec::new();
    for _ in 0..10 {
        let handoff = handoff.clone();
        let attempt = redeem(&code, &verifier, redirect);
        tasks.push(tokio::spawn(async move {
            handoff.redeem(&attempt, false).await.is_ok()
        }));
    }
    let mut successes = 0;
    for task in tasks {
        if task.await.unwrap() {
            successes += 1;
        }
    }
    assert_eq!(successes, 1);
}

#[tokio::test]
async fn issuing_rejects_unsafe_redirects_challenges_and_lifetimes() {
    let context = context();
    let (user_id, _) = signed_up_user(&context).await;
    let handoff = DesktopHandoffService::new(context).unwrap();
    let (_, challenge) = pkce();
    let good = "http://127.0.0.1:50123/callback";
    assert!(handoff
        .issue(
            &user_id,
            &request(
                "https://evil.example.test/cb",
                &challenge,
                Duration::from_secs(60)
            )
        )
        .await
        .is_err());
    assert!(handoff
        .issue(
            &user_id,
            &request(good, "not-an-s256-challenge", Duration::from_secs(60))
        )
        .await
        .is_err());
    assert!(handoff
        .issue(
            &user_id,
            &request(good, &challenge, Duration::from_secs(600))
        )
        .await
        .is_err());
}

#[tokio::test]
async fn forged_and_mismatched_callbacks_do_not_end_the_login() {
    let receiver = LoopbackCallbackReceiver::bind("/callback", STATE)
        .await
        .unwrap();
    let redirect_uri = receiver.redirect_uri();
    let port = port_of(&redirect_uri);
    let (_cancel_tx, cancel_rx) = oneshot::channel();
    let waiting = tokio::spawn(receiver.receive(Duration::from_secs(5), cancel_rx));
    let host = format!("127.0.0.1:{port}");

    // Wrong state, wrong path, wrong Host header (DNS-rebinding shape), and missing code.
    let wrong_state = browser_get(
        port,
        "/callback?code=attacker&state=guess-guess-guess-guess",
        &host,
    )
    .await;
    assert!(wrong_state.starts_with("HTTP/1.1 400"));
    let wrong_path = browser_get(port, "/other?code=attacker&state=x", &host).await;
    assert!(wrong_path.starts_with("HTTP/1.1 404"));
    let rebound = browser_get(
        port,
        &format!("/callback?code=attacker&state={STATE}"),
        "evil.example.test",
    )
    .await;
    assert!(rebound.starts_with("HTTP/1.1 404"));
    let no_code = browser_get(port, &format!("/callback?state={STATE}"), &host).await;
    assert!(no_code.starts_with("HTTP/1.1 400"));

    // The genuine callback still completes the login.
    let genuine = browser_get(
        port,
        &format!("/callback?code=real-code&state={STATE}"),
        &host,
    )
    .await;
    assert!(genuine.starts_with("HTTP/1.1 200"));
    assert_eq!(waiting.await.unwrap().unwrap(), "real-code");
}

#[tokio::test]
async fn provider_error_ends_the_login_with_an_error() {
    let receiver = LoopbackCallbackReceiver::bind("/callback", STATE)
        .await
        .unwrap();
    let port = port_of(&receiver.redirect_uri());
    let (_cancel_tx, cancel_rx) = oneshot::channel();
    let waiting = tokio::spawn(receiver.receive(Duration::from_secs(5), cancel_rx));
    browser_get(
        port,
        "/callback?error=access_denied",
        &format!("127.0.0.1:{port}"),
    )
    .await;
    assert!(waiting.await.unwrap().is_err());
}

#[tokio::test]
async fn loopback_wait_times_out_and_can_be_cancelled() {
    let receiver = LoopbackCallbackReceiver::bind("/callback", STATE)
        .await
        .unwrap();
    let (_cancel_tx, cancel_rx) = oneshot::channel();
    assert!(receiver
        .receive(Duration::from_millis(200), cancel_rx)
        .await
        .is_err());

    let receiver = LoopbackCallbackReceiver::bind("/callback", STATE)
        .await
        .unwrap();
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let waiting = tokio::spawn(receiver.receive(Duration::from_secs(30), cancel_rx));
    cancel_tx.send(()).unwrap();
    assert!(waiting.await.unwrap().is_err());
}

#[tokio::test]
async fn issue_for_session_requires_a_browser_session() {
    let context = context();
    let (_, cookie) = signed_up_user(&context).await;
    let handoff = DesktopHandoffService::new(context).unwrap();
    let (_, challenge) = pkce();
    let good = "http://127.0.0.1:50123/callback";
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, cookie.parse().unwrap());

    assert!(handoff
        .issue_for_session(
            &HeaderMap::new(),
            false,
            &request(good, &challenge, Duration::from_secs(60))
        )
        .await
        .is_err());
    assert!(handoff
        .issue_for_session(
            &headers,
            false,
            &request(good, &challenge, Duration::from_secs(60))
        )
        .await
        .is_ok());
}

#[tokio::test]
async fn handoff_requires_secondary_storage() {
    let context = AuthContext::new(
        AuthOptions {
            secret: "d".repeat(32),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        None,
        vec![],
    )
    .unwrap();
    assert!(DesktopHandoffService::new(context).is_err());
}

#[tokio::test]
async fn oauth_accepts_loopback_redirects_only_after_opt_in() {
    use better_auth::oauth::{OAuthProviderConfig, OAuthService, OAuthStateStorage};

    let provider = OAuthProviderConfig::new(
        "google",
        Url::parse("https://accounts.example.test/authorize").unwrap(),
        CLIENT_ID,
    )
    .unwrap();
    let native = "http://127.0.0.1:50123/callback";

    let default_service = OAuthService::new(context(), OAuthStateStorage::Verification).unwrap();
    assert!(default_service
        .begin(&provider, native, false)
        .await
        .is_err());

    let native_service = OAuthService::new(context(), OAuthStateStorage::Verification)
        .unwrap()
        .with_loopback_redirects();
    assert!(native_service.begin(&provider, native, false).await.is_ok());
    // Opting in does not admit a non-loopback host.
    assert!(native_service
        .begin(&provider, "http://evil.example.test/callback", false)
        .await
        .is_err());
}
