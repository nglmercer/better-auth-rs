//! Desktop login, end to end, in one process.
//!
//! Two roles run here, and they only communicate through the loopback HTTP callback and
//! the handoff code, as they would across a real network:
//!
//! 1. The native client generates a PKCE verifier and a `state`, binds a loopback
//!    listener, and "opens the system browser" (here, an HTTP request from this program).
//! 2. The backend has a browser session for the user. It issues a single-use handoff code
//!    bound to the client's challenge and redirect URI, and redirects the browser to the
//!    loopback URL with the code and the client's `state`.
//!
//! The native client then redeems the code with its verifier and authenticates with the
//! bearer token it receives. Run it with `cargo run --example desktop-login`.
//!
//! This is the library surface only. A real desktop app supplies its own UI, launches the
//! browser, and runs the backend in its own service. This example does not contact any
//! provider.

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
use tokio::sync::oneshot;

const CLIENT_ID: &str = "example-desktop-app";

fn random_secret() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Backend: an in-memory context and an existing user. Use a database adapter in production.
    let context = AuthContext::new(
        AuthOptions {
            secret: "example-secret-that-is-at-least-32-bytes".into(),
            base_url: Some(BaseUrl::Static("https://app.example.test".into())),
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
    )?;
    let user = EmailPasswordService::new(context.clone())?
        .sign_up(
            SignUpInput {
                email: "desktop-user@example.test".into(),
                name: "Desktop User".into(),
                password: "correct horse battery staple".into(),
            },
            false,
        )
        .await?;
    // The browser's session cookie. The backend uses it to identify the user at issue time.
    let browser_cookie = format!("{}={}", user.cookie.name, user.cookie.value);
    let handoff = DesktopHandoffService::new(context.clone())?;

    // Native client: PKCE pair, a state value, and a loopback listener.
    let verifier = format!("{}{}", random_secret(), random_secret());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_secret();
    let receiver = LoopbackCallbackReceiver::bind("/callback", &state).await?;
    let redirect_uri = receiver.redirect_uri();
    println!("native client listening on {redirect_uri}");
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let waiting = tokio::spawn(receiver.receive(Duration::from_secs(60), cancel_rx));

    // Backend: after the browser sign-in, issue a code and redirect the browser.
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, browser_cookie.parse()?);
    let code = handoff
        .issue_for_session(
            &headers,
            false,
            &HandoffRequest {
                client_id: CLIENT_ID.into(),
                redirect_uri: redirect_uri.clone(),
                code_challenge: challenge,
                ttl: Duration::from_secs(60),
            },
        )
        .await?;
    let callback = better_auth::loopback_callback_url(&redirect_uri, &code, &state)?;

    // The system browser follows the redirect to the loopback listener.
    let response = reqwest::get(&callback).await?;
    println!("browser received: {}", response.status());

    // Native client: the callback arrived. Redeem the code with the verifier.
    let received = waiting.await??;
    drop(cancel_tx); // the receiver has finished; dropping the sender would only cancel it
    let redemption = RedeemRequest {
        code: received,
        client_id: CLIENT_ID.into(),
        redirect_uri,
        code_verifier: verifier,
    };
    let session = handoff.redeem(&redemption, false).await?;
    println!("bearer session issued for {}", session.user.email);

    // The bearer token authenticates; a replayed code does not.
    let mut bearer = HeaderMap::new();
    bearer.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", session.session_token).parse()?,
    );
    let principal = SessionService::new(context.clone())?
        .resolve_with_transport(&bearer, false, SessionTransport::Bearer)
        .await?
        .expect("bearer session authenticates");
    println!("authenticated as {}", principal.user.email);
    // The same redemption a second time, as an interceptor replaying the callback would.
    let replay = handoff.redeem(&redemption, false).await;
    println!("replayed code refused: {}", replay.is_err());
    Ok(())
}
