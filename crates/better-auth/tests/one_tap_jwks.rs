//! Google One Tap with signing keys from a JWKS endpoint, against a local fixture.
//! Covers the same key lifecycle as the OAuth path: rotation after startup, unknown
//! keys, a broken endpoint at startup, plus One Tap's own replay and email rules.

#![cfg(all(feature = "test-utils", feature = "axum"))]

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use better_auth::{
    context::AuthContext, jwks::JwksIdTokenVerifier, one_tap::OneTapService, JwksRefreshPolicy,
};
use better_auth_core::{
    adapter::{memory::MemoryDb, memory::MemorySecondaryStorage},
    options::{AuthOptions, BaseUrl, PasswordHashOptions},
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::{pkcs8::DecodePrivateKey, traits::PublicKeyParts, RsaPrivateKey};
use serde_json::{json, Value};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use url::Url;

const ISSUER: &str = "https://accounts.google.com";
const CLIENT_ID: &str = "one-tap-client";

const KEY_A: &[u8] = include_bytes!("fixtures/jwks/key_a.pem");
const KEY_B: &[u8] = include_bytes!("fixtures/jwks/key_b.pem");
const KEY_C: &[u8] = include_bytes!("fixtures/jwks/key_c.pem");

fn public_jwk(kid: &str, pem: &[u8]) -> Value {
    let private = RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(pem).unwrap()).unwrap();
    let public = private.to_public_key();
    json!({
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
    })
}

fn jwks(keys: &[(&str, &[u8])]) -> Value {
    json!({ "keys": keys.iter().map(|(kid, pem)| public_jwk(kid, pem)).collect::<Vec<_>>() })
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Clone)]
struct Credential {
    expires_at: u64,
    email_verified: bool,
    email: String,
}

impl Default for Credential {
    fn default() -> Self {
        Self {
            expires_at: now() + 600,
            email_verified: true,
            email: "one-tap@example.test".into(),
        }
    }
}

fn credential(kid: &str, pem: &[u8], claims: &Credential) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    let payload = json!({
        "iss": ISSUER,
        "sub": "google-subject-tap",
        "aud": CLIENT_ID,
        "azp": CLIENT_ID,
        "iat": now(),
        "exp": claims.expires_at,
        "email": claims.email,
        "email_verified": claims.email_verified,
    });
    encode(&header, &payload, &EncodingKey::from_rsa_pem(pem).unwrap()).unwrap()
}

#[derive(Default)]
struct Served {
    body: Option<Value>,
    failing: bool,
}

type Shared = Arc<Mutex<Served>>;

async fn serve_jwks(State(state): State<Shared>) -> (StatusCode, Json<Value>) {
    let served = state.lock().unwrap();
    match (&served.body, served.failing) {
        (Some(body), false) => (StatusCode::OK, Json(body.clone())),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "down"})),
        ),
    }
}

/// Starts a JWKS endpoint on localhost. Returns its URL and the shared state to change keys.
async fn start_jwks() -> (Url, Shared) {
    let state: Shared = Arc::new(Mutex::new(Served::default()));
    let app = Router::new()
        .route("/jwks", get(serve_jwks))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (
        Url::parse(&format!("http://{address}/jwks")).unwrap(),
        state,
    )
}

fn context() -> AuthContext {
    AuthContext::new(
        AuthOptions {
            secret: "t".repeat(32),
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
    )
    .unwrap()
}

fn policy() -> JwksRefreshPolicy {
    JwksRefreshPolicy {
        refresh_after: Duration::from_secs(3600),
        max_stale: Duration::from_secs(24 * 3600),
        min_retry_interval: Duration::ZERO,
    }
}

async fn one_tap(url: Url, policy: JwksRefreshPolicy) -> (OneTapService, JwksIdTokenVerifier) {
    let verifier =
        JwksIdTokenVerifier::insecure_for_testing(ISSUER, CLIENT_ID, url, policy).unwrap();
    verifier.load().await.unwrap();
    (
        OneTapService::with_jwks(context(), verifier.clone()).unwrap(),
        verifier,
    )
}

#[tokio::test]
async fn one_tap_accepts_a_key_published_after_startup() {
    let (url, served) = start_jwks().await;
    served.lock().unwrap().body = Some(jwks(&[("a", KEY_A)]));
    let (service, _) = one_tap(url, policy()).await;

    // Google rotates: key b is published, key a is retired, then a token arrives under b.
    served.lock().unwrap().body = Some(jwks(&[("b", KEY_B)]));
    let token = credential("b", KEY_B, &Credential::default());
    let user = service.sign_in(&token).await.unwrap();
    assert_eq!(user.email, "one-tap@example.test");
}

#[tokio::test]
async fn one_tap_refuses_a_token_signed_by_an_unpublished_key() {
    let (url, served) = start_jwks().await;
    served.lock().unwrap().body = Some(jwks(&[("a", KEY_A)]));
    let (service, _) = one_tap(url, policy()).await;
    let forged = credential("a", KEY_C, &Credential::default());
    assert!(service.sign_in(&forged).await.is_err());
}

#[tokio::test]
async fn one_tap_startup_fails_when_the_keys_cannot_be_loaded() {
    let (url, served) = start_jwks().await;
    served.lock().unwrap().failing = true;
    let verifier =
        JwksIdTokenVerifier::insecure_for_testing(ISSUER, CLIENT_ID, url, policy()).unwrap();
    assert!(verifier.load().await.is_err());
}

#[tokio::test]
async fn one_tap_refuses_expired_and_unverified_credentials() {
    let (url, served) = start_jwks().await;
    served.lock().unwrap().body = Some(jwks(&[("a", KEY_A)]));
    let (service, _) = one_tap(url, policy()).await;
    let expired = Credential {
        expires_at: now() - 10,
        ..Credential::default()
    };
    assert!(service
        .sign_in(&credential("a", KEY_A, &expired))
        .await
        .is_err());
    let unverified = Credential {
        email_verified: false,
        email: "unverified@example.test".into(),
        ..Credential::default()
    };
    assert!(service
        .sign_in(&credential("a", KEY_A, &unverified))
        .await
        .is_err());
}

#[tokio::test]
async fn one_tap_credential_cannot_be_replayed() {
    let (url, served) = start_jwks().await;
    served.lock().unwrap().body = Some(jwks(&[("a", KEY_A)]));
    let (service, _) = one_tap(url, policy()).await;
    let token = credential("a", KEY_A, &Credential::default());
    assert!(service.sign_in(&token).await.is_ok());
    assert!(service.sign_in(&token).await.is_err());
}
