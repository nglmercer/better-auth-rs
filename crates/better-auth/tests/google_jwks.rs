//! OIDC signing-key lifecycle for the Google-style provider path, against a local
//! JWKS and token fixture. No live provider is contacted.
//!
//! Covers scheduled refresh, rotation through unknown key IDs, rate-limited
//! retries, fail-closed behaviour when keys cannot be refreshed or have expired,
//! the bound on JWKS size, single-flight refresh under concurrency, and the
//! claim checks (signature, expiry, issuer, audience, nonce).
//!
//! The RSA keys in `tests/fixtures/jwks` are test-only.

#![cfg(all(feature = "test-utils", feature = "axum"))]

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use better_auth::{
    http_oauth::HttpOAuthProvider, oauth::OAuthProvider, oidc::OidcIdTokenValidator,
    JwksRefreshPolicy,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::{pkcs8::DecodePrivateKey, traits::PublicKeyParts, RsaPrivateKey};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use url::Url;

const ISSUER: &str = "https://issuer.example.test";
const CLIENT_ID: &str = "client-1";
const SUBJECT: &str = "google-subject-1";
const NONCE: &str = "nonce-1";

const KEY_A: &[u8] = include_bytes!("fixtures/jwks/key_a.pem");
const KEY_B: &[u8] = include_bytes!("fixtures/jwks/key_b.pem");
/// Never published in any JWKS: used to forge tokens under a published `kid`.
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
struct Claims {
    issuer: String,
    audience: String,
    expires_at: u64,
    nonce: String,
}

impl Default for Claims {
    fn default() -> Self {
        Self {
            issuer: ISSUER.into(),
            audience: CLIENT_ID.into(),
            expires_at: now() + 600,
            nonce: NONCE.into(),
        }
    }
}

/// Signs an ID token with `pem`, labelled with `kid`.
fn id_token(kid: &str, pem: &[u8], claims: &Claims) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    let payload = json!({
        "iss": claims.issuer,
        "sub": SUBJECT,
        "aud": claims.audience,
        "azp": CLIENT_ID,
        "exp": claims.expires_at,
        "iat": now(),
        "nonce": claims.nonce,
        "email": "user@example.com",
        "email_verified": true,
    });
    encode(&header, &payload, &EncodingKey::from_rsa_pem(pem).unwrap()).unwrap()
}

#[derive(Default)]
struct FixtureState {
    /// Body served from the JWKS endpoint.
    jwks: Option<Value>,
    /// When set, the JWKS endpoint answers 500.
    jwks_failing: bool,
    jwks_fetches: AtomicUsize,
    /// ID token returned by the token endpoint.
    id_token: String,
}

type Shared = Arc<Mutex<FixtureState>>;

async fn serve_jwks(State(state): State<Shared>) -> (StatusCode, Json<Value>) {
    let state = state.lock().unwrap();
    state.jwks_fetches.fetch_add(1, Ordering::SeqCst);
    match (&state.jwks, state.jwks_failing) {
        (Some(body), false) => (StatusCode::OK, Json(body.clone())),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "down"})),
        ),
    }
}

async fn serve_token(State(state): State<Shared>) -> Json<Value> {
    let id_token = state.lock().unwrap().id_token.clone();
    Json(json!({"access_token": "access", "token_type": "Bearer", "id_token": id_token}))
}

async fn serve_userinfo() -> Json<Value> {
    Json(json!({"sub": SUBJECT, "email": "user@example.com", "email_verified": true}))
}

struct Fixture {
    base: String,
    state: Shared,
}

impl Fixture {
    async fn start() -> Self {
        let state: Shared = Arc::new(Mutex::new(FixtureState::default()));
        let app = Router::new()
            .route("/jwks", get(serve_jwks))
            .route("/token", post(serve_token))
            .route("/userinfo", get(serve_userinfo))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            base: format!("http://{address}"),
            state,
        }
    }

    fn set_jwks(&self, body: Value) {
        let mut state = self.state.lock().unwrap();
        state.jwks = Some(body);
        state.jwks_failing = false;
    }

    fn set_jwks_failing(&self, failing: bool) {
        self.state.lock().unwrap().jwks_failing = failing;
    }

    fn set_id_token(&self, token: String) {
        self.state.lock().unwrap().id_token = token;
    }

    fn jwks_fetches(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .jwks_fetches
            .load(Ordering::SeqCst)
    }

    /// A provider that verifies ID tokens against this fixture's JWKS.
    async fn provider(&self, policy: JwksRefreshPolicy) -> HttpOAuthProvider {
        let mut provider = HttpOAuthProvider::insecure_for_testing(
            "google",
            CLIENT_ID,
            "client-secret",
            Url::parse(&format!("{}/authorize", self.base)).unwrap(),
            Url::parse(&format!("{}/token", self.base)).unwrap(),
            Url::parse(&format!("{}/userinfo", self.base)).unwrap(),
            ["openid", "email"],
        )
        .with_oidc_validator(OidcIdTokenValidator::new(ISSUER, CLIENT_ID))
        .with_jwks_policy(policy)
        .unwrap();
        provider
            .refresh_oidc_jwks(Url::parse(&format!("{}/jwks", self.base)).unwrap())
            .await
            .expect("initial JWKS load");
        provider
    }
}

/// One login: code exchange, token validation, then profile lookup.
async fn login(provider: &HttpOAuthProvider) -> better_auth::core::error::Result<String> {
    let tokens = provider
        .exchange_code("code", "https://app.example.test/cb", "verifier")
        .await?;
    provider.validate_tokens(&tokens, NONCE)?;
    let profile = provider.profile(&tokens).await?;
    Ok(profile.provider_account_id)
}

fn fast_policy() -> JwksRefreshPolicy {
    JwksRefreshPolicy {
        refresh_after: Duration::from_secs(3600),
        max_stale: Duration::from_secs(24 * 3600),
        min_retry_interval: Duration::from_secs(0),
    }
}

#[tokio::test]
async fn valid_token_signed_by_a_published_key_is_accepted() {
    let fixture = Fixture::start().await;
    fixture.set_jwks(jwks(&[("a", KEY_A)]));
    let provider = fixture.provider(fast_policy()).await;
    fixture.set_id_token(id_token("a", KEY_A, &Claims::default()));
    assert_eq!(login(&provider).await.unwrap(), SUBJECT);
}

#[tokio::test]
async fn rotation_is_picked_up_when_a_token_names_an_unknown_key() {
    let fixture = Fixture::start().await;
    fixture.set_jwks(jwks(&[("a", KEY_A)]));
    let provider = fixture.provider(fast_policy()).await;
    let before = fixture.jwks_fetches();

    // The provider publishes key b, and retires a, before any token signed by b arrives.
    fixture.set_jwks(jwks(&[("b", KEY_B)]));
    fixture.set_id_token(id_token("b", KEY_B, &Claims::default()));

    assert_eq!(login(&provider).await.unwrap(), SUBJECT);
    assert_eq!(fixture.jwks_fetches(), before + 1);
}

#[tokio::test]
async fn retired_key_stops_verifying_at_the_next_scheduled_refresh() {
    // A key the provider has retired stays trusted until the cache refreshes. That
    // matches the token lifetime: a token signed before rotation is valid until its
    // `exp`. After the refresh window, the retired key is refused.
    let fixture = Fixture::start().await;
    fixture.set_jwks(jwks(&[("a", KEY_A)]));
    let policy = JwksRefreshPolicy {
        refresh_after: Duration::from_secs(1),
        max_stale: Duration::from_secs(60),
        min_retry_interval: Duration::from_secs(0),
    };
    let provider = fixture.provider(policy).await;
    fixture.set_jwks(jwks(&[("b", KEY_B)]));
    fixture.set_id_token(id_token("a", KEY_A, &Claims::default()));
    assert_eq!(login(&provider).await.unwrap(), SUBJECT);

    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert!(login(&provider).await.is_err());
}

#[tokio::test]
async fn forged_token_under_a_published_kid_is_refused() {
    let fixture = Fixture::start().await;
    fixture.set_jwks(jwks(&[("a", KEY_A)]));
    let provider = fixture.provider(fast_policy()).await;
    // Signed by key c, labelled with the published kid "a".
    fixture.set_id_token(id_token("a", KEY_C, &Claims::default()));
    assert!(login(&provider).await.is_err());
}

#[tokio::test]
async fn expired_token_is_refused_without_clock_skew_allowance() {
    let fixture = Fixture::start().await;
    fixture.set_jwks(jwks(&[("a", KEY_A)]));
    let provider = fixture.provider(fast_policy()).await;
    let expired = Claims {
        expires_at: now() - 5,
        ..Claims::default()
    };
    fixture.set_id_token(id_token("a", KEY_A, &expired));
    assert!(login(&provider).await.is_err());
}

#[tokio::test]
async fn wrong_issuer_audience_or_nonce_is_refused() {
    let fixture = Fixture::start().await;
    fixture.set_jwks(jwks(&[("a", KEY_A)]));
    let provider = fixture.provider(fast_policy()).await;
    for claims in [
        Claims {
            issuer: "https://evil.example.test".into(),
            ..Claims::default()
        },
        Claims {
            audience: "another-client".into(),
            ..Claims::default()
        },
        Claims {
            nonce: "replayed-nonce".into(),
            ..Claims::default()
        },
    ] {
        fixture.set_id_token(id_token("a", KEY_A, &claims));
        assert!(login(&provider).await.is_err());
    }
}

#[tokio::test]
async fn jwks_refresh_failure_for_an_unknown_kid_fails_closed() {
    let fixture = Fixture::start().await;
    fixture.set_jwks(jwks(&[("a", KEY_A)]));
    let provider = fixture.provider(fast_policy()).await;

    fixture.set_jwks_failing(true);
    fixture.set_id_token(id_token("b", KEY_B, &Claims::default()));
    assert!(login(&provider).await.is_err());

    // Keys that were verified and are still within max_stale keep working.
    fixture.set_id_token(id_token("a", KEY_A, &Claims::default()));
    assert_eq!(login(&provider).await.unwrap(), SUBJECT);
}

#[tokio::test]
async fn unknown_kid_refreshes_are_rate_limited() {
    let fixture = Fixture::start().await;
    fixture.set_jwks(jwks(&[("a", KEY_A)]));
    let policy = JwksRefreshPolicy {
        min_retry_interval: Duration::from_secs(3600),
        ..fast_policy()
    };
    let provider = fixture.provider(policy).await;
    let before = fixture.jwks_fetches();

    fixture.set_id_token(id_token("x", KEY_B, &Claims::default()));
    for _ in 0..5 {
        assert!(login(&provider).await.is_err());
    }
    // Five tokens with unknown kids cause at most one attempt inside the retry window.
    assert_eq!(fixture.jwks_fetches(), before);
}

#[tokio::test]
async fn keys_older_than_max_stale_are_refused_when_refresh_keeps_failing() {
    let fixture = Fixture::start().await;
    fixture.set_jwks(jwks(&[("a", KEY_A)]));
    let policy = JwksRefreshPolicy {
        refresh_after: Duration::from_secs(1),
        max_stale: Duration::from_secs(2),
        min_retry_interval: Duration::from_secs(0),
    };
    let provider = fixture.provider(policy).await;
    fixture.set_id_token(id_token("a", KEY_A, &Claims::default()));
    assert_eq!(login(&provider).await.unwrap(), SUBJECT);

    fixture.set_jwks_failing(true);
    // Timestamps have one-second resolution, so sleep past max_stale with margin.
    tokio::time::sleep(Duration::from_millis(3_500)).await;
    assert!(
        login(&provider).await.is_err(),
        "expired keys must not verify tokens"
    );
}

#[tokio::test]
async fn scheduled_refresh_fetches_again_even_when_the_kid_is_known() {
    let fixture = Fixture::start().await;
    fixture.set_jwks(jwks(&[("a", KEY_A)]));
    let policy = JwksRefreshPolicy {
        refresh_after: Duration::from_secs(1),
        max_stale: Duration::from_secs(60),
        min_retry_interval: Duration::from_secs(0),
    };
    let provider = fixture.provider(policy).await;
    fixture.set_id_token(id_token("a", KEY_A, &Claims::default()));
    let before = fixture.jwks_fetches();

    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(login(&provider).await.unwrap(), SUBJECT);
    assert_eq!(fixture.jwks_fetches(), before + 1);
}

#[tokio::test]
async fn oversized_jwks_is_refused_and_the_previous_keys_remain_trusted() {
    let fixture = Fixture::start().await;
    fixture.set_jwks(jwks(&[("a", KEY_A)]));
    let provider = fixture.provider(fast_policy()).await;

    // 33 entries exceed MAX_JWKS_KEYS. The extra kids all carry key a's material.
    let mut many: Vec<Value> = (0..33)
        .map(|index| public_jwk(&format!("extra-{index}"), KEY_A))
        .collect();
    many.push(public_jwk("a", KEY_A));
    fixture.set_jwks(json!({ "keys": many }));
    fixture.set_id_token(id_token("extra-0", KEY_A, &Claims::default()));
    assert!(login(&provider).await.is_err());

    fixture.set_jwks(jwks(&[("a", KEY_A)]));
    fixture.set_id_token(id_token("a", KEY_A, &Claims::default()));
    assert_eq!(login(&provider).await.unwrap(), SUBJECT);
}

#[tokio::test]
async fn concurrent_callbacks_that_need_a_new_key_share_one_refresh() {
    let fixture = Fixture::start().await;
    fixture.set_jwks(jwks(&[("a", KEY_A)]));
    let provider = Arc::new(fixture.provider(fast_policy()).await);
    let before = fixture.jwks_fetches();

    fixture.set_jwks(jwks(&[("b", KEY_B)]));
    fixture.set_id_token(id_token("b", KEY_B, &Claims::default()));
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let provider = provider.clone();
        tasks.push(tokio::spawn(async move { login(&provider).await }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().unwrap(), SUBJECT);
    }
    assert_eq!(fixture.jwks_fetches(), before + 1);
}

#[tokio::test]
async fn startup_load_fails_when_the_provider_is_unreachable() {
    let fixture = Fixture::start().await;
    fixture.set_jwks_failing(true);
    let mut provider = HttpOAuthProvider::insecure_for_testing(
        "google",
        CLIENT_ID,
        "client-secret",
        Url::parse(&format!("{}/authorize", fixture.base)).unwrap(),
        Url::parse(&format!("{}/token", fixture.base)).unwrap(),
        Url::parse(&format!("{}/userinfo", fixture.base)).unwrap(),
        ["openid"],
    )
    .with_oidc_validator(OidcIdTokenValidator::new(ISSUER, CLIENT_ID));
    let result = provider
        .refresh_oidc_jwks(Url::parse(&format!("{}/jwks", fixture.base)).unwrap())
        .await;
    assert!(result.is_err());
}
