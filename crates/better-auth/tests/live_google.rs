//! Live checks against Google's public OpenID metadata and signing keys.
//!
//! These need no credentials and send nothing private: they read Google's public discovery
//! document and JWKS. They confirm that the hard-coded Google presets match the live
//! provider and that the production key fetch parses real keys. They do not perform a
//! login, which needs OAuth client credentials and a user.
//!
//! Skipped unless `BETTER_AUTH_LIVE_PROVIDER_TESTS=1`, so CI never depends on the network.

#![cfg(feature = "axum")]

use better_auth::{http_oauth::HttpOAuthProvider, jwks::JwksIdTokenVerifier};
use serde_json::Value;
use url::Url;

fn enabled() -> bool {
    std::env::var("BETTER_AUTH_LIVE_PROVIDER_TESTS").as_deref() == Ok("1")
}

async fn discovery() -> Value {
    reqwest::get("https://accounts.google.com/.well-known/openid-configuration")
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn google_presets_match_the_live_discovery_document() {
    if !enabled() {
        return;
    }
    let document = discovery().await;
    let provider = HttpOAuthProvider::google("client-id", "client-secret").unwrap();
    let expect = |field: &str, actual: &Url| {
        assert_eq!(
            document[field].as_str().unwrap(),
            actual.as_str(),
            "{field} differs from Google's discovery document"
        );
    };
    expect("token_endpoint", provider.token_endpoint());
    expect("userinfo_endpoint", provider.userinfo_endpoint());
    expect(
        "authorization_endpoint",
        provider.authorization_endpoint().unwrap(),
    );
    expect(
        "revocation_endpoint",
        provider.revocation_endpoint().unwrap(),
    );
}

#[tokio::test]
async fn google_signing_keys_load_from_the_live_jwks_endpoint() {
    if !enabled() {
        return;
    }
    let document = discovery().await;
    let verifier = JwksIdTokenVerifier::google("client-id").unwrap();
    assert_eq!(
        verifier.jwks_url().as_str(),
        document["jwks_uri"].as_str().unwrap(),
        "JWKS endpoint differs from Google's discovery document"
    );
    let loaded = verifier.load().await.expect("live Google keys load");
    assert!(loaded >= 1, "Google publishes at least one RSA signing key");
}

#[tokio::test]
async fn a_token_that_is_not_signed_by_google_is_refused_with_live_keys() {
    if !enabled() {
        return;
    }
    let verifier = JwksIdTokenVerifier::google("client-id").unwrap();
    verifier.load().await.unwrap();
    // A structurally valid header and claims with a made-up signature.
    let forged = "eyJhbGciOiJSUzI1NiIsImtpZCI6Im5vdC1hLWdvb2dsZS1rZXkifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.c2ln";
    assert!(verifier.validate(forged, None).await.is_err());
}
