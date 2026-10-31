//! Server-side request forgery: OAuth provider endpoints must point at public HTTPS hosts.
//! A misconfigured or hostile endpoint must never make the server call its own network.

use better_auth::http_oauth::HttpOAuthProvider;
use url::Url;

/// Endpoints an attacker would use to reach internal services or cloud metadata.
const INTERNAL: &[&str] = &[
    "https://127.0.0.1/token",
    "https://localhost/token",
    "https://app.localhost/token",
    "https://169.254.169.254/latest/meta-data/",
    "https://10.0.0.5/token",
    "https://172.16.4.2/token",
    "https://192.168.1.10/token",
    "https://100.64.0.1/token",
    "https://0.0.0.0/token",
    "https://[::1]/token",
    "https://[fd00::1]/token",
    "https://[fe80::1]/token",
    "https://[::ffff:10.0.0.1]/token",
    "https://metadata.google.internal/token",
    "https://service.internal/token",
    "https://printer.local/token",
];

#[test]
fn internal_token_and_userinfo_endpoints_are_refused() {
    for target in INTERNAL {
        let url = Url::parse(target).unwrap();
        let other = Url::parse("https://example.com/userinfo").unwrap();
        assert!(
            HttpOAuthProvider::new("p", "id", "secret", url.clone(), other.clone()).is_err(),
            "token endpoint {target} must be refused"
        );
        assert!(
            HttpOAuthProvider::new("p", "id", "secret", other, url).is_err(),
            "userinfo endpoint {target} must be refused"
        );
    }
}

#[test]
fn plain_http_and_credentials_in_the_url_are_refused() {
    let public = Url::parse("https://example.com/token").unwrap();
    let userinfo = Url::parse("https://example.com/userinfo").unwrap();
    assert!(HttpOAuthProvider::new(
        "p",
        "id",
        "s",
        Url::parse("http://example.com/token").unwrap(),
        userinfo.clone()
    )
    .is_err());
    assert!(HttpOAuthProvider::new(
        "p",
        "id",
        "s",
        Url::parse("https://user:pass@example.com/token").unwrap(),
        userinfo.clone()
    )
    .is_err());
    assert!(HttpOAuthProvider::new("p", "id", "s", public, userinfo).is_ok());
}

#[test]
fn internal_authorization_and_verified_email_endpoints_are_refused() {
    let provider = HttpOAuthProvider::new(
        "p",
        "id",
        "s",
        Url::parse("https://example.com/token").unwrap(),
        Url::parse("https://example.com/userinfo").unwrap(),
    )
    .unwrap();
    for target in INTERNAL {
        let url = Url::parse(target).unwrap();
        assert!(
            provider
                .clone()
                .with_authorization_endpoint(url.clone())
                .is_err(),
            "{target}"
        );
        assert!(
            provider.clone().with_verified_emails_endpoint(url).is_err(),
            "{target}"
        );
    }
    let public = Url::parse("https://example.com/authorize").unwrap();
    assert!(provider.clone().with_authorization_endpoint(public).is_ok());
}

#[tokio::test]
async fn internal_jwks_endpoints_are_refused_before_any_request_is_made() {
    let mut provider = HttpOAuthProvider::new(
        "p",
        "id",
        "s",
        Url::parse("https://example.com/token").unwrap(),
        Url::parse("https://example.com/userinfo").unwrap(),
    )
    .unwrap();
    for target in [
        "https://169.254.169.254/keys",
        "http://example.com/keys",
        "https://localhost/keys",
    ] {
        assert!(
            provider
                .refresh_oidc_jwks(Url::parse(target).unwrap())
                .await
                .is_err(),
            "{target}"
        );
    }
}
