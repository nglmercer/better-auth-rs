//! OAuth sign-in against a live PostgreSQL server. Runs only when
//! `BETTER_AUTH_TEST_POSTGRES_URL` is set. The provider is a fixture; no network is used.

#![cfg(feature = "sqlx")]

use async_trait::async_trait;
use better_auth::{
    context::AuthContext,
    database::{SqlxDbAdapter, SqlxSecondaryStorage},
    oauth::{
        OAuthProvider, OAuthProviderConfig, OAuthService, OAuthStateStorage, OAuthTokens,
        OAuthUserProfile,
    },
};
use better_auth_core::{
    adapter::Query,
    migration::SqlDialect,
    options::{AuthOptions, BaseUrl, PasswordHashOptions},
};
use std::sync::Arc;
use uuid::Uuid;

struct FixtureGoogle {
    account: String,
    email: String,
}

#[async_trait]
impl OAuthProvider for FixtureGoogle {
    fn id(&self) -> &str {
        "google"
    }

    async fn exchange_code(
        &self,
        _code: &str,
        _redirect_uri: &str,
        _code_verifier: &str,
    ) -> better_auth_core::error::Result<OAuthTokens> {
        Ok(OAuthTokens {
            access_token: "fixture-access-token".into(),
            refresh_token: Some("fixture-refresh-token".into()),
            expires_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 3600,
            ),
            token_type: "Bearer".into(),
            id_token: None,
        })
    }

    async fn profile(
        &self,
        _tokens: &OAuthTokens,
    ) -> better_auth_core::error::Result<OAuthUserProfile> {
        Ok(OAuthUserProfile {
            provider_account_id: self.account.clone(),
            email: Some(self.email.clone()),
            name: Some("Pg Google".into()),
            image: None,
            email_verified: true,
        })
    }
}

#[tokio::test]
async fn google_sign_in_completes_and_stores_no_provider_tokens_on_postgres() {
    let Ok(url) = std::env::var("BETTER_AUTH_TEST_POSTGRES_URL") else {
        return;
    };
    let adapter = Arc::new(SqlxDbAdapter::postgres(&url).await.unwrap());
    let storage = SqlxSecondaryStorage::postgres(&url).await.unwrap();
    storage.migrate().await.unwrap();
    let context = AuthContext::new(
        AuthOptions {
            secret: "o".repeat(32),
            base_url: Some(BaseUrl::Static("https://app.example.test".into())),
            has_database: true,
            password_hash: PasswordHashOptions {
                scrypt_log_n: 10,
                ..PasswordHashOptions::default()
            },
            ..AuthOptions::default()
        },
        adapter.clone(),
        Some(Arc::new(storage)),
        vec![],
    )
    .unwrap();
    // Apply the core schema explicitly. A test must not depend on another test having run first.
    adapter
        .apply_migrations(&context.migration_plan(), SqlDialect::Postgres)
        .await
        .unwrap();
    let service = OAuthService::new(context.clone(), OAuthStateStorage::Verification).unwrap();
    let config = OAuthProviderConfig::new(
        "google",
        url::Url::parse("https://accounts.example.test/authorize").unwrap(),
        "client-1",
    )
    .unwrap();
    let account = format!("google-{}", Uuid::new_v4().simple());
    let provider = FixtureGoogle {
        account: account.clone(),
        email: format!("{}@example.test", Uuid::new_v4().simple()),
    };
    let authorization = service
        .begin(
            &config,
            "https://app.example.test/api/auth/callback/google",
            true,
        )
        .await
        .unwrap();
    let result = service
        .complete(&provider, "code", &authorization.state, None, true)
        .await
        .expect("OAuth sign-in on PostgreSQL");
    assert_eq!(result.user.email, provider.email);

    let record = context
        .adapter
        .find_one(
            "account",
            Query::new()
                .eq("provider_id", "google")
                .eq("account_id", account.as_str()),
        )
        .await
        .unwrap()
        .expect("account row");
    assert!(record
        .get("token_envelope")
        .is_none_or(|value| value.is_null()));
}
