//! Session lifecycle against live PostgreSQL and MySQL servers. Each runs only when its
//! URL variable is set (`BETTER_AUTH_TEST_POSTGRES_URL`, `BETTER_AUTH_TEST_MYSQL_URL`), and
//! uses fresh random emails so the database can be reused between runs.
//!
//! Each simulated application instance has its own connection pool, so every check
//! below goes through the database. Revocation must be visible to the other instances
//! and must survive a restart.

#![cfg(feature = "sqlx")]

use better_auth::{
    context::AuthContext,
    database::{SqlxDbAdapter, SqlxSecondaryStorage},
    email_password::{EmailPasswordService, SignInInput, SignUpInput},
    session::{SessionService, SessionTransport},
};
use better_auth_core::{
    migration::SqlDialect,
    options::{AuthOptions, BaseUrl, PasswordHashOptions},
};
use http::{header, HeaderMap};
use std::sync::Arc;
use uuid::Uuid;

const PASSWORD: &str = "correct horse battery staple";

/// Every configured live database: PostgreSQL and/or MySQL. Empty when neither is set.
fn database_urls() -> Vec<String> {
    [
        "BETTER_AUTH_TEST_POSTGRES_URL",
        "BETTER_AUTH_TEST_MYSQL_URL",
    ]
    .iter()
    .filter_map(|name| std::env::var(name).ok())
    .collect()
}

fn dialect_of(url: &str) -> SqlDialect {
    if url.starts_with("mysql") {
        SqlDialect::MySql
    } else {
        SqlDialect::Postgres
    }
}

async fn instance(url: &str) -> AuthContext {
    let (adapter, storage, dialect) = if dialect_of(url) == SqlDialect::MySql {
        (
            Arc::new(SqlxDbAdapter::mysql(url).await.unwrap()),
            SqlxSecondaryStorage::mysql(url).await.unwrap(),
            SqlDialect::MySql,
        )
    } else {
        (
            Arc::new(SqlxDbAdapter::postgres(url).await.unwrap()),
            SqlxSecondaryStorage::postgres(url).await.unwrap(),
            SqlDialect::Postgres,
        )
    };
    storage.migrate().await.unwrap();
    let context = AuthContext::new(
        AuthOptions {
            secret: "p".repeat(32),
            base_url: Some(BaseUrl::Static("https://example.com".into())),
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
    // Idempotent: every instance may apply the same plan.
    adapter
        .apply_migrations(&context.migration_plan(), dialect)
        .await
        .unwrap();
    context
}

fn cookie(name: &str, value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, format!("{name}={value}").parse().unwrap());
    headers
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    headers
}

async fn authenticates(
    context: &AuthContext,
    headers: &HeaderMap,
    transport: SessionTransport,
) -> bool {
    SessionService::new(context.clone())
        .unwrap()
        .resolve_with_transport(headers, false, transport)
        .await
        .unwrap()
        .is_some()
}

#[tokio::test]
async fn revocation_on_one_instance_is_persistent_and_seen_by_others() {
    for url in database_urls() {
        revocation_on_one_instance_is_persistent_and_seen_by_others_on(&url).await;
    }
}

async fn revocation_on_one_instance_is_persistent_and_seen_by_others_on(url: &str) {
    let node_a = instance(url).await;
    let node_b = instance(url).await;
    let email = format!("session-{}@example.test", Uuid::new_v4().simple());
    let login = EmailPasswordService::new(node_a.clone())
        .unwrap()
        .sign_up(
            SignUpInput {
                email,
                name: "Pg Session".into(),
                password: PASSWORD.into(),
            },
            false,
        )
        .await
        .unwrap();
    let cookie_headers = cookie(&login.cookie.name, &login.cookie.value);
    let bearer_headers = bearer(&login.session_token);
    assert!(authenticates(&node_b, &cookie_headers, SessionTransport::Cookie).await);
    assert!(authenticates(&node_b, &bearer_headers, SessionTransport::Bearer).await);

    SessionService::new(node_b.clone())
        .unwrap()
        .revoke_token(&login.session_token)
        .await
        .unwrap();
    assert!(!authenticates(&node_a, &cookie_headers, SessionTransport::Cookie).await);
    assert!(!authenticates(&node_a, &bearer_headers, SessionTransport::Bearer).await);

    // A restart (fresh pools) sees the same revocation.
    let restarted = instance(url).await;
    assert!(!authenticates(&restarted, &bearer_headers, SessionTransport::Bearer).await);
}

#[tokio::test]
async fn concurrent_logins_on_separate_instances_are_consistent_and_revocable_together() {
    for url in database_urls() {
        concurrent_logins_on_separate_instances_are_consistent_and_revocable_together_on(&url)
            .await;
    }
}

async fn concurrent_logins_on_separate_instances_are_consistent_and_revocable_together_on(
    url: &str,
) {
    let email = format!("session-{}@example.test", Uuid::new_v4().simple());
    let setup = instance(url).await;
    EmailPasswordService::new(setup.clone())
        .unwrap()
        .sign_up(
            SignUpInput {
                email: email.clone(),
                name: "Pg Concurrent".into(),
                password: PASSWORD.into(),
            },
            false,
        )
        .await
        .unwrap();

    let mut tasks = Vec::new();
    let url_owned = url.to_owned();
    for _ in 0..6 {
        let url = url_owned.clone();
        let email = email.clone();
        tasks.push(tokio::spawn(async move {
            let context = instance(&url).await;
            let result = EmailPasswordService::new(context.clone())
                .unwrap()
                .sign_in(
                    SignInInput {
                        email,
                        password: PASSWORD.into(),
                    },
                    false,
                )
                .await
                .unwrap();
            (context, result.session_token, result.user.id)
        }));
    }
    let mut tokens = Vec::new();
    let mut user_id = String::new();
    for task in tasks {
        let (context, token, id) = task.await.unwrap();
        assert!(authenticates(&context, &bearer(&token), SessionTransport::Bearer).await);
        tokens.push(token);
        user_id = id;
    }
    tokens.sort();
    tokens.dedup();
    assert_eq!(tokens.len(), 6, "every login gets its own session token");

    let checker = instance(url).await;
    SessionService::new(checker.clone())
        .unwrap()
        .revoke_all_for_user(&user_id)
        .await
        .unwrap();
    for token in &tokens {
        assert!(!authenticates(&checker, &bearer(token), SessionTransport::Bearer).await);
    }
}
