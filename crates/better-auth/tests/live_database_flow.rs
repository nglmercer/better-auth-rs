//! Account and second-factor flows against live PostgreSQL and MySQL servers.
//!
//! Each test runs only when its URL variable is set:
//! `BETTER_AUTH_TEST_POSTGRES_URL` and `BETTER_AUTH_TEST_MYSQL_URL`. Each run
//! uses fresh random emails, so one database can be reused between runs.

#![cfg(feature = "sqlx")]

use better_auth::{
    context::AuthContext,
    database::{SqlxDbAdapter, SqlxSecondaryStorage},
    email_password::{EmailPasswordService, SignUpInput},
    plugins::{totp_code, TwoFactorPlugin},
    second_factor::SecondFactorService,
};
use better_auth_core::{
    error::AuthError,
    migration::SqlDialect,
    options::{AuthOptions, BaseUrl},
};
use std::sync::Arc;
use uuid::Uuid;

const PASSWORD: &str = "correct horse battery staple";

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn postgres_sign_up_and_second_factor_hold_under_concurrency() {
    let Ok(url) = std::env::var("BETTER_AUTH_TEST_POSTGRES_URL") else {
        return;
    };
    let adapter = Arc::new(SqlxDbAdapter::postgres(&url).await.unwrap());
    let storage = SqlxSecondaryStorage::postgres(&url).await.unwrap();
    storage.migrate().await.unwrap();
    run_flow(adapter, storage, SqlDialect::Postgres).await;
}

#[tokio::test]
async fn mysql_sign_up_and_second_factor_hold_under_concurrency() {
    let Ok(url) = std::env::var("BETTER_AUTH_TEST_MYSQL_URL") else {
        return;
    };
    let adapter = Arc::new(SqlxDbAdapter::mysql(&url).await.unwrap());
    let storage = SqlxSecondaryStorage::mysql(&url).await.unwrap();
    storage.migrate().await.unwrap();
    run_flow(adapter, storage, SqlDialect::MySql).await;
}

async fn run_flow(adapter: Arc<SqlxDbAdapter>, storage: SqlxSecondaryStorage, dialect: SqlDialect) {
    let context = AuthContext::new(
        AuthOptions {
            secret: "p".repeat(32),
            base_url: Some(BaseUrl::Static("https://example.com".into())),
            has_database: true,
            ..AuthOptions::default()
        },
        adapter.clone(),
        Some(Arc::new(storage)),
        vec![Arc::new(TwoFactorPlugin)],
    )
    .unwrap();
    // The plan includes the plugin tables, so the two-factor table exists too.
    adapter
        .apply_migrations(&context.migration_plan(), dialect)
        .await
        .unwrap();

    // Concurrent sign-ups for one new address: exactly one account is created.
    let email = format!("pg-{}@example.com", Uuid::new_v4());
    let service = EmailPasswordService::new(context.clone()).unwrap();
    let input = || SignUpInput {
        email: email.clone(),
        name: "Postgres".into(),
        password: PASSWORD.into(),
    };
    let (first, second) = tokio::join!(
        service.sign_up(input(), true),
        service.sign_up(input(), true)
    );
    let outcomes = [first, second];
    assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1);
    let loser = outcomes
        .into_iter()
        .find(|o| o.is_err())
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(loser, AuthError::InvalidRequest(_)),
        "a constraint loss must map to a client error: {loser:?}"
    );
    let user = service
        .sign_in(
            better_auth::email_password::SignInInput {
                email: email.clone(),
                password: PASSWORD.into(),
            },
            true,
        )
        .await
        .unwrap()
        .user;

    // Enrollment, then concurrent use of one code: only one attempt may win.
    let second_factor = SecondFactorService::new(context.clone()).unwrap();
    let enrollment = second_factor.begin_enrollment(&user).await.unwrap();
    let code_at = |offset: u64| {
        totp_code(
            &enrollment.secret,
            (now_seconds() / 30 + offset) * 30,
            30,
            6,
        )
        .unwrap()
    };
    second_factor
        .confirm_enrollment(&user.id, &code_at(0))
        .await
        .unwrap();

    let code = code_at(1);
    let mut challenges = Vec::new();
    for _ in 0..8 {
        challenges.push(second_factor.create_challenge(&user.id).await.unwrap());
    }
    let mut attempts = Vec::new();
    for challenge in challenges {
        let service = second_factor.clone();
        let code = code.clone();
        attempts.push(tokio::spawn(async move {
            service.complete_challenge(&challenge, &code).await
        }));
    }
    let mut accepted = 0;
    for attempt in attempts {
        if attempt.await.unwrap().is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 1, "one TOTP step may be accepted exactly once");

    // The same code is refused on a later, fresh challenge.
    let replay = second_factor.create_challenge(&user.id).await.unwrap();
    assert!(second_factor
        .complete_challenge(&replay, &code)
        .await
        .is_err());
}
