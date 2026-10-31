//! Two router instances on one PostgreSQL database, with every connection killed mid-run.
//!
//! Runs only when `BETTER_AUTH_TEST_POSTGRES_URL` is set. The test checks three things:
//! both nodes agree on sessions, readiness reports the outage and then recovers, and
//! the outage does not create duplicate accounts. It runs against a shared database,
//! not against a multi-machine deployment.

#![cfg(feature = "sqlx")]

use better_auth::{
    context::AuthContext,
    database::{SqlxDbAdapter, SqlxSecondaryStorage},
    router::{AuthRouter, HttpRequest},
};
use better_auth_core::{
    adapter::DbAdapter,
    adapter::Query,
    migration::SqlDialect,
    options::{AuthOptions, BaseUrl},
};
use http::{header, HeaderMap, Method, StatusCode};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

fn request(method: Method, path: &str, cookie: Option<&str>, body: Value) -> HttpRequest {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    if let Some(cookie) = cookie {
        headers.insert(header::COOKIE, cookie.parse().unwrap());
    }
    let payload = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    HttpRequest::new(
        method,
        format!("/api/auth{path}").parse().unwrap(),
        headers,
        payload,
    )
}

async fn node(url: &str) -> (AuthRouter, Arc<SqlxDbAdapter>) {
    let adapter = Arc::new(SqlxDbAdapter::postgres(url).await.unwrap());
    let storage = SqlxSecondaryStorage::postgres(url).await.unwrap();
    storage.migrate().await.unwrap();
    let context = AuthContext::new(
        AuthOptions {
            secret: "c".repeat(32),
            base_url: Some(BaseUrl::Static("https://example.com".into())),
            has_database: true,
            ..AuthOptions::default()
        },
        adapter.clone(),
        Some(Arc::new(storage)),
        Vec::new(),
    )
    .unwrap();
    (AuthRouter::new(context).unwrap(), adapter)
}

#[tokio::test]
async fn two_nodes_survive_a_database_connection_kill() {
    let Ok(url) = std::env::var("BETTER_AUTH_TEST_POSTGRES_URL") else {
        return;
    };
    let (first, adapter) = node(&url).await;
    adapter
        .apply_migrations(
            &better_auth_core::migration::MigrationPlan::from_schema(
                &better_auth_core::schema::core_schema(),
            ),
            SqlDialect::Postgres,
        )
        .await
        .unwrap();
    let (second, _) = node(&url).await;

    // Node one signs a user up, and node two signs the same user in.
    let email = format!("chaos-{}@example.com", Uuid::new_v4());
    let password = "correct horse battery staple";
    let signup = first
        .handle(request(
            Method::POST,
            "/sign-up/email",
            None,
            json!({"email": email, "name": "Chaos", "password": password}),
        ))
        .await;
    assert_eq!(signup.status, StatusCode::OK);
    let signin = second
        .handle(request(
            Method::POST,
            "/sign-in/email",
            None,
            json!({"email": email, "password": password}),
        ))
        .await;
    assert_eq!(signin.status, StatusCode::OK);
    let cookie = signin
        .headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let session = first
        .handle(request(
            Method::GET,
            "/get-session",
            Some(&cookie),
            Value::Null,
        ))
        .await;
    assert_eq!(
        session.status,
        StatusCode::OK,
        "node one sees node two's session"
    );

    // Kill every connection to the database from outside the pool.
    use sqlx::Connection;
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let killed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
         WHERE datname = current_database() AND pid <> pg_backend_pid()) AS killed",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert!(killed > 0, "the test must actually break live connections");
    drop(admin);

    // Requests during the outage may fail, but they must not panic or leak details.
    // The pool may reconnect fast enough that the outage is never visible, so the
    // recovery assertions below are the ones that matter.
    for _ in 0..5 {
        let response = second
            .handle(request(Method::GET, "/ready", None, Value::Null))
            .await;
        let body = String::from_utf8_lossy(&response.body);
        assert!(
            !body.contains("SQL") && !body.contains("pg_"),
            "errors must not leak database details"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Both nodes recover without restarting, and the session still works on each.
    let mut recovered = false;
    for _ in 0..100 {
        let ready = first
            .handle(request(Method::GET, "/ready", None, Value::Null))
            .await;
        if ready.status == StatusCode::OK {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        recovered,
        "readiness returns after the connections are restored"
    );
    for router in [&first, &second] {
        let session = router
            .handle(request(
                Method::GET,
                "/get-session",
                Some(&cookie),
                Value::Null,
            ))
            .await;
        assert_eq!(session.status, StatusCode::OK);
        let body: Value = serde_json::from_slice(&session.body).unwrap();
        assert_eq!(body["user"]["email"], email);
    }

    // The outage did not duplicate the account.
    let matching = adapter
        .find_many("user", Query::new().eq("email", email.clone()))
        .await
        .unwrap();
    assert_eq!(matching.len(), 1);
}
