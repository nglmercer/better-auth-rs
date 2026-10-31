//! Rotating the secret does not lock anyone out of a second factor. A factor enrolled under an
//! old secret keeps working, and it is re-sealed under the current secret the first time it is used.

use better_auth::{
    context::AuthContext,
    plugins::{totp_code, TwoFactorPlugin},
    router::{AuthRouter, HttpRequest, HttpResponse},
};
use better_auth_core::{
    adapter::{memory::MemoryDb, memory::MemorySecondaryStorage, DbAdapter, Query},
    options::{AuthOptions, BaseUrl, SecretVersion},
};
use http::{header, HeaderMap, Method, StatusCode};
use serde_json::{json, Value};
use std::{sync::Arc, time::SystemTime};

const ORIGIN: &str = "https://example.com";
const PASSWORD: &str = "correct horse battery staple";
const OLD_SECRET: &str = "old-secret-old-secret-old-secret-00";
const NEW_SECRET: &str = "new-secret-new-secret-new-secret-99";

struct Stores {
    db: Arc<MemoryDb>,
    storage: Arc<MemorySecondaryStorage>,
}

fn router(
    stores: &Stores,
    secret_version: &str,
    secret: &str,
    rotation: Vec<SecretVersion>,
) -> AuthRouter {
    let context = AuthContext::new(
        AuthOptions {
            secret: secret.into(),
            secret_version: secret_version.into(),
            secret_rotation: rotation,
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            has_database: true,
            ..AuthOptions::default()
        },
        stores.db.clone(),
        Some(stores.storage.clone()),
        vec![Arc::new(TwoFactorPlugin)],
    )
    .unwrap();
    AuthRouter::new(context).unwrap()
}

async fn send(
    router: &AuthRouter,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    body: Value,
) -> (StatusCode, Value, HeaderMap) {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    if let Some(cookie) = cookie {
        headers.insert(header::COOKIE, cookie.parse().unwrap());
    }
    let response: HttpResponse = router
        .handle(HttpRequest::new(
            method,
            format!("/api/auth{path}").parse().unwrap(),
            headers,
            body.to_string().into_bytes(),
        ))
        .await;
    (
        response.status,
        serde_json::from_slice(&response.body).unwrap_or(Value::Null),
        response.headers,
    )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn a_factor_enrolled_under_an_old_secret_survives_rotation_and_is_resealed() {
    let stores = Stores {
        db: Arc::new(MemoryDb::default()),
        storage: Arc::new(MemorySecondaryStorage::default()),
    };

    // Enroll under v1.
    let before = router(&stores, "v1", OLD_SECRET, Vec::new());
    let (_, _, headers) = send(
        &before,
        Method::POST,
        "/sign-up/email",
        None,
        json!({"email": "rotate@example.com", "name": "Rotate", "password": PASSWORD}),
    )
    .await;
    let cookie = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.contains("session_token="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let (status, enrollment, _) = send(
        &before,
        Method::POST,
        "/two-factor/enable",
        Some(&cookie),
        json!({"password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let secret = enrollment["secret"].as_str().unwrap().to_owned();
    let (status, _, _) = send(
        &before,
        Method::POST,
        "/two-factor/confirm",
        Some(&cookie),
        json!({"code": totp_code(&secret, now(), 30, 6).unwrap()}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Rotate to v2, keeping v1 so the old factor can still be opened.
    let rotated = router(
        &stores,
        "v2",
        NEW_SECRET,
        vec![SecretVersion {
            version: "v1".into(),
            secret: OLD_SECRET.into(),
        }],
    );
    let (_, challenge, _) = send(
        &rotated,
        Method::POST,
        "/sign-in/email",
        None,
        json!({"email": "rotate@example.com", "password": PASSWORD}),
    )
    .await;
    let token = challenge["challenge_token"].as_str().unwrap().to_owned();
    let (status, _, _) = send(
        &rotated,
        Method::POST,
        "/two-factor/verify",
        None,
        json!({"challenge_token": token, "code": totp_code(&secret, now() + 30, 30, 6).unwrap()}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the factor enrolled under v1 still verifies after rotation"
    );

    // The stored secret is now sealed under v2.
    let record = stores
        .db
        .find_one("two_factor", Query::new())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record["secret_version"], "v2");

    // Once v1 is gone from the configuration, the stored secret still opens. A sign-in on the
    // v2-only server gets to the factor check, which opens the secret before it accepts a backup
    // code. Backup codes do not depend on the clock, so this check is deterministic.
    let retired = router(&stores, "v2", NEW_SECRET, Vec::new());
    let (_, challenge, _) = send(
        &retired,
        Method::POST,
        "/sign-in/email",
        None,
        json!({"email": "rotate@example.com", "password": PASSWORD}),
    )
    .await;
    let token = challenge["challenge_token"].as_str().unwrap().to_owned();
    let backup_code = enrollment["backup_codes"][0].as_str().unwrap().to_owned();
    let (status, body, _) = send(
        &retired,
        Method::POST,
        "/two-factor/verify",
        None,
        json!({"challenge_token": token, "code": backup_code}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
