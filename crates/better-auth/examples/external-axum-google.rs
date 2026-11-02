//! A minimal Axum backend that consumes Better Auth as a library.
//!
//! It mounts the auth routes under `/api/auth`, registers Google sign-in, and protects
//! `/api/me` with the session cookie. The Google signing keys are loaded at startup, so a
//! broken JWKS endpoint stops the boot instead of failing the first login.
//!
//! Environment:
//! - `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`: from the Google Cloud console.
//! - `AUTH_SECRET`: at least 32 bytes. Rotate it with `AuthOptions::secret_version` and
//!   `AuthOptions::secret_rotation`.
//! - `APP_ORIGIN`: the public HTTPS origin, for example `https://app.example.com`.
//! - `BIND_ADDR`: optional, defaults to `127.0.0.1:3000`.
//!
//! This example uses in-memory storage so it runs without a database. Do not deploy it that
//! way: use a PostgreSQL or SQLite adapter, as described in `docs/operations/PRODUCTION.md`.
//!
//! Run: `cargo run --example external-axum-google`

use axum::{routing::get, Json, Router};
use better_auth::{
    axum_integration::{auth_routes, AuthUser},
    context::AuthContext,
    http_oauth::HttpOAuthProvider,
    router::AuthRouter,
};
use better_auth_core::{
    adapter::{memory::MemoryDb, memory::MemorySecondaryStorage},
    options::{AuthOptions, BaseUrl},
};
use serde_json::json;
use std::{env, sync::Arc};

#[derive(Clone)]
struct AppState {
    auth: AuthContext,
}

impl axum::extract::FromRef<AppState> for AuthContext {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}

/// Protected application route. The extractor rejects requests without a valid session.
async fn me(AuthUser(principal): AuthUser) -> Json<serde_json::Value> {
    Json(json!({
        "id": principal.user.id,
        "email": principal.user.email,
        "name": principal.user.name,
    }))
}

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let origin = required("APP_ORIGIN");
    let secret = required("AUTH_SECRET");
    let google = HttpOAuthProvider::google_with_jwks(
        required("GOOGLE_CLIENT_ID"),
        required("GOOGLE_CLIENT_SECRET"),
    )
    .await?;

    let context = AuthContext::new(
        AuthOptions {
            secret,
            base_url: Some(BaseUrl::Static(origin)),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        vec![],
    )?;
    let auth = AuthRouter::new(context.clone())?.with_social_providers(vec![google])?;

    let app = Router::new()
        .route("/api/me", get(me))
        .with_state(AppState { auth: context })
        .merge(auth_routes(auth));

    let address = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let listener = tokio::net::TcpListener::bind(&address).await?;
    println!("listening on http://{address}; sign in at /api/auth/sign-in/social/google");
    axum::serve(listener, app).await?;
    Ok(())
}
