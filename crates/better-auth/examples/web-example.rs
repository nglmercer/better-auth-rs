use axum::{
    http::header,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use better_auth::{
    core::{
        adapter::memory::{MemoryDb, MemorySecondaryStorage},
        options::{AuthOptions, PasswordHashOptions},
    },
    router::axum_adapter,
    AuthContext, AuthRouter,
};
use std::{io::Write, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;

async fn index() -> Html<&'static str> {
    Html(include_str!("web-example/index.html"))
}

async fn styles() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("web-example/styles.css"),
    )
}

async fn app_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("web-example/app.js"),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let context = AuthContext::new(
        AuthOptions {
            // Resolve the origin from each request so browser Origin headers
            // include the ephemeral port selected below.
            secret: "web-example-secret-web-example-secret".into(),
            // Keep the local demo responsive. Production deployments should
            // benchmark a higher cost for their hardware and threat model.
            password_hash: PasswordHashOptions {
                scrypt_log_n: 13,
                ..PasswordHashOptions::default()
            },
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        Vec::new(),
    )?;
    let router = Arc::new(AuthRouter::new(context)?.with_verification_services()?);
    let app = Router::new()
        .route("/", get(index))
        .route("/styles.css", get(styles))
        .route("/app.js", get(app_js))
        .route("/api/auth/sign-up/email", post(axum_adapter::handler))
        .route("/api/auth/sign-in/email", post(axum_adapter::handler))
        .route(
            "/api/auth/request-password-reset",
            post(axum_adapter::handler),
        )
        .route("/api/auth/reset-password", post(axum_adapter::handler))
        .with_state(router);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address: SocketAddr = listener.local_addr()?;

    println!("READY http://{address}/api/auth");
    println!("WEB http://{address}/");
    std::io::stdout().flush()?;
    axum::serve(listener, app).await?;
    Ok(())
}
