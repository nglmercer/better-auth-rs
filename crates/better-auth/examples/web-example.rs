use axum::{
    http::header,
    response::{Html, IntoResponse},
    routing::{any, get},
    Json, Router,
};
use better_auth::{
    core::{
        adapter::memory::{MemoryDb, MemorySecondaryStorage},
        options::{AuthOptions, BaseUrl, PasswordHashOptions},
    },
    email::CapturingEmailSender,
    router::axum_adapter,
    AuthContext, AuthRouter,
};
use serde_json::json;
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

/// Set to run the example for browser tests. Test mode fixes the port, sets the
/// static base URL that reset links point at, sends email to an in-memory
/// mailbox, and serves that mailbox at `/__test/emails`. Off by default, so the
/// demo behaves as before.
const TEST_MODE_VAR: &str = "BETTER_AUTH_EXAMPLE_TEST_MODE";
/// The port to bind. Test mode requires it, because links are built from it.
const PORT_VAR: &str = "BETTER_AUTH_EXAMPLE_PORT";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let test_mode = std::env::var_os(TEST_MODE_VAR).is_some();
    let port: u16 = std::env::var(PORT_VAR)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    if test_mode && port == 0 {
        return Err(format!("{PORT_VAR} must be set in test mode").into());
    }
    let mailbox = Arc::new(CapturingEmailSender::default());
    let base_url = test_mode.then(|| BaseUrl::Static(format!("http://127.0.0.1:{port}")));
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
            base_url,
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        Vec::new(),
    )?;
    let mut router = AuthRouter::new(context)?.with_verification_services()?;
    if test_mode {
        router = router.with_email_sender(mailbox.clone())?;
    }
    let router = Arc::new(router);
    let mut app = Router::new()
        .route("/", get(index))
        .route("/styles.css", get(styles))
        .route("/app.js", get(app_js))
        // Every auth route goes through the router, so the router decides what
        // exists. Mounting paths one by one silently 404s any route added later.
        .route("/api/auth/{*path}", any(axum_adapter::handler));
    if test_mode {
        let mailbox = mailbox.clone();
        app = app.route(
            "/__test/emails",
            get(move || {
                let mailbox = mailbox.clone();
                async move {
                    let messages: Vec<_> = mailbox
                        .messages()
                        .into_iter()
                        .map(|message| {
                            json!({"to": message.to, "subject": message.subject, "text": message.text})
                        })
                        .collect();
                    Json(messages)
                }
            }),
        );
    }
    let app = app.with_state(router);
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let address: SocketAddr = listener.local_addr()?;

    println!("READY http://{address}/api/auth");
    println!("WEB http://{address}/");
    std::io::stdout().flush()?;
    axum::serve(listener, app).await?;
    Ok(())
}
