use axum::{
    response::Html,
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

const INDEX_HTML: &str = r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Better Auth Rust web example</title>
    <style>
      body { font: 16px system-ui, sans-serif; max-width: 42rem; margin: 2rem auto; padding: 0 1rem; }
      form { border: 1px solid #ddd; border-radius: 0.5rem; margin: 1rem 0; padding: 1rem; }
      label { display: block; margin: 0.75rem 0; }
      input { box-sizing: border-box; display: block; margin-top: 0.25rem; padding: 0.5rem; width: 100%; }
      button { padding: 0.5rem 0.75rem; }
      pre { background: #f5f5f5; overflow: auto; padding: 1rem; }
    </style>
  </head>
  <body>
    <h1>Better Auth Rust</h1>
    <p>This minimal web example exposes only email registration and login.</p>

    <form id="register">
      <h2>Register</h2>
      <label>Email <input name="email" type="email" required></label>
      <label>Name <input name="name" required></label>
      <label>Password <input name="password" type="password" required></label>
      <button type="submit">Register</button>
    </form>

    <form id="login">
      <h2>Login</h2>
      <label>Email <input name="email" type="email" required></label>
      <label>Password <input name="password" type="password" required></label>
      <button type="submit">Login</button>
    </form>

    <pre id="result" aria-live="polite">Submit a form to call the Rust API.</pre>
    <script>
      async function submitForm(event, path) {
        event.preventDefault();
        const form = event.currentTarget;
        const button = form.querySelector("button");
        if (button.disabled) return;
        button.disabled = true;
        button.textContent = "Working...";
        const data = Object.fromEntries(new FormData(form));
        try {
          const response = await fetch(`/api/auth/${path}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify(data),
          });
          document.querySelector("#result").textContent =
            `${response.status} ${response.statusText}\n${await response.text()}`;
        } catch (error) {
          document.querySelector("#result").textContent = String(error);
        } finally {
          button.disabled = false;
          button.textContent = path === "sign-up/email" ? "Register" : "Login";
        }
      }

      document.querySelector("#register").addEventListener("submit", (event) =>
        submitForm(event, "sign-up/email"));
      document.querySelector("#login").addEventListener("submit", (event) =>
        submitForm(event, "sign-in/email"));
    </script>
  </body>
</html>"##;

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
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
    let router = Arc::new(AuthRouter::new(context)?);
    let app = Router::new()
        .route("/", get(index))
        .route("/api/auth/sign-up/email", post(axum_adapter::handler))
        .route("/api/auth/sign-in/email", post(axum_adapter::handler))
        .with_state(router);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address: SocketAddr = listener.local_addr()?;

    println!("READY http://{address}/api/auth");
    println!("WEB http://{address}/");
    std::io::stdout().flush()?;
    axum::serve(listener, app).await?;
    Ok(())
}
