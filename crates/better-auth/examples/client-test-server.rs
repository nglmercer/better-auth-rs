use axum::Router;
use better_auth::{
    core::{
        adapter::memory::{MemoryDb, MemorySecondaryStorage},
        options::{AuthOptions, BaseUrl},
    },
    router::axum_adapter,
    AuthContext, AuthRouter,
};
use std::{io::Write, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let context = AuthContext::new(
        AuthOptions {
            base_url: Some(BaseUrl::Static("http://127.0.0.1".into())),
            secret: "client-e2e-secret-client-e2e-secret".into(),
            has_database: true,
            ..AuthOptions::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        Vec::new(),
    )?;
    let router = Arc::new(AuthRouter::new(context)?.with_verification_services()?);
    let app = Router::new()
        .fallback(axum_adapter::handler)
        .with_state(router);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address: SocketAddr = listener.local_addr()?;

    println!("READY http://{address}/api/auth");
    std::io::stdout().flush()?;
    axum::serve(listener, app).await?;
    Ok(())
}
