mod ssh;
mod selinux;
mod ebpf;
mod api;


use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use crate::api::api_routes;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging with better formatting
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "selinux_rust_manager=info,tower_http=debug,axum=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting SELinux Rust Manager API");

    // Load configuration (you can expand this with a config file)
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()?;

    let bind_addr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0".to_string());

    let addr: SocketAddr = format!("{}:{}", bind_addr, port).parse()?;

    // Create the application router
    let app = api_routes::create_router();

    // Create TCP listener
    let listener = TcpListener::bind(addr).await?;
    info!("Server listening on http://{}", addr);

    // Start the server
    axum::serve(listener, app)
        .await
        .map_err(|e| {
            error!("Server error: {}", e);
            e
        })?;

    Ok(())
}