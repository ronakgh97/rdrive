use crate::protocol_v1::start_tcp_server;
use crate::{get_allowed_client_path, get_storage_path};
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;

pub async fn serve_tcp(port: Option<u16>) -> Result<()> {
    dotenv::dotenv().ok();

    let port = port.unwrap_or_else(|| {
        if let Ok(env_port) = std::env::var("PORT") {
            env_port.parse::<u16>().unwrap_or(3000)
        } else {
            3000
        }
    });

    let storage_path: PathBuf = get_storage_path().await?;
    tokio::fs::create_dir_all(&storage_path).await?;

    let authorised_client = get_allowed_client_path().await?;
    tokio::fs::create_dir_all(&authorised_client).await?;

    start_tcp_server(port, Arc::new(storage_path)).await?;

    Ok(())
}

// TODO: use ACTIVE_CONNECTIONS to implement this
#[allow(unused)]
async fn ctrl_c() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed Ctrl+C handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
