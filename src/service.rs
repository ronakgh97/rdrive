use crate::protocol_v1::start_tcp_server;
use crate::{MAX_CONNECTIONS, get_storage_path};
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;

pub async fn serve_tcp(port: Option<u16>) -> Result<()> {
    let (port, max_connection) = server_init(port).await?;

    let storage_path: PathBuf = get_storage_path().await?;
    tokio::fs::create_dir_all(&storage_path).await?;

    start_tcp_server(port, max_connection, Arc::new(storage_path)).await?;

    Ok(())
}

#[inline]
/// Init necessary env and returns port and connection limit
async fn server_init(port: Option<u16>) -> Result<(u16, usize)> {
    dotenv::dotenv().ok();

    let max_connection: usize = std::env::var("MAX_CONNECTIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(128);

    MAX_CONNECTIONS.get_or_init(move || max_connection);

    let port = port.unwrap_or_else(|| {
        if let Ok(env_port) = std::env::var("PORT") {
            env_port.parse::<u16>().unwrap_or(3000)
        } else {
            3000
        }
    });

    Ok((port, max_connection))
}

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
