use crate::protocol_v1::start_http_server;
use crate::protocol_v2::start_raw_tcp_server;
use crate::{get_storage_path, get_storage_path_blocking};
use anyhow::Result;
use std::fs;

pub async fn serve_http(port: Option<u16>) -> Result<()> {
    dotenv::dotenv().ok();

    let port = port.unwrap_or_else(|| {
        if let Ok(env_port) = std::env::var("R_STORAGE_PORT") {
            env_port.parse::<u16>().unwrap_or(3000)
        } else {
            3000
        }
    });

    if !get_storage_path().await?.exists() {
        tokio::fs::create_dir_all(get_storage_path().await?).await?;
    }

    start_http_server(port).await?;

    Ok(())
}

pub async fn serve_raw_tcp(port: Option<u16>) -> Result<()> {
    dotenv::dotenv().ok();

    let port = port.unwrap_or_else(|| {
        if let Ok(env_port) = std::env::var("R_STORAGE_PORT") {
            env_port.parse::<u16>().unwrap_or(3000)
        } else {
            3000
        }
    });

    let storage_path = get_storage_path_blocking()?;
    if !storage_path.exists() {
        fs::create_dir_all(&storage_path)?;
    }

    start_raw_tcp_server(port)?;

    Ok(())
}
