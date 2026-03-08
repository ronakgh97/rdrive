use dashmap::DashMap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::OnceLock;

pub mod args;
pub mod log;
pub mod protocol_v1;
pub mod protocol_v2;
pub mod service;

#[inline]
pub async fn get_storage_path() -> anyhow::Result<PathBuf> {
    let home_dir =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Failed to get home directory"))?;
    let storage_path = home_dir.join(".r_storage").join("storage");
    Ok(storage_path)
}

#[inline]
pub fn get_storage_path_blocking() -> anyhow::Result<PathBuf> {
    let home_dir =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Failed to get home directory"))?;
    let storage_path = home_dir.join(".r_storage").join("storage");
    Ok(storage_path)
}

#[derive(Deserialize, Serialize)]
pub struct Metadata {
    filename: String,
    file_size: u64,
    file_hash: String,
    file_key: String,
}

static START_TIME: OnceLock<chrono::DateTime<chrono::Local>> = OnceLock::new();

lazy_static! {
    pub static ref ON_GOINGS: DashMap<String, String> = DashMap::new();
}
