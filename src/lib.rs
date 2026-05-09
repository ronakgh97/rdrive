use crate::crypto::{decrypt_data, encrypt_data};
use anyhow::Result;
use chrono::Local;
use colored::Colorize;
use dashmap::DashMap;
use hex::decode;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Duration;
use tokio::sync::RwLock;

pub mod args;
pub mod crypto;
pub mod header;
pub mod layer;
pub mod log;
pub mod protocol_v1;
pub mod protocol_v2;
pub mod service;

#[inline(always)]
pub async fn get_storage_path() -> Result<PathBuf> {
    let home_dir =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Failed to get home directory"))?;
    let storage_path = home_dir.join(".rdrive").join("storage");
    Ok(storage_path)
}

#[inline(always)]
pub fn get_catalog_path() -> Result<PathBuf> {
    let home_dir =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    let path = home_dir.join(".rdrive").join("catalog.bin");
    Ok(path)
}

/// Hash a whole file and return the hex string of the hash
pub fn file_hasher(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path)?;

    let mut buf_reader = std::io::BufReader::with_capacity(READ_CHUNK_SIZE * 2, file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; READ_CHUNK_SIZE];

    loop {
        let bytes_read = buf_reader.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buf[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

pub async fn file_hasher_async(path: &Path) -> Result<String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || file_hasher(&path)).await?
}

// TODO: THIS NEED A SERIOUS REFACTOR
//  I'M DITCHING TYPICAL CORPORATE AUTH SLOP, THIS GOING TO BE DECENTRALIZED, FILE_SYSTEM AS PLAYGROUND
//  Every file will go to either ~/.rdrive/storage/<file_key_hash + salt + timestamp>/<file-id> or
//  ~/.rdrive/storage/<public>/<file-id>, THATS FUCK IT!!!!

#[derive(Deserialize, Serialize)]
pub struct MetadataFile {
    filename: String,
    file_size: u64,
    file_hash: String,
    hashed_file_key: String,
}

impl MetadataFile {
    pub fn read_from_disk(path: &PathBuf) -> Result<Self> {
        use postcard::from_bytes;

        let key = MASTER_KEY.clone();
        let key_bytes = decode(key)?;

        let deserialized = std::fs::read(path)?;
        let decrypted = decrypt_data(&deserialized, &key_bytes);

        let metadata = from_bytes(&decrypted)?;
        Ok(metadata)
    }

    pub async fn read_from_disk_async(path: &Path) -> Result<Self> {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || Self::read_from_disk(&path)).await?
    }

    pub fn save_to_disk(&self, path: &PathBuf) -> Result<()> {
        use postcard::to_allocvec;

        let key = MASTER_KEY.clone();
        let key_bytes = decode(key)?;

        let serialized = to_allocvec(self)?;
        let encrypted = encrypt_data(&serialized, &key_bytes);

        std::fs::write(path, encrypted)?;
        Ok(())
    }

    pub async fn save_to_disk_async(self, path: &Path) -> Result<()> {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || self.save_to_disk(&path)).await?
    }
}

#[derive(Deserialize, Serialize, Default)]
pub struct FileInfo {
    pub name: String,
    pub last_push: String,
    pub last_pull: String,
}

#[derive(Deserialize, Serialize, Default)]
pub struct Catalog {
    pub file_map: HashMap<String, FileInfo>,
    pub file_index: HashMap<String, Vec<String>>,
}

impl Catalog {
    pub async fn read(path: &PathBuf) -> Result<Self> {
        use postcard::from_bytes;

        let file = tokio::fs::read(path).await?;
        let catalog = from_bytes(&file)?;
        Ok(catalog)
    }

    pub async fn write(&mut self, path: &PathBuf) -> Result<()> {
        use postcard::to_allocvec;

        let bytes = to_allocvec(self)?;
        tokio::fs::write(path, bytes).await?;
        Ok(())
    }

    #[inline]
    pub async fn update_on_push(
        &mut self,
        path: &PathBuf,
        file_name: &str,
        file_id: &str,
    ) -> Result<()> {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        self.file_map
            .entry(file_id.to_string())
            .and_modify(|meta| {
                meta.last_push = timestamp.clone();
            })
            .or_insert_with(|| FileInfo {
                name: file_name.to_string(),
                last_push: timestamp.clone(),
                last_pull: "never".to_string(),
            });
        self.file_index
            .entry(file_name.to_string())
            .and_modify(|tracked| {
                if !tracked.contains(&file_id.to_string()) {
                    tracked.push(file_id.to_string());
                }
            })
            .or_insert_with(|| vec![file_id.to_string()]);

        self.write(path).await?;

        Ok(())
    }
    #[inline]
    pub async fn update_on_pull(&mut self, path: &PathBuf, file_id: &str) -> Result<()> {
        if let Some(meta) = self.file_map.get_mut(file_id) {
            meta.last_pull = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        }
        self.write(path).await?;

        Ok(())
    }
}

pub static START_TIME: OnceLock<chrono::DateTime<Local>> = OnceLock::new();
pub static SHARED_FILE_LOCK: LazyLock<Arc<DashMap<String, String>>> =
    LazyLock::new(|| Arc::new(DashMap::new()));
pub static MASTER_KEY: LazyLock<String> = LazyLock::new(|| {
    dotenv::dotenv().ok();
    std::env::var("MASTER_KEY").expect("MASTER_KEY environment variable must be set for encryption")
});
pub static MAX_CONNECTIONS: OnceLock<usize> = OnceLock::new();
pub static MAX_FILE_SIZE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("MAX_FILE_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8 * 1024 * 1024 * 1024) // 8 GB default
});

pub const NETWORK_READ_BUFFER: usize = 4 * 1024 * 1024;
pub const NETWORK_WRITE_BUFFER: usize = 8 * 1024 * 1024;
pub const READ_CHUNK_SIZE: usize = 64 * 1024;
pub const WRITE_CHUNK_SIZE: usize = 96 * 1024;

// For Header only
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

pub static SERVER_TRACKER: LazyLock<Arc<RwLock<Tracker>>> =
    LazyLock::new(|| Arc::new(RwLock::new(Tracker::default())));

#[derive(Clone)]
pub struct Tracker {
    pub total_download: usize,
    pub total_uploaded: usize,
    pub total_bandwidth_gb: f64,
}

impl Default for Tracker {
    fn default() -> Self {
        Tracker {
            total_uploaded: 0,
            total_download: 0,
            total_bandwidth_gb: 0.0,
        }
    }
}

/// Get the server uptime in hours
#[inline]
pub fn try_get_uptime_hrs() -> f64 {
    if let Some(start_time) = START_TIME.get() {
        let now = Local::now();
        let duration = now.signed_duration_since(*start_time);
        duration.num_hours() as f64
    } else {
        0.0
    }
}

pub fn ascii_art() {
    let ascii = r"
               ▄▄
               ██       ▀▀
████▄       ▄████ ████▄ ██ ██ ██ ▄█▀█▄
██ ▀▀ ▀▀▀▀▀ ██ ██ ██ ▀▀ ██ ██▄██ ██▄█▀
██          ▀████ ██    ██▄ ▀█▀  ▀█▄▄▄

    ";

    println!(
        "{}",
        "rdrive; an object storage server written in Rust"
            .bright_blue()
            .bold()
    );

    println!("{}", ascii.blue());

    println!(
        "🔗 Github: {}",
        "https://github.com/ronakgh97/rstorage".magenta().bold()
    );
}
