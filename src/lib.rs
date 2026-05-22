#[allow(unused)]
use crate::crypto::{decrypt_data, encrypt_data};
use anyhow::Result;
use chrono::Local;
use colored::Colorize;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
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
pub async fn get_storage_dir() -> Result<PathBuf> {
    let home_dir =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Failed to get home directory"))?;
    let storage_path = home_dir.join(".rdrive").join("storage");
    Ok(storage_path)
}

// TODO: Implement public space
#[inline(always)]
pub async fn get_public_storage_dir() -> Result<PathBuf> {
    let home_dir =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Failed to get home directory"))?;
    let pub_storage_path = home_dir.join(".rdrive").join("storage").join("public");
    Ok(pub_storage_path)
}

#[inline(always)]
pub async fn get_authorized_client_dir() -> Result<PathBuf> {
    let home_dir =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Failed to get home directory"))?;
    let allowed_clients_path = home_dir.join(".rdrive").join("authorized_keys");
    Ok(allowed_clients_path)
}

#[inline]
pub fn get_server_key_dir() -> Result<PathBuf> {
    let home_dir =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Failed to get home directory"))?;
    let server_keys_path = home_dir.join(".rdrive").join("server");
    Ok(server_keys_path)
}

#[inline]
pub fn get_user_key_dir() -> Result<PathBuf> {
    let home_dir =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Failed to get home directory"))?;
    let user_path = home_dir.join(".rdrive").join("user");
    Ok(user_path)
}

// TODO: should store on server
#[inline]
pub fn get_catalog_path() -> Result<PathBuf> {
    let path = get_user_key_dir()?.join("catalog.map");
    Ok(path)
}

pub fn get_authorized_server_map_path() -> Result<PathBuf> {
    let path = get_user_key_dir()?.join("server.map");
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

#[derive(Deserialize, Serialize)]
pub struct MetadataFile {
    filename: String,
    file_size: u64,
    file_hash: String,
    file_key_hash: String,
}

impl MetadataFile {
    pub fn read_from_disk(path: &PathBuf) -> Result<Self> {
        use postcard::from_bytes;

        // TODO: Think over this later
        // let key = MASTER_KEY.clone();
        // let key_bytes = decode(key)?;

        let deserialized = std::fs::read(path)?;
        //let decrypted = decrypt_data(&deserialized, &key_bytes);

        let metadata = from_bytes(&deserialized)?;
        Ok(metadata)
    }

    pub async fn read_from_disk_async(path: &Path) -> Result<Self> {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || Self::read_from_disk(&path)).await?
    }

    pub fn save_to_disk(&self, path: &PathBuf) -> Result<()> {
        use postcard::to_allocvec;

        // TODO: Think over this later
        // let key = MASTER_KEY.clone();
        // let key_bytes = decode(key)?;

        let serialized = to_allocvec(self)?;
        //let encrypted = encrypt_data(&serialized, &key_bytes);

        std::fs::write(path, serialized)?;
        Ok(())
    }

    pub async fn save_to_disk_async(self, path: &Path) -> Result<()> {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || self.save_to_disk(&path)).await?
    }
}

#[derive(Deserialize, Serialize, Default)]
pub struct FileHistory {
    pub name: String,
    pub last_push: String,
    pub last_pull: String,
}

#[derive(Deserialize, Serialize, Default)]
pub struct Catalog {
    // TODO: key should be file hash not name
    pub file_map: HashMap<String, FileHistory>,
    pub file_index: HashMap<String, Vec<String>>,
}

impl Catalog {
    async fn read(path: &PathBuf) -> Result<Self> {
        let str = tokio::fs::read_to_string(path).await?;
        Ok(serde_json::from_str(&str)?)
    }
    async fn write(&mut self, path: &PathBuf) -> Result<()> {
        use postcard::to_allocvec;

        let bytes = to_allocvec(self)?;
        tokio::fs::write(path, bytes).await?;
        Ok(())
    }

    pub async fn read_or_create(path: &PathBuf) -> Result<Self> {
        let catalog_dir = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid catalog path"))?;
        tokio::fs::create_dir_all(catalog_dir).await?;

        // Read existing or new
        let catalog = match path.exists() {
            true => Self::read(path).await?,
            false => Self::default(),
        };

        Ok(catalog)
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
            .or_insert_with(|| FileHistory {
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

#[derive(Serialize, Deserialize, Default)]
pub struct AuthServerMap {
    /// Map -> (Host/IP, pubkey_pem)
    pub server_map: HashMap<SocketAddr, String>,
}

impl AuthServerMap {
    async fn read(path: &PathBuf) -> Result<Self> {
        let str_text = tokio::fs::read_to_string(path).await?;
        Ok(serde_json::from_str(&str_text)?)
    }
    pub async fn read_or_create(path: &PathBuf) -> Result<Self> {
        let server_map = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid server map path"))?;
        tokio::fs::create_dir_all(server_map).await?;

        let map = match path.exists() {
            true => Self::read(path).await?,
            false => Self::default(),
        };

        Ok(map)
    }

    pub async fn write(&mut self, path: &PathBuf) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize server map to JSON: {}", e))?;
        tokio::fs::write(path, json).await?;
        Ok(())
    }
}

pub static START_TIME: OnceLock<chrono::DateTime<Local>> = OnceLock::new();
pub static ACTIVE_CONNECTIONS: LazyLock<Arc<AtomicUsize>> =
    LazyLock::new(|| Arc::new(AtomicUsize::new(0)));
pub static ENABLE_CLIENT_WHITELIST: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("ENABLE_CLIENT_WHITELIST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(true) // default to true
});

// TODO: pem is not needed, for internal ops
//  use bytes to form key

pub static SERVER_PUB_KEY_PEM: LazyLock<String> = LazyLock::new(|| {
    let pubkey = get_server_key_dir()
        .unwrap_or_else(|e| {
            eprintln!(
                "{}",
                format!("Failed to get server key directory: {}", e)
                    .red()
                    .bold()
            );
            std::process::exit(1);
        })
        .join("public.pem");
    std::fs::read_to_string(pubkey).unwrap_or_else(|e| {
        eprintln!(
            "{}",
            format!("Failed to read server public key: {}", e)
                .red()
                .bold()
        );
        std::process::exit(1);
    })
});

pub static SERVER_PRI_KEY_PEM: LazyLock<String> = LazyLock::new(|| {
    let prikey = get_server_key_dir()
        .unwrap_or_else(|e| {
            eprintln!(
                "{}",
                format!("Failed to get server key directory: {}", e)
                    .red()
                    .bold()
            );
            std::process::exit(1);
        })
        .join("private.pem");
    std::fs::read_to_string(prikey).unwrap_or_else(|e| {
        eprintln!(
            "{}",
            format!("Failed to read server private key: {}", e)
                .red()
                .bold()
        );
        std::process::exit(1);
    })
});

pub static MAX_CONNECTIONS: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("MAX_CONNECTIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(256) // default to 256 connections
});
pub static MAX_FILE_SIZE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("MAX_FILE_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8 * 1024 * 1024 * 1024) // 8 GB default
});

pub static SHARED_FILE_LOCK: LazyLock<Arc<DashMap<String, Arc<RwLock<()>>>>> =
    LazyLock::new(|| Arc::new(DashMap::new()));

#[inline(always)]
pub fn hold_file_lock(file_id: &str) -> Arc<RwLock<()>> {
    let map = &*SHARED_FILE_LOCK;
    map.entry(file_id.to_string())
        .or_insert_with(|| Arc::new(RwLock::new(())))
        .clone()
}

#[inline(always)]
pub fn release_file_lock(file_id: &str) {
    let map = &*SHARED_FILE_LOCK;
    map.remove(file_id);
}

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

impl Tracker {
    pub async fn log_upload(bytes: usize) {
        let mut lock = SERVER_TRACKER.write().await;
        lock.total_bandwidth_gb += bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        lock.total_uploaded += 1;
        drop(lock)
    }

    pub async fn log_download(bytes: usize) {
        let mut lock = SERVER_TRACKER.write().await;
        lock.total_bandwidth_gb += bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        lock.total_download += 1;
        drop(lock)
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
