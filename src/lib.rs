use aes::Aes256;
use aes::cipher::{Block, BlockCipherEncrypt, KeyInit};
use anyhow::Result;
use dashmap::DashMap;
use hex::decode;
use rand::{Rng, RngExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Duration;
use tokio::sync::RwLock;

pub mod args;
pub mod header;
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

#[inline]
pub fn get_storage_path_blocking() -> Result<PathBuf> {
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

#[inline(always)]
pub fn file_hasher(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let file = std::fs::File::open(path)?;

    let mut buf_reader = std::io::BufReader::with_capacity(3 * READ_CHUNK_SIZE, file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; READ_CHUNK_SIZE * 2];

    loop {
        let bytes_read = buf_reader.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buf[..bytes_read]);
    }
    let final_hash = hasher.finalize();

    Ok(hex::encode(final_hash).to_string())
}

#[inline(always)]
pub async fn file_hasher_async(path: &Path) -> Result<String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || file_hasher(&path)).await?
}

#[inline(always)]
pub fn generate_master_key() -> String {
    let mut rng = rand::rng();
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    hex::encode(key)
}

#[derive(Deserialize, Serialize)]
pub struct Metadata {
    filename: String,
    file_size: u64,
    file_hash: String,
    file_key: String,
}

impl Metadata {
    pub fn read_from_disk(path: &PathBuf) -> Result<Self> {
        use postcard::from_bytes;

        let key = MASTER_KEY.get_or_init(generate_master_key).clone();

        let key_bytes = decode(key)?;
        let encrypted = std::fs::read(path)?;
        let read_bytes = decrypt_data(&encrypted, &key_bytes);

        let metadata = from_bytes(&read_bytes)?;
        Ok(metadata)
    }

    pub async fn read_from_disk_async(path: &Path) -> Result<Self> {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || Self::read_from_disk(&path)).await?
    }

    pub fn save_to_disk(&self, path: &PathBuf) -> Result<()> {
        use postcard::to_allocvec;

        let key = MASTER_KEY.get_or_init(generate_master_key).clone();

        let key_bytes = decode(key)?;
        let serialized = to_allocvec(self)?;
        let encrypted = encrypt_data(&serialized, &key_bytes);

        std::fs::write(path, encrypted)?;
        Ok(())
    }

    pub async fn save_to_disk_async(&self, path: &Path) -> Result<()> {
        let path = path.to_path_buf();
        let self_clone = Self {
            filename: self.filename.clone(),
            file_size: self.file_size,
            file_hash: self.file_hash.clone(),
            file_key: self.file_key.clone(),
        };
        tokio::task::spawn_blocking(move || self_clone.save_to_disk(&path)).await?
    }
}

#[derive(Deserialize, Serialize)]
pub struct Catalog {
    pub file_map: HashMap<String, String>,
}

impl Default for Catalog {
    fn default() -> Self {
        Catalog::new()
    }
}

impl Catalog {
    pub fn new() -> Self {
        Catalog {
            file_map: HashMap::new(),
        }
    }

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
}

/// XOR `data` with an AES-256 CTR keystream derived from `key` and `nonce`.
/// Encryption and decryption are the same operation.
#[inline(always)]
fn aes256_ctr_xor(key: &[u8; 32], nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).expect("Key must be 32 bytes");
    let mut output = Vec::with_capacity(data.len());
    let mut counter: u32 = 0;

    for chunk in data.chunks(16) {
        let mut counter_block = [0u8; 16];
        counter_block[..12].copy_from_slice(nonce);
        counter_block[12..].copy_from_slice(&counter.to_be_bytes());

        let mut block = Block::<Aes256>::from(counter_block);
        cipher.encrypt_block(&mut block);

        for (b, k) in chunk.iter().zip(block.iter()) {
            output.push(b ^ k);
        }

        counter = counter.wrapping_add(1);
    }

    output
}

/// Encrypt `data` with a 32-byte `key` using AES-256 CTR keystream XOR.
///
/// A random 12-byte nonce is generated and prepended to the output:
/// ```text
/// [ nonce: 12 bytes ][ ciphertext: N bytes ]
/// ```
#[inline]
pub fn encrypt_data(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(key.len() >= 32, "Key must be at least 32 bytes");

    // Generate a fresh random nonce for every encryption
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);

    let key_arr: &[u8; 32] = key[..32].try_into().unwrap();
    let ciphertext = aes256_ctr_xor(key_arr, &nonce, data);

    // Output: nonce || ciphertext
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend(ciphertext);
    out
}

/// Decrypt `data` that was encrypted with [`encrypt_data`].
///
/// Expects the first 12 bytes to be the nonce.
#[inline]
pub fn decrypt_data(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(key.len() >= 32, "Key must be at least 32 bytes");
    assert!(data.len() >= 12, "Ciphertext too short to contain nonce");

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce: &[u8; 12] = nonce_bytes.try_into().unwrap();
    let key: &[u8; 32] = key[..32].try_into().unwrap();

    aes256_ctr_xor(key, nonce, ciphertext)
}

pub static START_TIME: OnceLock<chrono::DateTime<chrono::Local>> = OnceLock::new();
pub static SHARED_FILE_LOCK: LazyLock<DashMap<String, String>> = LazyLock::new(DashMap::new);
pub static MASTER_KEY: OnceLock<String> = OnceLock::new();
pub static MAX_CONNECTIONS: OnceLock<usize> = OnceLock::new();
pub static MAX_FILE_SIZE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("MAX_FILE_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8 * 1024 * 1024 * 1024) // 8 GB default
});

pub static SERVER_TRACKER: LazyLock<Arc<RwLock<Tracker>>> =
    LazyLock::new(|| Arc::new(RwLock::new(Tracker::default())));

/// Get the server uptime in hours
#[inline]
pub fn try_get_uptime_hrs() -> f64 {
    if let Some(start_time) = START_TIME.get() {
        let now = chrono::Local::now();
        let duration = now.signed_duration_since(*start_time);
        duration.num_hours() as f64
    } else {
        0.0
    }
}

#[inline]
pub fn try_get_master_key() -> Option<String> {
    MASTER_KEY.get().cloned()
}

#[inline(always)]
pub fn fill_random_bytes(buf: &mut [u8]) {
    let mut rng = rand::rng();
    buf.iter_mut().for_each(|b| *b = rng.random::<u8>());
}
pub const NETWORK_READ_BUFFER: usize = 4 * 1024 * 1024;
pub const NETWORK_WRITE_BUFFER: usize = 8 * 1024 * 1024;
pub const READ_CHUNK_SIZE: usize = 64 * 1024;
pub const WRITE_CHUNK_SIZE: usize = 96 * 1024;

// For Header only
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct Tracker {
    // TODO: Add more
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

#[test]
fn encrypt_decrypt_round_trip() {
    let mut key = [0u8; 32];
    fill_random_bytes(&mut key);
    let mut data = [0u8; 4096 * 64];
    fill_random_bytes(&mut data);

    let encrypted = encrypt_data(&data, &key);
    assert_eq!(encrypted.len(), data.len() + 12);

    let decrypted = decrypt_data(&encrypted, &key);
    assert_eq!(decrypted, data);
}

#[test]
fn encrypt_decrypt_empty_payload() {
    let mut key = [0u8; 32];
    fill_random_bytes(&mut key);
    let data: &[u8] = b"";

    let encrypted = encrypt_data(data, &key);
    assert_eq!(encrypted.len(), 12);

    let decrypted = decrypt_data(&encrypted, &key);
    assert!(decrypted.is_empty());
}
