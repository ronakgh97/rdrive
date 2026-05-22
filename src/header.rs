use crate::{MAX_FILE_SIZE, get_storage_dir};
use anyhow::Result;
use postcard::from_bytes;
use postcard::to_allocvec;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct ClientHello {
    pub x22519_key: [u8; 32],
    // #[serde(with = "BigArray")]
    // pub signature: [u8; 64],
    pub nonce: [u8; 32], // must be 32 or hash256, I don't care about you
}

impl ClientHello {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        to_allocvec(self).map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))
    }
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        from_bytes(bytes).map_err(|e| anyhow::anyhow!("Failed to deserialize: {}", e))
    }
}

#[derive(Serialize, Deserialize)]
pub struct ServerHello {
    pub ed25519_key: [u8; 32],
    pub x22519_key: [u8; 32],
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    pub nonce: [u8; 32], // must be 32 or hash256, I don't care about you
}

impl ServerHello {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        to_allocvec(self).map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))
    }
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        from_bytes(bytes).map_err(|e| anyhow::anyhow!("Failed to deserialize: {}", e))
    }
}

#[derive(Serialize, Deserialize)]
pub enum Command {
    Auth(u8), // flags -> 1/2 = new/rotate ...bool not used, cause I don't like enum for obvious reasons
    Upload(UploadHeader),
    Download(DownloadHeader),
    Status,
}

impl Command {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        to_allocvec(self).map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))
    }
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        from_bytes(bytes).map_err(|e| anyhow::anyhow!("Failed to deserialize: {}", e))
    }
}

/// Echo Test for debugging, not used in production, just a simple header to test the connection and latency
#[derive(Serialize, Deserialize)]
pub struct EchoDebugHeader {
    /// secret from x25519 exchange
    session_key: [u8; 32],
    /// sha256 of the payload
    payload_hash: [u8; 32],
    /// timestamp before returning
    timestamp_ms: u64,
}

impl EchoDebugHeader {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        to_allocvec(self).map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))
    }
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        from_bytes(bytes).map_err(|e| anyhow::anyhow!("Failed to deserialize: {}", e))
    }
}

use ed25519_dalek::{Verifier, VerifyingKey};
use hex::encode;
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
pub struct NewKeyHeader {
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    pub new_public_bytes: [u8; 32],
}

impl NewKeyHeader {
    pub fn validate(&self, nonce: &[u8]) -> Result<()> {
        validate_signature(&self.new_public_bytes, &self.signature, nonce)?;
        Ok(())
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        to_allocvec(self).map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        from_bytes(data).map_err(|e| anyhow::anyhow!("Failed to deserialize: {}", e))
    }
}

#[derive(Serialize, Deserialize)]
pub struct RotateKeyHeader {
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    pub old_public_bytes: [u8; 32],
    pub new_public_bytes: [u8; 32],
}

impl RotateKeyHeader {
    /// Validates the signature and checks if the old public key is registered. Returns the user path if valid.
    pub async fn validate(&self, nonce: &[u8]) -> Result<PathBuf> {
        let old_pub_key = VerifyingKey::from_bytes(&self.old_public_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to construct old public key from bytes: {}", e))?;

        let old_pub_key_hash = encode(Sha256::digest(old_pub_key.as_bytes()));
        let old_user_path = get_storage_dir().await?.join(old_pub_key_hash);

        if !old_user_path.exists() {
            return Err(anyhow::anyhow!("User not registered, not found"));
        }

        validate_signature(&self.old_public_bytes, &self.signature, nonce)?;
        Ok(old_user_path)
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        to_allocvec(self).map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        from_bytes(data).map_err(|e| anyhow::anyhow!("Failed to deserialize: {}", e))
    }
}

#[inline(always)]
fn validate_signature(
    public_bytes: &[u8; 32],
    signature_bytes: &[u8; 64],
    nonce: &[u8],
) -> Result<()> {
    let signature = ed25519_dalek::Signature::from_bytes(signature_bytes);

    let public_key = VerifyingKey::from_bytes(public_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to construct public key from bytes: {}", e))?;

    public_key
        .verify(nonce, &signature)
        .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))?;

    Ok(())
}

// TODO; listen...for header..
//  we will use some derive from secret key as nonce challenge, this prevents roundtrip

// TODO; header needs a massive refactor, I'm being serious
#[derive(Serialize, Deserialize)]
pub struct UploadHeader {
    pub file_id: String,
    pub file_name: String,
    pub file_size: u64,
    pub file_hash: String,
    pub file_key: String,
}

impl UploadHeader {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        to_allocvec(self).map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        from_bytes(data).map_err(|e| anyhow::anyhow!("Failed to deserialize: {}", e))
    }

    pub fn validate(&self) -> Result<()> {
        // TODO: we dont need check or sanitized, just use hash
        if self.file_id.is_empty() || !(32..=256).contains(&self.file_id.len()) {
            return Err(anyhow::anyhow!(
                "File ID must be a non-empty hex string between 32 and 256 characters, without control characters"
            ));
        }
        if self.file_name.is_empty() {
            return Err(anyhow::anyhow!("File name cannot be empty"));
        }
        if self.file_size < 1024 * 1024 || self.file_size > *MAX_FILE_SIZE {
            return Err(anyhow::anyhow!(
                "File size must be between 1MB and {} MB",
                *(MAX_FILE_SIZE) / 1024 * 1024
            ));
        }
        if self.file_hash.is_empty() {
            return Err(anyhow::anyhow!("File hash cannot be empty"));
        }
        if self.file_key.is_empty() {
            return Err(anyhow::anyhow!("File key cannot be empty"));
        }
        Ok(())
    }
}

// TODO: this feels redundant
#[derive(Serialize, Deserialize)]
pub struct UploadResponse {
    pub file_id: String,
    pub network_time: f32,
}

impl UploadResponse {
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        from_bytes(data).map_err(|e| anyhow::anyhow!("Failed to deserialize: {}", e))
    }
}

#[derive(Serialize, Deserialize)]
pub struct DownloadHeader {
    pub file_id: String,
    pub file_key: String,
}

impl DownloadHeader {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        to_allocvec(self).map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        from_bytes(data).map_err(|e| anyhow::anyhow!("Failed to deserialize: {}", e))
    }

    pub fn validate(&self) -> Result<()> {
        if self.file_id.is_empty() {
            return Err(anyhow::anyhow!("File ID cannot be empty"));
        }
        if self.file_key.is_empty() {
            return Err(anyhow::anyhow!("File key cannot be empty"));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct DownloadResponse {
    pub file_name: String,
    pub file_size: u64,
    pub file_hash: String,
    pub network_time: f32,
}

impl DownloadResponse {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        to_allocvec(self).map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        from_bytes(data).map_err(|e| anyhow::anyhow!("Failed to deserialize: {}", e))
    }
}

#[derive(Serialize, Deserialize)]
pub struct ErrorHeader {
    pub code: u16,
    pub message: String,
}

impl ErrorHeader {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        to_allocvec(self).map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        from_bytes(data).map_err(|e| anyhow::anyhow!("Failed to deserialize: {}", e))
    }
}

#[derive(Serialize, Deserialize)]
pub struct WarnHeader {
    pub code: u16,
    pub message: String,
}

impl WarnHeader {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        to_allocvec(self).map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        from_bytes(data).map_err(|e| anyhow::anyhow!("Failed to deserialize: {}", e))
    }
}

#[derive(Serialize, Deserialize)]
pub struct StatusHeader {
    pub timestamp: String,
    pub uptime_hrs: f64,
    pub auth_client: u64,
    pub total_uploaded: u64,
    pub total_downloaded: u64,
    pub total_bandwidth_used: u64,
}

impl StatusHeader {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        to_allocvec(self).map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        from_bytes(data).map_err(|e| anyhow::anyhow!("Failed to deserialize: {}", e))
    }
}
