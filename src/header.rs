use crate::{MAX_FILE_SIZE, get_storage_path};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum Command {
    Init(u8), // flags -> 1/2 = new/rotate ...bool not used, cause I don't like enum for obvious reasons
    Upload(UploadHeader),
    Download(DownloadHeader),
    Status,
}

impl Command {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize Command: {}", e))
    }
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize Command: {}", e))
    }
}

use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Verifier, VerifyingKey};
use hex::encode;
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
pub struct NewKeyHeader {
    pub signature: String,
    pub new_public_pem: String,
}

impl NewKeyHeader {
    pub fn validate(&self, nonce: &[u8]) -> Result<()> {
        validate_signature(self.new_public_pem.clone(), self.signature.clone(), nonce)?;
        Ok(())
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize InitHeader: {}", e))
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        postcard::from_bytes(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize InitHeader: {}", e))
    }
}

#[derive(Serialize, Deserialize)]
pub struct RotateKeyHeader {
    pub signature: String,
    pub old_public_pem: String,
    pub new_public_pem: String,
}

impl RotateKeyHeader {
    pub async fn validate(&self, nonce: &[u8]) -> Result<()> {
        let old_pub_key = VerifyingKey::from_public_key_pem(&self.old_public_pem)
            .map_err(|e| anyhow::anyhow!("Failed to parse old public key from PEM: {}", e))?;

        let old_pub_key_hash = encode(Sha256::digest(old_pub_key.as_bytes()));
        let user_path = get_storage_path().await?.join(old_pub_key_hash);

        if !user_path.exists() {
            return Err(anyhow::anyhow!("User not registered, not found"));
        }

        validate_signature(self.new_public_pem.clone(), self.signature.clone(), nonce)?;
        Ok(())
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize RotateKeyHeader: {}", e))
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        postcard::from_bytes(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize RotateKeyHeader: {}", e))
    }
}

#[inline(always)]
pub fn validate_signature(public_pem: String, signature: String, nonce: &[u8]) -> Result<()> {
    let signature_bytes = hex::decode(&signature)
        .map_err(|e| anyhow::anyhow!("Failed to decode signature from hex: {}", e))?;
    let signature = ed25519_dalek::Signature::try_from(&signature_bytes[..])
        .map_err(|e| anyhow::anyhow!("Failed to parse signature: {}", e))?;

    let public_key = VerifyingKey::from_public_key_pem(&public_pem)
        .map_err(|e| anyhow::anyhow!("Failed to decode public key from PEM: {}", e))?;

    public_key
        .verify(nonce, &signature)
        .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))?;

    Ok(())
}

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
        postcard::to_allocvec(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize UploadHeader: {}", e))
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        postcard::from_bytes(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize UploadHeader: {}", e))
    }

    pub fn validate(&self) -> Result<()> {
        if self.file_id.is_empty()
            || !(32..=256).contains(&self.file_id.len())
            || self.file_id.chars().any(|c| c.is_control())
            || !self.file_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(anyhow::anyhow!(
                "File ID must be a non-empty hex string between 32 and 256 characters, without control characters"
            ));
        }
        if self.file_name.is_empty() {
            return Err(anyhow::anyhow!("File name cannot be empty"));
        }
        if self.file_size == 0 || self.file_size > *MAX_FILE_SIZE {
            return Err(anyhow::anyhow!("File size must be greater than zero"));
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

#[derive(Serialize, Deserialize)]
pub struct UploadResponse {
    pub file_id: String,
    pub time_took: f32,
}

impl UploadResponse {
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        postcard::from_bytes(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize UploadResponse: {}", e))
    }
}

#[derive(Serialize, Deserialize)]
pub struct DownloadHeader {
    pub file_id: String,
    pub file_key: String,
}

impl DownloadHeader {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize DownloadHeader: {}", e))
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        postcard::from_bytes(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize DownloadHeader: {}", e))
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
}

impl DownloadResponse {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize DownloadResponse: {}", e))
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        postcard::from_bytes(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize DownloadResponse: {}", e))
    }
}

#[derive(Serialize, Deserialize)]
pub struct ErrorHeader {
    pub code: u16,
    pub message: String,
}

impl ErrorHeader {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize ErrorHandler: {}", e))
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        postcard::from_bytes(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize ErrorHandler: {}", e))
    }
}

#[derive(Serialize, Deserialize)]
pub struct StatusHeader {
    pub timestamp: String,
    pub uptime_hrs: f64,
    pub total_uploaded: u64,
    pub total_downloaded: u64,
    pub total_bandwidth_used: u64,
}

impl StatusHeader {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize StatusHeader: {}", e))
    }
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        postcard::from_bytes(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize StatusHeader: {}", e))
    }
}
