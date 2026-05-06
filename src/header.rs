use crate::MAX_FILE_SIZE;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum Command {
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

#[derive(Serialize, Deserialize)]
pub struct UploadHeader {
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
    pub file_key: String,
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
