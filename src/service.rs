use crate::controller::{UploadStatus, start_server};
use anyhow::{Context, Result};
use futures_util::StreamExt;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::io;
use std::path::PathBuf;
use tokio::io::AsyncReadExt;

pub async fn serve(port: Option<u16>) -> Result<()> {
    dotenv::dotenv().ok();

    let port = port.unwrap_or_else(|| {
        if let Ok(env_port) = std::env::var("R_STORAGE_PORT") {
            env_port.parse::<u16>().unwrap_or(3000)
        } else {
            3000
        }
    });

    // Create a storage volume before server starts
    if !get_storage_path().await?.exists() {
        tokio::fs::create_dir_all(get_storage_path().await?).await?;
    }

    start_server(port).await?;

    Ok(())
}

#[inline]
pub async fn get_storage_path() -> Result<PathBuf> {
    let home_dir =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Failed to get home directory"))?;
    let storage_path = home_dir.join(".r_storage").join("storage");
    Ok(storage_path)
}

pub async fn upload_file(file_path: PathBuf, port: u16) -> Result<String> {
    let filename = file_path
        .file_name()
        .context("Invalid file path")?
        .to_string_lossy()
        .to_string();

    let metadata = tokio::fs::metadata(&file_path)
        .await
        .context("Failed to read file metadata")?;
    let file_size = metadata.len();

    let file = tokio::fs::File::open(&file_path)
        .await
        .context("Failed to open file")?;
    let mut reader = tokio::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 32 * 1024];

    loop {
        let n = reader.read(&mut buf).await.context("Failed to read file")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    print!("Enter file key: ");
    io::Write::flush(&mut io::stdout())?;
    let mut file_key = String::new();
    io::stdin().read_line(&mut file_key)?;
    let file_key = file_key.trim().to_string();

    let file_hash = format!("{:x}", hasher.finalize());
    println!("Computed hash: {}", file_hash);

    let client = Client::new();
    let url = format!("http://localhost:{}/upload", port);

    let file = tokio::fs::File::open(&file_path)
        .await
        .context("Failed to reopen file")?;

    let reader = tokio::io::BufReader::with_capacity(4 * 1024 * 1024, file);
    let stream = tokio_util::io::ReaderStream::new(reader);
    let body = reqwest::Body::wrap_stream(stream);

    let request = client
        .post(&url)
        .header("x-file-name", &filename)
        .header("x-file-size", file_size.to_string())
        .header("x-file-key", &file_key)
        .header("x-file-hash", &file_hash)
        .body(body);

    let response = request.send().await.context("Failed to send request")?;

    if !response.status().is_success() {
        anyhow::bail!("Upload failed with status: {}", response.status());
    }

    let upload_response: UploadStatus =
        response.json().await.context("Failed to parse response")?;

    println!("Upload successful! File ID: {}", upload_response.file_id);
    Ok(upload_response.file_id)
}

pub async fn download_file(
    file_id: String,
    file_key: String,
    output_path: Option<PathBuf>,
    port: u16,
) -> Result<PathBuf> {
    let client = Client::new();
    let url = format!("http://localhost:{}/download/{}", port, file_id);

    let response = client
        .get(&url)
        .header("x-file-key", &file_key)
        .send()
        .await
        .context("Failed to send request")?;

    if !response.status().is_success() {
        anyhow::bail!("Download failed with status: {}", response.status());
    }

    let filename = response
        .headers()
        .get("x-file-name")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| file_id.clone());

    let output = output_path
        .unwrap_or_else(|| PathBuf::from("."))
        .join(&filename);

    let mut file = tokio::fs::File::create(&output)
        .await
        .context("Failed to create output file")?;
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let data = chunk.context("Failed to read response chunk")?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &data)
            .await
            .context("Failed to write to file")?;
    }

    tokio::io::AsyncWriteExt::flush(&mut file)
        .await
        .context("Failed to flush file")?;

    // TODO: Add Hash validation after download completes

    println!("Download successful! Saved to: {}", output.display());
    Ok(output)
}
