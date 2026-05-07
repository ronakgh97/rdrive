use crate::header::{
    Command, DownloadHeader, DownloadResponse, ErrorHeader, StatusHeader, UploadHeader,
    UploadResponse,
};
use crate::{
    Metadata, NETWORK_READ_BUFFER, NETWORK_WRITE_BUFFER, READ_CHUNK_SIZE, READ_TIMEOUT,
    SERVER_TRACKER, SHARED_FILE_LOCK, START_TIME, WRITE_TIMEOUT, debug, error, file_hasher_async,
    info, trace, try_get_uptime_hrs, warn,
};
use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::cmp::min;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use uuid::Uuid;

/// Entry-point for TCP server using the v1 protocol
pub async fn start_tcp_server(
    port: u16,
    max_connections: usize,
    storage_path: Arc<PathBuf>,
) -> Result<()> {
    let now = chrono::Local::now();
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    let active_connections = Arc::new(AtomicUsize::new(0));

    info!(
        "TCP Server (v1 protocol) listening on 0.0.0.0:{} (max connections: {})",
        port, max_connections
    );
    START_TIME.get_or_init(|| now);
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                // Check connection limit
                let current = active_connections.fetch_add(1, Ordering::Relaxed);
                if current >= max_connections {
                    active_connections.fetch_sub(1, Ordering::Relaxed);
                    warn!("Connection rejected (max connections): {:?}", addr);
                    drop(stream); // Instant close
                    continue;
                }
                let storage_path = Arc::clone(&storage_path);
                let active_connections = Arc::clone(&active_connections);
                info!("Connection request from {:?}", addr);
                tokio::spawn(async move {
                    trace!("Task spawned for connection from {:?}", addr);
                    let result = handle_connection(stream, &storage_path).await;
                    active_connections.fetch_sub(1, Ordering::Relaxed);
                    if let Err(e) = result {
                        error!("Error handling connection from {:?}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

/// Handle a single client connection, read command and dispatch to appropriate handler
#[inline]
async fn handle_connection(mut stream: TcpStream, storage_path: &Path) -> Result<()> {
    let start_time = Instant::now();
    stream.set_nodelay(true).ok();

    let (mut reader, mut writer) = stream.split();

    let command = match read_headers(&mut reader).await {
        Ok(cmd) => cmd,
        Err(e) => {
            // Handle timeout or early EOF
            if e.to_string().contains("Timeout") {
                let _ = send_failed(
                    &mut writer,
                    ErrorHeader {
                        code: 408,
                        message: "Request timed out".to_string(),
                    },
                )
                .await;
                return Ok(());
            }
            if e.to_string().contains("early eof") || e.to_string().contains("EOF") {
                return Ok(());
            }
            return Err(e);
        }
    };
    match command {
        Command::Upload(header) => {
            debug!("Received UPLOAD request");

            match header.validate() {
                Ok(_) => {
                    handle_upload(&mut reader, &mut writer, header, start_time, storage_path)
                        .await?;
                }
                Err(e) => {
                    send_failed(
                        &mut writer,
                        ErrorHeader {
                            code: 400,
                            message: format!("Invalid upload header: {}", e),
                        },
                    )
                    .await?;
                }
            }

            writer.flush().await?;
            Ok(())
        }
        Command::Download(header) => {
            debug!("Received DOWNLOAD request");

            match header.validate() {
                Ok(_) => {
                    handle_download(&mut reader, &mut writer, header, start_time, storage_path)
                        .await?;
                }
                Err(e) => {
                    send_failed(
                        &mut writer,
                        ErrorHeader {
                            code: 400,
                            message: format!("Invalid download header: {}", e),
                        },
                    )
                    .await?;
                }
            }

            writer.flush().await?;
            Ok(())
        }
        Command::Status => {
            debug!("Received STATUS request");
            send_status(&mut writer).await?;
            Ok(())
        }
    }
}

// Read 4 bytes for frame length with timeout, return error on timeout or read failure
#[inline(always)]
pub async fn read_frame_length<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<u32> {
    let mut len_buf = [0u8; 4];
    let Ok(result) = timeout(READ_TIMEOUT, reader.read_exact(&mut len_buf)).await else {
        return Err(anyhow::anyhow!("Timeout reading frame length"));
    };
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Read error: {}", e));
    }
    let len = u32::from_be_bytes(len_buf);
    Ok(len)
}

// Read headers with timeout, return packed command, handle timeout and early EOF
#[inline(always)]
async fn read_headers<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Command> {
    let len = read_frame_length(reader).await? as usize;
    let mut header_bytes = vec![0u8; len];
    reader.read_exact(&mut header_bytes).await?;

    let command = Command::deserialize(&header_bytes)?;
    Ok(command)
}

// Write a frame with 4-byte length prefix, return error on write failure
#[inline(always)]
pub async fn write_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    let len = data.len();
    if len > u32::MAX as usize {
        return Err(anyhow::anyhow!("Too large content: {} bytes", len));
    }
    let len = (len as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

// Send a generic serialized success response with code and message, then close the connection
#[inline]
async fn send_success<W: AsyncWriteExt + Unpin, T: Serialize>(
    writer: &mut W,
    response: &T,
) -> Result<()> {
    let mut rsp = Vec::with_capacity(1 + 96);
    rsp.push(1u8); // 1 = success
    postcard::to_io(response, &mut rsp)
        .map_err(|e| anyhow::anyhow!("Failed to serialize success response: {}", e))?;
    timeout(WRITE_TIMEOUT, write_frame(writer, &rsp)).await??;
    writer.shutdown().await?; // Close connection after response
    Ok(())
}

// Send an error response with code and message, then close the connection
#[inline]
async fn send_failed<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: ErrorHeader,
) -> Result<()> {
    let payload_bytes = response.serialize()?;
    let mut rsp = Vec::with_capacity(1 + payload_bytes.len());
    rsp.push(2u8); // 2 = error
    rsp.extend(payload_bytes);
    timeout(WRITE_TIMEOUT, write_frame(writer, &rsp)).await??;
    writer.shutdown().await?;
    Ok(())
}

// Send a status response with server info, then close the connection
#[inline]
async fn send_status<W: AsyncWriteExt + Unpin>(writer: &mut W) -> Result<()> {
    let uptime_hrs = try_get_uptime_hrs();

    let (total_upl, total_dwn, total_bw) = {
        let lock = SERVER_TRACKER.read().await;
        (
            lock.total_uploaded,
            lock.total_download,
            lock.total_bandwidth_gb,
        )
    };

    let timestamp = chrono::Utc::now().to_rfc3339();

    let status = StatusHeader {
        timestamp,
        uptime_hrs,
        total_uploaded: total_upl as u64,
        total_downloaded: total_dwn as u64,
        total_bandwidth_used: total_bw as u64,
    }
    .serialize()?;

    timeout(WRITE_TIMEOUT, write_frame(writer, &status)).await??;
    writer.shutdown().await?;
    Ok(())
}

// Handle file upload: read file data, validate hash and size, save to disk, update metadata, send response
async fn handle_upload<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut R,
    writer: &mut W,
    headers: UploadHeader,
    time_start: Instant,
    storage_path: &Path,
) -> Result<()> {
    let file_id = Uuid::new_v4().simple().to_string();
    let file_path = storage_path.join(&file_id);

    info!(
        "Start Uploading: {} ({} bytes) - Hash: {}...",
        headers.file_name,
        headers.file_size,
        headers.file_hash[..8].dimmed()
    );

    SHARED_FILE_LOCK.insert(file_id.clone(), headers.file_name.clone());

    let file = File::create(&file_path).await?;

    // Send ACK
    timeout(WRITE_TIMEOUT, write_frame(writer, &[0x1u8])).await??;

    let mut buf_file = BufWriter::with_capacity(NETWORK_READ_BUFFER * 2, file);
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut buf = vec![0u8; READ_CHUNK_SIZE];

    {
        while received < headers.file_size {
            let to_read = min(buf.len(), (headers.file_size - received) as usize);
            let n = reader.read(&mut buf[..to_read]).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            buf_file.write_all(&buf[..n]).await?;
            received += n as u64;
        }
    }
    buf_file.flush().await?;

    // TODO: this check is quite redundant since, validate() handles that
    if received != headers.file_size {
        tokio::fs::remove_file(&file_path).await.ok();
        SHARED_FILE_LOCK.remove(&file_id);
        send_failed(
            writer,
            ErrorHeader {
                code: 400,
                message: format!(
                    "File size mismatch: expected {} bytes but received {} bytes",
                    &headers.file_size, received
                ),
            },
        )
        .await?;
        return Ok(());
    }

    let computed_hash = hex::encode(hasher.finalize());
    if computed_hash != headers.file_hash {
        tokio::fs::remove_file(&file_path).await.ok();
        warn!(
            "Hash mismatch: expected {} but computed {}",
            &headers.file_hash, computed_hash
        );
        SHARED_FILE_LOCK.remove(&file_id);
        send_failed(
            writer,
            ErrorHeader {
                code: 406,
                message: "File hash mismatch".to_string(),
            },
        )
        .await?;
        return Ok(());
    }

    let metadata = Metadata {
        filename: headers.file_name,
        file_size: headers.file_size,
        file_hash: headers.file_hash,
        file_key: headers.file_key,
    };

    let metadata_path = storage_path.join(format!("{}.meta", file_id));
    metadata.save_to_disk_async(&metadata_path).await?;

    SHARED_FILE_LOCK.remove(&file_id);

    let time_took = time_start.elapsed().as_secs_f32();

    info!(
        "Upload complete: File-ID: {}... Time_taken: {}F",
        &file_id[..8].dimmed(),
        time_took
    );

    send_success(writer, &UploadResponse { file_id, time_took }).await?;

    let mut lock = SERVER_TRACKER.write().await;
    lock.total_bandwidth_gb += headers.file_size as f64 / (1024.0 * 1024.0 * 1024.0);
    lock.total_uploaded += 1;
    Ok(())
}

// Handle file download: validate request, read file and metadata, send file data with headers, update stats
async fn handle_download<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    _reader: &mut R,
    writer: &mut W,
    headers: DownloadHeader,
    _start_time: Instant,
    storage_path: &Path,
) -> Result<()> {
    if SHARED_FILE_LOCK.contains_key(&headers.file_id) {
        send_failed(
            writer,
            ErrorHeader {
                code: 409,
                message: "File is currently being uploaded, please try again later".to_string(),
            },
        )
        .await?;
        return Ok(());
    }

    let file_id = headers.file_id.replace("-", "_");

    let file_path = storage_path.join(&file_id);
    let meta_path = storage_path.join(format!("{}.meta", file_id));

    if !meta_path.exists() {
        warn!("Metadata not found for file_id: {}", file_id);
        send_failed(
            writer,
            ErrorHeader {
                code: 404,
                message: "Metadata File not found".to_string(),
            },
        )
        .await?;
        return Ok(());
    }

    let metadata: Metadata = match Metadata::read_from_disk_async(&meta_path).await {
        Ok(meta) => meta,
        Err(e) => {
            error!("Failed to read metadata for file {}: {}", file_id, e);
            return send_failed(
                writer,
                ErrorHeader {
                    code: 500,
                    message: "Failed to read metadata".to_string(),
                },
            )
            .await;
        }
    };

    let file_name = metadata.filename;
    let file_size = metadata.file_size;
    let file_hash = metadata.file_hash;

    if metadata.file_key != headers.file_key {
        warn!("Invalid file key for file_id: {}", file_id);
        send_failed(
            writer,
            ErrorHeader {
                code: 403,
                message: "Invalid file key".to_string(),
            },
        )
        .await?;
        return Ok(());
    }

    info!(
        "Downloading: {} ({} bytes) - File-ID: {}",
        file_name, file_size, file_id
    );

    let header = DownloadResponse {
        file_name,
        file_size,
        file_hash,
        file_key: headers.file_key,
    }
    .serialize()?;

    let mut rsp = Vec::with_capacity(1 + header.len());
    rsp.push(1u8); // 1 = success;
    rsp.extend(header);
    timeout(WRITE_TIMEOUT, write_frame(writer, &rsp)).await??;

    let file = File::open(&file_path).await?;
    let mut buf_file = BufReader::with_capacity(NETWORK_READ_BUFFER, file);
    let mut buf = vec![0u8; READ_CHUNK_SIZE];

    loop {
        let n = buf_file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).await?;
    }

    writer.flush().await?;
    writer.shutdown().await?;

    info!("Download complete: File-ID: {}", file_id);

    let mut lock = SERVER_TRACKER.write().await;
    lock.total_bandwidth_gb += file_size as f64 / (1024.0 * 1024.0 * 1024.0);
    lock.total_download += 1;
    Ok(())
}

pub async fn upload_client(
    path: PathBuf,
    lock_key: String,
    host: &str,
    port: u16,
) -> Result<String> {
    let file_name = path
        .file_name()
        .context("Invalid file path")?
        .to_string_lossy()
        .to_string();

    let metadata = tokio::fs::metadata(&path)
        .await
        .context("Failed to read file metadata")?;
    let file_size = metadata.len();

    let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    stream.set_nodelay(true).ok();

    println!("↪ Starting upload: {} ({} bytes)", file_name, file_size);

    let file_hash = file_hasher_async(&path)
        .await
        .context("Failed to compute file hash")?;
    println!("↪ File hash: {}...", file_hash.to_string().dimmed());

    let progress_bar = indicatif::ProgressBar::new(file_size);
    progress_bar.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("[{bar:60.cyan/magenta}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
            .progress_chars("$>-"),
    );

    let request = Command::Upload(UploadHeader {
        file_name,
        file_size,
        file_hash,
        file_key: lock_key,
    })
    .serialize()?;

    let (reader, writer) = stream.split();
    let mut reader = BufReader::with_capacity(NETWORK_READ_BUFFER, reader);
    let mut writer = BufWriter::with_capacity(NETWORK_WRITE_BUFFER, writer);
    let len = (request.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&request).await?;
    writer.flush().await.context("Failed to flush request")?;

    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read response length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    reader
        .read_exact(&mut response)
        .await
        .context("Failed to read response")?;

    // Reading flags early ACK
    if response[0] == 0x2u8 {
        let err = ErrorHeader::deserialize(&response[1..])?;
        anyhow::bail!("Upload failed: {} - {}", err.code, err.message);
    }

    let file = File::open(&path).await.context("Failed to reopen file")?;
    let mut buf_file = BufReader::with_capacity(READ_CHUNK_SIZE * 4, file);
    let mut buf = vec![0u8; READ_CHUNK_SIZE];

    loop {
        let n = buf_file
            .read(&mut buf)
            .await
            .context("Failed to read file")?;
        if n == 0 {
            break;
        }
        writer
            .write_all(&buf[..n])
            .await
            .context("Failed to send file data")?;
        progress_bar.inc(n as u64);
    }

    progress_bar.finish_and_clear();
    writer.flush().await.context("Failed to flush")?;

    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read response length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    reader
        .read_exact(&mut response)
        .await
        .context("Failed to read response")?;

    if response[0] == 0x2u8 {
        let err = ErrorHeader::deserialize(&response[1..])?;
        anyhow::bail!("Upload failed: {} - {}", err.code, err.message);
    }

    let rsp = UploadResponse::deserialize(&response[1..])?;

    stream.shutdown().await.ok();

    println!("File ID: {} - Time took: {}", rsp.file_id, rsp.time_took);

    Ok(rsp.file_id)
}

pub async fn download_client(
    file_id: String,
    file_key: String,
    output: Option<PathBuf>,
    host: &str,
    port: u16,
) -> Result<PathBuf> {
    let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    stream.set_nodelay(true).ok();

    let request = Command::Download(DownloadHeader { file_id, file_key }).serialize()?;

    let (reader, writer) = stream.split();
    let mut reader = BufReader::with_capacity(NETWORK_READ_BUFFER, reader);
    let mut writer = BufWriter::with_capacity(NETWORK_WRITE_BUFFER, writer);
    let len = (request.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&request).await?;
    writer.flush().await.context("Failed to flush request")?;

    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read header length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut header_bytes = vec![0u8; len];
    reader
        .read_exact(&mut header_bytes)
        .await
        .context("Failed to read header")?;

    // Reading flags ACK
    if header_bytes[0] == 0x2u8 {
        let err = ErrorHeader::deserialize(&header_bytes[1..])?;
        anyhow::bail!("Download failed: {} - {}", err.code, err.message);
    }

    let response = DownloadResponse::deserialize(&header_bytes[1..])?;

    println!(
        "↩ Downloading: {} ({} bytes)",
        response.file_name, response.file_size
    );

    let progress_bar = indicatif::ProgressBar::new(response.file_size);
    progress_bar.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("[{bar:60.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
            .progress_chars("#>-"),
    );

    let output_path = output
        .unwrap_or_else(|| PathBuf::from("."))
        .join(&response.file_name);

    let raw_file = File::create(&output_path).await?;
    let mut buf_file = BufWriter::with_capacity(NETWORK_READ_BUFFER * 2, raw_file);
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut buf = vec![0u8; READ_CHUNK_SIZE * 2];

    while received < response.file_size {
        let to_read = min(buf.len(), (response.file_size - received) as usize);
        let n = reader
            .read(&mut buf[..to_read])
            .await
            .context("Failed to read file data")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        buf_file.write_all(&buf[..n]).await?;
        received += n as u64;
        progress_bar.inc(n as u64);
    }

    buf_file.flush().await?;
    progress_bar.finish_and_clear();

    let computed_hash = hex::encode(hasher.finalize());
    if computed_hash != response.file_hash {
        tokio::fs::remove_file(&output_path).await.ok();
        anyhow::bail!(
            "✗ Hash mismatch: expected {} but computed {}",
            response.file_hash,
            computed_hash
        );
    }

    stream.shutdown().await.ok();

    println!("Saved to: {}", output_path.display());
    Ok(output_path)
}

pub async fn get_server_status(host: &str, port: u16) -> Result<StatusHeader> {
    let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    stream.set_nodelay(true).ok();

    let request = Command::Status.serialize()?;

    let (reader, writer) = stream.split();
    let mut reader = BufReader::with_capacity(NETWORK_READ_BUFFER, reader);
    let mut writer = BufWriter::with_capacity(NETWORK_WRITE_BUFFER, writer);
    let len = (request.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&request).await?;
    writer.flush().await.context("Failed to flush request")?;

    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read response length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    reader
        .read_exact(&mut response)
        .await
        .context("Failed to read response")?;

    let response = StatusHeader::deserialize(&response)?;

    stream.shutdown().await.ok();

    Ok(response)
}
