use crate::header::Command::Init;
use crate::header::{
    Command, DownloadHeader, DownloadResponse, ErrorHeader, NewKeyHeader, RotateKeyHeader,
    StatusHeader, UploadHeader, UploadResponse,
};
use crate::{
    ACTIVE_CONNECTIONS, ALLOW_ALL_CLIENTS, MAX_CONNECTIONS, MetadataFile, NETWORK_READ_BUFFER,
    NETWORK_WRITE_BUFFER, READ_CHUNK_SIZE, READ_TIMEOUT, SERVER_TRACKER, START_TIME, Tracker,
    WRITE_TIMEOUT, debug, error, file_hasher_async, get_allowed_client_path, get_file_lock,
    get_storage_path, info, release_file_lock, trace, try_get_uptime_hrs, warn,
};
use anyhow::{Context, Result};
use colored::Colorize;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::{SigningKey, VerifyingKey, pkcs8::DecodePublicKey};
use hex::encode;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::cmp::min;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Entry-point for TCP server using the v1 protocol
pub async fn start_tcp_server(port: u16, storage_path: Arc<PathBuf>) -> Result<()> {
    let now = chrono::Local::now();
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    info!(
        "TCP Server (protocol v1) listening on 0.0.0.0:{} (Max connections: {})",
        port, *MAX_CONNECTIONS
    );

    START_TIME.get_or_init(|| now);
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                // Check connection limit
                let current = ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                if current >= *MAX_CONNECTIONS {
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                    warn!("Connection rejected (max connections): {:?}", addr);
                    drop(stream); // Instant close
                    continue;
                }
                let storage_path = Arc::clone(&storage_path);
                let active_connections = Arc::clone(&ACTIVE_CONNECTIONS);
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
#[inline(always)]
async fn handle_connection(mut stream: TcpStream, storage_path: &Path) -> Result<()> {
    stream.set_nodelay(true).ok();
    let (mut reader, mut writer) = stream.split();

    let start_time = Instant::now();
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
        Init(flags) => {
            debug!("Received INIT request");
            handle_keys(&mut reader, &mut writer, flags).await?;
            writer.flush().await?;
            Ok(())
        }
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
                    handle_download(&mut reader, &mut writer, header, storage_path).await?;
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
    const MAX_FRAME_LENGTH: u32 = 1024 * 1024 * 12;
    let mut len_buf = [0u8; 4];
    let Ok(result) = timeout(READ_TIMEOUT, reader.read_exact(&mut len_buf)).await else {
        return Err(anyhow::anyhow!("Timeout reading frame length"));
    };
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Read error: {}", e));
    }
    let len = u32::from_be_bytes(len_buf);

    if len == 0 || len > MAX_FRAME_LENGTH {
        return Err(anyhow::anyhow!("Invalid frame length: {}", len));
    }

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

// Handle key registration and rotation: send nonce challenge, verify signature, create/rename user directory, send ACK or error response
async fn handle_keys<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut R,
    writer: &mut W,
    flag: u8,
) -> Result<()> {
    use rand::Rng;
    let mut nonce = vec![0u8; 2048];
    rand::rng().fill_bytes(&mut nonce);

    // send nonce challenge to client for signature verification, FIRST
    timeout(WRITE_TIMEOUT, write_frame(writer, &nonce)).await??;

    // read key header and do the thing
    let len = read_frame_length(reader).await? as usize;
    let mut header_bytes = vec![0u8; len];
    reader.read_exact(&mut header_bytes).await?;

    // New key
    if flag == 1 {
        let key_header = NewKeyHeader::deserialize(&header_bytes)?;
        match key_header.validate(&nonce) {
            Ok(_) => {
                use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
                let public_key = VerifyingKey::from_public_key_pem(&key_header.new_public_pem)
                    .map_err(|e| anyhow::anyhow!("Failed to parse public key from PEM: {}", e))?;
                let public_key_pem = public_key.to_public_key_pem(LineEnding::LF)?;

                let authorized_keys = get_allowed_client_path().await?;

                if !*ALLOW_ALL_CLIENTS
                    && !authorized_keys
                        .join(encode(public_key_pem.as_bytes()))
                        .exists()
                    && !authorized_keys
                        .join(encode(public_key_pem.as_bytes()))
                        .is_dir()
                {
                    send_failed(
                        writer,
                        ErrorHeader {
                            code: 403,
                            message: "Client not authorized, Please contact the admin, provider or ssh into the server".to_string(),
                        },
                    )
                    .await?;
                    return Ok(());
                }

                let pub_key_hash = encode(Sha256::digest(public_key.as_bytes()));
                let user_storage_dir = get_storage_path().await?.join(pub_key_hash);

                tokio::fs::create_dir_all(authorized_keys.join(encode(public_key_pem.as_bytes())))
                    .await?;
                tokio::fs::create_dir_all(&user_storage_dir).await?;
                timeout(WRITE_TIMEOUT, write_frame(writer, &[0x1u8])).await??; // ACK
            }
            Err(e) => {
                send_failed(
                    writer,
                    ErrorHeader {
                        code: 401,
                        message: format!("Invalid signature: {}", e),
                    },
                )
                .await?;
                return Ok(());
            }
        }
        // Rotate existing keys
    } else if flag == 2 {
        let key_header = RotateKeyHeader::deserialize(&header_bytes)?;

        match key_header.validate(&nonce).await {
            Ok(user_path) => {
                let new_pub_key = VerifyingKey::from_public_key_pem(&key_header.new_public_pem)
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to parse new public key from PEM: {}", e)
                    })?;
                let old_pub_key = VerifyingKey::from_public_key_pem(&key_header.old_public_pem)
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to parse old public key from PEM: {}", e)
                    })?;

                let new_public_key_pem = new_pub_key.to_public_key_pem(LineEnding::LF)?;
                let old_public_key_pem = old_pub_key.to_public_key_pem(LineEnding::LF)?;

                let new_pub_key_hex = encode(new_public_key_pem.as_bytes());
                let old_pub_key_hex = encode(old_public_key_pem.as_bytes());

                let new_pub_key_hash = encode(Sha256::digest(new_pub_key.as_bytes()));
                //let old_pub_key_hash = encode(Sha256::digest(old_pub_key.as_bytes()));

                let new_user_path = get_storage_path().await?.join(new_pub_key_hash);
                //let user_path = get_storage_path().await?.join(old_pub_key_hash);

                let auth_keys_path = get_allowed_client_path().await?;

                // hope this does not fail
                tokio::fs::rename(
                    auth_keys_path.join(old_pub_key_hex),
                    auth_keys_path.join(new_pub_key_hex),
                )
                .await?;
                tokio::fs::rename(&user_path, &new_user_path).await?;

                timeout(WRITE_TIMEOUT, write_frame(writer, &[0x1u8])).await??; // ACK
            }
            Err(e) => {
                send_failed(
                    writer,
                    ErrorHeader {
                        code: 401,
                        message: format!("Invalid signature: {}", e),
                    },
                )
                .await?;
                return Ok(());
            }
        }
    } else {
        send_failed(
            writer,
            ErrorHeader {
                code: 400,
                message: "Invalid flag value".to_string(),
            },
        )
        .await?;
        return Ok(());
    }

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
    let file_id = headers.file_id.clone();
    let file_lock = get_file_lock(&file_id);

    let _guard = match file_lock.try_write() {
        Ok(guard) => guard,
        Err(_) => {
            send_failed(
                writer,
                ErrorHeader {
                    code: 409,
                    message: "File is currently locked by another operation".to_string(),
                },
            )
            .await?;
            return Ok(());
        }
    };

    let file_key_hash = encode(Sha256::digest(headers.file_key.as_bytes()));

    let dir_path = storage_path.join(&file_key_hash);
    let file_path = dir_path.join(format!("{}.file", &headers.file_id));
    let metadata_path = dir_path.join(format!("{}.meta", &headers.file_id));

    tokio::fs::create_dir_all(&dir_path).await?;

    info!(
        "Start Uploading: {} ({} bytes) - Hash: {}...",
        headers.file_id.dimmed(),
        headers.file_size,
        headers.file_hash[..8].dimmed()
    );

    // Send ACK
    timeout(WRITE_TIMEOUT, write_frame(writer, &[0x1u8])).await??;

    let file = File::create(&file_path).await?;
    let mut buf_file = BufWriter::with_capacity(READ_CHUNK_SIZE * 2, file);
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

    let computed_hash = encode(hasher.finalize());
    if computed_hash != headers.file_hash {
        tokio::fs::remove_file(&file_path).await.ok();
        warn!(
            "Hash mismatch: expected {} but computed {}",
            &headers.file_hash, computed_hash
        );
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

    let metadata = MetadataFile {
        filename: headers.file_name,
        file_size: headers.file_size,
        file_hash: headers.file_hash,
        file_key_hash,
    };
    metadata.save_to_disk_async(&metadata_path).await?;

    let time_took = time_start.elapsed().as_secs_f32();
    info!(
        "Upload complete: File-ID: {} Time_taken: {}sec",
        &headers.file_id.dimmed(),
        time_took
    );
    send_success(
        writer,
        &UploadResponse {
            file_id: headers.file_id,
            time_took,
        },
    )
    .await?;

    drop(_guard);
    release_file_lock(&file_id);

    Tracker::log_upload(headers.file_size as usize).await;

    Ok(())
}

// Handle file download: validate request, read file and metadata, send file data with headers, update stats
async fn handle_download<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    _reader: &mut R,
    writer: &mut W,
    headers: DownloadHeader,
    storage_path: &Path,
) -> Result<()> {
    let file_id = headers.file_id.clone();
    let file_lock = get_file_lock(&file_id);

    let _guard = match file_lock.try_read() {
        Ok(guard) => guard,
        Err(_) => {
            send_failed(
                writer,
                ErrorHeader {
                    code: 409,
                    message: "File is currently being uploaded or modified".to_string(),
                },
            )
            .await?;
            return Ok(());
        }
    };

    let file_key_hash = encode(Sha256::digest(headers.file_key.as_bytes()));

    let dir_path = storage_path.join(&file_key_hash);
    if !dir_path.exists() {
        send_failed(
            writer,
            ErrorHeader {
                code: 404,
                message: "File not found".to_string(),
            },
        )
        .await?;
        return Ok(());
    }

    let file_path = dir_path.join(format!("{}.file", &headers.file_id));
    let meta_path = dir_path.join(format!("{}.meta", &headers.file_id));

    if !meta_path.exists() {
        warn!("Metadata not found for file_id: {}", &headers.file_id);
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

    let metadata: MetadataFile = match MetadataFile::read_from_disk_async(&meta_path).await {
        Ok(meta) => meta,
        Err(e) => {
            error!(
                "Failed to read metadata for file {}: {}",
                &headers.file_id, e
            );
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

    info!(
        "Downloading: {} ({} bytes) - Hash: {}...",
        &headers.file_id.dimmed(),
        file_size,
        file_hash[..8].dimmed()
    );

    let header = DownloadResponse {
        file_name,
        file_size,
        file_hash,
    }
    .serialize()?;

    let mut rsp = Vec::with_capacity(1 + header.len());
    rsp.push(1u8); // 1 = success;
    rsp.extend(header);
    timeout(WRITE_TIMEOUT, write_frame(writer, &rsp)).await??;

    let file = File::open(&file_path).await?;
    let mut buf_file = BufReader::with_capacity(READ_CHUNK_SIZE * 2, file);
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

    info!("Download complete: File-ID: {}", &headers.file_id.dimmed());

    drop(_guard);
    release_file_lock(&file_id);

    Tracker::log_download(file_size as usize).await;

    Ok(())
}

// TODO: Too many repetitive lazy code, very poor thinking, refactor later

/// Client function to register a new public key or rotate existing keys: connect to server, perform nonce challenge, sign nonce, send key info, handle ACK or error response
pub async fn register_pubkey(
    private_key: SigningKey,
    public_pem: &str,
    old_public_pem: Option<String>,
    host: &str,
    port: u16,
) -> Result<()> {
    use ed25519_dalek::Signer;

    let request = Init(if old_public_pem.is_some() { 2 } else { 1 }).serialize()?;

    let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    stream.set_nodelay(true).ok();

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

    let mut nonce = vec![0u8; len];
    reader
        .read_exact(&mut nonce)
        .await
        .context("Failed to read response")?;

    let signature = private_key.sign(&nonce);
    let header_bytes = match old_public_pem {
        Some(old_public_pem) => {
            let header = RotateKeyHeader {
                signature: encode(signature.to_bytes()),
                old_public_pem,
                new_public_pem: public_pem.to_string(),
            };
            header.serialize()?
        }
        None => {
            let header = NewKeyHeader {
                signature: encode(signature.to_bytes()),
                new_public_pem: public_pem.to_string(),
            };
            header.serialize()?
        }
    };

    let len = (header_bytes.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&header_bytes).await?;
    writer.flush().await?;

    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read response length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut rsp = vec![0u8; len];
    reader
        .read_exact(&mut rsp)
        .await
        .context("Failed to read response")?;

    // Reading flag for ACK or error
    if rsp[0] == 0x1u8 {
        println!("Registered successfully");
    } else if rsp[0] == 0x2u8 {
        let err = ErrorHeader::deserialize(&rsp[1..])?;
        anyhow::bail!("Auth failed: {} - {}", err.code, err.message);
    } else {
        anyhow::bail!("Auth failed: Unknown reason");
    }

    Ok(())
}

/// Client function to upload a file: connect to server, send upload request, stream file data, handle responses and errors
/// returns file ID on success, or error message on failure
pub async fn upload_client(
    file_path: PathBuf,
    file_key: String,
    file_id: &str,
    host: &str,
    port: u16,
) -> Result<String> {
    let file_name = file_path
        .file_name()
        .context("Invalid file path")?
        .to_string_lossy()
        .to_string();

    let metadata = tokio::fs::metadata(&file_path)
        .await
        .context("Failed to read file metadata")?;
    let file_size = metadata.len();

    if file_size <= 1024 {
        anyhow::bail!("File size must be greater than 1KB");
    }

    let pg_bar = ProgressBar::new(file_size);
    let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    stream.set_nodelay(true).ok();

    println!(
        "Starting upload: {} ({} mb)",
        file_name,
        file_size as f32 / (1024.0 * 1024.0)
    );

    let file_hash = file_hasher_async(&file_path)
        .await
        .context("Failed to compute file hash")?;
    println!("File hash: {}", file_hash.dimmed());

    pg_bar.set_style(
        ProgressStyle::default_bar()
            .template("↪ [{bar:60.blue/cyan}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
            .progress_chars("▨>-"),
    );

    let request = Command::Upload(UploadHeader {
        file_id: file_id.to_string(),
        file_name,
        file_size,
        file_hash,
        file_key,
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

    let file = File::open(&file_path)
        .await
        .context("Failed to reopen file")?;
    let mut buf_file = BufReader::with_capacity(READ_CHUNK_SIZE * 2, file);
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
        pg_bar.inc(n as u64);
    }

    pg_bar.finish_and_clear();
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

/// Client function to download a file: connect to server, send download request, read file data, validate hash, save to disk, handle errors
/// returns output file path on success, or error message on failure
pub async fn download_client(
    file_id: &str,
    file_key: String,
    output: Option<PathBuf>,
    host: &str,
    port: u16,
) -> Result<PathBuf> {
    let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    stream.set_nodelay(true).ok();

    let request = Command::Download(DownloadHeader {
        file_id: file_id.to_string(),
        file_key,
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
        "Downloading: {} ({} mb)",
        response.file_name,
        response.file_size as f32 / (1024.0 * 1024.0)
    );

    let pg_bar = ProgressBar::new(response.file_size);
    pg_bar.set_style(
        ProgressStyle::default_bar()
            .template("↩ [{bar:60.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
            .progress_chars("▨>-"),
    );

    let output_path = output
        .unwrap_or_else(|| PathBuf::from("."))
        .join(&response.file_name);

    let raw_file = File::create(&output_path).await?;
    let mut buf_file = BufWriter::with_capacity(READ_CHUNK_SIZE * 2, raw_file);
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut buf = vec![0u8; READ_CHUNK_SIZE];

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
        pg_bar.inc(n as u64);
    }

    buf_file.flush().await?;
    pg_bar.finish_and_clear();

    let computed_hash = encode(hasher.finalize());
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
