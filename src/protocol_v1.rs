// TODO: HOLY FUCKING SHIT, THIS IS A MESS, LOGIC ARE SOUND, BUT GOD THIS IS UNREADIABLE NOT TASTEFULL

use crate::crypto::{decrypt_data_in_place, encrypt_data_in_place, generate_x25519_keypair};
use crate::header::{
    ClientHello, Command, DownloadHeader, DownloadResponse, ErrorHeader, NewKeyHeader,
    RotateKeyHeader, ServerHello, StatusHeader, UploadHeader, UploadResponse, WarnHeader,
};
use crate::{
    ACTIVE_CONNECTIONS, AuthServerMap, ENABLE_CLIENT_WHITELIST, MAX_CONNECTIONS, MetadataFile,
    NETWORK_READ_BUFFER, NETWORK_WRITE_BUFFER, READ_CHUNK_SIZE, READ_TIMEOUT, SERVER_PRI_KEY_PEM,
    SERVER_PUB_KEY_PEM, SERVER_TRACKER, START_TIME, Tracker, WRITE_TIMEOUT, debug, error,
    file_hasher_async, get_authorized_client_dir, get_authorized_server_map_path, get_storage_dir,
    hold_file_lock, info, release_file_lock, trace, try_get_uptime_hrs, warn,
};
use anyhow::{Context, Result};
use colored::Colorize;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hex::encode;
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
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
                error!("Connection accept error: {}", e);
            }
        }
    }
}

/// Handle a single client connection, read command and dispatch to appropriate handler
#[inline]
async fn handle_connection(mut stream: TcpStream, storage_path: &Path) -> Result<()> {
    stream.set_nodelay(true).ok();
    let (reader, writer) = stream.split();
    let mut reader = BufReader::with_capacity(NETWORK_READ_BUFFER, reader);
    let mut writer = BufWriter::with_capacity(NETWORK_WRITE_BUFFER, writer);

    //------

    // starts init common handshake, goal is secure tunnel, where server is auth by client.
    // client connects, we immediately do x22519 exchange, and question authenticity later
    // flow; client [nonce_c + x25519_c] to server ->
    // server sign[nonce_c + nonce_s + x25519_c + x25519_s] + (ed25519_s + x25519_s + nonce_s) to client {sign all, that will be immune to MITM}->
    // client either drop tcp on invalid signature/disapprove or move on with whatever handler
    // both compute shared secret, encrypted channel

    let client_hello = {
        let mut client_hello_data = vec![];
        read_data_in_place_raw(&mut reader, &mut client_hello_data).await?;
        ClientHello::deserialize(&client_hello_data)?
    };

    let (x25519_pri, x25519_pub) = generate_x25519_keypair()?;

    let server_hello_data = {
        use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);

        let ed22519_pub = VerifyingKey::from_public_key_pem(&SERVER_PUB_KEY_PEM).map_err(|e| {
            anyhow::anyhow!(
                "Failed to construct server Ed25519 public key from PEM: {}",
                e
            )
        })?;

        let ed22519_pri = SigningKey::from_pkcs8_pem(&SERVER_PRI_KEY_PEM).map_err(|e| {
            anyhow::anyhow!(
                "Failed to construct server Ed25519 private key from PEM: {}",
                e
            )
        })?;

        let mut data_signed = [0u8; 128];
        data_signed[0..32].copy_from_slice(&client_hello.nonce);
        data_signed[32..64].copy_from_slice(&nonce);
        data_signed[64..96].copy_from_slice(&client_hello.x22519_key);
        data_signed[96..128].copy_from_slice(&x25519_pub.to_bytes());

        use ed25519_dalek::ed25519::signature::AsyncSigner;
        let signature = ed22519_pri.sign_async(&data_signed).await?;

        let server_hello = ServerHello {
            ed25519_key: ed22519_pub.to_bytes(),
            x22519_key: x25519_pub.to_bytes(),
            signature: signature.to_bytes(),
            nonce,
        };
        server_hello.serialize()?
    };

    // send Hello to client
    timeout(
        WRITE_TIMEOUT,
        write_frame_raw(&mut writer, &server_hello_data),
    )
    .await??;

    // from here client must have trusted server or rejected
    // now we check client authenticity, BUT actually, I guess
    // we don't need to, because client need to pass AUTH header and create their user-space
    // TODO: I might be wrong about the design, or for now, let trust client,
    //  but maybe we can least check whitelist right there
    //  and do not create user-space, argh... transport layer logic colliding with application logic
    //  anyway, this is becoming ssh handshake

    let session_key: [u8; 32] = {
        use x25519_dalek::PublicKey;
        let mut key = [0u8; 64]; // first 32 are zero
        key[32..64].copy_from_slice(
            &x25519_pri
                .diffie_hellman(&PublicKey::from(client_hello.x22519_key))
                .to_bytes(),
        );
        Sha256::digest(key).into() // TODO; I HATEEEEE ".into()" SO MUCHHHHHHH
    };

    //------

    let start_time = Instant::now();
    let command = match read_headers(&mut reader, &session_key).await {
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
                    &session_key,
                )
                .await;
                return Ok(());
            }
            if ["eof", "early eof", "unexpected eof"]
                .iter()
                .any(|pattern| e.to_string().to_lowercase().contains(pattern))
            {
                return Ok(());
            }
            return Err(e);
        }
    };
    match command {
        Command::Auth(flags) => {
            debug!("Received INIT request");
            handle_auth_keys(&mut reader, &mut writer, flags, &session_key).await?;
            writer.flush().await?;
            Ok(())
        }
        // TODO: ok maybe file headers need nonce challenge MAYBE!!!
        Command::Upload(header) => {
            debug!("Received UPLOAD request");

            match header.validate() {
                Ok(_) => {
                    handle_upload(
                        &mut reader,
                        &mut writer,
                        header,
                        start_time,
                        storage_path,
                        &session_key,
                    )
                    .await?;
                }
                Err(e) => {
                    send_failed(
                        &mut writer,
                        ErrorHeader {
                            code: 400,
                            message: format!("Invalid upload header: {}", e),
                        },
                        &session_key,
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
                    handle_download(&mut reader, &mut writer, header, storage_path, &session_key)
                        .await?;
                }
                Err(e) => {
                    send_failed(
                        &mut writer,
                        ErrorHeader {
                            code: 400,
                            message: format!("Invalid download header: {}", e),
                        },
                        &session_key,
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

/// Read 4 bytes for frame length with timeout, return error on timeout or read failure
#[inline(always)]
async fn read_frame_length<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<u32> {
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

/// Read encrypted headers, decrypt and deserialize into Command, return error on timeout, read failure, decryption failure, or deserialization failure
#[inline(always)]
async fn read_headers<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    session_key: &[u8; 32],
) -> Result<Command> {
    let len = read_frame_length(reader).await? as usize;
    let mut header_bytes = vec![0u8; len];
    reader.read_exact(&mut header_bytes).await?;

    decrypt_data_in_place(&mut header_bytes, session_key)?;
    let command = Command::deserialize(&header_bytes)?;
    Ok(command)
}

/// Read encrypted data in-place with timeout, return error on timeout, read failure, or decryption failure
#[allow(unused)]
#[inline(always)]
async fn read_data_in_place<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    session_key: [u8; 32],
    mut data: Vec<u8>,
) -> Result<()> {
    let len = read_frame_length(reader).await? as usize;
    // data.clear();
    data.resize(len, 0); // zero-out the required space
    reader.read_exact(&mut data).await?;

    decrypt_data_in_place(&mut data, &session_key)
}

/// Read raw data in-place with timeout, return error on timeout or read failure, no decryption
#[inline(always)]
async fn read_data_in_place_raw<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    data: &mut Vec<u8>,
) -> Result<()> {
    let len = read_frame_length(reader).await? as usize;
    // data.clear();
    data.resize(len, 0); // zero-out the required space
    reader.read_exact(data).await?;
    Ok(())
}

/// Write encrypted data with 4-byte length prefix, return error on write failure or encryption failure
#[inline(always)]
async fn write_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
    session_key: &[u8; 32],
) -> Result<()> {
    let buf = data.to_vec(); // compute correct len
    let len = buf.len();
    if len > u32::MAX as usize {
        return Err(anyhow::anyhow!("Too large content: {} bytes", len));
    }
    let len = (len as u32).to_be_bytes();

    encrypt_data_in_place(&mut data.to_vec(), session_key)?;
    writer.write_all(&len).await?;
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

/// Write a raw frame with 4-byte length prefix, return error on write failure, no encryption
async fn write_frame_raw<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
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

/// Send a generic serialized success response with code and message, then close the connection
#[inline]
async fn send_success<W: AsyncWriteExt + Unpin, T: Serialize>(
    writer: &mut W,
    response: &T,
    session_key: &[u8; 32],
) -> Result<()> {
    let mut rsp = Vec::with_capacity(1 + 96);
    rsp.push(1u8); // 1 = success
    postcard::to_io(response, &mut rsp)
        .map_err(|e| anyhow::anyhow!("Failed to serialize success response: {}", e))?;
    timeout(WRITE_TIMEOUT, write_frame(writer, &rsp, session_key)).await??;
    writer.shutdown().await?; // Close connection after response
    Ok(())
}

/// Send a generic warning response with code and message, then close the connection
#[inline]
async fn send_warn<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: WarnHeader,
    session_key: &[u8; 32],
) -> Result<()> {
    let payload_bytes = response.serialize()?;
    let mut rsp = Vec::with_capacity(1 + payload_bytes.len());
    rsp.push(2u8); // 2 = warning
    rsp.extend(payload_bytes);
    timeout(WRITE_TIMEOUT, write_frame(writer, &rsp, session_key)).await??;
    writer.shutdown().await?;
    Ok(())
}

/// Send an error response with code and message, then close the connection
#[inline]
async fn send_failed<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: ErrorHeader,
    session_key: &[u8; 32],
) -> Result<()> {
    let payload_bytes = response.serialize()?;
    let mut rsp = Vec::with_capacity(1 + payload_bytes.len());
    rsp.push(3u8); // 3 = error
    rsp.extend(payload_bytes);
    timeout(WRITE_TIMEOUT, write_frame(writer, &rsp, session_key)).await??;
    writer.shutdown().await?;
    Ok(())
}

/// Send a status response with server info, then close the connection
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

    let user_storage_path = get_storage_dir().await?;
    let mut rd = tokio::fs::read_dir(&user_storage_path).await?;
    let mut dir_count: usize = 0;
    while let Some(entry) = rd.next_entry().await? {
        if entry.file_type().await?.is_dir() {
            dir_count += 1;
        }
    }

    let timestamp = chrono::Utc::now().to_rfc3339();

    let status = StatusHeader {
        timestamp,
        uptime_hrs,
        auth_client: dir_count as u64,
        total_uploaded: total_upl as u64,
        total_downloaded: total_dwn as u64,
        total_bandwidth_used: total_bw as u64,
    }
    .serialize()?;

    timeout(WRITE_TIMEOUT, write_frame_raw(writer, &status)).await??;
    writer.shutdown().await?;
    Ok(())
}
/// Handle key registration and rotation: send nonce challenge, verify signature, create/rename user directory, send ACK or error response
async fn handle_auth_keys<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut R,
    writer: &mut W,
    flag: u8,
    session_key: &[u8; 32],
) -> Result<()> {
    let mut nonce = vec![0u8; 4096];
    rand::rng().fill_bytes(&mut nonce);

    // TODO; we are sending nonce challenge regardless of authenticity of client, hmm?
    //  will this need x25519 encryption? (app level or network level?),
    //  I'm trying to come up with shared header flow, to reduce brain damage
    // send nonce challenge to client for signature verification, FIRST
    // hashing for good sake, 32 bytes cute
    timeout(
        WRITE_TIMEOUT,
        write_frame(writer, &Sha256::digest(&nonce), session_key),
    )
    .await??;

    // read key header and do the thing
    let len = read_frame_length(reader).await? as usize;
    let mut header_bytes = vec![0u8; len];
    reader.read_exact(&mut header_bytes).await?;

    // New key
    if flag == 1 {
        let key_header = NewKeyHeader::deserialize(&header_bytes)?;
        match key_header.validate(&nonce) {
            Ok(_) => {
                let pub_key =
                    VerifyingKey::from_bytes(&key_header.new_public_bytes).map_err(|e| {
                        anyhow::anyhow!("Failed to construct public key from bytes: {}", e)
                    })?;
                let pub_key_pem = pub_key.to_public_key_pem(LineEnding::LF).map_err(|e| {
                    anyhow::anyhow!("Failed to convert public key to PEM format: {}", e)
                })?;
                // hex because we want human-readable
                let pub_key_hex = encode(pub_key_pem.as_bytes());

                let auth_keys_path = get_authorized_client_dir().await?.join(&pub_key_hex);

                info!("Auth attempt with new key: {}", &pub_key_hex[..16].dimmed());

                // check if client is allowed (if ENABLE_CLIENT_WHITELIST, false) and if auth key path is valid
                match (
                    *ENABLE_CLIENT_WHITELIST,
                    auth_keys_path.exists(),
                    auth_keys_path.is_dir(),
                ) {
                    (false, false, _) => {
                        warn!(
                            "Client with key: {} is not authorized, rejecting client storage space",
                            &pub_key_hex[..18]
                        );
                        send_failed(
                            writer,
                            ErrorHeader {
                                code: 403,
                                message: "Client not authorized, please contact the admin, provider or ssh into the server"
                                    .to_string(),
                            },
                            session_key,
                        ).await?;

                        return Ok(());
                    }

                    (_, true, false) => {
                        error!(
                            "Auth key must be a directory for key: {}, skipping user storage space creation",
                            &pub_key_hex[..18]
                        );
                        send_failed(
                            writer,
                            ErrorHeader {
                                code: 500,
                                message: "Auth key path exists but is not a directory, skipping user storage dir creation".to_string(),
                            },
                            session_key,
                        ).await?;

                        return Ok(());
                    }

                    _ => {}
                }
                // hash collision free
                let pub_key_hash = encode(Sha256::digest(pub_key.as_bytes()));
                let user_storage_dir = get_storage_dir().await?.join(pub_key_hash);
                let user_key_path = auth_keys_path.join(encode(pub_key_pem.as_bytes()));

                // check and return from here, no needed
                if user_storage_dir.exists() && user_key_path.exists() {
                    send_warn(
                        writer,
                        WarnHeader {
                            code: 409,
                            message: "Client Auth & Storage directory already exists, not required"
                                .to_string(),
                        },
                        session_key,
                    )
                    .await?;
                    return Ok(());
                }

                // auto white-list if ALLOW_CLIENT false & dir not exists already
                match (
                    tokio::fs::create_dir_all(&user_key_path).await,
                    tokio::fs::create_dir_all(&user_storage_dir).await,
                ) {
                    (Err(_), Err(_)) | (Err(_), Ok(_)) | (Ok(_), Err(_)) => {
                        error!(
                            "Failed to create auth key or user space for key: {}, returning back",
                            &pub_key_hex[..18]
                        );
                        send_failed(
                            writer,
                            ErrorHeader {
                                code: 500,
                                message: "Failed to create auth key or user storage directory, try again later"
                                    .to_string(),
                            },
                            session_key,
                        ).await?;
                        return Ok(());
                    }
                    _ => {}
                }
                timeout(WRITE_TIMEOUT, write_frame(writer, &[0x1u8], session_key)).await??; // ACK
            }
            Err(e) => {
                send_failed(
                    writer,
                    ErrorHeader {
                        code: 401,
                        message: format!("Invalid signature: {}", e),
                    },
                    session_key,
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
                let new_pub_key =
                    VerifyingKey::from_bytes(&key_header.new_public_bytes).map_err(|e| {
                        anyhow::anyhow!("Failed to construct new public key from bytes: {}", e)
                    })?;
                let old_pub_key =
                    VerifyingKey::from_bytes(&key_header.old_public_bytes).map_err(|e| {
                        anyhow::anyhow!("Failed to construct old public key from bytes: {}", e)
                    })?;

                let new_pub_key_pem =
                    new_pub_key.to_public_key_pem(LineEnding::LF).map_err(|e| {
                        anyhow::anyhow!("Failed to convert new public key to PEM format: {}", e)
                    })?;
                let old_pub_key_pem =
                    old_pub_key.to_public_key_pem(LineEnding::LF).map_err(|e| {
                        anyhow::anyhow!("Failed to convert old public key to PEM format: {}", e)
                    })?;

                let new_pub_key_hex = encode(new_pub_key_pem.as_bytes());
                let old_pub_key_hex = encode(old_pub_key_pem.as_bytes());

                info!(
                    "Rotate key attempt: {} -> {}",
                    &new_pub_key_hex[..16].dimmed(),
                    &old_pub_key_hex[..16].dimmed()
                );

                let new_pub_key_hash = encode(Sha256::digest(new_pub_key.as_bytes()));
                //let old_pub_key_hash = encode(Sha256::digest(old_pub_key.as_bytes()));

                let new_user_path = get_storage_dir().await?.join(new_pub_key_hash);
                //let user_path = get_storage_path().await?.join(old_pub_key_hash);

                let auth_keys_path = get_authorized_client_dir().await?;

                // hope this does not fail
                match (
                    tokio::fs::rename(
                        auth_keys_path.join(&old_pub_key_hex),
                        auth_keys_path.join(&new_pub_key_hex),
                    )
                    .await,
                    tokio::fs::rename(&user_path, &new_user_path).await,
                ) {
                    (Err(_), Err(_)) | (Err(_), Ok(_)) | (Ok(_), Err(_)) => {
                        error!(
                            "Failed to rotate old keys for: {}, returning back",
                            &old_pub_key_hex
                        );
                        send_failed(
                            writer,
                            ErrorHeader {
                                code: 500,
                                message: "Failed to rotate keys, try again later".to_string(),
                            },
                            session_key,
                        )
                        .await?;
                        return Ok(());
                    }
                    _ => {}
                }

                timeout(WRITE_TIMEOUT, write_frame(writer, &[0x1u8], session_key)).await??; // ACK
            }
            Err(e) => {
                send_failed(
                    writer,
                    ErrorHeader {
                        code: 401,
                        message: format!("Invalid signature: {}", e),
                    },
                    session_key,
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
            session_key,
        )
        .await?;
        return Ok(());
    }

    Ok(())
}

/// Handle file upload: read file data, validate hash and size, save to disk, update metadata, send response
async fn handle_upload<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut R,
    writer: &mut W,
    headers: UploadHeader,
    time_start: Instant,
    storage_path: &Path,
    session_key: &[u8; 32],
) -> Result<()> {
    let file_id = headers.file_id.clone();
    let file_lock = hold_file_lock(&file_id);

    let guard = match file_lock.try_write() {
        Ok(g) => g,
        Err(_) => {
            send_failed(
                writer,
                ErrorHeader {
                    code: 409,
                    message: "File is currently locked by another operation".to_string(),
                },
                session_key,
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

    // Send ACK before streaming starts
    timeout(WRITE_TIMEOUT, write_frame(writer, &[0x1u8], session_key)).await??;

    let file = File::create(&file_path).await?;
    let mut buf_file = BufWriter::with_capacity(READ_CHUNK_SIZE * 2, file);
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut buf = vec![0u8; READ_CHUNK_SIZE];

    {
        while received < headers.file_size {
            let remaining = (headers.file_size - received) as usize;
            let to_read = min(buf.len(), remaining);
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
            session_key,
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
        session_key,
    )
    .await?;

    drop(guard);
    release_file_lock(&file_id);

    Tracker::log_upload(headers.file_size as usize).await;

    Ok(())
}

/// Handle file download: validate request, read file and metadata, send file data with headers, update stats
async fn handle_download<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    _reader: &mut R,
    writer: &mut W,
    headers: DownloadHeader,
    storage_path: &Path,
    session_key: &[u8; 32],
) -> Result<()> {
    let file_id = headers.file_id.clone();
    let file_lock = hold_file_lock(&file_id);

    let guard = match file_lock.try_read() {
        Ok(g) => g,
        Err(_) => {
            send_failed(
                writer,
                ErrorHeader {
                    code: 409,
                    message: "File is currently being uploaded or modified".to_string(),
                },
                session_key,
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
            session_key,
        )
        .await?;
        return Ok(());
    }

    let file_path = dir_path.join(format!("{}.file", &headers.file_id));
    let meta_path = dir_path.join(format!("{}.meta", &headers.file_id));

    // TODO; should be 500?
    if !meta_path.exists() {
        warn!("Metadata not found for file_id: {}", &headers.file_id);
        send_failed(
            writer,
            ErrorHeader {
                code: 404,
                message: "Metadata File not found".to_string(),
            },
            session_key,
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
                session_key,
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

    // ACK before streaming
    let mut rsp = Vec::with_capacity(1 + header.len());
    rsp.push(1u8); // 1 = success;
    rsp.extend(header);
    timeout(WRITE_TIMEOUT, write_frame(writer, &rsp, session_key)).await??; // connection should be kept alive

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

    drop(guard);
    release_file_lock(&file_id);

    Tracker::log_download(file_size as usize).await;

    Ok(())
}

/// Helper function to perform client handshake and return the computed shared secret session key and tcp stream for continue handler,
/// or error if handshake fails at any step (network error, invalid server response, signature verification failure, or user rejection of untrusted server)
async fn client_handshake_helper(host: &str, port: u16) -> Result<([u8; 32], TcpStream)> {
    // connect first
    let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    stream.set_nodelay(true).ok();

    let server_ip = stream
        .peer_addr()
        .map_err(|e| anyhow::anyhow!("Failed to get server IP: {}", e))?;

    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    let (x25519_pri, x25519_pub) = generate_x25519_keypair()?;

    let client_hello_data = ClientHello {
        x22519_key: x25519_pub.to_bytes(),
        nonce,
    }
    .serialize()?;

    let (reader, writer) = stream.split();
    let mut reader = BufReader::with_capacity(NETWORK_READ_BUFFER, reader);
    let mut writer = BufWriter::with_capacity(NETWORK_WRITE_BUFFER, writer);
    write_frame_raw(&mut writer, &client_hello_data).await?; // send client hello

    let mut server_hello_data = vec![];
    read_data_in_place_raw(&mut reader, &mut server_hello_data).await?; // read server hello
    let server_hello = ServerHello::deserialize(&server_hello_data)?;

    // we check server_map, proceed with caller handler or reject
    let mut authorized_server =
        AuthServerMap::read_or_create(&get_authorized_server_map_path()?).await?;

    let server_key = VerifyingKey::from_bytes(&server_hello.ed25519_key)
        .context("Failed to parse server Ed25519 public key")?;
    let server_key_pem = server_key
        .to_public_key_pem(LineEnding::LF)
        .context("Failed to encode server public key as PEM")?;

    // determine trusted key
    let trusted_key =
        if let Some(existing_server_pem) = authorized_server.server_map.get(&server_ip) {
            if existing_server_pem != &server_key_pem {
                println!("{} {}", "WARNING: server key changed for".red(), server_ip);
                println!("{}\n{}", "Before:".yellow(), existing_server_pem);
                println!("{}\n{}", "After:".yellow(), server_key_pem);
                println!("Trust new key? [y/N]");

                let mut input = String::new();
                std::io::stdin()
                    .read_line(&mut input)
                    .context("Failed to read user input")?;

                if !input.trim().eq_ignore_ascii_case("y") {
                    stream.shutdown().await?; // instant close, server gets graceful EOF
                    drop(stream);
                    anyhow::bail!("User rejected rotated server key");
                }

                // replace stored key
                authorized_server
                    .server_map
                    .insert(server_ip, server_key_pem);

                server_key
            } else {
                // use already trusted stored key
                VerifyingKey::from_public_key_pem(existing_server_pem)
                    .context("Stored PEM key is invalid")?
            }
        } else {
            println!("Unknown server ip: {}", server_ip);
            println!("Server key:\n{}", server_key_pem);
            println!("Trust this server? [y/N]");

            let mut input = String::new();
            std::io::stdin()
                .read_line(&mut input)
                .context("Failed to read user input")?;

            if !input.trim().eq_ignore_ascii_case("y") {
                stream.shutdown().await?; // instant close, server gets graceful EOF
                drop(stream);
                anyhow::bail!("User rejected unknown server");
            }

            authorized_server
                .server_map
                .insert(server_ip, server_key_pem);

            server_key
        };

    // construct signed payload SAME AS SERVER
    let mut data_signed = [0u8; 128];
    data_signed[0..32].copy_from_slice(&nonce);
    data_signed[32..64].copy_from_slice(&server_hello.nonce);
    data_signed[64..96].copy_from_slice(&x25519_pub.to_bytes());
    data_signed[96..128].copy_from_slice(&server_hello.x22519_key);

    // verify signature
    let signature = Signature::from_bytes(&server_hello.signature);

    trusted_key
        .verify(&data_signed, &signature)
        .context("Server signature verification failed")?;

    let session_key = {
        use x25519_dalek::PublicKey;
        let mut key = [0u8; 64];
        key[32..64].copy_from_slice(
            &x25519_pri
                .diffie_hellman(&PublicKey::from(server_hello.x22519_key))
                .to_bytes(),
        );
        Sha256::digest(key).into() // TODO; I HATEEEEE ".into()" SO MUCHHHHHHH
    };

    Ok((session_key, stream))
}

// TODO: Too many repetitive lazy code, very poor thinking, refactor later

/// Client function to register a new public key or rotate existing keys: connect to server, perform nonce challenge, sign nonce, send key info, handle ACK or error response
pub async fn auth_client(
    private_key: SigningKey,
    verifying_key: VerifyingKey,
    old_verifying_key: Option<VerifyingKey>,
    host: &str,
    port: u16,
) -> Result<()> {
    use ed25519_dalek::Signer;

    let (session_key, mut stream) = client_handshake_helper(host, port)
        .await
        .map_err(|e| anyhow::anyhow!("Handshake failed: {}", e))?;
    let (reader, writer) = stream.split();
    let mut reader = BufReader::with_capacity(NETWORK_READ_BUFFER, reader);
    let mut writer = BufWriter::with_capacity(NETWORK_WRITE_BUFFER, writer);

    // send auth header request
    let mut auth_request =
        Command::Auth(if old_verifying_key.is_some() { 2 } else { 1 }).serialize()?;
    encrypt_data_in_place(&mut auth_request, &session_key)?;
    write_frame(&mut writer, &auth_request, &session_key)
        .await
        .context("Failed to send auth header")?;

    let len_buf = read_frame_length(&mut reader).await? as usize;
    let mut nonce = vec![0u8; len_buf];
    reader
        .read_exact(&mut nonce)
        .await
        .context("Failed to read nonce challenge")?;
    decrypt_data_in_place(&mut nonce, &session_key)?; // TODO: FUCKING BORROW CHECKER

    //TODO: we may add some bullshit to nonce, when full protocol is implemented
    let signature = private_key.sign(&nonce);
    let header_bytes = match old_verifying_key {
        Some(old_verifying_key) => {
            let header = RotateKeyHeader {
                signature: signature.to_bytes(),
                old_public_bytes: old_verifying_key.to_bytes(),
                new_public_bytes: verifying_key.to_bytes(),
            };
            header.serialize()?
        }
        None => {
            let header = NewKeyHeader {
                signature: signature.to_bytes(),
                new_public_bytes: verifying_key.to_bytes(),
            };
            header.serialize()?
        }
    };

    write_frame(&mut writer, &header_bytes, &session_key)
        .await
        .context("Failed to send key header")?;

    let len_buf = read_frame_length(&mut reader).await? as usize;
    let mut rsp = vec![0u8; len_buf];
    reader
        .read_exact(&mut rsp)
        .await
        .context("Failed to read response")?;
    decrypt_data_in_place(&mut rsp, &session_key)?;

    // Reading flag for ACK or error
    if rsp[0] == 0x1u8 {
        println!("Auth successfully");
    } else if rsp[0] == 0x2u8 {
        let warn = WarnHeader::deserialize(&rsp[1..])?;
        println!("Auth warning: {} - {}", warn.code, warn.message);
    } else if rsp[0] == 0x3u8 {
        let err = ErrorHeader::deserialize(&rsp[1..])?;
        anyhow::bail!("Auth failed: {} - {}", err.code, err.message);
    } else {
        anyhow::bail!("Invalid response from server");
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
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
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

    // do handshake
    let (session_key, mut stream) = client_handshake_helper(host, port)
        .await
        .map_err(|e| anyhow::anyhow!("Handshake failed: {}", e))?;
    stream.set_nodelay(true).ok();

    let pg_bar = ProgressBar::new(file_size);
    println!(
        "Starting upload: {} ({} mb)",
        file_name,
        file_size as f32 / (1024.0 * 1024.0)
    );

    let file_hash = file_hasher_async(&file_path)
        .await
        .context("Failed to compute file hash")?;
    println!("File hash: {}", file_hash.dimmed());

    // TODO; will change this with nonce from server
    let mut signed_data = vec![0u8; 64];
    signed_data[..32].copy_from_slice(verifying_key.as_bytes());
    signed_data[32..64].copy_from_slice(&Sha256::digest(session_key));

    let signature = signing_key.sign(&signed_data);
    let request = Command::Upload(UploadHeader {
        file_id: file_id.to_string(),
        file_name,
        file_size,
        file_hash,
        file_key,
        ed25519_key_bytes: verifying_key.to_bytes(),
        signature: signature.to_bytes(),
    })
    .serialize()?;

    pg_bar.set_style(
        ProgressStyle::default_bar()
            .template("↪ [{bar:60.blue/cyan}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
            .progress_chars("▨◻-"),
    );

    let (reader, writer) = stream.split();
    let mut reader = BufReader::with_capacity(NETWORK_READ_BUFFER, reader);
    let mut writer = BufWriter::with_capacity(NETWORK_WRITE_BUFFER, writer);
    write_frame(&mut writer, &request, &session_key) // send header request
        .await
        .context("Failed to send upload request")?;

    let len_buf = read_frame_length(&mut reader).await? as usize;
    let mut response = vec![0u8; len_buf];
    reader
        .read_exact(&mut response)
        .await
        .context("Failed to read response")?;
    decrypt_data_in_place(&mut response, &session_key)?;

    // Reading flags early ACK
    if response[0] == 0x3u8 {
        let err = ErrorHeader::deserialize(&response[1..])?;
        anyhow::bail!("Upload failed: {} - {}", err.code, err.message);
    } else if response[0] == 0x2u8 {
        let warn = WarnHeader::deserialize(&response[1..])?;
        println!("Upload warning: {} - {}", warn.code, warn.message);
    }

    let file = File::open(&file_path)
        .await
        .context("Failed to reopen file")?;
    let mut buf_file = BufReader::with_capacity(READ_CHUNK_SIZE * 2, file);
    let mut buf = vec![0u8; READ_CHUNK_SIZE];

    // TODO; encrypt locally with file-key

    loop {
        let n = buf_file
            .read(&mut buf)
            .await
            .context("Failed to read file")?;
        if n == 0 {
            break;
        }

        // TODO; ok so THIS SHIT WILL CHANGE I CANT THINK RIGHT NOW!!!!
        // encrypt file chunks
        let mut encrypted_chunk = buf[..n].to_vec();
        encrypt_data_in_place(&mut encrypted_chunk, &session_key)?; // todo: this needed a rewrite, im tired now

        writer
            .write_all(&encrypted_chunk)
            .await
            .context("Failed to send file data")?;
        pg_bar.inc(n as u64);
    }

    pg_bar.finish_and_clear();
    writer.flush().await.context("Failed to flush")?;

    let len_buf = read_frame_length(&mut reader).await? as usize;
    let mut response = vec![0u8; len_buf];
    reader
        .read_exact(&mut response)
        .await
        .context("Failed to read response")?;
    decrypt_data_in_place(&mut response, &session_key)?;

    if response[0] == 0x3u8 {
        let err = ErrorHeader::deserialize(&response[1..])?;
        anyhow::bail!("Upload failed: {} - {}", err.code, err.message);
    } else if response[0] == 0x2u8 {
        let warn = WarnHeader::deserialize(&response[1..])?;
        println!("Upload warning: {} - {}", warn.code, warn.message);
    }

    let rsp = UploadResponse::deserialize(&response[1..])?;

    stream.shutdown().await?;

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

    let len_buf = read_frame_length(&mut reader).await? as usize;
    let mut header_bytes = vec![0u8; len_buf];
    reader
        .read_exact(&mut header_bytes)
        .await
        .context("Failed to read header")?;

    // Reading flags ACK
    if header_bytes[0] == 0x3u8 {
        let err = ErrorHeader::deserialize(&header_bytes[1..])?;
        anyhow::bail!("Download failed: {} - {}", err.code, err.message);
    } else if header_bytes[0] == 0x2u8 {
        let warn = WarnHeader::deserialize(&header_bytes[1..])?;
        println!("Download warning: {} - {}", warn.code, warn.message);
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
            .progress_chars("▨◻-"),
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
        let remaining_bytes = (response.file_size - received) as usize;
        let to_read = min(buf.len(), remaining_bytes);
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

    let len_buf = read_frame_length(&mut reader).await? as usize;
    let mut response = vec![0u8; len_buf];
    reader
        .read_exact(&mut response)
        .await
        .context("Failed to read response")?;

    let response = StatusHeader::deserialize(&response)?;

    stream.shutdown().await.ok();

    Ok(response)
}
