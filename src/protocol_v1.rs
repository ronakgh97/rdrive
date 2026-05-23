// TODO: HOLY FUCKING SHIT, THIS IS A MESS, LOGIC ARE SOUND, BUT GOD THIS IS UNREADIABLE NOT TASTEFULL

use crate::crypto::{NONCE_LEN, TAG_LEN, decrypt_into, encrypt_into, generate_x25519_keypair};
use crate::header::{
    ClientHello, Command, DownloadHeader, DownloadResponse, EchoDebugHeader, ErrorHeader,
    NewKeyHeader, RotateKeyHeader, ServerHello, StatusHeader, UploadHeader, UploadResponse,
    WarnHeader,
};
use crate::{
    ACTIVE_CONNECTIONS, AuthServerMap, ENABLE_CLIENT_WHITELIST, ENABLE_ECHO, MAX_CONNECTIONS,
    MetadataFile, NETWORK_READ_BUFFER, NETWORK_WRITE_BUFFER, READ_CHUNK_SIZE, READ_TIMEOUT,
    SERVER_PRI_KEY_BYTES, SERVER_PUB_KEY_BYTES, SERVER_TRACKER, START_TIME, Tracker, WRITE_TIMEOUT,
    debug, error, file_hasher_async, get_authorized_client_dir, get_authorized_server_map_path,
    get_storage_dir, hold_file_lock, info, release_file_lock, trace, try_get_uptime_hrs, warn,
};
use anyhow::{Context, Result};
use colored::Colorize;
use ed25519_dalek::ed25519::signature::{AsyncSigner, AsyncVerifier};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hex::{decode, encode};
use indicatif::{ProgressBar, ProgressStyle};
use rand::{Rng, RngExt, rng};
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};
use std::cmp::min;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use x25519_dalek::PublicKey;

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
    let network_time = Instant::now();

    // starts init common handshake, goal is secure tunnel, where server is auth by client.
    // client connects, we immediately do x22519 exchange, and question authenticity later
    // flow; client [nonce_c + x25519_c] to server ->
    // server sign[nonce_c + nonce_s + x25519_c + x25519_s] + (ed25519_s + x25519_s + nonce_s) to client {sign all, that will be immune to MITM}->
    // client either drop tcp on invalid signature/disapprove or move on with whatever handler
    // both compute shared secret, encrypted channel

    let (shared_key, client_key) = server_handshake(&mut reader, &mut writer)
        .await
        .map_err(|e| anyhow::anyhow!("Handshake failed: {}", e))?;

    // from here client must have trusted server or rejected
    // now we check client authenticity, BUT actually, I guess
    // we don't need to, because client need to pass AUTH header and create their user-space
    // TODO: I might be wrong about the design, or for now, let trust client,
    //  but maybe we can least check whitelist right there
    //  and do not create user-space, argh... transport layer logic colliding with application logic
    //  anyway, this is becoming ssh handshake

    let session_key: [u8; 32] = {
        // format [k]..[1]..[k]..[1]
        let mut key = [1u8; 128];
        key[0..32].copy_from_slice(&shared_key);
        key[64..96].copy_from_slice(&shared_key);
        Sha256::digest(key).into() // TODO; I HATEEEEE ".into()" SO MUCHHHHHHH
    };

    //------

    // global memory pool for header processing, to reduce allocations,
    // this is safe because we process one header at a time
    let mut global_pool = vec![0u8; 4 * 1024 * 1024];

    let command = match read_headers(&mut reader, &session_key, &mut global_pool).await {
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
                    &mut global_pool,
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
        Command::Echo => {
            debug!("Received ECHO request");

            match *ENABLE_ECHO {
                true => {
                    handle_echo_debug(&mut reader, &mut writer, &session_key, &mut global_pool)
                        .await?;
                    writer.flush().await?;
                    Ok(())
                }
                false => {
                    send_failed(
                        &mut writer,
                        ErrorHeader {
                            code: 403,
                            message: "ECHO command is disabled on this server".to_string(),
                        },
                        &session_key,
                        &mut global_pool,
                    )
                    .await?;
                    writer.flush().await?;
                    Ok(())
                }
            }
        }
        Command::Auth(flags) => {
            debug!("Received INIT request");
            handle_auth_keys(
                &mut reader,
                &mut writer,
                flags,
                &session_key,
                &mut global_pool,
            )
            .await?;
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
                        network_time,
                        storage_path,
                        &session_key,
                        &client_key,
                        &mut global_pool,
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
                        &mut global_pool,
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
                    handle_download(
                        &mut reader,
                        &mut writer,
                        header,
                        network_time,
                        storage_path,
                        &session_key,
                        &client_key,
                        &mut global_pool,
                    )
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
                        &mut global_pool,
                    )
                    .await?;
                }
            }

            writer.flush().await?;
            Ok(())
        }
        Command::Status => {
            debug!("Received STATUS request");
            send_status(&mut writer, &session_key, &mut global_pool).await?;
            Ok(())
        }
    }
}

/// Read 4 bytes for frame length with timeout, return error on timeout or read failure
#[inline(always)]
async fn read_frame_length<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<u32> {
    const MAX_FRAME_LENGTH: u32 = 1024 * 1024 * 16;
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

/// Read encrypted command header, decrypt and deserialize, return Command enum, return error on timeout, read failure, decryption failure, or deserialization failure
#[inline(always)]
async fn read_headers<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    session_key: &[u8; 32],
    mem_pool: &mut Vec<u8>, // global pool
) -> Result<Command> {
    let decrypted_buf = read_encrypt_data_into(reader, session_key, mem_pool).await?;
    let command = Command::deserialize(decrypted_buf)?;

    Ok(command)
}

/// Read encrypted frame into global memory pool, decrypt in-place, return decrypted slice, return error on timeout, read failure, or decryption failure
#[inline(always)]
async fn read_encrypt_data_into<'a, R: AsyncReadExt + Unpin>(
    reader: &mut R,
    session_key: &[u8; 32],
    mem_pool: &'a mut Vec<u8>,
) -> Result<&'a [u8]> {
    let ciphertext_len = read_frame_length(reader).await? as usize;

    if ciphertext_len < NONCE_LEN + TAG_LEN {
        anyhow::bail!(
            "Frame length too short for encrypted header: {}",
            ciphertext_len
        );
    }
    let plaintext_len = ciphertext_len - NONCE_LEN - TAG_LEN;

    // should accommodate both encrypted & decrypted chunk
    if mem_pool.len() < ciphertext_len + plaintext_len {
        mem_pool.resize(ciphertext_len + plaintext_len, 0);
    }

    let (encrypted_chunk, decrypted_chunk) = mem_pool.split_at_mut(ciphertext_len);
    let encrypted_buf = &mut encrypted_chunk[..ciphertext_len];
    reader.read_exact(encrypted_buf).await?;

    let decrypted_buf = &mut decrypted_chunk[..plaintext_len];
    decrypt_into(encrypted_buf, decrypted_buf, session_key)?;

    Ok(decrypted_buf)
}

/// Write encrypted data with 4-byte length prefix, return error on write failure or encryption failure
#[inline(always)]
async fn write_encrypt_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
    session_key: &[u8; 32],
    mem_pool: &mut Vec<u8>,
) -> Result<()> {
    let plaintext_len = data.len();
    if plaintext_len > u32::MAX as usize {
        return Err(anyhow::anyhow!(
            "Too large content: {} bytes",
            plaintext_len
        ));
    }

    let ciphertext_len = NONCE_LEN + plaintext_len + TAG_LEN;
    let total_frame_len = 4 + ciphertext_len;

    // alloc if less
    if mem_pool.len() < total_frame_len {
        mem_pool.resize(total_frame_len, 0);
    }

    let len_bytes = (ciphertext_len as u32).to_be_bytes();
    mem_pool[..4].copy_from_slice(&len_bytes); // 4-byte prefix

    // encrypt that
    encrypt_into(data, &mut mem_pool[4..total_frame_len], session_key)?;
    writer.write_all(&mem_pool[..total_frame_len]).await?;
    writer.flush().await?;
    Ok(())
}

/// Read raw data in-place with timeout, return error on timeout or read failure, no decryption
#[inline(always)]
async fn read_raw_data_into<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    mem_buf: &mut Vec<u8>,
) -> Result<()> {
    let len = read_frame_length(reader).await? as usize;
    mem_buf.resize(len, 0); // zero-out the required space
    reader.read_exact(mem_buf).await?;
    Ok(())
}

/// Write a raw frame with 4-byte length prefix, return error on write failure, no encryption
#[inline(always)]
async fn write_raw_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    let len = data.len();
    if len > u32::MAX as usize {
        return Err(anyhow::anyhow!("Too large content: {} bytes", len));
    }
    let len_u32 = (len as u32).to_be_bytes();
    let mut buf = Vec::with_capacity(4 + len);
    buf.extend_from_slice(&len_u32);
    buf.extend_from_slice(data);
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

/// Send a generic serialized success response with code and message, then close the connection
#[inline]
async fn send_success<W: AsyncWriteExt + Unpin, T: Serialize>(
    writer: &mut W,
    response: &T,
    session_key: &[u8; 32],
    mem_pool: &mut Vec<u8>,
) -> Result<()> {
    let mut rsp = Vec::with_capacity(1 + 96);
    rsp.push(1u8); // 1 = success
    postcard::to_io(response, &mut rsp)
        .map_err(|e| anyhow::anyhow!("Failed to serialize success response: {}", e))?;
    timeout(
        WRITE_TIMEOUT,
        write_encrypt_frame(writer, &rsp, session_key, mem_pool),
    )
    .await??;
    writer.shutdown().await?; // Close connection after response
    Ok(())
}

/// Send a generic warning response with code and message, then close the connection
#[inline]
async fn send_warn<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: WarnHeader,
    session_key: &[u8; 32],
    mem_pool: &mut Vec<u8>,
) -> Result<()> {
    let payload_bytes = response.serialize()?;
    let mut rsp = Vec::with_capacity(1 + payload_bytes.len());
    rsp.push(2u8); // 2 = warning
    rsp.extend(payload_bytes);
    timeout(
        WRITE_TIMEOUT,
        write_encrypt_frame(writer, &rsp, session_key, mem_pool),
    )
    .await??;
    writer.shutdown().await?;
    Ok(())
}

/// Send an error response with code and message, then close the connection
#[inline]
async fn send_failed<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: ErrorHeader,
    session_key: &[u8; 32],
    mem_pool: &mut Vec<u8>,
) -> Result<()> {
    let payload_bytes = response.serialize()?;
    let mut rsp = Vec::with_capacity(1 + payload_bytes.len());
    rsp.push(3u8); // 3 = error
    rsp.extend(payload_bytes);
    timeout(
        WRITE_TIMEOUT,
        write_encrypt_frame(writer, &rsp, session_key, mem_pool),
    )
    .await??;
    writer.shutdown().await?;
    Ok(())
}

/// Send a status response with server info, then close the connection
#[inline]
async fn send_status<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    session_key: &[u8; 32],
    mem_pool: &mut Vec<u8>,
) -> Result<()> {
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

    timeout(
        WRITE_TIMEOUT,
        write_encrypt_frame(writer, &status, session_key, mem_pool),
    )
    .await??;
    writer.shutdown().await?;
    Ok(())
}

/// Perform the initial handshake with the client, exchange hellos and nonce challenge
/// returning session key (unsalted) and client ed22519 key
async fn server_handshake<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut R,
    writer: &mut W,
) -> Result<([u8; 32], [u8; 32])> {
    let (x25519_pri, x25519_pub) = generate_x25519_keypair()?;

    // read client_hello
    let client_hello = {
        let mut client_hello_data = vec![];
        read_raw_data_into(reader, &mut client_hello_data).await?;
        ClientHello::deserialize(&client_hello_data)?
    };

    // prepare server_hello
    let server_hello = {
        let mut nonce = [0u8; 32];
        rng().fill_bytes(&mut nonce);

        let ed22519_pri = SigningKey::from_bytes(&SERVER_PRI_KEY_BYTES);
        let ed22519_pub = VerifyingKey::from_bytes(&SERVER_PUB_KEY_BYTES)?;

        // construct data to be signed
        let mut data_signed = [9u8; 128];
        data_signed[0..32].copy_from_slice(&client_hello.nonce);
        data_signed[32..64].copy_from_slice(&nonce);
        data_signed[64..96].copy_from_slice(&client_hello.x22519_key);
        data_signed[96..128].copy_from_slice(&x25519_pub.to_bytes());

        let signature = ed22519_pri.sign_async(&data_signed).await?;

        ServerHello {
            ed25519_key: ed22519_pub.to_bytes(),
            x22519_key: x25519_pub.to_bytes(),
            signature: signature.to_bytes(),
            nonce,
        }
    };

    // send Hello to client
    timeout(
        WRITE_TIMEOUT,
        write_raw_frame(writer, &server_hello.serialize()?),
    )
    .await??;

    //--- client will auth check the server

    // send nonce
    let mut nonce = [0u8; 64];
    rng().fill_bytes(&mut nonce);
    nonce = Sha512::digest(nonce).into();
    write_raw_frame(writer, &nonce).await?;

    // explicit flush b4 only read
    writer.flush().await?;

    // TODO: key headers in auth are bloated, we can use this later

    // read signature & key both
    let mut packet = vec![0u8; 96];
    read_raw_data_into(reader, &mut packet).await?;

    let (signature, pub_key) = packet.split_at(64);

    let signature = Signature::from_slice(signature)
        .map_err(|e| anyhow::anyhow!("Failed to parse signature from client: {}", e))?;

    let verify_key = VerifyingKey::try_from(pub_key).map_err(|e| {
        anyhow::anyhow!(
            "Failed to construct client's Ed25519 public key from bytes: {}",
            e
        )
    })?;

    verify_key
        .verify_async(&nonce, &signature)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to verify client's signature: {}", e))?;

    let client_ephemeral = &PublicKey::from(client_hello.x22519_key);
    Ok((
        x25519_pri.diffie_hellman(client_ephemeral).to_bytes(),
        verify_key.to_bytes(),
    ))
}

/// Handle ECHO command: read encrypted payloads in a loop, respond with payload hash and server timestamp, until client sends quit command or disconnects
async fn handle_echo_debug<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut R,
    writer: &mut W,
    session_key: &[u8; 32],
    mem_pool: &mut Vec<u8>,
) -> Result<()> {
    loop {
        let server_timestamp = chrono::Utc::now().timestamp_millis();
        // read any payload
        let payload = match read_encrypt_data_into(reader, session_key, mem_pool).await {
            Ok(p) => p,
            Err(e) => {
                // eof is fine here
                if [
                    "eof",
                    "early eof",
                    "unexpected eof",
                    "forcibly closed",
                    "connection reset",
                    "closed by the remote",
                    "connection aborted",
                    "broken pipe",
                ]
                .iter()
                .any(|pattern| e.to_string().to_lowercase().contains(pattern))
                {
                    return Ok(());
                }
                return Err(e);
            }
        };

        match payload {
            b"" | b" " | b"q" | b"quit" | b"exit" => {
                return Ok(());
            }
            _ => {
                let echo = EchoDebugHeader {
                    payload_len: payload.len() as u32,
                    payload_hash: Sha256::digest(payload).into(),
                    timestamp_ms: server_timestamp,
                };

                timeout(
                    WRITE_TIMEOUT,
                    write_encrypt_frame(writer, &echo.serialize()?, session_key, mem_pool),
                )
                .await??;
            }
        }
    }
}

/// Handle key registration and rotation: send nonce challenge, verify signature, create/rename user directory, send ACK or error response
async fn handle_auth_keys<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut R,
    writer: &mut W,
    flag: u8,
    session_key: &[u8; 32],
    mem_pool: &mut Vec<u8>,
) -> Result<()> {
    // doing this again
    let mut nonce = [0u8; 32];
    rng().fill_bytes(&mut nonce);

    // this is cool
    for _ in 0..6 {
        nonce = Sha256::digest(nonce).into();
    }

    // send nonce challenge to client for signature verification, FIRST
    // hashing for good sake, 32 bytes nice
    timeout(
        WRITE_TIMEOUT,
        write_encrypt_frame(writer, &nonce, session_key, mem_pool),
    )
    .await??;

    // read key header and do the thing
    let header_bytes = read_encrypt_data_into(reader, session_key, mem_pool).await?;

    // New key
    if flag == 1 {
        let key_header = NewKeyHeader::deserialize(header_bytes)?;
        match key_header.validate(&nonce) {
            Ok(_) => {
                let pub_key =
                    VerifyingKey::from_bytes(&key_header.new_public_bytes).map_err(|e| {
                        anyhow::anyhow!("Failed to construct public key from bytes: {}", e)
                    })?;
                let pub_key_hex = encode(pub_key.to_bytes());

                // NOTE; auth path is sha256 fp of HEX KEY BYTES and user key path is auth key path itself
                // storage space is sha512 of client raw bytes NOT PEM NOT HEX, because auth part needed reproducibility
                let pub_key_hash256 = encode(Sha256::digest(pub_key_hex.as_bytes()));
                let user_key_path = get_authorized_client_dir().await?.join(&pub_key_hash256);

                info!(
                    "Auth attempt with new key: {}",
                    &pub_key_hash256[..16].dimmed()
                );

                // check if client is allowed (if ENABLE_CLIENT_WHITELIST, false)
                // and if auth key path is valid, but DON'T CREATE ANYTHING
                match (
                    *ENABLE_CLIENT_WHITELIST,
                    user_key_path.exists(),
                    user_key_path.is_dir(),
                ) {
                    (false, false, _) => {
                        warn!(
                            "Client with key: {} is not authorized, rejecting client storage space",
                            &pub_key_hash256
                        );
                        send_failed(
                            writer,
                            ErrorHeader {
                                code: 403,
                                message: "Client not authorized, please contact the admin, provider or ssh into the server"
                                    .to_string(),
                            },
                            session_key,
                            mem_pool,
                        ).await?;

                        return Ok(());
                    }

                    (_, true, false) => {
                        error!(
                            "Auth key must be a directory for key: {}, skipping user storage space creation",
                            &pub_key_hash256
                        );
                        send_failed(
                            writer,
                            ErrorHeader {
                                code: 500,
                                message: "Auth key path exists but is not a directory, skipping user storage dir creation".to_string(),
                            },
                            session_key,
                            mem_pool,
                        ).await?;

                        return Ok(());
                    }

                    _ => {}
                }

                // check or create user storage space or return
                let pub_key_hash512 = encode(Sha512::digest(pub_key.as_bytes()));
                let user_storage_dir = get_storage_dir().await?.join(&pub_key_hash512);
                if user_storage_dir.exists() && user_key_path.exists() {
                    send_warn(
                        writer,
                        WarnHeader {
                            code: 409,
                            message: "Client Auth & Storage directory already exists, not required"
                                .to_string(),
                        },
                        session_key,
                        mem_pool,
                    )
                    .await?;
                    return Ok(());
                }

                // auto white-list if ALLOW_CLIENT false & create auth user space dir OTHERWISE
                match (
                    tokio::fs::create_dir_all(&user_key_path).await,
                    tokio::fs::create_dir_all(&user_storage_dir).await,
                ) {
                    (Err(_), Err(_)) | (Err(_), Ok(_)) | (Ok(_), Err(_)) => {
                        error!(
                            "Failed to create auth key or user space for key: {}, returning back",
                            &pub_key_hash256[..32]
                        );
                        send_failed(
                            writer,
                            ErrorHeader {
                                code: 500,
                                message: "Failed to create auth key or user storage directory, try again later"
                                    .to_string(),
                            },
                            session_key,
                            mem_pool,
                        ).await?;
                        return Ok(());
                    }
                    _ => {}
                }
                timeout(
                    WRITE_TIMEOUT,
                    write_encrypt_frame(writer, &[0x1u8], session_key, mem_pool),
                )
                .await??; // ACK
            }
            Err(e) => {
                send_failed(
                    writer,
                    ErrorHeader {
                        code: 401,
                        message: format!("Invalid signature: {}", e),
                    },
                    session_key,
                    mem_pool,
                )
                .await?;
                return Ok(());
            }
        }
        // Rotate existing keys
    } else if flag == 2 {
        let key_header = RotateKeyHeader::deserialize(header_bytes)?;
        match key_header.validate(&nonce).await {
            Ok((old_user_path, old_pub_key_hash_bytes)) => {
                let new_pub_key =
                    VerifyingKey::from_bytes(&key_header.new_public_bytes).map_err(|e| {
                        anyhow::anyhow!("Failed to construct new public key from bytes: {}", e)
                    })?;
                let old_pub_key =
                    VerifyingKey::from_bytes(&key_header.old_public_bytes).map_err(|e| {
                        anyhow::anyhow!("Failed to construct old public key from bytes: {}", e)
                    })?;

                let new_pub_key_hex = encode(new_pub_key.to_bytes());
                let old_pub_key_hex = encode(old_pub_key.to_bytes());

                let new_pub_key_hash_hex = encode(Sha256::digest(new_pub_key_hex.as_bytes()));
                let old_pub_key_hash_hex = encode(Sha256::digest(old_pub_key_hex.as_bytes()));

                info!(
                    "Rotate key attempt: {} -> {}",
                    &new_pub_key_hash_hex.dimmed(),
                    &old_pub_key_hash_hex.dimmed()
                );

                let auth_keys_path = get_authorized_client_dir().await?;
                let new_user_path = get_storage_dir()
                    .await?
                    .join(encode(Sha512::digest(new_pub_key.as_bytes())));
                // hope this does not fail
                match (
                    // change key space HEX SHA256
                    tokio::fs::rename(
                        auth_keys_path.join(old_pub_key_hash_hex),
                        auth_keys_path.join(new_pub_key_hash_hex),
                    )
                    .await,
                    // change user space KEY_BYTES SHA512
                    tokio::fs::rename(&old_user_path, &new_user_path).await,
                ) {
                    (Err(_), Err(_)) | (Err(_), Ok(_)) | (Ok(_), Err(_)) => {
                        error!(
                            "Failed to rotate old keys for: {}, returning back",
                            &old_pub_key_hash_bytes
                        );
                        send_failed(
                            writer,
                            ErrorHeader {
                                code: 500,
                                message: "Failed to rotate keys, try again later".to_string(),
                            },
                            session_key,
                            mem_pool,
                        )
                        .await?;
                        return Ok(());
                    }
                    _ => {}
                }

                timeout(
                    WRITE_TIMEOUT,
                    write_encrypt_frame(writer, &[0x1u8], session_key, mem_pool),
                )
                .await??; // ACK
            }
            Err(e) => {
                send_failed(
                    writer,
                    ErrorHeader {
                        code: 401,
                        message: format!("Invalid signature: {}", e),
                    },
                    session_key,
                    mem_pool,
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
            mem_pool,
        )
        .await?;
        return Ok(());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
/// Handle file upload: read file data, validate hash and size, save to disk, update metadata, send response
async fn handle_upload<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut R,
    writer: &mut W,
    headers: UploadHeader,
    time_start: Instant,
    storage_path: &Path,
    session_key: &[u8; 32],
    client_key: &[u8; 32],
    mem_pool: &mut Vec<u8>,
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
                mem_pool,
            )
            .await?;
            return Ok(());
        }
    };

    let client_key_hash = encode(Sha512::digest(client_key));
    let file_id_hash = encode(Sha256::digest(headers.file_id.as_bytes()));
    let file_key_hash = encode(Sha256::digest(headers.file_key.as_bytes()));

    // ~/<base_dir>/client_key_hash/file_key_hash/file_id_hash

    let user_dir_path = storage_path.join(&client_key_hash).join(&file_key_hash);
    let file_path = user_dir_path.join(format!("{}.file", &file_id_hash));
    let metadata_path = user_dir_path.join(format!("{}.meta", &file_id_hash));

    tokio::fs::create_dir_all(&user_dir_path).await?;

    info!(
        "Start Uploading: {} ({} bytes) - Hash: {}...",
        headers.file_id.dimmed(),
        headers.file_size,
        headers.file_hash[..8].dimmed()
    );

    // Send ACK before streaming starts
    timeout(
        WRITE_TIMEOUT,
        write_encrypt_frame(writer, &[0x1u8], session_key, mem_pool),
    )
    .await??;

    let network_elapsed = time_start.elapsed().as_secs_f32();

    let file = File::create(&file_path).await?;
    let mut buf_file = BufWriter::with_capacity(READ_CHUNK_SIZE * 2, file);
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut enc_buf = vec![0u8; READ_CHUNK_SIZE + NONCE_LEN + TAG_LEN];
    let mut dec_buf = vec![0u8; READ_CHUNK_SIZE];

    // TODO; client is send already double encrypted chunk,
    //  so HERE decrypt is network layer
    {
        while received < headers.file_size {
            let plain_text = min(READ_CHUNK_SIZE, (headers.file_size - received) as usize);
            let cipher_text = NONCE_LEN + plain_text + TAG_LEN;
            reader.read_exact(&mut enc_buf[..cipher_text]).await?;
            // decrypt file chunks
            let dec_len = decrypt_into(&enc_buf[..cipher_text], &mut dec_buf, session_key)?;
            hasher.update(&dec_buf[..dec_len]);
            buf_file.write_all(&dec_buf[..dec_len]).await?;
            received += dec_len as u64;
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
            mem_pool,
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

    info!(
        "Upload complete: File-Id: {} Network_time: {}sec",
        &headers.file_id.dimmed(),
        network_elapsed
    );
    send_success(
        writer,
        &UploadResponse {
            file_id: headers.file_id,
            network_time: network_elapsed,
        },
        session_key,
        mem_pool,
    )
    .await?;

    drop(guard);
    release_file_lock(&file_id);

    Tracker::log_upload(headers.file_size as usize).await;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
/// Handle file download: validate request, read file and metadata, send file data with headers, update stats
async fn handle_download<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    #[allow(unused)] reader: &mut R,
    writer: &mut W,
    headers: DownloadHeader,
    time_start: Instant,
    storage_path: &Path,
    session_key: &[u8; 32],
    client_key: &[u8; 32],
    mem_pool: &mut Vec<u8>,
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
                mem_pool,
            )
            .await?;
            return Ok(());
        }
    };

    let client_key_hash = encode(Sha512::digest(client_key));
    let file_key_hash = encode(Sha256::digest(headers.file_key.as_bytes()));
    let file_id_hash = encode(Sha256::digest(headers.file_id.as_bytes()));

    // ~/<base_dir>/client_key_hash/file_key_hash/file_id_hash

    let user_dir_path = storage_path.join(&client_key_hash).join(&file_key_hash);

    // this line SAVE US A LOT OF IO!!!!
    if !tokio::fs::try_exists(&user_dir_path).await? {
        send_failed(
            writer,
            ErrorHeader {
                code: 404,
                message: "File not found".to_string(),
            },
            session_key,
            mem_pool,
        )
        .await?;
        return Ok(());
    }

    let file_path = user_dir_path.join(format!("{}.file", &file_id_hash));
    let meta_path = user_dir_path.join(format!("{}.meta", &file_id_hash));

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
            mem_pool,
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
                mem_pool,
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

    let network_elapsed = time_start.elapsed().as_secs_f32();
    let header = DownloadResponse {
        file_name,
        file_size,
        file_hash,
        network_time: network_elapsed,
    }
    .serialize()?;

    // ACK before streaming
    let mut rsp = Vec::with_capacity(1 + header.len());
    rsp.push(1u8); // 1 = success;
    rsp.extend(header);
    timeout(
        WRITE_TIMEOUT,
        write_encrypt_frame(writer, &rsp, session_key, mem_pool),
    )
    .await??; // connection should be kept alive

    let file = File::open(&file_path).await?;
    let mut buf_file = BufReader::with_capacity(READ_CHUNK_SIZE * 2, file);
    let mut plan_buf = vec![0u8; READ_CHUNK_SIZE];
    let mut enc_buf = vec![0u8; READ_CHUNK_SIZE + NONCE_LEN + TAG_LEN];

    loop {
        let n = buf_file.read(&mut plan_buf).await?;
        if n == 0 {
            break;
        }
        // encrypt file chunks
        let enc_len = encrypt_into(&plan_buf[..n], &mut enc_buf, session_key)?;
        writer.write_all(&enc_buf[..enc_len]).await?;
    }

    writer.flush().await?;
    writer.shutdown().await?;

    info!(
        "Download complete: File-Id: {}, Network_time: {}",
        &headers.file_id.dimmed(),
        network_elapsed
    );

    drop(guard);
    release_file_lock(&file_id);

    Tracker::log_download(file_size as usize).await;

    Ok(())
}

/// Perform client-side handshake: connect to server, exchange hellos, verify server key, do nonce challenge,
/// return session key and tcp stream for forward handlers
async fn client_handshake_helper(
    host: &str,
    port: u16,
    signing_key: &SigningKey,
) -> Result<([u8; 32], TcpStream)> {
    let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    stream.set_nodelay(true).ok();

    let server_ip = stream
        .peer_addr()
        .map_err(|e| anyhow::anyhow!("Failed to get server IP: {}", e))?;

    let (reader, writer) = stream.split();
    let mut reader = BufReader::with_capacity(NETWORK_READ_BUFFER, reader);
    let mut writer = BufWriter::with_capacity(NETWORK_WRITE_BUFFER, writer);

    let (x25519_pri, x25519_pub) = generate_x25519_keypair()?;

    // construct client_hello
    let client_hello = {
        let mut nonce = [0u8; 32];
        rng().fill_bytes(&mut nonce);
        ClientHello {
            x22519_key: x25519_pub.to_bytes(),
            nonce,
        }
    };

    // send client Hello first
    write_raw_frame(&mut writer, &client_hello.serialize()?).await?; // send client hello

    // read server Hello
    let server_hello = {
        let mut server_hello_data = vec![];
        read_raw_data_into(&mut reader, &mut server_hello_data).await?; // read server hello
        ServerHello::deserialize(&server_hello_data)?
    };

    // we check server_map, proceed with caller handler or reject
    let mut authorized_server =
        AuthServerMap::read_or_create(&get_authorized_server_map_path()?).await?;

    let server_key = VerifyingKey::from_bytes(&server_hello.ed25519_key)?;
    let server_key_hex = encode(server_hello.ed25519_key);
    let server_key_fp = encode(Sha256::digest(server_key_hex.as_bytes()));

    // determine trusted key
    let trusted_key = if let Some(existing_server_key_hex) =
        authorized_server.server_map.get(&server_ip)
    {
        if existing_server_key_hex != &server_key_hex {
            println!("WARNING: Server key changed for {}", server_ip);
            println!(
                "Before FP: {}",
                encode(Sha256::digest(existing_server_key_hex.as_bytes()))
            );
            println!("After FP: {}", server_key_fp);
            print!("Trust new key? [y/N]: ");

            io::Write::flush(&mut io::stdout())?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if !input.trim().eq_ignore_ascii_case("y") {
                stream.shutdown().await?; // instant close, server gets graceful EOF
                drop(stream);
                anyhow::bail!("User rejected rotated server key");
            }

            // replace & save stored key
            authorized_server
                .server_map
                .insert(server_ip, server_key_fp);
            authorized_server
                .write(&get_authorized_server_map_path()?)
                .await?;

            server_key
        } else {
            // use already trusted stored key
            let key_bytes: [u8; 32] = decode(existing_server_key_hex)?.try_into().map_err(|e| {
                anyhow::anyhow!("Failed to decode existing server 32bytes key: {:?}", e)
            })?;
            VerifyingKey::from_bytes(&key_bytes)?
        }
    } else {
        println!("Unknown Server IP: {}", server_ip);
        println!("Server key FP: {}", server_key_fp);
        print!("Trust this server? [y/N]: ");

        io::Write::flush(&mut io::stdout())?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            stream.shutdown().await?; // instant close, server gets graceful EOF
            drop(stream);
            anyhow::bail!("User rejected unknown server");
        }

        // insert & save
        authorized_server
            .server_map
            .insert(server_ip, server_key_hex);
        authorized_server
            .write(&get_authorized_server_map_path()?)
            .await?;

        server_key
    };

    // construct signed payload SAME AS SERVER
    let mut data_signed = [9u8; 128];
    data_signed[0..32].copy_from_slice(&client_hello.nonce);
    data_signed[32..64].copy_from_slice(&server_hello.nonce);
    data_signed[64..96].copy_from_slice(&x25519_pub.to_bytes());
    data_signed[96..128].copy_from_slice(&server_hello.x22519_key);

    // verify signature
    let signature = Signature::from_bytes(&server_hello.signature);

    trusted_key
        .verify_async(&data_signed, &signature)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to verify server's signature: {}", e))?;

    // do nonce challenge here, saves us from doing per header handlers
    let mut nonce = vec![0u8; 64];
    read_raw_data_into(&mut reader, &mut nonce).await?; // read nonce challenge

    let signature: [u8; 64] = signing_key.sign_async(&nonce).await?.to_bytes();
    let pub_key = signing_key.verifying_key().to_bytes();

    // format [64][32]
    let mut packet = [0u8; 96];
    packet[0..64].copy_from_slice(&signature);
    packet[64..96].copy_from_slice(&pub_key);
    write_raw_frame(&mut writer, &packet).await?; // send signature and pubkey

    // explicit flush
    writer.flush().await?;

    let session_key = {
        let shared_key = x25519_pri
            .diffie_hellman(&PublicKey::from(server_hello.x22519_key))
            .to_bytes();
        // same as server
        let mut key = [1u8; 128];
        key[0..32].copy_from_slice(&shared_key);
        key[64..96].copy_from_slice(&shared_key);
        Sha256::digest(key).into()
    };

    Ok((session_key, stream))
}

// TODO; add args to cli
/// Client function to perform echo debug: connect to server, do handshake, send echo command, then continuously send random payloads and print server response with RTT and timestamp gap
pub async fn client_echo_debug(
    host: &str,
    port: u16,
    signing_key: SigningKey,
    mem_pool: &mut Vec<u8>,
) -> Result<()> {
    let (session_key, mut stream) = client_handshake_helper(host, port, &signing_key)
        .await
        .map_err(|e| anyhow::anyhow!("Handshake failed: {}", e))?;

    let (reader, writer) = stream.split();
    let mut reader = BufReader::with_capacity(NETWORK_READ_BUFFER, reader);
    let mut writer = BufWriter::with_capacity(NETWORK_WRITE_BUFFER, writer);

    let mut thread_rng = rng();
    let dur = Duration::from_secs(1);

    let request = Command::Echo.serialize()?;
    write_encrypt_frame(&mut writer, &request, &session_key, mem_pool).await?;

    //TODO; read any err or rej

    println!("Session Key: {}", encode(session_key).green());

    let mut rand_payload_buf = vec![0u8; 1024 * 1024];
    loop {
        // randomize
        let rand_len = rng().random_range(1024 * 1024..=14 * 1024 * 1024);
        rand_payload_buf.resize(rand_len, 0);
        thread_rng.fill_bytes(&mut rand_payload_buf);

        let compute_payload_hash = encode(Sha256::digest(&rand_payload_buf));

        let send_time = Instant::now();
        write_encrypt_frame(&mut writer, &rand_payload_buf, &session_key, mem_pool)
            .await
            .context("Failed to send echo payload")?;

        let response = read_encrypt_data_into(&mut reader, &session_key, mem_pool)
            .await
            .context("Failed to read echo response")?;

        let echo = EchoDebugHeader::deserialize(response)?;
        let rtt = send_time.elapsed();
        let client_timestamp = chrono::Utc::now().timestamp_millis();

        if compute_payload_hash != encode(echo.payload_hash) {
            eprintln!(
                "Payload hash mismatch! Sent: {}, Received: {}",
                compute_payload_hash,
                encode(echo.payload_hash)
            );
        }

        println!("---------------------------");
        println!("Payload Size:      {} bytes", echo.payload_len);
        println!("Payload SHA256:    {}", encode(echo.payload_hash));
        println!(
            "Timestamp Gap:          {} ms",
            client_timestamp - echo.timestamp_ms
        );
        println!("Total Round-Trip:  {:?}", rtt);

        mem_pool.clear();
        tokio::time::sleep(dur).await;
    }
}

// TODO: Too many repetitive lazy code, very poor thinking, refactor later

/// Client function to register a new public key or rotate existing keys: connect to server, perform nonce challenge, sign nonce, send key info, handle ACK or error response
pub async fn auth_client(
    private_key: SigningKey,
    public_key: VerifyingKey,
    old_public_key: Option<VerifyingKey>,
    host: &str,
    port: u16,
    mem_pool: &mut Vec<u8>,
) -> Result<()> {
    let (session_key, mut stream) = client_handshake_helper(host, port, &private_key)
        .await
        .map_err(|e| anyhow::anyhow!("Handshake failed: {}", e))?;
    let (reader, writer) = stream.split();
    let mut reader = BufReader::with_capacity(NETWORK_READ_BUFFER, reader);
    let mut writer = BufWriter::with_capacity(NETWORK_WRITE_BUFFER, writer);

    // send auth header request
    let auth_request = Command::Auth(if old_public_key.is_some() { 2 } else { 1 }).serialize()?;
    write_encrypt_frame(&mut writer, &auth_request, &session_key, mem_pool).await?;

    let nonce = read_encrypt_data_into(&mut reader, &session_key, mem_pool).await?;

    //TODO: we may add some random bullshit to nonce
    let signature = private_key.sign(nonce);
    let header_bytes = match old_public_key {
        Some(old_verifying_key) => {
            let header = RotateKeyHeader {
                signature: signature.to_bytes(),
                old_public_bytes: old_verifying_key.to_bytes(),
                new_public_bytes: public_key.to_bytes(),
            };
            header.serialize()?
        }
        None => {
            let header = NewKeyHeader {
                signature: signature.to_bytes(),
                new_public_bytes: public_key.to_bytes(),
            };
            header.serialize()?
        }
    };

    // send key header
    write_encrypt_frame(&mut writer, &header_bytes, &session_key, mem_pool).await?;

    // read ack or rej
    let rsp = read_encrypt_data_into(&mut reader, &session_key, mem_pool).await?;

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
    mem_pool: &mut Vec<u8>,
) -> Result<String> {
    let file_name = file_path
        .file_name()
        .context("Invalid file path")?
        .to_string_lossy()
        .to_string();

    let metadata = tokio::fs::metadata(&file_path).await?;
    let file_size = metadata.len();

    // do handshake
    let (session_key, mut stream) = client_handshake_helper(host, port, &signing_key)
        .await
        .map_err(|e| anyhow::anyhow!("Handshake failed: {}", e))?;
    let (reader, writer) = stream.split();
    let mut reader = BufReader::with_capacity(NETWORK_READ_BUFFER, reader);
    let mut writer = BufWriter::with_capacity(NETWORK_WRITE_BUFFER, writer);

    println!(
        "Starting upload: {} ({} mb)",
        file_name,
        file_size as f32 / (1024.0 * 1024.0)
    );

    let file_hash = file_hasher_async(&file_path)
        .await
        .context("Failed to compute file hash")?;
    println!("File hash: {}", file_hash.dimmed());

    let pg_bar = ProgressBar::new(file_size);
    pg_bar.set_style(
        ProgressStyle::default_bar()
            .template("↪ [{bar:60.blue/cyan}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
            .progress_chars("▨◻-"),
    );

    let request = Command::Upload(UploadHeader {
        file_id: file_id.to_string(),
        file_name,
        file_size,
        file_hash,
        file_key,
    })
    .serialize()?;

    write_encrypt_frame(&mut writer, &request, &session_key, mem_pool) // send header request
        .await
        .context("Failed to send upload header request")?;

    let response = read_encrypt_data_into(&mut reader, &session_key, mem_pool)
        .await
        .context("Failed to read upload header response")?;

    // Reading flags early ACK
    if response[0] == 0x3u8 {
        let err = ErrorHeader::deserialize(&response[1..])?;
        anyhow::bail!("Upload failed: {} - {}", err.code, err.message);
    } else if response[0] == 0x2u8 {
        let warn = WarnHeader::deserialize(&response[1..])?;
        println!("Upload warning: {} - {}", warn.code, warn.message);
    }

    let file = File::open(&file_path).await?;
    let mut buf_file = BufReader::with_capacity(READ_CHUNK_SIZE * 2, file);
    let mut plan_buf = vec![0u8; READ_CHUNK_SIZE];
    let mut enc_buf = vec![0u8; READ_CHUNK_SIZE + NONCE_LEN + TAG_LEN];

    // TODO; encrypt locally with file-key BUT WHAT ABOUT HASH CHECK?

    loop {
        let n = buf_file
            .read(&mut plan_buf)
            .await
            .context("Failed to read file data")?;
        if n == 0 {
            break;
        }

        // encrypt file chunks
        let enc_len = encrypt_into(&plan_buf[..n], &mut enc_buf, &session_key)?;
        writer
            // send only encrypted part
            .write_all(&enc_buf[..enc_len])
            .await
            .context("Failed to send file data")?;
        pg_bar.inc(n as u64);
    }

    pg_bar.finish_and_clear();
    writer.flush().await.context("Failed to flush")?;

    let response = read_encrypt_data_into(&mut reader, &session_key, mem_pool).await?;
    if response[0] == 0x3u8 {
        let err = ErrorHeader::deserialize(&response[1..])?;
        anyhow::bail!("Upload failed: {} - {}", err.code, err.message);
    } else if response[0] == 0x2u8 {
        let warn = WarnHeader::deserialize(&response[1..])?;
        println!("Upload warning: {} - {}", warn.code, warn.message);
    } else if response[0] != 0x1u8 {
        anyhow::bail!("Unknown header byte: {}", response[0]);
    }
    let rsp = UploadResponse::deserialize(&response[1..])?;

    stream.shutdown().await?;

    println!(
        "File ID: {} - Network took: {}",
        rsp.file_id, rsp.network_time
    );

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
    signing_key: SigningKey,
    mem_pool: &mut Vec<u8>,
) -> Result<PathBuf> {
    let (session_key, mut stream) = client_handshake_helper(host, port, &signing_key)
        .await
        .map_err(|e| anyhow::anyhow!("Handshake failed: {}", e))?;
    let (reader, writer) = stream.split();
    let mut reader = BufReader::with_capacity(NETWORK_READ_BUFFER, reader);
    let mut writer = BufWriter::with_capacity(NETWORK_WRITE_BUFFER, writer);

    let request = Command::Download(DownloadHeader {
        file_id: file_id.to_string(),
        file_key,
    })
    .serialize()?;

    write_encrypt_frame(&mut writer, &request, &session_key, mem_pool)
        .await
        .context("Failed to send download header request")?;

    let header_bytes = read_encrypt_data_into(&mut reader, &session_key, mem_pool)
        .await
        .context("Failed to read download header response")?;

    // Reading early flags
    if header_bytes[0] == 0x3u8 {
        let err = ErrorHeader::deserialize(&header_bytes[1..])?;
        anyhow::bail!("Download failed: {} - {}", err.code, err.message);
    } else if header_bytes[0] == 0x2u8 {
        let warn = WarnHeader::deserialize(&header_bytes[1..])?;
        println!("Download warning: {} - {}", warn.code, warn.message);
    } else if header_bytes[0] != 0x1u8 {
        anyhow::bail!("Unknown header byte: {}", header_bytes[0]);
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
    let mut enc_buf = vec![0u8; READ_CHUNK_SIZE + NONCE_LEN + TAG_LEN];
    let mut dec_buf = vec![0u8; READ_CHUNK_SIZE];

    while received < response.file_size {
        let plain_text = min(READ_CHUNK_SIZE, (response.file_size - received) as usize);
        let cipher_text = NONCE_LEN + plain_text + TAG_LEN;
        let n = reader
            .read_exact(&mut enc_buf[..cipher_text])
            .await
            .context("Failed to read file data")?;
        // decrypt file chunks
        let dec_len = decrypt_into(&enc_buf[..cipher_text], &mut dec_buf, &session_key)?;
        hasher.update(&dec_buf[..dec_len]);
        buf_file.write_all(&dec_buf[..dec_len]).await?;
        received += dec_len as u64;
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

    println!(
        "Saved to: {} - Network_time: {}",
        output_path.display(),
        &response.network_time
    );
    Ok(output_path)
}

/// Client function to get server status: connect to server, send status request, read and return status response, handle errors
pub async fn get_server_status(
    host: &str,
    port: u16,
    signing_key: SigningKey,
    mem_pool: &mut Vec<u8>,
) -> Result<StatusHeader> {
    let (session_key, mut stream) = client_handshake_helper(host, port, &signing_key)
        .await
        .map_err(|e| anyhow::anyhow!("Handshake failed: {}", e))?;
    let (reader, writer) = stream.split();
    let mut reader = BufReader::with_capacity(NETWORK_READ_BUFFER, reader);
    let mut writer = BufWriter::with_capacity(NETWORK_WRITE_BUFFER, writer);

    let request = Command::Status.serialize()?;
    write_encrypt_frame(&mut writer, &request, &session_key, mem_pool).await?;

    let response = read_encrypt_data_into(&mut reader, &session_key, mem_pool)
        .await
        .context("Failed to read status response")?;

    let response = StatusHeader::deserialize(response)?;

    stream.shutdown().await.ok();

    Ok(response)
}
