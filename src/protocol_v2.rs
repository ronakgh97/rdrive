use crate::{Metadata, error, get_storage_path_blocking, info};
use anyhow::Context;
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Instant;
use std::{fs, io};
use uuid::Uuid;

pub fn start_raw_tcp_server(port: u16) -> Result<()> {
    use std::net::TcpListener;

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;
    info!("Raw TCP server listening on 0.0.0.0:{}", port);

    for stream in listener.incoming() {
        match stream {
            Ok(mut socket) => {
                info!("New connection from {:?}", socket.peer_addr());
                if let Err(e) = handle_raw_connection(&mut socket) {
                    error!("Error handling connection: {}", e);
                }
            }
            Err(e) => {
                error!("Connection failed: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_raw_connection(socket: &mut TcpStream) -> Result<()> {
    let time_start = Instant::now();

    // Read command line
    let mut command_line = String::new();
    loop {
        let mut buf = [0u8; 1];
        let n = socket.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        if buf[0] == b'\n' {
            break;
        }
        command_line.push(buf[0] as char);
    }
    let command = command_line.trim().to_string();
    info!("Command: {}", command);

    // Read headers until empty line
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        loop {
            let mut buf = [0u8; 1];
            let n = socket.read(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            if buf[0] == b'\n' {
                break;
            }
            line.push(buf[0] as char);
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        // Parse header line: key: value and stored them in hashmap
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.insert(key, value);
        }
    }

    match command.as_str() {
        "UPLOAD" => {
            handle_raw_upload(socket, &headers, time_start)?;
        }
        "DOWNLOAD" => {
            handle_raw_download(socket, &headers)?;
        }
        _ => {
            send_error(socket, 400, "Unknown command")?;
        }
    }

    Ok(())
}

#[inline]
fn send_error(socket: &mut TcpStream, code: u16, message: &str) -> Result<()> {
    let response = format!("ERROR\ncode: {}\nmessage: {}\n\n", code, message);
    socket.write_all(response.as_bytes())?;
    socket.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}

#[inline]
fn send_ok_upload(socket: &mut TcpStream, file_id: &str, time_took: f64) -> Result<()> {
    let response = format!("OK\nfile-id: {}\ntime-took: {}\n\n", file_id, time_took);
    socket.write_all(response.as_bytes())?;
    socket.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}

fn handle_raw_upload(
    socket: &mut TcpStream,
    headers: &HashMap<String, String>,
    time_start: Instant,
) -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::{Read, Write};

    let filename = headers
        .get("file-name")
        .ok_or_else(|| anyhow::anyhow!("Missing file-name header"))?;
    let file_size: u64 = headers
        .get("file-size")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid file-size header"))?;
    let file_hash_expected = headers
        .get("file-hash")
        .ok_or_else(|| anyhow::anyhow!("Missing file-hash header"))?;
    let file_key = headers
        .get("file-key")
        .ok_or_else(|| anyhow::anyhow!("Missing file-key header"))?;

    let file_id = Uuid::new_v4().to_string();
    let sanitized_id = file_id
        .replace("-", "_")
        .replace("/", "_")
        .replace(".", "_")
        .replace("\\", "_");

    let storage_path = get_storage_path_blocking()?;
    let file_path = storage_path.join(&sanitized_id);

    info!(
        "Uploading: {} ({} bytes) - file_id: {}",
        filename, file_size, file_id
    );

    // Create file and read data
    let mut file = fs::File::create(&file_path)?;
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];

    while received < file_size {
        let to_read = std::cmp::min(buf.len(), (file_size - received) as usize);
        let n = socket.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n])?;
        received += n as u64;
    }

    file.flush()?;

    if received != file_size {
        fs::remove_file(&file_path)?;
        send_error(socket, 400, "File size mismatch")?;
        return Ok(());
    }

    let computed_hash = format!("{:x}", hasher.finalize());
    if computed_hash != *file_hash_expected {
        fs::remove_file(&file_path)?;
        send_error(socket, 400, "Hash mismatch")?;
        return Ok(());
    }

    // Save metadata
    let metadata = Metadata {
        filename: filename.clone(),
        file_size,
        file_hash: computed_hash.clone(),
        file_key: file_key.clone(),
    };

    let meta_path = storage_path.join(format!("{}.meta", sanitized_id));
    fs::write(&meta_path, serde_json::to_vec(&metadata)?)?;

    let time_took = time_start.elapsed().as_secs_f64();
    send_ok_upload(socket, &file_id, time_took)?;

    info!(
        "Upload complete: file-id: {} - file-hash: {}",
        file_id,
        computed_hash.dimmed()
    );
    Ok(())
}

fn handle_raw_download(socket: &mut TcpStream, headers: &HashMap<String, String>) -> Result<()> {
    let file_id = headers
        .get("file-id")
        .ok_or_else(|| anyhow::anyhow!("Missing file-id header"))?;
    let _file_key = headers
        .get("file-key")
        .ok_or_else(|| anyhow::anyhow!("Missing file-key header"))?;

    let sanitized_id = file_id
        .replace("-", "_")
        .replace("/", "_")
        .replace(".", "_")
        .replace("\\", "_");

    let storage_path = get_storage_path_blocking()?;
    let meta_path = storage_path.join(format!("{}.meta", sanitized_id));
    let file_path = storage_path.join(&sanitized_id);

    let meta_content = fs::read_to_string(&meta_path)?;
    let metadata: serde_json::Value = serde_json::from_str(&meta_content)?;

    let filename = metadata["filename"].as_str().unwrap_or("file");
    let file_size = metadata["file_size"].as_u64().unwrap_or(0);
    let file_hash = metadata["file_hash"].as_str().unwrap_or("");

    info!(
        "Downloading: {} ({} bytes) - file_id: {}",
        filename, file_size, file_id
    );

    // Send headers
    let header = format!(
        "file-name: {}\nfile-size: {}\nfile-hash: {}\n\n",
        filename, file_size, file_hash
    );
    socket.write_all(header.as_bytes())?;

    // Stream file
    let mut file = fs::File::open(&file_path)?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        socket.write_all(&buf[..n])?;
    }

    socket.shutdown(std::net::Shutdown::Write)?;

    info!("Download complete: {}", file_id);
    Ok(())
}

pub async fn upload_file_raw(file_path: PathBuf, port: u16) -> Result<String> {
    let filename = file_path
        .file_name()
        .context("Invalid file path")?
        .to_string_lossy()
        .to_string();

    let metadata = fs::metadata(&file_path).context("Failed to read file metadata")?;
    let file_size = metadata.len();

    // Compute hash using std::io (sync)
    let mut file = fs::File::open(&file_path).context("Failed to open file")?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 32 * 1024];

    loop {
        let n = file.read(&mut buf).context("Failed to read file")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    print!("Enter file key: ");
    Write::flush(&mut io::stdout())?;
    let mut file_key = String::new();
    io::stdin().read_line(&mut file_key)?;
    let file_key = file_key.trim().to_string();

    let file_hash = format!("{:x}", hasher.finalize());
    println!("Computed hash: {}", file_hash);

    // Connect to server
    let mut stream =
        TcpStream::connect(format!("localhost:{}", port)).context("Failed to connect to server")?;

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();

    // Send UPLOAD request
    let request = format!(
        "UPLOAD\nfile-name: {}\nfile-size: {}\nfile-hash: {}\nfile-key: {}\n\n",
        filename, file_size, file_hash, file_key
    );
    stream
        .write_all(request.as_bytes())
        .context("Failed to send request")?;

    // Stream file content
    let mut file = fs::File::open(&file_path).context("Failed to reopen file")?;

    loop {
        let n = file.read(&mut buf).context("Failed to read file")?;
        if n == 0 {
            break;
        }
        stream
            .write_all(&buf[..n])
            .context("Failed to send file data")?;
    }

    // Read response
    let mut response = String::new();
    let mut prev_char = b'\0';
    let mut buf = [0u8; 1];

    while let Ok(1) = stream.read(&mut buf) {
        response.push(buf[0] as char);
        if prev_char == b'\n' && buf[0] == b'\n' {
            break;
        }
        prev_char = buf[0];
    }

    if !response.starts_with("OK\n") {
        anyhow::bail!("Upload failed: {}", response);
    }

    // Parse file-id and time-took
    let mut file_id = String::new();
    let mut time_took = String::new();

    for line in response.lines() {
        if let Some(id) = line.strip_prefix("file-id: ") {
            file_id = id.trim().to_string();
        }
        if let Some(time) = line.strip_prefix("time-took: ") {
            time_took = time.trim().to_string();
        }
    }

    println!(
        "Upload successful! File ID: {} (took: {}s)",
        file_id, time_took
    );
    Ok(file_id)
}

pub async fn download_file_raw(
    file_id: String,
    file_key: String,
    output_path: Option<PathBuf>,
    port: u16,
) -> Result<PathBuf> {
    // Connect to server
    let mut stream =
        TcpStream::connect(format!("localhost:{}", port)).context("Failed to connect to server")?;

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();

    // Send DOWNLOAD request
    let request = format!("DOWNLOAD\nfile-id: {}\nfile-key: {}\n\n", file_id, file_key);
    stream
        .write_all(request.as_bytes())
        .context("Failed to send request")?;

    // Read headers until \n\n
    let mut headers = String::new();
    let mut prev_char = b'\0';
    let mut buf = [0u8; 1];

    while let Ok(1) = stream.read(&mut buf) {
        headers.push(buf[0] as char);
        if prev_char == b'\n' && buf[0] == b'\n' {
            break;
        }
        prev_char = buf[0];
    }

    // Check for ERROR
    if headers.starts_with("ERROR") {
        anyhow::bail!("Download failed: {}", headers);
    }

    // Parse headers
    let mut filename = file_id.clone();
    let mut file_size: u64 = 0;
    let mut _file_hash = String::new();

    for line in headers.lines() {
        if let Some(name) = line.strip_prefix("file-name: ") {
            filename = name.trim().to_string();
        }
        if let Some(size) = line.strip_prefix("file-size: ") {
            file_size = size.trim().parse().unwrap_or(0);
        }
        if let Some(hash) = line.strip_prefix("file-hash: ") {
            _file_hash = hash.trim().to_string();
        }
    }

    println!("Downloading: {} ({} bytes)", filename, file_size);

    // Read file content
    let output = output_path
        .unwrap_or_else(|| PathBuf::from("."))
        .join(&filename);

    let mut output_file = fs::File::create(&output).context("Failed to create output file")?;

    let mut received: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];

    while received < file_size {
        let to_read = std::cmp::min(buf.len(), (file_size - received) as usize);
        let n = stream
            .read(&mut buf[..to_read])
            .context("Failed to read file data")?;
        if n == 0 {
            break;
        }
        output_file
            .write_all(&buf[..n])
            .context("Failed to write file")?;
        received += n as u64;
    }

    output_file.flush().context("Failed to flush file")?;

    // TODO: Validate hash

    println!("Download successful! Saved to: {}", output.display());
    Ok(output)
}
