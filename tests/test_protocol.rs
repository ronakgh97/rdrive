use r_storage::get_storage_path_blocking;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

// Pick a free port, help me kernel!!
fn free_port() -> u16 {
    use std::net::TcpListener;
    let bind = TcpListener::bind("127.0.0.1:0").unwrap();
    bind.local_addr().unwrap().port()
}

fn start_server(port: u16) {
    thread::spawn(move || {
        r_storage::protocol_v2::start_tcp_server(port).unwrap();
    });

    std::fs::create_dir_all(get_storage_path_blocking().unwrap()).unwrap();

    thread::sleep(Duration::from_millis(100));
}

/// Send a complete UPLOAD request and return the file-id
fn client_upload(port: u16, data: &[u8], filename: &str, file_key: &str) -> String {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

    let mut hasher = Sha256::new();
    hasher.update(data);
    let file_hash = format!("{:x}", hasher.finalize());

    let request = format!(
        "UPLOAD\nfile-name: {}\nfile-size: {}\nfile-hash: {}\nfile-key: {}\n\n",
        filename,
        data.len(),
        file_hash,
        file_key
    );
    stream.write_all(request.as_bytes()).unwrap();
    stream.write_all(data).unwrap();
    stream.flush().unwrap();

    // Read response until \n\n
    let mut response = String::new();
    let mut prev = b'\0';
    let mut buf = [0u8; 1];
    while let Ok(1) = stream.read(&mut buf) {
        response.push(buf[0] as char);
        if prev == b'\n' && buf[0] == b'\n' {
            break;
        }
        prev = buf[0];
    }

    assert!(response.starts_with("OK\n"), "Upload failed: {}", response);

    response
        .lines()
        .find_map(|l| l.strip_prefix("file-id: ").map(|s| s.trim().to_string()))
        .expect("No file-id in upload response")
}

/// Send a DOWNLOAD request and return the raw file bytes
fn client_download(port: u16, file_id: &str, file_key: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

    let request = format!("DOWNLOAD\nfile-id: {}\nfile-key: {}\n\n", file_id, file_key);
    stream.write_all(request.as_bytes()).unwrap();

    // Read headers until \n\n
    let mut headers = String::new();
    let mut prev = b'\0';
    let mut buf = [0u8; 1];
    while let Ok(1) = stream.read(&mut buf) {
        headers.push(buf[0] as char);
        if prev == b'\n' && buf[0] == b'\n' {
            break;
        }
        prev = buf[0];
    }

    assert!(
        !headers.starts_with("ERROR"),
        "Download failed: {}",
        headers
    );

    let file_size: u64 = headers
        .lines()
        .find_map(|l| {
            l.strip_prefix("file-size: ")
                .and_then(|v| v.trim().parse().ok())
        })
        .expect("No file-size in download response");

    let file_hash: String = headers
        .lines()
        .find_map(|l| l.strip_prefix("file-hash: ").map(|s| s.trim().to_string()))
        .expect("No file-hash in download response");

    let mut received = Vec::with_capacity(file_size as usize);
    let mut chunk = vec![0u8; 32 * 1024];
    while received.len() < file_size as usize {
        let to_read = std::cmp::min(chunk.len(), file_size as usize - received.len());
        let n = stream.read(&mut chunk[..to_read]).unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&chunk[..n]);
    }

    // Check hash
    let mut hasher = Sha256::new();
    hasher.update(&received);
    let received_hash = format!("{:x}", hasher.finalize());
    assert_eq!(file_hash, received_hash, "Downloaded file hash mismatch");

    received
}

#[test]
fn test_concurrency() {
    let port = free_port();
    start_server(port);

    let num_clients = 4;
    let mut handles = Vec::new();

    for i in 0..num_clients {
        let handle = thread::spawn(move || {
            // Each client uploads a unique payload
            let payload: Vec<u8> = (0..64u32 * 1024u32 * 1024u32)
                .map(|b| ((b + i as u32) % 256) as u8)
                .collect();
            let filename = format!("test_file_{}.bin", i);
            let file_key = format!("key_{}", i);

            let file_id = client_upload(port, &payload, &filename, &file_key);
            println!("Client {} uploaded -> file_id: {}", i, file_id);

            let downloaded = client_download(port, &file_id, &file_key);
            println!(
                "Client {} downloaded {} bytes <- file-id: {}",
                i,
                downloaded.len(),
                file_id
            );

            assert_eq!(
                payload, downloaded,
                "Client {}: downloaded data does not match uploaded data",
                i
            );
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Client thread panicked!");
    }
}
