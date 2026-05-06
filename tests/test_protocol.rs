use r_drive::header::{
    Command, DownloadHeader, DownloadResponse, ErrorHeader, UploadHeader, UploadResponse,
};
use r_drive::{SERVER_TRACKER, fill_random_bytes, get_storage_path};
use sha2::{Digest, Sha256};
use std::io::ErrorKind;
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::{JoinHandle, JoinSet};

pub const GARBAGE_SIZE: usize = 32 * 1024 * 1024;

static SHARED_TRACKER: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn share_lock() -> &'static tokio::sync::Mutex<()> {
    SHARED_TRACKER.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn free_port() -> u16 {
    let bind = TcpListener::bind("127.0.0.1:0").unwrap();
    bind.local_addr().unwrap().port()
}

async fn cleanup_storage() {
    let path = get_storage_path()
        .await
        .expect("Failed to get storage path");
    if let Err(err) = tokio::fs::remove_dir_all(&path).await {
        assert_eq!(
            err.kind(),
            ErrorKind::NotFound,
            "Failed to remove storage dir {}: {}",
            path.display(),
            err
        );
    }
}

async fn wait_for_server(port: u16) {
    for _ in 0..64 {
        if TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("Server was not ready on port {}", port);
}

async fn start_server_v1(port: u16) -> JoinHandle<()> {
    let path = get_storage_path().await.unwrap();
    tokio::fs::create_dir_all(&path).await.unwrap();

    let handle = tokio::spawn(async move {
        r_drive::protocol_v1::start_tcp_server(port, 128, Arc::new(path))
            .await
            .unwrap();
    });

    wait_for_server(port).await;
    handle
}

async fn stop_server(handle: JoinHandle<()>) {
    handle.abort();
    let _ = handle.await;
}

async fn write_frame(stream: &mut TcpStream, data: &[u8]) {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await.unwrap();
    stream.write_all(data).await.unwrap();
}

async fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.unwrap();
    buf
}

async fn v1_client_upload(port: u16, data: &[u8], filename: &str, file_key: &str) -> String {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    let mut hasher = Sha256::new();
    hasher.update(data);
    let file_hash = hex::encode(hasher.finalize()).to_string();

    let header = UploadHeader {
        file_name: filename.to_string(),
        file_size: data.len() as u64,
        file_hash,
        file_key: file_key.to_string(),
    };
    let request_bytes = Command::Upload(header).serialize().unwrap();

    write_frame(&mut stream, &request_bytes).await;
    stream.write_all(data).await.unwrap();
    stream.flush().await.unwrap();

    let ack_bytes = read_frame(&mut stream).await;
    match ack_bytes.first().copied() {
        Some(1) => {}
        Some(2) => {
            let err = ErrorHeader::deserialize(&ack_bytes[1..]).unwrap();
            panic!(
                "v1 upload failed during ACK: {} - {}",
                err.code, err.message
            );
        }
        Some(other) => panic!("v1 upload failed: unexpected ACK tag {}", other),
        None => panic!("v1 upload failed: empty ACK frame"),
    }

    let resp_bytes = read_frame(&mut stream).await;
    match resp_bytes.first().copied() {
        Some(1) => {}
        Some(2) => {
            let err = ErrorHeader::deserialize(&resp_bytes[1..]).unwrap();
            panic!("v1 upload failed: {} - {}", err.code, err.message);
        }
        Some(other) => panic!("v1 upload failed: unexpected response tag {}", other),
        None => panic!("v1 upload failed: empty response frame"),
    }

    let response = UploadResponse::deserialize(&resp_bytes[1..]).unwrap();

    response.file_id
}

async fn v1_client_download(port: u16, file_id: &str, file_key: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    let header = DownloadHeader {
        file_id: file_id.to_string(),
        file_key: file_key.to_string(),
    };
    let request_bytes = Command::Download(header).serialize().unwrap();

    write_frame(&mut stream, &request_bytes).await;
    stream.flush().await.unwrap();

    let hdr_bytes = read_frame(&mut stream).await;
    match hdr_bytes.first().copied() {
        Some(1) => {}
        Some(2) => {
            let err = ErrorHeader::deserialize(&hdr_bytes[1..]).unwrap();
            panic!("v1 download failed: {} - {}", err.code, err.message);
        }
        Some(other) => panic!("v1 download failed: unexpected response tag {}", other),
        None => panic!("v1 download failed: empty response frame"),
    }

    let response = DownloadResponse::deserialize(&hdr_bytes[1..]).unwrap();

    let file_size = response.file_size;
    let file_hash = response.file_hash;

    let mut received = Vec::with_capacity(file_size as usize);
    let mut chunk = vec![0u8; 32 * 1024];
    while received.len() < file_size as usize {
        let to_read = std::cmp::min(chunk.len(), file_size as usize - received.len());
        let n = stream.read(&mut chunk[..to_read]).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&chunk[..n]);
    }

    assert_eq!(
        received.len() as u64,
        file_size,
        "v1 downloaded file size mismatch"
    );

    let mut hasher = Sha256::new();
    hasher.update(&received);
    let received_hash = hex::encode(hasher.finalize()).to_string();
    assert_eq!(file_hash, received_hash, "v1 downloaded file hash mismatch");

    received
}

async fn snapshot_tracker() -> (usize, usize, f64) {
    let lock = SERVER_TRACKER.read().await;
    (
        lock.total_uploaded,
        lock.total_download,
        lock.total_bandwidth_gb,
    )
}

async fn wait_for_tracker_metrics(
    base_up: usize,
    base_down: usize,
    base_bw: f64,
    expected_up_delta: usize,
    expected_down_delta: usize,
    expected_bw_delta: f64,
    protocol_name: &str,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    loop {
        let (uploaded, downloaded, bandwidth) = snapshot_tracker().await;
        let up_delta = uploaded.saturating_sub(base_up);
        let down_delta = downloaded.saturating_sub(base_down);
        let bw_delta = bandwidth - base_bw;

        let up_ok = up_delta == expected_up_delta;
        let down_ok = down_delta == expected_down_delta;
        let bandwidth_ok = (bw_delta - expected_bw_delta).abs() < 1e-6;

        if up_ok && down_ok && bandwidth_ok {
            return;
        }

        if tokio::time::Instant::now() >= deadline {
            assert!(
                up_ok,
                "{} tracker total_uploaded mismatch: expected {}, got {}",
                protocol_name, expected_up_delta, up_delta
            );
            assert!(
                down_ok,
                "{} tracker total_download mismatch: expected {}, got {}",
                protocol_name, expected_down_delta, down_delta
            );
            assert!(
                bandwidth_ok,
                "{} tracker bandwidth mismatch: expected delta {:.9} GB, got delta {:.9} GB",
                protocol_name, expected_bw_delta, bw_delta
            );
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_concurrency_v1() {
    let _guard = share_lock().lock().await;

    cleanup_storage().await;

    let port = free_port();
    let server = start_server_v1(port).await;

    // Reset tracker after server is ready (probe connection done) to measure only client connections
    {
        let mut lock = SERVER_TRACKER.write().await;
        lock.total_uploaded = 0;
        lock.total_download = 0;
        lock.total_bandwidth_gb = 0.0;
    }

    let (base_up, base_down, base_bw) = snapshot_tracker().await;

    let num_clients = 32;
    let mut tasks = JoinSet::new();

    for i in 0..num_clients {
        let mut payload = vec![0u8; GARBAGE_SIZE];
        tasks.spawn(async move {
            fill_random_bytes(&mut payload);
            let filename = format!("v1_test_file_{}.bin", i);
            let file_key = format!("v1_key_{}", i);

            let file_id = v1_client_upload(port, &payload, &filename, &file_key).await;
            let downloaded = v1_client_download(port, &file_id, &file_key).await;

            assert_eq!(
                payload, downloaded,
                "v1 client {}: downloaded data does not match uploaded data",
                i
            );
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }

    let expected_bw = 2.0 * num_clients as f64 * GARBAGE_SIZE as f64 / (1024.0 * 1024.0 * 1024.0);
    wait_for_tracker_metrics(
        base_up,
        base_down,
        base_bw,
        num_clients, // upload increases by 1 for each
        num_clients, // download increases by 1 for each
        expected_bw,
        "v1",
    )
    .await;

    stop_server(server).await;
    cleanup_storage().await;
}

// TODO: Protocol v2 test here when its done
