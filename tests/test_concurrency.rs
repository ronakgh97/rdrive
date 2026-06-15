use bytes::BytesMut;
use r_drive::crypto::generate_ed25519_keypair;
use r_drive::protocol_v1::{download_client, upload_client};
use r_drive::{
    AuthServerMap, SERVER_TRACKER, get_authorized_server_map_path, get_server_key_dir,
    get_storage_dir,
};
use rand::Rng;
use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::{JoinHandle, JoinSet};
use uuid::Uuid;

pub const TEST_FILE_SIZE: usize = 8 * 1024 * 1024;

static SHARED_TRACKER: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn share_lock() -> &'static tokio::sync::Mutex<()> {
    SHARED_TRACKER.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn free_port() -> u16 {
    let bind = TcpListener::bind("127.0.0.1:0").unwrap();
    bind.local_addr().unwrap().port()
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
    let path = get_storage_dir().await.unwrap();
    tokio::fs::create_dir_all(&path).await.unwrap();

    let handle = tokio::spawn(async move {
        r_drive::protocol_v1::start_tcp_server(port, Arc::new(path))
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

fn setup_temp_home() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("Failed to create temp dir");
    unsafe {
        std::env::set_var("HOME", tmp.path());
        std::env::set_var("USERPROFILE", tmp.path());
    }
    tmp
}

async fn prepare_server_keys() -> Vec<u8> {
    let (pri, pub_) = generate_ed25519_keypair().unwrap();
    let key_dir = get_server_key_dir().unwrap();
    tokio::fs::create_dir_all(&key_dir).await.unwrap();

    tokio::fs::write(
        key_dir.join("public_ed25519.key"),
        hex::encode(pub_.to_bytes()),
    )
    .await
    .unwrap();
    tokio::fs::write(
        key_dir.join("private_ed25519.key"),
        hex::encode(pri.to_bytes()),
    )
    .await
    .unwrap();

    pub_.to_bytes().to_vec()
}

/// Pre-seed the server map so client_handshake_helper skips the stdin TOFU prompt.
async fn prepare_server_map(port: u16, pub_key_bytes: &[u8]) {
    let map_path = get_authorized_server_map_path().unwrap();
    tokio::fs::create_dir_all(map_path.parent().unwrap())
        .await
        .unwrap();

    let mut map = AuthServerMap {
        server_map: HashMap::from([(
            format!("127.0.0.1:{}", port).parse().unwrap(),
            hex::encode(pub_key_bytes),
        )]),
    };
    map.write(&map_path).await.unwrap();
}

async fn snapshot_tracker() -> (usize, usize, f64) {
    let lock = SERVER_TRACKER.read().await;
    (
        lock.total_uploaded,
        lock.total_download,
        lock.total_bandwidth_gb,
    )
}

async fn wait_check_tracker_metrics(
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

#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn test_concurrency_v1() {
    unsafe {
        std::env::set_var("ENABLE_CLIENT_WHITELIST", "false");
    }

    let _guard = share_lock().lock().await;
    let _tmp_home = setup_temp_home();

    let server_pub = prepare_server_keys().await;

    let port = free_port();
    let server = start_server_v1(port).await;

    prepare_server_map(port, &server_pub).await;

    // Reset tracker to measure only client connections
    {
        let mut lock = SERVER_TRACKER.write().await;
        lock.total_uploaded = 0;
        lock.total_download = 0;
        lock.total_bandwidth_gb = 0.0;
    }

    let (base_up, base_down, base_bw) = snapshot_tracker().await;

    let num_clients = 32;
    let mut tasks = JoinSet::new();
    let task_root = tempfile::tempdir().unwrap();

    for i in 0..num_clients {
        let mut payload = vec![0u8; TEST_FILE_SIZE];
        rand::rng().fill_bytes(&mut payload);

        let task_dir = task_root.path().join(format!("t{}", i));
        tokio::fs::create_dir_all(&task_dir).await.unwrap();

        let file_path = task_dir.join(format!("src_{}.bin", i));
        tokio::fs::write(&file_path, &payload).await.unwrap();

        tasks.spawn(async move {
            let (client_key, _) = generate_ed25519_keypair().unwrap();
            let mut pool = BytesMut::with_capacity(1024 * 1024 * 4);
            let uuid = Uuid::new_v4().simple().to_string();
            let file_key = format!("key_{}", i);

            let file_id = upload_client(
                file_path.clone(),
                file_key.clone(),
                &uuid,
                "127.0.0.1",
                port,
                client_key.clone(),
                &mut pool,
            )
            .await
            .expect("Upload failed");

            let out_dir = task_dir.join("downloads");
            tokio::fs::create_dir_all(&out_dir).await.unwrap();
            let out_path = download_client(
                &file_id,
                file_key,
                Some(out_dir),
                "127.0.0.1",
                port,
                client_key,
                &mut pool,
            )
            .await
            .expect("Download failed");

            let downloaded = tokio::fs::read(&out_path).await.unwrap();
            assert_eq!(payload, downloaded, "Data mismatch for client {}", i);
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.map_err(|e| panic!("Task failed: {}", e)).unwrap();
    }

    let expected_bw = 2.0 * num_clients as f64 * TEST_FILE_SIZE as f64 / (1024.0 * 1024.0 * 1024.0);
    wait_check_tracker_metrics(
        base_up,
        base_down,
        base_bw,
        num_clients,
        num_clients,
        expected_bw,
        "v1",
    )
    .await;

    stop_server(server).await;
}
