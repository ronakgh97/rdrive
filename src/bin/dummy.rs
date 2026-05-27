// TODO: Can be improved????

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::task::JoinHandle;

const DATA_PER_THREAD: usize = 32 * 1024 * 1024;

struct SharedState {
    writer: BufWriter<File>,
    hasher: Sha256,
}

/// A simple utility to generate a dummy file with random data,
/// used for testing upload/download performance, layering debug, and integrity
#[tokio::main]
async fn main() -> Result<()> {
    let time = std::time::Instant::now();
    let size_mb: usize = std::env::args()
        .nth(1)
        .expect("Usage: dummy <sizeMB?> [path?]")
        .parse()?;
    let size_bytes = size_mb
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("Size too large"))?;
    let path: String = std::env::args()
        .nth(2)
        .expect("Usage: dummy <sizeMB?> [path?]")
        .parse()?;

    if let Some(parent) = PathBuf::from(&path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = File::create(&path)?;
    let state = Arc::new(Mutex::new(SharedState {
        writer: BufWriter::with_capacity(64 * 1024 * 1024, file),
        hasher: Sha256::new(),
    }));

    let total_threads = size_bytes.div_ceil(DATA_PER_THREAD);
    let mut handles = Vec::with_capacity(total_threads);

    for _ in 0..total_threads {
        let state = Arc::clone(&state);

        let handle: JoinHandle<Result<()>> = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut rng = fastrand::Rng::new();
            let mut write_buf = vec![0u8; DATA_PER_THREAD];
            rng.fill(&mut write_buf[..]);
            {
                let mut guard = state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Mutex poisoned"))?;
                guard.writer.write_all(&write_buf[..])?;
                guard.hasher.update(&write_buf[..]);
            }
            Ok(())
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await??;
    }

    let final_hash = {
        let mut guard = state
            .lock()
            .map_err(|_| anyhow::anyhow!("Mutex poisoned"))?;
        guard.writer.flush()?;

        hex::encode(std::mem::take(&mut guard.hasher).finalize())
    };

    println!(
        "Generated {} with size {} MB in {}s",
        path,
        size_mb,
        time.elapsed().as_secs()
    );

    println!("SHA256 digest: {final_hash}");

    Ok(())
}
