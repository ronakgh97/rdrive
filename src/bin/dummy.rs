use rand::Rng;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};

/// A simple utility to generate a dummy file with random data,
/// used for testing upload/download performance, layering debug, and integrity
#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let file = File::create(&path).await?;
    file.set_len(size_bytes as u64).await?;
    let mut buf_file = BufWriter::with_capacity(32 * 1024 * 1024, file);
    let mut rng = rand::rng();
    let mut hasher = Sha256::new();
    let mut written: usize = 0;
    let mut write_buf = vec![0u8; 18 * 1024 * 1024];

    while written < size_bytes {
        let to_write = std::cmp::min(size_bytes - written, write_buf.len());
        rng.fill_bytes(&mut write_buf[..to_write]);
        hasher.update(&write_buf[..to_write]);
        buf_file.write_all(&write_buf[..to_write]).await?;
        written += to_write;
    }

    buf_file.flush().await?;
    let checksum = hex::encode(hasher.finalize());

    println!(
        "Generated {} with size {} MB in {}s",
        path,
        size_mb,
        time.elapsed().as_secs()
    );
    println!("SHA256 digest: {}", checksum);

    Ok(())
}
