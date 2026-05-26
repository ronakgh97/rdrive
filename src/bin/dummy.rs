use rand::Rng;
use std::path::PathBuf;

/// A simple utility to generate a dummy file with random data,
/// used for testing upload/download performance, layering debug, and integrity
fn main() -> anyhow::Result<()> {
    let size: usize = std::env::args()
        .nth(1)
        .expect("Usage: dummy <sizeMB?> [path?]")
        .parse()?;
    let path: String = std::env::args()
        .nth(2)
        .expect("Usage: dummy <sizeMB?> [path?]")
        .parse()?;

    let mut data = vec![0u8; size * 1024 * 1024];
    rand::rng().fill_bytes(&mut data);

    match PathBuf::from(&path).parent() {
        Some(parent) => {
            std::fs::create_dir_all(parent)?;
            std::fs::write(&path, data)?;
        }
        None => {
            std::fs::write(&path, data)?;
        }
    }

    println!("Generated dummy file at {} with size {} MB", path, size);

    Ok(())
}
