// TODO: Can be improved????

use anyhow::Result;
use fs2::FileExt;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::time::Instant;

const CHUNK_SIZE: usize = 128 * 1024 * 1024;

/// A simple utility to generate a dummy file with random data,
/// used for testing upload/download performance, layering debug, and integrity
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: dummy_gen <sizeMB> <output_path>");
        return Ok(());
    }
    let size_mb: usize = args[1].parse()?;
    let path = &args[2];
    let size_bytes = (size_mb * 1024 * 1024) as u64;

    let start = Instant::now();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.set_len(size_bytes)?;
    file.allocate(size_bytes)?;

    // mmap thingy
    let mut mmap = unsafe { memmap2::MmapMut::map_mut(&file)? };

    let num_chunks = (size_bytes as usize).div_ceil(CHUNK_SIZE);
    let ptr = mmap.as_mut_ptr();
    let len = mmap.len();

    // real thread
    std::thread::scope(|s| {
        for i in 0..num_chunks {
            let start = i * CHUNK_SIZE;
            let end = (start + CHUNK_SIZE).min(len);
            let slice_len = end - start;
            let slice = unsafe { std::slice::from_raw_parts_mut(ptr.add(start), slice_len) };
            s.spawn(move || {
                rand::rng().fill_bytes(slice);
            });
        }
    });

    mmap.flush()?;

    let mut hasher = Sha256::new();
    hasher.update(&mmap[..]);
    let hash = hex::encode(hasher.finalize());

    let elapsed = start.elapsed();
    let size_gb = size_bytes as f64 / 1_073_741_824.0;
    println!(
        "Generated {} ({:.2} GiB) in {:.2}s  ({:.2} GiB/s)",
        path,
        size_gb,
        elapsed.as_secs_f64(),
        size_gb / elapsed.as_secs_f64()
    );
    println!("SHA256: {}", hash);

    Ok(())
}
