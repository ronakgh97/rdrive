use anyhow::{Context, Result};
use clap::Parser;
use hex::decode;
use postcard::{from_bytes, to_allocvec};
use r_drive::args::{ServerArgs, ServerCommands};
use r_drive::crypto::{decrypt_data, encrypt_data, generate_key};
use r_drive::service::serve_tcp;
use r_drive::{MetadataFile, ascii_art, get_storage_path};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

#[inline(always)]
fn atomic_write(target: &Path, data: &[u8]) -> Result<()> {
    let mut tmp = target.to_path_buf();
    tmp.set_extension("tmp");

    {
        let mut file =
            File::create(&tmp).with_context(|| format!("failed to create {}", tmp.display()))?;

        file.write_all(data)
            .with_context(|| format!("failed to write {}", tmp.display()))?;

        file.sync_all()
            .with_context(|| format!("failed to sync {}", tmp.display()))?;
    }

    fs::rename(&tmp, target).with_context(|| {
        format!(
            "failed to atomic rename {} to {}",
            tmp.display(),
            target.display()
        )
    })?;
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 24)]
async fn main() -> Result<()> {
    let args = ServerArgs::parse();

    match args.command {
        Some(ServerCommands::Serve { port, protocol }) => match protocol.as_str() {
            "v1" => {
                serve_tcp(Some(port)).await?;
            }
            "v2" => {
                println!("WIP: UDP protocol is not implemented yet, falling back to TCP");
                serve_tcp(Some(port)).await?;
            }
            _ => {
                println!("Unknown protocol: {}", protocol);
                std::process::exit(1);
            }
        },
        Some(ServerCommands::Rotate { .. }) => {
            dotenv::dotenv().ok();
            let curr_key = std::env::var("MASTER_KEY").expect("MASTER_KEY not set in .env file");
            let new_key = generate_key();
            let curr_key_bytes = decode(&curr_key)?;
            let new_key_bytes = decode(&new_key)?;
            let storage_path = get_storage_path().await?;

            println!("Rotating MASTER_KEY...");
            let rotated = rotate_meta_files(&storage_path, &curr_key_bytes, &new_key_bytes)?;
            update_env("MASTER_KEY", &new_key)?;

            println!("Rotated {rotated} metadata file(s)");
            println!("New MASTER_KEY: {new_key}");
        }
        None => {
            ascii_art();
        }
    }

    Ok(())
}

fn update_env(field: &str, value: &str) -> Result<bool> {
    let path = Path::new(".env");
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) => {
            anyhow::bail!("Failed to read file content: {}", e);
        }
    };

    let mut lines = Vec::new();
    let mut updated = false;
    for line in content.lines() {
        match line.split_once('=') {
            // If the line contains an '=', check if the field matches
            Some((env_field, _)) if env_field.trim() == field => {
                lines.push(format!("{field}={value}"));
                updated = true;
            }
            _ => lines.push(line.to_string()),
        }
    }

    if !updated {
        lines.push(format!("{field}={value}"));
    }

    // add a newline at the end
    let mut content = lines.join("\n");
    if !content.ends_with('\n') {
        content.push('\n');
    }

    atomic_write(path, content.as_bytes())
        .context("Failed to write updated .env file atomically")?;

    Ok(updated)
}

fn rotate_meta_files(storage_path: &Path, old_key: &[u8], new_key: &[u8]) -> Result<usize> {
    if !storage_path.exists() {
        return Ok(0);
    }

    let mut metadata_files = Vec::new();
    collect_meta_files(storage_path, &mut metadata_files)?;

    // Pre-build all the encrypted data so that failures during reading/decryption,
    // don't leave us in a partially rotated state
    let mut staged_writes: Vec<(PathBuf, Vec<u8>)> = Vec::with_capacity(metadata_files.len());
    for path in &metadata_files {
        let encrypted = fs::read(path)
            .with_context(|| format!("failed to read metadata file {}", path.display()))?;
        let decrypted = decrypt_data(&encrypted, old_key);
        let metadata: MetadataFile = from_bytes(&decrypted)
            .with_context(|| format!("failed to deserialize metadata file {}", path.display()))?;
        let serialized = to_allocvec(&metadata)
            .with_context(|| format!("failed to serialize metadata file {}", path.display()))?;
        let rotated = encrypt_data(&serialized, new_key);
        staged_writes.push((path.clone(), rotated));
    }

    // write each file atomically
    for (path, rotated) in &staged_writes {
        atomic_write(path, rotated)
            .with_context(|| format!("failed to rewrite metadata file {}", path.display()))?;
    }

    Ok(metadata_files.len())
}

fn collect_meta_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            collect_meta_files(&path, files)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("meta") {
            files.push(path);
        }
    }

    Ok(())
}
