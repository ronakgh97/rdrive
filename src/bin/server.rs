use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use r_drive::args::{ServerArgs, ServerCommands};
use r_drive::crypto::generate_ed25519_keypair;
use r_drive::service::serve_tcp;
use r_drive::{ascii_art, get_server_key_dir};
use rand::RngExt;
use std::io::Write;
use std::path::Path;

#[tokio::main(flavor = "multi_thread", worker_threads = 24)]
async fn main() -> Result<()> {
    let args = ServerArgs::parse();

    match args.command {
        Some(ServerCommands::Serve { port, protocol }) => match protocol.as_str() {
            "v1" => {
                let key_path = get_server_key_dir().await?;

                let (pri_key, pub_key) =
                    (key_path.join("private.pem"), key_path.join("public.pem"));

                match (pri_key.exists(), pub_key.exists()) {
                    (true, true) => {
                        print!("{}", tokio::fs::read_to_string(&pub_key).await?.cyan());
                    }
                    (false, false) | (true, false) | (false, true) => {
                        let (new_pri, new_pub) = generate_ed25519_keypair()?;
                        let new_pri_pem = new_pri.to_pkcs8_pem(LineEnding::LF)?;
                        let new_pub_pem = new_pub.to_public_key_pem(LineEnding::LF)?;

                        tokio::fs::create_dir_all(&key_path).await?;
                        tokio::fs::write(&pri_key, &new_pri_pem).await?;
                        tokio::fs::write(&pub_key, &new_pub_pem).await?;
                        print!("{}", tokio::fs::read_to_string(&pub_key).await?.cyan());
                    }
                }
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
            println!("WIP: Key rotation is not implemented yet");
            std::process::exit(1);
        }
        None => {
            ascii_art();
        }
    }

    Ok(())
}

#[allow(unused)]
fn atomic_write(target: &Path, data: &[u8]) -> Result<()> {
    let mut tmp = target.to_path_buf();
    let mut rng = rand::rng();
    let rand: u64 = rng.random_range(0..u64::MAX);

    tmp.set_extension(format!("tmp.{}", rand));
    {
        let mut file = std::fs::File::create(&tmp)
            .with_context(|| format!("failed to create {}", tmp.display()))?;

        file.write_all(data)
            .with_context(|| format!("failed to write {}", tmp.display()))?;

        file.sync_all()
            .with_context(|| format!("failed to sync {}", tmp.display()))?;
    }

    std::fs::rename(&tmp, target).with_context(|| {
        format!(
            "failed to atomic rename {} to {}",
            tmp.display(),
            target.display()
        )
    })?;

    // sync parent if any, anyway
    if let Some(parent) = tmp.parent() {
        std::fs::File::open(parent)?
            .sync_all()
            .with_context(|| format!("failed to sync parent dir {}", parent.display()))?;
    }

    Ok(())
}

/// TODO: Thought `Lazy lock` was hot-reloads env var, apparantly its not, this is reduntant now
#[allow(unused)]
fn update_env(field: &str, value: &str) -> Result<bool> {
    let path = Path::new(".env");
    let content = match std::fs::read_to_string(path) {
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
