use anyhow::{Context, Result};
use clap::Parser;
use r_drive::args::{ServerArgs, ServerCommands};
use r_drive::ascii_art;
use r_drive::service::serve_tcp;
use rand::RngExt;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[inline(always)]
#[allow(unused)]
fn atomic_write(target: &Path, data: &[u8]) -> Result<()> {
    let mut tmp = target.to_path_buf();
    let mut rng = rand::rng();
    let rand: u64 = rng.random_range(0..u64::MAX);

    tmp.set_extension(format!("tmp.{}", rand));
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

    // not required, but still try to sync the parent dir
    if let Some(parent) = tmp.parent() {
        File::open(parent)?
            .sync_all()
            .with_context(|| format!("failed to sync parent dir {}", parent.display()))?;
    }

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
        // TODO: Issue with file-lock for some reason
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
