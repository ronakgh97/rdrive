use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use r_drive::args::{ClientArgs, ClientCommands};
use r_drive::protocol_v1::{
    download_client as download_file_v1, get_server_status, upload_client as upload_file_v1,
};
use r_drive::{Catalog, ascii_art, get_catalog_path};
use std::io;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    let args = ClientArgs::parse();

    match args.command {
        Some(ClientCommands::Push {
            file,
            address,
            port,
            protocol,
            file_key,
        }) => {
            if !file.exists() {
                eprintln!("File not found: {}", file.display());
                std::process::exit(1);
            }

            let file_key = if let Some(key) = file_key {
                key
            } else {
                print!("Enter file key: ");
                io::Write::flush(&mut io::stdout())?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                if input.trim().is_empty() {
                    eprintln!("File key cannot be empty");
                    std::process::exit(1);
                }
                input.trim().to_string()
            };

            let file_name = file
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid file name"))?
                .to_string_lossy()
                .to_string();

            let catalog_path = get_catalog_path()?;
            let catalog_dir = catalog_path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("Invalid catalog path"))?;
            std::fs::create_dir_all(catalog_dir)?;

            // Read existing or new
            let mut catalog = if catalog_path.exists() {
                Catalog::read(&catalog_path).await?
            } else {
                Catalog::default()
            };

            let file_id = if let Some(tracked) = catalog.file_index.get(&file_name) {
                for (i, uuid) in tracked.iter().enumerate() {
                    let info = catalog
                        .file_map
                        .get(uuid)
                        .ok_or_else(|| anyhow::anyhow!("Couldn't find in file map {}", uuid))?;
                    println!(
                        "{} {} | pushed ({}) | pulled ({})",
                        i + 1,
                        uuid.yellow(),
                        info.last_push,
                        info.last_pull
                    );
                }
                print!("File already exists, overwrite? [N/0]: ");

                let input: usize = {
                    io::Write::flush(&mut io::stdout())?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    input
                        .trim()
                        .parse()
                        .map_err(|_| anyhow::anyhow!("Invalid input, expected a number"))?
                };
                match input {
                    0 => Uuid::new_v4().simple().to_string(),
                    n if n <= tracked.len() => tracked[n - 1].clone(),
                    _ => {
                        eprintln!("Invalid input, number out of range");
                        std::process::exit(1);
                    }
                }
            } else {
                Uuid::new_v4().simple().to_string()
            };

            match protocol.as_str() {
                "v1" => upload_file_v1(file, file_key, &file_id, &address, port).await?,
                "v2" => todo!("UDP protocol is WIP"),
                _ => {
                    eprintln!("Unknown protocol: {}", protocol);
                    std::process::exit(1);
                }
            };
            catalog
                .update_on_push(&catalog_path, &file_name, &file_id)
                .await?;
        }
        Some(ClientCommands::Pull {
            dir,
            address,
            port,
            protocol,
            file_key,
            file_id,
        }) => {
            let (file_id, file_key) = if let (Some(id), Some(key)) = (file_id, file_key) {
                (id, key)
            } else {
                print!("Enter file ID: ");
                let file_id: String = {
                    io::Write::flush(&mut io::stdout())?;
                    let mut id = String::new();
                    io::stdin().read_line(&mut id)?;
                    if id.trim().is_empty() {
                        eprintln!("File ID cannot be empty");
                        std::process::exit(1);
                    }
                    id.trim().to_string()
                };

                print!("Enter file key: ");
                let file_key: String = {
                    io::Write::flush(&mut io::stdout())?;
                    let mut key = String::new();
                    io::stdin().read_line(&mut key)?;
                    if key.trim().is_empty() {
                        eprintln!("File key cannot be empty");
                        std::process::exit(1);
                    }
                    key.trim().to_string()
                };
                (file_id, file_key)
            };

            match protocol.as_str() {
                "v1" => {
                    download_file_v1(&file_id, file_key, dir, &address, port).await?;

                    let catalog_path = get_catalog_path()?;

                    if catalog_path.exists() {
                        let mut catalog = Catalog::read(&catalog_path).await?;
                        catalog.update_on_pull(&catalog_path, &file_id).await?;
                    }
                }
                "v2" => {
                    todo!("UDP protocol is WIP")
                }
                _ => {
                    eprintln!("Unknown protocol: {}", protocol);
                    std::process::exit(1);
                }
            }
        }
        Some(ClientCommands::Serve { .. }) => {
            todo!("Non-trivial to implement this feature")
        }
        Some(ClientCommands::Listen { .. }) => {
            todo!("Non-trivial to implement this feature")
        }
        Some(ClientCommands::Ls { .. }) => {
            let file_map = Catalog::read(&get_catalog_path()?).await?;

            for (id, file) in file_map.file_map {
                println!(
                    " {} | {} | {} | {} ",
                    id.yellow(),
                    file.name.cyan(),
                    file.last_push,
                    file.last_pull
                );
            }
        }
        Some(ClientCommands::Status {
            port,
            address,
            protocol,
        }) => match protocol.as_str() {
            "v1" => {
                let status = get_server_status(&address, port).await?;

                println!("Status timestamp: {}", status.timestamp);
                println!("Uptime: {} hrs", status.uptime_hrs);
                println!(
                    "Total {} uploads, {} downloads",
                    status.total_uploaded, status.total_downloaded
                );
                println!("Bandwidth used: {} gb", status.total_bandwidth_used);
            }
            "v2" => {
                todo!("UDP protocol is WIP")
            }
            _ => {
                println!("Unknown protocol: {}", protocol);
                std::process::exit(1);
            }
        },
        None => {
            ascii_art();
        }
    }

    Ok(())
}
