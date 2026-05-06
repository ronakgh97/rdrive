use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use r_drive::args::{ClientArgs, ClientCommands};
use r_drive::protocol_v1::{
    download_client as download_file_v1, get_status_v1, upload_client as upload_file_v1,
};
use r_drive::{Catalog, get_catalog_path};
use std::io;

#[tokio::main]
async fn main() -> Result<()> {
    let args = ClientArgs::parse();

    match args.command {
        Some(ClientCommands::Push {
            file,
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
                print!("Enter a lock key: ");
                io::Write::flush(&mut io::stdout())?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                if input.trim().is_empty() {
                    eprintln!("File key cannot be empty");
                    std::process::exit(1);
                }
                input.trim().to_string()
            };

            let key = match protocol.as_str() {
                "v1" => upload_file_v1(file.clone(), file_key, "127.0.0.1", port).await?,
                "v2" => todo!("UDP protocol is WIP"),
                _ => {
                    eprintln!("Unknown protocol: {}", protocol);
                    std::process::exit(1);
                }
            };

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

            catalog
                .file_map
                .insert(key, file.file_name().unwrap().to_string_lossy().to_string());

            catalog.write(&catalog_path).await?;
        }
        Some(ClientCommands::Pull {
            dir,
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
                    download_file_v1(file_id, file_key, dir, "127.0.0.1", port).await?;
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
            todo!()
        }
        Some(ClientCommands::Listen { .. }) => {
            todo!()
        }
        Some(ClientCommands::Ls { .. }) => {
            list_file_map().await?;
        }
        Some(ClientCommands::Status { port, protocol }) => match protocol.as_str() {
            "v1" => {
                let status = get_status_v1("localhost", port).await?;

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

#[inline]
fn ascii_art() {
    let ascii = r"                                       
               ▄▄                      
               ██       ▀▀             
████▄       ▄████ ████▄ ██ ██ ██ ▄█▀█▄ 
██ ▀▀ ▀▀▀▀▀ ██ ██ ██ ▀▀ ██ ██▄██ ██▄█▀ 
██          ▀████ ██    ██▄ ▀█▀  ▀█▄▄▄ 

    ";

    println!("{}", ascii.cyan());

    println!(
        "🔗 Github: {}",
        "https://github.com/ronakgh97/rstorage".magenta().bold()
    );
}

async fn list_file_map() -> Result<()> {
    let file_map = Catalog::read(&get_catalog_path()?).await?;

    for (id, name) in file_map.file_map {
        println!("  {} - {}", id.yellow(), name.cyan());
    }

    Ok(())
}
