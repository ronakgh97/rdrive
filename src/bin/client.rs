use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use r_storage::args::{ClientArgs, ClientCommands};
use r_storage::protocol_v1::{download_file_http, upload_file_http};
use r_storage::protocol_v2::{download_file_raw, upload_file_raw};
use std::io;

#[tokio::main]
async fn main() -> Result<()> {
    let args = ClientArgs::parse();

    match args.command {
        Some(ClientCommands::Upload {
            file,
            port,
            protocol,
        }) => {
            let port: u16 = port.parse().unwrap_or(3000);
            if let Some(protocol) = protocol {
                match protocol.as_str() {
                    "v1" => {
                        upload_file_http(file, port).await?;
                    }
                    "v2" | _ => {
                        upload_file_raw(file, port).await?;
                    }
                }
            } else {
                // Default to v2 if no protocol specified
                upload_file_raw(file, port).await?;
            }
        }
        Some(ClientCommands::Download {
            output,
            port,
            protocol,
        }) => {
            let port: u16 = port.parse().unwrap_or(3000);

            print!("Enter file ID: ");
            io::Write::flush(&mut io::stdout())?;
            let mut id = String::new();
            io::stdin().read_line(&mut id)?;
            let id = id.trim().to_string();

            print!("Enter file key: ");
            io::Write::flush(&mut io::stdout())?;
            let mut file_key = String::new();
            io::stdin().read_line(&mut file_key)?;
            let file_key = file_key.trim().to_string();

            if let Some(protocol) = protocol {
                match protocol.as_str() {
                    "v1" => {
                        download_file_http(id, file_key, output, port).await?;
                    }
                    "v2" | _ => {
                        download_file_raw(id, file_key, output, port).await?;
                    }
                }
            } else {
                // Default to v2 if no protocol specified
                download_file_raw(id, file_key, output, port).await?;
            }
        }
        None => {
            ascii_art();
        }
    }

    Ok(())
}

fn ascii_art() {
    let ascii = r"                                                 
                   ██                                 
████▄       ▄█▀▀▀ ▀██▀▀ ▄███▄ ████▄  ▀▀█▄ ▄████ ▄█▀█▄ 
██ ▀▀ ▀▀▀▀▀ ▀███▄  ██   ██ ██ ██ ▀▀ ▄█▀██ ██ ██ ██▄█▀ 
██          ▄▄▄█▀  ██   ▀███▀ ██    ▀█▄██ ▀████ ▀█▄▄▄ 
                                             ██       
                                           ▀▀▀
    ";

    println!("{}", ascii);

    println!(
        "🔗 Github: {}",
        "https://github.com/ronakgh97/rstorage".magenta().bold()
    );
}
