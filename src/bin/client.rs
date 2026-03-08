use anyhow::Result;
use clap::Parser;
use r_storage::args::{ClientArgs, ClientCommands};
use r_storage::protocol_v1::{download_file_client, upload_file_client};
use r_storage::protocol_v2::{download_file_raw, upload_file_raw};
use std::io;

#[tokio::main]
async fn main() -> Result<()> {
    let args = ClientArgs::parse();

    match args.command {
        Some(ClientCommands::Upload {
            file,
            port,
            raw_tcp,
        }) => {
            let port: u16 = port.parse().unwrap_or(3000);
            if raw_tcp {
                let _file_id = upload_file_raw(file, port).await?;
            } else {
                let _file_id = upload_file_client(file, port).await?;
            }
        }
        Some(ClientCommands::Download {
            output,
            port,
            raw_tcp,
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

            if raw_tcp {
                download_file_raw(id, file_key, output, port).await?;
            } else {
                download_file_client(id, file_key, output, port).await?;
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
}
