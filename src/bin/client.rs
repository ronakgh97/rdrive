use anyhow::Result;
use clap::Parser;
use r_storage::args::{ClientArgs, ClientCommands};
use r_storage::service::{download_file, upload_file};
use std::io;

#[tokio::main]
async fn main() -> Result<()> {
    let args = ClientArgs::parse();

    match args.command {
        Some(ClientCommands::Upload { file, port }) => {
            let port: u16 = port.parse().unwrap_or(3000);
            let _file_id = upload_file(file, port).await?;
        }
        Some(ClientCommands::Download { output, port }) => {
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

            download_file(id, file_key, output, port).await?;
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
