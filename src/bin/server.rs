use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use r_storage::args::{ServerArgs, ServerCommands};
use r_storage::service::{serve_http, serve_raw_tcp};

#[tokio::main]
async fn main() -> Result<()> {
    let args = ServerArgs::parse();

    match args.command {
        Some(ServerCommands::Serve { port, protocol }) => match protocol.as_str() {
            "v1" => {
                serve_http(port).await?;
            }
            "v2" | _ => {
                serve_raw_tcp(port).await?;
            }
        },
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
