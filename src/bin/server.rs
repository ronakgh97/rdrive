use anyhow::Result;
use clap::Parser;
use r_drive::args::{ServerArgs, ServerCommands};
use r_drive::ascii_art;
use r_drive::service::serve_tcp;

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
        None => {
            ascii_art();
        }
    }

    Ok(())
}
