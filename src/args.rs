use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "r-drive",
    version = "1.0.0-gamma",
    about = "r-drive; a super simple file storage and sharing with simple & secure protocol",
    long_about = "r-drive; a super simple file storage and sharing with simple & secure protocol"
)]
pub struct ServerArgs {
    #[command(subcommand)]
    pub command: Option<ServerCommands>,
}

#[derive(Subcommand)]
pub enum ServerCommands {
    /// Start the server
    Serve {
        /// Port to run the server on and server listens to 0.0.0.0::<port>
        #[arg(long, default_value = "3000")]
        port: u16,

        /// Protocol version: v1 (TCP default) or v2 (UDP)
        #[arg(long, default_value = "v1")]
        protocol: String,
    },
}

#[derive(Parser)]
#[command(
    name = "r-drive-cli",
    version = "1.0.0-gamma",
    about = "r-drive; a minimal client wrapper for interacting with the r-drive server",
    long_about = "r-drive; a minimal client wrapper for interacting with the r-drive server"
)]
pub struct ClientArgs {
    #[command(subcommand)]
    pub command: Option<ClientCommands>,
}

#[derive(Subcommand)]
pub enum ClientCommands {
    /// User-specific operations, such as authentication, file management, etc.
    User {
        /// Create a new user space
        #[arg(short, long)]
        add: String,
        /// Remove a user space
        #[arg(short, long)]
        remove: String,
    },

    /// Upload a file to the server
    Push {
        /// Path to the file to upload
        #[arg(short, long)]
        file: PathBuf,

        /// Address of the server to connect to (default: localhost)
        #[arg(long, default_value = "localhost")]
        address: String,

        /// Port to connect to the server (default: 3000)
        #[arg(long, default_value = "3000")]
        port: u16,

        /// Protocol version: v1 default or v2 (Custom TCP)
        #[arg(long, default_value = "v1")]
        protocol: String,

        /// Lock the file with a key, can be used in CI (default is input prompt)
        #[arg(long)]
        file_key: Option<String>,
    },

    /// Download a file from the server
    Pull {
        /// Output dir for the downloaded file (default: current directory)
        #[arg(short, long)]
        dir: Option<PathBuf>,

        /// Address of the server to connect to (default: localhost)
        #[arg(long, default_value = "localhost")]
        address: String,

        /// Port to connect to the server (default: 3000)
        #[arg(long, default_value = "3000")]
        port: u16,

        /// Protocol version: v1 default or v2 (Custom TCP)
        #[arg(long, default_value = "v1")]
        protocol: String,

        /// Lock the file with a key, this arg can be used in CI (default is input prompt)
        #[arg(long)]
        file_key: Option<String>,

        /// File ID to download, if not provided, it will be prompted in the terminal
        #[arg(short, long)]
        file_id: Option<String>,
    },

    /// Get Status of remote server
    Status {
        /// Address of the server to connect to (default: localhost)
        #[arg(long, default_value = "localhost")]
        address: String,

        #[arg(long, default_value = "3000")]
        port: u16,

        #[arg(long, default_value = "v1")]
        protocol: String,
    },

    /// Stream a file to other clients via Zero-copy P2P
    Serve {
        /// Path to the file to send over
        #[arg(short, long)]
        file: PathBuf,

        /// Address of the server to connect to (default: localhost)
        #[arg(long, default_value = "localhost")]
        address: String,

        /// Port to connect to the server (default: 3000)
        #[arg(short, long)]
        port: u16,
    },

    /// Get a stream file and write to disk, similar to `pull` but with zero-copy P2P,
    /// so it can be used for large files without consuming much memory
    Listen {
        /// Output dir for the streamed file (default: current directory)
        #[arg(short, long)]
        dir: Option<PathBuf>,

        /// Secure code
        #[arg(short, long)]
        code: String,

        /// Address of the server to connect to (default: localhost)
        #[arg(long, default_value = "localhost")]
        address: String,

        /// Port to connect to the server (default: 3000)
        #[arg(short, long)]
        port: u16,
    },

    /// List local file map
    Ls {},
}
