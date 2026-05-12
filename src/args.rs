use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "r-drive",
    version = "1.0.0-gamma",
    about = "r-drive; a simple file storage and sharing with secure protocol, backups, and versioning support",
    long_about = "a fast and zero-trust object storage node, uses CAS/Layering like docker image hub and versioning & backups support"
)]
pub struct ServerArgs {
    #[command(subcommand)]
    pub command: Option<ServerCommands>,
}

#[derive(Subcommand)]
pub enum ServerCommands {
    /// Start the server
    Serve {
        /// Port to run the server on and server listens to 0.0.0.0`::<port>`
        #[arg(long, default_value = "3000")]
        port: u16,

        /// Protocol version: v1 (TCP default) or v2 (UDP)
        #[arg(long, default_value = "v1")]
        protocol: String,
    },
    /// Rotate ENV keys locally, (can be slow for 'obvious reason')
    Rotate {},
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
    /// Derive ED25519 key pair locally and register with the server,
    /// this is required before any push/pull operations
    Init {
        /// Address of the server to connect to (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        address: String,

        /// Port to connect to the server (default: 3000)
        #[arg(long, default_value = "3000")]
        port: u16,
    },

    /// Upload a file to the server
    Push {
        /// Path to the file to upload
        #[arg(short, long)]
        file: PathBuf,

        /// Address of the server to connect to (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
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

        /// Address of the server to connect to (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        address: String,

        /// Port to connect to the server (default: 3000)
        #[arg(long, default_value = "3000")]
        port: u16,

        /// Protocol version: v1 default or v2 (Custom TCP)
        #[arg(long, default_value = "v1")]
        protocol: String,

        /// File ID to download, if not provided, it will be prompted in the terminal
        #[arg(short, long)]
        file_id: Option<String>,

        /// Unlock the file with a key, this arg can be used in CI (default is input prompt)
        #[arg(long)]
        file_key: Option<String>,
    },

    /// Create backup for a file on the server
    Backup {
        /// File ID to back up, if not provided, it will be prompted in the terminal
        #[arg(short, long)]
        file_id: String,

        /// Unlock the file with a key, this arg can be used in CI (default is input prompt)
        #[arg(long)]
        file_key: Option<String>,

        /// Address of the server to connect to (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        address: String,

        /// Port to connect to the server (default: 3000)
        #[arg(long, default_value = "3000")]
        port: u16,
    },

    /// Get Status of remote server
    Status {
        /// Address of the server to connect to (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        address: String,

        #[arg(long, default_value = "3000")]
        port: u16,

        #[arg(long, default_value = "v1")]
        protocol: String,
    },

    /// List local file map & other info
    Ls {},

    // TODO: Not implement, skill issues
    /// Stream a file to other clients via Zero-copy P2P
    Serve {
        /// Path to the file to send over
        #[arg(short, long)]
        file: PathBuf,

        /// Address of the server to connect to (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        address: String,

        /// Port to connect to the server (default: 3000)
        #[arg(short, long)]
        port: u16,
    },

    // TODO: Not implement, skill issues
    /// Get a stream file and write to disk, similar to `pull` but with zero-copy P2P,
    /// so it can be used for large files without consuming much memory
    Listen {
        /// Output dir for the streamed file (default: current directory)
        #[arg(short, long)]
        dir: Option<PathBuf>,

        /// Secure code
        #[arg(short, long)]
        code: String,

        /// Address of the server to connect to (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        address: String,

        /// Port to connect to the server (default: 3000)
        #[arg(short, long)]
        port: u16,
    },
}
