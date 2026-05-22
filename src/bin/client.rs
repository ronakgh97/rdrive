use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use r_drive::args::{ClientArgs, ClientCommands};
use r_drive::crypto::generate_ed25519_keypair;
use r_drive::protocol_v1::{
    auth_client, download_client as download_file_v1, get_server_status,
    upload_client as upload_file_v1,
};
use r_drive::{Catalog, ascii_art, get_catalog_path, get_user_key_dir};
use sha2::{Digest, Sha512};
use std::io;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    let args = ClientArgs::parse();

    let mut alloc_mem = vec![0u8; 14 * 1024 * 1024];
    match args.command {
        // TODO: Somehow find a way to recover keys
        Some(ClientCommands::Key {
            address,
            port,
            rot,
            auth,
        }) => {
            let user_path = get_user_key_dir()?;
            let private_key_path = user_path.join("private_key.pem");
            let public_key_path = user_path.join("public_key.pem");

            let existing_keys = match (private_key_path.exists(), public_key_path.exists()) {
                (true, true) => Some((
                    tokio::fs::read_to_string(&private_key_path).await?,
                    tokio::fs::read_to_string(&public_key_path).await?,
                )),
                _ => None,
            };

            // this oneshot, we don't want to lockout client
            if rot {
                let (old_pri_pem, old_pub_pem) =
                    existing_keys.context("No existing keys. Cannot rotate.")?;

                let signing_key = SigningKey::from_pkcs8_pem(&old_pri_pem)
                    .context("Bad private key, cannot rotate")?;
                let old_public_key = VerifyingKey::from_public_key_pem(&old_pub_pem)
                    .context("Bad public key, cannot rotate")?;

                let (new_pri, new_pub) = generate_ed25519_keypair()?;
                let new_pri_pem = new_pri.to_pkcs8_pem(LineEnding::LF)?;
                let new_pub_pem = new_pub.to_public_key_pem(LineEnding::LF)?;

                println!(
                    "Preview Public key (PEM SHA)\n{} -> {}",
                    hex::encode(Sha512::digest(&old_pub_pem)).yellow(),
                    hex::encode(Sha512::digest(&new_pub_pem)).green()
                );

                // Try sync with server BEFORE writing to disk!!!
                auth_client(
                    signing_key,
                    new_pub,
                    Some(old_public_key),
                    &address,
                    port,
                    &mut alloc_mem,
                )
                .await?;

                println!("Key rotated/synced successfully");
                tokio::fs::create_dir_all(&user_path).await?;
                tokio::fs::write(&private_key_path, &new_pri_pem).await?;
                tokio::fs::write(&public_key_path, &new_pub_pem).await?;

                return Ok(());
            }

            let (signing_key, verifying_key) = match existing_keys {
                Some((pri_pem, pub_pem)) => {
                    println!("Found existing keypair");

                    let signing_key = SigningKey::from_pkcs8_pem(&pri_pem)
                        .context("Bad private key, cannot authenticate")?;
                    let verifying_key = VerifyingKey::from_public_key_pem(&pub_pem)
                        .context("Bad public key, cannot authenticate")?;

                    (signing_key, verifying_key)
                }

                None => {
                    let (prikey, pubkey) = generate_ed25519_keypair()?;
                    let pri_pem = prikey.to_pkcs8_pem(LineEnding::LF)?.to_string();
                    let pub_pem = pubkey.to_public_key_pem(LineEnding::LF)?;

                    tokio::fs::create_dir_all(&user_path).await?;
                    tokio::fs::write(&private_key_path, &pri_pem).await?;
                    tokio::fs::write(&public_key_path, &pub_pem).await?;

                    println!("Generated ed25519 keypair.");

                    (prikey, pubkey)
                }
            };

            // TODO: hash cant be reproduce
            let pub_key_pem = verifying_key.to_public_key_pem(LineEnding::LF)?;
            println!(
                "Public key (PEM SHA)\n{}",
                hex::encode(Sha512::digest(&pub_key_pem)).green()
            );

            if auth {
                auth_client(
                    signing_key,
                    verifying_key,
                    None,
                    &address,
                    port,
                    &mut alloc_mem,
                )
                .await?;
            } else {
                // TODO: do a little user prompt here after showing key
                println!(
                    "Make sure to mkdir (whitelist) your SHA512 public key on the server ~/.rdrive/authorized_keys/"
                );
            }
        }
        Some(ClientCommands::Push {
            file,
            address,
            port,
            protocol,
            file_key,
        }) => {
            let user_path = get_user_key_dir()?;
            let private_key_path = user_path.join("private_key.pem");
            let public_key_path = user_path.join("public_key.pem");

            if !private_key_path.exists() && public_key_path.exists() {
                eprintln!("Public key exists but private key is missing, cannot push.");
                std::process::exit(1);
            }

            let signing_key =
                SigningKey::from_pkcs8_pem(&tokio::fs::read_to_string(&private_key_path).await?)
                    .context("Bad private key, cannot push")?;

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

            // read existing or create new
            let catalog_path = get_catalog_path()?;
            let mut catalog = Catalog::read_or_create(&catalog_path).await?;

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
                print!("Overwrite? [n/0]: ");

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
                "v1" => {
                    upload_file_v1(
                        file,
                        file_key,
                        &file_id,
                        &address,
                        port,
                        signing_key,
                        &mut alloc_mem,
                    )
                    .await?
                }
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
            let user_path = get_user_key_dir()?;
            let private_key_path = user_path.join("private_key.pem");
            let public_key_path = user_path.join("public_key.pem");

            if !private_key_path.exists() && public_key_path.exists() {
                eprintln!("Public key exists but private key is missing, cannot pull.");
                std::process::exit(1);
            }

            let signing_key =
                SigningKey::from_pkcs8_pem(&tokio::fs::read_to_string(&private_key_path).await?)
                    .context("Bad private key, cannot pull")?;

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
                    download_file_v1(
                        &file_id,
                        file_key,
                        dir,
                        &address,
                        port,
                        signing_key,
                        &mut alloc_mem,
                    )
                    .await?;

                    let catalog_path = get_catalog_path()?;

                    if catalog_path.exists() {
                        let mut catalog = Catalog::read_or_create(&catalog_path).await?;
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
        Some(ClientCommands::Backup { .. }) => {
            todo!("WIP backup feature")
        }
        Some(ClientCommands::Serve { .. }) => {
            todo!("Non-trivial to implement this feature")
        }
        Some(ClientCommands::Listen { .. }) => {
            todo!("Non-trivial to implement this feature")
        }
        Some(ClientCommands::Ls { .. }) => {
            let file_map = Catalog::read_or_create(&get_catalog_path()?).await.map_err(|e| {
                anyhow::anyhow!(
                    "Failed to read catalog, make sure to push at least one file before listing: {}",
                    e
                )
            })?;

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
        }) => {
            let user_path = get_user_key_dir()?;
            let private_key_path = user_path.join("private_key.pem");
            let public_key_path = user_path.join("public_key.pem");

            if !private_key_path.exists() && public_key_path.exists() {
                eprintln!("Public key exists but private key is missing, cannot status.");
                std::process::exit(1);
            }

            let signing_key =
                SigningKey::from_pkcs8_pem(&tokio::fs::read_to_string(&private_key_path).await?)
                    .context("Bad private key, cannot status")?;

            match protocol.as_str() {
                "v1" => {
                    let status =
                        get_server_status(&address, port, signing_key, &mut alloc_mem).await?;

                    println!("Status timestamp: {}", status.timestamp);
                    println!("Uptime: {} hrs", status.uptime_hrs);
                    println!("Total Auth client: {}", status.auth_client);
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
                    eprintln!("Unknown protocol: {}", protocol);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            ascii_art();
        }
    }

    Ok(())
}
