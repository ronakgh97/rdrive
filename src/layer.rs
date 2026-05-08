use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::io::{BufReader, SeekFrom};

// TODO: EXPERIMENT, WILL CHANGE LATER,
//  Protocol design need a change to implement this, we need CAS (Content Addressable Storage) to make this work,
//  which means we need to store the layers in a separate file and use hash as the filename,
//  then we can just upload the changed layers and server will match the offset & compare hash from metadata file,
//  if changes, we can just overwrite or write new <hash>.bin file(spoilers warning: versioning) and finally update metadata file
//  Some like this
//   storage/
//   ├ fileA (file_uuid)/
//   │   ├ chunk1 (layer hash)
//   │   ├ chunk2 (layer hash)
//   |   ├ metadata (store file_name, file_size, file_full_hash, map<ptr_offset, layer_hash>)
//   │
//   ├ fileB(file_uuid)/
//   │   ├ chunk1  (layer hash)
//   │   ├ chunk2 (layer hash)
//   |   ├ metadata (store file_name, file_size, file_full_hash, map<ptr_offset, layer_hash>)

const LAYER_SIZE: usize = 1024 * 1024 * 64;

pub struct Layer {
    pub data: Vec<u8>,
    pub hash: String,
    pub mem_offset: usize,
}

/// Reads a file in chunks of `LAYER_SIZE`, creates layers with their hash and offset
/// EXPERIMENT: this is bad, since its layer file into vec memory
pub async fn to_layers(mut buf_file: BufReader<File>) -> Result<Vec<Layer>> {
    let mut layers: Vec<Layer> = Vec::new();
    let mut layer_buffer = vec![0u8; LAYER_SIZE];
    let mut mem_idx = 0usize;

    loop {
        // read up to layer_size, partially filled buffer is expected for last layer or small file
        let mut read_ptr = 0usize;
        while read_ptr < layer_buffer.len() {
            let n = buf_file
                .read(&mut layer_buffer[read_ptr..])
                .await
                .context("Failed to read chunk")?;
            if n == 0 {
                break;
            }
            read_ptr += n;
        }

        if read_ptr == 0 {
            break; // EOF
        }

        let layer_data = layer_buffer[..read_ptr].to_vec();
        let mut hasher = Sha256::new();
        hasher.update(&layer_data);
        let layer_hash = hex::encode(hasher.finalize());

        layers.push(Layer {
            data: layer_data,
            hash: layer_hash,
            mem_offset: mem_idx,
        });

        mem_idx += read_ptr;
    }

    layers.sort_by_key(|layer| layer.mem_offset);

    Ok(layers)
}

/// Takes the layers, sorts them by their offset, and writes them back to a file at the correct positions
/// EXPERIMENT: only for testing, not used in protocol
pub async fn from_layers(layers: &mut [Layer], write_path: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true) // overwrite if it already exists
        .open(write_path)
        .await
        .context("Failed to create output file")?;

    let mut writer = tokio::io::BufWriter::with_capacity(LAYER_SIZE * 2, file);

    layers.sort_by_key(|layer| layer.mem_offset);

    for layer in layers.iter() {
        // flush any pending buffered data before seeking the underlying file
        writer.flush().await?;
        writer
            .get_mut()
            .seek(SeekFrom::Start(layer.mem_offset as u64))
            .await?;
        writer.write_all(&layer.data).await?;
    }

    writer.flush().await?;

    // reset the file pointer to the beginning before returning, just in case
    writer.get_mut().seek(SeekFrom::Start(0)).await?;
    Ok(())
}

/// Compares the source layers with the destination layers and identifies which layers have changed.
/// returns ONLY the layers that the server is changed and needed a re-upload.
/// EXPERIMENT: only for testing
pub fn compare_layers(src: Vec<Layer>, des: &[Layer]) -> Result<Vec<Layer>> {
    let mut changed_layer = Vec::new();

    for src_layer in src {
        // Look for a layer in `des` that matches the exact offset AND hash
        let is_changed = des.iter().any(|des_layer| {
            des_layer.mem_offset == src_layer.mem_offset && des_layer.hash == src_layer.hash
        });

        // If the server doesn't have it, we need to upload it!
        if !is_changed {
            changed_layer.push(src_layer);
        }
    }

    Ok(changed_layer)
}

#[tokio::test]
async fn experimental_layer_test() {
    use rand::Rng;
    let mut rng = rand::rng();
    let mut file_data = vec![0u8; 256 * 1024 * 1024];
    rng.fill_bytes(&mut file_data);
    tokio::fs::write("old.bin", &file_data).await.unwrap();

    let buf_file = BufReader::new(File::open("old.bin").await.unwrap());
    let old_layers = to_layers(buf_file).await.unwrap();

    println!("hash of old layers:");
    for (i, layer) in old_layers.iter().enumerate() {
        println!(
            "Layer {}: hash={}, offset={}, size={}",
            i,
            layer.hash,
            layer.mem_offset,
            layer.data.len()
        );
    }

    assert!(!old_layers.is_empty());
    assert_eq!(
        old_layers
            .iter()
            .map(|layer| layer.data.len())
            .sum::<usize>(),
        file_data.len()
    );

    rng.fill_bytes(&mut file_data);
    tokio::fs::write("new.bin", &file_data).await.unwrap();
    let buf_file = BufReader::new(File::open("new.bin").await.unwrap());
    let new_layers = to_layers(buf_file).await.unwrap();

    println!("hash of new layers:");
    for (i, layer) in new_layers.iter().enumerate() {
        println!(
            "Layer {}: hash={}, offset={}, size={}",
            i,
            layer.hash,
            layer.mem_offset,
            layer.data.len()
        );
    }

    let changed_layers = compare_layers(old_layers, &new_layers).unwrap();

    println!("Changed layers:");
    for (i, layer) in changed_layers.iter().enumerate() {
        println!(
            "Layer {}: hash={}, offset={}, size={}",
            i,
            layer.hash,
            layer.mem_offset,
            layer.data.len()
        );
    }

    assert!(!changed_layers.is_empty());
    assert_eq!(
        changed_layers
            .iter()
            .map(|layer| layer.data.len())
            .sum::<usize>(),
        file_data.len()
    );

    tokio::fs::remove_file("old.bin").await.unwrap();
    tokio::fs::remove_file("new.bin").await.unwrap();
}
