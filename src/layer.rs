use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufWriter};
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
    pub layer_meta: LayerMeta,
}

pub struct LayerMeta {
    pub hash: String,
    pub mem_offset: usize,
}

/// Reads a file in chunks of `LAYER_SIZE`, creates layer metadata and does NOT store the actual data in memory
pub async fn read_file_layers(mut buf_reader: BufReader<File>) -> Result<Vec<LayerMeta>> {
    let mut layers_meta = Vec::with_capacity(8);
    let mut mem_offset = 0usize;

    loop {
        let mut buffer = vec![0u8; LAYER_SIZE];
        let mut hasher = Sha256::new();
        let mut read_idx = 0;

        while read_idx < LAYER_SIZE {
            let n = buf_reader.read(&mut buffer[read_idx..]).await?;

            if n == 0 {
                break;
            }

            hasher.update(&buffer[read_idx..read_idx + n]);
            read_idx += n;
        }

        if read_idx == 0 {
            break;
        }

        layers_meta.push(LayerMeta {
            hash: hex::encode(hasher.finalize()),
            mem_offset,
        });

        mem_offset += read_idx;
    }

    Ok(layers_meta)
}

/// Reads a file in chunks of `LAYER_SIZE` at `mem_offset`, and returns a layer
/// returns None if the offset is beyond EOF, otherwise returns the layer with file data and metadata
pub async fn read_data_layer(
    mut buf_reader: BufReader<File>,
    mem_offset: usize,
) -> Result<Option<Layer>> {
    let mut buffer = vec![0u8; LAYER_SIZE];

    buf_reader.seek(SeekFrom::Start(mem_offset as u64)).await?;

    let mut read_ptr = 0;
    let mut hasher = Sha256::new();

    while read_ptr < LAYER_SIZE {
        let n = buf_reader.read(&mut buffer[read_ptr..]).await?;

        if n == 0 {
            break;
        }

        hasher.update(&buffer[read_ptr..read_ptr + n]);
        read_ptr += n;
    }

    // offset beyond EOF
    if read_ptr == 0 {
        return Ok(None);
    }

    buffer.truncate(read_ptr);

    Ok(Some(Layer {
        data: buffer,
        layer_meta: LayerMeta {
            hash: hex::encode(hasher.finalize()),
            mem_offset,
        },
    }))
}

/// Reads a file in chunks of `LAYER_SIZE`, creates layers with their hash and offset
/// EXPERIMENT: only for testing, not used in protocol, because we don't want to store the actual data in memory
pub async fn to_layers(mut buf_reader: BufReader<File>) -> Result<Vec<Layer>> {
    let mut layers = Vec::new();
    let mut mem_offset = 0;

    loop {
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; LAYER_SIZE];
        let mut bytes_read = 0;

        while bytes_read < LAYER_SIZE {
            let n = buf_reader
                .read(&mut buffer[bytes_read..])
                .await
                .context("failed to read chunk")?;

            if n == 0 {
                break;
            }

            hasher.update(&buffer[bytes_read..bytes_read + n]);
            bytes_read += n;
        }

        if bytes_read == 0 {
            break;
        }

        buffer.truncate(bytes_read); // truncate if new layer is smaller than LAYER_SIZE
        layers.push(Layer {
            data: buffer,
            layer_meta: LayerMeta {
                hash: hex::encode(hasher.finalize()),
                mem_offset,
            },
        });

        mem_offset += bytes_read;
    }

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

    let mut writer = BufWriter::with_capacity(LAYER_SIZE * 2, file);

    // already sorted, we can ignore mem_offset while writing
    layers.sort_by_key(|layer| layer.layer_meta.mem_offset);
    for layer in layers.iter() {
        // writer.flush().await?;
        // writer
        //     .get_mut()
        //     .seek(SeekFrom::Start(layer.layer_meta.mem_offset as u64))
        //     .await?;
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
            des_layer.layer_meta.mem_offset == src_layer.layer_meta.mem_offset
                && des_layer.layer_meta.hash == src_layer.layer_meta.hash
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
    use crate::file_hasher_async;
    use rand::Rng;
    let mut rng = rand::rng();
    let mut file_data = vec![0u8; 256 * 1024 * 1024];
    rng.fill_bytes(&mut file_data);
    tokio::fs::write("old.bin", &file_data).await.unwrap();

    let buf_file = BufReader::new(File::open("old.bin").await.unwrap());
    let old_hash = file_hasher_async("old.bin".as_ref()).await.unwrap();
    println!("hash of old file: {}", old_hash);
    let mut old_layers = to_layers(buf_file).await.unwrap();

    println!("hash of old layers:");
    for (i, layer) in old_layers.iter().enumerate() {
        println!(
            "Layer {}: hash={}, offset={}, size={}",
            i,
            layer.layer_meta.hash,
            layer.layer_meta.mem_offset,
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

    //from_layer test
    from_layers(&mut old_layers, "reconstructed.bin".as_ref())
        .await
        .unwrap();
    let reconstructed_hash = file_hasher_async("reconstructed.bin".as_ref())
        .await
        .unwrap();
    println!("hash of reconstructed file: {}", reconstructed_hash);
    assert_eq!(old_hash, reconstructed_hash);

    tokio::fs::remove_file("reconstructed.bin").await.unwrap();

    // randomize again
    rng.fill_bytes(&mut file_data);
    tokio::fs::write("new.bin", &file_data).await.unwrap();
    let buf_file = BufReader::new(File::open("new.bin").await.unwrap());
    let new_layers = to_layers(buf_file).await.unwrap();

    println!("hash of new layers:");
    for (i, layer) in new_layers.iter().enumerate() {
        println!(
            "Layer {}: hash={}, offset={}, size={}",
            i,
            layer.layer_meta.hash,
            layer.layer_meta.mem_offset,
            layer.data.len()
        );
    }

    let changed_layers = compare_layers(old_layers, &new_layers).unwrap();

    println!("Changed layers:");
    for (i, layer) in changed_layers.iter().enumerate() {
        println!(
            "Layer {}: hash={}, offset={}, size={}",
            i,
            layer.layer_meta.hash,
            layer.layer_meta.mem_offset,
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
