use aes::Aes256;
use aes::cipher::{Block, BlockCipherEncrypt, KeyInit};
use anyhow::Result;
use rand::Rng;
use sha2::Digest;
use sha2::Sha256;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 32;

/// Encrypt `data` with a 32-byte `key` using AES-256 CTR keystream XOR.
/// A random 12-byte nonce is generated and prepended to the output:
/// \[ nonce: 12 bytes ]\[ ciphertext: N bytes ]
///
#[inline]
pub fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    // generate random 12-byte nonce
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let ciphertext = aes256_ctr_xor(key, &nonce, data)?;

    let mut tag = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    tag.extend_from_slice(&nonce);
    tag.extend(&ciphertext);

    // TODO; using sha2 for now
    let tag_hash = Sha256::digest(&tag);

    // output; nonce || ciphertext || tag_hash
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len() + TAG_LEN);
    out.extend_from_slice(&nonce); // 12
    out.extend(&ciphertext); // ?
    out.extend_from_slice(&tag_hash); // 32
    Ok(out)
}

/// Decrypt `data` that was encrypted with [`encrypt_data`],
/// expects the first 12 bytes to be the nonce.
#[inline]
pub fn decrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if data.len() < TAG_LEN + NONCE_LEN {
        return Err(anyhow::anyhow!(
            "Ciphertext too short, must be at least {} bytes",
            TAG_LEN + NONCE_LEN
        ));
    }
    let nonce_end = NONCE_LEN;
    let tag_start = data.len() - TAG_LEN;

    let nonce: &[u8; NONCE_LEN] = data[..nonce_end].try_into()?;
    let ciphertext = &data[nonce_end..tag_start];
    let tag_hash = &data[tag_start..];

    let expected_tag_hash = {
        let mut tag = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        tag.extend_from_slice(nonce);
        tag.extend(ciphertext);
        Sha256::digest(&tag)
    };

    if tag_hash != expected_tag_hash.as_slice() {
        return Err(anyhow::anyhow!(
            "Tag hash mismatch, data may be corrupted or tampered with"
        ));
    }

    aes256_ctr_xor(key, nonce, ciphertext)
}

/// XOR `data` with an AES-256 CTR keystream derived from `key` and `nonce`.
#[inline(always)]
fn aes256_ctr_xor(key: &[u8; 32], nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256::new_from_slice(key)?;
    let mut output = Vec::with_capacity(data.len());
    let mut counter: u32 = 0;

    for chunk in data.chunks(16) {
        let mut counter_block = [0u8; 16];
        counter_block[..12].copy_from_slice(nonce);
        counter_block[12..].copy_from_slice(&counter.to_be_bytes());

        let mut block = Block::<Aes256>::from(counter_block);
        cipher.encrypt_block(&mut block);

        for (b, k) in chunk.iter().zip(block.iter()) {
            output.push(b ^ k);
        }

        counter = counter.wrapping_add(1);
    }

    Ok(output)
}

/// Hashes a slice of bytes and returns the hex string
#[inline(always)]
pub fn hash_chunk(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Generate a generic random 32-byte key and return it as a hex string
#[inline(always)]
pub fn generate_b32key() -> String {
    let mut rng = rand::rng();
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    hex::encode(key)
}

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

/// Generates and returns a new Ed25519 keypair as hex strings (private_key, public_key)
#[inline]
pub fn generate_ed25519_keypair() -> Result<(SigningKey, VerifyingKey)> {
    let mut rng = rand::rng();

    let private_key: SigningKey = SigningKey::generate(&mut rng);
    let public_key: VerifyingKey = private_key.verifying_key();

    // Little test
    let message = b"ed25519 key gen-test";
    let signature = private_key.sign(message);
    public_key
        .verify(message, &signature)
        .map_err(|e| anyhow::anyhow!("Failed to verify signature: {}", e))?;

    Ok((private_key, public_key))
}

use x25519_dalek::{EphemeralSecret, PublicKey};
/// Generates and returns a new X25519 keypair (private_key, public_key)
#[inline(always)]
pub fn generate_x25519_keypair() -> Result<(EphemeralSecret, PublicKey)> {
    let private_key = EphemeralSecret::random_from_rng(&mut rand::rng());
    let public_key = PublicKey::from(&private_key);
    Ok((private_key, public_key))
}

#[test]
fn crypto_test() -> Result<()> {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    let mut data = vec![0u8; 64 * 1024 * 1024];
    rand::rng().fill_bytes(&mut data);

    let encrypted = encrypt_data(&data, &key)?;
    assert_eq!(encrypted.len(), data.len() + NONCE_LEN + TAG_LEN);

    let decrypted = decrypt_data(&encrypted, &key)?;
    assert_eq!(decrypted, data);

    let data: &[u8] = b"";

    let encrypted = encrypt_data(data, &key)?;
    assert_eq!(encrypted.len(), NONCE_LEN + TAG_LEN);

    let decrypted = decrypt_data(&encrypted, &key)?;
    assert!(decrypted.is_empty());

    Ok(())
}
