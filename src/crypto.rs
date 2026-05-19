use aes_gcm::aead::Aead;
use aes_gcm::{AeadInOut, Aes256Gcm, Tag};
use aes_gcm::{KeyInit, Nonce};
use anyhow::Result;
use rand::Rng;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Encrypt `data` with a 32-byte `key` using AES-256-GCM,
/// generates a random 12-byte nonce, and returns the output as:
/// \[ nonce: 12 bytes ]\[ ciphertext: N bytes ]
///
#[inline]
pub fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    // generate random 12-byte nonce
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);

    let cipher = Aes256Gcm::new(key.into());

    let ciphertext = cipher
        .encrypt(&nonce.into(), data)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // output; nonce || ciphertext || tag
    let mut out = vec![0u8; NONCE_LEN + ciphertext.len()];
    out[..NONCE_LEN].copy_from_slice(&nonce);
    out[NONCE_LEN..].copy_from_slice(&ciphertext); // aes-gcm add extra 12 bytes for tag
    Ok(out)
}

/// Decrypt `data` that was encrypted with [`encrypt_data`],
/// expects the first 12 bytes to be the nonce.
#[inline]
pub fn decrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        anyhow::bail!("Ciphertext too short");
    }

    let (nonce, ciphertext) = data.split_at(NONCE_LEN);

    let nonce = Nonce::try_from(nonce)?;
    let cipher = Aes256Gcm::new(key.into());

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
    Ok(plaintext)
}

// TODO; fucking hell this fn sucks!!!!
#[inline(always)]
pub fn encrypt_data_in_place(buffer: &mut Vec<u8>, key: &[u8; 32]) -> Result<()> {
    let plaintext_len = buffer.len();

    // alloc space for nonce + tag
    buffer.reserve(NONCE_LEN + TAG_LEN);
    // move data between [NONCE...TAG_LEN]
    buffer.resize(NONCE_LEN + plaintext_len + TAG_LEN, 0);
    // copy data from front to the nonce_end
    buffer.copy_within(0..plaintext_len, NONCE_LEN);

    // fill nonce in the front overwriting the plaintext
    rand::rng().fill_bytes(&mut buffer[..NONCE_LEN]);

    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::try_from(&buffer[..NONCE_LEN])?;
    let data = &mut buffer[NONCE_LEN..NONCE_LEN + plaintext_len];

    let tag = cipher
        .encrypt_inout_detached(&nonce, b"", data.into())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // copy tag attach to end
    buffer[NONCE_LEN + plaintext_len..].copy_from_slice(&tag);

    Ok(())
}

#[inline(always)]
pub fn decrypt_data_in_place(buffer: &mut Vec<u8>, key: &[u8; 32]) -> Result<()> {
    if buffer.len() < NONCE_LEN + TAG_LEN {
        anyhow::bail!("Ciphertext too short");
    }

    let total_len = buffer.len();

    let ciphertext_len = total_len - NONCE_LEN - TAG_LEN;
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::try_from(&buffer[..NONCE_LEN])?;

    // extract tag
    let tag = Tag::try_from(&buffer[NONCE_LEN + ciphertext_len..])?;
    // Ciphertext region only
    let data = &mut buffer[NONCE_LEN..NONCE_LEN + ciphertext_len];

    cipher
        .decrypt_inout_detached(&nonce, b"", data.into(), &tag)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;

    // move plaintext back to front
    buffer.copy_within(NONCE_LEN..NONCE_LEN + ciphertext_len, 0);
    // remove nonce + tag
    buffer.truncate(ciphertext_len);

    Ok(())
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

#[test]
fn crypto_in_place_test() -> Result<()> {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);

    let mut data = vec![0u8; 64 * 1024 * 1024];
    rand::rng().fill_bytes(&mut data);

    let original = data.clone();
    encrypt_data_in_place(&mut data, &key)?;
    assert_eq!(data.len(), original.len() + NONCE_LEN + TAG_LEN);

    decrypt_data_in_place(&mut data, &key)?;
    assert_eq!(data, original);

    let mut empty = Vec::new();
    encrypt_data_in_place(&mut empty, &key)?;
    assert_eq!(empty.len(), NONCE_LEN + TAG_LEN);

    decrypt_data_in_place(&mut empty, &key)?;
    assert!(empty.is_empty());

    Ok(())
}
