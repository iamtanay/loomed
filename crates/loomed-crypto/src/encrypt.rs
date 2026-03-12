//! # Vault Encryption
//!
//! Passphrase-to-key derivation and AES-256-GCM encryption of vault files.
//!
//! ## Responsibilities
//! - Deriving an AES-256 key from a passphrase using Argon2id (Phase 1)
//! - Encrypting commit files with AES-256-GCM before writing to disk
//! - Decrypting commit files after reading from disk
//!
//! ## Not Responsible For
//! - File I/O (see `loomed-store`)
//! - Key storage (see `loomed-store`)
//! - Identity provider key binding (spec §4, future: `loomed-idp`)

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};

use crate::error::CryptoError;

/// The byte length of an AES-256 key.
const AES_KEY_LEN: usize = 32;

/// The byte length of an AES-GCM nonce.
const NONCE_LEN: usize = 12;

/// Derives a 32-byte AES-256 key from a passphrase and salt using Argon2id.
///
/// Argon2id is a memory-hard key derivation function that resists both
/// GPU-based and side-channel attacks. It is the recommended KDF for
/// passphrase-based encryption in Phase 1 of LooMed.
///
/// The salt must be stored alongside the encrypted data and passed back
/// into this function during decryption to reproduce the same key.
///
/// # Arguments
///
/// * `passphrase` — The user's passphrase as a byte slice.
/// * `salt` — A 16-byte random salt. Generate once per vault and store
///   in `vault.toml`. Must be the same salt used during encryption.
///
/// # Returns
///
/// A 32-byte key suitable for AES-256-GCM encryption.
///
/// # Errors
///
/// * [`CryptoError::KeyDerivationFailed`] — Argon2id failed to derive
///   a key from the provided passphrase and salt.
pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; AES_KEY_LEN], CryptoError> {
    let salt_str = SaltString::encode_b64(salt).map_err(|e| CryptoError::KeyDerivationFailed {
        reason: e.to_string(),
    })?;

    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(passphrase, &salt_str)
        .map_err(|e| CryptoError::KeyDerivationFailed {
            reason: e.to_string(),
        })?;

    let hash_bytes = hash.hash.ok_or(CryptoError::KeyDerivationFailed {
        reason: "argon2 produced no hash output".to_string(),
    })?;

    let bytes = hash_bytes.as_bytes();
    if bytes.len() < AES_KEY_LEN {
        return Err(CryptoError::KeyDerivationFailed {
            reason: format!("hash output too short: {} bytes", bytes.len()),
        });
    }

    let mut key = [0u8; AES_KEY_LEN];
    key.copy_from_slice(&bytes[..AES_KEY_LEN]);
    Ok(key)
}

/// Encrypts plaintext using AES-256-GCM with a freshly generated nonce.
///
/// A random 12-byte nonce is generated for every encryption call. The nonce
/// is prepended to the ciphertext in the returned bytes. The caller must
/// store the full returned bytes — nonce + ciphertext — and pass them
/// unchanged to `decrypt()`.
///
/// # Arguments
///
/// * `key` — A 32-byte AES-256 key, typically derived via `derive_key()`.
/// * `plaintext` — The data to encrypt.
///
/// # Returns
///
/// A `Vec<u8>` containing the 12-byte nonce followed by the ciphertext.
///
/// # Errors
///
/// * [`CryptoError::EncryptionFailed`] — AES-GCM encryption failed.
pub fn encrypt(key: &[u8; AES_KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypts AES-256-GCM ciphertext produced by `encrypt()`.
///
/// The input must be the full byte sequence returned by `encrypt()` —
/// the 12-byte nonce followed by the ciphertext. The key must be
/// identical to the key used during encryption.
///
/// # Arguments
///
/// * `key` — A 32-byte AES-256 key, identical to the one used in `encrypt()`.
/// * `nonce_and_ciphertext` — The full output from `encrypt()`.
///
/// # Returns
///
/// The decrypted plaintext as a `Vec<u8>`.
///
/// # Errors
///
/// * [`CryptoError::DecryptionFailed`] — The key was wrong or the
///   ciphertext was tampered with.
pub fn decrypt(
    key: &[u8; AES_KEY_LEN],
    nonce_and_ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if nonce_and_ciphertext.len() < NONCE_LEN {
        return Err(CryptoError::DecryptionFailed);
    }

    let (nonce_bytes, ciphertext) = nonce_and_ciphertext.split_at(NONCE_LEN);
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Encryption and decryption roundtrip must recover the original plaintext.
    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let plaintext = b"test commit data";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Decryption with the wrong key must fail.
    #[test]
    fn wrong_key_fails_decryption() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let plaintext = b"test commit data";
        let encrypted = encrypt(&key1, plaintext).unwrap();
        assert!(decrypt(&key2, &encrypted).is_err());
    }

    /// Tampered ciphertext must fail decryption.
    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let key = [0u8; 32];
        let plaintext = b"test commit data";
        let mut encrypted = encrypt(&key, plaintext).unwrap();
        encrypted[15] ^= 0xFF;
        assert!(decrypt(&key, &encrypted).is_err());
    }

    /// derive_key must produce a 32-byte key.
    #[test]
    fn derive_key_produces_correct_length() {
        let passphrase = b"my secure passphrase";
        let salt = b"randomsalt123456";
        let key = derive_key(passphrase, salt).unwrap();
        assert_eq!(key.len(), 32);
    }

    /// derive_key must be deterministic — same inputs produce same key.
    #[test]
    fn derive_key_is_deterministic() {
        let passphrase = b"my secure passphrase";
        let salt = b"randomsalt123456";
        let key1 = derive_key(passphrase, salt).unwrap();
        let key2 = derive_key(passphrase, salt).unwrap();
        assert_eq!(key1, key2);
    }
}