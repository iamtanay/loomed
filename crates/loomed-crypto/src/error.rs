//! # Crypto Error Taxonomy
//!
//! All errors that can occur during LooMed cryptographic operations.

/// All errors that can occur in the LooMed cryptographic layer.
///
/// These are distinct from `LooMedError` in `loomed-core`. Cryptographic
/// errors are low-level failures in primitive operations. The protocol
/// layer translates these into protocol-level errors where appropriate.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// An ed25519 signature failed verification.
    ///
    /// Either the message was modified after signing, or the wrong
    /// public key was used for verification.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// AES-256-GCM decryption failed.
    ///
    /// This typically means the passphrase-derived key was incorrect,
    /// or the ciphertext was tampered with.
    #[error("decryption failed: invalid key or tampered ciphertext")]
    DecryptionFailed,

    /// AES-256-GCM encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,

    /// Serialisation of an object failed prior to hashing or signing.
    #[error("serialisation failed: {reason}")]
    SerializationFailed {
        /// The reason serialisation failed.
        reason: String,
    },

    /// A key derivation operation failed.
    #[error("key derivation failed: {reason}")]
    KeyDerivationFailed {
        /// The reason key derivation failed.
        reason: String,
    },
}