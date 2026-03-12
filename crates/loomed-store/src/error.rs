//! # Store Error Taxonomy
//!
//! All errors that can occur during LooMed vault storage operations.

/// All errors that can occur in the LooMed storage layer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The vault directory was not found at the expected path.
    ///
    /// Run `loomed init` to initialise a vault first.
    #[error("vault not found at {path}")]
    VaultNotFound {
        /// The path where the vault was expected.
        path: String,
    },

    /// The vault has already been initialised at this path.
    ///
    /// Each directory can only contain one vault.
    #[error("vault already initialised at {path}")]
    VaultAlreadyExists {
        /// The path where the vault already exists.
        path: String,
    },

    /// A commit file could not be written to disk.
    #[error("failed to write commit {commit_id}: {reason}")]
    CommitWriteFailed {
        /// The commit_id of the commit that failed to write.
        commit_id: String,
        /// The reason the write failed.
        reason: String,
    },

    /// A commit file could not be read from disk.
    #[error("failed to read commit {commit_id}: {reason}")]
    CommitReadFailed {
        /// The commit_id of the commit that failed to read.
        commit_id: String,
        /// The reason the read failed.
        reason: String,
    },

    /// The vault metadata file (vault.toml) could not be read or parsed.
    #[error("failed to read vault metadata: {reason}")]
    MetadataReadFailed {
        /// The reason the metadata read failed.
        reason: String,
    },

    /// The vault metadata file (vault.toml) could not be written.
    #[error("failed to write vault metadata: {reason}")]
    MetadataWriteFailed {
        /// The reason the metadata write failed.
        reason: String,
    },

    /// A commit file on disk failed decryption.
    ///
    /// This typically means the passphrase was incorrect.
    #[error("decryption failed for commit {commit_id}: incorrect passphrase or tampered file")]
    DecryptionFailed {
        /// The commit_id of the commit that failed to decrypt.
        commit_id: String,
    },

    /// A commit's JSON could not be deserialised after decryption.
    #[error("failed to deserialise commit {commit_id}: {reason}")]
    DeserialisationFailed {
        /// The commit_id of the commit that failed to deserialise.
        commit_id: String,
        /// The reason deserialisation failed.
        reason: String,
    },

    /// The hash chain is broken at the specified commit.
    ///
    /// See spec §7.
    #[error("chain integrity failure at commit {commit_id}: expected {expected}, found {found}")]
    ChainIntegrityFailure {
        /// The commit_id where the chain break was detected.
        commit_id: String,
        /// The previous_hash value that was expected.
        expected: String,
        /// The previous_hash value that was found.
        found: String,
    },

    /// An I/O error occurred during a file operation.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}