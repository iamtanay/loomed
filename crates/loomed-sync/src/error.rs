//! # Sync Error Taxonomy
//!
//! All errors that can occur during LooMed vault sync operations.
//!
//! See spec §8.

use loomed_store::StoreError;

/// All errors that can occur during a sync operation.
///
/// Distinct from [`StoreError`] (local vault I/O) — `SyncError` covers
/// the communication layer between the local vault and the remote backend.
/// See spec §8.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// No sync remote has been configured for this vault.
    ///
    /// Run `loomed remote set <path>` to configure one. See spec §8.1.
    #[error("no sync remote configured — run `loomed remote set <path>` first")]
    RemoteNotConfigured,

    /// The remote backend directory or resource does not exist.
    ///
    /// See spec §8.1.
    #[error("remote not found at \"{path}\"")]
    RemoteNotFound {
        /// The path or URI where the remote was expected.
        path: String,
    },

    /// A commit file could not be found on the remote backend.
    ///
    /// See spec §8.1.
    #[error("commit not found on remote: {commit_id}")]
    RemoteCommitNotFound {
        /// The commit_id that was not found on the remote.
        commit_id: String,
    },

    /// A write to the remote backend failed.
    ///
    /// See spec §8.1.
    #[error("remote write failed: {reason}")]
    RemoteWriteFailed {
        /// The reason the write failed.
        reason: String,
    },

    /// A read from the remote backend failed.
    ///
    /// See spec §8.1.
    #[error("remote read failed: {reason}")]
    RemoteReadFailed {
        /// The reason the read failed.
        reason: String,
    },

    /// An error in the local vault store during a sync operation.
    ///
    /// Wraps [`StoreError`] so callers can handle sync errors uniformly.
    #[error("vault error: {0}")]
    Store(#[from] StoreError),

    /// An I/O error during a sync operation.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
