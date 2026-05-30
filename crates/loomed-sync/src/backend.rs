//! # Cloud Vault Backend Trait
//!
//! The abstraction over all remote storage targets for LooMed vault sync.
//!
//! ## Design
//!
//! LooMed is backend-agnostic. The protocol does not dictate which cloud
//! provider stores the encrypted commits — only that the backend can
//! store and retrieve opaque ciphertext blobs addressed by commit_id.
//!
//! The interface is intentionally minimal:
//! - Push/pull individual encrypted commit files
//! - List which commits are present on the remote
//! - Push/pull the HEAD pointer
//!
//! The backend never sees plaintext. It stores and retrieves the exact
//! bytes written by `loomed-store::Vault::write_commit`. All encryption
//! and decryption happens in `loomed-crypto` before reaching the sync layer.
//!
//! ## Implementations
//!
//! Phase 2: `LocalFileBackend` — a local filesystem directory.
//!          Proves the sync algorithm without any cloud dependency.
//! Future:  S3Backend, GCSBackend, AzureBackend — same trait, different
//!          underlying client. The CLI and sync layer are unchanged.
//!
//! See spec §8 and §5.

use loomed_core::CommitHash;
use crate::error::SyncError;

/// The interface all sync backends must implement.
///
/// Every method operates on encrypted bytes — the backend never sees or
/// processes plaintext data. It is a dumb blob store addressed by commit_id.
///
/// The trait is object-safe to allow runtime dispatch (`Box<dyn CloudVaultBackend>`)
/// for future CLI backends selectable at runtime.
///
/// See spec §8 and §5.
pub trait CloudVaultBackend {
    /// Uploads a single encrypted commit file to the remote backend.
    ///
    /// # Arguments
    ///
    /// * `commit_id` — The commit_id, used to derive the remote filename.
    /// * `ciphertext` — The raw AES-256-GCM encrypted bytes from `vault.lmc`.
    ///
    /// # Errors
    ///
    /// * [`SyncError::RemoteWriteFailed`] — The remote could not be written.
    fn push_commit(&self, commit_id: &CommitHash, ciphertext: &[u8]) -> Result<(), SyncError>;

    /// Downloads a single encrypted commit file from the remote backend.
    ///
    /// # Arguments
    ///
    /// * `commit_id` — The commit_id to fetch.
    ///
    /// # Returns
    ///
    /// The raw encrypted bytes, identical to what was pushed.
    ///
    /// # Errors
    ///
    /// * [`SyncError::RemoteCommitNotFound`] — The commit_id is not on the remote.
    /// * [`SyncError::RemoteReadFailed`] — The remote could not be read.
    fn pull_commit(&self, commit_id: &CommitHash) -> Result<Vec<u8>, SyncError>;

    /// Lists all commit IDs present on the remote backend.
    ///
    /// Used by `SyncManager` to compute the diff between local and remote
    /// before a push or status check.
    ///
    /// # Errors
    ///
    /// * [`SyncError::RemoteReadFailed`] — The remote directory could not be listed.
    fn list_remote_commits(&self) -> Result<Vec<CommitHash>, SyncError>;

    /// Updates the remote HEAD pointer to the given commit_id.
    ///
    /// HEAD is updated after all commits have been pushed, ensuring the
    /// remote HEAD always points to a commit that is present on the remote.
    ///
    /// # Errors
    ///
    /// * [`SyncError::RemoteWriteFailed`] — The HEAD file could not be written.
    fn push_head(&self, commit_id: &CommitHash) -> Result<(), SyncError>;

    /// Reads the remote HEAD pointer.
    ///
    /// Returns `None` if the remote is empty (no commits pushed yet).
    ///
    /// # Errors
    ///
    /// * [`SyncError::RemoteReadFailed`] — The HEAD file could not be read.
    fn pull_head(&self) -> Result<Option<CommitHash>, SyncError>;
}
