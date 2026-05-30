//! # Local File Backend
//!
//! A `CloudVaultBackend` implementation that stores encrypted commits in a
//! local filesystem directory, mirroring the `.loomed/commits/` structure.
//!
//! ## Purpose
//!
//! `LocalFileBackend` is the Phase 2 reference backend. It proves the full
//! sync algorithm — push, status, and (in Phase 2 Session 2) Sync Rebase —
//! with zero cloud dependency and zero cost. The remote directory can be:
//!
//! - A path on the same machine (quick local testing)
//! - A network-mounted directory (NFS, SMB, SSHFS) for multi-device testing
//! - Any filesystem path accessible to the process
//!
//! When real cloud backends are added (Phase 2+), the sync algorithm, CLI
//! commands, and tests are unchanged — only a new `CloudVaultBackend` impl
//! is added. See spec §8.
//!
//! ## Remote Directory Structure
//!
//! ```text
//! <remote_path>/
//!   commits/
//!     <hash>.lmc    ← encrypted commit files, identical to local vault
//!   HEAD            ← latest commit_id, same format as local .loomed/HEAD
//! ```
//!
//! This structure mirrors the local vault and means any party with the
//! passphrase can open the remote as a standard `Vault` to inspect it.

use std::{
    fs,
    path::PathBuf,
};

use loomed_core::CommitHash;

use crate::{backend::CloudVaultBackend, error::SyncError};

const COMMITS_DIR: &str = "commits";
const COMMIT_EXT: &str = ".lmc";
const HEAD_FILE: &str = "HEAD";

/// A sync backend that stores encrypted commits in a local filesystem directory.
///
/// The remote directory is created automatically on construction if it does
/// not already exist. All operations are synchronous filesystem calls.
///
/// See the module-level documentation for the remote directory structure.
/// See spec §8.
pub struct LocalFileBackend {
    /// The root path of the remote vault directory.
    remote_path: PathBuf,
}

impl LocalFileBackend {
    /// Opens or creates a `LocalFileBackend` at the given path.
    ///
    /// Creates the `commits/` subdirectory if it does not already exist.
    /// If the path already contains a valid remote vault, it is opened
    /// as-is — no data is overwritten.
    ///
    /// # Arguments
    ///
    /// * `path` — The filesystem path to use as the remote vault root.
    ///
    /// # Errors
    ///
    /// * [`SyncError::RemoteWriteFailed`] — The directory could not be created.
    ///
    /// See spec §8.1.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, SyncError> {
        let remote_path = path.into();
        fs::create_dir_all(remote_path.join(COMMITS_DIR)).map_err(|e| {
            SyncError::RemoteWriteFailed {
                reason: format!("could not create remote directory: {}", e),
            }
        })?;
        Ok(Self { remote_path })
    }

    /// Returns the root path of this backend.
    ///
    /// Used by tests to inspect the backend directory structure.
    pub fn path(&self) -> &std::path::Path {
        &self.remote_path
    }
}

impl CloudVaultBackend for LocalFileBackend {
    /// Writes an encrypted commit file to the remote commits directory.
    ///
    /// The filename is derived from the commit_id by stripping the `sha256:`
    /// prefix and appending `.lmc`, matching the local vault convention.
    ///
    /// See spec §6 and §8.1.
    fn push_commit(&self, commit_id: &CommitHash, ciphertext: &[u8]) -> Result<(), SyncError> {
        let filename = commit_filename(commit_id);
        let path = self.remote_path.join(COMMITS_DIR).join(&filename);
        fs::write(&path, ciphertext).map_err(|e| SyncError::RemoteWriteFailed {
            reason: format!("writing commit {}: {}", commit_id.as_str(), e),
        })
    }

    /// Reads a raw encrypted commit file from the remote commits directory.
    ///
    /// See spec §6 and §8.1.
    fn pull_commit(&self, commit_id: &CommitHash) -> Result<Vec<u8>, SyncError> {
        let filename = commit_filename(commit_id);
        let path = self.remote_path.join(COMMITS_DIR).join(&filename);
        if !path.exists() {
            return Err(SyncError::RemoteCommitNotFound {
                commit_id: commit_id.as_str().to_string(),
            });
        }
        fs::read(&path).map_err(|e| SyncError::RemoteReadFailed {
            reason: format!("reading commit {}: {}", commit_id.as_str(), e),
        })
    }

    /// Lists all commit IDs present in the remote commits directory.
    ///
    /// Discovers commits by scanning for `.lmc` files. Order is not guaranteed.
    ///
    /// See spec §8.1.
    fn list_remote_commits(&self) -> Result<Vec<CommitHash>, SyncError> {
        let dir = self.remote_path.join(COMMITS_DIR);
        let mut ids = Vec::new();

        for entry in fs::read_dir(&dir).map_err(|e| SyncError::RemoteReadFailed {
            reason: format!("listing remote commits: {}", e),
        })? {
            let entry = entry.map_err(|e| SyncError::RemoteReadFailed {
                reason: format!("reading directory entry: {}", e),
            })?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(COMMIT_EXT) {
                let hash = name_str.trim_end_matches(COMMIT_EXT);
                ids.push(CommitHash(format!("sha256:{}", hash)));
            }
        }

        Ok(ids)
    }

    /// Writes the commit_id to the remote HEAD file.
    ///
    /// HEAD is updated after all commits for a push are written, ensuring
    /// the remote HEAD always points to a commit that exists on the remote.
    ///
    /// See spec §8.1.
    fn push_head(&self, commit_id: &CommitHash) -> Result<(), SyncError> {
        let path = self.remote_path.join(HEAD_FILE);
        fs::write(&path, commit_id.as_str()).map_err(|e| SyncError::RemoteWriteFailed {
            reason: format!("updating remote HEAD: {}", e),
        })
    }

    /// Reads the commit_id from the remote HEAD file.
    ///
    /// Returns `None` if no HEAD file exists (remote is empty).
    ///
    /// See spec §8.1.
    fn pull_head(&self) -> Result<Option<CommitHash>, SyncError> {
        let path = self.remote_path.join(HEAD_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path).map_err(|e| SyncError::RemoteReadFailed {
            reason: format!("reading remote HEAD: {}", e),
        })?;
        let trimmed = content.trim().to_string();
        if trimmed.is_empty() {
            return Ok(None);
        }
        Ok(Some(CommitHash(trimmed)))
    }
}

/// Derives the remote filename for a commit from its commit_id.
///
/// Strips the `sha256:` prefix and appends `.lmc`, matching the local
/// vault file naming convention in `loomed-store`.
fn commit_filename(commit_id: &CommitHash) -> String {
    format!(
        "{}{}",
        commit_id.as_str().replace("sha256:", ""),
        COMMIT_EXT
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    fn fake_commit_id() -> CommitHash {
        CommitHash(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
        )
    }

    /// Spec §8.1: LocalFileBackend::new must create the remote commits directory.
    #[test]
    fn new_creates_remote_commits_directory() {
        let dir = temp_dir();
        let backend = LocalFileBackend::new(dir.path()).unwrap();
        assert!(backend.path().join("commits").exists());
    }

    /// Spec §8.1: A commit pushed to the backend must be retrievable with pull_commit.
    #[test]
    fn push_and_pull_commit_roundtrip() {
        let dir = temp_dir();
        let backend = LocalFileBackend::new(dir.path()).unwrap();
        let id = fake_commit_id();
        let ciphertext = b"fake encrypted commit bytes";

        backend.push_commit(&id, ciphertext).unwrap();
        let retrieved = backend.pull_commit(&id).unwrap();

        assert_eq!(retrieved, ciphertext);
    }

    /// Spec §8.1: list_remote_commits must return one entry per pushed commit.
    #[test]
    fn list_remote_commits_returns_pushed_commits() {
        let dir = temp_dir();
        let backend = LocalFileBackend::new(dir.path()).unwrap();
        let id = fake_commit_id();

        assert!(backend.list_remote_commits().unwrap().is_empty());
        backend.push_commit(&id, b"data").unwrap();
        let ids = backend.list_remote_commits().unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], id);
    }

    /// Spec §8.1: pull_commit for a commit_id not on the remote must return
    /// RemoteCommitNotFound.
    #[test]
    fn pull_commit_returns_not_found_for_missing_commit() {
        let dir = temp_dir();
        let backend = LocalFileBackend::new(dir.path()).unwrap();
        let id = fake_commit_id();

        let result = backend.pull_commit(&id);
        assert!(matches!(result, Err(SyncError::RemoteCommitNotFound { .. })));
    }

    /// Spec §8.1: push_head and pull_head must roundtrip the HEAD commit_id.
    #[test]
    fn push_and_pull_head_roundtrip() {
        let dir = temp_dir();
        let backend = LocalFileBackend::new(dir.path()).unwrap();
        let id = fake_commit_id();

        assert!(backend.pull_head().unwrap().is_none());
        backend.push_head(&id).unwrap();
        assert_eq!(backend.pull_head().unwrap().unwrap(), id);
    }
}
