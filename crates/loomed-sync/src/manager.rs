//! # Sync Manager
//!
//! Orchestrates sync between a local LooMed vault and a remote backend.
//!
//! ## Responsibilities
//! - Computing which commits are local-only (not yet on remote)
//! - Pushing missing commits to the remote backend
//! - Updating the remote HEAD after a successful push
//! - Reporting sync status without side effects
//!
//! ## Not Responsible For
//! - Cryptography — transfers raw encrypted bytes between vault and backend
//! - Conflict resolution (Sync Rebase) — Phase 2 Session 2
//! - Pull / fetch from remote to local — Phase 2 Session 2
//!
//! ## Push Algorithm (spec §8.1)
//!
//! ```text
//! 1. list_local  = Vault::list_commit_ids()
//! 2. list_remote = backend.list_remote_commits()
//! 3. to_push     = list_local − list_remote  (set difference)
//! 4. for each id in to_push:
//!      bytes = Vault::read_commit_raw(id)   ← encrypted, no passphrase needed
//!      backend.push_commit(id, bytes)
//! 5. if local HEAD is set: backend.push_head(local_head)
//! 6. return SyncReport { pushed, already_remote }
//! ```
//!
//! No passphrase is required for push — only encrypted bytes are transferred.
//! See spec §8.

use std::collections::HashSet;

use loomed_store::Vault;

use crate::{backend::CloudVaultBackend, error::SyncError};
use loomed_core::CommitHash;

/// The result of a successful sync push operation.
///
/// Returned by [`SyncManager::push`]. Summarises what was transferred.
///
/// See spec §8.1.
#[derive(Debug)]
pub struct SyncReport {
    /// The commit_ids that were pushed to the remote during this operation.
    pub pushed: Vec<CommitHash>,

    /// The number of commits that were already on the remote (not re-pushed).
    pub already_remote: usize,
}

/// The result of a sync status check.
///
/// Returned by [`SyncManager::status`]. Contains commits that exist locally
/// but have not yet been pushed to the remote.
///
/// See spec §8.1.
#[derive(Debug)]
pub struct SyncStatus {
    /// Commit IDs that are present locally but absent from the remote.
    ///
    /// These will be pushed on the next `loomed sync` invocation.
    pub pending: Vec<CommitHash>,

    /// The number of commits already present on the remote.
    pub synced_count: usize,
}

/// Orchestrates sync operations between a local vault and a remote backend.
///
/// `SyncManager` is stateless — it reads from the vault and backend on each
/// call without caching. This ensures status and push operations always
/// reflect the current state of both sides.
///
/// See spec §8.
pub struct SyncManager<'v> {
    vault: &'v Vault,
}

impl<'v> SyncManager<'v> {
    /// Creates a new `SyncManager` for the given vault.
    ///
    /// # Arguments
    ///
    /// * `vault` — A handle to the local vault to sync.
    pub fn new(vault: &'v Vault) -> Self {
        Self { vault }
    }

    /// Pushes all commits present locally but absent from the remote.
    ///
    /// Reads raw encrypted bytes from the local vault (no passphrase required)
    /// and sends them to the backend unchanged. Updates the remote HEAD after
    /// all commits are pushed.
    ///
    /// # Arguments
    ///
    /// * `backend` — The remote backend to push to.
    ///
    /// # Returns
    ///
    /// A [`SyncReport`] summarising how many commits were pushed vs already remote.
    ///
    /// # Errors
    ///
    /// * [`SyncError::Store`] — A local vault read failed.
    /// * [`SyncError::RemoteWriteFailed`] — A remote write failed.
    ///
    /// See spec §8.1.
    pub fn push<B: CloudVaultBackend>(
        &self,
        backend: &B,
    ) -> Result<SyncReport, SyncError> {
        let local_ids = self.vault.list_commit_ids()?;
        let remote_ids = backend.list_remote_commits()?;
        let remote_set: HashSet<&CommitHash> = remote_ids.iter().collect();

        let already_remote = local_ids.iter().filter(|id| remote_set.contains(id)).count();
        let mut pushed = Vec::new();

        for commit_id in &local_ids {
            if remote_set.contains(commit_id) {
                continue;
            }
            let ciphertext = self.vault.read_commit_raw(commit_id)?;
            backend.push_commit(commit_id, &ciphertext)?;
            pushed.push(commit_id.clone());
        }

        // Update remote HEAD to match local HEAD after all commits are pushed.
        if let Some(head) = self.vault.read_head()? {
            backend.push_head(&head)?;
        }

        Ok(SyncReport {
            pushed,
            already_remote,
        })
    }

    /// Returns the sync status: which commits are pending and how many are synced.
    ///
    /// A read-only operation — no data is transferred. Does not require the
    /// vault passphrase.
    ///
    /// # Arguments
    ///
    /// * `backend` — The remote backend to check against.
    ///
    /// # Returns
    ///
    /// A [`SyncStatus`] with the list of pending commit IDs and the count of
    /// already-synced commits.
    ///
    /// # Errors
    ///
    /// * [`SyncError::Store`] — The local commit list could not be read.
    /// * [`SyncError::RemoteReadFailed`] — The remote could not be listed.
    ///
    /// See spec §8.1.
    pub fn status<B: CloudVaultBackend>(
        &self,
        backend: &B,
    ) -> Result<SyncStatus, SyncError> {
        let local_ids = self.vault.list_commit_ids()?;
        let remote_ids = backend.list_remote_commits()?;
        let remote_set: HashSet<&CommitHash> = remote_ids.iter().collect();

        let pending: Vec<CommitHash> = local_ids
            .iter()
            .filter(|id| !remote_set.contains(id))
            .cloned()
            .collect();

        let synced_count = remote_ids.len();

        Ok(SyncStatus {
            pending,
            synced_count,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use loomed_core::{builder, AuthorizationRef, ParticipantId, RecordType};
    use loomed_crypto::{derive_keypair, sign};
    use loomed_store::Vault;
    use tempfile::TempDir;

    use crate::local::LocalFileBackend;

    fn temp_dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    const TEST_PASSPHRASE: &[u8] = b"test-passphrase-sync";

    fn test_salt() -> [u8; 16] {
        [2u8; 16]
    }

    fn test_patient_id() -> ParticipantId {
        ParticipantId::new("LMP-7XKQR2MNVB-F4").unwrap()
    }

    fn init_test_vault(dir: &TempDir) -> Vault {
        let salt = test_salt();
        let keypair = derive_keypair(TEST_PASSPHRASE, &salt).unwrap();
        let public_key = keypair.public_key_hex();
        Vault::init(
            dir.path(),
            &test_patient_id(),
            &public_key,
            &hex::encode(salt),
        )
        .unwrap()
    }

    fn write_test_commit(vault: &Vault, previous: Option<CommitHash>) -> CommitHash {
        let patient_id = test_patient_id();
        let keypair = derive_keypair(TEST_PASSPHRASE, &test_salt()).unwrap();

        let pending = builder::prepare(
            patient_id.clone(),
            patient_id.clone(),
            patient_id,
            RecordType::LabResult,
            "test commit".to_string(),
            serde_json::json!({}),
            previous,
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();

        let sig = sign(&keypair, &pending.canonical_bytes);
        let commit = pending.finalise(sig).unwrap();
        let id = commit.commit_id.clone();
        vault.write_commit(&commit, TEST_PASSPHRASE).unwrap();
        id
    }

    /// Spec §8.1: SyncManager::push must push commits absent from the remote.
    #[test]
    fn push_transfers_local_commits_to_remote() {
        let local_dir = temp_dir();
        let remote_dir = temp_dir();

        let vault = init_test_vault(&local_dir);
        write_test_commit(&vault, None);
        write_test_commit(&vault, vault.read_head().unwrap());

        let backend = LocalFileBackend::new(remote_dir.path()).unwrap();
        let manager = SyncManager::new(&vault);

        let report = manager.push(&backend).unwrap();

        assert_eq!(report.pushed.len(), 2);
        assert_eq!(report.already_remote, 0);

        // Remote must have the same commits
        let remote_ids = backend.list_remote_commits().unwrap();
        assert_eq!(remote_ids.len(), 2);
    }

    /// Spec §8.1: Pushing a second time when remote is already up-to-date
    /// must push nothing.
    #[test]
    fn push_is_idempotent_when_remote_is_current() {
        let local_dir = temp_dir();
        let remote_dir = temp_dir();

        let vault = init_test_vault(&local_dir);
        write_test_commit(&vault, None);

        let backend = LocalFileBackend::new(remote_dir.path()).unwrap();
        let manager = SyncManager::new(&vault);

        let first = manager.push(&backend).unwrap();
        assert_eq!(first.pushed.len(), 1);

        let second = manager.push(&backend).unwrap();
        assert_eq!(second.pushed.len(), 0);
        assert_eq!(second.already_remote, 1);
    }

    /// Spec §8.1: SyncManager::push must update the remote HEAD after pushing.
    #[test]
    fn push_updates_remote_head() {
        let local_dir = temp_dir();
        let remote_dir = temp_dir();

        let vault = init_test_vault(&local_dir);
        write_test_commit(&vault, None);
        let local_head = vault.read_head().unwrap().unwrap();

        let backend = LocalFileBackend::new(remote_dir.path()).unwrap();
        let manager = SyncManager::new(&vault);

        manager.push(&backend).unwrap();

        let remote_head = backend.pull_head().unwrap().unwrap();
        assert_eq!(remote_head, local_head);
    }

    /// Spec §8.1: SyncManager::status must return all local commits when remote
    /// is empty.
    #[test]
    fn status_shows_all_commits_as_pending_on_empty_remote() {
        let local_dir = temp_dir();
        let remote_dir = temp_dir();

        let vault = init_test_vault(&local_dir);
        write_test_commit(&vault, None);

        let backend = LocalFileBackend::new(remote_dir.path()).unwrap();
        let manager = SyncManager::new(&vault);

        let status = manager.status(&backend).unwrap();
        assert_eq!(status.pending.len(), 1);
        assert_eq!(status.synced_count, 0);
    }

    /// Spec §8.1: SyncManager::status after a full push must show no pending commits.
    #[test]
    fn status_shows_no_pending_after_full_push() {
        let local_dir = temp_dir();
        let remote_dir = temp_dir();

        let vault = init_test_vault(&local_dir);
        write_test_commit(&vault, None);

        let backend = LocalFileBackend::new(remote_dir.path()).unwrap();
        let manager = SyncManager::new(&vault);

        manager.push(&backend).unwrap();
        let status = manager.status(&backend).unwrap();

        assert!(status.pending.is_empty());
        assert_eq!(status.synced_count, 1);
    }

    /// Spec §8.1: Push does not require the vault passphrase — it transfers
    /// raw encrypted bytes.
    #[test]
    fn push_transfers_raw_encrypted_bytes_without_passphrase() {
        let local_dir = temp_dir();
        let remote_dir = temp_dir();

        let vault = init_test_vault(&local_dir);
        let id = write_test_commit(&vault, None);

        let backend = LocalFileBackend::new(remote_dir.path()).unwrap();
        let manager = SyncManager::new(&vault);
        manager.push(&backend).unwrap();

        // The raw bytes on remote must match what was written locally
        let local_raw = vault.read_commit_raw(&id).unwrap();
        let remote_raw = backend.pull_commit(&id).unwrap();
        assert_eq!(local_raw, remote_raw);
    }
}
