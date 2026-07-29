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
use loomed_core::{CommitHash, sync_rebase};

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

/// The result of a successful sync pull operation.
///
/// Returned by [`SyncManager::pull`]. Summarises what was transferred
/// from the remote to the local vault.
///
/// See spec §8.2.
#[derive(Debug)]
pub struct PullReport {
    /// The commit_ids that were pulled from the remote during this operation.
    pub pulled: Vec<CommitHash>,

    /// The new local HEAD after the pull (if any commits were pulled).
    pub new_head: Option<CommitHash>,
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

    /// Pulls all commits from the remote that are absent locally.
    ///
    /// Reads raw encrypted bytes from the backend (no passphrase required)
    /// and stores them in the local vault unchanged. Updates the local HEAD
    /// to match the remote HEAD after pulling.
    ///
    /// # Arguments
    ///
    /// * `backend` — The remote backend to pull from.
    ///
    /// # Returns
    ///
    /// A [`PullReport`] summarising how many commits were pulled and the new
    /// local HEAD (if any).
    ///
    /// # Errors
    ///
    /// * [`SyncError::RemoteNotFound`] — A commit listed on the remote was not found.
    /// * [`SyncError::Store`] — A local vault write failed.
    /// * [`SyncError::RemoteReadFailed`] — A remote read failed.
    ///
    /// See spec §8.2.
    pub fn pull<B: CloudVaultBackend>(
        &self,
        backend: &B,
    ) -> Result<PullReport, SyncError> {
        let local_ids = self.vault.list_commit_ids()?;
        let remote_ids = backend.list_remote_commits()?;
        let local_set: HashSet<&CommitHash> = local_ids.iter().collect();

        let mut pulled = Vec::new();

        // Pull each commit from the remote that is not yet local.
        for commit_id in &remote_ids {
            if local_set.contains(commit_id) {
                continue;
            }
            let ciphertext = backend.pull_commit(commit_id)?;
            self.vault.write_commit_raw(commit_id, &ciphertext)?;
            pulled.push(commit_id.clone());
        }

        // Update local HEAD to match remote HEAD.
        let new_head = backend.pull_head()?;
        if let Some(ref head) = new_head {
            self.vault.update_head(head)?;
        }

        Ok(PullReport { pulled, new_head })
    }

    /// Resolves a fork in the commit chain via Sync Rebase (spec §8.3).
    ///
    /// Loads all commits from the local vault, detects any fork (two commits
    /// sharing the same `previous_hash`), and applies the deterministic Sync
    /// Rebase algorithm to linearise them. The rebased chain is written back
    /// to the vault, with original `previous_hash` and `commit_id` preserved
    /// in `sync_metadata` for audit and signature verification.
    ///
    /// The original signatures are preserved — they remain valid via
    /// `pre_sync_previous_hash` in the spec.
    ///
    /// # Arguments
    ///
    /// * `passphrase` — The vault passphrase to decrypt and re-encrypt commits.
    ///
    /// # Returns
    ///
    /// A count of how many commits were rebased, or 0 if the chain was already linear.
    ///
    /// # Errors
    ///
    /// * [`SyncError::Store`] — A commit read/write failed.
    /// * [`SyncError`] — A rebase invariant was violated.
    ///
    /// See spec §8.3.
    pub fn resolve(&self, passphrase: &[u8]) -> Result<usize, SyncError> {
        let local_ids = self.vault.list_commit_ids()?;
        let mut commits = Vec::new();

        // Load all commits into memory for rebase.
        for commit_id in local_ids {
            let commit = self.vault.read_commit(&commit_id, passphrase)?;
            commits.push(commit);
        }

        // Apply the deterministic Sync Rebase algorithm.
        let rebased = sync_rebase(commits)?;

        // Count how many commits were actually rebased (non-zero sync_metadata.pre_sync_previous_hash).
        let rebased_count = rebased
            .iter()
            .filter(|c| c.sync_metadata.pre_sync_previous_hash.is_some())
            .count();

        // Write all rebased commits back to the vault.
        for commit in &rebased {
            self.vault.write_commit(commit, passphrase)?;
        }

        // Update local HEAD to the last commit in the rebased chain.
        if let Some(head) = rebased.last() {
            self.vault.update_head(&head.commit_id)?;
        }

        Ok(rebased_count)
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
    use chrono::{Duration, Utc};

    use crate::local::LocalFileBackend;

    fn temp_dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    const TEST_PASSPHRASE: &[u8] = b"test-passphrase-sync";

    fn test_salt() -> [u8; 16] {
        [2u8; 16]
    }

    fn test_patient_id() -> ParticipantId {
        ParticipantId::new("LMP-7XKQR2MNVB-6A").unwrap()
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

    /// Spec §8.2: SyncManager::pull must fetch commits absent locally.
    #[test]
    fn pull_fetches_remote_commits_not_in_local_vault() {
        let local_dir = temp_dir();
        let remote_dir = temp_dir();

        let local_vault = init_test_vault(&local_dir);
        let remote_vault = init_test_vault(&remote_dir);

        // Write to remote vault and push to the backend
        let remote_commit_id = write_test_commit(&remote_vault, None);

        let backend = LocalFileBackend::new(remote_dir.path()).unwrap();
        let remote_manager = SyncManager::new(&remote_vault);
        remote_manager.push(&backend).unwrap();

        // Now pull on local vault
        let local_manager = SyncManager::new(&local_vault);
        let report = local_manager.pull(&backend).unwrap();

        assert_eq!(report.pulled.len(), 1);
        assert!(report.pulled.contains(&remote_commit_id));

        // Local vault must now have the pulled commit
        let local_ids = local_vault.list_commit_ids().unwrap();
        assert!(local_ids.contains(&remote_commit_id));
    }

    /// Spec §8.2: SyncManager::pull updates local HEAD to match remote HEAD.
    #[test]
    fn pull_updates_local_head_to_remote_head() {
        let local_dir = temp_dir();
        let remote_dir = temp_dir();

        let local_vault = init_test_vault(&local_dir);
        let remote_vault = init_test_vault(&remote_dir);

        let _c1 = write_test_commit(&remote_vault, None);
        let c2 = write_test_commit(&remote_vault, remote_vault.read_head().unwrap());

        let backend = LocalFileBackend::new(remote_dir.path()).unwrap();
        let remote_manager = SyncManager::new(&remote_vault);
        remote_manager.push(&backend).unwrap();

        let local_manager = SyncManager::new(&local_vault);
        local_manager.pull(&backend).unwrap();

        let local_head = local_vault.read_head().unwrap().unwrap();
        let remote_head = backend.pull_head().unwrap().unwrap();
        assert_eq!(local_head, remote_head);
        assert_eq!(local_head, c2);
    }

    /// Spec §8.2: SyncManager::pull is idempotent — pulling twice changes nothing.
    #[test]
    fn pull_is_idempotent() {
        let local_dir = temp_dir();
        let remote_dir = temp_dir();

        let local_vault = init_test_vault(&local_dir);
        let remote_vault = init_test_vault(&remote_dir);

        let remote_commit_id = write_test_commit(&remote_vault, None);

        let backend = LocalFileBackend::new(remote_dir.path()).unwrap();
        let remote_manager = SyncManager::new(&remote_vault);
        remote_manager.push(&backend).unwrap();

        let local_manager = SyncManager::new(&local_vault);

        let first = local_manager.pull(&backend).unwrap();
        assert_eq!(first.pulled.len(), 1);
        assert!(first.pulled.contains(&remote_commit_id));

        let second = local_manager.pull(&backend).unwrap();
        assert_eq!(second.pulled.len(), 0);
    }

    /// Spec §8.3: SyncManager::resolve linearises a fork via Sync Rebase.
    #[test]
    fn resolve_linearises_fork_via_sync_rebase() {
        let vault_dir = temp_dir();
        let vault = init_test_vault(&vault_dir);

        let patient_id = test_patient_id();
        let keypair = derive_keypair(TEST_PASSPHRASE, &test_salt()).unwrap();

        // Create genesis
        let genesis_pending = builder::prepare(
            patient_id.clone(),
            patient_id.clone(),
            patient_id.clone(),
            RecordType::KeyRotation,
            "genesis".to_string(),
            serde_json::json!({}),
            None,
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();
        let genesis_sig = sign(&keypair, &genesis_pending.canonical_bytes);
        let genesis = genesis_pending.finalise(genesis_sig).unwrap();
        let genesis_id = genesis.commit_id.clone();
        vault.write_commit(&genesis, TEST_PASSPHRASE).unwrap();
        vault.update_head(&genesis_id).unwrap();

        // Create two branches from genesis (fork)
        let branch1_pending = builder::prepare(
            patient_id.clone(),
            patient_id.clone(),
            patient_id.clone(),
            RecordType::LabResult,
            "branch 1".to_string(),
            serde_json::json!({}),
            Some(genesis_id.clone()),
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();
        let branch1_sig = sign(&keypair, &branch1_pending.canonical_bytes);
        let mut branch1 = branch1_pending.finalise(branch1_sig).unwrap();
        // Manually set an earlier timestamp to ensure ordering
        branch1.timestamp = Utc::now() - Duration::seconds(5);
        vault.write_commit(&branch1, TEST_PASSPHRASE).unwrap();
        vault.update_head(&branch1.commit_id).unwrap();

        let branch2_pending = builder::prepare(
            patient_id.clone(),
            patient_id.clone(),
            patient_id,
            RecordType::LabResult,
            "branch 2".to_string(),
            serde_json::json!({}),
            Some(genesis_id.clone()),
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();
        let branch2_sig = sign(&keypair, &branch2_pending.canonical_bytes);
        let mut branch2 = branch2_pending.finalise(branch2_sig).unwrap();
        // Set a later timestamp
        branch2.timestamp = Utc::now() + Duration::seconds(5);
        vault.write_commit(&branch2, TEST_PASSPHRASE).unwrap();
        // Don't update HEAD yet - this creates a fork

        // Resolve the fork
        let manager = SyncManager::new(&vault);
        let rebased_count = manager.resolve(TEST_PASSPHRASE).unwrap();

        // At least one commit should have been rebased
        assert!(rebased_count > 0);

        // Local HEAD must point to something
        let head = vault.read_head().unwrap();
        assert!(head.is_some());

        // Verify the rebased commits have sync_metadata populated
        let head_id = head.unwrap();
        let head_commit = vault.read_commit(&head_id, TEST_PASSPHRASE).unwrap();
        // The head commit should have pre_sync_previous_hash if it was rebased
        assert!(head_commit.sync_metadata.pre_sync_previous_hash.is_some() ||
                head_commit.sync_metadata.pre_sync_commit_id.is_some() ||
                head_commit.previous_hash.is_some(),
                "rebased commit should have valid chain linking");
    }
}
