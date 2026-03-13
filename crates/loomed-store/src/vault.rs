//! # Vault
//!
//! Local encrypted vault storage for a single patient's medical record ledger.
//!
//! ## Vault Structure on Disk
//!
//! ```text
//! .loomed/
//!   vault.toml          ← non-sensitive vault metadata
//!   commits/
//!     sha256:<hash>.lmc ← one encrypted commit file per commit
//!   HEAD                ← commit_id of the latest commit in the chain
//! ```
//!
//! Every .lmc file is an AES-256-GCM encrypted JSON commit object.
//! The nonce is prepended to the ciphertext. The encryption key is
//! derived from the user's passphrase via Argon2id.
//!
//! See spec §5 and §6.

use std::fs;
use std::path::{Path, PathBuf};

use loomed_core::{Commit, CommitHash, ParticipantId};
use loomed_crypto::{decrypt, derive_key, encrypt};
use serde::{Deserialize, Serialize};

use crate::error::StoreError;

/// The name of the vault directory within the project folder.
const VAULT_DIR: &str = ".loomed";

/// The name of the commits subdirectory.
const COMMITS_DIR: &str = "commits";

/// The name of the vault metadata file.
const VAULT_TOML: &str = "vault.toml";

/// The name of the HEAD file, which stores the latest commit_id.
const HEAD_FILE: &str = "HEAD";

/// The file extension for encrypted commit files.
const COMMIT_EXT: &str = ".lmc";

/// Non-sensitive vault metadata stored in vault.toml.
///
/// This file is stored in plaintext. It contains only non-sensitive
/// metadata needed to identify the vault and its owner. No medical
/// data, no private keys, and no personally identifiable information
/// is stored here. See spec §5.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultMetadata {
    /// The participant ID of the patient who owns this vault.
    pub patient_id: String,

    /// The LooMed protocol version this vault was initialised with.
    pub protocol_version: String,

    /// The identity provider type used for this vault.
    ///
    /// In Phase 1, this is always "passphrase". In Phase 4+, this will
    /// reflect the configured IdP (e.g., "national_registry", "enclave").
    /// See spec §4.2.
    pub idp_type: String,

    /// The hex-encoded Argon2id salt used to derive the vault encryption key.
    ///
    /// Generated once at vault initialisation. Must never change.
    /// Required to reproduce the encryption key from the passphrase.
    pub argon2_salt: String,

    /// The public key of the vault owner, encoded as "ed25519:<hex>".
    pub public_key: String,
}

/// A handle to an open local vault.
///
/// Provides read and write access to the encrypted commit store on disk.
/// Every operation that reads or writes commit data requires the vault
/// passphrase to derive the AES-256 encryption key.
///
/// See spec §5 and §6.
pub struct Vault {
    /// The root path of the vault directory (the .loomed/ folder).
    vault_path: PathBuf,

    /// The vault metadata loaded from vault.toml.
    pub metadata: VaultMetadata,
}

impl Vault {
    /// Initialises a new patient vault at the given base directory.
    ///
    /// Creates the `.loomed/` directory structure, generates a random
    /// Argon2id salt, and writes the vault metadata to `vault.toml`.
    ///
    /// # Arguments
    ///
    /// * `base_dir` — The directory in which to create the `.loomed/` folder.
    /// * `patient_id` — The participant ID of the vault owner.
    /// * `public_key` — The patient's ed25519 public key as "ed25519:<hex>".
    /// * `argon2_salt` — A randomly generated 16-byte salt, hex-encoded.
    ///
    /// # Errors
    ///
    /// * [`StoreError::VaultAlreadyExists`] — A vault already exists here.
    /// * [`StoreError::MetadataWriteFailed`] — Could not write vault.toml.
    /// * [`StoreError::Io`] — A filesystem error occurred.
    pub fn init(
        base_dir: &Path,
        patient_id: &ParticipantId,
        public_key: &str,
        argon2_salt: &str,
    ) -> Result<Self, StoreError> {
        let vault_path = base_dir.join(VAULT_DIR);

        if vault_path.exists() {
            return Err(StoreError::VaultAlreadyExists {
                path: vault_path.display().to_string(),
            });
        }

        fs::create_dir_all(vault_path.join(COMMITS_DIR))?;

        let metadata = VaultMetadata {
            patient_id: patient_id.as_str().to_string(),
            protocol_version: "0.2".to_string(),
            idp_type: "passphrase".to_string(),
            argon2_salt: argon2_salt.to_string(),
            public_key: public_key.to_string(),
        };

        let toml_str = toml::to_string(&metadata).map_err(|e| StoreError::MetadataWriteFailed {
            reason: e.to_string(),
        })?;

        fs::write(vault_path.join(VAULT_TOML), toml_str)?;

        Ok(Self {
            vault_path,
            metadata,
        })
    }

    /// Opens an existing vault at the given base directory.
    ///
    /// Reads and parses vault.toml. Does not decrypt any commit data.
    ///
    /// # Arguments
    ///
    /// * `base_dir` — The directory containing the `.loomed/` folder.
    ///
    /// # Errors
    ///
    /// * [`StoreError::VaultNotFound`] — No vault exists at this path.
    /// * [`StoreError::MetadataReadFailed`] — vault.toml could not be read.
    pub fn open(base_dir: &Path) -> Result<Self, StoreError> {
        let vault_path = base_dir.join(VAULT_DIR);

        if !vault_path.exists() {
            return Err(StoreError::VaultNotFound {
                path: vault_path.display().to_string(),
            });
        }

        let toml_str =
            fs::read_to_string(vault_path.join(VAULT_TOML)).map_err(|e| {
                StoreError::MetadataReadFailed {
                    reason: e.to_string(),
                }
            })?;

        let metadata: VaultMetadata =
            toml::from_str(&toml_str).map_err(|e| StoreError::MetadataReadFailed {
                reason: e.to_string(),
            })?;

        Ok(Self {
            vault_path,
            metadata,
        })
    }

    /// Writes a signed commit to disk as an encrypted .lmc file.
    ///
    /// The commit is serialised to JSON, encrypted with AES-256-GCM using
    /// a key derived from the passphrase, and written to:
    /// `.loomed/commits/<commit_id>.lmc`
    ///
    /// The HEAD file is updated to point to this commit.
    ///
    /// # Arguments
    ///
    /// * `commit` — The signed commit to write.
    /// * `passphrase` — The vault passphrase used to derive the encryption key.
    ///
    /// # Errors
    ///
    /// * [`StoreError::CommitWriteFailed`] — Serialisation or encryption failed.
    /// * [`StoreError::Io`] — A filesystem error occurred.
    pub fn write_commit(&self, commit: &Commit, passphrase: &[u8]) -> Result<(), StoreError> {
        let commit_id = commit.commit_id.as_str();

        let json =
            serde_json::to_vec(commit).map_err(|e| StoreError::CommitWriteFailed {
                commit_id: commit_id.to_string(),
                reason: e.to_string(),
            })?;

        let key = self.derive_encryption_key(passphrase, commit_id)?;
        let encrypted =
            encrypt(&key, &json).map_err(|e| StoreError::CommitWriteFailed {
                commit_id: commit_id.to_string(),
                reason: e.to_string(),
            })?;

        let filename = format!("{}{}", commit_id.replace("sha256:", ""), COMMIT_EXT);
        let commit_path = self.vault_path.join(COMMITS_DIR).join(&filename);

        fs::write(&commit_path, &encrypted)?;

        let head_path = self.vault_path.join(HEAD_FILE);
        fs::write(head_path, commit_id)?;

        Ok(())
    }

    /// Reads and decrypts a single commit from disk by its commit_id.
    ///
    /// # Arguments
    ///
    /// * `commit_id` — The commit_id of the commit to read.
    /// * `passphrase` — The vault passphrase used to derive the decryption key.
    ///
    /// # Errors
    ///
    /// * [`StoreError::CommitReadFailed`] — The file could not be read.
    /// * [`StoreError::DecryptionFailed`] — Decryption failed (wrong passphrase).
    /// * [`StoreError::DeserialisationFailed`] — JSON parsing failed.
    pub fn read_commit(
        &self,
        commit_id: &CommitHash,
        passphrase: &[u8],
    ) -> Result<Commit, StoreError> {
        let id_str = commit_id.as_str();
        let filename = format!("{}{}", id_str.replace("sha256:", ""), COMMIT_EXT);
        let commit_path = self.vault_path.join(COMMITS_DIR).join(&filename);

        let encrypted =
            fs::read(&commit_path).map_err(|e| StoreError::CommitReadFailed {
                commit_id: id_str.to_string(),
                reason: e.to_string(),
            })?;

        let key = self.derive_encryption_key(passphrase, id_str)?;

        let json = decrypt(&key, &encrypted).map_err(|_| StoreError::DecryptionFailed {
            commit_id: id_str.to_string(),
        })?;

        let commit =
            serde_json::from_slice(&json).map_err(|e| StoreError::DeserialisationFailed {
                commit_id: id_str.to_string(),
                reason: e.to_string(),
            })?;

        Ok(commit)
    }

    /// Returns the commit_id stored in the HEAD file.
    ///
    /// HEAD points to the most recently committed record in the chain.
    /// Returns `None` if no commits have been written yet (empty vault).
    ///
    /// # Errors
    ///
    /// * [`StoreError::Io`] — The HEAD file could not be read.
    pub fn read_head(&self) -> Result<Option<CommitHash>, StoreError> {
        let head_path = self.vault_path.join(HEAD_FILE);

        if !head_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(head_path)?;
        let trimmed = content.trim().to_string();

        if trimmed.is_empty() {
            return Ok(None);
        }

        Ok(Some(CommitHash(trimmed)))
    }

    /// Lists all commit IDs stored in the vault, unsorted.
    ///
    /// Returns the commit_id of every .lmc file present in the commits
    /// directory. Order is not guaranteed — use `read_head()` and follow
    /// the chain via `previous_hash` for ordered traversal.
    ///
    /// # Errors
    ///
    /// * [`StoreError::Io`] — The commits directory could not be read.
    pub fn list_commit_ids(&self) -> Result<Vec<CommitHash>, StoreError> {
        let commits_dir = self.vault_path.join(COMMITS_DIR);
        let mut ids = Vec::new();

        for entry in fs::read_dir(commits_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if name_str.ends_with(COMMIT_EXT) {
                let hash = name_str.trim_end_matches(COMMIT_EXT);
                ids.push(CommitHash(format!("sha256:{}", hash)));
            }
        }

        Ok(ids)
    }

    /// Derives the AES-256 encryption key from the passphrase and vault salt.
    fn derive_encryption_key(
        &self,
        passphrase: &[u8],
        _commit_id: &str,
    ) -> Result<[u8; 32], StoreError> {
        let salt =
            hex::decode(&self.metadata.argon2_salt).map_err(|e| {
                StoreError::MetadataReadFailed {
                    reason: format!("invalid argon2 salt in vault.toml: {}", e),
                }
            })?;

        derive_key(passphrase, &salt).map_err(|e| StoreError::MetadataReadFailed {
            reason: format!("key derivation failed: {}", e),
        })
    }
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use loomed_core::{
        builder, AuthorizationRef, ParticipantId, RecordType,
    };
    use loomed_crypto::{derive_keypair, sign};
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Creates an isolated temporary directory for each test.
    /// Tests must never read from or write to the real .loomed/ vault.
    /// Per coding standards §6.2.
    fn temp_dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    fn test_patient_id() -> ParticipantId {
        ParticipantId::new("LMP-7XKQR2MNVB-F4").unwrap()
    }

    fn test_passphrase() -> &'static [u8] {
        b"test-passphrase-session3"
    }

    fn test_salt() -> [u8; 16] {
        [1u8; 16]
    }

    fn test_salt_hex() -> String {
        hex::encode(test_salt())
    }

    /// Initialises a vault in the temp dir with consistent test credentials.
    fn init_test_vault(dir: &TempDir) -> Vault {
        let salt = test_salt();
        let keypair = derive_keypair(test_passphrase(), &salt).unwrap();
        let public_key = keypair.public_key_hex();
        Vault::init(dir.path(), &test_patient_id(), &public_key, &test_salt_hex()).unwrap()
    }

    /// Builds and writes a signed commit to an open vault.
    ///
    /// Returns the written commit so callers can inspect its commit_id
    /// and chain it as the previous_hash of the next commit.
    fn write_test_commit(
        vault: &Vault,
        previous_hash: Option<CommitHash>,
        message: &str,
        record_type: RecordType,
    ) -> Commit {
        let patient_id = test_patient_id();
        let salt = test_salt();
        let keypair = derive_keypair(test_passphrase(), &salt).unwrap();

        let pending = builder::prepare(
            patient_id.clone(),
            patient_id.clone(),
            patient_id,
            record_type,
            message.to_string(),
            serde_json::json!({}),
            previous_hash,
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();

        let signature = sign(&keypair, &pending.canonical_bytes);
        let commit = pending.finalise(signature).unwrap();
        vault.write_commit(&commit, test_passphrase()).unwrap();
        commit
    }

    // -----------------------------------------------------------------------
    // Vault::init tests
    // -----------------------------------------------------------------------

    /// Spec §5: Vault::init must create the .loomed/ directory structure.
    #[test]
    fn init_creates_vault_directory_structure() {
        let dir = temp_dir();
        init_test_vault(&dir);

        assert!(dir.path().join(".loomed").exists());
        assert!(dir.path().join(".loomed").join("commits").exists());
        assert!(dir.path().join(".loomed").join("vault.toml").exists());
    }

    /// Spec §5: Vault::init must write the correct patient_id to vault.toml.
    #[test]
    fn init_writes_correct_metadata() {
        let dir = temp_dir();
        let vault = init_test_vault(&dir);

        assert_eq!(vault.metadata.patient_id, "LMP-7XKQR2MNVB-F4");
        assert_eq!(vault.metadata.protocol_version, "0.2");
        assert_eq!(vault.metadata.idp_type, "passphrase");
        assert_eq!(vault.metadata.argon2_salt, test_salt_hex());
    }

    /// Spec §5: Vault::init on an already-initialised directory must fail
    /// with VaultAlreadyExists.
    #[test]
    fn init_fails_if_vault_already_exists() {
        let dir = temp_dir();
        init_test_vault(&dir);

        let salt = test_salt();
        let keypair = derive_keypair(test_passphrase(), &salt).unwrap();
        let result = Vault::init(
            dir.path(),
            &test_patient_id(),
            &keypair.public_key_hex(),
            &test_salt_hex(),
        );

        assert!(matches!(result, Err(StoreError::VaultAlreadyExists { .. })));
    }

    // -----------------------------------------------------------------------
    // Vault::open tests
    // -----------------------------------------------------------------------

    /// Spec §5: Vault::open must load the same metadata that was written
    /// by Vault::init.
    #[test]
    fn open_reads_metadata_written_by_init() {
        let dir = temp_dir();
        init_test_vault(&dir);

        let opened = Vault::open(dir.path()).unwrap();
        assert_eq!(opened.metadata.patient_id, "LMP-7XKQR2MNVB-F4");
        assert_eq!(opened.metadata.argon2_salt, test_salt_hex());
    }

    /// Spec §5: Vault::open on a directory with no vault must fail
    /// with VaultNotFound.
    #[test]
    fn open_fails_if_vault_does_not_exist() {
        let dir = temp_dir();
        let result = Vault::open(dir.path());
        assert!(matches!(result, Err(StoreError::VaultNotFound { .. })));
    }

    // -----------------------------------------------------------------------
    // write_commit / read_commit tests
    // -----------------------------------------------------------------------

    /// Spec §6: A commit written with write_commit must be readable and
    /// identical after read_commit decrypts it.
    #[test]
    fn write_and_read_commit_roundtrip() {
        let dir = temp_dir();
        let vault = init_test_vault(&dir);

        let written = write_test_commit(&vault, None, "vault initialised", RecordType::KeyRotation);
        let read_back = vault
            .read_commit(&written.commit_id, test_passphrase())
            .unwrap();

        assert_eq!(written.commit_id, read_back.commit_id);
        assert_eq!(written.message, read_back.message);
        assert_eq!(written.patient_id, read_back.patient_id);
        assert_eq!(written.signature, read_back.signature);
    }

    /// Spec §6: read_commit with the wrong passphrase must fail with
    /// DecryptionFailed.
    #[test]
    fn read_commit_with_wrong_passphrase_fails() {
        let dir = temp_dir();
        let vault = init_test_vault(&dir);

        let commit = write_test_commit(&vault, None, "vault initialised", RecordType::KeyRotation);
        let result = vault.read_commit(&commit.commit_id, b"wrong-passphrase");

        assert!(matches!(result, Err(StoreError::DecryptionFailed { .. })));
    }

    /// Spec §6: read_commit for a commit_id that does not exist on disk
    /// must fail with CommitReadFailed.
    #[test]
    fn read_commit_missing_file_fails() {
        let dir = temp_dir();
        let vault = init_test_vault(&dir);

        let nonexistent = CommitHash("sha256:000000000000000000000000000000000000000000000000000000000000dead".to_string());
        let result = vault.read_commit(&nonexistent, test_passphrase());

        assert!(matches!(result, Err(StoreError::CommitReadFailed { .. })));
    }

    // -----------------------------------------------------------------------
    // read_head tests
    // -----------------------------------------------------------------------

    /// Spec §5: read_head on a vault with no commits must return None.
    #[test]
    fn read_head_returns_none_on_empty_vault() {
        let dir = temp_dir();
        let vault = init_test_vault(&dir);

        let head = vault.read_head().unwrap();
        assert!(head.is_none());
    }

    /// Spec §6: read_head must return the commit_id of the most recently
    /// written commit.
    #[test]
    fn read_head_returns_latest_commit_id() {
        let dir = temp_dir();
        let vault = init_test_vault(&dir);

        let first = write_test_commit(&vault, None, "genesis", RecordType::KeyRotation);
        let second = write_test_commit(
            &vault,
            Some(first.commit_id.clone()),
            "lab result",
            RecordType::LabResult,
        );

        let head = vault.read_head().unwrap().unwrap();
        assert_eq!(head, second.commit_id);
    }

    // -----------------------------------------------------------------------
    // list_commit_ids tests
    // -----------------------------------------------------------------------

    /// Spec §5: list_commit_ids must return one entry per written commit.
    #[test]
    fn list_commit_ids_returns_all_commits() {
        let dir = temp_dir();
        let vault = init_test_vault(&dir);

        let first = write_test_commit(&vault, None, "genesis", RecordType::KeyRotation);
        let second = write_test_commit(
            &vault,
            Some(first.commit_id.clone()),
            "lab result",
            RecordType::LabResult,
        );

        let ids = vault.list_commit_ids().unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&first.commit_id));
        assert!(ids.contains(&second.commit_id));
    }

    /// Spec §5: list_commit_ids on a vault with no commits must return
    /// an empty list, not an error.
    #[test]
    fn list_commit_ids_returns_empty_on_fresh_vault() {
        let dir = temp_dir();
        let vault = init_test_vault(&dir);

        let ids = vault.list_commit_ids().unwrap();
        assert!(ids.is_empty());
    }

    // -----------------------------------------------------------------------
    // Full lifecycle integration test
    // -----------------------------------------------------------------------

    /// Spec §6 and §7: Full vault lifecycle — init, write genesis, write two
    /// more commits, traverse chain from HEAD to genesis, verify all links.
    ///
    /// This is the integration test equivalent of the end-to-end CLI flow
    /// verified manually in Session 2.
    #[test]
    fn full_vault_lifecycle_chain_traversal() {
        let dir = temp_dir();
        let vault = init_test_vault(&dir);

        // Write three commits forming a chain
        let genesis = write_test_commit(
            &vault,
            None,
            "vault initialised",
            RecordType::KeyRotation,
        );
        let second = write_test_commit(
            &vault,
            Some(genesis.commit_id.clone()),
            "fasting blood glucose",
            RecordType::LabResult,
        );
        let third = write_test_commit(
            &vault,
            Some(second.commit_id.clone()),
            "type 2 diabetes",
            RecordType::Diagnosis,
        );

        // HEAD must point to the last commit
        let head = vault.read_head().unwrap().unwrap();
        assert_eq!(head, third.commit_id);

        // Traverse from HEAD to genesis via previous_hash
        let mut chain = Vec::new();
        let mut current = Some(head);
        while let Some(id) = current {
            let commit = vault.read_commit(&id, test_passphrase()).unwrap();
            let prev = commit.previous_hash.clone();
            chain.push(commit);
            current = prev;
        }

        // Chain traversal must visit all three commits
        assert_eq!(chain.len(), 3);

        // Traversal order is HEAD → genesis, so reverse for genesis-first order
        chain.reverse();

        // Verify chain linkage is correct
        assert!(chain[0].previous_hash.is_none()); // genesis has no parent
        assert_eq!(chain[1].previous_hash.as_ref().unwrap(), &chain[0].commit_id);
        assert_eq!(chain[2].previous_hash.as_ref().unwrap(), &chain[1].commit_id);

        // All commit_ids must have the correct prefix
        for commit in &chain {
            assert!(commit.commit_id.as_str().starts_with("sha256:"));
        }
    }
}