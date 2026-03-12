//! # Staged Record
//!
//! The staging area for a record that has been prepared for commit but
//! not yet signed and written to the vault.
//!
//! ## Responsibilities
//! - Writing a staged record to `.loomed/staged.json` (spec §6)
//! - Reading a staged record from `.loomed/staged.json`
//! - Clearing the staging area after a successful commit
//!
//! ## Not Responsible For
//! - Building or signing commits (see `loomed-core::builder`)
//! - Writing committed .lmc files (see `loomed-store::vault`)
//!
//! ## Staging Flow
//!
//! ```text
//! loomed add  → writes staged.json
//! loomed commit → reads staged.json → builds commit → writes .lmc → clears staged.json
//! ```
//!
//! Only one record can be staged at a time. Running `loomed add` twice
//! overwrites the previous staged record. This matches git's index model
//! where staging replaces rather than accumulates.

use std::fs;
use std::path::Path;

use loomed_core::RecordType;
use serde::{Deserialize, Serialize};

use crate::error::StoreError;

/// The filename of the staging area file within the vault directory.
const STAGED_FILE: &str = "staged.json";

/// A record staged for the next commit.
///
/// Written by `loomed add` and consumed by `loomed commit`.
/// Stored in plaintext in `.loomed/staged.json` — the payload at this
/// stage is not yet part of the encrypted ledger.
///
/// See spec §6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedRecord {
    /// The type of medical record being staged.
    ///
    /// Determines how the payload will be interpreted when the commit
    /// is built. See spec §9.
    pub record_type: RecordType,

    /// A short human-readable description of this record.
    ///
    /// Becomes the commit message. Analogous to a git commit message.
    pub message: String,

    /// The medical record payload as a JSON value.
    ///
    /// In Phase 1, this is an empty object — the user provides the
    /// record type and message via the CLI, and the payload is populated
    /// in future phases when record schemas are enforced.
    pub payload: serde_json::Value,
}

/// Writes a staged record to `.loomed/staged.json`.
///
/// Overwrites any previously staged record. Only one record can be
/// staged at a time.
///
/// # Arguments
///
/// * `vault_dir` — The `.loomed/` directory path.
/// * `record` — The staged record to write.
///
/// # Errors
///
/// * [`StoreError::Io`] — The file could not be written.
/// * [`StoreError::MetadataWriteFailed`] — Serialisation failed.
pub fn write_staged(vault_dir: &Path, record: &StagedRecord) -> Result<(), StoreError> {
    let path = vault_dir.join(STAGED_FILE);

    let json =
        serde_json::to_string_pretty(record).map_err(|e| StoreError::MetadataWriteFailed {
            reason: e.to_string(),
        })?;

    fs::write(path, json)?;
    Ok(())
}

/// Reads the staged record from `.loomed/staged.json`.
///
/// # Arguments
///
/// * `vault_dir` — The `.loomed/` directory path.
///
/// # Returns
///
/// The staged record if one exists.
///
/// # Errors
///
/// * [`StoreError::Io`] — The file could not be read.
/// * [`StoreError::MetadataReadFailed`] — The file exists but could not
///   be deserialised. This indicates a corrupted staging area.
pub fn read_staged(vault_dir: &Path) -> Result<Option<StagedRecord>, StoreError> {
    let path = vault_dir.join(STAGED_FILE);

    if !path.exists() {
        return Ok(None);
    }

    let json = fs::read_to_string(&path).map_err(|e| StoreError::MetadataReadFailed {
        reason: e.to_string(),
    })?;

    let record =
        serde_json::from_str(&json).map_err(|e| StoreError::MetadataReadFailed {
            reason: format!("staged.json is corrupted: {}", e),
        })?;

    Ok(Some(record))
}

/// Clears the staging area by deleting `.loomed/staged.json`.
///
/// Called by `loomed commit` after a record has been successfully
/// committed to the vault. A missing staged file is not an error —
/// clearing an already-empty staging area is a no-op.
///
/// # Arguments
///
/// * `vault_dir` — The `.loomed/` directory path.
///
/// # Errors
///
/// * [`StoreError::Io`] — The file exists but could not be deleted.
pub fn clear_staged(vault_dir: &Path) -> Result<(), StoreError> {
    let path = vault_dir.join(STAGED_FILE);

    if path.exists() {
        fs::remove_file(path)?;
    }

    Ok(())
}

/// Returns true if a staged record is currently present.
///
/// # Arguments
///
/// * `vault_dir` — The `.loomed/` directory path.
pub fn has_staged(vault_dir: &Path) -> bool {
    vault_dir.join(STAGED_FILE).exists()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use loomed_core::RecordType;
    use tempfile::TempDir;

    fn temp_vault_dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    fn sample_record() -> StagedRecord {
        StagedRecord {
            record_type: RecordType::LabResult,
            message: "fasting blood glucose".to_string(),
            payload: serde_json::json!({}),
        }
    }

    /// A staged record written and read back must be identical.
    #[test]
    fn write_and_read_staged_roundtrip() {
        let dir = temp_vault_dir();
        let record = sample_record();

        write_staged(dir.path(), &record).unwrap();
        let read_back = read_staged(dir.path()).unwrap().unwrap();

        assert_eq!(read_back.message, record.message);
        assert_eq!(
            serde_json::to_string(&read_back.record_type).unwrap(),
            serde_json::to_string(&record.record_type).unwrap()
        );
    }

    /// Reading from an empty staging area must return None, not an error.
    #[test]
    fn read_staged_returns_none_when_empty() {
        let dir = temp_vault_dir();
        let result = read_staged(dir.path()).unwrap();
        assert!(result.is_none());
    }

    /// Clearing a staged record must make it unreadable.
    #[test]
    fn clear_staged_removes_record() {
        let dir = temp_vault_dir();
        let record = sample_record();

        write_staged(dir.path(), &record).unwrap();
        assert!(has_staged(dir.path()));

        clear_staged(dir.path()).unwrap();
        assert!(!has_staged(dir.path()));

        let result = read_staged(dir.path()).unwrap();
        assert!(result.is_none());
    }

    /// Clearing an already-empty staging area must be a no-op, not an error.
    #[test]
    fn clear_staged_is_noop_when_empty() {
        let dir = temp_vault_dir();
        assert!(clear_staged(dir.path()).is_ok());
    }

    /// Writing a second record must overwrite the first.
    #[test]
    fn second_write_overwrites_first() {
        let dir = temp_vault_dir();

        let first = StagedRecord {
            record_type: RecordType::LabResult,
            message: "first record".to_string(),
            payload: serde_json::json!({}),
        };

        let second = StagedRecord {
            record_type: RecordType::Prescription,
            message: "second record".to_string(),
            payload: serde_json::json!({}),
        };

        write_staged(dir.path(), &first).unwrap();
        write_staged(dir.path(), &second).unwrap();

        let read_back = read_staged(dir.path()).unwrap().unwrap();
        assert_eq!(read_back.message, "second record");
    }
}