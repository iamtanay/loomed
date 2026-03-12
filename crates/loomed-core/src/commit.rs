//! # Commit Types
//!
//! The commit is the atomic unit of the LooMed protocol. Every medical event
//! becomes a commit. This module defines the commit struct, all supporting
//! types, and the record type taxonomy.
//!
//! ## Responsibilities
//! - Base commit schema (spec §6.2)
//! - Record type taxonomy (spec §9)
//! - Authorization reference types (spec §10)
//! - Sync metadata for offline-first operation (spec §8)
//!
//! ## Not Responsible For
//! - Computing commit hashes (see `loomed-crypto`)
//! - Signing commits (see `loomed-crypto`)
//! - Writing commits to disk (see `loomed-store`)
//! - Verifying the hash chain (see `loomed-core::verify`)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::participant::ParticipantId;

// ---------------------------------------------------------------------------
// Newtypes for cryptographic identifiers
// ---------------------------------------------------------------------------

/// A SHA-256 commit hash, encoded as a lowercase hex string prefixed with "sha256:".
///
/// This is the unique identifier for every commit in the LooMed ledger.
/// It is computed from the full commit object excluding the commit_id field
/// itself. See spec §6.2.
///
/// Example: `sha256:7f8e21a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommitHash(pub String);

impl CommitHash {
    /// Returns the raw string value of this commit hash.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CommitHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A BLAKE3 content hash, encoded as a lowercase hex string prefixed with "blake3:".
///
/// Computed from the commit payload only — not the full commit object.
/// Used to verify that the payload has not been tampered with independently
/// of the commit_id chain verification. See spec §6.2.
///
/// Example: `blake3:9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash(pub String);

impl ContentHash {
    /// Returns the raw string value of this content hash.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A consent token identifier.
///
/// Format: `lmt_` prefix followed by random alphanumeric characters.
/// Example: `lmt_7x9k2mP3qRnBzWv`
///
/// See spec §10.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenId(pub String);

impl TokenId {
    /// Returns the raw string value of this token ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Record type taxonomy
// ---------------------------------------------------------------------------

/// The type of a medical record commit.
///
/// Each variant maps to a defined payload schema in the protocol specification.
/// The record type determines how the payload field is interpreted.
///
/// See spec §9.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordType {
    /// A laboratory test result. See spec §9.1.
    LabResult,

    /// A medication prescription. See spec §9.2.
    Prescription,

    /// An interpreted radiology report (not raw imaging files). See spec §9.3.
    ///
    /// Raw imaging files (DICOM, MRI, X-ray) are not stored in LooMed.
    /// Only the interpreted report and an external_ref to the raw files
    /// are stored. This is a first-class design decision. See spec §9.3.
    RadiologyReport,

    /// A vaccination record. See spec §9.4.
    Vaccination,

    /// A clinical diagnosis. See spec §9.5.
    Diagnosis,

    /// A surgical or medical procedure. See spec §9.6.
    Procedure,

    /// A protocol-level key rotation event.
    ///
    /// Written when a patient rotates their keypair after a suspected
    /// compromise. Signed by both old and new keys where possible.
    /// See spec §12.1.
    KeyRotation,

    /// A protocol-level vault re-encryption event.
    ///
    /// Written automatically after a key rotation to record that historical
    /// records have been re-encrypted under the new key. See spec §12.2.
    VaultReencryption,

    /// A retraction of a prior commit.
    ///
    /// Nothing is ever deleted in LooMed. A retraction is a new commit
    /// that declares a prior commit invalid. The original commit remains
    /// in the chain. See spec §6.1.
    Retraction,

    /// A family relationship link between two patient participants.
    ///
    /// Requires consent from both the patient and the referenced family
    /// member before a link is established. See spec §15.
    FamilyLink,
}

// ---------------------------------------------------------------------------
// Authorization reference
// ---------------------------------------------------------------------------

/// The authorization context of a commit.
///
/// Present in every commit from genesis. Declares whether the commit was
/// written by the vault owner (patient) or by an external participant
/// holding a patient-issued consent token.
///
/// In Phase 1, all commits are `SelfAuthored`. In Phase 2+, institution
/// commits carry the token ID that authorized the write. See spec §10.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum AuthorizationRef {
    /// The commit was authored by the patient who owns the vault.
    ///
    /// No external consent token is required. The patient's own private
    /// key signs the commit directly.
    SelfAuthored,

    /// The commit was authorized by a patient-issued consent token.
    ///
    /// The token_id references the token in the patient's consent log.
    /// The token must be write-scoped, valid, and unused at the time of
    /// the commit. See spec §10.1.
    ConsentToken {
        /// The ID of the consent token that authorized this write.
        token_id: TokenId,
    },
}

// ---------------------------------------------------------------------------
// Sync metadata
// ---------------------------------------------------------------------------

/// Metadata recorded during offline sync and Sync Rebase operations.
///
/// LooMed is offline-first. Records are created and signed locally without
/// network connectivity. When two nodes create commits referencing the same
/// previous_hash, a fork occurs. The Sync Rebase algorithm resolves this
/// deterministically. This struct preserves the original pre-rebase values
/// for full audit traceability. See spec §8.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncMetadata {
    /// Whether this commit was created without network connectivity.
    ///
    /// `true` if the commit was signed and staged locally before a network
    /// connection was available. See spec §8.1.
    pub created_offline: bool,

    /// The timestamp at which this commit was synced to the cloud vault.
    ///
    /// `None` if the commit has not yet been synced. See spec §8.1.
    pub synced_at: Option<DateTime<Utc>>,

    /// The original previous_hash before Sync Rebase, if a rebase occurred.
    ///
    /// During Sync Rebase, previous_hash may be updated to form a linear
    /// chain. The original value is preserved here for audit traceability.
    /// `None` if this commit was not affected by a rebase. See spec §8.3.
    pub pre_sync_previous_hash: Option<CommitHash>,

    /// The original commit_id before Sync Rebase, if a rebase occurred.
    ///
    /// During Sync Rebase, the commit_id is recomputed after previous_hash
    /// is updated. The original value is preserved here. `None` if this
    /// commit was not affected by a rebase. See spec §8.3.
    pub pre_sync_commit_id: Option<CommitHash>,
}

// ---------------------------------------------------------------------------
// Base commit schema
// ---------------------------------------------------------------------------

/// A single commit in the LooMed medical record ledger.
///
/// A commit is the atomic unit of the LooMed protocol. Every medical event —
/// a lab result, a prescription, a diagnosis — becomes a commit. Commits are
/// immutable once written. Corrections are new commits that reference the
/// original. Nothing is ever edited or deleted.
///
/// The commit_id is a SHA-256 hash of the entire commit object excluding the
/// commit_id field itself. The signature covers the full commit content.
/// The previous_hash chains this commit to its predecessor, forming a
/// tamper-evident ledger.
///
/// See spec §6.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    /// The SHA-256 hash of this commit object, excluding this field itself.
    ///
    /// This is the commit's unique identifier and its position in the hash
    /// chain. Computed after all other fields are set. See spec §6.2.
    pub commit_id: CommitHash,

    /// The commit_id of the immediately preceding commit in the chain.
    ///
    /// `None` only for the genesis commit — the first commit in a vault.
    /// All subsequent commits must reference a valid prior commit_id.
    /// See spec §6.2 and §7.
    pub previous_hash: Option<CommitHash>,

    /// The UTC timestamp at which this commit was created.
    ///
    /// Used as the primary sort key during Sync Rebase conflict resolution.
    /// A clock skew tolerance of ±60 seconds is permitted. See spec §8.3.
    pub timestamp: DateTime<Utc>,

    /// The participant ID of the patient whose vault this commit belongs to.
    ///
    /// Immutable after the vault is initialised. Every commit in a vault
    /// carries the same patient_id. A commit whose patient_id does not
    /// match the vault owner is rejected at the protocol level. See spec §3.1.
    pub patient_id: ParticipantId,

    /// The participant ID of the institution responsible for this commit.
    ///
    /// In Phase 1 (self-authored commits), this is the patient's own ID.
    /// In Phase 2+, this is the institution writing the record under a
    /// patient-issued write token. See spec §6.2.
    pub author_id: ParticipantId,

    /// The participant ID of the individual clinician who authored this commit.
    ///
    /// In Phase 1 (self-authored commits), this is the patient's own ID.
    /// In Phase 2+, this is the specific clinician within the institution.
    /// Distinct from author_id which identifies the institution. See spec §6.2.
    pub authored_by: ParticipantId,

    /// The type of medical record this commit represents.
    ///
    /// Determines how the payload field is interpreted. Each variant maps
    /// to a defined schema in the protocol specification. See spec §9.
    pub record_type: RecordType,

    /// A short human-readable description of this commit.
    ///
    /// Analogous to a git commit message. Used in `loomed log` output.
    /// Example: "fasting blood glucose report". See spec §6.2.
    pub message: String,

    /// The BLAKE3 hash of the payload field only.
    ///
    /// Allows payload integrity to be verified independently of the full
    /// commit hash chain. See spec §6.2.
    pub content_hash: ContentHash,

    /// The medical record payload for this commit.
    ///
    /// Structure depends on record_type. Stored as a JSON value to allow
    /// each record type to carry its own schema without requiring a fixed
    /// enum at the commit level. See spec §9.
    pub payload: serde_json::Value,

    /// The ed25519 signature over this commit's content.
    ///
    /// Produced by the author's private key. Verifiable against the
    /// author's public key from the participant registry. See spec §6.2.
    pub signature: String,

    /// The LooMed protocol version under which this commit was created.
    ///
    /// Used to detect commits created under incompatible protocol versions
    /// during chain verification and sync. Example: "0.2".
    pub protocol_version: String,

    /// The authorization context for this commit.
    ///
    /// Declares whether this commit was self-authored by the patient or
    /// authorized by a consent token. Present from genesis. See spec §10.
    pub authorization_ref: AuthorizationRef,

    /// Sync and rebase metadata for offline-first operation.
    ///
    /// Records whether the commit was created offline, when it was synced,
    /// and preserves pre-rebase values if a Sync Rebase occurred. See spec §8.
    pub sync_metadata: SyncMetadata,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec §6.1: The genesis commit must have previous_hash set to None.
    #[test]
    fn genesis_commit_has_no_previous_hash() {
        let genesis_hash: Option<CommitHash> = None;
        assert!(genesis_hash.is_none());
    }

    /// Spec §9: RecordType serialises to snake_case strings matching the spec.
    #[test]
    fn record_type_serialises_to_snake_case() {
        let rt = RecordType::LabResult;
        let serialised = serde_json::to_string(&rt).unwrap();
        assert_eq!(serialised, "\"lab_result\"");

        let rt = RecordType::RadiologyReport;
        let serialised = serde_json::to_string(&rt).unwrap();
        assert_eq!(serialised, "\"radiology_report\"");
    }

    /// Spec §10: SelfAuthored authorization serialises correctly.
    #[test]
    fn self_authored_authorization_serialises_correctly() {
        let auth = AuthorizationRef::SelfAuthored;
        let serialised = serde_json::to_string(&auth).unwrap();
        assert!(serialised.contains("self_authored"));
    }

    /// Spec §10: ConsentToken authorization preserves the token_id.
    #[test]
    fn consent_token_authorization_preserves_token_id() {
        let token_id = TokenId("lmt_7x9k2mP3qRnBzWv".to_string());
        let auth = AuthorizationRef::ConsentToken {
            token_id: token_id.clone(),
        };
        let serialised = serde_json::to_string(&auth).unwrap();
        assert!(serialised.contains("lmt_7x9k2mP3qRnBzWv"));
    }

    /// Spec §8.1: SyncMetadata for a fresh local commit has correct defaults.
    #[test]
    fn fresh_offline_commit_sync_metadata() {
        let meta = SyncMetadata {
            created_offline: true,
            synced_at: None,
            pre_sync_previous_hash: None,
            pre_sync_commit_id: None,
        };
        assert!(meta.created_offline);
        assert!(meta.synced_at.is_none());
        assert!(meta.pre_sync_previous_hash.is_none());
        assert!(meta.pre_sync_commit_id.is_none());
    }
}