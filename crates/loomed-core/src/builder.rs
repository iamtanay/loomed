//! # Commit Builder
//!
//! Constructs and finalises LooMed commits from staged record data.
//!
//! ## Responsibilities
//! - Assembling a complete `Commit` from its constituent parts
//! - Computing the content_hash (BLAKE3) from the payload
//! - Computing the commit_id (SHA-256) from the full commit object
//! - Accepting an externally produced signature and embedding it
//!
//! ## Not Responsible For
//! - Signing the commit (the caller holds the private key)
//! - Writing the commit to disk (see `loomed-store`)
//! - Generating keypairs (see `loomed-crypto`)
//!
//! ## Commit Finalisation Flow
//!
//! ```text
//! 1. Caller provides: patient_id, author_id, authored_by, record_type,
//!    message, payload, previous_hash, authorization_ref
//! 2. Builder computes content_hash from payload (BLAKE3)
//! 3. Builder assembles commit with empty signature and empty commit_id
//! 4. Builder serialises the commit to canonical JSON
//! 5. Caller signs the canonical JSON bytes with their private key
//! 6. Builder embeds the signature and computes the final commit_id (SHA-256)
//! 7. Final Commit is returned — ready to write to disk
//! ```

use chrono::Utc;
use serde_json::Value;

use crate::commit::{AuthorizationRef, Commit, CommitHash, ContentHash, RecordType, SyncMetadata};
use crate::error::LooMedError;
use crate::participant::ParticipantId;

/// A partially assembled commit awaiting a signature.
///
/// Created by [`CommitBuilder::prepare`]. The caller serialises this to
/// JSON, signs the bytes, then calls [`PendingCommit::finalise`] to
/// produce the completed [`Commit`].
///
/// See the module-level flow documentation for the full sequence.
pub struct PendingCommit {
    /// The assembled commit with an empty commit_id and empty signature.
    ///
    /// These two fields are intentionally blank — commit_id cannot be
    /// computed until the signature is known, and the signature cannot
    /// be produced until the rest of the commit is fixed.
    commit: Commit,

    /// The canonical JSON bytes of the commit, with commit_id and
    /// signature set to empty strings.
    ///
    /// These are the bytes the caller must sign. Signing any other
    /// representation would produce a signature that cannot be verified.
    pub canonical_bytes: Vec<u8>,
}

impl PendingCommit {
    /// Finalises the commit by embedding the signature and computing the commit_id.
    ///
    /// The commit_id is SHA-256 of the full commit JSON with the real
    /// signature embedded but commit_id still empty. This matches the
    /// protocol definition: commit_id = SHA256(commit excluding commit_id).
    ///
    /// # Arguments
    ///
    /// * `signature` — The ed25519 signature over `self.canonical_bytes`,
    ///   produced by the author's private key. Must be in the format
    ///   `"ed25519:<lowercase hex>"`.
    ///
    /// # Returns
    ///
    /// The completed [`Commit`] with all fields set, ready to write to disk.
    ///
    /// # Errors
    ///
    /// * [`LooMedError::SerializationFailed`] — The commit could not be
    ///   serialised for commit_id computation.
    pub fn finalise(mut self, signature: String) -> Result<Commit, LooMedError> {
        // Embed the real signature
        self.commit.signature = signature;

        // Serialise the commit with the real signature but empty commit_id
        // This is the canonical form used to compute commit_id per spec §6.2
        let for_hashing =
            serde_json::to_vec(&self.commit).map_err(|e| LooMedError::SerializationFailed {
                reason: e.to_string(),
            })?;

        // Compute commit_id as SHA-256 of the above
        let commit_id = loomed_crypto::compute_commit_hash(&for_hashing)
            .map_err(|e| LooMedError::SerializationFailed {
                reason: e.to_string(),
            })?;

        self.commit.commit_id = CommitHash(commit_id);

        Ok(self.commit)
    }
}

/// Builds a [`PendingCommit`] from the provided record data.
///
/// This is the primary entry point for creating new commits. It handles
/// content hashing, timestamp assignment, sync metadata initialisation,
/// and canonical serialisation. The caller is responsible only for
/// providing the record data and performing the signing step.
///
/// # Arguments
///
/// * `patient_id` — The participant ID of the vault owner.
/// * `author_id` — The participant ID of the institution authoring this commit.
///   In Phase 1 this is always the patient's own ID.
/// * `authored_by` — The participant ID of the individual author.
///   In Phase 1 this is always the patient's own ID.
/// * `record_type` — The type of medical record this commit represents.
/// * `message` — A short human-readable description of this commit.
/// * `payload` — The medical record data as a JSON value.
/// * `previous_hash` — The commit_id of the preceding commit.
///   `None` for the genesis commit only.
/// * `authorization_ref` — The authorization context for this commit.
///
/// # Returns
///
/// A [`PendingCommit`] whose `canonical_bytes` must be signed before
/// calling [`PendingCommit::finalise`].
///
/// # Errors
///
/// * [`LooMedError::SerializationFailed`] — The payload or commit could
///   not be serialised.
///
/// See spec §6.2.
pub fn prepare(
    patient_id: ParticipantId,
    author_id: ParticipantId,
    authored_by: ParticipantId,
    record_type: RecordType,
    message: String,
    payload: Value,
    previous_hash: Option<CommitHash>,
    authorization_ref: AuthorizationRef,
) -> Result<PendingCommit, LooMedError> {
    // Compute BLAKE3 content hash from the payload
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|e| LooMedError::SerializationFailed {
            reason: e.to_string(),
        })?;

    let content_hash_str = loomed_crypto::compute_content_hash(&payload_bytes)
        .map_err(|e| LooMedError::SerializationFailed {
            reason: e.to_string(),
        })?;

    // Assemble the commit with empty commit_id and signature.
    // These will be filled in during finalise().
    let commit = Commit {
        commit_id: CommitHash(String::new()),
        previous_hash,
        timestamp: Utc::now(),
        patient_id,
        author_id,
        authored_by,
        record_type,
        message,
        content_hash: ContentHash(content_hash_str),
        payload,
        signature: String::new(),
        protocol_version: "0.2".to_string(),
        authorization_ref,
        sync_metadata: SyncMetadata {
            created_offline: false,
            synced_at: None,
            pre_sync_previous_hash: None,
            pre_sync_commit_id: None,
        },
    };

    // Serialise to canonical JSON — these are the bytes to sign
    let canonical_bytes =
        serde_json::to_vec(&commit).map_err(|e| LooMedError::SerializationFailed {
            reason: e.to_string(),
        })?;

    Ok(PendingCommit {
        commit,
        canonical_bytes,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::AuthorizationRef;
    use loomed_crypto::{generate_keypair, sign};

    fn test_patient_id() -> ParticipantId {
        ParticipantId::new("LMP-7XKQR2MNVB-F4").unwrap()
    }

    /// Spec §6.2: A prepared commit must have an empty commit_id before finalisation.
    #[test]
    fn prepared_commit_has_empty_commit_id() {
        let pending = prepare(
            test_patient_id(),
            test_patient_id(),
            test_patient_id(),
            RecordType::KeyRotation,
            "vault initialised".to_string(),
            serde_json::json!({}),
            None,
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();

        assert_eq!(pending.commit.commit_id.as_str(), "");
    }

    /// Spec §6.2: A prepared commit must have an empty signature before finalisation.
    #[test]
    fn prepared_commit_has_empty_signature() {
        let pending = prepare(
            test_patient_id(),
            test_patient_id(),
            test_patient_id(),
            RecordType::KeyRotation,
            "vault initialised".to_string(),
            serde_json::json!({}),
            None,
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();

        assert_eq!(pending.commit.signature, "");
    }

    /// Spec §6.2: After finalisation, commit_id must be prefixed with "sha256:".
    #[test]
    fn finalised_commit_has_sha256_commit_id() {
        let keypair = generate_keypair();
        let pending = prepare(
            test_patient_id(),
            test_patient_id(),
            test_patient_id(),
            RecordType::KeyRotation,
            "vault initialised".to_string(),
            serde_json::json!({}),
            None,
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();

        let signature = sign(&keypair, &pending.canonical_bytes);
        let commit = pending.finalise(signature).unwrap();

        assert!(commit.commit_id.as_str().starts_with("sha256:"));
    }

    /// Spec §6.2: After finalisation, content_hash must be prefixed with "blake3:".
    #[test]
    fn finalised_commit_has_blake3_content_hash() {
        let keypair = generate_keypair();
        let pending = prepare(
            test_patient_id(),
            test_patient_id(),
            test_patient_id(),
            RecordType::KeyRotation,
            "vault initialised".to_string(),
            serde_json::json!({}),
            None,
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();

        let signature = sign(&keypair, &pending.canonical_bytes);
        let commit = pending.finalise(signature).unwrap();

        assert!(commit.content_hash.as_str().starts_with("blake3:"));
    }

    /// Spec §6.1: The genesis commit must have previous_hash set to None.
    #[test]
    fn genesis_commit_has_no_previous_hash() {
        let keypair = generate_keypair();
        let pending = prepare(
            test_patient_id(),
            test_patient_id(),
            test_patient_id(),
            RecordType::KeyRotation,
            "vault initialised".to_string(),
            serde_json::json!({}),
            None,
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();

        let signature = sign(&keypair, &pending.canonical_bytes);
        let commit = pending.finalise(signature).unwrap();

        assert!(commit.previous_hash.is_none());
    }

    /// Spec §7: Two commits with different payloads must have different commit_ids.
    #[test]
    fn different_payloads_produce_different_commit_ids() {
        let keypair = generate_keypair();

        let pending1 = prepare(
            test_patient_id(),
            test_patient_id(),
            test_patient_id(),
            RecordType::KeyRotation,
            "first commit".to_string(),
            serde_json::json!({ "data": "first" }),
            None,
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();

        let pending2 = prepare(
            test_patient_id(),
            test_patient_id(),
            test_patient_id(),
            RecordType::KeyRotation,
            "second commit".to_string(),
            serde_json::json!({ "data": "second" }),
            None,
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();

        let sig1 = sign(&keypair, &pending1.canonical_bytes);
        let sig2 = sign(&keypair, &pending2.canonical_bytes);

        let commit1 = pending1.finalise(sig1).unwrap();
        let commit2 = pending2.finalise(sig2).unwrap();

        assert_ne!(commit1.commit_id, commit2.commit_id);
    }
}