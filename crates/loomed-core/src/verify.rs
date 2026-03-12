//! # Chain Verification
//!
//! Commit integrity and hash chain verification for the LooMed protocol.
//!
//! ## Responsibilities
//! - Verifying a single commit's hash and signature (spec §7)
//! - Verifying the full hash chain from genesis to HEAD (spec §7)
//!
//! ## Not Responsible For
//! - Reading commits from disk (see `loomed-store`)
//! - Computing hashes or verifying signatures (see `loomed-crypto`)
//! - Resolving sync conflicts (spec §8, future: `loomed-sync`)
//!
//! ## Verification Rules (spec §7)
//!
//! A commit is valid if and only if:
//! 1. Its commit_id matches the SHA-256 of the commit object with commit_id set to empty string
//! 2. Its signature verifies against the author's public key
//! 3. Its previous_hash matches the commit_id of the preceding commit in the chain
//! 4. The genesis commit has previous_hash = None

use crate::commit::{Commit, CommitHash};
use crate::error::LooMedError;

/// The result of verifying a single commit.
///
/// Returned by [`verify_commit`] to give the caller full information
/// about what was verified and whether it passed.
#[derive(Debug)]
pub struct CommitVerification {
    /// The commit_id of the commit that was verified.
    pub commit_id: CommitHash,

    /// Whether the commit_id hash is valid.
    ///
    /// `true` if the recomputed SHA-256 matches the stored commit_id.
    pub hash_valid: bool,

    /// Whether the ed25519 signature is valid.
    ///
    /// `true` if the signature verifies against the author's public key.
    pub signature_valid: bool,

    /// Whether this commit is fully valid.
    ///
    /// `true` only if both `hash_valid` and `signature_valid` are `true`.
    pub is_valid: bool,
}

/// The result of verifying the full hash chain.
///
/// Returned by [`verify_chain`]. Contains the per-commit results and
/// a summary of the overall chain state.
#[derive(Debug)]
pub struct ChainVerification {
    /// The per-commit verification results, in chain order from genesis.
    pub commits: Vec<CommitVerification>,

    /// Whether every commit in the chain is valid.
    ///
    /// `true` only if all commits passed both hash and signature verification
    /// and all previous_hash links are correct.
    pub chain_valid: bool,

    /// The total number of commits verified.
    pub commit_count: usize,

    /// The commit_id where the first failure was detected, if any.
    ///
    /// `None` if the chain is fully valid.
    pub first_failure: Option<CommitHash>,
}

/// Verifies the integrity of a single commit.
///
/// Recomputes the commit_id by temporarily clearing the commit_id field
/// and hashing the result, then compares it to the stored value.
/// Also verifies the ed25519 signature against the provided public key.
///
/// This function does NOT verify chain continuity — it does not check
/// that `previous_hash` points to a valid prior commit. Use
/// [`verify_chain`] for full chain verification.
///
/// # Arguments
///
/// * `commit` — The commit to verify.
/// * `author_public_key` — The ed25519 public key of the commit's author,
///   in the format `"ed25519:<lowercase hex>"`.
///
/// # Returns
///
/// A [`CommitVerification`] with the results of hash and signature checks.
///
/// # Errors
///
/// * [`LooMedError::SerializationFailed`] — The commit could not be
///   serialised for hash recomputation.
///
/// See spec §7.
pub fn verify_commit(
    commit: &Commit,
    author_public_key: &str,
) -> Result<CommitVerification, LooMedError> {
    // Step 1 — Recompute the commit_id.
    //
    // Per spec §6.2, commit_id = SHA256(commit object with commit_id = "").
    // We clone the commit, clear the commit_id, serialise, and hash.
    let mut commit_for_hashing = commit.clone();
    commit_for_hashing.commit_id = crate::commit::CommitHash(String::new());

    let serialised =
        serde_json::to_vec(&commit_for_hashing).map_err(|e| LooMedError::SerializationFailed {
            reason: e.to_string(),
        })?;

    let recomputed = loomed_crypto::compute_commit_hash(&serialised)
        .map_err(|e| LooMedError::SerializationFailed {
            reason: e.to_string(),
        })?;

    let hash_valid = recomputed == commit.commit_id.as_str();

    // Step 2 — Verify the ed25519 signature.
    //
    // The signature covers the canonical bytes — the same serialisation
    // used during commit preparation (commit_id and signature both empty).
    // We reconstruct those bytes here for verification.
    let mut commit_for_sig = commit.clone();
    commit_for_sig.commit_id = crate::commit::CommitHash(String::new());
    commit_for_sig.signature = String::new();

    let sig_bytes =
        serde_json::to_vec(&commit_for_sig).map_err(|e| LooMedError::SerializationFailed {
            reason: e.to_string(),
        })?;

    let signature_valid =
        loomed_crypto::verify(author_public_key, &sig_bytes, &commit.signature).is_ok();

    let is_valid = hash_valid && signature_valid;

    Ok(CommitVerification {
        commit_id: commit.commit_id.clone(),
        hash_valid,
        signature_valid,
        is_valid,
    })
}

/// Verifies the full hash chain from genesis to the provided HEAD commit.
///
/// Iterates through the commits in chain order, verifying each commit's
/// hash and signature, and checking that each commit's previous_hash
/// correctly references the preceding commit.
///
/// # Arguments
///
/// * `commits` — All commits in the chain, in order from genesis (index 0)
///   to HEAD (last index). Must be pre-sorted by the caller using
///   previous_hash chain traversal.
/// * `author_public_key` — The ed25519 public key of the vault owner.
///   In Phase 1 all commits are self-authored so one key covers the chain.
///
/// # Returns
///
/// A [`ChainVerification`] with per-commit results and an overall verdict.
///
/// # Errors
///
/// * [`LooMedError::SerializationFailed`] — A commit could not be
///   serialised during verification.
///
/// See spec §7.
pub fn verify_chain(
    commits: &[Commit],
    author_public_key: &str,
) -> Result<ChainVerification, LooMedError> {
    let mut results = Vec::with_capacity(commits.len());
    let mut chain_valid = true;
    let mut first_failure: Option<CommitHash> = None;

    for (i, commit) in commits.iter().enumerate() {
        // Verify this commit's hash and signature
        let verification = verify_commit(commit, author_public_key)?;

        if !verification.is_valid && first_failure.is_none() {
            first_failure = Some(commit.commit_id.clone());
            chain_valid = false;
        }

        // Verify chain continuity — previous_hash must match the
        // commit_id of the preceding commit. See spec §7.
        if i == 0 {
            // Genesis commit must have no previous_hash
            if commit.previous_hash.is_some() {
                chain_valid = false;
                if first_failure.is_none() {
                    first_failure = Some(commit.commit_id.clone());
                }
            }
        } else {
            // Every subsequent commit must reference the prior commit_id
            let expected = &commits[i - 1].commit_id;
            match &commit.previous_hash {
                None => {
                    chain_valid = false;
                    if first_failure.is_none() {
                        first_failure = Some(commit.commit_id.clone());
                    }
                }
                Some(actual) => {
                    if actual != expected {
                        chain_valid = false;
                        if first_failure.is_none() {
                            first_failure = Some(commit.commit_id.clone());
                        }
                    }
                }
            }
        }

        results.push(verification);
    }

    Ok(ChainVerification {
        commit_count: results.len(),
        commits: results,
        chain_valid,
        first_failure,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder;
    use crate::commit::AuthorizationRef;
    use crate::participant::ParticipantId;
    use loomed_crypto::{generate_keypair, sign};

    fn test_patient_id() -> ParticipantId {
        ParticipantId::new("LMP-7XKQR2MNVB-F4").unwrap()
    }

    /// Builds a valid signed commit for testing.
    fn build_commit(
        previous_hash: Option<CommitHash>,
        keypair: &loomed_crypto::LooMedKeypair,
    ) -> Commit {
        let pending = builder::prepare(
            test_patient_id(),
            test_patient_id(),
            test_patient_id(),
            crate::commit::RecordType::KeyRotation,
            "test commit".to_string(),
            serde_json::json!({}),
            previous_hash,
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();

        let signature = sign(keypair, &pending.canonical_bytes);
        pending.finalise(signature).unwrap()
    }

    /// Spec §7: A valid commit must pass verification.
    #[test]
    fn valid_commit_passes_verification() {
        let keypair = generate_keypair();
        let commit = build_commit(None, &keypair);
        let result = verify_commit(&commit, &keypair.public_key_hex()).unwrap();
        assert!(result.is_valid);
        assert!(result.hash_valid);
        assert!(result.signature_valid);
    }

    /// Spec §7: Tampering with the message must cause hash verification to fail.
    #[test]
    fn tampered_message_fails_hash_verification() {
        let keypair = generate_keypair();
        let mut commit = build_commit(None, &keypair);
        commit.message = "tampered message".to_string();
        let result = verify_commit(&commit, &keypair.public_key_hex()).unwrap();
        assert!(!result.hash_valid);
        assert!(!result.is_valid);
    }

    /// Spec §7: Tampering with the payload must cause hash verification to fail.
    #[test]
    fn tampered_payload_fails_hash_verification() {
        let keypair = generate_keypair();
        let mut commit = build_commit(None, &keypair);
        commit.payload = serde_json::json!({ "tampered": true });
        let result = verify_commit(&commit, &keypair.public_key_hex()).unwrap();
        assert!(!result.hash_valid);
        assert!(!result.is_valid);
    }

    /// Spec §7: A commit verified with the wrong public key must fail.
    #[test]
    fn wrong_public_key_fails_signature_verification() {
        let keypair1 = generate_keypair();
        let keypair2 = generate_keypair();
        let commit = build_commit(None, &keypair1);
        let result = verify_commit(&commit, &keypair2.public_key_hex()).unwrap();
        assert!(!result.signature_valid);
        assert!(!result.is_valid);
    }

    /// Spec §7: A valid two-commit chain must pass full chain verification.
    #[test]
    fn valid_chain_passes_verification() {
        let keypair = generate_keypair();
        let genesis = build_commit(None, &keypair);
        let second = build_commit(Some(genesis.commit_id.clone()), &keypair);

        let chain = vec![genesis, second];
        let result = verify_chain(&chain, &keypair.public_key_hex()).unwrap();

        assert!(result.chain_valid);
        assert_eq!(result.commit_count, 2);
        assert!(result.first_failure.is_none());
    }

    /// Spec §7: A chain with a broken previous_hash link must fail verification.
    #[test]
    fn broken_chain_link_fails_verification() {
        let keypair = generate_keypair();
        let genesis = build_commit(None, &keypair);

        // Build second commit with wrong previous_hash
        let wrong_hash = CommitHash("sha256:000000000000000000000000000000000000000000000000000000000000dead".to_string());
        let second = build_commit(Some(wrong_hash), &keypair);

        let chain = vec![genesis, second];
        let result = verify_chain(&chain, &keypair.public_key_hex()).unwrap();

        assert!(!result.chain_valid);
        assert!(result.first_failure.is_some());
    }

    /// Spec §6.1: A genesis commit with a non-None previous_hash must fail chain verification.
    #[test]
    fn genesis_with_previous_hash_fails_chain_verification() {
        let keypair = generate_keypair();
        let fake_previous = CommitHash("sha256:000000000000000000000000000000000000000000000000000000000000dead".to_string());
        let bad_genesis = build_commit(Some(fake_previous), &keypair);

        let chain = vec![bad_genesis];
        let result = verify_chain(&chain, &keypair.public_key_hex()).unwrap();

        assert!(!result.chain_valid);
        assert!(result.first_failure.is_some());
    }
}