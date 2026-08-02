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

use crate::commit::{Commit, CommitHash, RecordType};
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

/// Determines which public key was active to sign each commit in
/// `commits`, given the key that signed `commits[0]` and any embedded
/// key rotations.
///
/// Walks forward from genesis. The genesis commit's own `KeyRotation`
/// payload only carries `public_key` (the key that signed it, matching
/// `genesis_public_key`), so it does not shift the active key. A later
/// self-signed rotation (`loomed key rotate`) carries `new_public_key` in
/// its payload — once that commit is verified against the key active
/// *before* it (the old key, which signs the rotation attesting to the
/// new one), every subsequent commit is verified against `new_public_key`
/// instead. See spec §12.1 and `FIRST_RELEASE_PLAN.md` R6.
///
/// # Arguments
///
/// * `commits` — Commits in chain order, genesis first.
/// * `genesis_public_key` — The public key that signed `commits[0]`.
///
/// # Returns
///
/// One public key per commit, same order and length as `commits` — the
/// key that must verify each commit at that position.
pub fn resolve_signing_keys(commits: &[Commit], genesis_public_key: &str) -> Vec<String> {
    let mut active_key = genesis_public_key.to_string();
    let mut keys = Vec::with_capacity(commits.len());

    for commit in commits {
        keys.push(active_key.clone());

        if commit.record_type == RecordType::KeyRotation {
            if let Some(new_key) = commit.payload.get("new_public_key").and_then(|v| v.as_str()) {
                active_key = new_key.to_string();
            }
        }
    }

    keys
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
/// * `author_public_key` — The ed25519 public key that signed the genesis
///   commit (`commits[0]`). If the chain contains one or more `loomed key
///   rotate` commits, [`resolve_signing_keys`] is used internally to
///   verify each subsequent commit against the key active at that point
///   in the chain, rather than this one key uniformly. See spec §12.1.
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
    let signing_keys = resolve_signing_keys(commits, author_public_key);
    let mut results = Vec::with_capacity(commits.len());
    let mut chain_valid = true;
    let mut first_failure: Option<CommitHash> = None;

    for (i, commit) in commits.iter().enumerate() {
        // Verify this commit's hash and signature against the key that
        // was active at this position in the chain (see resolve_signing_keys).
        let verification = verify_commit(commit, &signing_keys[i])?;

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
        ParticipantId::new("LMP-7XKQR2MNVB-6A").unwrap()
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

    // -----------------------------------------------------------------------
    // resolve_signing_keys / verify_chain with key rotation —
    // FIRST_RELEASE_PLAN.md R6
    // -----------------------------------------------------------------------

    /// Builds a `KeyRotation` commit signed by `old_keypair`, attesting to
    /// `new_keypair`'s public key — the same shape `loomed key rotate` writes.
    fn build_rotation_commit(
        previous_hash: Option<CommitHash>,
        old_keypair: &loomed_crypto::LooMedKeypair,
        new_keypair: &loomed_crypto::LooMedKeypair,
    ) -> Commit {
        let payload = serde_json::json!({
            "old_public_key": old_keypair.public_key_hex(),
            "new_public_key": new_keypair.public_key_hex(),
        });

        let pending = builder::prepare(
            test_patient_id(),
            test_patient_id(),
            test_patient_id(),
            crate::commit::RecordType::KeyRotation,
            "key rotation".to_string(),
            payload,
            previous_hash,
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();

        let signature = sign(old_keypair, &pending.canonical_bytes);
        pending.finalise(signature).unwrap()
    }

    /// FIRST_RELEASE_PLAN.md R6: resolve_signing_keys must keep the genesis
    /// key active until a rotation commit, then switch to the new key for
    /// every commit that follows it — not the rotation commit itself.
    #[test]
    fn resolve_signing_keys_switches_after_rotation_commit() {
        let old_keypair = generate_keypair();
        let new_keypair = generate_keypair();

        let genesis = build_commit(None, &old_keypair);
        let rotation = build_rotation_commit(Some(genesis.commit_id.clone()), &old_keypair, &new_keypair);
        let post_rotation = build_commit(Some(rotation.commit_id.clone()), &new_keypair);

        let commits = vec![genesis, rotation, post_rotation];
        let keys = resolve_signing_keys(&commits, &old_keypair.public_key_hex());

        assert_eq!(keys[0], old_keypair.public_key_hex(), "genesis verified with old key");
        assert_eq!(keys[1], old_keypair.public_key_hex(), "rotation commit itself verified with old key");
        assert_eq!(keys[2], new_keypair.public_key_hex(), "commit after rotation verified with new key");
    }

    /// FIRST_RELEASE_PLAN.md R6: A full chain spanning a key rotation must
    /// pass verify_chain end-to-end, even though two different keys signed it.
    #[test]
    fn verify_chain_passes_across_a_key_rotation() {
        let old_keypair = generate_keypair();
        let new_keypair = generate_keypair();

        let genesis = build_commit(None, &old_keypair);
        let rotation = build_rotation_commit(Some(genesis.commit_id.clone()), &old_keypair, &new_keypair);
        let post_rotation = build_commit(Some(rotation.commit_id.clone()), &new_keypair);

        let commits = vec![genesis, rotation, post_rotation];
        let result = verify_chain(&commits, &old_keypair.public_key_hex()).unwrap();

        assert!(result.chain_valid);
        assert_eq!(result.commit_count, 3);
    }

    /// FIRST_RELEASE_PLAN.md R6: A commit written after rotation but signed
    /// with the OLD key (as if the old key were still in use) must fail
    /// verification — rotation must actually retire the old key.
    #[test]
    fn commit_after_rotation_signed_with_old_key_fails_verification() {
        let old_keypair = generate_keypair();
        let new_keypair = generate_keypair();

        let genesis = build_commit(None, &old_keypair);
        let rotation = build_rotation_commit(Some(genesis.commit_id.clone()), &old_keypair, &new_keypair);
        // Wrong: signed with the old key after rotation.
        let post_rotation = build_commit(Some(rotation.commit_id.clone()), &old_keypair);

        let commits = vec![genesis, rotation, post_rotation];
        let result = verify_chain(&commits, &old_keypair.public_key_hex()).unwrap();

        assert!(!result.chain_valid);
        assert_eq!(result.first_failure, Some(commits[2].commit_id.clone()));
    }
}