//! # Sync Rebase Algorithm
//!
//! Deterministic resolution of forked commit chains per spec §8.3.
//!
//! ## Why forks occur
//!
//! LooMed is offline-first. When a patient (or an institution with a write
//! token) creates commits without network connectivity, those commits chain
//! from whatever the local HEAD was at the time. If another node (another
//! device, or an institution) independently creates commits from the same
//! parent, a fork is produced: two or more commits share the same
//! `previous_hash`. The commit chain is now non-linear and must be resolved
//! before the vault can be used as a single source of truth.
//!
//! ## The algorithm (spec §8.3)
//!
//! Sync Rebase produces a **canonical, linear chain** from any set of forked
//! commits. The algorithm requires no human intervention and is deterministic:
//! any two nodes independently rebasing the same fork always produce an
//! identical result.
//!
//! ```text
//! 1. Separate the genesis commit (previous_hash = None).
//! 2. If the remaining chain is already linear, return it in chain order.
//! 3. Fork detected: sort ALL non-genesis commits by
//!      primary:   timestamp ascending  (earlier events go first)
//!      secondary: commit_id lexicographic ascending  (tiebreaker for ±60s clock skew)
//! 4. Walk the sorted list. For each commit whose previous_hash no longer
//!    equals the preceding commit's (possibly recomputed) commit_id:
//!      a. Set previous_hash = preceding commit's commit_id
//!      b. Recompute commit_id = SHA256(commit with commit_id = "")
//!      c. Store original previous_hash in sync_metadata.pre_sync_previous_hash
//!      d. Store original commit_id   in sync_metadata.pre_sync_commit_id
//! 5. Return the fully re-linked linear chain (genesis first).
//! ```
//!
//! ## Signature preservation (spec §8.3)
//!
//! Original signatures are **never modified**. After rebase, a rebased
//! commit's signature is valid against its **original** canonical bytes
//! (with the original `previous_hash`). The `pre_sync_previous_hash` field
//! lets verifiers reconstruct those bytes — see `verify_commit` in
//! `loomed-core::verify`.
//!
//! This is a first-class protocol guarantee: rebase is a transparent,
//! auditable protocol operation, not a content modification.
//!
//! ## Responsibilities
//! - Pure algorithm — no I/O, no network, no cryptography (beyond commit_id
//!   recomputation via `loomed_crypto::compute_commit_hash`)
//!
//! ## Not Responsible For
//! - Writing rebased commits to disk (see `loomed-store`)
//! - Transferring commits between nodes (see `loomed-sync`)
//! - Detecting whether a pull is needed before rebase

use std::collections::{HashMap, HashSet};

use crate::{
    commit::{Commit, CommitHash},
    error::LooMedError,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Resolves a forked commit chain into a canonical linear sequence.
///
/// Implements the Sync Rebase algorithm defined in spec §8.3. Accepts any
/// set of commits (local + remote, combined, in any order) and returns them
/// as a single linear chain with genesis first.
///
/// If the input chain is already linear (no forks), the commits are returned
/// in proper chain order without modification — no commits are rebased.
///
/// Rebased commits have their `sync_metadata` fields populated:
/// - `pre_sync_previous_hash`: the original `previous_hash` before rebase
/// - `pre_sync_commit_id`: the original `commit_id` before rebase
///
/// Signatures are preserved unchanged. The `verify_commit` function in
/// `loomed-core::verify` reconstructs the original canonical bytes from
/// `pre_sync_previous_hash` when verifying rebased commits.
///
/// # Arguments
///
/// * `commits` — All commits from the combined local and remote vault,
///   in any order. May contain any number of forks.
///
/// # Returns
///
/// The linearized chain in chain order (genesis at index 0, HEAD last).
///
/// # Errors
///
/// * [`LooMedError::ChainBroken`] — No genesis commit found, or multiple
///   genesis commits found.
/// * [`LooMedError::SerializationFailed`] — A commit could not be serialised
///   for commit_id recomputation.
///
/// See spec §8.3.
pub fn sync_rebase(commits: Vec<Commit>) -> Result<Vec<Commit>, LooMedError> {
    if commits.is_empty() {
        return Ok(commits);
    }

    // Separate genesis (the one commit with no parent)
    let (mut genesis_vec, rest): (Vec<Commit>, Vec<Commit>) =
        commits.into_iter().partition(|c| c.previous_hash.is_none());

    let genesis = match genesis_vec.len() {
        1 => genesis_vec.remove(0),
        0 => {
            return Err(LooMedError::ChainBroken {
                commit_id: "unknown".to_string(),
                expected: "a genesis commit with previous_hash = None".to_string(),
                found: "no genesis commit present".to_string(),
            })
        }
        n => {
            return Err(LooMedError::ChainBroken {
                commit_id: "unknown".to_string(),
                expected: "exactly one genesis commit".to_string(),
                found: format!("{} commits with previous_hash = None", n),
            })
        }
    };

    if rest.is_empty() {
        return Ok(vec![genesis]);
    }

    // Detect fork: any previous_hash value that two or more commits share
    let has_fork = has_fork_in(&rest);

    let mut result = vec![genesis.clone()];

    if !has_fork {
        // Already linear — traverse by previous_hash linkage to get proper order
        let chain = traverse_linear_chain(rest, &genesis.commit_id)?;
        result.extend(chain);
        return Ok(result);
    }

    // -----------------------------------------------------------------------
    // Fork resolution — spec §8.3
    // -----------------------------------------------------------------------
    //
    // Sort ALL non-genesis commits by (timestamp, commit_id).
    // This produces the canonical ordering: earlier real-world events first,
    // commit_id tiebreaker for near-simultaneous commits (±60s clock skew).
    let mut rest = rest;
    rest.sort_by(|a, b| {
        a.timestamp
            .cmp(&b.timestamp)
            .then_with(|| a.commit_id.as_str().cmp(b.commit_id.as_str()))
    });

    // Re-link: assign new previous_hash to commits whose position changed.
    // Walk in sorted order; each commit must point to the preceding commit.
    for mut commit in rest {
        let expected_prev = result.last().map(|c: &Commit| c.commit_id.clone());

        if commit.previous_hash != expected_prev {
            // This commit's position in the chain changed — rebase it.
            let original_prev = commit.previous_hash.clone();
            let original_id = commit.commit_id.clone();

            // Update the chain link
            commit.previous_hash = expected_prev;

            // Recompute commit_id from the updated content (spec §6.2, §8.3)
            commit.commit_id = recompute_commit_id(&commit)?;

            // Preserve original values for audit traceability (spec §8.3)
            commit.sync_metadata.pre_sync_previous_hash = original_prev;
            commit.sync_metadata.pre_sync_commit_id = Some(original_id);
        }

        result.push(commit);
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns `true` if any `previous_hash` value appears in two or more commits.
///
/// A fork exists when two commits share the same parent — both were created
/// independently, offline, referencing the same preceding commit.
fn has_fork_in(commits: &[Commit]) -> bool {
    let mut seen: HashSet<CommitHash> = HashSet::new();
    for commit in commits {
        if let Some(ref prev) = commit.previous_hash {
            if !seen.insert(prev.clone()) {
                return true;
            }
        }
    }
    false
}

/// Traverses a linear (non-forked) commit set and returns them in chain order.
///
/// Builds a `previous_hash → Commit` map and walks from `from_id` forward
/// until no successor is found.
///
/// # Errors
///
/// Returns a `SerializationFailed` error (reused as a structural error here)
/// if the chain is malformed and a cycle is detected.
fn traverse_linear_chain(
    commits: Vec<Commit>,
    from_id: &CommitHash,
) -> Result<Vec<Commit>, LooMedError> {
    let mut by_parent: HashMap<CommitHash, Commit> = HashMap::new();
    for c in commits {
        if let Some(ref prev) = c.previous_hash {
            by_parent.insert(prev.clone(), c);
        }
    }

    let mut result = Vec::new();
    let mut current_id = from_id.clone();
    let mut visited: HashSet<CommitHash> = HashSet::new();

    while let Some(commit) = by_parent.remove(&current_id) {
        if !visited.insert(commit.commit_id.clone()) {
            // Cycle detected — should never happen in a valid vault
            return Err(LooMedError::SerializationFailed {
                reason: format!(
                    "cycle detected in commit chain at {}",
                    commit.commit_id.as_str()
                ),
            });
        }
        current_id = commit.commit_id.clone();
        result.push(commit);
    }

    Ok(result)
}

/// Recomputes a commit's `commit_id` after its `previous_hash` has changed.
///
/// Per spec §6.2: `commit_id = SHA256(commit JSON with commit_id = "")`.
/// This must be called whenever `previous_hash` is updated during Sync Rebase
/// to keep the hash chain consistent.
///
/// See spec §6.2 and §8.3.
fn recompute_commit_id(commit: &Commit) -> Result<CommitHash, LooMedError> {
    let mut for_hashing = commit.clone();
    for_hashing.commit_id = CommitHash(String::new());

    let bytes =
        serde_json::to_vec(&for_hashing).map_err(|e| LooMedError::SerializationFailed {
            reason: e.to_string(),
        })?;

    let id = loomed_crypto::compute_commit_hash(&bytes)
        .map_err(|e| LooMedError::SerializationFailed {
            reason: e.to_string(),
        })?;

    Ok(CommitHash(id))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        builder,
        commit::{AuthorizationRef, RecordType},
        participant::ParticipantId,
    };
    use chrono::{TimeZone, Utc};
    use loomed_crypto::{generate_keypair, sign};

    fn patient_id() -> ParticipantId {
        ParticipantId::new("LMP-7XKQR2MNVB-F4").unwrap()
    }

    /// Builds a signed commit with a specific timestamp for rebase ordering tests.
    fn build_commit_at(
        previous: Option<CommitHash>,
        timestamp_secs: i64,
        message: &str,
    ) -> Commit {
        let keypair = generate_keypair();
        let id = patient_id();
        let pending = builder::prepare(
            id.clone(),
            id.clone(),
            id,
            RecordType::LabResult,
            message.to_string(),
            serde_json::json!({}),
            previous,
            AuthorizationRef::SelfAuthored,
        )
        .unwrap();
        let sig = sign(&keypair, &pending.canonical_bytes);
        let mut commit = pending.finalise(sig).unwrap();
        // Override the timestamp to control rebase ordering
        commit.timestamp = Utc.timestamp_opt(timestamp_secs, 0).unwrap();
        commit
    }

    /// Builds a standard signed commit (current time).
    fn build_commit(previous: Option<CommitHash>) -> Commit {
        build_commit_at(previous, Utc::now().timestamp(), "test")
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    /// Spec §8.3: sync_rebase on an empty input returns an empty vec.
    #[test]
    fn empty_input_returns_empty() {
        let result = sync_rebase(vec![]).unwrap();
        assert!(result.is_empty());
    }

    /// Spec §8.3: sync_rebase on a single genesis returns it unchanged.
    #[test]
    fn single_genesis_returns_unchanged() {
        let genesis = build_commit(None);
        let id = genesis.commit_id.clone();
        let result = sync_rebase(vec![genesis]).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].commit_id, id);
        assert!(result[0].previous_hash.is_none());
    }

    /// Spec §8.3: sync_rebase on a linear chain returns it in chain order
    /// without modifying any commit.
    #[test]
    fn linear_chain_is_returned_in_chain_order_unchanged() {
        let genesis = build_commit(None);
        let second = build_commit(Some(genesis.commit_id.clone()));
        let third = build_commit(Some(second.commit_id.clone()));

        let genesis_id = genesis.commit_id.clone();
        let second_id = second.commit_id.clone();
        let third_id = third.commit_id.clone();

        // Feed in reverse order to ensure reordering works
        let result = sync_rebase(vec![third, genesis, second]).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].commit_id, genesis_id);
        assert_eq!(result[1].commit_id, second_id);
        assert_eq!(result[2].commit_id, third_id);

        // No sync_metadata should be set for an already-linear chain
        for commit in &result {
            assert!(commit.sync_metadata.pre_sync_previous_hash.is_none());
            assert!(commit.sync_metadata.pre_sync_commit_id.is_none());
        }
    }

    // -----------------------------------------------------------------------
    // Two-branch fork — the spec §8.3 canonical example
    // -----------------------------------------------------------------------

    /// Spec §8.3: A two-branch fork is resolved by timestamp ordering.
    /// The earlier branch's commits are preserved unchanged.
    #[test]
    fn two_branch_fork_is_linearized_by_timestamp() {
        let genesis = build_commit(None);
        let genesis_id = genesis.commit_id.clone();

        // Branch 1: earlier timestamp
        let branch1 = build_commit_at(Some(genesis_id.clone()), 1_000_000, "branch1");
        let branch1_id = branch1.commit_id.clone();

        // Branch 2: later timestamp — forks from same genesis
        let branch2 = build_commit_at(Some(genesis_id.clone()), 1_000_060, "branch2");

        let result = sync_rebase(vec![genesis, branch1, branch2]).unwrap();

        assert_eq!(result.len(), 3);
        // genesis unchanged
        assert_eq!(result[0].commit_id, genesis_id);
        // branch1 first (earlier timestamp), unchanged
        assert_eq!(result[1].commit_id, branch1_id);
        assert!(result[1].sync_metadata.pre_sync_previous_hash.is_none());
        // branch2 rebased after branch1
        assert_eq!(
            result[2].previous_hash,
            Some(branch1_id.clone()),
            "branch2 must be re-linked after branch1"
        );
    }

    /// Spec §8.3: The earlier-timestamp branch must not be rebased.
    #[test]
    fn earlier_branch_is_preserved_unchanged() {
        let genesis = build_commit(None);
        let genesis_id = genesis.commit_id.clone();

        let early = build_commit_at(Some(genesis_id.clone()), 1_000_000, "early");
        let early_id = early.commit_id.clone();
        let early_prev = early.previous_hash.clone();
        let early_sig = early.signature.clone();

        let late = build_commit_at(Some(genesis_id.clone()), 1_000_999, "late");

        let result = sync_rebase(vec![genesis, early, late]).unwrap();

        // The early commit is first after genesis — nothing changes
        assert_eq!(result[1].commit_id, early_id);
        assert_eq!(result[1].previous_hash, early_prev);
        assert_eq!(result[1].signature, early_sig);
        assert!(result[1].sync_metadata.pre_sync_previous_hash.is_none());
        assert!(result[1].sync_metadata.pre_sync_commit_id.is_none());
    }

    /// Spec §8.3: The rebased commit must have a new commit_id reflecting
    /// its updated previous_hash.
    #[test]
    fn rebased_commit_gets_new_commit_id() {
        let genesis = build_commit(None);
        let genesis_id = genesis.commit_id.clone();

        let early = build_commit_at(Some(genesis_id.clone()), 1_000_000, "early");
        let late = build_commit_at(Some(genesis_id.clone()), 1_000_999, "late");
        let late_original_id = late.commit_id.clone();

        let result = sync_rebase(vec![genesis, early, late]).unwrap();

        // late was rebased — its commit_id must be different from the original
        assert_ne!(
            result[2].commit_id, late_original_id,
            "rebased commit must have a new commit_id"
        );
        // The new commit_id must have the sha256: prefix
        assert!(result[2].commit_id.as_str().starts_with("sha256:"));
    }

    /// Spec §8.3: sync_metadata must preserve the original previous_hash and
    /// commit_id for full audit traceability.
    #[test]
    fn rebased_commit_sync_metadata_preserves_originals() {
        let genesis = build_commit(None);
        let genesis_id = genesis.commit_id.clone();

        let early = build_commit_at(Some(genesis_id.clone()), 1_000_000, "early");
        let late = build_commit_at(Some(genesis_id.clone()), 1_000_999, "late");

        let late_original_prev = late.previous_hash.clone();
        let late_original_id = late.commit_id.clone();

        let result = sync_rebase(vec![genesis, early, late]).unwrap();

        let rebased = &result[2];
        assert_eq!(
            rebased.sync_metadata.pre_sync_previous_hash,
            late_original_prev,
            "pre_sync_previous_hash must equal the original previous_hash"
        );
        assert_eq!(
            rebased.sync_metadata.pre_sync_commit_id,
            Some(late_original_id),
            "pre_sync_commit_id must equal the original commit_id"
        );
    }

    /// Spec §8.3: The signature on a rebased commit must be preserved
    /// unchanged — it remains valid against the original canonical bytes.
    #[test]
    fn rebased_commit_signature_is_preserved() {
        let genesis = build_commit(None);
        let genesis_id = genesis.commit_id.clone();

        let early = build_commit_at(Some(genesis_id.clone()), 1_000_000, "early");
        let late = build_commit_at(Some(genesis_id.clone()), 1_000_999, "late");
        let late_original_sig = late.signature.clone();

        let result = sync_rebase(vec![genesis, early, late]).unwrap();

        assert_eq!(
            result[2].signature, late_original_sig,
            "signature must be preserved unchanged after rebase"
        );
    }

    /// Spec §8.3: Commits with identical timestamps are ordered by commit_id
    /// lexicographically (deterministic tiebreaker for ±60s clock skew).
    #[test]
    fn tiebreaker_uses_commit_id_lexicographic_order() {
        let genesis = build_commit(None);
        let genesis_id = genesis.commit_id.clone();

        // Both branches created at exactly the same timestamp
        let same_ts = 1_000_000i64;
        let a = build_commit_at(Some(genesis_id.clone()), same_ts, "commit_a");
        let b = build_commit_at(Some(genesis_id.clone()), same_ts, "commit_b");

        // Ensure b's commit_id is lexicographically greater than a's
        // so we can assert ordering
        let a_id = a.commit_id.as_str().to_string();
        let b_id = b.commit_id.as_str().to_string();

        let (first, second) = if a_id < b_id { (a, b) } else { (b, a) };
        let first_id = first.commit_id.clone();

        let result = sync_rebase(vec![genesis, first, second]).unwrap();

        // first (lexicographically smaller commit_id) should come before second
        assert_eq!(result[1].commit_id, first_id);
    }

    /// Spec §8.3: Multi-commit branches — a fork where each branch has
    /// multiple commits — must be fully linearized with cascading rebase.
    #[test]
    fn multi_commit_fork_is_fully_linearized() {
        // Build: genesis → A → B (branch 1, earlier timestamps)
        //                ↘ C → D (branch 2, later timestamps)
        let genesis = build_commit(None);
        let genesis_id = genesis.commit_id.clone();

        let a = build_commit_at(Some(genesis_id.clone()), 1_000, "a");
        let a_id = a.commit_id.clone();
        let b = build_commit_at(Some(a_id.clone()), 2_000, "b");

        let c = build_commit_at(Some(genesis_id.clone()), 3_000, "c");
        let c_original_id = c.commit_id.clone();
        let d = build_commit_at(Some(c_original_id.clone()), 4_000, "d");
        let d_original_id = d.commit_id.clone();

        let result = sync_rebase(vec![genesis, a, b, c, d]).unwrap();

        // Expected linear order by timestamp: genesis(0) → A(1k) → B(2k) → C'(3k) → D'(4k)
        assert_eq!(result.len(), 5);
        assert!(result[0].previous_hash.is_none(), "genesis must be first");
        assert_eq!(result[1].previous_hash, Some(result[0].commit_id.clone()));
        assert_eq!(result[2].previous_hash, Some(result[1].commit_id.clone()));
        assert_eq!(result[3].previous_hash, Some(result[2].commit_id.clone()));
        assert_eq!(result[4].previous_hash, Some(result[3].commit_id.clone()));

        // C and D should have been rebased (their sync_metadata must be set)
        assert!(result[3].sync_metadata.pre_sync_previous_hash.is_some());
        assert!(result[4].sync_metadata.pre_sync_previous_hash.is_some());

        // The rebased D's pre_sync_commit_id should be the original D commit_id
        assert_eq!(
            result[4].sync_metadata.pre_sync_commit_id,
            Some(d_original_id)
        );
    }

    /// Spec §8.3: sync_rebase must be deterministic — the same forked input
    /// always produces the same linear chain regardless of input order.
    #[test]
    fn rebase_is_deterministic_regardless_of_input_order() {
        let genesis = build_commit(None);
        let genesis_id = genesis.commit_id.clone();

        let early = build_commit_at(Some(genesis_id.clone()), 1_000, "early");
        let late = build_commit_at(Some(genesis_id.clone()), 2_000, "late");

        let result_a = sync_rebase(vec![
            genesis.clone(),
            early.clone(),
            late.clone(),
        ])
        .unwrap();

        let result_b = sync_rebase(vec![
            late.clone(),
            genesis.clone(),
            early.clone(),
        ])
        .unwrap();

        // The chain order and commit_ids must be identical regardless of input order
        assert_eq!(result_a.len(), result_b.len());
        for (a, b) in result_a.iter().zip(result_b.iter()) {
            assert_eq!(a.commit_id, b.commit_id);
        }
    }

    /// Spec §8.3: After rebase, the full chain must satisfy chain continuity:
    /// every commit's previous_hash equals the preceding commit's commit_id.
    #[test]
    fn rebased_chain_satisfies_chain_continuity() {
        let genesis = build_commit(None);
        let genesis_id = genesis.commit_id.clone();

        let a = build_commit_at(Some(genesis_id.clone()), 100, "a");
        let b = build_commit_at(Some(genesis_id.clone()), 200, "b");
        let c = build_commit_at(Some(genesis_id.clone()), 300, "c");

        let result = sync_rebase(vec![genesis, a, b, c]).unwrap();

        // Check full chain continuity
        assert!(result[0].previous_hash.is_none());
        for i in 1..result.len() {
            assert_eq!(
                result[i].previous_hash,
                Some(result[i - 1].commit_id.clone()),
                "chain continuity violated at position {}: expected {:?}, got {:?}",
                i,
                Some(&result[i - 1].commit_id),
                &result[i].previous_hash
            );
        }
    }
}
