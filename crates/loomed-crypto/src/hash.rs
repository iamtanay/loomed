//! # Hashing
//!
//! SHA-256 commit hashing and BLAKE3 payload content hashing.
//!
//! ## Responsibilities
//! - Computing commit_id from a serialised commit object (spec §6.2, §7)
//! - Computing content_hash from a payload (spec §6.2)
//!
//! ## Not Responsible For
//! - Serialising commit structs (see `loomed-core`)
//! - Verifying the hash chain (see `loomed-core::verify`)

use sha2::{Digest, Sha256};

use crate::error::CryptoError;

/// Computes the SHA-256 commit hash from a serialised commit object.
///
/// The input must be the full JSON-serialised commit object with the
/// `commit_id` field excluded (set to an empty string or omitted).
/// The output is prefixed with `"sha256:"` as required by the protocol.
///
/// # Arguments
///
/// * `commit_json` — The JSON bytes of the commit object, with commit_id excluded.
///
/// # Returns
///
/// A `String` of the form `"sha256:<lowercase hex>"`.
///
/// # Errors
///
/// This function is infallible for valid byte slices. The `CryptoError`
/// return type is reserved for future use with streaming input.
///
/// See spec §6.2 and §7.
pub fn compute_commit_hash(commit_json: &[u8]) -> Result<String, CryptoError> {
    let mut hasher = Sha256::new();
    hasher.update(commit_json);
    let result = hasher.finalize();
    Ok(format!("sha256:{}", hex::encode(result)))
}

/// Computes the BLAKE3 content hash from a serialised payload.
///
/// The input must be the JSON-serialised payload field only — not the
/// full commit object. The output is prefixed with `"blake3:"` as
/// required by the protocol.
///
/// # Arguments
///
/// * `payload_json` — The JSON bytes of the payload object.
///
/// # Returns
///
/// A `String` of the form `"blake3:<lowercase hex>"`.
///
/// See spec §6.2.
pub fn compute_content_hash(payload_json: &[u8]) -> Result<String, CryptoError> {
    let hash = blake3::hash(payload_json);
    Ok(format!("blake3:{}", hash.to_hex()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec §6.2: commit hash output must be prefixed with "sha256:".
    #[test]
    fn commit_hash_has_correct_prefix() {
        let hash = compute_commit_hash(b"test input").unwrap();
        assert!(hash.starts_with("sha256:"));
    }

    /// Spec §6.2: content hash output must be prefixed with "blake3:".
    #[test]
    fn content_hash_has_correct_prefix() {
        let hash = compute_content_hash(b"test payload").unwrap();
        assert!(hash.starts_with("blake3:"));
    }

    /// Spec §7: identical inputs must produce identical commit hashes.
    #[test]
    fn commit_hash_is_deterministic() {
        let hash1 = compute_commit_hash(b"same input").unwrap();
        let hash2 = compute_commit_hash(b"same input").unwrap();
        assert_eq!(hash1, hash2);
    }

    /// Spec §7: different inputs must produce different commit hashes.
    #[test]
    fn different_inputs_produce_different_hashes() {
        let hash1 = compute_commit_hash(b"input one").unwrap();
        let hash2 = compute_commit_hash(b"input two").unwrap();
        assert_ne!(hash1, hash2);
    }
}