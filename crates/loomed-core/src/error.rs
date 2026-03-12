//! # Error Taxonomy
//!
//! All errors that can occur during LooMed protocol operations.
//!
//! Every error variant corresponds to a specific, defined failure mode
//! in the LooMed protocol specification. There are no catch-all string
//! errors. Consuming code must handle each variant explicitly.

/// All errors that can occur during LooMed protocol operations.
///
/// Every variant is a distinct, named type that consuming code can match
/// against. No variant is a generic string. This is a protocol-grade
/// error taxonomy, not a debugging aid.
#[derive(Debug, thiserror::Error)]
pub enum LooMedError {
    /// A commit's stored commit_id does not match the recomputed hash.
    ///
    /// This indicates the commit has been tampered with after signing.
    /// The chain is broken at this point. See spec §7.
    #[error("commit hash mismatch: stored={stored}, computed={computed}")]
    CommitHashMismatch {
        /// The hash stored inside the commit object.
        stored: String,
        /// The hash recomputed from the commit's contents.
        computed: String,
    },

    /// A commit's ed25519 signature failed verification.
    ///
    /// Either the commit was modified after signing, or the wrong public
    /// key was provided for verification. See spec §6.2.
    #[error("signature verification failed for commit {commit_id}")]
    SignatureInvalid {
        /// The commit_id of the commit whose signature failed.
        commit_id: String,
    },

    /// An attempt was made to write a commit by a participant who does
    /// not hold a valid write-scoped consent token.
    ///
    /// In Phase 1, only the vault owner (patient) may write commits.
    /// In Phase 2+, a valid patient-issued write token is required.
    /// See spec §10.
    #[error("unauthorized commit: participant {author_id} does not hold write access to vault {patient_id}")]
    UnauthorizedCommitAuthor {
        /// The participant ID of the unauthorized author.
        author_id: String,
        /// The patient ID of the vault being written to.
        patient_id: String,
    },

    /// The hash chain is broken: a commit's previous_hash does not match
    /// the commit_id of the commit that precedes it in the chain.
    ///
    /// See spec §7.
    #[error("chain broken at commit {commit_id}: expected previous_hash {expected}, found {found}")]
    ChainBroken {
        /// The commit_id where the break was detected.
        commit_id: String,
        /// The previous_hash value that was expected.
        expected: String,
        /// The previous_hash value that was actually found.
        found: String,
    },

    /// A consent token was presented after its expiry timestamp.
    ///
    /// See spec §10.2.
    #[error("consent token {token_id} expired at {expired_at}")]
    TokenExpired {
        /// The ID of the expired token.
        token_id: String,
        /// The timestamp at which the token expired.
        expired_at: String,
    },

    /// A consent token was presented that has already been used.
    ///
    /// Tokens are single-use. Once presented, they are permanently
    /// marked as used and cannot be reused. See spec §10.2.
    #[error("consent token {token_id} has already been used")]
    TokenAlreadyUsed {
        /// The ID of the already-used token.
        token_id: String,
    },

    /// The vault passphrase was incorrect.
    ///
    /// Returned when AES-256-GCM decryption fails due to a wrong
    /// passphrase-derived key.
    #[error("vault decryption failed: incorrect passphrase")]
    IncorrectPassphrase,

    /// A required field was absent from a commit or record.
    #[error("required field missing: {field}")]
    MissingField {
        /// The name of the missing field.
        field: &'static str,
    },

    /// Serialisation of a protocol object failed.
    #[error("serialisation failed: {reason}")]
    SerializationFailed {
        /// The reason serialisation failed.
        reason: String,
    },

    /// The vault has not been initialised.
    ///
    /// Returned when an operation is attempted on a path that contains
    /// no valid LooMed vault. Run `loomed init` first.
    #[error("vault not initialised at {path}")]
    VaultNotInitialised {
        /// The path where the vault was expected but not found.
        path: String,
    },

    /// A participant ID failed format validation.
    ///
    /// The ID did not match the expected format:
    /// `<TYPE>-<SCOPE?>-<BASE32_ID>-<CHECKSUM>`. See spec §3.1.
    #[error("invalid participant ID format: {id}")]
    InvalidParticipantId {
        /// The malformed participant ID string.
        id: String,
    },

    /// A record type string did not match any known record type.
    ///
    /// See spec §9 for the full list of valid record types.
    #[error("unknown record type: {record_type}")]
    UnknownRecordType {
        /// The unrecognised record type string.
        record_type: String,
    },
}