//! # loomed-core
//!
//! The LooMed protocol core library.
//!
//! This crate defines the protocol types, commit lifecycle, and verification
//! logic for the LooMed patient-owned medical record protocol.
//!
//! ## Responsibilities
//! - Commit struct definition and serialisation (spec §6)
//! - Participant identity types (spec §3)
//! - Hash chain construction and verification (spec §7)
//! - Consent token types (spec §10)
//! - Error taxonomy for all protocol operations
//!
//! ## Not Responsible For
//! - Disk I/O (see `loomed-store`)
//! - Cryptographic primitives (see `loomed-crypto`)
//! - CLI argument parsing (see `loomed-cli`)
//! - Network communication (future: `loomed-sync`)

pub mod builder;
pub mod commit;
pub mod error;
pub mod participant;
pub mod verify;

pub use builder::{prepare, PendingCommit};
pub use commit::{AuthorizationRef, Commit, CommitHash, ContentHash, RecordType, SyncMetadata, TokenId};
pub use error::LooMedError;
pub use participant::{ParticipantId, ParticipantType};
pub use verify::{verify_chain, verify_commit, ChainVerification, CommitVerification};