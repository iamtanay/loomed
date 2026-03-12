//! # loomed-store
//!
//! Encrypted local vault storage for the LooMed protocol.
//!
//! This crate is the only place in the LooMed codebase that performs
//! file I/O. It reads and writes encrypted commit files to the local
//! vault directory.
//!
//! ## Responsibilities
//! - Initialising a new patient vault on disk (spec §5)
//! - Writing signed commits to encrypted .lmc files (spec §6)
//! - Reading and decrypting commits from disk
//! - Managing the staging area for pending records
//! - Reading the commit log in chain order
//! - Verifying the hash chain of all commits in the vault (spec §7)
//!
//! ## Not Responsible For
//! - Cryptographic primitives (see `loomed-crypto`)
//! - Protocol type definitions (see `loomed-core`)
//! - CLI argument parsing (see `loomed-cli`)
//! - Cloud sync (future: `loomed-sync`)

pub mod error;
pub mod stage;
pub mod vault;

pub use error::StoreError;
pub use stage::{clear_staged, has_staged, read_staged, write_staged, StagedRecord};
pub use vault::Vault;