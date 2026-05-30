//! # loomed-sync
//!
//! Sync layer for the LooMed protocol — transfers encrypted commits between
//! the local patient vault and a remote backend.
//!
//! ## Responsibilities
//! - Defining the `CloudVaultBackend` trait (spec §8)
//! - `LocalFileBackend` — filesystem-based backend for Phase 2 (spec §8.1)
//! - `SyncManager` — orchestrates push and status operations (spec §8.1)
//! - `SyncReport` and `SyncStatus` result types
//!
//! ## Not Responsible For
//! - Cryptographic operations (see `loomed-crypto`)
//! - Local vault I/O (see `loomed-store`)
//! - Conflict resolution / Sync Rebase (spec §8.3 — Phase 2 Session 2)
//! - CLI argument parsing (see `loomed-cli`)
//!
//! ## Backend Abstraction
//!
//! The sync layer never processes plaintext. All bytes transferred are
//! AES-256-GCM ciphertext produced by `loomed-store`. The `CloudVaultBackend`
//! trait is the extension point for future cloud providers (S3, GCS, Azure).
//! Adding a new backend requires only a new trait impl — the CLI, sync
//! algorithm, and tests are unchanged.
//!
//! ## Phase 2 Scope
//!
//! Phase 2 Session 1 (this crate): push and status.
//! Phase 2 Session 2: pull, Sync Rebase conflict resolution (spec §8.3).
//!
//! See spec §8.

pub mod backend;
pub mod error;
pub mod local;
pub mod manager;

pub use backend::CloudVaultBackend;
pub use error::SyncError;
pub use local::LocalFileBackend;
pub use manager::{SyncManager, SyncReport, SyncStatus};
