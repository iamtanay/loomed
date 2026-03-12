//! # loomed-crypto
//!
//! Cryptographic primitives for the LooMed protocol.
//!
//! This crate is the only place in the entire LooMed codebase where
//! cryptographic operations are performed. No other crate touches keys,
//! signatures, hashes, or encryption directly.
//!
//! ## Responsibilities
//! - SHA-256 commit hashing (spec §6.2, §7)
//! - BLAKE3 payload content hashing (spec §6.2)
//! - ed25519 keypair generation, signing, and verification (spec §6.2)
//! - Passphrase-to-key derivation via Argon2id (Phase 1 vault encryption)
//! - AES-256-GCM encryption and decryption of vault files
//!
//! ## Not Responsible For
//! - Commit struct definition (see `loomed-core`)
//! - Storing encrypted files to disk (see `loomed-store`)
//! - Identity provider abstraction (spec §4, future: `loomed-idp`)

pub mod hash;
pub mod keys;
pub mod encrypt;
pub mod error;

pub use error::CryptoError;
pub use hash::{compute_commit_hash, compute_content_hash};
pub use keys::{generate_keypair, sign, verify, LooMedKeypair};
pub use encrypt::{derive_key, encrypt, decrypt};