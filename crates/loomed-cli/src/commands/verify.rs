//! # `loomed verify`
//!
//! Verifies the cryptographic integrity of the vault.
//!
//! Two modes are supported:
//!
//! - `loomed verify --chain`        — verifies the full hash chain from genesis to HEAD
//! - `loomed verify <commit_id>`    — verifies a single commit by ID
//!
//! ## What this command does (--chain mode)
//! 1. Opens the vault in the current directory
//! 2. Prompts for the vault passphrase
//! 3. Reads all commits by traversing the chain from HEAD to genesis
//! 4. Reverses the list to get genesis-to-HEAD order
//! 5. Runs the chain verifier from loomed-core
//! 6. Prints the result for each commit and an overall verdict
//!
//! ## What this command does (<commit_id> mode)
//! 1. Validates the commit_id prefix
//! 2. Opens the vault in the current directory
//! 3. Prompts for the vault passphrase
//! 4. Reads and decrypts the specific commit
//! 5. Runs verify_commit() against the vault's public key
//! 6. Prints hash validity, signature validity, and overall verdict
//!
//! ## What it does NOT do
//! - Modify any data
//! - Require network access

use std::env;

use loomed_core::{verify_chain, verify_commit, CommitHash};
use loomed_store::Vault;

/// Runs the `loomed verify` command.
///
/// Dispatches to single-commit or full-chain verification based on the
/// arguments provided. Exactly one of `commit_id` or `chain` must be
/// supplied — if neither is provided, usage guidance is printed.
///
/// # Arguments
///
/// * `commit_id` — If `Some`, verifies the single commit with this ID.
/// * `chain` — If `true`, verifies the full hash chain from genesis to HEAD.
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised, the passphrase
/// is incorrect, or any commit file cannot be read.
///
/// See spec §7 and §20.
pub fn run(commit_id: Option<&str>, chain: bool) -> Result<(), Box<dyn std::error::Error>> {
    match (commit_id, chain) {
        (Some(id), false) => verify_single(id),
        (None, true) => verify_full_chain(),
        (Some(_), true) => {
            eprintln!("error: --chain and <commit_id> cannot be used together");
            eprintln!("usage:");
            eprintln!("  loomed verify <commit_id>   — verify a single commit");
            eprintln!("  loomed verify --chain        — verify the full hash chain");
            std::process::exit(1);
        }
        (None, false) => {
            println!("usage:");
            println!("  loomed verify <commit_id>   — verify a single commit");
            println!("  loomed verify --chain        — verify the full hash chain");
            Ok(())
        }
    }
}

/// Verifies a single commit by its commit_id.
///
/// Reads the commit from disk, recomputes its hash, and verifies its
/// ed25519 signature against the vault owner's public key from vault.toml.
///
/// Exits with code 1 if the commit fails verification.
///
/// # Arguments
///
/// * `commit_id` — The full commit_id string, including the `sha256:` prefix.
///
/// # Errors
///
/// Returns a boxed error if the vault is not found, the commit file cannot
/// be read, or the passphrase is incorrect.
///
/// See spec §7.
fn verify_single(commit_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1 — Validate prefix before opening vault or prompting passphrase.
    // Per coding standards §0.6: fail fast before credentials.
    if !commit_id.starts_with("sha256:") {
        return Err(format!(
            "invalid commit_id: \"{}\"\ncommit IDs must begin with \"sha256:\"",
            commit_id
        )
        .into());
    }

    // Step 2 — Open the vault
    let current_dir = env::current_dir()?;
    let vault = Vault::open(&current_dir)?;

    // Step 3 — Prompt for passphrase only after all preconditions pass.
    // Per coding standards §0.6.
    let passphrase = rpassword::prompt_password("vault passphrase: ")?;
    let passphrase_bytes = passphrase.as_bytes();

    // Step 4 — Read and decrypt the commit
    let hash = CommitHash(commit_id.to_string());
    let commit = vault.read_commit(&hash, passphrase_bytes)?;

    // Step 5 — Verify hash and signature against the vault owner's public key.
    //
    // In Phase 1, all commits are self-authored and signed with the keypair
    // derived from passphrase + salt. The public key in vault.toml is the
    // verifying key for all Phase 1 commits. See spec §7.
    //
    // TODO: In Phase 4, the public key will be loaded from the vault's
    // persisted key file rather than vault.toml. The call site interface
    // does not change — only the source of the key changes. See spec §4
    // and coding standards §0.1.
    let public_key = &vault.metadata.public_key;
    let result = verify_commit(&commit, public_key)?;

    // Step 6 — Print result
    println!();
    println!("verifying commit {}", commit_id);
    println!();

    let hash_status = if result.hash_valid { "✓ valid" } else { "✗ INVALID" };
    let sig_status = if result.signature_valid { "✓ valid" } else { "✗ INVALID" };

    println!("  hash      : {}", hash_status);
    println!("  signature : {}", sig_status);
    println!();

    if result.is_valid {
        println!("ok — commit verified.");
    } else {
        if !result.hash_valid {
            println!("FAILED — hash mismatch: commit has been tampered with.");
        }
        if !result.signature_valid {
            println!("FAILED — signature invalid.");
        }
        std::process::exit(1);
    }

    Ok(())
}

/// Verifies the full hash chain from genesis to HEAD.
///
/// Traverses every commit in the vault, verifies each commit's hash and
/// signature, and checks that the previous_hash links are unbroken.
///
/// Exits with code 1 if any commit fails verification or any chain link
/// is broken.
///
/// # Errors
///
/// Returns a boxed error if the vault is not found, any commit file cannot
/// be read, or the passphrase is incorrect.
///
/// See spec §7.
fn verify_full_chain() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;

    // Step 1 — Open the vault
    let vault = Vault::open(&current_dir)?;

    // Step 2 — Check HEAD before prompting passphrase.
    // Per coding standards §0.6: fail fast before credentials.
    let head = vault.read_head()?;
    if head.is_none() {
        println!("no commits to verify.");
        return Ok(());
    }

    // Step 3 — Prompt for passphrase
    let passphrase = rpassword::prompt_password("vault passphrase: ")?;
    let passphrase_bytes = passphrase.as_bytes();

    // Step 4 — Traverse the chain from HEAD to genesis
    let mut commits = Vec::new();
    let mut current: Option<CommitHash> = head;

    while let Some(commit_id) = current {
        let commit = vault.read_commit(&commit_id, passphrase_bytes)?;
        let previous = commit.previous_hash.clone();
        commits.push(commit);
        current = previous;
    }

    // Step 5 — Reverse to genesis-to-HEAD order for the verifier
    commits.reverse();

    // Step 6 — Run chain verification.
    //
    // TODO: In Phase 4, the public key will be loaded from the vault's
    // persisted key file rather than vault.toml. The call site interface
    // does not change — only the source of the key changes. See spec §4
    // and coding standards §0.1.
    let public_key = &vault.metadata.public_key;
    let result = verify_chain(&commits, public_key)?;

    // Step 7 — Print results
    println!();
    println!("verifying {} commit(s)...", result.commit_count);
    println!();

    for verification in &result.commits {
        let status = if verification.is_valid { "✓" } else { "✗" };
        println!("  {} {}", status, verification.commit_id.as_str());
        if !verification.hash_valid {
            println!("    hash      : INVALID — commit has been tampered with");
        }
        if !verification.signature_valid {
            println!("    signature : INVALID");
        }
    }

    println!();
    if result.chain_valid {
        println!("chain ok — all {} commit(s) verified.", result.commit_count);
    } else {
        if let Some(ref failure) = result.first_failure {
            println!("chain FAILED — first failure at: {}", failure.as_str());
        }
        std::process::exit(1);
    }

    Ok(())
}