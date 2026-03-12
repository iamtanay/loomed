//! # `loomed verify`
//!
//! Verifies the integrity of the vault's hash chain.
//!
//! ## What this command does
//! 1. Opens the vault in the current directory
//! 2. Prompts for the vault passphrase
//! 3. Reads all commits by traversing the chain from HEAD to genesis
//! 4. Reverses the list to get genesis-to-HEAD order
//! 5. Runs the chain verifier from loomed-core
//! 6. Prints the result for each commit and an overall verdict
//!
//! ## What it does NOT do
//! - Modify any data
//! - Require network access

use std::env;

use loomed_core::{verify_chain, CommitHash};
use loomed_store::Vault;

/// Runs the `loomed verify` command.
///
/// # Arguments
///
/// * `chain` — If true, verifies the full hash chain. If false, prints
///   usage guidance (additional verify modes are planned for Phase 2+).
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised, the passphrase
/// is incorrect, or any commit file cannot be read.
pub fn run(chain: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !chain {
        println!("usage: loomed verify --chain");
        println!("additional verify modes are planned for future phases.");
        return Ok(());
    }

    let current_dir = env::current_dir()?;

    // Step 1 — Open the vault
    let vault = Vault::open(&current_dir)?;

    // Step 2 — Check HEAD before prompting passphrase
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
    // persisted key file. For now we read it from vault.toml. Because
    // Phase 1 commits are signed with a freshly generated keypair (not
    // the one stored in vault.toml), hash verification will pass but
    // signature verification will fail until Phase 4. This is a known
    // Phase 1 limitation documented in the session summary.
    // See spec §4 and coding standards §0.1.
    let public_key = &vault.metadata.public_key;
    let result = verify_chain(&commits, public_key)?;

    // Step 7 — Print results
    println!();
    println!("verifying {} commit(s)...", result.commit_count);
    println!();

    for verification in &result.commits {
        let status = if verification.is_valid { "✓" } else { "✗" };
        println!(
            "  {} {}",
            status,
            verification.commit_id.as_str()
        );
        if !verification.hash_valid {
            println!("    hash     : INVALID — commit has been tampered with");
        }
        if !verification.signature_valid {
            println!("    signature: INVALID");
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