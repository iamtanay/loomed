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
//! 5. Runs the chain verifier from loomed-core, using the genesis
//!    commit's own embedded public key — not `vault.metadata.public_key`,
//!    which reflects the *current* key after any `loomed key rotate` and
//!    would be the wrong key to verify pre-rotation commits against
//! 6. Prints the result for each commit and an overall verdict
//!
//! ## What this command does (<commit_id> mode)
//! 1. Validates the commit_id prefix
//! 2. Opens the vault in the current directory
//! 3. Prompts for the vault passphrase
//! 4. Reads the full chain from genesis (same as --chain mode) so the
//!    correct key for the target commit's position can be resolved even
//!    if a key rotation occurred before or after it
//! 5. Runs verify_commit() against the key active at that position
//! 6. Prints hash validity, signature validity, and overall verdict
//!
//! ## What it does NOT do
//! - Modify any data
//! - Require network access

use std::env;

use loomed_core::{resolve_signing_keys, verify_chain, verify_commit, Commit};
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

/// Reads every commit in the vault by traversing from HEAD to genesis via
/// `previous_hash`, then reverses the list to genesis-first order.
///
/// Shared by both verification modes: single-commit verification needs
/// the full chain to resolve which key was active at the target commit's
/// position (see [`resolve_signing_keys`]), and full-chain verification
/// obviously needs every commit regardless.
///
/// # Errors
///
/// Returns a boxed error if any commit cannot be read or decrypted with
/// `passphrase_bytes`.
fn load_full_chain(
    vault: &Vault,
    passphrase_bytes: &[u8],
) -> Result<Vec<Commit>, Box<dyn std::error::Error>> {
    let mut commits = Vec::new();
    let mut current = vault.read_head()?;

    while let Some(commit_id) = current {
        let commit = vault.read_commit(&commit_id, passphrase_bytes)?;
        current = commit.previous_hash.clone();
        commits.push(commit);
    }

    commits.reverse();
    Ok(commits)
}

/// Returns the public key embedded in the genesis commit's own payload —
/// the key that signed it, and the starting point for
/// [`resolve_signing_keys`] across the rest of the chain.
///
/// This is read from the genesis commit itself rather than
/// `vault.metadata.public_key`, which reflects the *current* signing key
/// and would be the wrong key to verify pre-rotation commits against
/// after a `loomed key rotate`. See spec §12.1.
///
/// # Errors
///
/// Returns a boxed error if `commits` is empty or the first commit's
/// payload does not carry a `public_key` field.
fn genesis_public_key(commits: &[Commit]) -> Result<&str, Box<dyn std::error::Error>> {
    commits
        .first()
        .and_then(|genesis| genesis.payload.get("public_key"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "genesis commit is missing its embedded public_key".into())
}

/// Verifies a single commit by its commit_id.
///
/// Reads the full chain from genesis, resolves which public key was
/// active at the target commit's position (accounting for any
/// `loomed key rotate` before or after it), and verifies the target
/// commit's hash and signature against that key.
///
/// Exits with code 1 if the commit fails verification.
///
/// # Arguments
///
/// * `commit_id` — The full commit_id string, including the `sha256:` prefix.
///
/// # Errors
///
/// Returns a boxed error if the vault is not found, the target commit_id
/// is not present in the chain, any commit file cannot be read, or the
/// passphrase is incorrect.
///
/// See spec §7 and §12.1.
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

    // Step 3 — Prompt for passphrase via the shared helper.
    //
    // In interactive use this prompts the terminal via rpassword.
    // When LOOMED_PASSPHRASE is set the env var value is used directly.
    // See commands::read_passphrase and coding standards §0.6.
    let passphrase = super::read_passphrase("vault passphrase: ")?;
    let passphrase_bytes = passphrase.as_bytes();

    // Step 4 — Read the full chain from genesis and locate the target
    // commit's position within it, so the correct key for that position
    // can be resolved even across a key rotation. See spec §12.1.
    let commits = load_full_chain(&vault, passphrase_bytes)?;
    let genesis_key = genesis_public_key(&commits)?;
    let signing_keys = resolve_signing_keys(&commits, genesis_key);

    let index = commits
        .iter()
        .position(|c| c.commit_id.as_str() == commit_id)
        .ok_or_else(|| format!("commit not found in this vault's chain: {}", commit_id))?;

    let commit = &commits[index];

    // Step 5 — Verify hash and signature against the key active at this
    // commit's position in the chain. See spec §7 and §12.1.
    let result = verify_commit(commit, &signing_keys[index])?;

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

    // Step 3 — Prompt for passphrase via the shared helper.
    //
    // In interactive use this prompts the terminal via rpassword.
    // When LOOMED_PASSPHRASE is set the env var value is used directly.
    // See commands::read_passphrase and coding standards §0.6.
    let passphrase = super::read_passphrase("vault passphrase: ")?;
    let passphrase_bytes = passphrase.as_bytes();

    // Step 4 — Read the full chain from genesis to HEAD
    let commits = load_full_chain(&vault, passphrase_bytes)?;

    // Step 5 — Run chain verification, starting from the key embedded in
    // the genesis commit's own payload rather than vault.metadata.public_key
    // (which reflects the *current* key after any `loomed key rotate`).
    // verify_chain resolves the correct key per commit internally when the
    // chain contains one or more key rotations. See spec §7 and §12.1.
    let genesis_key = genesis_public_key(&commits)?;
    let result = verify_chain(&commits, genesis_key)?;

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