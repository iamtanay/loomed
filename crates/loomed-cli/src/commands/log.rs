//! # `loomed log`
//!
//! Displays the full commit history from HEAD to genesis.
//!
//! ## What this command does
//! 1. Opens the vault in the current directory
//! 2. Prompts for the vault passphrase
//! 3. Reads HEAD and traverses the chain backwards via previous_hash
//! 4. Prints each commit in reverse chronological order (newest first)
//!
//! ## What it does NOT do
//! - Verify signatures or hashes (use `loomed verify --chain` for that)
//! - Modify any data

use std::env;

use loomed_core::CommitHash;
use loomed_store::Vault;

/// Runs the `loomed log` command.
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised, the passphrase
/// is incorrect, or any commit file cannot be read.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;

    // Step 1 — Open the vault
    let vault = Vault::open(&current_dir)?;

    // Step 2 — Check HEAD before prompting passphrase
    let head = vault.read_head()?;
    if head.is_none() {
        println!("no commits yet.");
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

    // Step 5 — Print commits (already in reverse chronological order)
    println!();
    for commit in &commits {
        println!(
            "commit  {}",
            commit.commit_id.as_str()
        );
        println!(
            "type    {}",
            serde_json::to_string(&commit.record_type)
                .unwrap_or_default()
                .trim_matches('"')
        );
        println!("date    {}", commit.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("        {}", commit.message);
        println!();
    }

    println!("{} commit(s) total.", commits.len());

    Ok(())
}