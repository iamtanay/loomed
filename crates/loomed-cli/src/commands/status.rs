//! # `loomed status`
//!
//! Displays the current state of the vault: the vault owner, the HEAD
//! commit, and the currently staged record (if any).
//!
//! ## What this command does
//! 1. Opens the vault in the current directory
//! 2. Reads the vault metadata (patient_id, public_key) from vault.toml
//! 3. Reads the HEAD file to find the latest commit_id
//! 4. Reads staged.json to check whether a record is staged
//! 5. Prints a summary of all three
//!
//! ## What it does NOT do
//! - Prompt for a passphrase (all data read here is plaintext)
//! - Decrypt any commit files
//! - Modify any data
//!
//! ## Design note
//! `loomed status` is the equivalent of `git status` — a zero-cost
//! inspection of the current working state. It requires no credentials
//! because everything it reads (vault.toml, HEAD, staged.json) is
//! stored in plaintext by design. Medical record content is never
//! exposed here.

use std::env;

use loomed_store::{read_staged, Vault};

/// Runs the `loomed status` command.
///
/// Reads vault metadata, HEAD, and the staging area — all plaintext —
/// and prints a summary of the current vault state. No passphrase is
/// required.
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised or if any
/// plaintext file cannot be read.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;
    let vault_dir = current_dir.join(".loomed");

    // Step 1 — Open the vault. Fails clearly if not initialised.
    let vault = Vault::open(&current_dir)?;

    // Step 2 — Read HEAD (plaintext — no passphrase needed).
    let head = vault.read_head()?;

    // Step 3 — Check staging area (plaintext — no passphrase needed).
    let staged = read_staged(&vault_dir)?;

    // Step 4 — Print vault state.
    println!();
    println!("vault");
    println!("  patient  : {}", vault.metadata.patient_id);
    println!("  key      : {}", vault.metadata.public_key);
    println!("  protocol : {}", vault.metadata.protocol_version);
    println!("  idp      : {}", vault.metadata.idp_type);
    println!();

    // HEAD — the last committed record in the chain.
    match &head {
        Some(commit_id) => println!("head       : {}", commit_id.as_str()),
        None => println!("head       : none (vault is empty — run `loomed commit` after `loomed add`)"),
    }

    println!();

    // Staged record — the next record waiting to be committed.
    match &staged {
        None => {
            println!("staged     : nothing staged");
            println!("             run `loomed add --type <type> -m \"message\"` to stage a record.");
        }
        Some(record) => {
            let type_str = serde_json::to_string(&record.record_type)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string();

            println!("staged");
            println!("  type     : {}", type_str);
            println!("  message  : {}", record.message);

            // Show payload summary if non-empty.
            // In Phase 1, payload may be an empty object — skip printing
            // it in that case to avoid noise. Once schema enforcement is
            // active (Session 4+), payloads will always be non-empty.
            let payload_is_empty = record.payload
                .as_object()
                .map(|o| o.is_empty())
                .unwrap_or(false);

            if !payload_is_empty {
                println!();
                println!("  payload");
                let pretty = serde_json::to_string_pretty(&record.payload)
                    .unwrap_or_else(|_| "<payload could not be displayed>".to_string());
                for line in pretty.lines() {
                    println!("    {}", line);
                }
            }
        }
    }

    println!();

    Ok(())
}