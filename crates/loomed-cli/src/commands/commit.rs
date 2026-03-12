//! # `loomed commit`
//!
//! Signs and commits the currently staged record to the vault.
//!
//! ## What this command does
//! 1. Opens the vault in the current directory
//! 2. Checks that a staged record exists before prompting for passphrase
//! 3. Prompts for the vault passphrase
//! 4. Reads the current HEAD to determine previous_hash
//! 5. Derives the deterministic signing keypair from passphrase + salt
//! 6. Builds the commit via loomed-core builder
//! 7. Signs the canonical bytes
//! 8. Finalises the commit (embeds signature, computes commit_id)
//! 9. Writes the encrypted .lmc file to disk
//! 10. Clears the staging area
//!
//! ## What it does NOT do
//! - Modify any existing commit
//! - Connect to any network

use std::env;

use loomed_core::{builder, AuthorizationRef};
use loomed_crypto::sign;
use loomed_store::{clear_staged, read_staged, Vault};

/// Runs the `loomed commit` command.
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised, there is no
/// staged record, the passphrase is incorrect, or any I/O operation fails.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;
    let vault_dir = current_dir.join(".loomed");

    // Step 1 — Open the vault
    let vault = Vault::open(&current_dir)?;

    // Step 2 — Check for a staged record before prompting for passphrase.
    //
    // We check staging first so the user is not asked for their passphrase
    // only to be told nothing is staged. Fail fast with a clear message.
    let staged = read_staged(&vault_dir)?
        .ok_or("nothing staged. run `loomed add --type <type> -m \"message\"` first.")?;

    // Step 3 — Prompt for passphrase
    let passphrase = rpassword::prompt_password("vault passphrase: ")?;
    let passphrase_bytes = passphrase.as_bytes();

    // Step 4 — Read current HEAD to determine previous_hash
    let previous_hash = vault.read_head()?;

    // Step 5 — Derive the deterministic signing keypair from passphrase + salt.
    //
    // The same passphrase and salt always produce the same keypair, ensuring
    // that commits signed here verify against the public key in vault.toml.
    //
    // TODO: In Phase 4, this is replaced by loading a persisted encrypted
    // key file bound to the identity provider. The call site interface does
    // not change — only the source of the key changes. See spec §4 and
    // coding standards §0.1.
    let salt = hex::decode(&vault.metadata.argon2_salt)?;
    let keypair = loomed_crypto::derive_keypair(passphrase_bytes, &salt)?;

    // Step 6 — Build the commit from the staged record
    let patient_id = loomed_core::ParticipantId::new(&vault.metadata.patient_id)?;

    let pending = builder::prepare(
        patient_id.clone(),
        patient_id.clone(),
        patient_id,
        staged.record_type,
        staged.message.clone(),
        staged.payload,
        previous_hash,
        AuthorizationRef::SelfAuthored,
    )?;

    // Step 7 — Sign the canonical bytes
    let signature = sign(&keypair, &pending.canonical_bytes);

    // Step 8 — Finalise the commit
    let commit = pending.finalise(signature)?;
    let commit_id = commit.commit_id.clone();

    // Step 9 — Write the encrypted .lmc file
    vault.write_commit(&commit, passphrase_bytes)?;

    // Step 10 — Clear the staging area
    clear_staged(&vault_dir)?;

    println!("committed: {}", commit_id);
    println!(
        "  type    : {}",
        serde_json::to_string(&commit.record_type)
            .unwrap_or_default()
            .trim_matches('"')
    );
    println!("  message : {}", commit.message);

    Ok(())
}