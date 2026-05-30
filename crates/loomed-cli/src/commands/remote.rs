//! # `loomed remote set`
//!
//! Configures the sync remote for the current vault.
//!
//! ## What this command does
//! 1. Opens the vault in the current directory
//! 2. Validates the provided path exists (for local backends)
//! 3. Writes the path to `vault.toml` as `sync_remote`
//!
//! ## What it does NOT do
//! - Require the vault passphrase — vault.toml is plaintext
//! - Connect to any network
//! - Push or pull any data
//!
//! See spec §5 and §8.1.

use std::env;

use loomed_store::Vault;

/// Runs the `loomed remote set <path>` command.
///
/// Configures the sync remote in vault.toml. Validates that the provided
/// path exists as a filesystem path so the user gets an immediate error if
/// they mistype it, rather than discovering the problem at sync time.
///
/// # Arguments
///
/// * `path` — The filesystem path to use as the sync remote.
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised, the path
/// does not exist, or vault.toml cannot be written.
///
/// See spec §5 and §8.1.
pub fn run(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;

    // Step 1 — Open the vault. Fails with a clear error if not initialised.
    let mut vault = Vault::open(&current_dir)?;

    // Step 2 — Validate the path exists so the user gets immediate feedback.
    //
    // For local backends the remote must be an existing directory. Future
    // cloud URIs (s3://, gcs://) will bypass this check.
    if !path.contains("://") && !std::path::Path::new(path).exists() {
        return Err(format!(
            "path not found: \"{}\"\nthe remote directory must exist before setting it",
            path
        )
        .into());
    }

    // Step 3 — Persist the remote to vault.toml.
    vault.set_remote(path)?;

    println!("remote set: {}", path);
    println!("run `loomed sync` to push committed records to this remote.");

    Ok(())
}
