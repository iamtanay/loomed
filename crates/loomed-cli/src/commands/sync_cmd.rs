//! # `loomed sync`
//!
//! Synchronises the local patient vault with the configured remote backend.
//!
//! ## What this command does (push mode)
//! 1. Opens the vault in the current directory
//! 2. Resolves the sync remote from vault.toml (or the --to flag)
//! 3. Connects to the backend (Phase 2: LocalFileBackend)
//! 4. Pushes all commits present locally but absent from the remote
//! 5. Updates the remote HEAD
//! 6. Prints a summary of what was pushed
//!
//! ## What this command does (--status mode)
//! 1. Opens the vault in the current directory
//! 2. Resolves the sync remote
//! 3. Lists which local commits are not yet on the remote
//! 4. Prints a summary — no data is transferred
//!
//! ## What it does NOT do
//! - Require the vault passphrase — push transfers raw encrypted bytes
//! - Pull from remote to local (Phase 2 Session 2)
//! - Resolve sync conflicts / Sync Rebase (Phase 2 Session 2)
//!
//! See spec §8 and §20.

use std::env;

use loomed_store::Vault;
use loomed_sync::{LocalFileBackend, SyncError, SyncManager};

/// Runs the `loomed sync` and `loomed sync --status` commands.
///
/// In push mode (default): pushes all commits absent from the remote and
/// updates the remote HEAD. No passphrase is required — only encrypted
/// bytes are transferred.
///
/// In status mode (`--status`): reports how many commits are pending
/// without transferring any data.
///
/// # Arguments
///
/// * `status_only` — If `true`, print status and exit without pushing.
/// * `to` — An optional remote path that overrides the configured remote
///   in vault.toml. Useful for one-off syncs or first-time setup.
///
/// # Errors
///
/// Returns a boxed error if no remote is configured, the remote is
/// inaccessible, or any I/O fails.
///
/// See spec §8 and §20.
pub fn run(status_only: bool, to: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;

    // Step 1 — Open the vault.
    let vault = Vault::open(&current_dir)?;

    // Step 2 — Resolve the sync remote.
    //
    // The --to flag overrides the configured remote for this invocation.
    // If neither is set, fail fast with a clear error before any I/O.
    let remote_path = match to {
        Some(path) => path.to_string(),
        None => vault
            .metadata
            .sync_remote
            .clone()
            .ok_or(SyncError::RemoteNotConfigured)?,
    };

    // Step 3 — Connect to the backend.
    //
    // Phase 2: LocalFileBackend handles local filesystem paths.
    // TODO: Phase 2+: resolve URI scheme (s3://, gcs://) to the appropriate
    // backend impl once cloud backends are added. The call site below
    // does not change — only the resolved backend type changes.
    // See spec §8 and coding standards §0.1.
    let backend = LocalFileBackend::new(&remote_path)?;
    let manager = SyncManager::new(&vault);

    if status_only {
        run_status(&manager, &backend, &remote_path)
    } else {
        run_push(&manager, &backend, &remote_path)
    }
}

/// Runs the push path: transfer unsynced commits to the remote.
fn run_push<B: loomed_sync::CloudVaultBackend>(
    manager: &SyncManager,
    backend: &B,
    remote_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("syncing to {}...", remote_path);

    let report = manager.push(backend)?;

    if report.pushed.is_empty() {
        if report.already_remote == 0 {
            println!("nothing to sync — vault has no commits.");
        } else {
            println!(
                "already up to date. {} commit(s) on remote.",
                report.already_remote
            );
        }
        return Ok(());
    }

    for commit_id in &report.pushed {
        println!("  pushed  {}", commit_id.as_str());
    }

    println!();
    println!(
        "sync complete. {} commit(s) pushed, {} already on remote.",
        report.pushed.len(),
        report.already_remote
    );

    Ok(())
}

/// Runs the status path: show pending commits without transferring data.
fn run_status<B: loomed_sync::CloudVaultBackend>(
    manager: &SyncManager,
    backend: &B,
    remote_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = manager.status(backend)?;

    println!("remote: {}", remote_path);

    if status.pending.is_empty() {
        println!(
            "up to date — all {} commit(s) are on the remote.",
            status.synced_count
        );
        return Ok(());
    }

    println!(
        "{} commit(s) pending sync ({} already on remote):",
        status.pending.len(),
        status.synced_count
    );

    for commit_id in &status.pending {
        println!("  pending  {}", commit_id.as_str());
    }

    println!();
    println!("run `loomed sync` to push these commits.");

    Ok(())
}
