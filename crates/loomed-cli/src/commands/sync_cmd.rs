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
//! ## What this command does (--pull mode)
//! 1. Opens the vault
//! 2. Fetches all commits from the remote that are absent locally
//! 3. Updates the local HEAD to match the remote HEAD
//! 4. Prints a summary
//!
//! ## What this command does (--resolve mode)
//! 1. Opens the vault
//! 2. Loads all local commits and detects any fork
//! 3. Applies the deterministic Sync Rebase algorithm
//! 4. Updates local HEAD to the linearised chain
//! 5. Prints the number of commits rebased
//!
//! See spec §8 and §20.

use std::env;

use loomed_store::Vault;
use loomed_sync::{LocalFileBackend, SyncError, SyncManager};

/// Runs the `loomed sync`, `loomed sync --status`, `loomed sync --pull`,
/// and `loomed sync --resolve` commands.
///
/// In push mode (default): pushes all commits absent from the remote and
/// updates the remote HEAD. No passphrase is required — only encrypted
/// bytes are transferred.
///
/// In status mode (`--status`): reports how many commits are pending
/// without transferring any data.
///
/// In pull mode (`--pull`): fetches all commits from the remote that are
/// absent locally and updates the local HEAD.
///
/// In resolve mode (`--resolve`): loads all local commits, detects any fork,
/// and applies the deterministic Sync Rebase algorithm to linearise the chain.
///
/// # Arguments
///
/// * `status_only` — If `true`, print status and exit without pushing.
/// * `pull` — If `true`, fetch commits from the remote.
/// * `resolve` — If `true`, resolve any fork via Sync Rebase.
/// * `to` — An optional remote path that overrides the configured remote
///   in vault.toml. Useful for one-off syncs or first-time setup.
///
/// # Errors
///
/// Returns a boxed error if no remote is configured (unless --resolve),
/// the remote is inaccessible, or any I/O fails.
///
/// See spec §8 and §20.
pub fn run(status_only: bool, pull: bool, resolve: bool, to: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;

    // Step 1 — Open the vault.
    let vault = Vault::open(&current_dir)?;

    // Resolve mode does not require a remote (works with local vault only)
    if resolve {
        return run_resolve(&vault);
    }

    // Step 2 — Resolve the sync remote for push/pull/status modes.
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
    } else if pull {
        run_pull(&manager, &backend, &remote_path)
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

/// Runs the pull path: fetch commits from the remote.
fn run_pull<B: loomed_sync::CloudVaultBackend>(
    manager: &SyncManager,
    backend: &B,
    remote_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("pulling from {}...", remote_path);

    let report = manager.pull(backend)?;

    if report.pulled.is_empty() {
        println!("already up to date — no new commits on remote.");
        return Ok(());
    }

    for commit_id in &report.pulled {
        println!("  pulled   {}", commit_id.as_str());
    }

    println!();
    println!(
        "pull complete. {} commit(s) fetched.",
        report.pulled.len()
    );

    if let Some(head) = &report.new_head {
        println!("local HEAD updated to {}", head.as_str());
    }

    Ok(())
}

/// Runs the resolve path: detect and resolve forks via Sync Rebase.
fn run_resolve(vault: &Vault) -> Result<(), Box<dyn std::error::Error>> {
    let passphrase_str = super::read_passphrase("passphrase: ")?;
    let passphrase = passphrase_str.as_bytes();

    println!("checking for forks...");

    let manager = SyncManager::new(vault);
    let rebased_count = manager.resolve(passphrase)?;

    if rebased_count == 0 {
        println!("no forks detected — chain is linear.");
        return Ok(());
    }

    println!();
    println!(
        "resolve complete. {} commit(s) rebased.",
        rebased_count
    );

    println!("chain is now linear and deterministic.");

    Ok(())
}
