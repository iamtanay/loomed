//! # `loomed audit`
//!
//! Displays the consent token audit trail: every token this vault has
//! issued, and its current status — active, used, expired, or revoked.
//!
//! ## What this command does
//! 1. Opens the vault, prompts for the passphrase (reading token state
//!    requires decrypting the chain)
//! 2. Scans the full chain once for every `consent_token` issuance,
//!    `ConsentToken`-authorized commit, and `token_revocation` commit
//! 3. Prints one entry per issued token, newest-issued first, optionally
//!    filtered to one recipient via `--entity <participant_id>`
//!
//! ## Scope note (v1)
//! This is a derived view over data already in the chain, not a separate
//! spec §11 `access_event` commit log. Spec §11 defines a richer schema
//! (`event_id`, `accessed_by_name`, `records_accessed`) that needs data
//! this CLI does not have yet: `accessed_by_name` needs the participant
//! registry (Phase 5), and a `records_accessed` list only matters once a
//! single token can authorize more than the one write that consumes it —
//! v1 tokens are single-use, so "issued" and "accessed" are already a
//! 1:1 relationship for writes. Read-token presentation is not tracked
//! at all: there is no CLI-level read-access flow yet for an institution
//! to actually present one against (see FIRST_RELEASE_PLAN.md).
//!
//! ## What it does NOT do
//! - Verify signatures or hashes — use `loomed verify --chain` for that
//! - Modify any data

use std::env;

use loomed_store::Vault;

use super::token_chain::{self, TokenState};

/// Runs the `loomed audit` command.
///
/// # Arguments
///
/// * `entity` — The `--entity <participant_id>` value, if provided.
///   When present, only tokens issued to this participant are shown.
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised, the passphrase
/// is incorrect, or any commit cannot be read or decrypted.
pub fn run(entity: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;
    let vault = Vault::open(&current_dir)?;

    let passphrase = super::read_passphrase("vault passphrase: ")?;
    let passphrase_bytes = passphrase.as_bytes();

    let mut states = token_chain::scan_all_tokens(&vault, passphrase_bytes)?;

    if let Some(entity_id) = entity {
        states.retain(|state| state.token.issued_to.as_str() == entity_id);
    }

    // Newest issued first, matching `loomed log`'s reverse-chronological convention.
    states.sort_by_key(|state| std::cmp::Reverse(state.token.issued_at));

    if states.is_empty() {
        println!("no consent tokens issued yet.");
        return Ok(());
    }

    println!();
    for state in &states {
        print_token_entry(state);
    }

    println!("{} token(s) total.", states.len());

    Ok(())
}

/// The current status of a token, derived from its chain-recorded state.
fn status_of(state: &TokenState) -> &'static str {
    if state.revoked_at.is_some() {
        "revoked"
    } else if state.used_by.is_some() {
        "used"
    } else if state.token.expires_at <= chrono::Utc::now() {
        "expired"
    } else {
        "active"
    }
}

/// Prints a single audit entry for one token's chain-derived state.
fn print_token_entry(state: &TokenState) {
    let token = &state.token;

    println!("token       {}", token.token_id.as_str());
    println!("  issued_to   {}", token.issued_to.as_str());
    println!("  scope       {}", token.scope);
    println!(
        "  access_type {}",
        serde_json::to_string(&token.access_type)
            .unwrap_or_default()
            .trim_matches('"')
    );
    println!("  purpose     {}", token.purpose);
    println!(
        "  issued_at   {}",
        token.issued_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "  expires_at  {}",
        token.expires_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!("  status      {}", status_of(state));

    if let Some((commit_id, timestamp)) = &state.used_by {
        println!(
            "  used_at     {} (commit {})",
            timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            commit_id.as_str()
        );
    }

    if let Some(timestamp) = &state.revoked_at {
        println!(
            "  revoked_at  {}",
            timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        );
    }

    println!();
}
