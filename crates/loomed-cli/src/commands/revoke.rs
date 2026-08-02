//! # `loomed revoke`
//!
//! Invalidates an active consent token before its natural expiry.
//!
//! ## What this command does
//! 1. Validates the token_id format before opening the vault or
//!    prompting for anything
//! 2. Opens the vault, prompts for the passphrase
//! 3. Scans the chain to confirm the token exists and has not already
//!    been revoked
//! 4. Writes a `token_revocation` commit referencing the token_id,
//!    chained after HEAD like any other commit
//!
//! ## What it does NOT do
//! - Undo a write that already happened under the token — revocation
//!   only blocks *future* presentation (spec §10.2 makes tokens
//!   single-use in the first place, so a used token revoked afterward
//!   is a no-op in practice; revoking it anyway is harmless and allowed)
//! - Notify the institution the token was issued to — there is no
//!   delivery channel in this phase, same limitation as `loomed share`

use std::env;

use loomed_core::{builder, AuthorizationRef, RecordType};
use loomed_crypto::sign;
use loomed_store::Vault;

use super::token_chain;

/// Runs the `loomed revoke <token_id>` command.
///
/// # Errors
///
/// Returns a boxed error if the token_id is malformed, the vault is not
/// initialised, the token cannot be found, the token was already
/// revoked, the passphrase is incorrect, or any I/O operation fails.
pub fn run(token_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1 — Validate the token_id format before opening the vault or
    // prompting for anything. Per coding standards §0.6.
    if !token_id.starts_with("lmt_") {
        return Err(format!(
            "invalid token_id: \"{}\"\nconsent token IDs must begin with \"lmt_\"",
            token_id
        )
        .into());
    }

    let current_dir = env::current_dir()?;

    // Step 2 — Open the vault
    let vault = Vault::open(&current_dir)?;

    // Step 3 — Prompt for passphrase via the shared helper.
    //
    // Needed even to confirm the token exists — that requires decrypting
    // the chain. See commands::read_passphrase and coding standards §0.6.
    let passphrase = super::read_passphrase("vault passphrase: ")?;
    let passphrase_bytes = passphrase.as_bytes();

    // Step 4 — Confirm the token exists and has not already been revoked.
    let state = token_chain::find_token(&vault, passphrase_bytes, token_id)?.ok_or_else(|| {
        loomed_core::LooMedError::TokenNotFound {
            token_id: token_id.to_string(),
        }
    })?;

    if state.revoked_at.is_some() {
        return Err(loomed_core::LooMedError::TokenAlreadyRevoked {
            token_id: token_id.to_string(),
        }
        .into());
    }

    // Step 5 — Derive the deterministic signing keypair from passphrase + salt.
    //
    // Uses current_signing_salt() rather than argon2_salt directly so that
    // a prior `loomed key rotate` is honoured — argon2_salt never changes
    // (it also derives the AES encryption key), but the signing salt does.
    // See spec §12.1.
    //
    // TODO: In Phase 4, this is replaced by loading a persisted encrypted
    // key file bound to the identity provider. The call site interface does
    // not change — only the source of the key changes. See spec §4 and
    // coding standards §0.1.
    let salt = hex::decode(vault.current_signing_salt())?;
    let keypair = loomed_crypto::derive_keypair(passphrase_bytes, &salt)?;

    let patient_id = loomed_core::ParticipantId::new(&vault.metadata.patient_id)?;
    let previous_hash = vault.read_head()?;

    // Step 6 — Build, sign, and write the token_revocation commit.
    let payload = serde_json::json!({ "token_id": token_id });
    let message = format!("revoked consent token {}", token_id);

    let pending = builder::prepare(
        patient_id.clone(),
        patient_id.clone(),
        patient_id,
        RecordType::TokenRevocation,
        message,
        payload,
        previous_hash,
        AuthorizationRef::SelfAuthored,
    )?;

    let signature = sign(&keypair, &pending.canonical_bytes);
    let commit = pending.finalise(signature)?;
    let commit_id = commit.commit_id.clone();

    vault.write_commit(&commit, passphrase_bytes)?;

    println!("consent token revoked: {}", token_id);
    println!("  commit  : {}", commit_id);
    if state.used_by.is_some() {
        println!("  note    : this token had already been used before revocation");
    }

    Ok(())
}
