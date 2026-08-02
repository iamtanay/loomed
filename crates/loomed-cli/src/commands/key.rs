//! # `loomed key`
//!
//! Identity and key management commands (spec §4, §12.1).
//!
//! ## Subcommands
//! - `loomed key status` — shows the current identity tier and public key
//! - `loomed key rotate`  — writes a self-signed key rotation commit
//!
//! ## `loomed key rotate` — what it does
//! 1. Opens the vault, prompts for the passphrase
//! 2. Derives the current signing keypair via
//!    `Vault::current_signing_salt()` and confirms it matches
//!    `vault.metadata.public_key` (proves the passphrase is correct)
//! 3. Generates a fresh random signing salt — not `argon2_salt`, which
//!    never changes — and derives a new keypair from the same passphrase
//!    and this new salt
//! 4. Writes a self-signed `key_rotation` commit: the OLD key signs,
//!    attesting to the NEW public key (spec §12.1 step 3)
//! 5. Updates vault.toml via `Vault::rotate_signing_key` so all future
//!    signing operations use the new key
//! 6. Scans the chain for every still-active consent token (not expired,
//!    not used, not already revoked) and writes a `token_revocation`
//!    commit for each, signed by the NEW key, so tokens issued under the
//!    old key cannot be presented after rotation (spec §10.2)
//!
//! ## What it does NOT do (v1 scope, see `FIRST_RELEASE_PLAN.md`)
//! - Change the vault passphrase or `argon2_salt` — the AES-256 encryption
//!   key never changes, so every historical `.lmc` file stays readable
//!   under exactly the key it was written with. No re-encryption is
//!   performed (spec §12.1 step 5, deferred past v1.0)
//! - Support custodian quorum or re-authentication — rotation is
//!   patient-initiated and self-authorized only, per Tier 0
//! - Implement Tier 1 (national ID), Tier 2 (hardware enclave), or Tier 3
//!   (Shamir custodian quorum) — v1.0 ships Tier 0 (software passphrase
//!   custody) only

use std::env;

use loomed_core::{builder, AuthorizationRef, RecordType};
use loomed_crypto::{derive_keypair, sign};
use loomed_store::Vault;
use rand::RngCore;

use super::token_chain;

/// Runs the `loomed key status` command.
///
/// Prints the vault's current identity tier and public key. Reads only
/// plaintext vault.toml data — no passphrase is required, matching the
/// design of `loomed status`.
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised.
pub fn status() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;
    let vault = Vault::open(&current_dir)?;

    println!();
    println!("identity");
    println!("  tier       : {}", vault.metadata.idp_type);
    println!("  public key : {}", vault.metadata.public_key);
    println!();

    if vault.metadata.idp_type == "software_passphrase" {
        println!("Tier 0 (software passphrase custody): the signing key is derived");
        println!("deterministically from your vault passphrase. Recovery is possible");
        println!("only via the 24-word recovery phrase shown once at `loomed init`");
        println!("(or at your most recent `loomed key rotate`).");
        println!();
    }

    Ok(())
}

/// Runs the `loomed key rotate` command.
///
/// Writes a self-signed `key_rotation` commit — the current key signs,
/// attesting to a freshly derived new public key — then updates vault.toml
/// so all future signing operations use the new key. Every still-active
/// consent token is explicitly revoked as part of the same operation.
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised, the passphrase
/// does not match the vault's current public key, or any I/O operation
/// fails.
///
/// See spec §12.1 and `FIRST_RELEASE_PLAN.md` R6.
pub fn rotate() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;

    // Step 1 — Open the vault.
    let mut vault = Vault::open(&current_dir)?;

    // Step 2 — Prompt for the passphrase via the shared helper.
    // See commands::read_passphrase and coding standards §0.6.
    let passphrase = super::read_passphrase("vault passphrase: ")?;
    let passphrase_bytes = passphrase.as_bytes();

    // Step 3 — Derive the current keypair and confirm it matches the
    // vault's recorded public key, proving the passphrase is correct
    // before anything is written.
    let old_salt = hex::decode(vault.current_signing_salt())?;
    let old_keypair = derive_keypair(passphrase_bytes, &old_salt)?;

    if old_keypair.public_key_hex() != vault.metadata.public_key {
        return Err(loomed_core::LooMedError::IncorrectPassphrase.into());
    }

    // Step 4 — Generate a fresh random signing salt before deriving the
    // new keypair, per coding standards §0.5. This salt is independent of
    // argon2_salt, which never changes — see this module's doc comment.
    let mut new_salt_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut new_salt_bytes);
    let new_signing_salt = hex::encode(new_salt_bytes);
    let new_keypair = derive_keypair(passphrase_bytes, &new_salt_bytes)?;
    let new_public_key = new_keypair.public_key_hex();

    let patient_id = loomed_core::ParticipantId::new(&vault.metadata.patient_id)?;

    // Step 5 — Build and sign the key_rotation commit with the OLD key,
    // attesting to the NEW public key. See spec §12.1 step 3.
    let mut previous_hash = vault.read_head()?;
    let rotation_payload = serde_json::json!({
        "old_public_key": vault.metadata.public_key,
        "new_public_key": new_public_key,
        "idp_type": "software_passphrase",
    });

    let pending = builder::prepare(
        patient_id.clone(),
        patient_id.clone(),
        patient_id.clone(),
        RecordType::KeyRotation,
        "key rotation".to_string(),
        rotation_payload,
        previous_hash.clone(),
        AuthorizationRef::SelfAuthored,
    )?;
    let signature = sign(&old_keypair, &pending.canonical_bytes);
    let rotation_commit = pending.finalise(signature)?;
    let rotation_commit_id = rotation_commit.commit_id.clone();

    vault.write_commit(&rotation_commit, passphrase_bytes)?;
    previous_hash = Some(rotation_commit_id.clone());

    // Step 6 — Update vault.toml to the new key and signing salt.
    // argon2_salt is untouched — see this module's doc comment.
    vault.rotate_signing_key(&new_public_key, &new_signing_salt)?;

    // Step 7 — Revoke every still-active consent token. Tokens issued
    // under the old key would fail signature verification against the
    // new one anyway (spec §10.2), but an explicit token_revocation
    // commit makes the invalidation auditable rather than an incidental
    // side effect. Signed with the NEW key, since these commits chain
    // after the rotation. See spec §10.2 and §12.1.
    let active_tokens: Vec<_> = token_chain::scan_all_tokens(&vault, passphrase_bytes)?
        .into_iter()
        .filter(|state| {
            state.used_by.is_none()
                && state.revoked_at.is_none()
                && state.token.expires_at > chrono::Utc::now()
        })
        .collect();

    let mut revoked_count = 0;
    for state in &active_tokens {
        let token_id = state.token.token_id.as_str();
        let payload = serde_json::json!({ "token_id": token_id });
        let message = format!("consent token {} revoked by key rotation", token_id);

        let pending = builder::prepare(
            patient_id.clone(),
            patient_id.clone(),
            patient_id.clone(),
            RecordType::TokenRevocation,
            message,
            payload,
            previous_hash.clone(),
            AuthorizationRef::SelfAuthored,
        )?;
        let signature = sign(&new_keypair, &pending.canonical_bytes);
        let commit = pending.finalise(signature)?;
        previous_hash = Some(commit.commit_id.clone());

        vault.write_commit(&commit, passphrase_bytes)?;
        revoked_count += 1;
    }

    // Step 8 — Print summary.
    println!();
    println!("key rotated successfully.");
    println!();
    println!("  old public key : {}", old_keypair.public_key_hex());
    println!("  new public key : {}", new_public_key);
    println!("  rotation commit: {}", rotation_commit_id.as_str());
    println!("  tokens revoked : {}", revoked_count);
    println!();
    println!("historical records remain encrypted under your original");
    println!("passphrase-derived key — only the signing key rotated.");
    println!("vault re-encryption on rotation is not yet implemented.");
    println!();

    Ok(())
}
