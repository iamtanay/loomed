//! # `loomed commit`
//!
//! Signs and commits the currently staged record to the vault.
//!
//! ## What this command does
//! 1. Validates the `--token <token_id>` format, if provided, before
//!    opening the vault or prompting for anything
//! 2. Opens the vault in the current directory
//! 3. Checks that a staged record exists before prompting for passphrase
//! 4. Prompts for the vault passphrase
//! 5. Reads the current HEAD to determine previous_hash
//! 6. Derives the deterministic signing keypair from passphrase + salt
//! 7. If `--token` was given: traverses the chain to find the token and
//!    confirm it has not already been presented, then runs the full
//!    spec §10.1–§10.2 authorization check (signature, expiry, access
//!    type, scope) against the staged record's type
//! 8. Builds the commit via loomed-core builder — `SelfAuthored` by
//!    default, or `ConsentToken { token_id }` when `--token` was given
//! 9. Signs the canonical bytes
//! 10. Finalises the commit (embeds signature, computes commit_id)
//! 11. Writes the encrypted .lmc file to disk
//! 12. Clears the staging area
//!
//! ## Token Enforcement (spec §10)
//! A token authorizes a write if and only if: its `patient_signature`
//! verifies against the vault's own public key, it has not expired, its
//! `access_type` is `Write`, its scope permits the staged record's type,
//! and no earlier commit in this vault already carries this token's ID.
//! The last check is what makes a token single-use — once a commit is
//! written under a token, that commit is itself the permanent,
//! tamper-evident "used" marker; no separate marker commit is needed.
//!
//! ## What it does NOT do
//! - Modify any existing commit
//! - Connect to any network
//! - Support a separate institution identity — in this phase, the same
//!   vault keypair both issues and (when exercised via `--token`) is
//!   checked against the presented token. Real cross-participant writes
//!   need per-participant keys, which land with the identity provider
//!   work (see FIRST_RELEASE_PLAN.md)

use std::env;

use loomed_core::{builder, AuthorizationRef, Commit, ConsentToken, RecordType};
use loomed_crypto::sign;
use loomed_store::{clear_staged, read_staged, Vault};

/// Runs the `loomed commit` command.
///
/// # Arguments
///
/// * `token` — The `--token <token_id>` value, if provided. When present,
///   the commit is authorized by this consent token instead of being
///   self-authored; the token must pass every spec §10 enforcement check.
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised, there is no
/// staged record, the token_id is malformed, the token cannot be found,
/// has expired, has already been used, does not grant write access to
/// this record type, the passphrase is incorrect, or any I/O operation
/// fails.
pub fn run(token: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1 — Validate the token_id format before opening the vault or
    // prompting for anything. Per coding standards §0.6.
    if let Some(token_id) = token {
        if !token_id.starts_with("lmt_") {
            return Err(format!(
                "invalid token_id: \"{}\"\nconsent token IDs must begin with \"lmt_\"",
                token_id
            )
            .into());
        }
    }

    let current_dir = env::current_dir()?;
    let vault_dir = current_dir.join(".loomed");

    // Step 2 — Open the vault
    let vault = Vault::open(&current_dir)?;

    // Step 3 — Check for a staged record before prompting for passphrase.
    //
    // We check staging first so the user is not asked for their passphrase
    // only to be told nothing is staged. Fail fast with a clear message.
    let staged = read_staged(&vault_dir)?
        .ok_or("nothing staged. run `loomed add --type <type> -m \"message\"` first.")?;

    // Step 4 — Prompt for passphrase via the shared helper.
    //
    // In interactive use this prompts the terminal via rpassword.
    // When LOOMED_PASSPHRASE is set the env var value is used directly.
    // See commands::read_passphrase and coding standards §0.6.
    let passphrase = super::read_passphrase("vault passphrase: ")?;
    let passphrase_bytes = passphrase.as_bytes();

    // Step 5 — Read current HEAD to determine previous_hash
    let previous_hash = vault.read_head()?;

    // Step 6 — Derive the deterministic signing keypair from passphrase + salt.
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

    let patient_id = loomed_core::ParticipantId::new(&vault.metadata.patient_id)?;

    // Step 7 — If a token was presented, find it in the chain, confirm it
    // has not already been used, and run the full authorization check.
    let authorization_ref = match token {
        None => AuthorizationRef::SelfAuthored,
        Some(token_id_str) => {
            let token = find_and_authorize_token(
                &vault,
                passphrase_bytes,
                token_id_str,
                &staged.record_type,
                &vault.metadata.public_key,
            )?;
            AuthorizationRef::ConsentToken {
                token_id: token.token_id,
            }
        }
    };

    // Step 8 — Build the commit from the staged record
    let pending = builder::prepare(
        patient_id.clone(),
        patient_id.clone(),
        patient_id,
        staged.record_type,
        staged.message.clone(),
        staged.payload,
        previous_hash,
        authorization_ref,
    )?;

    // Step 9 — Sign the canonical bytes
    let signature = sign(&keypair, &pending.canonical_bytes);

    // Step 10 — Finalise the commit
    let commit = pending.finalise(signature)?;
    let commit_id = commit.commit_id.clone();

    // Step 11 — Write the encrypted .lmc file
    vault.write_commit(&commit, passphrase_bytes)?;

    // Step 12 — Clear the staging area
    clear_staged(&vault_dir)?;

    println!("committed: {}", commit_id);
    println!(
        "  type    : {}",
        serde_json::to_string(&commit.record_type)
            .unwrap_or_default()
            .trim_matches('"')
    );
    println!("  message : {}", commit.message);
    if let Some(token_id_str) = token {
        println!("  token   : {}", token_id_str);
    }

    Ok(())
}

/// Finds a consent token by ID in the vault's commit chain, confirms it
/// has not already been used, and runs the full spec §10.1–§10.2
/// authorization check against `record_type`.
///
/// Traverses the full chain from HEAD to genesis in a single pass,
/// checking every commit for either an `AuthorizationRef::ConsentToken`
/// already carrying this token_id (meaning it was already used) or a
/// `consent_token` record whose payload is this token's issuance.
///
/// # Errors
///
/// * [`loomed_core::LooMedError::TokenNotFound`] — No `consent_token`
///   commit in the chain issued this token_id.
/// * [`loomed_core::LooMedError::TokenAlreadyUsed`] — An earlier commit
///   already carries this token_id as its authorization.
/// * [`loomed_core::LooMedError::TokenSignatureInvalid`],
///   [`loomed_core::LooMedError::TokenExpired`],
///   [`loomed_core::LooMedError::TokenNotAuthorizedForWrite`] — See
///   [`ConsentToken::authorize_write`].
fn find_and_authorize_token(
    vault: &Vault,
    passphrase_bytes: &[u8],
    token_id_str: &str,
    record_type: &RecordType,
    public_key: &str,
) -> Result<ConsentToken, Box<dyn std::error::Error>> {
    let mut found_token: Option<ConsentToken> = None;
    let mut already_used = false;

    let mut current = vault.read_head()?;
    while let Some(commit_id) = current {
        let commit: Commit = vault.read_commit(&commit_id, passphrase_bytes)?;

        if let AuthorizationRef::ConsentToken { token_id } = &commit.authorization_ref {
            if token_id.as_str() == token_id_str {
                already_used = true;
            }
        }

        if found_token.is_none() && commit.record_type == RecordType::ConsentToken {
            if let Ok(candidate) = serde_json::from_value::<ConsentToken>(commit.payload.clone()) {
                if candidate.token_id.as_str() == token_id_str {
                    found_token = Some(candidate);
                }
            }
        }

        current = commit.previous_hash.clone();
    }

    let token = found_token.ok_or_else(|| loomed_core::LooMedError::TokenNotFound {
        token_id: token_id_str.to_string(),
    })?;

    if already_used {
        return Err(loomed_core::LooMedError::TokenAlreadyUsed {
            token_id: token_id_str.to_string(),
        }
        .into());
    }

    token.authorize_write(public_key, record_type, chrono::Utc::now())?;

    Ok(token)
}
