//! # `loomed share`
//!
//! Issues a consent token granting an institution scoped, time-bound
//! access to the patient's vault.
//!
//! ## What this command does
//! 1. Validates the recipient participant ID, scope string, duration, and
//!    access type before opening the vault or prompting for anything
//! 2. Opens the vault in the current directory
//! 3. Prompts for the vault passphrase
//! 4. Derives the deterministic signing keypair from passphrase + salt
//! 5. Builds and signs the consent token (spec §10.1)
//! 6. Wraps the signed token in a `consent_token` commit for auditability
//!    and writes it to the vault, chained after the current HEAD
//! 7. Prints the token — this is what gets handed to the institution
//!    out of band; there is no delivery channel in this phase
//!
//! ## What it does NOT do
//! - Enforce the token at presentation time (expiry, single-use, scope
//!   checks) — that is token *enforcement*, landing with write-token
//!   support in a later session
//! - Transmit the token to the institution over any network

use std::env;
use std::str::FromStr;

use loomed_core::{builder, consent, AuthorizationRef, ParticipantId};
use loomed_crypto::sign;
use loomed_store::Vault;

/// Runs the `loomed share` command.
///
/// # Arguments
///
/// * `participant_id` — The institution's participant ID, from the CLI
///   positional argument. Validated before the vault is opened.
/// * `scope` — The scope string (`full_record`, `record_type:<type>`, or
///   `commit:<commit_id>`) from `--scope`.
/// * `duration_hours` — How many hours from now the token remains valid,
///   from `--duration`. Must be positive.
/// * `purpose` — A short statement of why access was requested, from
///   `--purpose`.
/// * `access_type` — `"read"` or `"write"`, from `--access-type`. Defaults
///   to `"read"` when not provided.
///
/// # Errors
///
/// Returns a boxed error if any input fails validation, the vault is not
/// initialised, the passphrase is incorrect, or any I/O operation fails.
pub fn run(
    participant_id: &str,
    scope: &str,
    duration_hours: i64,
    purpose: &str,
    access_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1 — Validate every input before opening the vault or prompting
    // for a passphrase. Per coding standards §0.6: fail fast before
    // credentials.
    let issued_to = ParticipantId::new(participant_id)?;
    let parsed_scope = consent::ConsentScope::from_str(scope)?;
    let parsed_access_type = parse_access_type(access_type)?;

    if purpose.trim().is_empty() {
        return Err("purpose must not be empty".into());
    }

    if duration_hours <= 0 {
        return Err(format!(
            "invalid duration: {} hours (must be positive)",
            duration_hours
        )
        .into());
    }

    // Step 2 — Open the vault. Fails with a clear error if not initialised.
    let current_dir = env::current_dir()?;
    let vault = Vault::open(&current_dir)?;

    // Step 3 — Prompt for passphrase via the shared helper.
    //
    // In interactive use this prompts the terminal via rpassword.
    // When LOOMED_PASSPHRASE is set the env var value is used directly.
    // See commands::read_passphrase and coding standards §0.6.
    let passphrase = super::read_passphrase("vault passphrase: ")?;
    let passphrase_bytes = passphrase.as_bytes();

    // Step 4 — Derive the deterministic signing keypair from passphrase + salt.
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

    let patient_id = ParticipantId::new(&vault.metadata.patient_id)?;

    // Step 5 — Build and sign the consent token.
    let pending_token = consent::prepare_token(
        patient_id.clone(),
        issued_to,
        parsed_scope,
        purpose.to_string(),
        parsed_access_type,
        duration_hours,
    )?;
    let token_signature = sign(&keypair, &pending_token.canonical_bytes);
    let token = pending_token.finalise(token_signature);

    // Step 6 — Wrap the token in a consent_token commit and write it to
    // the vault. The commit's own signature covers the whole commit
    // (including the token payload) for chain integrity; the token's own
    // patient_signature lets it be verified independently once handed to
    // the institution. See spec §10 and §6.2.
    let previous_hash = vault.read_head()?;
    let message = format!("consent token issued to {}", token.issued_to.as_str());
    let payload = serde_json::to_value(&token)?;

    let pending_commit = builder::prepare(
        patient_id.clone(),
        patient_id.clone(),
        patient_id,
        loomed_core::RecordType::ConsentToken,
        message,
        payload,
        previous_hash,
        AuthorizationRef::SelfAuthored,
    )?;
    let commit_signature = sign(&keypair, &pending_commit.canonical_bytes);
    let commit = pending_commit.finalise(commit_signature)?;
    let commit_id = commit.commit_id.clone();

    vault.write_commit(&commit, passphrase_bytes)?;

    // Step 7 — Print the token for out-of-band delivery to the institution.
    println!();
    println!("consent token issued.");
    println!();
    println!("  token_id    : {}", token.token_id.as_str());
    println!("  issued_to   : {}", token.issued_to.as_str());
    println!("  scope       : {}", token.scope);
    println!(
        "  access_type : {}",
        serde_json::to_string(&token.access_type)
            .unwrap_or_default()
            .trim_matches('"')
    );
    println!(
        "  expires_at  : {}",
        token.expires_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!("  commit      : {}", commit_id.as_str());
    println!();
    println!("hand the token below to the institution out of band:");
    println!();
    println!("{}", serde_json::to_string_pretty(&token)?);
    println!();

    Ok(())
}

/// Parses an access type string into [`consent::AccessType`].
///
/// # Errors
///
/// Returns an error listing valid values if the string is neither `"read"`
/// nor `"write"`.
fn parse_access_type(s: &str) -> Result<consent::AccessType, Box<dyn std::error::Error>> {
    match s {
        "read" => Ok(consent::AccessType::Read),
        "write" => Ok(consent::AccessType::Write),
        other => Err(format!(
            "unknown access type: \"{}\"\nvalid values: read, write",
            other
        )
        .into()),
    }
}
