//! # `loomed add`
//!
//! Stages a medical record for the next commit.
//!
//! ## What this command does
//! 1. Opens the vault in the current directory
//! 2. Validates the record type string
//! 3. If `-i` is passed: prompts for all payload fields interactively
//!    and stages the fully populated record
//! 4. If `-i` is not passed: stages the record with an empty payload —
//!    the default scriptable behaviour
//!
//! ## What it does NOT do
//! - Sign anything
//! - Write any .lmc file
//! - Require the passphrase
//!
//! ## Interactive mode
//! Passing `-i` invokes the prompt layer in `loomed-cli::commands::prompts`.
//! Each record type prompts for its required and optional fields per spec §9.
//! Required fields loop until valid input is provided. Optional fields
//! accept an empty Enter press to skip.

use std::env;

use loomed_core::RecordType;
use loomed_store::{write_staged, StagedRecord, Vault};

use super::prompts;

/// Runs the `loomed add` command.
///
/// # Arguments
///
/// * `record_type` — The record type string from `--type`. Validated before
///   the vault is opened or the user is prompted for anything.
/// * `message` — The commit message from `-m`.
/// * `interactive` — If `true`, prompts for all payload fields interactively
///   via the `-i` flag. If `false`, stages an empty payload.
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised, the record
/// type is invalid, the interactive prompts fail, or the staging area
/// cannot be written.
pub fn run(
    record_type: &str,
    message: &str,
    interactive: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1 — Validate the record type before opening the vault or
    // prompting the user for anything. Per coding standards §0.6:
    // fail fast before credentials or interactive input.
    let parsed_type = parse_record_type(record_type)?;

    // Step 2 — Open the vault. Fails with a clear error if not initialised.
    let current_dir = env::current_dir()?;
    let vault = Vault::open(&current_dir)?;

    // Step 3 — Build the payload.
    //
    // In non-interactive mode, the payload is an empty JSON object. This
    // preserves the scriptable default behaviour and matches the Phase 1
    // design where payload schema enforcement is opt-in via -i.
    //
    // In interactive mode, the prompt layer collects all required and
    // optional fields for this record type and returns a typed RecordPayload,
    // which is then serialised to a serde_json::Value for storage.
    //
    // TODO: In a future session, non-interactive mode will require payload
    // fields to be passed as flags once the schema is stable. For now,
    // the empty payload path remains valid for scripting and testing.
    // See spec §9 and coding standards §0.1.
    let payload = if interactive {
        let record_payload = prompts::prompt_payload(record_type)?;
        record_payload.to_value()?
    } else {
        serde_json::json!({})
    };

    // Step 4 — Write to the staging area.
    let staged = StagedRecord {
        record_type: parsed_type,
        message: message.to_string(),
        payload,
    };

    let vault_dir = current_dir.join(".loomed");
    write_staged(&vault_dir, &staged)?;

    println!("staged: [{}] {}", record_type, message);

    if interactive {
        println!("payload captured. run `loomed commit` to sign and commit this record.");
    } else {
        println!("run `loomed commit` to sign and commit this record.");
    }

    // vault is opened to verify it exists — key persistence in Phase 4
    // will use vault metadata here. See spec §4 and coding standards §0.1.
    let _ = &vault;

    Ok(())
}

/// Parses a record type string into a [`RecordType`] enum variant.
///
/// # Errors
///
/// Returns an error if the string does not match any known record type.
/// The error message lists all valid values for the user.
fn parse_record_type(s: &str) -> Result<RecordType, Box<dyn std::error::Error>> {
    match s {
        "lab_result" => Ok(RecordType::LabResult),
        "prescription" => Ok(RecordType::Prescription),
        "radiology_report" => Ok(RecordType::RadiologyReport),
        "vaccination" => Ok(RecordType::Vaccination),
        "diagnosis" => Ok(RecordType::Diagnosis),
        "procedure" => Ok(RecordType::Procedure),
        other => Err(format!(
            "unknown record type: \"{}\"\nvalid types: lab_result, prescription, radiology_report, vaccination, diagnosis, procedure",
            other
        )
        .into()),
    }
}