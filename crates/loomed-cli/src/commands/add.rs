//! # `loomed add`
//!
//! Stages a medical record for the next commit.
//!
//! ## What this command does
//! 1. Opens the vault in the current directory
//! 2. Validates the record type string
//! 3. Writes the staged record to .loomed/staged.json
//!
//! ## What it does NOT do
//! - Sign anything
//! - Write any .lmc file
//! - Require the passphrase

use std::env;

use loomed_core::RecordType;
use loomed_store::{write_staged, StagedRecord, Vault};

/// Runs the `loomed add` command.
///
/// # Arguments
///
/// * `record_type` — The record type string from the CLI flag `--type`.
/// * `message` — The commit message from the CLI flag `--message`.
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised, the record
/// type is invalid, or the staging area cannot be written.
pub fn run(record_type: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;

    // Open the vault — fails with a clear error if not initialised
    let vault = Vault::open(&current_dir)?;

    // Parse and validate the record type
    let parsed_type = parse_record_type(record_type)?;

    // Build the staged record
    let staged = StagedRecord {
        record_type: parsed_type,
        message: message.to_string(),
        payload: serde_json::json!({}),
    };

    // Write to staging area
    let vault_dir = current_dir.join(".loomed");
    write_staged(&vault_dir, &staged)?;

    println!("staged: [{}] {}", record_type, message);
    println!("run `loomed commit` to sign and commit this record.");

    // vault is opened to verify it exists — not used further in Phase 1
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
        ).into()),
    }
}