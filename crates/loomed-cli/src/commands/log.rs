//! # `loomed log`
//!
//! Displays the full commit history from HEAD to genesis.
//!
//! ## What this command does
//! 1. Opens the vault in the current directory
//! 2. Checks HEAD before prompting for passphrase
//! 3. Prompts for the vault passphrase
//! 4. Reads HEAD and traverses the chain backwards via previous_hash
//! 5. Prints each commit in reverse chronological order (newest first),
//!    with a one-line typed payload summary for the six clinical record
//!    types (spec §9)
//!
//! ## What it does NOT do
//! - Verify signatures or hashes (use `loomed verify --chain` for that)
//! - Modify any data

use std::env;

use loomed_core::{
    payload::{
        DiagnosisPayload, LabResultPayload, PrescriptionPayload, ProcedurePayload,
        RadiologyReportPayload, VaccinationPayload,
    },
    CommitHash, RecordType,
};
use loomed_store::Vault;

/// Runs the `loomed log` command.
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised, the passphrase
/// is incorrect, or any commit file cannot be read.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;

    // Step 1 — Open the vault
    let vault = Vault::open(&current_dir)?;

    // Step 2 — Check HEAD before prompting passphrase.
    // Per coding standards §0.6: fail fast before credentials.
    let head = vault.read_head()?;
    if head.is_none() {
        println!("no commits yet.");
        return Ok(());
    }

    // Step 3 — Prompt for passphrase via the shared helper.
    //
    // In interactive use this prompts the terminal via rpassword.
    // When LOOMED_PASSPHRASE is set the env var value is used directly.
    // See commands::read_passphrase and coding standards §0.6.
    let passphrase = super::read_passphrase("vault passphrase: ")?;
    let passphrase_bytes = passphrase.as_bytes();

    // Step 4 — Traverse the chain from HEAD to genesis
    let mut commits = Vec::new();
    let mut current: Option<CommitHash> = head;

    while let Some(commit_id) = current {
        let commit = vault.read_commit(&commit_id, passphrase_bytes)?;
        let previous = commit.previous_hash.clone();
        commits.push(commit);
        current = previous;
    }

    // Step 5 — Print commits (already in reverse chronological order)
    println!();
    for commit in &commits {
        println!("commit  {}", commit.commit_id.as_str());
        println!(
            "type    {}",
            serde_json::to_string(&commit.record_type)
                .unwrap_or_default()
                .trim_matches('"')
        );
        println!("date    {}", commit.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("        {}", commit.message);
        if let Some(summary) = payload_summary(&commit.record_type, &commit.payload) {
            println!("        {}", summary);
        }
        println!();
    }

    println!("{} commit(s) total.", commits.len());

    Ok(())
}

/// Builds a one-line typed payload summary for the six clinical record
/// types defined in spec §9 (e.g. `FBG: 98.5 mg/dL`, `Metformin 500mg × 30d`).
///
/// Returns `None` for an empty payload (staged without `-i`), a protocol-
/// internal record type, or a payload that fails to deserialise as its
/// declared type — in every case `loomed log` simply omits the summary
/// line rather than showing raw JSON. See spec §6.2, §9, §20.
fn payload_summary(record_type: &RecordType, payload: &serde_json::Value) -> Option<String> {
    if payload.as_object().map(|o| o.is_empty()).unwrap_or(false) {
        return None;
    }

    match record_type {
        RecordType::LabResult => serde_json::from_value::<LabResultPayload>(payload.clone())
            .ok()
            .map(|p| format!("{}: {} {}", p.test_code, p.value, p.unit)),
        RecordType::Prescription => {
            serde_json::from_value::<PrescriptionPayload>(payload.clone())
                .ok()
                .map(|p| format!("{} {} \u{d7} {}d", p.drug_name, p.dosage, p.duration_days))
        }
        RecordType::RadiologyReport => {
            serde_json::from_value::<RadiologyReportPayload>(payload.clone())
                .ok()
                .map(|p| format!("{} {}", p.modality, p.body_part))
        }
        RecordType::Vaccination => serde_json::from_value::<VaccinationPayload>(payload.clone())
            .ok()
            .map(|p| format!("{} (dose {} of {})", p.vaccine_name, p.dose_number, p.total_doses)),
        RecordType::Diagnosis => serde_json::from_value::<DiagnosisPayload>(payload.clone())
            .ok()
            .map(|p| format!("{} ({})", p.condition, p.icd_code)),
        RecordType::Procedure => serde_json::from_value::<ProcedurePayload>(payload.clone())
            .ok()
            .map(|p| format!("{} ({} min)", p.procedure_name, p.duration_minutes)),
        _ => None,
    }
}