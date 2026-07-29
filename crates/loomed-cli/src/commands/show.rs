//! # `loomed show`
//!
//! Inspects and displays a specific commit from the vault by its commit_id.
//!
//! ## What this command does
//! 1. Opens the vault in the current directory
//! 2. Validates the commit_id prefix before any vault I/O or credential prompt
//! 3. Prompts for the vault passphrase
//! 4. Reads and decrypts the specific .lmc file for this commit_id
//! 5. Displays every commit field, with typed payload display per spec §9
//!
//! ## Typed Payload Display (spec §9)
//! For the six clinical record types (lab_result, prescription, radiology_report,
//! vaccination, diagnosis, procedure), the payload is deserialised into its
//! typed struct and displayed as labelled fields. Records staged without `-i`
//! (empty payload) show a brief note instead of an empty JSON block. Protocol
//! record types (key_rotation, vault_reencryption, etc.) fall back to raw JSON.
//!
//! ## What it does NOT do
//! - Verify signatures or hashes — use `loomed verify <commit_id>` for that
//! - Modify any data
//! - Traverse the chain — reads exactly one commit by ID

use std::env;

use loomed_core::{
    payload::{
        DiagnosisPayload, LabResultPayload, PrescriptionPayload, ProcedurePayload,
        RadiologyReportPayload, VaccinationPayload,
    },
    AuthorizationRef, CommitHash, RecordType,
};
use loomed_store::Vault;

/// Runs the `loomed show <commit_id>` command.
///
/// Validates the commit_id prefix (fail fast per coding standards §0.6),
/// then reads, decrypts, and displays the commit with typed payload fields
/// where the record type is one of the six clinical types defined in spec §9.
///
/// # Arguments
///
/// * `commit_id` — The full commit_id string from the CLI argument, including
///   the `sha256:` prefix.
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised, the commit_id
/// is not found on disk, the passphrase is incorrect, or any I/O fails.
///
/// See spec §6.2 and §20.
pub fn run(commit_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;

    // Step 1 — Validate the commit_id prefix before opening vault or
    // prompting for a passphrase. Per coding standards §0.6.
    if !commit_id.starts_with("sha256:") {
        return Err(format!(
            "invalid commit_id: \"{}\"\ncommit IDs must begin with \"sha256:\"",
            commit_id
        )
        .into());
    }

    // Step 2 — Open the vault. Fails with a clear error if not initialised.
    let vault = Vault::open(&current_dir)?;

    // Step 3 — Prompt for passphrase via the shared helper.
    //
    // In interactive use this prompts the terminal via rpassword.
    // When LOOMED_PASSPHRASE is set the env var value is used directly.
    // See commands::read_passphrase and coding standards §0.7.
    let passphrase = super::read_passphrase("vault passphrase: ")?;
    let passphrase_bytes = passphrase.as_bytes();

    // Step 4 — Read and decrypt the specific commit file.
    let hash = CommitHash(commit_id.to_string());
    let commit = vault.read_commit(&hash, passphrase_bytes)?;

    // Step 5 — Display all commit fields defined in spec §6.2.
    println!();
    println!("commit      {}", commit.commit_id.as_str());
    println!(
        "type        {}",
        serde_json::to_string(&commit.record_type)
            .unwrap_or_default()
            .trim_matches('"')
    );
    println!("date        {}", commit.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("message     {}", commit.message);
    println!();
    println!("patient     {}", commit.patient_id.as_str());
    println!("author      {}", commit.author_id.as_str());
    println!("authored by {}", commit.authored_by.as_str());
    println!(
        "previous    {}",
        commit
            .previous_hash
            .as_ref()
            .map(|h| h.as_str())
            .unwrap_or("none (genesis)")
    );
    println!("content     {}", commit.content_hash.as_str());
    println!("signature   {}", commit.signature);
    println!("protocol    {}", commit.protocol_version);

    // Authorization context — see spec §10
    let auth_str = match &commit.authorization_ref {
        AuthorizationRef::SelfAuthored => "self_authored".to_string(),
        AuthorizationRef::ConsentToken { token_id } => {
            format!("consent_token({})", token_id.as_str())
        }
    };
    println!("auth        {}", auth_str);

    // Sync metadata — see spec §8. pre_sync_previous_hash and
    // pre_sync_commit_id are populated only when Sync Rebase has re-linked
    // this commit (spec §8.3); shown only when present so unrebased commits
    // display exactly as before.
    println!();
    println!("sync");
    println!("  offline                {}", commit.sync_metadata.created_offline);
    println!(
        "  synced_at              {}",
        commit
            .sync_metadata
            .synced_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "not yet synced".to_string())
    );
    if let Some(ref pre_hash) = commit.sync_metadata.pre_sync_previous_hash {
        println!("  pre_sync_previous_hash {}", pre_hash.as_str());
    }
    if let Some(ref pre_id) = commit.sync_metadata.pre_sync_commit_id {
        println!("  pre_sync_commit_id     {}", pre_id.as_str());
    }

    // Typed payload display per spec §9
    println!();
    display_payload(&commit.record_type, &commit.payload);
    println!();

    Ok(())
}

// ---------------------------------------------------------------------------
// Payload display — spec §9
// ---------------------------------------------------------------------------

/// Displays the commit payload with typed field labels where the record type
/// is one of the six clinical types defined in spec §9.
///
/// Empty payloads (staged without `-i`) print a brief note. Protocol-level
/// record types (key_rotation, vault_reencryption, etc.) fall back to raw JSON.
/// Deserialisation failures also fall back to raw JSON with a note.
///
/// See spec §9.
fn display_payload(record_type: &RecordType, payload: &serde_json::Value) {
    println!("payload");

    // Empty payload — staged with `loomed add` without -i.
    if payload.as_object().map(|o| o.is_empty()).unwrap_or(false) {
        println!("  (empty — record was staged without interactive prompts)");
        return;
    }

    match record_type {
        RecordType::LabResult => display_lab_result(payload),
        RecordType::Prescription => display_prescription(payload),
        RecordType::RadiologyReport => display_radiology_report(payload),
        RecordType::Vaccination => display_vaccination(payload),
        RecordType::Diagnosis => display_diagnosis(payload),
        RecordType::Procedure => display_procedure(payload),
        // Protocol-internal types carry arbitrary payloads — show raw JSON.
        _ => display_raw_json(payload),
    }
}

/// Prints a single labelled payload field with consistent column alignment.
///
/// Label is left-padded to 16 characters so all values line up cleanly
/// regardless of label length.
fn print_payload_field(label: &str, value: &str) {
    println!("  {:<16}{}", format!("{}:", label), value);
}

/// Displays raw JSON payload indented under the payload header.
///
/// Used as the fallback for protocol-internal record types and when typed
/// deserialisation fails. See spec §9.
fn display_raw_json(payload: &serde_json::Value) {
    let pretty = serde_json::to_string_pretty(payload)
        .unwrap_or_else(|_| "<payload could not be serialised>".to_string());
    for line in pretty.lines() {
        println!("  {}", line);
    }
}

// ---------------------------------------------------------------------------
// §9.1 Lab Result
// ---------------------------------------------------------------------------

/// Displays a `LabResultPayload` as labelled fields.
///
/// Falls back to raw JSON if the payload cannot be deserialised.
/// See spec §9.1.
fn display_lab_result(payload: &serde_json::Value) {
    match serde_json::from_value::<LabResultPayload>(payload.clone()) {
        Ok(p) => {
            print_payload_field("test_name", &p.test_name);
            print_payload_field("test_code", &p.test_code);
            print_payload_field("value", &p.value.to_string());
            print_payload_field("unit", &p.unit);
            print_payload_field(
                "ref_range",
                &format!("{} – {}", p.reference_range.min, p.reference_range.max),
            );
            print_payload_field("status", &p.status);
            if let Some(ref device_id) = p.device_id {
                print_payload_field("device_id", device_id);
            }
            if let Some(ref notes) = p.notes {
                print_payload_field("notes", notes);
            }
        }
        Err(_) => {
            println!("  (could not parse as lab_result — displaying raw JSON)");
            display_raw_json(payload);
        }
    }
}

// ---------------------------------------------------------------------------
// §9.2 Prescription
// ---------------------------------------------------------------------------

/// Displays a `PrescriptionPayload` as labelled fields.
///
/// Falls back to raw JSON if the payload cannot be deserialised.
/// See spec §9.2.
fn display_prescription(payload: &serde_json::Value) {
    match serde_json::from_value::<PrescriptionPayload>(payload.clone()) {
        Ok(p) => {
            print_payload_field("drug_name", &p.drug_name);
            print_payload_field("drug_code", &p.drug_code);
            print_payload_field("dosage", &p.dosage);
            print_payload_field("frequency", &p.frequency);
            print_payload_field("duration", &format!("{} days", p.duration_days));
            print_payload_field("instructions", &p.instructions);
            print_payload_field("reason", &p.reason);
            if let Some(refills) = p.refills {
                print_payload_field("refills", &refills.to_string());
            }
            if let Some(ref diagnosis_ref) = p.diagnosis_ref {
                print_payload_field("diagnosis_ref", diagnosis_ref);
            }
        }
        Err(_) => {
            println!("  (could not parse as prescription — displaying raw JSON)");
            display_raw_json(payload);
        }
    }
}

// ---------------------------------------------------------------------------
// §9.3 Radiology Report
// ---------------------------------------------------------------------------

/// Displays a `RadiologyReportPayload` as labelled fields, including the
/// mandatory `external_ref` block.
///
/// Raw imaging files are never stored in LooMed. The external_ref links to
/// the custodian institution that holds them. See spec §9.3 and §9.7.
///
/// Falls back to raw JSON if the payload cannot be deserialised.
fn display_radiology_report(payload: &serde_json::Value) {
    match serde_json::from_value::<RadiologyReportPayload>(payload.clone()) {
        Ok(p) => {
            print_payload_field("report_id", &p.report_id);
            print_payload_field("modality", &p.modality);
            print_payload_field("body_part", &p.body_part);
            print_payload_field("findings", &p.findings);
            print_payload_field("impression", &p.impression);
            print_payload_field("radiologist", &p.radiologist_id);
            if let Some(ref machine_id) = p.machine_id {
                print_payload_field("machine_id", machine_id);
            }
            // External reference — always present per spec §9.3
            println!("  external_ref:");
            println!("    ref_id       : {}", p.external_ref.ref_id);
            println!("    ref_type     : {}", p.external_ref.ref_type);
            println!("    custodian    : {}", p.external_ref.custodian_id);
            println!("    description  : {}", p.external_ref.description);
            println!("    retrieval    : {}", p.external_ref.retrieval);
        }
        Err(_) => {
            println!("  (could not parse as radiology_report — displaying raw JSON)");
            display_raw_json(payload);
        }
    }
}

// ---------------------------------------------------------------------------
// §9.4 Vaccination
// ---------------------------------------------------------------------------

/// Displays a `VaccinationPayload` as labelled fields.
///
/// Falls back to raw JSON if the payload cannot be deserialised.
/// See spec §9.4.
fn display_vaccination(payload: &serde_json::Value) {
    match serde_json::from_value::<VaccinationPayload>(payload.clone()) {
        Ok(p) => {
            print_payload_field("vaccine_name", &p.vaccine_name);
            print_payload_field("vaccine_code", &p.vaccine_code);
            print_payload_field("manufacturer", &p.manufacturer);
            print_payload_field("batch_number", &p.batch_number);
            print_payload_field(
                "dose",
                &format!("{} of {}", p.dose_number, p.total_doses),
            );
            print_payload_field("site", &p.site);
            if let Some(ref next_dose) = p.next_dose_due {
                print_payload_field("next_dose_due", next_dose);
            }
            if let Some(ref programme) = p.programme {
                print_payload_field("programme", programme);
            }
            if let Some(ref programme_id) = p.programme_id {
                print_payload_field("programme_id", programme_id);
            }
        }
        Err(_) => {
            println!("  (could not parse as vaccination — displaying raw JSON)");
            display_raw_json(payload);
        }
    }
}

// ---------------------------------------------------------------------------
// §9.5 Diagnosis
// ---------------------------------------------------------------------------

/// Displays a `DiagnosisPayload` as labelled fields, including the
/// `supporting_refs` list.
///
/// Falls back to raw JSON if the payload cannot be deserialised.
/// See spec §9.5.
fn display_diagnosis(payload: &serde_json::Value) {
    match serde_json::from_value::<DiagnosisPayload>(payload.clone()) {
        Ok(p) => {
            print_payload_field("condition", &p.condition);
            print_payload_field("icd_code", &p.icd_code);
            print_payload_field("severity", &p.severity);
            print_payload_field("onset", &p.onset);
            print_payload_field("status", &p.status);
            if let Some(ref notes) = p.notes {
                print_payload_field("notes", notes);
            }
            if !p.supporting_refs.is_empty() {
                println!("  supporting_refs:");
                for r in &p.supporting_refs {
                    println!("    {}", r);
                }
            }
        }
        Err(_) => {
            println!("  (could not parse as diagnosis — displaying raw JSON)");
            display_raw_json(payload);
        }
    }
}

// ---------------------------------------------------------------------------
// §9.6 Procedure
// ---------------------------------------------------------------------------

/// Displays a `ProcedurePayload` as labelled fields, including the
/// `team` list.
///
/// Falls back to raw JSON if the payload cannot be deserialised.
/// See spec §9.6.
fn display_procedure(payload: &serde_json::Value) {
    match serde_json::from_value::<ProcedurePayload>(payload.clone()) {
        Ok(p) => {
            print_payload_field("procedure", &p.procedure_name);
            print_payload_field("code", &p.procedure_code);
            print_payload_field("type", &p.procedure_type);
            print_payload_field("anaesthesia", &p.anaesthesia);
            print_payload_field("duration", &format!("{} min", p.duration_minutes));
            print_payload_field("outcome", &p.outcome);
            if let Some(ref notes) = p.notes {
                print_payload_field("notes", notes);
            }
            if let Some(ref diagnosis_ref) = p.diagnosis_ref {
                print_payload_field("diagnosis_ref", diagnosis_ref);
            }
            if !p.team.is_empty() {
                println!("  team:");
                for member in &p.team {
                    println!("    {:<14} {}", format!("{}:", member.role), member.participant_id);
                }
            }
        }
        Err(_) => {
            println!("  (could not parse as procedure — displaying raw JSON)");
            display_raw_json(payload);
        }
    }
}
