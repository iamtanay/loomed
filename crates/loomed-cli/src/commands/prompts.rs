//! # Payload Prompts
//!
//! Interactive field-by-field prompts for building typed record payloads
//! during `loomed add -i`.
//!
//! ## Responsibilities
//! - Prompting the user for required and optional fields per record type
//! - Parsing and validating each field before accepting it
//! - Returning a fully constructed `RecordPayload` ready for staging
//!
//! ## Not Responsible For
//! - Writing to the staging area (see `loomed-store`)
//! - Building or signing commits (see `loomed-core::builder`)
//! - Record type parsing (see `loomed-cli::commands::add`)
//!
//! ## UX Design
//! Required fields loop until valid input is provided.
//! Optional fields accept an empty Enter press to skip, producing `None`.
//! Every prompt labels the field clearly and states expected format
//! where relevant.
//!
//! Interactive mode is opt-in via the `-i` flag on `loomed add`.
//! Without `-i`, `loomed add` stages an empty payload — the default
//! scriptable behaviour is unchanged. See coding standards §0.6.

use std::io::{self, Write};

use loomed_core::payload::{
    DiagnosisPayload, ExternalRef, LabResultPayload, PrescriptionPayload, ProcedurePayload,
    RadiologyReportPayload, RecordPayload, ReferenceRange, TeamMember, VaccinationPayload,
};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Prompts the user for all fields required by the given record type
/// and returns a fully constructed [`RecordPayload`].
///
/// Required fields loop until valid input is given. Optional fields
/// accept an empty Enter press to produce `None`.
///
/// Called only when `loomed add -i` is passed. The default non-interactive
/// path in `loomed add` never calls this function.
///
/// # Arguments
///
/// * `record_type` — The validated record type string (e.g. `"lab_result"`).
///   Must be one of the six types defined in spec §9. The caller is
///   responsible for validating this before calling.
///
/// # Returns
///
/// A [`RecordPayload`] variant matching the record type, with all fields
/// populated from user input.
///
/// # Errors
///
/// Returns a boxed error only if stdin or stdout encounters an I/O failure.
pub fn prompt_payload(record_type: &str) -> Result<RecordPayload, Box<dyn std::error::Error>> {
    println!();
    println!("enter record fields (* = required, press Enter to skip optional fields)");
    println!();

    match record_type {
        "lab_result" => Ok(RecordPayload::LabResult(prompt_lab_result()?)),
        "prescription" => Ok(RecordPayload::Prescription(prompt_prescription()?)),
        "radiology_report" => Ok(RecordPayload::RadiologyReport(prompt_radiology_report()?)),
        "vaccination" => Ok(RecordPayload::Vaccination(prompt_vaccination()?)),
        "diagnosis" => Ok(RecordPayload::Diagnosis(prompt_diagnosis()?)),
        "procedure" => Ok(RecordPayload::Procedure(prompt_procedure()?)),
        other => Err(format!("unknown record type: \"{}\"", other).into()),
    }
}

// ---------------------------------------------------------------------------
// Low-level prompt helpers
// ---------------------------------------------------------------------------

/// Prompts for a required string field.
///
/// Loops until the user enters a non-empty value. The field label is
/// printed with a `*` suffix to indicate it is required.
fn prompt_required(label: &str) -> Result<String, Box<dyn std::error::Error>> {
    loop {
        print!("  {}*: ", label);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_string();

        if trimmed.is_empty() {
            println!("  {} is required — please enter a value.", label);
        } else {
            return Ok(trimmed);
        }
    }
}

/// Prompts for an optional string field.
///
/// Returns `None` if the user presses Enter without entering a value.
fn prompt_optional(label: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    print!("  {}: ", label);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_string();

    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed))
    }
}

/// Prompts for a required `f64` field.
///
/// Loops until the user enters a value that parses as a valid floating
/// point number.
fn prompt_required_f64(label: &str) -> Result<f64, Box<dyn std::error::Error>> {
    loop {
        let raw = prompt_required(label)?;
        match raw.parse::<f64>() {
            Ok(v) => return Ok(v),
            Err(_) => println!("  {} must be a number (e.g. 98.5).", label),
        }
    }
}

/// Prompts for a required `u32` field.
///
/// Loops until the user enters a value that parses as a valid
/// non-negative integer.
fn prompt_required_u32(label: &str) -> Result<u32, Box<dyn std::error::Error>> {
    loop {
        let raw = prompt_required(label)?;
        match raw.parse::<u32>() {
            Ok(v) => return Ok(v),
            Err(_) => println!("  {} must be a whole number (e.g. 30).", label),
        }
    }
}

/// Prompts for an optional `u32` field.
///
/// Returns `None` if the user presses Enter without entering a value.
/// If the user enters a value that does not parse as a whole number,
/// the field is treated as skipped and `None` is returned.
fn prompt_optional_u32(label: &str) -> Result<Option<u32>, Box<dyn std::error::Error>> {
    print!("  {} (whole number, optional): ", label);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_string();

    if trimmed.is_empty() {
        return Ok(None);
    }

    match trimmed.parse::<u32>() {
        Ok(v) => Ok(Some(v)),
        Err(_) => {
            println!("  {} must be a whole number — skipping.", label);
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// §9.1 Lab Result
// ---------------------------------------------------------------------------

/// Prompts for all fields of a [`LabResultPayload`].
///
/// Required: test_name, test_code, value, unit, reference_range, status.
/// Optional: device_id, notes.
///
/// See spec §9.1.
fn prompt_lab_result() -> Result<LabResultPayload, Box<dyn std::error::Error>> {
    println!("--- lab result ---");

    let test_name = prompt_required("test name (e.g. Fasting Blood Glucose)")?;
    let test_code = prompt_required("test code (e.g. FBG)")?;
    let value = prompt_required_f64("result value (e.g. 98.5)")?;
    let unit = prompt_required("unit (e.g. mg/dL)")?;

    println!("  reference range");
    let ref_min = prompt_required_f64("    min")?;
    let ref_max = prompt_required_f64("    max")?;

    let status = prompt_required("status (normal / high / low / critical)")?;
    let device_id = prompt_optional("device ID (e.g. LMV-ROCHE-5QNZK8MXBT-D7)")?;
    let notes = prompt_optional("notes")?;

    Ok(LabResultPayload {
        test_name,
        test_code,
        value,
        unit,
        reference_range: ReferenceRange { min: ref_min, max: ref_max },
        status,
        device_id,
        notes,
    })
}

// ---------------------------------------------------------------------------
// §9.2 Prescription
// ---------------------------------------------------------------------------

/// Prompts for all fields of a [`PrescriptionPayload`].
///
/// Required: drug_name, drug_code, dosage, frequency, duration_days,
///           instructions, reason.
/// Optional: refills, diagnosis_ref.
///
/// See spec §9.2.
fn prompt_prescription() -> Result<PrescriptionPayload, Box<dyn std::error::Error>> {
    println!("--- prescription ---");

    let drug_name = prompt_required("drug name (e.g. Metformin)")?;
    let drug_code = prompt_required("drug code (e.g. MET500)")?;
    let dosage = prompt_required("dosage (e.g. 500mg)")?;
    let frequency = prompt_required("frequency (e.g. twice daily)")?;
    let duration_days = prompt_required_u32("duration in days (e.g. 30)")?;
    let instructions = prompt_required("instructions (e.g. take with meals)")?;
    let reason = prompt_required("reason (e.g. type 2 diabetes management)")?;
    let refills = prompt_optional_u32("refills")?;
    let diagnosis_ref = prompt_optional("diagnosis commit ID (sha256:...)")?;

    Ok(PrescriptionPayload {
        drug_name,
        drug_code,
        dosage,
        frequency,
        duration_days,
        instructions,
        reason,
        refills,
        diagnosis_ref,
    })
}

// ---------------------------------------------------------------------------
// §9.3 Radiology Report
// ---------------------------------------------------------------------------

/// Prompts for all fields of a [`RadiologyReportPayload`].
///
/// Required: report_id, modality, body_part, findings, impression,
///           radiologist_id, and all external_ref fields.
/// Optional: machine_id.
///
/// The external_ref block is always required — raw imaging files are
/// never stored in LooMed. See spec §9.3 and §9.7.
fn prompt_radiology_report() -> Result<RadiologyReportPayload, Box<dyn std::error::Error>> {
    println!("--- radiology report ---");

    let report_id = prompt_required("report ID (e.g. APL-RAD-2026-00421)")?;
    let modality = prompt_required("modality (e.g. MRI / CT / X-ray / Ultrasound)")?;
    let body_part = prompt_required("body part (e.g. lumbar spine)")?;
    let findings = prompt_required("findings (radiologist narrative)")?;
    let impression = prompt_required("impression (summary and recommendations)")?;
    let radiologist_id = prompt_required("radiologist participant ID (LMD-...)")?;
    let machine_id = prompt_optional("imaging machine participant ID (LMV-...)")?;

    println!();
    println!("  external reference (raw imaging files are held by the originating institution)");
    let ref_id = prompt_required("  ref ID (e.g. APL-RAD-2026-00421)")?;
    let ref_type = prompt_required("  ref type (e.g. pacs_imaging)")?;
    let custodian_id = prompt_required("  custodian institution ID (LMI-...)")?;
    let description = prompt_required("  description (e.g. raw MRI DICOM files)")?;
    let retrieval = prompt_required("  retrieval instructions")?;

    Ok(RadiologyReportPayload {
        report_id,
        modality,
        body_part,
        findings,
        impression,
        radiologist_id,
        machine_id,
        external_ref: ExternalRef {
            ref_id,
            ref_type,
            custodian_id,
            description,
            retrieval,
        },
    })
}

// ---------------------------------------------------------------------------
// §9.4 Vaccination
// ---------------------------------------------------------------------------

/// Prompts for all fields of a [`VaccinationPayload`].
///
/// Required: vaccine_name, vaccine_code, manufacturer, batch_number,
///           dose_number, total_doses, site.
/// Optional: next_dose_due, programme, programme_id.
///
/// See spec §9.4.
fn prompt_vaccination() -> Result<VaccinationPayload, Box<dyn std::error::Error>> {
    println!("--- vaccination ---");

    let vaccine_name = prompt_required("vaccine name (e.g. Covishield)")?;
    let vaccine_code = prompt_required("vaccine code (e.g. AZ-COV19)")?;
    let manufacturer = prompt_required("manufacturer (e.g. Serum Institute of India)")?;
    let batch_number = prompt_required("batch number (e.g. SII-2021-B0041)")?;
    let dose_number = prompt_required_u32("dose number (e.g. 1)")?;
    let total_doses = prompt_required_u32("total doses in series (e.g. 2)")?;
    let site = prompt_required("administration site (e.g. left deltoid)")?;
    let next_dose_due = prompt_optional("next dose due date (YYYY-MM-DD)")?;
    let programme = prompt_optional("programme name")?;
    let programme_id = prompt_optional("programme ID (e.g. LMG-GOV-COWIN-2021)")?;

    Ok(VaccinationPayload {
        vaccine_name,
        vaccine_code,
        manufacturer,
        batch_number,
        dose_number,
        total_doses,
        site,
        next_dose_due,
        programme,
        programme_id,
    })
}

// ---------------------------------------------------------------------------
// §9.5 Diagnosis
// ---------------------------------------------------------------------------

/// Prompts for all fields of a [`DiagnosisPayload`].
///
/// Required: condition, icd_code, severity, onset, status.
/// Optional: notes.
/// supporting_refs: zero or more commit IDs entered one per line,
///   terminated by an empty Enter press.
///
/// See spec §9.5.
fn prompt_diagnosis() -> Result<DiagnosisPayload, Box<dyn std::error::Error>> {
    println!("--- diagnosis ---");

    let condition = prompt_required("condition name (e.g. Type 2 Diabetes Mellitus)")?;
    let icd_code = prompt_required("ICD code (e.g. E11)")?;
    let severity = prompt_required("severity (mild / moderate / severe)")?;
    let onset = prompt_required("onset date (YYYY-MM-DD)")?;
    let status = prompt_required("status (active / resolved / chronic)")?;
    let notes = prompt_optional("notes")?;

    println!("  supporting commit refs (sha256:..., one per line, empty line to finish)");
    let supporting_refs = prompt_string_list("  ref")?;

    Ok(DiagnosisPayload {
        condition,
        icd_code,
        severity,
        onset,
        status,
        notes,
        supporting_refs,
    })
}

// ---------------------------------------------------------------------------
// §9.6 Procedure
// ---------------------------------------------------------------------------

/// Prompts for all fields of a [`ProcedurePayload`].
///
/// Required: procedure_name, procedure_code, procedure_type, anaesthesia,
///           duration_minutes, outcome.
/// Optional: notes, diagnosis_ref.
/// team: zero or more members entered as role + participant_id pairs,
///   terminated by an empty Enter press on the role prompt.
///
/// See spec §9.6.
fn prompt_procedure() -> Result<ProcedurePayload, Box<dyn std::error::Error>> {
    println!("--- procedure ---");

    let procedure_name = prompt_required("procedure name (e.g. Appendectomy)")?;
    let procedure_code = prompt_required("procedure code (e.g. 47.09)")?;
    let procedure_type = prompt_required("type (surgical / diagnostic / therapeutic)")?;
    let anaesthesia = prompt_required("anaesthesia (general / local / regional / none)")?;
    let duration_minutes = prompt_required_u32("duration in minutes")?;
    let outcome = prompt_required("outcome (successful / complicated / abandoned)")?;
    let notes = prompt_optional("notes")?;
    let diagnosis_ref = prompt_optional("diagnosis commit ID (sha256:...)")?;

    println!("  team members (empty role to finish)");
    let team = prompt_team_members()?;

    Ok(ProcedurePayload {
        procedure_name,
        procedure_code,
        procedure_type,
        anaesthesia,
        duration_minutes,
        outcome,
        notes,
        team,
        diagnosis_ref,
    })
}

// ---------------------------------------------------------------------------
// Collection prompt helpers
// ---------------------------------------------------------------------------

/// Prompts for a list of strings, one per line.
///
/// Used for `DiagnosisPayload.supporting_refs`. The user enters one
/// value per line. An empty Enter press terminates the list.
/// Returns an empty `Vec` if the user skips immediately.
fn prompt_string_list(label: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut items = Vec::new();

    loop {
        print!("  {}: ", label);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_string();

        if trimmed.is_empty() {
            return Ok(items);
        }

        items.push(trimmed);
    }
}

/// Prompts for a list of team members for a procedure.
///
/// Each member requires a role and a participant ID. An empty Enter
/// press on the role prompt terminates the list.
/// Returns an empty `Vec` if the user skips immediately.
fn prompt_team_members() -> Result<Vec<TeamMember>, Box<dyn std::error::Error>> {
    let mut members = Vec::new();

    loop {
        print!("  role (e.g. surgeon, empty to finish): ");
        io::stdout().flush()?;

        let mut role_input = String::new();
        io::stdin().read_line(&mut role_input)?;
        let role = role_input.trim().to_string();

        if role.is_empty() {
            return Ok(members);
        }

        let participant_id = prompt_required("  participant ID (LMD-...)")?;

        members.push(TeamMember { role, participant_id });
    }
}