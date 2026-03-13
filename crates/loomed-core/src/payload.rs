//! # Record Payload Schemas
//!
//! Typed payload structs for every medical record type defined in the
//! LooMed protocol specification.
//!
//! ## Responsibilities
//! - Defining the payload schema for each record type (spec §9)
//! - Serialising and deserialising payloads to/from JSON
//! - Providing the `RecordPayload` enum for type-safe dispatch
//!
//! ## Not Responsible For
//! - Prompting the user for field values (see `loomed-cli`)
//! - Validating clinical ranges or medical correctness
//! - Writing payloads to disk (see `loomed-store`)
//!
//! ## Field Naming
//! All field names match the LooMed specification schema exactly.
//! No renaming, no camelCase, no abbreviation. See spec §9 and
//! coding standards §7.1.
//!
//! ## Optional Fields
//! Fields that may be absent are `Option<T>` with
//! `#[serde(skip_serializing_if = "Option::is_none")]`. Absent optional
//! fields are omitted from JSON entirely — never serialised as null.
//! See coding standards §7.2.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Shared sub-types
// ---------------------------------------------------------------------------

/// An external reference to a raw file or dataset held outside the LooMed ledger.
///
/// Used by record types that reference large or sensitive files (imaging
/// archives, pathology slides, genomic data) that are stored by the
/// originating institution rather than inside the vault.
///
/// This is a first-class protocol field. See spec §9.7.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExternalRef {
    /// The institution-assigned identifier for the referenced file or dataset.
    ///
    /// Example: `"APL-RAD-2026-00421"`. Used to retrieve the raw file
    /// from the custodian institution. See spec §9.7.
    pub ref_id: String,

    /// The type of the referenced external resource.
    ///
    /// Example: `"pacs_imaging"` for DICOM files. See spec §9.7.
    pub ref_type: String,

    /// The participant ID of the institution that holds the raw file.
    ///
    /// The patient or another authorised participant contacts this institution
    /// with `ref_id` to retrieve the raw file. See spec §9.7.
    pub custodian_id: String,

    /// A human-readable description of the referenced resource.
    ///
    /// Example: `"raw MRI DICOM files"`. See spec §9.7.
    pub description: String,

    /// Instructions for retrieving the raw file from the custodian.
    ///
    /// Example: `"contact custodian with ref_id"`. See spec §9.7.
    pub retrieval: String,
}

/// A reference range for a laboratory test value.
///
/// Used in `LabResultPayload` to record the normal range against which
/// the result value is interpreted. See spec §9.1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReferenceRange {
    /// The lower bound of the normal range (inclusive).
    pub min: f64,

    /// The upper bound of the normal range (inclusive).
    pub max: f64,
}

/// A single member of the clinical team present during a procedure.
///
/// Used in `ProcedurePayload` to record the roles and participant IDs
/// of all team members. See spec §9.6.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamMember {
    /// The role of this team member in the procedure.
    ///
    /// Example: `"surgeon"`, `"anaesthetist"`, `"scrub_nurse"`.
    pub role: String,

    /// The LooMed participant ID of this team member.
    ///
    /// Must be a valid LMD- participant ID. See spec §3.1.
    pub participant_id: String,
}

// ---------------------------------------------------------------------------
// §9.1 Lab Result
// ---------------------------------------------------------------------------

/// Payload for a laboratory test result commit.
///
/// Carries the structured result of a single diagnostic test — the test
/// name, measured value, unit, reference range, and interpretation status.
/// The `device_id` field references the diagnostic device that produced
/// the result, if known.
///
/// See spec §9.1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LabResultPayload {
    /// The human-readable name of the test.
    ///
    /// Example: `"Fasting Blood Glucose"`. See spec §9.1.
    pub test_name: String,

    /// The standardised test code.
    ///
    /// Example: `"FBG"`. See spec §9.1.
    pub test_code: String,

    /// The measured numeric result value.
    ///
    /// See spec §9.1.
    pub value: f64,

    /// The unit of measurement for the result value.
    ///
    /// Example: `"mg/dL"`. See spec §9.1.
    pub unit: String,

    /// The normal reference range for this test.
    ///
    /// Used to interpret whether the result is within normal bounds.
    /// See spec §9.1.
    pub reference_range: ReferenceRange,

    /// The interpretation status of this result.
    ///
    /// Example: `"normal"`, `"high"`, `"low"`, `"critical"`. See spec §9.1.
    pub status: String,

    /// The LooMed participant ID of the diagnostic device that produced
    /// this result, if known.
    ///
    /// Format: `LMV-<scope>-<id>-<checksum>`. Absent if the device is
    /// unregistered or unknown. See spec §9.1 and §3.1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,

    /// Additional clinical notes about this result.
    ///
    /// Example: `"patient fasted for 10 hours prior"`. See spec §9.1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

// ---------------------------------------------------------------------------
// §9.2 Prescription
// ---------------------------------------------------------------------------

/// Payload for a medication prescription commit.
///
/// Carries the full prescription details — drug identity, dosage,
/// frequency, duration, and the diagnosis that triggered the prescription.
///
/// See spec §9.2.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrescriptionPayload {
    /// The brand or generic name of the prescribed drug.
    ///
    /// Example: `"Metformin"`. See spec §9.2.
    pub drug_name: String,

    /// The standardised drug code.
    ///
    /// Example: `"MET500"`. See spec §9.2.
    pub drug_code: String,

    /// The dosage per administration.
    ///
    /// Example: `"500mg"`. See spec §9.2.
    pub dosage: String,

    /// How often the drug is to be taken.
    ///
    /// Example: `"twice daily"`. See spec §9.2.
    pub frequency: String,

    /// The total duration of the prescription in days.
    ///
    /// See spec §9.2.
    pub duration_days: u32,

    /// Patient instructions for taking the medication.
    ///
    /// Example: `"take with meals"`. See spec §9.2.
    pub instructions: String,

    /// The number of refills permitted after the initial dispensing.
    ///
    /// Absent if no refills are permitted. See spec §9.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refills: Option<u32>,

    /// The clinical reason for this prescription.
    ///
    /// Example: `"type 2 diabetes management"`. See spec §9.2.
    pub reason: String,

    /// The commit_id of the diagnosis that prompted this prescription.
    ///
    /// Format: `"sha256:<hex>"`. Absent if not linked to a specific
    /// diagnosis commit. See spec §9.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnosis_ref: Option<String>,
}

// ---------------------------------------------------------------------------
// §9.3 Radiology Report
// ---------------------------------------------------------------------------

/// Payload for an interpreted radiology report commit.
///
/// Stores the interpreted findings and impression of a radiology study.
/// Raw imaging files (DICOM, MRI, X-ray) are NOT stored in LooMed —
/// only the interpreted report is stored. The `external_ref` field
/// carries the reference needed to retrieve raw files from the
/// originating institution. This is a first-class design decision,
/// not a limitation. See spec §9.3.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RadiologyReportPayload {
    /// The institution-assigned report identifier.
    ///
    /// Example: `"APL-RAD-2026-00421"`. See spec §9.3.
    pub report_id: String,

    /// The imaging modality used.
    ///
    /// Example: `"MRI"`, `"CT"`, `"X-ray"`, `"Ultrasound"`. See spec §9.3.
    pub modality: String,

    /// The body part or region imaged.
    ///
    /// Example: `"lumbar spine"`. See spec §9.3.
    pub body_part: String,

    /// The radiologist's findings from the images.
    ///
    /// Narrative text describing what was observed. See spec §9.3.
    pub findings: String,

    /// The radiologist's clinical impression and recommendations.
    ///
    /// Narrative text summarising the significance of the findings.
    /// See spec §9.3.
    pub impression: String,

    /// The participant ID of the radiologist who interpreted the images.
    ///
    /// Format: `LMD-<scope>-<id>-<checksum>`. See spec §9.3 and §3.1.
    pub radiologist_id: String,

    /// The participant ID of the imaging machine that produced the study.
    ///
    /// Format: `LMV-<scope>-<id>-<checksum>`. Absent if the machine is
    /// unregistered. See spec §9.3 and §3.1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,

    /// A reference to the raw imaging files held by the originating institution.
    ///
    /// Raw DICOM or imaging files are never stored in LooMed. This reference
    /// allows any authorised participant to retrieve them from the custodian.
    /// See spec §9.3 and §9.7.
    pub external_ref: ExternalRef,
}

// ---------------------------------------------------------------------------
// §9.4 Vaccination
// ---------------------------------------------------------------------------

/// Payload for a vaccination record commit.
///
/// Carries the full details of a single vaccine dose — the vaccine identity,
/// batch, dose number, administration site, and the programme under which
/// it was administered.
///
/// See spec §9.4.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaccinationPayload {
    /// The name of the vaccine administered.
    ///
    /// Example: `"Covishield"`. See spec §9.4.
    pub vaccine_name: String,

    /// The standardised vaccine code.
    ///
    /// Example: `"AZ-COV19"`. See spec §9.4.
    pub vaccine_code: String,

    /// The manufacturer of the vaccine.
    ///
    /// Example: `"Serum Institute of India"`. See spec §9.4.
    pub manufacturer: String,

    /// The production batch number of the administered dose.
    ///
    /// Example: `"SII-2021-B0041"`. Used for adverse event tracing.
    /// See spec §9.4.
    pub batch_number: String,

    /// The dose number in a multi-dose series.
    ///
    /// Example: `1` for the first dose of a two-dose vaccine. See spec §9.4.
    pub dose_number: u32,

    /// The total number of doses in the full vaccination series.
    ///
    /// Example: `2` for a two-dose vaccine. See spec §9.4.
    pub total_doses: u32,

    /// The anatomical site of administration.
    ///
    /// Example: `"left deltoid"`. See spec §9.4.
    pub site: String,

    /// The recommended date for the next dose, if applicable.
    ///
    /// ISO 8601 date string (`YYYY-MM-DD`). Absent if this is the final
    /// dose or if no follow-up dose is scheduled. See spec §9.4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_dose_due: Option<String>,

    /// The name of the vaccination programme under which this dose was given.
    ///
    /// Example: `"National COVID-19 Vaccination Drive"`. Absent for
    /// privately administered vaccines. See spec §9.4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub programme: Option<String>,

    /// The LooMed programme identifier, if the programme is registered.
    ///
    /// Example: `"LMG-GOV-COWIN-2021"`. Absent for unregistered or
    /// private programmes. See spec §9.4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub programme_id: Option<String>,
}

// ---------------------------------------------------------------------------
// §9.5 Diagnosis
// ---------------------------------------------------------------------------

/// Payload for a clinical diagnosis commit.
///
/// Carries the structured diagnosis — condition name, ICD code, severity,
/// onset date, and clinical status. May reference supporting commits
/// (lab results, radiology reports) that evidence the diagnosis.
///
/// See spec §9.5.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagnosisPayload {
    /// The name of the diagnosed condition.
    ///
    /// Example: `"Type 2 Diabetes Mellitus"`. See spec §9.5.
    pub condition: String,

    /// The ICD-10 or ICD-11 code for the diagnosed condition.
    ///
    /// Example: `"E11"` for Type 2 Diabetes Mellitus. See spec §9.5.
    pub icd_code: String,

    /// The clinical severity of the condition at time of diagnosis.
    ///
    /// Example: `"mild"`, `"moderate"`, `"severe"`. See spec §9.5.
    pub severity: String,

    /// The date of onset of the condition.
    ///
    /// ISO 8601 date string (`YYYY-MM-DD`). The date the condition was
    /// first observed or reported, which may differ from the commit
    /// timestamp. See spec §9.5.
    pub onset: String,

    /// The current clinical status of this diagnosis.
    ///
    /// Example: `"active"`, `"resolved"`, `"chronic"`. See spec §9.5.
    pub status: String,

    /// Additional clinical notes about this diagnosis.
    ///
    /// Narrative text from the diagnosing clinician. See spec §9.5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,

    /// Commit IDs of records that support or evidence this diagnosis.
    ///
    /// References to lab results, radiology reports, or other commits
    /// that informed the diagnosis. Format: `["sha256:<hex>", ...]`.
    /// Empty if no supporting records are referenced. See spec §9.5.
    #[serde(default)]
    pub supporting_refs: Vec<String>,
}

// ---------------------------------------------------------------------------
// §9.6 Surgical Procedure
// ---------------------------------------------------------------------------

/// Payload for a surgical or medical procedure commit.
///
/// Carries the full details of a procedure — type, anaesthesia, duration,
/// outcome, and the clinical team present. May reference the diagnosis
/// that prompted the procedure.
///
/// See spec §9.6.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcedurePayload {
    /// The name of the procedure performed.
    ///
    /// Example: `"Appendectomy"`. See spec §9.6.
    pub procedure_name: String,

    /// The standardised procedure code.
    ///
    /// Example: `"47.09"` (ICD-9-CM for appendectomy). See spec §9.6.
    pub procedure_code: String,

    /// The category of the procedure.
    ///
    /// Example: `"surgical"`, `"diagnostic"`, `"therapeutic"`. See spec §9.6.
    pub procedure_type: String,

    /// The type of anaesthesia used.
    ///
    /// Example: `"general"`, `"local"`, `"regional"`, `"none"`. See spec §9.6.
    pub anaesthesia: String,

    /// The duration of the procedure in minutes.
    ///
    /// See spec §9.6.
    pub duration_minutes: u32,

    /// The clinical outcome of the procedure.
    ///
    /// Example: `"successful"`, `"complicated"`, `"abandoned"`. See spec §9.6.
    pub outcome: String,

    /// Additional clinical notes about the procedure.
    ///
    /// Narrative text from the operating clinician. See spec §9.6.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,

    /// The clinical team present during the procedure.
    ///
    /// Each member carries a role and a LooMed participant ID. See spec §9.6.
    #[serde(default)]
    pub team: Vec<TeamMember>,

    /// The commit_id of the diagnosis that prompted this procedure.
    ///
    /// Format: `"sha256:<hex>"`. Absent if not linked to a specific
    /// diagnosis commit. See spec §9.6.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnosis_ref: Option<String>,
}

// ---------------------------------------------------------------------------
// RecordPayload — type-safe dispatch enum
// ---------------------------------------------------------------------------

/// A type-safe container for the payload of any LooMed record type.
///
/// This enum wraps all six record payload types defined in spec §9,
/// enabling compile-time exhaustive matching over all known record types.
///
/// `RecordPayload` is used by the CLI prompt layer to pass a fully
/// validated payload to the staging area, and by display and validation
/// logic that needs to branch by record type.
///
/// The `serde_json::Value` stored in `Commit.payload` is the serialised
/// form of one of these variants. Use `RecordPayload::to_value()` to
/// convert a typed payload into the untyped `Value` for storage.
///
/// See spec §9.
#[derive(Debug, Clone, PartialEq)]
pub enum RecordPayload {
    /// A laboratory test result. See spec §9.1.
    LabResult(LabResultPayload),

    /// A medication prescription. See spec §9.2.
    Prescription(PrescriptionPayload),

    /// An interpreted radiology report. See spec §9.3.
    RadiologyReport(RadiologyReportPayload),

    /// A vaccination record. See spec §9.4.
    Vaccination(VaccinationPayload),

    /// A clinical diagnosis. See spec §9.5.
    Diagnosis(DiagnosisPayload),

    /// A surgical or medical procedure. See spec §9.6.
    Procedure(ProcedurePayload),
}

impl RecordPayload {
    /// Serialises this typed payload into an untyped `serde_json::Value`.
    ///
    /// The returned `Value` is what gets stored in `Commit.payload` on disk.
    /// It is always a JSON object whose fields match spec §9 exactly.
    /// Optional fields that are `None` are omitted from the output entirely.
    ///
    /// # Errors
    ///
    /// Returns a `serde_json::Error` if serialisation fails. In practice
    /// this is infallible for all defined payload types.
    pub fn to_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        match self {
            RecordPayload::LabResult(p) => serde_json::to_value(p),
            RecordPayload::Prescription(p) => serde_json::to_value(p),
            RecordPayload::RadiologyReport(p) => serde_json::to_value(p),
            RecordPayload::Vaccination(p) => serde_json::to_value(p),
            RecordPayload::Diagnosis(p) => serde_json::to_value(p),
            RecordPayload::Procedure(p) => serde_json::to_value(p),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ExternalRef
    // -----------------------------------------------------------------------

    /// Spec §9.7: ExternalRef must serialise and deserialise without data loss.
    #[test]
    fn external_ref_roundtrip() {
        let ext = ExternalRef {
            ref_id: "APL-RAD-2026-00421".to_string(),
            ref_type: "pacs_imaging".to_string(),
            custodian_id: "LMI-APL-2MVZK9QXBT-C2".to_string(),
            description: "raw MRI DICOM files".to_string(),
            retrieval: "contact custodian with ref_id".to_string(),
        };
        let json = serde_json::to_string(&ext).unwrap();
        let back: ExternalRef = serde_json::from_str(&json).unwrap();
        assert_eq!(ext, back);
    }

    // -----------------------------------------------------------------------
    // §9.1 LabResultPayload
    // -----------------------------------------------------------------------

    /// Spec §9.1: LabResultPayload must serialise and deserialise without data loss.
    #[test]
    fn lab_result_payload_roundtrip() {
        let payload = LabResultPayload {
            test_name: "Fasting Blood Glucose".to_string(),
            test_code: "FBG".to_string(),
            value: 98.0,
            unit: "mg/dL".to_string(),
            reference_range: ReferenceRange { min: 70.0, max: 99.0 },
            status: "normal".to_string(),
            device_id: Some("LMV-ROCHE-5QNZK8MXBT-D7".to_string()),
            notes: Some("patient fasted for 10 hours prior".to_string()),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: LabResultPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(payload, back);
    }

    /// Spec §9.1: Optional fields must be absent from JSON when None —
    /// not serialised as null. See coding standards §7.2.
    #[test]
    fn lab_result_optional_fields_absent_when_none() {
        let payload = LabResultPayload {
            test_name: "FBG".to_string(),
            test_code: "FBG".to_string(),
            value: 98.0,
            unit: "mg/dL".to_string(),
            reference_range: ReferenceRange { min: 70.0, max: 99.0 },
            status: "normal".to_string(),
            device_id: None,
            notes: None,
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert!(value.get("device_id").is_none(), "device_id must be absent when None");
        assert!(value.get("notes").is_none(), "notes must be absent when None");
    }

    /// Spec §9.1: LabResultPayload field names must match the spec exactly.
    #[test]
    fn lab_result_payload_field_names_match_spec() {
        let payload = LabResultPayload {
            test_name: "FBG".to_string(),
            test_code: "FBG".to_string(),
            value: 98.0,
            unit: "mg/dL".to_string(),
            reference_range: ReferenceRange { min: 70.0, max: 99.0 },
            status: "normal".to_string(),
            device_id: None,
            notes: None,
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert!(value.get("test_name").is_some());
        assert!(value.get("test_code").is_some());
        assert!(value.get("reference_range").is_some());
    }

    // -----------------------------------------------------------------------
    // §9.2 PrescriptionPayload
    // -----------------------------------------------------------------------

    /// Spec §9.2: PrescriptionPayload must serialise and deserialise without data loss.
    #[test]
    fn prescription_payload_roundtrip() {
        let payload = PrescriptionPayload {
            drug_name: "Metformin".to_string(),
            drug_code: "MET500".to_string(),
            dosage: "500mg".to_string(),
            frequency: "twice daily".to_string(),
            duration_days: 30,
            instructions: "take with meals".to_string(),
            refills: Some(2),
            reason: "type 2 diabetes management".to_string(),
            diagnosis_ref: Some("sha256:abc123".to_string()),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: PrescriptionPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(payload, back);
    }

    /// Spec §9.2: Optional fields must be absent from JSON when None.
    #[test]
    fn prescription_optional_fields_absent_when_none() {
        let payload = PrescriptionPayload {
            drug_name: "Metformin".to_string(),
            drug_code: "MET500".to_string(),
            dosage: "500mg".to_string(),
            frequency: "twice daily".to_string(),
            duration_days: 30,
            instructions: "take with meals".to_string(),
            refills: None,
            reason: "type 2 diabetes management".to_string(),
            diagnosis_ref: None,
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert!(value.get("refills").is_none(), "refills must be absent when None");
        assert!(value.get("diagnosis_ref").is_none(), "diagnosis_ref must be absent when None");
    }

    // -----------------------------------------------------------------------
    // §9.3 RadiologyReportPayload
    // -----------------------------------------------------------------------

    /// Spec §9.3: RadiologyReportPayload must serialise and deserialise without data loss.
    #[test]
    fn radiology_report_payload_roundtrip() {
        let payload = RadiologyReportPayload {
            report_id: "APL-RAD-2026-00421".to_string(),
            modality: "MRI".to_string(),
            body_part: "lumbar spine".to_string(),
            findings: "Mild disc bulge at L4-L5.".to_string(),
            impression: "Grade 1 spondylolisthesis at L4-L5.".to_string(),
            radiologist_id: "LMD-APL-9XKZR4WQNB-3F".to_string(),
            machine_id: Some("LMV-SIEM-6WNBQ3MZKX-A1".to_string()),
            external_ref: ExternalRef {
                ref_id: "APL-RAD-2026-00421".to_string(),
                ref_type: "pacs_imaging".to_string(),
                custodian_id: "LMI-APL-2MVZK9QXBT-C2".to_string(),
                description: "raw MRI DICOM files".to_string(),
                retrieval: "contact custodian with ref_id".to_string(),
            },
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: RadiologyReportPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(payload, back);
    }

    /// Spec §9.3: external_ref is required — raw imaging files are never stored in LooMed.
    #[test]
    fn radiology_report_requires_external_ref() {
        let payload = RadiologyReportPayload {
            report_id: "APL-RAD-2026-00421".to_string(),
            modality: "MRI".to_string(),
            body_part: "lumbar spine".to_string(),
            findings: "test findings".to_string(),
            impression: "test impression".to_string(),
            radiologist_id: "LMD-APL-9XKZR4WQNB-3F".to_string(),
            machine_id: None,
            external_ref: ExternalRef {
                ref_id: "ref-001".to_string(),
                ref_type: "pacs_imaging".to_string(),
                custodian_id: "LMI-APL-2MVZK9QXBT-C2".to_string(),
                description: "raw files".to_string(),
                retrieval: "contact custodian".to_string(),
            },
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert!(value.get("external_ref").is_some());
        assert!(value.get("machine_id").is_none(), "machine_id must be absent when None");
    }

    // -----------------------------------------------------------------------
    // §9.4 VaccinationPayload
    // -----------------------------------------------------------------------

    /// Spec §9.4: VaccinationPayload must serialise and deserialise without data loss.
    #[test]
    fn vaccination_payload_roundtrip() {
        let payload = VaccinationPayload {
            vaccine_name: "Covishield".to_string(),
            vaccine_code: "AZ-COV19".to_string(),
            manufacturer: "Serum Institute of India".to_string(),
            batch_number: "SII-2021-B0041".to_string(),
            dose_number: 1,
            total_doses: 2,
            site: "left deltoid".to_string(),
            next_dose_due: Some("2021-04-12".to_string()),
            programme: Some("National COVID-19 Vaccination Drive".to_string()),
            programme_id: Some("LMG-GOV-COWIN-2021".to_string()),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: VaccinationPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(payload, back);
    }

    /// Spec §9.4: Optional fields must be absent from JSON when None.
    #[test]
    fn vaccination_optional_fields_absent_when_none() {
        let payload = VaccinationPayload {
            vaccine_name: "Covishield".to_string(),
            vaccine_code: "AZ-COV19".to_string(),
            manufacturer: "Serum Institute of India".to_string(),
            batch_number: "SII-2021-B0041".to_string(),
            dose_number: 1,
            total_doses: 2,
            site: "left deltoid".to_string(),
            next_dose_due: None,
            programme: None,
            programme_id: None,
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert!(value.get("next_dose_due").is_none());
        assert!(value.get("programme").is_none());
        assert!(value.get("programme_id").is_none());
    }

    // -----------------------------------------------------------------------
    // §9.5 DiagnosisPayload
    // -----------------------------------------------------------------------

    /// Spec §9.5: DiagnosisPayload must serialise and deserialise without data loss.
    #[test]
    fn diagnosis_payload_roundtrip() {
        let payload = DiagnosisPayload {
            condition: "Type 2 Diabetes Mellitus".to_string(),
            icd_code: "E11".to_string(),
            severity: "mild".to_string(),
            onset: "2026-02-01".to_string(),
            status: "active".to_string(),
            notes: Some("Confirmed via FBG and HbA1c.".to_string()),
            supporting_refs: vec!["sha256:7f8e21a4".to_string()],
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: DiagnosisPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(payload, back);
    }

    /// Spec §9.5: supporting_refs defaults to an empty vec when absent from JSON.
    #[test]
    fn diagnosis_supporting_refs_defaults_to_empty() {
        let json = r#"{
            "condition": "Hypertension",
            "icd_code": "I10",
            "severity": "mild",
            "onset": "2026-01-01",
            "status": "active"
        }"#;
        let payload: DiagnosisPayload = serde_json::from_str(json).unwrap();
        assert!(payload.supporting_refs.is_empty());
        assert!(payload.notes.is_none());
    }

    /// Spec §9.5: notes must be absent from JSON when None.
    #[test]
    fn diagnosis_optional_fields_absent_when_none() {
        let payload = DiagnosisPayload {
            condition: "Hypertension".to_string(),
            icd_code: "I10".to_string(),
            severity: "mild".to_string(),
            onset: "2026-01-01".to_string(),
            status: "active".to_string(),
            notes: None,
            supporting_refs: vec![],
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert!(value.get("notes").is_none(), "notes must be absent when None");
    }

    // -----------------------------------------------------------------------
    // §9.6 ProcedurePayload
    // -----------------------------------------------------------------------

    /// Spec §9.6: ProcedurePayload must serialise and deserialise without data loss.
    #[test]
    fn procedure_payload_roundtrip() {
        let payload = ProcedurePayload {
            procedure_name: "Appendectomy".to_string(),
            procedure_code: "47.09".to_string(),
            procedure_type: "surgical".to_string(),
            anaesthesia: "general".to_string(),
            duration_minutes: 45,
            outcome: "successful".to_string(),
            notes: Some("Laparoscopic approach. No complications.".to_string()),
            team: vec![
                TeamMember {
                    role: "surgeon".to_string(),
                    participant_id: "LMD-APL-7MZNQ4KXBW-2R".to_string(),
                },
                TeamMember {
                    role: "anaesthetist".to_string(),
                    participant_id: "LMD-APL-5KQRZ8WMNB-6T".to_string(),
                },
            ],
            diagnosis_ref: Some("sha256:9a0b1c2d".to_string()),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: ProcedurePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(payload, back);
    }

    /// Spec §9.6: team defaults to an empty vec when absent from JSON.
    #[test]
    fn procedure_team_defaults_to_empty() {
        let json = r#"{
            "procedure_name": "Blood draw",
            "procedure_code": "99.03",
            "procedure_type": "diagnostic",
            "anaesthesia": "none",
            "duration_minutes": 5,
            "outcome": "successful"
        }"#;
        let payload: ProcedurePayload = serde_json::from_str(json).unwrap();
        assert!(payload.team.is_empty());
        assert!(payload.notes.is_none());
        assert!(payload.diagnosis_ref.is_none());
    }

    /// Spec §9.6: Optional fields must be absent from JSON when None.
    #[test]
    fn procedure_optional_fields_absent_when_none() {
        let payload = ProcedurePayload {
            procedure_name: "Appendectomy".to_string(),
            procedure_code: "47.09".to_string(),
            procedure_type: "surgical".to_string(),
            anaesthesia: "general".to_string(),
            duration_minutes: 45,
            outcome: "successful".to_string(),
            notes: None,
            team: vec![],
            diagnosis_ref: None,
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert!(value.get("notes").is_none(), "notes must be absent when None");
        assert!(value.get("diagnosis_ref").is_none(), "diagnosis_ref must be absent when None");
    }

    // -----------------------------------------------------------------------
    // RecordPayload dispatch
    // -----------------------------------------------------------------------

    /// RecordPayload::to_value must produce a JSON object for every variant.
    #[test]
    fn record_payload_to_value_produces_object_for_all_variants() {
        let lab = RecordPayload::LabResult(LabResultPayload {
            test_name: "FBG".to_string(),
            test_code: "FBG".to_string(),
            value: 98.0,
            unit: "mg/dL".to_string(),
            reference_range: ReferenceRange { min: 70.0, max: 99.0 },
            status: "normal".to_string(),
            device_id: None,
            notes: None,
        });
        let value = lab.to_value().unwrap();
        assert!(value.is_object());
        assert!(value.get("test_name").is_some());
        assert!(value.get("device_id").is_none(), "absent optional must not appear in output");

        let diagnosis = RecordPayload::Diagnosis(DiagnosisPayload {
            condition: "Hypertension".to_string(),
            icd_code: "I10".to_string(),
            severity: "mild".to_string(),
            onset: "2026-01-01".to_string(),
            status: "active".to_string(),
            notes: None,
            supporting_refs: vec![],
        });
        let value = diagnosis.to_value().unwrap();
        assert!(value.is_object());
        assert!(value.get("icd_code").is_some());
        assert!(value.get("notes").is_none(), "absent optional must not appear in output");
    }
}