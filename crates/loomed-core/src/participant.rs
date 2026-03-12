//! # Participant Identity Types
//!
//! Every actor in the LooMed protocol is a participant. This module defines
//! the identity types for all participant kinds — patients, clinicians,
//! institutions, devices, and government bodies.
//!
//! ## Responsibilities
//! - Participant ID newtype and format validation (spec §3.1)
//! - Participant type enum (spec §3.1)
//! - Participant registration schemas (spec §3.2)
//!
//! ## Not Responsible For
//! - Cryptographic key generation (see `loomed-crypto`)
//! - Storing participant records to disk (see `loomed-store`)
//! - Verifying participants against external registries (future: `loomed-sync`)

use serde::{Deserialize, Serialize};

use crate::error::LooMedError;

// ---------------------------------------------------------------------------
// Newtypes for protocol identifiers
// ---------------------------------------------------------------------------

/// A participant identifier in the LooMed protocol.
///
/// Format: `<TYPE>-<SCOPE?>-<BASE32_ID>-<CHECKSUM>`
///
/// Examples:
/// - `LMP-7XKQR2MNVB-F4` — a patient (no institutional scope)
/// - `LMD-APL-3NKWQ7HZRC-8A` — a clinician affiliated with Apollo
/// - `LMI-APL-2MVZK9QXBT-C2` — Apollo Hospitals institution
/// - `LMV-ROCHE-5QNZK8MXBT-D7` — a Roche diagnostic device
/// - `LMG-AIIMS-4KZQR9WMNV-B3` — AIIMS Delhi government body
///
/// Patient IDs carry no personally identifiable information at the protocol
/// level. See spec §3.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantId(pub String);

impl ParticipantId {
    /// Creates a new ParticipantId after validating the format.
    ///
    /// The ID must begin with a known type prefix (`LMP`, `LMD`, `LMI`,
    /// `LMV`, or `LMG`) and contain at least two `-` separated segments
    /// after the prefix.
    ///
    /// # Arguments
    ///
    /// * `id` — The raw participant ID string to validate and wrap.
    ///
    /// # Returns
    ///
    /// `Ok(ParticipantId)` if the format is valid.
    ///
    /// # Errors
    ///
    /// * [`LooMedError::InvalidParticipantId`] — The string does not match
    ///   the expected participant ID format. See spec §3.1.
    pub fn new(id: impl Into<String>) -> Result<Self, LooMedError> {
        let id = id.into();
        let valid_prefix = id.starts_with("LMP-")
            || id.starts_with("LMD-")
            || id.starts_with("LMI-")
            || id.starts_with("LMV-")
            || id.starts_with("LMG-");

        if !valid_prefix || id.len() < 10 {
            return Err(LooMedError::InvalidParticipantId { id });
        }

        Ok(Self(id))
    }

    /// Returns the raw string value of this participant ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the participant type prefix of this ID.
    ///
    /// Returns the first 3 characters — `LMP`, `LMD`, `LMI`, `LMV`, or `LMG`.
    pub fn prefix(&self) -> &str {
        &self.0[..3]
    }
}

impl std::fmt::Display for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Participant type enum
// ---------------------------------------------------------------------------

/// The type of a LooMed participant.
///
/// Each participant type has a distinct ID prefix and registration schema.
/// The type is encoded in the first three characters of the participant ID.
///
/// See spec §3.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantType {
    /// A patient. ID prefix: `LMP`.
    ///
    /// Institutional scope is optional for patients. Patient IDs carry
    /// no personally identifiable information at the protocol level.
    Patient,

    /// A clinician (doctor, nurse, pharmacist). ID prefix: `LMD`.
    ///
    /// Institutional scope is required. Must be verified by a recognised
    /// medical council (e.g., NMC in India). See spec §4.4.
    Clinician,

    /// An institution (hospital, lab, pharmacy, insurer). ID prefix: `LMI`.
    ///
    /// Institutional scope is required. Must be verified by a recognised
    /// body (e.g., NABH for hospitals in India). See spec §4.4.
    Institution,

    /// A diagnostic device (analyser, imaging machine). ID prefix: `LMV`.
    ///
    /// Institutional scope is required. Scoped to the registering
    /// organisation. See spec §3.1.
    Device,

    /// A government or public health body. ID prefix: `LMG`.
    ///
    /// Institutional scope is required. Used for vaccination programmes,
    /// public health registries, and government-issued records.
    /// See spec §3.1.
    GovernmentBody,
}

impl ParticipantType {
    /// Returns the ID prefix string for this participant type.
    ///
    /// The prefix is the first three characters of every participant ID
    /// of this type. See spec §3.1.
    pub fn prefix(&self) -> &'static str {
        match self {
            ParticipantType::Patient => "LMP",
            ParticipantType::Clinician => "LMD",
            ParticipantType::Institution => "LMI",
            ParticipantType::Device => "LMV",
            ParticipantType::GovernmentBody => "LMG",
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec §3.1: A valid patient ID must be accepted.
    #[test]
    fn valid_patient_id_is_accepted() {
        let id = ParticipantId::new("LMP-7XKQR2MNVB-F4");
        assert!(id.is_ok());
    }

    /// Spec §3.1: A valid clinician ID with institutional scope must be accepted.
    #[test]
    fn valid_clinician_id_with_scope_is_accepted() {
        let id = ParticipantId::new("LMD-APL-3NKWQ7HZRC-8A");
        assert!(id.is_ok());
    }

    /// Spec §3.1: An ID with an unknown prefix must be rejected.
    #[test]
    fn unknown_prefix_is_rejected() {
        let id = ParticipantId::new("XYZ-7XKQR2MNVB-F4");
        assert!(matches!(id, Err(LooMedError::InvalidParticipantId { .. })));
    }

    /// Spec §3.1: An empty string must be rejected as an invalid participant ID.
    #[test]
    fn empty_string_is_rejected() {
        let id = ParticipantId::new("");
        assert!(matches!(id, Err(LooMedError::InvalidParticipantId { .. })));
    }

    /// Spec §3.1: prefix() returns the correct 3-character type prefix.
    #[test]
    fn prefix_returns_correct_value() {
        let id = ParticipantId::new("LMP-7XKQR2MNVB-F4").unwrap();
        assert_eq!(id.prefix(), "LMP");
    }

    /// Spec §3.1: ParticipantType prefix strings match the spec exactly.
    #[test]
    fn participant_type_prefixes_match_spec() {
        assert_eq!(ParticipantType::Patient.prefix(), "LMP");
        assert_eq!(ParticipantType::Clinician.prefix(), "LMD");
        assert_eq!(ParticipantType::Institution.prefix(), "LMI");
        assert_eq!(ParticipantType::Device.prefix(), "LMV");
        assert_eq!(ParticipantType::GovernmentBody.prefix(), "LMG");
    }
}