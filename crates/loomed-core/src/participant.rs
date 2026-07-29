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

/// The Crockford Base32 alphabet used for the random ID segment and the
/// checksum of a participant ID.
///
/// Excludes `I`, `L`, `O`, `U` to avoid visual confusion with `1`, `1`,
/// `0`, and `V`. Index into this array is used directly as the numeric
/// value of a base-32 digit. See spec §3.1.
const BASE32_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A participant identifier in the LooMed protocol.
///
/// Format:
/// - Patient: `<TYPE>-<BASE32_ID>-<CHECKSUM>`
/// - Clinician / Institution / Device / Government: `<TYPE>-<SCOPE>-<BASE32_ID>-<CHECKSUM>`
///
/// Examples:
/// - `LMP-7XKQR2MNVB-6A` — a patient (no institutional scope)
/// - `LMD-APL-3NKWQ7HZRC-5N` — a clinician affiliated with Apollo
/// - `LMI-APL-2MVZK9QXBT-08` — Apollo Hospitals institution
/// - `LMV-ROCHE-5QNZK8MXBT-3P` — a Roche diagnostic device
/// - `LMG-AIIMS-4KZQR9WMNV-43` — AIIMS Delhi government body
///
/// The `BASE32_ID` segment uses the Crockford Base32 alphabet. The
/// `CHECKSUM` segment is a CRC-8 checksum of every segment preceding it
/// (type, scope if present, and the base-32 ID), encoded as two Crockford
/// Base32 digits — this detects a transcription error anywhere in the ID,
/// not just in the random segment.
///
/// Patient IDs carry no personally identifiable information at the protocol
/// level. See spec §3.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantId(pub String);

impl ParticipantId {
    /// Creates a new ParticipantId after validating the full spec §3.1 format.
    ///
    /// Validates, in order: the type prefix (`LMP`, `LMD`, `LMI`, `LMV`, or
    /// `LMG`), the segment count (3 for patients — no scope; 4 for every
    /// other type — scope required), the Crockford Base32 charset of the
    /// ID and checksum segments, and finally the CRC-8 checksum itself.
    ///
    /// # Arguments
    ///
    /// * `id` — The raw participant ID string to validate and wrap.
    ///
    /// # Returns
    ///
    /// `Ok(ParticipantId)` if the format and checksum are valid.
    ///
    /// # Errors
    ///
    /// * [`LooMedError::InvalidParticipantId`] — The string does not match
    ///   the expected participant ID format, contains characters outside
    ///   the Crockford Base32 alphabet, or fails checksum verification.
    ///   See spec §3.1.
    pub fn new(id: impl Into<String>) -> Result<Self, LooMedError> {
        let id = id.into();

        let valid_prefix = id.starts_with("LMP-")
            || id.starts_with("LMD-")
            || id.starts_with("LMI-")
            || id.starts_with("LMV-")
            || id.starts_with("LMG-");
        if !valid_prefix {
            return Err(LooMedError::InvalidParticipantId { id });
        }

        let prefix = &id[..3];
        let segments: Vec<&str> = id.split('-').collect();

        // Patients carry no scope: TYPE-BASE32ID-CHECKSUM (3 segments).
        // Every other type requires a scope: TYPE-SCOPE-BASE32ID-CHECKSUM
        // (4 segments). See spec §3.1 "ID Structure".
        let (base32_id, checksum, checked_data) = match (prefix, segments.len()) {
            ("LMP", 3) => (segments[1], segments[2], id[..segments[0].len() + 1 + segments[1].len()].to_string()),
            (_, 4) if prefix != "LMP" => (
                segments[2],
                segments[3],
                id[..segments[0].len() + 1 + segments[1].len() + 1 + segments[2].len()].to_string(),
            ),
            _ => return Err(LooMedError::InvalidParticipantId { id }),
        };

        if base32_id.is_empty() || !base32_id.bytes().all(is_base32_char) {
            return Err(LooMedError::InvalidParticipantId { id });
        }

        if checksum.len() != 2 || !checksum.bytes().all(is_base32_char) {
            return Err(LooMedError::InvalidParticipantId { id });
        }

        if checksum != compute_checksum(&checked_data) {
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

/// Returns `true` if `byte` is a valid Crockford Base32 character.
fn is_base32_char(byte: u8) -> bool {
    BASE32_ALPHABET.contains(&byte)
}

/// Computes the spec §3.1 checksum of `data`: a CRC-8 (polynomial `0x07`,
/// initial value `0x00`, no reflection, no output XOR) rendered as two
/// Crockford Base32 digits.
///
/// `data` is every ID segment preceding the checksum segment, joined by
/// `-` — the type prefix, the scope if present, and the base-32 ID.
fn compute_checksum(data: &str) -> String {
    let mut crc: u8 = 0x00;
    for byte in data.bytes() {
        crc ^= byte;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }
    let high = (crc / 32) as usize;
    let low = (crc % 32) as usize;
    format!(
        "{}{}",
        BASE32_ALPHABET[high] as char,
        BASE32_ALPHABET[low] as char
    )
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
        let id = ParticipantId::new("LMP-7XKQR2MNVB-6A");
        assert!(id.is_ok());
    }

    /// Spec §3.1: A valid clinician ID with institutional scope must be accepted.
    #[test]
    fn valid_clinician_id_with_scope_is_accepted() {
        let id = ParticipantId::new("LMD-APL-3NKWQ7HZRC-5N");
        assert!(id.is_ok());
    }

    /// Spec §3.1: A valid institution, device, and government ID must be accepted.
    #[test]
    fn valid_institution_device_and_government_ids_are_accepted() {
        assert!(ParticipantId::new("LMI-APL-2MVZK9QXBT-08").is_ok());
        assert!(ParticipantId::new("LMV-ROCHE-5QNZK8MXBT-3P").is_ok());
        assert!(ParticipantId::new("LMG-AIIMS-4KZQR9WMNV-43").is_ok());
    }

    /// Spec §3.1: An ID with an unknown prefix must be rejected.
    #[test]
    fn unknown_prefix_is_rejected() {
        let id = ParticipantId::new("XYZ-7XKQR2MNVB-6A");
        assert!(matches!(id, Err(LooMedError::InvalidParticipantId { .. })));
    }

    /// Spec §3.1: An empty string must be rejected as an invalid participant ID.
    #[test]
    fn empty_string_is_rejected() {
        let id = ParticipantId::new("");
        assert!(matches!(id, Err(LooMedError::InvalidParticipantId { .. })));
    }

    /// Spec §3.1: A patient ID carrying a scope segment (4 segments) must be
    /// rejected — the patient format is exactly TYPE-BASE32ID-CHECKSUM.
    #[test]
    fn patient_id_with_scope_segment_is_rejected() {
        let id = ParticipantId::new("LMP-APL-7XKQR2MNVB-6A");
        assert!(matches!(id, Err(LooMedError::InvalidParticipantId { .. })));
    }

    /// Spec §3.1: A non-patient ID missing its required scope segment
    /// (3 segments instead of 4) must be rejected.
    #[test]
    fn non_patient_id_missing_scope_is_rejected() {
        let id = ParticipantId::new("LMD-3NKWQ7HZRC-5N");
        assert!(matches!(id, Err(LooMedError::InvalidParticipantId { .. })));
    }

    /// Spec §3.1: A base-32 ID segment containing a character outside the
    /// Crockford alphabet (here, `I`) must be rejected.
    #[test]
    fn non_base32_character_in_id_segment_is_rejected() {
        let id = ParticipantId::new("LMP-7XKQRIMNVB-6A");
        assert!(matches!(id, Err(LooMedError::InvalidParticipantId { .. })));
    }

    /// Spec §3.1: A checksum segment that does not match the CRC-8 checksum
    /// of the preceding segments must be rejected.
    #[test]
    fn incorrect_checksum_is_rejected() {
        let id = ParticipantId::new("LMP-7XKQR2MNVB-00");
        assert!(matches!(id, Err(LooMedError::InvalidParticipantId { .. })));
    }

    /// Spec §3.1: A checksum segment of the wrong length must be rejected,
    /// even if every character in it is individually valid base-32.
    #[test]
    fn checksum_of_wrong_length_is_rejected() {
        let id = ParticipantId::new("LMP-7XKQR2MNVB-6");
        assert!(matches!(id, Err(LooMedError::InvalidParticipantId { .. })));
    }

    /// Spec §3.1: The checksum detects a single-character transcription
    /// error anywhere in the ID, including the scope segment.
    #[test]
    fn checksum_detects_transcription_error_in_scope() {
        let valid = ParticipantId::new("LMD-APL-3NKWQ7HZRC-5N");
        assert!(valid.is_ok());

        // "APL" mistyped as "APM" — same checksum, different scope.
        let tampered = ParticipantId::new("LMD-APM-3NKWQ7HZRC-5N");
        assert!(matches!(
            tampered,
            Err(LooMedError::InvalidParticipantId { .. })
        ));
    }

    /// Spec §3.1: prefix() returns the correct 3-character type prefix.
    #[test]
    fn prefix_returns_correct_value() {
        let id = ParticipantId::new("LMP-7XKQR2MNVB-6A").unwrap();
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