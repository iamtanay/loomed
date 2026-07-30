//! # Consent Token Model
//!
//! Record-level, time-bound, single-use consent tokens. A patient issues a
//! token to an institution; the token, not a standing grant, is what the
//! institution presents to gain access. Every token is self-signed by the
//! patient so it can be verified independently of the vault or chain it was
//! issued from.
//!
//! ## Responsibilities
//! - `ConsentScope` — the three in-scope grant shapes (spec §10.1)
//! - `AccessType` — read vs write, strictly separated (spec §10.1)
//! - `ConsentToken` — the token schema and its own `patient_signature`
//! - `prepare_token()` / `PendingConsentToken::finalise()` — the sign-then-embed
//!   flow, mirroring `builder::prepare()` / `PendingCommit::finalise()`
//!
//! ## Not Responsible For
//! - Wrapping the token in a `consent_token` commit (see `loomed-cli::commands::share`)
//! - Enforcing expiry, single-use, and scope at presentation time — that is
//!   token *enforcement*, not issuance, and lands with write-token support
//!   in a later session (see FIRST_RELEASE_PLAN.md R3)
//! - `date_range:<from>:<to>` scope — deferred past v1.0, see
//!   FIRST_RELEASE_PLAN.md
//!
//! See spec §10.

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::commit::{CommitHash, RecordType, TokenId};
use crate::error::LooMedError;
use crate::participant::ParticipantId;

// ---------------------------------------------------------------------------
// Consent scope
// ---------------------------------------------------------------------------

/// The scope of access granted by a consent token.
///
/// Serialises to and parses from the exact flat string format defined in
/// spec §10.1 (`"full_record"`, `"record_type:lab_result"`,
/// `"commit:sha256:..."`) rather than a nested JSON object, so the wire
/// format matches the spec schema exactly.
///
/// `date_range:<from>:<to>` is defined in spec §10.1 but deferred past
/// v1.0 — see FIRST_RELEASE_PLAN.md.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentScope {
    /// Grants access to the entire medical record.
    FullRecord,

    /// Grants access to every commit of a single record type.
    RecordType(RecordType),

    /// Grants access to a single commit by ID.
    Commit(CommitHash),
}

impl std::fmt::Display for ConsentScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsentScope::FullRecord => write!(f, "full_record"),
            ConsentScope::RecordType(record_type) => {
                let type_str = serde_json::to_value(record_type)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default();
                write!(f, "record_type:{}", type_str)
            }
            ConsentScope::Commit(hash) => write!(f, "commit:{}", hash.as_str()),
        }
    }
}

impl std::str::FromStr for ConsentScope {
    type Err = LooMedError;

    /// Parses a scope string per spec §10.1.
    ///
    /// # Errors
    ///
    /// * [`LooMedError::InvalidConsentScope`] — The string is not
    ///   `full_record`, does not have a `record_type:` prefix followed by a
    ///   known record type, or does not have a `commit:` prefix followed by
    ///   a non-empty commit ID.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "full_record" {
            return Ok(ConsentScope::FullRecord);
        }

        if let Some(type_str) = s.strip_prefix("record_type:") {
            let record_type: RecordType =
                serde_json::from_value(serde_json::Value::String(type_str.to_string())).map_err(
                    |_| LooMedError::InvalidConsentScope {
                        scope: s.to_string(),
                    },
                )?;
            return Ok(ConsentScope::RecordType(record_type));
        }

        if let Some(commit_id) = s.strip_prefix("commit:") {
            if commit_id.is_empty() {
                return Err(LooMedError::InvalidConsentScope {
                    scope: s.to_string(),
                });
            }
            return Ok(ConsentScope::Commit(CommitHash(commit_id.to_string())));
        }

        Err(LooMedError::InvalidConsentScope {
            scope: s.to_string(),
        })
    }
}

impl Serialize for ConsentScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ConsentScope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Access type
// ---------------------------------------------------------------------------

/// Whether a consent token grants read or write access.
///
/// Read and write tokens are entirely separate and require separate
/// patient issuance — a single token never grants both. See spec §10.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessType {
    /// Grants read-only access to the scoped records.
    Read,

    /// Grants write access — the holder may add new commits to the
    /// patient's vault within the token's scope. See spec §10.1.
    Write,
}

// ---------------------------------------------------------------------------
// Consent token
// ---------------------------------------------------------------------------

/// A patient-issued, time-bound, single-use consent token.
///
/// Carries its own `patient_signature`, independent of any commit that
/// wraps it, so an institution presented with the raw token JSON can
/// verify its authenticity without needing the patient's full chain.
/// See spec §10.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentToken {
    /// The unique token identifier. Format: `lmt_<alphanumeric>`.
    pub token_id: TokenId,

    /// The participant ID of the patient who issued this token.
    pub issued_by: ParticipantId,

    /// The participant ID of the institution this token was issued to.
    pub issued_to: ParticipantId,

    /// The UTC timestamp at which this token was issued.
    pub issued_at: DateTime<Utc>,

    /// The UTC timestamp after which this token is no longer valid.
    ///
    /// Enforced at the protocol layer — a token presented after this time
    /// is unconditionally rejected. See spec §10.2.
    pub expires_at: DateTime<Utc>,

    /// The scope of access this token grants. See spec §10.1.
    pub scope: ConsentScope,

    /// A short, patient-supplied statement of why access was requested.
    ///
    /// Example: `"claim_verification"`. Free text in v1 — the spec does
    /// not define a closed set of purpose values.
    pub purpose: String,

    /// Whether this token grants read or write access.
    pub access_type: AccessType,

    /// Whether this token may be presented only once.
    ///
    /// Always `true` in v1 — every token is single-use per spec §10.2.
    /// The field exists on the wire (matching spec §10.1) even though its
    /// value is currently fixed, since the schema defines it as a token
    /// property, not a protocol constant.
    pub one_time_use: bool,

    /// Whether this token has already been presented and consumed.
    ///
    /// Always `false` at issuance. Set `true` permanently the first time
    /// the token is presented — enforced at presentation time, not
    /// issuance time. See spec §10.2.
    pub used: bool,

    /// The ed25519 signature over this token's content, produced by the
    /// issuing patient's private key.
    ///
    /// Computed over the canonical JSON of every other field with this
    /// field set to an empty string — the same sign-then-embed pattern
    /// used for commits. See spec §10.1 and §10.2.
    pub patient_signature: String,
}

/// A partially assembled consent token awaiting the patient's signature.
///
/// Created by [`prepare_token`]. The caller signs `canonical_bytes` with
/// the patient's private key, then calls [`PendingConsentToken::finalise`]
/// to produce the completed [`ConsentToken`].
pub struct PendingConsentToken {
    /// The assembled token with an empty `patient_signature`.
    token: ConsentToken,

    /// The canonical JSON bytes of the token, with `patient_signature` set
    /// to an empty string. These are the bytes the caller must sign.
    pub canonical_bytes: Vec<u8>,
}

impl PendingConsentToken {
    /// Embeds the signature and returns the completed token.
    ///
    /// # Arguments
    ///
    /// * `signature` — The ed25519 signature over `self.canonical_bytes`,
    ///   produced by the issuing patient's private key. Must be in the
    ///   format `"ed25519:<lowercase hex>"`.
    pub fn finalise(mut self, signature: String) -> ConsentToken {
        self.token.patient_signature = signature;
        self.token
    }
}

/// Builds a [`PendingConsentToken`] for a new consent token issuance.
///
/// Generates the `token_id`, sets `issued_at` to now, and computes
/// `expires_at` from `duration_hours`. `one_time_use` is always `true` and
/// `used` is always `false` at issuance, per spec §10.1–§10.2.
///
/// # Arguments
///
/// * `issued_by` — The patient issuing the token (the vault owner).
/// * `issued_to` — The institution the token is issued to.
/// * `scope` — The scope of access granted.
/// * `purpose` — A short statement of why access was requested.
/// * `access_type` — Whether this token grants read or write access.
/// * `duration_hours` — How many hours from now the token remains valid.
///   Must be positive.
///
/// # Returns
///
/// A [`PendingConsentToken`] whose `canonical_bytes` must be signed before
/// calling [`PendingConsentToken::finalise`].
///
/// # Errors
///
/// * [`LooMedError::InvalidConsentDuration`] — `duration_hours` is zero or
///   negative.
/// * [`LooMedError::SerializationFailed`] — The token could not be
///   serialised.
///
/// See spec §10.1.
pub fn prepare_token(
    issued_by: ParticipantId,
    issued_to: ParticipantId,
    scope: ConsentScope,
    purpose: String,
    access_type: AccessType,
    duration_hours: i64,
) -> Result<PendingConsentToken, LooMedError> {
    if duration_hours <= 0 {
        return Err(LooMedError::InvalidConsentDuration {
            hours: duration_hours,
        });
    }

    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::hours(duration_hours);

    let token = ConsentToken {
        token_id: generate_token_id(),
        issued_by,
        issued_to,
        issued_at,
        expires_at,
        scope,
        purpose,
        access_type,
        one_time_use: true,
        used: false,
        patient_signature: String::new(),
    };

    let canonical_bytes =
        serde_json::to_vec(&token).map_err(|e| LooMedError::SerializationFailed {
            reason: e.to_string(),
        })?;

    Ok(PendingConsentToken {
        token,
        canonical_bytes,
    })
}

/// Generates a random token ID in the format `lmt_<16 alphanumeric chars>`.
///
/// See spec §10.1. Uniqueness is probabilistic (16 characters from a
/// 62-character alphabet), the same approach used for commit and other
/// protocol-random identifiers in this codebase.
fn generate_token_id() -> TokenId {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let suffix: String = (0..16)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect();
    TokenId(format!("lmt_{}", suffix))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use loomed_crypto::{generate_keypair, sign, verify};

    fn patient_id() -> ParticipantId {
        ParticipantId::new("LMP-7XKQR2MNVB-6A").unwrap()
    }

    fn institution_id() -> ParticipantId {
        ParticipantId::new("LMI-APL-2MVZK9QXBT-08").unwrap()
    }

    /// Spec §10.1: token_id must carry the `lmt_` prefix.
    #[test]
    fn generated_token_id_has_lmt_prefix() {
        let token_id = generate_token_id();
        assert!(token_id.as_str().starts_with("lmt_"));
    }

    /// Spec §10.1: `full_record` scope round-trips through Display/FromStr.
    #[test]
    fn full_record_scope_roundtrips() {
        let scope = ConsentScope::FullRecord;
        assert_eq!(scope.to_string(), "full_record");
        assert_eq!("full_record".parse::<ConsentScope>().unwrap(), scope);
    }

    /// Spec §10.1: `record_type:<type>` scope round-trips through Display/FromStr.
    #[test]
    fn record_type_scope_roundtrips() {
        let scope = ConsentScope::RecordType(RecordType::LabResult);
        assert_eq!(scope.to_string(), "record_type:lab_result");
        assert_eq!(
            "record_type:lab_result".parse::<ConsentScope>().unwrap(),
            scope
        );
    }

    /// Spec §10.1: `commit:<commit_id>` scope round-trips through Display/FromStr.
    #[test]
    fn commit_scope_roundtrips() {
        let hash = CommitHash("sha256:abc123".to_string());
        let scope = ConsentScope::Commit(hash.clone());
        assert_eq!(scope.to_string(), format!("commit:{}", hash.as_str()));
        assert_eq!(
            format!("commit:{}", hash.as_str())
                .parse::<ConsentScope>()
                .unwrap(),
            scope
        );
    }

    /// Spec §10.1: An unrecognised scope string must be rejected.
    #[test]
    fn unknown_scope_string_is_rejected() {
        let result = "some_other_scope".parse::<ConsentScope>();
        assert!(matches!(
            result,
            Err(LooMedError::InvalidConsentScope { .. })
        ));
    }

    /// Spec §10.1: A `record_type:` scope with an unknown record type must be rejected.
    #[test]
    fn record_type_scope_with_unknown_type_is_rejected() {
        let result = "record_type:not_a_real_type".parse::<ConsentScope>();
        assert!(matches!(
            result,
            Err(LooMedError::InvalidConsentScope { .. })
        ));
    }

    /// Spec §10.1: A `commit:` scope with an empty commit ID must be rejected.
    #[test]
    fn commit_scope_with_empty_id_is_rejected() {
        let result = "commit:".parse::<ConsentScope>();
        assert!(matches!(
            result,
            Err(LooMedError::InvalidConsentScope { .. })
        ));
    }

    /// Spec §10.1: A token serialises the scope as a flat string, not a nested object.
    #[test]
    fn scope_serialises_as_flat_string_on_token() {
        let pending = prepare_token(
            patient_id(),
            institution_id(),
            ConsentScope::RecordType(RecordType::Prescription),
            "claim_verification".to_string(),
            AccessType::Read,
            4,
        )
        .unwrap();

        let value: serde_json::Value = serde_json::from_slice(&pending.canonical_bytes).unwrap();
        assert_eq!(value["scope"], "record_type:prescription");
    }

    /// Spec §10.1: A zero or negative duration must be rejected.
    #[test]
    fn non_positive_duration_is_rejected() {
        let result = prepare_token(
            patient_id(),
            institution_id(),
            ConsentScope::FullRecord,
            "claim_verification".to_string(),
            AccessType::Read,
            0,
        );
        assert!(matches!(
            result,
            Err(LooMedError::InvalidConsentDuration { hours: 0 })
        ));
    }

    /// Spec §10.1: `expires_at` must be strictly after `issued_at`.
    #[test]
    fn expires_at_is_after_issued_at() {
        let pending = prepare_token(
            patient_id(),
            institution_id(),
            ConsentScope::FullRecord,
            "claim_verification".to_string(),
            AccessType::Read,
            4,
        )
        .unwrap();

        assert!(pending.token.expires_at > pending.token.issued_at);
    }

    /// Spec §10.1: A prepared token has an empty patient_signature before finalisation.
    #[test]
    fn prepared_token_has_empty_signature() {
        let pending = prepare_token(
            patient_id(),
            institution_id(),
            ConsentScope::FullRecord,
            "claim_verification".to_string(),
            AccessType::Read,
            4,
        )
        .unwrap();

        assert_eq!(pending.token.patient_signature, "");
    }

    /// Spec §10.1–§10.2: A finalised token's signature verifies against the
    /// issuing patient's public key, and `used`/`one_time_use` default correctly.
    #[test]
    fn finalised_token_signature_is_valid_and_defaults_are_correct() {
        let keypair = generate_keypair();

        let pending = prepare_token(
            patient_id(),
            institution_id(),
            ConsentScope::FullRecord,
            "claim_verification".to_string(),
            AccessType::Read,
            4,
        )
        .unwrap();

        let signature = sign(&keypair, &pending.canonical_bytes);
        let canonical_bytes = pending.canonical_bytes.clone();
        let token = pending.finalise(signature.clone());

        assert!(verify(&keypair.public_key_hex(), &canonical_bytes, &signature).is_ok());
        assert_eq!(token.patient_signature, signature);
        assert!(token.one_time_use);
        assert!(!token.used);
    }

    /// Spec §10.2: A token signature must not verify against a different keypair.
    #[test]
    fn token_signature_does_not_verify_against_wrong_key() {
        let keypair = generate_keypair();
        let other_keypair = generate_keypair();

        let pending = prepare_token(
            patient_id(),
            institution_id(),
            ConsentScope::FullRecord,
            "claim_verification".to_string(),
            AccessType::Read,
            4,
        )
        .unwrap();

        let signature = sign(&keypair, &pending.canonical_bytes);
        let canonical_bytes = pending.canonical_bytes.clone();

        assert!(verify(&other_keypair.public_key_hex(), &canonical_bytes, &signature).is_err());
    }
}
