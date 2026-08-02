//! # Identity Provider Abstraction
//!
//! The `IdentityProvider` trait is the seam the spec calls for at §4: a
//! single interface behind which any identity tier — software passphrase,
//! national digital ID, hardware secure enclave, or Shamir custodian
//! quorum — can produce commit signatures. v1.0 ships exactly one
//! implementation, [`PassphraseIdentityProvider`] (Tier 0). Tier 1–3 slot
//! in later as new trait implementations with no call-site changes, per
//! `ARCHITECTURE.md` and `FIRST_RELEASE_PLAN.md`.
//!
//! ## Responsibilities
//! - `IdentityProvider` — the tier-agnostic signing interface (spec §4)
//! - `PassphraseIdentityProvider` — Tier 0, wraps the existing deterministic
//!   `derive_keypair` (spec §4.2, §4.3)
//! - BIP-39 recovery mnemonic generation and recovery, independent of the
//!   vault passphrase (spec §4, Tier 0 recovery path)
//!
//! ## Not Responsible For
//! - Persisting any key material to disk (see `loomed-store`)
//! - Deciding when a mnemonic must be confirmed by the user (see
//!   `loomed-cli::commands::init`)
//! - Tier 1 (national ID), Tier 2 (hardware enclave), Tier 3 (Shamir
//!   quorum) — deferred past v1.0, see `FIRST_RELEASE_PLAN.md`

use bip39::Mnemonic;

use crate::error::CryptoError;
use crate::keys::{derive_keypair, sign, LooMedKeypair};

/// The byte length of a BIP-39 24-word mnemonic's entropy.
///
/// 24 words encode exactly 256 bits (32 bytes) of entropy — the same
/// length as an ed25519 signing key seed. This is deliberate: the
/// mnemonic's entropy *is* the signing key seed, not a hash or wrapper
/// around it, so recovery is a direct, lossless round trip with no
/// separate derivation step to keep in sync.
const MNEMONIC_ENTROPY_LEN: usize = 32;

/// A tier-agnostic identity that can produce commit signatures.
///
/// Every identity tier in the LooMed spec (§4) — software passphrase
/// custody, national digital ID binding, hardware secure enclave, Shamir
/// custodian quorum — implements this same trait. Call sites that need a
/// signature (`loomed commit`, `loomed share`, `loomed revoke`, `loomed
/// key rotate`) depend only on this trait, never on a concrete tier.
///
/// See spec §4.
pub trait IdentityProvider {
    /// Signs `message` and returns the signature as `"ed25519:<hex>"`.
    ///
    /// See spec §6.2.
    fn sign(&self, message: &[u8]) -> String;

    /// Returns the public key as `"ed25519:<hex>"`.
    ///
    /// See spec §4.3.
    fn public_key_hex(&self) -> String;

    /// Returns the identity tier this provider implements.
    ///
    /// One of `"software_passphrase"` (Tier 0), `"national_id"` (Tier 1),
    /// `"hardware_enclave"` (Tier 2), or `"custodian_quorum"` (Tier 3).
    /// v1.0 ships only Tier 0. See spec §4.2.
    fn tier(&self) -> &'static str;
}

/// Tier 0 identity: a keypair deterministically derived from the vault
/// passphrase and Argon2id salt.
///
/// This is exactly what Phase 1 already does — `PassphraseIdentityProvider`
/// formalises it behind [`IdentityProvider`] so stronger tiers can be added
/// later without touching any call site. See spec §4.2 and
/// `FIRST_RELEASE_PLAN.md`.
pub struct PassphraseIdentityProvider {
    keypair: LooMedKeypair,
}

impl PassphraseIdentityProvider {
    /// Derives a `PassphraseIdentityProvider` from a passphrase and salt.
    ///
    /// The salt must be generated (or loaded from vault.toml) before this
    /// call, per coding standards §0.5.
    ///
    /// # Arguments
    ///
    /// * `passphrase` — The vault passphrase as bytes.
    /// * `salt` — The hex-decoded Argon2id salt.
    ///
    /// # Errors
    ///
    /// * [`CryptoError::KeyDerivationFailed`] — Argon2id derivation failed.
    pub fn new(passphrase: &[u8], salt: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            keypair: derive_keypair(passphrase, salt)?,
        })
    }

    /// Returns the 32-byte ed25519 signing key seed underlying this
    /// identity, suitable for encoding as a BIP-39 recovery mnemonic via
    /// [`mnemonic_from_seed`].
    ///
    /// This is the same 32 bytes Argon2id produced from the passphrase —
    /// exposing it is safe only in the sense that the caller already holds
    /// the passphrase; the seed must never be logged or written to disk
    /// outside the one-time mnemonic display at `loomed init`. See
    /// coding standards §0.4.
    pub fn signing_key_seed(&self) -> [u8; 32] {
        self.keypair.signing_key_bytes()
    }
}

impl IdentityProvider for PassphraseIdentityProvider {
    fn sign(&self, message: &[u8]) -> String {
        sign(&self.keypair, message)
    }

    fn public_key_hex(&self) -> String {
        self.keypair.public_key_hex()
    }

    fn tier(&self) -> &'static str {
        "software_passphrase"
    }
}

/// Generates a 24-word BIP-39 English recovery mnemonic that encodes
/// `seed` directly as its entropy.
///
/// Because the mnemonic's entropy *is* the ed25519 signing key seed, the
/// phrase alone — independent of the vault passphrase — is enough to
/// reconstruct the exact same signing key via [`seed_from_mnemonic`]. This
/// is the Tier 0 recovery path: it does not replace the passphrase as the
/// day-to-day credential, but it recovers the same keypair if the
/// passphrase is forgotten. See `FIRST_RELEASE_PLAN.md` (R5).
///
/// # Arguments
///
/// * `seed` — The 32-byte ed25519 signing key seed, e.g. from
///   [`PassphraseIdentityProvider::signing_key_seed`].
///
/// # Errors
///
/// * [`CryptoError::InvalidMnemonic`] — BIP-39 entropy encoding failed
///   (only possible if `seed` were an unsupported length, which the fixed
///   32-byte input here never is).
pub fn mnemonic_from_seed(seed: &[u8; 32]) -> Result<String, CryptoError> {
    let mnemonic = Mnemonic::from_entropy(seed).map_err(|e| CryptoError::InvalidMnemonic {
        reason: e.to_string(),
    })?;
    Ok(mnemonic.to_string())
}

/// Recovers the original 32-byte ed25519 signing key seed from a BIP-39
/// recovery phrase produced by [`mnemonic_from_seed`].
///
/// # Arguments
///
/// * `phrase` — A 24-word BIP-39 English mnemonic.
///
/// # Errors
///
/// * [`CryptoError::InvalidMnemonic`] — The phrase is not valid BIP-39
///   English wordlist text with a correct checksum, or does not encode
///   exactly 32 bytes of entropy.
pub fn seed_from_mnemonic(phrase: &str) -> Result<[u8; 32], CryptoError> {
    let mnemonic = Mnemonic::parse_normalized(phrase).map_err(|e| CryptoError::InvalidMnemonic {
        reason: e.to_string(),
    })?;
    let entropy = mnemonic.to_entropy();

    if entropy.len() != MNEMONIC_ENTROPY_LEN {
        return Err(CryptoError::InvalidMnemonic {
            reason: format!(
                "expected {} bytes of entropy (24-word phrase), found {}",
                MNEMONIC_ENTROPY_LEN,
                entropy.len()
            ),
        });
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&entropy);
    Ok(seed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec §4: PassphraseIdentityProvider must be deterministic — the
    /// same passphrase and salt always produce the same public key.
    #[test]
    fn passphrase_identity_provider_is_deterministic() {
        let provider1 = PassphraseIdentityProvider::new(b"test-passphrase", b"salt1234salt5678").unwrap();
        let provider2 = PassphraseIdentityProvider::new(b"test-passphrase", b"salt1234salt5678").unwrap();
        assert_eq!(provider1.public_key_hex(), provider2.public_key_hex());
    }

    /// Spec §4.2: PassphraseIdentityProvider reports the software_passphrase tier.
    #[test]
    fn passphrase_identity_provider_reports_tier_0() {
        let provider = PassphraseIdentityProvider::new(b"test-passphrase", b"salt1234salt5678").unwrap();
        assert_eq!(provider.tier(), "software_passphrase");
    }

    /// Spec §6.2: A signature from IdentityProvider::sign must verify
    /// against IdentityProvider::public_key_hex.
    #[test]
    fn identity_provider_sign_and_verify_roundtrip() {
        let provider = PassphraseIdentityProvider::new(b"test-passphrase", b"salt1234salt5678").unwrap();
        let message = b"a commit's canonical bytes";
        let signature = provider.sign(message);
        assert!(crate::verify(&provider.public_key_hex(), message, &signature).is_ok());
    }

    /// FIRST_RELEASE_PLAN.md R5: A mnemonic generated from a seed must
    /// recover the exact same seed.
    #[test]
    fn mnemonic_round_trips_to_original_seed() {
        let seed = [42u8; 32];
        let phrase = mnemonic_from_seed(&seed).unwrap();
        let recovered = seed_from_mnemonic(&phrase).unwrap();
        assert_eq!(seed, recovered);
    }

    /// FIRST_RELEASE_PLAN.md R5: The generated recovery phrase must be
    /// exactly 24 words (256 bits of entropy).
    #[test]
    fn mnemonic_is_24_words() {
        let seed = [7u8; 32];
        let phrase = mnemonic_from_seed(&seed).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    /// FIRST_RELEASE_PLAN.md R5: A mnemonic recovered from a seed must
    /// reconstruct the identical keypair the seed originally produced.
    #[test]
    fn recovered_seed_reconstructs_identical_keypair() {
        let provider = PassphraseIdentityProvider::new(b"test-passphrase", b"salt1234salt5678").unwrap();
        let seed = provider.signing_key_seed();
        let phrase = mnemonic_from_seed(&seed).unwrap();

        let recovered_seed = seed_from_mnemonic(&phrase).unwrap();
        let recovered_keypair = crate::keys::keypair_from_seed(&recovered_seed);

        assert_eq!(provider.public_key_hex(), recovered_keypair.public_key_hex());
    }

    /// Spec §4: A malformed recovery phrase must be rejected, not panic
    /// or silently produce a wrong key.
    #[test]
    fn malformed_mnemonic_is_rejected() {
        let result = seed_from_mnemonic("not a valid recovery phrase at all");
        assert!(matches!(result, Err(CryptoError::InvalidMnemonic { .. })));
    }

    /// Spec §4: A well-formed but wrong-length (12-word) phrase must be
    /// rejected — v1 mnemonics are always 24 words / 32 bytes.
    #[test]
    fn twelve_word_mnemonic_is_rejected() {
        // A valid 12-word BIP-39 test vector (128 bits of entropy).
        let twelve_words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = seed_from_mnemonic(twelve_words);
        assert!(matches!(result, Err(CryptoError::InvalidMnemonic { .. })));
    }

    /// Spec §4: Different seeds must produce different mnemonics.
    #[test]
    fn different_seeds_produce_different_mnemonics() {
        let phrase1 = mnemonic_from_seed(&[1u8; 32]).unwrap();
        let phrase2 = mnemonic_from_seed(&[2u8; 32]).unwrap();
        assert_ne!(phrase1, phrase2);
    }
}
