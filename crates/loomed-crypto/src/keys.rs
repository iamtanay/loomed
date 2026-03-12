//! # Key Management
//!
//! ed25519 keypair generation, commit signing, and signature verification.
//!
//! ## Responsibilities
//! - Generating ed25519 keypairs for new participants (spec §4.3)
//! - Signing commit content with a participant's private key (spec §6.2)
//! - Verifying commit signatures against a participant's public key (spec §6.2)
//!
//! ## Not Responsible For
//! - Key derivation from passphrases (see `loomed-crypto::encrypt`)
//! - Key storage or persistence (see `loomed-store`)
//! - Identity provider binding (spec §4, future: `loomed-idp`)

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::CryptoError;

/// An ed25519 keypair for a LooMed participant.
///
/// The signing key is the private key used to sign commits. The verifying
/// key is the public key published in the participant registry and used
/// by any participant to verify commit signatures.
///
/// The private key must never be serialised to disk in plaintext. In Phase 1,
/// it is derived from a passphrase via Argon2id. In Phase 2+, it is bound
/// to an identity provider. See spec §4.
pub struct LooMedKeypair {
    /// The ed25519 signing key (private key).
    ///
    /// Never exposed outside this struct in raw form. Use `sign()` to
    /// produce signatures.
    signing_key: SigningKey,

    /// The ed25519 verifying key (public key).
    ///
    /// Safe to publish. Stored in the participant registry. Used by any
    /// participant to verify commits authored by this keypair.
    pub verifying_key: VerifyingKey,
}

impl LooMedKeypair {
    /// Returns the public key as a lowercase hex string prefixed with "ed25519:".
    ///
    /// This is the format used in participant registration schemas and
    /// the vault.toml metadata file. See spec §3.2.
    pub fn public_key_hex(&self) -> String {
        format!("ed25519:{}", hex::encode(self.verifying_key.as_bytes()))
    }
}

/// Generates a new ed25519 keypair using a cryptographically secure RNG.
///
/// Used when initialising a new patient vault or registering a new
/// participant. The returned keypair must be protected immediately —
/// in Phase 1, by deriving an encryption key from the user's passphrase
/// and encrypting the signing key before writing it to disk.
///
/// # Returns
///
/// A new [`LooMedKeypair`] with a freshly generated signing and verifying key.
///
/// See spec §4.3.
pub fn generate_keypair() -> LooMedKeypair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    LooMedKeypair {
        signing_key,
        verifying_key,
    }
}

/// Signs a message with the given keypair's private key.
///
/// The message should be the canonical JSON serialisation of the commit
/// object prior to the signature field being set. The returned signature
/// is a lowercase hex string prefixed with "ed25519:".
///
/// # Arguments
///
/// * `keypair` — The keypair whose private key will sign the message.
/// * `message` — The raw bytes to sign. Must be the same bytes used
///   during verification.
///
/// # Returns
///
/// A `String` of the form `"ed25519:<lowercase hex signature>"`.
///
/// See spec §6.2.
pub fn sign(keypair: &LooMedKeypair, message: &[u8]) -> String {
    let signature: Signature = keypair.signing_key.sign(message);
    format!("ed25519:{}", hex::encode(signature.to_bytes()))
}

/// Verifies an ed25519 signature against a public key and message.
///
/// # Arguments
///
/// * `public_key_hex` — The signer's public key as a hex string, with or
///   without the "ed25519:" prefix.
/// * `message` — The raw bytes that were signed. Must be identical to
///   the bytes passed to `sign()`.
/// * `signature_hex` — The signature to verify, as a hex string, with or
///   without the "ed25519:" prefix.
///
/// # Returns
///
/// `Ok(())` if the signature is valid.
///
/// # Errors
///
/// * [`CryptoError::SignatureInvalid`] — The signature did not verify.
///   Either the message was modified after signing or the wrong public
///   key was provided. See spec §6.2.
pub fn verify(
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), CryptoError> {
    let key_hex = public_key_hex.trim_start_matches("ed25519:");
    let sig_hex = signature_hex.trim_start_matches("ed25519:");

    let key_bytes = hex::decode(key_hex).map_err(|_| CryptoError::SignatureInvalid)?;
    let sig_bytes = hex::decode(sig_hex).map_err(|_| CryptoError::SignatureInvalid)?;

    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| CryptoError::SignatureInvalid)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CryptoError::SignatureInvalid)?;

    let verifying_key =
        VerifyingKey::from_bytes(&key_array).map_err(|_| CryptoError::SignatureInvalid)?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(message, &signature)
        .map_err(|_| CryptoError::SignatureInvalid)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec §6.2: A signature produced by sign() must verify successfully.
    #[test]
    fn sign_and_verify_roundtrip() {
        let keypair = generate_keypair();
        let message = b"test commit content";
        let signature = sign(&keypair, message);
        let public_key = keypair.public_key_hex();
        assert!(verify(&public_key, message, &signature).is_ok());
    }

    /// Spec §6.2: A tampered message must fail signature verification.
    #[test]
    fn tampered_message_fails_verification() {
        let keypair = generate_keypair();
        let message = b"original commit content";
        let signature = sign(&keypair, message);
        let public_key = keypair.public_key_hex();
        let tampered = b"tampered commit content";
        assert!(verify(&public_key, tampered, &signature).is_err());
    }

    /// Spec §6.2: A signature verified against the wrong public key must fail.
    #[test]
    fn wrong_public_key_fails_verification() {
        let keypair1 = generate_keypair();
        let keypair2 = generate_keypair();
        let message = b"test commit content";
        let signature = sign(&keypair1, message);
        let wrong_key = keypair2.public_key_hex();
        assert!(verify(&wrong_key, message, &signature).is_err());
    }

    /// Spec §4.3: public_key_hex must be prefixed with "ed25519:".
    #[test]
    fn public_key_hex_has_correct_prefix() {
        let keypair = generate_keypair();
        assert!(keypair.public_key_hex().starts_with("ed25519:"));
    }
}