//! # Consent Token Chain Scanning
//!
//! Shared chain-traversal logic for the three commands that need to
//! answer questions about consent tokens that only the full commit chain
//! can answer: has this token been used, has it been revoked, what
//! tokens exist at all. `loomed commit --token`, `loomed revoke`, and
//! `loomed audit` all call into this module so the three commands agree
//! on exactly what "used" and "revoked" mean — there is exactly one
//! place that defines it.
//!
//! Not in `loomed-core`: answering these questions requires reading and
//! decrypting every commit in the vault, which is disk I/O. `loomed-core`
//! is I/O-free by design; see `ARCHITECTURE.md`.

use chrono::{DateTime, Utc};
use loomed_core::{AuthorizationRef, CommitHash, ConsentToken, RecordType};
use loomed_store::Vault;

/// The chain-derived state of one consent token: its issuance data, plus
/// whether and when it was used or revoked.
pub struct TokenState {
    /// The token as issued — signature, scope, expiry, everything from
    /// its `consent_token` commit.
    pub token: ConsentToken,

    /// The commit_id and timestamp of the write that consumed this token,
    /// if any. A token is "used" the moment any commit in the chain
    /// carries its ID as `AuthorizationRef::ConsentToken` — see
    /// `crates/loomed-cli/src/commands/commit.rs`'s module doc for why no
    /// separate marker commit is needed for this.
    pub used_by: Option<(CommitHash, DateTime<Utc>)>,

    /// The timestamp of the `token_revocation` commit that invalidated
    /// this token early, if any.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Traverses the full commit chain once and returns the state of every
/// consent token ever issued in this vault.
///
/// Order is not significant to the result: every `consent_token` issuance,
/// every `ConsentToken`-authorized commit, and every `token_revocation`
/// commit are collected first, then cross-referenced by token_id — so it
/// does not matter that traversal moves backwards in time from HEAD while
/// a token's own issuance is necessarily earlier than its use or its
/// revocation.
///
/// # Errors
///
/// Returns a boxed error if the vault's HEAD or any commit cannot be
/// read or decrypted with `passphrase_bytes`.
pub fn scan_all_tokens(
    vault: &Vault,
    passphrase_bytes: &[u8],
) -> Result<Vec<TokenState>, Box<dyn std::error::Error>> {
    let mut issued: Vec<ConsentToken> = Vec::new();
    let mut used: Vec<(String, CommitHash, DateTime<Utc>)> = Vec::new();
    let mut revoked: Vec<(String, DateTime<Utc>)> = Vec::new();

    let mut current = vault.read_head()?;
    while let Some(commit_id) = current {
        let commit = vault.read_commit(&commit_id, passphrase_bytes)?;

        if let AuthorizationRef::ConsentToken { token_id } = &commit.authorization_ref {
            used.push((
                token_id.as_str().to_string(),
                commit.commit_id.clone(),
                commit.timestamp,
            ));
        }

        match commit.record_type {
            RecordType::ConsentToken => {
                if let Ok(token) = serde_json::from_value::<ConsentToken>(commit.payload.clone()) {
                    issued.push(token);
                }
            }
            RecordType::TokenRevocation => {
                if let Some(token_id) = commit.payload.get("token_id").and_then(|v| v.as_str()) {
                    revoked.push((token_id.to_string(), commit.timestamp));
                }
            }
            _ => {}
        }

        current = commit.previous_hash.clone();
    }

    let states = issued
        .into_iter()
        .map(|token| {
            let used_by = used
                .iter()
                .find(|(id, _, _)| id == token.token_id.as_str())
                .map(|(_, commit_id, ts)| (commit_id.clone(), *ts));
            let revoked_at = revoked
                .iter()
                .find(|(id, _)| id == token.token_id.as_str())
                .map(|(_, ts)| *ts);
            TokenState {
                token,
                used_by,
                revoked_at,
            }
        })
        .collect();

    Ok(states)
}

/// Finds one token's chain state by ID.
///
/// # Errors
///
/// Returns a boxed error if the chain cannot be read or decrypted.
/// Returns `Ok(None)` (not an error) if no `consent_token` commit in the
/// chain issued this token_id — callers decide whether that's an error.
pub fn find_token(
    vault: &Vault,
    passphrase_bytes: &[u8],
    token_id_str: &str,
) -> Result<Option<TokenState>, Box<dyn std::error::Error>> {
    Ok(scan_all_tokens(vault, passphrase_bytes)?
        .into_iter()
        .find(|state| state.token.token_id.as_str() == token_id_str))
}
