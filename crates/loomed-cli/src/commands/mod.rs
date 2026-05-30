//! # CLI Commands
//!
//! Each subcommand of the LooMed CLI is implemented in its own module.
//! Modules parse their arguments and delegate to `loomed-core` and
//! `loomed-store`. No business logic lives here.
//!
//! ## Passphrase Handling
//!
//! All commands that require a passphrase call [`read_passphrase`] rather
//! than invoking `rpassword` directly. In normal use this is identical —
//! `read_passphrase` delegates to `rpassword::prompt_password`. When the
//! `LOOMED_PASSPHRASE` environment variable is set, the passphrase is read
//! from it instead. This is the standard pattern used by OpenSSL, GPG, and
//! SSH for non-interactive and test use. The production `loomed` binary
//! behaves identically to before when `LOOMED_PASSPHRASE` is not set.
//!
//! See coding standards §0.6.

pub mod add;
pub mod commit;
pub mod init;
pub mod log;
pub mod prompts;
pub mod remote;
pub mod show;
pub mod status;
pub mod sync_cmd;
pub mod verify;

/// Reads the vault passphrase for the current operation.
///
/// In normal interactive use, this delegates to `rpassword::prompt_password`,
/// which reads from the terminal without echoing characters. When the
/// `LOOMED_PASSPHRASE` environment variable is set, the passphrase is read
/// from it instead — no prompt is shown and no terminal is required.
///
/// This follows the same convention as OpenSSL (`OPENSSL_PASS`), GPG
/// (`--passphrase-fd`), and SSH (`SSH_ASKPASS`): non-interactive callers
/// supply credentials via the environment. The production `loomed` binary
/// behaves identically to before when the variable is not set.
///
/// # Arguments
///
/// * `prompt` — The prompt string shown to the user in interactive mode.
///   Ignored when `LOOMED_PASSPHRASE` is set.
///
/// # Errors
///
/// Returns an error if `rpassword` fails to read from the terminal
/// (interactive mode only). Never fails when `LOOMED_PASSPHRASE` is set.
///
/// See coding standards §0.6.
pub fn read_passphrase(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(p) = std::env::var("LOOMED_PASSPHRASE") {
        return Ok(p);
    }
    Ok(rpassword::prompt_password(prompt)?)
}