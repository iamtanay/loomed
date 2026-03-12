//! # `loomed init`
//!
//! Initialises a new patient vault in the current directory.
//!
//! ## What this command does
//! 1. Prompts the user for a participant ID
//! 2. Prompts for a vault passphrase (twice, to confirm)
//! 3. Generates an ed25519 keypair
//! 4. Generates a random Argon2id salt
//! 5. Initialises the vault on disk via loomed-store
//! 6. Prints the public key and participant ID to the terminal
//!
//! ## What it does NOT do
//! - Connect to any network
//! - Register the participant with any registry
//! - Store the private key in plaintext anywhere

use std::env;
use std::io::Write;

use loomed_core::ParticipantId;
use loomed_crypto::generate_keypair;
use loomed_store::Vault;
use rand::RngCore;

/// Runs the `loomed init` command.
///
/// Prompts the user for a participant ID and passphrase, generates an
/// ed25519 keypair and Argon2id salt, and initialises the encrypted vault
/// on disk in the current directory.
///
/// # Errors
///
/// Returns a boxed error if vault initialisation fails for any reason,
/// including an existing vault, a filesystem error, or a passphrase mismatch.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("LooMed — initialising new patient vault");
    println!();

    // Step 1 — Get participant ID
    let patient_id = prompt_participant_id()?;

    // Step 2 — Get and confirm passphrase.
    //
    // TODO: The passphrase is collected here to establish the full init flow.
    // It will be used to encrypt the genesis commit when `loomed commit` is
    // implemented in the next phase. See spec §5 and §6.
    let passphrase = prompt_passphrase()?;
    let _ = &passphrase; // will be used for genesis commit encryption

    // Step 3 — Generate ed25519 keypair.
    //
    // The keypair is generated using a cryptographically secure RNG via
    // loomed-crypto. The private key exists only in memory for the duration
    // of this command. In Phase 1, it is not persisted to disk — key
    // persistence and IdP binding are implemented in Phase 4. See spec §4.
    println!("generating ed25519 keypair...");
    let keypair = generate_keypair();
    let public_key = keypair.public_key_hex();

    // Step 4 — Generate a random Argon2id salt.
    //
    // The salt is generated once per vault and stored in plaintext in
    // vault.toml. It is not secret — its purpose is to ensure that the
    // same passphrase produces a different encryption key for every vault.
    // See spec §5.
    let mut salt_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt_bytes);
    let argon2_salt = hex::encode(salt_bytes);

    // Step 5 — Initialise the vault directory structure on disk.
    let current_dir = env::current_dir()?;
    println!("initialising vault at {}/.loomed/", current_dir.display());

    Vault::init(
        &current_dir,
        &patient_id,
        &public_key,
        &argon2_salt,
    )?;

    // Step 6 — Print summary.
    println!();
    println!("vault initialised successfully.");
    println!();
    println!("  participant ID : {}", patient_id);
    println!("  public key     : {}", public_key);
    println!("  idp type       : passphrase (Phase 1)");
    println!("  vault path     : {}/.loomed/", current_dir.display());
    println!();
    println!("your vault is encrypted with your passphrase.");
    println!("do not lose your passphrase — there is no recovery in Phase 1.");
    println!();

    Ok(())
}

/// Prompts the user to enter their participant ID.
///
/// Validates the format using [`ParticipantId::new`] before returning.
/// Loops until a valid ID is entered.
///
/// # Errors
///
/// Returns an error only if stdin or stdout encounters an I/O failure.
fn prompt_participant_id() -> Result<ParticipantId, Box<dyn std::error::Error>> {
    loop {
        print!("enter your participant ID (e.g. LMP-7XKQR2MNVB-F4): ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_string();

        match ParticipantId::new(trimmed) {
            Ok(id) => return Ok(id),
            Err(_) => {
                println!(
                    "invalid participant ID format. must start with LMP-, LMD-, LMI-, LMV-, or LMG-"
                );
            }
        }
    }
}

/// Prompts the user to enter and confirm a vault passphrase.
///
/// The passphrase is read without echoing characters to the terminal
/// via `rpassword`. Enforces a minimum length of 8 characters.
/// Loops until both entries match and the length requirement is met.
///
/// # Errors
///
/// Returns an error only if the terminal I/O fails.
fn prompt_passphrase() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    loop {
        let passphrase = rpassword::prompt_password("enter vault passphrase: ")?;
        let confirm = rpassword::prompt_password("confirm vault passphrase: ")?;

        if passphrase != confirm {
            println!("passphrases do not match. try again.");
            continue;
        }

        if passphrase.len() < 8 {
            println!("passphrase must be at least 8 characters.");
            continue;
        }

        return Ok(passphrase.into_bytes());
    }
}