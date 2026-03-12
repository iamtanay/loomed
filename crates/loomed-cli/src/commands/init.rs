//! # `loomed init`
//!
//! Initialises a new patient vault in the current directory.
//!
//! ## What this command does
//! 1. Prompts the user for a participant ID
//! 2. Prompts for a vault passphrase (twice, to confirm)
//! 3. Generates a random Argon2id salt
//! 4. Derives a deterministic ed25519 keypair from passphrase + salt
//! 5. Initialises the vault on disk via loomed-store
//! 6. Writes the genesis commit to the vault
//! 7. Prints the public key and participant ID to the terminal
//!
//! ## What it does NOT do
//! - Connect to any network
//! - Register the participant with any registry
//! - Store the private key in plaintext anywhere

use std::env;
use std::io::Write;

use loomed_core::{builder, AuthorizationRef, ParticipantId};
use loomed_crypto::sign;
use loomed_store::Vault;
use rand::RngCore;

/// Runs the `loomed init` command.
///
/// Prompts the user for a participant ID and passphrase, derives a
/// deterministic ed25519 keypair from the passphrase and a random salt,
/// initialises the encrypted vault on disk, and writes the genesis commit.
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

    // Step 2 — Get and confirm passphrase
    let passphrase = prompt_passphrase()?;
    let passphrase_bytes = passphrase.as_bytes();

    // Step 3 — Generate a random Argon2id salt.
    //
    // The salt is generated once per vault and stored in plaintext in
    // vault.toml. It is not secret — its purpose is to ensure the same
    // passphrase produces a different keypair and encryption key for every
    // vault. The salt must be generated before the keypair because the
    // keypair is derived from passphrase + salt. See spec §5.
    let mut salt_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt_bytes);
    let argon2_salt = hex::encode(salt_bytes);

    // Step 4 — Derive a deterministic ed25519 keypair from passphrase + salt.
    //
    // Using derive_keypair ensures the same passphrase always produces the
    // same keypair. The public key stored in vault.toml matches the key
    // used to sign all commits, so `loomed verify --chain` passes in Phase 1.
    //
    // TODO: In Phase 4, the keypair will be replaced by a persisted encrypted
    // key file bound to the identity provider. The call site interface does
    // not change — only the source of the key changes. See spec §4 and
    // coding standards §0.1.
    println!("deriving keypair...");
    let keypair = loomed_crypto::derive_keypair(passphrase_bytes, &salt_bytes)?;
    let public_key = keypair.public_key_hex();

    // Step 5 — Initialise the vault directory structure on disk
    let current_dir = env::current_dir()?;
    println!("initialising vault at {}/.loomed/", current_dir.display());

    let vault = Vault::init(
        &current_dir,
        &patient_id,
        &public_key,
        &argon2_salt,
    )?;

    // Step 6 — Write the genesis commit.
    //
    // The genesis commit records that this vault was created with this
    // keypair. It is the first commit in every vault — previous_hash is
    // None. All subsequent commits chain from this one. See spec §6.1.
    println!("writing genesis commit...");

    let genesis_payload = serde_json::json!({
        "public_key": public_key,
        "idp_type": "passphrase",
        "protocol_version": "0.2"
    });

    let pending = builder::prepare(
        patient_id.clone(),
        patient_id.clone(),
        patient_id.clone(),
        loomed_core::RecordType::KeyRotation,
        "vault initialised".to_string(),
        genesis_payload,
        None, // genesis — no previous commit
        AuthorizationRef::SelfAuthored,
    )?;

    let signature = sign(&keypair, &pending.canonical_bytes);
    let genesis_commit = pending.finalise(signature)?;
    let genesis_id = genesis_commit.commit_id.clone();

    vault.write_commit(&genesis_commit, passphrase_bytes)?;

    // Step 7 — Print summary
    println!();
    println!("vault initialised successfully.");
    println!();
    println!("  participant ID : {}", patient_id);
    println!("  public key     : {}", public_key);
    println!("  genesis commit : {}", genesis_id);
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
fn prompt_passphrase() -> Result<String, Box<dyn std::error::Error>> {
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

        return Ok(passphrase);
    }
}