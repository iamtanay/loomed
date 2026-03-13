//! # `loomed show`
//!
//! Inspects and displays a specific commit from the vault by its commit_id.
//!
//! ## What this command does
//! 1. Opens the vault in the current directory
//! 2. Validates that the provided commit_id has the correct sha256: prefix
//! 3. Prompts for the vault passphrase
//! 4. Reads and decrypts the specific .lmc file for this commit_id
//! 5. Pretty-prints every field of the commit to the terminal
//!
//! ## What it does NOT do
//! - Verify signatures or hashes (use `loomed verify <commit_id>` for that)
//! - Modify any data
//! - Traverse the chain — it reads exactly one commit by ID

use std::env;

use loomed_store::Vault;
use loomed_core::CommitHash;

/// Runs the `loomed show <commit_id>` command.
///
/// # Arguments
///
/// * `commit_id` — The full commit_id string from the CLI argument, including
///   the `sha256:` prefix.
///
/// # Errors
///
/// Returns a boxed error if the vault is not initialised, the commit_id
/// is not found on disk, the passphrase is incorrect, or any I/O fails.
///
/// See spec §6.2 and §20.
pub fn run(commit_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;

    // Step 1 — Validate the commit_id prefix before opening vault or
    // prompting for a passphrase. Fail fast with a clear error if the
    // user passed a malformed ID. Per coding standards §0.6.
    if !commit_id.starts_with("sha256:") {
        return Err(format!(
            "invalid commit_id: \"{}\"\ncommit IDs must begin with \"sha256:\"",
            commit_id
        )
        .into());
    }

    // Step 2 — Open the vault. Fails with a clear error if not initialised.
    let vault = Vault::open(&current_dir)?;

    // Step 3 — Prompt for passphrase only after all preconditions pass.
    // Per coding standards §0.6: credentials are never requested before
    // we know there is work to do.
    let passphrase = rpassword::prompt_password("vault passphrase: ")?;
    let passphrase_bytes = passphrase.as_bytes();

    // Step 4 — Read and decrypt the specific commit file.
    let hash = CommitHash(commit_id.to_string());
    let commit = vault.read_commit(&hash, passphrase_bytes)?;

    // Step 5 — Pretty-print all commit fields.
    //
    // Display format is intentionally verbose — `loomed show` is an
    // inspection tool. Every field defined in spec §6.2 is shown.
    println!();
    println!("commit      {}", commit.commit_id.as_str());
    println!(
        "type        {}",
        serde_json::to_string(&commit.record_type)
            .unwrap_or_default()
            .trim_matches('"')
    );
    println!("date        {}", commit.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("message     {}", commit.message);
    println!();
    println!("patient     {}", commit.patient_id.as_str());
    println!("author      {}", commit.author_id.as_str());
    println!("authored by {}", commit.authored_by.as_str());
    println!(
        "previous    {}",
        commit
            .previous_hash
            .as_ref()
            .map(|h| h.as_str())
            .unwrap_or("none (genesis)")
    );
    println!("content     {}", commit.content_hash.as_str());
    println!("signature   {}", commit.signature);
    println!("protocol    {}", commit.protocol_version);

    // Authorization context — see spec §10
    let auth_str = match &commit.authorization_ref {
        loomed_core::AuthorizationRef::SelfAuthored => "self_authored".to_string(),
        loomed_core::AuthorizationRef::ConsentToken { token_id } => {
            format!("consent_token({})", token_id.as_str())
        }
    };
    println!("auth        {}", auth_str);

    // Sync metadata — see spec §8
    println!();
    println!("sync");
    println!(
        "  offline   {}",
        commit.sync_metadata.created_offline
    );
    println!(
        "  synced_at {}",
        commit
            .sync_metadata
            .synced_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "not yet synced".to_string())
    );

    // Payload — pretty-printed JSON, indented under a header
    println!();
    println!("payload");
    let pretty = serde_json::to_string_pretty(&commit.payload)
        .unwrap_or_else(|_| "<payload could not be displayed>".to_string());
    for line in pretty.lines() {
        println!("  {}", line);
    }
    println!();

    Ok(())
}