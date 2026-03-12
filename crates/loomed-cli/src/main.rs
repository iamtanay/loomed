//! # loomed-cli
//!
//! The LooMed command-line interface.
//!
//! This binary is a thin wrapper over `loomed-core` and `loomed-store`.
//! It contains no business logic. It parses arguments, calls the appropriate
//! library functions, and prints results to the terminal.
//!
//! ## Available Commands (Phase 1)
//! - `loomed init`           — Initialise a new patient vault
//! - `loomed add`            — Stage a record for commit
//! - `loomed commit`         — Sign and commit the staged record
//! - `loomed log`            — Display the full commit history
//! - `loomed verify --chain` — Verify the full hash chain
//!
//! See the LooMed Protocol Specification for the full CLI reference (spec §20).

use clap::{Parser, Subcommand};

mod commands;

/// The LooMed protocol command-line interface.
#[derive(Parser)]
#[command(
    name = "loomed",
    about = "LooMed — patient-owned medical records protocol",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// All available LooMed CLI commands.
#[derive(Subcommand)]
enum Command {
    /// Initialise a new patient vault in the current directory.
    ///
    /// Creates a .loomed/ directory, generates an ed25519 keypair,
    /// encrypts the vault with a passphrase, and writes the genesis commit.
    Init,

    /// Stage a medical record for the next commit.
    ///
    /// Writes the record type and message to .loomed/staged.json.
    /// Running add twice overwrites the previous staged record.
    Add {
        /// The type of medical record to stage.
        ///
        /// Valid values: lab_result, prescription, radiology_report,
        /// vaccination, diagnosis, procedure
        #[arg(long, short = 't')]
        r#type: String,

        /// A short description of this record (becomes the commit message).
        #[arg(long, short = 'm')]
        message: String,
    },

    /// Sign and commit the currently staged record.
    ///
    /// Reads .loomed/staged.json, builds a full commit, signs it with
    /// the vault keypair, encrypts it, and writes a .lmc file to disk.
    Commit,

    /// Display the full commit history from HEAD to genesis.
    Log,

    /// Verify the integrity of the vault.
    Verify {
        /// Verify the full hash chain from genesis to HEAD.
        #[arg(long)]
        chain: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Init => commands::init::run(),
        Command::Add { r#type, message } => commands::add::run(&r#type, &message),
        Command::Commit => commands::commit::run(),
        Command::Log => commands::log::run(),
        Command::Verify { chain } => commands::verify::run(chain),
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}