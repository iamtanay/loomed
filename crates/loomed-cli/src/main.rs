//! # loomed-cli
//!
//! The LooMed command-line interface.
//!
//! This binary is a thin wrapper over `loomed-core` and `loomed-store`.
//! It contains no business logic. It parses arguments, calls the appropriate
//! library functions, and prints results to the terminal.
//!
//! ## Available Commands (Phase 1)
//! - `loomed init` — Initialise a new patient vault in the current directory.
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
    /// and encrypts the vault with a passphrase you provide.
    Init,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Init => commands::init::run(),
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}