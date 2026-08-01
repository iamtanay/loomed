//! # loomed-cli
//!
//! The LooMed command-line interface.
//!
//! This binary is a thin wrapper over `loomed-core` and `loomed-store`.
//! It contains no business logic. It parses arguments, calls the appropriate
//! library functions, and prints results to the terminal.
//!
//! ## Available Commands (Phase 1 + Phase 2)
//! - `loomed init`                         — Initialise a new patient vault
//! - `loomed add`                          — Stage a record for commit (empty payload)
//! - `loomed add -i`                       — Stage a record with interactive payload prompts
//! - `loomed commit`                       — Sign and commit the staged record
//! - `loomed commit --token <token_id>`    — Commit under a consent token instead of self-authoring
//! - `loomed log`                          — Display the full commit history
//! - `loomed show <commit_id>`             — Inspect a specific commit by ID
//! - `loomed status`                       — Show current vault state and staged record
//! - `loomed verify <commit_id>`           — Verify a single commit's integrity
//! - `loomed verify --chain`               — Verify the full hash chain
//! - `loomed remote set <path>`            — Configure the sync remote
//! - `loomed sync`                         — Push commits to the remote
//! - `loomed sync --status`                — Show which commits are pending sync
//! - `loomed sync --pull`                  — Fetch commits from the remote
//! - `loomed sync --resolve`               — Resolve forks via Sync Rebase
//! - `loomed sync --to <path>`             — Push/pull to/from a specific remote
//! - `loomed share <participant_id>`       — Issue a consent token to an institution
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
    /// Without -i: stages the record type and message with an empty payload.
    /// This is the default scriptable path — no prompts, no interaction.
    ///
    /// With -i: prompts for all required and optional payload fields for
    /// the given record type per spec §9. Required fields loop until valid
    /// input is provided. Optional fields accept an empty Enter to skip.
    ///
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

        /// Enable interactive payload prompts for this record type.
        ///
        /// Prompts for all required and optional fields defined in spec §9.
        /// Without this flag, the record is staged with an empty payload.
        #[arg(short = 'i', long = "interactive", default_value_t = false)]
        interactive: bool,
    },

    /// Sign and commit the currently staged record.
    ///
    /// Reads .loomed/staged.json, builds a full commit, signs it with
    /// the vault keypair, encrypts it, and writes a .lmc file to disk.
    ///
    /// With --token <token_id>: the commit is authorized by a
    /// patient-issued consent token instead of being self-authored. The
    /// token must be found in the chain, unexpired, write-scoped to this
    /// record type, and not already used (spec §10).
    Commit {
        /// Authorize this commit with a consent token issued via
        /// `loomed share`, instead of self-authoring it.
        #[arg(long)]
        token: Option<String>,
    },

    /// Display the full commit history from HEAD to genesis.
    Log,

    /// Inspect a specific commit by its commit_id.
    ///
    /// Displays every field of the commit in a readable format.
    /// Use `loomed verify <commit_id>` to check its cryptographic integrity.
    Show {
        /// The commit_id to inspect, including the sha256: prefix.
        ///
        /// Example: loomed show sha256:7f8e21a4b3c2d1e0f9a8b7c6d5e4f3a2...
        commit_id: String,
    },

    /// Show the current vault state and staged record.
    ///
    /// Displays the vault owner, public key, HEAD commit, and any
    /// record currently staged for commit. No passphrase is required —
    /// all data shown is stored in plaintext.
    Status,

    /// Verify the cryptographic integrity of the vault.
    ///
    /// Two modes:
    ///   loomed verify <commit_id>  — verify a single commit by ID
    ///   loomed verify --chain      — verify the full hash chain from genesis
    Verify {
        /// The commit_id of a single commit to verify.
        ///
        /// Mutually exclusive with --chain.
        /// Example: loomed verify sha256:7f8e21a4b3c2d1e0f9a8b7c6d5e4f3a2...
        commit_id: Option<String>,

        /// Verify the full hash chain from genesis to HEAD.
        ///
        /// Mutually exclusive with <commit_id>.
        #[arg(long)]
        chain: bool,
    },

    /// Configure the sync remote for this vault.
    ///
    /// `loomed remote set <path>` stores the path in vault.toml.
    /// Future `loomed sync` invocations use this path as the default remote.
    Remote {
        #[command(subcommand)]
        subcommand: RemoteSubcommand,
    },

    /// Sync committed records to the remote vault.
    ///
    /// Without flags: pushes all commits absent from the remote and
    /// updates the remote HEAD. No passphrase required.
    ///
    /// With --status: shows which commits are pending without pushing.
    ///
    /// With --pull: fetches all commits from the remote that are absent locally
    /// and updates the local HEAD.
    ///
    /// With --resolve: detects and resolves forks in the local commit chain via
    /// Sync Rebase (spec §8.3). Requires the vault passphrase.
    ///
    /// With --to <path>: overrides the configured remote for push/status/pull modes.
    ///
    /// Example: loomed sync --to /backup/loomed
    Sync {
        /// Show pending commits without pushing.
        #[arg(long)]
        status: bool,

        /// Fetch commits from the remote.
        #[arg(long)]
        pull: bool,

        /// Resolve forks via Sync Rebase.
        ///
        /// Does not require a configured remote. Requires the vault passphrase.
        #[arg(long)]
        resolve: bool,

        /// Override the configured remote for this invocation.
        ///
        /// Example: loomed sync --to /backup/loomed
        #[arg(long)]
        to: Option<String>,
    },

    /// Issue a consent token granting an institution scoped, time-bound
    /// access to the patient's vault.
    ///
    /// The token is signed by the patient and written as a `consent_token`
    /// commit for auditability. There is no delivery channel in this
    /// phase — the printed token must be handed to the institution
    /// out of band.
    ///
    /// Example: loomed share LMI-APL-2MVZK9QXBT-08 --scope full_record --duration 4 --purpose claim_verification
    Share {
        /// The institution's participant ID.
        participant_id: String,

        /// The scope of access to grant.
        ///
        /// Valid values: full_record, record_type:<type>, commit:<commit_id>
        #[arg(long)]
        scope: String,

        /// How many hours from now the token remains valid.
        #[arg(long)]
        duration: i64,

        /// A short statement of why access was requested.
        #[arg(long)]
        purpose: String,

        /// Whether this token grants read or write access.
        ///
        /// Valid values: read, write. Defaults to read.
        #[arg(long, default_value = "read")]
        access_type: String,
    },
}

/// Subcommands for `loomed remote`.
#[derive(clap::Subcommand)]
enum RemoteSubcommand {
    /// Set the sync remote path for this vault.
    ///
    /// Writes the path to vault.toml. Run `loomed sync` afterwards to push.
    ///
    /// Example: loomed remote set /backup/loomed
    Set {
        /// The filesystem path to use as the sync remote.
        path: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Init => commands::init::run(),
        Command::Add { r#type, message, interactive } => {
            commands::add::run(&r#type, &message, interactive)
        }
        Command::Commit { token } => commands::commit::run(token.as_deref()),
        Command::Log => commands::log::run(),
        Command::Show { commit_id } => commands::show::run(&commit_id),
        Command::Status => commands::status::run(),
        Command::Verify { commit_id, chain } => {
            commands::verify::run(commit_id.as_deref(), chain)
        }
        Command::Remote {
            subcommand: RemoteSubcommand::Set { path },
        } => commands::remote::run(&path),
        Command::Sync { status, pull, resolve, to } => {
            commands::sync_cmd::run(status, pull, resolve, to.as_deref())
        }
        Command::Share {
            participant_id,
            scope,
            duration,
            purpose,
            access_type,
        } => commands::share::run(&participant_id, &scope, duration, &purpose, &access_type),
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}