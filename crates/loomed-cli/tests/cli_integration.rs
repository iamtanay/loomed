//! # loomed-cli Integration Tests
//!
//! ## Purpose
//!
//! This file tests every LooMed CLI command as a black box: spawning the
//! compiled `loomed` binary with arguments and asserting on stdout, stderr,
//! and exit codes. No business logic is tested here — that belongs in
//! loomed-core and loomed-store unit tests. This layer verifies that the
//! CLI correctly wires arguments to commands and produces correct output.
//!
//! ## Design Rules
//!
//! - Every test uses an isolated `tempfile::TempDir` as its working directory.
//!   No test reads from or writes to the real `.loomed/` vault. Per coding
//!   standards §6.2.
//!
//! - Commands that require a passphrase (`init`, `commit`, `log`, `show`,
//!   `verify`) receive credentials via the `LOOMED_PASSPHRASE` environment
//!   variable. This is the same convention used by OpenSSL, GPG, and SSH for
//!   non-interactive invocation. The production `loomed` binary behaves
//!   identically when `LOOMED_PASSPHRASE` is not set.
//!
//! - `loomed init` receives the participant ID via stdin (one line). The
//!   passphrase is supplied via `LOOMED_PASSPHRASE` — the confirmation prompt
//!   is skipped automatically in non-interactive mode.
//!
//! - Tests are ordered from simplest (no vault) to most complex (full
//!   lifecycle). Each test is independent — no shared mutable state.
//!
//! - Test names state the protocol rule or behaviour being verified, not
//!   implementation details. See coding standards §6.1.
//!
//! See spec §20 and coding standards §6.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

/// A short valid participant ID used across all tests.
///
/// The format must match the LooMed participant ID grammar:
/// prefix (LMP-, LMD-, LMI-, LMV-, LMG-) + 10 chars + dash + 2 chars.
const TEST_PATIENT_ID: &str = "LMP-7XKQR2MNVB-F4";

/// The passphrase used by all tests that initialise a vault.
///
/// Supplied via `LOOMED_PASSPHRASE` — never via stdin for passphrase prompts.
/// Must be at least 8 characters per coding standards §0.6.
const TEST_PASSPHRASE: &str = "testpass99";

/// Runs `loomed init` in `dir` with standard test credentials.
///
/// The participant ID is supplied via stdin (one line).
/// The passphrase is supplied via `LOOMED_PASSPHRASE` — no terminal required.
///
/// Returns the assert_cmd output for further assertion, or panics if
/// the command cannot be spawned.
///
/// Used as a precondition helper in tests that require an initialised vault.
fn run_init(dir: &TempDir) -> assert_cmd::assert::Assert {
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .write_stdin(format!("{}\n", TEST_PATIENT_ID))
        .arg("init")
        .assert()
}

/// Initialises a vault in `dir` and panics if init fails.
///
/// Use this when init is a precondition for the test under examination,
/// not the behaviour being tested. The init output is not asserted here —
/// only success is checked.
fn require_vault(dir: &TempDir) {
    run_init(dir).success();
}

/// Reads the HEAD file from a vault directory and returns the commit_id.
///
/// Used by tests that need to reference a committed commit_id without
/// running `loomed log`.
///
/// # Panics
///
/// Panics if the HEAD file does not exist or cannot be read.
fn read_head(dir: &TempDir) -> String {
    let head_path = dir.path().join(".loomed").join("HEAD");
    fs::read_to_string(head_path)
        .expect("HEAD file should exist after at least one commit")
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------------
// `loomed init` tests
// ---------------------------------------------------------------------------

/// Spec §5: `loomed init` in a directory with no vault must succeed and
/// create the `.loomed/` directory structure.
#[test]
fn init_creates_vault_structure() {
    let dir = TempDir::new().unwrap();

    run_init(&dir)
        .success()
        .stdout(predicate::str::contains("vault initialised successfully."));

    assert!(dir.path().join(".loomed").exists(), ".loomed/ must exist");
    assert!(
        dir.path().join(".loomed").join("vault.toml").exists(),
        "vault.toml must exist"
    );
    assert!(
        dir.path().join(".loomed").join("commits").exists(),
        "commits/ must exist"
    );
}

/// Spec §5: `loomed init` must print the participant ID and public key
/// in the success output so the user can confirm their vault identity.
#[test]
fn init_output_contains_participant_id_and_public_key() {
    let dir = TempDir::new().unwrap();

    run_init(&dir)
        .success()
        .stdout(predicate::str::contains(TEST_PATIENT_ID))
        .stdout(predicate::str::contains("ed25519:"))
        .stdout(predicate::str::contains("genesis commit"))
        .stdout(predicate::str::contains("idp type       : passphrase"));
}

/// Spec §5: Running `loomed init` a second time in the same directory
/// must fail with a clear error — the vault already exists.
#[test]
fn init_fails_if_vault_already_exists() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    run_init(&dir)
        .failure()
        .stderr(predicate::str::contains("error:"));
}

// ---------------------------------------------------------------------------
// `loomed status` tests
// ---------------------------------------------------------------------------

/// Coding standards §0.6: `loomed status` with no vault initialised must
/// fail fast with a clear error — no passphrase should ever be requested.
#[test]
fn status_fails_with_no_vault() {
    let dir = TempDir::new().unwrap();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

/// Spec §5: `loomed status` on an initialised vault must display the
/// patient ID, public key, and protocol version without requiring a passphrase.
#[test]
fn status_shows_vault_metadata_without_passphrase() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains(TEST_PATIENT_ID))
        .stdout(predicate::str::contains("ed25519:"))
        .stdout(predicate::str::contains("passphrase"));
}

/// Spec §6: `loomed status` immediately after `loomed init` must show
/// that HEAD points to the genesis commit.
#[test]
fn status_shows_genesis_head_after_init() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("sha256:"))
        // Nothing should be staged immediately after init
        .stdout(predicate::str::contains("nothing staged"));
}

/// Spec §6: `loomed status` after a `loomed add` must show the staged
/// record type and message. No passphrase must be requested.
#[test]
fn status_shows_staged_record_after_add() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "lab_result", "-m", "fasting blood glucose"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("lab_result"))
        .stdout(predicate::str::contains("fasting blood glucose"));
}

// ---------------------------------------------------------------------------
// `loomed add` tests
// ---------------------------------------------------------------------------

/// Spec §9: `loomed add` with a valid record type must succeed and confirm
/// the staged type and message on stdout.
#[test]
fn add_valid_record_type_succeeds() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "lab_result", "-m", "HbA1c result"])
        .assert()
        .success()
        .stdout(predicate::str::contains("staged:"))
        .stdout(predicate::str::contains("lab_result"))
        .stdout(predicate::str::contains("HbA1c result"));
}

/// Spec §9: `loomed add` must accept all six record types defined in spec §9.
#[test]
fn add_accepts_all_six_record_types() {
    let record_types = [
        "lab_result",
        "prescription",
        "radiology_report",
        "vaccination",
        "diagnosis",
        "procedure",
    ];

    for record_type in &record_types {
        let dir = TempDir::new().unwrap();
        require_vault(&dir);

        Command::cargo_bin("loomed")
            .unwrap()
            .current_dir(dir.path())
            .args(["add", "--type", record_type, "-m", "test message"])
            .assert()
            .success()
            .stdout(predicate::str::contains(*record_type));
    }
}

/// Coding standards §0.6: `loomed add` with an unknown record type must
/// fail before opening the vault or prompting for any credentials.
/// The error must name the invalid type and list valid values.
#[test]
fn add_unknown_record_type_fails_with_clear_error() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "xray_scan", "-m", "test"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("xray_scan"))
        .stderr(predicate::str::contains("lab_result")); // lists valid types
}

/// Coding standards §0.6: `loomed add` with an unknown type must fail
/// even when no vault has been initialised — type validation runs first.
#[test]
fn add_unknown_record_type_fails_before_vault_check() {
    let dir = TempDir::new().unwrap();
    // Intentionally no vault here — type check must run first

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "not_a_type", "-m", "test"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not_a_type"));
}

/// Spec §6: Running `loomed add` twice must overwrite the first staged
/// record. The second record must be the one visible in `loomed status`.
#[test]
fn add_overwrites_previous_staged_record() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "lab_result", "-m", "first record"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "diagnosis", "-m", "second record"])
        .assert()
        .success();

    // Status must show the second record, not the first
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("diagnosis"))
        .stdout(predicate::str::contains("second record"))
        .stdout(predicate::str::contains("first record").not());
}

/// Coding standards §0.6: `loomed add` with no vault must fail with a
/// clear error about the vault not being initialised.
#[test]
fn add_fails_with_no_vault() {
    let dir = TempDir::new().unwrap();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "lab_result", "-m", "test"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

// ---------------------------------------------------------------------------
// `loomed commit` tests
// ---------------------------------------------------------------------------

/// Spec §6: `loomed commit` with a staged record and correct passphrase
/// must succeed and print the commit_id.
#[test]
fn commit_succeeds_with_staged_record_and_correct_passphrase() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "lab_result", "-m", "fasting blood glucose"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("commit")
        .assert()
        .success()
        .stdout(predicate::str::contains("committed: sha256:"))
        .stdout(predicate::str::contains("lab_result"))
        .stdout(predicate::str::contains("fasting blood glucose"));
}

/// Coding standards §0.6: `loomed commit` with nothing staged must fail
/// before prompting for a passphrase.
///
/// This test verifies the fail-fast rule: no credentials are requested
/// when there is no work to do.
#[test]
fn commit_fails_with_nothing_staged() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // No LOOMED_PASSPHRASE set — if commit incorrectly prompts for the
    // passphrase before checking staging, the process will block on /dev/tty.
    // The fail-fast check must run before any passphrase read.
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("commit")
        .assert()
        .failure()
        .stderr(predicate::str::contains("nothing staged"));
}

/// Spec §6: `loomed commit` must clear the staging area after a successful
/// commit. `loomed status` must show "nothing staged" afterwards.
#[test]
fn commit_clears_staging_area_on_success() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "vaccination", "-m", "influenza 2025"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("commit")
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("nothing staged"));
}

/// Spec §6, §7: A commit written with the wrong passphrase is encrypted
/// with a key derived from that wrong passphrase. It cannot be decrypted
/// or verified with the correct passphrase. `loomed verify --chain` must
/// fail on such a commit.
///
/// Note: `loomed commit` itself does not validate the passphrase at write
/// time — it encrypts with whatever key it derives. The protocol detects
/// the wrong passphrase at read time (decrypt fails) and at verify time
/// (signature fails against the vault public key). This is by design:
/// the vault's public key in vault.toml is the ground truth.
#[test]
fn commit_with_wrong_passphrase_produces_unverifiable_commit() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "diagnosis", "-m", "type 2 diabetes"])
        .assert()
        .success();

    // Commit with the wrong passphrase — this succeeds at write time but
    // produces a commit encrypted with the wrong key and signed with the
    // wrong keypair. The staging area is cleared regardless.
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", "wrongpassphrase")
        .arg("commit")
        .assert()
        .success();

    // verify --chain with the correct passphrase must now fail — it cannot
    // decrypt the commit written with the wrong passphrase.
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["verify", "--chain"])
        .assert()
        .failure();
}

/// Spec §6: After a commit, `loomed status` HEAD must be updated to point
/// to the new commit, not the genesis commit.
#[test]
fn commit_advances_head() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // Capture genesis commit ID from HEAD before any user commit
    let genesis_head = read_head(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "lab_result", "-m", "TSH thyroid"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("commit")
        .assert()
        .success();

    let new_head = read_head(&dir);

    // HEAD must have advanced to a new commit_id
    assert_ne!(genesis_head, new_head, "HEAD must advance after a commit");
    assert!(
        new_head.starts_with("sha256:"),
        "HEAD must be a valid commit_id"
    );
}

// ---------------------------------------------------------------------------
// `loomed log` tests
// ---------------------------------------------------------------------------

/// Spec §6: `loomed log` on a freshly initialised vault must show the
/// genesis commit written during `loomed init`.
#[test]
fn log_shows_genesis_commit_after_init() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("log")
        .assert()
        .success()
        .stdout(predicate::str::contains("commit  sha256:"))
        .stdout(predicate::str::contains("vault initialised"))
        .stdout(predicate::str::contains("1 commit(s) total."));
}

/// Spec §6: `loomed log` must list commits in reverse chronological
/// order — most recent first.
#[test]
fn log_shows_commits_newest_first() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // Add and commit a lab result
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "lab_result", "-m", "first lab"])
        .assert()
        .success();
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("commit")
        .assert()
        .success();

    // Add and commit a prescription
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "prescription", "-m", "metformin 500mg"])
        .assert()
        .success();
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("commit")
        .assert()
        .success();

    let output = Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("log")
        .assert()
        .success()
        .stdout(predicate::str::contains("3 commit(s) total.")) // genesis + 2
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8_lossy(&output);

    // "metformin" must appear before "first lab" in the output (newest first)
    let metformin_pos = output_str.find("metformin").expect("metformin must appear in log");
    let first_lab_pos = output_str.find("first lab").expect("first lab must appear in log");
    assert!(
        metformin_pos < first_lab_pos,
        "newest commit must appear first in `loomed log` output"
    );
}

/// Coding standards §0.6: `loomed log` with no vault must fail before
/// prompting for a passphrase.
#[test]
fn log_fails_with_no_vault() {
    let dir = TempDir::new().unwrap();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("log")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

// ---------------------------------------------------------------------------
// `loomed show` tests
// ---------------------------------------------------------------------------

/// Spec §6.2: `loomed show <commit_id>` must display all commit fields
/// for the given commit.
#[test]
fn show_displays_all_commit_fields() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "diagnosis", "-m", "type 2 diabetes"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("commit")
        .assert()
        .success();

    let commit_id = read_head(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["show", &commit_id])
        .assert()
        .success()
        .stdout(predicate::str::contains(&commit_id))
        .stdout(predicate::str::contains("diagnosis"))
        .stdout(predicate::str::contains("type 2 diabetes"))
        .stdout(predicate::str::contains(TEST_PATIENT_ID))
        .stdout(predicate::str::contains("signature"))
        .stdout(predicate::str::contains("payload"));
}

/// Coding standards §0.6: `loomed show` with a malformed commit_id (missing
/// sha256: prefix) must fail before opening the vault or prompting for
/// the passphrase.
#[test]
fn show_rejects_malformed_commit_id_before_passphrase() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // No LOOMED_PASSPHRASE set — if show incorrectly reads the passphrase
    // before validating the commit_id, it will block on /dev/tty.
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["show", "not-a-valid-id"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("sha256:"));
}

/// Spec §6.2: `loomed show` for a commit_id that does not exist on disk
/// must fail with a clear error.
#[test]
fn show_fails_for_nonexistent_commit_id() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    let nonexistent = "sha256:000000000000000000000000000000000000000000000000000000000000dead";

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["show", nonexistent])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

/// Spec §6.2: `loomed show` for the genesis commit must display
/// "none (genesis)" for the previous_hash field.
#[test]
fn show_genesis_commit_displays_no_previous_hash() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // The genesis commit is at HEAD right after init
    let genesis_id = read_head(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["show", &genesis_id])
        .assert()
        .success()
        .stdout(predicate::str::contains("none (genesis)"));
}

// ---------------------------------------------------------------------------
// `loomed verify` tests
// ---------------------------------------------------------------------------

/// Spec §7: `loomed verify --chain` on a freshly initialised vault must
/// pass — the genesis commit must always verify cleanly.
#[test]
fn verify_chain_passes_on_fresh_vault() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["verify", "--chain"])
        .assert()
        .success()
        .stdout(predicate::str::contains("chain ok"));
}

/// Spec §7: `loomed verify --chain` must pass after multiple commits,
/// confirming the full chain of hash links is intact.
#[test]
fn verify_chain_passes_after_multiple_commits() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // Commit 1
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "lab_result", "-m", "fasting glucose"])
        .assert()
        .success();
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("commit")
        .assert()
        .success();

    // Commit 2
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "prescription", "-m", "metformin 500mg"])
        .assert()
        .success();
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("commit")
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["verify", "--chain"])
        .assert()
        .success()
        .stdout(predicate::str::contains("chain ok"))
        .stdout(predicate::str::contains("3 commit(s) verified")); // genesis + 2
}

/// Spec §7: `loomed verify --chain` must fail and exit with code 1 when
/// a commit file has been tampered with.
///
/// This is the most important security test in Session 5: tampering must
/// always be detected.
#[test]
fn verify_chain_fails_on_tampered_commit() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "diagnosis", "-m", "hypertension"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("commit")
        .assert()
        .success();

    // Tamper with the most recently committed .lmc file by corrupting its bytes
    let commits_dir = dir.path().join(".loomed").join("commits");
    let lmc_files: Vec<_> = fs::read_dir(&commits_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".lmc"))
        .collect();

    // Pick the first .lmc file and overwrite it with garbage
    assert!(!lmc_files.is_empty(), "at least one .lmc file must exist");
    let target = lmc_files[0].path();
    fs::write(&target, b"TAMPERED_GARBAGE_BYTES_THAT_CANNOT_DECRYPT").unwrap();

    // verify --chain must detect the tampering and exit with code 1
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["verify", "--chain"])
        .assert()
        .failure(); // exit code 1
}

/// Spec §7: `loomed verify <commit_id>` must succeed for a valid commit.
#[test]
fn verify_single_commit_passes_for_valid_commit() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "vaccination", "-m", "COVID-19 booster"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("commit")
        .assert()
        .success();

    let commit_id = read_head(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["verify", &commit_id])
        .assert()
        .success()
        .stdout(predicate::str::contains("ok — commit verified."))
        .stdout(predicate::str::contains("✓ valid")); // hash and sig both valid
}

/// Spec §7: `loomed verify <commit_id>` must exit with code 1 for a
/// tampered commit, and must print a clear failure message.
#[test]
fn verify_single_commit_fails_on_tampered_commit() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "lab_result", "-m", "CBC panel"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("commit")
        .assert()
        .success();

    let commit_id = read_head(&dir);

    // Tamper with the .lmc file for this specific commit
    let hash_part = commit_id.trim_start_matches("sha256:");
    let lmc_path = dir
        .path()
        .join(".loomed")
        .join("commits")
        .join(format!("{}.lmc", hash_part));

    fs::write(&lmc_path, b"TAMPERED_GARBAGE").unwrap();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["verify", &commit_id])
        .assert()
        .failure(); // exit code 1
}

/// Coding standards §0.6: `loomed verify <commit_id>` with a missing
/// sha256: prefix must fail before prompting for a passphrase.
#[test]
fn verify_single_rejects_malformed_commit_id_before_passphrase() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // No LOOMED_PASSPHRASE set — if verify incorrectly reads the passphrase
    // before validating the commit_id, it will block on /dev/tty.
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["verify", "not-a-sha256-id"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("sha256:"));
}

/// Spec §7: `loomed verify` with neither <commit_id> nor --chain must
/// print usage guidance and exit with code 0.
#[test]
fn verify_with_no_args_prints_usage() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("verify")
        .assert()
        .success()
        .stdout(predicate::str::contains("usage:"));
}

/// Spec §7: `loomed verify --chain` and `loomed verify <commit_id>` must
/// not be usable together — this is a user error that must be caught.
#[test]
fn verify_chain_and_commit_id_together_is_rejected() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    let some_id = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["verify", some_id, "--chain"])
        .assert()
        .failure();
}

// ---------------------------------------------------------------------------
// Full end-to-end lifecycle test
// ---------------------------------------------------------------------------

/// Spec §6, §7: Full protocol lifecycle — init, add, commit twice, log,
/// show, and verify --chain — must all complete without error.
///
/// This is the integration test equivalent of the manual end-to-end
/// verification described in the Session 4 summary. It must pass cleanly
/// after every session.
#[test]
fn full_lifecycle_init_add_commit_log_show_verify() {
    let dir = TempDir::new().unwrap();

    // 1. Init
    run_init(&dir)
        .success()
        .stdout(predicate::str::contains("vault initialised successfully."));

    // 2. Status — nothing staged, genesis commit at HEAD
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains(TEST_PATIENT_ID))
        .stdout(predicate::str::contains("nothing staged"));

    // 3. Add first record
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "lab_result", "-m", "fasting blood glucose"])
        .assert()
        .success();

    // 4. Status — lab_result staged
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("lab_result"))
        .stdout(predicate::str::contains("fasting blood glucose"));

    // 5. Commit first record
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("commit")
        .assert()
        .success()
        .stdout(predicate::str::contains("committed: sha256:"));

    // 6. Status — nothing staged, HEAD advanced
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("nothing staged"));

    // 7. Add second record
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "prescription", "-m", "metformin 500mg"])
        .assert()
        .success();

    // 8. Commit second record
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("commit")
        .assert()
        .success();

    // 9. Log — must show 3 commits (genesis + 2 user commits)
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("log")
        .assert()
        .success()
        .stdout(predicate::str::contains("3 commit(s) total."))
        .stdout(predicate::str::contains("metformin"))
        .stdout(predicate::str::contains("fasting blood glucose"));

    // 10. Show the HEAD commit (most recent)
    let head = read_head(&dir);
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["show", &head])
        .assert()
        .success()
        .stdout(predicate::str::contains(&head))
        .stdout(predicate::str::contains("prescription"));

    // 11. Verify --chain — must pass cleanly
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["verify", "--chain"])
        .assert()
        .success()
        .stdout(predicate::str::contains("chain ok"))
        .stdout(predicate::str::contains("3 commit(s) verified"));
}