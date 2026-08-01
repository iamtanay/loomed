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
//! - `loomed add -i` interactive payload tests feed all required field values
//!   through `write_stdin()`. The stdin sequences exactly match the prompt
//!   order in `crates/loomed-cli/src/commands/prompts.rs`. Optional fields
//!   are skipped by sending an empty line.
//!
//! - Tests are ordered from simplest (no vault) to most complex (full
//!   lifecycle). Each test is independent — no shared mutable state.
//!
//! - Test names state the protocol rule or behaviour being verified, not
//!   implementation details. See coding standards §6.1.
//!
//! ## Test Coverage
//!
//! init (3), status (4), add (5), add -i (7), commit (5), log (3),
//! show (6), verify (8), remote/sync (11), share (8),
//! commit --token (9), full lifecycle (1) — 68 tests total.
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
const TEST_PATIENT_ID: &str = "LMP-7XKQR2MNVB-6A";

/// A valid institution participant ID used as a consent token recipient
/// across `loomed share` tests. Checksum-valid per spec §3.1.
const TEST_INSTITUTION_ID: &str = "LMI-APL-2MVZK9QXBT-08";

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

/// Runs `loomed share` with the given scope and access type, returning the
/// issued token_id parsed from stdout.
///
/// Used as a precondition helper by `loomed commit --token` tests, which
/// need a real, chain-issued token_id to present.
///
/// # Panics
///
/// Panics if `loomed share` fails or its output has no token_id line.
fn issue_token(dir: &TempDir, scope: &str, access_type: &str) -> String {
    let output = Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "share",
            TEST_INSTITUTION_ID,
            "--scope",
            scope,
            "--duration",
            "4",
            "--purpose",
            "test_purpose",
            "--access-type",
            access_type,
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "loomed share must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find(|line| line.contains("token_id") && line.contains("lmt_"))
        .and_then(|line| line.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .expect("share output must contain a token_id line")
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

// ---------------------------------------------------------------------------
// `loomed add -i` interactive payload tests — spec §9
// ---------------------------------------------------------------------------
//
// Each test stages a fully typed record via interactive prompts, feeding the
// required field values through stdin with write_stdin(). Optional fields are
// skipped by sending an empty line.
//
// The stdin sequences are derived directly from the prompt order in
// crates/loomed-cli/src/commands/prompts.rs. Required fields are listed
// with a `*` marker there; optional fields accept an empty Enter.

/// Spec §9.1: `loomed add -i` with type `lab_result` must stage a typed
/// payload containing all required fields and succeed.
#[test]
fn add_interactive_lab_result_stages_typed_payload() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // Prompt order (from prompts::prompt_lab_result):
    //   test_name*, test_code*, value*, unit*, ref_min*, ref_max*,
    //   status*, device_id (opt), notes (opt)
    let stdin = "Fasting Blood Glucose\nFBG\n98.5\nmg/dL\n70\n99\nnormal\n\n\n";

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "lab_result", "-m", "fasting glucose", "-i"])
        .write_stdin(stdin)
        .assert()
        .success()
        .stdout(predicate::str::contains("lab_result"))
        .stdout(predicate::str::contains("fasting glucose"));

    // Status must reflect the staged payload is non-empty
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Fasting Blood Glucose"));
}

/// Spec §9.2: `loomed add -i` with type `prescription` must stage a typed
/// payload containing all required fields and succeed.
#[test]
fn add_interactive_prescription_stages_typed_payload() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // Prompt order (from prompts::prompt_prescription):
    //   drug_name*, drug_code*, dosage*, frequency*, duration_days*,
    //   instructions*, reason*, refills (opt u32), diagnosis_ref (opt)
    let stdin = "Metformin\nMET500\n500mg\ntwice daily\n30\ntake with meals\ntype 2 diabetes\n\n\n";

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "prescription", "-m", "metformin 500mg", "-i"])
        .write_stdin(stdin)
        .assert()
        .success()
        .stdout(predicate::str::contains("prescription"))
        .stdout(predicate::str::contains("metformin 500mg"));

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Metformin"));
}

/// Spec §9.3: `loomed add -i` with type `radiology_report` must stage a typed
/// payload including the mandatory external_ref block and succeed.
///
/// Raw imaging files are never stored in LooMed. The external_ref is
/// required, not optional. See spec §9.3 and §9.7.
#[test]
fn add_interactive_radiology_report_stages_typed_payload() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // Prompt order (from prompts::prompt_radiology_report):
    //   report_id*, modality*, body_part*, findings*, impression*,
    //   radiologist_id*, machine_id (opt),
    //   then external_ref: ref_id*, ref_type*, custodian_id*, description*, retrieval*
    let stdin = concat!(
        "APL-RAD-2026-00421\n",   // report_id
        "MRI\n",                   // modality
        "lumbar spine\n",          // body_part
        "Mild disc bulge at L4-L5\n", // findings
        "Grade 1 spondylolisthesis\n", // impression
        "LMD-APL-9XKZR4WQNB-3F\n",   // radiologist_id
        "\n",                       // machine_id (skip)
        "APL-RAD-2026-00421\n",   // ref_id
        "pacs_imaging\n",          // ref_type
        "LMI-APL-2MVZK9QXBT-C2\n", // custodian_id
        "raw MRI DICOM files\n",   // description
        "contact custodian with ref_id\n", // retrieval
    );

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "radiology_report", "-m", "lumbar spine MRI", "-i"])
        .write_stdin(stdin)
        .assert()
        .success()
        .stdout(predicate::str::contains("radiology_report"))
        .stdout(predicate::str::contains("lumbar spine MRI"));

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("APL-RAD-2026-00421"));
}

/// Spec §9.4: `loomed add -i` with type `vaccination` must stage a typed
/// payload containing all required fields and succeed.
#[test]
fn add_interactive_vaccination_stages_typed_payload() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // Prompt order (from prompts::prompt_vaccination):
    //   vaccine_name*, vaccine_code*, manufacturer*, batch_number*,
    //   dose_number*, total_doses*, site*,
    //   next_dose_due (opt), programme (opt), programme_id (opt)
    let stdin = concat!(
        "Covishield\n",
        "AZ-COV19\n",
        "Serum Institute of India\n",
        "SII-2021-B0041\n",
        "1\n",
        "2\n",
        "left deltoid\n",
        "\n", // next_dose_due (skip)
        "\n", // programme (skip)
        "\n", // programme_id (skip)
    );

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "vaccination", "-m", "COVID-19 dose 1", "-i"])
        .write_stdin(stdin)
        .assert()
        .success()
        .stdout(predicate::str::contains("vaccination"))
        .stdout(predicate::str::contains("COVID-19 dose 1"));

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Covishield"));
}

/// Spec §9.5: `loomed add -i` with type `diagnosis` must stage a typed
/// payload with condition, ICD code, and supporting metadata.
#[test]
fn add_interactive_diagnosis_stages_typed_payload() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // Prompt order (from prompts::prompt_diagnosis):
    //   condition*, icd_code*, severity*, onset*, status*, notes (opt),
    //   then supporting_refs (one per line, empty to end)
    let stdin = concat!(
        "Type 2 Diabetes Mellitus\n",
        "E11\n",
        "mild\n",
        "2026-02-01\n",
        "active\n",
        "\n", // notes (skip)
        "\n", // supporting_refs (end list immediately)
    );

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "diagnosis", "-m", "type 2 diabetes", "-i"])
        .write_stdin(stdin)
        .assert()
        .success()
        .stdout(predicate::str::contains("diagnosis"))
        .stdout(predicate::str::contains("type 2 diabetes"));

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Type 2 Diabetes Mellitus"));
}

/// Spec §9.6: `loomed add -i` with type `procedure` must stage a typed
/// payload with all required fields and succeed.
#[test]
fn add_interactive_procedure_stages_typed_payload() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // Prompt order (from prompts::prompt_procedure):
    //   procedure_name*, procedure_code*, procedure_type*, anaesthesia*,
    //   duration_minutes*, outcome*, notes (opt), diagnosis_ref (opt),
    //   then team members (role + participant_id pairs, empty role to finish)
    let stdin = concat!(
        "Appendectomy\n",
        "47.09\n",
        "surgical\n",
        "general\n",
        "45\n",
        "successful\n",
        "\n", // notes (skip)
        "\n", // diagnosis_ref (skip)
        "\n", // team role (end team list immediately)
    );

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "procedure", "-m", "appendectomy", "-i"])
        .write_stdin(stdin)
        .assert()
        .success()
        .stdout(predicate::str::contains("procedure"))
        .stdout(predicate::str::contains("appendectomy"));

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Appendectomy"));
}

/// Spec §9.1, §0.6 (coding standards): A required field that receives an
/// empty line must trigger a validation message and loop until a valid value
/// is provided. The command must still succeed when valid input follows.
#[test]
fn add_interactive_required_field_loops_until_valid_input_provided() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // Send an empty line first for test_name — this should trigger the
    // "is required" message and loop. Then send the real value and all
    // subsequent required fields.
    let stdin = "\nFasting Blood Glucose\nFBG\n98.5\nmg/dL\n70\n99\nnormal\n\n\n";

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "lab_result", "-m", "test validation", "-i"])
        .write_stdin(stdin)
        .assert()
        .success()
        // The "is required" message is printed to stdout by prompt_required()
        .stdout(predicate::str::contains("is required — please enter a value."));
}

/// Spec §9.1, §6.2, §20: `loomed show` must display typed payload fields
/// with labelled formatting for a commit staged via `loomed add -i`.
///
/// This is the end-to-end proof that the typed payload display works:
/// add interactively → commit → show → see labelled fields, not raw JSON.
#[test]
fn show_displays_typed_payload_fields_after_interactive_add() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // Stage a lab_result with a full interactive payload
    let stdin = "Fasting Blood Glucose\nFBG\n98.5\nmg/dL\n70\n99\nnormal\n\n\n";

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "lab_result", "-m", "fasting glucose", "-i"])
        .write_stdin(stdin)
        .assert()
        .success();

    // Commit the staged record
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("commit")
        .assert()
        .success();

    let commit_id = read_head(&dir);

    // Show must display typed labelled fields, not raw JSON
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["show", &commit_id])
        .assert()
        .success()
        // Section header still present
        .stdout(predicate::str::contains("payload"))
        // Typed field labels — these only appear with typed display
        .stdout(predicate::str::contains("test_name:"))
        .stdout(predicate::str::contains("test_code:"))
        .stdout(predicate::str::contains("ref_range:"))
        .stdout(predicate::str::contains("status:"))
        // Actual field values from the interactive input
        .stdout(predicate::str::contains("Fasting Blood Glucose"))
        .stdout(predicate::str::contains("FBG"))
        .stdout(predicate::str::contains("98.5"))
        .stdout(predicate::str::contains("mg/dL"))
        .stdout(predicate::str::contains("normal"));
}

/// Spec §9: `loomed show` for a commit staged without `-i` (empty payload)
/// must display the "empty payload" note rather than an empty JSON block.
#[test]
fn show_displays_empty_payload_note_for_non_interactive_add() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["add", "--type", "lab_result", "-m", "test without -i"])
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
        .stdout(predicate::str::contains("payload"))
        .stdout(predicate::str::contains("empty — record was staged without interactive prompts"));
}

// ---------------------------------------------------------------------------
// `loomed remote` and `loomed sync` tests — spec §8
// ---------------------------------------------------------------------------

/// Spec §8.1: `loomed remote set` must store the remote path in vault.toml and
/// confirm the setting to the user.
#[test]
fn remote_set_configures_sync_remote_in_vault() {
    let dir = TempDir::new().unwrap();
    let remote_dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["remote", "set", remote_dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("remote set:"))
        .stdout(predicate::str::contains(remote_dir.path().to_str().unwrap()));

    // vault.toml must now contain sync_remote
    let vault_toml = std::fs::read_to_string(dir.path().join(".loomed").join("vault.toml"))
        .expect("vault.toml must be readable");
    assert!(
        vault_toml.contains("sync_remote"),
        "vault.toml must contain sync_remote after `loomed remote set`"
    );
}

/// Spec §8.1: `loomed remote set` with a path that does not exist must fail
/// with a clear error before writing anything.
#[test]
fn remote_set_fails_for_nonexistent_path() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["remote", "set", "/this/path/does/not/exist"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

/// Spec §8.1: `loomed sync --status` on a fresh vault with a configured remote
/// must report the genesis commit as pending.
#[test]
fn sync_status_reports_pending_commits() {
    let dir = TempDir::new().unwrap();
    let remote_dir = TempDir::new().unwrap();
    require_vault(&dir);

    // Configure remote
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["remote", "set", remote_dir.path().to_str().unwrap()])
        .assert()
        .success();

    // Status must show the genesis commit as pending
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["sync", "--status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pending"))
        .stdout(predicate::str::contains("sha256:"));
}

/// Spec §8.1: `loomed sync` must push all unsynced commits to the remote and
/// report the number of commits pushed.
#[test]
fn sync_pushes_all_local_commits_to_remote() {
    let dir = TempDir::new().unwrap();
    let remote_dir = TempDir::new().unwrap();
    require_vault(&dir);

    // Add and commit a record so there's more than just the genesis commit
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

    // Configure and push
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["remote", "set", remote_dir.path().to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("sync")
        .assert()
        .success()
        .stdout(predicate::str::contains("pushed  sha256:"))
        .stdout(predicate::str::contains("sync complete."))
        .stdout(predicate::str::contains("2 commit(s) pushed")); // genesis + lab_result
}

/// Spec §8.1: Running `loomed sync` a second time when the remote is already
/// up-to-date must report "already up to date" and push nothing.
#[test]
fn sync_is_idempotent_when_remote_is_current() {
    let dir = TempDir::new().unwrap();
    let remote_dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["remote", "set", remote_dir.path().to_str().unwrap()])
        .assert()
        .success();

    // First sync — pushes genesis
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("sync")
        .assert()
        .success();

    // Second sync — nothing to push
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("sync")
        .assert()
        .success()
        .stdout(predicate::str::contains("already up to date"));
}

/// Spec §8.1: `loomed sync --status` after a full push must report
/// "up to date" with no pending commits.
#[test]
fn sync_status_shows_up_to_date_after_full_push() {
    let dir = TempDir::new().unwrap();
    let remote_dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["remote", "set", remote_dir.path().to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("sync")
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["sync", "--status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("up to date"));
}

/// Spec §8.1: `loomed sync` with no configured remote and no --to flag must
/// fail with a clear error before doing any work.
#[test]
fn sync_fails_with_no_remote_configured() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .arg("sync")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

/// Spec §8.1: `loomed sync --to <path>` must override the configured remote
/// for a single invocation without modifying vault.toml.
#[test]
fn sync_to_flag_overrides_configured_remote() {
    let dir = TempDir::new().unwrap();
    let override_remote = TempDir::new().unwrap();
    require_vault(&dir);

    // No configured remote — but --to provides one
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["sync", "--to", override_remote.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("pushed  sha256:"));

    // vault.toml must still have no sync_remote (--to is a one-off)
    let vault_toml = std::fs::read_to_string(dir.path().join(".loomed").join("vault.toml"))
        .unwrap();
    assert!(
        !vault_toml.contains("sync_remote"),
        "vault.toml must not be modified by --to flag"
    );
}

// ---------------------------------------------------------------------------
// loomed share
// ---------------------------------------------------------------------------

/// Spec §10.1: `loomed share` must issue a signed consent token and write
/// a `consent_token` commit, printing the token_id and scope.
#[test]
fn share_issues_token_and_writes_consent_token_commit() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "share",
            TEST_INSTITUTION_ID,
            "--scope",
            "full_record",
            "--duration",
            "4",
            "--purpose",
            "claim_verification",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("lmt_"))
        .stdout(predicate::str::contains("full_record"))
        .stdout(predicate::str::contains(TEST_INSTITUTION_ID));
}

/// Spec §10: A consent token issuance must appear in `loomed log` as a
/// `consent_token` commit, chained after the genesis commit.
#[test]
fn share_token_appears_in_log_as_consent_token_commit() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "share",
            TEST_INSTITUTION_ID,
            "--scope",
            "record_type:lab_result",
            "--duration",
            "2",
            "--purpose",
            "second_opinion",
        ])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .arg("log")
        .assert()
        .success()
        .stdout(predicate::str::contains("consent_token"))
        .stdout(predicate::str::contains(format!(
            "consent token issued to {}",
            TEST_INSTITUTION_ID
        )));
}

/// Spec §10.1: `loomed share --access-type write` must succeed and the
/// printed token must reflect write access.
#[test]
fn share_with_write_access_type_succeeds() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "share",
            TEST_INSTITUTION_ID,
            "--scope",
            "full_record",
            "--duration",
            "4",
            "--purpose",
            "lab_upload",
            "--access-type",
            "write",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"access_type\": \"write\""));
}

/// Coding standards §0.6: `loomed share` with a malformed participant ID
/// must fail before prompting for the passphrase.
#[test]
fn share_rejects_invalid_participant_id_before_passphrase() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    // No LOOMED_PASSPHRASE set — if share incorrectly reads the passphrase
    // before validating the participant ID, it will block on /dev/tty.
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "share",
            "not-a-valid-id",
            "--scope",
            "full_record",
            "--duration",
            "4",
            "--purpose",
            "claim_verification",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

/// Coding standards §0.6: `loomed share` with an invalid scope string must
/// fail before prompting for the passphrase.
#[test]
fn share_rejects_invalid_scope_before_passphrase() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "share",
            TEST_INSTITUTION_ID,
            "--scope",
            "not_a_real_scope",
            "--duration",
            "4",
            "--purpose",
            "claim_verification",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid consent scope"));
}

/// Spec §10.1: `loomed share` with a non-positive duration must fail
/// before prompting for the passphrase.
#[test]
fn share_rejects_non_positive_duration_before_passphrase() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "share",
            TEST_INSTITUTION_ID,
            "--scope",
            "full_record",
            "--duration",
            "0",
            "--purpose",
            "claim_verification",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

/// Coding standards §0.6: `loomed share` with an empty purpose must fail
/// before prompting for the passphrase.
#[test]
fn share_rejects_empty_purpose_before_passphrase() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "share",
            TEST_INSTITUTION_ID,
            "--scope",
            "full_record",
            "--duration",
            "4",
            "--purpose",
            "  ",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("purpose must not be empty"));
}

/// Coding standards §0.6: `loomed share` with an unknown access type must
/// fail before prompting for the passphrase.
#[test]
fn share_rejects_unknown_access_type_before_passphrase() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "share",
            TEST_INSTITUTION_ID,
            "--scope",
            "full_record",
            "--duration",
            "4",
            "--purpose",
            "claim_verification",
            "--access-type",
            "delete",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown access type"));
}

// ---------------------------------------------------------------------------
// loomed commit --token
// ---------------------------------------------------------------------------

/// Spec §10.1–§10.2: `loomed commit --token <token_id>` with a valid,
/// unexpired, write-scoped token must succeed and print the token_id.
#[test]
fn commit_with_valid_write_token_succeeds() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);
    let token_id = issue_token(&dir, "full_record", "write");

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["add", "--type", "lab_result", "-m", "fasting glucose"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["commit", "--token", &token_id])
        .assert()
        .success()
        .stdout(predicate::str::contains(&token_id));
}

/// Spec §10: A commit written under a token must show
/// `consent_token(<token_id>)` as its authorization in `loomed show`,
/// distinguishing it from a self-authored commit.
#[test]
fn commit_with_token_shows_consent_token_authorization() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);
    let token_id = issue_token(&dir, "full_record", "write");

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["add", "--type", "lab_result", "-m", "fasting glucose"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["commit", "--token", &token_id])
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
        .stdout(predicate::str::contains(format!(
            "consent_token({})",
            token_id
        )));
}

/// Spec §10.2: A token presented a second time must be rejected — tokens
/// are single-use, permanently, regardless of remaining validity window.
#[test]
fn commit_with_already_used_token_fails_on_second_presentation() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);
    let token_id = issue_token(&dir, "full_record", "write");

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["add", "--type", "lab_result", "-m", "first record"])
        .assert()
        .success();
    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["commit", "--token", &token_id])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["add", "--type", "lab_result", "-m", "second record"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["commit", "--token", &token_id])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already been used"));
}

/// Spec §10: `loomed commit --token` with a token_id that does not exist
/// in the chain must fail with a clear error.
#[test]
fn commit_with_nonexistent_token_fails() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["add", "--type", "lab_result", "-m", "fasting glucose"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["commit", "--token", "lmt_doesnotexist00000000"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("consent token not found"));
}

/// Coding standards §0.6: `loomed commit --token` with a malformed
/// token_id must fail before prompting for the passphrase.
#[test]
fn commit_with_malformed_token_id_fails_before_passphrase() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .args(["commit", "--token", "not-a-token"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("lmt_"));
}

/// Spec §10.1: A read-access token must not authorize a commit — read and
/// write tokens are strictly separated.
#[test]
fn commit_with_read_only_token_fails() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);
    let token_id = issue_token(&dir, "full_record", "read");

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["add", "--type", "lab_result", "-m", "fasting glucose"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["commit", "--token", &token_id])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not authorise this write"));
}

/// Spec §10.1: A token scoped to a different record type must not
/// authorize a write of the staged record's actual type.
#[test]
fn commit_with_out_of_scope_token_fails() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);
    let token_id = issue_token(&dir, "record_type:prescription", "write");

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["add", "--type", "lab_result", "-m", "fasting glucose"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["commit", "--token", &token_id])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not authorise this write"));
}

/// Spec §10.1: A token scoped to a matching record type must succeed.
#[test]
fn commit_with_matching_scoped_token_succeeds() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);
    let token_id = issue_token(&dir, "record_type:lab_result", "write");

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["add", "--type", "lab_result", "-m", "fasting glucose"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["commit", "--token", &token_id])
        .assert()
        .success();
}

/// Spec §10.1: A `commit:<id>` scoped token must never authorize a new
/// write — it grants access to one existing commit, a read-access concept.
#[test]
fn commit_with_commit_scoped_token_fails() {
    let dir = TempDir::new().unwrap();
    require_vault(&dir);
    let genesis_id = read_head(&dir);
    let token_id = issue_token(&dir, &format!("commit:{}", genesis_id), "write");

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["add", "--type", "lab_result", "-m", "fasting glucose"])
        .assert()
        .success();

    Command::cargo_bin("loomed")
        .unwrap()
        .current_dir(dir.path())
        .env("LOOMED_PASSPHRASE", TEST_PASSPHRASE)
        .args(["commit", "--token", &token_id])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not authorise this write"));
}