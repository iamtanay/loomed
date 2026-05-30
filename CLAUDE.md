# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Key Documents

- `ARCHITECTURE.md` — the full mental model: crate boundaries, commit finalisation order, Phase 1 key model, all protocol invariants, future phases
- `PLAN.md` — what has been built session by session, what Session 6 must build, and the full phase roadmap with spec references
- `.claude/coding-standards.md` — the active coding standard (v0.5); follow without exception

---

## What This Is

LooMed is a Rust implementation of an open protocol for patient-owned medical records. Every medical event becomes a cryptographically signed, hash-chained, encrypted **commit** — like Git for medical history. The patient holds the keys; no institution can read or write without a token the patient issues.

Protocol spec: `LooMed_V0_2.pdf`. Coding standards: `loomed-coding-standards-v0.4.docx`. Every function references the spec section it implements (e.g. `spec §6.2`). Every test names the rule it proves.

## Commands

```bash
cargo build                    # build all crates
cargo build --release          # release build (lto + strip)
cargo test                     # run all 59 tests
cargo test -p loomed-core      # test one crate
cargo test -p loomed-store
cargo test -p loomed-crypto
cargo test -p loomed-cli
cargo test <test_name>         # run a single test by name
```

The CLI binary is `loomed` (from `loomed-cli`). After `cargo build`:

```bash
# Non-interactive invocation (how tests work):
LOOMED_PASSPHRASE=mypassphrase echo "LMP-7XKQR2MNVB-F4" | ./target/debug/loomed init
LOOMED_PASSPHRASE=mypassphrase ./target/debug/loomed commit
```

Integration tests in `loomed-cli/tests/cli_integration.rs` run the compiled binary via `assert_cmd`. They set `LOOMED_PASSPHRASE` in the environment and supply the participant ID via stdin.

## Crate Architecture

Strict one-way dependency chain — each crate has exactly one job:

```
loomed-crypto   ← no LooMed deps. Only place crypto operations happen.
     ↓
loomed-core     ← protocol types and logic. No I/O, no disk access.
     ↓
loomed-store    ← only place file I/O happens. Reads/writes disk.
     ↓
loomed-cli      ← thin CLI wrapper. No business logic. Parses args, calls libs.
```

Breaking this dependency order is always wrong.

### loomed-crypto

Five public exports: `compute_commit_hash` (SHA-256, prefixed `sha256:`), `compute_content_hash` (BLAKE3, prefixed `blake3:`), `generate_keypair`, `derive_keypair`, `sign`, `verify`, `derive_key`, `encrypt`, `decrypt`.

The critical design: **keypairs are derived deterministically** from `passphrase + salt` via Argon2id → ed25519 seed. There is no private key file. The same passphrase used at `loomed init` will always reproduce the same signing key at `loomed commit`, which always matches the public key stored in `vault.toml`. This is what makes `loomed verify --chain` work in Phase 1 without key persistence.

### loomed-core

Protocol types and pure logic:

- `commit.rs` — `Commit` struct (the atomic unit), `CommitHash`, `ContentHash`, `RecordType`, `AuthorizationRef`, `SyncMetadata`
- `builder.rs` — `prepare()` → `PendingCommit` → `finalise(signature)` → `Commit`. The builder computes content_hash (BLAKE3) and commit_id (SHA-256). The caller signs; the builder embeds the signature and computes the final hash.
- `verify.rs` — `verify_commit()` and `verify_chain()`. Verifies hash and ed25519 signature; chain verification also checks `previous_hash` continuity.
- `participant.rs` — `ParticipantId` newtype with prefix validation (LMP/LMD/LMI/LMV/LMG). `ParticipantType` enum.
- `payload.rs` — Typed payload structs for all 6 record types (§9.1–§9.6): `LabResultPayload`, `PrescriptionPayload`, `RadiologyReportPayload`, `VaccinationPayload`, `DiagnosisPayload`, `ProcedurePayload`. Plus `RecordPayload` enum for type-safe dispatch and `ExternalRef` for raw imaging files.
- `error.rs` — `LooMedError` with named variants, no catch-all strings.

**Commit ID computation**: SHA-256 of the full commit JSON with `commit_id` set to empty string. The `signature` field is also empty when computing `commit_id` but present when hashing.

### loomed-store

Two modules:

- `vault.rs` — `Vault` struct. `init()` creates `.loomed/` structure, writes `vault.toml`. `open()` reads metadata. `write_commit()` serialises → encrypts (AES-256-GCM) → writes `.lmc`. `read_commit()` reads → decrypts → deserialises. `read_head()` / `list_commit_ids()`. The encryption key is derived from `passphrase + argon2_salt` (from vault.toml) on every call — no key is cached.
- `stage.rs` — `write_staged()`, `read_staged()`, `clear_staged()`, `has_staged()`. The staging area is `.loomed/staged.json` (plaintext JSON). One record at a time; writing overwrites.

**Vault on disk:**

```
.loomed/
  vault.toml          ← plaintext: patient_id, protocol_version, idp_type, argon2_salt, public_key
  commits/
    <hash>.lmc        ← AES-256-GCM encrypted JSON. Filename is the commit hash without "sha256:" prefix.
  HEAD                ← plaintext: the full commit_id ("sha256:<hex>") of the latest commit
  staged.json         ← plaintext: the currently staged record (if any)
```

### loomed-cli

Commands in `crates/loomed-cli/src/commands/`: `init`, `add`, `commit`, `log`, `show`, `status`, `verify`, `prompts`.

The shared `read_passphrase()` in `commands/mod.rs` checks `LOOMED_PASSPHRASE` env var before prompting. All passphrase-reading commands use this function — never call `rpassword` directly.

`loomed add -i` invokes `prompts::prompt_payload()` which collects all typed fields per spec §9 and returns a `RecordPayload`. Without `-i`, an empty JSON object `{}` is staged.

## Key Protocol Invariants

- **Genesis commit**: `previous_hash = None`, `record_type = KeyRotation`, written by `loomed init`.
- **Every subsequent commit**: `previous_hash` = the `commit_id` of the preceding commit (the HEAD at time of commit).
- **Append-only**: nothing is edited or deleted. Corrections are new commits. Retractions reference the original commit.
- **Payload optional fields**: always `#[serde(skip_serializing_if = "Option::is_none")]` — absent `Option` fields are omitted from JSON entirely, never serialised as `null` (coding standards §7.2).
- **Raw imaging files are never stored**: `RadiologyReportPayload` always carries an `ExternalRef` pointing to the custodian institution. This is a first-class design decision, not a limitation (spec §9.3).
- **Fail before passphrase**: commands validate all arguments (record type, commit ID format) before opening the vault or prompting for credentials (coding standards §0.6).

## Testing Rules

- Every test uses an isolated `tempfile::TempDir`. No test touches the real `.loomed/` vault (coding standards §6.2).
- CLI integration tests inject the passphrase via `LOOMED_PASSPHRASE` env var. `loomed init` receives the participant ID via stdin.
- Test names state the protocol rule being verified, not implementation details (coding standards §6.1).
- The `loomed-cli` tests are black-box: they assert on stdout/stderr and exit codes only. No business logic in the CLI test layer.

## Roadmap Context

Phase 1 (complete): local vault — init, add, commit, log, show, verify.

Phase 2 (next): encrypted cloud sync, offline-first, conflict resolution via Sync Rebase (see `SyncMetadata` in `commit.rs`).

Phase 3: consent tokens — `AuthorizationRef::ConsentToken` is already defined; `ConsentToken.token_id` format is `lmt_<alphanumeric>`.

Phase 4: identity provider abstraction, key rotation, persisted encrypted key file replacing `derive_keypair`. All call sites for keypair derivation have `// TODO: Phase 4` comments.

Every `TODO` comment in the codebase references the spec section and phase that will replace it. The call site interface is designed not to change — only the implementation behind it.
