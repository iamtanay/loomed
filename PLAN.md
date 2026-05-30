# LooMed — Build Plan

This file tracks what has been built, what is next, and what is coming in later phases. It is the ground truth for where we are in the protocol implementation.

**Current status: Session 6 complete. 119 tests passing. Phase 1 complete.**

---

## We Are Building a Protocol

LooMed is not an application. It is a protocol — comparable to Git or HTTP. Every decision, every field name, every error variant, every test name is a promise to developers who will implement, audit, and build on LooMed. Code that shortcuts correctness, is ambiguous, or doesn't match the spec is not acceptable. The bar is: would an Apache Software Foundation developer be comfortable merging this?

This framing matters for how we write code. We do not add features beyond the spec. We do not design for hypothetical future requirements that aren't in the spec. We implement the spec section by section. Every public function references the spec section it implements.

---

## Phase 1 — Protocol Core CLI ✅ Complete

Phase 1 is fully implemented and all 110 tests pass.

### What Was Built

| Session | What Was Delivered |
|---|---|
| Session 1 | Workspace scaffolding, all four crates, `loomed-crypto` (hash, sign, encrypt, key derivation), `loomed-core` types (Commit, ParticipantId, RecordType, AuthorizationRef, SyncMetadata, all errors), `loomed-store` vault init/read/write, `loomed init` CLI command |
| Session 2 | `loomed-core` builder + verifier, `derive_keypair` (deterministic), `loomed-store` staged records, `loomed add`, `loomed commit`, `loomed log`, `loomed verify --chain` |
| Session 3 | `loomed show <commit_id>`, `loomed verify <commit_id>`, 13 vault integration tests, 4 deterministic keypair tests |
| Session 4 | Typed payload structs for all 6 record types (spec §9), `RecordPayload` enum, interactive prompts (`loomed add -i`), `loomed status`, §7.2 optional field fix |
| Session 5 | 34 CLI integration tests via `assert_cmd`, `LOOMED_PASSPHRASE` env var for non-interactive passphrase injection, `read_passphrase()` shared helper |
| Session 6 | Typed payload display in `loomed show` (spec §9), 9 integration tests for `loomed add -i` across all 6 record types + validation + end-to-end show, GitHub Actions CI with `cargo test` and Clippy |

### Phase 1 Test Coverage

| Crate | Tests |
|---|---|
| `loomed-core` | 41 — commit types, builder, chain verifier, participant IDs, all 6 payload types |
| `loomed-crypto` | 17 — hashing, signing, encryption, key derivation, determinism proofs |
| `loomed-store` | 18 — staged record lifecycle, vault init/open/write/read, full chain traversal |
| `loomed-cli` | 43 — black-box integration tests for every command including all 6 `add -i` types |
| **Total** | **119, 0 failures** |

### Phase 1 CLI Surface (Complete)

```bash
loomed init                              # vault + genesis commit
loomed add --type <type> -m "msg"        # stage with empty payload
loomed add --type <type> -m "msg" -i    # stage with interactive payload (spec §9)
loomed commit                            # sign, encrypt, write .lmc
loomed log                               # full history, newest first
loomed show sha256:<hash>                # inspect a specific commit
loomed status                            # vault state + staged record (no passphrase)
loomed verify sha256:<hash>              # verify single commit
loomed verify --chain                    # verify full chain from genesis
```

---

## Session 6 — Complete ✅

### What Was Built

**`loomed show` — Typed Payload Display (spec §9)**
- `crates/loomed-cli/src/commands/show.rs` rewritten with typed payload display
- For the six clinical record types, `commit.payload` is deserialised into the appropriate typed struct (`LabResultPayload`, `PrescriptionPayload`, etc.) and displayed as labelled fields with consistent column alignment
- Empty payloads (staged without `-i`) display `"(empty — record was staged without interactive prompts)"` rather than `{}`
- Protocol-internal types (`key_rotation`, `vault_reencryption`, etc.) fall back to raw JSON
- Graceful deserialization fallback: if a payload cannot be parsed as its declared type, raw JSON is shown with a note
- `print_payload_field()` private helper ensures 16-char label alignment across all 6 display functions

**Integration Tests — `loomed add -i` (spec §9)**
- 9 new tests in `crates/loomed-cli/tests/cli_integration.rs`
- One happy-path test per record type (all 6): feeds exact stdin sequence matching `prompts.rs` prompt order, asserts success and that staged content appears in `loomed status`
- `add_interactive_required_field_loops_until_valid_input_provided` — sends empty line then valid value, proves the validation loop fires
- `show_displays_typed_payload_fields_after_interactive_add` — full end-to-end: add -i → commit → show → assert labelled fields (`test_name:`, `ref_range:`, actual values)
- `show_displays_empty_payload_note_for_non_interactive_add` — proves empty payload message appears for non-interactive adds

**GitHub Actions CI (`.github/workflows/ci.yml`)**
- `test` job: Ubuntu Linux, stable Rust, `cargo build --workspace` + `cargo test --workspace`
- `clippy` job: same runner, `-D warnings` on all targets
- Cargo cache via `actions/cache@v4` keyed on `Cargo.toml` hash
- Triggers on push and pull_request to `main`

### Session 6 Test Count

| Crate | Before | After |
|---|---|---|
| `loomed-cli` | 34 | 43 (+9) |
| `loomed-core` | 41 | 41 |
| `loomed-crypto` | 17 | 17 |
| `loomed-store` | 18 | 18 |
| **Total** | **110** | **119, 0 failures** |

---

## Session 7 — Next

Phase 1 post-completion hardening. Three tasks to tighten the CLI surface before moving to Phase 2.

### Task 1: `loomed log` — Payload Summary Line
**What:** `loomed log` currently shows `commit_id`, type, date, and message for each commit. For commits with typed payloads, add a one-line payload summary (e.g. `FBG: 98.5 mg/dL` for lab results, `Metformin 500mg × 30d` for prescriptions).
**Spec:** §6.2, §9, §20.
**Scope:** `crates/loomed-cli/src/commands/log.rs` only. Deserialise payload into typed struct and format a summary string per record type. Empty payloads are silently omitted from the log line (no change to current output for non-interactive records).

### Task 2: `loomed show` — Display `sync_metadata` pre-rebase fields
**What:** The `sync_metadata` block in `loomed show` currently shows `offline` and `synced_at`. Phase 2 will populate `pre_sync_previous_hash` and `pre_sync_commit_id` during Sync Rebase. Extend the display to show those fields when non-null, so rebased commits are visually distinguishable in Phase 2.
**Spec:** §8.3.
**Scope:** `crates/loomed-cli/src/commands/show.rs` only.

### Task 3: Participant ID Format Validation — Full Spec §3.1
**What:** `ParticipantId::new()` currently validates only the prefix (`LMP-`, `LMD-`, etc.) and minimum length. The full spec §3.1 ID format is `<TYPE>-<SCOPE?>-<BASE32_ID>-<CHECKSUM>`. Implement the full validation: base-32 character set check on the ID segment, and CRC-8 checksum verification on the final segment.
**Why:** Phase 5 adds participant registration with full ID generation. The validation layer should be correct before the registry is built on top of it.
**Spec:** §3.1.
**Scope:** `crates/loomed-core/src/participant.rs`. Add 6+ tests covering valid and invalid ID formats including bad checksums and non-base32 characters.

---

---

## Phase 2 — Encrypted Cloud Sync 🔜 Next Phase

**Spec:** §5, §8.

This phase adds cloud persistence and offline-first sync. The local vault remains the source of truth during offline operation; the cloud vault is the authoritative sync target.

### What to Build

**`loomed-sync` crate** (new):
- Cloud vault adapter interface — defined as a trait, not tied to any specific backend
- `loomed sync` — push all committed-but-unsynced `.lmc` files to cloud vault
- `loomed sync --status` — show which commits are pending sync
- `loomed sync --resolve` — detect and resolve forks via Sync Rebase algorithm

**Sync Rebase algorithm** (in `loomed-sync` or `loomed-core`):
- Detect fork: two commits share the same `previous_hash`
- Sort conflicting commits by timestamp (ascending), tiebreak by `commit_id` lexicographic
- Re-link sequentially, recompute `commit_id` for shifted commits
- Preserve original values in `sync_metadata.pre_sync_previous_hash` and `pre_sync_commit_id`
- Original signature is preserved (remains valid against original content)
- Clock skew tolerance: ±60 seconds (use `commit_id` tiebreaker within this window)

**`loomed-store` additions:**
- `SyncState` tracking per commit: `unsynced | synced | rebased`
- `Vault::mark_synced(commit_id)` — update sync state after successful push

### Data Already in Place

`SyncMetadata` is in every commit from genesis:
```rust
pub struct SyncMetadata {
    pub created_offline: bool,
    pub synced_at: Option<DateTime<Utc>>,
    pub pre_sync_previous_hash: Option<CommitHash>,
    pub pre_sync_commit_id: Option<CommitHash>,
}
```

Phase 2 populates these fields. The commit struct does not change.

---

## Phase 3 — Consent Tokens + Audit Trail 🔵 Planned

**Spec:** §10, §11.

This phase implements the patient consent model — the mechanism by which patients grant time-bound, scoped, single-use access to institutions.

### What to Build

**Consent token issuance** (`loomed share`):
- `loomed share <participant_id> --scope <scope> --duration <hours> --purpose <purpose>`
- Generates a `ConsentToken` signed by the patient's private key
- Scope: `full_record | record_type:<type> | commit:<id> | date_range:<from>:<to>`
- Access type: `read` (default) or `write` — strictly separated
- Writes a `consent_token` commit to the vault for auditability

**Token lifecycle enforcement**:
- Tokens are single-use — marked `used: true` on first presentation
- Tokens are time-bounded — `expires_at` enforced at the protocol layer
- A token without a valid patient signature is unconditionally rejected

**Audit trail** (`loomed audit`):
- `loomed audit` — display full access event log
- `loomed audit --entity <participant_id>` — filter by entity
- Access events are immutable commits of a new record type

**Token revocation** (`loomed revoke`):
- `loomed revoke <token_id>` — invalidate an active token before expiry

### Types Already in Place

```rust
pub struct TokenId(pub String);  // "lmt_<alphanumeric>"

pub enum AuthorizationRef {
    SelfAuthored,
    ConsentToken { token_id: TokenId },
}
```

All existing commits carry `AuthorizationRef::SelfAuthored`. Phase 3 enforces token validation when a commit carries `ConsentToken`.

---

## Phase 4 — Identity Provider + Key Rotation 🔵 Planned

**Spec:** §4, §12.

This phase replaces the passphrase-derived key model with a proper IdP abstraction. The call sites do not change — only the source of the key changes.

### What to Build

**IdP abstraction** (new `loomed-idp` crate or trait in `loomed-crypto`):
- Define the `IdentityProvider` trait: `sign(&self, message: &[u8]) -> Result<String>`
- Tier 1: National digital identity binding (Aadhaar OTP, eIDAS, etc.)
- Tier 2: Hardware secure enclave (Apple Secure Enclave, Android StrongBox, YubiKey)
- Tier 3: Shamir Secret Sharing recovery (3-of-5 custodians)

**Persisted encrypted key file**:
- Replace `derive_keypair(passphrase, salt)` with loading a key file encrypted with AES-256-GCM
- Key file lives at `.loomed/key.enc` (never in plaintext)
- `loomed key rotate` — initiate key rotation, write `key_rotation` commit signed by old + new key
- `loomed key status` — show current key binding and IdP type

**Key rotation flow** (spec §12.1):
1. Patient authenticates via IdP recovery path
2. New keypair generated
3. `key_rotation` commit written, signed by old key (if available) or recovery quorum
4. All active consent tokens issued under old key are invalidated
5. Historical records re-encrypted under new key → `vault_reencryption` commit

**Affected call sites** (all have `// TODO: Phase 4` already):
- `crates/loomed-cli/src/commands/init.rs`
- `crates/loomed-cli/src/commands/commit.rs`
- `crates/loomed-cli/src/commands/show.rs`
- `crates/loomed-cli/src/commands/verify.rs`

---

## Phase 5 — Participant Registry + Verification 🔵 Planned

**Spec:** §3, §4.4.

This phase adds participant registration, cryptographic verification against external bodies (NMC, NABH), and the web-of-trust model for cross-border verification.

### What to Build

**`loomed-registry` crate** (new):
- Participant registration schema for all five types (patient, clinician, institution, device, government)
- Verification body attestation schema
- `loomed participant add --type <type>` — register a participant
- `loomed participant show <id>` — inspect a participant record
- `loomed participant verify <id>` — check verification status against the registry

**Participant ID generation** (full spec §3.1):
- Currently: format validation only (prefix check)
- Phase 5: full ID generation — base-32 random segment + CRC-8 checksum computation

---

## Phase 6 — FHIR / HL7 Adapter + Open Source Release 🔵 Planned

**Spec:** §13.

This phase adds the interoperability layer and prepares the codebase for public open source release.

### What to Build

**`loomed-fhir` crate** (new):
- FHIR R4 resource → LooMed commit translation
- HL7 v2 message → LooMed commit translation
- ABDM (India) health record → LooMed commit translation
- This is the application layer — the protocol itself does not change

**Open source release checklist:**
- Foundation model governance documents
- Contributor licence agreement (CLA)
- Protocol conformance test suite
- `CHANGELOG.md` and versioned release tags
- `loomed-conformance` crate — test suite any implementation can run to prove compliance

---

## Known Limitations (Acknowledged in Spec)

| Limitation | Status | Spec Reference |
|---|---|---|
| Correlation attacks on access logs | Known protocol-level limitation | §18 |
| Backward secrecy after key compromise | Open design problem for v1 | §12.2 |
| Post-quantum cryptography | Out of scope for v0.2, planned extension | §17 |
| Side-channel attacks on secure enclaves | Out of scope for v0.2 | §17 |
| Insider at verification body | Trust problem, public auditing is primary defence | §17 |
| `loomed add -i` not covered by integration tests | Planned for Session 6 | — |
| No GitHub Actions CI | Planned for Session 6 | — |
