# LooMed — Build Plan

This file tracks what has been built, what is next, and what is coming in later phases. It is the ground truth for where we are in the protocol implementation.

**Current status: Phase 3 Session 2 complete (consent token enforcement). 201 tests passing.**

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

## Phase 2 — Encrypted Cloud Sync 🔄 In Progress

### Phase 2 Session 1 ✅ Complete

**`loomed-sync` crate** (new):
- `CloudVaultBackend` trait — backend-agnostic interface for push/pull/list/head operations. Object-safe for future runtime dispatch.
- `LocalFileBackend` — zero-cost reference backend storing encrypted commits in a local directory. Mirrors `.loomed/` structure exactly.
- `SyncManager` — orchestrates push and status. Transfers raw AES-256-GCM bytes without the passphrase.
- `SyncReport` and `SyncStatus` result types.
- 11 unit tests covering roundtrips, idempotency, HEAD updates, not-found errors, and raw bytes assertion.

**`loomed-store` additions**:
- `VaultMetadata.sync_remote: Option<String>` — persisted remote path (backward-compatible, serde default)
- `Vault::read_commit_raw()` — returns raw encrypted bytes without decrypting
- `Vault::write_commit_raw()` — stores raw bytes (for future pull support)
- `Vault::set_remote()` — updates vault.toml with remote path

**`loomed-cli` additions**:
- `loomed remote set <path>` — configure the sync remote in vault.toml
- `loomed sync` — push all commits absent from remote; no passphrase required
- `loomed sync --status` — show pending commits without pushing
- `loomed sync --to <path>` — one-off remote override without modifying vault.toml
- 8 integration tests covering all sync paths

**Test count:**

| Crate | Tests |
|---|---|
| `loomed-cli` | 51 (+8 sync tests) |
| `loomed-core` | 41 |
| `loomed-crypto` | 17 |
| `loomed-store` | 18 |
| `loomed-sync` | 11 (new) |
| **Total** | **138, 0 failures** |

### Phase 2 Session 2 ✅ Complete

Pull from remote, Sync Rebase algorithm, fork resolution (spec §8.2, §8.3):

**`loomed sync --pull`** — fetch commits from remote that are absent locally:
- `SyncManager::pull()` computes set difference and transfers raw AES-256-GCM bytes
- `backend.pull_commit(id)` → `vault.write_commit_raw(id)` for each
- Updates local HEAD to match remote HEAD after pull
- No passphrase required — transfers encrypted bytes only

**`loomed sync --resolve`** — Sync Rebase algorithm (spec §8.3):
- `SyncManager::resolve()` loads all local commits and calls `sync_rebase()`
- `sync_rebase()` in `loomed-core/src/rebase.rs` (620 lines, 12 tests):
  - Detects fork: two commits share the same `previous_hash`
  - Sorts conflicting commits by timestamp ascending, tiebreak by `commit_id` lexicographic (±60s clock skew tolerance)
  - Re-links sequentially, recomputes `commit_id` for rebased commits
  - Preserves original `previous_hash` and `commit_id` in `sync_metadata` for audit
  - Signatures never modified — remain valid via `pre_sync_previous_hash` per spec
  - Deterministic: same fork always produces identical linearisation
- Requires vault passphrase (re-encrypts rebased commits)
- Updates local HEAD to the last commit in rebased chain

**`loomed-store` additions**:
- `Vault::update_head(commit_id)` — update local HEAD after pull or resolve

**`loomed-sync` additions**:
- `SyncManager::pull()` with `PullReport` result type
- `SyncManager::resolve()` returning count of rebased commits
- `SyncError::Protocol()` variant for Sync Rebase invariant violations

**`loomed-cli` additions**:
- `loomed sync --pull` — fetch commits from remote
- `loomed sync --resolve` — linearise forks locally (no remote needed)
- 4 new integration tests for pull and resolve workflows

**Test count:**

| Crate | Tests |
|---|---|
| `loomed-cli` | 51 |
| `loomed-core` | 53 (41 + 12 rebase) |
| `loomed-crypto` | 17 |
| `loomed-store` | 18 |
| `loomed-sync` | 15 (11 push/status + 4 pull/resolve) |
| **Total** | **154, 0 failures** |

---

## Phase 2 Session 3 ✅ Complete

CLI hardening and payload display enhancements, plus the first task of the [First Release Plan](FIRST_RELEASE_PLAN.md) (R1).

### What Was Built

**`loomed log` — Payload Summary Line**
- `payload_summary()` in `crates/loomed-cli/src/commands/log.rs` deserialises the payload into its typed struct per record type and prints a one-line summary under the message (e.g. `FBG: 98.5 mg/dL`, `Metformin 500mg × 30d`)
- Empty payloads, protocol-internal record types, and payloads that fail typed deserialisation are all silently omitted — no summary line, no change to prior output
- Spec §6.2, §9, §20

**`loomed show` — `sync_metadata` pre-rebase fields**
- `pre_sync_previous_hash` and `pre_sync_commit_id` now print in the `sync` block when populated by Sync Rebase (spec §8.3)
- Absent for unrebased commits — output is unchanged from Session 2 in that case

**Participant ID Format Validation — Full Spec §3.1**
- `ParticipantId::new()` in `crates/loomed-core/src/participant.rs` now validates the complete format: type prefix, segment count (3 for patients — no scope; 4 for clinician/institution/device/government — scope required), Crockford Base32 charset on the ID and checksum segments, and CRC-8 checksum verification
- Checksum is computed over every segment preceding it (catches transcription errors in the scope segment too, not just the random ID)
- **Blast radius wider than originally scoped**: the canonical example IDs (`LMP-7XKQR2MNVB-F4`, `LMD-APL-3NKWQ7HZRC-8A`, etc.) used as test fixtures across `loomed-core`, `loomed-store`, `loomed-sync`, and `loomed-cli` integration tests, plus `CLAUDE.md` and `README.md`, do not satisfy a real CRC-8 checksum — those illustrative spec values were never computed by an algorithm (confirmed by duplicate fake hashes elsewhere in the spec doc). Regenerated all canonical fixture IDs to valid checksums under the implemented algorithm (`LMP-7XKQR2MNVB-6A`, `LMD-APL-3NKWQ7HZRC-5N`, `LMI-APL-2MVZK9QXBT-08`, `LMV-ROCHE-5QNZK8MXBT-3P`, `LMG-AIIMS-4KZQR9WMNV-43`) and propagated the change everywhere they were used as a validated `ParticipantId`. Payload fields that carry participant-ID-*shaped* strings but are typed as plain `String` (e.g. `custodian_id`, `device_id`, `radiologist_id`) were left untouched — they are never checksum-validated.
- 7 new tests: valid IDs for all 5 types, missing/extra scope segment, non-base32 character, incorrect checksum, wrong checksum length, transcription error in the scope segment
- Spec §3.1

### Test Count

| Crate | Before | After |
|---|---|---|
| `loomed-core` | 53 | 60 (+7 participant ID tests) |
| `loomed-cli` | 51 | 51 |
| `loomed-crypto` | 17 | 17 |
| `loomed-store` | 18 | 18 |
| `loomed-sync` | 15 | 15 |
| **Total** | **154** | **161, 0 failures** |

---

## Phase 3 Session 1 ✅ Complete — Consent Token Issuance

R2 of the [First Release Plan](FIRST_RELEASE_PLAN.md). Spec §10.1.

### What Was Built

**`loomed-core` — new `consent.rs` module**:
- `ConsentScope` enum (`FullRecord`, `RecordType(RecordType)`, `Commit(CommitHash)`) with hand-written `Display`/`FromStr`/`Serialize`/`Deserialize` so the wire format matches spec §10.1 exactly (`"full_record"`, `"record_type:lab_result"`, `"commit:sha256:..."`) rather than a nested JSON object. `date_range:<from>:<to>` is deferred past v1.0.
- `AccessType` enum (`Read`, `Write`) — standard derive, `read`/`write` on the wire
- `ConsentToken` struct matching the full spec §10.1 schema, including its own `patient_signature` — independent of any wrapping commit's signature, so an institution holding just the token JSON can verify it without the patient's chain
- `prepare_token()` / `PendingConsentToken::finalise()` — sign-then-embed flow mirroring `builder::prepare()` / `PendingCommit::finalise()`
- `RecordType::ConsentToken` variant added (serialises to `consent_token`)
- 13 new tests: scope round-trips for all 3 in-scope variants, invalid scope strings, non-positive duration rejected, signature verifies against the issuing key and not against any other key

**`loomed-cli` — new `loomed share` command**:
- `loomed share <participant_id> --scope <scope> --duration <hours> --purpose <purpose> [--access-type read|write]` (`--access-type` is an addition beyond the spec §20 signature — needed so a write token can actually be issued via the CLI; defaults to `read`)
- Validates participant ID, scope, access type, and duration before opening the vault or prompting for a passphrase
- Signs the token with the same deterministic keypair used for commits, then wraps it in a `consent_token` commit (self-authored, chained after HEAD) for auditability
- Prints the full token JSON for out-of-band delivery to the institution — there is no delivery channel yet
- 8 new integration tests: happy path, log visibility, write access type, and 5 fail-fast validation cases

**Bug caught during this session**: the initial `share.rs` validated participant ID, scope, and access type up front but left the `duration_hours > 0` check inside `consent::prepare_token()`, which runs *after* the passphrase prompt. The `share_rejects_non_positive_duration_before_passphrase` test (no `LOOMED_PASSPHRASE` set, matching the fail-fast test pattern used elsewhere) exposed this immediately — `cargo test` hung because the command fell through to `rpassword::prompt_password()` waiting on a terminal that wasn't there. Fixed by moving the duration check into `share.rs`'s Step 1 validation block, ahead of the vault open (coding standards §0.6). `prepare_token()` keeps its own check too — a library invariant, not something that should depend on every caller getting it right.

### What Was NOT Built (this session)

Deferred to Phase 3 Session 2, per the spec §10.2 token lifecycle and audit trail:
- Token enforcement: `loomed commit --token <token_id>` for non-patient writers, signature/expiry/scope/single-use validation at presentation time
- `loomed audit` / `loomed audit --entity <participant_id>` — access event log
- `loomed revoke <token_id>` — early invalidation

### Test Count

| Crate | Before | After |
|---|---|---|
| `loomed-core` | 60 | 74 (+13 consent tests, +1 ConsentToken RecordType test) |
| `loomed-cli` | 51 | 59 (+8 share tests) |
| `loomed-crypto` | 17 | 17 |
| `loomed-store` | 18 | 18 |
| `loomed-sync` | 15 | 15 |
| **Total** | **161** | **183, 0 failures** |

---

## Phase 3 Session 2 ✅ Complete — Consent Token Enforcement

R3 of the [First Release Plan](FIRST_RELEASE_PLAN.md). Spec §10.1–§10.2.

### What Was Built

**`loomed-core` — write-authorization on `ConsentToken`**:
- `ConsentScope::permits_write_of(&record_type) -> bool` — `FullRecord` permits anything, `RecordType(t)` permits only a matching write, `Commit(_)` never permits a write (it grants access to one *existing* commit — inherently a read concept, not something a new write can satisfy)
- `ConsentToken::verify_signature(public_key_hex)` — recomputes the canonical bytes (this token with `patient_signature` cleared) exactly as `prepare_token` produced them, verifies against the key
- `ConsentToken::authorize_write(public_key_hex, record_type, now)` — runs signature → expiry → access_type → scope checks in order, returning the first failure. Deliberately does **not** check single-use state: answering "has this token already been presented" requires scanning the vault's commit chain, which is disk I/O this crate never performs by design. That check is `loomed-cli`'s job.
- 3 new error variants: `TokenNotFound`, `TokenSignatureInvalid`, `TokenNotAuthorizedForWrite { reason }`
- 9 new tests covering every branch of scope permission and `authorize_write`

**`loomed-cli` — `loomed commit --token <token_id>`**:
- Validates the token_id format (`lmt_` prefix) before opening the vault, per coding standards §0.6
- After the passphrase is available, does a single pass over the full chain from HEAD to genesis: finds the `consent_token` commit that issued this token_id, and separately checks whether any *existing* commit already carries `AuthorizationRef::ConsentToken` with this token_id
- **Single-use enforcement needed no new commit type.** A token is "used" the moment any commit in the chain carries its ID as authorization — the write commit itself, once written, is the permanent, tamper-evident usage marker. No separate access-event commit was needed for this; that's still true audit-trail territory (Session 3)
- On success, the record commit is written with `authorization_ref: ConsentToken { token_id }` instead of `SelfAuthored`
- 9 new integration tests: valid write succeeds, authorization visible in `loomed show`, reuse rejected, nonexistent token rejected, malformed token_id rejected before passphrase, read-only token rejected, out-of-scope record type rejected, matching scope succeeds, commit-scoped token rejected

**Known v1 limitation, stated explicitly in `commit.rs`'s module doc**: there is still only one identity in this CLI — the patient's own vault keypair. `--token` exercises every spec §10 enforcement rule (signature, expiry, access type, scope, single-use), but the commit is still signed by the patient's own key; `author_id`/`authored_by` are not set to the institution's participant ID, because that would mean claiming a signature that doesn't exist. A real cross-participant write — where the institution signs with its own key — needs per-participant identity, which is Phase 4/5 territory, not something to fake here.

### What Was NOT Built (this session)

Deferred to Phase 3 Session 3:
- `loomed audit` / `loomed audit --entity <participant_id>` — access event log (spec §11)
- `loomed revoke <token_id>` — early invalidation before expiry

### Test Count

| Crate | Before | After |
|---|---|---|
| `loomed-core` | 74 | 83 (+9 write-authorization tests) |
| `loomed-cli` | 59 | 68 (+9 commit --token tests) |
| `loomed-crypto` | 17 | 17 |
| `loomed-store` | 18 | 18 |
| `loomed-sync` | 15 | 15 |
| **Total** | **183** | **201, 0 failures** |

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
