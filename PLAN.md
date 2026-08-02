# LooMed — Build Plan

This file tracks what has been built, what is next, and what is coming in later phases. It is the ground truth for where we are in the protocol implementation.

**Current status: Phase 4-lite Session 2 complete (key rotation). R5+R6 of the First Release Plan done. 240 tests passing.**

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

## Phase 3 Session 3 ✅ Complete — Audit Trail + Revocation

Final session of Phase 3. R4 of the [First Release Plan](FIRST_RELEASE_PLAN.md). Spec §11, §10.2, §12.

### What Was Built

**`loomed-core`**:
- `RecordType::TokenRevocation` variant (serialises to `token_revocation`) — a new commit type declaring a previously issued token invalid, written by `loomed revoke`. Nothing is edited or deleted: the original `consent_token` issuance commit stays in the chain exactly as before.
- 2 new error variants: `TokenRevoked`, `TokenAlreadyRevoked`

**`loomed-cli` — shared chain-scanning module, `token_chain.rs`**:
- `scan_all_tokens()` / `find_token()` — one place that answers "what tokens exist, have they been used, have they been revoked" by scanning the full chain once. `loomed commit --token`, `loomed revoke`, and `loomed audit` all call into this instead of each re-implementing chain traversal — there is exactly one definition of what "used" and "revoked" mean
- `commit.rs`'s `find_and_authorize_token` was refactored to use this shared scan (previously it had its own bespoke traversal) and now also rejects a revoked token, with a new error path proven by `commit_with_revoked_token_fails`

**`loomed-cli` — `loomed revoke <token_id>`**:
- Validates token_id format before opening the vault; confirms the token exists and is not already revoked; writes a `token_revocation` commit self-authored by the patient
- Revoking an already-used token is allowed (harmless, since the token is already consumed) — only double-revocation is rejected
- 5 new integration tests, including the cross-command proof that a revoked token is rejected by `loomed commit --token`

**`loomed-cli` — `loomed audit` / `loomed audit --entity <participant_id>`**:
- One entry per issued token, newest-issued first, showing status: `active`, `used` (with the consuming commit_id and timestamp), `expired`, or `revoked` (with timestamp)
- `--entity` filters to tokens issued to one participant
- 6 new integration tests

**Scope note, stated in `audit.rs`'s module doc**: this is a derived view over data already in the chain, not literally spec §11's `access_event` commit schema. The spec's schema carries `event_id`, `accessed_by_name`, and a `records_accessed` list — `accessed_by_name` needs the participant registry (Phase 5, not built), and `records_accessed` only matters once a single token can authorize more than the one write that consumes it, which single-use v1 tokens never do. Read-token presentation isn't tracked at all: there is no CLI-level read-access flow yet for an institution to actually present one against — that needs Phase 4/5 identity and Phase 6's API layer, not something to fake in the reference CLI.

### Phase 3 Complete

All three sessions of Phase 3 (issuance, enforcement, audit + revocation) are done. The full consent model — `loomed share`, `loomed commit --token`, `loomed revoke`, `loomed audit` — works end-to-end against real single-use write tokens, verified by a live smoke test: issue two tokens, exercise one via a real commit, revoke the other unused, confirm both show correctly in the audit trail.

### Test Count

| Crate | Before | After |
|---|---|---|
| `loomed-core` | 83 | 84 (+1 TokenRevocation RecordType test) |
| `loomed-cli` | 68 | 79 (+11: 5 revoke, 6 audit) |
| `loomed-crypto` | 17 | 17 |
| `loomed-store` | 18 | 18 |
| `loomed-sync` | 15 | 15 |
| **Total** | **201** | **213, 0 failures** |

---

## Phase 4-lite Session 1 ✅ Complete — Identity Provider Trait + Tier 0

R5 of the [First Release Plan](FIRST_RELEASE_PLAN.md). Spec §4.

### What Was Built

**`loomed-crypto` — new `identity.rs` module**:
- `IdentityProvider` trait — `sign()`, `public_key_hex()`, `tier()`. The tier-agnostic seam spec §4 calls for: every future identity tier (Tier 1 national ID, Tier 2 hardware enclave, Tier 3 Shamir quorum) implements the same trait, so call sites never change
- `PassphraseIdentityProvider` — the sole v1.0 implementation (Tier 0), wrapping the existing deterministic `derive_keypair`. Reports `tier() == "software_passphrase"`
- `mnemonic_from_seed()` / `seed_from_mnemonic()` — BIP-39 24-word recovery phrase generation and recovery. The mnemonic's 256-bit entropy *is* the ed25519 signing key seed directly (no intermediate hash), so recovery is a lossless round trip independent of the vault passphrase
- `LooMedKeypair::signing_key_bytes()` / `keypair_from_seed()` — expose and reconstruct the raw seed, scoped narrowly to mnemonic recovery per coding standards §0.4 (never logged or persisted outside the one-time display)
- Added `bip39` as a workspace dependency
- 9 new tests: determinism, tier reporting, sign/verify roundtrip via the trait, mnemonic round-trip, 24-word length, malformed/wrong-length phrase rejection, different seeds produce different phrases

**`loomed-cli` — `loomed init` displays a recovery mnemonic**:
- After deriving the keypair, `init.rs` generates the mnemonic from the signing key seed, prints it once inside a clearly marked banner, and requires the user to type `"yes"` before anything is written to disk — the confirmation gate is skipped automatically when `LOOMED_PASSPHRASE` is set (non-interactive/test mode), matching the existing passphrase-confirmation convention
- The mnemonic does not replace the passphrase as the day-to-day credential — it is an independent recovery path Phase 1 never had at all
- `vault.toml`'s `idp_type` and the genesis commit's payload were renamed from `"passphrase"` to `"software_passphrase"` throughout, matching the Tier 0 terminology introduced here (pre-1.0, so this is a clean rename, not a migration)

**`loomed-cli` — new `loomed key status` command**:
- Shows the vault's current identity tier and public key. No passphrase required — reads only plaintext `vault.toml`, same design principle as `loomed status`
- 3 new integration tests, plus 2 for the recovery phrase display (banner text, 24-word count, differs across vaults)

### Test Count

| Crate | Before | After |
|---|---|---|
| `loomed-cli` | 79 | 84 (+5: 2 recovery phrase, 3 key status) |
| `loomed-core` | 84 | 84 |
| `loomed-crypto` | 17 | 26 (+9 identity tests) |
| `loomed-store` | 18 | 18 |
| `loomed-sync` | 15 | 15 |
| **Total** | **213** | **227, 0 failures** |

---

## Phase 4-lite Session 2 ✅ Complete — Key Rotation

R6 of the [First Release Plan](FIRST_RELEASE_PLAN.md). Spec §12.1.

### The Design Problem This Session Had to Solve

A naive rotation — just deriving a new keypair from a new passphrase — breaks history: `Vault::read_commit` derives its AES-256 key from `argon2_salt` on every call, uniformly for the whole vault. If `argon2_salt` (or the passphrase feeding it) ever changed, every historical `.lmc` file encrypted under the old key would become permanently undecryptable — not a documented limitation, an actual regression. The plan's own text ("historical `.lmc` files stay encrypted under the original key") requires the encryption key to *never* change in v1.

**The fix**: decouple the signing key from the encryption key. `VaultMetadata` gained a new `signing_salt: Option<String>` field — `None` before any rotation (signing key derives from `argon2_salt`, identical to Phase 1), `Some(salt)` after a rotation (a freshly generated salt, independent of `argon2_salt`). `argon2_salt` itself is never touched, so the AES key — and every historical commit's readability — is untouched by rotation. This is additive and backward-compatible: existing vaults and every prior test needed zero changes.

The second problem this created: `verify_chain`/`verify_commit` previously took one public key applied uniformly to every commit. After a rotation, different chain segments are signed by different keys. Fixed by adding `resolve_signing_keys(commits, genesis_public_key)` to `loomed-core::verify` — it walks the chain forward, switching the active key whenever it crosses a `KeyRotation` commit whose payload carries `new_public_key` (the genesis commit's own `KeyRotation` payload only carries `public_key`, so it never triggers a switch). `verify_chain` uses this internally per-commit instead of one key for the whole chain; existing tests needed no changes since a chain with no rotation never switches keys.

### What Was Built

**`loomed-store`**:
- `VaultMetadata.signing_salt: Option<String>` (see above)
- `Vault::current_signing_salt()` — returns `signing_salt` if set, else falls back to `argon2_salt`
- `Vault::rotate_signing_key(new_public_key, new_signing_salt)` — updates only those two fields; `argon2_salt` is never touched
- 3 new tests: defaults to `argon2_salt` pre-rotation, rotation updates key+salt without touching `argon2_salt`, changes persist across `Vault::open`

**`loomed-core`**:
- `resolve_signing_keys()` in `verify.rs` (see above), exported from the crate root
- `verify_chain()` refactored to resolve one key per commit internally rather than taking a single uniform key
- 3 new tests: key switches after (not at) the rotation commit, a full chain spanning a rotation verifies end-to-end, a commit signed with the retired old key after rotation correctly fails

**`loomed-cli` — new `loomed key rotate` command** (`commands/key.rs`):
- Derives the current keypair via `current_signing_salt()` and confirms it matches `vault.metadata.public_key` before anything is written
- Generates a fresh random signing salt (before deriving the new keypair, per coding standards §0.5) and derives the new keypair from the *same* passphrase — the passphrase itself is never changed, since changing it would break AES decryption of history (see above)
- Writes a self-signed `key_rotation` commit: the OLD key signs, attesting to the NEW public key (payload: `old_public_key`, `new_public_key`, `idp_type`) — spec §12.1 step 3
- Updates `vault.toml` via `rotate_signing_key()`
- Scans the chain (reusing `token_chain::scan_all_tokens`, the same shared module Phase 3 built) for every still-active consent token and writes an explicit `token_revocation` commit for each, signed by the NEW key. This is deliberate and auditable, not just an incidental side effect of the old key no longer matching `vault.metadata.public_key` for signature checks
- `commit.rs`, `share.rs`, `revoke.rs` updated to derive their signing keypair via `current_signing_salt()` instead of `argon2_salt` directly, so a prior rotation is honoured by every command that signs

**`loomed-cli` — `loomed verify` made rotation-aware**:
- `verify --chain` now reads the genesis commit's own embedded public key (from its payload) as the chain's starting key, instead of `vault.metadata.public_key` — which reflects the *current* key after rotation and would be the wrong key to verify pre-rotation commits against
- `verify <commit_id>` (single-commit mode) now reads the full chain from genesis and uses `resolve_signing_keys` to find the key active at the target commit's position, since a single commit can no longer be verified in isolation once rotation exists
- Both paths share a new `load_full_chain()` helper (previously duplicated inline in `verify_full_chain`)

**Explicit v1 scope note** (`commands/key.rs` module doc, also printed by `loomed key rotate` itself): historical records remain encrypted under the original passphrase-derived key; vault re-encryption on rotation (spec §12.1 step 5) is not implemented — deferred past v1.0, per `FIRST_RELEASE_PLAN.md`. Rotation is patient-initiated and self-authorized only — no custodian quorum, no re-authentication tier, consistent with Tier 0.

### Test Count

| Crate | Before | After |
|---|---|---|
| `loomed-cli` | 84 | 91 (+7: 5 key rotate, 1 verify-across-rotation, 1 token revoked by rotation) |
| `loomed-core` | 84 | 87 (+3 rotation-aware verify tests) |
| `loomed-crypto` | 26 | 26 |
| `loomed-store` | 18 | 21 (+3 signing_salt/rotate tests) |
| `loomed-sync` | 15 | 15 |
| **Total** | **227** | **240, 0 failures** |

Phase 4-lite (R5+R6) is now complete: identity is a real trait with one honest Tier 0 implementation, recovery has an independent path, and rotation works end-to-end including token invalidation and cross-rotation chain verification — all without touching the AES encryption key, so nothing in history breaks.

---

## Phase 4 — Full Identity Provider (Tier 1–3) 🔵 Planned (post-v1.0)

**Spec:** §4, §12.

Deferred past v1.0 per `FIRST_RELEASE_PLAN.md`'s fast-follow roadmap. The `IdentityProvider` trait and Tier 0 implementation already exist (Phase 4-lite, above) — these slot in as new trait implementations with no call-site changes.

### What's Left

- Tier 1: National digital identity binding (Aadhaar OTP, eIDAS, etc.)
- Tier 2: Hardware secure enclave (Apple Secure Enclave, Android StrongBox, YubiKey)
- Tier 3: Shamir Secret Sharing custodian quorum recovery (3-of-5)
- Persisted encrypted key file (`.loomed/key.enc`) replacing passphrase-only derivation for Tier 1+
- Vault re-encryption on rotation (spec §12.1 step 5) — re-encrypt historical `.lmc` files under the new key so a rotation eventually retires the old AES key too, not just the signing key

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
