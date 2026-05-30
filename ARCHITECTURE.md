# LooMed — Vibe Coding Architecture

This document is the working mental model for building LooMed. Read it before writing any code. It exists so that every session starts from the same understanding of what we are building, why the codebase is shaped the way it is, and what constraints are non-negotiable.

---

## The Mental Model

LooMed is not an app. It is an open protocol — comparable in ambition to Git or HTTP. The reference implementation is a Rust CLI (`loomed`). That CLI is the protocol made executable.

Every decision flows from this: **we are writing a protocol, not a product.** Code that is clever, implicit, or shortcuts correctness is wrong — not because of aesthetics, but because a medical data protocol that is ambiguous has real consequences for real patients.

The guiding question before every code change: **would a developer at the Apache Software Foundation be comfortable merging this?**

---

## The Stack in One Picture

```
Applications (hospital dashboards, mobile apps, insurance, research tools)
     ↑
API Layer (GraphQL / REST) — not yet built
     ↑
LooMed Protocol Core (loomed-core + loomed-crypto)
     ↑
Cryptographic Storage Engine (loomed-store)
     ↑
Identity Provider Abstraction Layer (Phase 4 — passphrase in Phase 1)
     ↑
Patient-Controlled Vault (local .loomed/ now, cloud in Phase 2)
```

---

## Crate Responsibilities (Hard Boundaries)

```
loomed-crypto   — the only place cryptography lives
loomed-core     — protocol types and logic; zero I/O, zero disk
loomed-store    — the only place file I/O lives
loomed-cli      — thin arg-parsing wrapper; zero business logic
```

These are hard walls. `loomed-core` importing `loomed-store` is wrong. A hash function living in `loomed-store` is wrong. Any blurring of these lines breaks the separation that makes LooMed auditable and portable.

---

## The Commit as the Atomic Unit

Every medical event — a lab result, a prescription, a diagnosis — becomes a **commit**. A commit is:

- **Signed** — ed25519 signature by the author's private key
- **Hashed** — `commit_id = SHA256(commit JSON with commit_id field set to "")`. The hash is over the whole object.
- **Content-addressed** — `content_hash = BLAKE3(payload JSON)`. Payload can be verified independently.
- **Chained** — `previous_hash` links every commit to its predecessor, forming a tamper-evident ledger
- **Encrypted at rest** — AES-256-GCM, key derived from passphrase via Argon2id; infrastructure stores only ciphertext

The genesis commit has `previous_hash: null`. Every subsequent commit's `previous_hash` is the `commit_id` of the commit before it.

**The finalisation order matters:**
1. Assemble commit with `commit_id = ""` and `signature = ""`
2. Serialize to canonical JSON → these bytes are signed
3. Embed signature
4. Serialize again with signature embedded → SHA-256 these bytes → this is the `commit_id`

Getting this order wrong breaks verification. The code in `loomed-core/src/builder.rs` implements it exactly.

---

## Phase 1 Key Model (Critical to Understand)

There is no private key file on disk. The signing keypair is derived **deterministically** every time it's needed:

```
passphrase (user input) + argon2_salt (vault.toml) → Argon2id → 32 bytes → ed25519 SigningKey
```

The same passphrase + same salt = same keypair, always. This is why `loomed verify --chain` works in Phase 1 without any key persistence: the public key stored in `vault.toml` was derived the same way.

**The salt must exist before the keypair is derived.** This is a required ordering constraint documented at every call site.

In Phase 4, `derive_keypair()` is replaced by loading a persisted encrypted key file. The call sites (`init.rs`, `commit.rs`, `show.rs`, `verify.rs`) do not change. Only the source of the key changes.

---

## The Vault on Disk

```
.loomed/
  vault.toml          — plaintext: patient_id, public_key, argon2_salt, protocol_version, idp_type
  commits/
    <hex>.lmc         — AES-256-GCM encrypted JSON, one file per commit, filename is hash without "sha256:" prefix
  HEAD                — plaintext: "sha256:<hex>" of the most recent commit
  staged.json         — plaintext: StagedRecord JSON, present only between `loomed add` and `loomed commit`
```

`vault.toml` is not sensitive — it contains no medical data, no private key. The salt is there because it is needed to decrypt. The public key is there because it is needed to verify.

`.lmc` files are ciphertext. The infrastructure provider (cloud, local disk) can store them without reading them.

---

## The Add → Commit → Verify Flow

```
loomed add --type lab_result -m "fasting glucose"
  → validates record type
  → opens vault (to confirm it exists)
  → writes .loomed/staged.json (plaintext, transient)

loomed add -i --type lab_result -m "fasting glucose"
  → validates record type first (before vault open, before any prompts)
  → prompts for all §9 payload fields interactively
  → serializes typed payload via RecordPayload::to_value()
  → writes .loomed/staged.json

loomed commit
  → opens vault
  → checks staged.json exists (fail-fast: if nothing staged, error before passphrase prompt)
  → reads passphrase (LOOMED_PASSPHRASE or rpassword)
  → reads HEAD → previous_hash
  → derives keypair (passphrase + argon2_salt)
  → calls builder::prepare() → gets PendingCommit with canonical_bytes
  → signs canonical_bytes → signature string
  → calls pending.finalise(signature) → Commit with real commit_id
  → vault.write_commit() → serialize → encrypt → write .lmc → update HEAD
  → clears staged.json

loomed verify --chain
  → opens vault
  → reads passphrase
  → reads all commit IDs from commits/
  → reads HEAD, traverses chain from HEAD to genesis
  → passes genesis-first slice to verify_chain()
  → verify_chain() checks: hash validity, signature validity, previous_hash linkage
  → prints per-commit result and overall verdict
  → exits with code 1 if any failure
```

---

## Consent Model (Phase 3 — Not Yet Built)

The token model is already type-defined in `commit.rs` (`AuthorizationRef`, `TokenId`). The mechanism is:

- Patient issues a `ConsentToken` — signed, single-use, time-bounded, scoped
- Token grants either `read` or `write` access (never both from one token)
- Every commit written under a token carries `AuthorizationRef::ConsentToken { token_id }`
- Every access is logged as an immutable `access_event` commit
- Token is permanently marked `used: true` after first presentation

Currently all commits carry `AuthorizationRef::SelfAuthored`. The type system is ready; the enforcement layer is Phase 3.

---

## Sync Model (Phase 2 — Not Yet Built)

LooMed is offline-first. Records are created locally without network. When two participants commit offline against the same `previous_hash`, a fork is created. The Sync Rebase algorithm resolves it:

1. Detect fork: two commits share the same `previous_hash`
2. Sort the conflicting commits by timestamp (ascending), then by `commit_id` (lexicographic tiebreaker for ±60s clock skew)
3. Re-link sequentially, updating `previous_hash` values
4. Recompute `commit_id` for shifted commits (since `previous_hash` changed)
5. Preserve original `previous_hash` and `commit_id` in `sync_metadata` for audit traceability
6. Original signature is preserved — it remains valid against the original content

`SyncMetadata` in every commit already carries the fields for this: `pre_sync_previous_hash`, `pre_sync_commit_id`, `created_offline`, `synced_at`.

---

## Record Types and Payload Schemas

Six record types are fully implemented (spec §9):

| Type | Key Fields |
|---|---|
| `lab_result` | `test_name`, `value`, `unit`, `reference_range`, `status` |
| `prescription` | `drug_name`, `dosage`, `frequency`, `duration_days`, `instructions` |
| `radiology_report` | `modality`, `findings`, `impression`, `radiologist_id`, `external_ref` (required) |
| `vaccination` | `vaccine_name`, `batch_number`, `dose_number`, `total_doses` |
| `diagnosis` | `condition`, `icd_code`, `severity`, `onset`, `status`, `supporting_refs` |
| `procedure` | `procedure_name`, `anaesthesia`, `duration_minutes`, `outcome`, `team` |

**Raw imaging files are never stored.** `RadiologyReportPayload` always carries an `ExternalRef` pointing to the custodian institution. This is a first-class design decision, not a limitation.

All `Option<T>` fields carry `#[serde(skip_serializing_if = "Option::is_none")]`. Absent optional fields are omitted from JSON — never `null`. This is spec §7.2 and is non-negotiable.

---

## What the Future Looks Like

The spec defines the full protocol. The implementation is currently at Phase 1 with 5 phases remaining:

| Phase | Spec Sections | Rust Crates Affected |
|---|---|---|
| Phase 2 — Cloud sync | §5, §8 | `loomed-store`, new `loomed-sync` |
| Phase 3 — Consent tokens + audit | §10, §11 | `loomed-core`, `loomed-cli` |
| Phase 4 — IdP + key rotation | §4, §12 | `loomed-crypto`, `loomed-store`, `loomed-cli` |
| Phase 5 — Participant registry | §3, §4.4 | new `loomed-registry` |
| Phase 6 — FHIR/HL7 adapter | §13 | new `loomed-fhir` |

Every `// TODO:` comment in the codebase references the phase that will replace it. The call site interface is designed not to change — only the implementation behind it.

---

## Non-Negotiable Protocol Rules

These are invariants. Breaking them breaks the protocol.

1. **Nothing is ever edited or deleted.** Corrections are new commits. Retractions are `record_type: retraction` commits that reference the original.
2. **Every commit is signed.** No unsigned commit enters the vault.
3. **The hash chain is linear.** Every commit's `previous_hash` must equal the `commit_id` of the commit before it.
4. **The genesis commit has `previous_hash: null`.** There is exactly one genesis per vault.
5. **No PII at the protocol level.** Patient IDs contain no name, date of birth, or demographics. Those live only inside the encrypted vault.
6. **No private key on disk in plaintext.** Ever. In any phase.
7. **Tokens are single-use.** A presented token is permanently invalidated regardless of expiry.
8. **Fail fast before passphrase.** Validate all inputs, check all preconditions, then ask for credentials. Never the other way around.
