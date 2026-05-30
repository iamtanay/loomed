# LooMed Coding Standards

**Version 0.5** — aligned with `loomed-coding-standards-v0.5.docx`

This is the active coding standard for the LooMed protocol reference implementation. Follow it without exception. Any deviation from these standards — shortcuts, implicit behaviour, missing documentation — is a protocol violation, not a style preference.

---

## The Governing Principle

LooMed is a **protocol, not an application**. Every line of code is a promise to every developer who will ever implement, audit, or build on this protocol. Ambiguity in a medical data protocol has real consequences.

**Before committing anything, ask: would a developer at the Apache Software Foundation be comfortable merging this?**

---

## 0. Non-Negotiable Rules

### 0.1 The Phase System

Code is built in phases. Placeholders for future phases are acceptable if and only if they meet the TODO standard in §0.2.

| Phase | Scope |
|---|---|
| Phase 1 | Protocol core CLI — init, add, commit, log, show, verify ✅ |
| Phase 2 | Encrypted cloud vault + sync + conflict resolution |
| Phase 3 | Consent tokens + audit trail |
| Phase 4 | Identity provider abstraction + key rotation |
| Phase 5 | Participant registry + verification |
| Phase 6 | FHIR adapter + open source release |

### 0.2 TODO Standard

Every TODO must state exactly three things. A TODO missing any element is treated as missing documentation.

```rust
// TODO: In Phase 4, the keypair will be loaded from a persisted encrypted
// key file bound to the identity provider. The call site interface does
// not change — only the source of the key changes. See spec §4 and
// coding standards §0.1.
let keypair = loomed_crypto::derive_keypair(passphrase_bytes, &salt)?;
```

Required elements:
1. **What** the value/operation will be used for
2. **Which phase or command** will implement it
3. **The spec section reference**

### 0.3 The Suppression Rule

`let _ =` is permitted only with a documented TODO explaining why. Blind suppression is rejected.

```rust
// ✅ Correct
let _ = &vault; // Phase 4: vault metadata used to load persisted key. See spec §4 and coding standards §0.1.

// ❌ Rejected
let _ = &vault;
```

### 0.4 Private Key Handling

**The private key must never be written to disk in plaintext. Ever. In any phase.**

- Phase 1: derived in memory from passphrase + salt via `derive_keypair()`. Not persisted.
- Phase 4: encrypted with AES-256-GCM before writing, bound to IdP.

Any code that writes a raw private key to disk in any format is a critical security violation.

### 0.5 Deterministic Keypair Derivation — Phase 1

The salt must be generated or loaded **before** the keypair is derived. This ordering is mandatory and must be documented at the call site.

```rust
// ✅ Correct — salt before keypair
let mut salt_bytes = [0u8; 16];
rand::rngs::OsRng.fill_bytes(&mut salt_bytes);
let keypair = loomed_crypto::derive_keypair(passphrase_bytes, &salt_bytes)?;

// ❌ Rejected — keypair before salt
let keypair = generate_keypair(); // non-deterministic, won't verify
```

### 0.6 Fail Fast Before Credentials

Any command that requires a passphrase must verify all preconditions and validate all inputs **before** prompting for credentials. The user must never be asked for their passphrase only to be told nothing can be done.

```rust
// ✅ Correct
if !commit_id.starts_with("sha256:") {
    return Err("commit IDs must begin with sha256:".into());
}
let vault = Vault::open(&current_dir)?;
let passphrase = commands::read_passphrase("vault passphrase: ")?;

// ❌ Rejected
let passphrase = commands::read_passphrase("vault passphrase: ")?;
let staged = read_staged(&vault_dir)?.ok_or("nothing staged.")?;
```

### 0.7 Passphrase Reading

All commands that need the passphrase must call `commands::read_passphrase()`. Never call `rpassword::prompt_password()` directly. `read_passphrase()` checks `LOOMED_PASSPHRASE` env var first (non-interactive/test mode), then falls back to rpassword.

```rust
// ✅ Correct
let passphrase = super::read_passphrase("vault passphrase: ")?;

// ❌ Rejected
let passphrase = rpassword::prompt_password("vault passphrase: ")?;
```

---

## 1. Crate Boundaries (Hard Walls)

```
loomed-crypto   — only place cryptography lives (no loomed deps)
loomed-core     — protocol types and logic; zero I/O, zero disk access
loomed-store    — only place file I/O lives
loomed-cli      — thin arg-parsing wrapper; zero business logic
```

These boundaries are enforced by the Cargo dependency graph. Blurring them breaks auditability.

---

## 2. Workspace Dependency Management

All dependency versions declared once at workspace root. Individual crates inherit from workspace.

```toml
# Correct
[dependencies]
serde = { workspace = true }

# Never pin a version in a crate-level Cargo.toml directly
```

---

## 3. Documentation Standards

Every public item carries a Rustdoc comment. Undocumented public API is a protocol violation.

### Module-level doc

```rust
//! # loomed-core
//!
//! ## Responsibilities
//! - Commit struct definition and serialisation (spec §6)
//!
//! ## Not Responsible For
//! - Disk I/O (see `loomed-store`)
```

### Function doc

```rust
/// Verifies the integrity of a single commit.
///
/// # Arguments
/// * `commit` — The commit to verify.
/// * `author_public_key` — The ed25519 public key as "ed25519:<hex>".
///
/// # Returns
/// A [`CommitVerification`] with hash and signature results.
///
/// # Errors
/// * [`LooMedError::SerializationFailed`] — Commit could not be serialised.
///
/// See spec §7.
```

Every public function documents: what it does, every parameter, the return value, and every error it can return, with spec section references.

---

## 4. Error Handling

```rust
// ❌ Never
let value = some_option.unwrap();

// ✅ Always
let value = some_option.ok_or(LooMedError::MissingField { field: "name" })?;
```

- `unwrap()`, `expect()`, `panic!()` are forbidden outside `#[cfg(test)]` blocks
- Each crate defines its own typed error enum using `thiserror`
- Every variant is a distinct named type — no catch-all strings
- `anyhow` is not used in protocol code

---

## 5. Type Standards

### Protocol identifiers are newtypes — never raw strings

```rust
pub struct CommitHash(pub String);
pub struct ParticipantId(pub String);
pub struct ContentHash(pub String);
pub struct TokenId(pub String);
```

This prevents mixing up a `CommitHash` with a `ParticipantId` at compile time.

### Typed fields are enums — never strings

`RecordType`, `ParticipantType`, `AuthorizationRef` — all enums. A field with a fixed set of valid values is never a `String`.

---

## 6. Testing Standards

### Tests are specification tools

Every test documents a protocol rule. The name states the rule. The body proves it.

```rust
/// Spec §7: Tampering with the message must cause hash verification to fail.
#[test]
fn tampered_message_fails_hash_verification() { ... }

/// Spec §6.1: The genesis commit must have previous_hash set to None.
#[test]
fn genesis_commit_has_no_previous_hash() { ... }
```

### Integration tests use `TempDir` — never the real vault

```rust
fn temp_dir() -> TempDir {
    tempfile::tempdir().unwrap()
}
```

Tests must never read from or write to the real `.loomed/` vault directory.

### CLI integration tests use `LOOMED_PASSPHRASE`

```rust
Command::cargo_bin("loomed")
    .unwrap()
    .current_dir(dir.path())
    .env("LOOMED_PASSPHRASE", "testpass99")
    .arg("commit")
    .assert()
    .success();
```

### Coverage requirements

- Every error variant has at least one test that triggers it
- Every public function has a happy-path test and one test per documented error condition
- Cryptographic operations are tested for determinism
- File I/O is tested with `tempfile` — never against the real vault

---

## 7. Serialisation Standards

### Field names match the spec exactly

JSON field names must match the LooMed specification schema exactly. No renaming, no camelCase, no abbreviation. Snake_case serialises correctly by default.

### Optional fields are omitted — never `null`

```rust
// ✅ Correct — absent field is omitted from JSON entirely
#[serde(skip_serializing_if = "Option::is_none")]
pub device_id: Option<String>,

// ❌ Rejected — absent field serialised as null
pub device_id: Option<String>,  // missing attribute
```

Every `Option<T>` field in any serialised struct must carry `#[serde(skip_serializing_if = "Option::is_none")]`. A `null` value does not exist in the LooMed protocol.

---

## 8. Git Commit Standards

Conventional Commits format, scoped to the affected crate:

```
feat(loomed-cli): add loomed show <commit_id> command
fix(loomed-core): omit absent optional payload fields from JSON per §7.2
test(loomed-store): add vault integration tests with full lifecycle
test(loomed-crypto): add deterministic keypair derivation tests
docs(loomed-core): add spec references to CommitHash and ContentHash
```

Types: `feat`, `fix`, `docs`, `chore`, `test`, `refactor`, `spec`

---

## 9. Session Checklist

Before marking any session's work complete:

- [ ] `cargo build` with zero errors and zero warnings
- [ ] `cargo test --workspace` — all tests pass
- [ ] Every new public item has Rustdoc
- [ ] Every new type/function references the spec section it implements
- [ ] No `unwrap()` or `expect()` outside `#[cfg(test)]`
- [ ] Every TODO has purpose + phase + spec reference
- [ ] No blind `let _ =` suppressions
- [ ] Salt generated before keypair derivation at every call site
- [ ] Preconditions validated before passphrase prompts
- [ ] No private key material written to disk
- [ ] `loomed verify --chain` passes on a fresh vault
- [ ] `loomed verify --chain` exits with code 1 after tampering with a `.lmc` file
- [ ] New commands that read a passphrase call `commands::read_passphrase()`, not `rpassword` directly
