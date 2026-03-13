# LooMed

**Patient-owned medical records. Cryptographically signed. Append-only. Yours.**

LooMed is an open protocol for medical records that belong to the patient — not the hospital, not the lab, not the insurer. Every record is signed, chained, and encrypted. Nothing is ever edited or deleted. Access requires your explicit consent.

Think of it as Git for your medical history.

---

## The Problem

Your medical records are scattered across every hospital and lab you have ever visited. You cannot take them with you. You cannot verify they have not been altered. You cannot control who reads them. The institution owns the data about your body.

LooMed flips this.

---

## How It Works

Every medical event — a lab result, a prescription, a diagnosis — becomes a **commit**. Commits are:

- **Signed** with your ed25519 private key
- **Chained** via SHA-256 hashes, forming a tamper-evident ledger
- **Encrypted** with AES-256-GCM before touching disk
- **Yours** — no institution can read or write without a token you issue

The result is an append-only medical history that any participant can verify but only you can authorise.

```
genesis commit (vault initialised)
    ↓
commit: fasting blood glucose  [sha256:2633f1...]
    ↓
commit: type 2 diabetes        [sha256:220e69...]
    ↓
HEAD
```

Tamper with any commit and every commit that follows it fails verification. Instantly detectable by anyone running `loomed verify --chain`.

---

## Cryptography

| Purpose | Algorithm |
|---|---|
| Commit identity | SHA-256 hash chain |
| Payload integrity | BLAKE3 |
| Authorship | Ed25519 signatures |
| Key derivation | Argon2id |
| Encryption at rest | AES-256-GCM |

No custom cryptography. No novel constructions. Every primitive is a well-audited, widely deployed standard.

---

## CLI — Phase 1

```bash
# Initialise a new patient vault
loomed init

# Stage a medical record
loomed add --type lab_result -m "fasting blood glucose"
loomed add --type diagnosis -m "type 2 diabetes"
loomed add --type prescription -m "metformin 500mg"
loomed add --type vaccination -m "COVID-19 dose 1"

# Sign and commit the staged record
loomed commit

# View full history
loomed log

# Inspect a specific commit
loomed show sha256:<commit_id>

# Verify a single commit's integrity
loomed verify sha256:<commit_id>

# Verify the entire hash chain
loomed verify --chain
```

Record types: `lab_result` · `prescription` · `radiology_report` · `vaccination` · `diagnosis` · `procedure`

---

## Vault Structure

```
.loomed/
  vault.toml          ← non-sensitive metadata (patient ID, public key, salt)
  commits/
    sha256:<hash>.lmc ← one encrypted commit file per record
  HEAD                ← commit_id of the latest record
```

Every `.lmc` file is AES-256-GCM encrypted JSON. The key is derived from your passphrase via Argon2id. The infrastructure provider stores only ciphertext.

---

## Getting Started

**Prerequisites:** Rust 1.75+

```bash
git clone https://github.com/iamtanay/loomed
cd loomed
cargo build --release
```

Then add the binary to your PATH and run:

```bash
loomed init
```

You will be prompted for a participant ID and a passphrase. Your vault is created locally. No network connection required.

---

## Participant IDs

Every actor in LooMed has a typed, permanent identifier:

| Type | Example | Description |
|---|---|---|
| Patient | `LMP-7XKQR2MNVB-F4` | Vault owner |
| Clinician | `LMD-APL-3NKWQ7HZRC-8A` | Doctor at Apollo |
| Institution | `LMI-APL-2MVZK9QXBT-C2` | Apollo Hospitals |
| Device | `LMV-ROCHE-5QNZK8MXBT-D7` | Roche analyser |
| Government | `LMG-AIIMS-4KZQR9WMNV-B3` | AIIMS Delhi |

Patient IDs carry no personally identifiable information at the protocol level.

---

## Workspace

```
crates/
  loomed-crypto/   ← hashing, signing, encryption, key derivation
  loomed-core/     ← protocol types, commit builder, chain verifier
  loomed-store/    ← encrypted vault storage, file I/O
  loomed-cli/      ← CLI binary, thin wrapper over the above
```

Each crate has one job. `loomed-crypto` has no LooMed dependencies. `loomed-core` has no I/O. The dependency graph is strict and documented.

---

## Test Coverage

```
loomed-core    24 tests — commit types, builder, chain verifier, participant IDs
loomed-crypto  17 tests — hashing, signing, encryption, key derivation, determinism
loomed-store   18 tests — staged records, vault lifecycle, encryption roundtrips
─────────────────────────────────────────────────────────────────────────────
Total          59 tests, 0 failures
```

```bash
cargo test
```

---

## Roadmap

| Phase | Status | Description |
|---|---|---|
| Phase 1 | ✅ Complete | Local vault — init, add, commit, log, show, verify |
| Phase 2 | 🔜 Next | Encrypted cloud sync, offline-first, conflict resolution |
| Phase 3 | 🔵 Planned | Consent tokens — time-bound, single-use, patient-signed |
| Phase 4 | 🔵 Planned | Identity provider abstraction, key rotation |
| Phase 5 | 🔵 Planned | Participant registry, clinician and institution verification |
| Phase 6 | 🔵 Planned | FHIR / HL7 adapter, open source release |

---

## Design Principles

- **Append-only.** Nothing is ever edited or deleted. Corrections are new commits.
- **Patient consent required.** No institution reads or writes without a token you issue.
- **Offline-first.** Records are created and signed locally. Sync is eventual.
- **No PII at the protocol level.** Your name and demographics live only inside your encrypted vault.
- **Open protocol, not a platform.** Anyone can implement it, extend it, or build on it.

---

## Contributing

LooMed is in active early development. The protocol specification is in `LooMed_V0_2.pdf`. Coding standards are in `loomed-coding-standards-v0.4.docx`.

If you want to contribute, read the spec first. Every function references the section it implements. Every test names the rule it proves.

---

## Licence

Apache 2.0 — LooMed by Baniloo