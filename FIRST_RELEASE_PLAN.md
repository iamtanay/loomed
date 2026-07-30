# LooMed — First Release Plan (v1.0, closes at Phase 6)

This document defines the trimmed critical path from where we are now (Phase 2 Session 2 complete) to a tagged, public v1.0 release. It is separate from `PLAN.md`. `PLAN.md` remains the full phase roadmap and the session-by-session build log — every session executed under this plan still gets logged there as it always has. This document exists to answer one question: **what is the minimum real, honest, spec-faithful scope that gets us to Phase 6 fastest, and what do we explicitly cut to a post-release fast-follow?**

Nothing in this plan lowers the bar from `.claude/coding-standards.md`. Trimming scope means shipping fewer features completely, never shipping a feature partially. A cut item is not built at all in v1 — it is not built badly.

---

## What "Release" Means

A tagged `v1.0.0`, public repository, with:

- Every command in the CLI surface working end-to-end and spec-conformant for the scope below
- A conformance test suite third parties can run against their own implementation
- Governance docs (LICENSE, CONTRIBUTING, CLA, CODE_OF_CONDUCT)
- `CHANGELOG.md` and a real version tag
- A README written for external readers, not just us

This is Phase 6's own definition in `PLAN.md` — we are not inventing a new bar, just sequencing everything else to arrive there as directly as possible.

---

## The Big Scope Call: Identity Provider

Full Phase 4 as specced is three tiers: national digital ID binding (Aadhaar/eIDAS), hardware secure enclave, and Shamir custodian quorum recovery. None of these are buildable to a real, non-theatrical standard in a first release — Tier 1 needs a live government IdP integration we don't have access to, Tier 2 needs per-platform secure-enclave bindings, Tier 3 needs a live custodian network. Building fake versions of these would violate the project's own bar ("would an ASF developer be comfortable merging this?") more than not building them at all.

**v1 ships a real but narrower identity model: Tier 0 — Software Custody.**

- Formalize the `IdentityProvider` trait now (in `loomed-crypto`), so the abstraction the spec calls for actually exists in the type system — not deferred as a TODO comment, but present with exactly one honest implementation.
- `PassphraseIdentityProvider` — wraps the existing deterministic `derive_keypair(passphrase, salt)`. This is what Phase 1 already does; formalizing it behind the trait costs little and means Tier 1/2/3 slot in later as new trait impls with no call-site changes, exactly as `ARCHITECTURE.md` already promises.
- **Recovery mnemonic at `loomed init`**: generate a BIP-39 mnemonic (12 or 24 words) as an independent recovery path, displayed once, with an explicit user confirmation step before the vault is finalized. This is new — Phase 1 has no recovery path at all if the passphrase is forgotten. The mnemonic recovers the keypair independent of remembering the passphrase; it does not replace the passphrase as the day-to-day credential.
- **`loomed key rotate`**: writes a self-signed `key_rotation` commit (old key signs, attesting to the new public key), per spec §12.1 step 3. No custodian quorum, no re-authentication tier — rotation is patient-initiated and self-authorized only. This is enough to recover from a suspected passphrase compromise.
- **Explicitly out of v1, documented as such in the release notes**: vault re-encryption on rotation (§12.1 step 5 — historical `.lmc` files stay encrypted under the original key; only the signing key rotates), Tier 1 national ID binding, Tier 2 hardware enclave binding, Tier 3 Shamir quorum recovery.

This is a real, spec-referenced, testable slice — not a stub. It just claims exactly what it is: single-factor software custody with a documented recovery path, clearly labeled as the v1 identity tier with stronger tiers coming post-release.

---

## What's IN v1 vs Deferred

| Area | In v1 | Deferred (post-release fast-follow) |
|---|---|---|
| Sync | Push/pull/status/resolve (done) | — |
| Consent | Token issuance, single-use + expiry enforcement, scopes `full_record` / `record_type:<type>` / `commit:<id>`, audit log, revocation | Scope `date_range:<from>:<to>` (adds little for v1, meaningfully more validation surface) |
| Identity | Tier 0 passphrase + mnemonic recovery + self-signed key rotation | Tier 1 (national ID), Tier 2 (hardware enclave), Tier 3 (Shamir quorum), vault re-encryption on rotation |
| Registry | Full participant ID generation (base32 + CRC-8), local unverified registry (`loomed participant add/show`) | External verification against real bodies (NMC, NABH) — depends on third parties we don't control |
| Interop | — | `loomed-fhir` (FHIR R4 / HL7 v2 / ABDM adapters) — explicitly an application layer per `ARCHITECTURE.md`, not required to call the protocol itself released |
| Release engineering | Governance docs, CLA, CHANGELOG, `loomed-conformance` suite, versioned tag | — |

Every deferred item gets its own tracked entry in `PLAN.md`'s roadmap after v1.0 ships — this plan does not delete scope, it sequences it after the tag.

---

## Session Plan

Numbering continues from where `PLAN.md` left off (Phase 2 Session 2 complete, 154 tests passing). Each session is a coherent, testable vertical slice, consistent with how every prior session has been scoped.

### R1 — Phase 2 Session 3 ✅ Complete (already scoped in `PLAN.md`)
- Payload summary line in `loomed log`
- `sync_metadata` pre-rebase field display in `loomed show`
- Full participant ID validation: base-32 charset + CRC-8 checksum on `ParticipantId::new()`
- This also lays the groundwork for R9 (participant ID generation reuses the same checksum logic)
- **Scope note surfaced during implementation**: the spec's example participant IDs turned out to be illustrative, not real checksums — regenerating them rippled into every crate's test fixtures plus `README.md`/`CLAUDE.md`. Full detail logged in `PLAN.md`'s Phase 2 Session 3 entry. 161 tests passing, 0 failures.

### R2 — Consent Token Issuance ✅ Complete (Phase 3, part 1)
- `ConsentToken` commit type wired into `loomed-core`
- `loomed share <participant_id> --scope <scope> --duration <hours> --purpose <purpose> [--access-type read|write]`
- Signed by patient key, written as a `consent_token` commit for auditability
- Scopes: `full_record`, `record_type:<type>`, `commit:<id>` (date_range deferred)
- Added `--access-type` beyond the spec §20 CLI signature — otherwise there'd be no way to issue a write token at all, and R3 needs one to test enforcement against
- **Caught during implementation**: an early cut validated everything except `duration_hours` before the passphrase prompt, which hung `cargo test` on the fail-fast test for it (blocked on a passphrase read with no terminal attached). Fixed before landing — full detail in `PLAN.md`'s Phase 3 Session 1 entry. 183 tests passing, 0 failures.

### R3 — Consent Token Enforcement (Phase 3, part 2)
- `loomed commit --token <token_id>` path for non-patient participants writing under a token
- Token validated against: signature, expiry, scope, single-use state
- Every commit written under a token carries `AuthorizationRef::ConsentToken { token_id }`
- Token marked `used: true` on first presentation, permanently, regardless of remaining validity window

### R4 — Audit Trail + Revocation (Phase 3, part 3)
- Every token presentation writes an immutable `access_event` commit
- `loomed audit` / `loomed audit --entity <participant_id>`
- `loomed revoke <token_id>` — invalidates an active token before expiry

### R5 — Identity Provider Trait + Tier 0 (Phase 4-lite, part 1)
- `IdentityProvider` trait in `loomed-crypto`
- `PassphraseIdentityProvider` implementation wrapping existing `derive_keypair`
- BIP-39 recovery mnemonic generated and displayed at `loomed init`, with explicit confirmation gate
- `loomed key status` — shows current tier (`software_passphrase` for v1) and public key

### R6 — Key Rotation (Phase 4-lite, part 2)
- `loomed key rotate` — self-signed `key_rotation` commit
- Invalidates active consent tokens issued under the old key (ties into R4's token store)
- Explicit doc note (README + `loomed key status` output) that historical `.lmc` files remain encrypted under the pre-rotation key — re-encryption is a documented post-v1 item, not silently skipped

### R7 — Participant Registry, Local + Unverified (Phase 5-lite)
- `loomed-registry` crate (new)
- `loomed participant add --type <type>` / `loomed participant show <id>`
- Participants are stored and displayed with an explicit `verification: unverified` status field — the field exists now so Phase 5's real external verification is additive later, not a breaking change

### R8 — Conformance Suite + Governance Docs (Phase 6, part 1)
- `loomed-conformance` crate: a runnable suite covering commit hashing/signing rules, chain linkage, Sync Rebase determinism, and consent token lifecycle rules — the rules any third-party implementation must satisfy to interoperate
- `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, CLA
- `CHANGELOG.md` seeded with the full history from Phase 1 through here

### R9 — Release Cut (Phase 6, part 2)
- Full regression pass across all crates
- README rewritten for an external, public audience (currently internal-facing)
- Version tag `v1.0.0`
- Explicit "Identity Model" and "Known Limitations" sections in the public README, pointing at this plan's deferred list so nobody mistakes Tier 0 for the full spec

**Total: 9 sessions from today to a tagged v1.0**, versus 4 full phases (3, 4, 5, 6) if built to the unabridged spec. The reduction comes almost entirely from the identity tier cut and deferring external verification and FHIR/HL7 — both of which depend on integrations outside our control anyway, so deferring them isn't just faster, it removes a dependency on third parties from the release-blocking path entirely.

---

## Post-v1 Fast-Follow Roadmap

Tracked in `PLAN.md` once v1.0 ships, in priority order:

1. Vault re-encryption on key rotation (§12.1 step 5)
2. Consent scope `date_range:<from>:<to>`
3. Tier 1 IdP — national digital identity binding
4. External participant verification (NMC, NABH) — Phase 5 completion
5. Tier 2 IdP — hardware secure enclave
6. `loomed-fhir` — FHIR R4 / HL7 v2 / ABDM adapters
7. Tier 3 IdP — Shamir custodian quorum recovery
