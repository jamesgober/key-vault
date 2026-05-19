# key-vault - Production Roadmap to 1.0

> The engineering contract that takes `key-vault` from `0.1.0` scaffold to `1.0.0` stable.
>
> Reads: `REPS.md` (supreme authority), `_strategy/UNIVERSAL_PROMPT.md`, `.dev/DIRECTIVES.md`, `.dev/PROMPT.md`.
>
> Target ship date: **4-5 focused weeks**.
> Status: Phase 0.1.0 complete (scaffold). Phase 0.2.0 next.

---

## The 1.0 contract

When `key-vault 1.0.0` ships, it commits to:

### Functional contract

- `KeyVault` - main vault type with builder API
- `KeyHandle` - opaque reference, never exposes raw bytes
- `KeyAcquirer` trait with 4 built-in implementations (Keychain, File, Env, TPM)
- `ScatterStrategy` trait with 4 built-in implementations
- Memory protection: mlock + zeroize + page guards
- Master key recovery
- Atomic key rotation
- Multi-key vaults
- Cross-platform parity (Linux, macOS, Windows)

### Performance contract

| Operation | Target |
|-----------|--------|
| Vault creation, empty | <100us |
| Acquisition from keychain | <10ms |
| Acquisition from file | <1ms |
| Key access (reassembly) | <1us |
| Concurrent reads same handle | no degradation |
| Memory overhead per key | <16 KiB |

### Security contract

- Zero unsafe code in public API
- Constant-time comparisons everywhere keys are compared
- mlock prevents swap to disk
- zeroize wipes memory on drop
- Fuzz testing clean for 1 CPU-hour per acquirer
- `cargo audit` and `cargo deny check` clean
- Threat model documented in `docs/SECURITY.md`

### Stability contract

- Public API frozen for v1.x lifetime
- MSRV 1.75
- Edition 2024
- Apache-2.0 OR MIT dual licensed

---

## Phase 0.1.0 - Scaffold (complete)

- [x] Repository created on GitHub
- [x] Topics set (10 keywords)
- [x] Cargo.toml with full feature flag plan
- [x] REPS.md canonical
- [x] LICENSE-APACHE + LICENSE-MIT
- [x] README, CHANGELOG, .editorconfig, .gitignore
- [x] rustfmt.toml, clippy.toml
- [x] src/lib.rs with REPS lints
- [x] tests/smoke.rs
- [x] benches/vault_bench.rs placeholder
- [x] PROMPT.md, DIRECTIVES.md, this ROADMAP.md
- [x] CI workflow

---

## Phase 0.2.0 - Foundation types + KeyHandle

**Goal:** Define the core types and the opaque KeyHandle. No real storage yet.

**Effort:** 4-5 days.

### Tasks

- [ ] Design `KeyHandle` - opaque reference type
  - Internal: handle ID (u64), reference to vault
  - Debug impl: prints "KeyHandle(<redacted>)"
  - No deserialization (handles are runtime-only)
- [ ] Design `KeyMetadata` - metadata about a key (algorithm hint, creation time, etc.)
- [ ] Design `Error` enum with thiserror, all variant types
- [ ] Design `Result<T>` type alias
- [ ] Define `KeyAcquirer` trait
- [ ] Define `ScatterStrategy` trait
- [ ] Define `KeyVault` struct (skeleton)
- [ ] Define `KeyVaultBuilder` (skeleton)
- [ ] Unit tests for KeyHandle opacity
- [ ] First doctest examples
- [ ] CHANGELOG updated

### Exit criteria

- [ ] All core types defined
- [ ] Smoke test passing
- [ ] No real storage yet (stubs are OK)
- [ ] CI green

---

## Phase 0.3.0 - StandardScatter + zeroize integration

**Goal:** First working scatter strategy with full zeroize/mlock integration.

**Effort:** 1 week.

### Tasks

- [ ] Implement `StandardScatter`:
  - Variable chunk sizes (1-8 bytes typical)
  - Variable chunk count (8-64 chunks)
  - Self-referential filler bytes
  - Per-scatter random seed
- [ ] Reassembly logic with `Zeroizing<Vec<u8>>` output
- [ ] `mlock`/`VirtualLock` integration (cross-platform)
- [ ] Zeroize on KeyVault drop
- [ ] Constant-time equality for KeyHandle
- [ ] Unit tests:
  - Scatter -> reassemble round-trip
  - Multiple scatters of same key produce different layouts
  - Memory cleared on drop
- [ ] Property tests (proptest) for scatter/reassemble invariants
- [ ] Linux: verify mlock works via /proc/self/status

### Exit criteria

- [ ] StandardScatter functional and tested
- [ ] mlock + zeroize verified working on all 3 platforms
- [ ] Round-trip property test passes

---

## Phase 0.4.0 - Additional scatter strategies + LayeredScatter

**Goal:** Three more scatter strategies + composition.

**Effort:** 4-5 days.

### Tasks

- [ ] Implement `InterleavedScatter`
- [ ] Implement `FragmentedScatter` (non-contiguous memory)
- [ ] Implement `LayeredScatter` (composes multiple strategies)
- [ ] Tests for each
- [ ] Cross-strategy benchmarks
- [ ] Documentation: comparison of strategies and their threat model coverage

### Exit criteria

- [ ] 4 scatter strategies functional
- [ ] Layered composition working
- [ ] Docs explain when to use each

---

## Phase 0.5.0 - Acquirer implementations

**Goal:** Built-in acquirers for the common sources.

**Effort:** 1 week.

### Tasks

- [ ] `EnvAcquirer` - environment variable
- [ ] `FileAcquirer` - encrypted file (using derived key from master)
- [ ] `KeychainAcquirer` - OS keychain via `keyring` crate
- [ ] `TpmAcquirer` (feature-gated) - Linux + Windows
- [ ] Acquirer error handling with thiserror
- [ ] Audit logging integration with `log-io`
- [ ] Cross-platform tests for keychain on Linux/macOS/Windows
- [ ] Integration tests (gated by env vars in CI)

### Exit criteria

- [ ] 3+ acquirers functional (TPM may stub if hardware unavailable)
- [ ] Real keychain integration verified
- [ ] Encrypted file format documented

---

## Phase 0.6.0 - Multi-key vaults + key rotation

**Goal:** Multiple named keys per vault, atomic rotation.

**Effort:** 3-4 days.

### Tasks

- [ ] Multi-key support (named keys with independent lifecycles)
- [ ] `KeyVault::rotate(name, new_key)` - atomic swap
- [ ] Concurrent access during rotation (lock-free reads)
- [ ] Master key concept for vault-level operations
- [ ] Master key recovery flow

### Exit criteria

- [ ] Multi-key vaults working
- [ ] Rotation atomic and verified concurrent-safe
- [ ] Master key recovery tested

---

## Phase 0.7.0 - Performance verification + tuning

**Goal:** Hit Performance Contract numbers via benchmarks.

**Effort:** 1 week.

### Tasks

- [ ] Comprehensive benchmark suite
- [ ] `benches/access_latency.rs`
- [ ] `benches/concurrent_access.rs`
- [ ] `benches/scatter_strategies.rs`
- [ ] `benches/memory_overhead.rs`
- [ ] Run on dev machine, commit baselines.json
- [ ] Compare against Performance Contract
- [ ] Tune as needed
- [ ] Allocation profile with dhat - zero allocation on hot path
- [ ] `docs/PERFORMANCE.md`

### Exit criteria

- [ ] All Performance Contract targets met
- [ ] Baselines committed
- [ ] PERFORMANCE.md complete

---

## Phase 0.8.0 - Fuzz testing + security hardening

**Goal:** Nuclear-proof security.

**Effort:** 4-5 days.

### Tasks

- [ ] Set up cargo-fuzz workspace
- [ ] Fuzz target for each acquirer (random inputs)
- [ ] Fuzz target for scatter strategies (random key bytes)
- [ ] Fuzz target for configuration parsing
- [ ] Run each for 1 CPU-hour minimum
- [ ] Fix any findings
- [ ] Security test: verify Debug doesn't leak (proptest)
- [ ] Security test: verify zeroize actually overwrites (dhat)
- [ ] Threat model document
- [ ] `docs/SECURITY.md`

### Exit criteria

- [ ] All fuzz targets clean
- [ ] No memory leak or persistence issues found
- [ ] SECURITY.md documents methodology and findings

---

## Phase 0.9.0 - Docs + Release Candidate

**Goal:** Final documentation and 1.0.0-rc.1.

**Effort:** 3-4 days.

### Tasks

- [ ] `docs/STABILITY-1.0.md`
- [ ] `docs/ARCHITECTURE.md` (vault internals, scatter algorithms, acquirer pattern)
- [ ] `docs/SECURITY.md` (threat model, defense layers, audit history)
- [ ] `docs/PERFORMANCE.md` (benchmarks, methodology)
- [ ] `docs/PLATFORM-NOTES.md` (Linux/macOS/Windows specifics)
- [ ] `docs/HARDWARE.md` (TPM 2.0, HSM, secure enclave integration notes)
- [ ] Audit every public item's rustdoc
- [ ] `docs/release-notes/v1.0.0.md`
- [ ] Cut `1.0.0-rc.1` per RELEASE_WORKFLOW.md
- [ ] Soak period (1 week minimum)
- [ ] Address rc.N if needed

### Exit criteria

- [ ] All docs in place
- [ ] 1.0.0-rc.1 published as pre-release
- [ ] 1 week soak clean

---

## Phase 1.0.0 - Stable release

**Goal:** Ship the canonical key-vault crate.

### Pre-flight

- [ ] No critical issues from RC soak
- [ ] All CI checks green
- [ ] Performance + security contracts met
- [ ] `cargo public-api diff` clean
- [ ] `cargo audit` clean

### Release sequence

- [ ] Bump to 1.0.0
- [ ] Move [Unreleased] CHANGELOG to [1.0.0]
- [ ] Finalize release notes
- [ ] Commit, push, verify CI
- [ ] Tag v1.0.0, push tag
- [ ] GitHub release (NOT pre-release)
- [ ] cargo publish --dry-run, then cargo publish
- [ ] Verify crates.io + docs.rs

### Exit criteria

- [ ] key-vault 1.0.0 on crates.io
- [ ] docs.rs builds clean
- [ ] At least one Hive DB component consuming key-vault = "1.0"

---

## Post-1.0 backlog

- [ ] AWS KMS acquirer (separate feature)
- [ ] GCP KMS acquirer
- [ ] Azure Key Vault acquirer
- [ ] Vault (HashiCorp) acquirer
- [ ] Post-quantum asymmetric algorithms (when NIST standards finalize)
- [ ] CLI tool for vault operations (separate crate `key-vault-cli`)
- [ ] Distributed vault (cross-process key sharing - separate concern)
- [ ] no_std support for embedded use cases

### Explicitly out of scope forever

- Encryption/decryption operations (use `crypt-io`)
- Password management (different problem)
- Identity / authentication services
- Centralized secrets distribution

---

## Quick reference

```
==============================================================
key-vault roadmap to 1.0
==============================================================
0.1.0  Scaffold                              DONE
0.2.0  Foundation types + KeyHandle          4-5 days
0.3.0  StandardScatter + zeroize             1 week
0.4.0  Additional scatter strategies         4-5 days
0.5.0  Acquirer implementations              1 week
0.6.0  Multi-key vaults + rotation           3-4 days
0.7.0  Performance verification              1 week
0.8.0  Fuzz + security hardening             4-5 days
0.9.0  Docs + Release Candidate              3-4 days
1.0.0  Stable Release                        1 day
==============================================================
Total: ~4-5 focused weeks
==============================================================
```

---

## Roadmap discipline

- Every task has a checkbox - track explicitly
- Every phase has exit criteria - dont skip
- No security claim without verification
- No performance claim without benchmark
- CHANGELOG updated under [Unreleased] every commit
- `Milestone Update vX.Y.Z` commit format for releases

---

<sub>key-vault roadmap - Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>