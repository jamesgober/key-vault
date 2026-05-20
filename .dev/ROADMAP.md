# key-vault - Production Roadmap to 1.0

> **PRIORITY: MAXIMUM. PREMIUM QUALITY.**
> This is the engineering contract that takes `key-vault` from `0.1.0` scaffold to `1.0.0` stable.
>
> Reads: `REPS.md` (supreme authority), `_strategy/UNIVERSAL_PROMPT.md` (peak performance + max efficiency + max concurrency + nuclear-proof security + cross-platform), `.dev/DIRECTIVES.md`, `.dev/PROMPT.md`, `docs/SECURITY.md` (9-layer defense), `docs/TRANSFORMATION.md` (visual reference).
>
> Target ship date: **4-5 focused weeks**. Crunch as needed.
> Status: Phase 0.1.0 complete (scaffold). Phase 0.2.0 next.

---

## The 1.0 Contract

When `key-vault 1.0.0` ships, it commits to:

### Functional contract

- **`KeyVault`** — main vault type with builder API
- **`KeyHandle`** — opaque reference, never exposes raw bytes
- **`KeyFetch` trait** with 4 built-in implementations (Keychain, File, Env, TPM detection-only at 1.0)
- **`FragmentStrategy` trait** with 4 built-in implementations (Standard, Interleaved, Random, Layered)
- **`DecoyStrategy` trait** with 3 built-in implementations (Random, SelfReference, KeyDerived)
- **`Codex` trait** with 4 built-in implementations (Identity, Static, Dynamic, FnCodex)
- **`SecurityMonitor` trait** with 4 built-in implementations (None, Log, Metrics, Webhook, Composite)
- **TEE detection** — `detect_tee_capabilities()` for Intel SGX/TDX, AMD SEV, ARM TrustZone, Apple SE, AWS Nitro
- **Memory protection** — mlock + zeroize + page guards + (optional) page protection toggling
- **Master key recovery** — fallback path
- **Key rotation** — atomic swap
- **Multi-key vaults** — named keys with independent lifecycles
- **Key normalization** — BLAKE3 input hashing to neutralize format pattern leaks
- **Cross-platform parity** — Linux, macOS, Windows

### Performance contract (verified by benchmark)

| Operation | Target |
|-----------|--------|
| Vault creation, empty | <100µs |
| Key acquisition from keychain | <10ms |
| Key acquisition from file | <1ms |
| Key access (defrag, no codex) | <500ns |
| Key access (defrag with codex) | <1µs |
| Concurrent reads on same handle | lock-free, no degradation |
| Memory overhead per key | <16 KiB |
| Zero allocations on hot path | verified by dhat |

### Security contract (nuclear-proof requirement)

| Property | Verification |
|----------|--------------|
| Zero unsafe code in public API | code review + Miri |
| No key bytes leak via Debug | doctest + fuzz |
| No timing leaks on key comparison | const-time benchmark |
| No memory persistence after drop | zeroize integration tests |
| Fuzz clean for 1 CPU-hour per fetcher | cargo-fuzz |
| Fuzz clean for 1 CPU-hour per fragment strategy | cargo-fuzz |
| Fuzz clean for 1 CPU-hour per decoy strategy | cargo-fuzz |
| `cargo audit` clean | CI |
| `cargo deny check` clean | CI |
| 9-layer architecture documented | docs/SECURITY.md |
| Visual walkthrough complete | docs/TRANSFORMATION.md |

### Stability contract

- Public API frozen for v1.x lifetime
- `#[non_exhaustive]` on enums that may grow
- MSRV 1.75 held for v1.x
- Edition 2024
- Apache-2.0 OR MIT dual licensed

---

## Phase 0.1.0 - Scaffold (COMPLETE)

- [x] Repository created on GitHub
- [x] 10 topics set (rust, reps, vault, encryption, keys, keychain, secure, cryptography, security, key-management)
- [x] Cargo.toml with full feature flag plan (9 layers represented)
- [x] REPS.md canonical
- [x] LICENSE-APACHE + LICENSE-MIT
- [x] README, CHANGELOG, .editorconfig, .gitignore
- [x] rustfmt.toml, clippy.toml
- [x] src/lib.rs with full REPS lint discipline
- [x] tests/smoke.rs
- [x] benches/vault_bench.rs placeholder
- [x] PROMPT.md, DIRECTIVES.md, this ROADMAP.md
- [x] docs/SECURITY.md (9-layer architecture)
- [x] docs/TRANSFORMATION.md (visual walkthrough)
- [x] CI workflow

---

## Phase 0.2.0 - Foundation types + KeyHandle + TEE detection (COMPLETE)

**Goal:** Core types defined. TEE detection working. No real storage yet.

**Effort:** 5-6 days. **Actual:** shipped 2026-05-20.

### Tasks

- [x] Design `KeyHandle` - opaque reference type
  - Internal: `KeyId` (`NonZeroU64`), allocated from a process-global counter
  - Debug impl: prints `KeyHandle(<redacted>)`
  - No deserialization (handles are runtime-only)
- [x] Design `KeyMetadata` - metadata about a key (algorithm hint, length, registration time)
- [x] Design `Error` enum, all variant types (manual `Display` + `std::error::Error`; `thiserror` not pulled in for 0.2)
- [x] Define `Result<T>` type alias
- [x] Define core traits (no implementations yet):
  - [x] `KeyFetch`
  - [x] `FragmentStrategy`
  - [x] `DecoyStrategy`
  - [x] `Codex`
  - [x] `SecurityMonitor`
- [x] Implement `IdentityCodex` (no-op default) + `FnCodex<F>` for user closures
- [x] Define `KeyVault` struct (skeleton, `Arc<VaultInner>`-backed)
- [x] Define `KeyVaultBuilder` (skeleton)
- [x] **TEE detection** (`detect_tee_capabilities()`):
  - [x] Intel SGX detection via CPUID leaf 7
  - [x] Intel TDX detection via CPUID leaf 0x21 signature
  - [x] AMD SEV/SNP detection via CPUID 0x8000001F
  - [x] ARM TrustZone detection (reports `Unknown` — userspace cannot reliably probe)
  - [x] Apple Secure Enclave detection (`Detected` on Apple Silicon)
  - [x] AWS Nitro detection (DMI sys_vendor on Linux)
  - [x] Returns `TeeCapabilities` struct
- [x] Unit tests for KeyHandle opacity (1024-handle Debug sweep + targeted)
- [x] First doctest examples (codex, vault, handle, tee)
- [x] CHANGELOG updated
- [x] .dev/release/v0.2.0.md

### Exit criteria

- [x] All core types defined
- [x] TEE detection compiles cross-platform; x86_64 probes return real values
- [x] Smoke test passing
- [x] No real storage yet (stubs OK)
- [x] CI gate (fmt + clippy + test + doc) green locally

### Carry-over notes

- MSRV bumped from 1.75 → 1.85 to resolve a pre-existing conflict with
  `edition = "2024"`. CI matrix updated to match.

---

## Phase 0.3.0 - StandardFragmenter + mlock + zeroize

**Goal:** Layers 2, 3, 7 functional. The core memory protection working.

**Effort:** 1 week.

### Tasks

- [ ] **Layer 3: `StandardFragmenter`:**
  - [ ] Variable chunk sizes (frag_min, frag_max config)
  - [ ] Variable chunk count
  - [ ] Per-vault random seed
  - [ ] Position map (stored separately, in protected memory)
  - [ ] Defrag (reassembly) logic
- [ ] **Layer 2: mlock integration:**
  - [ ] Linux `mlock(2)` + munlock
  - [ ] macOS `mlock(2)` + munlock
  - [ ] Windows `VirtualLock` + `VirtualUnlock`
  - [ ] Graceful fallback if mlock not permitted (ulimit) — log warning
- [ ] **Layer 7: zeroize integration:**
  - [ ] All key buffers via `Zeroizing<Vec<u8>>`
  - [ ] Zeroize on KeyVault drop
  - [ ] Zeroize on fragment deallocation
  - [ ] Verify with `dhat` — memory actually overwritten
- [ ] **Key normalization:**
  - [ ] BLAKE3 input hashing
  - [ ] Configurable via `KeyVaultBuilder::normalize_with_blake3()`
- [ ] **Layer 6: constant-time equality**
  - [ ] `subtle::ConstantTimeEq` on KeyHandle comparison
  - [ ] No variable-time branches on key bytes
- [ ] Unit tests:
  - [ ] Fragment -> defrag round-trip identical
  - [ ] Multiple fragmentations produce different layouts
  - [ ] Memory cleared on drop
  - [ ] mlock actually prevents swap (Linux: check /proc/self/status)
- [ ] Property tests (proptest):
  - [ ] Round-trip for any input length (1 byte to 64 KiB)
  - [ ] Position map opacity

### Exit criteria

- [ ] StandardFragmenter functional with mlock + zeroize
- [ ] All 3 platforms verified working (Linux, macOS, Windows)
- [ ] Round-trip property test passes
- [ ] No memory leak in 10K iteration stress test

---

## Phase 0.4.0 - Decoy strategies + key normalization

**Goal:** Layer 4 (decoy bytes) working with all three strategies.

**Effort:** 4-5 days.

### Tasks

- [ ] **Layer 4: `RandomDecoy`** (raw RNG bytes — fastest)
- [ ] **Layer 4: `SelfReferenceDecoy`** (real key bytes as filler — strongest, default)
- [ ] **Layer 4: `KeyDerivedDecoy`** (BLAKE3-derived bytes matching key entropy)
- [ ] Decoy generation integrates with FragmentStrategy
- [ ] Output length configurable via `frag_len` setting
- [ ] Symbol whitelist support (`frag_symbols` config)
- [ ] Tests for each decoy strategy:
  - [ ] Statistical analysis (real key bytes indistinguishable from decoy)
  - [ ] Output length matches `frag_len`
  - [ ] Decoy bytes correctly interleaved with real fragments

### Exit criteria

- [ ] 3 decoy strategies functional
- [ ] SelfReferenceDecoy verified to defeat statistical analysis
- [ ] Symbol whitelist works

---

## Phase 0.5.0 - Additional fragment strategies + LayeredFragmenter

**Goal:** Three more fragment strategies + composition.

**Effort:** 4-5 days.

### Tasks

- [ ] **`InterleavedFragmenter`** — bytes interleaved at random strides
- [ ] **`RandomFragmenter`** — non-contiguous fragments at randomized offsets
- [ ] **`LayeredFragmenter`** — composes multiple strategies
- [ ] Tests for each
- [ ] Cross-strategy benchmarks
- [ ] Documentation: comparison of strategies and threat model coverage in docs/SECURITY.md

### Exit criteria

- [ ] 4 fragment strategies functional
- [ ] Layered composition working with all 3 sub-strategies
- [ ] docs/SECURITY.md updated with strategy comparison table

---

## Phase 0.6.0 - Codex layer (Layer 5)

**Goal:** Optional byte-swap transformation layer.

**Effort:** 3-4 days.

### Tasks

- [ ] **`Codex` trait** (already defined in 0.2)
- [ ] **`IdentityCodex`** (already in 0.2, verify default)
- [ ] **`StaticCodex`**:
  - [ ] `StaticCodex::from_swaps(&[(u8, u8)])` for involution-based swaps
  - [ ] `StaticCodex::random_involution(rng)` for random involutions
  - [ ] Lookup table internally (256-byte array)
- [ ] **`DynamicCodex`**:
  - [ ] Per-vault randomized involution generated at vault creation
  - [ ] Stored in protected memory
- [ ] **`FnCodex<F>`**:
  - [ ] Wraps user-provided closure
  - [ ] Documented: closure must be involution (encode == decode)
- [ ] Codex integration in fragment storage:
  - [ ] All bytes (real + decoy) pass through codex.encode() on storage
  - [ ] codex.decode() applied during defrag
- [ ] Feature-gated behind `codex` Cargo feature (default off)
- [ ] Unit tests for involution property: `decode(encode(x)) == x`
- [ ] Property tests across all codex implementations

### Exit criteria

- [ ] 4 codex implementations functional
- [ ] Round-trip property verified for all
- [ ] Performance impact measured and documented

---

## Phase 0.7.0 - Key fetchers (Layer 1)

**Goal:** Built-in fetchers for the common key sources.

**Effort:** 1 week.

### Tasks

- [ ] **`EnvFetch`** — environment variable
  - [ ] Redaction in error messages
  - [ ] Configurable variable name
- [ ] **`FileFetch`** — encrypted file
  - [ ] AEAD encryption (ChaCha20-Poly1305 via crypt-io or directly)
  - [ ] File format documented
  - [ ] Permission checks (0600 on Unix)
- [ ] **`KeychainFetch`** — OS keychain via `keyring` crate
  - [ ] macOS Keychain integration
  - [ ] Windows Credential Manager integration
  - [ ] Linux Secret Service integration
  - [ ] Feature-gated behind `fetcher-keychain`
- [ ] **`TpmFetch`** — TPM 2.0 (DETECTION ONLY in 1.0, full integration deferred to 1.x)
  - [ ] Detection works via `detect_tee_capabilities()`
  - [ ] Stub fetcher returns "TPM not yet integrated" error
  - [ ] Documented as 1.x feature
- [ ] Fetcher error handling with thiserror
- [ ] Audit logging integration with `log-io`
- [ ] Cross-platform tests for keychain (Linux/macOS/Windows)
- [ ] Integration tests (gated by env vars in CI)

### Exit criteria

- [ ] 3 working fetchers (env, file, keychain)
- [ ] TPM detection works but integration deferred (clearly documented)
- [ ] Real keychain verified on all 3 platforms

---

## Phase 0.8.0 - Security monitor (Layer 8) + audit (Layer 9)

**Goal:** Failure detection + access logging.

**Effort:** 4-5 days.

### Tasks

- [ ] **`SecurityMonitor` trait** + implementations:
  - [ ] `NoMonitor` (default, disabled)
  - [ ] `LogMonitor` (logs via `log-io` or tracing)
  - [ ] `MetricsMonitor` (increments counters in `metrics-lib`)
  - [ ] `WebhookMonitor` (POSTs to alert endpoint)
  - [ ] `CompositeMonitor` (chains multiple)
- [ ] **Threshold detection:**
  - [ ] N failures in M seconds → alert
  - [ ] N failures in M seconds → lockout
  - [ ] Configurable thresholds per vault
- [ ] **Anomalous access detection:**
  - [ ] Unusual caller context
  - [ ] Unusual frequency
  - [ ] Sustained extraction patterns
- [ ] **Layer 9: Audit logging:**
  - [ ] Every key access produces `AuditEvent`
  - [ ] Routed through `log-io` if available
  - [ ] Caller context captured (module, function, file:line)
  - [ ] Thread ID, timestamp, metadata
  - [ ] Feature-gated behind `audit` Cargo feature
- [ ] Integration tests for monitor + audit

### Exit criteria

- [ ] All monitor implementations working
- [ ] Audit logging emits events correctly
- [ ] Threshold lockout verified
- [ ] Performance: zero cost on success path

---

## Phase 0.9.0 - Multi-key vaults + key rotation + master key recovery

**Goal:** Operational features for production use.

**Effort:** 4-5 days.

### Tasks

- [ ] Multi-key support (named keys with independent lifecycles)
- [ ] `KeyVault::rotate(name, new_key)` - atomic swap
- [ ] Concurrent access during rotation (lock-free reads via ArcSwap)
- [ ] Master key concept for vault-level operations
- [ ] Master key recovery flow:
  - [ ] Recovery from master key
  - [ ] Recovery key validation
  - [ ] Emergency unlock path
- [ ] Tests for concurrent rotation
- [ ] Tests for master key recovery

### Exit criteria

- [ ] Multi-key vaults working
- [ ] Rotation atomic and verified concurrent-safe
- [ ] Master key recovery tested

---

## Phase 0.10.0 - Performance verification + tuning (Max-Perf phase)

**Goal:** Hit Performance Contract numbers. No claim ships without committed benchmark.

**Effort:** 1 week.

### Tasks

- [ ] Comprehensive benchmark suite:
  - [ ] `benches/access_latency.rs` — single-key access, all layer combinations
  - [ ] `benches/concurrent_access.rs` — 1, 4, 16, 64 thread contention
  - [ ] `benches/fragment_strategies.rs` — comparison across strategies
  - [ ] `benches/decoy_strategies.rs` — overhead per strategy
  - [ ] `benches/codex_overhead.rs` — codex vs no-codex
  - [ ] `benches/memory_overhead.rs` — per-key footprint
- [ ] Run on dev machine, commit baselines.json
- [ ] Compare against Performance Contract:
  - [ ] All targets met OR
  - [ ] Tune until they are
- [ ] Profile with `perf` / `flamegraph`
- [ ] Allocation profile with `dhat` — zero allocation on hot path
- [ ] Layer 10 (page protection toggling) — opt-in feature with documented perf impact
- [ ] `docs/PERFORMANCE.md` — methodology + results + tuning guide

### Exit criteria

- [ ] All Performance Contract targets met
- [ ] Baselines committed
- [ ] docs/PERFORMANCE.md complete

---

## Phase 0.11.0 - Fuzz testing + security hardening (Nuclear-proof phase)

**Goal:** No panics, no infinite loops, no OOMs on any input across all layers.

**Effort:** 4-5 days.

### Tasks

- [ ] Set up `cargo-fuzz` workspace
- [ ] **Fuzz targets:**
  - [ ] Each fetcher with random inputs
  - [ ] Each fragment strategy with random key bytes
  - [ ] Each decoy strategy with random key bytes
  - [ ] Each codex with random byte tables
  - [ ] Configuration parser with malformed inputs
  - [ ] Monitor threshold logic
- [ ] **Run each for 1 CPU-hour minimum** on dev machine
- [ ] **Fix any findings:**
  - [ ] Panic → replace with `Result<_, Error>`
  - [ ] Infinite loop → add iteration cap
  - [ ] OOM → add input size limits
- [ ] **Security tests:**
  - [ ] Verify Debug doesn't leak (proptest)
  - [ ] Verify zeroize actually overwrites (`dhat`)
  - [ ] Verify mlock actually prevents swap (Linux: `/proc/self/status`)
  - [ ] Verify constant-time property (`dudect` or similar)
- [ ] Corpus inputs committed to `fuzz/corpus/`
- [ ] Regression tests added for any corpus input

### Exit criteria

- [ ] All fuzz targets clean for 1 CPU-hour
- [ ] No memory leaks
- [ ] All security properties verified
- [ ] `docs/SECURITY.md` updated with verification methodology

---

## Phase 0.12.0 - Documentation completion + Release Candidate

**Goal:** Final documentation. Cut `1.0.0-rc.1`.

**Effort:** 3-4 days.

### Tasks

- [ ] **Documentation completeness:**
  - [ ] `docs/STABILITY-1.0.md` — the 1.0 stability contract
  - [ ] `docs/ARCHITECTURE.md` — internal architecture (vault, fragments, fetchers, monitors)
  - [ ] `docs/SECURITY.md` — already in place, polish + update with verification methodology
  - [ ] `docs/TRANSFORMATION.md` — already in place, verify accuracy with final implementation
  - [ ] `docs/PERFORMANCE.md` — from 0.10
  - [ ] `docs/PLATFORM-NOTES.md` — Linux/macOS/Windows specifics
  - [ ] `docs/HARDWARE.md` — TPM 2.0, HSM, secure enclave integration notes
  - [ ] Every public item rustdoc'd with at least one example
- [ ] **Release notes:**
  - [ ] `docs/release-notes/v1.0.0.md` per `_strategy/RELEASE_NOTES_TEMPLATE.md`
- [ ] **Release candidate:**
  - [ ] Bump Cargo.toml to `1.0.0-rc.1`
  - [ ] Move `[Unreleased]` CHANGELOG to `[1.0.0-rc.1]`
  - [ ] Commit `Milestone Update v1.0.0-rc.1`
  - [ ] Push, verify CI green
  - [ ] Tag `v1.0.0-rc.1`, push tag
  - [ ] GitHub release marked as pre-release
  - [ ] `cargo publish --dry-run` then `cargo publish` (pre-release flag)
- [ ] **Soak period:**
  - [ ] 1 week minimum
  - [ ] Solicit external feedback
  - [ ] Iterate to `rc.N` if needed

### Exit criteria

- [ ] All docs in place
- [ ] `1.0.0-rc.1` published as pre-release on crates.io
- [ ] 1 week soak with no critical issues

---

## Phase 1.0.0 - Stable release

**Goal:** Ship the premium key vault crate.

**Effort:** 1 day.

### Pre-flight verification

- [ ] No critical issues from RC soak
- [ ] All CI checks green on Linux + macOS + Windows on stable + MSRV
- [ ] All Performance Contract targets met
- [ ] All Security Contract verifications complete
- [ ] `cargo public-api diff` clean vs rc.N
- [ ] `cargo audit` clean
- [ ] `cargo deny check` clean
- [ ] Documentation review — every doc accurate and complete

### Release sequence

- [ ] Update `Cargo.toml` version → `1.0.0`
- [ ] Move `[Unreleased]` CHANGELOG → `[1.0.0] - <date>`
- [ ] Finalize `docs/release-notes/v1.0.0.md`
- [ ] Commit: `Milestone Update v1.0.0`
- [ ] Push to `main`
- [ ] Verify CI green
- [ ] Tag: `git tag -a v1.0.0 -m "v1.0.0"`
- [ ] Push tag: `git push origin v1.0.0`
- [ ] Create GitHub release (NOT marked as pre-release):
  - Title: `v1.0.0 — Premium Key Vault Stable Release`
  - Body: contents of `docs/release-notes/v1.0.0.md`
- [ ] `cargo publish --dry-run` → verify clean
- [ ] `cargo publish` → ship it
- [ ] Verify crates.io shows `1.0.0`
- [ ] Verify docs.rs builds `1.0.0` clean

### Post-release

- [ ] Announcement (project README, Hive DB README, social, blog post if appropriate)
- [ ] Begin tracking 1.1+ backlog
- [ ] At least one portfolio crate (likely `crypt-io` or `audit-trail`) consumes `key-vault = "1.0"`

### Exit criteria

- [ ] `key-vault 1.0.0` live on crates.io
- [ ] docs.rs builds clean
- [ ] At least one Hive DB component consuming `key-vault = "1.0"`

---

## Post-1.0 backlog

### High-value 1.1.x additions

- [ ] **Full TPM 2.0 integration** (currently detection-only)
  - Intel SGX wrapping
  - AMD SEV/SNP wrapping
  - ARM TrustZone integration
- [ ] **Apple Secure Enclave** acquisition (macOS, iOS)
- [ ] **AWS Nitro Enclaves** acquisition
- [ ] **AWS KMS** fetcher (acquirer plugin)
- [ ] **GCP KMS** fetcher
- [ ] **Azure Key Vault** fetcher
- [ ] **HashiCorp Vault** fetcher
- [ ] **CLI tool** `key-vault-cli` for vault operations (separate crate)

### 1.2.x and beyond

- [ ] **Post-quantum asymmetric algorithms** (when NIST standards finalize and ecosystem support arrives)
- [ ] **Distributed vault** (cross-process key sharing — separate crate)
- [ ] **`no_std` support** for embedded use cases
- [ ] **Audit log persistence** (write audit events to durable storage)
- [ ] **Web UI** for vault operations (separate crate)

### Explicitly out of scope forever

- Encryption/decryption operations (use `crypt-io`)
- Password management (different problem)
- Identity management
- Centralized secrets distribution

---

## Quick reference

```
==============================================================
key-vault roadmap to 1.0 (MAX PRIORITY)
==============================================================
0.1.0   Scaffold                              DONE
0.2.0   Foundation + TEE detection             5-6 days
0.3.0   Layers 2, 3, 7: mlock + frag + zero    1 week
0.4.0   Layer 4: decoy strategies              4-5 days
0.5.0   Additional fragment strategies         4-5 days
0.6.0   Layer 5: codex                         3-4 days
0.7.0   Layer 1: key fetchers                  1 week
0.8.0   Layers 8 + 9: monitor + audit          4-5 days
0.9.0   Multi-key + rotation + master recovery 4-5 days
0.10.0  Performance verification (Max-Perf)    1 week
0.11.0  Fuzz testing (Nuclear-proof)           4-5 days
0.12.0  Docs + Release Candidate               3-4 days
1.0.0   Premium Stable Release                 1 day
==============================================================
Total: ~4-5 focused weeks
==============================================================
```

---

## Roadmap discipline (MAX PRIORITY enforcement)

- Every task has a checkbox - tracked explicitly
- Every phase has exit criteria - no advancement without exit cleanly
- No skipping phases without explicit written justification
- No performance claim without committed benchmark (the contract requires this)
- No security claim without verification (fuzz, dhat, dudect, etc.)
- CHANGELOG updated under [Unreleased] every commit
- `Milestone Update vX.Y.Z` commit format for releases
- Premium quality on documentation throughout — this is competing with established players

---

<sub>key-vault roadmap - Copyright (c) 2026 James Gober. Apache-2.0 OR MIT. MAX PRIORITY.</sub>