# Changelog

All notable changes to `key-vault` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

### Changed

### Fixed

### Security

---

## [0.3.0] - 2026-05-20

### Added

- **Layer 2 — Memory page locking.** New crate-internal `LockedBytes`
  wrapper around `Vec<u8>` that calls `mlock(2)` (Unix) / `VirtualLock`
  (Windows) at construction and `munlock` / `VirtualUnlock` on drop.
  Soft-fails when the OS declines the lock (e.g. `RLIMIT_MEMLOCK`); the
  wrapper records the outcome and continues. Always zeroes its bytes
  before unlocking.
- **Layer 3 — `StandardFragmenter`.** First real `FragmentStrategy`
  implementation: variable-size chunks (configurable range, default 1–8
  bytes), Fisher-Yates permutation, per-chunk independent heap
  allocations (each `LockedBytes`-locked), separate locked layout buffer.
  Round-trip verified by 1000-iteration stress test.
- **Layer 6 — `ConstantTimeEq` for `KeyHandle`.** Public equality on
  handles now goes through `subtle::ConstantTimeEq`. `PartialEq` and
  `Hash` are kept consistent: equal handles always hash equal.
- **Layer 7 — Zero-on-drop.** `LockedBytes` overwrites its bytes with
  `write_volatile` + a compiler fence before releasing the lock and
  freeing the allocation. The temporary plaintext copy used to build the
  layout buffer is also volatile-zeroed.
- **BLAKE3 normalization wired through.** The previously-toggle-only
  `KeyVaultBuilder::normalize_with_blake3` setting now actually applies a
  BLAKE3 hash to the input key before fragmentation. Default remains on.
- **`KeyVault::fragment` / `KeyVault::defragment`.** Convenience methods
  routing through the configured normalizer and `StandardFragmenter`.
  Downstream crates can now exercise the full Layer 2 + 3 + 7 stack from
  the public API. (Named-key registration still arrives in 0.9.0.)
- **`KeyVaultBuilder::with_chunk_range`** — propagates a custom chunk-size
  range to the underlying fragmenter.
- New module `src/memory` with `LockedBytes` + per-OS backends
  (`unix.rs`, `windows.rs`).
- New module `src/normalize` with `blake3_normalize` helper.
- New integration test `tests/fragment_roundtrip.rs` covering the full
  pipeline through the public API plus `Send + Sync` assertions on
  `KeyVault`.

### Changed

- **CI: replaced `actions/cache@v4` with `Swatinem/rust-cache@v2`.**
  Removes the Node.js 20 deprecation warning and gives the Rust-aware
  caching policy (sccache-friendly, target-dir aware).
- Dropped the unused `actions/setup-node@v5` step from CI.
- `Fragments` gained real internal storage (a `Vec<LockedBytes>` for
  chunks plus a separate `LockedBytes` layout buffer); `Debug` continues
  to redact contents and now uses `finish_non_exhaustive` to document
  that the layout field is intentionally hidden.
- `KeyHandle` no longer derives `PartialEq` and `Hash` — both are
  implemented manually so equality routes through `ConstantTimeEq` while
  preserving the `Hash`/`Eq` consistency invariant.

### Security

- **Layer 2** is now actually in force for every fragment and layout
  buffer; pages are pinned in RAM unless the OS refuses.
- **Layer 6** equality on handles is now constant-time.
- **Layer 7** zero-on-drop applies to every fragment, every layout
  buffer, and intermediate plaintext copies created during
  fragmentation.

[0.3.0]: https://github.com/jamesgober/key-vault/compare/v0.2.0...v0.3.0

---

## [0.2.0] - 2026-05-20

### Added

- `Error` enum (`#[non_exhaustive]`) covering acquisition, fragmentation,
  defragmentation, decoy, codex, lock-out, memory-lock, configuration, and
  internal-invariant failures. All variants are redaction-clean by design.
- `Result<T>` type alias.
- `KeyHandle` and `KeyId` opaque reference types with hard `Debug` redaction
  (every variant prints `KeyHandle(<redacted>)` / `KeyId(<redacted>)`).
- `KeyMetadata` and `AlgorithmHint` for non-secret per-key metadata.
- Layer 1: `KeyFetch` trait + `FetchContext` + `RawKey` container with
  redacting `Debug`.
- Layer 3: `FragmentStrategy` trait + opaque `Fragments` placeholder.
- Layer 4: `DecoyStrategy` trait.
- Layer 5: `Codex` trait, `IdentityCodex` default implementation, and
  `FnCodex<F>` for user-provided involutions.
- Layer 8: `SecurityMonitor` trait + `FailureContext` / `AccessContext` /
  `ThresholdContext` event structs.
- `KeyVault` and `KeyVaultBuilder` skeletons with a `VaultConfig` carrying the
  BLAKE3 normalization toggle.
- `tee::detect_tee_capabilities()` returning a `TeeCapabilities` snapshot for
  Intel SGX, Intel TDX, AMD SEV, AMD SEV-SNP, ARM TrustZone, Apple Secure
  Enclave, and AWS Nitro. Each capability reports `Detected`, `NotDetected`,
  or `Unknown`. x86_64 probes use CPUID directly; AWS Nitro is inferred from
  the Linux DMI vendor string; Apple Secure Enclave is inferred from
  `aarch64-apple-darwin`.
- Integration test suite under `tests/tee_detection.rs`.
- 27 unit tests + 4 integration tests + 5 doctests cover the new surface.

### Changed

- MSRV raised from `1.75` to `1.85` to match the `edition = "2024"` declaration
  that was already in `Cargo.toml`. The two were mutually incompatible — Cargo
  ≥1.84 refuses to parse the previous combination. CI matrix updated.
- `src/lib.rs` rewritten as a module graph (`codex`, `decoy`, `error`,
  `fetcher`, `fragment`, `handle`, `metadata`, `monitor`, `tee`, `vault`) with
  appropriate public re-exports.
- `clippy.toml` gained a `doc-valid-idents` whitelist covering domain terms
  (`x86_64`, `TrustZone`, `IntelTDX`, `ChaCha20`, `VirtualLock`, etc.) so the
  pedantic `doc_markdown` lint focuses on real backtick misses.

[Unreleased]: https://github.com/jamesgober/key-vault/compare/v0.3.0...HEAD
[0.2.0]: https://github.com/jamesgober/key-vault/compare/v0.1.0...v0.2.0

---

## [0.1.0] - 2026-05-18

### Added

- Initial scaffold and repository bootstrap.
- REPS compliance baseline.
- CI for Linux/macOS/Windows on stable and MSRV (1.75).
- Project documentation framework (PROMPT, DIRECTIVES, ROADMAP).
- **9-layer security architecture** locked in:
  - Layer 1: Secure Acquisition (`KeyFetch` trait)
  - Layer 2: Memory Page Locking (mlock / VirtualLock)
  - Layer 3: Fragment Strategy (variable chunks)
  - Layer 4: Decoy Bytes (self-referential filler)
  - Layer 5: Codex Transformation (involution-based byte swap)
  - Layer 6: Constant-Time Operations
  - Layer 7: Zero-On-Drop (zeroize)
  - Layer 8: Security Monitor (failure detection)
  - Layer 9: Audit Logging
  - Bonus Layer 10: Page Protection Toggling
- Cargo feature flags for all fetchers, fragment strategies, decoy strategies, codex, monitor, audit, mlock, zeroize, tee-detect, post-quantum
- Convenience presets: preset-balanced, preset-paranoid, preset-fast
- `docs/SECURITY.md` (24 KB) - comprehensive 9-layer security architecture
- `docs/TRANSFORMATION.md` (12 KB) - visual walkthrough of key transformation
- BLAKE3 key normalization
- TEE detection in 1.0 scope (full TEE integration deferred to 1.x)

[0.1.0]: https://github.com/jamesgober/key-vault/releases/tag/v0.1.0