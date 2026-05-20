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

[Unreleased]: https://github.com/jamesgober/key-vault/compare/v0.2.0...HEAD
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