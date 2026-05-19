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

[Unreleased]: https://github.com/jamesgober/key-vault/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jamesgober/key-vault/releases/tag/v0.1.0