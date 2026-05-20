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

## [0.8.0] - 2026-05-20

### Added

- **Layer 8 — Monitor implementations.** Three new `SecurityMonitor`
  impls covering the common observability surface:
  - `NoMonitor` — the inert default (always available).
  - `CompositeMonitor` — fan-out across `Vec<Arc<dyn SecurityMonitor>>`.
  - `LogMonitor` — emits structured `tracing` events at warn/error
    levels (gated behind the `monitor-tracing` Cargo feature).
- **Threshold-driven lockout.** `VaultConfig` gained
  `max_failures_before_lockout` and `failure_window` fields.
  `KeyVaultBuilder::with_failure_threshold(max, window)` configures
  per-key sliding-window failure tracking. Lockout disabled by default
  (`max = 0`).
- **`KeyVault::report_failure(key_name, note)`** — caller-driven
  failure reporting. Forwards to the configured monitor and feeds the
  threshold detector. When the threshold is crossed, the vault
  transitions to lock-out state and `on_threshold_breach` fires.
- **`KeyVault::report_anomalous_access(key_name, note)`** — caller-
  driven anomaly reporting. Forwards to the configured monitor without
  affecting vault state.
- **`KeyVault::clear_lockout()`** — operator escape hatch. Resets the
  lockout flag and clears the failure tracker.
- **`KeyVaultBuilder::with_monitor(M)`** — attach a `SecurityMonitor`
  implementation. Replaces any previously-configured monitor.
- Blanket `impl SecurityMonitor for Arc<dyn SecurityMonitor>` so
  pre-wrapped monitors can be passed to APIs that accept
  `impl SecurityMonitor`.
- New crate-root re-exports: `NoMonitor`, `CompositeMonitor`,
  `LogMonitor` (latter feature-gated).

### Changed

- `KeyVault::fragment` / `defragment` now return
  `Error::LockedOut` when the vault is in lock-out state. They were
  previously infallible w.r.t. the lockout flag.
- `VaultConfig::Default` is now manually implemented (was derived) to
  account for the new threshold fields.
- `KeyVaultBuilder::Default` is now manually implemented.

### Security

- **Threshold-driven lockout** turns the failure-tracking signal into
  enforcement: a vault that has crossed the threshold refuses to
  fragment or defragment until an operator explicitly calls
  `clear_lockout`. Prevents an attacker who can poke the API into
  burning through brute-force attempts.
- **No secrets in monitor events.** `FailureContext`,
  `AccessContext`, and `ThresholdContext` are sanitized by trait
  contract; `LogMonitor` emits only key names, counters, and the
  caller-supplied note. The note field is `Cow<'static, str>` — caller
  responsibility to keep it sanitized.

[0.8.0]: https://github.com/jamesgober/key-vault/compare/v0.7.0...v0.8.0

---

## [0.7.0] - 2026-05-20

### Added

- **Layer 1 — Built-in `KeyFetch` implementations.** Four fetchers,
  each gated behind its own Cargo feature:
  - `EnvFetch` (`fetcher-env`) — read key bytes from a process
    environment variable. Error messages include the variable name but
    never the value.
  - `FileFetch` (`fetcher-file`) — read key bytes from a file on disk.
    Strict Unix permission checking (`0o600` or tighter) by default;
    relaxable via `FileFetch::allow_loose_perms()`.
  - `KeychainFetch` (`fetcher-keychain`) — read from the OS native
    credential store via the `keyring` crate (macOS Keychain, Windows
    Credential Manager, Linux Secret Service / KWallet). Error messages
    redact `keyring` internals.
  - `TpmFetch` (`fetcher-tpm`) — **detection-only in 1.0**. Returns a
    documented `Error::Acquisition` so consumers can wire it into
    composite fetcher chains and inherit the 1.x upgrade.
- Crate-root re-exports for all four fetchers (feature-gated).
- Documentation: each fetcher's module ships its own threat-profile
  notes.

### Changed

- `clippy.toml` `doc-valid-idents` whitelist extended with `FileVault`,
  `BitLocker`, `KWallet`, `TrustZone`, `IntelSGX`.

### Security

- **No fetcher writes key material to its `Error` variants.** All four
  redact the source value: `EnvFetch` prints the variable name only;
  `FileFetch` prints the path and the I/O error kind only;
  `KeychainFetch` prints the entry locator and a discriminant-only
  rendering of the `keyring` error; `TpmFetch` carries no input at all.
- **`FileFetch` Unix permission gate.** Default rejects files readable
  by group or world. Opting out requires an explicit
  `.allow_loose_perms()` call documented as "not recommended outside
  tests."

[0.7.0]: https://github.com/jamesgober/key-vault/compare/v0.6.0...v0.7.0

---

## [0.6.0] - 2026-05-20

### Added

- **Layer 5 — `StaticCodex`.** 256-byte involution lookup table held in
  a `LockedBytes` buffer (mlock'd + zeroed on drop). Construct via
  `StaticCodex::from_swaps(&[(u8, u8)])` for declarative swap pairs or
  `StaticCodex::random_involution()` for a fresh random permutation with
  no fixed points.
- **Layer 5 — `DynamicCodex`.** Thin wrapper around
  `StaticCodex::random_involution()` for the common "fresh random codex
  per vault" use case.
- **`KeyVaultBuilder::with_codex`.** Attach any `Codex + 'static` to the
  vault; the codex transformation is applied transparently at the
  fragment/defragment boundary (after BLAKE3 normalization, before
  fragmentation; reversed on defragment).
- **Crate-root re-exports.** `StaticCodex`, `DynamicCodex` available
  at `key_vault::StaticCodex` / `key_vault::DynamicCodex`.

### Changed

- `KeyVaultBuilder` is no longer `#[derive(Debug)]` — it now holds an
  `Option<Arc<dyn Codex>>` whose dyn trait is not `Debug`. A manual
  `Debug` impl reports the codex as `Some("<set>")` / `None` without
  inspecting it.
- `crate::fragment::util` helpers (`random_u64`, `sample_range`,
  `fisher_yates`, `zero_buffer`, `zero_buffer_owned`) promoted from
  `pub(super)` to `pub(crate)` so the codex module can reuse the same
  RNG/shuffle plumbing.

### Security

- **Codex table is `LockedBytes`-protected.** The 256-byte lookup table
  in both `StaticCodex` and `DynamicCodex` lives in a `LockedBytes`
  buffer — mlock'd against swap, volatile-zeroed before drop. Knowing
  the table is equivalent to knowing the transformation, so the table
  is treated as key-equivalent material.
- **`random_involution` produces no fixed points.** Every byte
  transforms to a *different* byte (pairs are formed by Fisher-Yates of
  all 256 bytes). An attacker scanning the stored fragments sees no
  byte that maps to itself.
- **Per-call freshness.** Each `DynamicCodex::new()` and each
  `StaticCodex::random_involution()` produces an independent random
  table; CSPRNG entropy comes from `getrandom`.

[0.6.0]: https://github.com/jamesgober/key-vault/compare/v0.5.0...v0.6.0

---

## [0.5.0] - 2026-05-20

### Added

- **`RandomFragmenter`** — Layer-3 strategy that scatters bytes
  **non-contiguously**. Each chunk holds bytes drawn from independently
  chosen random positions of the original key, so no chunk ever contains
  a contiguous run of key bytes longer than 1.
- **`InterleavedFragmenter`** — Layer-3 strategy that places key bytes
  at random positions inside a single large `LockedBytes` pool (default
  4× key length), padding the gaps with CSPRNG bytes. Defeats byte-level
  statistical analysis of the pool.
- **`LayeredFragmenter`** — composition strategy that holds a `Vec<Arc<dyn FragmentStrategy>>`
  and picks one uniformly at random per `fragment` call. The picked
  sub-strategy's index is prepended (4 bytes LE) to the layout buffer so
  `defragment` can dispatch correctly. Routing-based composition avoids
  materializing the key between layers.
- New crate-internal `src/fragment/util.rs` consolidating
  `random_u64`, `sample_range`, `fisher_yates`, `zero_buffer`,
  `zero_buffer_owned` — previously duplicated across fragmenters.
- `Fragments::into_parts()` pub(crate) accessor — destructure the
  inner `(Vec<LockedBytes>, LockedBytes, usize)` for compositional
  strategies without copying chunk buffers.
- `Fragments::chunk_count()` is now `pub` (was `pub(crate)`).
- Integration test suite [`tests/fragment_strategies.rs`](../../tests/fragment_strategies.rs)
  exercising all four strategies through the public `FragmentStrategy`
  trait + `Send + Sync` assertions.

### Changed

- **`docs/SECURITY.md`** strategy-comparison section rewritten with a
  per-strategy storage shape, layout encoding, threat focus, memory
  overhead, and decoy compatibility table.
- `StandardFragmenter` now imports its RNG/shuffle/zero helpers from
  `fragment::util` instead of defining them locally.
- Per-strategy unit tests use the shared helpers transitively (no test
  changes).

### Security

- **Routing-based composition** (`LayeredFragmenter`) adds an additional
  `log2(N)` bits of uncertainty against an attacker who has the chunks
  and the layout buffer but does not know which sub-strategy was used.
- **`RandomFragmenter`** explicitly defeats contiguous-format
  recognition (DER envelopes, PEM markers, ASCII-armored data) by
  ensuring no chunk contains a contiguous run of key bytes longer than 1.

[0.5.0]: https://github.com/jamesgober/key-vault/compare/v0.4.0...v0.5.0

---

## [0.4.0] - 2026-05-20

### Added

- **Layer 4 — Decoy strategies.** Three implementations of the
  `DecoyStrategy` trait shipped:
  - `RandomDecoy` — uniformly random bytes from the OS CSPRNG (fastest,
    weakest).
  - `SelfReferenceDecoy` — bytes sampled independently from the key
    itself, so the decoy's byte distribution exactly matches the key's
    (strongest indistinguishability, recommended default).
  - `KeyDerivedDecoy` — BLAKE3 XOF seeded by the key plus a fresh
    per-call CSPRNG nonce (CSPRNG-like output correlated with the key).
- **`StandardFragmenter::with_decoy`** — attach any
  `DecoyStrategy + 'static` to the fragmenter. When set, every
  `fragment` call also emits decoy chunks; `defragment` recognizes them
  via a `u32::MAX` sentinel in the locked layout buffer and skips them
  during reassembly.
- **`KeyVaultBuilder::with_decoy`** — fluent forwarder that wires the
  decoy strategy into the underlying fragmenter without exposing
  builder internals.
- New crate-root re-exports: `RandomDecoy`, `SelfReferenceDecoy`,
  `KeyDerivedDecoy`.

### Changed

- `StandardFragmenter` is no longer `Copy`; it now holds an
  `Option<Arc<dyn DecoyStrategy>>` so the decoy can outlive the builder.
  `Clone` is preserved (`Arc` clones cheaply).
- `StandardFragmenter`'s `Debug` impl is now manual (it inspects the
  decoy's `describe()` rather than the trait object) — display
  semantics are unchanged.
- The layout buffer encoding gained a sentinel: `u32::MAX` means "this
  chunk is a decoy, skip it during defragment." Real key lengths are
  bounded by `u32::MAX - 1` bytes (~4 GiB), well above any realistic
  key. Internally, `fragment` now returns
  `Error::Fragment("key too large")` if this bound is exceeded.

### Security

- **Statistical indistinguishability.** With `SelfReferenceDecoy` set,
  decoy chunks are byte-for-byte drawn from the same distribution as
  the real key; entropy and chi-squared distinguishers cannot separate
  them.
- **Per-call freshness.** `KeyDerivedDecoy` mixes in a fresh 32-byte
  CSPRNG nonce per generate call so an attacker who later recovers the
  key cannot recompute the decoy stream and confirm a fragmentation.
- **Intermediate plaintext scrubbing.** The temporary `Vec<u8>` used to
  carry decoy bytes from a strategy into the `LockedBytes` it lives in
  is volatile-zeroed before drop.

[0.4.0]: https://github.com/jamesgober/key-vault/compare/v0.3.0...v0.4.0

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

[Unreleased]: https://github.com/jamesgober/key-vault/compare/v0.8.0...HEAD
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