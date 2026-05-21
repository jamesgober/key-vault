<h1 align="center">
    <b>key-vault — 1.0 Stability Contract</b>
    <br>
    <sub><sup>WHAT'S STABLE · WHAT MAY CHANGE · MIGRATION POLICY</sup></sub>
</h1>

<p align="center">
    <i>The contract that takes effect at the <code>v1.0.0</code> tag.</i>
    <br>
    <i>Companion to <a href="./API.md">API.md</a>, <a href="./SECURITY.md">SECURITY.md</a>, and <a href="./PERFORMANCE.md">PERFORMANCE.md</a>.</i>
</p>

---

## TL;DR

After `1.0.0` tags, the following surfaces are **frozen** under
[semver](https://semver.org). Breaking any of them requires a `2.0`
release.

- All items re-exported from `key_vault` at the crate root.
- The signature and behaviour contract of every public trait method.
- Cargo feature flag names (additive only — removing a feature is a
  breaking change).
- MSRV `1.85`. Raising it is a `MINOR` bump; lowering it is a `MAJOR`
  bump.
- The `KeyHandle` opaque-id behaviour: `Debug` redaction, constant-time
  equality.
- The audit / monitor sink contracts (non-blocking, no panics, no
  back-pressure).
- File and registry on-disk / in-memory layouts that downstream
  consumers can observe.

The internal modules (`memory`, `metadata`, `normalize`) and the
contents of `pub(crate)` items are explicitly **not** part of the
contract.

---

## What is frozen at 1.0

### Public type surface

Every item below is part of the 1.0 API contract. Renames, removals,
or signature changes require a `2.0` major release.

**Core types**
- `KeyVault`, `KeyVaultBuilder`, `VaultConfig`
- `KeyHandle`, `KeyId`
- `KeyMetadata`, `AlgorithmHint`
- `Error`, `Result<T>`
- `RawKey`, `FetchContext`
- `Fragments`

**Trait surfaces**
- `KeyFetch` (+ `EnvFetch`, `FileFetch`, `KeychainFetch`, `TpmFetch`)
- `FragmentStrategy` (+ `StandardFragmenter`, `InterleavedFragmenter`, `RandomFragmenter`, `LayeredFragmenter`)
- `DecoyStrategy` (+ `RandomDecoy`, `SelfReferenceDecoy`, `KeyDerivedDecoy`)
- `Codex` (+ `IdentityCodex`, `StaticCodex`, `DynamicCodex`, `codex::FnCodex`)
- `SecurityMonitor` (+ `NoMonitor`, `LogMonitor`, `CompositeMonitor`)
- `AuditSink` (+ `NoAudit`, `LogAudit`) — including `AuditSink::is_no_op()` from 0.11.0
- `AuditEvent`, `AccessKind` (both `#[non_exhaustive]`)
- `AccessContext`, `FailureContext`, `ThresholdContext`

**TEE detection**
- `tee::detect_tee_capabilities()`, `tee::TeeCapabilities`, the
  `Detected` / `NotDetected` / `Unknown` variants.

**Constants**
- `VERSION` — populated by Cargo at build time.

### Behavioural contracts

- `KeyHandle::Debug` **always** prints `KeyHandle(<redacted>)` — never
  any byte of the internal id. Verified by `proptest` in
  `tests/proptest_invariants.rs`.
- `KeyHandle::eq` uses `subtle::ConstantTimeEq`. Equality of two
  handles is constant-time relative to the id contents.
- `KeyVault::with_key` callback receives a `&[u8]` that is valid for
  the call only. The underlying `RawKey` zeroes on drop.
- `KeyVault::rotate` is atomic. Concurrent `with_key` readers see
  either the old or the new fragmentation, never a torn read.
- Every `FragmentStrategy` satisfies `defragment(fragment(k))` =
  `k` (length-equality at minimum; byte-equality when normalisation
  is off). Verified by `proptest` over 256-case sweeps.
- Every `Codex` satisfies `decode(encode(b)) == b` for every byte.
  Verified by `proptest` + `cargo-fuzz`.
- Every `AuditSink` implementor must be non-blocking, panic-free, and
  must not back-pressure into the vault. Documented on the trait.

### Cargo feature flags

The following feature names are frozen. New features may be added in
`MINOR` releases; existing features may not be renamed or removed
without a `MAJOR`.

```toml
default = ["std", "mlock", "zeroize", "fragment-standard", "decoy-self-ref"]

# Core
std, mlock, zeroize

# Fetchers
fetcher-keychain, fetcher-file, fetcher-env, fetcher-tpm, fetcher-all

# Fragments
fragment-standard, fragment-interleaved, fragment-random,
fragment-layered, fragment-all

# Decoys
decoy-random, decoy-self-ref, decoy-key-derived, decoy-all

# Layer 5: Codex
codex, codex-dynamic

# Layer 8: Monitor
monitor, monitor-tracing

# Layer 9: Audit
audit

# TEE
tee-detect

# Post-quantum (informational marker)
post-quantum

# Convenience presets
preset-balanced, preset-paranoid, preset-fast
```

### MSRV policy

- `1.0.0` ships with MSRV `1.85.0` (Rust edition 2024).
- Raising MSRV in a `1.x` release is allowed and is treated as a
  `MINOR` bump.
- Lowering MSRV is allowed (and would also be `MINOR`).
- The pin lives in `Cargo.toml` (`rust-version = "1.85"`) and in
  `rust-toolchain.toml`. CI exercises both `stable` and the pinned
  MSRV on Linux, macOS, and Windows.

---

## What is explicitly NOT frozen

These items may change in any `MINOR` release without warning. Do not
depend on them.

- Items behind `pub(crate)`, `pub(super)`, or `pub(in path)`.
- The internal modules `crate::memory`, `crate::metadata`,
  `crate::normalize`, `crate::handle::__for_test`. These have public
  paths only because the doctest and test infrastructure needs them;
  they are not part of the 1.0 contract.
- Exact byte layout of `Fragments`. The type round-trips identically
  through `fragment` / `defragment`, but its internal representation
  may be reshaped for performance.
- The text of error messages. The variants and their semantics are
  frozen; the human-readable strings are not. Programmatic callers
  must match on the variant.
- Internal allocation counts on the hot path. `docs/PERFORMANCE.md`
  reports current measurements; the contract is on the **wall-clock**
  targets, not on the dhat block count.
- Internal `tracing` event field names. Sinks that consume
  `LogMonitor` / `LogAudit` should treat the field set as
  best-effort. Custom sinks (implementing `SecurityMonitor` /
  `AuditSink` directly) receive structured data that is contract-
  bound.

---

## Migration policy

### Within `1.x`

- Additive items only. New traits, new methods (with default
  implementations), new feature flags, new enum variants on
  `#[non_exhaustive]` enums.
- Deprecated items are marked `#[deprecated(since = "X.Y.Z", note = "use ... instead")]`
  and remain functional until at least the next `MAJOR` release.

### `1.x` → `2.0`

A `2.0` release will land only when a documented design constraint
cannot be lifted within the 1.0 contract. The migration guide for
any future major release will:

1. List every breaking change.
2. Provide a per-change migration recipe.
3. Land in a `MAJOR-N-MIGRATION.md` document under `docs/` before the
   pre-release tag.

---

## Pre-1.0 history

Phases 0.1.0 through 0.11.0 + the 0.9.1 patch built up to the 1.0
contract. Pre-1.0 releases are documented in `docs/release/`. The
public API stabilised across those releases as follows:

- 0.2.0 — core type system, traits, `KeyHandle`, TEE detection.
- 0.3.0 — Layer 2/3/7 (mlock + fragmenter + zeroize).
- 0.4.0 — Layer 4 (3 decoy strategies).
- 0.5.0 — 3 additional fragment strategies + layered composition.
- 0.6.0 — Layer 5 (full codex stack).
- 0.7.0 — Layer 1 (4 fetchers).
- 0.8.0 — Layer 8 (monitor + threshold lockout).
- 0.9.0 — multi-key registry, rotation, master recovery.
- 0.9.1 — Layer 9 audit trail (closed deferral in 0.9.0).
- 0.10.0 — criterion benchmark suite + `docs/PERFORMANCE.md`.
- 0.11.0 — fuzz harness + property tests + mlock proof + dhat profile
  + audit fast-skip optimization.

The 1.0.0 stable cut adds the four 1.0-readiness docs
(this file, `ARCHITECTURE.md`, `PLATFORM-NOTES.md`, `HARDWARE.md`)
plus the REPS-compliance pass (lint set, `rust-toolchain.toml`,
`deny.toml`, CI supply-chain job).

---

<sub>key-vault Stability Contract — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
