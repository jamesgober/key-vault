# key-vault - Project Prompt

> Context document for AI editor sessions working on `key-vault`.
> Read this BEFORE writing any code on this crate.

---

## Read order (mandatory)

1. `REPS.md` at repo root - Rust Efficiency & Performance Standards. **SUPREME AUTHORITY.**
2. `_strategy/UNIVERSAL_PROMPT.md` - portfolio-wide engineering directives.
3. `.dev/DIRECTIVES.md` - this project's specific directives.
4. `docs/SECURITY.md` - the 9-layer defense architecture (comprehensive reference).
5. `docs/TRANSFORMATION.md` - visual walkthrough of key transformation.
6. This file - project context.
7. `.dev/ROADMAP.md` - current phase, milestone targets, exit criteria.

REPS is mandatory and overrides anything else in this repository.

---

## What this crate is

`key-vault` is an **enterprise-grade in-memory key management vault** for Rust. It implements **9 layers of defense-in-depth** to keep cryptographic key material safe:

1. **Secure Acquisition** (TPM/HSM/Keychain via `KeyFetch` trait)
2. **Memory Page Locking** (mlock/VirtualLock — prevents swap)
3. **Fragment Strategy** (variable-size chunks, shuffled, mlock'd)
4. **Decoy Bytes** (self-referential filler, statistically indistinguishable)
5. **Codex Transformation** (byte swap via involution: encode == decode)
6. **Constant-Time Operations** (subtle::ConstantTimeEq)
7. **Zero-On-Drop** (zeroize crate)
8. **Security Monitor** (failed decrypt detection, threshold lockout)
9. **Audit Logging** (every key access, caller context, via log-io)

Plus a **bonus Layer 10**: page protection toggling (PROT_NONE when not in use).

It is the **key management primitive for the Hive DB stack** and is intended to be the canonical key-management crate in the Rust ecosystem.

## What it is NOT

- A cryptographic library (encryption algorithms live in a sibling crate, `crypt-io`)
- A centralized secrets manager (use HashiCorp Vault for that)
- A password manager (different problem domain)
- A KMS client (those are fetcher plugins on top of this)

## Why it exists

Most Rust applications that handle key material:

- Store keys in `Vec<u8>` or `String` — readable in memory dumps
- Don't lock pages — keys leak via swap files
- Don't zeroize on drop — keys persist after use
- Have no fragment/decoy — pattern recognition finds them
- Tightly couple key acquisition to encryption — hard to swap sources
- Have no failed-decrypt detection — brute-force attacks succeed silently

`key-vault` fills this gap with a focused, REPS-compliant, audited, 9-layer-protected primitive.

## Downstream dependencies

This crate is foundational for:

- **`crypt-io`** - the encryption library uses vault for key references
- **Hive DB storage layer** - encryption at rest of CORD pages
- **`audit-trail`** - record signing keys
- **`hive-server`** - TLS session keys, JWT signing keys
- **`DISTRO`** - encrypted WAL key management
- **Any application needing secure in-memory key storage**

## Naming conventions (locked in)

- **Trait: `KeyFetch`** — handles acquisition (NOT `KeyAcquirer`, NOT `KeyFetcher`)
- **Operation: `defrag`** — defragmentation/reassembly (NOT `defragment`, NOT `reassemble`)
- **Filler bytes: `Decoy`** — `DecoyStrategy` trait, `KeyDecoy` type
- **Strategy splitting key: `Fragment`** — `FragmentStrategy` trait, `StandardFragmenter` etc.
- **Memory lock: `mlock`** — short, matches POSIX (NOT `memlock`)
- **Byte swap layer: `Codex`** — `Codex` trait, `IdentityCodex`/`StaticCodex`/`DynamicCodex`/`FnCodex`
- **Failure detection: `SecurityMonitor`** trait, with monitor implementations

## Status

**Version:** `0.7.0` — Layers **1 (built-in fetchers: `EnvFetch`, `FileFetch`, `KeychainFetch`, `TpmFetch` detection-only)**, **2 (mlock)**, **3 (all four fragment strategies)**, **4 (3 decoy strategies)**, **5 (full codex)**, **6 (constant-time `KeyHandle`)**, **7 (zero-on-drop)**. Defense layers 1/2/3/4/5/6/7 (7 out of 9) are complete. Layer 8 (monitor implementations) and Layer 9 (audit logging) remain. Next phase: 0.8.0 — `SecurityMonitor` impls + audit logging.
**Target:** `1.0.0` stable. Effort estimate: 4-5 weeks focused work.
**MSRV:** Rust 1.85 (edition 2024).
**Priority:** MAXIMUM. Premium quality on all deliverables.

## Skill areas

Working on this crate requires comfort with:

- **Cryptographic best practices** - constant-time ops, side-channel awareness, defense-in-depth
- **Low-level memory management** - mmap, mlock, page protection, manual allocation
- **Pluggable architectures** - trait-based extension points
- **Defensive programming** - threat modeling, fail-safe defaults
- **Cross-platform OS APIs** - Windows DPAPI/Credential Manager, macOS Keychain, Linux Secret Service
- **Hardware integration** - TPM 2.0, HSM patterns (detection only in 1.0)
- **Lock-free data structures** - ArcSwap for vault state
- **Zeroize discipline** - knowing when and how to overwrite memory
- **Hashing** - BLAKE3 for key normalization

## Scope (1.0)

### In scope for 1.0

- **`KeyVault`** core type with builder API
- **`KeyHandle`** opaque reference to a stored key
- **`KeyFetch` trait** with built-in implementations:
  - `KeychainFetch` (OS keychain)
  - `FileFetch` (encrypted file)
  - `EnvFetch` (environment variable)
  - `TpmFetch` (TPM 2.0 — DETECTION ONLY at 1.0, full integration deferred)
- **`FragmentStrategy` trait** with built-in implementations:
  - `StandardFragmenter` (variable chunks + shuffle)
  - `InterleavedFragmenter` (interleaved bytes)
  - `RandomFragmenter` (non-contiguous fragments)
  - `LayeredFragmenter` (composition)
- **`DecoyStrategy` trait** with built-in implementations:
  - `RandomDecoy` (raw RNG)
  - `SelfReferenceDecoy` (real key bytes as filler — default)
  - `KeyDerivedDecoy` (hash-derived to match entropy)
- **`Codex` trait** with built-in implementations:
  - `IdentityCodex` (no-op, default)
  - `StaticCodex` (build-time table for private builds)
  - `DynamicCodex` (per-vault randomized)
  - `FnCodex` (user closure)
- **`SecurityMonitor` trait** with built-in implementations:
  - `NoMonitor` (default)
  - `LogMonitor` (via log-io or tracing)
  - `MetricsMonitor` (via metrics-lib)
  - `WebhookMonitor` (HTTP POST)
  - `CompositeMonitor` (chains)
- **TEE detection** — `detect_tee_capabilities()` for Intel SGX/TDX, AMD SEV, ARM TrustZone, Apple Secure Enclave, AWS Nitro
- **Memory protection** - mlock, zeroize on drop, page guards
- **Master key recovery** - fallback path
- **Key rotation** - atomic swap
- **Multi-key vaults** - named keys with independent lifecycles
- **Key normalization** - BLAKE3 hash to neutralize format pattern leaks
- **Comprehensive benchmarks** - access latency, memory overhead
- **Fuzz testing** - fetcher inputs, fragment strategies, decoy strategies, codex
- **Full REPS compliance** - all lints, all tests, all docs

### Out of scope (deferred to 1.x)

- **Cryptographic operations** - that's `crypt-io`'s responsibility
- **Full TPM integration** (detection only in 1.0)
- **Network-based KMS clients** (AWS KMS, GCP KMS, Azure Key Vault) - 1.1+, separate fetcher feature
- **Apple Secure Enclave full integration** (detection only in 1.0)
- **AWS Nitro Enclaves full integration** (detection only in 1.0)
- **Distributed vault** - keys shared across processes (separate problem, separate crate)
- **Web UI for key management** - operational tooling, separate concern
- **Post-quantum asymmetric algorithms** - 1.x or 2.x when standards stabilize

## Performance targets (verified by benchmark)

| Operation | Target |
|-----------|--------|
| Vault creation, empty | <100µs |
| Key acquisition from keychain | <10ms |
| Key acquisition from file | <1ms |
| Key access (defrag, no codex) | <500ns |
| Key access (defrag with codex) | <1µs |
| Concurrent reads on same handle | lock-free, no degradation |
| Memory overhead per key | <16 KiB |

## Security targets

| Property | Verification |
|----------|--------------|
| Zero unsafe code in public API | code review + Miri |
| No key bytes leak via Debug | doctest + fuzz |
| No timing leaks on key comparison | const-time benchmark |
| No memory persistence after drop | zeroize integration tests |
| Fuzz clean for 1 CPU-hour per fetcher | cargo-fuzz |
| Fuzz clean for 1 CPU-hour per fragment | cargo-fuzz |
| `cargo audit` clean | CI |
| `cargo deny check` clean | CI |
| 9-layer architecture documented | docs/SECURITY.md |
| Visual walkthrough complete | docs/TRANSFORMATION.md |

## Architectural constraints

### MUST

- Zero unsafe code in the public API (internal unsafe acceptable with `// SAFETY:` and Miri verification)
- All key bytes go through `Zeroizing<Vec<u8>>` or equivalent zero-on-drop wrapper
- All key comparisons use `subtle::ConstantTimeEq`
- `mlock`/`VirtualLock` on fragment allocations by default
- BLAKE3 key normalization as default option
- Cross-platform identical behavior (Linux, macOS, Windows)
- Compatible with stable Rust 1.75+

### MUST NOT

- Expose raw `&[u8]` to key material in any public API
- Use `String` or `Vec<u8>` for key storage (must use protected types)
- Allow `Debug` to print key bytes (ever)
- Use variable-time comparisons on key material
- Rely on a single defense layer

## How to develop on this crate

1. Read this document, REPS, DIRECTIVES, ROADMAP, SECURITY.md.
2. Check current phase in `.dev/ROADMAP.md`.
3. Pick the next unchecked task.
4. Implement with REPS + security discipline:
   - No `unwrap`, no `expect`, no `todo!`, no `unimplemented!`
   - No `print_stdout`, no `print_stderr`, no `dbg!`
   - Every new public item: rustdoc + at least one example
   - Every new fetcher/fragment/decoy/codex: corresponding test suite
   - Every cryptographic operation: constant-time verified
5. Update `CHANGELOG.md` under `[Unreleased]` in the same commit.
6. Run the full CI gate locally before pushing.
7. Mark the task done in `.dev/ROADMAP.md` in the same commit.
8. Push.

## Reference patterns

When designing the vault, study:

- `secrecy` crate - opaque secret wrapper patterns
- `keyring` crate - OS keychain abstractions
- `zeroize` crate - secure memory wiping
- `subtle` crate - constant-time operations
- `aws-lc-rs` - production crypto patterns
- `ring` - constant-time discipline

When designing fragment algorithms:

- Memory hiding techniques in research papers
- Boojum (cryptocurrency wallet) for inspiration on key handling
- 1Password's approach to memory-resident secrets

## When in doubt

- Read REPS first.
- Check the security target table.
- If a feature isn't in the roadmap, propose it (update roadmap first) before implementing.
- If a defense layer is contested, ask: "What attack does this prevent that the existing layers don't?"
- If performance is contested, write a benchmark.
- For cryptographic decisions, default to the most conservative option and document rationale.

---

<sub>key-vault - Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>