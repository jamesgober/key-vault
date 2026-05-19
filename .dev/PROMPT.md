# key-vault - Project Prompt

> Context document for AI editor sessions working on `key-vault`.
> Read this BEFORE writing any code on this crate.

---

## Read order (mandatory)

1. `REPS.md` at repo root - Rust Efficiency & Performance Standards. **SUPREME AUTHORITY.**
2. `_strategy/UNIVERSAL_PROMPT.md` - portfolio-wide engineering directives.
3. `.dev/DIRECTIVES.md` - this project's specific directives.
4. This file - project context.
5. `.dev/ROADMAP.md` - current phase, milestone targets, exit criteria.

REPS is mandatory and overrides anything else in this repository.

---

## What this crate is

`key-vault` is an **enterprise-grade in-memory key management vault** for Rust. It keeps cryptographic key material safe via defense-in-depth:

- Memory page locking (no swap to disk)
- Scattered storage with distortion patterns
- Zero-on-drop
- Constant-time comparisons
- Pluggable acquisition from hardware, OS keychains, files, environment

It is the **key management primitive for the Hive DB stack** and is intended to be the canonical key-management crate in the Rust ecosystem.

## What it is NOT

- A cryptographic library (encryption algorithms live in a sibling crate, `crypt-io`)
- A centralized secrets manager (use HashiCorp Vault for that)
- A password manager (different problem domain)
- A KMS client (those are acquirer plugins on top of this)

## Why it exists

Most Rust applications that handle key material:

- Store keys in `Vec<u8>` or `String` — readable in memory dumps
- Don't lock pages — keys leak via swap files
- Don't zeroize on drop — keys persist after use
- Have no scatter/distortion — pattern recognition finds them
- Tightly couple key acquisition to encryption — hard to swap sources

`key-vault` fills this gap with a focused, REPS-compliant, well-audited primitive.

## Downstream dependencies

This crate is foundational for:

- **`crypt-io`** - the encryption library uses vault for key references
- **Hive DB storage layer** - encryption at rest of CORD pages
- **`audit-trail`** - record signing keys
- **`hive-server`** - TLS session keys, JWT signing keys
- **`DISTRO`** - encrypted WAL key management
- **Any application needing secure in-memory key storage**

## Status

**Version:** `0.1.0` - scaffolded, no implementation yet.
**Target:** `1.0.0` stable. Effort estimate: 4-5 weeks focused work.

## Skill areas

Working on this crate requires comfort with:

- **Cryptographic best practices** - constant-time ops, side-channel awareness, defense-in-depth
- **Low-level memory management** - mmap, mlock, page protection, manual allocation
- **Pluggable architectures** - trait-based extension points
- **Defensive programming** - threat modeling, fail-safe defaults
- **Cross-platform OS APIs** - Windows DPAPI/Credential Manager, macOS Keychain, Linux Secret Service
- **Hardware integration** - TPM 2.0, HSM patterns
- **Lock-free data structures** - ArcSwap for vault state
- **Zeroize discipline** - knowing when and how to overwrite memory

## Scope (1.0)

### In scope for 1.0

- **`KeyVault`** core type with builder API
- **`KeyHandle`** opaque reference to a stored key
- **`KeyAcquirer` trait** with built-in implementations:
  - `KeychainAcquirer` (OS keychain)
  - `FileAcquirer` (encrypted file)
  - `EnvAcquirer` (environment variable)
  - `TpmAcquirer` (TPM 2.0, Linux/Windows)
- **`ScatterStrategy` trait** with built-in implementations:
  - `StandardScatter` (chunked shuffle + filler)
  - `InterleavedScatter` (interleaved bytes)
  - `FragmentedScatter` (non-contiguous fragments)
  - `LayeredScatter` (composition)
- **Memory protection** - mlock, zeroize on drop, page guards
- **Master key recovery** - fallback path
- **Key rotation** - atomic swap
- **Multi-key vaults** - named keys with independent lifecycles
- **Comprehensive benchmarks** - access latency, memory overhead
- **Fuzz testing** - acquirer inputs, scatter strategies
- **Full REPS compliance** - all lints, all tests, all docs

### Out of scope (deferred to 1.1+)

- **Cryptographic operations** - that's `crypt-io`'s responsibility
- **Network-based KMS clients** (AWS KMS, GCP KMS, Azure Key Vault) - 1.1+, separate acquirer feature
- **Distributed vault** - keys shared across processes (separate problem, separate crate)
- **Web UI for key management** - operational tooling, separate concern
- **Post-quantum asymmetric algorithms** - 1.x or 2.x when standards stabilize

## Performance targets (verified by benchmark before claiming)

| Operation | Target |
|-----------|--------|
| Vault creation, empty | <100us |
| Key acquisition from keychain | <10ms |
| Key acquisition from file | <1ms |
| Key access (reassembly into temp buffer) | <1us |
| Concurrent reads on same handle | lock-free, no degradation |
| Memory overhead per key | <16 KiB |
| `mlock` setup overhead | <10us |
| `zeroize` overhead | <1us per byte |

## Security targets

| Property | Verification |
|----------|--------------|
| Zero unsafe code in public API | code review + Miri |
| No key bytes leak via Debug | doctest + fuzz |
| No timing leaks on key comparison | const-time benchmark |
| No memory persistence after drop | `zeroize` integration tests |
| Fuzz clean for 1 CPU-hour per acquirer | cargo-fuzz |
| `cargo audit` clean | CI |
| `cargo deny check` clean | CI |

## Architectural constraints

### MUST

- Zero unsafe code in the public API (internal unsafe acceptable with `// SAFETY:` and Miri verification)
- All key bytes go through `Zeroizing<Vec<u8>>` or equivalent zero-on-drop wrapper
- All key comparisons use `subtle::ConstantTimeEq`
- `mlock`/`VirtualLock` on scatter allocations by default
- Cross-platform identical behavior (Linux, macOS, Windows)
- Compatible with stable Rust 1.75+

### MUST NOT

- Expose raw `&[u8]` to key material in any public API
- Use `String` or `Vec<u8>` for key storage (must use protected types)
- Allow `Debug` to print key bytes (ever)
- Use variable-time comparisons on key material
- Rely on a single defense layer

## How to develop on this crate

1. Read this document, REPS, DIRECTIVES, ROADMAP.
2. Check current phase in `.dev/ROADMAP.md`.
3. Pick the next unchecked task.
4. Implement with REPS + security discipline:
   - No `unwrap`, no `expect`, no `todo!`, no `unimplemented!`
   - No `print_stdout`, no `print_stderr`, no `dbg!`
   - Every new public item: rustdoc + at least one example
   - Every new acquirer/scatter: corresponding test suite
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

When designing scatter algorithms:

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