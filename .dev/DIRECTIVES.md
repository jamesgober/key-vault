# key-vault - Directives

> Project-specific engineering directives. Apply on top of REPS and the portfolio universal directives.

---

## Priority order

1. `REPS.md` at repo root - **SUPREME AUTHORITY**
2. `_strategy/UNIVERSAL_PROMPT.md` - portfolio-wide directives
3. This file - key-vault specific directives
4. `docs/SECURITY.md` - 9-layer defense architecture
5. `.dev/PROMPT.md` - project context
6. `.dev/ROADMAP.md` - current phase and tasks

REPS overrides everything else.

---

## Security discipline (the central concern)

This crate handles cryptographic key material. A bug is a security bug. Every code change must be evaluated against the security implications.

### Non-negotiable

- **No raw key bytes in public API.** Public API exposes `KeyHandle`, never `&[u8]` or `Vec<u8>` to key material.
- **All key bytes wrapped in `Zeroizing<Vec<u8>>`** or equivalent zero-on-drop wrapper.
- **Constant-time comparisons** for any key equality check, using `subtle::ConstantTimeEq`.
- **`mlock`/`VirtualLock` by default** on fragment allocations.
- **No Debug exposure.** `KeyHandle::Debug` prints `KeyHandle(<redacted>)` only.
- **No serialization of key bytes** to any format that could persist (logs, error messages, panics).
- **9-layer defense by default.** Disabling any layer requires explicit user opt-out + documentation of trade-off.

### Fail-safe defaults

- Default features enable: `std`, `mlock`, `zeroize`, `fragment-standard`, `decoy-self-ref`
- Default fragment strategy: `StandardFragmenter` (the most-tested baseline)
- Default decoy strategy: `SelfReferenceDecoy` (strongest)
- Default codex: `IdentityCodex` (no-op, max performance — opt-in via `codex` feature for actual transformation)
- Default monitor: `NoMonitor` (opt-in for production use)
- Default key normalization: BLAKE3 (configurable)
- Default key size: 256 bits minimum (post-quantum safe for symmetric crypto)
- Default RNG: `getrandom` (OS-level CSPRNG)

### Defense layer composition

Every operational vault MUST have at minimum:
1. `mlock`/`VirtualLock` page locking (Layer 2)
2. Fragment storage (Layer 3, any strategy)
3. Decoy bytes (Layer 4, any strategy)
4. Constant-time comparison (Layer 6)
5. `zeroize` on drop (Layer 7)

Disabling any of these requires explicit user action (Cargo feature flag or runtime opt-out) and is documented as "reduced security mode" in rustdoc.

---

## Fragment strategy discipline

When implementing or modifying a `FragmentStrategy`:

- **Variable chunk sizes.** Never use fixed chunk sizes. Randomize per fragmentation.
- **Variable chunk counts.** Random number of chunks within reasonable bounds.
- **Position map stored separately.** The map of "fragment N is at memory location X" lives in a different protected memory region.
- **Per-vault randomization seed.** Each vault initialization gets a fresh seed.

When designing a new fragment strategy:

- Document the threat model it specifically defends against
- Document weaknesses or attack vectors it does NOT defend against
- Provide benchmarks: fragmentation time, defrag time, memory overhead
- Provide tests proving the basic property: fragment then defrag equals original key

---

## Decoy strategy discipline

When implementing or modifying a `DecoyStrategy`:

- **Filler must look like key material.** Use self-referential bytes or hash-derived filler, not raw RNG bytes that show as high-entropy regions.
- **No detectable patterns.** Statistical analysis of memory should not reveal where key bytes are.
- **Decoy generation is one-time.** Decoy bytes are computed at vault creation, not at every access.
- **Decoy must not contain plaintext key bytes accidentally.** Verify decoy generation never produces a sequence that matches actual key bytes.

---

## Codex discipline

When implementing or modifying a `Codex`:

- **Must be an involution.** `decode(encode(x)) == x`. Single transformation function used for both directions.
- **Lookup-table based for performance.** O(1) per byte, no branching.
- **Codex table is itself protected.** Stored in `Zeroizing` memory.
- **Default is no-op.** `IdentityCodex` is the default; users opt-in to actual codex via Cargo feature.

---

## Security monitor discipline

When implementing or modifying a `SecurityMonitor`:

- **Success path costs zero.** Monitor calls only fire on failure or anomaly.
- **No blocking on monitor calls.** Webhook calls happen on a separate thread; vault never blocks on monitor.
- **Failures in the monitor itself must not crash the vault.** Monitor errors logged, vault continues.
- **Thresholds are user-configurable per vault.**

---

## Fetcher discipline

When implementing or modifying a `KeyFetch`:

- **Acquisition errors must be specific.** Don't return generic "failed to acquire"; tell the caller what went wrong (no permission, hardware not available, key not found, etc.).
- **No retry of failed acquisitions.** A failure to find a key is not a transient error; it's a configuration error. Let the caller decide.
- **Acquisition is slow path.** Optimize for correctness, not speed. Sub-second is acceptable.
- **Audit logging of acquisition.** Every successful and failed acquisition logged through `log-io` if available.
- **No caching of acquired keys.** The vault caches in fragmented form; the fetcher returns once.

### Built-in fetchers

- `KeychainFetch` - OS keychain (via `keyring` crate)
- `FileFetch` - encrypted file (the encryption uses a derived key from a master key)
- `EnvFetch` - environment variable (with redaction in error messages)
- `TpmFetch` - TPM 2.0 (DETECTION only at 1.0, full integration deferred)

### Custom fetchers

Users implement `KeyFetch` trait. They get the same security guarantees automatically.

---

## REPS compliance (non-negotiable)

`src/lib.rs` MUST contain:

```rust
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_must_use)]
#![deny(unused_results)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::missing_safety_doc)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
```

Internal `unsafe` is acceptable but must:

1. Be in a private function or module
2. Have a `// SAFETY:` comment explaining invariants
3. Be exercised by tests (Miri preferred)
4. Be minimized — prefer safe alternatives

---

## Performance discipline

Hot path: key access (defrag). Slow path: acquisition.

### Hot path requirements

- Sub-microsecond defrag into temporary buffer
- No allocation on common paths (use thread-local scratch buffers)
- Lock-free reads via `ArcSwap`
- `#[inline]` on accessor methods

### Slow path is fine

- Acquisition can take milliseconds to seconds (hardware queries are slow)
- Vault setup can take longer (one-time cost on application startup)
- Fragmentation can take microseconds (one-time per key)

### Required benchmarks

- Access latency (defrag time) per fragment strategy
- Access latency with and without codex
- Concurrent access (no degradation under load)
- Memory overhead (per-key and total)
- Each fragment strategy's setup time
- Each decoy strategy's setup time

---

## Testing discipline

The vault MUST have:

### Unit tests
- Each fetcher: success and failure paths
- Each fragment strategy: fragment -> defrag round-trip equality
- Each fragment strategy: variable inputs (32 bytes, 256 bytes, 1KB, 4KB)
- Each decoy strategy: statistical indistinguishability from key
- Each codex: involution property (decode(encode(x)) == x)
- KeyHandle: opacity, no leaks through Debug
- Master key recovery flow
- Key rotation atomicity
- Each security monitor: failure detection accuracy

### Property tests (proptest)
- Fragment -> defrag preserves bytes exactly for any input length
- Multiple fragmentations of same key produce different memory layouts
- Memory regions don't overlap inappropriately
- Codex involution for all bytes 0-255

### Concurrency tests
- 8 threads concurrently accessing the same KeyHandle - no corruption
- Vault rotation while access is in progress - no torn reads
- Multiple monitors fired concurrently - no deadlock

### Fuzz tests
- Each fetcher: fuzz the input source
- Each fragment strategy: fuzz the key bytes
- Each decoy strategy: fuzz the input
- Codex: fuzz with random byte tables
- Configuration fuzz: any bad config returns error, not panic

### Integration tests
- Real keychain acquisition (gated by env var for CI)
- Real file acquisition with on-disk encryption
- Memory leak verification across many register/drop cycles

### Security tests
- Verify `mlock` actually prevents swap (Linux: check `/proc/self/status`)
- Verify `zeroize` actually overwrites memory (manual check via `dhat`)
- Verify Debug doesn't leak bytes (doctest)
- Verify constant-time property (via `dudect` or similar)

---

## Dependencies

Approved dependencies for 1.0:

- `subtle = "2.5"` - constant-time comparisons
- `arc-swap = "1.7"` - lock-free vault state
- `getrandom = "0.2"` - OS CSPRNG
- `rand_core = "0.6"` - RNG traits
- `blake3 = "1"` - cryptographic hash for key normalization

Optional dependencies (feature-gated):

- `zeroize = "1.7"` - zero-on-drop (default on)
- `keyring = "3"` - OS keychain integration (feature: fetcher-keychain)
- `tracing = "0.1"` - tracing integration for monitor (feature: monitor-tracing)

Approved dev-dependencies:

- `criterion = "0.5"` - benchmarks
- `proptest = "1"` - property tests

**Future considerations** (probably 1.x post-launch):

- `tss-esapi` for TPM 2.0 support (feature: fetcher-tpm)
- `aws-sdk-kms` for AWS KMS fetcher (feature: fetcher-aws-kms)
- `azure_identity` for Azure Key Vault fetcher

**New dependencies require:**
- Strong justification (why can't we implement this in-house?)
- License compatibility (Apache-2.0 / MIT / compatible)
- MSRV check (must support Rust 1.75)
- `cargo audit` clean
- Security review (these touch crypto material)

---

## Out of scope (always)

- **Encryption/decryption algorithms.** That's `crypt-io`'s responsibility.
- **Network-based KMS.** Use a KMS-specific client library and bridge via `KeyFetch`.
- **Distributed key storage.** Different problem, different crate.
- **Web UI for vault management.** Operational tooling, separate concern.
- **Password manager features.** Different problem domain.
- **Identity management.** Different problem domain.

---

## When you must break a directive

If a directive in this file genuinely needs an exception:

1. STOP. Don't break it silently. Security crate.
2. Document why in the PR description.
3. Get explicit maintainer approval.
4. Add a `// KEY-VAULT-EXCEPTION:` comment at the violation point with the rationale.
5. Update this file or `.dev/PROMPT.md` if the exception reveals a flaw in the directive.
6. For security-related exceptions, also document in `docs/SECURITY.md`.

---

<sub>key-vault directives - Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>