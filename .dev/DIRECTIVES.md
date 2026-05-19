# key-vault - Directives

> Project-specific engineering directives. Apply on top of REPS and the portfolio universal directives.

---

## Priority order

1. `REPS.md` at repo root - **SUPREME AUTHORITY**
2. `_strategy/UNIVERSAL_PROMPT.md` - portfolio-wide directives
3. This file - key-vault specific directives
4. `.dev/PROMPT.md` - project context
5. `.dev/ROADMAP.md` - current phase and tasks

REPS overrides everything else.

---

## Security discipline (the central concern)

This crate handles cryptographic key material. A bug is a security bug. Every code change must be evaluated against the security implications.

### Non-negotiable

- **No raw key bytes in public API.** Public API exposes `KeyHandle`, never `&[u8]` or `Vec<u8>` to key material.
- **All key bytes wrapped in `Zeroizing<Vec<u8>>`** or equivalent zero-on-drop wrapper.
- **Constant-time comparisons** for any key equality check, using `subtle::ConstantTimeEq`.
- **`mlock`/`VirtualLock` by default** on scatter allocations.
- **No Debug exposure.** `KeyHandle::Debug` prints `KeyHandle(<redacted>)` only.
- **No serialization of key bytes** to any format that could persist (logs, error messages, panics).

### Fail-safe defaults

- Default features enable: `std`, `mlock`, `zeroize`
- Default scatter strategy: `StandardScatter` (the most-tested baseline)
- Default key size: 256 bits minimum (post-quantum safe for symmetric crypto)
- Default RNG: `getrandom` (OS-level CSPRNG)

### Defense layer composition

Every operational vault MUST have at minimum:
1. `mlock`/`VirtualLock` page locking
2. Scattered storage (one of the strategies)
3. `zeroize` on drop
4. Constant-time comparison for key equality

Disabling any of these requires explicit user action (Cargo feature flag or runtime opt-out) and is documented as "reduced security mode" in rustdoc.

---

## Scatter strategy discipline

When implementing or modifying a `ScatterStrategy`:

- **Variable chunk sizes.** Never use fixed chunk sizes. Randomize per scatter.
- **Variable chunk counts.** Random number of chunks within reasonable bounds.
- **Filler must look like key material.** Use self-referential bytes or hash-derived filler, not raw RNG bytes that show as high-entropy regions.
- **No detectable patterns.** Statistical analysis of memory should not reveal where key bytes are.
- **Position tracking is opaque.** The reassembly map is itself stored in a protected memory region.
- **Per-scatter randomization seed.** Each vault initialization gets a fresh seed.

When designing a new scatter strategy:

- Document the threat model it specifically defends against
- Document weaknesses or attack vectors it does NOT defend against
- Provide benchmarks: scatter time, reassemble time, memory overhead
- Provide tests proving the basic property: scatter then reassemble equals original key

---

## Acquirer discipline

When implementing or modifying a `KeyAcquirer`:

- **Acquisition errors must be specific.** Don't return generic "failed to acquire"; tell the caller what went wrong (no permission, hardware not available, key not found, etc.).
- **No retry of failed acquisitions.** A failure to find a key is not a transient error; it's a configuration error. Let the caller decide.
- **Acquisition is slow path.** Optimize for correctness, not speed. Sub-second is acceptable.
- **Audit logging of acquisition.** Every successful and failed acquisition logged through `log-io` if available.
- **No caching of acquired keys.** The vault caches in scattered form; the acquirer returns once.

### Built-in acquirers

- `KeychainAcquirer` - OS keychain (via `keyring` crate)
- `FileAcquirer` - encrypted file (the encryption uses a derived key from a master key)
- `EnvAcquirer` - environment variable (with redaction in error messages)
- `TpmAcquirer` - TPM 2.0 (Linux + Windows, feature-gated)

### Custom acquirers

Users implement `KeyAcquirer` trait. They get the same security guarantees automatically.

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

Hot path: key access (reassembly). Slow path: acquisition.

### Hot path requirements

- Sub-microsecond reassembly into temporary buffer
- No allocation on common paths (use thread-local scratch buffers)
- Lock-free reads via `ArcSwap`
- `#[inline]` on accessor methods

### Slow path is fine

- Acquisition can take milliseconds to seconds (hardware queries are slow)
- Vault setup can take longer (one-time cost on application startup)
- Scatter computation can take microseconds (one-time per key)

### Required benchmarks

- Access latency (reassembly time)
- Concurrent access (no degradation under load)
- Memory overhead (per-key and total)
- Each scatter strategy's setup time

---

## Testing discipline

The vault MUST have:

### Unit tests
- Each acquirer: success and failure paths
- Each scatter: scatter -> reassemble round-trip equality
- Each scatter: variable inputs (32 bytes, 256 bytes, 1KB, 4KB)
- KeyHandle: opacity, no leaks through Debug
- Master key recovery flow
- Key rotation atomicity

### Property tests (proptest)
- Scatter -> reassemble preserves bytes exactly for any input length
- Multiple scatters of same key produce different memory layouts
- Memory regions don't overlap inappropriately

### Concurrency tests
- 8 threads concurrently accessing the same KeyHandle - no corruption
- Vault rotation while access is in progress - no torn reads

### Fuzz tests
- Each acquirer: fuzz the input source
- Each scatter strategy: fuzz the key bytes
- Configuration fuzz: any bad config returns error, not panic

### Integration tests
- Real keychain acquisition (gated by env var for CI)
- Real file acquisition with on-disk encryption
- Memory leak verification across many register/drop cycles

### Security tests
- Verify `mlock` actually prevents swap (Linux: check `/proc/self/status`)
- Verify `zeroize` actually overwrites memory (manual check via `dhat`)
- Verify Debug doesn't leak bytes (doctest)

---

## Dependencies

Approved dependencies for 1.0:

- `subtle = "2.5"` - constant-time comparisons
- `arc-swap = "1.7"` - lock-free vault state
- `getrandom = "0.2"` - OS CSPRNG
- `rand_core = "0.6"` - RNG traits

Optional dependencies (feature-gated):

- `zeroize = "1.7"` - zero-on-drop (default on)
- `keyring = "3"` - OS keychain integration (feature: acquirer-keychain)

Approved dev-dependencies:

- `criterion = "0.5"` - benchmarks
- `proptest = "1"` - property tests

**Future considerations** (probably 1.x post-launch):

- `tss-esapi` for TPM 2.0 support (feature: acquirer-tpm)
- `aws-sdk-kms` for AWS KMS acquirer (feature: acquirer-aws-kms)
- `azure_identity` for Azure Key Vault acquirer

**New dependencies require:**
- Strong justification (why can't we implement this in-house?)
- License compatibility (Apache-2.0 / MIT / compatible)
- MSRV check (must support Rust 1.75)
- `cargo audit` clean
- Security review (these touch crypto material)

---

## Out of scope (always)

- **Encryption/decryption algorithms.** That's `crypt-io`'s responsibility.
- **Network-based KMS.** Use a KMS-specific client library and bridge via `KeyAcquirer`.
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