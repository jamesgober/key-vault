# Security Architecture

> **9-Layer Defense-in-Depth + 1 Bonus Layer**
>
> This document is the full security architecture for `key-vault`. Every layer is documented with what it defends against, what it does NOT defend against, performance impact, and how it composes with other layers.

---

## Why layers

No single defense is bulletproof. A sophisticated attacker with unlimited time and access can defeat any one technique. Real-world security comes from layered defenses where:

1. Each layer adds friction
2. Layers are independent (defeating one doesn't defeat the others)
3. Multiple layers must fail simultaneously for total compromise
4. The cost of attack exceeds the value of the target

The 0.1% of elite attackers may still win. The other 99.9% — opportunistic attackers, automated tools, forensic recovery — get stopped at one of the layers.

---

## The 9 layers (plus bonus)

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: Secure Acquisition (TPM/HSM/Keychain)             │
│  ├── Hardware-rooted trust where available                  │
│  └── Untrusted input is never accepted                      │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: Memory Page Locking (mlock / VirtualLock)         │
│  ├── Prevents swap to disk                                  │
│  └── Reduces hibernation/coredump exposure                  │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3: Fragment Strategy (key splicing + shuffling)      │
│  ├── Variable chunk sizes (1-8 bytes typical)               │
│  ├── Variable chunk counts (8-64 per scatter)               │
│  └── Per-vault randomized layout                            │
├─────────────────────────────────────────────────────────────┤
│  LAYER 4: Decoy Bytes (nonsense filler)                     │
│  ├── Self-referential (looks like real key material)        │
│  ├── Key-derived (matches statistical profile)              │
│  └── Defeats entropy/frequency analysis                     │
├─────────────────────────────────────────────────────────────┤
│  LAYER 5: Codex Transformation (byte swap)                  │
│  ├── Per-vault or per-build transformation table            │
│  ├── Involutional (encode == decode operation)              │
│  └── Adds work for attacker even with memory access         │
├─────────────────────────────────────────────────────────────┤
│  LAYER 6: Constant-Time Operations                          │
│  ├── No timing side-channels on key comparisons             │
│  └── subtle::ConstantTimeEq for all equality checks         │
├─────────────────────────────────────────────────────────────┤
│  LAYER 7: Zero-On-Drop                                      │
│  ├── zeroize crate overwrites memory on drop                │
│  └── No persistence in freed memory                         │
├─────────────────────────────────────────────────────────────┤
│  LAYER 8: Security Monitor (failure detection)              │
│  ├── Failed decryption attempts trigger alerts              │
│  ├── Anomalous access patterns logged                       │
│  └── Pluggable: webhook, metrics, logs, custom              │
├─────────────────────────────────────────────────────────────┤
│  LAYER 9: Audit Logging (access tracking)                   │
│  ├── Every key access logged with context                   │
│  ├── Caller identification, timestamp, thread               │
│  └── Anomalies surface for forensic review                  │
├─────────────────────────────────────────────────────────────┤
│  BONUS LAYER 10: Page Protection Toggling                   │
│  ├── PROT_NONE when not in use                              │
│  ├── PROT_READ only during reassembly                       │
│  └── Reduces vulnerability window                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Secure Acquisition

### What it does

Determines where keys come from. The root of trust for everything else.

### Defends against

- Untrusted user input becoming a key
- Hardcoded keys in source code
- Keys in environment variables read by other processes
- Keys in files with weak permissions

### Implementation

The `KeyFetch` trait is the pluggable acquisition mechanism:

```rust
pub trait KeyFetch: Send + Sync {
    fn fetch(&self, ctx: &FetchContext) -> Result<RawKey>;
}
```

Built-in fetchers (all feature-gated):

| Fetcher | Source | Security level |
|---------|--------|---------------|
| `TpmFetch` | TPM 2.0 hardware | Highest (hardware-backed) |
| `KeychainFetch` | OS keychain | High (OS-protected) |
| `FileFetch` | Encrypted file | Medium (encrypted at rest) |
| `EnvFetch` | Environment variable | Low (process-readable) |

### Performance

- One-time cost at startup: 1ms - 100ms depending on source
- Zero impact at runtime: keys are fetched once, then cached in fragmented form

### Trade-offs

- TPM: Highest security, slowest acquisition (~100ms), requires hardware
- Keychain: Good security, fast (<10ms), requires OS support
- File: Acceptable security with encryption, fast (<1ms)
- Env: Lowest security, fastest (<1µs), suitable for development only

---

## Layer 2: Memory Page Locking (mlock)

### What it does

Tells the OS "do not move these memory pages to disk." Pages stay in RAM, never written to swap or hibernation.

### Defends against

- Swap file persistence (keys ending up on disk via OS paging)
- Hibernation file exposure (partially — some platforms handle locked pages specially)
- Forensic recovery from disk
- Cold-boot attacks (reduces but doesn't eliminate)

### Does NOT defend against

- Privileged code reading RAM directly
- Hardware compromise (e.g., DMA attacks)
- Kernel-level forensic tools

### Implementation

Linux/macOS: `mlock(addr, len)` and `munlock(addr, len)`
Windows: `VirtualLock(addr, size)` and `VirtualUnlock(addr, size)`

Applied automatically to every fragment allocation. Pages are unlocked on drop after zeroize.

### Performance

- One-time cost: ~1µs per `mlock` call (rare path)
- Zero runtime cost: doesn't affect read/write operations

### Limitations

- Locked memory counts against process limits (RLIMIT_MEMLOCK on Linux)
- Linux requires CAP_IPC_LOCK or appropriate ulimit
- Windows: works at page granularity

---

## Layer 3: Fragment Strategy

### What it does

Splits the key into variable-size chunks at non-contiguous memory addresses. The original key never exists as contiguous bytes in memory after fragmentation.

### Defends against

- Memory scraping for high-entropy regions
- Pattern matching for known key formats
- Linear memory dumps
- Adjacent memory leaks (a vulnerability finds the wrong chunk)

### Does NOT defend against

- Reverse engineering of the reassembly logic
- Targeted attacks that can trace allocations

### Implementation

```
ORIGINAL KEY:    0fx03mmqrhxhrk13
                 ↓
FRAGMENTS:       ["hxh", "03", "m", "fx", "k13", "qrr", "0m"]  (shuffled)
                 ↓
STORED AT:       0x7fa1b2c3 (allocation 1), 0x7fa1b400 (allocation 2), ...
                 (non-contiguous addresses, mlock'd)
```

Variable chunk sizes: 1-8 bytes typical (configurable via `frag_min`, `frag_max`)
Variable chunk counts: 8-64 chunks per scatter (depends on key length)
Per-scatter random seed: each vault initialization gets fresh randomization

### Strategies (shipped in 0.5.0)

| Strategy                | Storage shape                              | Layout encoding                        | Defends best against    | Memory overhead |
|-------------------------|--------------------------------------------|----------------------------------------|-------------------------|-----------------|
| `StandardFragmenter`    | Many `LockedBytes`, each 1–8 contiguous key bytes, shuffled order | One u32 offset per chunk; `u32::MAX` sentinel for decoy chunks | Pattern recognition + linear scans | 1–2× key (with decoy) |
| `RandomFragmenter`      | Many `LockedBytes` (default 1–4 bytes), each holding bytes drawn from **non-contiguous** key positions | Per chunk: `(size: u32, pos[0]..pos[size-1]: u32)` | Contiguous-format recognition (DER, PEM, ASCII-armor) | 5× key (4 bytes layout per real byte) |
| `InterleavedFragmenter` | One large `LockedBytes` pool (default 4× key length), key bytes scattered at random positions, padding filled with CSPRNG bytes | `(pool_size: u32, pos[0]..pos[key_len-1]: u32)` | Byte-level statistical analysis | 4× key |
| `LayeredFragmenter`     | Whatever the picked sub-strategy produces, with a 4-byte strategy-index header prepended to its layout | `(strategy_idx: u32, sub_strategy_layout)` | Sophisticated attackers who know one strategy but not which | Same as picked sub-strategy |

#### Per-strategy threat focus

- **`StandardFragmenter`** (the baseline): chunks are contiguous runs of
  key bytes. The defense is "find a chunk, you got 1–8 bytes." When
  combined with `SelfReferenceDecoy` (Layer 4), an attacker also can't
  tell which chunks are real.

- **`RandomFragmenter`**: each chunk's bytes are *non-contiguous in the
  original key*. Even a successful chunk read reveals at most
  `max_chunk` (default 4) bytes from random positions, with no
  contiguous run. Defeats format-recognition attacks that need a
  contiguous header.

- **`InterleavedFragmenter`**: one large pool, key bytes at random
  positions among CSPRNG-random padding. An attacker who reads the pool
  cannot distinguish key bytes from padding without the layout map.
  The trade-off: the pool is a single contiguous allocation, so a
  partial-read attack against the pool yields a substring of the pool
  (mostly padding, occasionally a key byte). Best paired with
  `LayeredFragmenter` so the attacker doesn't even know they have a
  pool.

- **`LayeredFragmenter`**: each `fragment` call picks one sub-strategy
  uniformly at random and delegates. The attacker has to guess which
  sub-strategy was used to know what layout encoding to apply.
  Composition through routing (rather than chained transformations)
  avoids materializing the key between layers.

#### Decoy compatibility

- `StandardFragmenter::with_decoy` — full support; emits paired real and
  decoy chunks recognized via the `u32::MAX` sentinel.
- `RandomFragmenter` — no built-in decoy slot in 0.5.0. Combine with
  `LayeredFragmenter` if you want decoy + non-contiguous scatter.
- `InterleavedFragmenter` — no separate decoy: the pool padding itself
  is CSPRNG noise that doubles as decoy.
- `LayeredFragmenter` — inherits decoy behavior from whichever
  sub-strategy was picked for a given fragmentation.

### Performance

- Fragmentation: ~100-500ns per key (one-time setup)
- Reassembly (defrag): ~50-200ns per key access (hot path)
- Memory overhead: ~2-4x key size due to fragments + decoy

---

## Layer 4: Decoy Bytes

### What it does

Fills the spaces around real fragments with "nonsense" bytes that look indistinguishable from real key material.

### Defends against

- Entropy analysis (finding high-entropy regions in memory)
- Frequency analysis (statistical patterns in byte distributions)
- Pattern recognition (recognizing where key bytes are)

### Does NOT defend against

- Knowing the fragmentation algorithm and reversing it
- Attackers with code execution that can call defrag logic

### Implementation

```
KEY:           0fx03mmqrhxhrk13
FRAGMENTS:     ["hxh", "03", "m", "fx", "k13", "qrr", "0m"]
DECOY BYTES:   "x0", "x0", "mhx", "qx0", "fxh", "101", "qrr", "0hxq", "rrx", "0mx"
                ↓ (interleaved)
FINAL OUTPUT:  x0hxhmhx03qrr0fxh13mqrrx0mx01hxh...
                ↑    ↑      ↑  ↑          ↑
                decoy real   decoy real   decoy
```

Notice how the decoy bytes contain fragments OF the key (`hxh`, `0m`, `qrr`). An attacker can't determine which is real and which is decoy without the position map.

### Strategies

| Strategy | Approach | Strength |
|----------|----------|----------|
| `RandomDecoy` | Pure CSPRNG bytes | Weak — high entropy distinguishes from key bytes |
| `KeyDerivedDecoy` | Hash of key material | Medium — same entropy profile as key |
| `SelfReferenceDecoy` | Real key bytes as filler | Strong — indistinguishable from real fragments |

### Performance

- Decoy generation: ~50-100ns per key (one-time setup)
- Storage overhead: configurable via `frag_len` (target output length)

---

## Layer 5: Codex Transformation

### What it does

Applies a byte-level swap transformation to all bytes (real key + decoy) before storage. Adds an obfuscation layer that even a successful memory dump must defeat.

### Defends against

- Memory dump analysis (attacker sees transformed bytes, not real ones)
- Reverse engineering pattern attacks
- "Read the memory and try it as a key" attacks

### Does NOT defend against

- Attackers with the codex table (e.g., from reverse-engineered binary)
- Cryptographic attacks (this is obfuscation, not encryption)
- Sophisticated frequency analysis if transformation is naive

### Implementation

The `Codex` trait defines the transformation:

```rust
pub trait Codex: Send + Sync {
    fn encode(&self, byte: u8) -> u8;
    fn decode(&self, byte: u8) -> u8;
}
```

**For involution-based codices (encode = decode):**

```rust
// Static lookup table — built into the binary
pub struct StaticCodex([u8; 256]);

impl StaticCodex {
    /// Build from a list of swap pairs.
    /// `[('h', '%'), ('k', '$'), ('0', '#')]` means:
    ///   h ↔ % (encode h → %, encode % → h, decode same)
    ///   k ↔ $
    ///   0 ↔ #
    /// Bytes not in swap pairs pass through unchanged.
    pub fn from_swaps(swaps: &[(u8, u8)]) -> Self;

    /// Generate a random involution.
    /// Produces a permutation where applying it twice returns the original.
    /// Used by DynamicCodex for per-vault randomization.
    pub fn random_involution(rng: &mut impl RngCore) -> Self;
}

// User-provided closure
pub struct FnCodex<F>(F);

impl<F: Fn(u8) -> u8 + Send + Sync> Codex for FnCodex<F> {
    fn encode(&self, byte: u8) -> u8 { (self.0)(byte) }
    fn decode(&self, byte: u8) -> u8 { (self.0)(byte) }  // assumes involution
}
```

### Example transformation

```
PRE-CODEX:    0fx03mmqrhxhrk13
CODEX TABLE:  h ↔ %, k ↔ $, 0 ↔ #
POST-CODEX:   #fx#3mmqr%x%r$13
              ↑    ↑     ↑   ↑
              0→#  0→#   h→% k→$
```

To decode: same operation. Apply codex.decode() (or codex.encode(), they're the same for involutions). Original key returns.

### Variants

| Codex | Description |
|-------|-------------|
| `IdentityCodex` | No transformation (default, max perf) |
| `StaticCodex` | Build-time transformation table (private builds customize this) |
| `DynamicCodex` | Per-vault randomized table |
| `FnCodex` | User-provided closure |

### Performance

- Per-byte transformation: ~5-10ns (lookup table)
- For a 256-bit key with full reassembly: ~80-160ns total
- For 256-byte fragmented output (with decoy): ~1.3-2.6µs

**Feature-gated.** Opt-in via `codex` feature. Default off for maximum performance.

### Hive DB pattern

Hive DB ships its own `HiveCodex` with a proprietary swap table:

```rust
// In hive-key-vault (private crate)
pub struct HiveCodex;

impl Codex for HiveCodex {
    fn encode(&self, byte: u8) -> u8 {
        // Proprietary transformation, never exposed
    }
    fn decode(&self, byte: u8) -> u8 {
        self.encode(byte)  // Involution
    }
}
```

---

## Layer 6: Constant-Time Operations

### What it does

Ensures that operations on key material take the same amount of time regardless of the key values. Defeats timing side-channel attacks.

### Defends against

- Timing attacks on key comparison
- Side-channel leakage through CPU branch prediction
- Cache-timing attacks (partially — depends on implementation)

### Does NOT defend against

- Power analysis
- Electromagnetic emanation analysis
- Most cache-timing attacks on cryptographic operations (that's the crypto library's job)

### Implementation

All key comparisons use `subtle::ConstantTimeEq`:

```rust
use subtle::ConstantTimeEq;

if key_a.ct_eq(&key_b).into() {
    // ...
}
```

NEVER:

```rust
if key_a == key_b {  // VULNERABLE — early-exit on first mismatch
    // ...
}
```

### Performance

- Constant-time comparison of 32 bytes: ~10-20ns
- Compared to non-CT comparison: ~5ns difference (acceptable)

---

## Layer 7: Zero-On-Drop

### What it does

When key material leaves scope (function returns, struct drops), the memory is overwritten with zeros. Subsequent reads of that memory location yield zeros, not stale key bytes.

### Defends against

- Use-after-free leakage
- Stale data in freed memory pools
- Forensic recovery of recently-freed memory

### Does NOT defend against

- Memory access during the lifetime of the key
- Hardware-level memory persistence (rare, mostly DRAM rowhammer territory)

### Implementation

The `zeroize` crate provides `Zeroize` and `ZeroizeOnDrop`:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct KeyMaterial {
    bytes: Vec<u8>,
}
```

Compiler optimizations might otherwise elide the overwrite (since the memory is about to be freed). `zeroize` uses volatile writes to prevent this.

### Performance

- Zeroize 32 bytes: ~5ns
- Zeroize 4 KiB page: ~500ns
- Runs only on drop, never on access path

---

## Layer 8: Security Monitor

### What it does

Detects anomalous behavior and triggers configured response (logging, alerts, lockout).

### Defends against

- Brute-force decryption attempts (failed decrypts trigger alerts)
- Anomalous access patterns (unusual caller, unusual time, unusual frequency)
- Slow data exfiltration (sustained access from one source)

### Does NOT defend against

- One-shot successful attacks
- Attacks below detection thresholds
- Attacks that defeat the monitor itself

### Implementation

```rust
pub trait SecurityMonitor: Send + Sync {
    /// Called when a decryption attempt fails (wrong key, tampered data, etc.)
    fn on_decryption_failure(&self, ctx: &FailureContext);

    /// Called when access patterns look anomalous
    fn on_anomalous_access(&self, ctx: &AccessContext);

    /// Called when a threshold is breached (N failures in M seconds)
    fn on_threshold_breach(&self, ctx: &ThresholdContext);
}
```

Built-in implementations:

- `NoMonitor` — disabled (default)
- `LogMonitor` — logs events via `log-io` or `tracing`
- `MetricsMonitor` — increments counters in `metrics-lib`
- `WebhookMonitor` — POSTs to alert endpoint
- `CompositeMonitor` — chains multiple

### Thresholds

Configurable per vault:

```rust
VaultConfig {
    max_failures_before_alert: 5,          // After 5 failures, alert
    max_failures_before_lockout: 10,       // After 10 failures, lock vault
    failure_window_seconds: 60,            // Window for counting
    anomaly_detection_enabled: true,
}
```

### Performance

- Success path (no failure): zero cost
- Failure path: cost of the monitor call (typically <100µs for logging)

### Hive DB pattern

Hive DB plugs in its own monitor that:
1. Triggers admin alerts via webhook
2. Locks the affected vault
3. Optionally takes the database offline pending investigation

---

## Layer 9: Audit Logging

### What it does

Records every key access with context: who, what, when, where. Provides forensic trail for incident response.

### Defends against

- Undetected long-term access (everything is logged)
- Insider threats (anomalies surface in audit logs)
- Compliance violations (HIPAA, SOC 2, PCI-DSS require audit trails)

### Does NOT defend against

- Attacks that complete before logs are reviewed
- Attacks that modify the audit log (use `audit-trail` with hash chaining)

### Implementation

Every successful key access produces an audit event:

```rust
AuditEvent {
    timestamp: SystemTime,
    vault_id: VaultId,
    key_id: KeyId,
    operation: AccessKind,        // Fetch, Defrag, Rotate, ...
    caller: CallerContext,         // Module, function, file:line
    thread_id: ThreadId,
    success: bool,
    metadata: HashMap<String, Value>,
}
```

Routed through `log-io` if available, or a user-provided sink.

### Performance

- Per-access cost: ~50-100ns
- Async log shipping (out of hot path)
- Feature-gated via `audit` flag

---

## Bonus Layer 10: Page Protection Toggling

### What it does

Memory pages holding fragments are set to `PROT_NONE` (no read/write access) when not actively being read. Reset to `PROT_READ` briefly during reassembly. Returned to `PROT_NONE` after.

### Defends against

- Snapshot attacks (memory dump at an instant — sees only inaccessible pages)
- Page-cache-only attacks (pages can't be read directly)

### Does NOT defend against

- Attackers who can call mprotect themselves
- Hardware DMA attacks

### Implementation

- Linux/macOS: `mprotect(addr, len, PROT_NONE)` / `mprotect(addr, len, PROT_READ)`
- Windows: `VirtualProtect(addr, size, PAGE_NOACCESS)` / `VirtualProtect(addr, size, PAGE_READONLY)`

### Performance

- Mprotect cost: ~1-2µs per call
- Per-access overhead: ~2-4µs (toggle on + toggle off)

**Significant performance impact.** Available as opt-in feature for highest-security use cases. Not recommended for hot paths.

---

## Defense Composition

How layers compose:

```
                     ATTACKER WITH MEMORY READ ACCESS
                                  ↓
                       Layer 10: PROT_NONE
                          (can't read pages)
                                  ↓
                       Layer 2: mlock
                          (can't read from swap)
                                  ↓
                  Layer 3+4: Fragments + Decoy
                  (can't tell real from filler)
                                  ↓
                       Layer 5: Codex
                  (bytes are transformed)
                                  ↓
                                  X
                          ATTACKER STOPPED
```

For an attacker to succeed, they must:

1. Bypass Layer 10 (page protection) — requires code execution OR
2. Bypass Layer 2 (mlock) — requires kernel access AND
3. Defeat Layer 3+4 (fragmentation + decoy) — requires reverse engineering of strategies AND
4. Reverse Layer 5 (codex) — requires knowing the transformation table

Each is a meaningful step. Together, they're exponentially harder than any single one.

---

## Threat Model

`key-vault` is designed for these threats:

| Threat | Defense |
|--------|---------|
| Process memory scraper | Layers 2, 3, 4, 5, 10 |
| Swap file forensics | Layer 2 |
| Hibernation file analysis | Layer 2 |
| Timing side-channels | Layer 6 |
| Memory persistence | Layer 7 |
| Brute-force | Layer 8 |
| Insider threats | Layer 9 |
| Sustained exfiltration | Layers 8, 9 |
| Reverse engineering | Layers 5, 10 |

`key-vault` is NOT designed for these threats:

- Kernel-level rootkit with full memory access (use TEE if available)
- Hardware DMA attacks (use IOMMU + hardware mitigations)
- Cold-boot attacks (use full disk encryption + power-down protocol)
- Side-channel attacks on crypto operations (that's `crypt-io`'s job)
- Quantum computer attacks on asymmetric crypto (use post-quantum algorithms)

---

## Performance Cost Summary

Cumulative cost on the **hot path** (key access via defragmentation):

| Layer | Cost | Cumulative |
|-------|------|------------|
| Layer 3: Defragment | 50-200ns | 200ns |
| Layer 5: Codex (optional) | 80-160ns | 360ns |
| Layer 6: Constant-time | 10-20ns | 380ns |
| Layer 9: Audit (optional) | 50-100ns | 480ns |
| **Total (full stack)** | | **~500ns** |

For a 32-byte (256-bit) key access. Well within the sub-microsecond target.

On the **startup path** (one-time):

| Layer | Cost |
|-------|------|
| Layer 1: Acquisition | 1-100ms |
| Layer 2: mlock setup | 10-100µs |
| Layer 3: Fragmentation | 1-10µs |
| Layer 4: Decoy generation | 1-10µs |
| Layer 5: Codex init | 1-5µs |
| **Total** | **~1-100ms** |

Acceptable for application startup.

---

## Configuration

```toml
# .vault.toml (or via builder API)

[vault]
key_normalization = "blake3"        # Hash input to fixed-size
frag_min = 1                         # Min fragment length
frag_max = 4                         # Max fragment length
frag_level = 2                       # Strength level (1-5)
frag_len = 256                       # Target output length
frag_symbols = "#%$&"                # Symbol set for decoy bytes

[security]
mlock_enabled = true                 # Layer 2
fragment_strategy = "standard"       # Layer 3
decoy_strategy = "self-reference"    # Layer 4
codex_enabled = false                # Layer 5 (opt-in)
constant_time = true                 # Layer 6
zeroize_on_drop = true               # Layer 7
monitor = "log+webhook"              # Layer 8
audit_enabled = true                 # Layer 9
page_protection = false              # Layer 10 (opt-in, perf impact)

[monitor]
max_failures_before_alert = 5
max_failures_before_lockout = 10
failure_window_seconds = 60
```

---

## Verification methodology (shipped in 0.11.0)

The 1.0 contract makes specific security claims. Each is backed by a
runnable verification:

| Claim | Verification | Location |
|-------|--------------|----------|
| Fragment round-trip is identity across arbitrary inputs | `proptest` sweeps over `StandardFragmenter`, `InterleavedFragmenter`, `RandomFragmenter`, plus the `with_chunk_range` variant | `tests/proptest_invariants.rs` |
| Every codex implementation satisfies `decode(encode(b)) == b` for every byte | `proptest` full byte-range sweep for `IdentityCodex`, `StaticCodex`, `DynamicCodex` | `tests/proptest_invariants.rs` |
| `SelfReferenceDecoy` only emits bytes drawn from the source key | `proptest` (cross-platform) + dedicated fuzz target | `tests/proptest_invariants.rs`, `fuzz/fuzz_targets/fuzz_decoy_strategies.rs` |
| `KeyHandle::Debug` never reveals the internal id | `proptest` regex assertion + unit-test sweep over 1024 handles | `tests/proptest_invariants.rs`, `src/handle.rs` |
| Concurrent readers never observe a torn read across rotation | 4-thread reader loop vs. 50 rotations, asserting byte uniformity | `tests/proptest_invariants.rs` |
| Layer 2: `mlock` actually pins pages on Linux | `/proc/self/status` `VmLck` delta after 64 registrations | `tests/mlock_verified.rs` (cfg = `target_os = "linux"`) |
| No panics / infinite loops / OOMs on arbitrary inputs | `cargo-fuzz` targets, one per fetcher / fragment strategy / decoy strategy / codex / vault end-to-end | `fuzz/fuzz_targets/*.rs` |
| Hot-path allocation profile | `dhat`-based example binary measuring `with_key` × 100,000 | `examples/dhat_hot_path.rs` |
| Constant-time `KeyHandle` equality | Built on `subtle::ConstantTimeEq` — same primitive `ring` / `aws-lc-rs` use | `src/handle.rs` (the dependency does the heavy lifting; we apply it) |

### Running the verifications

```bash
# All cross-platform property tests run as part of the normal gate.
cargo test --all-features

# Linux-only mlock verification (skipped on macOS/Windows by cfg gate).
cargo test --all-features --test mlock_verified

# Hot-path allocation profile.
cargo run --release --example dhat_hot_path
# → produces dhat-heap.json

# cargo-fuzz targets (Linux/macOS; nightly Rust).
cd fuzz
cargo +nightly fuzz run fuzz_fragment_standard -- -max_total_time=3600
# Repeat per target. Roadmap requires 1 CPU-hour per target for 1.0 sign-off.
```

### What's not yet verified by automation

- **Constant-time property of the full `with_key` call** (not just
  `KeyHandle::eq`) — `dudect` is the gold standard; deferred to a
  post-0.11 follow-up because dudect's runtime hookup is intrusive.
- **`zeroize` actually overwrites memory after drop** — the `zeroize`
  crate's own tests cover this for the primitive; an end-to-end test
  reading freed memory through raw pointers requires `unsafe` outside
  the crate's safety contract.
- **Cold-boot resistance** — out of scope, requires hardware testing.

---

## When to Disable Layers

There are legitimate reasons to disable layers:

| Layer | Reason to disable | Risk |
|-------|------|------|
| mlock | Memory-constrained system | Keys may swap to disk |
| Codex | Maximum performance needed | One less obfuscation layer |
| Monitor | Embedded system without log infrastructure | No anomaly detection |
| Audit | Maximum performance needed | No forensic trail |
| Page protection | Latency-sensitive hot path | Memory readable when active |

Document the trade-off when disabling any layer. Never disable layers 1, 3, 4, 6, 7 — these have minimal performance cost and high security value.

---

<sub>key-vault Security Architecture - Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>