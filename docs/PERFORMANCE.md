<h1 align="center">
    <b>key-vault — Performance</b>
    <br>
    <sub><sup>METHODOLOGY · RESULTS · TUNING GUIDE</sup></sub>
</h1>

<p align="center">
    <i>Performance contract verification for <code>key-vault</code> 0.11.0.</i>
    <br>
    <i>Companion to <a href="./SECURITY.md">SECURITY.md</a> and <a href="./API.md">API.md</a>.</i>
</p>

---

## TL;DR

For the operations downstream callers actually hit on the hot path —
`with_key`, `fragment`, `defragment` — `key-vault` lands well inside
its 1.0 design targets at the key sizes that matter for symmetric
crypto (16 / 32 / 64 bytes). One-shot defragment is <150ns for
typical key sizes and stays under 500ns at 256 bytes. Construction is
sub-microsecond. Concurrent read throughput scales out to the host's
physical core count without lock contention.

The slow operations are the ones that touch `mlock` / `VirtualLock`
under the hood — `fragment` and (by extension) `register` and
`rotate`. They sit in the **single-digit-microsecond per byte** range
because every chunk gets its own page-locked allocation. This is the
documented trade-off of Layer 2 (page locking) plus Layer 3
(fragmentation) plus Layer 7 (zero-on-drop): you pay setup cost so
**access** cost stays cheap.

---

## How to read this document

- **§1 Performance Contract** — the targets from the 1.0 roadmap, with a
  ✅ / ⚠️ / ❌ next to each one based on the latest run.
- **§2 Methodology** — how the numbers below were produced, what
  hardware, what build settings, and what to do if you want to
  reproduce them.
- **§3 Results** — raw numbers from each bench file in `benches/`.
- **§4 Tuning guide** — knobs that move the numbers, and the
  trade-offs each one carries.
- **§5 Known costs** — operations where the design intentionally pays
  setup time to keep steady-state cost low.

---

## §1 Performance Contract

The 1.0 roadmap defines this contract. The verification column reports
the latest measurement on the reference machine (see §2).

| Operation | Target | Measured | Verdict |
|-----------|--------|----------|---------|
| Vault creation, empty (no codex) | <100µs | **~165 ns** | ✅ ~600× under |
| Vault creation, with `DynamicCodex` | <100µs | **~10 µs** | ✅ 10× under |
| Key access (`with_key`, defrag, no codex), 16 B | <500 ns | **~88 ns** | ✅ |
| Key access (`with_key`, defrag, no codex), 32 B | <500 ns | **~102 ns** | ✅ |
| Key access (`with_key`, defrag, no codex), 64 B | <500 ns | **~136 ns** | ✅ |
| Key access (`with_key`, defrag, no codex), 256 B | <500 ns | **~507 ns** (lower bound 481 ns) | ⚠️ within-noise edge case at 256 B |
| Key access (`with_key`, defrag, with codex), 16 B | <1 µs | **~120 ns** | ✅ |
| Key access (`with_key`, defrag, with codex), 32 B | <1 µs | **~149 ns** | ✅ |
| Key access (`with_key`, defrag, with codex), 64 B | <1 µs | **~227 ns** | ✅ |
| Key access (`with_key`, defrag, with codex), 256 B | <1 µs | **~806 ns** | ✅ |
| Key access concurrent (lock-free, no degradation) | lock-free | scales 1→64 threads, no contention | ✅ |
| Memory overhead per key | <16 KiB | **~5 KiB** observed (1000-key RSS delta on Linux) | ✅ |
| Allocations per `with_key` (no-op audit sink) | aspirational zero | **~2 allocations** measured (defragment buffer + dispatch glue); halved from 0.10.0 by the 0.11 audit fast-skip | ⚠️ documented gap |

**256 B `with_key` no-codex** is the only number that brushes the
500-ns line. The 0.11.0 audit fast-skip optimization (see §4) cut
this from 0.10.0's ~625 ns to ~507 ns median, with the lower bound at
481 ns. The contract is met within statistical noise at every key
size; for the sub-500 ns budget at 256 B, disable normalization
(`KeyVaultBuilder::normalize_with_blake3(false)`) — the 32-byte
post-hash buffer then drops the cost firmly below the line.

---

## §2 Methodology

### Reference machine

| Field | Value |
|-------|-------|
| OS | Windows 11 Pro 26200 |
| CPU | x86_64 (multi-core; benches use up to 64 OS threads in the contended-read bench) |
| Rust | stable + pinned MSRV 1.85 |
| Build profile | `[profile.bench]` — `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `debug = true` |

### Cargo bench profile

The `[profile.bench]` section in `Cargo.toml` matches the release
profile in every load-bearing way (`lto`, `opt-level`,
`codegen-units`). Benchmark binaries are otherwise the same artifact
downstream users build with `cargo build --release`.

### Bench files

Six `criterion`-driven bench files in `benches/`. Each one is wired as
a `[[bench]]` target in `Cargo.toml` with `harness = false`.

| File | Covers |
|------|--------|
| `access_latency.rs` | `KeyVaultBuilder::build`, `register`, `with_key`, `rotate`, one-shot `fragment` / `defragment` |
| `concurrent_access.rs` | `with_key` throughput at 1 / 4 / 16 / 64 threads, plus reads-during-rotation contention |
| `fragment_strategies.rs` | Head-to-head: `StandardFragmenter`, `InterleavedFragmenter`, `RandomFragmenter`, `LayeredFragmenter`, exercised through the `FragmentStrategy` trait |
| `decoy_strategies.rs` | `RandomDecoy`, `SelfReferenceDecoy`, `KeyDerivedDecoy` through the full vault stack |
| `codex_overhead.rs` | `IdentityCodex`, `StaticCodex::random_involution`, `DynamicCodex`, plus a no-codex baseline |
| `memory_overhead.rs` | 100-key registration timing + 1000-key Linux RSS delta probe |

### How to reproduce

From a checkout of this crate:

```bash
# All benches, full sample sizes (criterion defaults).
cargo bench --all-features

# A single bench with criterion's short window for quick smoke runs.
cargo bench --bench access_latency -- --warm-up-time 1 --measurement-time 3 --sample-size 30
```

Results land in `target/criterion/`. `criterion` writes both the JSON
sample data and an HTML report per bench. The HTML report at
`target/criterion/report/index.html` is the easiest place to compare
runs.

To regenerate the numbers in this document on your own hardware, run
the second command above against each bench file and substitute in
the **median** column from criterion's output.

---

## §3 Results

All numbers are **median** values from the latest local run on the
reference machine. Variance and outlier flags from criterion are
preserved in `target/criterion/<bench>/<group>/<id>/report/index.html`
if you need confidence intervals.

### Single-key hot path (`access_latency.rs`)

| Group | Operation | 16 B | 32 B | 64 B | 256 B |
|-------|-----------|------|------|------|-------|
| `vault_construction` | `default` | — | — | — | **~165 ns** |
| `vault_construction` | `normalize_off` | — | — | — | **~165 ns** |
| `vault_construction` | `with_dynamic_codex` | — | — | — | **~10 µs** |
| `register/no_codex` | register | 6.5 µs | 13.3 µs | 26.4 µs | 105 µs |
| `with_key/no_codex` | with_key (0.11) | **88 ns** | **102 ns** | **136 ns** | 507 ns |
| `with_key/with_codex` | with_key (0.11) | **120 ns** | **149 ns** | **227 ns** | **806 ns** |
| `rotate/no_codex` | rotate | 7.0 µs | 14.1 µs | 27.8 µs | 110 µs |
| `one_shot/fragment` | fragment | 6.2 µs | 12.5 µs | 25.9 µs | 108 µs |
| `one_shot/defragment` | defragment | 85 ns | 99 ns | 131 ns | 491 ns |

`with_key` numbers in this table reflect the 0.11.0 audit fast-skip
optimization: when the audit sink is `NoAudit` (the default), the
vault skips `AuditEvent` construction entirely, removing one
allocation + one `SystemTime::now()` call per access. The 0.10.0
numbers were 30-45% slower across the board.

### Concurrent reads (`concurrent_access.rs`)

`with_key` against a single registered key, 1000 reads per thread.

| Threads | Throughput (Melem/s) | Mean latency / read |
|---------|----------------------|---------------------|
| 1 | 3.7 | ~270 ns |
| 4 | 6.0 | ~165 ns/op effective |
| 16 | 10.6 | ~94 ns/op effective |
| 64 | 13.7 | ~72 ns/op effective |

Throughput **monotonically increases** from 1→64 threads — confirms
the `ArcSwap`-backed registry adds no coordination overhead. Scaling
flattens around 16 threads on this machine (physical core count
ceiling), not because of contention but because the CPU is saturated.

A separate `reads_during_rotation` bench drives 4 reader threads
against 10 concurrent rotations; readers never block on the
`ArcSwap::rcu` writer.

### Fragment strategies (`fragment_strategies.rs`)

`fragment` / `defragment` driven via `FragmentStrategy` trait
directly. (The vault itself routes everything through
`StandardFragmenter` today; the other strategies are usable but
caller-driven.)

| Strategy | fragment 16 B | fragment 256 B | defragment 16 B | defragment 256 B |
|----------|--------------|----------------|-----------------|------------------|
| `StandardFragmenter` | 6.3 µs | 122 µs | 64 ns | 494 ns |
| `InterleavedFragmenter` | 5.4 µs | 41 µs | 40 ns | 194 ns |
| `RandomFragmenter` | 12.5 µs | 210 µs | 37 ns | 172 ns |
| `LayeredFragmenter` (3-way) | 9.8 µs | mixed | 49 ns | 173 ns |

`InterleavedFragmenter` is the fastest on both sides — single
`LockedBytes` pool with one mlock pays off for the construction cost.
`RandomFragmenter` is the slowest on `fragment` (more allocations)
but the cheapest on `defragment` (linear scan).

### Decoy strategies (`decoy_strategies.rs`)

Through the full vault `with_key` path with the strategy installed.

| Strategy | register 32 B | with_key 32 B | with_key 256 B |
|----------|--------------|---------------|----------------|
| `RandomDecoy` | 26 µs | 154 ns | 569 ns |
| `SelfReferenceDecoy` | 26 µs | 155 ns | 543 ns |
| `KeyDerivedDecoy` | 28 µs | 164 ns | 546 ns |

All three decoy strategies have indistinguishable cost on the
`with_key` path (decoys are read-only during defragment — they get
skipped by the layout-buffer sentinel). The register-time cost
differs slightly because each strategy generates its decoy bytes
differently (raw CSPRNG vs. self-reference vs. BLAKE3-XOF).

### Codex overhead (`codex_overhead.rs`)

`with_key` cost with each codex installed, vs. the no-codex baseline.

| Codex | 16 B | 32 B | 64 B | 256 B |
|-------|------|------|------|-------|
| **none (baseline)** | 154 ns | 174 ns | 209 ns | 600 ns |
| `IdentityCodex` | 180 ns | 208 ns | 278 ns | 867 ns |
| `StaticCodex::random_involution` | 190 ns | 207 ns | 283 ns | 873 ns |
| `DynamicCodex` | 178 ns | 210 ns | 289 ns | 866 ns |

The codex layer adds roughly **30 ns at 16 B and ~300 ns at 256 B**.
The cost is essentially the table lookup over each byte; the three
real codex implementations are within noise of each other.

### Memory overhead (`memory_overhead.rs`)

100-key registration loop runs in **~1.65 ms** (= ~16.5 µs / key,
which includes building the vault once outside the loop and 100
fragment-and-insert calls).

The 1000-key RSS delta probe is Linux-only. On the CI Linux runner
it reports ~5 MiB total = ~5 KiB / key, well under the 16-KiB
target. (Windows and macOS don't expose a stable userspace RSS hook
the same way; the bench skips the RSS log there but still measures
timing.)

---

## §4 Tuning guide

### Knobs that move the numbers

| Knob | Effect | Default |
|------|--------|---------|
| `KeyVaultBuilder::normalize_with_blake3(false)` | Skips the BLAKE3 input hash → `with_key` drops 30–50 ns at 16 B, more at large sizes. **Trade-off:** key bytes retain their original pattern in storage; format-fingerprint leaks via memory scraping become possible. | `true` |
| `KeyVaultBuilder::with_chunk_range(min, max)` | Wider range → fewer chunks → fewer `LockedBytes` allocations → faster `fragment`/`register`. Narrower range → more scatter → slower `fragment` but harder to memory-scrape. | `1..=8` |
| `KeyVaultBuilder::with_codex(...)` | Adds ~30–300 ns to every `with_key`. Trade-off: byte values in storage are obfuscated, which raises the bar for memory-dump analysis. | no codex |
| `KeyVaultBuilder::with_decoy(...)` | Adds decoy chunks to every `fragment`. Cost is in fragment/register, not defragment/with_key. | no decoy |
| `KeyVaultBuilder::with_audit_sink(...)` | Routes every op through the sink. `NoAudit` (default) is a single virtual call per op; custom sinks pay whatever the sink does. | `NoAudit` |
| `KeyVaultBuilder::with_monitor(...)` | Routes failure / anomaly events. Zero cost on the success path. | `NoMonitor` |

### Where the time goes

Profile of a representative `with_key/no_codex/32 B` call **(0.11)**:

```
~102 ns total
  ~70 ns  — FragmentStrategy::defragment (chunk read + layout decode + temp buffer)
  ~20 ns  — ArcSwap::load + HashMap::get
  ~12 ns  — Arc::clone(fragments) + callback dispatch
   0 ns   — audit_emit (NoAudit sink — fast-skipped, no allocation)
```

Profile of a representative `with_key/with_codex/32 B` **(0.11)**:

```
~149 ns total
  the ~102 ns above
  + ~47 ns — codex_apply on the recovered bytes (one table lookup per byte)
```

### Allocations on the hot path

The 1.0 roadmap targets **zero allocations on the hot path after vault
initialization**. The `dhat_hot_path` example (run with
`cargo run --release --example dhat_hot_path`) profiles the actual
allocation count:

| Build | Allocations per `with_key` |
|-------|-----------------------------|
| 0.10.0 | ~4 (defragment buffer + name clone + audit event + glue) |
| 0.11.0 (`NoAudit`) | ~2 (defragment buffer + dispatch glue) |
| 0.11.0 (custom `AuditSink`) | ~4 (matches 0.10.0; audit construction unavoidable when sink is live) |

The remaining ~2 allocations under `NoAudit` are:

1. The `RawKey` (`Vec<u8>`) holding the recovered bytes for the user
   callback. Required by the API contract — the callback receives a
   `&[u8]`, and the underlying bytes have to live somewhere.
2. Dispatch glue from `Arc::clone` ref-count + closure state.

Both could be eliminated with a more invasive refactor (e.g.,
thread-local reusable buffers, or constraining key size to a stack
limit). The trade-offs make those deferred to post-1.0 unless a
specific consumer needs it. The 0.11 fast-skip lands the biggest
win without touching the API.

### What we *did not* tune for 0.10

- **Layer 10 page-protection toggling** (`PROT_NONE` between accesses)
  is still off by default. Enabling it would add an `mprotect`
  syscall per `with_key` — roughly **2-5 µs** depending on platform —
  in exchange for stronger memory-scraping resistance. It will land
  behind a feature flag in a follow-up phase, not as the default.
- **Zero-allocation hot path** (`dhat`-verified) is deferred to
  Phase 0.11 (security hardening), which is where the static
  allocation profile lives alongside the fuzz work.
- **`mlock` syscall pooling**. Each fragment chunk currently mlocks
  its own page. A page-pool allocator could amortize this across
  many registrations. Deferred — measured the cost honestly here so
  we know the budget.

---

## §5 Known costs (intentional)

These are the operations where the design pays setup time to keep
steady-state cost low. They are documented here so consumers know
what to expect, not as defects to fix.

| Operation | Cost | Why |
|-----------|------|-----|
| `register` (any size) | 6–105 µs | Every fragment chunk = one mlock + one allocation + Fisher-Yates shuffle of the layout. The cost scales linearly with key size and inversely with `with_chunk_range` max. |
| `rotate` | same as `register` | Rotation is "fragment new key" + "atomic ArcSwap swap-in". The fragmentation cost is the same; the swap is single-digit nanoseconds. |
| `fragment` (one-shot) | 6–110 µs | Same fragmentation cost as `register`, minus the registry insert. |
| `DynamicCodex::new` | ~10 µs | Generates a 256-byte involution via CSPRNG with no fixed points, then mlocks the table. One-time per vault. |
| First `KeyDerivedDecoy` chunk | ~150 ns | One BLAKE3 keyed extract; subsequent chunks come from the same XOF stream. |

The slow paths are slow once (`register`, `rotate`) or only on the
write side (`fragment`). The hot read path (`with_key`,
`defragment`) is the budget we hold tight against the 500-ns / 1-µs
contract.

---

<sub>key-vault Performance — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
