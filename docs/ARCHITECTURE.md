<h1 align="center">
    <b>key-vault — Internal Architecture</b>
    <br>
    <sub><sup>HOW THE CRATE FITS TOGETHER UNDER THE HOOD</sup></sub>
</h1>

<p align="center">
    <i>Reader's map for contributors and code reviewers.</i>
    <br>
    <i>For the public API see <a href="./API.md">API.md</a>; for the security layering see <a href="./SECURITY.md">SECURITY.md</a>.</i>
</p>

---

## Crate-wide layering

Top-down, the public surface (left) routes calls through the vault
core (centre) which delegates to the strategy traits (right):

```
┌──────────────────────────┐    ┌──────────────────────┐    ┌─────────────────────┐
│  KeyVault                │ →  │  VaultInner          │ →  │  FragmentStrategy   │
│  KeyVaultBuilder         │    │   ArcSwap<HashMap<   │    │  DecoyStrategy      │
│  fragment / defragment   │    │     KeyId, KeyEntry  │    │  Codex              │
│  register / with_key /   │    │   >>                 │    │  SecurityMonitor    │
│  rotate / unregister     │    │   audit: Arc<dyn>    │    │  AuditSink          │
│  unlock_with_master      │    │   monitor: Arc<dyn>  │    │                     │
│                          │    │   codex:  Arc<dyn>   │    │                     │
└──────────────────────────┘    └──────────────────────┘    └─────────────────────┘
                                          │
                                          ▼
                                ┌──────────────────────┐
                                │  LockedBytes         │
                                │   (mlock + zeroize)  │
                                └──────────────────────┘
```

Every public call enters through `KeyVault`, which acquires (or
clones) the relevant strategy via the `Arc<dyn …>` slot in
`VaultInner`, and runs the fragmentation / defragmentation pipeline.
The output is held in `LockedBytes` — the internal page-locked,
zero-on-drop byte buffer — until the caller's scoped callback returns.

### Source-tree map

| Path | Owns | Public to |
|------|------|-----------|
| `src/lib.rs` | Lint config, module declarations, re-exports | crate root |
| `src/vault/mod.rs` | `KeyVault`, `KeyVaultBuilder`, `VaultConfig`, the registry, all public ops | external |
| `src/vault/trie.rs` | Persistent hash trie for the registry snapshot (1.2) | private |
| `src/vault/tracker.rs` | Bounded, sharded failure tracker for the lockout thresholds (1.2) | private |
| `src/fetcher/` | `KeyFetch` trait + 4 implementations + `RawKey` + `FetchContext` | external |
| `src/fragment/` | `FragmentStrategy` trait + 4 implementations + `Fragments` | external |
| `src/decoy/` | `DecoyStrategy` trait + 3 implementations | external |
| `src/codex/` | `Codex` trait + 4 implementations | external |
| `src/monitor/` | `SecurityMonitor` trait + `NoMonitor` / `LogMonitor` / `CompositeMonitor` | external |
| `src/audit/` | `AuditSink` trait + `AuditEvent` + `AccessKind` + `NoAudit` / `LogAudit` | external |
| `src/tee/` | TEE detection per architecture (`std` only) | external |
| `src/clock.rs` | `Clock` trait, `StdClock` | external |
| `src/rng.rs` | Randomness through `getrandom`, `register_rng!` | external (macro) |
| `src/handle.rs` | `KeyHandle`, `KeyId`, the constant-time equality contract | external |
| `src/error.rs` | `Error` enum, `Result<T>` alias | external |
| `src/metadata.rs` | `KeyMetadata`, `AlgorithmHint` | external |
| `src/memory/` | `LockedBytes`, the page table (lock + dump exclusion), `GuardedRegion` (page protection), OS shims | `pub(crate)` |
| `src/normalize.rs` | Plain and keyed BLAKE3 normalisation helpers | `pub(crate)` |
| `src/sync.rs` | `Mutex` (std or spin lock), `no_std` registry cell | `pub(crate)` |

---

## Module-level design

### `src/vault/` — the orchestrator

`KeyVault` is a thin `Arc<VaultInner>` wrapper. Cloning a vault is
cheap (atomic refcount). Reads are lock-free through `ArcSwap`; writes
(register / rotate / unregister) are serialized by a writer mutex
(since 1.0.2).

```rust
struct VaultInner {
    keys: ArcSwap<Snapshot>,         // no_std: spin-locked Arc<Snapshot>
    writer: Mutex<()>,
    config: VaultConfig,
    fragmenter: Fragmenter,          // Standard (static dispatch) or Arc<dyn FragmentStrategy>
    normalizer: Normalizer,          // off, plain BLAKE3, or keyed BLAKE3 (key in locked memory)
    codex: Option<Arc<dyn Codex>>,
    monitor: Arc<dyn SecurityMonitor>,
    audit: Arc<dyn AuditSink>,
    clock: Arc<dyn Clock>,           // StdClock, or the caller's without std
    master: Option<MasterVerifier>,  // random hash key + keyed digest, locked
    master_backoff: Mutex<Backoff>,
    names: NameHasher,               // SipHash-2-4 under a random per-vault key
    tracker: Option<FailureTracker>, // None when no threshold is on
    locked_out: AtomicBool,          // vault-wide lockout
    lock_failing: AtomicBool,        // reports lock failures to the monitor once per run
}

struct Snapshot {                    // persistent hash tries (trie.rs), 1.2
    by_id: HashTrie<KeyId, Arc<KeyEntry>>,
    by_name: HashTrie<String, KeyId>,
}

struct KeyEntry {
    name: String,
    name_hash: u64,
    fragments: Fragments,            // Arc'd store; may own a protected region
    metadata: KeyMetadata,
    lock: Arc<KeyLock>,              // per-key lockout word, kept across rotations
}
```

**Hot path** (`with_key`): load the `ArcSwap` snapshot, look up the
entry in the id trie, check the per-key lockout (one atomic load of the
key's own lock word), open the protected region if there is one,
defragment into the thread-local scratch buffer (page-locked,
dump-excluded, zeroed after every call), close the region, drop the
snapshot, run the user closure on the scratch copy, optionally emit an
audit event. No reference count is taken on the key, so readers of one
key share no written cache line (1.2; before, each read cloned the
store's `Arc`). A `with_key` inside another one's callback finds the
thread's scratch in use and reassembles into a buffer of its own (1.2;
before, it panicked).

**Write path** (`register` / `rotate` / `unregister`): fragment the new
key outside any lock, then take the writer mutex, load the current
snapshot, re-check the precondition (name not taken, key still
present), build the new snapshot and `swap` it in, and release the
mutex. Readers either see the old snapshot or the new one, never a torn
intermediate. The snapshot is a pair of persistent hash tries (32-way
branches, at most 13 levels): a write copies the nodes on one path and
shares everything else, so its cost does not grow with the number of
keys, and duplicate-name checks and `handle_for_name` are hashed
lookups (1.2; before, every write cloned the whole map and scanned
every name). Before 1.0.2 writers used `ArcSwap::rcu` with the check
outside the retry loop, which let two `register` calls insert the same
name and let `rotate` report success for a key removed concurrently.

**Failure tracking** (`report_failure`, `tracker.rs`, 1.2): nothing is
recorded when both thresholds are off. Otherwise each name (by keyed
hash) keeps at most 64 `(time, count)` slots; names of registered keys
and the master credential are pinned, other names share a fixed
capacity with oldest-idle eviction; sixteen shards, each with its own
lock. Per-key lockouts live in each entry's lock word, so no separate
map or counter has to be kept in step with them.

### `src/fragment/` — Layer 3

`FragmentStrategy` is the canonical extension point for splitting key
bytes across storage:

```rust
pub trait FragmentStrategy: Send + Sync {
    fn fragment(&self, key: &RawKey) -> Result<Fragments>;
    fn defragment(&self, fragments: &Fragments) -> Result<RawKey>;
    fn describe(&self) -> Cow<'_, str>;
}
```

`Fragments` owns one or more `LockedBytes` allocations plus a layout
buffer (also `LockedBytes`) that records the per-chunk position map.
The default `StandardFragmenter` uses Fisher–Yates to shuffle the
chunks; `InterleavedFragmenter` puts the bytes into a single pool with
CSPRNG padding; `RandomFragmenter` scatters bytes across non-contiguous
chunks; `LayeredFragmenter` routes through one of N sub-strategies and
encodes the choice into the layout header so `defragment` dispatches
correctly.

### `src/memory/` — Layer 2 + 7

`LockedBytes` takes a block from the page pool (`pool.rs`) when it is
2048 bytes or smaller: pool memory is mapped by the crate in 16-page
chunks (each excluded from dumps once), pages are locked as they are
handed to a size class, and everything is kept for the life of the
process. The pool records each page's lock state, hands out blocks on
locked pages first, and retries pages whose lock failed (1.2).
Larger buffers own an exact-size heap buffer, and a page-protected
key's buffers point into its `GuardedRegion`. A heap buffer takes a
reference on every page it touches in a process-wide page table; a page
is locked (`mlock` / `VirtualLock`) and excluded from dumps
(`MADV_DONTDUMP` / `MADV_NOCORE` / WER) when its count goes from 0 to 1,
and released when it returns to 0. On drop the bytes are zeroed first,
then the references are released. The Unix and Windows backends live in
`unix.rs` and `windows.rs`.

`GuardedRegion` (`guarded.rs`) is a private mapping per protected key:
locked (not on Windows), excluded from dumps, `PROT_NONE` /
`PAGE_NOACCESS` except while a `RegionAccess` guard is alive, zeroed and
unmapped on drop.

Whether a key's memory is actually locked is public since 1.2:
`Fragments::is_locked()`, `KeyVault::is_memory_locked()` and
`KeyVault::memory_status()` read the pool's and the page table's
current state (a lock can fail at the process's `RLIMIT_MEMLOCK` or,
on Windows, its working-set limit). The buffer still works as a plain
zero-on-drop wrapper when the lock fails; strict locking
(`with_strict_locking`) refuses such keys instead. On Windows a failed
lock first raises the working-set size (`windows.rs`). After `fork`, a
`pthread_atfork` flag makes the child's next vault call lock every page
again (`relock_if_forked`).

### `src/decoy/` — Layer 4

`DecoyStrategy::generate` returns the requested number of filler bytes
in a `Vec<u8>`. The fragmenter mixes them with real key chunks during
`fragment`; `defragment` recognises decoy chunks via a sentinel value
in the layout buffer and skips them.

### `src/codex/` — Layer 5

`Codex::encode` / `decode` is byte-wise involution. The default
`IdentityCodex` is a no-op; the `StaticCodex` and `DynamicCodex`
implementations hold a 256-entry lookup table (themselves stored in
`LockedBytes`) generated as a random involution with no fixed points.

The vault applies the codex transparently — between normalisation
and fragmentation on the write side, and between defragmentation and
the user callback on the read side.

### `src/audit/` + `src/monitor/` — Layers 8 + 9

These are mirror surfaces. `SecurityMonitor` (Layer 8) receives
**anomaly / failure** events: `report_failure`, threshold breaches,
caller-driven anomaly reports. `AuditSink` (Layer 9) receives **every
successful operation** as an `AuditEvent`. Both traits are
`Send + Sync`, both contract for non-blocking implementors, both
default to inert sinks (`NoMonitor` / `NoAudit`).

`AuditSink::is_no_op()` (added in 0.11.0) is the hot-path optimisation
hook: when it returns `true`, the vault skips `AuditEvent`
construction entirely.

### `src/tee/` — Layer 1 sibling concern

Hardware-trusted-execution-environment **detection**. Not acquisition;
just "what does this CPU advertise?". `detect_tee_capabilities()`
probes CPUID on x86_64, reads DMI on Linux for AWS Nitro, and reports
Apple Secure Enclave on Apple Silicon. The output is a
`TeeCapabilities` struct that downstream code can use to gate which
fetcher to enable.

### `src/handle.rs` — opacity contract

`KeyHandle` is an opaque newtype around `KeyId = NonZeroU64`. Three
properties hold by construction:

1. `Debug` redacts the id (`KeyHandle(<redacted>)`).
2. `PartialEq` / `Eq` go through `subtle::ConstantTimeEq`.
3. `Hash` is consistent with `Eq` (both use the id).

`KeyId` is allocated from a process-global counter. Handles are
runtime-only; there is no `Serialize` / `Deserialize`.

---

## Data flow walk-throughs

### `register`

```
caller bytes
   │
   ▼
RawKey  ◄─ caller owns; zeroed on drop
   │
   ▼  (optional) BLAKE3 normalise → fresh RawKey of 32 bytes
   ▼  (optional) codex.encode each byte
   │
   ▼  fragmenter.fragment
Fragments  ◄─ contains LockedBytes chunks + LockedBytes layout
   │
   ▼  KeyHandle = next id
   ▼  writer lock: re-check name is free, insert, store new map
   ▼  emit_audit(Register) if audit is not no-op
   │
   ▼
returned KeyHandle
```

### `with_key`

```
KeyHandle from caller
   │
   ▼  load snapshot, look up entry, clone Arc<Fragments>
   ▼  drop snapshot
   │
   ▼  fragmenter.defragment_into(&fragments, scratch)  (thread-local,
   ▼  page-locked buffer; a guard zeroes it on every exit path)
   ▼  (optional) codex.decode each byte in place
   │
   ▼  callback(&scratch[..len])  ◄─ &[u8] valid for the call only
   ▼  guard drops here: volatile zero
   │
   ▼  emit_audit(Read) if audit is not no-op
   │
   ▼
T (the callback's return value)
```

### `rotate`

```
KeyHandle from caller, new RawKey
   │
   ▼  fragmenter.fragment(new_key)  →  new Fragments
   ▼  writer lock: re-check the key is still registered (KeyNotFound
   ▼  if not), build a new HashMap with the entry replaced, store it;
   ▼  concurrent readers see old or new
   │
   ▼  emit_audit(Rotate)
   │
   ▼
()
```

---

## Cross-crate dependencies

| Crate | Used for |
|-------|----------|
| `subtle` | Constant-time `KeyHandle` equality + master-key digest comparison |
| `arc-swap` | Lock-free reads + atomic writes on the named-key registry |
| `getrandom` | CSPRNG seeding for the fragmenter and decoy strategies |
| `blake3` | Key normalisation hash + master-key digest hash + XOF in `KeyDerivedDecoy` |
| `zeroize` | Wiping of every secret-bearing buffer the crate owns (always on since 1.0.2) |
| `keyring` (`fetcher-keychain` feature) | OS keychain integration |
| `tracing` (`monitor-tracing` feature) | `LogMonitor` and `LogAudit` event emission |
| `libc` (Unix) | `mlock(2)` / `munlock(2)` |
| `windows-sys` (Windows) | `VirtualLock` / `VirtualUnlock` |

Dev-only: `criterion`, `proptest`, `dhat`. Fuzz workspace pulls in
`libfuzzer-sys` and `arbitrary`.

---

## Why some things are not workspace-shaped

REPS describes a `crates/` + `bins/` workspace layout. `key-vault` is
a single library crate by design. The 1.0 contract is a single
focused API surface; splitting it into multiple crates would force
downstream consumers to depend on a feature graph instead of a single
version pin.

If the post-1.0 backlog (CLI tool, full TPM integration, KMS fetchers)
calls for it, those will ship as **sibling crates** depending on this
one — not as sub-crates of a workspace.

---

<sub>key-vault Architecture — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
