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
    keys: ArcSwap<HashMap<KeyId, KeyEntry>>,   // no_std: spin-locked Arc<BTreeMap>
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
    failure_tracker: Mutex<BTreeMap<String, VecDeque<Duration>>>,  // clock time
    locked_out: AtomicBool,                            // vault-wide lockout
    key_locks: Mutex<BTreeMap<String, Option<Duration>>>,  // per-key lockout
    key_locks_active: AtomicUsize,                     // lets with_key skip key_locks
}

struct KeyEntry {
    name: String,
    fragments: Fragments,            // shares an Arc'd store; may own a protected region
    metadata: KeyMetadata,
}
```

**Hot path** (`with_key`): load the `ArcSwap` snapshot, look up the
entry, check the per-key lockout (one atomic load when no key is locked
out), take a reference to the fragments, drop the snapshot, open the
protected region if there is one, defragment into the thread-local
scratch buffer (page-locked, dump-excluded, zeroed after every call),
close the region, run the user closure, optionally emit an audit event.

**Write path** (`register` / `rotate` / `unregister`): fragment the new
key outside any lock, then take the writer mutex, load the current map,
re-check the precondition (name not taken, key still present), clone
the map with the change applied and `store` it, and release the mutex.
Readers either see the old map or the new map, never a torn
intermediate. Before 1.0.2 writers used `ArcSwap::rcu` with the check
outside the retry loop, which let two `register` calls insert the same
name and let `rotate` report success for a key removed concurrently.

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
2048 bytes or smaller: pool pages are mapped by the crate, locked and
excluded from dumps once, and kept for the life of the process.
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

`LockedBytes::is_locked()` reports whether mlock was actually
permitted (containers and unprivileged contexts may have
`RLIMIT_MEMLOCK = 0`). The buffer still works as a plain
zero-on-drop wrapper when mlock fails.

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
