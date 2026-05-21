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
| `src/tee/` | TEE detection per architecture | external |
| `src/handle.rs` | `KeyHandle`, `KeyId`, the constant-time equality contract | external |
| `src/error.rs` | `Error` enum, `Result<T>` alias | external |
| `src/metadata.rs` | `KeyMetadata`, `AlgorithmHint` | external |
| `src/memory/` | `LockedBytes`, `mlock` / `VirtualLock` wrappers | `pub(crate)` |
| `src/normalize.rs` | BLAKE3 key normalisation helper | `pub(crate)` |

---

## Module-level design

### `src/vault/` — the orchestrator

`KeyVault` is a thin `Arc<VaultInner>` wrapper. Cloning a vault is
cheap (atomic refcount); registering / rotating goes through
`ArcSwap::rcu` for atomic, lock-free writes.

```rust
struct VaultInner {
    keys: ArcSwap<HashMap<KeyId, KeyEntry>>,
    config: VaultConfig,
    codex: Option<Arc<dyn Codex>>,
    fragmenter: StandardFragmenter,
    monitor: Arc<dyn SecurityMonitor>,
    audit: Arc<dyn AuditSink>,
    master_hash: Option<[u8; 32]>,
    failure_tracker: Mutex<HashMap<String, VecDeque<Instant>>>,
    locked_out: AtomicBool,
}

struct KeyEntry {
    name: String,
    fragments: Arc<Fragments>,
    metadata: KeyMetadata,
}
```

**Hot path** (`with_key`): load the `ArcSwap` snapshot, look up the
entry, clone the `Arc<Fragments>`, drop the snapshot, defragment, run
the user closure, optionally emit an audit event.

**Write path** (`register` / `rotate` / `unregister`): build the new
key entry, then `keys.rcu(|current| { let mut next = current.clone(); … ; next })`.
The atomic swap means readers either see the old map or the new map,
never a torn intermediate.

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

`LockedBytes` wraps a `Vec<u8>`, calls `mlock`/`VirtualLock` on
construction, and unmlocks + volatile-zeroes the bytes on drop. The
Unix and Windows backends live in `unix.rs` and `windows.rs`
respectively; `mod.rs` exposes a single `LockedBytes` type that
selects the right backend via `#[cfg(unix)]` / `#[cfg(windows)]`.

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
   ▼  ArcSwap::rcu insert into keys map
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
   ▼  fragmenter.defragment(&fragments)  →  RawKey
   ▼  (optional) codex.decode each byte
   │
   ▼  callback(raw.as_bytes())  ◄─ &[u8] valid for the call only
   ▼  RawKey drops here — volatile zero
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
   ▼  ArcSwap::rcu: build a new HashMap with the entry replaced
   ▼  swap the Arc atomically — concurrent readers see old or new
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
| `getrandom` + `rand_core` | CSPRNG seeding for the fragmenter and decoy strategies |
| `blake3` | Key normalisation hash + master-key digest hash + XOF in `KeyDerivedDecoy` |
| `zeroize` | Optional `ZeroizeOnDrop` derive on internal byte buffers |
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
