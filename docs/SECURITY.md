# Security Architecture

> What each layer of `key-vault` does in 1.0.x, what it protects against, and what it does not. This document was rewritten for 1.0.2 to match the code; earlier versions overstated several layers.

---

## Threat model

`key-vault` keeps secret keys in process memory for a running application. The question every layer answers is: who could get at those bytes, and how?

### What it helps with

| Threat | What helps | How much |
|--------|------------|----------|
| Keys written to swap | Layer 2 (page locking) | Real, but best effort: locking can fail silently against `RLIMIT_MEMLOCK` (Linux/macOS) or the minimum working-set size (Windows). Check `ulimit -l`. |
| Keys left in freed memory | Layer 7 (zero-on-drop) | Real for every buffer the crate allocates. Not for copies made by `std`, the OS, `keyring`, or your own code. |
| Keys leaking through logs, `Debug`, error messages | Redacted `Debug` impls, sanitized errors, opaque `KeyHandle` | Real. |
| Long-lived plaintext copies in application code | `with_key` hands out a slice only for the duration of a callback | Real, as long as the callback does not copy the bytes somewhere long-lived. |
| Casual memory scans, heap dumps searched with generic tools (looking for a contiguous key, a known format, or a high-entropy run) | Layers 3, 4, 5 (fragmentation, decoys, codex), BLAKE3 normalization | **Obfuscation only.** Raises the effort for tools that do not know this crate. See below. |
| Timing differences in the master-credential check | Layer 6 (`subtle::ConstantTimeEq`) | Real for that comparison. |

### What it does not protect against

- **Anyone who can read the process's memory.** This includes a debugger, another process running as the same user with `ptrace` / `ReadProcessMemory`, a full core dump or Windows crash dump, malware injected into the process, and the kernel. Every piece needed to rebuild a key is in the same address space:
  - the fragments (Layer 3),
  - the layout buffer that records where each fragment belongs **and which chunks are decoys** (Layer 4 marks decoys with the offset `u32::MAX`),
  - the codex lookup table (Layer 5).

  An attacker with read access walks the vault's structures and rebuilds every key. Fragmentation, decoys and the codex only help against tools that do not understand this layout. They are obfuscation, not encryption, and not protection against a memory reader.
- **Code running inside the process.** It can call `KeyVault::with_key` like your application does.
- **Hardware attacks** (DMA, cold boot) and **side channels in the cryptographic code** that uses the key.
- **Offline guessing of low-entropy keys.** BLAKE3 normalization and the master-key digest are unsalted, fast hashes, not password hashes. If the input is a passphrase, anyone who obtains the normalized value or the master digest can test guesses at BLAKE3 speed. Run passphrases through a slow KDF (Argon2, scrypt) before registering them.

---

## Layer summary (1.0.x)

| Layer | What it is | Status | Protects against | Does not protect against |
|-------|-----------|--------|------------------|--------------------------|
| **1** | Key acquisition (`KeyFetch`) | Keychain, plaintext file, env var. `TpmFetch` **not implemented** | Hardcoding keys in source | Anything once the key is in memory |
| **2** | Page locking (`mlock` / `VirtualLock`) | On, best effort, per-page reference counted (1.0.2) | Swap | Memory readers, core/crash dumps |
| **3** | Fragmentation (`StandardFragmenter`) | Always on in the vault | Contiguous-key scans | Memory readers (layout map is in memory) |
| **4** | Decoy chunks | **Off** unless `with_decoy` is called | Statistical scans for key-like regions | Memory readers (layout map marks decoys) |
| **5** | Codex byte substitution | **Off** unless `with_codex` is called | Scans for the raw key bytes | Memory readers (table is in memory) |
| **6** | Constant-time comparison | Master digest and handle equality | Timing on the master check | Timing of defragmentation or registry lookups (not constant-time) |
| **7** | Zero-on-drop (`zeroize`) | On for every buffer the crate owns (extended in 1.0.2) | Freed-memory leakage | Copies outside the crate's control |
| **8** | Failure monitor + lockout | **Advisory**, caller-reported, vault-wide | Repeated failures *that the caller reports* | Memory readers; failures the caller does not report |
| **9** | Audit hooks | One event per operation | Undetected API-level use | Tampering with the sink; anything below the API |
| **10** | Page protection toggling (`PROT_NONE`) | **Not implemented** | | |

Cargo features do not switch layers on or off. In 1.0.x only `std`, the `fetcher-*` features and `monitor-tracing` change what is compiled. `mlock`, `zeroize`, `codex`, `codex-dynamic`, all `decoy-*`, all `fragment-*`, `monitor`, `audit`, `tee-detect`, `post-quantum` and all `preset-*` features are reserved and have no effect. `preset-fast` does not turn off page locking, and `preset-paranoid` does not turn on decoys or a codex.

---

## Layer 1: Key acquisition

### What it does

The `KeyFetch` trait is where key bytes come from. Fetchers read a key once; the vault takes it from there.

```rust
pub trait KeyFetch: Send + Sync {
    fn fetch(&self, ctx: &FetchContext) -> Result<RawKey>;
    fn describe(&self) -> Cow<'_, str>;
}
```

### Built-in fetchers

| Fetcher | Feature | Source | Notes |
|---------|---------|--------|-------|
| `KeychainFetch` | `fetcher-keychain` | OS credential store via `keyring` | Strongest built-in. UTF-8 secrets only (`get_password`); a binary secret fails, and the bytes carried by that error are zeroized (1.0.2). |
| `FileFetch` | `fetcher-file` | **Plaintext** file | No decryption of any kind. On Unix the file is opened once and the mode is read from the open handle, so the check and the read see the same file (1.0.2; before that a path swap between check and read was possible). Files with any `0o077` bit are rejected unless `allow_loose_perms()`. The owner and the parent directory are not checked. No permission check on Windows. |
| `EnvFetch` | `fetcher-env` | Environment variable | The value **stays in the environment** (and `/proc/<pid>/environ`, and child processes). UTF-8 only; a non-UTF-8 value is zeroized before the error is returned (1.0.2). |
| `TpmFetch` | `fetcher-tpm` | Nothing | **Not implemented.** `fetch` always returns `Error::Acquisition`. No TPM is detected or used anywhere in the crate. |

### Limits

Buffers inside `std` (file I/O, the environment block, UTF-16 conversion on Windows), the OS page cache and the platform credential APIs are outside this crate's control and are not wiped.

---

## Key normalization (BLAKE3)

With normalization on (the default), the key is replaced by `BLAKE3(key)` before it is stored. The 32-byte digest **is** the effective key: it is what `with_key` returns. This removes format cues (PEM headers, DER structure) from memory.

It is an unkeyed, unsalted, fast hash. It does not make a weak key stronger, and the stored digest allows offline guessing of low-entropy inputs. Since 1.0.2 the hasher state and output reader are zeroized after use and the digest is written straight into a zeroize-on-drop buffer. Temporaries inside BLAKE3's compression function live on the stack and are not wiped.

---

## Layer 2: Page locking

### What it does

Every `LockedBytes` buffer (fragments, layout maps, codex tables) and, since 1.0.2, the `with_key` scratch buffer, asks the OS to keep its pages in RAM: `mlock` on Linux/macOS, `VirtualLock` on Windows.

### Reference counting (1.0.2)

The OS locks whole pages, and locks do not nest: one `munlock` releases a page no matter how many buffers on it were locked. Fragments are small separate allocations, so fragments of different keys routinely share a page. In 1.0.1 and earlier, dropping any fragment (on `rotate`, `unregister` or a one-shot `defragment`) unlocked its whole page, including pages other live keys still used, and the lock was silently lost.

1.0.2 keeps a process-wide table counting, per page, how many live locked buffers touch it. A page is locked when its count goes from 0 to 1 and unlocked only when the count returns to 0.

### Protects against

- Key pages being written to swap.

### Does not protect against

- Memory readers of any kind.
- Core dumps and Windows crash dumps: locked pages are still dumped. The crate does not use `MADV_DONTDUMP` or exclude memory from Windows dumps.
- Hibernation: platform dependent.
- Lock failures. If the OS refuses (resource limit), the buffer works unlocked and nothing is reported to the caller.

---

## Layer 3: Fragmentation

### What it does

`StandardFragmenter` splits the (normalized, optionally codex-encoded) key into chunks of 1-8 bytes (configurable with `with_chunk_range`), shuffles them, and stores each chunk in its own `LockedBytes`. A separate `LockedBytes` layout buffer stores each chunk's original offset.

The vault always uses `StandardFragmenter`. `InterleavedFragmenter`, `RandomFragmenter` and `LayeredFragmenter` exist and can be used directly through the `FragmentStrategy` trait, but the builder cannot select them in 1.0.x, and the `fragment-*` features do nothing.

### Protects against

- A scan that looks for the key as one contiguous run of bytes.

### Does not protect against

- Memory readers: the layout buffer that reassembles the key is in the same process memory. Small heap allocations are also usually close together, often on the same page, so "non-contiguous" does not mean "far apart".

---

## Layer 4: Decoy chunks

### What it does

When a `DecoyStrategy` is set with `KeyVaultBuilder::with_decoy`, `StandardFragmenter` adds one decoy chunk per real chunk and shuffles them together. **No decoy is used by default**, and the `decoy-*` features do not add one.

| Strategy | Output | Statistical cover |
|----------|--------|-------------------|
| `RandomDecoy` | CSPRNG bytes | Weakest |
| `KeyDerivedDecoy` | BLAKE3 XOF of key + nonce | Medium |
| `SelfReferenceDecoy` | Bytes sampled from the key | Strongest |

### Protects against

- Statistical scans (entropy, byte histograms) that try to find key-like regions without knowing the vault's layout.

### Does not protect against

- Memory readers: the layout buffer marks every decoy chunk with the offset `u32::MAX`.

---

## Layer 5: Codex

### What it does

When a codex is set with `KeyVaultBuilder::with_codex`, every byte of the key is passed through `Codex::encode` before fragmentation and `Codex::decode` after reassembly. The built-in codices (`StaticCodex`, `DynamicCodex`) are 256-byte substitution tables that are involutions (encode equals decode). **No codex is used by default**, and the `codex` / `codex-dynamic` features do not add one.

### Protects against

- A scan for the raw key bytes, or a tool that reassembles fragments without knowing a codex was applied.

### Does not protect against

- Memory readers: the table is stored in a `LockedBytes` in the same process. A substitution table is not a cipher.

---

## Layer 6: Constant-time comparison

`subtle::ConstantTimeEq` is used for the master-credential digest check (`unlock_with_master`) and for `KeyHandle` equality.

Not constant-time: the registry lookup by handle (a `HashMap`), `handle_for_name`, and defragmentation, whose time depends on chunk count and layout. Handle ids are not secret, so the handle comparison is hygiene, not a security property.

---

## Layer 7: Zero-on-drop

### What is wiped

Through the `zeroize` crate (always on since 1.0.2; the `zeroize` feature is reserved):

- `LockedBytes` (fragments, layout maps, codex tables) on drop, before unlocking.
- `RawKey` on drop: the **whole allocation including spare capacity** (1.0.2; before that only `0..len`, so bytes beyond the length after a `truncate` survived).
- The `with_key` scratch buffer after every call, including on defragment errors and panics.
- Normalization and master-digest hasher state, output readers and digests (1.0.2).
- The master-credential digest held by the builder and the vault (1.0.2).
- Decoy generator output and hasher state, codex construction tables, fragmenter temporaries (layout encodings, positions, pools) on every exit path (1.0.2).
- `FileFetch` read buffers on error and on growth; rejected non-UTF-8 `EnvFetch` values; the bytes inside `keyring`'s `BadEncoding` error (1.0.2).

### Not wiped (outside the crate's control)

- Copies made inside `std`, the OS, `keyring` or the platform credential APIs while fetching.
- Copies your callback makes (into a cipher's key schedule, a `Vec`, the stack).
- Stack temporaries inside BLAKE3 and other dependencies.
- A buffer you reallocated while filling it before handing it to `RawKey::new`.

### Protects against

- Key bytes surviving in freed heap memory that is later reused or dumped.

### Does not protect against

- Reading memory while the key is live.

---

## Layer 8: Failure monitor and lockout

### What it does

`SecurityMonitor` receives failure, anomaly and threshold-breach events. `with_failure_threshold(max, window)` turns on lockout: once `max` failures for one key name are reported within `window`, the whole vault refuses `register`, `with_key`, `rotate`, `fragment` and `defragment` until `clear_lockout` or a successful `unlock_with_master`.

### How it really works

- **Advisory.** The vault never detects failures itself. Only failures the caller passes to `report_failure` (and wrong master credentials) count. The vault never sees what you do with a key, so it cannot know a decryption failed.
- **Vault-wide.** Failures reported for one key name lock out every key. Code that reports failures on untrusted input can be used to deny service. Per-key lockout is planned for 1.1.
- **No master-unlock rate limit.** `unlock_with_master` has no backoff of its own; repeated wrong attempts count toward the threshold like any reported failure. Throttle it yourself if it is reachable from untrusted input.
- Lockout does nothing against a memory reader.

Built-in monitors: `NoMonitor` (default), `CompositeMonitor`, `LogMonitor` (`monitor-tracing`).

---

## Layer 9: Audit hooks

Every vault operation (register, unregister, read, rotate, one-shot fragment/defragment, master-unlock attempt) emits an `AuditEvent` to the configured `AuditSink` (`NoAudit` by default). Events carry the key name, never key bytes.

- Since 1.0.2, `register` and `rotate` no longer emit an extra unnamed `OneShotFragment` event.
- Events are emitted after the operation completes. Two operations that run concurrently on different threads may reach the sink in either order.
- The crate does not protect the audit trail from tampering; that is the sink's job.

---

## Layer 10: Page protection toggling

**Not implemented.** Earlier documentation described `PROT_NONE` / `PAGE_NOACCESS` toggling between accesses. There is no `mprotect` or `VirtualProtect` call anywhere in the crate. If it is added in a later release it will be opt-in, and it would still not stop an attacker who can call `mprotect` or read memory through the kernel.

---

## Concurrency (1.0.2)

Reads are lock-free (`ArcSwap` snapshots). Writes are serialized by a writer mutex; each writer re-checks its precondition under the lock. This fixes two races in 1.0.1:

- Two concurrent `register` calls with the same name could both succeed, leaving two keys under one name.
- `rotate` could return `Ok` (and emit a Rotate audit event) for a key that a concurrent `unregister` had already removed.

---

## Verification

| Claim | Verification | Location |
|-------|--------------|----------|
| Fragment round-trip is identity | `proptest` sweeps over all strategies | `tests/proptest_invariants.rs` |
| Codex involution holds for every byte | `proptest` full byte-range sweep | `tests/proptest_invariants.rs` |
| `SelfReferenceDecoy` only emits key bytes | `proptest` + fuzz target | `tests/proptest_invariants.rs`, `fuzz/` |
| `KeyHandle::Debug` never reveals the id | `proptest` + unit sweep | `tests/proptest_invariants.rs`, `src/handle.rs` |
| No torn reads across rotation | 4-thread reader loop vs. rotations | `tests/proptest_invariants.rs`, `tests/registry_concurrent.rs` |
| `mlock` pins pages on Linux | `VmLck` delta after registrations | `tests/mlock_verified.rs` |
| A page stays locked while any buffer on it is alive | Two regions on one page: release one, count stays 1; two keys sharing a page: unregister one, the other's pages stay counted | `src/memory/mod.rs`, `src/vault/mod.rs` unit tests |
| `RawKey` wipes its spare capacity | Truncated buffer inspected through the still-owned allocation after `wipe` | `src/fetcher/mod.rs` unit test |
| Normalization output unchanged by the rewrite | Compared against `blake3::hash` | `src/normalize.rs` unit test |
| Scratch buffer zeroed on error / panic | Buffer inspected after forced defragment error, codex panic, callback panic | `src/vault/mod.rs` unit tests |
| One winner per name under concurrent `register` | 8 threads x 200 rounds on the same name | `tests/registry_races.rs` |
| `rotate` fails cleanly against concurrent `unregister` | `rotate` parked between pre-check and update while `unregister` runs; plus a 4-thread stress loop | `src/vault/mod.rs` unit tests |
| `FileFetch` checks and reads the same file | Path swapped after open; read returns the checked file | `src/fetcher/file.rs` unit test (Unix) |
| No panics on arbitrary input | `cargo-fuzz` targets | `fuzz/fuzz_targets/*.rs` |
| Zero-allocation hot path | `dhat` over 100,000 `with_key` calls | `examples/dhat_hot_path.rs` |

### Not verified by automation

- That zeroized memory stays zero after it is freed (would require reading freed memory).
- Constant-time behavior of `with_key` (it is not constant-time; see Layer 6).
- That page locks hold under memory pressure on every platform. The refcount table is tested; the OS lock itself is only checked on Linux via `VmLck`.
- Cold-boot and DMA resistance (out of scope).

---

<sub>key-vault Security Architecture - Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
