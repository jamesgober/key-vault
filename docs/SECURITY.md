# Security Architecture

> What each layer of `key-vault` does in 1.1, what it protects against, and what it does not. Rewritten for 1.0.2 to match the code and updated for 1.1, which added dump exclusion, page protection, per-key lockout, master-unlock backoff and keyed normalization.

---

## Threat model

`key-vault` keeps secret keys in process memory for a running application. The question every layer answers is: who could get at those bytes, and how?

### What it helps with

| Threat | What helps | How much |
|--------|------------|----------|
| Keys written to swap | Layer 2 (page locking) | Real, but best effort: locking can fail against `RLIMIT_MEMLOCK` (Linux/macOS) or the minimum working-set size (Windows), and the crate does not report it. Check `ulimit -l`. |
| Keys in core dumps and crash dumps | Layer 2 (dump exclusion, 1.1) | Linux and Android core dumps (`MADV_DONTDUMP`), FreeBSD and DragonFly core dumps (`MADV_NOCORE`), Windows Error Reporting dumps (`WerRegisterExcludedMemoryBlock`). Not macOS, and not dumps that a debugger or another tool takes (see below). |
| Keys left in freed memory | Layer 7 (zero-on-drop) | Real for every buffer the crate allocates. Not for copies made by `std`, the OS, `keyring`, or your own code. |
| Stray reads of key memory from inside the process (a buffer over-read, a scan of readable memory) | Layer 10 (page protection, opt-in, 1.1) | Real while no thread is reading the key: the pages are `PROT_NONE` / `PAGE_NOACCESS` and any access faults. |
| Keys leaking through logs, `Debug`, error messages | Redacted `Debug` impls, sanitized errors, opaque `KeyHandle` | Real. |
| Long-lived plaintext copies in application code | `with_key` hands out a slice only for the duration of a callback | Real, as long as the callback does not copy the bytes somewhere long-lived. |
| Guessing through the API: repeated failures, master-credential guessing | Layer 8 (per-key and vault-wide lockout, master-unlock backoff) | Real for failures the caller reports and for `unlock_with_master`. Off by default. |
| A copy of a stored normalized key or of the master verifier being used to guess the input offline | Keyed normalization (opt-in, 1.1), keyed master verifier (always, 1.1) | Real when the copy does not also include the hash key. See [Key normalization](#key-normalization-blake3). |
| Casual memory scans, heap dumps searched with generic tools (looking for a contiguous key, a known format, or a high-entropy run) | Layers 3, 4, 5 (fragmentation, decoys, codex), BLAKE3 normalization | **Obfuscation only.** Raises the effort for tools that do not know this crate. See below. |
| Timing differences in the master-credential check | Layer 6 (`subtle::ConstantTimeEq`) | Real for that comparison. |

### What it does not protect against

- **Anyone who can read the process's memory through the kernel or a debugger.** This includes a debugger, another process running as the same user with `ptrace` / `ReadProcessMemory` / `/proc/<pid>/mem`, a full-memory dump taken by such a tool (gdb's `gcore`, procdump, Task Manager, `MiniDumpWriteDump`), malware injected into the process, and the kernel. These readers ignore or can change page permissions and do not consult dump-exclusion flags. Every piece needed to rebuild a key is in the same address space:
  - the fragments (Layer 3),
  - the layout buffer that records where each fragment belongs **and which chunks are decoys** (Layer 4 marks decoys with the offset `u32::MAX`),
  - the codex lookup table (Layer 5),
  - the normalization key and master verifier key, if used.

  An attacker with that access walks the vault's structures and rebuilds every key. Fragmentation, decoys and the codex only help against tools that do not understand this layout. They are obfuscation, not encryption.
- **Code running inside the process.** It can call `KeyVault::with_key` like your application does.
- **Hardware attacks** (DMA, cold boot) and **side channels in the cryptographic code** that uses the key.
- **Offline guessing of low-entropy keys with plain normalization (the default).** The normalized value is a fast, unkeyed BLAKE3 hash. If the input is a passphrase, anyone who obtains the normalized value can test guesses at BLAKE3 speed. Use keyed normalization, or run passphrases through a slow KDF (Argon2, scrypt) before registering them.

---

## Layer summary (1.1)

| Layer | What it is | Status | Protects against | Does not protect against |
|-------|-----------|--------|------------------|--------------------------|
| **1** | Key acquisition (`KeyFetch`) | Keychain (native stores since 1.1), plaintext file, env var. `TpmFetch` **not implemented** | Hardcoding keys in source | Anything once the key is in memory |
| **2** | Page locking + dump exclusion | On, best effort, per-page reference counted | Swap; core dumps and WER dumps | Memory readers; dumps taken by debuggers; macOS core dumps |
| **3** | Fragmentation | `StandardFragmenter` by default; any strategy with `with_fragmenter` (1.1) | Contiguous-key scans | Memory readers (layout map is in memory) |
| **4** | Decoy chunks | **Off** unless `with_decoy` (or `from_features`) | Statistical scans for key-like regions | Memory readers (layout map marks decoys) |
| **5** | Codex byte substitution | **Off** unless `with_codex` (or `from_features`) | Scans for the raw key bytes | Memory readers (table is in memory) |
| **6** | Constant-time comparison | Master verifier and handle equality | Timing on the master check | Timing of defragmentation or registry lookups (not constant-time) |
| **7** | Zero-on-drop (`zeroize`) | On for every buffer the crate owns | Freed-memory leakage | Copies outside the crate's control |
| **8** | Failure monitor, lockout, backoff | **Advisory**, caller-reported. Vault-wide and per-key (1.1) lockout, master-unlock backoff (1.1), all off by default | Repeated failures *that the caller reports*; master guessing through the API | Memory readers; failures the caller does not report |
| **9** | Audit hooks | One event per operation | Undetected API-level use | Tampering with the sink; anything below the API |
| **10** | Page protection (`PROT_NONE` / `PAGE_NOACCESS`) | **Opt-in** (`with_page_protection`, 1.1) | Stray in-process reads between accesses | Kernel/debugger readers; the scratch copy during the callback |

Cargo features never change what `KeyVaultBuilder::new()` builds. The `fragment-*`, `decoy-*`, `codex*`, `monitor`, `audit` and `preset-*` features choose what `KeyVaultBuilder::from_features()` configures; `mlock`, `zeroize`, `tee-detect` and `post-quantum` are deprecated no-ops. Page locking, dump exclusion and zeroization cannot be turned off. See [docs/API.md](API.md#cargo-features).

---

## Layer 1: Key acquisition

### What it does

The `KeyFetch` trait is where key bytes come from. Fetchers read a key once; the vault takes it from there. All built-in fetchers need `std`.

```rust
pub trait KeyFetch: Send + Sync {
    fn fetch(&self, ctx: &FetchContext) -> Result<RawKey>;
    fn describe(&self) -> Cow<'_, str>;
}
```

### Built-in fetchers

| Fetcher | Feature | Source | Notes |
|---------|---------|--------|-------|
| `KeychainFetch` | `fetcher-keychain` | OS credential store via `keyring` | Keychain Services (macOS), Credential Manager (Windows), Secret Service over D-Bus (Linux, BSDs). **Before 1.1 it never reached the OS:** `keyring` was used without a store feature and fell back to its in-memory mock. UTF-8 passwords by default (a binary value fails, and the bytes carried by that error are zeroized); `.binary()` (1.1) reads raw bytes with `get_secret`. |
| `FileFetch` | `fetcher-file` | **Plaintext** file | No decryption of any kind. On Unix the file is opened once and checked through the open handle: mode (no `0o077` bits), owner (the process user or root, 1.1), and every directory on the resolved path plus the directory holding the given path (owned by the process user or root, not writable by group or others unless sticky, 1.1). The resolved path must still lead to the opened file. `skip_directory_check()` drops the directory check; `allow_loose_perms()` drops all checks. No permission check on Windows: NTFS ACLs are trusted. |
| `EnvFetch` | `fetcher-env` | Environment variable | The value **stays in the environment** (and `/proc/<pid>/environ`, and child processes). UTF-8 only; a non-UTF-8 value is zeroized before the error is returned. |
| `TpmFetch` | `fetcher-tpm` | Nothing | **Not implemented.** `fetch` always returns `Error::Acquisition`. No TPM is detected or used anywhere in the crate. |

### Limits

Buffers inside `std` (file I/O, the environment block, UTF-16 conversion on Windows), the OS page cache and the platform credential APIs are outside this crate's control and are not wiped.

---

## Key normalization (BLAKE3)

With normalization on (the default), the key is replaced by a 32-byte BLAKE3 output before it is stored. That output **is** the effective key: it is what `with_key` returns. This removes format cues (PEM headers, DER structure) from memory.

| Mode | Builder | Stored value | Stable across processes |
|------|---------|--------------|-------------------------|
| Plain (default) | `normalize_with_blake3(true)` | `BLAKE3(key)` | Yes |
| Keyed, random key | `with_keyed_normalization()` (1.1) | `BLAKE3-keyed(k, key)`, `k` random per vault | **No** |
| Keyed, your key | `with_normalization_key(nk)` (1.1) | `BLAKE3-keyed(derive_key(nk), key)` | Yes, with the same `nk` |
| Off | `normalize_with_blake3(false)` | the key itself | Yes |

Plain BLAKE3 is a fast, unkeyed hash: it does not make a weak key stronger, and a copy of the stored value allows offline guessing of a low-entropy input. In the keyed modes the hash key `k` is held like key material (locked, excluded from dumps, zeroed on drop, page-protected when that option is on), so a copy of a stored value alone is useless for guessing. An attacker who reads both `k` and the stored value from the process can still guess, so a passphrase should still go through a slow KDF first.

**Why plain BLAKE3 stays the default.** The normalized value is not internal: it is the key `with_key` hands to your cipher, and applications derive data-at-rest keys from it. Switching the default to a keyed hash would change every effective key and make existing data undecryptable, so it is planned for 2.0. The random-key mode is for keys whose derived value never has to match across runs; for anything else, use `with_normalization_key`.

Hasher state and output readers are zeroized after use and outputs are written straight into zeroize-on-drop buffers. Temporaries inside BLAKE3's compression function live on the stack and are not wiped.

---

## Layer 2: Page locking and dump exclusion

### What it does

Every `LockedBytes` buffer (fragments, layout maps, codex tables, the normalization key, the master verifier) and the `with_key` scratch buffer ask the OS for two things on each page they touch:

- **Locking** (`mlock` on Linux/macOS, `VirtualLock` on Windows): keep the page in RAM so it is not written to swap.
- **Dump exclusion** (1.1): `madvise(MADV_DONTDUMP)` on Linux and Android, `madvise(MADV_NOCORE)` on FreeBSD and DragonFly, `WerRegisterExcludedMemoryBlock` on Windows 10 1709 and later (looked up at run time, so older Windows still loads the crate).

### Page pool (1.1)

Buffers of up to 2048 bytes (fragments, layout maps, codex tables, the normalization key, the master verifier) come from a pool of pages the crate maps for itself. Each pool page serves one block size, is locked and excluded from dumps once when it is mapped, holds only key buffers, and stays mapped for the life of the process; freed blocks are zeroed and reused. Registering, rotating and dropping keys therefore makes no system calls once the pool has grown to its working size, and no unrelated data shares a key page. The pool keeps its pages after keys are dropped, so it stays at the peak number of live key buffers.

### Reference counting

Larger buffers and the `with_key` scratch buffer live on the general heap. The OS applies locking and exclusion to whole pages, and they do not nest: one `munlock` releases a page no matter how many buffers on it were locked. A process-wide table counts, per page, how many live buffers touch it. A page is locked and excluded when its count goes from 0 to 1, and released (unlocked, included in dumps again) only when the count returns to 0. A page whose lock or exclusion failed is retried the next time a buffer arrives on it.

### Protects against

- Key pages being written to swap.
- Key pages appearing in kernel core dumps (Linux, Android, FreeBSD, DragonFly) and in Windows Error Reporting crash dumps.

### Does not protect against

- Memory readers of any kind.
- Dumps that are not written by the kernel or WER: `gcore`, debuggers, procdump, Task Manager "Create dump file", `MiniDumpWriteDump` with full memory. These read memory directly.
- macOS core dumps: macOS has no per-page exclusion.
- Hibernation: platform dependent.
- Lock or exclusion failures, which leave the buffer working without that protection and are not reported to the caller.

### Side effects and limits

- Heap pages (large buffers, the scratch buffer) are shared with whatever else the allocator placed on them, so the unrelated objects on such a page are left out of core dumps too. Pool pages hold only key buffers.
- WER keeps at most 512 excluded blocks per process (measured on Windows 11). Each pool page, each excluded heap page and each page-protected key is one block; beyond that, further pages are not excluded until earlier ones are released.
- Because all small key buffers sit in a few dedicated pages, a reader who can see page flags (locked, no-dump) can find them more easily than on the general heap. That is the memory reader the threat model already excludes.

---

## Layer 3: Fragmentation

### What it does

`StandardFragmenter` (the default) splits the (normalized, optionally codex-encoded) key into chunks of 1-8 bytes (configurable with `with_chunk_range`), shuffles them, and stores each chunk in its own `LockedBytes`. A separate layout buffer stores each chunk's original offset.

Since 1.1 `KeyVaultBuilder::with_fragmenter` selects any `FragmentStrategy`: the built-in `InterleavedFragmenter`, `RandomFragmenter` and `LayeredFragmenter`, or your own (`RawKey::expose_secret`, `Fragments::from_chunks` and the `Fragments` accessors make that possible). `LayeredFragmenter` no longer copies every chunk into new locked buffers on each read; it hands the sub-strategy a view of the same chunks.

### Protects against

- A scan that looks for the key as one contiguous run of bytes.

### Does not protect against

- Memory readers: the layout buffer that reassembles the key is in the same process memory. Small heap allocations are also usually close together, often on the same page, so "non-contiguous" does not mean "far apart". `LayeredFragmenter` records which sub-strategy it used in the clear.

---

## Layer 4: Decoy chunks

### What it does

When a `DecoyStrategy` is set with `KeyVaultBuilder::with_decoy`, `StandardFragmenter` adds one decoy chunk per real chunk and shuffles them together. **No decoy is used by `KeyVaultBuilder::new()`**. `KeyVaultBuilder::from_features()` adds the decoy chosen by the `decoy-*` features (`SelfReferenceDecoy` with the default features). With another fragmenter, decoys from `with_decoy` are not used (`Debug` shows `decoy_ignored: true`); configure them on the strategy.

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

When a codex is set with `KeyVaultBuilder::with_codex` (or by `from_features()` with the `codex` feature), every byte of the key is passed through `Codex::encode` before fragmentation and `Codex::decode` after reassembly. The built-in codices (`StaticCodex`, `DynamicCodex`) are 256-byte substitution tables that are involutions (encode equals decode). **No codex is used by `KeyVaultBuilder::new()`**.

### Protects against

- A scan for the raw key bytes, or a tool that reassembles fragments without knowing a codex was applied.

### Does not protect against

- Memory readers: the table is stored in a `LockedBytes` in the same process. A substitution table is not a cipher.

---

## Layer 6: Constant-time comparison

`subtle::ConstantTimeEq` is used for the master-credential check (`unlock_with_master`) and for `KeyHandle` equality.

Not constant-time: the registry lookup by handle (a `HashMap` with `std`, a `BTreeMap` without), `handle_for_name`, and defragmentation, whose time depends on chunk count and layout. Handle ids are not secret, so the handle comparison is hygiene, not a security property.

---

## Layer 7: Zero-on-drop

### What is wiped

Through the `zeroize` crate:

- `LockedBytes` (fragments, layout maps, codex tables, normalization key, master verifier) on drop, before the pages are released.
- Page-protected regions (1.1): the whole mapping, before it is unmapped.
- `RawKey` on drop: the whole allocation including spare capacity.
- The `with_key` scratch buffer after every call, including on defragment errors and panics (per thread with `std`, per call without).
- Normalization and master-verifier hasher state, output readers and digests, including the keyed variants (1.1).
- The caller-supplied normalization key passed to `with_normalization_key` (1.1).
- Decoy generator output and hasher state, codex construction tables, fragmenter temporaries (layout encodings, positions, pools) on every exit path.
- `FileFetch` read buffers on error and on growth; rejected non-UTF-8 `EnvFetch` values; the bytes inside `keyring`'s `BadEncoding` error.

### Not wiped (outside the crate's control)

- Copies made inside `std`, the OS, `keyring` or the platform credential APIs while fetching.
- Copies your callback makes (into a cipher's key schedule, a `Vec`, the stack).
- Stack temporaries inside BLAKE3 and other dependencies.
- A buffer you reallocated while filling it before handing it to `RawKey::new`, and copies you made of `RawKey::expose_secret`.

### Protects against

- Key bytes surviving in freed heap memory that is later reused or dumped.

### Does not protect against

- Reading memory while the key is live.

---

## Layer 8: Failure monitor, lockout and backoff

### What it does

`SecurityMonitor` receives failure, anomaly and threshold-breach events. Three independent, opt-in controls build on the failures you report with `report_failure`:

- **Vault-wide lockout** (`with_failure_threshold(max, window)`): once `max` failures for one key name are reported within `window`, the whole vault refuses `register`, `with_key`, `rotate`, `fragment` and `defragment`.
- **Per-key lockout** (`with_key_lockout(max, window, lock_for)`, 1.1): once `max` failures for one key name are reported within `window`, only that key refuses `with_key` and `rotate`; every other key keeps working. The lockout ends after `lock_for`, or when cleared with `clear_key_lockout` / `clear_lockout` / a successful `unlock_with_master` if `lock_for` is `None`. `unregister` still works on a locked-out key.
- **Master-unlock backoff** (`with_master_unlock_backoff(base, max)`, 1.1): after a failed `unlock_with_master`, further attempts are refused with `Error::RateLimited { retry_after }`, without being checked, for `base`, then `2 * base`, `4 * base`, ... up to `max`. A success resets it. Attempts are serialized, so parallel guesses cannot share one window.

Breach events carry a `LockoutScope` (`Vault` or `Key`). Time comes from the vault's `Clock` (`StdClock` with `std`, your own without).

The master verifier (1.1) is `BLAKE3-keyed(k, master)` with a random 32-byte `k` per builder, held in locked, dump-excluded memory. Before 1.1 it was plain, unsalted BLAKE3 of the master. The verifier is never exposed or persisted, so this changed nothing for callers.

### How it really works

- **Advisory.** The vault never detects failures itself. Only failures the caller passes to `report_failure` (and wrong master credentials) count. The vault never sees what you do with a key, so it cannot know a decryption failed.
- **Off by default.** All three controls are off unless configured, so 1.1 behaves like 1.0 for existing code. The backoff is off because turning it on makes a correct credential wait after a wrong one; switching it on by default is planned for 2.0.
- The vault-wide lockout can be used to deny service by code that reports failures on untrusted input; prefer the per-key lockout for that.
- Master failures count toward the vault-wide threshold, not the per-key one.
- None of this does anything against a memory reader.

Built-in monitors: `NoMonitor` (default), `CompositeMonitor`, `LogMonitor` (`monitor-tracing`).

---

## Layer 9: Audit hooks

Every vault operation (register, unregister, read, rotate, one-shot fragment/defragment, master-unlock attempt) emits an `AuditEvent` to the configured `AuditSink` (`NoAudit` by default). Events carry the key name, never key bytes. Timestamps come from the vault's `Clock`; `thread_id` exists only with `std`.

- Events are emitted after the operation completes. Two operations that run concurrently on different threads may reach the sink in either order.
- An attempt refused by the master backoff is not checked and emits no event.
- The crate does not protect the audit trail from tampering; that is the sink's job.

---

## Layer 10: Page protection

### What it does

With `KeyVaultBuilder::with_page_protection(true)` (1.1), each registered key's fragments and layout are copied into a private mapping of their own (`mmap` / `VirtualAlloc`, at least one page per key), and the heap copies are wiped. The mapping is `PROT_NONE` (`PAGE_NOACCESS` on Windows) except while `with_key` reassembles the key: the first reader makes it read-only, the last reader makes it inaccessible again. The normalization key and the master verifier are held the same way. One-shot `fragment()` output is not protected, because it is handed to the caller.

Heap pages cannot be made inaccessible (other objects share them), which is why protected keys get dedicated mappings rather than going through the shared page table. Each mapping is locked and excluded from dumps as a whole.

### Cost

Two protection changes per `with_key` call plus a small mutex: about 1.4-1.6 µs per call on Linux against about 40 ns without (see [docs/PERFORMANCE.md](PERFORMANCE.md#opt-in-layers-11)), and one page per key (4 KiB, 16 KiB on Apple Silicon). Many threads reading the same key share one open window, but they contend on its mutex.

### Protects against

- Reads of key memory from inside the process while no thread is reading that key: a buffer over-read elsewhere in the program, a scan of readable memory, a stray pointer. They fault instead of finding the key.

### Does not protect against

- Readers that go through the kernel or a debugger (`ptrace`, `/proc/<pid>/mem`, `ReadProcessMemory`): they bypass user page permissions or can change them.
- Code in the process that calls `mprotect` / `VirtualProtect` itself, or calls `with_key`.
- The plaintext in the scratch buffer while your callback runs, and copies the callback makes.

### Windows: page protection and locking

Windows drops a `VirtualLock` when pages become `PAGE_NOACCESS` (`VirtualUnlock` afterwards fails with `ERROR_NOT_LOCKED`), so on Windows a protected key's pages can be written to the page file while they are inaccessible. Unprotected keys on Windows stay locked as before. If you enable page protection on Windows, keep the page file encrypted (BitLocker on the system drive, or `fsutil behavior set EncryptPagingFile 1`). On Linux and macOS the lock is kept while the pages are inaccessible.

---

## `no_std`

Without the `std` feature the crate is `#![no_std]` with `alloc`. The vault works the same with these differences:

- **Clock.** The vault is built with `build_with_clock` and your `Clock`. `build` does not exist without `std`, so a missing clock is a compile error, not a lockout that never expires.
- **Randomness.** `getrandom` is used wherever it has a backend. On targets without one (bare metal), the application registers its RNG with `key_vault::register_rng!`; without it, linking fails with an undefined `__getrandom_custom`.
- **Locks.** Spin locks replace `std::sync`; the registry is a `BTreeMap` behind a short lock instead of `arc-swap`; the `with_key` scratch buffer is allocated per call.
- **Memory.** On bare metal there is no swap and no core dump, so page locking and dump exclusion do not apply, and page protection is not available (the builder method does not exist there). On a hosted Unix or Windows target they keep working without `std`.
- **Needs `std`:** the fetchers, `monitor-tracing`, TEE detection, and `AuditEvent::thread_id`.

---

## Concurrency

Reads load a registry snapshot (lock-free `ArcSwap` with `std`). Writes are serialized by a writer mutex; each writer re-checks its precondition under the lock, so two concurrent `register` calls with the same name cannot both succeed, and `rotate` cannot return `Ok` for a key that a concurrent `unregister` removed.

---

## Planned for 2.0

These are breaking behavior changes and wait for a major version:

- Keyed normalization by default (changes every effective key).
- Master-unlock backoff on by default (a correct credential would have to wait after a wrong one).

---

## Verification

| Claim | Verification | Location |
|-------|--------------|----------|
| Fragment round-trip is identity | `proptest` sweeps over all strategies | `tests/proptest_invariants.rs` |
| Every built-in fragmenter works in the vault (1.1) | register / read / rotate with interleaved, random and layered + codex | `src/vault/mod.rs` unit tests |
| Codex involution holds for every byte | `proptest` full byte-range sweep | `tests/proptest_invariants.rs` |
| `SelfReferenceDecoy` only emits key bytes | `proptest` + fuzz target | `tests/proptest_invariants.rs`, `fuzz/` |
| `KeyHandle::Debug` never reveals the id | `proptest` + unit sweep | `tests/proptest_invariants.rs`, `src/handle.rs` |
| No torn reads across rotation | 4-thread reader loop vs. rotations | `tests/proptest_invariants.rs`, `tests/registry_concurrent.rs` |
| `mlock` pins pages on Linux | `VmLck` delta after registrations | `tests/mlock_verified.rs` |
| A page stays locked while any buffer on it is alive | Two regions on one page; two keys sharing a page | `src/memory/mod.rs`, `src/vault/mod.rs` unit tests |
| Pool pages are locked and excluded; freed blocks are zeroed (1.1) | `lo` and `dd` in `VmFlags`; freed block inspected | `src/memory/pool.rs`, `src/memory/mod.rs` unit tests |
| Key pages are excluded from core dumps on Linux (1.1) | `dd` in the mapping's `VmFlags` in `/proc/self/smaps` while a key buffer lives on the page, gone after | `src/memory/mod.rs` unit test |
| Protected regions are excluded from dumps (1.1) | `dd` flag on Linux; `WerRegisterExcludedMemoryBlock` succeeds on Windows | `src/vault/mod.rs` unit test |
| Protected key pages are inaccessible between reads (1.1) | `---p` in `/proc/self/maps` / `PAGE_NOACCESS` from `VirtualQuery`, readable only while a reader holds the region open | `src/vault/mod.rs` unit tests |
| Touching a protected key faults (1.1) | A child process reads the mapping directly and dies with `SIGSEGV` / `SIGBUS` / `STATUS_ACCESS_VIOLATION` | `src/vault/mod.rs` unit test |
| Protected regions stay locked on Linux; Windows drops the lock (1.1) | `Locked:` in `/proc/self/smaps`; `VirtualUnlock` returns `ERROR_NOT_LOCKED` | `src/memory/guarded.rs` unit tests |
| Per-key lockout triggers, stays per key, resets and expires (1.1) | Thresholds, windows, `clear_key_lockout`, `clear_lockout`, master unlock, expiry with a test clock | `src/vault/mod.rs` unit tests |
| Master backoff timing (1.1) | Delays 1, 2, 4, 5, 5 s with a test clock; real-time check with `StdClock` | `src/vault/mod.rs` unit tests |
| Keyed normalization differs from plain BLAKE3 (1.1) | Compared against `blake3::hash` / `keyed_hash` / `derive_key`; two random-key vaults differ; same caller key gives same output | `src/normalize.rs`, `src/vault/mod.rs` unit tests |
| Master verifier is keyed (1.1) | Stored digest compared against `blake3::hash` and `keyed_hash` | `src/vault/mod.rs` unit test |
| `KeychainFetch` uses the OS store (1.1) | The `keyring` entry is not the mock credential | `src/fetcher/keychain.rs` unit test |
| `FileFetch` owner and directory checks (1.1) | Group/other-writable directory, sticky directory, symlink in an open directory, owner rule, path swapped after open | `src/fetcher/file.rs` unit tests (Unix) |
| `no_std` build (1.1) | Library built for `thumbv7em-none-eabihf`; vault run without `std` on the host | CI `no_std` job, `tests/no_std_vault.rs` |
| `RawKey` wipes its spare capacity | Truncated buffer inspected after `wipe` | `src/fetcher/mod.rs` unit test |
| Scratch buffer zeroed on error / panic | Buffer inspected after forced defragment error, codex panic, callback panic | `src/vault/mod.rs` unit tests |
| One winner per name under concurrent `register` | 8 threads x 200 rounds on the same name | `tests/registry_races.rs` |
| `rotate` fails cleanly against concurrent `unregister` | `rotate` parked between pre-check and update while `unregister` runs; stress loop | `src/vault/mod.rs` unit tests |
| No panics on arbitrary input | `cargo-fuzz` targets | `fuzz/fuzz_targets/*.rs` |
| Zero-allocation hot path | `dhat` over 100,000 `with_key` calls | `examples/dhat_hot_path.rs` |

### Not verified by automation

- That zeroized memory stays zero after it is freed (would require reading freed memory).
- Constant-time behavior of `with_key` (it is not constant-time; see Layer 6).
- That page locks hold under memory pressure on every platform. The refcount table is tested; the OS lock itself is checked only on Linux.
- That a real crash dump omits the excluded pages. The kernel flag (Linux) and the WER registration (Windows) are checked; producing and parsing a dump is not.
- Dump exclusion and page protection on macOS, FreeBSD and DragonFly beyond compiling and the fault test (macOS CI).
- Cold-boot and DMA resistance (out of scope).

---

<sub>key-vault Security Architecture - Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
