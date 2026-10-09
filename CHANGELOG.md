# Changelog

All notable changes to `key-vault` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

### Changed

### Fixed

### Security

---

## [1.1.0] - 2026-10-09

Minor release: new API, no breaking changes. Everything new is opt-in
except dump exclusion, the keyed master verifier, the `KeychainFetch`
and `FileFetch` fixes, and the `LayeredFragmenter` speed-up.
`cargo semver-checks` against 1.0.2 finds no breaking change (default
and all features).

### Security

- **Key memory is kept out of crash and core dumps.** Every page that
  holds key material (fragments, layout maps, codex tables, the
  `with_key` scratch buffer, and the new normalization key and master
  verifier) is excluded through the same per-page reference count that
  handles page locking: `madvise(MADV_DONTDUMP)` on Linux and Android,
  `madvise(MADV_NOCORE)` on FreeBSD and DragonFly, and
  `WerRegisterExcludedMemoryBlock` on Windows 10 1709 and later (looked
  up at run time; WER caps it at 512 blocks per process). The flag is
  removed when the last buffer on a page is dropped. macOS has no
  per-page exclusion, and dumps taken by a debugger or another tool
  (gcore, procdump, Task Manager) are not affected. A test checks the
  `dd` flag in `/proc/self/smaps` on Linux.
- **Small key buffers come from a dedicated page pool.** Buffers of up
  to 2048 bytes (fragments, layout maps, codex tables, the normalization
  key, the master verifier) are carved from pages the crate maps for
  itself, locked and excluded from dumps once, holding only key
  buffers, and kept for the life of the process; freed blocks are zeroed
  and reused. Before, each one sat on a general heap page shared with
  unrelated objects, and every register / rotate / unregister locked and
  released heap pages one system call at a time. Larger buffers keep
  the per-page reference count from 1.0.2.
- **Page protection (Layer 10) is implemented**, opt-in with
  `KeyVaultBuilder::with_page_protection(true)`. Heap pages are shared
  with unrelated objects and cannot be made inaccessible, so each
  registered key gets a private mapping of its own (at least one page)
  that is `PROT_NONE` / `PAGE_NOACCESS` except while `with_key` reads
  it. Concurrent readers share one open window. The mapping is locked
  and excluded from dumps, and zeroed before it is unmapped. It costs
  about 1.5 µs per `with_key` on Linux. Windows drops a `VirtualLock`
  when pages become `PAGE_NOACCESS`, so on Windows protected keys can
  be paged out while inaccessible; the docs say to keep the page file
  encrypted if you turn this on there. Tests check the mapping state
  (`/proc/self/maps`, `VirtualQuery`) and that reading a protected key
  in a child process crashes it.
- **Per-key lockout.** `with_key_lockout(max, window, lock_for)` locks
  out only the key whose name crossed the threshold; every other key
  keeps working. Before, the only lockout was vault-wide, so failures
  reported for one key name locked out every key. New
  `KeyVault::is_key_locked_out` and `KeyVault::clear_key_lockout`;
  `clear_lockout` and a successful `unlock_with_master` clear per-key
  lockouts too. Off by default.
- **Master-unlock backoff.** `with_master_unlock_backoff(base, max)`
  refuses `unlock_with_master` attempts, without checking them, for
  `base`, `2 * base`, ... up to `max` after each failure, with the new
  `Error::RateLimited { retry_after }`. Attempts are serialized. Off by
  default, because it makes a correct credential wait after a wrong one.
- **The master verifier is keyed.** It was plain, unsalted
  `BLAKE3(master)`; it is now `BLAKE3-keyed(k, master)` with a random
  32-byte `k` per builder, kept in locked, dump-excluded memory, so a
  copy of the digest alone cannot be used to guess the master offline.
  The verifier is never exposed or persisted, so nothing changes for
  callers.
- **Keyed normalization (opt-in).** `with_keyed_normalization()` (random
  key per vault; effective keys change every run) and
  `with_normalization_key(key)` (stable with the same key) store
  `BLAKE3-keyed(k, key)` instead of `BLAKE3(key)`. Plain BLAKE3 stays
  the default: the normalized value is the effective key `with_key`
  returns, and callers persist data under it, so changing the default
  would change every key. That change is planned for 2.0.
- **`KeychainFetch` never reached the OS keychain.** The crate depended
  on `keyring` 3 without any store feature, and `keyring` then uses its
  in-memory mock store on every platform, so every fetch failed with
  "no such entry". `fetcher-keychain` now enables the native stores:
  Keychain Services, Windows Credential Manager, and the Secret Service
  over D-Bus on Linux and the BSDs (pure Rust, no `libdbus`). A test
  checks the entry is not the mock credential.
- **`FileFetch` checks the owner and the directories (Unix).** The file
  must be owned by the process's effective user or root, and every
  directory on the resolved path, plus the directory holding the path
  as given (where a symlink would live), must be owned by that user or
  root and not be writable by group or others unless sticky. The
  resolved path must still lead to the opened file, so a swap after
  `open` is reported. `skip_directory_check()` keeps the mode and owner
  checks only. This rejects files that 1.0.x accepted when they sit in
  a directory others can write.

### Added

- **`no_std` + `alloc` support**
  ([#3](https://github.com/jamesgober/key-vault/issues/3)). With
  `default-features = false` the crate is `#![no_std]`. The vault is
  built with `KeyVaultBuilder::build_with_clock` and a caller-supplied
  `Clock` (`build` does not exist without `std`, so forgetting the clock
  is a compile error). Randomness comes from `getrandom`; on targets it
  has no backend for, register an RNG with `key_vault::register_rng!`,
  or linking fails. Spin locks replace `std::sync`, the registry is a
  `BTreeMap`, and the `with_key` scratch buffer is allocated per call.
  Fetchers, `monitor-tracing`, the `tee` module and
  `AuditEvent::thread_id` need `std`. On hosted Unix and Windows targets
  page locking, dump exclusion and page protection work without `std`.
  A new CI job builds the library for `thumbv7em-none-eabihf` and runs
  `tests/no_std_vault.rs` against the `no_std` build.
- `Clock` trait and `StdClock`; `KeyVaultBuilder::build_with_clock`.
  Lockout windows, per-key lockout expiry, backoff, and metadata and
  audit timestamps come from the vault's clock.
- `KeyVaultBuilder::with_fragmenter` selects any `FragmentStrategy` for
  the vault (it always used `StandardFragmenter`). The default is
  dispatched statically, so the hot path does not pay for the choice.
- `KeyVaultBuilder::from_features()` configures a builder from the Cargo
  features (see Changed).
- For custom strategies: `RawKey::expose_secret`,
  `Fragments::from_chunks`, `Fragments::chunk`,
  `Fragments::layout_bytes` and `Fragments::total_len`. External crates
  could not implement `FragmentStrategy` before.
- `KeychainFetch::binary()` reads binary secrets with `get_secret`.
- `FileFetch::skip_directory_check()`.
- `VaultConfig` fields: `keyed_normalization`, `key_lockout_threshold`,
  `key_lockout_window`, `key_lockout_duration`, `master_backoff_base`,
  `master_backoff_max`, `page_protection`.
- `LockoutScope` and `ThresholdContext::scope`: breach events say
  whether the vault-wide or the per-key threshold fired. `LogMonitor`
  logs it.
- `Error::RateLimited { retry_after }`.
- `KeyId` implements `PartialOrd` and `Ord`.

### Changed

- **The 20 reserved Cargo features have meaning or are deprecated.**
  They never change what `KeyVaultBuilder::new()` builds, so existing
  vaults behave the same. `fragment-*`, `decoy-*`, `codex`,
  `codex-dynamic`, `monitor`, `audit` and the presets choose what
  `KeyVaultBuilder::from_features()` sets up: the fragmenter (layered,
  then random, then interleaved, then standard), the decoy on the
  standard fragmenter (the strongest enabled: self-reference, then
  key-derived, then random), a `DynamicCodex`, and with
  `monitor-tracing` the `LogMonitor` / `LogAudit`. With the default
  features that is the standard fragmenter with self-reference decoys,
  which is what the 1.0 docs described. `mlock`, `zeroize`, `tee-detect`
  and `post-quantum` are deprecated no-ops: page locking and
  zeroization cannot be turned off, TEE detection is always compiled
  with `std`, and `post-quantum` was informational.
- The `fetcher-*` features and `monitor-tracing` imply `std`.
- `LayeredFragmenter::defragment` no longer copies every chunk into a
  new locked buffer (one `mlock` each) on every call; it hands the
  sub-strategy a view of the same chunks, and it now implements the
  allocation-free `defragment_into`.
- `KeyVault`'s `Debug` output shows the fragmenter and whether a decoy
  was ignored because a non-standard fragmenter is in use.
- `blake3`, `subtle` and `libc` are used without default features, and
  `arc-swap` only with `std`; `std` turns their `std` features back on.
  `getrandom` enables its `custom` feature, which only takes effect on
  targets without a `getrandom` backend.
- The `TpmFetch` error message no longer calls itself "detection-only".

### Fixed

- `LayeredFragmenter` module docs claimed `log2(N)` bits of extra
  uncertainty; the strategy index is stored in the clear in the layout.
- `KeyId` docs said the counter saturates; it is a 64-bit counter that
  cannot realistically wrap.

---

## [1.0.2] - 2026-10-08

No public API changes. `cargo semver-checks` against 1.0.1 reports no
semver update required.

### Security

- **The documentation overstated what the crate protects against.**
  README, `docs/SECURITY.md`, `docs/API.md`, `docs/TRANSFORMATION.md`
  and the crate docs described fragmentation, decoys and the codex as
  protection against process memory scrapers. They are obfuscation: the
  layout buffer that reassembles the fragments (and marks every decoy
  chunk) and the codex table are stored in the same process memory, so
  anyone who can read that memory can rebuild every key. The docs now
  have a threat model that says this, and each layer states what it
  does and does not protect against.
- **Layer 10 (page protection toggling) was documented but never
  implemented.** There is no `mprotect` / `VirtualProtect` call in the
  crate. It is now marked as not implemented everywhere it appeared.
- **Page locks were released while other keys still used the page.**
  `mlock` / `VirtualLock` work on whole pages and do not nest, and
  fragments of different keys routinely share a page. Dropping any
  fragment (on `rotate`, `unregister`, a one-shot `defragment`, or a
  dropped codex) unlocked its whole page range, so pages backing other
  live keys silently lost their lock. A process-wide per-page reference
  count now locks a page when its first buffer arrives and unlocks it
  only when its last buffer is dropped. On Linux, registering 200 pairs
  of keys and unregistering one key of each pair took `VmLck` from
  276 kB to 0 kB in 1.0.1; it now stays unchanged. New tests check the
  count directly and check `VmLck` on Linux.
- **The `with_key` scratch buffer is now page-locked** through the same
  reference-counted table, so the plaintext copy that exists while the
  callback runs is not paged out.
- **More key-derived buffers are wiped.** The `zeroize` crate is now a
  required dependency and is used for:
  - `RawKey`: the whole allocation, including spare capacity beyond the
    length. Before, only `0..len` was cleared, so bytes left after a
    `truncate` survived.
  - BLAKE3 normalization and the master-key digest: the hasher state
    and output reader are zeroized (blake3's `zeroize` feature), and the
    digest is written straight into a zeroizing buffer instead of
    passing through a `blake3::Hash` copy.
  - The master-key digest held by `KeyVaultBuilder` and `KeyVault`
    (and every clone of the builder) is zeroized on drop. Before, it was
    a plain `[u8; 32]`.
  - `KeyDerivedDecoy` hasher state and output reader; the
    `SelfReferenceDecoy` output buffer on early return; decoy output in
    `StandardFragmenter` over its full capacity.
  - Fragmenter temporaries (layout encodings, position lists, the
    interleaved pool, random-fragment chunk buffers) on every exit
    path, not only on success.
  - `StaticCodex` / `DynamicCodex` construction tables on the stack.
  - `FileFetch` read buffers on error and whenever they grow (the old
    `std::fs::read` freed reallocated buffers unwiped), the rejected
    value in `EnvFetch`'s non-UTF-8 error path, and the secret bytes
    carried by `keyring`'s `BadEncoding` error in `KeychainFetch`.

  Copies made inside `std`, the OS, `keyring` or the caller's own
  `with_key` callback are outside the crate's control; the docs now say
  so.

### Fixed

- **`register` could insert the same name twice.** The duplicate check
  ran on one snapshot of the registry and the insert on a later one,
  so concurrent registrations of the same name could all succeed.
  Registry writers (`register`, `unregister`, `rotate`) are now
  serialized by a writer lock and re-check under it. A new test runs 8
  threads x 200 rounds on the same name; against 1.0.1 every round
  registered the name 8 times.
- **`rotate` could return `Ok` for a key that was unregistered at the
  same moment.** Its `found` flag was set inside the `ArcSwap::rcu`
  closure and never reset between retries, so if a concurrent
  `unregister` won, `rotate` reported success and emitted a Rotate
  audit event although the new key was never stored. It now returns
  `Error::KeyNotFound` in that case. A new test parks `rotate` between
  its existence check and its update while `unregister` runs; against
  1.0.1 it returned `Ok` in 10 of 10 rounds.
- **`FileFetch` checked one file and could read another.** It called
  `metadata(path)` for the permission check and then `read(path)`, so
  the path could be swapped (for example via a symlink) in between. It
  now opens the file once and reads the mode from the open handle.
- **`register` and `rotate` emitted an extra unnamed `OneShotFragment`
  audit event.** They now emit only `Register` / `Rotate`.
- **`TpmFetch`'s error message** told callers to use
  `detect_tee_capabilities()` to probe for a TPM, which it cannot do.
  The message now says TPM acquisition is not implemented.
- `rustfmt` 1.99 formatting: lowercase hex literals in
  `src/tee/x86_64.rs` and `tests/proptest_invariants.rs`.

### Changed

- **Documentation of Cargo features.** Only `std`, the four
  `fetcher-*` features and `monitor-tracing` change what is compiled
  (`default` and `fetcher-all` just enable others). The other 20 gate no
  code: `mlock`, `zeroize`, `codex`, `codex-dynamic`, all `decoy-*`, all
  `fragment-*`, `monitor`, `audit`, `tee-detect`, `post-quantum` and all
  `preset-*`. They are now documented as reserved with no effect in
  1.0.x (in `Cargo.toml`, `docs/API.md`, `docs/STABILITY-1.0.md` and the
  crate docs). They are kept because removing a feature is a breaking
  change. `preset-fast` does not turn off page locking and
  `preset-paranoid` does not turn on decoys or a codex.
- **`zeroize` is no longer an optional dependency**, and `blake3` is
  now required at `>= 1.5` with its `zeroize` feature. The `zeroize`
  Cargo feature still exists and has no effect.
- **`FileFetch` is documented as reading plaintext.** Cargo.toml and
  `docs/SECURITY.md` called it "encrypted file storage"; it has never
  decrypted anything.
- **`TpmFetch` is documented as not implemented** instead of
  "detection-only" or "highest security (hardware-backed)". It always
  returns an error, and nothing in the crate detects a TPM.
- **Lockout is documented as advisory and vault-wide.** The vault only
  counts failures the caller passes to `report_failure` (and wrong
  master credentials); one key name crossing the threshold locks out
  every key. Behavior is unchanged; per-key lockout is planned for 1.1.
- **`unlock_with_master` is documented as having no rate limit**, and
  normalization and the master digest as unsalted, fast BLAKE3 that
  allows offline guessing of low-entropy inputs.
- Other doc corrections: constant-time claims limited to the master
  digest check and handle equality; TEE detection documented as
  heuristic and informational; `EnvFetch` documented as leaving the
  value in the environment; `KeychainFetch` documented as UTF-8 only;
  stale "Phase 0.x" status text removed from the crate docs; the
  crates.io description no longer claims TPM support or "9-layer"
  defense.

---

## [1.0.1] - 2026-10-08

### Fixed

- **Plaintext could remain in the `with_key` scratch buffer if
  decoding failed or panicked.** `KeyVault::with_key` rebuilds the key
  in a thread-local scratch buffer, but the guard that zeroes that
  buffer was created only after defragmentation and the codex decode.
  If `defragment_into` returned an error after a partial write, or a
  `Codex::decode` implementation panicked, the bytes already written
  stayed in the buffer. The guard now covers the buffer from before the
  first write, so it is zeroed on success, on error and on unwind. New
  unit tests check the buffer is all zeros after a defragment error, a
  panicking codex and a panicking callback.
- **Same gap in the one-shot paths.** `StandardFragmenter`,
  `InterleavedFragmenter` and `RandomFragmenter::defragment` built
  their output in a plain `Vec<u8>` and wrapped it in a `RawKey` only on
  success, so a partial result was freed without being zeroed on error.
  The internal codex pass used by `KeyVault::fragment` and
  `KeyVault::defragment` had the same problem if a codex panicked. Both
  now write into a `RawKey` from the start, whose drop zeroes the
  buffer.

### Changed

- **The `std` feature is now explicitly required**
  ([#3](https://github.com/jamesgober/key-vault/issues/3)). The crate
  declared `#![cfg_attr(not(feature = "std"), no_std)]`, but it uses
  `std` types throughout and a build without `std` has never compiled.
  That attribute is removed, and building without the `std` feature
  now stops with a clear `compile_error!` instead of a list of
  unresolved `std` paths. The `std` feature itself is kept (and stays
  on by default), so existing feature lists keep working. Docs that
  mentioned future `no_std` builds now say that `std` is required.
  `no_std` support is not part of this release.

### Removed

- **Unused `rand_core = "0.6"` dependency.** Nothing in the crate used
  it under any feature; randomness comes from `getrandom`.

---

## [1.0.0] - 2026-05-21

### Added

- **`FragmentStrategy::defragment_into(&mut [u8])`** — new trait
  method that writes recovered bytes directly into a caller-supplied
  scratch buffer. Backward-compatible default implementation
  forwards to `defragment()` + copy; the three in-tree strategies
  (`StandardFragmenter`, `InterleavedFragmenter`, `RandomFragmenter`)
  override it for the zero-allocation hot path. Existing out-of-tree
  `FragmentStrategy` implementations compile unchanged.
- **`docs/STABILITY-1.0.md`** — the 1.0 stability contract: every
  frozen item, every behavioural contract, the MSRV policy, the
  migration plan for `1.x` and `2.x`.
- **`docs/ARCHITECTURE.md`** — internal module layout, data flows for
  the three hot paths (`register`, `with_key`, `rotate`), strategy
  trait extension points, dependency rationale.
- **`docs/PLATFORM-NOTES.md`** — Linux / macOS / Windows specifics,
  per-platform mlock behaviour, fetcher availability matrix, TEE
  detection per architecture, CI matrix, cross-compilation notes.
- **`docs/HARDWARE.md`** — TPM / HSM / TEE integration status at 1.0
  (detection only) and the post-1.0 hardware roadmap.
- **`rust-toolchain.toml`** — pins the toolchain channel to `1.85.0`
  at the crate root so fresh clones build against the MSRV without
  manual setup. REPS §Reproducibility requires this.
- **`deny.toml`** — `cargo deny` policy: permissive licenses only,
  official crates.io registry only, no git deps, advisories deny on
  detected.
- **CI supply-chain job** — `cargo audit` (RustSec advisory database)
  + `cargo deny check` on every push. REPS §Dependency Management
  requires both.

### Changed

- **Zero-allocation hot path.** `KeyVault::with_key` now performs
  zero heap allocations under the default `NoAudit` sink (dhat-
  measured over 100,000 iterations). Implementation: thread-local
  scratch buffer + the new `defragment_into` trait method + in-place
  codex decode + panic-safe volatile-zero guard. Wall-clock impact
  on `with_key/no_codex/32 B`: 102 ns (0.11) → 39 ns (1.0); -78%
  cumulative from 0.10.0.
- **`StandardFragmenter::defragment_into`** uses a single-pass write
  to chunk offsets — no intermediate `Vec<(offset, chunk)>` for
  sorting. The semantics are unchanged; only the algorithm allocates
  less.
- **Lint set** in `src/lib.rs` extended with
  `#![deny(clippy::unreachable)]` to match the REPS canonical block.
  Documented why `#![deny(warnings)]` is enforced at CI (via
  `RUSTFLAGS`) rather than at the crate root.
- **REPS-forbidden doc terms** replaced: "comprehensive" in
  `docs/SECURITY.md` and `docs/API.md`, "placeholder" in
  `src/handle.rs`.

### Security

- No security-surface changes — this is the stable 1.0 cut. All 9
  defense layers and the 1.0 verification matrix carry forward from
  0.11.0 unchanged.

### Stability

- **The 1.0 API contract** in `docs/STABILITY-1.0.md` takes effect at
  this tag. Breaking any item listed there requires a `2.0` release
  with a documented migration guide.

---

## [0.11.0] - 2026-05-21

### Added

- **`fuzz/` workspace** — seven `cargo-fuzz` targets covering each
  fragment strategy (`fuzz_fragment_{standard,interleaved,random,layered}`),
  every decoy strategy (`fuzz_decoy_strategies`), every codex
  (`fuzz_codex_involution`), and the full vault op sequence
  (`fuzz_vault_end_to_end` via `arbitrary`). Linux/macOS only; the
  roadmap requires 1 CPU-hour per target for the 1.0 sign-off.
- **`tests/proptest_invariants.rs`** — 12 cross-platform property
  tests for round-trip identity, codex involution,
  `SelfReferenceDecoy` only-uses-key-bytes, `KeyHandle::Debug`
  opacity, registered-handle uniqueness, and concurrent-read
  consistency across rotation.
- **`tests/mlock_verified.rs`** — Linux-only `/proc/self/status`
  `VmLck`-delta verification that Layer 2 actually pins fragment
  pages.
- **`examples/dhat_hot_path.rs`** — `dhat::Alloc` global-allocator
  example that profiles `with_key` × 100,000 iterations and writes
  `dhat-heap.json`.
- **`AuditSink::is_no_op()`** — optional fast-path predicate
  (default `false`) so sinks can opt out of event construction.
  `NoAudit` overrides it to `true`.
- **`docs/SECURITY.md` §Verification methodology** — runnable
  verification table mapping every 1.0 security claim to the
  test / fuzz target / example that proves it.

### Changed

- **`with_key` hot-path optimization.** When the configured audit
  sink reports `is_no_op() == true` (the default `NoAudit` case),
  the vault now skips `AuditEvent` construction entirely. Measured
  impact on `with_key/no_codex/32 B`: ~175 ns → ~102 ns (-42%).
  Full numbers in `docs/PERFORMANCE.md`.
- **Allocation profile** — dhat-measured ~4 allocations per
  `with_key` in 0.10.0; ~2 per call in 0.11.0 under `NoAudit`.
- README + `docs/PERFORMANCE.md` + `docs/API.md` updated with
  post-optimization numbers and the "what's not yet in 0.11.0"
  list trimmed.

### Fixed

- Allocator pressure on the hot path halved without API change.

### Security

- All 1.0 security claims now have a runnable verification
  (proptest / cargo-fuzz / dhat / mlock-status). The two items
  still on the deferred list are `dudect`-asserted constant-time
  for the full `with_key` call (post-1.0) and true
  zero-allocation hot-path (post-1.0).

---

## [0.10.0] - 2026-05-21

### Added

- **Criterion benchmark suite.** Six `[[bench]]` targets under
  `benches/`, all `harness = false`:
  - `access_latency.rs` — `KeyVaultBuilder::build`, `register`,
    `with_key`, `rotate`, one-shot `fragment` / `defragment` across
    16/32/64/256-byte keys.
  - `concurrent_access.rs` — `with_key` throughput at 1 / 4 / 16 / 64
    threads, plus a 4-reader / 1-rotator contention bench.
  - `fragment_strategies.rs` — `StandardFragmenter` vs.
    `InterleavedFragmenter` vs. `RandomFragmenter` vs.
    `LayeredFragmenter` through the `FragmentStrategy` trait.
  - `decoy_strategies.rs` — `RandomDecoy` vs. `SelfReferenceDecoy`
    vs. `KeyDerivedDecoy` through the full vault stack.
  - `codex_overhead.rs` — `IdentityCodex` /
    `StaticCodex::random_involution` / `DynamicCodex` plus a no-codex
    baseline.
  - `memory_overhead.rs` — 100-key registration timing + Linux
    1000-key RSS-delta probe.
- **`docs/PERFORMANCE.md`** — methodology, reference-machine results,
  tuning guide, and documented intentional costs.

### Changed

- `StandardFragmenter` no longer `#[derive(Default)]`. Added an
  explicit `impl Default for StandardFragmenter` that forwards to
  `StandardFragmenter::new()` (default chunk range `1..=8`). Fixes a
  latent panic where `StandardFragmenter::default()` would produce
  `min_chunk = 0, max_chunk = 0` and panic on the first `fragment`
  call with `Error::Fragment("invalid chunk-size range")`.
- Removed placeholder `benches/vault_bench.rs`; replaced by the six
  bench files above.

### Fixed

- `StandardFragmenter::default()` panicking on first use (see
  Changed). Behaviour now matches the documented `new()` constructor.

### Security

- No security-surface changes in 0.10.0; all 9 defense layers carry
  forward from 0.9.1 unchanged.

---

## [0.9.1] - 2026-05-21

### Added

- **Layer 9 — Audit trail.** Closes the gap left open in 0.9.0
  (which had listed Layer 9 as "partial — per-access audit hook
  deferred"). New module `key_vault::audit`:
  - `AuditEvent { timestamp, key_name, kind, thread_id, note }` —
    `#[non_exhaustive]`, carries only non-secret fields.
  - `AccessKind` enum covering `Register`, `Unregister`, `Read`,
    `Rotate`, `OneShotFragment`, `OneShotDefragment`, and
    `MasterUnlockAttempt { matched: bool }` — `#[non_exhaustive]`.
  - `AuditSink` trait — `Send + Sync`, contract is non-blocking,
    no panics, no back-pressure into the vault.
  - Blanket impl `AuditSink for Arc<dyn AuditSink>` so callers can
    pre-wrap a sink and pass it through the builder.
  - `NoAudit` — default no-op sink.
  - `LogAudit` — `tracing`-backed sink emitting `info!` events at
    `key_vault::audit` (feature `monitor-tracing`).
- **`KeyVaultBuilder::with_audit_sink`** — install a sink at build
  time. Defaults to `NoAudit`.
- **Per-operation emission.** `KeyVault::register`, `unregister`,
  `with_key`, `rotate`, `fragment`, `defragment`, and
  `unlock_with_master` all emit an `AuditEvent` before returning.

### Changed

- `.gitignore` restructured into clear sections (Rust artifacts,
  editor / OS junk, secrets) with no behavior change.
- README status table now reads "Status as of 0.9.1"; the Layer 9
  row is marked **shipped (0.9.1)**.
- `docs/API.md` documents the new audit module with examples.

### Security

- The audit trail carries **only the key name**, never key bytes.
- The reserved name `"<master>"` is used for master-unlock attempts;
  `MasterUnlockAttempt.matched` reports the constant-time
  comparison result.
- Sink contract explicitly forbids back-pressure into the vault.

---

## [0.9.0] - 2026-05-20

### Added

- **Named-key registry.** The vault now stores keys by name and hands
  back opaque `KeyHandle`s. New API:
  - `KeyVault::register(name, RawKey) -> Result<KeyHandle>` —
    duplicate names rejected with `Error::InvalidConfig`.
  - `KeyVault::unregister(handle) -> Result<()>`.
  - `KeyVault::with_key(handle, |bytes| { ... }) -> Result<T>` —
    scoped access. The byte slice handed to the closure is valid only
    for the call; the temporary `RawKey` zeroes its buffer when the
    closure returns.
  - `KeyVault::rotate(handle, new_key) -> Result<()>` — atomic swap
    via `ArcSwap::rcu`. Concurrent `with_key` readers see either the
    old or the new fragmentation, never a torn read.
  - `KeyVault::contains(handle) -> bool`,
    `KeyVault::metadata(handle) -> Option<KeyMetadata>`,
    `KeyVault::handle_for_name(name) -> Option<KeyHandle>`,
    `KeyVault::key_count() -> usize`.
- **Master-key emergency unlock.**
  `KeyVaultBuilder::with_master_key(RawKey)` stores the BLAKE3 digest
  of the supplied bytes (plaintext drops + zeroes immediately).
  `KeyVault::unlock_with_master(&[u8])` verifies the digest in
  constant time via `subtle::ConstantTimeEq` and clears the lockout
  flag on success. Mismatched attempts feed the failure tracker
  under the reserved name `"<master>"`.
- **`KeyVault::has_master_key()`** — `true` if a master credential
  was registered at build time.
- **`RawKey: Drop`** — volatile-zeroes the internal `Vec<u8>` before
  freeing. Any temporary `RawKey` (including the buffers handed back
  from `KeyVault::defragment` and the bytes flowing through
  `with_key`) now scrubs its allocation on drop.
- New integration test suite [`tests/registry_concurrent.rs`](../../tests/registry_concurrent.rs)
  exercising concurrent `with_key` + `rotate` (4 reader threads × 200
  reads each interleaved with 20 rotations) and concurrent
  `unregister` / `with_key`.

### Changed

- `KeyVault::fragment` / `defragment` are still available for ad-hoc
  one-shot use; the new registry API is recommended for production
  deployments where keys are long-lived.
- `KeyEntry` (crate-private) wraps `Fragments` in an `Arc` so the
  registry's `HashMap` can be cloned during `ArcSwap::rcu` updates
  without duplicating the actual `LockedBytes` chunks.

### Security

- **Zero-on-drop coverage extended.** `RawKey` now zeroes its buffer
  on drop, closing the previously-acknowledged gap where the
  temporary defragmented buffer in `with_key`-style scoped access
  paths could linger.
- **Master-key digest, not plaintext.** The vault never holds the
  master credential's bytes after registration — only the
  BLAKE3 digest. Comparison uses `subtle::ConstantTimeEq` so timing
  cannot reveal whether an attempt was close.
- **Atomic rotation.** `ArcSwap::rcu` guarantees readers observe
  either the pre-rotation or the post-rotation `Fragments`, never a
  half-updated state.

[0.9.0]: https://github.com/jamesgober/key-vault/compare/v0.8.0...v0.9.0

---

## [0.8.0] - 2026-05-20

### Added

- **Layer 8 — Monitor implementations.** Three new `SecurityMonitor`
  impls covering the common observability surface:
  - `NoMonitor` — the inert default (always available).
  - `CompositeMonitor` — fan-out across `Vec<Arc<dyn SecurityMonitor>>`.
  - `LogMonitor` — emits structured `tracing` events at warn/error
    levels (gated behind the `monitor-tracing` Cargo feature).
- **Threshold-driven lockout.** `VaultConfig` gained
  `max_failures_before_lockout` and `failure_window` fields.
  `KeyVaultBuilder::with_failure_threshold(max, window)` configures
  per-key sliding-window failure tracking. Lockout disabled by default
  (`max = 0`).
- **`KeyVault::report_failure(key_name, note)`** — caller-driven
  failure reporting. Forwards to the configured monitor and feeds the
  threshold detector. When the threshold is crossed, the vault
  transitions to lock-out state and `on_threshold_breach` fires.
- **`KeyVault::report_anomalous_access(key_name, note)`** — caller-
  driven anomaly reporting. Forwards to the configured monitor without
  affecting vault state.
- **`KeyVault::clear_lockout()`** — operator escape hatch. Resets the
  lockout flag and clears the failure tracker.
- **`KeyVaultBuilder::with_monitor(M)`** — attach a `SecurityMonitor`
  implementation. Replaces any previously-configured monitor.
- Blanket `impl SecurityMonitor for Arc<dyn SecurityMonitor>` so
  pre-wrapped monitors can be passed to APIs that accept
  `impl SecurityMonitor`.
- New crate-root re-exports: `NoMonitor`, `CompositeMonitor`,
  `LogMonitor` (latter feature-gated).

### Changed

- `KeyVault::fragment` / `defragment` now return
  `Error::LockedOut` when the vault is in lock-out state. They were
  previously infallible w.r.t. the lockout flag.
- `VaultConfig::Default` is now manually implemented (was derived) to
  account for the new threshold fields.
- `KeyVaultBuilder::Default` is now manually implemented.

### Security

- **Threshold-driven lockout** turns the failure-tracking signal into
  enforcement: a vault that has crossed the threshold refuses to
  fragment or defragment until an operator explicitly calls
  `clear_lockout`. Prevents an attacker who can poke the API into
  burning through brute-force attempts.
- **No secrets in monitor events.** `FailureContext`,
  `AccessContext`, and `ThresholdContext` are sanitized by trait
  contract; `LogMonitor` emits only key names, counters, and the
  caller-supplied note. The note field is `Cow<'static, str>` — caller
  responsibility to keep it sanitized.

[0.8.0]: https://github.com/jamesgober/key-vault/compare/v0.7.0...v0.8.0

---

## [0.7.0] - 2026-05-20

### Added

- **Layer 1 — Built-in `KeyFetch` implementations.** Four fetchers,
  each gated behind its own Cargo feature:
  - `EnvFetch` (`fetcher-env`) — read key bytes from a process
    environment variable. Error messages include the variable name but
    never the value.
  - `FileFetch` (`fetcher-file`) — read key bytes from a file on disk.
    Strict Unix permission checking (`0o600` or tighter) by default;
    relaxable via `FileFetch::allow_loose_perms()`.
  - `KeychainFetch` (`fetcher-keychain`) — read from the OS native
    credential store via the `keyring` crate (macOS Keychain, Windows
    Credential Manager, Linux Secret Service / KWallet). Error messages
    redact `keyring` internals.
  - `TpmFetch` (`fetcher-tpm`) — **detection-only in 1.0**. Returns a
    documented `Error::Acquisition` so consumers can wire it into
    composite fetcher chains and inherit the 1.x upgrade.
- Crate-root re-exports for all four fetchers (feature-gated).
- Documentation: each fetcher's module ships its own threat-profile
  notes.

### Changed

- `clippy.toml` `doc-valid-idents` whitelist extended with `FileVault`,
  `BitLocker`, `KWallet`, `TrustZone`, `IntelSGX`.

### Security

- **No fetcher writes key material to its `Error` variants.** All four
  redact the source value: `EnvFetch` prints the variable name only;
  `FileFetch` prints the path and the I/O error kind only;
  `KeychainFetch` prints the entry locator and a discriminant-only
  rendering of the `keyring` error; `TpmFetch` carries no input at all.
- **`FileFetch` Unix permission gate.** Default rejects files readable
  by group or world. Opting out requires an explicit
  `.allow_loose_perms()` call documented as "not recommended outside
  tests."

[0.7.0]: https://github.com/jamesgober/key-vault/compare/v0.6.0...v0.7.0

---

## [0.6.0] - 2026-05-20

### Added

- **Layer 5 — `StaticCodex`.** 256-byte involution lookup table held in
  a `LockedBytes` buffer (mlock'd + zeroed on drop). Construct via
  `StaticCodex::from_swaps(&[(u8, u8)])` for declarative swap pairs or
  `StaticCodex::random_involution()` for a fresh random permutation with
  no fixed points.
- **Layer 5 — `DynamicCodex`.** Thin wrapper around
  `StaticCodex::random_involution()` for the common "fresh random codex
  per vault" use case.
- **`KeyVaultBuilder::with_codex`.** Attach any `Codex + 'static` to the
  vault; the codex transformation is applied transparently at the
  fragment/defragment boundary (after BLAKE3 normalization, before
  fragmentation; reversed on defragment).
- **Crate-root re-exports.** `StaticCodex`, `DynamicCodex` available
  at `key_vault::StaticCodex` / `key_vault::DynamicCodex`.

### Changed

- `KeyVaultBuilder` is no longer `#[derive(Debug)]` — it now holds an
  `Option<Arc<dyn Codex>>` whose dyn trait is not `Debug`. A manual
  `Debug` impl reports the codex as `Some("<set>")` / `None` without
  inspecting it.
- `crate::fragment::util` helpers (`random_u64`, `sample_range`,
  `fisher_yates`, `zero_buffer`, `zero_buffer_owned`) promoted from
  `pub(super)` to `pub(crate)` so the codex module can reuse the same
  RNG/shuffle plumbing.

### Security

- **Codex table is `LockedBytes`-protected.** The 256-byte lookup table
  in both `StaticCodex` and `DynamicCodex` lives in a `LockedBytes`
  buffer — mlock'd against swap, volatile-zeroed before drop. Knowing
  the table is equivalent to knowing the transformation, so the table
  is treated as key-equivalent material.
- **`random_involution` produces no fixed points.** Every byte
  transforms to a *different* byte (pairs are formed by Fisher-Yates of
  all 256 bytes). An attacker scanning the stored fragments sees no
  byte that maps to itself.
- **Per-call freshness.** Each `DynamicCodex::new()` and each
  `StaticCodex::random_involution()` produces an independent random
  table; CSPRNG entropy comes from `getrandom`.

[0.6.0]: https://github.com/jamesgober/key-vault/compare/v0.5.0...v0.6.0

---

## [0.5.0] - 2026-05-20

### Added

- **`RandomFragmenter`** — Layer-3 strategy that scatters bytes
  **non-contiguously**. Each chunk holds bytes drawn from independently
  chosen random positions of the original key, so no chunk ever contains
  a contiguous run of key bytes longer than 1.
- **`InterleavedFragmenter`** — Layer-3 strategy that places key bytes
  at random positions inside a single large `LockedBytes` pool (default
  4× key length), padding the gaps with CSPRNG bytes. Defeats byte-level
  statistical analysis of the pool.
- **`LayeredFragmenter`** — composition strategy that holds a `Vec<Arc<dyn FragmentStrategy>>`
  and picks one uniformly at random per `fragment` call. The picked
  sub-strategy's index is prepended (4 bytes LE) to the layout buffer so
  `defragment` can dispatch correctly. Routing-based composition avoids
  materializing the key between layers.
- New crate-internal `src/fragment/util.rs` consolidating
  `random_u64`, `sample_range`, `fisher_yates`, `zero_buffer`,
  `zero_buffer_owned` — previously duplicated across fragmenters.
- `Fragments::into_parts()` pub(crate) accessor — destructure the
  inner `(Vec<LockedBytes>, LockedBytes, usize)` for compositional
  strategies without copying chunk buffers.
- `Fragments::chunk_count()` is now `pub` (was `pub(crate)`).
- Integration test suite [`tests/fragment_strategies.rs`](../../tests/fragment_strategies.rs)
  exercising all four strategies through the public `FragmentStrategy`
  trait + `Send + Sync` assertions.

### Changed

- **`docs/SECURITY.md`** strategy-comparison section rewritten with a
  per-strategy storage shape, layout encoding, threat focus, memory
  overhead, and decoy compatibility table.
- `StandardFragmenter` now imports its RNG/shuffle/zero helpers from
  `fragment::util` instead of defining them locally.
- Per-strategy unit tests use the shared helpers transitively (no test
  changes).

### Security

- **Routing-based composition** (`LayeredFragmenter`) adds an additional
  `log2(N)` bits of uncertainty against an attacker who has the chunks
  and the layout buffer but does not know which sub-strategy was used.
- **`RandomFragmenter`** explicitly defeats contiguous-format
  recognition (DER envelopes, PEM markers, ASCII-armored data) by
  ensuring no chunk contains a contiguous run of key bytes longer than 1.

[0.5.0]: https://github.com/jamesgober/key-vault/compare/v0.4.0...v0.5.0

---

## [0.4.0] - 2026-05-20

### Added

- **Layer 4 — Decoy strategies.** Three implementations of the
  `DecoyStrategy` trait shipped:
  - `RandomDecoy` — uniformly random bytes from the OS CSPRNG (fastest,
    weakest).
  - `SelfReferenceDecoy` — bytes sampled independently from the key
    itself, so the decoy's byte distribution exactly matches the key's
    (strongest indistinguishability, recommended default).
  - `KeyDerivedDecoy` — BLAKE3 XOF seeded by the key plus a fresh
    per-call CSPRNG nonce (CSPRNG-like output correlated with the key).
- **`StandardFragmenter::with_decoy`** — attach any
  `DecoyStrategy + 'static` to the fragmenter. When set, every
  `fragment` call also emits decoy chunks; `defragment` recognizes them
  via a `u32::MAX` sentinel in the locked layout buffer and skips them
  during reassembly.
- **`KeyVaultBuilder::with_decoy`** — fluent forwarder that wires the
  decoy strategy into the underlying fragmenter without exposing
  builder internals.
- New crate-root re-exports: `RandomDecoy`, `SelfReferenceDecoy`,
  `KeyDerivedDecoy`.

### Changed

- `StandardFragmenter` is no longer `Copy`; it now holds an
  `Option<Arc<dyn DecoyStrategy>>` so the decoy can outlive the builder.
  `Clone` is preserved (`Arc` clones cheaply).
- `StandardFragmenter`'s `Debug` impl is now manual (it inspects the
  decoy's `describe()` rather than the trait object) — display
  semantics are unchanged.
- The layout buffer encoding gained a sentinel: `u32::MAX` means "this
  chunk is a decoy, skip it during defragment." Real key lengths are
  bounded by `u32::MAX - 1` bytes (~4 GiB), well above any realistic
  key. Internally, `fragment` now returns
  `Error::Fragment("key too large")` if this bound is exceeded.

### Security

- **Statistical indistinguishability.** With `SelfReferenceDecoy` set,
  decoy chunks are byte-for-byte drawn from the same distribution as
  the real key; entropy and chi-squared distinguishers cannot separate
  them.
- **Per-call freshness.** `KeyDerivedDecoy` mixes in a fresh 32-byte
  CSPRNG nonce per generate call so an attacker who later recovers the
  key cannot recompute the decoy stream and confirm a fragmentation.
- **Intermediate plaintext scrubbing.** The temporary `Vec<u8>` used to
  carry decoy bytes from a strategy into the `LockedBytes` it lives in
  is volatile-zeroed before drop.

[0.4.0]: https://github.com/jamesgober/key-vault/compare/v0.3.0...v0.4.0

---

## [0.3.0] - 2026-05-20

### Added

- **Layer 2 — Memory page locking.** New crate-internal `LockedBytes`
  wrapper around `Vec<u8>` that calls `mlock(2)` (Unix) / `VirtualLock`
  (Windows) at construction and `munlock` / `VirtualUnlock` on drop.
  Soft-fails when the OS declines the lock (e.g. `RLIMIT_MEMLOCK`); the
  wrapper records the outcome and continues. Always zeroes its bytes
  before unlocking.
- **Layer 3 — `StandardFragmenter`.** First real `FragmentStrategy`
  implementation: variable-size chunks (configurable range, default 1–8
  bytes), Fisher-Yates permutation, per-chunk independent heap
  allocations (each `LockedBytes`-locked), separate locked layout buffer.
  Round-trip verified by 1000-iteration stress test.
- **Layer 6 — `ConstantTimeEq` for `KeyHandle`.** Public equality on
  handles now goes through `subtle::ConstantTimeEq`. `PartialEq` and
  `Hash` are kept consistent: equal handles always hash equal.
- **Layer 7 — Zero-on-drop.** `LockedBytes` overwrites its bytes with
  `write_volatile` + a compiler fence before releasing the lock and
  freeing the allocation. The temporary plaintext copy used to build the
  layout buffer is also volatile-zeroed.
- **BLAKE3 normalization wired through.** The previously-toggle-only
  `KeyVaultBuilder::normalize_with_blake3` setting now actually applies a
  BLAKE3 hash to the input key before fragmentation. Default remains on.
- **`KeyVault::fragment` / `KeyVault::defragment`.** Convenience methods
  routing through the configured normalizer and `StandardFragmenter`.
  Downstream crates can now exercise the full Layer 2 + 3 + 7 stack from
  the public API. (Named-key registration still arrives in 0.9.0.)
- **`KeyVaultBuilder::with_chunk_range`** — propagates a custom chunk-size
  range to the underlying fragmenter.
- New module `src/memory` with `LockedBytes` + per-OS backends
  (`unix.rs`, `windows.rs`).
- New module `src/normalize` with `blake3_normalize` helper.
- New integration test `tests/fragment_roundtrip.rs` covering the full
  pipeline through the public API plus `Send + Sync` assertions on
  `KeyVault`.

### Changed

- **CI: replaced `actions/cache@v4` with `Swatinem/rust-cache@v2`.**
  Removes the Node.js 20 deprecation warning and gives the Rust-aware
  caching policy (sccache-friendly, target-dir aware).
- Dropped the unused `actions/setup-node@v5` step from CI.
- `Fragments` gained real internal storage (a `Vec<LockedBytes>` for
  chunks plus a separate `LockedBytes` layout buffer); `Debug` continues
  to redact contents and now uses `finish_non_exhaustive` to document
  that the layout field is intentionally hidden.
- `KeyHandle` no longer derives `PartialEq` and `Hash` — both are
  implemented manually so equality routes through `ConstantTimeEq` while
  preserving the `Hash`/`Eq` consistency invariant.

### Security

- **Layer 2** is now actually in force for every fragment and layout
  buffer; pages are pinned in RAM unless the OS refuses.
- **Layer 6** equality on handles is now constant-time.
- **Layer 7** zero-on-drop applies to every fragment, every layout
  buffer, and intermediate plaintext copies created during
  fragmentation.

[0.3.0]: https://github.com/jamesgober/key-vault/compare/v0.2.0...v0.3.0

---

## [0.2.0] - 2026-05-20

### Added

- `Error` enum (`#[non_exhaustive]`) covering acquisition, fragmentation,
  defragmentation, decoy, codex, lock-out, memory-lock, configuration, and
  internal-invariant failures. All variants are redaction-clean by design.
- `Result<T>` type alias.
- `KeyHandle` and `KeyId` opaque reference types with hard `Debug` redaction
  (every variant prints `KeyHandle(<redacted>)` / `KeyId(<redacted>)`).
- `KeyMetadata` and `AlgorithmHint` for non-secret per-key metadata.
- Layer 1: `KeyFetch` trait + `FetchContext` + `RawKey` container with
  redacting `Debug`.
- Layer 3: `FragmentStrategy` trait + opaque `Fragments` placeholder.
- Layer 4: `DecoyStrategy` trait.
- Layer 5: `Codex` trait, `IdentityCodex` default implementation, and
  `FnCodex<F>` for user-provided involutions.
- Layer 8: `SecurityMonitor` trait + `FailureContext` / `AccessContext` /
  `ThresholdContext` event structs.
- `KeyVault` and `KeyVaultBuilder` skeletons with a `VaultConfig` carrying the
  BLAKE3 normalization toggle.
- `tee::detect_tee_capabilities()` returning a `TeeCapabilities` snapshot for
  Intel SGX, Intel TDX, AMD SEV, AMD SEV-SNP, ARM TrustZone, Apple Secure
  Enclave, and AWS Nitro. Each capability reports `Detected`, `NotDetected`,
  or `Unknown`. x86_64 probes use CPUID directly; AWS Nitro is inferred from
  the Linux DMI vendor string; Apple Secure Enclave is inferred from
  `aarch64-apple-darwin`.
- Integration test suite under `tests/tee_detection.rs`.
- 27 unit tests + 4 integration tests + 5 doctests cover the new surface.

### Changed

- MSRV raised from `1.75` to `1.85` to match the `edition = "2024"` declaration
  that was already in `Cargo.toml`. The two were mutually incompatible — Cargo
  ≥1.84 refuses to parse the previous combination. CI matrix updated.
- `src/lib.rs` rewritten as a module graph (`codex`, `decoy`, `error`,
  `fetcher`, `fragment`, `handle`, `metadata`, `monitor`, `tee`, `vault`) with
  appropriate public re-exports.
- `clippy.toml` gained a `doc-valid-idents` whitelist covering domain terms
  (`x86_64`, `TrustZone`, `IntelTDX`, `ChaCha20`, `VirtualLock`, etc.) so the
  pedantic `doc_markdown` lint focuses on real backtick misses.

[Unreleased]: https://github.com/jamesgober/key-vault/compare/v0.9.0...HEAD
[0.2.0]: https://github.com/jamesgober/key-vault/compare/v0.1.0...v0.2.0

---

## [0.1.0] - 2026-05-18

### Added

- Initial scaffold and repository bootstrap.
- REPS compliance baseline.
- CI for Linux/macOS/Windows on stable and MSRV (1.75).
- Project documentation framework (PROMPT, DIRECTIVES, ROADMAP).
- **9-layer security architecture** locked in:
  - Layer 1: Secure Acquisition (`KeyFetch` trait)
  - Layer 2: Memory Page Locking (mlock / VirtualLock)
  - Layer 3: Fragment Strategy (variable chunks)
  - Layer 4: Decoy Bytes (self-referential filler)
  - Layer 5: Codex Transformation (involution-based byte swap)
  - Layer 6: Constant-Time Operations
  - Layer 7: Zero-On-Drop (zeroize)
  - Layer 8: Security Monitor (failure detection)
  - Layer 9: Audit Logging
  - Bonus Layer 10: Page Protection Toggling
- Cargo feature flags for all fetchers, fragment strategies, decoy strategies, codex, monitor, audit, mlock, zeroize, tee-detect, post-quantum
- Convenience presets: preset-balanced, preset-paranoid, preset-fast
- `docs/SECURITY.md` (24 KB) - comprehensive 9-layer security architecture
- `docs/TRANSFORMATION.md` (12 KB) - visual walkthrough of key transformation
- BLAKE3 key normalization
- TEE detection in 1.0 scope (full TEE integration deferred to 1.x)

[0.1.0]: https://github.com/jamesgober/key-vault/releases/tag/v0.1.0