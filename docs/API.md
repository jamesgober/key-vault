<h1 align="center">    
  <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg"><br>
  <b>key-vault</b>
  <br><sub><sup>API REFERENCE</sup></sub>
</h1>

<p align="center">
    <b><a href="#installation">Installation</a></b>
    &nbsp;&middot;&nbsp;
    <b><a href="#quick-start">Quick Start</a></b>
    &nbsp;&middot;&nbsp;
    <b><a href="#public-apis">Public APIs</a></b>
    &nbsp;&middot;&nbsp;
    <b><a href="#examples">Examples</a></b>
    &nbsp;&middot;&nbsp;
    <b><a href="#api-safety">API Safety</a></b>
    &nbsp;&middot;&nbsp;
    <b><a href="#notes">Notes</a></b>
</p>

<p align="center">
    <i>Complete public-API reference for <code>key-vault</code> 1.1.</i>
    <br>
    <i>For the threat model and what each layer does see <a href="SECURITY.md">SECURITY.md</a>.
    For a per-version change log see <a href="../CHANGELOG.md">CHANGELOG.md</a>.</i>
</p>

<hr>

## Installation

### Default installation

Add to `Cargo.toml`:

```toml
[dependencies]
key-vault = "1.1"
```

### Install via terminal

```bash
cargo add key-vault
```

### Minimum supported Rust version

**Rust 1.85** (edition 2024). Older toolchains will not build.

### Cargo features

Cargo features never change what `KeyVaultBuilder::new()` builds. The
`fragment-*`, `decoy-*`, `codex*`, `monitor`, `audit` and `preset-*`
features choose what [`KeyVaultBuilder::from_features()`](#keyvaultbuilder)
configures, so turning one on changes nothing for existing vaults.

| Feature | Default | Effect |
|---------|---------|--------|
| `std` | ✅ | The full crate. Without it the crate is `no_std` + `alloc`; see [`no_std`](#no_std). |
| `fetcher-env` |   | Compiles `EnvFetch`. Implies `std`. |
| `fetcher-file` |   | Compiles `FileFetch` (plaintext key file). Implies `std`. |
| `fetcher-keychain` |   | Compiles `KeychainFetch` with `keyring`'s native stores (Keychain Services, Credential Manager, Secret Service over pure-Rust D-Bus). Implies `std`. |
| `fetcher-tpm` |   | Compiles `TpmFetch`, which is **not implemented** and always returns an error. Implies `std`. |
| `fetcher-all` |   | `fetcher-keychain` + `fetcher-file` + `fetcher-env`. |
| `monitor-tracing` |   | Compiles `LogMonitor` and `LogAudit` (pulls in `tracing`). Implies `monitor` and `std`. |
| `fragment-standard` | ✅ | `from_features()`: `StandardFragmenter` (when no other `fragment-*` feature is on). |
| `fragment-interleaved` |   | `from_features()`: `InterleavedFragmenter`. |
| `fragment-random` |   | `from_features()`: `RandomFragmenter`. |
| `fragment-layered` |   | `from_features()`: `LayeredFragmenter` over standard, interleaved and random. |
| `fragment-all` |   | All four; layered wins. |
| `decoy-self-ref` | ✅ | `from_features()`: `SelfReferenceDecoy` on the standard fragmenter. |
| `decoy-key-derived` |   | `from_features()`: `KeyDerivedDecoy` (when `decoy-self-ref` is off). |
| `decoy-random` |   | `from_features()`: `RandomDecoy` (when neither of the above is on). |
| `decoy-all` |   | All three; self-reference wins. |
| `codex`, `codex-dynamic` |   | `from_features()`: a fresh `DynamicCodex` per vault. |
| `monitor` |   | With `monitor-tracing`, `from_features()` attaches `LogMonitor`. |
| `audit` |   | With `monitor-tracing`, `from_features()` attaches `LogAudit`. |
| `preset-balanced` |   | The default set: standard fragmenter + self-reference decoys. |
| `preset-paranoid` |   | Layered fragmenter + self-reference decoys + `DynamicCodex` (+ `LogMonitor` / `LogAudit` if `monitor-tracing` is on). |
| `preset-fast` |   | Standard fragmenter + `RandomDecoy` when used with `default-features = false`. |
| `mlock` | ✅ | **Deprecated, no effect.** Page locking is always on and cannot be turned off. |
| `zeroize` | ✅ | **Deprecated, no effect.** Zero-on-drop is always on. |
| `tee-detect` |   | **Deprecated, no effect.** TEE detection is always compiled with `std`. |
| `post-quantum` |   | **Deprecated, no effect.** It was informational only. |

**When several features of one kind are on,** the fragmenter is the first
of layered, random, interleaved, standard, and the decoy is the strongest
of self-reference, key-derived, random. Features from every crate in a
build are merged, so this rule makes sure one crate asking for a stronger
setting is not undone by another. Decoys apply only to the standard
fragmenter (alone, or as the layered fragmenter's standard sub-strategy).
No preset turns off page locking, dump exclusion or zeroization.

The deprecated features are kept so existing feature lists keep
building; removing a feature is a breaking change.

### `no_std`

```toml
[dependencies]
key-vault = { version = "1.1", default-features = false }
```

Without `std` the crate is `#![no_std]` and needs `alloc`. What changes:

- Build the vault with [`KeyVaultBuilder::build_with_clock`](#keyvaultbuilder)
  and a [`Clock`](#clock). `build()` does not exist without `std`, so a
  missing clock is a compile error.
- Randomness comes from `getrandom`. On targets it has no backend for
  (bare metal), register your RNG with [`register_rng!`](#register_rng);
  without it, linking fails with an undefined `__getrandom_custom`.
- Spin locks replace `std::sync`, the registry is a `BTreeMap`, and the
  `with_key` scratch buffer is allocated per call.
- The fetchers, `monitor-tracing`, the `tee` module and
  `AuditEvent::thread_id` need `std`.
- On bare metal there is no swap and no core dump: page locking and dump
  exclusion do not apply, and `with_page_protection` does not exist. On a
  hosted Unix or Windows target they work without `std`.

CI builds the library for `thumbv7em-none-eabihf` and runs
`tests/no_std_vault.rs` against the `no_std` build.

<a href="#top">↑ TOP</a>

<hr>

## Error handling and panic guarantees

- Every fallible operation returns [`Result<T>`](#resultt) — an alias for
  `core::result::Result<T, Error>`.
- [`Error`](#error) is `#[non_exhaustive]`; new variants are added in
  minor releases. Match wildcards (`_ => ...`) are required.
- **No `unwrap` / `expect` / `panic!`** in the public API. The crate is
  REPS-compliant; every panic in library code is a bug.
- **No raw key bytes in any `Error` variant.** Failure messages are
  redaction-clean — safe to log, safe to include in audit records, safe
  to ship to monitoring sinks.
- **Debug** impls for every key-adjacent type print `<redacted>` for key
  material. The `KeyHandle::Debug` impl prints exactly `KeyHandle(<redacted>)`
  regardless of the underlying id.

<a href="#top">↑ TOP</a>

<hr>

## Quick Start

Always on: BLAKE3 normalization (unless disabled), `StandardFragmenter`,
page locking and zero-on-drop. `SelfReferenceDecoy` and `DynamicCodex`
below are opt-in obfuscation; they apply only because the builder sets
them. None of this protects keys from code that can read the process's
memory; see [SECURITY.md](SECURITY.md).

```rust
use key_vault::{DynamicCodex, KeyVaultBuilder, RawKey, SelfReferenceDecoy};
use key_vault::tee::detect_tee_capabilities;

# fn main() -> Result<(), key_vault::Error> {
// Layers 2 (mlock), 3 (StandardFragmenter) and 7 (zero-on-drop) are always
// on; 4 (decoy) and 5 (codex) are added here explicitly.
let vault = KeyVaultBuilder::new()
    .normalize_with_blake3(true)            // default
    .with_codex(DynamicCodex::new()?)       // Layer 5
    .with_decoy(SelfReferenceDecoy)         // Layer 4
    .build();

// Fragment a key. Returns an opaque `Fragments` token.
let raw = RawKey::new(b"my application key".to_vec());
let fragments = vault.fragment(&raw)?;

// Defragment when you need the bytes back. With normalization on, the
// recovered material is the 32-byte BLAKE3 hash of the original input.
let recovered = vault.defragment(&fragments)?;
assert_eq!(recovered.len(), 32);

// Optionally check the host's TEE capabilities at startup.
let caps = detect_tee_capabilities();
println!("{caps}");
# Ok(())
# }
```

<a href="#top">↑ TOP</a>

<hr>

## Public APIs

### `VERSION`

```rust
pub const VERSION: &str;
```

Source: `src/lib.rs`

Crate version string populated by Cargo at build time. Equal to
`env!("CARGO_PKG_VERSION")`.

**Example:**

```rust
assert!(key_vault::VERSION.starts_with("0."));
```

<hr>

### `Error`

Source: `src/error.rs`

The crate-wide error type. `#[non_exhaustive]`; future variants additive.
**No variant carries raw key material** — error messages are redaction-clean.

**Variants:**

| Variant | Meaning |
|---------|---------|
| `Acquisition { source, reason }` | A `KeyFetch` impl failed; `source` names the fetcher, `reason` is sanitized prose. |
| `KeyNotFound` | Requested key id is not registered with the vault. |
| `Fragment(String)` | Fragmentation failed (configuration error or input outside supported bounds). |
| `Defragment(String)` | Reassembly failed (layout/chunk mismatch, corruption). |
| `Decoy(String)` | A `DecoyStrategy` cannot produce the requested output. |
| `Codex(String)` | A `Codex` rejected an input (e.g. conflicting swap pairs in `StaticCodex::from_swaps`). |
| `LockedOut` | A lockout is in effect: vault-wide, or (1.1) per key for the key you asked for. |
| `RateLimited { retry_after }` | (1.1) A master-unlock attempt was refused, unchecked, by the backoff. `retry_after: Duration` says when the next attempt will be checked. |
| `MemoryLock(String)` | (Page protection) The OS refused to map or protect a key's private region. Page *locking* failures are not errors. |
| `InvalidConfig(String)` | Builder produced an internally inconsistent configuration. |
| `Internal(&'static str)` | Crate invariant violated; please file an issue. |

**Example:**

```rust
use key_vault::{Error, KeyVaultBuilder, RawKey};

# fn main() -> Result<(), Error> {
let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
let err = vault.fragment(&RawKey::new(Vec::new())).unwrap_err();
match err {
    Error::Fragment(reason) => assert!(reason.contains("empty")),
    other => panic!("expected Fragment, got {other:?}"),
}
# Ok(())
# }
```

<hr>

### `Result<T>`

```rust
pub type Result<T> = core::result::Result<T, Error>;
```

Source: `src/error.rs`

Shorthand for fallible vault operations.

<hr>

### `KeyHandle`

Source: `src/handle.rs`

Opaque, redacted reference to a registered key. `Copy + Clone + Eq + Hash`.

**Key properties:**

- `Debug` always prints `KeyHandle(<redacted>)` — never the underlying id.
- `PartialEq` routes through [`subtle::ConstantTimeEq`] so equality is
  constant-time.
- `Hash` is implemented manually to remain consistent with `PartialEq`
  (equal handles always hash equal).
- The inner numeric id is `pub(crate)` only — outside callers cannot
  read it.

**Public methods:**

- `KeyHandle::__for_test() -> Self` — placeholder constructor for
  doctests and external tests. Not part of the supported API; do not
  use in production.

**Example:**

```rust
use key_vault::KeyHandle;

let h = KeyHandle::__for_test();
let rendered = format!("{h:?}");
assert_eq!(rendered, "KeyHandle(<redacted>)");
```

<hr>

### `KeyId`

Source: `src/handle.rs`

Process-wide handle identifier (`NonZeroU64` newtype). Public surface
exposes the type itself only; the inner value is crate-private. Use it
where APIs need a `KeyId` parameter; never depend on its numeric value.

`Debug` prints `KeyId(<redacted>)`.

<hr>

### `KeyMetadata`

Source: `src/metadata.rs`

Public, non-secret information about a registered key. Safe to log.

**Read accessors:**

- `length(&self) -> usize` — raw key length, in bytes.
- `algorithm(&self) -> Option<AlgorithmHint>` — optional algorithm hint.
- `registered_since_epoch(&self) -> Duration` — registration time as a
  `Duration` since `UNIX_EPOCH`.

The constructor (`new`) is crate-internal; vault registration produces
metadata in 0.9+.

**Example:**

```rust
// `KeyMetadata` is produced by the vault. Use the accessors to inspect
// non-secret properties (length, algorithm hint, registration time).
fn report(metadata: &key_vault::KeyMetadata) -> String {
    format!(
        "key is {} bytes, algorithm = {:?}",
        metadata.length(),
        metadata.algorithm()
    )
}
```

<hr>

### `AlgorithmHint`

Source: `src/metadata.rs`

```rust
#[non_exhaustive]
pub enum AlgorithmHint {
    Symmetric128, Symmetric256,
    Ed25519, X25519, P256, P384,
    Rsa2048, Rsa3072, Rsa4096,
    Hmac, Other,
}
```

Advisory tag attached to `KeyMetadata`. The vault does not verify that
the registered bytes match the named algorithm — the variant exists so
audit trails and monitors can label events meaningfully.

<hr>

### `RawKey`

Source: `src/fetcher/mod.rs`

Container for raw key material exchanged between `KeyFetch` impls, the
vault, and the fragmenter. `Debug` redacts contents.

**Constructors:**

- `RawKey::new(bytes: Vec<u8>) -> Self` — wrap an existing buffer (moved,
  not copied).

**Read accessors:**

- `len(&self) -> usize` — length in bytes.
- `is_empty(&self) -> bool` — whether the buffer is zero-length.
- `expose_secret(&self) -> &[u8]` — (1.1) the key bytes. For custom
  `FragmentStrategy` / `DecoyStrategy` implementations and for reading
  what `KeyVault::defragment` returns. Copies you make of the slice are
  yours to wipe.

`Debug` prints `RawKey { len, bytes: "<redacted>" }`.

**`Drop`** zeroizes the whole allocation, including spare capacity
beyond the length.

**Example:**

```rust
use key_vault::RawKey;

let key = RawKey::new(b"my application key".to_vec());
assert_eq!(key.len(), 18);
assert!(!key.is_empty());
assert_eq!(key.expose_secret(), b"my application key");
let rendered = format!("{key:?}");
assert!(rendered.contains("<redacted>"));
```

<hr>

### `FetchContext`

Source: `src/fetcher/mod.rs`

Information given to a `KeyFetch` impl. `#[non_exhaustive]`.

**Fields:**

- `pub key_name: String` — logical name of the key being requested.

**Constructors:**

- `FetchContext::new(key_name: impl Into<String>) -> Self`

**Example:**

```rust
use key_vault::FetchContext;

let ctx = FetchContext::new("db-primary");
assert_eq!(ctx.key_name, "db-primary");
```

<hr>

### `Fragments`

Source: `src/fragment/mod.rs`

The fragmented form of a key, produced by `FragmentStrategy::fragment`
and consumed by `FragmentStrategy::defragment`. Holds the chunks and the
layout buffer, each in locked, dump-excluded, zero-on-drop memory. Anyone
holding a `Fragments` can rebuild the key with the strategy that made it,
so treat it like the key.

**Constructors:**

- `Fragments::from_chunks(chunks: impl IntoIterator<Item = impl AsRef<[u8]>>, layout: &[u8], total_len: usize) -> Self`
  — (1.1) for custom strategies. Copies each chunk and the layout into
  locked buffers. The layout format is the strategy's own.

**Public accessors:**

- `chunk_count(&self) -> usize` — number of chunks (real + decoy if
  configured).
- `chunk(&self, index: usize) -> Option<&[u8]>` — (1.1) one chunk's bytes.
- `layout_bytes(&self) -> &[u8]` — (1.1) the layout map.
- `total_len(&self) -> usize` — (1.1) length of the key the chunks
  reassemble into.

`Debug` prints `Fragments { chunks: N, total_len: M, contents: "<opaque>", .. }`.

**Example:**

```rust
use key_vault::{Fragments, KeyVaultBuilder, RawKey};

# fn main() -> Result<(), key_vault::Error> {
let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
let raw = RawKey::new(vec![0u8; 32]);
let fragments = vault.fragment(&raw)?;
assert!(fragments.chunk_count() >= 4); // 32 / 8 (max chunk size) = 4
assert_eq!(fragments.total_len(), 32);

// A custom strategy builds its own:
let mine = Fragments::from_chunks([&b"lo"[..], b"hel"], &[3, 0], 5);
assert_eq!(mine.chunk(1), Some(&b"hel"[..]));
# Ok(())
# }
```

<hr>

### `KeyVault`

Source: `src/vault/mod.rs`

The vault itself. `Arc`-backed, `Clone`, `Send + Sync`. Construct via
[`KeyVaultBuilder`](#keyvaultbuilder).

**Named-key registry:**

- `register(name: impl Into<String>, key: RawKey) -> Result<KeyHandle>`
  — fragment a key and insert it under `name`. Returns the opaque
  handle. Errors on duplicate name (`Error::InvalidConfig`), when the
  vault is locked out, or (page protection on) when the private mapping
  cannot be created (`Error::MemoryLock`). Of several simultaneous
  `register` calls with the same name, exactly one succeeds.
- `unregister(handle: KeyHandle) -> Result<()>` — remove. The
  underlying storage drops and zeroizes when the last reference goes
  away. Works on a locked-out key.
- `with_key<F, T>(handle, f: F) -> Result<T>` where
  `F: FnOnce(&[u8]) -> T` — scoped byte access. The slice handed to
  `f` points into a page-locked, dump-excluded scratch buffer (per
  thread with `std`, per call without) and is valid only during the
  call; the buffer is zeroed when `f` returns, panics, or
  defragmentation fails. Copies `f` makes are not wiped. Returns
  `Error::LockedOut` if the vault or this key is locked out.
- `rotate(handle, new_key: RawKey) -> Result<()>` — atomic swap.
  Concurrent readers see either the old or the new fragmentation,
  never a torn read. Returns `Error::KeyNotFound` if a concurrent
  `unregister` removed the key first, `Error::LockedOut` if the vault
  or this key is locked out.
- `contains(handle: KeyHandle) -> bool`
- `metadata(handle: KeyHandle) -> Option<KeyMetadata>` — non-secret
  per-key metadata.
- `handle_for_name(name: &str) -> Option<KeyHandle>` — lookup.
- `key_count() -> usize` — number of registered keys.

**Master-key emergency unlock:**

- `unlock_with_master(attempt: &[u8]) -> Result<()>` — compare
  `BLAKE3-keyed(k, attempt)` with the stored verifier in constant time
  (`k` is a random key per builder, held in locked memory; 1.1). On
  match, clears every lockout and the failure tracker. On mismatch,
  reports the failure under the reserved name `"<master>"` (vault-wide
  threshold only), starts or extends the backoff if configured, and
  returns `Error::Acquisition`. During the backoff delay it returns
  `Error::RateLimited { retry_after }` without checking. Attempts are
  serialized.
- `has_master_key() -> bool` — whether a master credential was
  registered at build time.

**One-shot fragment / defragment:**

- `fragment(&self, key: &RawKey) -> Result<Fragments>` — pipeline:
  optional normalization → optional codex encode → fragmenter.fragment.
  Never page-protected. Returns `Error::LockedOut` when the vault is
  locked out.
- `defragment(&self, fragments: &Fragments) -> Result<RawKey>` —
  inverse: fragmenter.defragment → optional codex decode. Read the
  result with `RawKey::expose_secret`.

**Lockout + monitor controls:**

- `is_locked_out(&self) -> bool` — `true` if the vault-wide threshold
  has been crossed. **Lockout is advisory:** only failures the caller
  reports through `report_failure` (and wrong master credentials)
  count, and crossing the vault-wide threshold for one key name locks
  out every key.
- `is_key_locked_out(&self, handle: KeyHandle) -> bool` — (1.1) `true`
  if the per-key threshold has locked out this key.
- `clear_key_lockout(&self, name: &str) -> bool` — (1.1) clear one
  key's lockout and its failure count; `true` if it was locked out.
- `clear_lockout(&self)` — clear the vault-wide flag, every per-key
  lockout and the failure tracker.
- `report_failure(&self, key_name: &str, note: Option<&'static str>)`
  — caller-driven failure reporting. Forwards to the configured
  monitor and feeds both thresholds.
- `report_anomalous_access(&self, key_name: &str, note: Option<&'static str>)`
  — caller-driven anomaly reporting (no state change).
- `config(&self) -> &VaultConfig` — the configuration.

**Example:**

```rust
use std::time::Duration;
use key_vault::{KeyVault, KeyVaultBuilder, RawKey};

# fn main() -> Result<(), key_vault::Error> {
let vault: KeyVault = KeyVaultBuilder::new()
    .normalize_with_blake3(false)
    .with_key_lockout(3, Duration::from_secs(60), None)
    .build();

let raw = RawKey::new(b"my application key".to_vec());
let fragments = vault.fragment(&raw)?;
let recovered = vault.defragment(&fragments)?;
assert_eq!(recovered.expose_secret(), b"my application key");

let h = vault.register("db", RawKey::new(vec![1; 32]))?;
for _ in 0..3 {
    vault.report_failure("db", Some("decrypt failed"));
}
assert!(vault.is_key_locked_out(h));
assert!(!vault.is_locked_out()); // only that key
vault.clear_key_lockout("db");
# Ok(())
# }
```

<hr>

### `KeyVaultBuilder`

Source: `src/vault/mod.rs`

Fluent builder for [`KeyVault`](#keyvault). `Clone`.

**Constructors:**

- `KeyVaultBuilder::new() -> Self` — normalization on, default-range
  `StandardFragmenter`, no decoy, no codex, every lockout and backoff
  off, no page protection. Features never change this.
- `KeyVaultBuilder::default()` — same as `new()`.
- `KeyVaultBuilder::from_features() -> Result<Self>` — (1.1) a builder
  configured by the enabled Cargo features (see
  [Cargo features](#cargo-features)). Errors only if the RNG fails while
  building a codex table.

**Builder methods:**

- `normalize_with_blake3(self, enabled: bool) -> Self` — toggle
  normalization. Default `true`. `false` also turns keyed normalization
  off.
- `with_keyed_normalization(self) -> Self` — (1.1) keyed BLAKE3 under a
  random key per built vault. **Effective keys change every run.**
- `with_normalization_key(self, key: RawKey) -> Self` — (1.1) keyed
  BLAKE3 under a key derived from `key` (`derive_key` mode); stable
  across processes with the same `key`.
- `with_fragmenter<F: FragmentStrategy + 'static>(self, f: F) -> Self` —
  (1.1) choose the fragmentation strategy. `with_decoy` decoys are not
  used with a non-standard strategy (`Debug` shows `decoy_ignored: true`).
- `with_chunk_range(self, min: usize, max: usize) -> Self` — select a
  `StandardFragmenter` with this chunk-size range. Replaces any
  previously set fragmenter and decoy.
- `with_decoy<D: DecoyStrategy + 'static>(self, decoy: D) -> Self` —
  attach a Layer-4 decoy strategy to the standard fragmenter.
- `with_codex<C: Codex + 'static>(self, codex: C) -> Self` — attach a
  Layer-5 codex.
- `with_monitor<M: SecurityMonitor + 'static>(self, monitor: M) -> Self`
  — attach a Layer-8 monitor.
- `with_failure_threshold(self, max: u32, window: Duration) -> Self` —
  vault-wide lockout. `max = 0` (default) disables it.
- `with_key_lockout(self, max: u32, window: Duration, lock_for: Option<Duration>) -> Self`
  — (1.1) per-key lockout. `max = 0` (default) disables it; `lock_for =
  None` keeps the lockout until cleared.
- `with_master_key(self, master: RawKey) -> Self` — register a
  master-key credential. Stores a random 32-byte hash key and
  `BLAKE3-keyed(key, master)` in locked memory; the plaintext is wiped
  immediately.
- `with_master_unlock_backoff(self, base: Duration, max: Duration) -> Self`
  — (1.1) refuse master attempts for `base`, `2 * base`, ... (capped at
  `max`) after each failure. `base = 0` (default) disables it.
- `with_page_protection(self, enabled: bool) -> Self` — (1.1, Unix and
  Windows only) give each registered key its own mapping that is
  `PROT_NONE` / `PAGE_NOACCESS` except while it is read. Costs about
  1.5 µs per `with_key` and one page per key; see
  [SECURITY.md](SECURITY.md#layer-10-page-protection) for the Windows
  page-file note.
- `with_audit_sink<A: AuditSink + 'static>(self, sink: A) -> Self`
  — attach a Layer-9 audit sink. Default is `NoAudit`.
- `build(self) -> KeyVault` — finalize with `StdClock`. `std` only.
- `build_with_clock<C: Clock + 'static>(self, clock: C) -> KeyVault` —
  (1.1) finalize with your own [`Clock`](#clock). The only way to build
  without `std`.

**Example:**

```rust
use std::time::Duration;
use key_vault::{DynamicCodex, KeyVaultBuilder, RandomFragmenter, SelfReferenceDecoy};

# fn main() -> Result<(), key_vault::Error> {
let vault = KeyVaultBuilder::new()
    .normalize_with_blake3(true)
    .with_chunk_range(2, 6)
    .with_decoy(SelfReferenceDecoy)
    .with_codex(DynamicCodex::new()?)
    .with_key_lockout(5, Duration::from_secs(60), Some(Duration::from_secs(300)))
    .build();
# let _ = vault;

let other = KeyVaultBuilder::new()
    .with_fragmenter(RandomFragmenter::new())
    .with_page_protection(true)
    .build();
# let _ = other;

let from_features = KeyVaultBuilder::from_features()?.build();
# let _ = from_features;
# Ok(())
# }
```

<hr>

### `VaultConfig`

Source: `src/vault/mod.rs`

`#[non_exhaustive]` configuration struct exposed by `KeyVault::config()`.

**Fields:**

- `pub key_normalization: bool` — normalization on. Default `true`.
- `pub keyed_normalization: bool` — (1.1) keyed BLAKE3 in use.
- `pub max_failures_before_lockout: u32` — vault-wide threshold. `0` =
  disabled (default).
- `pub failure_window: Duration` — vault-wide window. Default 60 s.
- `pub key_lockout_threshold: u32` — (1.1) per-key threshold. `0` =
  disabled (default).
- `pub key_lockout_window: Duration` — (1.1) per-key window. Default 60 s.
- `pub key_lockout_duration: Option<Duration>` — (1.1) per-key lockout
  length; `None` = until cleared.
- `pub master_backoff_base: Duration` — (1.1) first backoff delay;
  `Duration::ZERO` = disabled (default).
- `pub master_backoff_max: Duration` — (1.1) backoff cap.
- `pub page_protection: bool` — (1.1) page protection on. Default
  `false`.

<hr>

### `Clock`

Source: `src/clock.rs`

(1.1) Time source for failure windows, per-key lockout expiry,
master-unlock backoff, and metadata / audit timestamps.

```rust
pub trait Clock: Send + Sync {
    /// Monotonic time since an arbitrary fixed point.
    fn now(&self) -> Duration;
    /// Wall-clock time since the Unix epoch. Default: Duration::ZERO.
    fn unix_time(&self) -> Duration { Duration::ZERO }
}
```

`StdClock` (`std` only) implements it with `Instant` and `SystemTime`;
`KeyVaultBuilder::build` uses it. Pass your own to `build_with_clock`
(required without `std`, also handy for tests).

<hr>

### `register_rng!`

Source: `src/rng.rs`

(1.1) Register the random source on targets `getrandom` has no backend
for (bare metal). Call it once in the binary crate with a
`fn(&mut [u8]) -> bool` that fills the buffer from a hardware RNG (or a
CSPRNG seeded from one) and returns `false` on failure. Without it,
linking fails with an undefined `__getrandom_custom`; there is no
fallback. On other targets it has no effect.

```rust
# mod trng { pub fn read(_: &mut [u8]) -> bool { true } }
fn fill(buf: &mut [u8]) -> bool {
    trng::read(buf)
}
key_vault::register_rng!(fill);
# fn main() {}
```

<hr>

### `KeyFetch` (trait, Layer 1)

Source: `src/fetcher/mod.rs`

Pluggable source of raw key material.

```rust
pub trait KeyFetch: Send + Sync {
    fn fetch(&self, ctx: &FetchContext) -> Result<RawKey>;
    fn describe(&self) -> Cow<'_, str>;
}
```

**Contract:**

- No retries. A failure to find a key is a configuration error, not a
  transient.
- No caching. The vault calls `fetch` exactly once per registration.
- Sanitized errors. Returned `Error::Acquisition.reason` must not include
  key material or secret-equivalent values.

Built-in implementations, each feature-gated:
[`EnvFetch`](#envfetch), [`FileFetch`](#filefetch) (plaintext file),
[`KeychainFetch`](#keychainfetch). [`TpmFetch`](#tpmfetch) is **not
implemented** and always returns an error.

**Example (custom impl):**

```rust
use std::borrow::Cow;
use key_vault::{Error, FetchContext, KeyFetch, RawKey, Result};

struct StaticFetch(Vec<u8>);

impl KeyFetch for StaticFetch {
    fn fetch(&self, _ctx: &FetchContext) -> Result<RawKey> {
        Ok(RawKey::new(self.0.clone()))
    }
    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("static-test")
    }
}
```

<hr>

### `EnvFetch`

Source: `src/fetcher/env.rs` · Feature: `fetcher-env`

Reads key bytes from a named process environment variable. The variable
**name** appears in error messages for diagnostics; the variable
**value** is never logged.

**Constructors:**

- `EnvFetch::new(var_name: impl Into<String>) -> Self`

**Threat profile.** Lowest-security built-in. Anything in the process
environment is readable by other processes with the right privileges
(`/proc/<pid>/environ` on Linux), debuggers, and crash-dump tooling.
Best for development and orchestration-managed deployments (Kubernetes
Secrets → env, systemd `EnvironmentFile=` with restricted permissions).
The value **stays in the environment** after `fetch`; `EnvFetch` does
not remove it. UTF-8 values only; a rejected non-UTF-8 value is
zeroized before the error is returned.

**Example:**

```rust,no_run
use key_vault::{EnvFetch, FetchContext, KeyFetch};

# fn main() -> Result<(), key_vault::Error> {
let fetcher = EnvFetch::new("MY_APP_KEY");
let raw = fetcher.fetch(&FetchContext::new("primary"))?;
# let _ = raw;
# Ok(())
# }
```

<hr>

### `FileFetch`

Source: `src/fetcher/file.rs` · Feature: `fetcher-file`

Reads key bytes from a **plaintext** file on disk. There is no
decryption: the file contents are the key. On Unix the file is opened
once and every check uses the open handle or is tied back to it:

- the mode must have no `0o077` bits (`0o600` or stricter);
- the owner must be the process's effective user or root (1.1);
- every directory on the resolved path, and the directory holding the
  path you gave, must be owned by the process user or root and not be
  writable by group or others unless it has the sticky bit (1.1). The
  resolved path must still lead to the opened file.

Windows trusts NTFS ACLs and performs no check.

**Constructors:**

- `FileFetch::new(path: impl Into<PathBuf>) -> Self` — all checks on.

**Builder methods:**

- `skip_directory_check(self) -> Self` — (1.1) keep the mode and owner
  checks, skip the directory check.
- `allow_loose_perms(self) -> Self` — disable every Unix check (not
  recommended outside of tests).

**Read accessors:**

- `path(&self) -> &Path` — the configured path. Used in audit / error
  attribution.

**Threat profile.** Higher than `EnvFetch` (POSIX permissions confine
access). Lower than `KeychainFetch` (bytes live on disk in cleartext).
Pair with OS-level disk encryption (LUKS / FileVault / BitLocker) for
encryption at rest.

**Example:**

```rust,no_run
use key_vault::{FetchContext, FileFetch, KeyFetch};

# fn main() -> Result<(), key_vault::Error> {
let fetcher = FileFetch::new("/etc/myapp/key.bin");
let raw = fetcher.fetch(&FetchContext::new("primary"))?;
# let _ = raw;
# Ok(())
# }
```

<hr>

### `KeychainFetch`

Source: `src/fetcher/keychain.rs` · Feature: `fetcher-keychain`

Reads from the OS native credential store via the
[`keyring`](https://crates.io/crates/keyring) crate:

- **macOS** — Keychain Services
- **Windows** — Credential Manager
- **Linux, FreeBSD, OpenBSD** — Secret Service over D-Bus (gnome-keyring,
  KWallet), pure Rust, no `libdbus` needed

Before 1.1, `keyring` was used without any store feature, so it fell
back to its in-memory mock store and `KeychainFetch` never reached the
OS keychain.

**Constructors:**

- `KeychainFetch::new(service: impl Into<String>, account: impl Into<String>) -> Self`

`service` is the application/namespace name; `account` is the entry
identifier within that service. Both appear in failure messages.

**Builder methods:**

- `binary(self) -> Self` — (1.1) read the entry with `get_secret` and
  return the stored bytes as they are, instead of a UTF-8 password. On
  Windows a value stored with `set_password` is UTF-16, so store binary
  keys with `set_secret`.

`keyring::Error` variants are mapped to short, discriminant-only
strings — platform-specific error details never appear in `Error`
messages.

**Threat profile.** The strongest built-in fetcher. The OS confines
access to the user account (and on macOS to the signing identity). In
the default (password) mode a binary secret fails with "stored value is
not UTF-8", and the bytes carried by that error are zeroized.

**Example:**

```rust,no_run
use key_vault::{FetchContext, KeyFetch, KeychainFetch};

# fn main() -> Result<(), key_vault::Error> {
let password = KeychainFetch::new("my-app", "primary-key")
    .fetch(&FetchContext::new("primary"))?;
let binary = KeychainFetch::new("my-app", "aes-key")
    .binary()
    .fetch(&FetchContext::new("aes"))?;
# let _ = (password, binary);
# Ok(())
# }
```

<hr>

### `TpmFetch`

Source: `src/fetcher/tpm.rs` · Feature: `fetcher-tpm`

TPM 2.0 fetcher — **not implemented**. `fetch` always returns
`Error::Acquisition`; it never reads a key and provides no hardware
protection. Nothing in the crate detects or talks to a TPM
(`tee::detect_tee_capabilities()` reports CPU/platform TEEs only).

**Constructors:**

- `TpmFetch` is a unit struct — construct directly: `TpmFetch`.

**Example:**

```rust
use key_vault::{FetchContext, KeyFetch, TpmFetch};

let err = TpmFetch.fetch(&FetchContext::new("k")).unwrap_err();
// Not implemented: fetch always fails.
assert!(format!("{err}").contains("TPM"));
```

<hr>

### `FragmentStrategy` (trait, Layer 3)

Source: `src/fragment/mod.rs`

Splits a `RawKey` into a `Fragments` token and reassembles it.

```rust,ignore
pub trait FragmentStrategy: Send + Sync {
    fn fragment(&self, key: &RawKey) -> Result<Fragments>;
    fn defragment(&self, fragments: &Fragments) -> Result<RawKey>;
    /// Hot path used by `with_key`; default calls `defragment` and copies.
    fn defragment_into(&self, fragments: &Fragments, out: &mut [u8]) -> Result<()> { .. }
    fn describe(&self) -> Cow<'_, str>;
}
```

Since 1.1 you can implement it outside the crate: read the key with
`RawKey::expose_secret`, build the output with `Fragments::from_chunks`,
and read it back with `Fragments::chunk` / `layout_bytes` / `total_len`.
Select it for a vault with `KeyVaultBuilder::with_fragmenter`.

**Contract:**

- Round-trip: `defragment(&fragment(&key)?)?` must produce `key`
  byte-for-byte.
- Variable layout per call: two consecutive `fragment` calls on the same
  input must produce distinct `Fragments` layouts.
- `Send + Sync`.

Four built-in implementations follow.

<hr>

### `StandardFragmenter`

Source: `src/fragment/standard.rs`

Default Layer-3 implementation. Variable-size chunks (default `min=1`,
`max=8`), Fisher-Yates shuffle, each chunk in its own `LockedBytes`
allocation.

**Constructors:**

- `StandardFragmenter::new() -> Self` — default chunk range.
- `StandardFragmenter::with_chunk_range(min: usize, max: usize) -> Self`
  — `min` clamped to `>= 1`, `max` clamped to `>= min`.
- `StandardFragmenter::default()` — same as `new`.

**Builder methods:**

- `with_decoy<D: DecoyStrategy + 'static>(self, decoy: D) -> Self` —
  emit decoy chunks alongside real ones; defragment recognizes them via
  a `u32::MAX` sentinel in the layout buffer.

**Example:**

```rust
use key_vault::{FragmentStrategy, RawKey, StandardFragmenter, SelfReferenceDecoy};

# fn main() -> Result<(), key_vault::Error> {
let frag = StandardFragmenter::with_chunk_range(2, 6)
    .with_decoy(SelfReferenceDecoy);
let raw = RawKey::new(b"some key material".to_vec());
let fragments = frag.fragment(&raw)?;
let recovered = frag.defragment(&fragments)?;
assert_eq!(recovered.len(), raw.len());
# Ok(())
# }
```

<hr>

### `RandomFragmenter`

Source: `src/fragment/random.rs`

Non-contiguous byte scatter. Each chunk's bytes come from independently-
chosen random positions of the original key — no chunk contains a
contiguous run of key bytes longer than 1.

**Threat focus.** Defeats contiguous-format recognition attacks (DER
envelopes, PEM markers, ASCII-armored data, JWT headers).

**Constructors:**

- `RandomFragmenter::new() -> Self` — default chunk range (1–4).
- `RandomFragmenter::with_chunk_range(min: usize, max: usize) -> Self`

**Example:**

```rust
use key_vault::{FragmentStrategy, RandomFragmenter, RawKey};

# fn main() -> Result<(), key_vault::Error> {
let frag = RandomFragmenter::new();
let raw = RawKey::new((0u8..32).collect());
let fragments = frag.fragment(&raw)?;
let recovered = frag.defragment(&fragments)?;
assert_eq!(recovered.len(), 32);
# Ok(())
# }
```

<hr>

### `InterleavedFragmenter`

Source: `src/fragment/interleaved.rs`

Single-pool byte placement. Allocates one `LockedBytes` pool (default
4× key length) and writes key bytes at random positions, padding the
gaps with CSPRNG bytes.

**Threat focus.** Defeats byte-level statistical analysis of the pool.

**Constructors:**

- `InterleavedFragmenter::new() -> Self` — default pool factor of 4.
- `InterleavedFragmenter::with_pool_factor(factor: usize) -> Self` —
  factor clamped to `>= 2`.

**Example:**

```rust
use key_vault::{FragmentStrategy, InterleavedFragmenter, RawKey};

# fn main() -> Result<(), key_vault::Error> {
let frag = InterleavedFragmenter::with_pool_factor(6);
let raw = RawKey::new(vec![0xa5; 32]);
let fragments = frag.fragment(&raw)?;
// Single chunk (the pool) of size 32 * 6 = 192 bytes.
assert_eq!(fragments.chunk_count(), 1);
# Ok(())
# }
```

<hr>

### `LayeredFragmenter`

Source: `src/fragment/layered.rs`

Composition by random routing among sub-strategies. Each `fragment`
call picks a sub-strategy uniformly at random; the picked index is
prepended to the layout as a 4-byte LE header so `defragment` dispatches
correctly. Since 1.1 `defragment` hands the sub-strategy a view of the
same chunks instead of copying each one into a new locked buffer.

**Constructors:**

- `LayeredFragmenter::new(sub_strategies: Vec<Arc<dyn FragmentStrategy>>) -> Result<Self>`
  — empty list returns `Error::InvalidConfig`.

**Read accessors:**

- `sub_strategy_count(&self) -> usize` — number of sub-strategies in
  the rotation.

**Example:**

```rust
use std::sync::Arc;
use key_vault::{
    FragmentStrategy, InterleavedFragmenter, LayeredFragmenter,
    RandomFragmenter, RawKey, StandardFragmenter,
};

# fn main() -> Result<(), key_vault::Error> {
let frag = LayeredFragmenter::new(vec![
    Arc::new(StandardFragmenter::new()) as Arc<dyn FragmentStrategy>,
    Arc::new(InterleavedFragmenter::new()) as Arc<dyn FragmentStrategy>,
    Arc::new(RandomFragmenter::new()) as Arc<dyn FragmentStrategy>,
])?;
assert_eq!(frag.sub_strategy_count(), 3);

let raw = RawKey::new(vec![0u8; 32]);
let fragments = frag.fragment(&raw)?;
let recovered = frag.defragment(&fragments)?;
assert_eq!(recovered.len(), 32);
# Ok(())
# }
```

<hr>

### `DecoyStrategy` (trait, Layer 4)

Source: `src/decoy/mod.rs`

Generates decoy chunks stored alongside the real fragments when a
decoy is configured with `KeyVaultBuilder::with_decoy`. Obfuscation
only: the layout buffer marks every decoy chunk.

```rust
pub trait DecoyStrategy: Send + Sync {
    fn generate(&self, key: &RawKey, output_len: usize) -> Result<Vec<u8>>;
    fn describe(&self) -> Cow<'_, str>;
}
```

**Contract:**

- For strategies that derive filler from the key, mix in a fresh
  per-call nonce so two consecutive `generate` calls produce different
  output.
- No accidental key recovery — a decoy must never emit a contiguous run
  of bytes that matches the real key.

<hr>

### `RandomDecoy`

Source: `src/decoy/random.rs`

Pure CSPRNG bytes from `getrandom`. Weakest of the three built-in
strategies — uniformly random distribution is distinguishable from key
material that has format markers.

```rust
use key_vault::{DecoyStrategy, RandomDecoy, RawKey};

# fn main() -> Result<(), key_vault::Error> {
let key = RawKey::new(b"anything".to_vec());
let bytes = RandomDecoy.generate(&key, 32)?;
assert_eq!(bytes.len(), 32);
# Ok(())
# }
```

<hr>

### `SelfReferenceDecoy`

Source: `src/decoy/self_reference.rs`

For each output byte, sample an independent random index into the key
and emit `key[idx]`. The decoy's byte-value distribution is **identical**
to the key's, the closest statistical match of the three. Not used
unless passed to `with_decoy`.

```rust
use key_vault::{DecoyStrategy, RawKey, SelfReferenceDecoy};

# fn main() -> Result<(), key_vault::Error> {
let key = RawKey::new(vec![0xa1, 0xb2, 0xc3]);
let decoy = SelfReferenceDecoy.generate(&key, 32)?;
// Every decoy byte is drawn from the key's byte set.
for b in &decoy {
    assert!([0xa1, 0xb2, 0xc3].contains(b));
}
# Ok(())
# }
```

<hr>

### `KeyDerivedDecoy`

Source: `src/decoy/key_derived.rs`

BLAKE3-XOF seeded by `key bytes ‖ 32-byte CSPRNG nonce`. Per-call nonce
ensures fresh output even for the same key. Middle ground between
`RandomDecoy` and `SelfReferenceDecoy`.

```rust
use key_vault::{DecoyStrategy, KeyDerivedDecoy, RawKey};

# fn main() -> Result<(), key_vault::Error> {
let key = RawKey::new(b"k".to_vec());
let a = KeyDerivedDecoy.generate(&key, 32)?;
let b = KeyDerivedDecoy.generate(&key, 32)?;
// Per-call nonce: two consecutive calls produce different output.
assert_ne!(a, b);
# Ok(())
# }
```

<hr>

### `Codex` (trait, Layer 5)

Source: `src/codex/mod.rs`

Byte-wise substitution applied to the key before fragmentation when a
codex is configured with `KeyVaultBuilder::with_codex`. Obfuscation, not
encryption: table codices keep their table in the same process memory.

```rust
pub trait Codex: Send + Sync {
    fn encode(&self, byte: u8) -> u8;
    fn decode(&self, byte: u8) -> u8;
}
```

**Contract:**

- Involution: `decode(encode(x)) == x` for every byte.
- Constant-time, branch-free; canonical shape is a 256-byte lookup table.

<hr>

### `IdentityCodex`

Source: `src/codex/identity.rs`

No-op codex. `encode(x) == decode(x) == x`. Default Layer-5
implementation.

```rust
use key_vault::{Codex, IdentityCodex};

let c = IdentityCodex;
assert_eq!(c.encode(0xab), 0xab);
assert_eq!(c.decode(0xab), 0xab);
```

<hr>

### `FnCodex<F>`

Source: `src/codex/mod.rs`

Wraps a user-provided closure. The closure **must be an involution** —
nothing in the type system enforces this; violation will corrupt every
stored key.

**Constructors:**

- `FnCodex::new(f: F) -> Self` where `F: Fn(u8) -> u8 + Send + Sync`.

**Example (XOR with fixed mask is an involution):**

```rust
use key_vault::codex::{Codex, FnCodex};

let codex = FnCodex::new(|b: u8| b ^ 0x5a);
for byte in 0u8..=255 {
    assert_eq!(codex.decode(codex.encode(byte)), byte);
}
```

<hr>

### `StaticCodex`

Source: `src/codex/static_codex.rs`

256-byte involution lookup table held in a `LockedBytes` buffer
(mlock'd, zeroed on drop).

**Constructors:**

- `StaticCodex::from_swaps(swaps: &[(u8, u8)]) -> Result<Self>` —
  declarative. Each `(a, b)` means `a ↔ b`. Bytes not in any pair are
  fixed points. Returns `Error::Codex` if a byte appears in more than
  one swap pair.
- `StaticCodex::random_involution() -> Result<Self>` — pair up all 256
  bytes randomly. No fixed points. Returns `Error::Internal` on
  CSPRNG failure.

**Example (declarative):**

```rust
use key_vault::{Codex, StaticCodex};

# fn main() -> Result<(), key_vault::Error> {
let codex = StaticCodex::from_swaps(&[(b'0', b'#'), (b'A', b'@')])?;
assert_eq!(codex.encode(b'0'), b'#');
assert_eq!(codex.encode(b'B'), b'B'); // fixed point
# Ok(())
# }
```

**Example (random):**

```rust
use key_vault::{Codex, StaticCodex};

# fn main() -> Result<(), key_vault::Error> {
let codex = StaticCodex::random_involution()?;
for byte in 0u8..=255 {
    assert_eq!(codex.decode(codex.encode(byte)), byte);
    assert_ne!(codex.encode(byte), byte); // no fixed points
}
# Ok(())
# }
```

<hr>

### `DynamicCodex`

Source: `src/codex/dynamic.rs`

Per-vault random involution. Thin wrapper around
`StaticCodex::random_involution()` for the common case.

**Constructors:**

- `DynamicCodex::new() -> Result<Self>` — fresh random table.

**Example:**

```rust
use key_vault::{Codex, DynamicCodex};

# fn main() -> Result<(), key_vault::Error> {
let codex = DynamicCodex::new()?;
for byte in 0u8..=255 {
    assert_eq!(codex.decode(codex.encode(byte)), byte);
}
# Ok(())
# }
```

<hr>

### `SecurityMonitor` (trait, Layer 8)

Source: `src/monitor/mod.rs`

Outbound channel for anomaly events.

```rust
pub trait SecurityMonitor: Send + Sync {
    fn on_decryption_failure(&self, ctx: &FailureContext);
    fn on_anomalous_access(&self, ctx: &AccessContext);
    fn on_threshold_breach(&self, ctx: &ThresholdContext);
}
```

**Contract:**

- Non-blocking: monitor calls must return promptly. Network/disk work
  belongs on a background thread.
- No panics. No key material in calls.
- `Send + Sync`.

Built-in implementations: `NoMonitor`, `CompositeMonitor`, `LogMonitor`
(`monitor-tracing`). The vault calls the monitor only for failures and
anomalies the caller reports, wrong master credentials, and threshold
breaches; it does not detect decryption failures itself.

<hr>

### `NoMonitor`

Source: `src/monitor/no_monitor.rs`

Inert default. Discards every event. Always available.

```rust
use key_vault::{KeyVaultBuilder, NoMonitor};
let _vault = KeyVaultBuilder::new().with_monitor(NoMonitor).build();
```

<hr>

### `CompositeMonitor`

Source: `src/monitor/composite.rs`

Fan-out across `Vec<Arc<dyn SecurityMonitor>>`. Inner monitors are
called in registration order; an empty list yields a no-op monitor.

**Constructors:**

- `CompositeMonitor::new(inner: Vec<Arc<dyn SecurityMonitor>>) -> Self`

**Read accessors:**

- `len(&self) -> usize`
- `is_empty(&self) -> bool`

```rust
use std::sync::Arc;
use key_vault::{CompositeMonitor, NoMonitor, SecurityMonitor};

let composite = CompositeMonitor::new(vec![
    Arc::new(NoMonitor) as Arc<dyn SecurityMonitor>,
    Arc::new(NoMonitor) as Arc<dyn SecurityMonitor>,
]);
assert_eq!(composite.len(), 2);
```

<hr>

### `LogMonitor`

Source: `src/monitor/log_monitor.rs` · Feature: `monitor-tracing`

Emits structured `tracing` events. `on_decryption_failure` and
`on_anomalous_access` log at `warn!`; `on_threshold_breach` logs at
`error!`. All events target `key_vault::monitor`. Fields are
structured (`key_name`, `consecutive_failures`, `window_elapsed_ms`,
etc.) for easy filtering.

**Constructors:**

- `LogMonitor::new() -> Self`
- `LogMonitor::default()` — same.

Stateless; one instance can be shared across all vaults.

```rust
use key_vault::{KeyVaultBuilder, LogMonitor};
let _vault = KeyVaultBuilder::new().with_monitor(LogMonitor::new()).build();
```

<hr>

### `AuditSink` (trait, Layer 9)

Source: `src/audit/mod.rs`

Outbound channel for the vault's audit trail.

```rust,ignore
pub trait AuditSink: Send + Sync {
    fn on_event(&self, event: &AuditEvent);
}
```

**Contract:**

- **Non-blocking.** Sink calls must return promptly. Network / disk
  work belongs on a background worker.
- **No panics.** A panicking sink implementation is a bug in the
  implementation, not the vault.
- **No back-pressure.** If the sink is overloaded, shed events
  internally — never block the caller.
- **`Send + Sync`.** Sinks are shared across threads.

Built-in implementations: [`NoAudit`](#noaudit) (default),
[`LogAudit`](#logaudit) (feature `monitor-tracing`).

A blanket `impl AuditSink for Arc<dyn AuditSink>` lets callers pass
pre-wrapped sinks.

<hr>

### `AuditEvent`

Source: `src/audit/mod.rs`

`#[non_exhaustive]`. Single record in the vault's audit trail.

**Fields:**

- `pub timestamp: Duration` — since the Unix epoch, from the vault's
  `Clock`.
- `pub key_name: String` — never key bytes. Empty for one-shot
  `fragment` / `defragment`; `"<master>"` for master-unlock attempts.
- `pub kind: AccessKind` — discriminant of the operation.
- `pub thread_id: std::thread::ThreadId` — `std` builds only.
- `pub note: Cow<'static, str>` — caller-supplied free-text label.

<hr>

### `AccessKind`

Source: `src/audit/mod.rs`

```rust,ignore
#[non_exhaustive]
pub enum AccessKind {
    Register,
    Unregister,
    Read,
    Rotate,
    OneShotFragment,
    OneShotDefragment,
    MasterUnlockAttempt { matched: bool },
}
```

Implements `Display` for human-readable labels (`"register"`,
`"master-unlock-ok"` / `"master-unlock-fail"`, etc.).

<hr>

### `NoAudit`

Source: `src/audit/no_audit.rs`

Inert default. Discards every event. Always available. The vault
uses this when no sink is configured.

<hr>

### `LogAudit`

Source: `src/audit/log_audit.rs` · Feature: `monitor-tracing`

Emits structured `tracing` events at `info!` level on the
`key_vault::audit` target. Fields are structured (`key_name`,
`kind`, `thread_id`, `timestamp_ms_since_epoch`, `note`) for easy
filtering.

```rust
use key_vault::{KeyVaultBuilder, LogAudit};
let _vault = KeyVaultBuilder::new().with_audit_sink(LogAudit::new()).build();
```

<hr>

### `FailureContext`

Source: `src/monitor/mod.rs`

`#[non_exhaustive]`. Passed to `SecurityMonitor::on_decryption_failure`.

**Fields:**

- `pub key_name: String`
- `pub consecutive_failures: u32`
- `pub window_elapsed: Duration`
- `pub note: Cow<'static, str>`

<hr>

### `AccessContext`

Source: `src/monitor/mod.rs`

`#[non_exhaustive]`. Passed to `SecurityMonitor::on_anomalous_access`.

**Fields:**

- `pub key_name: String`
- `pub note: Cow<'static, str>`

<hr>

### `ThresholdContext`

Source: `src/monitor/mod.rs`

`#[non_exhaustive]`. Passed to `SecurityMonitor::on_threshold_breach`.

**Fields:**

- `pub key_name: String`
- `pub failures_in_window: u32`
- `pub window: Duration`
- `pub lockout_triggered: bool` — this breach started the lockout.
- `pub scope: LockoutScope` — (1.1) `LockoutScope::Vault` or
  `LockoutScope::Key`. `LockoutScope` is `#[non_exhaustive]`.

<hr>

### `tee::detect_tee_capabilities`

Source: `src/tee/mod.rs`

```rust
#[must_use]
pub fn detect_tee_capabilities() -> TeeCapabilities;
```

Probe the host platform for available Trusted Execution Environments.
Side-effect-free; suitable for calling at process startup. Reads a
handful of CPUID instructions on x86_64 and (on Linux) the DMI sysfs
vendor string. Never opens privileged files, loads drivers, or makes
network calls.

**Example:**

```rust
use key_vault::tee::{detect_tee_capabilities, Detection};

let caps = detect_tee_capabilities();
if caps.any_detected() {
    println!("TEE available: {caps}");
}
let sgx_present = matches!(caps.sgx, Detection::Detected);
```

<hr>

### `tee::TeeCapabilities`

Source: `src/tee/mod.rs`

`#[non_exhaustive]` snapshot of every TEE probe.

**Fields:**

- `pub sgx: Detection` — Intel SGX (CPUID.07H EBX[2] on x86_64; feature
  bit only, not whether SGX is enabled or usable).
- `pub tdx: Detection` — Intel TDX (CPUID.21H "IntelTDX    " signature).
- `pub sev: Detection` — AMD SEV (CPUID 0x8000001F EAX[1]).
- `pub sev_snp: Detection` — AMD SEV-SNP (CPUID 0x8000001F EAX[4]).
- `pub trustzone: Detection` — ARM TrustZone (always `Unknown` in 1.0).
- `pub secure_enclave: Detection` — Apple Secure Enclave
  (`Detected` on every `aarch64-apple-darwin` build; no hardware probe).
- `pub nitro: Detection` — AWS Nitro Enclaves (Linux DMI vendor is
  `Amazon EC2`, which is true on EC2 in general).

Detection is informational; it never changes what the vault does.

**Methods:**

- `any_detected(self) -> bool` — `true` if at least one probe positively
  confirmed a TEE. `Unknown` does not count.

`Display` produces a single-line summary suitable for logging.

<hr>

### `tee::Detection`

Source: `src/tee/mod.rs`

```rust
#[non_exhaustive]
pub enum Detection {
    Detected,
    NotDetected,
    Unknown,
}
```

`Unknown` is distinct from `NotDetected` — it means "this platform
can't be probed from userspace." Treating `Unknown` as
"not available" is the safe default for selecting fetchers.

**Methods:**

- `is_detected(self) -> bool` — `true` only for `Detected`.

`Display` prints `"detected"` / `"not detected"` / `"unknown"`.

<a href="#top">↑ TOP</a>

<hr>

## Examples

### Every optional layer turned on

```rust
use key_vault::{
    DynamicCodex, KeyVaultBuilder, RawKey, SelfReferenceDecoy,
};

# fn main() -> Result<(), key_vault::Error> {
let vault = KeyVaultBuilder::new()
    .normalize_with_blake3(true)
    .with_codex(DynamicCodex::new()?)
    .with_decoy(SelfReferenceDecoy)
    .build();

let raw = RawKey::new(b"my application key".to_vec());
let fragments = vault.fragment(&raw)?;
let recovered = vault.defragment(&fragments)?;
assert_eq!(recovered.len(), 32); // BLAKE3 normalization → 32 bytes
# Ok(())
# }
```

### Minimal vault (no normalization, no decoy, no codex)

```rust
use key_vault::{KeyVaultBuilder, RawKey};

# fn main() -> Result<(), key_vault::Error> {
let vault = KeyVaultBuilder::new()
    .normalize_with_blake3(false)
    .build();

let raw = RawKey::new(b"raw bytes here".to_vec());
let fragments = vault.fragment(&raw)?;
let recovered = vault.defragment(&fragments)?;
assert_eq!(recovered.len(), raw.len());
# Ok(())
# }
```

### Custom Layer-3 fragmenter selection with composition

```rust
use std::sync::Arc;
use key_vault::{
    FragmentStrategy, InterleavedFragmenter, LayeredFragmenter,
    RandomFragmenter, RawKey, StandardFragmenter,
};

# fn main() -> Result<(), key_vault::Error> {
// Route each fragmentation to one of three strategies.
let composite = LayeredFragmenter::new(vec![
    Arc::new(StandardFragmenter::with_chunk_range(2, 6)) as Arc<dyn FragmentStrategy>,
    Arc::new(InterleavedFragmenter::with_pool_factor(8)) as Arc<dyn FragmentStrategy>,
    Arc::new(RandomFragmenter::new()) as Arc<dyn FragmentStrategy>,
])?;

let raw = RawKey::new(vec![0u8; 64]);
let fragments = composite.fragment(&raw)?;
let recovered = composite.defragment(&fragments)?;
assert_eq!(recovered.len(), 64);
# Ok(())
# }
```

### Declarative codex (private build)

```rust
use key_vault::{KeyVaultBuilder, StaticCodex};

# fn main() -> Result<(), key_vault::Error> {
// Build-time-known swap table for a private deployment.
let codex = StaticCodex::from_swaps(&[
    (b'0', b'#'),
    (b'A', b'@'),
    (b'h', b'!'),
])?;

let vault = KeyVaultBuilder::new()
    .with_codex(codex)
    .build();
# let _ = vault;
# Ok(())
# }
```

### Custom `KeyFetch`

```rust
use std::borrow::Cow;
use key_vault::{Error, FetchContext, KeyFetch, RawKey, Result};

struct EnvironmentFetch {
    var_name: String,
}

impl KeyFetch for EnvironmentFetch {
    fn fetch(&self, _ctx: &FetchContext) -> Result<RawKey> {
        let value = std::env::var(&self.var_name).map_err(|_| {
            Error::Acquisition {
                source: Cow::Borrowed("env"),
                reason: format!("variable {} not set", self.var_name),
            }
        })?;
        Ok(RawKey::new(value.into_bytes()))
    }
    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("env")
    }
}
```

<a href="#top">↑ TOP</a>

<hr>

## API Safety

**Public-API guarantees in 1.1:**

| Guarantee | Verification |
|-----------|--------------|
| Zero `unsafe` in public API | Code review; the `unsafe` blocks are crate-private: `tee::x86_64::safe_cpuid_count`, the OS shims and buffers in `src/memory/` (`mlock`, `madvise`, `mmap` / `mprotect`, `VirtualLock` / `VirtualProtect`, WER), and the `no_std` spin lock in `src/sync.rs`. Every block has a `SAFETY` comment. |
| No key bytes leak via `Debug` | `KeyHandle` / `KeyId` / `RawKey` / `Fragments` all print `<redacted>` or `<opaque>`. 1024-handle sweep test in CI. |
| No key bytes in `Error` variants | All variants carry only sanitized prose. |
| Constant-time handle equality | `KeyHandle: subtle::ConstantTimeEq`; `PartialEq` routes through it. `Hash` consistent. |
| Zero-on-drop | Every `LockedBytes` (fragments, layout buffer, codex table) zeroizes its bytes before unlocking and freeing. `RawKey` zeroizes its whole allocation including spare capacity. The `with_key` scratch buffer is zeroed after every call. |
| mlock / VirtualLock + dump exclusion | Applied to every `LockedBytes` allocation and the `with_key` scratch buffer, with per-page reference counting so a page stays locked and excluded while any buffer on it is alive. Soft-fails when `RLIMIT_MEMLOCK` is exceeded. |
| Page protection (opt-in) | Protected keys' mappings are inaccessible between reads; tests check `/proc/self/maps` / `VirtualQuery` and that a direct read crashes a child process. |
| `RawKey` bytes exposed only on request | `RawKey::expose_secret()` (1.1) is the only public accessor. |
| Round-trip for every `FragmentStrategy` | 1000-iteration stress + per-strategy unit tests in CI. |
| Codex involution property | 256-byte sweep verified for `StaticCodex`, `DynamicCodex`, `FnCodex`, `IdentityCodex`. |

**Threat model.** See [`docs/SECURITY.md`](SECURITY.md) for the full
per-layer architecture and threat-model coverage.

<a href="#top">↑ TOP</a>

<hr>

## Notes

### What's not in 1.1

- **TPM / HSM acquisition**: `TpmFetch` is a placeholder that always
  errors.
- **Keyed normalization by default** and **master-unlock backoff by
  default**: both are available as options; making them the default
  changes behavior and is planned for 2.0.
- **A slow KDF** for normalization or the master verifier. Run
  passphrases through Argon2 or scrypt before registering them.
- **Windows ACL checks in `FileFetch`**: NTFS ACLs are trusted.
- **`MetricsMonitor` / `WebhookMonitor`**: not provided. Build a
  custom `SecurityMonitor` impl.
- **Master-key-as-KEK**: the master is an emergency-unlock
  credential only.
- **Constant-time `with_key`**: reassembly time depends on the
  chunk layout; only the master check and handle equality use
  `subtle::ConstantTimeEq`.

### Stability

`key-vault` follows the 1.0 stability contract in
[`STABILITY-1.0.md`](STABILITY-1.0.md): no breaking changes within 1.x.

### Cross-platform support

- **Linux**: x86_64, aarch64. `mlock`, `MADV_DONTDUMP`, `mmap` /
  `mprotect` via `libc`. AWS Nitro detection via DMI sysfs.
- **macOS**: x86_64, aarch64 (Apple Silicon). `mlock`, `mmap` /
  `mprotect` via `libc`; no per-page dump exclusion. Secure Enclave
  detection via target triple.
- **Windows**: x86_64. `VirtualLock`, `WerRegisterExcludedMemoryBlock`,
  `VirtualAlloc` / `VirtualProtect` via `windows-sys`. No Apple SE / AWS
  Nitro detection.
- **FreeBSD / DragonFly**: `MADV_NOCORE` for dump exclusion (compiled,
  not tested in CI).
- **`no_std`**: bare-metal targets such as `thumbv7em-none-eabihf`
  (built in CI).

CI exercises Linux, macOS and Windows on `stable` and pinned MSRV
`1.85.0`, plus the `no_std` build.

### Licensing

Apache-2.0 OR MIT, at your option. See [`LICENSE-APACHE`](../LICENSE-APACHE)
and [`LICENSE-MIT`](../LICENSE-MIT).

---

<sub>key-vault API Reference — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
