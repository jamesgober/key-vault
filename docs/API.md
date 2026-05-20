<h1 align="center">
    <b>key-vault</b>
    <br>
    <sub><sup>API REFERENCE</sup></sub>
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
    <i>Complete public-API reference for <code>key-vault</code> 0.7.0.</i>
    <br>
    <i>For the 9-layer architecture see <a href="SECURITY.md">SECURITY.md</a>.
    For a per-version change log see <a href="../CHANGELOG.md">CHANGELOG.md</a>.</i>
</p>

<hr>

## Installation

### Default installation

Add to `Cargo.toml`:

```toml
[dependencies]
key-vault = "0.7"
```

### Install via terminal

```bash
cargo add key-vault
```

### Minimum supported Rust version

**Rust 1.85** (edition 2024). Older toolchains will not build.

### Cargo features

| Feature | Default | Effect |
|---------|---------|--------|
| `std` | ✅ | Standard-library types. Required by the current implementation. |
| `mlock` | ✅ | `mlock` / `VirtualLock` page locking on `LockedBytes`. |
| `zeroize` | ✅ | `zeroize` integration; zero-on-drop on every key buffer. |
| `fragment-standard` | ✅ | `StandardFragmenter` (the default). |
| `decoy-self-ref` | ✅ | `SelfReferenceDecoy` (the recommended default). |
| `fetcher-keychain` |   | `KeychainFetch` via the `keyring` crate (0.7.0). |
| `codex` |   | Marker for the codex layer (currently informational; codex types are always available). |
| `monitor`, `audit` |   | Layer 8 / 9 integration (0.8.0). |
| `tee-detect` |   | TEE-capability detection (always available; this flag is informational). |
| `preset-balanced` |   | `std` + `mlock` + `zeroize` + `fragment-standard` + `decoy-self-ref`. |
| `preset-paranoid` |   | All defaults + every fragmenter + all decoys + codex + monitor + audit + TEE detect. |
| `preset-fast` |   | `std` + `fragment-standard` + `decoy-random` (no `mlock`, no zeroize). |

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

The minimal, on-by-default stack: BLAKE3 normalization + `StandardFragmenter`
+ `SelfReferenceDecoy` + `DynamicCodex` + mlock + zero-on-drop +
constant-time handle equality.

```rust
use key_vault::{DynamicCodex, KeyVaultBuilder, RawKey, SelfReferenceDecoy};
use key_vault::tee::detect_tee_capabilities;

# fn main() -> Result<(), key_vault::Error> {
// Build a vault wiring up Layers 2 (mlock), 3 (StandardFragmenter),
// 4 (SelfReferenceDecoy), 5 (DynamicCodex), 6 (ConstantTimeEq), 7 (zero-on-drop).
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
| `LockedOut` | A `SecurityMonitor` threshold lockout is in effect. |
| `MemoryLock(String)` | mlock/VirtualLock operation failed at the OS layer. |
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
vault, and the fragmenter. **`RawKey` exposes no method that returns
`&[u8]` to outside callers** — only its `len()` is observable from
outside the crate. `Debug` redacts contents.

**Constructors:**

- `RawKey::new(bytes: Vec<u8>) -> Self` — wrap an existing buffer.

**Read accessors:**

- `len(&self) -> usize` — length in bytes.
- `is_empty(&self) -> bool` — whether the buffer is zero-length.

`Debug` prints `RawKey { len, bytes: "<redacted>" }`.

**Example:**

```rust
use key_vault::RawKey;

let key = RawKey::new(b"my application key".to_vec());
assert_eq!(key.len(), 18);
assert!(!key.is_empty());
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

Opaque token returned by `FragmentStrategy::fragment` and consumed by
`FragmentStrategy::defragment`. Holds the chunks and the locked layout
buffer; storage layout is intentionally a black box from the public-API
side.

**Public accessors:**

- `chunk_count(&self) -> usize` — number of chunks (real + decoy if
  configured).

`Debug` prints `Fragments { chunks: N, total_len: M, contents: "<opaque>" }`.

**Example:**

```rust
use key_vault::{KeyVaultBuilder, RawKey};

# fn main() -> Result<(), key_vault::Error> {
let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
let raw = RawKey::new(vec![0u8; 32]);
let fragments = vault.fragment(&raw)?;
assert!(fragments.chunk_count() >= 4); // 32 / 8 (max chunk size) = 4
# Ok(())
# }
```

<hr>

### `KeyVault`

Source: `src/vault/mod.rs`

The vault itself. `Arc`-backed, `Clone`, `Send + Sync`. Construct via
[`KeyVaultBuilder`](#keyvaultbuilder).

**Public methods:**

- `fragment(&self, key: &RawKey) -> Result<Fragments>` — pipeline:
  optional BLAKE3 normalize → optional codex encode → fragmenter.fragment.
- `defragment(&self, fragments: &Fragments) -> Result<RawKey>` —
  inverse: fragmenter.defragment → optional codex decode.
- `is_locked_out(&self) -> bool` — `true` if a `SecurityMonitor`
  threshold breach has put the vault in lock-out state (0.8+).
- `config(&self) -> &VaultConfig` — snapshot of the configuration.

**Example:**

```rust
use key_vault::{KeyVault, KeyVaultBuilder, RawKey};

# fn main() -> Result<(), key_vault::Error> {
let vault: KeyVault = KeyVaultBuilder::new()
    .normalize_with_blake3(false)
    .build();

let raw = RawKey::new(b"my application key".to_vec());
let fragments = vault.fragment(&raw)?;
let recovered = vault.defragment(&fragments)?;
assert_eq!(recovered.len(), raw.len());
assert!(!vault.is_locked_out());
# Ok(())
# }
```

<hr>

### `KeyVaultBuilder`

Source: `src/vault/mod.rs`

Fluent builder for [`KeyVault`](#keyvault).

**Constructors:**

- `KeyVaultBuilder::new() -> Self` — default-on configuration:
  normalization enabled, default-range `StandardFragmenter`, no decoy,
  no codex.
- `KeyVaultBuilder::default()` — same as `new()`.

**Builder methods:**

- `normalize_with_blake3(self, enabled: bool) -> Self` — toggle BLAKE3
  input normalization. Default `true`.
- `with_chunk_range(self, min: usize, max: usize) -> Self` — customize
  the fragmenter chunk-size range. Replaces any previously-set decoy.
- `with_decoy<D: DecoyStrategy + 'static>(self, decoy: D) -> Self` —
  attach a Layer-4 decoy strategy.
- `with_codex<C: Codex + 'static>(self, codex: C) -> Self` — attach a
  Layer-5 codex.
- `build(self) -> KeyVault` — finalize. Infallible.

**Example:**

```rust
use key_vault::{DynamicCodex, KeyVaultBuilder, SelfReferenceDecoy};

# fn main() -> Result<(), key_vault::Error> {
let vault = KeyVaultBuilder::new()
    .normalize_with_blake3(true)
    .with_chunk_range(2, 6)
    .with_decoy(SelfReferenceDecoy)
    .with_codex(DynamicCodex::new()?)
    .build();
# let _ = vault;
# Ok(())
# }
```

<hr>

### `VaultConfig`

Source: `src/vault/mod.rs`

`#[non_exhaustive]` configuration struct exposed by `KeyVault::config()`.

**Fields:**

- `pub key_normalization: bool` — whether BLAKE3 normalization is on.

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

Four built-in implementations shipped in 0.7.0:
[`EnvFetch`](#envfetch), [`FileFetch`](#filefetch),
[`KeychainFetch`](#keychainfetch), [`TpmFetch`](#tpmfetch). Each is
feature-gated.

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

Reads key bytes from a file on disk. **On Unix, rejects files with
permissions stricter than `0o600` by default** (any bit in `0o077`
set). Windows trusts NTFS ACLs.

**Constructors:**

- `FileFetch::new(path: impl Into<PathBuf>) -> Self` — strict perms on.

**Builder methods:**

- `allow_loose_perms(self) -> Self` — disable the Unix permission gate
  (not recommended outside of tests).

**Read accessors:**

- `path(&self) -> &Path` — the configured path. Used in audit / error
  attribution.

**Threat profile.** Higher than `EnvFetch` (POSIX permissions confine
access). Lower than `KeychainFetch` (bytes live on disk in cleartext).
Pair with OS-level disk encryption (LUKS / FileVault / BitLocker) for
encryption-at-rest. AEAD-encrypted file format is on the post-1.0
backlog.

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
- **Linux** — Secret Service (gnome-keyring, KWallet)

**Constructors:**

- `KeychainFetch::new(service: impl Into<String>, account: impl Into<String>) -> Self`

`service` is the application/namespace name; `account` is the entry
identifier within that service. Both appear in failure messages.

`keyring::Error` variants are mapped to short, discriminant-only
strings — platform-specific error details never appear in `Error`
messages.

**Threat profile.** Highest-security general-purpose backend short of
dedicated hardware. The OS confines access to the user account (and on
macOS to the signing identity).

**Example:**

```rust,no_run
use key_vault::{FetchContext, KeyFetch, KeychainFetch};

# fn main() -> Result<(), key_vault::Error> {
let fetcher = KeychainFetch::new("my-app", "primary-key");
let raw = fetcher.fetch(&FetchContext::new("primary"))?;
# let _ = raw;
# Ok(())
# }
```

<hr>

### `TpmFetch`

Source: `src/fetcher/tpm.rs` · Feature: `fetcher-tpm`

TPM 2.0 fetcher — **detection-only in 1.0**. Always returns
`Error::Acquisition` with a documented message. Full integration
(`tss-esapi` wiring, unsealing, attestation) arrives in 1.x.

Use [`tee::detect_tee_capabilities()`](#teedetect_tee_capabilities) to
probe for TPM presence at startup. `TpmFetch` itself can be wired into
composite fetcher chains today so the 1.x upgrade is automatic.

**Constructors:**

- `TpmFetch` is a unit struct — construct directly: `TpmFetch`.

**Example:**

```rust
use key_vault::{FetchContext, KeyFetch, TpmFetch};

let err = TpmFetch.fetch(&FetchContext::new("k")).unwrap_err();
// 1.0 ships detection only; full integration in the 1.x line.
assert!(format!("{err}").contains("TPM"));
```

<hr>

### `FragmentStrategy` (trait, Layer 3)

Source: `src/fragment/mod.rs`

Splits a `RawKey` into a `Fragments` token and reassembles it.

```rust
pub trait FragmentStrategy: Send + Sync {
    fn fragment(&self, key: &RawKey) -> Result<Fragments>;
    fn defragment(&self, fragments: &Fragments) -> Result<RawKey>;
    fn describe(&self) -> Cow<'_, str>;
}
```

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
correctly.

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

Generates filler bytes that surround real key fragments.

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
to the key's — strongest indistinguishability, **recommended default**.

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

Byte-wise involution applied to all stored bytes.

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

Built-in implementations (`NoMonitor`, `LogMonitor`, `MetricsMonitor`,
`WebhookMonitor`, `CompositeMonitor`) arrive in 0.8.0.

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
- `pub lockout_triggered: bool`

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

- `pub sgx: Detection` — Intel SGX (CPUID.07H EBX[2] on x86_64).
- `pub tdx: Detection` — Intel TDX (CPUID.21H "IntelTDX    " signature).
- `pub sev: Detection` — AMD SEV (CPUID 0x8000001F EAX[1]).
- `pub sev_snp: Detection` — AMD SEV-SNP (CPUID 0x8000001F EAX[4]).
- `pub trustzone: Detection` — ARM TrustZone (always `Unknown` in 1.0).
- `pub secure_enclave: Detection` — Apple Secure Enclave
  (`Detected` on `aarch64-apple-darwin`).
- `pub nitro: Detection` — AWS Nitro Enclaves (Linux DMI vendor).

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

### Full default stack (every shipped layer)

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

**Public-API guarantees in 0.6.0:**

| Guarantee | Verification |
|-----------|--------------|
| Zero `unsafe` in public API | Code review; the only `unsafe` blocks are in `tee::x86_64::safe_cpuid_count` and the `mlock`/`VirtualLock` shims in `src/memory/`, all crate-private. |
| No key bytes leak via `Debug` | `KeyHandle` / `KeyId` / `RawKey` / `Fragments` all print `<redacted>` or `<opaque>`. 1024-handle sweep test in CI. |
| No key bytes in `Error` variants | All variants carry only sanitized prose. |
| Constant-time handle equality | `KeyHandle: subtle::ConstantTimeEq`; `PartialEq` routes through it. `Hash` consistent. |
| Zero-on-drop | Every `LockedBytes` (fragments, layout buffer, codex table) volatile-zeroes its bytes before unlocking and freeing. |
| mlock / VirtualLock | Applied unconditionally to every `LockedBytes` allocation. Soft-fails (records `is_locked = false`) when `RLIMIT_MEMLOCK` is exceeded. |
| `RawKey` bytes not exposed | `RawKey::as_bytes()` is `pub(crate)`; outside callers see only `len()`. |
| Round-trip for every `FragmentStrategy` | 1000-iteration stress + per-strategy unit tests in CI. |
| Codex involution property | 256-byte sweep verified for `StaticCodex`, `DynamicCodex`, `FnCodex`, `IdentityCodex`. |

**Threat model.** See [`docs/SECURITY.md`](SECURITY.md) for the
comprehensive per-layer architecture and threat-model coverage.

<a href="#top">↑ TOP</a>

<hr>

## Notes

### What's not in 0.7.0 (yet)

- **Layer 8 monitor implementations** (`NoMonitor`, `LogMonitor`,
  `MetricsMonitor`, `WebhookMonitor`, `CompositeMonitor`) — planned for
  0.8.0. Custom `SecurityMonitor` impls work today.
- **Layer 9 audit logging** — planned for 0.8.0.
- **Multi-key vaults, key rotation, master key recovery** — planned for
  0.9.0. Today's `KeyVault::fragment` / `defragment` operate per-call
  without a named-key registry.
- **Criterion benchmarks** — planned for 0.10.0. Performance targets in
  the README are 1.0 design goals, not measurements.
- **`frag_len` / `frag_symbols` configuration knobs** — deferred to a
  later phase.

### Stability

`key-vault` is pre-1.0. The public API surface listed above will receive
additions in every minor release through 0.9.x; renames and removals
are possible but flagged in the CHANGELOG. The 1.0.0 stability contract
takes effect at the v1.0.0 tag.

### Cross-platform support

- **Linux**: x86_64, aarch64. mlock via `libc`. AWS Nitro detection via
  DMI sysfs.
- **macOS**: x86_64, aarch64 (Apple Silicon). mlock via `libc`. Secure
  Enclave detection via target triple.
- **Windows**: x86_64. VirtualLock via `windows-sys`. No Apple SE / AWS
  Nitro detection.

CI exercises every combination on `stable` and pinned MSRV `1.85.0`.

### Licensing

Apache-2.0 OR MIT, at your option. See [`LICENSE-APACHE`](../LICENSE-APACHE)
and [`LICENSE-MIT`](../LICENSE-MIT).

---

<sub>key-vault API Reference — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
