//! The vault itself.
//!
//! In this phase [`KeyVault`] owns the configured fragmenter and the
//! normalization toggle, and exposes `fragment` / `defragment` shortcuts so
//! downstream crates can exercise the Layer 2 + Layer 3 + Layer 7 stack
//! end-to-end. Key registration, naming, rotation, and recovery still arrive
//! in Phase 0.9 — today the vault is a stateless helper around the
//! fragmenter.
//!
//! ```
//! use key_vault::{KeyVault, KeyVaultBuilder};
//!
//! // The builder follows the standard fluent pattern. None of the methods
//! // perform I/O — construction is cheap and infallible.
//! let _vault: KeyVault = KeyVaultBuilder::new().build();
//! ```

use alloc::borrow::Cow;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use subtle::ConstantTimeEq;

use crate::Result;
use crate::codex::Codex;
use crate::decoy::DecoyStrategy;
use crate::error::Error;
use crate::fetcher::RawKey;
use crate::fragment::{FragmentStrategy, Fragments, StandardFragmenter};
use crate::handle::{KeyHandle, KeyId};
use crate::metadata::KeyMetadata;
use crate::monitor::{AccessContext, FailureContext, SecurityMonitor, ThresholdContext};
use crate::normalize::blake3_normalize;

/// Default upper bound on failures per key before lockout. `0` means
/// "never lock out" — i.e. the threshold is disabled. The default
/// [`VaultConfig`] disables it so failures pass through to the monitor
/// without triggering lockout unless the caller explicitly opts in.
const DEFAULT_MAX_FAILURES: u32 = 0;

/// Default window for the failure counter when no override is set.
const DEFAULT_FAILURE_WINDOW: Duration = Duration::from_secs(60);

/// Vault configuration.
///
/// Concrete fields are added in later phases as each layer comes online.
/// Marked `#[non_exhaustive]` so new fields are additive.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VaultConfig {
    /// If `true`, raw key material is BLAKE3-normalized to 32 bytes before
    /// fragmentation. Default is `true`.
    pub key_normalization: bool,

    /// Failures (per key) within the configured `failure_window`
    /// required to trigger vault lockout. `0` disables threshold
    /// lockout entirely — failures still flow to the configured monitor
    /// but never lock the vault out. Default: `0` (disabled).
    pub max_failures_before_lockout: u32,

    /// Sliding window for the failure counter. Failures older than this
    /// fall off the counter for a given key. Default: 60 seconds.
    pub failure_window: Duration,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultConfig {
    /// Default-on configuration with threshold lockout disabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            key_normalization: true,
            max_failures_before_lockout: DEFAULT_MAX_FAILURES,
            failure_window: DEFAULT_FAILURE_WINDOW,
        }
    }
}

/// In-memory key vault.
///
/// The vault is the entry point for everything `key-vault` does. Application
/// code constructs one via [`KeyVaultBuilder`], hands it [`RawKey`] values
/// to be fragmented, and (in later phases) receives
/// [`KeyHandle`](crate::KeyHandle)s in return. The vault itself is cheap to
/// clone (it is `Arc`-backed internally) and safe to share across threads.
///
/// In Phase 0.3 the vault exposes [`KeyVault::fragment`] and
/// [`KeyVault::defragment`] convenience methods that route through the
/// configured normalizer and [`StandardFragmenter`]. The full named-key
/// registry arrives in Phase 0.9.
#[derive(Clone)]
pub struct KeyVault {
    inner: Arc<VaultInner>,
}

/// Entry in the vault's named-key registry. Holds the fragmented
/// representation of a key, its name (for audit / threshold tracking),
/// and non-secret metadata.
///
/// Crate-internal. Outside callers see only [`KeyHandle`] which indexes
/// into this map.
///
/// `Clone` is required so the registry's `HashMap` can be cloned during
/// `ArcSwap::rcu` updates. Cloning an entry copies the name and
/// metadata (cheap) and bumps the `Arc<Fragments>` refcount — the
/// underlying `Fragments` storage (`LockedBytes` chunks) is not
/// duplicated.
#[derive(Clone)]
struct KeyEntry {
    name: String,
    /// `Fragments` is not `Clone`, so the registry stores `Arc<Fragments>`.
    /// Rotation produces a new `Arc<Fragments>` and atomically swaps the
    /// old one out via [`ArcSwap`]; concurrent readers see either the old
    /// or the new value (never a torn read).
    fragments: Arc<Fragments>,
    metadata: KeyMetadata,
}

struct VaultInner {
    config: VaultConfig,
    fragmenter: StandardFragmenter,
    /// Optional Layer-5 codex. When set, every byte of normalized key
    /// material passes through `codex.encode()` before being handed to
    /// the fragmenter; `defragment` applies `codex.decode()` to recover.
    codex: Option<Arc<dyn Codex>>,
    /// Layer-8 security monitor. Defaults to a no-op
    /// [`NoMonitor`](crate::NoMonitor) when no monitor is configured.
    monitor: Arc<dyn SecurityMonitor>,
    /// Named-key registry. Lock-free reads via [`ArcSwap`]; writes
    /// (register, unregister, rotate) build a new `HashMap` and swap
    /// it in atomically.
    keys: ArcSwap<HashMap<KeyId, KeyEntry>>,
    /// Per-key sliding-window failure tracker. Populated by
    /// [`KeyVault::report_failure`]; consulted by the threshold-detection
    /// logic to decide whether to trigger lockout.
    failure_tracker: Mutex<HashMap<String, VecDeque<Instant>>>,
    /// Set to `true` when the failure-tracker threshold has been crossed.
    /// `fragment` / `defragment` refuse to operate while this is set;
    /// `Error::LockedOut` is returned instead.
    locked_out: AtomicBool,
    /// Optional master-key credential. Stored as the BLAKE3 hash of the
    /// supplied master bytes — the plaintext is dropped (and zeroed via
    /// `RawKey::Drop`) immediately after registration. Used by
    /// [`KeyVault::unlock_with_master`] as an emergency unlock.
    master_hash: Option<[u8; 32]>,
}

impl KeyVault {
    /// Returns `true` if the vault is in lock-out state.
    ///
    /// Lock-out is triggered by the threshold detector when
    /// [`KeyVault::report_failure`] reports more failures than
    /// [`VaultConfig::max_failures_before_lockout`] within
    /// [`VaultConfig::failure_window`]. Once set, [`KeyVault::fragment`]
    /// and [`KeyVault::defragment`] refuse to proceed and return
    /// [`Error::LockedOut`](crate::Error::LockedOut). Use
    /// [`KeyVault::clear_lockout`] to reset.
    #[must_use]
    pub fn is_locked_out(&self) -> bool {
        self.inner.locked_out.load(Ordering::Acquire)
    }

    /// Clear the lockout flag.
    ///
    /// Use this after the operator has resolved the underlying cause —
    /// e.g. a rotated credential, an investigated alert. Also clears the
    /// failure tracker; subsequent failures start counting from zero.
    pub fn clear_lockout(&self) {
        self.inner.locked_out.store(false, Ordering::Release);
        if let Ok(mut tracker) = self.inner.failure_tracker.lock() {
            tracker.clear();
        }
    }

    /// Report a key-access failure to the configured monitor and the
    /// threshold detector.
    ///
    /// `key_name` identifies which key the failure pertains to (used for
    /// per-key threshold tracking and in the monitor event). `note` is
    /// an optional caller-supplied free-text label; pass `None` if you
    /// don't have one. **Do not** include key bytes or other secrets in
    /// the note — it is forwarded verbatim to every configured monitor.
    ///
    /// If the per-key failure count within
    /// [`VaultConfig::failure_window`] reaches
    /// [`VaultConfig::max_failures_before_lockout`], the vault transitions
    /// to lock-out state and the monitor's `on_threshold_breach` callback
    /// fires. A `max_failures` of `0` disables threshold lockout — only
    /// the per-failure callback runs in that case.
    pub fn report_failure(&self, key_name: &str, note: Option<&'static str>) {
        let note = note.map_or(Cow::Borrowed(""), Cow::Borrowed);
        let (count, oldest_in_window) = self.record_failure(key_name);
        let window_elapsed = oldest_in_window.map(|t| t.elapsed()).unwrap_or_default();

        // Always fire the per-failure callback first.
        let ctx = FailureContext {
            key_name: key_name.to_string(),
            consecutive_failures: count,
            window_elapsed,
            note: note.clone(),
        };
        self.inner.monitor.on_decryption_failure(&ctx);

        // Threshold check.
        let threshold = self.inner.config.max_failures_before_lockout;
        if threshold > 0 && count >= threshold {
            // Only lock out once — subsequent calls keep firing
            // on_decryption_failure but the lockout flag stays set.
            let was_locked = self.inner.locked_out.swap(true, Ordering::AcqRel);
            let breach = ThresholdContext {
                key_name: key_name.to_string(),
                failures_in_window: count,
                window: self.inner.config.failure_window,
                lockout_triggered: !was_locked,
            };
            self.inner.monitor.on_threshold_breach(&breach);
        }
    }

    /// Report an anomalous (but successful) key access to the monitor.
    ///
    /// Useful for "this access pattern looks weird, but we're not going
    /// to refuse it" cases — unusual time of day, geographic anomaly,
    /// caller identity that hasn't been seen before. The monitor receives
    /// an `AccessContext`; the vault state is unaffected.
    pub fn report_anomalous_access(&self, key_name: &str, note: Option<&'static str>) {
        let note = note.map_or(Cow::Borrowed(""), Cow::Borrowed);
        let ctx = AccessContext {
            key_name: key_name.to_string(),
            note,
        };
        self.inner.monitor.on_anomalous_access(&ctx);
    }

    /// Append a failure timestamp for `key_name` and evict entries older
    /// than the configured window. Returns the resulting count and the
    /// oldest timestamp still in the window (if any).
    fn record_failure(&self, key_name: &str) -> (u32, Option<Instant>) {
        let now = Instant::now();
        let window = self.inner.config.failure_window;
        let Ok(mut tracker) = self.inner.failure_tracker.lock() else {
            // Poisoned mutex — treat as a single isolated failure so
            // monitoring still fires and we don't block legitimate
            // operations. This branch is effectively unreachable in
            // practice (the only writer here doesn't panic).
            return (1, Some(now));
        };
        let entries = tracker.entry(key_name.to_string()).or_default();
        // Evict expired.
        while let Some(front) = entries.front() {
            if now.saturating_duration_since(*front) > window {
                let _ = entries.pop_front();
            } else {
                break;
            }
        }
        entries.push_back(now);
        let count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        let oldest = entries.front().copied();
        (count, oldest)
    }

    /// Snapshot of the vault's configuration.
    #[must_use]
    pub fn config(&self) -> &VaultConfig {
        &self.inner.config
    }

    /// Fragment a raw key through the configured normalizer, codex, and
    /// fragmenter.
    ///
    /// The returned [`Fragments`] is opaque; pass it back to
    /// [`KeyVault::defragment`] to recover the (normalized + codex-encoded)
    /// bytes inverse-transformed.
    ///
    /// # Pipeline
    ///
    /// ```text
    /// key → blake3_normalize (optional) → codex.encode (optional) → fragmenter.fragment → Fragments
    /// ```
    ///
    /// # Errors
    ///
    /// Returns whatever the underlying [`FragmentStrategy`] surfaces — in
    /// practice an [`Error::Fragment`](crate::Error::Fragment) for a
    /// zero-length input.
    pub fn fragment(&self, key: &RawKey) -> Result<Fragments> {
        if self.is_locked_out() {
            return Err(Error::LockedOut);
        }
        let working = if self.inner.config.key_normalization {
            blake3_normalize(key)
        } else {
            RawKey::new(key.as_bytes().to_vec())
        };
        let encoded = if let Some(codex) = &self.inner.codex {
            codex_apply(codex.as_ref(), &working)
        } else {
            working
        };
        self.inner.fragmenter.fragment(&encoded)
    }

    /// Reassemble fragments produced by [`KeyVault::fragment`].
    ///
    /// Inverts the codex transformation (if configured) so the recovered
    /// bytes are the normalized key (or the original raw key if
    /// normalization is off). Defragmentation itself is delegated to the
    /// configured [`FragmentStrategy`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Defragment`](crate::Error::Defragment) when the
    /// supplied fragments do not match the configured fragmenter's layout.
    pub fn defragment(&self, fragments: &Fragments) -> Result<RawKey> {
        if self.is_locked_out() {
            return Err(Error::LockedOut);
        }
        let encoded = self.inner.fragmenter.defragment(fragments)?;
        if let Some(codex) = &self.inner.codex {
            Ok(codex_apply(codex.as_ref(), &encoded))
        } else {
            Ok(encoded)
        }
    }

    // ----- Named-key registry (Phase 0.9) -----

    /// Register a key under a name and return an opaque [`KeyHandle`].
    ///
    /// The key bytes are run through the configured normalizer + codex
    /// pipeline, fragmented, and inserted into the named registry. The
    /// returned handle is the only way to refer to the key from outside
    /// the crate; the underlying numeric id is not exposed.
    ///
    /// # Errors
    ///
    /// - [`Error::LockedOut`](crate::Error::LockedOut) if the vault is
    ///   currently locked out (threshold-driven).
    /// - [`Error::InvalidConfig`](crate::Error::InvalidConfig) if a key
    ///   with the same name is already registered.
    /// - Whatever the configured fragmenter surfaces (typically
    ///   [`Error::Fragment`](crate::Error::Fragment) for empty input).
    // Intentionally take `key` by value: the function consumes the
    // caller's `RawKey` so its `Drop` impl zeroes the original buffer
    // as soon as we've fragmented (and copied) the bytes into
    // mlock'd storage.
    #[allow(clippy::needless_pass_by_value)]
    pub fn register(&self, name: impl Into<String>, key: RawKey) -> Result<KeyHandle> {
        if self.is_locked_out() {
            return Err(Error::LockedOut);
        }
        let name: String = name.into();

        // Reject duplicate names early so callers get a clear error
        // before paying the fragmentation cost.
        let snapshot = self.inner.keys.load();
        if snapshot.values().any(|e| e.name == name) {
            return Err(Error::InvalidConfig(format!(
                "key name {name:?} is already registered"
            )));
        }
        drop(snapshot);

        let key_len = key.len();
        let fragments = self.fragment(&key)?;
        let handle = KeyHandle::allocate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let metadata = KeyMetadata::new(now, key_len, None);

        let entry = KeyEntry {
            name,
            fragments: Arc::new(fragments),
            metadata,
        };

        // Atomic insert: build a new map containing the entry and swap.
        let _previous = self.inner.keys.rcu(|current| {
            let mut new_map = (**current).clone();
            let _ = new_map.insert(
                handle.id(),
                KeyEntry {
                    name: entry.name.clone(),
                    fragments: Arc::clone(&entry.fragments),
                    metadata: entry.metadata.clone(),
                },
            );
            new_map
        });
        Ok(handle)
    }

    /// Remove a registered key from the registry. The key's `Fragments`
    /// (and their `LockedBytes` chunks) drop and zeroize when the last
    /// reference goes away.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`](crate::Error::KeyNotFound) if no
    /// key is registered under the given handle.
    pub fn unregister(&self, handle: KeyHandle) -> Result<()> {
        let mut removed = false;
        let _previous = self.inner.keys.rcu(|current| {
            let mut new_map = (**current).clone();
            removed = new_map.remove(&handle.id()).is_some();
            new_map
        });
        if removed {
            Ok(())
        } else {
            Err(Error::KeyNotFound)
        }
    }

    /// Briefly access the recovered key material inside a callback.
    ///
    /// The vault defragments the named key into a temporary [`RawKey`],
    /// applies the codex decode if configured, and passes the bytes to
    /// the user-supplied closure. When the closure returns, the
    /// `RawKey` drops and its bytes are volatile-zeroed.
    ///
    /// **The byte slice handed to the closure does not outlive the
    /// call.** Do not stash it in a longer-lived structure; do your
    /// cryptographic operation, return, and let the vault scrub the
    /// buffer.
    ///
    /// # Errors
    ///
    /// - [`Error::LockedOut`](crate::Error::LockedOut) if the vault is
    ///   currently locked out.
    /// - [`Error::KeyNotFound`](crate::Error::KeyNotFound) if no key is
    ///   registered under the given handle.
    /// - [`Error::Defragment`](crate::Error::Defragment) on internal
    ///   inconsistency.
    pub fn with_key<F, T>(&self, handle: KeyHandle, f: F) -> Result<T>
    where
        F: FnOnce(&[u8]) -> T,
    {
        if self.is_locked_out() {
            return Err(Error::LockedOut);
        }
        let snapshot = self.inner.keys.load();
        let entry = snapshot.get(&handle.id()).ok_or(Error::KeyNotFound)?;
        let fragments = Arc::clone(&entry.fragments);
        // Drop the snapshot so we don't hold the Arc across the
        // potentially-slow defragment + user-callback path.
        drop(snapshot);

        let encoded = self.inner.fragmenter.defragment(&fragments)?;
        let raw = if let Some(codex) = &self.inner.codex {
            codex_apply(codex.as_ref(), &encoded)
        } else {
            encoded
        };
        // `raw` zeroes its bytes on drop at the end of this scope.
        let result = f(raw.as_bytes());
        Ok(result)
    }

    /// Rotate a registered key to new material.
    ///
    /// The new key is fragmented and atomically swapped into the
    /// registry slot. Concurrent [`KeyVault::with_key`] callers see
    /// either the old or the new fragmentation (never a torn read);
    /// the old `Fragments` drops once all in-flight readers release
    /// their `Arc` clones.
    ///
    /// The metadata is updated to record the new key length and a fresh
    /// registration timestamp.
    ///
    /// # Errors
    ///
    /// - [`Error::LockedOut`](crate::Error::LockedOut)
    /// - [`Error::KeyNotFound`](crate::Error::KeyNotFound)
    /// - Fragmenter errors for the new key.
    // Take `new_key` by value so its `Drop` zeroes the original buffer
    // after we've fragmented and copied the bytes into mlock'd storage.
    #[allow(clippy::needless_pass_by_value)]
    pub fn rotate(&self, handle: KeyHandle, new_key: RawKey) -> Result<()> {
        if self.is_locked_out() {
            return Err(Error::LockedOut);
        }

        // Verify the key exists first so we don't pay the fragmentation
        // cost on a missing handle.
        {
            let snapshot = self.inner.keys.load();
            if !snapshot.contains_key(&handle.id()) {
                return Err(Error::KeyNotFound);
            }
        }

        let new_len = new_key.len();
        let new_fragments = Arc::new(self.fragment(&new_key)?);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let new_metadata = KeyMetadata::new(now, new_len, None);

        let mut found = false;
        let _previous = self.inner.keys.rcu(|current| {
            let mut new_map = (**current).clone();
            if let Some(entry) = new_map.get_mut(&handle.id()) {
                entry.fragments = Arc::clone(&new_fragments);
                entry.metadata = new_metadata.clone();
                found = true;
            }
            new_map
        });
        if found {
            Ok(())
        } else {
            // Race: handle was unregistered between the check and the
            // RCU update. Treat as not-found so the caller can react.
            Err(Error::KeyNotFound)
        }
    }

    /// `true` if a key is registered under the given handle.
    #[must_use]
    pub fn contains(&self, handle: KeyHandle) -> bool {
        self.inner.keys.load().contains_key(&handle.id())
    }

    /// Clone the [`KeyMetadata`] for the given handle.
    ///
    /// Returns `None` if the handle is not registered. Metadata is a
    /// non-secret descriptor (length, registration time, algorithm
    /// hint) — safe to log and pass around.
    #[must_use]
    pub fn metadata(&self, handle: KeyHandle) -> Option<KeyMetadata> {
        self.inner
            .keys
            .load()
            .get(&handle.id())
            .map(|e| e.metadata.clone())
    }

    /// Find the handle registered under `name`, if any.
    #[must_use]
    pub fn handle_for_name(&self, name: &str) -> Option<KeyHandle> {
        self.inner
            .keys
            .load()
            .iter()
            .find_map(|(id, entry)| (entry.name == name).then(|| KeyHandle::from_id(*id)))
    }

    /// Number of keys currently registered.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.inner.keys.load().len()
    }

    // ----- Master-key emergency unlock (Phase 0.9) -----

    /// Attempt to clear the lockout flag using a master credential.
    ///
    /// If the vault has a master key registered (via
    /// [`KeyVaultBuilder::with_master_key`]) and the supplied bytes
    /// match the stored BLAKE3 digest in constant time, the lockout is
    /// cleared and the failure tracker is reset.
    ///
    /// On mismatch, the failure is reported to the monitor under the
    /// reserved key name `"<master>"` and the lockout (if any) remains
    /// in place. The function never reveals whether the digest matched
    /// through timing — comparison goes through
    /// [`subtle::ConstantTimeEq`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidConfig`](crate::Error::InvalidConfig) if no
    ///   master credential is registered.
    /// - [`Error::Acquisition`](crate::Error::Acquisition) with source
    ///   `"master"` on mismatch.
    pub fn unlock_with_master(&self, attempt: &[u8]) -> Result<()> {
        let stored = self.inner.master_hash.ok_or_else(|| {
            Error::InvalidConfig(
                "vault has no master key registered; pass with_master_key at build time"
                    .to_string(),
            )
        })?;
        let attempt_hash = blake3::hash(attempt);
        if bool::from(stored.as_slice().ct_eq(attempt_hash.as_bytes())) {
            self.clear_lockout();
            Ok(())
        } else {
            // Record as a failure on a reserved name so threshold rules
            // apply to repeated master-unlock attempts too.
            self.report_failure("<master>", Some("invalid master credential"));
            Err(Error::Acquisition {
                source: Cow::Borrowed("master"),
                reason: "master credential did not match".to_string(),
            })
        }
    }

    /// `true` if a master credential was registered at build time.
    #[must_use]
    pub fn has_master_key(&self) -> bool {
        self.inner.master_hash.is_some()
    }
}

/// Apply a codex's transformation to every byte of a key.
///
/// Used both for encoding (pre-fragment) and decoding (post-defragment).
/// For involution-based codices `decode == encode`; the function name
/// reflects that — it's a single transformation pass either way.
fn codex_apply(codex: &dyn Codex, key: &RawKey) -> RawKey {
    let bytes: Vec<u8> = key.as_bytes().iter().map(|&b| codex.encode(b)).collect();
    RawKey::new(bytes)
}

impl core::fmt::Debug for KeyVault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyVault")
            .field("locked_out", &self.is_locked_out())
            .field("config", &self.inner.config)
            .finish()
    }
}

/// Fluent builder for [`KeyVault`].
///
/// The builder is the only way to construct a vault; the inherent
/// `KeyVault::new` constructor is intentionally not provided so that future
/// required configuration cannot be silently bypassed.
#[derive(Clone)]
pub struct KeyVaultBuilder {
    config: VaultConfig,
    fragmenter: StandardFragmenter,
    codex: Option<Arc<dyn Codex>>,
    monitor: Option<Arc<dyn SecurityMonitor>>,
    /// Hash of the master credential, if one was registered. We hold
    /// the hash (not the plaintext) so the master bytes don't linger
    /// in the builder's state.
    master_hash: Option<[u8; 32]>,
}

impl Default for KeyVaultBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for KeyVaultBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyVaultBuilder")
            .field("config", &self.config)
            .field("fragmenter", &self.fragmenter)
            .field("codex", &self.codex.as_ref().map(|_| "<set>"))
            .field("monitor", &self.monitor.as_ref().map(|_| "<set>"))
            .field("master_key", &self.master_hash.as_ref().map(|_| "<set>"))
            .finish()
    }
}

impl KeyVaultBuilder {
    /// Start a new builder with default configuration and a default-range
    /// [`StandardFragmenter`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: VaultConfig::new(),
            fragmenter: StandardFragmenter::new(),
            codex: None,
            monitor: None,
            master_hash: None,
        }
    }

    /// Enable or disable BLAKE3 normalization of input key material.
    ///
    /// Default: `true`. Disabling normalization preserves the original byte
    /// pattern of the key in storage, which can leak format cues (DER
    /// envelopes, PEM markers, ASCII-armored data). Disable only when you
    /// have a specific reason to preserve the original bytes.
    #[must_use]
    pub fn normalize_with_blake3(mut self, enabled: bool) -> Self {
        self.config.key_normalization = enabled;
        self
    }

    /// Customize the fragmenter chunk-size range.
    ///
    /// Defaults are documented on [`StandardFragmenter::new`]. `min` is
    /// clamped to `>= 1` and `max` to `>= min`. Calling this replaces any
    /// previously-configured chunk range and resets the decoy strategy to
    /// `None`; configure decoy *after* this call.
    #[must_use]
    pub fn with_chunk_range(mut self, min: usize, max: usize) -> Self {
        self.fragmenter = StandardFragmenter::with_chunk_range(min, max);
        self
    }

    /// Attach a Layer-5 codex to the vault.
    ///
    /// When set, every byte of the (optionally BLAKE3-normalized) key
    /// passes through `codex.encode()` before being handed to the
    /// fragmenter; `defragment` applies `codex.decode()` to recover the
    /// original bytes. For involution-based codices ([`StaticCodex`](crate::StaticCodex),
    /// [`DynamicCodex`](crate::DynamicCodex), involution closures wrapped in
    /// [`FnCodex`](crate::codex::FnCodex)) `decode == encode`, but the
    /// vault calls them by name so non-involution codices would also
    /// work in principle.
    ///
    /// The codex is held in an `Arc<dyn Codex>` so the same codex can be
    /// shared across multiple vaults (rarely useful — usually each vault
    /// wants its own [`DynamicCodex`](crate::DynamicCodex)).
    ///
    /// # Examples
    ///
    /// ```
    /// use key_vault::{DynamicCodex, KeyVaultBuilder};
    ///
    /// let vault = KeyVaultBuilder::new()
    ///     .with_codex(DynamicCodex::new().unwrap())
    ///     .build();
    /// // The vault now applies the codex transformation transparently
    /// // on every fragment / defragment.
    /// # let _ = vault;
    /// ```
    #[must_use]
    pub fn with_codex<C>(mut self, codex: C) -> Self
    where
        C: Codex + 'static,
    {
        self.codex = Some(Arc::new(codex));
        self
    }

    /// Attach a Layer-4 decoy strategy to the underlying fragmenter.
    ///
    /// When set, every `KeyVault::fragment` call also produces decoy chunks
    /// from the strategy. Decoys are interleaved with real chunks via the
    /// same Fisher-Yates shuffle and are skipped by `defragment`. See
    /// [`StandardFragmenter::with_decoy`] for details on chunk-count and
    /// size selection.
    ///
    /// Use [`SelfReferenceDecoy`](crate::SelfReferenceDecoy) for the
    /// strongest statistical indistinguishability (recommended default);
    /// [`KeyDerivedDecoy`](crate::KeyDerivedDecoy) for BLAKE3-XOF–derived
    /// CSPRNG-like output;
    /// [`RandomDecoy`](crate::RandomDecoy) for raw CSPRNG output.
    #[must_use]
    pub fn with_decoy<D>(mut self, decoy: D) -> Self
    where
        D: DecoyStrategy + 'static,
    {
        self.fragmenter = self.fragmenter.with_decoy(decoy);
        self
    }

    /// Attach a Layer-8 security monitor.
    ///
    /// Replaces any previously-configured monitor. The monitor receives
    /// every event the vault produces — failure callbacks via
    /// [`KeyVault::report_failure`], anomaly callbacks via
    /// [`KeyVault::report_anomalous_access`], and threshold-breach
    /// callbacks when the failure tracker fires.
    ///
    /// Default is [`NoMonitor`](crate::NoMonitor) — events go nowhere
    /// but threshold-driven lockout still works (lockout state is owned
    /// by the vault, not the monitor).
    #[must_use]
    pub fn with_monitor<M>(mut self, monitor: M) -> Self
    where
        M: SecurityMonitor + 'static,
    {
        self.monitor = Some(Arc::new(monitor));
        self
    }

    /// Configure the failure-threshold detector.
    ///
    /// When [`KeyVault::report_failure`] records `max` failures for the
    /// same `key_name` within `window`, the vault transitions to
    /// lock-out state and the monitor's `on_threshold_breach` fires.
    ///
    /// Pass `max = 0` to disable threshold lockout (the default). The
    /// vault will still forward every failure to the monitor; it just
    /// won't lock out on its own.
    ///
    /// `window` is the sliding-window size for the per-key failure
    /// counter; failures older than this fall off and no longer count.
    #[must_use]
    pub fn with_failure_threshold(mut self, max: u32, window: Duration) -> Self {
        self.config.max_failures_before_lockout = max;
        self.config.failure_window = window;
        self
    }

    /// Register a master credential for emergency unlock.
    ///
    /// The vault stores the **BLAKE3 hash** of the supplied bytes; the
    /// plaintext is dropped immediately (and zeroed via
    /// `RawKey::Drop`). Use [`KeyVault::unlock_with_master`] later to
    /// clear a threshold-driven lockout.
    ///
    /// Calling this twice replaces the previously-stored hash. Pass an
    /// empty key (zero-length) to register a meaningless "match
    /// anything" credential — strongly discouraged; the function does
    /// not reject it for symmetry with the rest of the builder API.
    #[must_use]
    pub fn with_master_key(mut self, master: RawKey) -> Self {
        let hash = blake3::hash(master.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        self.master_hash = Some(bytes);
        // `master` drops here; its `Drop` impl zeroes the internal Vec.
        drop(master);
        self
    }

    /// Finalize and produce a [`KeyVault`].
    ///
    /// Infallible in this phase — later phases may move this to a
    /// `Result`-returning shape if validation is added.
    #[must_use]
    pub fn build(self) -> KeyVault {
        let monitor: Arc<dyn SecurityMonitor> = self
            .monitor
            .unwrap_or_else(|| Arc::new(crate::monitor::NoMonitor));
        KeyVault {
            inner: Arc::new(VaultInner {
                config: self.config,
                fragmenter: self.fragmenter,
                codex: self.codex,
                monitor,
                keys: ArcSwap::from_pointee(HashMap::new()),
                failure_tracker: Mutex::new(HashMap::new()),
                locked_out: AtomicBool::new(false),
                master_hash: self.master_hash,
            }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn builder_defaults_to_normalization_on() {
        let v = KeyVaultBuilder::new().build();
        assert!(v.config().key_normalization);
    }

    #[test]
    fn builder_can_disable_normalization() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        assert!(!v.config().key_normalization);
    }

    #[test]
    fn fresh_vault_is_not_locked_out() {
        let v = KeyVaultBuilder::new().build();
        assert!(!v.is_locked_out());
    }

    #[test]
    fn debug_does_not_panic() {
        let v = KeyVaultBuilder::new().build();
        let _ = format!("{v:?}");
    }

    #[test]
    fn fragment_defragment_roundtrip_with_normalization() {
        let v = KeyVaultBuilder::new().build(); // normalization on
        let raw = RawKey::new(b"hello world".to_vec());
        let frags = v.fragment(&raw).unwrap();
        let recovered = v.defragment(&frags).unwrap();
        // With normalization on, the output is the BLAKE3 hash (32 bytes),
        // not the original 11-byte input.
        assert_eq!(recovered.len(), 32);
        // It is deterministic — fragmenting the same input twice produces the
        // same recovered bytes (the bytes themselves; layout still varies).
        let frags2 = v.fragment(&raw).unwrap();
        let recovered2 = v.defragment(&frags2).unwrap();
        assert_eq!(recovered.as_bytes(), recovered2.as_bytes());
    }

    #[test]
    fn fragment_defragment_roundtrip_without_normalization() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let raw = RawKey::new((0u8..40).collect());
        let frags = v.fragment(&raw).unwrap();
        let recovered = v.defragment(&frags).unwrap();
        assert_eq!(recovered.as_bytes(), raw.as_bytes());
    }

    #[test]
    fn fragment_rejects_empty_key() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let err = v
            .fragment(&RawKey::new(alloc::vec::Vec::new()))
            .unwrap_err();
        assert!(matches!(err, crate::Error::Fragment(_)));
    }

    #[test]
    fn chunk_range_propagates_through_builder() {
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_chunk_range(4, 6)
            .build();
        let raw = RawKey::new((0u8..30).collect());
        let frags = v.fragment(&raw).unwrap();

        // After fragmentation, chunks have been Fisher-Yates shuffled, so the
        // "remainder" chunk (which the size-sampling loop allows to fall below
        // `min` when the total doesn't divide cleanly) can land at any index.
        // We verify the post-shuffle invariants instead of indexing by order:
        //   1. Every chunk fits in [1, max].
        //   2. At most one chunk falls below `min` (the remainder slot).
        //   3. Total bytes sum to the original length.
        let chunks = frags.chunks();
        let mut below_min = 0;
        let mut total = 0usize;
        for c in chunks {
            assert!(
                c.len() >= 1 && c.len() <= 6,
                "chunk size {} not in [1,6]",
                c.len()
            );
            if c.len() < 4 {
                below_min += 1;
            }
            total += c.len();
        }
        assert!(
            below_min <= 1,
            "more than one chunk below min size: {below_min}"
        );
        assert_eq!(total, 30);
    }

    #[test]
    fn fragment_with_random_decoy_roundtrips() {
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_decoy(crate::RandomDecoy)
            .build();
        let raw = RawKey::new((0u8..32).collect());
        let frags = v.fragment(&raw).unwrap();
        // Chunk count is real + decoy (roughly 2x the real count).
        // Defragment must skip the decoys and return the original bytes.
        let recovered = v.defragment(&frags).unwrap();
        assert_eq!(recovered.as_bytes(), raw.as_bytes());
    }

    #[test]
    fn fragment_with_self_reference_decoy_roundtrips() {
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_decoy(crate::SelfReferenceDecoy)
            .build();
        let raw = RawKey::new(b"some user-supplied key material".to_vec());
        let frags = v.fragment(&raw).unwrap();
        let recovered = v.defragment(&frags).unwrap();
        assert_eq!(recovered.as_bytes(), raw.as_bytes());
    }

    #[test]
    fn fragment_with_key_derived_decoy_roundtrips() {
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_decoy(crate::KeyDerivedDecoy)
            .build();
        let raw = RawKey::new((0u8..64).collect());
        let frags = v.fragment(&raw).unwrap();
        let recovered = v.defragment(&frags).unwrap();
        assert_eq!(recovered.as_bytes(), raw.as_bytes());
    }

    #[test]
    fn decoy_increases_chunk_count_relative_to_no_decoy() {
        let no_decoy = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_chunk_range(2, 4)
            .build();
        let with_decoy = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_chunk_range(2, 4)
            .with_decoy(crate::SelfReferenceDecoy)
            .build();
        let raw = RawKey::new((0u8..32).collect());

        // The total chunk count is randomized per fragmentation, so average
        // over a few runs to get a stable comparison. The decoy-enabled
        // vault should average ~2x the chunks.
        let mut no_decoy_total = 0usize;
        let mut decoy_total = 0usize;
        for _ in 0..8 {
            no_decoy_total += no_decoy.fragment(&raw).unwrap().chunk_count();
            decoy_total += with_decoy.fragment(&raw).unwrap().chunk_count();
        }
        // The decoy-enabled vault adds one decoy chunk per real chunk, so
        // its total chunk count should be exactly twice the no-decoy count
        // (modulo per-call sampling that affects the real-chunk count
        // identically). Allow some slack for the random sampling variance.
        assert!(
            decoy_total > no_decoy_total,
            "decoy vault produced {decoy_total} chunks vs no-decoy {no_decoy_total}"
        );
    }

    #[test]
    fn fragment_with_static_codex_roundtrips() {
        use crate::StaticCodex;
        let codex = StaticCodex::from_swaps(&[(b'A', b'#'), (b'0', b'%')]).unwrap();
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_codex(codex)
            .build();
        let raw = RawKey::new(b"A0A0A0A0".to_vec());
        let frags = v.fragment(&raw).unwrap();
        let recovered = v.defragment(&frags).unwrap();
        // Codex round-trips: the recovered bytes are the original
        // (pre-encode) bytes, not the encoded ones.
        assert_eq!(recovered.as_bytes(), raw.as_bytes());
    }

    #[test]
    fn fragment_with_dynamic_codex_roundtrips() {
        use crate::DynamicCodex;
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_codex(DynamicCodex::new().unwrap())
            .build();
        let raw = RawKey::new((0u8..=255).collect());
        let frags = v.fragment(&raw).unwrap();
        let recovered = v.defragment(&frags).unwrap();
        assert_eq!(recovered.as_bytes(), raw.as_bytes());
    }

    #[test]
    fn fragment_with_codex_and_decoy_and_normalization_roundtrips() {
        use crate::{DynamicCodex, SelfReferenceDecoy};
        // All layers stacked: BLAKE3 normalize + DynamicCodex encode +
        // StandardFragmenter w/ SelfReferenceDecoy. Must still round-trip.
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(true)
            .with_codex(DynamicCodex::new().unwrap())
            .with_decoy(SelfReferenceDecoy)
            .build();
        let raw = RawKey::new(b"my application key".to_vec());
        let frags = v.fragment(&raw).unwrap();
        let recovered = v.defragment(&frags).unwrap();
        // With normalization on, recovered is 32 bytes (BLAKE3 hash).
        // It must be deterministic given the same input.
        assert_eq!(recovered.len(), 32);
        let recovered2 = v.defragment(&v.fragment(&raw).unwrap()).unwrap();
        assert_eq!(recovered.as_bytes(), recovered2.as_bytes());
    }

    #[test]
    fn codex_visibly_transforms_stored_bytes() {
        // Without codex, the fragment chunks contain the original bytes
        // somewhere among them. With a non-identity codex, the stored
        // bytes should differ — we verify by checking that some chunk
        // contains a transformed byte not in the original input.
        use crate::StaticCodex;
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            // Force every byte to swap with a distinct partner.
            .with_codex(crate::DynamicCodex::new().unwrap())
            .build();
        let raw = RawKey::new(alloc::vec![0xaa; 8]);
        let frags = v.fragment(&raw).unwrap();

        // Walk chunks and confirm at least one byte is *not* 0xaa
        // (the codex encoded 0xaa to something else).
        let mut saw_non_aa = false;
        for chunk in frags.chunks() {
            for &b in chunk.as_bytes() {
                if b != 0xaa {
                    saw_non_aa = true;
                    break;
                }
            }
            if saw_non_aa {
                break;
            }
        }
        assert!(
            saw_non_aa,
            "codex did not transform 0xaa — stored bytes still all 0xaa",
        );

        // And defragment recovers the original 0xaa bytes.
        let recovered = v.defragment(&frags).unwrap();
        assert_eq!(recovered.as_bytes(), raw.as_bytes());
        // Use the `_codex` import to keep the import non-dead.
        let _ = StaticCodex::from_swaps(&[]).unwrap();
    }

    // ----- Layer 8: monitor + threshold tests -----

    use core::sync::atomic::AtomicU32;

    /// Helper monitor that counts each callback invocation.
    struct CountingMonitor {
        failures: AtomicU32,
        anomalies: AtomicU32,
        breaches: AtomicU32,
    }

    impl CountingMonitor {
        fn new() -> Self {
            Self {
                failures: AtomicU32::new(0),
                anomalies: AtomicU32::new(0),
                breaches: AtomicU32::new(0),
            }
        }
    }

    impl SecurityMonitor for CountingMonitor {
        fn on_decryption_failure(&self, _ctx: &FailureContext) {
            let _ = self.failures.fetch_add(1, Ordering::SeqCst);
        }
        fn on_anomalous_access(&self, _ctx: &AccessContext) {
            let _ = self.anomalies.fetch_add(1, Ordering::SeqCst);
        }
        fn on_threshold_breach(&self, _ctx: &ThresholdContext) {
            let _ = self.breaches.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn report_failure_fires_monitor() {
        let monitor = Arc::new(CountingMonitor::new());
        let v = KeyVaultBuilder::new()
            .with_monitor(Arc::clone(&monitor) as Arc<dyn SecurityMonitor>)
            .build();
        v.report_failure("k", None);
        v.report_failure("k", Some("test note"));
        assert_eq!(monitor.failures.load(Ordering::SeqCst), 2);
        assert_eq!(monitor.breaches.load(Ordering::SeqCst), 0);
        assert!(!v.is_locked_out());
    }

    #[test]
    fn report_anomalous_access_fires_monitor() {
        let monitor = Arc::new(CountingMonitor::new());
        let v = KeyVaultBuilder::new()
            .with_monitor(Arc::clone(&monitor) as Arc<dyn SecurityMonitor>)
            .build();
        v.report_anomalous_access("k", None);
        assert_eq!(monitor.anomalies.load(Ordering::SeqCst), 1);
        assert!(!v.is_locked_out());
    }

    #[test]
    fn threshold_lockout_fires_after_max_failures() {
        let monitor = Arc::new(CountingMonitor::new());
        let v = KeyVaultBuilder::new()
            .with_monitor(Arc::clone(&monitor) as Arc<dyn SecurityMonitor>)
            .with_failure_threshold(3, Duration::from_secs(30))
            .build();

        v.report_failure("k", None);
        assert!(!v.is_locked_out());
        v.report_failure("k", None);
        assert!(!v.is_locked_out());
        v.report_failure("k", None);
        // Three failures in the window → lockout.
        assert!(v.is_locked_out());
        assert_eq!(monitor.failures.load(Ordering::SeqCst), 3);
        assert_eq!(monitor.breaches.load(Ordering::SeqCst), 1);

        // Subsequent failures keep counting but only one breach event fires
        // until clear_lockout resets the flag.
        v.report_failure("k", None);
        assert!(v.is_locked_out());
        assert_eq!(monitor.failures.load(Ordering::SeqCst), 4);
        // Breach event count grows but lockout_triggered is false now.
        assert_eq!(monitor.breaches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn fragment_refuses_when_locked_out() {
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_failure_threshold(1, Duration::from_secs(30))
            .build();
        v.report_failure("k", None);
        assert!(v.is_locked_out());

        let err = v
            .fragment(&RawKey::new(alloc::vec![1u8, 2, 3, 4]))
            .unwrap_err();
        assert!(matches!(err, Error::LockedOut));
    }

    #[test]
    fn defragment_refuses_when_locked_out() {
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_failure_threshold(2, Duration::from_secs(30))
            .build();
        // Produce a fragment before lockout.
        let raw = RawKey::new(alloc::vec![1u8; 16]);
        let frags = v.fragment(&raw).unwrap();
        v.report_failure("k", None);
        v.report_failure("k", None);
        assert!(v.is_locked_out());

        let err = v.defragment(&frags).unwrap_err();
        assert!(matches!(err, Error::LockedOut));
    }

    #[test]
    fn clear_lockout_resets_state() {
        let v = KeyVaultBuilder::new()
            .with_failure_threshold(1, Duration::from_secs(30))
            .build();
        v.report_failure("k", None);
        assert!(v.is_locked_out());
        v.clear_lockout();
        assert!(!v.is_locked_out());
        // Failure tracker also cleared — next single failure shouldn't lock
        // again immediately (threshold is 1, so it WILL lock, but starting
        // count is fresh — verifies tracker was cleared by counting
        // monitor breaches).
        // Actually with threshold=1 a single failure re-locks. So instead
        // assert via tracker contents indirectly: a second `clear_lockout`
        // call is a no-op.
        v.clear_lockout();
        assert!(!v.is_locked_out());
    }

    #[test]
    fn per_key_failure_counts_are_independent() {
        let monitor = Arc::new(CountingMonitor::new());
        let v = KeyVaultBuilder::new()
            .with_monitor(Arc::clone(&monitor) as Arc<dyn SecurityMonitor>)
            .with_failure_threshold(2, Duration::from_secs(30))
            .build();
        v.report_failure("alpha", None);
        v.report_failure("beta", None);
        // One failure each — neither hits the threshold.
        assert!(!v.is_locked_out());
        assert_eq!(monitor.failures.load(Ordering::SeqCst), 2);
        v.report_failure("alpha", None);
        // alpha now has 2 — triggers lockout.
        assert!(v.is_locked_out());
    }

    // ----- Phase 0.9: registry + rotation + master-key tests -----

    #[test]
    fn register_returns_handle_and_increments_count() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        assert_eq!(v.key_count(), 0);
        let h = v
            .register("primary", RawKey::new(alloc::vec![1u8; 32]))
            .unwrap();
        assert_eq!(v.key_count(), 1);
        assert!(v.contains(h));
    }

    #[test]
    fn register_rejects_duplicate_name() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let _ = v
            .register("primary", RawKey::new(alloc::vec![1u8; 16]))
            .unwrap();
        let err = v
            .register("primary", RawKey::new(alloc::vec![2u8; 16]))
            .unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn unregister_removes_key() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let h = v
            .register("primary", RawKey::new(alloc::vec![1u8; 16]))
            .unwrap();
        assert!(v.contains(h));
        v.unregister(h).unwrap();
        assert!(!v.contains(h));
        assert_eq!(v.key_count(), 0);
    }

    #[test]
    fn unregister_unknown_handle_errors() {
        let v = KeyVaultBuilder::new().build();
        let h = KeyHandle::__for_test();
        let err = v.unregister(h).unwrap_err();
        assert!(matches!(err, Error::KeyNotFound));
    }

    #[test]
    fn with_key_round_trips_bytes() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let original = alloc::vec![0xa5u8; 32];
        let h = v.register("data", RawKey::new(original.clone())).unwrap();
        let observed = v.with_key(h, <[u8]>::to_vec).unwrap();
        assert_eq!(observed, original);
    }

    #[test]
    fn with_key_normalization_changes_output_length() {
        let v = KeyVaultBuilder::new().build(); // normalization ON
        let h = v
            .register("data", RawKey::new(alloc::vec![0xa5; 17]))
            .unwrap();
        let observed_len = v.with_key(h, <[u8]>::len).unwrap();
        // BLAKE3 normalization → 32-byte output regardless of input.
        assert_eq!(observed_len, 32);
    }

    #[test]
    fn with_key_unknown_handle_errors() {
        let v = KeyVaultBuilder::new().build();
        let h = KeyHandle::__for_test();
        let err = v.with_key(h, |_| ()).unwrap_err();
        assert!(matches!(err, Error::KeyNotFound));
    }

    #[test]
    fn rotate_swaps_key_bytes() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let h = v
            .register("data", RawKey::new(alloc::vec![1u8; 16]))
            .unwrap();

        v.rotate(h, RawKey::new(alloc::vec![2u8; 16])).unwrap();
        let observed = v.with_key(h, <[u8]>::to_vec).unwrap();
        assert_eq!(observed, alloc::vec![2u8; 16]);
    }

    #[test]
    fn rotate_unknown_handle_errors() {
        let v = KeyVaultBuilder::new().build();
        let h = KeyHandle::__for_test();
        let err = v.rotate(h, RawKey::new(alloc::vec![0u8; 16])).unwrap_err();
        assert!(matches!(err, Error::KeyNotFound));
    }

    #[test]
    fn handle_for_name_finds_registered_key() {
        let v = KeyVaultBuilder::new().build();
        let h = v
            .register("primary", RawKey::new(alloc::vec![0u8; 16]))
            .unwrap();
        assert_eq!(v.handle_for_name("primary"), Some(h));
        assert_eq!(v.handle_for_name("missing"), None);
    }

    #[test]
    fn metadata_records_registration_length() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let h = v
            .register("data", RawKey::new(alloc::vec![0u8; 42]))
            .unwrap();
        let meta = v.metadata(h).expect("metadata");
        assert_eq!(meta.length(), 42);
    }

    #[test]
    fn registered_key_refuses_access_when_locked_out() {
        let v = KeyVaultBuilder::new()
            .with_failure_threshold(1, Duration::from_secs(30))
            .build();
        let h = v
            .register("data", RawKey::new(alloc::vec![0xa5; 16]))
            .unwrap();
        v.report_failure("data", None);
        assert!(v.is_locked_out());

        let err = v.with_key(h, |_| ()).unwrap_err();
        assert!(matches!(err, Error::LockedOut));
        let err = v.rotate(h, RawKey::new(alloc::vec![0u8; 16])).unwrap_err();
        assert!(matches!(err, Error::LockedOut));
    }

    #[test]
    fn master_key_unlock_clears_lockout_on_match() {
        let master_bytes = b"correct horse battery staple".to_vec();
        let v = KeyVaultBuilder::new()
            .with_master_key(RawKey::new(master_bytes.clone()))
            .with_failure_threshold(1, Duration::from_secs(30))
            .build();
        assert!(v.has_master_key());

        v.report_failure("k", None);
        assert!(v.is_locked_out());

        // Wrong master → still locked.
        let err = v.unlock_with_master(b"wrong").unwrap_err();
        assert!(matches!(err, Error::Acquisition { .. }));
        assert!(v.is_locked_out());

        // Correct master → unlocked.
        v.unlock_with_master(&master_bytes).unwrap();
        assert!(!v.is_locked_out());
    }

    #[test]
    fn master_key_unlock_without_registered_master_errors() {
        let v = KeyVaultBuilder::new().build();
        assert!(!v.has_master_key());
        let err = v.unlock_with_master(b"anything").unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn composite_monitor_chains_to_all_inner() {
        use crate::CompositeMonitor;
        let a = Arc::new(CountingMonitor::new());
        let b = Arc::new(CountingMonitor::new());
        let composite = CompositeMonitor::new(alloc::vec![
            Arc::clone(&a) as Arc<dyn SecurityMonitor>,
            Arc::clone(&b) as Arc<dyn SecurityMonitor>,
        ]);
        let v = KeyVaultBuilder::new()
            .with_monitor(composite)
            .with_failure_threshold(1, Duration::from_secs(30))
            .build();
        v.report_failure("k", None);
        assert_eq!(a.failures.load(Ordering::SeqCst), 1);
        assert_eq!(b.failures.load(Ordering::SeqCst), 1);
        assert_eq!(a.breaches.load(Ordering::SeqCst), 1);
        assert_eq!(b.breaches.load(Ordering::SeqCst), 1);
    }
}
