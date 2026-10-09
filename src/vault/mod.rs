//! The vault itself.
//!
//! [`KeyVault`] owns the named-key registry, the configured fragmenter,
//! optional decoy and codex, the failure tracker and lockout flag, the
//! optional master credential, and the monitor / audit hooks.
//!
//! # Concurrency
//!
//! Reads (`with_key`, `contains`, `metadata`, `handle_for_name`) are
//! lock-free: they load an `Arc` snapshot of the registry. Writes
//! (`register`, `unregister`, `rotate`) are serialized by an internal
//! writer lock: each one re-checks the registry and installs its change
//! while holding the lock, so a duplicate name cannot be inserted twice and
//! `rotate` cannot report success for a key that was removed first.
//! Fragmentation (the slow part of `register` and `rotate`) runs before
//! the lock is taken.
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
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::Result;
use crate::audit::{AccessKind, AuditEvent, AuditSink};
use crate::codex::Codex;
use crate::decoy::DecoyStrategy;
use crate::error::Error;
use crate::fetcher::RawKey;
use crate::fragment::{FragmentStrategy, Fragments, StandardFragmenter};
use crate::handle::{KeyHandle, KeyId};
use crate::memory::{acquire_region, release_region};
use crate::metadata::KeyMetadata;
use crate::monitor::{AccessContext, FailureContext, SecurityMonitor, ThresholdContext};
use crate::normalize::{blake3_into, blake3_normalize};

/// BLAKE3 digest of the master credential. Zeroized on drop, including
/// every clone the builder makes.
type MasterDigest = Zeroizing<[u8; 32]>;

/// BLAKE3 digest of `bytes` in a zeroize-on-drop buffer.
fn master_digest(bytes: &[u8]) -> MasterDigest {
    let mut digest = Zeroizing::new([0u8; 32]);
    blake3_into(bytes, &mut digest[..]);
    digest
}

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

    /// Failures (per key name) within the configured `failure_window`
    /// required to trigger vault lockout. `0` disables threshold
    /// lockout entirely: failures still flow to the configured monitor
    /// but never lock the vault out. Default: `0` (disabled).
    ///
    /// Failures are counted only when the caller reports them through
    /// [`KeyVault::report_failure`] (and on a wrong master credential).
    /// The lockout that follows applies to the whole vault, not just the
    /// key name that crossed the threshold.
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
/// code constructs one via [`KeyVaultBuilder`], registers [`RawKey`] values
/// under a name, and receives [`KeyHandle`](crate::KeyHandle)s in return.
/// The vault itself is cheap to clone (it is `Arc`-backed internally) and
/// safe to share across threads.
///
/// The vault always uses a [`StandardFragmenter`]. Decoys and a codex are
/// used only when configured on the builder
/// ([`KeyVaultBuilder::with_decoy`], [`KeyVaultBuilder::with_codex`]);
/// Cargo features do not turn them on.
///
/// [`KeyVault::fragment`] and [`KeyVault::defragment`] are one-shot
/// helpers that run the same pipeline without touching the registry.
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
    /// it in while holding `writer`.
    keys: ArcSwap<HashMap<KeyId, KeyEntry>>,
    /// Serializes registry writers. A writer takes this lock, loads the
    /// current map, checks its precondition (name free, key present),
    /// stores the new map and only then releases the lock, so the check
    /// and the update cannot be split by another writer.
    writer: Mutex<()>,
    /// Per-key sliding-window failure tracker. Populated by
    /// [`KeyVault::report_failure`]; consulted by the threshold-detection
    /// logic to decide whether to trigger lockout.
    failure_tracker: Mutex<HashMap<String, VecDeque<Instant>>>,
    /// Set to `true` when the failure-tracker threshold has been crossed.
    /// `fragment` / `defragment` refuse to operate while this is set;
    /// `Error::LockedOut` is returned instead.
    locked_out: AtomicBool,
    /// Optional master-key credential. Stored as the BLAKE3 hash of the
    /// supplied master bytes; the plaintext is dropped (and zeroed via
    /// `RawKey::Drop`) immediately after registration. The digest itself
    /// is zeroized when the vault drops. Used by
    /// [`KeyVault::unlock_with_master`] as an emergency unlock.
    master_hash: Option<MasterDigest>,
    /// Layer-9 audit sink. Defaults to a no-op
    /// [`NoAudit`](crate::NoAudit) when no sink is configured. Every
    /// vault operation (register / unregister / read / rotate /
    /// fragment / defragment / master-unlock) emits an
    /// [`AuditEvent`](crate::AuditEvent) through this sink.
    audit: Arc<dyn AuditSink>,
}

impl KeyVault {
    /// Returns `true` if the vault is in lock-out state.
    ///
    /// Lock-out is triggered by the threshold detector when
    /// [`KeyVault::report_failure`] reports
    /// [`VaultConfig::max_failures_before_lockout`] failures for one key
    /// name within [`VaultConfig::failure_window`]. Once set,
    /// [`KeyVault::register`], [`KeyVault::with_key`],
    /// [`KeyVault::rotate`], [`KeyVault::fragment`] and
    /// [`KeyVault::defragment`] refuse to proceed and return
    /// [`Error::LockedOut`](crate::Error::LockedOut). Use
    /// [`KeyVault::clear_lockout`] or [`KeyVault::unlock_with_master`] to
    /// reset.
    ///
    /// # Lockout is advisory and vault-wide
    ///
    /// The vault never detects failures on its own: it only counts what
    /// the caller reports through [`KeyVault::report_failure`] (plus wrong
    /// master credentials). Lockout blocks every key in the vault, so
    /// failures reported for one key name lock out all keys; code that
    /// reports failures for untrusted input can be used to deny service.
    /// Lockout is an API-level gate for well-behaved callers. It does
    /// nothing against code that can read the process's memory.
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
    /// [`VaultConfig::max_failures_before_lockout`], the whole vault
    /// transitions to lock-out state (every key, not only `key_name`) and
    /// the monitor's `on_threshold_breach` callback fires. A
    /// `max_failures` of `0` disables threshold lockout; only the
    /// per-failure callback runs in that case.
    ///
    /// This is the only way failures reach the threshold detector: the
    /// vault does not observe decryption failures itself. See
    /// [`KeyVault::is_locked_out`].
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

    /// Build an [`AuditEvent`] with `now` timestamp and the calling
    /// thread's id, and forward it to the configured audit sink.
    ///
    /// Crate-internal helper. Hot enough to be worth keeping in one
    /// place — every public vault op funnels through this.
    fn emit_audit(&self, key_name: &str, kind: AccessKind, note: Cow<'static, str>) {
        // Hot-path fast-skip: a sink that declares itself no-op gets
        // zero allocations + zero clock-read overhead per call.
        if self.inner.audit.is_no_op() {
            return;
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let event = AuditEvent {
            timestamp,
            key_name: key_name.to_string(),
            kind,
            thread_id: std::thread::current().id(),
            note,
        };
        self.inner.audit.on_event(&event);
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
        let result = self.fragment_pipeline(key);
        if result.is_ok() {
            self.emit_audit("", AccessKind::OneShotFragment, Cow::Borrowed(""));
        }
        result
    }

    /// Normalize, codex-encode and fragment `key` without emitting an
    /// audit event. `register` and `rotate` use this so that a
    /// registration produces one `Register` event and no extra unnamed
    /// `OneShotFragment` event.
    fn fragment_pipeline(&self, key: &RawKey) -> Result<Fragments> {
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

    /// Take the registry writer lock. The lock guards no data (`()`), so a
    /// poisoned lock is still safe to use.
    fn lock_writer(&self) -> MutexGuard<'_, ()> {
        self.inner
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
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
        let decoded = if let Some(codex) = &self.inner.codex {
            codex_apply(codex.as_ref(), &encoded)
        } else {
            encoded
        };
        self.emit_audit("", AccessKind::OneShotDefragment, Cow::Borrowed(""));
        Ok(decoded)
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
    ///   with the same name is already registered. Concurrent `register`
    ///   calls with the same name are safe: exactly one succeeds.
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
        let duplicate = || Error::InvalidConfig(format!("key name {name:?} is already registered"));

        // Reject duplicate names early so callers get a clear error
        // before paying the fragmentation cost. This check is only a
        // shortcut; the authoritative one runs under the writer lock.
        if self.inner.keys.load().values().any(|e| e.name == name) {
            return Err(duplicate());
        }

        let key_len = key.len();
        let fragments = Arc::new(self.fragment_pipeline(&key)?);
        let handle = KeyHandle::allocate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let metadata = KeyMetadata::new(now, key_len, None);

        let previous = {
            let _writer = self.lock_writer();
            let current = self.inner.keys.load_full();
            // Re-check under the lock: another `register` may have
            // inserted the same name while we were fragmenting.
            if current.values().any(|e| e.name == name) {
                return Err(duplicate());
            }
            let mut new_map = (*current).clone();
            let _ = new_map.insert(
                handle.id(),
                KeyEntry {
                    name: name.clone(),
                    fragments,
                    metadata,
                },
            );
            self.inner.keys.swap(Arc::new(new_map))
        };
        // Release the old map outside the writer lock.
        drop(previous);
        self.emit_audit(&name, AccessKind::Register, Cow::Borrowed(""));
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
        let (previous, name) = {
            let _writer = self.lock_writer();
            let current = self.inner.keys.load_full();
            let Some(entry) = current.get(&handle.id()) else {
                return Err(Error::KeyNotFound);
            };
            let name = entry.name.clone();
            let mut new_map = (*current).clone();
            let _ = new_map.remove(&handle.id());
            (self.inner.keys.swap(Arc::new(new_map)), name)
        };
        // The removed entry's fragments are freed (and zeroed) here, or
        // later when the last in-flight `with_key` reader lets go.
        drop(previous);
        self.emit_audit(&name, AccessKind::Unregister, Cow::Borrowed(""));
        Ok(())
    }

    /// Briefly access the recovered key material inside a callback.
    ///
    /// The vault defragments the named key into a per-thread scratch
    /// buffer, applies the codex decode if configured, and passes the
    /// bytes to the user-supplied closure. When the closure returns (or
    /// panics, or defragmentation fails) the used part of the buffer is
    /// volatile-zeroed. The scratch buffer's pages are locked like the
    /// fragments' pages.
    ///
    /// **The byte slice handed to the closure does not outlive the
    /// call.** Do not stash it in a longer-lived structure; do your
    /// cryptographic operation, return, and let the vault scrub the
    /// buffer. Copies the closure makes (into a cipher's key schedule,
    /// a `Vec`, the stack) are not tracked or wiped by the vault.
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
        // Skip cloning the name when the audit sink is inert — this
        // is the common case and removes one `String` allocation per
        // `with_key` call.
        let name: Option<String> = if self.inner.audit.is_no_op() {
            None
        } else {
            Some(entry.name.clone())
        };
        // Drop the snapshot so we don't hold the Arc across the
        // potentially-slow defragment + user-callback path.
        drop(snapshot);

        let total = fragments.total_len();
        let codex = self.inner.codex.clone();
        let result = SCRATCH.with(|cell| -> Result<T> {
            let mut scratch = cell.borrow_mut();
            // Grow lazily; the buffer is reused across calls so the
            // typical steady state is a no-op.
            scratch.ensure_len(total);
            // The guard is created before the first plaintext byte is
            // written, so the scratch is volatile-zeroed on every exit
            // path: normal return, an error from `defragment_into`
            // after a partial write, or a panic in the codex or the
            // user callback.
            let guard = ZeroOnExit(&mut scratch.buf[..total]);
            // Defragment directly into the scratch — no `RawKey` /
            // `Vec<u8>` allocation on the hot path.
            self.inner
                .fragmenter
                .defragment_into(&fragments, &mut *guard.0)?;
            // Codex decode in place (also alloc-free).
            if let Some(c) = &codex {
                codex_decode_in_place(c.as_ref(), &mut *guard.0);
            }
            Ok(f(&*guard.0))
        })?;
        if let Some(name) = name {
            self.emit_audit(&name, AccessKind::Read, Cow::Borrowed(""));
        }
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
    /// - [`Error::KeyNotFound`](crate::Error::KeyNotFound), including when
    ///   a concurrent [`KeyVault::unregister`] removes the key before the
    ///   rotation is installed. `rotate` returns `Ok` only if the new
    ///   material was actually stored under the handle.
    /// - Fragmenter errors for the new key.
    // Take `new_key` by value so its `Drop` zeroes the original buffer
    // after we've fragmented and copied the bytes into mlock'd storage.
    #[allow(clippy::needless_pass_by_value)]
    pub fn rotate(&self, handle: KeyHandle, new_key: RawKey) -> Result<()> {
        if self.is_locked_out() {
            return Err(Error::LockedOut);
        }

        // Check the key exists first so we don't pay the fragmentation
        // cost on a missing handle. This check is only a shortcut; the
        // authoritative one runs under the writer lock.
        if !self.inner.keys.load().contains_key(&handle.id()) {
            return Err(Error::KeyNotFound);
        }

        let new_len = new_key.len();
        let new_fragments = Arc::new(self.fragment_pipeline(&new_key)?);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let new_metadata = KeyMetadata::new(now, new_len, None);

        let (previous, name) = {
            let _writer = self.lock_writer();
            let current = self.inner.keys.load_full();
            if !current.contains_key(&handle.id()) {
                // Unregistered while we were fragmenting.
                return Err(Error::KeyNotFound);
            }
            let mut new_map = (*current).clone();
            let Some(entry) = new_map.get_mut(&handle.id()) else {
                return Err(Error::KeyNotFound);
            };
            entry.fragments = new_fragments;
            entry.metadata = new_metadata;
            let name = entry.name.clone();
            (self.inner.keys.swap(Arc::new(new_map)), name)
        };
        drop(previous);
        self.emit_audit(&name, AccessKind::Rotate, Cow::Borrowed(""));
        Ok(())
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
    /// reserved key name `"<master>"` (so it counts toward the lockout
    /// threshold like any other reported failure) and the lockout (if
    /// any) remains in place. The digest comparison goes through
    /// [`subtle::ConstantTimeEq`].
    ///
    /// # Limits
    ///
    /// - There is **no rate limit or backoff** on attempts. Callers that
    ///   expose this to untrusted input must throttle it themselves.
    /// - The stored value is an unsalted, fast BLAKE3 digest. A low-entropy
    ///   master credential can be guessed offline by anyone who can read
    ///   the vault's memory. Use a high-entropy credential.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidConfig`](crate::Error::InvalidConfig) if no
    ///   master credential is registered.
    /// - [`Error::Acquisition`](crate::Error::Acquisition) with source
    ///   `"master"` on mismatch.
    pub fn unlock_with_master(&self, attempt: &[u8]) -> Result<()> {
        let stored = self.inner.master_hash.as_ref().ok_or_else(|| {
            Error::InvalidConfig(
                "vault has no master key registered; pass with_master_key at build time"
                    .to_string(),
            )
        })?;
        let attempt_hash = master_digest(attempt);
        let matched = bool::from(stored[..].ct_eq(&attempt_hash[..]));
        drop(attempt_hash);
        self.emit_audit(
            "<master>",
            AccessKind::MasterUnlockAttempt { matched },
            Cow::Borrowed(""),
        );
        if matched {
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
/// Used by the `fragment` (write) path. For involution-based codices
/// `decode == encode`; the function name reflects that — it's a single
/// transformation pass either way. Allocates a fresh [`RawKey`] for the
/// transformed output and transforms it in place, so the buffer is
/// zeroed on drop even if a user codex panics partway through.
fn codex_apply(codex: &dyn Codex, key: &RawKey) -> RawKey {
    let mut out = RawKey::new(key.as_bytes().to_vec());
    for b in out.as_bytes_mut() {
        *b = codex.encode(*b);
    }
    out
}

/// In-place codex decode over a mutable byte slice.
///
/// Used by the [`KeyVault::with_key`] hot path: the thread-local scratch
/// buffer holds the defragmented (codex-encoded) bytes; we run the codex
/// over them in place rather than allocating a fresh [`RawKey`]. Zero
/// allocations.
fn codex_decode_in_place(codex: &dyn Codex, bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        *b = codex.decode(*b);
    }
}

// ------------------------- Hot-path scratch -------------------------
//
// `KeyVault::with_key` defragments into this thread-local instead of
// allocating a fresh `RawKey` per call. The buffer grows lazily to the
// largest key the thread has accessed; subsequent calls reuse the
// allocation. A `ZeroOnExit` guard zeroes it when each call ends
// (panic-safe). The buffer's pages are locked through the same
// reference-counted page table as `LockedBytes`, so the plaintext copy
// that exists while the callback runs is not paged out either.

thread_local! {
    static SCRATCH: core::cell::RefCell<Scratch> = const { core::cell::RefCell::new(Scratch::new()) };
}

/// Per-thread scratch buffer for [`KeyVault::with_key`].
struct Scratch {
    buf: Vec<u8>,
    /// `true` if `buf`'s pages are referenced in the page-lock table.
    locked: bool,
}

impl Scratch {
    const fn new() -> Self {
        Self {
            buf: Vec::new(),
            locked: false,
        }
    }

    /// Make sure the buffer holds at least `len` bytes. Growing allocates
    /// a new locked buffer and releases the old one; the buffer is never
    /// resized in place, so the locked address range stays valid.
    fn ensure_len(&mut self, len: usize) {
        if self.buf.len() >= len {
            return;
        }
        let new_buf = alloc::vec![0u8; len];
        let new_locked = if new_buf.is_empty() {
            false
        } else {
            // SAFETY: `new_buf` is a live allocation of `len` bytes. It is
            // moved into `self.buf` (the heap buffer does not move) and
            // never resized; `release` passes the same pointer and length.
            unsafe { acquire_region(new_buf.as_ptr(), new_buf.len()) }
        };
        self.release();
        self.buf = new_buf;
        self.locked = new_locked;
    }

    /// Zero the current buffer and drop its page references.
    fn release(&mut self) {
        self.buf.as_mut_slice().zeroize();
        if self.locked {
            // SAFETY: same pointer and length as the `acquire_region` call
            // in `ensure_len`; the buffer is still live.
            unsafe { release_region(self.buf.as_ptr(), self.buf.len()) };
            self.locked = false;
        }
        self.buf = Vec::new();
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.release();
    }
}

/// Guard that volatile-zeros the borrowed scratch slice when it drops.
/// `KeyVault::with_key` creates it before defragmenting into the
/// scratch, so recovered key material is scrubbed on success, on an
/// error partway through defragmentation, and on unwind from a
/// panicking codex or user callback.
struct ZeroOnExit<'a>(&'a mut [u8]);

impl Drop for ZeroOnExit<'_> {
    fn drop(&mut self) {
        volatile_zero_slice(self.0);
    }
}

/// Volatile-zero a byte slice. Used to scrub the scratch buffer when
/// the user callback returns, even if it panics.
fn volatile_zero_slice(s: &mut [u8]) {
    let len = s.len();
    if len == 0 {
        return;
    }
    let ptr = s.as_mut_ptr();
    for i in 0..len {
        // SAFETY: ptr is the unique writable borrow we hold for the
        // duration of this function call; ptr.add(i) for i in 0..len
        // is in-bounds.
        unsafe {
            core::ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
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
    /// Optional Layer-9 audit sink. Defaults to
    /// [`NoAudit`](crate::NoAudit) at `build` time.
    audit: Option<Arc<dyn AuditSink>>,
    /// Hash of the master credential, if one was registered. We hold
    /// the hash (not the plaintext) so the master bytes don't linger
    /// in the builder's state. Zeroized on drop, including clones.
    master_hash: Option<MasterDigest>,
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
            .field("audit", &self.audit.as_ref().map(|_| "<set>"))
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
            audit: None,
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
    /// The codex is obfuscation, not encryption: its table is stored in the
    /// same process memory as the fragments. Without this call no codex is
    /// used; the `codex` Cargo feature does not add one.
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
    /// closest statistical match to the key;
    /// [`KeyDerivedDecoy`](crate::KeyDerivedDecoy) for BLAKE3-XOF derived
    /// CSPRNG-like output;
    /// [`RandomDecoy`](crate::RandomDecoy) for raw CSPRNG output.
    ///
    /// Without this call the vault stores no decoys; the `decoy-*` Cargo
    /// features do not add one. Decoys are obfuscation only: the layout
    /// buffer that marks them is in the same process memory.
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

    /// Attach a Layer-9 audit sink.
    ///
    /// Every vault operation (register, unregister, read, rotate,
    /// fragment, defragment, master-unlock attempt) emits an
    /// [`AuditEvent`](crate::AuditEvent) through this sink. Default
    /// is [`NoAudit`](crate::NoAudit) — events are constructed and
    /// discarded.
    ///
    /// See [`AuditSink`](crate::AuditSink) for the implementor
    /// contract (non-blocking, no panics, no back-pressure).
    #[must_use]
    pub fn with_audit_sink<A>(mut self, sink: A) -> Self
    where
        A: AuditSink + 'static,
    {
        self.audit = Some(Arc::new(sink));
        self
    }

    /// Register a master credential for emergency unlock.
    ///
    /// The vault stores the **BLAKE3 hash** of the supplied bytes; the
    /// plaintext is dropped immediately (and zeroed via
    /// `RawKey::Drop`). The stored digest is zeroized when the builder
    /// or vault drops. Use [`KeyVault::unlock_with_master`] later to
    /// clear a threshold-driven lockout.
    ///
    /// The digest is unsalted, fast BLAKE3, not a password hash: use a
    /// high-entropy credential, not a memorable passphrase.
    ///
    /// Calling this twice replaces the previously-stored hash. An empty
    /// key (zero length) registers the BLAKE3 hash of the empty string,
    /// which any empty attempt matches; the function does not reject it
    /// for symmetry with the rest of the builder API.
    #[must_use]
    pub fn with_master_key(mut self, master: RawKey) -> Self {
        self.master_hash = Some(master_digest(master.as_bytes()));
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
        let audit: Arc<dyn AuditSink> = self
            .audit
            .unwrap_or_else(|| Arc::new(crate::audit::NoAudit));
        KeyVault {
            inner: Arc::new(VaultInner {
                config: self.config,
                fragmenter: self.fragmenter,
                codex: self.codex,
                monitor,
                keys: ArcSwap::from_pointee(HashMap::new()),
                writer: Mutex::new(()),
                failure_tracker: Mutex::new(HashMap::new()),
                locked_out: AtomicBool::new(false),
                master_hash: self.master_hash,
                audit,
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

    // ----- Phase 0.9: Layer 9 audit-trail tests -----

    /// Helper audit sink that captures every event for assertions.
    struct CapturingAudit {
        events: Mutex<Vec<(crate::audit::AccessKind, String)>>,
    }

    impl CapturingAudit {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }
        fn count_of(&self, kind: crate::audit::AccessKind) -> usize {
            self.events
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| *k == kind)
                .count()
        }
        fn last_for(&self, kind: crate::audit::AccessKind) -> Option<String> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find_map(|(k, name)| (*k == kind).then(|| name.clone()))
        }
    }

    impl crate::audit::AuditSink for CapturingAudit {
        fn on_event(&self, event: &crate::audit::AuditEvent) {
            self.events
                .lock()
                .unwrap()
                .push((event.kind, event.key_name.clone()));
        }
    }

    #[test]
    fn register_emits_register_event() {
        let audit = Arc::new(CapturingAudit::new());
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_audit_sink(Arc::clone(&audit) as Arc<dyn crate::audit::AuditSink>)
            .build();
        let _ = v
            .register("primary", RawKey::new(alloc::vec![1u8; 16]))
            .unwrap();
        assert_eq!(audit.count_of(crate::audit::AccessKind::Register), 1);
        assert_eq!(
            audit.last_for(crate::audit::AccessKind::Register),
            Some("primary".to_string())
        );
    }

    #[test]
    fn unregister_emits_unregister_event() {
        let audit = Arc::new(CapturingAudit::new());
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_audit_sink(Arc::clone(&audit) as Arc<dyn crate::audit::AuditSink>)
            .build();
        let h = v
            .register("primary", RawKey::new(alloc::vec![1u8; 16]))
            .unwrap();
        v.unregister(h).unwrap();
        assert_eq!(audit.count_of(crate::audit::AccessKind::Unregister), 1);
        assert_eq!(
            audit.last_for(crate::audit::AccessKind::Unregister),
            Some("primary".to_string())
        );
    }

    #[test]
    fn with_key_emits_read_event() {
        let audit = Arc::new(CapturingAudit::new());
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_audit_sink(Arc::clone(&audit) as Arc<dyn crate::audit::AuditSink>)
            .build();
        let h = v
            .register("data", RawKey::new(alloc::vec![0xa5u8; 16]))
            .unwrap();
        let _ = v.with_key(h, <[u8]>::to_vec).unwrap();
        assert_eq!(audit.count_of(crate::audit::AccessKind::Read), 1);
        assert_eq!(
            audit.last_for(crate::audit::AccessKind::Read),
            Some("data".to_string())
        );
    }

    #[test]
    fn rotate_emits_rotate_event() {
        let audit = Arc::new(CapturingAudit::new());
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_audit_sink(Arc::clone(&audit) as Arc<dyn crate::audit::AuditSink>)
            .build();
        let h = v
            .register("data", RawKey::new(alloc::vec![1u8; 16]))
            .unwrap();
        v.rotate(h, RawKey::new(alloc::vec![2u8; 16])).unwrap();
        assert_eq!(audit.count_of(crate::audit::AccessKind::Rotate), 1);
        assert_eq!(
            audit.last_for(crate::audit::AccessKind::Rotate),
            Some("data".to_string())
        );
    }

    #[test]
    fn fragment_and_defragment_emit_oneshot_events() {
        let audit = Arc::new(CapturingAudit::new());
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_audit_sink(Arc::clone(&audit) as Arc<dyn crate::audit::AuditSink>)
            .build();
        let raw = RawKey::new(alloc::vec![0u8; 16]);
        let frags = v.fragment(&raw).unwrap();
        let _ = v.defragment(&frags).unwrap();
        assert_eq!(audit.count_of(crate::audit::AccessKind::OneShotFragment), 1);
        assert_eq!(
            audit.count_of(crate::audit::AccessKind::OneShotDefragment),
            1
        );
    }

    #[test]
    fn master_unlock_emits_event_with_match_status() {
        let audit = Arc::new(CapturingAudit::new());
        let master = b"correct".to_vec();
        let v = KeyVaultBuilder::new()
            .with_master_key(RawKey::new(master.clone()))
            .with_failure_threshold(1, Duration::from_secs(30))
            .with_audit_sink(Arc::clone(&audit) as Arc<dyn crate::audit::AuditSink>)
            .build();

        v.report_failure("k", None);
        assert!(v.is_locked_out());

        let _ = v.unlock_with_master(b"wrong");
        assert_eq!(
            audit.count_of(crate::audit::AccessKind::MasterUnlockAttempt { matched: false }),
            1
        );

        v.unlock_with_master(&master).unwrap();
        assert_eq!(
            audit.count_of(crate::audit::AccessKind::MasterUnlockAttempt { matched: true }),
            1
        );
    }

    #[test]
    fn no_audit_default_does_not_panic() {
        // Default sink is NoAudit — events are still constructed but go
        // nowhere. Verify the happy path completes without surprises.
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let h = v.register("k", RawKey::new(alloc::vec![0u8; 16])).unwrap();
        let _ = v.with_key(h, <[u8]>::to_vec).unwrap();
        v.unregister(h).unwrap();
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

    // ----- Scratch-buffer wiping on every exit path -----

    /// `true` if every byte of this thread's `with_key` scratch buffer
    /// is zero. Also returns the buffer length so callers can check the
    /// scratch was actually used.
    fn scratch_is_all_zero() -> (bool, usize) {
        SCRATCH.with(|cell| {
            let scratch = cell.borrow();
            (scratch.buf.iter().all(|&b| b == 0), scratch.buf.len())
        })
    }

    /// Replace the fragments stored for `handle` with `fragments`.
    fn replace_fragments(v: &KeyVault, handle: KeyHandle, fragments: Fragments) {
        let fragments = Arc::new(fragments);
        let _previous = v.inner.keys.rcu(|current| {
            let mut new_map = (**current).clone();
            let entry = new_map.get_mut(&handle.id()).expect("handle registered");
            entry.fragments = Arc::clone(&fragments);
            new_map
        });
    }

    #[test]
    fn with_key_zeroes_scratch_when_defragment_fails_partway() {
        use crate::memory::LockedBytes;

        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let h = v
            .register("partial", RawKey::new(b"abcdef".to_vec()))
            .unwrap();

        // Corrupt layout: chunk 0 (4 bytes at offset 0) is valid and gets
        // copied into the scratch; chunk 1 (4 bytes at offset 4) runs past
        // `total_len = 6`, so `defragment_into` errors after the first
        // write.
        let chunks = alloc::vec![
            LockedBytes::from_slice(b"SECR"),
            LockedBytes::from_slice(b"ETXX"),
        ];
        let mut layout = Vec::new();
        layout.extend_from_slice(&0u32.to_le_bytes());
        layout.extend_from_slice(&4u32.to_le_bytes());
        let corrupt = Fragments::from_parts(chunks, LockedBytes::from_slice(&layout), 6);
        replace_fragments(&v, h, corrupt);

        let mut called = false;
        let result = v.with_key(h, |_| called = true);
        assert!(matches!(result, Err(Error::Defragment(_))));
        assert!(!called);

        let (all_zero, len) = scratch_is_all_zero();
        assert!(len >= 6, "scratch buffer was not used");
        assert!(all_zero, "plaintext left in scratch after defragment error");
    }

    /// Codex whose `encode` is the identity and whose `decode` panics on
    /// the third byte once armed.
    struct PanickingCodex {
        armed: AtomicBool,
        decoded: core::sync::atomic::AtomicUsize,
    }

    impl Codex for PanickingCodex {
        fn encode(&self, byte: u8) -> u8 {
            byte
        }

        fn decode(&self, byte: u8) -> u8 {
            let fail = self.armed.load(Ordering::SeqCst)
                && self.decoded.fetch_add(1, Ordering::SeqCst) == 2;
            assert!(!fail, "codex decode failure (test)");
            byte
        }
    }

    #[test]
    fn with_key_zeroes_scratch_when_codex_panics() {
        let codex = Arc::new(PanickingCodex {
            armed: AtomicBool::new(false),
            decoded: core::sync::atomic::AtomicUsize::new(0),
        });
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_codex(ArcCodex(Arc::clone(&codex)))
            .build();
        let h = v
            .register("panicky", RawKey::new(b"panic-secret-123".to_vec()))
            .unwrap();

        codex.armed.store(true, Ordering::SeqCst);
        let mut called = false;
        let outcome = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
            v.with_key(h, |_| called = true)
        }));
        assert!(outcome.is_err(), "codex panic should propagate");
        assert!(!called);

        let (all_zero, len) = scratch_is_all_zero();
        assert!(len >= 16, "scratch buffer was not used");
        assert!(all_zero, "plaintext left in scratch after codex panic");

        // The vault stays usable on this thread after the unwind.
        codex.armed.store(false, Ordering::SeqCst);
        let copy = v.with_key(h, <[u8]>::to_vec).unwrap();
        assert_eq!(copy, b"panic-secret-123");
        assert!(scratch_is_all_zero().0);
    }

    #[test]
    fn with_key_zeroes_scratch_when_callback_panics() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let h = v
            .register("cb", RawKey::new(b"callback-secret".to_vec()))
            .unwrap();
        let outcome = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
            v.with_key(h, |_| panic!("callback failure (test)"))
        }));
        assert!(outcome.is_err());
        let (all_zero, len) = scratch_is_all_zero();
        assert!(len >= 15, "scratch buffer was not used");
        assert!(all_zero, "plaintext left in scratch after callback panic");
    }

    /// Adapter so a test can keep an `Arc` handle to a codex it also
    /// hands to the builder (which takes the codex by value).
    struct ArcCodex<C>(Arc<C>);

    impl<C: Codex> Codex for ArcCodex<C> {
        fn encode(&self, byte: u8) -> u8 {
            self.0.encode(byte)
        }

        fn decode(&self, byte: u8) -> u8 {
            self.0.decode(byte)
        }
    }

    // ----- Audit: no phantom one-shot events from register / rotate -----

    #[test]
    fn register_and_rotate_emit_no_oneshot_fragment_event() {
        let audit = Arc::new(CapturingAudit::new());
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_audit_sink(Arc::clone(&audit) as Arc<dyn crate::audit::AuditSink>)
            .build();
        let h = v.register("k", RawKey::new(alloc::vec![1u8; 16])).unwrap();
        v.rotate(h, RawKey::new(alloc::vec![2u8; 16])).unwrap();
        assert_eq!(audit.count_of(crate::audit::AccessKind::Register), 1);
        assert_eq!(audit.count_of(crate::audit::AccessKind::Rotate), 1);
        assert_eq!(
            audit.count_of(crate::audit::AccessKind::OneShotFragment),
            0,
            "register/rotate emitted an unnamed OneShotFragment event"
        );
    }

    // ----- Registry write races -----

    /// Codex whose `encode` blocks once, when armed, until the test lets it
    /// continue. `rotate` calls `encode` while fragmenting the new key,
    /// after its existence pre-check and before it installs the update, so
    /// this parks `rotate` at the point where a concurrent `unregister`
    /// used to slip in.
    struct GateCodex {
        armed: AtomicBool,
        at_gate: AtomicBool,
        release: AtomicBool,
    }

    impl Codex for GateCodex {
        fn encode(&self, byte: u8) -> u8 {
            if self.armed.swap(false, Ordering::SeqCst) {
                self.at_gate.store(true, Ordering::SeqCst);
                while !self.release.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
            }
            byte
        }

        fn decode(&self, byte: u8) -> u8 {
            byte
        }
    }

    /// `rotate` and `unregister` on the same key, with `unregister`
    /// running while `rotate` sits between its pre-check and its update.
    /// `rotate` must report `KeyNotFound` and must not emit a Rotate audit
    /// event.
    ///
    /// The vault is padded with filler keys so each copy of the registry
    /// takes a while. In 1.0.1 `rotate` used `ArcSwap::rcu` and never
    /// reset its `found` flag between retries: when the `unregister` swap
    /// landed inside `rotate`'s copy-and-swap window, the retry ran on a
    /// map without the key and `rotate` still returned `Ok`.
    #[test]
    fn rotate_loses_to_concurrent_unregister_cleanly() {
        for round in 0..10 {
            let gate = Arc::new(GateCodex {
                armed: AtomicBool::new(false),
                at_gate: AtomicBool::new(false),
                release: AtomicBool::new(false),
            });
            let audit = Arc::new(CapturingAudit::new());
            let v = KeyVaultBuilder::new()
                .normalize_with_blake3(false)
                .with_codex(ArcCodex(Arc::clone(&gate)))
                .with_audit_sink(Arc::clone(&audit) as Arc<dyn crate::audit::AuditSink>)
                .build();
            let h = v
                .register(format!("k{round}"), RawKey::new(alloc::vec![1u8; 32]))
                .unwrap();
            pad_registry(&v, 100_000);
            gate.armed.store(true, Ordering::SeqCst);

            std::thread::scope(|s| {
                let rotator = s.spawn(|| v.rotate(h, RawKey::new(alloc::vec![2u8; 32])));
                while !gate.at_gate.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                // `rotate` has passed its pre-check and is parked in the
                // codex. Start the unregister, let `rotate` continue once
                // the unregister is under way, then wait for both.
                let unregister = s.spawn(|| v.unregister(h));
                wait_until_writer_busy_or_done(&v, &unregister);
                gate.release.store(true, Ordering::SeqCst);
                unregister.join().unwrap().unwrap();
                let result = rotator.join().unwrap();
                assert!(
                    matches!(result, Err(Error::KeyNotFound)),
                    "round {round}: rotate returned {result:?} for an unregistered key"
                );
            });
            assert!(!v.contains(h));
            assert_eq!(audit.count_of(crate::audit::AccessKind::Rotate), 0);
            assert_eq!(audit.count_of(crate::audit::AccessKind::Unregister), 1);
        }
    }

    /// Add `n` filler entries straight into the registry (sharing one
    /// `Fragments`), so that copying the map is slow.
    fn pad_registry(v: &KeyVault, n: usize) {
        let mut map = (*v.inner.keys.load_full()).clone();
        let shared = Arc::new(
            v.inner
                .fragmenter
                .fragment(&RawKey::new(alloc::vec![9u8; 8]))
                .unwrap(),
        );
        for i in 0..n {
            let _ = map.insert(
                KeyHandle::allocate().id(),
                KeyEntry {
                    name: format!("filler-{i}"),
                    fragments: Arc::clone(&shared),
                    metadata: KeyMetadata::new(Duration::ZERO, 8, None),
                },
            );
        }
        v.inner.keys.store(Arc::new(map));
    }

    /// Spin until another thread holds the registry writer lock, or the
    /// given thread has finished.
    fn wait_until_writer_busy_or_done<T>(
        v: &KeyVault,
        other: &std::thread::ScopedJoinHandle<'_, T>,
    ) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !other.is_finished() && Instant::now() < deadline {
            match v.inner.writer.try_lock() {
                Ok(guard) => drop(guard),
                Err(_) => return,
            }
            std::thread::yield_now();
        }
    }

    /// Several threads race `rotate` against one `unregister` per key.
    /// For every key, `unregister` succeeds exactly once, the key is gone
    /// afterwards, and the number of `Rotate` audit events equals the
    /// number of `rotate` calls that returned `Ok`.
    #[test]
    fn rotate_unregister_stress_keeps_registry_and_audit_consistent() {
        let audit = Arc::new(CapturingAudit::new());
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_audit_sink(Arc::clone(&audit) as Arc<dyn crate::audit::AuditSink>)
            .build();
        pad_registry(&v, 2000);

        let rotators = 4;
        let mut rotate_ok = 0usize;
        for round in 0..100 {
            let h = v
                .register(format!("target-{round}"), RawKey::new(alloc::vec![1u8; 32]))
                .unwrap();
            let barrier = std::sync::Barrier::new(rotators + 1);
            let (unreg, oks) = std::thread::scope(|s| {
                let joins: Vec<_> = (0..rotators)
                    .map(|t| {
                        let (v, barrier) = (&v, &barrier);
                        s.spawn(move || {
                            let _ = barrier.wait();
                            let fill = u8::try_from(t + 10).unwrap();
                            v.rotate(h, RawKey::new(alloc::vec![fill; 32])).is_ok()
                        })
                    })
                    .collect();
                let _ = barrier.wait();
                let unreg = v.unregister(h);
                let oks = joins
                    .into_iter()
                    .map(|j| j.join().unwrap())
                    .filter(|&ok| ok)
                    .count();
                (unreg, oks)
            });
            assert!(unreg.is_ok(), "round {round}: unregister failed");
            assert!(!v.contains(h));
            assert!(matches!(v.unregister(h), Err(Error::KeyNotFound)));
            assert!(matches!(
                v.rotate(h, RawKey::new(alloc::vec![0u8; 32])),
                Err(Error::KeyNotFound)
            ));
            rotate_ok += oks;
            assert_eq!(
                audit.count_of(crate::audit::AccessKind::Rotate),
                rotate_ok,
                "round {round}: Rotate events do not match successful rotations"
            );
        }
        assert_eq!(audit.count_of(crate::audit::AccessKind::Unregister), 100);
    }

    // ----- Page-lock reference counting through the vault -----

    /// Pages touched by every locked chunk and layout buffer of
    /// `handle`'s fragments.
    fn locked_pages_of(v: &KeyVault, handle: KeyHandle) -> Vec<usize> {
        let snapshot = v.inner.keys.load();
        let frags = &snapshot.get(&handle.id()).expect("registered").fragments;
        let mut pages = Vec::new();
        for lb in frags
            .chunks()
            .iter()
            .chain(core::iter::once(frags.layout()))
        {
            if lb.is_locked() {
                pages.extend(crate::memory::pages_of(lb.as_bytes()));
            }
        }
        pages.sort_unstable();
        pages.dedup();
        pages
    }

    /// Two keys whose fragments share a page: unregistering one must leave
    /// that page locked for the other. In 1.0.1 every fragment called
    /// `munlock` / `VirtualUnlock` on its whole page range when dropped,
    /// which released the lock on pages the other key still used.
    #[test]
    fn unregistering_one_key_keeps_shared_pages_locked_for_another() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        // Small fragments come from the allocator's small-size bins, so two
        // keys registered back to back almost always share a page. Keep
        // registering pairs until they do.
        let mut shared = None;
        for i in 0..64 {
            let a = v
                .register(format!("a{i}"), RawKey::new(alloc::vec![0x11; 32]))
                .unwrap();
            let b = v
                .register(format!("b{i}"), RawKey::new(alloc::vec![0x22; 32]))
                .unwrap();
            let pa = locked_pages_of(&v, a);
            let pb = locked_pages_of(&v, b);
            if let Some(&page) = pa.iter().find(|p| pb.contains(p)) {
                shared = Some((a, b, page));
                break;
            }
        }
        let Some((a, b, page)) = shared else {
            // No locks were granted at all (RLIMIT_MEMLOCK of 0, or the
            // Windows working-set quota is exhausted): nothing to count.
            return;
        };
        assert!(crate::memory::page_lock_count(page) >= 2);

        v.unregister(a).unwrap();

        assert!(
            crate::memory::page_lock_count(page) >= 1,
            "shared page was unlocked when the other key was unregistered"
        );
        for p in locked_pages_of(&v, b) {
            assert!(crate::memory::page_lock_count(p) >= 1);
        }
        assert_eq!(
            v.with_key(b, <[u8]>::to_vec).unwrap(),
            alloc::vec![0x22; 32]
        );
    }

    #[test]
    fn with_key_scratch_buffer_is_page_locked() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let h = v
            .register("scratch", RawKey::new(alloc::vec![0x33; 48]))
            .unwrap();
        let _ = v.with_key(h, <[u8]>::len).unwrap();
        SCRATCH.with(|cell| {
            let scratch = cell.borrow();
            assert!(scratch.buf.len() >= 48);
            if scratch.locked {
                for p in crate::memory::pages_of(&scratch.buf) {
                    assert!(crate::memory::page_lock_count(p) >= 1);
                }
            }
        });
    }

    #[test]
    fn scratch_growth_keeps_results_and_leaves_buffer_zeroed() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let small = v.register("s", RawKey::new(alloc::vec![0x44; 8])).unwrap();
        let big = v
            .register("b", RawKey::new(alloc::vec![0x55; 4096]))
            .unwrap();
        assert_eq!(
            v.with_key(small, <[u8]>::to_vec).unwrap(),
            alloc::vec![0x44; 8]
        );
        assert_eq!(
            v.with_key(big, <[u8]>::to_vec).unwrap(),
            alloc::vec![0x55; 4096]
        );
        assert_eq!(
            v.with_key(small, <[u8]>::to_vec).unwrap(),
            alloc::vec![0x44; 8]
        );
        let (all_zero, len) = scratch_is_all_zero();
        assert!(len >= 4096);
        assert!(all_zero);
    }
}
