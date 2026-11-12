//! The vault itself.
//!
//! [`KeyVault`] owns the named-key registry, the configured fragmenter,
//! optional decoy and codex, the failure tracker and lockout state, the
//! optional master credential, and the monitor / audit hooks.
//!
//! # Concurrency
//!
//! Reads (`with_key`, `contains`, `metadata`, `handle_for_name`) load a
//! snapshot of the registry: lock-free with `std` (`ArcSwap`), a short
//! spin lock without it. A read takes no reference count on the key it
//! reads (since 1.2), so threads reading the same key do not write to a
//! shared cache line. Writes (`register`, `unregister`, `rotate`) are
//! serialized by an internal writer lock: each one re-checks the registry
//! and installs its change while holding the lock, so a duplicate name
//! cannot be inserted twice and `rotate` cannot report success for a key
//! that was removed first. Fragmentation (the slow part of `register`
//! and `rotate`) runs before the lock is taken.
//!
//! The snapshot is a persistent hash trie (`trie.rs`, since 1.2): a write
//! copies only the few nodes on the path to the key it changes, so its
//! cost does not grow with the number of keys. Before 1.2 every write
//! copied the whole map.
//!
//! ```
//! use key_vault::KeyVault;
//!
//! // `KeyVault::new()` is `KeyVaultBuilder::new().build()`. Construction
//! // is cheap and infallible.
//! let _vault = KeyVault::new();
//! ```

mod tracker;
mod trie;

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::hash::Hasher;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

#[cfg(feature = "std")]
use arc_swap::ArcSwap;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use self::tracker::{FailureCounts, FailureTracker, Windows};
use self::trie::HashTrie;
use crate::Result;
use crate::audit::{AccessKind, AuditEvent, AuditSink};
use crate::clock::Clock;
use crate::codex::Codex;
use crate::decoy::DecoyStrategy;
use crate::error::Error;
use crate::fetcher::RawKey;
use crate::fragment::{FragmentStrategy, Fragments, StandardFragmenter};
use crate::handle::{KeyHandle, KeyId};
use crate::memory::{LockedBytes, ScratchBuf};
use crate::metadata::KeyMetadata;
use crate::monitor::{
    AccessContext, FailureContext, LockoutScope, MemoryLockContext, SecurityMonitor,
    ThresholdContext,
};
use crate::normalize::{
    blake3_derive_into, blake3_keyed_into, blake3_keyed_normalize, blake3_normalize,
};
use crate::sync::Mutex;

/// The registry: every registered key by id, and the id of every name.
#[derive(Clone, Default)]
struct Snapshot {
    by_id: HashTrie<KeyId, Arc<KeyEntry>>,
    by_name: HashTrie<String, KeyId>,
}

impl Snapshot {
    #[inline]
    fn get(&self, id: KeyId) -> Option<&Arc<KeyEntry>> {
        self.by_id.get(id_hash(id), &id)
    }

    /// The entry registered under `name`, whose hash is `name_hash`.
    fn find(&self, name_hash: u64, name: &str) -> Option<&Arc<KeyEntry>> {
        self.by_name
            .get(name_hash, name)
            .and_then(|id| self.get(*id))
    }

    fn len(&self) -> usize {
        self.by_id.len()
    }

    fn for_each_entry(&self, mut f: impl FnMut(&KeyEntry)) {
        self.by_id.for_each(|_, entry| f(entry));
    }
}

/// Trie hash of a key id. Ids are sequential, which spreads them evenly
/// over the low bits the trie uses first.
#[inline]
fn id_hash(id: KeyId) -> u64 {
    id.get().get()
}

/// Atomically replaceable registry snapshot.
#[cfg(feature = "std")]
type Registry = ArcSwap<Snapshot>;
#[cfg(not(feature = "std"))]
type Registry = crate::sync::ArcCell<Snapshot>;

/// What `Registry::load` returns.
#[cfg(feature = "std")]
type SnapshotGuard = arc_swap::Guard<Arc<Snapshot>>;
#[cfg(not(feature = "std"))]
type SnapshotGuard = Arc<Snapshot>;

/// Context string for deriving a 32-byte normalization key from a
/// caller-supplied one (BLAKE3 `derive_key` mode). Changing it changes
/// every normalized key, so it is fixed forever.
const NORMALIZATION_KEY_CONTEXT: &str = "key-vault 2026-10 normalization key v1";

/// Reserved key name used for master-unlock failures and audit events.
const MASTER_NAME: &str = "<master>";

/// Default upper bound on failures per key before lockout. `0` means
/// "never lock out" — i.e. the threshold is disabled. The default
/// [`VaultConfig`] disables it so failures pass through to the monitor
/// without triggering lockout unless the caller explicitly opts in.
const DEFAULT_MAX_FAILURES: u32 = 0;

/// Default window for the failure counter when no override is set.
const DEFAULT_FAILURE_WINDOW: Duration = Duration::from_secs(60);

/// Vault configuration.
///
/// Read it back with [`KeyVault::config`]. Every field is set through
/// [`KeyVaultBuilder`]. Marked `#[non_exhaustive]` so new fields are
/// additive.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)] // independent switches, public since 1.0.
pub struct VaultConfig {
    /// If `true`, raw key material is BLAKE3-normalized to 32 bytes before
    /// fragmentation. Default is `true`.
    pub key_normalization: bool,

    /// `true` if normalization uses keyed BLAKE3
    /// ([`KeyVaultBuilder::with_keyed_normalization`] or
    /// [`KeyVaultBuilder::with_normalization_key`]). Only meaningful when
    /// `key_normalization` is on. Default: `false`.
    pub keyed_normalization: bool,

    /// Failures (per key name) within the configured `failure_window`
    /// required to trigger vault-wide lockout. `0` disables it: failures
    /// still flow to the configured monitor but never lock the vault out.
    /// Default: `0` (disabled).
    ///
    /// Failures are counted only when the caller reports them through
    /// [`KeyVault::report_failure`] (and on a wrong master credential).
    /// The lockout that follows applies to the whole vault, not just the
    /// key name that crossed the threshold; see `key_lockout_threshold`
    /// for a per-key lockout.
    pub max_failures_before_lockout: u32,

    /// Sliding window for the vault-wide failure counter. Failures older
    /// than this fall off the counter for a given key. Default: 60 seconds.
    pub failure_window: Duration,

    /// Failures reported for one key name within `key_lockout_window`
    /// that lock out that key only ([`KeyVaultBuilder::with_key_lockout`]).
    /// `0` disables per-key lockout. Default: `0` (disabled).
    pub key_lockout_threshold: u32,

    /// Sliding window for the per-key failure counter. Default: 60 seconds.
    pub key_lockout_window: Duration,

    /// How long a per-key lockout lasts. `None` (the default) means until
    /// [`KeyVault::clear_key_lockout`], [`KeyVault::clear_lockout`] or a
    /// successful [`KeyVault::unlock_with_master`].
    pub key_lockout_duration: Option<Duration>,

    /// Delay after the first failed master-unlock attempt; it doubles
    /// with each further failure. `Duration::ZERO` (the default) disables
    /// the backoff. See [`KeyVaultBuilder::with_master_unlock_backoff`].
    pub master_backoff_base: Duration,

    /// Upper bound on the master-unlock backoff delay.
    pub master_backoff_max: Duration,

    /// `true` if registered keys live in private page-protected mappings
    /// that are inaccessible except while being read
    /// (`KeyVaultBuilder::with_page_protection`). Default: `false`.
    pub page_protection: bool,

    /// `true` if [`KeyVault::register`], [`KeyVault::rotate`] and
    /// [`KeyVault::with_key`] fail with
    /// [`Error::MemoryLock`](crate::Error::MemoryLock) rather than hold key
    /// bytes in memory that could not be page-locked
    /// ([`KeyVaultBuilder::with_strict_locking`]). Default: `false`.
    /// Since 1.2.
    pub strict_locking: bool,

    /// Most names of unregistered keys the failure tracker remembers at
    /// once ([`KeyVaultBuilder::with_failure_tracking_capacity`]). Names of
    /// registered keys are always tracked. Default: 4096. Since 1.2.
    pub failure_tracking_capacity: usize,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultConfig {
    /// Default configuration: normalization on, every lockout, backoff and
    /// page protection off.
    #[must_use]
    pub fn new() -> Self {
        Self {
            key_normalization: true,
            keyed_normalization: false,
            max_failures_before_lockout: DEFAULT_MAX_FAILURES,
            failure_window: DEFAULT_FAILURE_WINDOW,
            key_lockout_threshold: 0,
            key_lockout_window: DEFAULT_FAILURE_WINDOW,
            key_lockout_duration: None,
            master_backoff_base: Duration::ZERO,
            master_backoff_max: Duration::ZERO,
            page_protection: false,
            strict_locking: false,
            failure_tracking_capacity: tracker::DEFAULT_CAPACITY,
        }
    }
}

/// Page-locking and dump-exclusion state of a vault's registered keys,
/// from [`KeyVault::memory_status`].
///
/// A key counts as locked only if every page holding its fragments and
/// layout is locked, and as excluded from dumps only if every such page
/// is excluded. Since 1.2.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoryStatus {
    /// Keys registered.
    pub keys: usize,
    /// Keys held entirely in page-locked memory.
    pub locked: usize,
    /// Keys held entirely in memory excluded from crash dumps.
    pub excluded_from_dumps: usize,
}

impl MemoryStatus {
    /// Keys with at least one page that is not locked, and that the OS may
    /// therefore write to swap.
    #[must_use]
    pub fn unlocked(&self) -> usize {
        self.keys - self.locked
    }

    /// `true` if every registered key is held in page-locked memory.
    #[must_use]
    pub fn all_locked(&self) -> bool {
        self.locked == self.keys
    }
}

/// In-memory key vault.
///
/// The vault is the entry point for everything `key-vault` does. Application
/// code constructs one with [`KeyVault::new`] or [`KeyVaultBuilder`],
/// registers [`RawKey`] values under a name, and receives
/// [`KeyHandle`](crate::KeyHandle)s in return. The vault itself is cheap to
/// clone (it is `Arc`-backed internally) and safe to share across threads.
///
/// The vault uses a [`StandardFragmenter`] unless another strategy is set
/// with [`KeyVaultBuilder::with_fragmenter`]. Decoys and a codex are used
/// only when configured on the builder ([`KeyVaultBuilder::with_decoy`],
/// [`KeyVaultBuilder::with_codex`], or [`KeyVaultBuilder::from_features`]).
///
/// [`KeyVault::fragment`] and [`KeyVault::defragment`] are one-shot
/// helpers that run the same pipeline without touching the registry.
#[derive(Clone)]
pub struct KeyVault {
    inner: Arc<VaultInner>,
}

/// Entry in the vault's named-key registry. Holds the fragmented
/// representation of a key, its name (for audit / threshold tracking),
/// and non-secret metadata. Entries are shared between registry
/// snapshots; `rotate` installs a new entry that shares `lock`.
struct KeyEntry {
    name: String,
    /// The vault's hash of `name`.
    name_hash: u64,
    fragments: Fragments,
    metadata: KeyMetadata,
    /// Per-key lockout state, kept across rotations.
    lock: Arc<KeyLock>,
}

/// Lock word: not locked out.
const UNLOCKED: u64 = 0;
/// Lock word: locked out until cleared.
const LOCKED_UNTIL_CLEARED: u64 = u64::MAX;

/// Per-key lockout state: one word, `UNLOCKED`, `LOCKED_UNTIL_CLEARED`, or
/// the clock time in nanoseconds the lockout ends, plus one.
///
/// Before 1.2 lockouts lived in a map keyed by name next to a count of its
/// entries, and the count could drift from the map under concurrent
/// clears. Each key now carries its own word, so there is nothing to keep
/// in step: every change is one atomic operation on the key it is about.
struct KeyLock {
    #[cfg(target_has_atomic = "64")]
    word: core::sync::atomic::AtomicU64,
    #[cfg(not(target_has_atomic = "64"))]
    word: Mutex<u64>,
}

impl KeyLock {
    fn new() -> Self {
        Self {
            #[cfg(target_has_atomic = "64")]
            word: core::sync::atomic::AtomicU64::new(UNLOCKED),
            #[cfg(not(target_has_atomic = "64"))]
            word: Mutex::new(UNLOCKED),
        }
    }

    #[inline]
    fn load(&self) -> u64 {
        #[cfg(target_has_atomic = "64")]
        {
            self.word.load(Ordering::Acquire)
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            *self.word.lock()
        }
    }

    fn swap(&self, value: u64) -> u64 {
        #[cfg(target_has_atomic = "64")]
        {
            self.word.swap(value, Ordering::AcqRel)
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            core::mem::replace(&mut *self.word.lock(), value)
        }
    }

    /// Set the word to `UNLOCKED` if it still holds `current`.
    fn clear_if(&self, current: u64) -> bool {
        #[cfg(target_has_atomic = "64")]
        {
            self.word
                .compare_exchange(current, UNLOCKED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            let mut word = self.word.lock();
            if *word == current {
                *word = UNLOCKED;
                true
            } else {
                false
            }
        }
    }
}

/// `d` in nanoseconds, saturating.
fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// Lock word for a lockout that ends at `until` (`None`: until cleared).
fn lock_word(until: Option<Duration>) -> u64 {
    until.map_or(LOCKED_UNTIL_CLEARED, |t| {
        nanos(t).saturating_add(1).min(LOCKED_UNTIL_CLEARED - 1)
    })
}

/// The fragmenter a vault uses. The built-in default is held by value so
/// the `with_key` hot path calls it without dynamic dispatch.
#[derive(Clone)]
enum Fragmenter {
    Standard(StandardFragmenter),
    Custom(Arc<dyn FragmentStrategy>),
}

impl Fragmenter {
    #[inline]
    fn fragment(&self, key: &RawKey) -> Result<Fragments> {
        match self {
            Self::Standard(s) => s.fragment(key),
            Self::Custom(c) => c.fragment(key),
        }
    }

    #[inline]
    fn defragment(&self, fragments: &Fragments) -> Result<RawKey> {
        match self {
            Self::Standard(s) => s.defragment(fragments),
            Self::Custom(c) => c.defragment(fragments),
        }
    }

    #[inline]
    fn defragment_into(&self, fragments: &Fragments, out: &mut [u8]) -> Result<()> {
        match self {
            Self::Standard(s) => s.defragment_into(fragments, out),
            Self::Custom(c) => c.defragment_into(fragments, out),
        }
    }

    fn describe(&self) -> Cow<'_, str> {
        match self {
            Self::Standard(s) => s.describe(),
            Self::Custom(c) => c.describe(),
        }
    }
}

/// A small secret (normalization key, master verifier) held like key
/// material: locked, excluded from dumps, zeroed on drop, and in a
/// page-protected mapping when page protection is on.
struct SecretBytes(Fragments);

impl SecretBytes {
    // Fallible only where page protection exists.
    #[cfg_attr(not(any(unix, windows)), allow(clippy::unnecessary_wraps))]
    fn new(bytes: &[u8], protect: bool) -> Result<Self> {
        let fragments = Fragments::from_parts(
            alloc::vec![LockedBytes::from_slice(bytes)],
            LockedBytes::from_slice(&[]),
            bytes.len(),
        );
        #[cfg(any(unix, windows))]
        if protect {
            return Ok(Self(fragments.into_protected()?));
        }
        let _ = protect;
        Ok(Self(fragments))
    }

    /// Run `f` over the bytes, opening the protected mapping if there is
    /// one.
    #[cfg_attr(not(any(unix, windows)), allow(clippy::unnecessary_wraps))]
    fn read<T>(&self, f: impl FnOnce(&[u8]) -> T) -> Result<T> {
        #[cfg(any(unix, windows))]
        let _access = self.0.open()?;
        Ok(f(self.0.chunk(0).unwrap_or_default()))
    }
}

/// How registered keys are normalized.
enum Normalizer {
    /// Keys are stored as given.
    Off,
    /// Plain BLAKE3.
    Plain,
    /// Keyed BLAKE3 under a 32-byte key.
    Keyed(SecretBytes),
    /// Keyed normalization was requested but its key could not be set up;
    /// every registration fails with this error instead of silently
    /// falling back to plain BLAKE3.
    Unavailable(&'static str),
}

/// The master credential verifier: a random 32-byte BLAKE3 key followed by
/// `BLAKE3-keyed(key, master)`.
enum MasterVerifier {
    Ready(SecretBytes),
    Unavailable(&'static str),
}

/// The vault's time source. `StdClock` is held inline so `build()` does
/// not allocate for it.
enum VaultClock {
    #[cfg(feature = "std")]
    Std,
    Custom(Arc<dyn Clock>),
}

impl VaultClock {
    fn now(&self) -> Duration {
        match self {
            #[cfg(feature = "std")]
            Self::Std => crate::clock::StdClock.now(),
            Self::Custom(c) => c.now(),
        }
    }

    fn unix_time(&self) -> Duration {
        match self {
            #[cfg(feature = "std")]
            Self::Std => crate::clock::StdClock.unix_time(),
            Self::Custom(c) => c.unix_time(),
        }
    }

    /// `true` if the lock word `word` is in force now.
    fn in_force(&self, word: u64) -> bool {
        match word {
            UNLOCKED => false,
            LOCKED_UNTIL_CLEARED => true,
            ends => nanos(self.now()) < ends - 1,
        }
    }
}

/// Keyed hash of key names (SipHash-2-4 under a random per-vault key).
/// Indexes the registry's names and the failure tracker; an attacker who
/// picks names cannot predict where they land.
struct NameHasher {
    k0: u64,
    k1: u64,
}

impl NameHasher {
    fn new() -> Self {
        // If the RNG fails the keys are fixed. Names are still looked up
        // by full comparison, so the only effect is that colliding names
        // could be chosen deliberately to share a tracker entry.
        Self {
            k0: crate::rng::random_u64().unwrap_or(0x6b65_792d_7661_756c),
            k1: crate::rng::random_u64().unwrap_or(0x7420_6e61_6d65_7321),
        }
    }

    // `core::hash::SipHasher` is deprecated in favour of std's
    // `DefaultHasher`, which `no_std` builds do not have. It is stable and
    // keyed, which is what this needs.
    #[allow(deprecated)]
    fn hash(&self, name: &str) -> u64 {
        let mut h = core::hash::SipHasher::new_with_keys(self.k0, self.k1);
        h.write(name.as_bytes());
        h.finish()
    }
}

/// Master-unlock backoff state.
#[derive(Default)]
struct Backoff {
    /// Consecutive failed attempts.
    failures: u32,
    /// Clock time before which attempts are refused.
    next_allowed: Duration,
}

struct VaultInner {
    config: VaultConfig,
    fragmenter: Fragmenter,
    /// `true` if a decoy was configured but the fragmenter is not the
    /// standard one, so the decoy is not used (reported by `Debug`).
    decoy_ignored: bool,
    normalizer: Normalizer,
    /// Optional Layer-5 codex. When set, every byte of normalized key
    /// material passes through `codex.encode()` before being handed to
    /// the fragmenter; `defragment` applies `codex.decode()` to recover.
    codex: Option<Arc<dyn Codex>>,
    /// Layer-8 security monitor. Defaults to a no-op
    /// [`NoMonitor`](crate::NoMonitor) when no monitor is configured.
    monitor: Arc<dyn SecurityMonitor>,
    /// Time source for windows, lockout expiry, backoff and timestamps.
    clock: VaultClock,
    /// Named-key registry. Readers load a snapshot; writers (register,
    /// unregister, rotate) build a new one and swap it in while holding
    /// `writer`.
    keys: Registry,
    /// Serializes registry writers. A writer takes this lock, loads the
    /// current snapshot, checks its precondition (name free, key present),
    /// stores the new snapshot and only then releases the lock, so the
    /// check and the update cannot be split by another writer.
    writer: Mutex<()>,
    /// Hash of key names for the registry and the failure tracker.
    names: NameHasher,
    /// Failure history for the thresholds. `None` when both thresholds
    /// are off: nothing is recorded then.
    tracker: Option<FailureTracker>,
    /// Set to `true` when the vault-wide threshold has been crossed.
    locked_out: AtomicBool,
    /// `true` while the most recently stored key could not be locked, so
    /// the monitor hears about each run of lock failures once.
    lock_failing: AtomicBool,
    /// Optional master credential verifier.
    master: Option<MasterVerifier>,
    /// Master-unlock backoff state. Also serializes master attempts.
    master_backoff: Mutex<Backoff>,
    /// Layer-9 audit sink. Defaults to a no-op
    /// [`NoAudit`](crate::NoAudit) when no sink is configured.
    audit: Arc<dyn AuditSink>,
}

impl KeyVault {
    /// A vault with the default configuration: the same as
    /// `KeyVaultBuilder::new().build()`. Since 1.2.
    ///
    /// # Examples
    ///
    /// ```
    /// use key_vault::{KeyVault, RawKey};
    ///
    /// let vault = KeyVault::new();
    /// let handle = vault.register("db-key", RawKey::new(vec![7; 32]))?;
    /// assert_eq!(vault.with_key(handle, |key| key.len())?, 32);
    /// # Ok::<(), key_vault::Error>(())
    /// ```
    #[cfg(feature = "std")]
    #[must_use]
    pub fn new() -> Self {
        KeyVaultBuilder::new().build()
    }

    /// A builder with the default configuration: the same as
    /// [`KeyVaultBuilder::new`]. Since 1.2.
    #[must_use]
    pub fn builder() -> KeyVaultBuilder {
        KeyVaultBuilder::new()
    }

    /// Returns `true` if the vault is in vault-wide lock-out state.
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
    /// # Lockout is advisory
    ///
    /// The vault never detects failures on its own: it only counts what
    /// the caller reports through [`KeyVault::report_failure`] (plus wrong
    /// master credentials). This lockout blocks every key in the vault, so
    /// failures reported for one key name lock out all keys; code that
    /// reports failures for untrusted input can be used to deny service.
    /// Use the per-key lockout ([`KeyVaultBuilder::with_key_lockout`]) to
    /// confine the effect to one key. Lockout is an API-level gate for
    /// well-behaved callers. It does nothing against code that can read
    /// the process's memory.
    #[must_use]
    pub fn is_locked_out(&self) -> bool {
        self.inner.locked_out.load(Ordering::Acquire)
    }

    /// Returns `true` if the key behind `handle` is locked out by the
    /// per-key threshold ([`KeyVaultBuilder::with_key_lockout`]).
    ///
    /// The vault-wide lockout is reported separately by
    /// [`KeyVault::is_locked_out`]. Returns `false` for an unknown handle.
    #[must_use]
    pub fn is_key_locked_out(&self, handle: KeyHandle) -> bool {
        let snapshot = self.inner.keys.load();
        snapshot
            .get(handle.id())
            .is_some_and(|entry| self.key_locked(entry))
    }

    /// Clear the per-key lockout for `name`. Returns `true` if the key
    /// registered under `name` was locked out. Also forgets the failures
    /// recorded for that name.
    #[allow(clippy::must_use_candidate)] // the result is informational.
    pub fn clear_key_lockout(&self, name: &str) -> bool {
        let hash = self.inner.names.hash(name);
        let was_locked = {
            let snapshot = self.inner.keys.load();
            snapshot.find(hash, name).is_some_and(|entry| {
                let previous = entry.lock.swap(UNLOCKED);
                self.inner.clock.in_force(previous)
            })
        };
        #[cfg(test)]
        hooks::after_clear_key_lockout();
        if let Some(tracker) = &self.inner.tracker {
            tracker.remove(hash);
        }
        was_locked
    }

    /// Clear every lockout: the vault-wide flag and all per-key lockouts.
    ///
    /// Use this after the operator has resolved the underlying cause —
    /// e.g. a rotated credential, an investigated alert. Also clears the
    /// failure tracker; subsequent failures start counting from zero.
    pub fn clear_lockout(&self) {
        self.inner.locked_out.store(false, Ordering::Release);
        if let Some(tracker) = &self.inner.tracker {
            tracker.clear();
        }
        self.inner.keys.load().for_each_entry(|entry| {
            let _ = entry.lock.swap(UNLOCKED);
        });
    }

    /// Report a key-access failure to the configured monitor and the
    /// threshold detectors.
    ///
    /// `key_name` identifies which key the failure pertains to (used for
    /// per-key threshold tracking and in the monitor event). `note` is
    /// an optional caller-supplied free-text label; pass `None` if you
    /// don't have one. **Do not** include key bytes or other secrets in
    /// the note — it is forwarded verbatim to every configured monitor.
    /// [`KeyVault::report_failure_with_note`] takes a note built at run
    /// time.
    ///
    /// - If the vault-wide threshold is on and the count for `key_name`
    ///   within [`VaultConfig::failure_window`] reaches
    ///   [`VaultConfig::max_failures_before_lockout`], the whole vault is
    ///   locked out (every key, not only `key_name`).
    /// - If the per-key threshold is on ([`KeyVaultBuilder::with_key_lockout`])
    ///   and the count within [`VaultConfig::key_lockout_window`] reaches
    ///   [`VaultConfig::key_lockout_threshold`], only the key registered
    ///   under `key_name` is locked out. Failures reported for a name
    ///   that no key is registered under do not count toward it (since
    ///   1.2).
    ///
    /// Either breach fires the monitor's `on_threshold_breach` with the
    /// matching [`LockoutScope`]. With both thresholds at `0` (the
    /// default) only the per-failure callback runs, and nothing is
    /// recorded.
    ///
    /// # Cost and memory
    ///
    /// Safe to call with names taken from untrusted input. The failure
    /// history is bounded: names of registered keys are always tracked,
    /// other names share a fixed capacity
    /// ([`KeyVaultBuilder::with_failure_tracking_capacity`]) and the
    /// longest-idle one is forgotten when it is full. Each call costs a
    /// keyed hash of the name and a few `O(log n)` steps on one of
    /// sixteen independently locked shards, however many failures came
    /// before it.
    ///
    /// This is the only way failures reach the threshold detectors: the
    /// vault does not observe decryption failures itself. See
    /// [`KeyVault::is_locked_out`].
    pub fn report_failure(&self, key_name: &str, note: Option<&'static str>) {
        self.handle_failure(
            key_name,
            note.map_or(Cow::Borrowed(""), Cow::Borrowed),
            true,
        );
    }

    /// [`KeyVault::report_failure`] with a note that can be built at run
    /// time (an error code from the cipher, say). The note is forwarded
    /// to the monitor as is: never put key bytes or other secrets in it.
    /// Since 1.2.
    pub fn report_failure_with_note(&self, key_name: &str, note: impl Into<Cow<'static, str>>) {
        self.handle_failure(key_name, note.into(), true);
    }

    /// Record a failure and apply the thresholds. `per_key` is `false` for
    /// master-unlock failures, which have their own backoff.
    fn handle_failure(&self, key_name: &str, note: Cow<'static, str>, per_key: bool) {
        let config = &self.inner.config;
        let hash = self.inner.names.hash(key_name);
        // Only a registered key can be locked out on its own, so only a
        // registered name is counted for the per-key threshold.
        let entry = if per_key && config.key_lockout_threshold > 0 {
            self.inner.keys.load().find(hash, key_name).cloned()
        } else {
            None
        };
        let windows = Windows {
            vault: (config.max_failures_before_lockout > 0).then_some(config.failure_window),
            key: entry.as_ref().map(|_| config.key_lockout_window),
        };
        let counts = match &self.inner.tracker {
            Some(tracker) if windows.vault.is_some() || windows.key.is_some() => {
                // Names of registered keys and the master credential are
                // pinned: other names cannot push them out of the tracker.
                let pinned = !per_key
                    || entry.is_some()
                    || self.inner.keys.load().find(hash, key_name).is_some();
                tracker.record(hash, pinned, self.inner.clock.now(), windows)
            }
            _ => FailureCounts {
                in_window: 1,
                in_key_window: 0,
                window_elapsed: Duration::ZERO,
            },
        };

        // Always fire the per-failure callback first.
        let ctx = FailureContext {
            key_name: key_name.to_string(),
            consecutive_failures: counts.in_window,
            window_elapsed: counts.window_elapsed,
            note,
        };
        self.inner.monitor.on_decryption_failure(&ctx);

        // Vault-wide threshold.
        let threshold = config.max_failures_before_lockout;
        if threshold > 0 && counts.in_window >= threshold {
            // Only lock out once — subsequent calls keep firing
            // on_decryption_failure but the lockout flag stays set.
            let was_locked = self.inner.locked_out.swap(true, Ordering::AcqRel);
            let breach = ThresholdContext {
                key_name: key_name.to_string(),
                failures_in_window: counts.in_window,
                window: config.failure_window,
                lockout_triggered: !was_locked,
                scope: LockoutScope::Vault,
            };
            self.inner.monitor.on_threshold_breach(&breach);
        }

        // Per-key threshold.
        if let Some(entry) = entry {
            if counts.in_key_window >= config.key_lockout_threshold {
                let until = config
                    .key_lockout_duration
                    .map(|d| self.inner.clock.now().saturating_add(d));
                let previous = entry.lock.swap(lock_word(until));
                let breach = ThresholdContext {
                    key_name: key_name.to_string(),
                    failures_in_window: counts.in_key_window,
                    window: config.key_lockout_window,
                    lockout_triggered: !self.inner.clock.in_force(previous),
                    scope: LockoutScope::Key,
                };
                self.inner.monitor.on_threshold_breach(&breach);
            }
        }
    }

    /// `true` if `entry` is under a per-key lockout that has not expired.
    /// An expired lockout is cleared here.
    #[inline]
    fn key_locked(&self, entry: &KeyEntry) -> bool {
        // Fast path for `with_key`: one load of a word only this key's
        // lockouts write to.
        let word = entry.lock.load();
        if word == UNLOCKED {
            return false;
        }
        self.key_locked_slow(entry, word)
    }

    #[cold]
    fn key_locked_slow(&self, entry: &KeyEntry, word: u64) -> bool {
        if self.inner.clock.in_force(word) {
            return true;
        }
        // Expired. Clear it, unless a new lockout replaced it meanwhile,
        // and forget the failures that led to it.
        if entry.lock.clear_if(word) {
            if let Some(tracker) = &self.inner.tracker {
                tracker.remove(entry.name_hash);
            }
        }
        false
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

    /// Build an [`AuditEvent`] with the clock's timestamp (and, with
    /// `std`, the calling thread's id) and forward it to the audit sink.
    fn emit_audit(&self, key_name: &str, kind: AccessKind, note: Cow<'static, str>) {
        // Hot-path fast-skip: a sink that declares itself no-op gets
        // zero allocations + zero clock-read overhead per call.
        if self.inner.audit.is_no_op() {
            return;
        }
        let event = AuditEvent {
            timestamp: self.inner.clock.unix_time(),
            key_name: key_name.to_string(),
            kind,
            #[cfg(feature = "std")]
            thread_id: std::thread::current().id(),
            note,
        };
        self.inner.audit.on_event(&event);
    }

    /// Snapshot of the vault's configuration.
    #[must_use]
    pub fn config(&self) -> &VaultConfig {
        &self.inner.config
    }

    /// Page-locking and dump-exclusion state of every registered key.
    ///
    /// The OS limits how much memory a process may lock (`RLIMIT_MEMLOCK`
    /// on Linux and macOS, the minimum working-set size on Windows). A
    /// key registered after that limit is reached is stored anyway, in
    /// memory the OS may write to swap; this call shows how many keys are
    /// in that state. [`KeyVaultBuilder::with_strict_locking`] refuses such
    /// keys instead, and [`SecurityMonitor::on_memory_lock_failure`] reports
    /// them as they are stored. See `docs/PLATFORM-NOTES.md` for how to
    /// raise the limit.
    ///
    /// Walks the whole registry: meant for health checks and start-up
    /// logs, not for every request. Since 1.2.
    ///
    /// # Examples
    ///
    /// ```
    /// use key_vault::{KeyVault, RawKey};
    ///
    /// let vault = KeyVault::new();
    /// let _ = vault.register("k", RawKey::new(vec![1; 32]))?;
    /// let status = vault.memory_status();
    /// assert_eq!(status.keys, 1);
    /// if !status.all_locked() {
    ///     eprintln!("{} key(s) are not page-locked", status.unlocked());
    /// }
    /// # Ok::<(), key_vault::Error>(())
    /// ```
    #[must_use]
    pub fn memory_status(&self) -> MemoryStatus {
        crate::memory::relock_if_forked();
        let snapshot = self.inner.keys.load();
        let mut status = MemoryStatus::default();
        snapshot.for_each_entry(|entry| {
            status.keys += 1;
            if entry.fragments.is_locked() {
                status.locked += 1;
            }
            if entry.fragments.is_excluded_from_dumps() {
                status.excluded_from_dumps += 1;
            }
        });
        status
    }

    /// `Some(true)` if the key behind `handle` is held entirely in
    /// page-locked memory, `Some(false)` if it is not (see
    /// [`KeyVault::memory_status`]), `None` for an unknown handle.
    /// Since 1.2.
    #[must_use]
    pub fn is_memory_locked(&self, handle: KeyHandle) -> Option<bool> {
        crate::memory::relock_if_forked();
        self.inner
            .keys
            .load()
            .get(handle.id())
            .map(|entry| entry.fragments.is_locked())
    }

    /// Fragment a raw key through the configured normalizer, codex, and
    /// fragmenter.
    ///
    /// The returned [`Fragments`] is opaque; pass it back to
    /// [`KeyVault::defragment`] to recover the (normalized + codex-encoded)
    /// bytes inverse-transformed. One-shot fragments are never
    /// page-protected, even when page protection is on: they leave the
    /// vault, and the caller reads them.
    ///
    /// # Pipeline
    ///
    /// ```text
    /// key → normalize (optional) → codex.encode (optional) → fragmenter.fragment → Fragments
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
        let working = match &self.inner.normalizer {
            Normalizer::Off => RawKey::new(key.as_bytes().to_vec()),
            Normalizer::Plain => blake3_normalize(key),
            Normalizer::Keyed(secret) => secret.read(|k| {
                <&[u8; 32]>::try_from(k)
                    .map(|k| blake3_keyed_normalize(k, key))
                    .map_err(|_| Error::Internal("normalization key has the wrong length"))
            })??,
            Normalizer::Unavailable(reason) => return Err(Error::Internal(reason)),
        };
        let encoded = if let Some(codex) = &self.inner.codex {
            codex_apply(codex.as_ref(), &working)
        } else {
            working
        };
        self.inner.fragmenter.fragment(&encoded)
    }

    /// Fragment `key` for the registry: the pipeline above, then (with
    /// page protection on) a move into a private protected mapping, then
    /// the lock check.
    fn fragment_for_registry(&self, name: &str, key: &RawKey) -> Result<Fragments> {
        let fragments = self.fragment_pipeline(key)?;
        #[cfg(any(unix, windows))]
        let fragments = if self.inner.config.page_protection {
            fragments.into_protected()?
        } else {
            fragments
        };
        self.check_locked(name, &fragments)?;
        Ok(fragments)
    }

    /// Report fragments that are not page-locked to the monitor (once per
    /// run of failures) and, with strict locking, refuse them.
    fn check_locked(&self, name: &str, fragments: &Fragments) -> Result<()> {
        let strict = self.inner.config.strict_locking;
        // With strict locking, retry the pages that failed before giving
        // up: the pool backs off retries while locks keep failing, and the
        // limit may have been raised since.
        if fragments.is_locked() || (strict && fragments.retry_lock()) {
            self.inner.lock_failing.store(false, Ordering::Release);
            return Ok(());
        }
        if !self.inner.lock_failing.swap(true, Ordering::AcqRel) {
            self.inner
                .monitor
                .on_memory_lock_failure(&MemoryLockContext {
                    key_name: name.to_string(),
                    refused: strict,
                });
        }
        if strict {
            return Err(Error::MemoryLock(
                "the key's memory could not be page-locked and strict locking is on".into(),
            ));
        }
        Ok(())
    }

    /// Take the registry writer lock.
    fn lock_writer(&self) -> impl Drop + '_ {
        self.inner.writer.lock()
    }

    /// Reassemble fragments produced by [`KeyVault::fragment`].
    ///
    /// Inverts the codex transformation (if configured) so the recovered
    /// bytes are the normalized key (or the original raw key if
    /// normalization is off). Defragmentation itself is delegated to the
    /// configured [`FragmentStrategy`]. Read the result with
    /// [`RawKey::expose_secret`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Defragment`](crate::Error::Defragment) when the
    /// supplied fragments do not match the configured fragmenter's layout.
    pub fn defragment(&self, fragments: &Fragments) -> Result<RawKey> {
        if self.is_locked_out() {
            return Err(Error::LockedOut);
        }
        // One-shot fragments are never page-protected (only registry
        // entries are), so there is nothing to open here.
        let encoded = self.inner.fragmenter.defragment(fragments)?;
        let decoded = if let Some(codex) = &self.inner.codex {
            codex_apply(codex.as_ref(), &encoded)
        } else {
            encoded
        };
        self.emit_audit("", AccessKind::OneShotDefragment, Cow::Borrowed(""));
        Ok(decoded)
    }

    // ----- Named-key registry -----

    /// Register a key under a name and return an opaque [`KeyHandle`].
    ///
    /// The key bytes are run through the configured normalizer + codex
    /// pipeline, fragmented, and inserted into the named registry. With
    /// page protection on, the fragments are moved into a private mapping
    /// that stays inaccessible except while [`KeyVault::with_key`] reads
    /// it. The returned handle is the only way to refer to the key from
    /// outside the crate; the underlying numeric id is not exposed.
    ///
    /// If the key's memory could not be page-locked (the process is at
    /// its lock limit), the key is stored anyway and the monitor's
    /// [`SecurityMonitor::on_memory_lock_failure`] fires, unless strict
    /// locking is on ([`KeyVaultBuilder::with_strict_locking`]).
    ///
    /// The cost does not depend on how many keys are registered (since
    /// 1.2).
    ///
    /// # Errors
    ///
    /// - [`Error::LockedOut`](crate::Error::LockedOut) if the vault is
    ///   currently locked out (vault-wide threshold).
    /// - [`Error::InvalidConfig`](crate::Error::InvalidConfig) if a key
    ///   with the same name is already registered. Concurrent `register`
    ///   calls with the same name are safe: exactly one succeeds.
    /// - Whatever the configured fragmenter surfaces (typically
    ///   [`Error::Fragment`](crate::Error::Fragment) for empty input).
    /// - [`Error::MemoryLock`](crate::Error::MemoryLock) if page protection
    ///   is on and the protected mapping cannot be created, or if strict
    ///   locking is on and the key's memory could not be page-locked.
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
        let name_hash = self.inner.names.hash(&name);
        let duplicate = || Error::InvalidConfig(format!("key name {name:?} is already registered"));

        // Reject duplicate names early so callers get a clear error
        // before paying the fragmentation cost. This check is only a
        // shortcut; the authoritative one runs under the writer lock.
        if self.inner.keys.load().find(name_hash, &name).is_some() {
            return Err(duplicate());
        }

        let key_len = key.len();
        let fragments = self.fragment_for_registry(&name, &key)?;
        let handle = KeyHandle::allocate();
        let id = handle.id();
        let entry = Arc::new(KeyEntry {
            name: name.clone(),
            name_hash,
            fragments,
            metadata: KeyMetadata::new(self.inner.clock.unix_time(), key_len, None),
            lock: Arc::new(KeyLock::new()),
        });

        let previous = {
            let _writer = self.lock_writer();
            let current = self.inner.keys.load_full();
            // Re-check under the lock: another `register` may have
            // inserted the same name while we were fragmenting.
            if current.by_name.get(name_hash, name.as_str()).is_some() {
                return Err(duplicate());
            }
            let next = Snapshot {
                by_id: current.by_id.insert(id_hash(id), id, entry).0,
                by_name: current.by_name.insert(name_hash, name.clone(), id).0,
            };
            self.inner.keys.swap(Arc::new(next))
        };
        // Release the old snapshot outside the writer lock.
        drop(previous);
        self.emit_audit(&name, AccessKind::Register, Cow::Borrowed(""));
        Ok(handle)
    }

    /// Remove a registered key from the registry. The key's `Fragments`
    /// (and their `LockedBytes` chunks) drop and zeroize when the last
    /// reference goes away.
    ///
    /// Allowed while the key (or the vault) is locked out. The key's
    /// per-key lockout and recorded failures go with it (since 1.2): a key
    /// registered later under the same name starts clean.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`](crate::Error::KeyNotFound) if no
    /// key is registered under the given handle.
    pub fn unregister(&self, handle: KeyHandle) -> Result<()> {
        let (previous, name, name_hash) = {
            let _writer = self.lock_writer();
            let current = self.inner.keys.load_full();
            let id = handle.id();
            let Some((by_id, entry)) = current.by_id.remove(id_hash(id), &id) else {
                return Err(Error::KeyNotFound);
            };
            let by_name = match current.by_name.remove(entry.name_hash, entry.name.as_str()) {
                Some((by_name, _)) => by_name,
                None => current.by_name.clone(),
            };
            let previous = self.inner.keys.swap(Arc::new(Snapshot { by_id, by_name }));
            (previous, entry.name.clone(), entry.name_hash)
        };
        // The removed entry's fragments are freed (and zeroed) here, or
        // later when the last in-flight `with_key` reader lets go.
        drop(previous);
        if let Some(tracker) = &self.inner.tracker {
            tracker.remove(name_hash);
        }
        self.emit_audit(&name, AccessKind::Unregister, Cow::Borrowed(""));
        Ok(())
    }

    /// Briefly access the recovered key material inside a callback.
    ///
    /// The vault defragments the named key into a scratch buffer, applies
    /// the codex decode if configured, and passes the bytes to the
    /// user-supplied closure. When the closure returns (or panics, or
    /// defragmentation fails) the used part of the buffer is
    /// volatile-zeroed. The scratch buffer's pages are locked and excluded
    /// from dumps like the fragments' pages. With `std` the scratch buffer
    /// is per thread and reused; without `std` it is allocated per call.
    ///
    /// With page protection on, the key's mapping is readable only while
    /// it is being reassembled; the closure runs on the scratch copy.
    ///
    /// **The byte slice handed to the closure does not outlive the
    /// call.** Do not stash it in a longer-lived structure; do your
    /// cryptographic operation, return, and let the vault scrub the
    /// buffer. Copies the closure makes (into a cipher's key schedule,
    /// a `Vec`, the stack) are not tracked or wiped by the vault.
    ///
    /// # Nesting
    ///
    /// The closure may call `with_key` again, on this vault or another,
    /// to use two keys at once (since 1.2; earlier versions panicked).
    /// The inner call gets its own locked scratch buffer, allocated for
    /// that call and wiped when it returns.
    ///
    /// ```
    /// use key_vault::{KeyVault, RawKey};
    ///
    /// let vault = KeyVault::new();
    /// let kek = vault.register("kek", RawKey::new(vec![1; 32]))?;
    /// let dek = vault.register("dek", RawKey::new(vec![2; 32]))?;
    /// let both = vault.with_key(kek, |kek| {
    ///     vault.with_key(dek, |dek| kek.len() + dek.len())
    /// })??;
    /// assert_eq!(both, 64);
    /// # Ok::<(), key_vault::Error>(())
    /// ```
    ///
    /// # Concurrency
    ///
    /// Reads take no lock and write no shared memory, so threads reading
    /// the same key do not slow each other down (since 1.2).
    ///
    /// # Errors
    ///
    /// - [`Error::LockedOut`](crate::Error::LockedOut) if the vault, or
    ///   this key, is currently locked out.
    /// - [`Error::KeyNotFound`](crate::Error::KeyNotFound) if no key is
    ///   registered under the given handle.
    /// - [`Error::Defragment`](crate::Error::Defragment) on internal
    ///   inconsistency.
    /// - [`Error::MemoryLock`](crate::Error::MemoryLock) if page protection
    ///   is on and the OS refuses to make the key readable, or if strict
    ///   locking is on and the scratch buffer could not be page-locked.
    pub fn with_key<F, T>(&self, handle: KeyHandle, f: F) -> Result<T>
    where
        F: FnOnce(&[u8]) -> T,
    {
        if self.is_locked_out() {
            return Err(Error::LockedOut);
        }
        crate::memory::relock_if_forked();
        let snapshot = self.inner.keys.load();
        let (result, name) = self.read_key(snapshot, handle.id(), f)?;
        if let Some(name) = name {
            self.emit_audit(&name, AccessKind::Read, Cow::Borrowed(""));
        }
        Ok(result)
    }

    /// Read the key `id` from `snapshot` into the per-thread scratch
    /// buffer, or into a buffer of its own when the thread's scratch is
    /// already in use (a `with_key` inside another one's callback).
    #[cfg(feature = "std")]
    fn read_key<F, T>(
        &self,
        snapshot: SnapshotGuard,
        id: KeyId,
        f: F,
    ) -> Result<(T, Option<String>)>
    where
        F: FnOnce(&[u8]) -> T,
    {
        SCRATCH.with(move |cell| match cell.try_borrow_mut() {
            Ok(mut scratch) => self.read_into(snapshot, id, Some(&mut scratch), f),
            Err(_) => self.read_into(snapshot, id, None, f),
        })
    }

    /// Read the key `id` from `snapshot` into a per-call scratch buffer
    /// (no thread-local storage without `std`).
    #[cfg(not(feature = "std"))]
    fn read_key<F, T>(
        &self,
        snapshot: SnapshotGuard,
        id: KeyId,
        f: F,
    ) -> Result<(T, Option<String>)>
    where
        F: FnOnce(&[u8]) -> T,
    {
        self.read_into(snapshot, id, None, f)
    }

    /// Reassemble the key `id` into `scratch` (or a fresh buffer), let go
    /// of the snapshot, and run `f` over the bytes. Returns `f`'s result
    /// and, when auditing, the key's name.
    ///
    /// The snapshot is held only while the key is reassembled, and no
    /// reference count on the key is taken: a writer that replaces or
    /// removes the key meanwhile keeps the old storage alive through the
    /// snapshot until it is released here.
    fn read_into<F, T>(
        &self,
        snapshot: SnapshotGuard,
        id: KeyId,
        scratch: Option<&mut Scratch>,
        f: F,
    ) -> Result<(T, Option<String>)>
    where
        F: FnOnce(&[u8]) -> T,
    {
        let entry = snapshot.get(id).ok_or(Error::KeyNotFound)?;
        if self.key_locked(entry) {
            return Err(Error::LockedOut);
        }
        // Skip cloning the name when the audit sink is inert; this is the
        // common case and removes one `String` allocation per call.
        let name = if self.inner.audit.is_no_op() {
            None
        } else {
            Some(entry.name.clone())
        };
        let total = entry.fragments.total_len();
        let strict = self.inner.config.strict_locking;
        let mut own;
        let buf = if let Some(scratch) = scratch {
            scratch.slice(total, strict)?
        } else {
            own = ScratchBuf::new(total);
            own.slice(strict)?
        };
        // The guard is created before the first plaintext byte is
        // written, so the buffer is volatile-zeroed on every exit path:
        // normal return, an error from `defragment_into` after a partial
        // write, or a panic in the codex or the user callback.
        let guard = ZeroOnExit(buf);
        self.reassemble(&entry.fragments, &mut *guard.0)?;
        // The callback runs on the copy; the registry is not needed for it.
        drop(snapshot);
        Ok((f(&*guard.0), name))
    }

    /// Defragment into `out` and apply the codex decode in place. Opens
    /// the page-protected mapping (if any) only for the duration of the
    /// defragmentation.
    #[inline]
    fn reassemble(&self, fragments: &Fragments, out: &mut [u8]) -> Result<()> {
        {
            // Registry fragments are page-protected exactly when the
            // vault has page protection on.
            #[cfg(any(unix, windows))]
            let _access = if self.inner.config.page_protection {
                fragments.open()?
            } else {
                None
            };
            // Defragment directly into the scratch — no `RawKey` /
            // `Vec<u8>` allocation on the hot path.
            self.inner.fragmenter.defragment_into(fragments, out)?;
        }
        // Codex decode in place (also alloc-free).
        if let Some(c) = &self.inner.codex {
            codex_decode_in_place(c.as_ref(), out);
        }
        Ok(())
    }

    /// Rotate a registered key to new material.
    ///
    /// The new key is fragmented and atomically swapped into the
    /// registry slot. Concurrent [`KeyVault::with_key`] callers see
    /// either the old or the new fragmentation (never a torn read);
    /// the old `Fragments` drops once all in-flight readers release
    /// their references. The key keeps its per-key lockout state.
    ///
    /// The metadata is updated to record the new key length and a fresh
    /// registration timestamp. The cost does not depend on how many keys
    /// are registered (since 1.2).
    ///
    /// # Errors
    ///
    /// - [`Error::LockedOut`](crate::Error::LockedOut) if the vault, or
    ///   this key, is locked out.
    /// - [`Error::KeyNotFound`](crate::Error::KeyNotFound), including when
    ///   a concurrent [`KeyVault::unregister`] removes the key before the
    ///   rotation is installed. `rotate` returns `Ok` only if the new
    ///   material was actually stored under the handle.
    /// - Fragmenter errors for the new key.
    /// - [`Error::MemoryLock`](crate::Error::MemoryLock) as for
    ///   [`KeyVault::register`].
    // Take `new_key` by value so its `Drop` zeroes the original buffer
    // after we've fragmented and copied the bytes into mlock'd storage.
    #[allow(clippy::needless_pass_by_value)]
    pub fn rotate(&self, handle: KeyHandle, new_key: RawKey) -> Result<()> {
        if self.is_locked_out() {
            return Err(Error::LockedOut);
        }
        let id = handle.id();

        // Check the key exists (and is not locked out) first so we don't
        // pay the fragmentation cost for nothing. This check is only a
        // shortcut; the authoritative one runs under the writer lock.
        let name = {
            let snapshot = self.inner.keys.load();
            let entry = snapshot.get(id).ok_or(Error::KeyNotFound)?;
            if self.key_locked(entry) {
                return Err(Error::LockedOut);
            }
            entry.name.clone()
        };

        let new_len = new_key.len();
        let new_fragments = self.fragment_for_registry(&name, &new_key)?;
        let new_metadata = KeyMetadata::new(self.inner.clock.unix_time(), new_len, None);

        let previous = {
            let _writer = self.lock_writer();
            let current = self.inner.keys.load_full();
            let Some(old) = current.get(id) else {
                // Unregistered while we were fragmenting.
                return Err(Error::KeyNotFound);
            };
            let entry = Arc::new(KeyEntry {
                name: old.name.clone(),
                name_hash: old.name_hash,
                fragments: new_fragments,
                metadata: new_metadata,
                lock: Arc::clone(&old.lock),
            });
            let next = Snapshot {
                by_id: current.by_id.insert(id_hash(id), id, entry).0,
                by_name: current.by_name.clone(),
            };
            self.inner.keys.swap(Arc::new(next))
        };
        drop(previous);
        self.emit_audit(&name, AccessKind::Rotate, Cow::Borrowed(""));
        Ok(())
    }

    /// `true` if a key is registered under the given handle.
    #[must_use]
    pub fn contains(&self, handle: KeyHandle) -> bool {
        self.inner.keys.load().get(handle.id()).is_some()
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
            .get(handle.id())
            .map(|e| e.metadata.clone())
    }

    /// Find the handle registered under `name`, if any. A hashed lookup
    /// (since 1.2; earlier versions scanned every key).
    #[must_use]
    pub fn handle_for_name(&self, name: &str) -> Option<KeyHandle> {
        let hash = self.inner.names.hash(name);
        self.inner
            .keys
            .load()
            .by_name
            .get(hash, name)
            .map(|id| KeyHandle::from_id(*id))
    }

    /// Number of keys currently registered.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.inner.keys.load().len()
    }

    // ----- Master-key emergency unlock -----

    /// Attempt to clear every lockout using a master credential.
    ///
    /// If the vault has a master key registered (via
    /// [`KeyVaultBuilder::with_master_key`]) and the supplied bytes match,
    /// all lockouts are cleared and the failure tracker is reset (see
    /// [`KeyVault::clear_lockout`]).
    ///
    /// The stored verifier is `BLAKE3-keyed(k, master)` under a random
    /// 32-byte key `k` generated for this vault, kept in locked,
    /// dump-excluded memory; the comparison goes through
    /// [`subtle::ConstantTimeEq`]. Attempts are serialized.
    ///
    /// On mismatch the failure is reported to the monitor under the
    /// reserved key name `"<master>"`, counts toward the vault-wide
    /// threshold, and (with [`KeyVaultBuilder::with_master_unlock_backoff`])
    /// starts or extends the backoff delay.
    ///
    /// # Limits
    ///
    /// - Without the backoff option there is no rate limit; callers that
    ///   expose this to untrusted input should turn it on.
    /// - The verifier is a fast hash, not a password hash. Keying it
    ///   means a copy of the digest alone is useless for guessing, but an
    ///   attacker who reads both the key and the digest from the process
    ///   can guess a low-entropy master offline. Use a high-entropy
    ///   credential.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidConfig`](crate::Error::InvalidConfig) if no
    ///   master credential is registered.
    /// - [`Error::RateLimited`](crate::Error::RateLimited) if the backoff
    ///   delay after the previous failure has not passed. The attempt is
    ///   not checked and does not count as a failure.
    /// - [`Error::Acquisition`](crate::Error::Acquisition) with source
    ///   `"master"` on mismatch.
    /// - [`Error::Internal`](crate::Error::Internal) if the verifier could
    ///   not be set up at build time (RNG failure).
    pub fn unlock_with_master(&self, attempt: &[u8]) -> Result<()> {
        let master = self.inner.master.as_ref().ok_or_else(|| {
            Error::InvalidConfig(
                "vault has no master key registered; pass with_master_key at build time"
                    .to_string(),
            )
        })?;
        let matched = {
            // Held for the whole attempt: attempts are serialized, so
            // parallel guesses cannot all slip through one backoff window.
            let mut backoff = self.inner.master_backoff.lock();
            let now = self.inner.clock.now();
            if now < backoff.next_allowed {
                return Err(Error::RateLimited {
                    retry_after: backoff.next_allowed.saturating_sub(now),
                });
            }
            let matched = match master {
                MasterVerifier::Unavailable(reason) => return Err(Error::Internal(reason)),
                MasterVerifier::Ready(secret) => secret.read(|stored| {
                    let Some((hash_key, digest)) = stored.split_first_chunk::<32>() else {
                        return false;
                    };
                    let mut attempt_digest = Zeroizing::new([0u8; 32]);
                    blake3_keyed_into(hash_key, attempt, &mut attempt_digest[..]);
                    bool::from(digest.ct_eq(&attempt_digest[..]))
                })?,
            };
            if matched {
                *backoff = Backoff::default();
            } else {
                backoff.failures = backoff.failures.saturating_add(1);
                backoff.next_allowed = now.saturating_add(self.backoff_delay(backoff.failures));
            }
            matched
        };
        self.emit_audit(
            MASTER_NAME,
            AccessKind::MasterUnlockAttempt { matched },
            Cow::Borrowed(""),
        );
        if matched {
            self.clear_lockout();
            Ok(())
        } else {
            // Counts toward the vault-wide threshold like any reported
            // failure. Master attempts have their own backoff, so they do
            // not feed the per-key lockout.
            self.handle_failure(
                MASTER_NAME,
                Cow::Borrowed("invalid master credential"),
                false,
            );
            Err(Error::Acquisition {
                source: Cow::Borrowed("master"),
                reason: "master credential did not match".to_string(),
            })
        }
    }

    /// Backoff delay after `failures` consecutive master failures:
    /// `base * 2^(failures - 1)`, capped at the configured maximum.
    fn backoff_delay(&self, failures: u32) -> Duration {
        let config = &self.inner.config;
        if config.master_backoff_base.is_zero() {
            return Duration::ZERO;
        }
        let shift = failures.saturating_sub(1).min(31);
        config
            .master_backoff_base
            .checked_mul(1u32 << shift)
            .unwrap_or(config.master_backoff_max)
            .min(config.master_backoff_max)
    }

    /// `true` if a master credential was registered at build time.
    #[must_use]
    pub fn has_master_key(&self) -> bool {
        self.inner.master.is_some()
    }
}

#[cfg(feature = "std")]
impl Default for KeyVault {
    /// Same as [`KeyVault::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// Test hooks: code that runs at a fixed point inside a vault operation,
/// to drive an exact interleaving of concurrent calls.
#[cfg(test)]
mod hooks {
    use alloc::boxed::Box;
    use core::cell::RefCell;

    std::thread_local! {
        static AFTER_CLEAR_KEY_LOCKOUT: RefCell<Option<Box<dyn FnOnce()>>> =
            const { RefCell::new(None) };
    }

    /// Run `f` (once, on this thread) inside the next
    /// `clear_key_lockout`, after the key's lockout is cleared and before
    /// its failures are forgotten.
    pub(super) fn set_after_clear_key_lockout(f: impl FnOnce() + 'static) {
        AFTER_CLEAR_KEY_LOCKOUT.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub(super) fn after_clear_key_lockout() {
        if let Some(f) = AFTER_CLEAR_KEY_LOCKOUT.with(|h| h.borrow_mut().take()) {
            f();
        }
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
/// Used by the [`KeyVault::with_key`] hot path: the scratch buffer holds
/// the defragmented (codex-encoded) bytes; we run the codex over them in
/// place rather than allocating a fresh [`RawKey`]. Zero allocations.
fn codex_decode_in_place(codex: &dyn Codex, bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        *b = codex.decode(*b);
    }
}

// ------------------------- Hot-path scratch -------------------------
//
// With `std`, `KeyVault::with_key` defragments into this thread-local
// instead of allocating a fresh buffer per call. The buffer grows lazily
// to the largest key the thread has accessed; subsequent calls reuse the
// allocation. A `ZeroOnExit` guard zeroes it when each call ends
// (panic-safe). The buffer's pages are locked and excluded from dumps
// through the same reference-counted page table as `LockedBytes`.

#[cfg(feature = "std")]
std::thread_local! {
    static SCRATCH: core::cell::RefCell<Scratch> = const { core::cell::RefCell::new(Scratch::new()) };
}

/// Per-thread scratch buffer for [`KeyVault::with_key`].
#[cfg_attr(not(feature = "std"), allow(dead_code))] // only `std` has the thread-local.
struct Scratch {
    buf: Vec<u8>,
    /// `true` if every page of `buf` is locked.
    locked: bool,
}

#[cfg_attr(not(feature = "std"), allow(dead_code))]
impl Scratch {
    const fn new() -> Self {
        Self {
            buf: Vec::new(),
            locked: true,
        }
    }

    /// The first `len` bytes, growing the buffer if needed. With `strict`,
    /// retries the lock on a buffer whose pages are not all locked and
    /// fails with [`Error::MemoryLock`] if that does not help.
    fn slice(&mut self, len: usize, strict: bool) -> Result<&mut [u8]> {
        self.ensure_len(len);
        if strict && !self.locked && !self.buf.is_empty() {
            let (ptr, len) = (self.buf.as_ptr(), self.buf.len());
            // SAFETY: the buffer is non-empty and holds the reference
            // taken in `ensure_len`.
            self.locked = unsafe { crate::memory::retry_region(ptr, len) };
            if !self.locked {
                return Err(Error::MemoryLock(
                    "could not lock the scratch buffer for the key".into(),
                ));
            }
        }
        Ok(&mut self.buf[..len])
    }

    /// Make sure the buffer holds at least `len` bytes. Growing allocates
    /// a new buffer and releases the old one; the buffer is never resized
    /// in place, so the page references stay valid.
    fn ensure_len(&mut self, len: usize) {
        if self.buf.len() >= len {
            return;
        }
        let new_buf = alloc::vec![0u8; len];
        // `len > buf.len() >= 0`, so the new buffer is non-empty.
        // SAFETY: `new_buf` is a live allocation of `len` bytes. It is
        // moved into `self.buf` (the heap buffer does not move) and never
        // resized; `release` passes the same pointer and length.
        let locked = unsafe { crate::memory::acquire_region(new_buf.as_ptr(), new_buf.len()) };
        self.release();
        self.buf = new_buf;
        self.locked = locked;
    }

    /// Zero the current buffer and drop its page references.
    fn release(&mut self) {
        zeroize::Zeroize::zeroize(self.buf.as_mut_slice());
        if !self.buf.is_empty() {
            // SAFETY: same pointer and length as the `acquire_region` call
            // in `ensure_len`; the buffer is still live.
            unsafe { crate::memory::release_region(self.buf.as_ptr(), self.buf.len()) };
        }
        self.buf = Vec::new();
        self.locked = true;
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
        let mut keys_locked_out = 0usize;
        self.inner.keys.load().for_each_entry(|entry| {
            if self.inner.clock.in_force(entry.lock.load()) {
                keys_locked_out += 1;
            }
        });
        f.debug_struct("KeyVault")
            .field("locked_out", &self.is_locked_out())
            .field("keys_locked_out", &keys_locked_out)
            .field("fragmenter", &self.inner.fragmenter.describe())
            .field("decoy_ignored", &self.inner.decoy_ignored)
            .field("config", &self.inner.config)
            .finish()
    }
}

/// Fragmenter choice held by the builder.
#[derive(Clone)]
enum BuilderFragmenter {
    Standard(StandardFragmenter),
    Custom(Arc<dyn FragmentStrategy>),
}

/// Normalization key choice held by the builder.
#[derive(Clone)]
enum NormalizationKey {
    /// Plain BLAKE3 (the default).
    None,
    /// A fresh random key per built vault.
    Random,
    /// A key derived from caller-supplied material.
    Derived(Arc<LockedBytes>),
}

/// Master verifier held by the builder: 32-byte hash key, then the
/// 32-byte keyed digest. `Err` if the RNG failed.
type MasterSeed = core::result::Result<Arc<LockedBytes>, &'static str>;

/// Fluent builder for [`KeyVault`].
///
/// [`KeyVault::new`] (since 1.2) is the builder with every default; use the
/// builder for anything else.
///
/// With `std`, finish with `KeyVaultBuilder::build`. Without `std`,
/// finish with [`KeyVaultBuilder::build_with_clock`]: there is no default
/// clock, and `build` does not exist, so a missing clock is a compile
/// error.
#[derive(Clone)]
pub struct KeyVaultBuilder {
    config: VaultConfig,
    fragmenter: BuilderFragmenter,
    /// `true` if `with_decoy` was called while a custom fragmenter was
    /// set (or before one was set), so the decoy is not applied.
    decoy_without_standard: bool,
    codex: Option<Arc<dyn Codex>>,
    monitor: Option<Arc<dyn SecurityMonitor>>,
    /// Optional Layer-9 audit sink. Defaults to
    /// [`NoAudit`](crate::NoAudit) at `build` time.
    audit: Option<Arc<dyn AuditSink>>,
    /// Master verifier, if one was registered. We hold a keyed digest
    /// (not the plaintext) so the master bytes don't linger in the
    /// builder's state. Locked and zeroized on drop.
    master: Option<MasterSeed>,
    normalization_key: NormalizationKey,
    /// Set when `with_decoy` was used, to report a decoy that a later
    /// `with_fragmenter` call makes ineffective.
    decoy_set: bool,
}

impl Default for KeyVaultBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for KeyVaultBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let fragmenter: Cow<'_, str> = match &self.fragmenter {
            BuilderFragmenter::Standard(s) => s.describe(),
            BuilderFragmenter::Custom(c) => c.describe(),
        };
        f.debug_struct("KeyVaultBuilder")
            .field("config", &self.config)
            .field("fragmenter", &fragmenter)
            .field("decoy_ignored", &self.decoy_ignored())
            .field("codex", &self.codex.as_ref().map(|_| "<set>"))
            .field("monitor", &self.monitor.as_ref().map(|_| "<set>"))
            .field("audit", &self.audit.as_ref().map(|_| "<set>"))
            .field("master_key", &self.master.as_ref().map(|_| "<set>"))
            .finish_non_exhaustive()
    }
}

impl KeyVaultBuilder {
    /// Start a new builder with default configuration and a default-range
    /// [`StandardFragmenter`]. Cargo features never change what this
    /// returns; see [`KeyVaultBuilder::from_features`] for that.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: VaultConfig::new(),
            fragmenter: BuilderFragmenter::Standard(StandardFragmenter::new()),
            decoy_without_standard: false,
            codex: None,
            monitor: None,
            audit: None,
            master: None,
            normalization_key: NormalizationKey::None,
            decoy_set: false,
        }
    }

    /// Start a builder configured by the enabled Cargo features.
    ///
    /// | Features | Effect |
    /// |----------|--------|
    /// | `fragment-layered` | [`LayeredFragmenter`](crate::LayeredFragmenter) over standard (with the decoy below), interleaved and random |
    /// | `fragment-random` | [`RandomFragmenter`](crate::RandomFragmenter) |
    /// | `fragment-interleaved` | [`InterleavedFragmenter`](crate::InterleavedFragmenter) |
    /// | `fragment-standard` or none | [`StandardFragmenter`] |
    /// | `decoy-self-ref` | [`SelfReferenceDecoy`](crate::SelfReferenceDecoy) on the standard fragmenter |
    /// | `decoy-key-derived` | [`KeyDerivedDecoy`](crate::KeyDerivedDecoy) |
    /// | `decoy-random` | [`RandomDecoy`](crate::RandomDecoy) |
    /// | `codex` / `codex-dynamic` | a fresh [`DynamicCodex`](crate::DynamicCodex) |
    /// | `monitor` + `monitor-tracing` | `LogMonitor` |
    /// | `audit` + `monitor-tracing` | `LogAudit` |
    ///
    /// When several fragment features are on, the first in the table wins;
    /// when several decoy features are on, the strongest wins
    /// (self-reference, then key-derived, then random). Features from every
    /// crate in a build are merged, so this rule makes sure one crate
    /// enabling a stronger option is never undone by another. Decoys apply
    /// to the standard fragmenter only (alone or inside the layered one).
    ///
    /// With the default features this is a [`StandardFragmenter`] with
    /// [`SelfReferenceDecoy`](crate::SelfReferenceDecoy).
    ///
    /// # Errors
    ///
    /// [`Error::Internal`](crate::Error::Internal) if a codex is enabled and
    /// the RNG fails while building its table.
    pub fn from_features() -> Result<Self> {
        let mut builder = Self::new();

        let mut standard = StandardFragmenter::new();
        if cfg!(feature = "decoy-self-ref") {
            standard = standard.with_decoy(crate::SelfReferenceDecoy);
        } else if cfg!(feature = "decoy-key-derived") {
            standard = standard.with_decoy(crate::KeyDerivedDecoy);
        } else if cfg!(feature = "decoy-random") {
            standard = standard.with_decoy(crate::RandomDecoy);
        }

        builder.fragmenter = if cfg!(feature = "fragment-layered") {
            let layered = crate::LayeredFragmenter::new(alloc::vec![
                Arc::new(standard) as Arc<dyn FragmentStrategy>,
                Arc::new(crate::InterleavedFragmenter::new()) as Arc<dyn FragmentStrategy>,
                Arc::new(crate::RandomFragmenter::new()) as Arc<dyn FragmentStrategy>,
            ])?;
            BuilderFragmenter::Custom(Arc::new(layered))
        } else if cfg!(feature = "fragment-random") {
            BuilderFragmenter::Custom(Arc::new(crate::RandomFragmenter::new()))
        } else if cfg!(feature = "fragment-interleaved") {
            BuilderFragmenter::Custom(Arc::new(crate::InterleavedFragmenter::new()))
        } else {
            BuilderFragmenter::Standard(standard)
        };

        if cfg!(feature = "codex") {
            builder.codex = Some(Arc::new(crate::DynamicCodex::new()?));
        }

        #[cfg(feature = "monitor-tracing")]
        {
            // `monitor-tracing` implies `monitor`.
            builder.monitor = Some(Arc::new(crate::LogMonitor::new()));
            if cfg!(feature = "audit") {
                builder.audit = Some(Arc::new(crate::LogAudit::new()));
            }
        }

        Ok(builder)
    }

    /// `true` if a decoy was configured but will not be used because the
    /// fragmenter is not [`StandardFragmenter`].
    fn decoy_ignored(&self) -> bool {
        (self.decoy_set && matches!(self.fragmenter, BuilderFragmenter::Custom(_)))
            || self.decoy_without_standard
    }

    /// Enable or disable BLAKE3 normalization of input key material.
    ///
    /// Default: `true`. Disabling normalization preserves the original byte
    /// pattern of the key in storage, which can leak format cues (DER
    /// envelopes, PEM markers, ASCII-armored data). Disable only when you
    /// have a specific reason to preserve the original bytes. Disabling it
    /// also disables keyed normalization.
    #[must_use]
    pub fn normalize_with_blake3(mut self, enabled: bool) -> Self {
        self.config.key_normalization = enabled;
        self
    }

    /// Normalize with keyed BLAKE3 under a random 32-byte key generated for
    /// each vault this builder builds.
    ///
    /// The stored value (and the bytes [`KeyVault::with_key`] returns)
    /// become `BLAKE3-keyed(k, key)` instead of `BLAKE3(key)`. `k` is held
    /// like key material (locked, excluded from dumps, zeroed on drop,
    /// page-protected when that option is on), so a copy of a stored
    /// value cannot be used on its own to test guesses of a low-entropy
    /// input.
    ///
    /// **The effective key changes every time the process starts.** Use
    /// this only for keys whose derived value never has to match across
    /// runs (session keys, in-process MACs). For keys that encrypt data at
    /// rest, use [`KeyVaultBuilder::with_normalization_key`] with a key
    /// you keep, or plain normalization.
    ///
    /// Turns normalization on. Plain BLAKE3 stays the default; switching
    /// the default is planned for 2.0, since it changes every effective
    /// key.
    #[must_use]
    pub fn with_keyed_normalization(mut self) -> Self {
        self.config.key_normalization = true;
        self.config.keyed_normalization = true;
        self.normalization_key = NormalizationKey::Random;
        self
    }

    /// Normalize with keyed BLAKE3 under a key derived from `key`.
    ///
    /// Like [`KeyVaultBuilder::with_keyed_normalization`], but the effective
    /// keys are stable across processes as long as you supply the same
    /// normalization key (from a keychain, say). Any length is accepted;
    /// it is turned into a 32-byte BLAKE3 key with BLAKE3's `derive_key`
    /// mode. `key` is wiped when this call returns.
    ///
    /// Turns normalization on.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // consumed so its Drop wipes it.
    pub fn with_normalization_key(mut self, key: RawKey) -> Self {
        let mut derived = Zeroizing::new([0u8; 32]);
        blake3_derive_into(NORMALIZATION_KEY_CONTEXT, key.as_bytes(), &mut derived[..]);
        self.config.key_normalization = true;
        self.config.keyed_normalization = true;
        self.normalization_key =
            NormalizationKey::Derived(Arc::new(LockedBytes::from_slice(&derived[..])));
        self
    }

    /// Select the fragmentation strategy.
    ///
    /// Default: [`StandardFragmenter`]. Any [`FragmentStrategy`] works,
    /// including your own (see [`Fragments::from_chunks`]). The built-in
    /// alternatives are [`InterleavedFragmenter`](crate::InterleavedFragmenter),
    /// [`RandomFragmenter`](crate::RandomFragmenter) and
    /// [`LayeredFragmenter`](crate::LayeredFragmenter).
    ///
    /// [`KeyVaultBuilder::with_decoy`] and [`KeyVaultBuilder::with_chunk_range`]
    /// configure the built-in [`StandardFragmenter`]. With another strategy
    /// a decoy set through `with_decoy` is **not** used; configure decoys
    /// on the strategy itself (for example a `LayeredFragmenter` whose
    /// sub-strategy is `StandardFragmenter::new().with_decoy(..)`).
    /// `Debug` output of the builder and vault shows `decoy_ignored: true`
    /// in that case. Calling `with_chunk_range` afterwards switches back to
    /// `StandardFragmenter`.
    ///
    /// # Examples
    ///
    /// ```
    /// use key_vault::{KeyVaultBuilder, RandomFragmenter, RawKey};
    ///
    /// let vault = KeyVaultBuilder::new()
    ///     .with_fragmenter(RandomFragmenter::new())
    ///     .build();
    /// let h = vault.register("k", RawKey::new(vec![7; 32])).unwrap();
    /// assert_eq!(vault.with_key(h, |k| k.len()).unwrap(), 32);
    /// ```
    #[must_use]
    pub fn with_fragmenter<F>(mut self, fragmenter: F) -> Self
    where
        F: FragmentStrategy + 'static,
    {
        self.fragmenter = BuilderFragmenter::Custom(Arc::new(fragmenter));
        self
    }

    /// Customize the fragmenter chunk-size range.
    ///
    /// Defaults are documented on [`StandardFragmenter::new`]. `min` is
    /// clamped to `>= 1` and `max` to `>= min`. Calling this selects a
    /// [`StandardFragmenter`] with that range, replacing any previously
    /// configured fragmenter, and resets the decoy strategy to `None`;
    /// configure decoy *after* this call.
    #[must_use]
    pub fn with_chunk_range(mut self, min: usize, max: usize) -> Self {
        self.fragmenter =
            BuilderFragmenter::Standard(StandardFragmenter::with_chunk_range(min, max));
        self.decoy_set = false;
        self.decoy_without_standard = false;
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
    /// same process memory as the fragments. Without this call (or
    /// [`KeyVaultBuilder::from_features`] with the `codex` feature) no
    /// codex is used.
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

    /// Attach a Layer-4 decoy strategy to the standard fragmenter.
    ///
    /// When set, every fragmentation also produces decoy chunks from the
    /// strategy. Decoys are interleaved with real chunks via the same
    /// Fisher-Yates shuffle and are skipped by `defragment`. See
    /// [`StandardFragmenter::with_decoy`] for details on chunk-count and
    /// size selection.
    ///
    /// Use [`SelfReferenceDecoy`](crate::SelfReferenceDecoy) for the
    /// closest statistical match to the key;
    /// [`KeyDerivedDecoy`](crate::KeyDerivedDecoy) for BLAKE3-XOF derived
    /// CSPRNG-like output;
    /// [`RandomDecoy`](crate::RandomDecoy) for raw CSPRNG output.
    ///
    /// Only the built-in [`StandardFragmenter`] uses this decoy; with a
    /// strategy chosen by [`KeyVaultBuilder::with_fragmenter`] it has no
    /// effect (see there). Decoys are obfuscation only: the layout buffer
    /// that marks them is in the same process memory.
    #[must_use]
    pub fn with_decoy<D>(mut self, decoy: D) -> Self
    where
        D: DecoyStrategy + 'static,
    {
        match self.fragmenter {
            BuilderFragmenter::Standard(standard) => {
                self.fragmenter = BuilderFragmenter::Standard(standard.with_decoy(decoy));
            }
            BuilderFragmenter::Custom(custom) => {
                self.fragmenter = BuilderFragmenter::Custom(custom);
                self.decoy_without_standard = true;
            }
        }
        self.decoy_set = true;
        self
    }

    /// Attach a Layer-8 security monitor.
    ///
    /// Replaces any previously-configured monitor. The monitor receives
    /// every event the vault produces — failure callbacks via
    /// [`KeyVault::report_failure`], anomaly callbacks via
    /// [`KeyVault::report_anomalous_access`], and threshold-breach
    /// callbacks when either failure threshold fires.
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

    /// Configure the vault-wide failure-threshold detector.
    ///
    /// When [`KeyVault::report_failure`] records `max` failures for the
    /// same `key_name` within `window`, the whole vault transitions to
    /// lock-out state and the monitor's `on_threshold_breach` fires with
    /// [`LockoutScope::Vault`].
    ///
    /// Pass `max = 0` to disable it (the default). The vault will still
    /// forward every failure to the monitor; it just won't lock out on its
    /// own. For a lockout that affects only the key that failed, use
    /// [`KeyVaultBuilder::with_key_lockout`] instead (or as well).
    ///
    /// `window` is the sliding-window size for the per-name failure
    /// counter; failures older than this fall off and no longer count.
    #[must_use]
    pub fn with_failure_threshold(mut self, max: u32, window: Duration) -> Self {
        self.config.max_failures_before_lockout = max;
        self.config.failure_window = window;
        self
    }

    /// Configure per-key lockout.
    ///
    /// When [`KeyVault::report_failure`] records `max` failures for one key
    /// name within `window`, only the key registered under that name is
    /// locked out: [`KeyVault::with_key`] and [`KeyVault::rotate`] on it
    /// return [`Error::LockedOut`](crate::Error::LockedOut), and every
    /// other key keeps working. The monitor's `on_threshold_breach` fires
    /// with [`LockoutScope::Key`].
    ///
    /// `lock_for` is how long the lockout lasts, measured with the vault's
    /// [`Clock`]; `None` keeps it until [`KeyVault::clear_key_lockout`],
    /// [`KeyVault::clear_lockout`] or a successful
    /// [`KeyVault::unlock_with_master`]. [`KeyVault::unregister`] still
    /// works on a locked-out key.
    ///
    /// Off by default (`max = 0`). It is independent of the vault-wide
    /// threshold ([`KeyVaultBuilder::with_failure_threshold`]); both can be
    /// on. Master-unlock failures do not count toward it (they have their
    /// own backoff).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use key_vault::{KeyVaultBuilder, RawKey};
    ///
    /// let vault = KeyVaultBuilder::new()
    ///     .with_key_lockout(3, Duration::from_secs(60), Some(Duration::from_secs(300)))
    ///     .build();
    /// let a = vault.register("a", RawKey::new(vec![1; 32])).unwrap();
    /// let b = vault.register("b", RawKey::new(vec![2; 32])).unwrap();
    /// for _ in 0..3 {
    ///     vault.report_failure("a", None);
    /// }
    /// assert!(vault.is_key_locked_out(a));
    /// assert!(vault.with_key(a, |_| ()).is_err());
    /// assert!(vault.with_key(b, |_| ()).is_ok()); // other keys unaffected
    /// assert!(vault.clear_key_lockout("a"));
    /// assert!(vault.with_key(a, |_| ()).is_ok());
    /// ```
    #[must_use]
    pub fn with_key_lockout(
        mut self,
        max: u32,
        window: Duration,
        lock_for: Option<Duration>,
    ) -> Self {
        self.config.key_lockout_threshold = max;
        self.config.key_lockout_window = window;
        self.config.key_lockout_duration = lock_for;
        self
    }

    /// Rate-limit [`KeyVault::unlock_with_master`] with exponential backoff.
    ///
    /// After a failed attempt, further attempts are refused with
    /// [`Error::RateLimited`](crate::Error::RateLimited) (without being
    /// checked) for `base`, then `2 * base`, `4 * base`, ... after each
    /// further failure, never more than `max`. A successful unlock resets
    /// the delay. Attempts are serialized, so concurrent guesses cannot
    /// share one window. Time is measured with the vault's [`Clock`].
    ///
    /// Off by default (`base = Duration::ZERO`), because turning it on
    /// makes a correct credential wait after a wrong one.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use key_vault::{Error, KeyVaultBuilder, RawKey};
    ///
    /// let vault = KeyVaultBuilder::new()
    ///     .with_master_key(RawKey::new(b"a long random master credential".to_vec()))
    ///     .with_master_unlock_backoff(Duration::from_secs(1), Duration::from_secs(60))
    ///     .build();
    /// assert!(vault.unlock_with_master(b"wrong").is_err());
    /// // The next attempt within a second is not even checked.
    /// assert!(matches!(
    ///     vault.unlock_with_master(b"a long random master credential"),
    ///     Err(Error::RateLimited { .. })
    /// ));
    /// ```
    #[must_use]
    pub fn with_master_unlock_backoff(mut self, base: Duration, max: Duration) -> Self {
        self.config.master_backoff_base = base;
        self.config.master_backoff_max = max.max(base);
        self
    }

    /// Keep each registered key in its own private mapping that is
    /// inaccessible (`PROT_NONE` / `PAGE_NOACCESS`) except while
    /// [`KeyVault::with_key`] reassembles it.
    ///
    /// Ordinary fragments live on heap pages shared with unrelated
    /// objects, which cannot be made inaccessible. With this option each
    /// key's fragments and layout are copied into a dedicated mapping
    /// (at least one page per key), which is also locked and excluded from
    /// dumps. While no thread is reading the key, any access to those
    /// pages faults, so a stray read or a scan of readable memory from
    /// inside the process cannot see them. The normalization key and
    /// the master verifier are held the same way.
    ///
    /// Cost: each `with_key` call makes two protection changes (about
    /// 1.5 µs on Linux, see `docs/PERFORMANCE.md`), and each key uses at
    /// least one page. Concurrent readers of one key share a single open
    /// window.
    ///
    /// It does not stop an attacker who can change page protections or
    /// read memory through the kernel (a debugger, `ptrace`,
    /// `/proc/<pid>/mem`), and the plaintext still exists in the scratch
    /// buffer while your callback runs.
    ///
    /// Default: off. One-shot [`KeyVault::fragment`] output is never
    /// protected (it is handed to the caller).
    #[cfg(any(unix, windows))]
    #[must_use]
    pub fn with_page_protection(mut self, enabled: bool) -> Self {
        self.config.page_protection = enabled;
        self
    }

    /// Refuse to hold key bytes in memory that could not be page-locked.
    ///
    /// By default a key is stored even when the OS will not lock its pages
    /// (the process reached `RLIMIT_MEMLOCK` on Linux or macOS, or its
    /// working-set limit on Windows): it works, but the OS may write it to
    /// swap. [`KeyVault::memory_status`] counts such keys and
    /// [`SecurityMonitor::on_memory_lock_failure`] reports them.
    ///
    /// With strict locking on, [`KeyVault::register`] and
    /// [`KeyVault::rotate`] fail with
    /// [`Error::MemoryLock`](crate::Error::MemoryLock) instead (nothing is
    /// stored, and the copy made for fragmenting is wiped), and
    /// [`KeyVault::with_key`] fails the same way if its scratch buffer
    /// cannot be locked. Raising the limit while the process runs makes
    /// later calls succeed; the crate retries pages that failed before.
    ///
    /// Two combinations always fail and are best avoided: page protection
    /// on Windows (Windows drops the lock on inaccessible pages, so a
    /// protected key is never locked there), and targets without an OS,
    /// where nothing can be locked.
    ///
    /// Default: off. Since 1.2.
    ///
    /// # Examples
    ///
    /// ```
    /// use key_vault::{Error, KeyVaultBuilder, RawKey};
    ///
    /// let vault = KeyVaultBuilder::new().with_strict_locking(true).build();
    /// match vault.register("k", RawKey::new(vec![7; 32])) {
    ///     Ok(_) => {}                       // the key is page-locked
    ///     Err(Error::MemoryLock(_)) => {}   // at the lock limit: not stored
    ///     Err(e) => return Err(e),
    /// }
    /// # Ok::<(), Error>(())
    /// ```
    #[must_use]
    pub fn with_strict_locking(mut self, enabled: bool) -> Self {
        self.config.strict_locking = enabled;
        self
    }

    /// Set how many names of unregistered keys the failure tracker
    /// remembers at once. Default: 4096.
    ///
    /// [`KeyVault::report_failure`] accepts any name. Names that a key is
    /// registered under are always tracked; other names (an unknown key
    /// id taken from a request, say) share this capacity, and when it is
    /// full the name whose last failure is oldest is forgotten. Only the
    /// vault-wide threshold counts such names. Each tracked name uses
    /// about 100 bytes plus 24 bytes per remembered failure (at most the
    /// larger threshold, and at most 64). Values below 16 are raised to
    /// 16. Since 1.2.
    #[must_use]
    pub fn with_failure_tracking_capacity(mut self, names: usize) -> Self {
        self.config.failure_tracking_capacity = names;
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
    /// The builder generates a random 32-byte BLAKE3 key and stores it
    /// with `BLAKE3-keyed(key, master)`, in locked, dump-excluded memory;
    /// the plaintext is dropped immediately (and zeroed via
    /// `RawKey::Drop`). Use [`KeyVault::unlock_with_master`] later to clear
    /// a lockout. Vaults built from clones of this builder share the
    /// verifier.
    ///
    /// The verifier is a fast hash, not a password hash: use a
    /// high-entropy credential, not a memorable passphrase, and consider
    /// [`KeyVaultBuilder::with_master_unlock_backoff`].
    ///
    /// Calling this twice replaces the previously-stored verifier. An
    /// empty key (zero length) is accepted and matches an empty attempt.
    #[must_use]
    pub fn with_master_key(mut self, master: RawKey) -> Self {
        let mut hash_key = Zeroizing::new([0u8; 32]);
        let seed = match crate::rng::fill(&mut hash_key[..]) {
            Ok(()) => {
                let mut stored = Zeroizing::new([0u8; 64]);
                stored[..32].copy_from_slice(&hash_key[..]);
                blake3_keyed_into(&hash_key, master.as_bytes(), &mut stored[32..]);
                Ok(Arc::new(LockedBytes::from_slice(&stored[..])))
            }
            Err(_) => Err("RNG failed while setting up the master key verifier"),
        };
        self.master = Some(seed);
        // `master` drops here; its `Drop` impl zeroes the internal Vec.
        drop(master);
        self
    }

    /// Finalize and produce a [`KeyVault`] that uses [`StdClock`](crate::StdClock).
    ///
    /// Only with `std`. Without it, use [`KeyVaultBuilder::build_with_clock`].
    #[cfg(feature = "std")]
    #[must_use]
    pub fn build(self) -> KeyVault {
        self.finish(VaultClock::Std)
    }

    /// Finalize and produce a [`KeyVault`] that reads time from `clock`.
    ///
    /// Lockout windows, per-key lockout expiry, master-unlock backoff and
    /// the timestamps in [`KeyMetadata`] and [`AuditEvent`] all come from
    /// `clock`. In `no_std` builds this is the only way to build a vault.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::time::Duration;
    /// use key_vault::{Clock, KeyVaultBuilder};
    ///
    /// struct Fixed;
    /// impl Clock for Fixed {
    ///     fn now(&self) -> Duration {
    ///         Duration::from_secs(5)
    ///     }
    /// }
    ///
    /// let vault = KeyVaultBuilder::new().build_with_clock(Fixed);
    /// # let _ = vault;
    /// ```
    #[must_use]
    pub fn build_with_clock<C>(self, clock: C) -> KeyVault
    where
        C: Clock + 'static,
    {
        self.finish(VaultClock::Custom(Arc::new(clock)))
    }

    fn finish(self, clock: VaultClock) -> KeyVault {
        let decoy_ignored = self.decoy_ignored();
        let protect = self.config.page_protection;
        let monitor: Arc<dyn SecurityMonitor> = self
            .monitor
            .unwrap_or_else(|| Arc::new(crate::monitor::NoMonitor));
        let audit: Arc<dyn AuditSink> = self
            .audit
            .unwrap_or_else(|| Arc::new(crate::audit::NoAudit));
        let fragmenter = match self.fragmenter {
            BuilderFragmenter::Standard(s) => Fragmenter::Standard(s),
            BuilderFragmenter::Custom(c) => Fragmenter::Custom(c),
        };
        let normalizer = if self.config.key_normalization {
            match self.normalization_key {
                NormalizationKey::None => Normalizer::Plain,
                NormalizationKey::Random => {
                    let mut k = Zeroizing::new([0u8; 32]);
                    match crate::rng::fill(&mut k[..]) {
                        Ok(()) => secret_or_unavailable(&k[..], protect),
                        Err(_) => Normalizer::Unavailable(
                            "RNG failed while creating the normalization key",
                        ),
                    }
                }
                NormalizationKey::Derived(k) => secret_or_unavailable(k.as_bytes(), protect),
            }
        } else {
            Normalizer::Off
        };
        let master = self.master.map(|seed| match seed {
            Ok(stored) => match SecretBytes::new(stored.as_bytes(), protect) {
                Ok(secret) => MasterVerifier::Ready(secret),
                Err(_) => MasterVerifier::Unavailable(
                    "could not create the protected mapping for the master key verifier",
                ),
            },
            Err(reason) => MasterVerifier::Unavailable(reason),
        });
        let config = self.config;
        let max_threshold = config
            .max_failures_before_lockout
            .max(config.key_lockout_threshold);
        let tracker = (max_threshold > 0)
            .then(|| FailureTracker::new(max_threshold, config.failure_tracking_capacity));
        // Memory locks are not inherited across `fork`; have the crate
        // lock its pages again in a child process.
        crate::memory::install_fork_handler();
        KeyVault {
            inner: Arc::new(VaultInner {
                config,
                fragmenter,
                decoy_ignored,
                normalizer,
                codex: self.codex,
                monitor,
                clock,
                keys: Registry::from_pointee(Snapshot::default()),
                writer: Mutex::new(()),
                names: NameHasher::new(),
                tracker,
                locked_out: AtomicBool::new(false),
                lock_failing: AtomicBool::new(false),
                master,
                master_backoff: Mutex::new(Backoff::default()),
                audit,
            }),
        }
    }
}

/// Hold a normalization key as a [`SecretBytes`], or record why that
/// failed.
fn secret_or_unavailable(key: &[u8], protect: bool) -> Normalizer {
    match SecretBytes::new(key, protect) {
        Ok(secret) => Normalizer::Keyed(secret),
        Err(_) => Normalizer::Unavailable(
            "could not create the protected mapping for the normalization key",
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Instant;

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
    fn replace_fragments(v: &KeyVault, handle: KeyHandle, fragments: &Fragments) {
        let current = v.inner.keys.load_full();
        let id = handle.id();
        let old = current.get(id).expect("handle registered");
        let entry = Arc::new(KeyEntry {
            name: old.name.clone(),
            name_hash: old.name_hash,
            fragments: fragments.share(),
            metadata: old.metadata.clone(),
            lock: Arc::clone(&old.lock),
        });
        let next = Snapshot {
            by_id: current.by_id.insert(id_hash(id), id, entry).0,
            by_name: current.by_name.clone(),
        };
        v.inner.keys.store(Arc::new(next));
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
        replace_fragments(&v, h, &corrupt);

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
    /// `Fragments`).
    fn pad_registry(v: &KeyVault, n: usize) {
        let mut map = (*v.inner.keys.load_full()).clone();
        let shared = v
            .inner
            .fragmenter
            .fragment(&RawKey::new(alloc::vec![9u8; 8]))
            .unwrap();
        for i in 0..n {
            let id = KeyHandle::allocate().id();
            let name = format!("filler-{i}");
            let name_hash = v.inner.names.hash(&name);
            map.by_name = map.by_name.insert(name_hash, name.clone(), id).0;
            let entry = Arc::new(KeyEntry {
                name,
                name_hash,
                fragments: shared.share(),
                metadata: KeyMetadata::new(Duration::ZERO, 8, None),
                lock: Arc::new(KeyLock::new()),
            });
            map.by_id = map.by_id.insert(id_hash(id), id, entry).0;
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
            if v.inner.writer.is_locked() {
                return;
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
        let frags = &snapshot.get(handle.id()).expect("registered").fragments;
        let mut pages = Vec::new();
        for lb in frags
            .chunks()
            .iter()
            .chain(core::iter::once(frags.layout_buffer()))
        {
            if lb.is_locked() && lb.uses_page_table() {
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
        // Chunks larger than the page pool's biggest block live on the
        // heap and go through the page table, which this test is about.
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_chunk_range(2100, 2100)
            .build();
        // Heap allocations made back to back usually end up next to each
        // other, so two keys often share a page. Keep registering pairs
        // until they do.
        let mut shared = None;
        for i in 0..64 {
            let a = v
                .register(format!("a{i}"), RawKey::new(alloc::vec![0x11; 2100]))
                .unwrap();
            let b = v
                .register(format!("b{i}"), RawKey::new(alloc::vec![0x22; 2100]))
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
            alloc::vec![0x22; 2100]
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
            for p in crate::memory::pages_of(&scratch.buf) {
                let state = crate::memory::page_state(p).expect("scratch page referenced");
                assert!(state.0 >= 1);
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

    // ----- 1.1: test clock -----

    /// Clock the test moves by hand.
    #[derive(Clone, Default)]
    struct TestClock(Arc<core::sync::atomic::AtomicU64>);

    impl TestClock {
        fn advance(&self, by: Duration) {
            let nanos = u64::try_from(by.as_nanos()).unwrap();
            let _ = self.0.fetch_add(nanos, Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> Duration {
            Duration::from_nanos(self.0.load(Ordering::SeqCst))
        }

        fn unix_time(&self) -> Duration {
            Duration::from_secs(1_800_000_000) + self.now()
        }
    }

    /// Monitor that records the scope of every threshold breach.
    #[derive(Default)]
    struct ScopeMonitor {
        breaches: Mutex<Vec<(String, LockoutScope, bool)>>,
    }

    impl SecurityMonitor for ScopeMonitor {
        fn on_decryption_failure(&self, _ctx: &FailureContext) {}
        fn on_anomalous_access(&self, _ctx: &AccessContext) {}
        fn on_threshold_breach(&self, ctx: &ThresholdContext) {
            self.breaches.lock().unwrap().push((
                ctx.key_name.clone(),
                ctx.scope,
                ctx.lockout_triggered,
            ));
        }
    }

    // ----- 1.1: per-key lockout -----

    #[test]
    fn per_key_lockout_is_off_by_default() {
        let v = KeyVaultBuilder::new().build();
        let h = v.register("k", RawKey::new(alloc::vec![1u8; 16])).unwrap();
        for _ in 0..100 {
            v.report_failure("k", None);
        }
        assert!(!v.is_key_locked_out(h));
        assert!(!v.is_locked_out());
        assert!(v.with_key(h, |_| ()).is_ok());
    }

    #[test]
    fn per_key_lockout_triggers_for_that_key_only_and_resets() {
        let monitor = Arc::new(ScopeMonitor::default());
        let v = KeyVaultBuilder::new()
            .with_monitor(Arc::clone(&monitor) as Arc<dyn SecurityMonitor>)
            .with_key_lockout(3, Duration::from_secs(60), None)
            .build();
        let a = v.register("a", RawKey::new(alloc::vec![1u8; 16])).unwrap();
        let b = v.register("b", RawKey::new(alloc::vec![2u8; 16])).unwrap();

        v.report_failure("a", None);
        v.report_failure("a", None);
        assert!(!v.is_key_locked_out(a));
        assert!(v.with_key(a, |_| ()).is_ok());
        v.report_failure("a", None);

        // `a` is locked out; `b` and the vault are not.
        assert!(v.is_key_locked_out(a));
        assert!(!v.is_key_locked_out(b));
        assert!(!v.is_locked_out());
        assert!(matches!(v.with_key(a, |_| ()), Err(Error::LockedOut)));
        assert!(matches!(
            v.rotate(a, RawKey::new(alloc::vec![3u8; 16])),
            Err(Error::LockedOut)
        ));
        assert_eq!(v.with_key(b, <[u8]>::to_vec).unwrap().len(), 32);
        assert_eq!(
            monitor.breaches.lock().unwrap().as_slice(),
            &[("a".to_string(), LockoutScope::Key, true)]
        );

        // Explicit reset, and the failure count starts over.
        assert!(v.clear_key_lockout("a"));
        assert!(!v.clear_key_lockout("a"));
        assert!(!v.is_key_locked_out(a));
        assert!(v.with_key(a, |_| ()).is_ok());
        v.report_failure("a", None);
        v.report_failure("a", None);
        assert!(!v.is_key_locked_out(a));
        v.report_failure("a", None);
        assert!(v.is_key_locked_out(a));

        // clear_lockout clears per-key lockouts too.
        v.clear_lockout();
        assert!(!v.is_key_locked_out(a));
        assert!(v.with_key(a, |_| ()).is_ok());

        // Unregister works on a locked-out key.
        for _ in 0..3 {
            v.report_failure("a", None);
        }
        assert!(v.is_key_locked_out(a));
        v.unregister(a).unwrap();
    }

    #[test]
    fn per_key_lockout_expires_after_its_duration() {
        let clock = TestClock::default();
        let v = KeyVaultBuilder::new()
            .with_key_lockout(2, Duration::from_secs(10), Some(Duration::from_secs(30)))
            .build_with_clock(clock.clone());
        let h = v.register("k", RawKey::new(alloc::vec![1u8; 16])).unwrap();
        v.report_failure("k", None);
        v.report_failure("k", None);
        assert!(v.is_key_locked_out(h));
        clock.advance(Duration::from_secs(29));
        assert!(matches!(v.with_key(h, |_| ()), Err(Error::LockedOut)));
        clock.advance(Duration::from_secs(1));
        assert!(!v.is_key_locked_out(h));
        assert!(v.with_key(h, |_| ()).is_ok());
        assert!(format!("{v:?}").contains("keys_locked_out: 0"));
    }

    #[test]
    fn per_key_failures_age_out_of_the_window() {
        let clock = TestClock::default();
        let v = KeyVaultBuilder::new()
            .with_key_lockout(2, Duration::from_secs(10), None)
            .build_with_clock(clock.clone());
        let h = v.register("k", RawKey::new(alloc::vec![1u8; 16])).unwrap();
        v.report_failure("k", None);
        clock.advance(Duration::from_secs(11));
        v.report_failure("k", None);
        assert!(!v.is_key_locked_out(h), "an expired failure still counted");
        v.report_failure("k", None);
        assert!(v.is_key_locked_out(h));
    }

    #[test]
    fn master_unlock_clears_per_key_lockouts_and_master_failures_do_not_lock_keys() {
        let v = KeyVaultBuilder::new()
            .with_master_key(RawKey::new(b"master".to_vec()))
            .with_key_lockout(1, Duration::from_secs(60), None)
            .build();
        let h = v.register("k", RawKey::new(alloc::vec![1u8; 16])).unwrap();
        let m = v
            .register(MASTER_NAME, RawKey::new(alloc::vec![2u8; 16]))
            .unwrap();
        assert!(v.unlock_with_master(b"wrong").is_err());
        assert!(
            !v.is_key_locked_out(m),
            "master failures fed the per-key lockout"
        );
        v.report_failure("k", None);
        assert!(v.is_key_locked_out(h));
        v.unlock_with_master(b"master").unwrap();
        assert!(!v.is_key_locked_out(h));
    }

    #[test]
    fn vault_wide_and_per_key_breaches_report_their_scope() {
        let monitor = Arc::new(ScopeMonitor::default());
        let v = KeyVaultBuilder::new()
            .with_monitor(Arc::clone(&monitor) as Arc<dyn SecurityMonitor>)
            .with_failure_threshold(2, Duration::from_secs(60))
            .with_key_lockout(1, Duration::from_secs(60), None)
            .build();
        let _ = v.register("x", RawKey::new(alloc::vec![1u8; 16])).unwrap();
        v.report_failure("x", None);
        v.report_failure("x", None);
        let breaches = monitor.breaches.lock().unwrap().clone();
        assert_eq!(
            breaches,
            alloc::vec![
                ("x".to_string(), LockoutScope::Key, true),
                ("x".to_string(), LockoutScope::Vault, true),
                ("x".to_string(), LockoutScope::Key, false),
            ]
        );
    }

    // ----- 1.1: master unlock backoff -----

    #[test]
    fn master_backoff_refuses_attempts_until_the_delay_passes() {
        let clock = TestClock::default();
        let v = KeyVaultBuilder::new()
            .with_master_key(RawKey::new(b"right".to_vec()))
            .with_master_unlock_backoff(Duration::from_secs(1), Duration::from_secs(5))
            .build_with_clock(clock.clone());

        let rate_limited = |r: Result<()>| match r {
            Err(Error::RateLimited { retry_after }) => Some(retry_after),
            _ => None,
        };

        // First failure: 1 s.
        assert!(matches!(
            v.unlock_with_master(b"wrong"),
            Err(Error::Acquisition { .. })
        ));
        assert_eq!(
            rate_limited(v.unlock_with_master(b"right")),
            Some(Duration::from_secs(1))
        );
        clock.advance(Duration::from_millis(400));
        assert_eq!(
            rate_limited(v.unlock_with_master(b"right")),
            Some(Duration::from_millis(600))
        );
        clock.advance(Duration::from_millis(600));

        // Second failure: 2 s; third: 4 s; fourth: capped at 5 s.
        for expected in [2u64, 4, 5, 5] {
            assert!(matches!(
                v.unlock_with_master(b"wrong"),
                Err(Error::Acquisition { .. })
            ));
            assert_eq!(
                rate_limited(v.unlock_with_master(b"wrong")),
                Some(Duration::from_secs(expected))
            );
            clock.advance(Duration::from_secs(expected));
        }

        // A refused attempt is not checked and does not count: the delay
        // after the next failure continues from the cap.
        v.unlock_with_master(b"right").unwrap();
        // Success resets the backoff.
        assert!(v.unlock_with_master(b"wrong").is_err());
        assert_eq!(
            rate_limited(v.unlock_with_master(b"right")),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn master_backoff_is_off_by_default() {
        let v = KeyVaultBuilder::new()
            .with_master_key(RawKey::new(b"right".to_vec()))
            .build();
        for _ in 0..5 {
            assert!(matches!(
                v.unlock_with_master(b"wrong"),
                Err(Error::Acquisition { .. })
            ));
        }
        v.unlock_with_master(b"right").unwrap();
    }

    /// Same as above with the real clock: a retry inside the delay is
    /// refused, a retry after it is checked.
    #[test]
    fn master_backoff_timing_with_the_std_clock() {
        let v = KeyVaultBuilder::new()
            .with_master_key(RawKey::new(b"right".to_vec()))
            .with_master_unlock_backoff(Duration::from_millis(150), Duration::from_secs(1))
            .build();
        let started = Instant::now();
        assert!(v.unlock_with_master(b"wrong").is_err());
        match v.unlock_with_master(b"right") {
            Err(Error::RateLimited { retry_after }) => {
                assert!(retry_after <= Duration::from_millis(150));
                assert!(retry_after + started.elapsed() >= Duration::from_millis(140));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
        std::thread::sleep(Duration::from_millis(160));
        v.unlock_with_master(b"right").unwrap();
    }

    // ----- 1.1: keyed normalization and master verifier -----

    #[test]
    fn keyed_normalization_differs_from_plain_blake3_and_per_vault() {
        let input = b"low entropy passphrase".to_vec();
        let plain = KeyVaultBuilder::new().build();
        let keyed_a = KeyVaultBuilder::new().with_keyed_normalization().build();
        let keyed_b = KeyVaultBuilder::new().with_keyed_normalization().build();
        assert!(keyed_a.config().keyed_normalization);
        let read = |v: &KeyVault| {
            let h = v.register("k", RawKey::new(input.clone())).unwrap();
            v.with_key(h, <[u8]>::to_vec).unwrap()
        };
        let p = read(&plain);
        let a = read(&keyed_a);
        let b = read(&keyed_b);
        assert_eq!(p, blake3::hash(&input).as_bytes().to_vec());
        assert_eq!(a.len(), 32);
        assert_ne!(a, p, "keyed normalization stored plain BLAKE3");
        assert_ne!(a, b, "two vaults shared a random normalization key");
    }

    #[test]
    fn caller_supplied_normalization_key_is_stable_across_vaults() {
        let nk = || RawKey::new(b"normalization key from the keychain".to_vec());
        let v1 = KeyVaultBuilder::new().with_normalization_key(nk()).build();
        let v2 = KeyVaultBuilder::new().with_normalization_key(nk()).build();
        let other = KeyVaultBuilder::new()
            .with_normalization_key(RawKey::new(b"another".to_vec()))
            .build();
        let read = |v: &KeyVault| {
            let h = v.register("k", RawKey::new(b"key".to_vec())).unwrap();
            v.with_key(h, <[u8]>::to_vec).unwrap()
        };
        let a = read(&v1);
        assert_eq!(a, read(&v2));
        assert_ne!(a, read(&other));
        let derived = blake3::derive_key(
            NORMALIZATION_KEY_CONTEXT,
            b"normalization key from the keychain",
        );
        assert_eq!(a, blake3::keyed_hash(&derived, b"key").as_bytes().to_vec());
        assert_ne!(a, blake3::hash(b"key").as_bytes().to_vec());
    }

    #[test]
    fn disabling_normalization_also_disables_keyed_mode() {
        let v = KeyVaultBuilder::new()
            .with_keyed_normalization()
            .normalize_with_blake3(false)
            .build();
        let h = v.register("k", RawKey::new(b"abc".to_vec())).unwrap();
        assert_eq!(v.with_key(h, <[u8]>::to_vec).unwrap(), b"abc");
    }

    #[test]
    fn master_verifier_is_keyed_not_plain_blake3() {
        let v = KeyVaultBuilder::new()
            .with_master_key(RawKey::new(b"master".to_vec()))
            .build();
        let Some(MasterVerifier::Ready(secret)) = &v.inner.master else {
            panic!("verifier missing");
        };
        let stored = secret.read(<[u8]>::to_vec).unwrap();
        assert_eq!(stored.len(), 64);
        let (hash_key, digest) = stored.split_at(32);
        assert_ne!(digest, blake3::hash(b"master").as_bytes());
        let hash_key: [u8; 32] = hash_key.try_into().unwrap();
        assert_eq!(digest, blake3::keyed_hash(&hash_key, b"master").as_bytes());
        // A second vault gets a different hash key.
        let w = KeyVaultBuilder::new()
            .with_master_key(RawKey::new(b"master".to_vec()))
            .build();
        let Some(MasterVerifier::Ready(other)) = &w.inner.master else {
            panic!("verifier missing");
        };
        assert_ne!(other.read(<[u8]>::to_vec).unwrap(), stored);
    }

    // ----- 1.1: fragmenter selection -----

    #[test]
    fn every_builtin_fragmenter_works_in_the_vault() {
        use crate::{InterleavedFragmenter, LayeredFragmenter, RandomFragmenter};
        let layered = LayeredFragmenter::new(alloc::vec![
            Arc::new(StandardFragmenter::new().with_decoy(crate::SelfReferenceDecoy))
                as Arc<dyn FragmentStrategy>,
            Arc::new(InterleavedFragmenter::new()) as Arc<dyn FragmentStrategy>,
            Arc::new(RandomFragmenter::new()) as Arc<dyn FragmentStrategy>,
        ])
        .unwrap();
        let vaults = [
            KeyVaultBuilder::new()
                .normalize_with_blake3(false)
                .with_fragmenter(InterleavedFragmenter::new())
                .build(),
            KeyVaultBuilder::new()
                .normalize_with_blake3(false)
                .with_fragmenter(RandomFragmenter::new())
                .build(),
            KeyVaultBuilder::new()
                .normalize_with_blake3(false)
                .with_fragmenter(layered)
                .with_codex(crate::DynamicCodex::new().unwrap())
                .build(),
        ];
        let key: Vec<u8> = (0u8..64).collect();
        for v in &vaults {
            for i in 0..20 {
                let h = v
                    .register(format!("k{i}"), RawKey::new(key.clone()))
                    .unwrap();
                assert_eq!(v.with_key(h, <[u8]>::to_vec).unwrap(), key);
                v.rotate(h, RawKey::new(alloc::vec![9u8; 40])).unwrap();
                assert_eq!(v.with_key(h, <[u8]>::to_vec).unwrap(), alloc::vec![9u8; 40]);
            }
        }
    }

    #[test]
    fn decoy_with_a_custom_fragmenter_is_reported_as_ignored() {
        let b = KeyVaultBuilder::new()
            .with_fragmenter(crate::RandomFragmenter::new())
            .with_decoy(crate::RandomDecoy);
        assert!(format!("{b:?}").contains("decoy_ignored: true"));
        let v = b.build();
        assert!(v.inner.decoy_ignored);
        let b = KeyVaultBuilder::new()
            .with_decoy(crate::RandomDecoy)
            .with_fragmenter(crate::RandomFragmenter::new());
        assert!(b.decoy_ignored());
        let b = KeyVaultBuilder::new().with_decoy(crate::RandomDecoy);
        assert!(!b.decoy_ignored());
    }

    /// With the default features `from_features` gives the standard
    /// fragmenter with self-reference decoys; with `--all-features` the
    /// layered fragmenter and a codex. Either way it round-trips.
    #[test]
    fn from_features_builds_a_working_vault() {
        let v = KeyVaultBuilder::from_features().unwrap().build();
        let described = v.inner.fragmenter.describe().into_owned();
        if cfg!(feature = "fragment-layered") {
            assert_eq!(described, "layered");
        } else if cfg!(feature = "fragment-random") {
            assert_eq!(described, "random");
        } else if cfg!(feature = "fragment-interleaved") {
            assert_eq!(described, "interleaved");
        } else {
            assert_eq!(described, "standard");
        }
        assert_eq!(v.inner.codex.is_some(), cfg!(feature = "codex"));
        let h = v.register("k", RawKey::new(b"material".to_vec())).unwrap();
        assert_eq!(v.with_key(h, <[u8]>::len).unwrap(), 32);
        if cfg!(feature = "decoy-self-ref") && described == "standard" {
            let snapshot = v.inner.keys.load();
            let frags = &snapshot.get(h.id()).unwrap().fragments;
            assert!(
                frags
                    .layout_bytes()
                    .chunks(4)
                    .any(|c| c == u32::MAX.to_le_bytes()),
                "no decoy chunk stored"
            );
        }
    }
}

// ----- 1.1: page protection -----

#[cfg(all(test, any(unix, windows)))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod page_protection_tests {
    use super::*;

    fn protected_vault() -> KeyVault {
        KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_page_protection(true)
            .build()
    }

    /// Mapping address and length of the protected region behind `h`.
    fn region_of(v: &KeyVault, h: KeyHandle) -> (usize, usize) {
        let snapshot = v.inner.keys.load();
        let frags = &snapshot.get(h.id()).unwrap().fragments;
        frags.region().expect("key is not page-protected").mapping()
    }

    /// `Some(true)` if the OS reports the region as inaccessible,
    /// `Some(false)` if readable, `None` where the test cannot ask the OS.
    #[allow(clippy::unnecessary_wraps)] // `None` on other platforms.
    fn is_inaccessible(addr: usize) -> Option<bool> {
        #[cfg(target_os = "linux")]
        {
            Some(crate::test_util::maps_perms(addr).as_deref() == Some("---p"))
        }
        #[cfg(windows)]
        {
            Some(
                crate::test_util::virtual_query_protect(addr)
                    == windows_sys::Win32::System::Memory::PAGE_NOACCESS,
            )
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = addr;
            None
        }
    }

    #[test]
    fn protected_keys_round_trip_and_rotate() {
        let v = protected_vault();
        assert!(v.config().page_protection);
        let mut handles = Vec::new();
        for i in 0..50u8 {
            handles.push(
                v.register(
                    format!("k{i}"),
                    RawKey::new(alloc::vec![i; 32 + usize::from(i)]),
                )
                .unwrap(),
            );
        }
        for (i, h) in handles.iter().enumerate() {
            let i = u8::try_from(i).unwrap();
            assert_eq!(
                v.with_key(*h, <[u8]>::to_vec).unwrap(),
                alloc::vec![i; 32 + usize::from(i)]
            );
        }
        v.rotate(handles[3], RawKey::new(alloc::vec![0xee; 16]))
            .unwrap();
        assert_eq!(
            v.with_key(handles[3], <[u8]>::to_vec).unwrap(),
            alloc::vec![0xee; 16]
        );
        v.unregister(handles[4]).unwrap();
        assert_eq!(v.key_count(), 49);
    }

    /// The key's pages are inaccessible except while a reader holds the
    /// region open, and go back to inaccessible afterwards.
    #[test]
    fn mapping_is_inaccessible_between_reads() {
        let v = protected_vault();
        let h = v.register("k", RawKey::new(alloc::vec![0x5a; 48])).unwrap();
        let (addr, len) = region_of(&v, h);
        assert!(len >= crate::memory::page_size());
        assert_ne!(
            is_inaccessible(addr),
            Some(false),
            "region readable after register"
        );

        let snapshot = v.inner.keys.load();
        let frags = snapshot.get(h.id()).unwrap().fragments.share();
        drop(snapshot);
        {
            let _open = frags.open().unwrap().expect("region");
            assert_ne!(
                is_inaccessible(addr),
                Some(true),
                "region not readable while open"
            );
            #[cfg(target_os = "linux")]
            assert_eq!(crate::test_util::maps_perms(addr).as_deref(), Some("r--p"));
            // A second reader shares the window.
            let second = frags.open().unwrap();
            drop(second);
            assert_ne!(
                is_inaccessible(addr),
                Some(true),
                "inner reader closed the window"
            );
        }
        assert_ne!(
            is_inaccessible(addr),
            Some(false),
            "region readable after the last reader"
        );

        assert_eq!(
            v.with_key(h, <[u8]>::to_vec).unwrap(),
            alloc::vec![0x5a; 48]
        );
        assert_ne!(
            is_inaccessible(addr),
            Some(false),
            "region readable after with_key"
        );
    }

    /// Normalization key and master verifier are protected too.
    #[test]
    fn secrets_are_protected_with_the_keys() {
        let v = KeyVaultBuilder::new()
            .with_page_protection(true)
            .with_keyed_normalization()
            .with_master_key(RawKey::new(b"m".to_vec()))
            .build();
        let Normalizer::Keyed(secret) = &v.inner.normalizer else {
            panic!("keyed normalizer missing");
        };
        let (addr, _) = secret.0.region().expect("protected").mapping();
        assert_ne!(is_inaccessible(addr), Some(false));
        let h = v.register("k", RawKey::new(b"abc".to_vec())).unwrap();
        assert_eq!(v.with_key(h, <[u8]>::len).unwrap(), 32);
        assert_ne!(is_inaccessible(addr), Some(false));
        v.unlock_with_master(b"m").unwrap();
    }

    #[test]
    fn concurrent_readers_of_one_protected_key() {
        let v = protected_vault();
        let h = v.register("k", RawKey::new(alloc::vec![0x42; 64])).unwrap();
        let (addr, _) = region_of(&v, h);
        std::thread::scope(|s| {
            for _ in 0..8 {
                let v = &v;
                let _ = s.spawn(move || {
                    for _ in 0..2_000 {
                        let sum: u32 = v
                            .with_key(h, |k| k.iter().map(|&b| u32::from(b)).sum())
                            .unwrap();
                        assert_eq!(sum, 0x42 * 64);
                    }
                });
            }
        });
        assert_ne!(is_inaccessible(addr), Some(false));
    }

    #[test]
    fn protected_region_is_locked_and_excluded_from_dumps() {
        let v = protected_vault();
        let h = v.register("k", RawKey::new(alloc::vec![1u8; 32])).unwrap();
        let snapshot = v.inner.keys.load();
        let region = snapshot.get(h.id()).unwrap().fragments.region().unwrap();
        #[cfg(target_os = "linux")]
        {
            let (addr, _) = region.mapping();
            assert!(region.is_excluded_from_dumps());
            assert!(crate::test_util::smaps_flags(addr).contains(&"dd".to_owned()));
        }
        #[cfg(windows)]
        assert!(
            region.is_excluded_from_dumps(),
            "WerRegisterExcludedMemoryBlock failed"
        );
        let _ = region.is_locked();
    }

    /// Touching a protected key outside `with_key` crashes the process.
    /// The test re-runs itself in a child process, which reads the region
    /// directly; the parent checks that the child died of an access
    /// violation.
    #[test]
    fn touching_a_protected_key_faults() {
        const CHILD: &str = "KEY_VAULT_TOUCH_PROTECTED";
        if std::env::var_os(CHILD).is_some() {
            let v = protected_vault();
            let h = v.register("k", RawKey::new(alloc::vec![7u8; 32])).unwrap();
            let (addr, _) = region_of(&v, h);
            // SAFETY: deliberately reading a live but inaccessible mapping;
            // the expected outcome is that the OS kills this process.
            let byte = unsafe { core::ptr::read_volatile(addr as *const u8) };
            // Only reached if the read did not fault.
            std::process::exit(if byte == 7 { 3 } else { 4 });
        }
        let exe = std::env::current_exe().unwrap();
        let output = std::process::Command::new(exe)
            .args([
                "vault::page_protection_tests::touching_a_protected_key_faults",
                "--exact",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let status = output.status;
        assert!(
            !status.success(),
            "child read the protected key and exited 0"
        );
        assert_ne!(status.code(), Some(3), "protected key was readable");
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            let signal = status.signal();
            assert!(
                signal == Some(libc::SIGSEGV) || signal == Some(libc::SIGBUS),
                "child did not fault: {status:?}"
            );
        }
        #[cfg(windows)]
        {
            // STATUS_ACCESS_VIOLATION
            assert_eq!(
                status.code().map(|c| u32::from_ne_bytes(c.to_ne_bytes())),
                Some(0xc000_0005),
                "child did not fault: {status:?}"
            );
        }
    }

    #[test]
    fn one_shot_fragments_are_not_protected() {
        let v = protected_vault();
        let frags = v.fragment(&RawKey::new(alloc::vec![3u8; 32])).unwrap();
        assert!(frags.region().is_none());
        assert!(frags.chunk(0).is_some());
        let back = v.defragment(&frags).unwrap();
        assert_eq!(back.expose_secret(), &[3u8; 32]);
    }
}

/// Regression tests for the 1.2 fixes: bounded failure tracking, nested
/// `with_key`, the per-key lockout state, registry write cost, and the
/// read path's shared state.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod regression_tests {
    use super::*;
    use std::time::Instant;

    fn key(b: u8) -> RawKey {
        RawKey::new(alloc::vec![b; 32])
    }

    // ----- Failure tracking -----

    /// With no threshold on (the default), reported failures leave no
    /// trace, however many distinct names are reported. In 1.1 every
    /// name stayed in the tracker forever.
    #[test]
    fn a_million_distinct_names_record_nothing_without_a_threshold() {
        let v = KeyVaultBuilder::new().build();
        assert!(v.inner.tracker.is_none());
        for i in 0..1_000_000u32 {
            v.report_failure(&format!("kid-{i:08x}"), None);
        }
        assert!(v.inner.tracker.is_none());
        assert!(!v.is_locked_out());
    }

    /// With the vault-wide threshold on, a million distinct names keep the
    /// tracker at its capacity, and a registered key's count survives the
    /// flood (its entry is pinned).
    #[test]
    fn a_million_distinct_names_keep_the_tracker_bounded() {
        let v = KeyVaultBuilder::new()
            .with_failure_threshold(3, Duration::from_secs(600))
            .with_failure_tracking_capacity(1024)
            .build();
        let _ = v.register("real", key(1)).unwrap();
        v.report_failure("real", None);
        v.report_failure("real", None);
        for i in 0..1_000_000u32 {
            v.report_failure(&format!("kid-{i:08x}"), None);
        }
        let tracked = v.inner.tracker.as_ref().unwrap().len();
        assert!(tracked <= 1024 + 1, "{tracked} names tracked");
        assert!(!v.is_locked_out(), "one failure per name must not lock out");
        // The registered key's two failures were not evicted.
        v.report_failure("real", None);
        assert!(v.is_locked_out());
    }

    /// Per-key lockout counts only names of registered keys, so unknown
    /// names neither use memory nor create lockout state. In 1.1 each one
    /// added a permanent lockout entry and pushed every `with_key` onto a
    /// locked slow path.
    #[test]
    fn unknown_names_create_no_per_key_state() {
        let v = KeyVaultBuilder::new()
            .with_key_lockout(1, Duration::from_secs(60), None)
            .build();
        let h = v.register("real", key(3)).unwrap();
        for i in 0..100_000u32 {
            v.report_failure(&format!("attacker-{i}"), None);
        }
        assert_eq!(v.inner.tracker.as_ref().unwrap().len(), 0);
        assert!(format!("{v:?}").contains("keys_locked_out: 0"));
        assert!(v.with_key(h, |k| k[0]).is_ok());
    }

    /// Many failures for one name use a bounded number of slots and the
    /// cost per call does not grow with the number of failures. In 1.1
    /// each call walked every failure in the window (quadratic overall).
    #[test]
    fn many_failures_for_one_name_cost_the_same_per_call() {
        let v = KeyVaultBuilder::new()
            .with_failure_threshold(5, Duration::from_secs(3600))
            .build();
        let hash = v.inner.names.hash("same");
        let batch = |n: u32| {
            let t = Instant::now();
            for _ in 0..n {
                v.report_failure("same", None);
            }
            t.elapsed()
        };
        let first = batch(10_000);
        let _ = batch(140_000);
        let last = batch(10_000);
        let slots = v.inner.tracker.as_ref().unwrap().slots_of(hash);
        assert!(slots <= 5, "{slots} slots for one name");
        // Quadratic growth made the last batch about 30 times slower than
        // the first; allow generous noise.
        assert!(
            last < first * 8 + Duration::from_millis(50),
            "first 10k: {first:?}, last 10k: {last:?}"
        );
    }

    // ----- Per-key lockout state -----

    /// The interleaving that bypassed a per-key lockout in 1.1, driven
    /// exactly: thread A's `clear_key_lockout("a")` is paused at the point
    /// where 1.1 had released the map lock but not yet decremented the
    /// locked-key count; there, B's `clear_lockout()` and C's failure for
    /// "b" (which locks "b") run to completion. 1.1 then left "b" locked
    /// in the map with a count of 0, so `with_key(b)` succeeded.
    #[test]
    fn clearing_one_lockout_cannot_hide_another() {
        let v = KeyVaultBuilder::new()
            .with_key_lockout(1, Duration::from_secs(600), None)
            .build();
        let _a = v.register("a", key(4)).unwrap();
        let b = v.register("b", key(5)).unwrap();
        v.report_failure("a", None);

        let (b_vault, c_vault) = (v.clone(), v.clone());
        hooks::set_after_clear_key_lockout(move || {
            // B and C on their own threads, run to completion while A is
            // paused.
            std::thread::spawn(move || b_vault.clear_lockout())
                .join()
                .unwrap();
            std::thread::spawn(move || c_vault.report_failure("b", None))
                .join()
                .unwrap();
        });
        assert!(v.clear_key_lockout("a"));

        assert!(v.is_key_locked_out(b));
        assert!(matches!(v.with_key(b, |_| ()), Err(Error::LockedOut)));
        assert!(format!("{v:?}").contains("keys_locked_out: 1"));
        assert!(v.clear_key_lockout("b"));
        assert!(v.with_key(b, |_| ()).is_ok());
        assert!(format!("{v:?}").contains("keys_locked_out: 0"));
    }

    /// The three calls released together, many times: the lockout state
    /// read by `is_key_locked_out`, `with_key` and `clear_key_lockout`
    /// always agrees.
    #[test]
    fn concurrent_clears_and_lockouts_agree() {
        let v = KeyVaultBuilder::new()
            .with_key_lockout(1, Duration::from_secs(600), None)
            .build();
        let _ = v.register("a", key(4)).unwrap();
        let hb = v.register("b", key(5)).unwrap();
        let rounds = 2000;
        let start = Arc::new(std::sync::Barrier::new(3));
        let go = Arc::new(std::sync::Barrier::new(4));
        let done = Arc::new(std::sync::Barrier::new(4));
        let threads: Vec<_> = (0..3)
            .map(|role| {
                let (v, start, go, done) = (v.clone(), start.clone(), go.clone(), done.clone());
                std::thread::spawn(move || {
                    for _ in 0..rounds {
                        let _ = go.wait();
                        let _ = start.wait();
                        match role {
                            0 => {
                                let _ = v.clear_key_lockout("a");
                            }
                            1 => v.clear_lockout(),
                            _ => v.report_failure("b", None),
                        }
                        let _ = done.wait();
                    }
                })
            })
            .collect();
        for round in 0..rounds {
            v.clear_lockout();
            v.report_failure("a", None);
            let _ = go.wait();
            let _ = done.wait();
            let says_locked = v.is_key_locked_out(hb);
            let readable = v.with_key(hb, |_| ()).is_ok();
            let was_locked = v.clear_key_lockout("b");
            assert_eq!(says_locked, !readable, "round {round}");
            assert_eq!(says_locked, was_locked, "round {round}");
            assert!(!format!("{v:?}").contains(&usize::MAX.to_string()));
        }
        for t in threads {
            t.join().unwrap();
        }
    }

    /// Unregistering a key drops its lockout and failure history; a key
    /// registered later under the same name starts clean.
    #[test]
    fn unregister_forgets_lockout_and_failures() {
        let v = KeyVaultBuilder::new()
            .with_key_lockout(2, Duration::from_secs(600), None)
            .build();
        let h = v.register("k", key(1)).unwrap();
        v.report_failure("k", None);
        v.report_failure("k", None);
        assert!(v.is_key_locked_out(h));
        v.unregister(h).unwrap();
        assert_eq!(v.inner.tracker.as_ref().unwrap().len(), 0);
        let h = v.register("k", key(1)).unwrap();
        assert!(!v.is_key_locked_out(h));
        v.report_failure("k", None);
        assert!(!v.is_key_locked_out(h), "old failures still counted");
    }

    /// Rotation keeps the key's lockout.
    #[test]
    fn rotate_keeps_the_lockout() {
        let v = KeyVaultBuilder::new()
            .with_key_lockout(1, Duration::from_secs(600), None)
            .build();
        let h = v.register("k", key(1)).unwrap();
        v.rotate(h, key(2)).unwrap();
        v.report_failure("k", None);
        assert!(v.is_key_locked_out(h));
        assert!(matches!(v.rotate(h, key(3)), Err(Error::LockedOut)));
        assert!(v.clear_key_lockout("k"));
        v.rotate(h, key(3)).unwrap();
        assert!(!v.is_key_locked_out(h));
    }

    /// Dynamic notes reach the monitor.
    #[test]
    fn report_failure_with_note_forwards_the_note() {
        #[derive(Default)]
        struct Notes(std::sync::Mutex<Vec<String>>);
        impl SecurityMonitor for Notes {
            fn on_decryption_failure(&self, ctx: &FailureContext) {
                self.0.lock().unwrap().push(ctx.note.to_string());
            }
            fn on_anomalous_access(&self, _: &AccessContext) {}
            fn on_threshold_breach(&self, _: &ThresholdContext) {}
        }
        let notes = Arc::new(Notes::default());
        let v = KeyVaultBuilder::new()
            .with_monitor(Arc::clone(&notes) as Arc<dyn SecurityMonitor>)
            .build();
        v.report_failure_with_note("k", format!("tag error {}", 7));
        v.report_failure("k", Some("static"));
        assert_eq!(
            *notes.0.lock().unwrap(),
            alloc::vec!["tag error 7".to_string(), "static".to_string()]
        );
    }

    // ----- Nested with_key -----

    /// A `with_key` inside another `with_key` callback works, on the same
    /// vault and on another one, three levels deep. In 1.1 it panicked
    /// with "`RefCell` already borrowed".
    #[test]
    fn nested_with_key_works() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let other = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let a = v.register("a", key(1)).unwrap();
        let b = v.register("b", RawKey::new(alloc::vec![2u8; 48])).unwrap();
        let c = other
            .register("c", RawKey::new(alloc::vec![3u8; 8]))
            .unwrap();
        let sum = v
            .with_key(a, |ka| {
                v.with_key(b, |kb| {
                    other
                        .with_key(c, |kc| {
                            assert!(ka.iter().all(|&x| x == 1));
                            assert!(kb.iter().all(|&x| x == 2));
                            assert!(kc.iter().all(|&x| x == 3));
                            ka.len() + kb.len() + kc.len()
                        })
                        .unwrap()
                })
                .unwrap()
            })
            .unwrap();
        assert_eq!(sum, 32 + 48 + 8);
        // The thread's scratch was wiped, and is usable again.
        SCRATCH.with(|cell| assert!(cell.borrow().buf.iter().all(|&x| x == 0)));
        assert_eq!(v.with_key(b, <[u8]>::len).unwrap(), 48);
    }

    /// Strict locking applies to the per-call buffer of a nested read too.
    #[test]
    fn nested_with_key_under_strict_locking() {
        let v = KeyVaultBuilder::new().with_strict_locking(true).build();
        let Ok(a) = v.register("a", key(1)) else {
            return; // no lock budget on this machine
        };
        let Ok(b) = v.register("b", key(2)) else {
            return;
        };
        let r = v.with_key(a, |_| v.with_key(b, <[u8]>::len)).unwrap();
        assert!(matches!(r, Ok(32) | Err(Error::MemoryLock(_))));
    }

    // ----- Registry writes -----

    /// Writes cost the same with 200,000 keys registered as with none. In
    /// 1.1 every write copied the whole map (milliseconds per write at
    /// this size); the trie copies one path.
    #[test]
    fn writes_do_not_copy_the_registry() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let t = Instant::now();
        let handles: Vec<_> = (0..200)
            .map(|i| v.register(format!("small-{i}"), key(1)).unwrap())
            .collect();
        for &h in &handles {
            v.rotate(h, key(2)).unwrap();
        }
        let small = t.elapsed();

        pad_registry(&v, 200_000);
        let t = Instant::now();
        let handles: Vec<_> = (0..200)
            .map(|i| v.register(format!("large-{i}"), key(1)).unwrap())
            .collect();
        for &h in &handles {
            v.rotate(h, key(2)).unwrap();
        }
        for &h in &handles {
            v.unregister(h).unwrap();
        }
        let large = t.elapsed();
        assert_eq!(v.key_count(), 200_200);
        assert!(v.handle_for_name("filler-199999").is_some());
        assert!(v.handle_for_name("large-0").is_none());
        assert!(
            large < small * 20 + Duration::from_millis(500),
            "200 writes: {small:?} on a small registry, {large:?} with 200k keys"
        );
    }

    /// Duplicate names are found by hash, including after removals.
    #[test]
    fn duplicate_names_are_rejected_by_lookup() {
        let v = KeyVaultBuilder::new().build();
        let h = v.register("x", key(1)).unwrap();
        assert!(matches!(
            v.register("x", key(2)),
            Err(Error::InvalidConfig(_))
        ));
        v.unregister(h).unwrap();
        let h2 = v.register("x", key(3)).unwrap();
        assert_eq!(v.handle_for_name("x"), Some(h2));
    }

    /// Add `n` filler entries straight into the registry.
    fn pad_registry(v: &KeyVault, n: usize) {
        let mut map = (*v.inner.keys.load_full()).clone();
        let shared = v
            .inner
            .fragmenter
            .fragment(&RawKey::new(alloc::vec![9u8; 8]))
            .unwrap();
        for i in 0..n {
            let id = KeyHandle::allocate().id();
            let name = format!("filler-{i}");
            let name_hash = v.inner.names.hash(&name);
            map.by_name = map.by_name.insert(name_hash, name.clone(), id).0;
            let entry = Arc::new(KeyEntry {
                name,
                name_hash,
                fragments: shared.share(),
                metadata: KeyMetadata::new(Duration::ZERO, 8, None),
                lock: Arc::new(KeyLock::new()),
            });
            map.by_id = map.by_id.insert(id_hash(id), id, entry).0;
        }
        v.inner.keys.store(Arc::new(map));
    }

    // ----- Read path -----

    /// `with_key` takes no reference on the key's storage or entry: the
    /// callback runs with the counts the registry alone holds. In 1.1 each
    /// read cloned the storage `Arc`, so every thread reading one key
    /// wrote to the same counter.
    #[test]
    fn with_key_takes_no_reference_on_the_key() {
        let v = KeyVaultBuilder::new().build();
        let h = v.register("k", key(1)).unwrap();
        let counts = || {
            let snapshot = v.inner.keys.load();
            let entry = snapshot.get(h.id()).unwrap();
            (Arc::strong_count(entry), entry.fragments.store_refs())
        };
        let outside = counts();
        let inside = v.with_key(h, |_| counts()).unwrap();
        assert_eq!(outside, (1, 1));
        assert_eq!(inside, outside);
    }

    /// A key unregistered while a reader is inside its callback stays
    /// intact for that reader: the callback works on the copy.
    #[test]
    fn unregister_during_a_read_is_safe() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let h = v.register("k", key(7)).unwrap();
        let seen = v
            .with_key(h, |k| {
                v.unregister(h).unwrap();
                k.to_vec()
            })
            .unwrap();
        assert_eq!(seen, alloc::vec![7u8; 32]);
        assert!(!v.contains(h));
    }

    // ----- Memory status -----

    #[test]
    fn memory_status_counts_every_key() {
        let v = KeyVaultBuilder::new().build();
        assert_eq!(v.memory_status(), MemoryStatus::default());
        let hs: Vec<_> = (0..10)
            .map(|i| v.register(format!("k{i}"), key(1)).unwrap())
            .collect();
        let status = v.memory_status();
        assert_eq!(status.keys, 10);
        assert_eq!(status.locked + status.unlocked(), 10);
        for h in hs {
            let locked = v.is_memory_locked(h).unwrap();
            if status.all_locked() {
                assert!(locked);
            }
        }
        assert_eq!(v.is_memory_locked(KeyHandle::allocate()), None);
        #[cfg(target_os = "linux")]
        assert_eq!(status.excluded_from_dumps, 10);
    }

    #[test]
    fn new_and_default_match_the_builder() {
        let a = KeyVault::new();
        let b = KeyVault::default();
        let c = KeyVault::builder().build();
        for v in [&a, &b, &c] {
            assert!(v.config().key_normalization);
            assert!(!v.config().strict_locking);
            assert_eq!(v.config().failure_tracking_capacity, 4096);
        }
    }
}
