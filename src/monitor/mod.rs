//! Layer 8: security monitor.
//!
//! A [`SecurityMonitor`] is the vault's outbound channel for failure and
//! anomaly events: failures and anomalies that the **caller reports**
//! through [`KeyVault::report_failure`](crate::KeyVault::report_failure)
//! and [`KeyVault::report_anomalous_access`](crate::KeyVault::report_anomalous_access),
//! wrong master credentials, and threshold breaches. The vault does not
//! detect decryption failures or unusual access on its own; it never sees
//! what the caller does with a key.
//!
//! The lockouts that go with this layer are advisory: the vault-wide
//! threshold ([`KeyVault::is_locked_out`](crate::KeyVault::is_locked_out))
//! and, since 1.1, the per-key threshold
//! ([`KeyVault::is_key_locked_out`](crate::KeyVault::is_key_locked_out)).
//! They count only the failures reported to the vault and do nothing
//! against an attacker who can read process memory.
//!
//! Built-in monitors: [`NoMonitor`] (default), [`CompositeMonitor`], and
//! `LogMonitor` (behind the `monitor-tracing` feature).

use alloc::borrow::Cow;
use alloc::string::String;
use core::time::Duration;

mod composite;
#[cfg(feature = "monitor-tracing")]
mod log_monitor;
mod no_monitor;

pub use self::composite::CompositeMonitor;
#[cfg(feature = "monitor-tracing")]
pub use self::log_monitor::LogMonitor;
pub use self::no_monitor::NoMonitor;

/// Context passed when a decryption attempt fails — wrong key, tampered
/// ciphertext, etc.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct FailureContext {
    /// Logical name of the key whose use produced the failure.
    pub key_name: String,
    /// Failures recorded for this key name inside the window, including
    /// this one.
    ///
    /// Failures are counted only while a lockout threshold is on
    /// ([`KeyVaultBuilder::with_failure_threshold`](crate::KeyVaultBuilder::with_failure_threshold)
    /// or [`KeyVaultBuilder::with_key_lockout`](crate::KeyVaultBuilder::with_key_lockout)).
    /// With both off (the default) the vault keeps no failure history and
    /// this is always `1` (since 1.2; earlier versions kept an unbounded
    /// history). The count is exact up to 64 failures in the window; past
    /// that, failures that arrive close together can be counted as
    /// slightly newer than they are, so near the edge of the window the
    /// count can run high, never low.
    pub consecutive_failures: u32,
    /// Time elapsed since the first failure in the current window.
    /// `Duration::ZERO` when no threshold is on.
    pub window_elapsed: Duration,
    /// Caller-supplied free-form note. Sanitized — never includes key bytes
    /// or ciphertext.
    pub note: Cow<'static, str>,
}

/// Context for a successful access that the monitor flagged as anomalous —
/// unusual caller, unusual frequency, off-hours activity.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct AccessContext {
    /// Logical name of the key that was accessed.
    pub key_name: String,
    /// Caller-supplied free-form note. Sanitized.
    pub note: Cow<'static, str>,
}

/// Which lockout a [`ThresholdContext`] is about.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockoutScope {
    /// The vault-wide threshold
    /// ([`KeyVaultBuilder::with_failure_threshold`](crate::KeyVaultBuilder::with_failure_threshold)):
    /// every key is locked out.
    Vault,
    /// The per-key threshold
    /// ([`KeyVaultBuilder::with_key_lockout`](crate::KeyVaultBuilder::with_key_lockout)):
    /// only the key registered under `key_name` is locked out.
    Key,
}

/// Context for a configured threshold being crossed (e.g. N failures in M
/// seconds).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ThresholdContext {
    /// Logical name of the key.
    pub key_name: String,
    /// Number of failures observed within the configured window.
    pub failures_in_window: u32,
    /// Width of the configured window.
    pub window: Duration,
    /// `true` if this breach started the lockout (it was not already in
    /// place).
    pub lockout_triggered: bool,
    /// Whether the vault-wide or the per-key threshold was crossed.
    pub scope: LockoutScope,
}

/// Context for a key stored in memory that could not be page-locked.
///
/// Fired by [`SecurityMonitor::on_memory_lock_failure`] when
/// [`KeyVault::register`](crate::KeyVault::register) or
/// [`KeyVault::rotate`](crate::KeyVault::rotate) could not lock every page
/// the key occupies, once per run of such failures: after a key is stored
/// locked again, the next failure fires again.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct MemoryLockContext {
    /// Logical name of the key.
    pub key_name: String,
    /// `true` if the vault refused the key because strict locking is on
    /// ([`KeyVaultBuilder::with_strict_locking`](crate::KeyVaultBuilder::with_strict_locking));
    /// `false` if it stored the key in unlocked memory.
    pub refused: bool,
}

/// Outbound channel for anomaly events.
///
/// Implementations should treat monitor calls as advisory and fire-and-forget:
/// the vault must not block on a monitor, must not crash if a monitor panics
/// or returns an error, and must not retry. Implementations that need
/// retry, queuing, or batching are expected to handle that internally
/// (typically on a background thread).
///
/// # Implementor contract
///
/// - **Non-blocking.** Calls must return promptly. Network or disk work should
///   be deferred to a background worker.
/// - **No panics.** A panicking monitor implementation is a bug in the
///   implementation, not the vault. Wrap fallible operations and absorb
///   their errors.
/// - **No key material in calls.** None of the context structs carry raw key
///   bytes; do not introduce custom side-channels that do.
/// - **`Send + Sync`.** Monitors are shared across threads.
pub trait SecurityMonitor: Send + Sync {
    /// Called when a decryption attempt fails.
    fn on_decryption_failure(&self, ctx: &FailureContext);

    /// Called when an access pattern looks anomalous to the configured
    /// detector.
    fn on_anomalous_access(&self, ctx: &AccessContext);

    /// Called when a configured failure threshold is crossed.
    fn on_threshold_breach(&self, ctx: &ThresholdContext);

    /// Called when a key could not be stored in page-locked memory (the
    /// process reached its lock limit), so the OS may write it to swap.
    /// See [`MemoryLockContext`] for when it fires and
    /// [`KeyVault::memory_status`](crate::KeyVault::memory_status) for the
    /// current state of every key.
    ///
    /// The default implementation does nothing. Since 1.2.
    fn on_memory_lock_failure(&self, ctx: &MemoryLockContext) {
        let _ = ctx;
    }
}

// Blanket forwarding impl so callers can pass a pre-wrapped
// `Arc<dyn SecurityMonitor>` to APIs that accept `impl SecurityMonitor`.
// Useful when the same monitor is referenced from multiple places and
// the caller already holds it as a trait object.
impl SecurityMonitor for alloc::sync::Arc<dyn SecurityMonitor> {
    fn on_decryption_failure(&self, ctx: &FailureContext) {
        (**self).on_decryption_failure(ctx);
    }
    fn on_anomalous_access(&self, ctx: &AccessContext) {
        (**self).on_anomalous_access(ctx);
    }
    fn on_threshold_breach(&self, ctx: &ThresholdContext) {
        (**self).on_threshold_breach(ctx);
    }
    fn on_memory_lock_failure(&self, ctx: &MemoryLockContext) {
        (**self).on_memory_lock_failure(ctx);
    }
}
