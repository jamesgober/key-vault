//! Layer 8 — Security monitor.
//!
//! A [`SecurityMonitor`] is the vault's outbound channel for anomaly events:
//! repeated decryption failures, unusual access patterns, and threshold
//! breaches. Monitor calls happen on the failure path only; the success path
//! costs nothing.
//!
//! Built-in monitors (`NoMonitor`, `LogMonitor`, `MetricsMonitor`,
//! `WebhookMonitor`, `CompositeMonitor`) arrive in Phase 0.8. This module
//! currently defines the trait surface and the three event-context structs.

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
    /// Number of consecutive failures observed for this key, including this
    /// one.
    pub consecutive_failures: u32,
    /// Time elapsed since the first failure in the current window.
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
    /// `true` if this breach has put the vault into lock-out state.
    pub lockout_triggered: bool,
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
}
