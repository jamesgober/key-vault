//! [`LogMonitor`] — `tracing`-backed `SecurityMonitor`.
//!
//! Gated behind the `monitor-tracing` Cargo feature. The monitor emits
//! `tracing` events at three levels:
//!
//! - `on_decryption_failure` → `warn!` with structured fields
//! - `on_anomalous_access` → `warn!`
//! - `on_threshold_breach` → `error!`
//!
//! All fields are sanitized: only `key_name`, counters, and the
//! caller-supplied note are emitted. Nothing the monitor receives is
//! itself a secret (the `SecurityMonitor` trait contract forbids passing
//! key material in context structs), so the log lines are safe to ship
//! to any centralized log aggregator.

use super::{AccessContext, FailureContext, SecurityMonitor, ThresholdContext};

/// `SecurityMonitor` implementation that emits `tracing` events.
///
/// Construct with [`LogMonitor::new`]; the type holds no state and is
/// `Copy`. Each event becomes a `tracing` log entry with structured
/// fields suitable for filtering in `tracing-subscriber`.
///
/// # Examples
///
/// ```
/// use key_vault::{KeyVaultBuilder, LogMonitor};
///
/// let _vault = KeyVaultBuilder::new()
///     .with_monitor(LogMonitor::new())
///     .build();
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct LogMonitor;

impl LogMonitor {
    /// Construct a new log monitor. Stateless; consider sharing one
    /// instance across all vaults.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SecurityMonitor for LogMonitor {
    fn on_decryption_failure(&self, ctx: &FailureContext) {
        // Saturating cast: u128→u64. Durations exceeding 2^64 ms (~585
        // million years) would lose precision; we cap rather than fail
        // because losing a few high bits in a log timestamp is fine.
        let elapsed_ms = u64::try_from(ctx.window_elapsed.as_millis()).unwrap_or(u64::MAX);
        tracing::warn!(
            target: "key_vault::monitor",
            key_name = %ctx.key_name,
            consecutive_failures = ctx.consecutive_failures,
            window_elapsed_ms = elapsed_ms,
            note = %ctx.note,
            "key access failure",
        );
    }

    fn on_anomalous_access(&self, ctx: &AccessContext) {
        tracing::warn!(
            target: "key_vault::monitor",
            key_name = %ctx.key_name,
            note = %ctx.note,
            "anomalous key access",
        );
    }

    fn on_threshold_breach(&self, ctx: &ThresholdContext) {
        let window_ms = u64::try_from(ctx.window.as_millis()).unwrap_or(u64::MAX);
        tracing::error!(
            target: "key_vault::monitor",
            key_name = %ctx.key_name,
            failures_in_window = ctx.failures_in_window,
            window_ms = window_ms,
            lockout_triggered = ctx.lockout_triggered,
            "threshold breach",
        );
    }
}
