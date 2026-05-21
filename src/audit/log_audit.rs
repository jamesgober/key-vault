//! [`LogAudit`] — `tracing`-backed audit sink.
//!
//! Gated behind the `monitor-tracing` Cargo feature (which brings the
//! `tracing` dependency that both [`crate::LogMonitor`] and `LogAudit`
//! depend on). Emits structured events at `info!` level on the
//! `key_vault::audit` target.

use super::{AuditEvent, AuditSink};

/// `AuditSink` implementation that emits structured `tracing` events.
///
/// Construct with [`LogAudit::new`]; stateless and cheap to clone.
/// Each emitted event becomes a `tracing` log entry at `info!` level
/// with structured fields suitable for filtering in
/// `tracing-subscriber`.
///
/// # Examples
///
/// ```
/// use key_vault::{KeyVaultBuilder, LogAudit};
///
/// let _vault = KeyVaultBuilder::new()
///     .with_audit_sink(LogAudit::new())
///     .build();
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct LogAudit;

impl LogAudit {
    /// Construct a new log audit sink. Stateless; consider sharing one
    /// instance across all vaults.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl AuditSink for LogAudit {
    fn on_event(&self, event: &AuditEvent) {
        let ts_ms = u64::try_from(event.timestamp.as_millis()).unwrap_or(u64::MAX);
        tracing::info!(
            target: "key_vault::audit",
            key_name = %event.key_name,
            kind = %event.kind,
            thread_id = ?event.thread_id,
            timestamp_ms_since_epoch = ts_ms,
            note = %event.note,
            "audit event",
        );
    }
}
