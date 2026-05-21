//! [`NoAudit`] — the inert default audit sink.

use super::{AuditEvent, AuditSink};

/// `AuditSink` implementation that discards every event.
///
/// This is the vault's default; constructing a `KeyVault` without
/// calling [`KeyVaultBuilder::with_audit_sink`](crate::KeyVaultBuilder::with_audit_sink)
/// leaves the audit trail unrouted. Events are still constructed by the
/// vault and passed through this sink — the cost is one struct
/// construction + one virtual call per operation, both negligible.
///
/// Use this explicitly when you want to make "no audit configured" a
/// load-bearing part of your vault setup.
///
/// # Examples
///
/// ```
/// use key_vault::{KeyVaultBuilder, NoAudit};
///
/// let _vault = KeyVaultBuilder::new()
///     .with_audit_sink(NoAudit)
///     .build();
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct NoAudit;

impl AuditSink for NoAudit {
    #[inline]
    fn on_event(&self, _event: &AuditEvent) {}
}
