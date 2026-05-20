//! [`NoMonitor`] — the inert default.

use super::{AccessContext, FailureContext, SecurityMonitor, ThresholdContext};

/// `SecurityMonitor` implementation that discards every event.
///
/// Use this when you want to construct a vault without configuring any
/// observability surface — anomaly events go nowhere, but the vault's
/// own threshold detection (see
/// [`KeyVaultBuilder::with_failure_threshold`](crate::KeyVaultBuilder::with_failure_threshold))
/// still works and can still lock the vault out.
///
/// `NoMonitor` is the default when no monitor is configured. Calling
/// [`with_monitor(NoMonitor)`](crate::KeyVaultBuilder::with_monitor)
/// explicitly is equivalent to leaving the slot empty; the difference is
/// stylistic.
///
/// # Examples
///
/// ```
/// use key_vault::{KeyVaultBuilder, NoMonitor};
///
/// let _vault = KeyVaultBuilder::new()
///     .with_monitor(NoMonitor)
///     .build();
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct NoMonitor;

impl SecurityMonitor for NoMonitor {
    #[inline]
    fn on_decryption_failure(&self, _ctx: &FailureContext) {}

    #[inline]
    fn on_anomalous_access(&self, _ctx: &AccessContext) {}

    #[inline]
    fn on_threshold_breach(&self, _ctx: &ThresholdContext) {}
}
