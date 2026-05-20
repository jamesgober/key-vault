//! [`CompositeMonitor`] — fan-out across several `SecurityMonitor` impls.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use super::{AccessContext, FailureContext, SecurityMonitor, ThresholdContext};

/// `SecurityMonitor` that fans every event out to a list of inner
/// monitors.
///
/// Useful when you want, for example, a `LogMonitor` for human-readable
/// alerts and a custom `MetricsMonitor` for dashboards from the same
/// vault. Inner monitors are called in registration order; one failing
/// monitor does not affect the others (monitor implementations should
/// not panic per the trait contract).
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use key_vault::{CompositeMonitor, NoMonitor, SecurityMonitor};
///
/// let composite = CompositeMonitor::new(vec![
///     Arc::new(NoMonitor) as Arc<dyn SecurityMonitor>,
///     Arc::new(NoMonitor) as Arc<dyn SecurityMonitor>,
/// ]);
/// assert_eq!(composite.len(), 2);
/// ```
#[derive(Clone)]
pub struct CompositeMonitor {
    inner: Vec<Arc<dyn SecurityMonitor>>,
}

impl CompositeMonitor {
    /// Construct a composite over the supplied inner monitors. An empty
    /// list is permitted and yields a no-op monitor (effectively the same
    /// as [`NoMonitor`](super::NoMonitor)).
    #[must_use]
    pub fn new(inner: Vec<Arc<dyn SecurityMonitor>>) -> Self {
        Self { inner }
    }

    /// Number of inner monitors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` if no inner monitors are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for CompositeMonitor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompositeMonitor")
            .field("inner_count", &self.inner.len())
            .finish()
    }
}

impl SecurityMonitor for CompositeMonitor {
    fn on_decryption_failure(&self, ctx: &FailureContext) {
        for m in &self.inner {
            m.on_decryption_failure(ctx);
        }
    }

    fn on_anomalous_access(&self, ctx: &AccessContext) {
        for m in &self.inner {
            m.on_anomalous_access(ctx);
        }
    }

    fn on_threshold_breach(&self, ctx: &ThresholdContext) {
        for m in &self.inner {
            m.on_threshold_breach(ctx);
        }
    }
}
