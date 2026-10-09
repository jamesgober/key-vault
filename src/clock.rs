//! Time source for lockout, backoff and timestamps.
//!
//! The vault reads time through the [`Clock`] trait: the failure window,
//! per-key lockout expiry and master-unlock backoff use
//! [`Clock::now`], and key metadata and audit events use
//! [`Clock::unix_time`].
//!
//! With the `std` feature, `KeyVaultBuilder::build` uses `StdClock`.
//! Without `std` there is no clock to fall back on, so
//! `build` does not exist and the vault is built with
//! [`KeyVaultBuilder::build_with_clock`](crate::KeyVaultBuilder::build_with_clock):
//! forgetting the clock is a compile error, not a vault whose lockout
//! silently never expires.

use core::time::Duration;

/// A source of time for the vault.
///
/// # Implementor contract
///
/// - [`now`](Clock::now) is **monotonic**: it never goes backwards. It
///   counts from any fixed point (boot, first call). Lockout windows and
///   backoff delays are measured with it, so a clock that stands still
///   makes lockouts never expire and failures never age out.
/// - [`unix_time`](Clock::unix_time) is wall-clock time since the Unix
///   epoch, used only for [`KeyMetadata`](crate::KeyMetadata) and
///   [`AuditEvent`](crate::AuditEvent) timestamps. The default returns
///   `Duration::ZERO`; override it if your target has a real-time clock.
/// - `Send + Sync`: the vault calls the clock from any thread.
///
/// # Examples
///
/// A bare-metal clock backed by a free-running microsecond counter:
///
/// ```
/// use core::sync::atomic::{AtomicU64, Ordering};
/// use core::time::Duration;
/// use key_vault::Clock;
///
/// static TICKS_US: AtomicU64 = AtomicU64::new(0); // advanced by a timer interrupt
///
/// struct BoardClock;
///
/// impl Clock for BoardClock {
///     fn now(&self) -> Duration {
///         Duration::from_micros(TICKS_US.load(Ordering::Relaxed))
///     }
/// }
///
/// assert_eq!(BoardClock.unix_time(), Duration::ZERO);
/// ```
pub trait Clock: Send + Sync {
    /// Monotonic time since an arbitrary fixed point.
    fn now(&self) -> Duration;

    /// Wall-clock time since the Unix epoch. Default: `Duration::ZERO`.
    fn unix_time(&self) -> Duration {
        Duration::ZERO
    }
}

/// The standard-library clock: `Instant` for [`Clock::now`] and
/// `SystemTime` for [`Clock::unix_time`].
///
/// This is what [`KeyVaultBuilder::build`](crate::KeyVaultBuilder::build)
/// uses.
#[cfg(feature = "std")]
#[derive(Debug, Default, Clone, Copy)]
pub struct StdClock;

#[cfg(feature = "std")]
impl Clock for StdClock {
    fn now(&self) -> Duration {
        static BASE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        BASE.get_or_init(std::time::Instant::now).elapsed()
    }

    fn unix_time(&self) -> Duration {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn std_clock_is_monotonic_and_has_wall_time() {
        let a = StdClock.now();
        let b = StdClock.now();
        assert!(b >= a);
        assert!(StdClock.unix_time() > Duration::from_secs(1_600_000_000));
    }
}
