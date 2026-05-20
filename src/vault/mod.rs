//! The vault itself.
//!
//! In this phase [`KeyVault`] is a skeleton: it holds a configuration and
//! exposes the builder API, but it does not yet store keys — fragmentation,
//! mlock, and zeroize land in Phase 0.3. The shape of the public API is
//! finalized here so that downstream crates can begin compiling against it.
//!
//! ```
//! use key_vault::{KeyVault, KeyVaultBuilder};
//!
//! // The builder follows the standard fluent pattern. None of the methods
//! // perform I/O — construction is cheap and infallible.
//! let _vault: KeyVault = KeyVaultBuilder::new().build();
//! ```

use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

/// Vault configuration.
///
/// Concrete fields are added in later phases as each layer comes online —
/// fragment strategy in 0.3/0.5, decoy in 0.4, codex in 0.6, monitor in 0.8.
/// Today this struct exists so that `KeyVaultBuilder::build` has somewhere to
/// store its decisions.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct VaultConfig {
    /// If `true`, raw key material is BLAKE3-normalized to 32 bytes before
    /// fragmentation. Default is `true`.
    pub key_normalization: bool,
}

impl VaultConfig {
    /// Default-on configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            key_normalization: true,
        }
    }
}

/// In-memory key vault.
///
/// The vault is the entry point for everything `key-vault` does. Application
/// code constructs one via [`KeyVaultBuilder`], registers keys against it, and
/// receives [`KeyHandle`](crate::KeyHandle)s in return. The vault itself is
/// cheap to clone (it is `Arc`-backed internally) and safe to share across
/// threads.
///
/// Key registration, access, rotation, and recovery are introduced in later
/// phases. This skeleton exposes only the public shape — construction,
/// cloning, and the lock-out indicator — so that downstream crates can wire
/// against it now.
#[derive(Clone)]
pub struct KeyVault {
    inner: Arc<VaultInner>,
}

struct VaultInner {
    config: VaultConfig,
    /// Set to `true` when a [`SecurityMonitor`](crate::SecurityMonitor)
    /// threshold breach has put the vault into lock-out state. Lock-out is
    /// not yet driven by the monitor — that arrives in Phase 0.8.
    locked_out: AtomicBool,
}

impl KeyVault {
    /// Returns `true` if the vault is in lock-out state.
    ///
    /// Lock-out is the [`SecurityMonitor`](crate::SecurityMonitor)'s response
    /// to repeated failures: once the threshold is crossed, access to every
    /// key in the vault is denied until the configured recovery condition is
    /// met. In Phase 0.2 the lock-out flag exists but is never set; Phase 0.8
    /// connects it to monitor events.
    #[must_use]
    pub fn is_locked_out(&self) -> bool {
        self.inner.locked_out.load(Ordering::Acquire)
    }

    /// Snapshot of the vault's configuration.
    #[must_use]
    pub fn config(&self) -> &VaultConfig {
        &self.inner.config
    }
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
#[derive(Debug, Default, Clone)]
pub struct KeyVaultBuilder {
    config: VaultConfig,
}

impl KeyVaultBuilder {
    /// Start a new builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: VaultConfig::new(),
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

    /// Finalize and produce a [`KeyVault`].
    ///
    /// Infallible in this phase — later phases may move this to a
    /// `Result`-returning shape if validation is added.
    #[must_use]
    pub fn build(self) -> KeyVault {
        KeyVault {
            inner: Arc::new(VaultInner {
                config: self.config,
                locked_out: AtomicBool::new(false),
            }),
        }
    }
}

#[cfg(test)]
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
}
