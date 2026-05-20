//! [`DynamicCodex`] — per-vault randomized involution.
//!
//! `DynamicCodex` is functionally a [`StaticCodex`] whose lookup table is
//! generated at construction by [`StaticCodex::random_involution`]. The
//! difference is intent: a `StaticCodex` is meant to be built from a
//! known set of swaps or otherwise reproducibly, while a `DynamicCodex`
//! is always fresh-random.
//!
//! Use `DynamicCodex::new()` once per vault. Sharing one across vaults
//! defeats the point.

use super::{Codex, StaticCodex};
use crate::Result;

/// Per-vault randomized involution codex.
///
/// Construct with [`DynamicCodex::new`]; each call produces an
/// independent random involution.
pub struct DynamicCodex {
    inner: StaticCodex,
}

impl core::fmt::Debug for DynamicCodex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The table is sensitive; same redaction as `StaticCodex`.
        f.debug_struct("DynamicCodex")
            .field("table", &"<redacted>")
            .finish()
    }
}

impl DynamicCodex {
    /// Construct a new dynamic codex with a fresh random involution.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Internal`](crate::Error::Internal) if the OS
    /// CSPRNG fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use key_vault::{Codex, DynamicCodex};
    ///
    /// let codex = DynamicCodex::new().unwrap();
    /// for byte in 0u8..=255 {
    ///     assert_eq!(codex.decode(codex.encode(byte)), byte);
    /// }
    /// ```
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: StaticCodex::random_involution()?,
        })
    }
}

impl Codex for DynamicCodex {
    #[inline]
    fn encode(&self, byte: u8) -> u8 {
        self.inner.encode(byte)
    }

    #[inline]
    fn decode(&self, byte: u8) -> u8 {
        self.inner.decode(byte)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
mod tests {
    use super::*;

    #[test]
    fn involution_holds_for_every_byte() {
        let codex = DynamicCodex::new().unwrap();
        for byte in 0u8..=255 {
            assert_eq!(codex.decode(codex.encode(byte)), byte);
        }
    }

    #[test]
    fn no_fixed_points() {
        let codex = DynamicCodex::new().unwrap();
        for byte in 0u8..=255 {
            assert_ne!(codex.encode(byte), byte);
        }
    }

    #[test]
    fn two_instances_have_different_tables() {
        let a = DynamicCodex::new().unwrap();
        let b = DynamicCodex::new().unwrap();
        // Compare via encoding behavior — at least one byte must differ.
        let any_diff = (0u8..=255).any(|b_in| a.encode(b_in) != b.encode(b_in));
        assert!(
            any_diff,
            "two random codices encoded identically — broken RNG?"
        );
    }
}
