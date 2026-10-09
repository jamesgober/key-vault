//! Layer 5: codex transformation.
//!
//! A [`Codex`] applies a byte-wise substitution to the (normalized) key
//! before it is fragmented. The built-in codices are involutions: applying
//! the transformation twice returns the original byte. Decoy chunks are
//! generated from the already-encoded key and are not passed through the
//! codex separately.
//!
//! # What it is and is not
//!
//! The codex is **obfuscation, not encryption**. A substitution table is
//! not a cipher, and the table itself ([`StaticCodex`], [`DynamicCodex`]) is
//! stored in the same process memory as the fragments it encodes. Anyone
//! who can read process memory can read the table and undo the codex. It
//! only means that a scan for the raw key bytes, or a tool that reassembles
//! fragments without knowing about the codex, finds transformed bytes.
//!
//! # When to use
//!
//! The vault uses no codex unless one is passed to
//! [`KeyVaultBuilder::with_codex`](crate::KeyVaultBuilder::with_codex).
//! The `codex` and `codex-dynamic` Cargo features are reserved and have no
//! effect in 1.0.x; the codex types are always compiled. A table codex adds
//! a few nanoseconds per byte to the access path.
//!
//! # Involution requirement
//!
//! All implementations must satisfy `decode(encode(x)) == x` for every byte.
//! This is verified by tests for the built-in codices and, beginning in Phase
//! 0.6, by proptest sweeps over the full byte range.

use core::marker::PhantomData;

mod dynamic;
mod identity;
mod static_codex;

pub use self::dynamic::DynamicCodex;
pub use self::identity::IdentityCodex;
pub use self::static_codex::StaticCodex;

/// Byte-wise transformation applied to all stored bytes.
///
/// # Implementor contract
///
/// - **Involution.** For every byte `b`, `self.decode(self.encode(b)) == b`.
///   Equivalently, the transformation is its own inverse.
/// - **Constant-time.** Implementations should be branch-free; the canonical
///   shape is a 256-entry lookup table.
/// - **`Send + Sync`.** Codex instances are shared across threads.
pub trait Codex: Send + Sync {
    /// Transform a byte on the way into storage.
    fn encode(&self, byte: u8) -> u8;

    /// Transform a byte on the way out of storage.
    ///
    /// For involution-based codices `decode == encode`. The two methods are
    /// kept separate so that downstream consumers reading the code do not have
    /// to remember the invariant.
    fn decode(&self, byte: u8) -> u8;
}

/// Wrap a user-provided closure as a [`Codex`].
///
/// The closure is presumed to be an involution; nothing in the type system
/// enforces this and **violating the property will corrupt every stored key**.
/// Test your closure with the property test in the `codex` integration suite
/// before using it in production.
///
/// # Examples
///
/// ```
/// use key_vault::codex::{Codex, FnCodex};
///
/// // XOR with a fixed mask is an involution.
/// let codex = FnCodex::new(|b: u8| b ^ 0x5a);
/// assert_eq!(codex.decode(codex.encode(0x42)), 0x42);
/// ```
pub struct FnCodex<F> {
    f: F,
    // `PhantomData` keeps the type parameter bound even if `F`'s captured
    // environment is empty — defensive against future tightening.
    _marker: PhantomData<fn(u8) -> u8>,
}

impl<F> FnCodex<F>
where
    F: Fn(u8) -> u8 + Send + Sync,
{
    /// Wrap the given involution.
    #[must_use]
    pub fn new(f: F) -> Self {
        Self {
            f,
            _marker: PhantomData,
        }
    }
}

impl<F> Codex for FnCodex<F>
where
    F: Fn(u8) -> u8 + Send + Sync,
{
    fn encode(&self, byte: u8) -> u8 {
        (self.f)(byte)
    }

    fn decode(&self, byte: u8) -> u8 {
        (self.f)(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fn_codex_round_trips_xor() {
        let c = FnCodex::new(|b: u8| b ^ 0x37);
        for b in 0u8..=255 {
            assert_eq!(c.decode(c.encode(b)), b);
        }
    }
}
