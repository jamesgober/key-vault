//! Layer 5 — Codex transformation.
//!
//! A [`Codex`] applies a byte-wise transformation to every byte (real key
//! material **and** decoy) before it is stored in fragments. The transformation
//! is an involution: applying it twice returns the original byte. Encoding and
//! decoding therefore call the same operation.
//!
//! # When to use
//!
//! The codex layer is off by default ([`IdentityCodex`]). It is feature-gated
//! behind the `codex` Cargo feature and adds approximately 5–10 ns per byte to
//! the access path. Enabling it raises the work required for an attacker who
//! has already defeated layers 2–4 (mlock, fragmentation, decoy): the bytes
//! they recover are not the bytes the application uses.
//!
//! # Involution requirement
//!
//! All implementations must satisfy `decode(encode(x)) == x` for every byte.
//! This is verified by tests for the built-in codices and, beginning in Phase
//! 0.6, by proptest sweeps over the full byte range.

use core::marker::PhantomData;

mod identity;

pub use self::identity::IdentityCodex;

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
