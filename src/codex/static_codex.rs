//! [`StaticCodex`] — 256-byte involution lookup table.
//!
//! `StaticCodex` is the canonical Layer-5 implementation. It is a fixed
//! permutation of `[0, 256)` chosen so that applying it twice returns the
//! original byte — an involution. The permutation is stored as a 256-byte
//! lookup table inside a [`LockedBytes`] buffer so the table itself is
//! mlock'd and zeroed-on-drop just like every other piece of key-adjacent
//! state.
//!
//! # Construction
//!
//! - [`StaticCodex::from_swaps`] — declarative: give it a list of swap
//!   pairs like `&[(b'A', b'#'), (b'B', b'!')]` and it builds the table.
//!   Useful for private builds that want a stable, build-time-known
//!   transformation.
//! - [`StaticCodex::random_involution`] — programmatic: pair up every
//!   byte randomly with another distinct byte (no fixed points). Useful
//!   for tests and as the engine behind
//!   [`DynamicCodex`](super::DynamicCodex).
//!
//! # Lookup-table cost
//!
//! Encoding or decoding one byte is exactly one memory load
//! (`table[byte as usize]`). Branch-free, constant-time, ~1 cycle on
//! modern CPUs.

use alloc::vec::Vec;

use super::Codex;
use crate::Result;
use crate::error::Error;
use crate::fragment::util::fisher_yates;
use crate::memory::LockedBytes;

/// Involution-based byte-swap codex backed by a 256-byte lookup table.
///
/// The table is held in a crate-internal `LockedBytes` buffer (mlock'd,
/// zeroed on drop) since knowledge of the table is equivalent to
/// knowledge of the transformation.
pub struct StaticCodex {
    table: LockedBytes,
}

impl core::fmt::Debug for StaticCodex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The table itself is sensitive (it's the transformation). Debug
        // only reports the type name.
        f.debug_struct("StaticCodex")
            .field("table", &"<redacted>")
            .finish()
    }
}

impl StaticCodex {
    /// Construct a codex from a list of swap pairs.
    ///
    /// Each `(a, b)` in `swaps` means "byte `a` encodes to `b` and `b`
    /// encodes to `a`." Bytes not mentioned in any pair are fixed points
    /// (encode to themselves). Self-swaps (`(x, x)`) are accepted as
    /// no-ops.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Codex`](crate::Error::Codex) if a byte appears in
    /// more than one swap pair — that would force the table to disagree
    /// with itself and break the involution property.
    ///
    /// # Examples
    ///
    /// ```
    /// use key_vault::{Codex, StaticCodex};
    ///
    /// // Swap the ASCII digit '0' with '#' and 'A' with '@'.
    /// let codex = StaticCodex::from_swaps(&[(b'0', b'#'), (b'A', b'@')]).unwrap();
    /// assert_eq!(codex.encode(b'0'), b'#');
    /// assert_eq!(codex.encode(b'#'), b'0');
    /// assert_eq!(codex.encode(b'B'), b'B'); // not in any swap, fixed point
    /// // Involution holds:
    /// for byte in 0u8..=255 {
    ///     assert_eq!(codex.decode(codex.encode(byte)), byte);
    /// }
    /// ```
    pub fn from_swaps(swaps: &[(u8, u8)]) -> Result<Self> {
        let mut table = [0u8; 256];
        // Initialize as the identity permutation (each byte maps to itself).
        for (i, slot) in table.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *slot = i as u8;
            }
        }

        let mut used = [false; 256];
        for &(a, b) in swaps {
            if a == b {
                // Self-swap: equivalent to no swap. Allowed.
                used[a as usize] = true;
                continue;
            }
            if used[a as usize] || used[b as usize] {
                return Err(Error::Codex(alloc::string::ToString::to_string(
                    "byte appears in more than one swap pair",
                )));
            }
            table[a as usize] = b;
            table[b as usize] = a;
            used[a as usize] = true;
            used[b as usize] = true;
        }

        Ok(Self {
            table: LockedBytes::from_slice(&table),
        })
    }

    /// Generate a random involution with no fixed points.
    ///
    /// Pairs up all 256 bytes uniformly at random and writes the
    /// resulting permutation into the lookup table. Every byte transforms
    /// to a different byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Internal`](crate::Error::Internal) if the OS CSPRNG
    /// fails — same failure mode as everywhere else in the crate.
    ///
    /// # Examples
    ///
    /// ```
    /// use key_vault::{Codex, StaticCodex};
    ///
    /// let codex = StaticCodex::random_involution().unwrap();
    /// // Involution: applying it twice returns the original byte.
    /// for byte in 0u8..=255 {
    ///     assert_eq!(codex.decode(codex.encode(byte)), byte);
    /// }
    /// // No fixed points: every byte transforms to a different byte.
    /// for byte in 0u8..=255 {
    ///     assert_ne!(codex.encode(byte), byte);
    /// }
    /// ```
    pub fn random_involution() -> Result<Self> {
        // Start with the identity table.
        let mut table = [0u8; 256];
        // Initialize as the identity permutation (each byte maps to itself).
        for (i, slot) in table.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *slot = i as u8;
            }
        }

        // Build a permutation of all 256 byte values.
        let mut perm: Vec<u8> = (0u8..=255).collect();
        fisher_yates(&mut perm)?;

        // Pair adjacent elements: perm[0]↔perm[1], perm[2]↔perm[3], ...,
        // perm[254]↔perm[255]. Every byte is in exactly one pair, so
        // every byte is in exactly one swap — a perfect involution with
        // no fixed points.
        let mut i = 0usize;
        while i + 1 < perm.len() {
            let a = perm[i];
            let b = perm[i + 1];
            table[a as usize] = b;
            table[b as usize] = a;
            i += 2;
        }

        Ok(Self {
            table: LockedBytes::from_slice(&table),
        })
    }
}

impl Codex for StaticCodex {
    #[inline]
    fn encode(&self, byte: u8) -> u8 {
        self.table.as_bytes()[byte as usize]
    }

    #[inline]
    fn decode(&self, byte: u8) -> u8 {
        // Involution: decode == encode.
        self.table.as_bytes()[byte as usize]
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
    fn identity_when_no_swaps() {
        let codex = StaticCodex::from_swaps(&[]).unwrap();
        for byte in 0u8..=255 {
            assert_eq!(codex.encode(byte), byte);
            assert_eq!(codex.decode(byte), byte);
        }
    }

    #[test]
    fn explicit_swap_pair() {
        let codex = StaticCodex::from_swaps(&[(0x42, 0x99)]).unwrap();
        assert_eq!(codex.encode(0x42), 0x99);
        assert_eq!(codex.encode(0x99), 0x42);
        assert_eq!(codex.decode(0x99), 0x42);
        assert_eq!(codex.decode(0x42), 0x99);
        // Untouched bytes stay fixed.
        for byte in 0u8..=255 {
            if byte != 0x42 && byte != 0x99 {
                assert_eq!(codex.encode(byte), byte);
            }
        }
    }

    #[test]
    fn rejects_byte_in_two_swap_pairs() {
        let err = StaticCodex::from_swaps(&[(0x42, 0x99), (0x42, 0xab)]).unwrap_err();
        assert!(matches!(err, Error::Codex(_)));
    }

    #[test]
    fn rejects_byte_in_two_swap_pairs_either_side() {
        let err = StaticCodex::from_swaps(&[(0x42, 0x99), (0xab, 0x99)]).unwrap_err();
        assert!(matches!(err, Error::Codex(_)));
    }

    #[test]
    fn self_swap_is_a_noop() {
        let codex = StaticCodex::from_swaps(&[(0x42, 0x42)]).unwrap();
        assert_eq!(codex.encode(0x42), 0x42);
    }

    #[test]
    fn involution_holds_for_every_byte_from_swaps() {
        let codex = StaticCodex::from_swaps(&[(0x00, 0xff), (0x10, 0xa1), (0x42, 0x88)]).unwrap();
        for byte in 0u8..=255 {
            assert_eq!(codex.decode(codex.encode(byte)), byte);
        }
    }

    #[test]
    fn random_involution_holds_for_every_byte() {
        let codex = StaticCodex::random_involution().unwrap();
        for byte in 0u8..=255 {
            assert_eq!(codex.decode(codex.encode(byte)), byte);
        }
    }

    #[test]
    fn random_involution_has_no_fixed_points() {
        let codex = StaticCodex::random_involution().unwrap();
        for byte in 0u8..=255 {
            assert_ne!(
                codex.encode(byte),
                byte,
                "byte {byte:#04x} is a fixed point"
            );
        }
    }

    #[test]
    fn random_involutions_differ_across_calls() {
        let a = StaticCodex::random_involution().unwrap();
        let b = StaticCodex::random_involution().unwrap();
        // 256-byte tables match identically with probability ~ 1/256!
        // Astronomically improbable for a working RNG.
        assert_ne!(a.table.as_bytes(), b.table.as_bytes());
    }

    #[test]
    fn debug_redacts_table() {
        let codex = StaticCodex::from_swaps(&[(0x00, 0xff)]).unwrap();
        let rendered = alloc::format!("{codex:?}");
        assert!(rendered.contains("<redacted>"));
    }
}
