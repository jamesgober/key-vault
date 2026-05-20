//! Layer 3 — Fragmentation.
//!
//! The [`FragmentStrategy`] trait splits a [`RawKey`] into a number of opaque
//! [`Fragments`] that the vault stores separately in mlock'd, non-contiguous
//! memory. Reassembly is the inverse operation, performed only when the caller
//! needs to use the key.
//!
//! In this phase the trait surface is defined; concrete implementations
//! (`StandardFragmenter`, `InterleavedFragmenter`, `RandomFragmenter`,
//! `LayeredFragmenter`) arrive in Phases 0.3 and 0.5.

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt;

use crate::Result;
use crate::fetcher::RawKey;

/// Opaque container for the fragmented representation of a key.
///
/// `Fragments` is intentionally a black box from the public API's point of
/// view. Its internal layout is the [`FragmentStrategy`] implementation's
/// concern; the vault treats it as a token that you hand to the same strategy
/// to recover the original key.
///
/// In this phase the type carries no payload — strategies have not been
/// implemented yet. Phase 0.3 introduces the real storage (variable-size
/// chunks, position maps, mlock'd allocations).
pub struct Fragments {
    /// Internal placeholder. The concrete layout is added in 0.3 alongside the
    /// `StandardFragmenter` implementation. Stored as `Vec<u8>` so that
    /// `Drop` cleanup can be wired up incrementally without changing the
    /// outer type's shape.
    _payload: Vec<u8>,
}

impl Fragments {
    /// Crate-internal: construct an empty placeholder.
    ///
    /// Real construction paths are added with the concrete fragmenters in 0.3.
    #[allow(dead_code)] // populated by concrete fragmenters in Phase 0.3.
    #[must_use]
    pub(crate) fn empty() -> Self {
        Self {
            _payload: Vec::new(),
        }
    }
}

impl fmt::Debug for Fragments {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The whole purpose of fragmentation is to obscure storage layout.
        // Debug never describes it.
        f.write_str("Fragments(<opaque>)")
    }
}

/// Strategy for splitting and reassembling a key.
///
/// # Implementor contract
///
/// - **Round-trip.** For every `key`,
///   `self.defragment(&self.fragment(&key)?)?` must produce a [`RawKey`] equal
///   to `key` byte-for-byte. This invariant is the basis of all property tests
///   in later phases.
/// - **Variable layout per call.** Two consecutive calls to `fragment` on the
///   same input must produce [`Fragments`] with distinct internal layouts. If a
///   strategy is deterministic it should document the threat trade-off
///   explicitly.
/// - **No allocation beyond the produced [`Fragments`].** Hot-path defragment
///   should write into a caller-supplied scratch buffer rather than allocate.
/// - **`Send + Sync`.** A strategy may be invoked from any thread.
pub trait FragmentStrategy: Send + Sync {
    /// Split a key into the strategy-defined fragmented representation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Fragment`](crate::Error::Fragment) on configuration
    /// inconsistency (for example a strategy that requires a minimum key
    /// length and was handed a shorter input).
    fn fragment(&self, key: &RawKey) -> Result<Fragments>;

    /// Reassemble fragments into the original raw key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Defragment`](crate::Error::Defragment) if the layout
    /// disagrees with what this strategy produced. The vault will not attempt
    /// to retry — a defragmentation failure indicates corruption or a
    /// mismatched strategy.
    fn defragment(&self, fragments: &Fragments) -> Result<RawKey>;

    /// Short identifier for audit and error attribution.
    fn describe(&self) -> Cow<'_, str>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn fragments_debug_is_opaque() {
        let f = Fragments::empty();
        let rendered = format!("{f:?}");
        assert_eq!(rendered, "Fragments(<opaque>)");
    }
}
