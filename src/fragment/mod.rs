//! Layer 3 — Fragmentation.
//!
//! The [`FragmentStrategy`] trait splits a [`RawKey`] into a number of
//! [`Fragments`] that the vault stores separately in mlock'd, non-contiguous
//! memory. Reassembly is the inverse operation, performed only when the
//! caller needs to use the key.
//!
//! Phase 0.3 ships [`StandardFragmenter`], which produces variable-size
//! chunks at independent heap allocations (each `mlock`'d on Unix /
//! `VirtualLock`'d on Windows) and stores the reconstruction order in a
//! separately-locked layout buffer. Additional strategies (`Interleaved`,
//! `Random`, `Layered`) follow in Phase 0.5.

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt;

use crate::Result;
use crate::fetcher::RawKey;
use crate::memory::LockedBytes;

mod interleaved;
mod layered;
mod random;
mod standard;
pub(crate) mod util;

pub use self::interleaved::InterleavedFragmenter;
pub use self::layered::LayeredFragmenter;
pub use self::random::RandomFragmenter;
pub use self::standard::StandardFragmenter;

/// Opaque container for the fragmented representation of a key.
///
/// Each chunk lives in its own internal `LockedBytes` allocation (a crate-
/// private wrapper that pins the bytes in RAM via `mlock` / `VirtualLock`
/// and zeroes them on drop), so chunks are at independent (non-contiguous)
/// heap addresses by construction. The layout buffer encodes the order in
/// which chunks must be concatenated to reconstruct the original key and
/// is itself locked + zeroed on drop.
///
/// `Fragments` exposes no method that returns key bytes to outside the
/// crate: the only way to recover the original material is to hand the
/// `Fragments` back to a [`FragmentStrategy::defragment`] call on the same
/// strategy that produced it.
pub struct Fragments {
    /// Per-chunk locked buffers. Length matches the number of fragments;
    /// each entry's `LockedBytes::len()` is the chunk's size in bytes.
    chunks: Vec<LockedBytes>,

    /// Locked buffer holding the reconstruction order. Encoded as a
    /// sequence of little-endian `u32`s — `layout[4*i .. 4*(i+1)]` is the
    /// original-key offset of `chunks[i]`. Sorting chunks by this offset
    /// recovers the original byte order.
    layout: LockedBytes,

    /// Original length of the unfragmented key, in bytes. Stored so
    /// `defragment` can preallocate the output buffer and validate the
    /// final length.
    total_len: usize,
}

impl Fragments {
    /// Crate-internal: construct from already-prepared chunks and layout.
    pub(crate) fn from_parts(
        chunks: Vec<LockedBytes>,
        layout: LockedBytes,
        total_len: usize,
    ) -> Self {
        Self {
            chunks,
            layout,
            total_len,
        }
    }

    /// Crate-internal: original key length in bytes.
    pub(crate) fn total_len(&self) -> usize {
        self.total_len
    }

    /// Number of chunks the original key was split into.
    ///
    /// Exposed to outside callers because the chunk count itself does not
    /// reveal anything about the key value — only about the chosen
    /// fragmentation strategy's parameters. Tests use this to verify that
    /// two consecutive fragmentations of the same input produce different
    /// layouts.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Crate-internal: borrow the chunks for defragmentation.
    pub(crate) fn chunks(&self) -> &[LockedBytes] {
        &self.chunks
    }

    /// Crate-internal: borrow the layout buffer.
    pub(crate) fn layout(&self) -> &LockedBytes {
        &self.layout
    }

    /// Crate-internal: destructure into its components. Used by
    /// [`LayeredFragmenter`] to wrap a sub-strategy's output in additional
    /// layout metadata without copying the chunk buffers.
    pub(crate) fn into_parts(self) -> (Vec<LockedBytes>, LockedBytes, usize) {
        (self.chunks, self.layout, self.total_len)
    }
}

impl fmt::Debug for Fragments {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The whole purpose of fragmentation is to obscure storage layout.
        // Debug describes the shape only — the layout buffer is
        // deliberately omitted; `finish_non_exhaustive` documents the
        // intent to the compiler.
        f.debug_struct("Fragments")
            .field("chunks", &self.chunks.len())
            .field("total_len", &self.total_len)
            .field("contents", &"<opaque>")
            .finish_non_exhaustive()
    }
}

/// Strategy for splitting and reassembling a key.
///
/// # Implementor contract
///
/// - **Round-trip.** For every `key`,
///   `self.defragment(&self.fragment(&key)?)?` must produce a [`RawKey`] equal
///   to `key` byte-for-byte. This invariant is the basis of all property
///   tests in later phases.
/// - **Variable layout per call.** Two consecutive calls to `fragment` on the
///   same input must produce [`Fragments`] with distinct internal layouts. If
///   a strategy is deterministic it should document the threat trade-off
///   explicitly.
/// - **No allocation beyond the produced [`Fragments`].** Hot-path defragment
///   should write into a single contiguous output buffer rather than spread
///   work across many intermediate allocations.
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
    /// disagrees with what this strategy produced. The vault will not
    /// attempt to retry — a defragmentation failure indicates corruption or
    /// a mismatched strategy.
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
        let chunks = alloc::vec![LockedBytes::from_slice(&[1, 2, 3])];
        let layout = LockedBytes::from_slice(&[0, 0, 0, 0]);
        let f = Fragments::from_parts(chunks, layout, 3);
        let rendered = format!("{f:?}");
        assert!(rendered.contains("<opaque>"));
        assert!(rendered.contains("chunks: 1"));
        assert!(rendered.contains("total_len: 3"));
    }
}
