//! [`RandomFragmenter`] — non-contiguous byte scatter.
//!
//! Where [`StandardFragmenter`](super::StandardFragmenter) splits the key
//! into contiguous chunks and shuffles those chunks, `RandomFragmenter`
//! scatters bytes **within** each chunk: each chunk holds bytes drawn from
//! non-contiguous positions in the original key. This defeats the "long
//! contiguous run of key bytes" cue that an attacker might use to confirm
//! a chunk hit.
//!
//! # When to use
//!
//! Use `RandomFragmenter` when:
//!
//! - You suspect an attacker can scan memory linearly and recognize
//!   structured key formats (DER, PEM, ASCII-armored) even from a partial
//!   contiguous read.
//! - You are willing to pay slightly higher per-chunk overhead (each
//!   chunk's bytes come from up to `max_chunk` random positions) for the
//!   reduced linear-recognition risk.
//!
//! For most cases, [`StandardFragmenter`](super::StandardFragmenter)
//! combined with [`SelfReferenceDecoy`](crate::SelfReferenceDecoy) is
//! sufficient and faster.
//!
//! # Layout encoding
//!
//! Each chunk's layout records the **original position** of each byte in
//! the chunk:
//!
//! ```text
//! layout = [size: u32 LE,
//!           pos[0]: u32 LE, pos[1]: u32 LE, ..., pos[size-1]: u32 LE,
//!           size: u32 LE, ...]
//! ```
//!
//! `defragment` walks the layout, places each byte at its recorded
//! original position, and returns the result. Decoys are not currently
//! supported by this strategy — combine with
//! [`LayeredFragmenter`](super::LayeredFragmenter) if you need decoy mixing.

use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::util::{fisher_yates, sample_range, zero_buffer};
use super::{FragmentStrategy, Fragments};
use crate::Result;
use crate::error::Error;
use crate::fetcher::RawKey;
use crate::memory::LockedBytes;

/// Default minimum chunk size for [`RandomFragmenter`].
const DEFAULT_MIN_CHUNK: usize = 1;
/// Default maximum chunk size for [`RandomFragmenter`].
const DEFAULT_MAX_CHUNK: usize = 4;

/// Non-contiguous-scatter Layer 3 fragmenter.
///
/// Each chunk holds bytes drawn from independently-chosen random positions
/// in the original key — no chunk ever contains a contiguous run of key
/// bytes longer than 1.
#[derive(Debug, Clone, Copy)]
pub struct RandomFragmenter {
    min_chunk: usize,
    max_chunk: usize,
}

impl Default for RandomFragmenter {
    fn default() -> Self {
        Self::new()
    }
}

impl RandomFragmenter {
    /// Construct with the default chunk-size range (`min = 1`, `max = 4`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_chunk: DEFAULT_MIN_CHUNK,
            max_chunk: DEFAULT_MAX_CHUNK,
        }
    }

    /// Construct with a custom chunk-size range. `min` is clamped to
    /// `>= 1`, `max` to `>= min`.
    #[must_use]
    pub fn with_chunk_range(min: usize, max: usize) -> Self {
        let min = min.max(1);
        let max = max.max(min);
        Self {
            min_chunk: min,
            max_chunk: max,
        }
    }
}

impl FragmentStrategy for RandomFragmenter {
    // All `as u32` casts in this method are bounded by checked
    // pre-conditions (`total_len <= u32::MAX`, `size <= max_chunk <= u32`).
    #[allow(clippy::cast_possible_truncation)]
    fn fragment(&self, key: &RawKey) -> Result<Fragments> {
        let bytes = key.as_bytes();
        let total_len = bytes.len();
        if total_len == 0 {
            return Err(Error::Fragment(alloc::string::ToString::to_string(
                "empty key cannot be fragmented",
            )));
        }
        // Real-byte positions must fit in u32.
        if total_len > u32::MAX as usize {
            return Err(Error::Fragment(alloc::string::ToString::to_string(
                "key too large for fragmentation",
            )));
        }

        // Step 1: build a shuffled permutation of all original positions.
        // Each position appears exactly once.
        let mut positions: Vec<u32> = (0..total_len as u32).collect();
        fisher_yates(&mut positions)?;

        // Step 2: walk the permutation, peeling off variable-size groups
        // and turning each group into a chunk. Each chunk's bytes thus
        // come from non-contiguous, randomly-chosen original positions.
        let mut chunks: Vec<LockedBytes> = Vec::new();
        let mut layout_bytes: Vec<u8> = Vec::new();
        let mut cursor = 0usize;
        while cursor < positions.len() {
            let remaining = positions.len() - cursor;
            let size = if remaining <= self.max_chunk {
                remaining
            } else {
                let pick = sample_range(self.min_chunk, self.max_chunk)?;
                // Ensure we leave at least `min` bytes for at least one
                // more chunk.
                pick.min(remaining.saturating_sub(self.min_chunk))
                    .max(self.min_chunk)
                    .min(self.max_chunk)
                    .min(remaining)
            };

            // Build the chunk's bytes by reading from each picked position.
            let mut chunk_bytes: Vec<u8> = Vec::with_capacity(size);
            for &pos in &positions[cursor..cursor + size] {
                chunk_bytes.push(bytes[pos as usize]);
            }
            chunks.push(LockedBytes::from_slice(&chunk_bytes));
            zero_buffer(&mut chunk_bytes);
            drop(chunk_bytes);

            // Append the layout entry: u32 size + size × u32 positions.
            // Size fits in u32 because max_chunk <= u32::MAX (practically
            // <= 4 by default).
            layout_bytes.extend_from_slice(&(size as u32).to_le_bytes());
            for &pos in &positions[cursor..cursor + size] {
                layout_bytes.extend_from_slice(&pos.to_le_bytes());
            }

            cursor += size;
        }

        let layout = LockedBytes::from_slice(&layout_bytes);
        zero_buffer(&mut layout_bytes);
        drop(layout_bytes);
        drop(positions);

        Ok(Fragments::from_parts(chunks, layout, total_len))
    }

    fn defragment(&self, fragments: &Fragments) -> Result<RawKey> {
        let mut out = alloc::vec![0u8; fragments.total_len()];
        self.defragment_into(fragments, &mut out)?;
        Ok(RawKey::new(out))
    }

    fn defragment_into(&self, fragments: &Fragments, out: &mut [u8]) -> Result<()> {
        let layout = fragments.layout().as_bytes();
        let chunks = fragments.chunks();
        let total_len = fragments.total_len();

        if out.len() != total_len {
            return Err(Error::Defragment(alloc::string::ToString::to_string(
                "scratch buffer size does not match fragments.total_len()",
            )));
        }
        let mut layout_cursor = 0usize;
        for chunk in chunks {
            // Read size prefix.
            if layout_cursor + 4 > layout.len() {
                return Err(Error::Defragment(alloc::string::ToString::to_string(
                    "layout buffer truncated before size prefix",
                )));
            }
            let size_raw: [u8; 4] = layout[layout_cursor..layout_cursor + 4]
                .try_into()
                .map_err(|_| {
                    Error::Defragment(alloc::string::ToString::to_string("layout slice"))
                })?;
            let size = u32::from_le_bytes(size_raw) as usize;
            layout_cursor += 4;

            if size != chunk.as_bytes().len() {
                return Err(Error::Defragment(alloc::string::ToString::to_string(
                    "layout size does not match chunk length",
                )));
            }
            if layout_cursor + size * 4 > layout.len() {
                return Err(Error::Defragment(alloc::string::ToString::to_string(
                    "layout buffer truncated before position list",
                )));
            }

            // Place each byte at its recorded original position.
            for (i, byte) in chunk.as_bytes().iter().enumerate() {
                let pos_raw: [u8; 4] = layout[layout_cursor + i * 4..layout_cursor + (i + 1) * 4]
                    .try_into()
                    .map_err(|_| {
                        Error::Defragment(alloc::string::ToString::to_string("layout slice"))
                    })?;
                let pos = u32::from_le_bytes(pos_raw) as usize;
                if pos >= total_len {
                    return Err(Error::Defragment(alloc::string::ToString::to_string(
                        "layout position out of range",
                    )));
                }
                out[pos] = *byte;
            }
            layout_cursor += size * 4;
        }

        if layout_cursor != layout.len() {
            return Err(Error::Defragment(alloc::string::ToString::to_string(
                "trailing bytes in layout buffer",
            )));
        }

        Ok(())
    }

    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("random")
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

    fn key(bytes: &[u8]) -> RawKey {
        RawKey::new(bytes.to_vec())
    }

    #[test]
    fn round_trip_short_key() {
        let frag = RandomFragmenter::new();
        let original = key(&[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let fragments = frag.fragment(&original).unwrap();
        let recovered = frag.defragment(&fragments).unwrap();
        assert_eq!(recovered.as_bytes(), original.as_bytes());
    }

    #[test]
    fn round_trip_many_sizes() {
        let frag = RandomFragmenter::new();
        for len in [1usize, 7, 16, 32, 64, 128, 255, 256, 500, 1024] {
            let bytes: Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
            let original = key(&bytes);
            let fragments = frag.fragment(&original).unwrap();
            let recovered = frag.defragment(&fragments).unwrap();
            assert_eq!(recovered.as_bytes(), &bytes[..], "mismatch at len {len}");
        }
    }

    #[test]
    fn empty_key_rejected() {
        let frag = RandomFragmenter::new();
        let err = frag.fragment(&key(&[])).unwrap_err();
        assert!(matches!(err, Error::Fragment(_)));
    }

    #[test]
    fn two_calls_produce_different_layouts() {
        let frag = RandomFragmenter::new();
        let bytes: Vec<u8> = (0..32).map(|i| i as u8).collect();
        let original = key(&bytes);
        let a = frag.fragment(&original).unwrap();
        let b = frag.fragment(&original).unwrap();
        assert_ne!(a.layout().as_bytes(), b.layout().as_bytes());
    }

    #[test]
    fn describe_returns_random() {
        assert_eq!(RandomFragmenter::new().describe(), "random");
    }
}
