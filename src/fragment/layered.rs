//! [`LayeredFragmenter`] — randomly route between a set of sub-strategies.
//!
//! `LayeredFragmenter` holds a list of inner `FragmentStrategy`
//! implementations. Each call to `fragment` picks one of them uniformly at
//! random and delegates entirely; `defragment` reads which sub-strategy
//! was used from the layout header and dispatches to it.
//!
//! # Threat model
//!
//! Against an attacker who has both the chunks and the layout buffer (the
//! worst-case Layer 3 / 4 break), `LayeredFragmenter` raises the work
//! factor by an additional `log2(N)` bits of uncertainty about which
//! strategy was used — plus the attacker has to know that we are even
//! using a layered scheme. Against an attacker who has only the chunks,
//! they cannot guess which sub-strategy was used and so cannot decode.
//!
//! Composition through **routing** (rather than chained transformations)
//! avoids materializing the key between layers, which would itself create
//! a recoverable plaintext moment.
//!
//! # Layout encoding
//!
//! ```text
//! layout = [strategy_index: u32 LE | sub_layout_bytes...]
//! ```
//!
//! `strategy_index` indexes into the `sub_strategies` vector at
//! construction time. `defragment` strips the prefix, hands the rest back
//! to the indexed sub-strategy as the layout of a reconstructed
//! `Fragments`.

use alloc::borrow::Cow;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use super::util::{random_u64, zero_buffer};
use super::{FragmentStrategy, Fragments};
use crate::Result;
use crate::error::Error;
use crate::fetcher::RawKey;
use crate::memory::LockedBytes;

/// Composition fragmenter that routes each call to one of several
/// sub-strategies.
#[derive(Clone)]
pub struct LayeredFragmenter {
    sub_strategies: Vec<Arc<dyn FragmentStrategy>>,
}

impl LayeredFragmenter {
    /// Construct a layered fragmenter from a list of sub-strategies.
    ///
    /// `sub_strategies` must be non-empty; the constructor returns
    /// [`Error::InvalidConfig`](crate::Error::InvalidConfig) on an empty
    /// list.
    ///
    /// Holds each sub-strategy in an `Arc<dyn FragmentStrategy>` so the
    /// same strategy can be shared across multiple builders.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`](crate::Error::InvalidConfig) if
    /// `sub_strategies` is empty. The number of sub-strategies is also
    /// capped at `u32::MAX` (any realistic count is fine).
    pub fn new(sub_strategies: Vec<Arc<dyn FragmentStrategy>>) -> Result<Self> {
        if sub_strategies.is_empty() {
            return Err(Error::InvalidConfig(alloc::string::ToString::to_string(
                "LayeredFragmenter requires at least one sub-strategy",
            )));
        }
        if sub_strategies.len() > u32::MAX as usize {
            return Err(Error::InvalidConfig(alloc::string::ToString::to_string(
                "LayeredFragmenter sub-strategy count exceeds u32",
            )));
        }
        Ok(Self { sub_strategies })
    }

    /// Number of sub-strategies in the rotation.
    #[must_use]
    pub fn sub_strategy_count(&self) -> usize {
        self.sub_strategies.len()
    }
}

impl fmt::Debug for LayeredFragmenter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<_> = self
            .sub_strategies
            .iter()
            .map(|s| s.describe().into_owned())
            .collect();
        f.debug_struct("LayeredFragmenter")
            .field("sub_strategies", &names)
            .finish()
    }
}

impl FragmentStrategy for LayeredFragmenter {
    fn fragment(&self, key: &RawKey) -> Result<Fragments> {
        // Pick one sub-strategy uniformly at random.
        // The `as u64` cast on `len()` is bounded by the constructor's
        // `len <= u32::MAX` check; the `% n` result is `< n` so fits in
        // usize on every supported target.
        #[allow(clippy::cast_possible_truncation)]
        let n = self.sub_strategies.len() as u64;
        #[allow(clippy::cast_possible_truncation)]
        let pick = (random_u64()? % n) as usize;
        let sub_fragments = self.sub_strategies[pick].fragment(key)?;

        // Unpack the sub-strategy's Fragments and wrap them with our own
        // layout header. We hold ownership of the chunks so the move
        // doesn't introduce any extra allocation.
        let (chunks, sub_layout, total_len) = sub_fragments.into_parts();
        let sub_layout_bytes = sub_layout.as_bytes();

        let mut new_layout_bytes: Vec<u8> = Vec::with_capacity(4 + sub_layout_bytes.len());
        let pick_u32 = u32::try_from(pick)
            .map_err(|_| Error::Internal("LayeredFragmenter sub-strategy index exceeded u32"))?;
        new_layout_bytes.extend_from_slice(&pick_u32.to_le_bytes());
        new_layout_bytes.extend_from_slice(sub_layout_bytes);

        let new_layout = LockedBytes::from_slice(&new_layout_bytes);
        zero_buffer(&mut new_layout_bytes);
        drop(new_layout_bytes);
        // Explicitly drop the old (sub-strategy's) layout buffer now;
        // its destructor zeroes and unlocks.
        drop(sub_layout);

        Ok(Fragments::from_parts(chunks, new_layout, total_len))
    }

    fn defragment(&self, fragments: &Fragments) -> Result<RawKey> {
        let layout = fragments.layout().as_bytes();
        if layout.len() < 4 {
            return Err(Error::Defragment(alloc::string::ToString::to_string(
                "layered layout shorter than 4-byte header",
            )));
        }
        let pick_raw: [u8; 4] = layout[0..4]
            .try_into()
            .map_err(|_| Error::Defragment(alloc::string::ToString::to_string("layout slice")))?;
        let pick = u32::from_le_bytes(pick_raw) as usize;
        if pick >= self.sub_strategies.len() {
            return Err(Error::Defragment(format!(
                "layered layout strategy index {pick} out of range",
            )));
        }

        // Reconstruct the sub-strategy's Fragments by stripping the header
        // off our layout. The chunks are not moved — we only borrow them.
        let sub_layout = LockedBytes::from_slice(&layout[4..]);
        // To pass to the sub-strategy without consuming our chunks, we
        // build a temporary Fragments that aliases our chunks. We can't
        // alias a Vec<LockedBytes> directly (each LockedBytes is owned),
        // so we route via a dedicated `defragment_with_chunks` shape:
        // simpler to clone the chunk *bytes* into fresh LockedBytes and
        // hand those off. The sub-strategy never holds onto them past its
        // return.
        let chunks_copy: Vec<LockedBytes> = fragments
            .chunks()
            .iter()
            .map(|c| LockedBytes::from_slice(c.as_bytes()))
            .collect();
        let sub_fragments = Fragments::from_parts(chunks_copy, sub_layout, fragments.total_len());
        self.sub_strategies[pick].defragment(&sub_fragments)
    }

    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("layered")
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
    use crate::fragment::{InterleavedFragmenter, RandomFragmenter, StandardFragmenter};

    fn key(bytes: &[u8]) -> RawKey {
        RawKey::new(bytes.to_vec())
    }

    #[test]
    fn rejects_empty_sub_strategy_list() {
        let err = LayeredFragmenter::new(Vec::new()).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn round_trip_with_three_sub_strategies() {
        let frag = LayeredFragmenter::new(alloc::vec![
            Arc::new(StandardFragmenter::new()) as Arc<dyn FragmentStrategy>,
            Arc::new(InterleavedFragmenter::new()) as Arc<dyn FragmentStrategy>,
            Arc::new(RandomFragmenter::new()) as Arc<dyn FragmentStrategy>,
        ])
        .unwrap();

        // Run several rounds so each sub-strategy gets exercised at least
        // once (probability of skipping any across 30 rounds is 2^-17).
        let bytes: Vec<u8> = (0u8..64).collect();
        let original = key(&bytes);
        for _ in 0..30 {
            let fragments = frag.fragment(&original).unwrap();
            let recovered = frag.defragment(&fragments).unwrap();
            assert_eq!(recovered.as_bytes(), &bytes[..]);
        }
    }

    #[test]
    fn round_trip_with_single_sub_strategy() {
        // Degenerate case: LayeredFragmenter wrapping a single strategy
        // should still work and just add the 4-byte header.
        let frag = LayeredFragmenter::new(alloc::vec![
            Arc::new(StandardFragmenter::new()) as Arc<dyn FragmentStrategy>,
        ])
        .unwrap();
        let bytes: Vec<u8> = (0u8..32).collect();
        let original = key(&bytes);
        let fragments = frag.fragment(&original).unwrap();
        let recovered = frag.defragment(&fragments).unwrap();
        assert_eq!(recovered.as_bytes(), &bytes[..]);
    }

    #[test]
    fn describe_returns_layered() {
        let frag = LayeredFragmenter::new(alloc::vec![
            Arc::new(StandardFragmenter::new()) as Arc<dyn FragmentStrategy>,
        ])
        .unwrap();
        assert_eq!(frag.describe(), "layered");
    }

    #[test]
    fn sub_strategy_count_is_correct() {
        let frag = LayeredFragmenter::new(alloc::vec![
            Arc::new(StandardFragmenter::new()) as Arc<dyn FragmentStrategy>,
            Arc::new(RandomFragmenter::new()) as Arc<dyn FragmentStrategy>,
        ])
        .unwrap();
        assert_eq!(frag.sub_strategy_count(), 2);
    }
}
