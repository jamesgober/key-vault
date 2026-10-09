//! [`LayeredFragmenter`] — randomly route between a set of sub-strategies.
//!
//! `LayeredFragmenter` holds a list of inner `FragmentStrategy`
//! implementations. Each call to `fragment` picks one of them uniformly at
//! random and delegates entirely; `defragment` reads which sub-strategy
//! was used from the layout header and dispatches to it.
//!
//! # Threat model
//!
//! Obfuscation, like the strategies it routes to. The 4-byte layout
//! header records which sub-strategy produced the chunks, in the clear,
//! so anyone who can read the layout buffer knows how to decode them. What
//! layering adds is that the storage format differs from key to key, so a
//! tool written for one strategy's format does not work on every key.
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
//! construction time. `defragment` hands the indexed sub-strategy a view
//! of the same chunks whose layout starts after the prefix. Nothing is
//! copied.

use alloc::borrow::Cow;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroizing;

use super::util::random_u64;
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

impl LayeredFragmenter {
    /// Read the strategy index from the 4-byte layout header.
    fn pick(&self, fragments: &Fragments) -> Result<usize> {
        let layout = fragments.layout_bytes();
        let header: [u8; 4] = layout
            .get(0..4)
            .and_then(|h| h.try_into().ok())
            .ok_or_else(|| {
                Error::Defragment(alloc::string::ToString::to_string(
                    "layered layout shorter than 4-byte header",
                ))
            })?;
        let pick = u32::from_le_bytes(header) as usize;
        if pick >= self.sub_strategies.len() {
            return Err(Error::Defragment(format!(
                "layered layout strategy index {pick} out of range",
            )));
        }
        Ok(pick)
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

        // Prefix the sub-strategy's layout with our 4-byte header.
        let pick_u32 = u32::try_from(pick)
            .map_err(|_| Error::Internal("LayeredFragmenter sub-strategy index exceeded u32"))?;
        let sub_layout_bytes = sub_fragments.layout_bytes();
        let mut new_layout_bytes: Zeroizing<Vec<u8>> =
            Zeroizing::new(Vec::with_capacity(4 + sub_layout_bytes.len()));
        new_layout_bytes.extend_from_slice(&pick_u32.to_le_bytes());
        new_layout_bytes.extend_from_slice(sub_layout_bytes);
        let new_layout = LockedBytes::from_slice(&new_layout_bytes);
        drop(new_layout_bytes);

        let total_len = sub_fragments.total_len();
        // Moves the chunk buffers (no copy); the sub-strategy's own layout
        // buffer is zeroed as it drops.
        let chunks = sub_fragments.into_chunks();
        Ok(Fragments::from_parts(chunks, new_layout, total_len))
    }

    fn defragment(&self, fragments: &Fragments) -> Result<RawKey> {
        // Wrap the output in `RawKey` before writing so a partial write
        // is zeroed on drop if `defragment_into` returns an error.
        let mut out = RawKey::new(alloc::vec![0u8; fragments.total_len()]);
        self.defragment_into(fragments, out.as_bytes_mut())?;
        Ok(out)
    }

    fn defragment_into(&self, fragments: &Fragments, out: &mut [u8]) -> Result<()> {
        let pick = self.pick(fragments)?;
        // Hand the sub-strategy a view of the same chunks with our header
        // hidden. Nothing is copied: before 1.1 every call copied each
        // chunk into a new locked buffer (one `mlock` per chunk).
        let sub_fragments = fragments.view_skipping(4);
        self.sub_strategies[pick].defragment_into(&sub_fragments, out)
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
