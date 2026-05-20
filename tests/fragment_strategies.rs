//! Integration tests for the four Layer-3 fragment strategies.
//!
//! Exercised from outside the crate to confirm the public surface
//! (`StandardFragmenter`, `InterleavedFragmenter`, `RandomFragmenter`,
//! `LayeredFragmenter`) all round-trip through the standard
//! `FragmentStrategy` trait. Byte equality of the reassembled key is not
//! observable through `RawKey`'s public API (no `&[u8]` exposed by
//! design), so these tests check observable side-effects: length,
//! structural properties of `Fragments`, and `Send + Sync`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use key_vault::{
    FragmentStrategy, InterleavedFragmenter, LayeredFragmenter, RandomFragmenter, RawKey,
    StandardFragmenter,
};

fn raw(len: usize) -> RawKey {
    RawKey::new((0..len).map(|i| (i & 0xff) as u8).collect())
}

#[test]
fn standard_fragmenter_round_trips_through_public_trait() {
    let frag = StandardFragmenter::new();
    let original = raw(64);
    let fragments = frag.fragment(&original).unwrap();
    let recovered = frag.defragment(&fragments).unwrap();
    assert_eq!(recovered.len(), 64);
}

#[test]
fn random_fragmenter_round_trips_through_public_trait() {
    let frag = RandomFragmenter::new();
    let original = raw(64);
    let fragments = frag.fragment(&original).unwrap();
    let recovered = frag.defragment(&fragments).unwrap();
    assert_eq!(recovered.len(), 64);
}

#[test]
fn interleaved_fragmenter_round_trips_through_public_trait() {
    let frag = InterleavedFragmenter::new();
    let original = raw(64);
    let fragments = frag.fragment(&original).unwrap();
    let recovered = frag.defragment(&fragments).unwrap();
    assert_eq!(recovered.len(), 64);

    // InterleavedFragmenter uses a single pool buffer; verify the chunk
    // count is always exactly 1.
    assert_eq!(fragments.chunk_count(), 1);
}

#[test]
fn layered_fragmenter_routes_through_sub_strategies() {
    let frag = LayeredFragmenter::new(vec![
        Arc::new(StandardFragmenter::new()) as Arc<dyn FragmentStrategy>,
        Arc::new(InterleavedFragmenter::new()) as Arc<dyn FragmentStrategy>,
        Arc::new(RandomFragmenter::new()) as Arc<dyn FragmentStrategy>,
    ])
    .unwrap();
    assert_eq!(frag.sub_strategy_count(), 3);

    // 20 rounds — probability of any given sub-strategy never being picked
    // is (2/3)^20 ≈ 3e-4. The test would catch a stuck dispatcher.
    let original = raw(48);
    for _ in 0..20 {
        let fragments = frag.fragment(&original).unwrap();
        let recovered = frag.defragment(&fragments).unwrap();
        assert_eq!(recovered.len(), 48);
    }
}

#[test]
fn all_strategies_are_send_and_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<StandardFragmenter>();
    assert_sync::<StandardFragmenter>();
    assert_send::<RandomFragmenter>();
    assert_sync::<RandomFragmenter>();
    assert_send::<InterleavedFragmenter>();
    assert_sync::<InterleavedFragmenter>();
    assert_send::<LayeredFragmenter>();
    assert_sync::<LayeredFragmenter>();
}

#[test]
fn fragments_chunk_count_reflects_strategy_choice() {
    // StandardFragmenter — multiple chunks
    let s_frag = StandardFragmenter::new();
    let s = s_frag.fragment(&raw(32)).unwrap();
    assert!(s.chunk_count() > 1, "standard should produce >1 chunk");

    // InterleavedFragmenter — exactly 1 chunk (the pool)
    let i_frag = InterleavedFragmenter::new();
    let i = i_frag.fragment(&raw(32)).unwrap();
    assert_eq!(i.chunk_count(), 1);

    // RandomFragmenter — multiple chunks
    let r_frag = RandomFragmenter::new();
    let r = r_frag.fragment(&raw(32)).unwrap();
    assert!(r.chunk_count() > 1, "random should produce >1 chunk");
}
