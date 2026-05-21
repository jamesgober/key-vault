#![no_main]
//! Round-trip fuzz for `LayeredFragmenter` composing all three
//! in-tree sub-strategies.

use std::sync::Arc;

use key_vault::{
    FragmentStrategy, InterleavedFragmenter, LayeredFragmenter, RandomFragmenter, RawKey,
    StandardFragmenter,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let strat = LayeredFragmenter::new(vec![
        Arc::new(StandardFragmenter::new()) as Arc<dyn FragmentStrategy>,
        Arc::new(InterleavedFragmenter::new()) as Arc<dyn FragmentStrategy>,
        Arc::new(RandomFragmenter::new()) as Arc<dyn FragmentStrategy>,
    ])
    .expect("non-empty sub-strategy list");
    let key = RawKey::new(data.to_vec());
    let frags = match strat.fragment(&key) {
        Ok(f) => f,
        Err(_) => return,
    };
    let recovered = strat.defragment(&frags).expect("defragment must succeed");
    assert_eq!(recovered.len(), data.len(), "layered round-trip length mismatch");
});
