#![no_main]
//! Round-trip fuzz for `InterleavedFragmenter`.

use key_vault::{FragmentStrategy, InterleavedFragmenter, RawKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let strat = InterleavedFragmenter::new();
    let key = RawKey::new(data.to_vec());
    let frags = match strat.fragment(&key) {
        Ok(f) => f,
        Err(_) => return,
    };
    let recovered = strat.defragment(&frags).expect("defragment must succeed");
    assert_eq!(recovered.len(), data.len(), "interleaved round-trip length mismatch");
});
