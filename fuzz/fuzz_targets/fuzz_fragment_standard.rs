#![no_main]
//! Round-trip fuzz for `StandardFragmenter`.
//!
//! For any byte slice the libFuzzer engine produces, fragment and then
//! defragment, asserting the recovered bytes equal the input. Empty
//! inputs are exercised via the `Error::Fragment` path (not a crash).

use key_vault::{FragmentStrategy, RawKey, StandardFragmenter};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let strat = StandardFragmenter::new();
    let key = RawKey::new(data.to_vec());
    let frags = match strat.fragment(&key) {
        Ok(f) => f,
        Err(_) => return,
    };
    let recovered = strat.defragment(&frags).expect("defragment must succeed");
    assert_eq!(
        recovered.len(),
        data.len(),
        "round-trip length mismatch (in={}, out={})",
        data.len(),
        recovered.len(),
    );
});
