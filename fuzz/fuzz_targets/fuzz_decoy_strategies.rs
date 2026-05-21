#![no_main]
//! Decoy strategy fuzz.
//!
//! libFuzzer hands us a `(strategy_selector, output_len, key_bytes)`
//! triple via `Arbitrary`. We verify that:
//! - The strategy either returns `Ok` with exactly `output_len` bytes
//!   or returns a documented `Error` (no panic, no infinite loop).
//! - `SelfReferenceDecoy` output bytes are drawn from the key's byte
//!   set (defining property).
//! - The output never reproduces a contiguous run of the key (3-byte
//!   window check — strong enough to catch trivial leaks).

use arbitrary::Arbitrary;
use key_vault::{DecoyStrategy, KeyDerivedDecoy, RandomDecoy, RawKey, SelfReferenceDecoy};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct DecoyInput {
    selector: u8,
    output_len: u16,
    key: Vec<u8>,
}

fuzz_target!(|input: DecoyInput| {
    let output_len = usize::from(input.output_len) % 4096;
    let key = RawKey::new(input.key.clone());

    let bytes = match input.selector % 3 {
        0 => {
            let strat = RandomDecoy;
            strat.generate(&key, output_len)
        }
        1 => {
            let strat = SelfReferenceDecoy;
            strat.generate(&key, output_len)
        }
        _ => {
            let strat = KeyDerivedDecoy;
            strat.generate(&key, output_len)
        }
    };

    let bytes = match bytes {
        Ok(b) => b,
        Err(_) => return,
    };

    assert_eq!(bytes.len(), output_len, "decoy output length mismatch");

    // SelfReferenceDecoy must only draw bytes that appear in the key.
    if (input.selector % 3) == 1 && !input.key.is_empty() {
        for b in &bytes {
            assert!(
                input.key.contains(b),
                "SelfReferenceDecoy emitted byte 0x{b:02x} not present in key"
            );
        }
    }

    // None of the strategies should reproduce a 3-byte contiguous
    // window of the input key.
    if input.key.len() >= 3 && bytes.len() >= 3 {
        for win in input.key.windows(3) {
            for cand in bytes.windows(3) {
                assert_ne!(cand, win, "decoy reproduced a 3-byte key window");
            }
        }
    }
});
