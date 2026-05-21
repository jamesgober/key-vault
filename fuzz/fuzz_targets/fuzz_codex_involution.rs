#![no_main]
//! Codex involution fuzz.
//!
//! For each input byte and each in-tree codex, assert
//! `decode(encode(b)) == b`. `DynamicCodex::new` uses fresh randomness
//! at construction so the table differs every fuzz iteration — broad
//! coverage of the involution-with-no-fixed-points generation logic.

use key_vault::codex::{Codex, DynamicCodex, IdentityCodex, StaticCodex};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let identity = IdentityCodex::default();
    let static_codex = match StaticCodex::random_involution() {
        Ok(c) => c,
        Err(_) => return,
    };
    let dynamic = match DynamicCodex::new() {
        Ok(c) => c,
        Err(_) => return,
    };

    for &b in data {
        // Involution property: decode(encode(b)) == b for every codex.
        assert_eq!(identity.decode(identity.encode(b)), b);
        assert_eq!(static_codex.decode(static_codex.encode(b)), b);
        assert_eq!(dynamic.decode(dynamic.encode(b)), b);
    }
});
