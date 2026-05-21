//! Phase 0.11.0 — allocation profile for the `with_key` hot path.
//!
//! Built behind the standard `cargo run --example dhat_hot_path` so it
//! does not affect normal builds. Wires `dhat::Alloc` as the global
//! allocator, registers a key, hammers `with_key` 100_000 times, and
//! writes `dhat-heap.json` to the working directory.
//!
//! The 1.0 contract aims for **zero allocations on the hot path after
//! vault initialization**. This binary is the verification tool; the
//! result is reproduced in `docs/PERFORMANCE.md`.
//!
//! ```bash
//! cargo run --release --example dhat_hot_path
//! # Then open dhat-heap.json in the dhat viewer.
//! ```

use key_vault::{KeyVaultBuilder, RawKey};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const ITERATIONS: usize = 100_000;
const KEY_LEN: usize = 32;

fn main() {
    let _profiler = dhat::Profiler::new_heap();

    let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();

    let key: Vec<u8> = (0..KEY_LEN).map(|i| (i as u8).wrapping_mul(7)).collect();
    let handle = vault.register("hot", RawKey::new(key)).expect("register");

    // Warm-up — anything dhat sees up to here is registered as setup.
    for _ in 0..1_000 {
        let _: u32 = vault
            .with_key(handle, |bytes| {
                bytes
                    .iter()
                    .copied()
                    .fold(0u32, |a, b| a.wrapping_add(u32::from(b)))
            })
            .expect("with_key");
    }

    // Hot path. dhat's verdict on this section is what
    // PERFORMANCE.md should quote.
    for _ in 0..ITERATIONS {
        let _: u32 = vault
            .with_key(handle, |bytes| {
                bytes
                    .iter()
                    .copied()
                    .fold(0u32, |a, b| a.wrapping_add(u32::from(b)))
            })
            .expect("with_key");
    }

    println!(
        "dhat_hot_path: ran {ITERATIONS} with_key iterations on a {KEY_LEN}-byte key. \
         See dhat-heap.json for the allocation profile."
    );
}
