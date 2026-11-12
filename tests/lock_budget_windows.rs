//! The Windows lock budget.
//!
//! A default Windows process can lock only about 44 pages (its minimum
//! working set is 200 KiB). In 1.1 the pool ran out after roughly a
//! thousand keys, and every key after that was stored in memory that could
//! be paged out, with no error. The crate now raises the process's
//! working-set size when `VirtualLock` runs out of quota. This test runs
//! in its own process, so it starts from the default working set.
#![cfg(windows)]
#![allow(clippy::unwrap_used, clippy::print_stdout)]

use key_vault::{KeyVaultBuilder, RawKey};

#[test]
fn five_thousand_keys_are_all_locked() {
    let vault = KeyVaultBuilder::new().build();
    let strict = KeyVaultBuilder::new().with_strict_locking(true).build();
    for i in 0..5000u32 {
        let _ = vault
            .register(format!("k{i}"), RawKey::new(vec![1; 32]))
            .unwrap();
    }
    for i in 0..500u32 {
        let _ = strict
            .register(format!("s{i}"), RawKey::new(vec![2; 32]))
            .unwrap();
    }
    let status = vault.memory_status();
    println!("{status:?}");
    assert!(status.all_locked(), "{} keys not locked", status.unlocked());
    assert!(strict.memory_status().all_locked());
}
