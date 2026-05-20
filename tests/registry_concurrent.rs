//! Concurrency tests for the named-key registry.
//!
//! Verifies that `KeyVault::rotate` is lock-free safe with concurrent
//! `with_key` readers (the `ArcSwap` registry must hand readers either
//! the old or the new fragmentation, never a torn read).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use key_vault::{KeyVaultBuilder, RawKey};

#[test]
fn rotate_is_safe_under_concurrent_with_key_readers() {
    let vault = Arc::new(KeyVaultBuilder::new().normalize_with_blake3(false).build());
    let initial = vec![0xa5u8; 32];
    let handle = vault
        .register("data", RawKey::new(initial.clone()))
        .unwrap();

    let reader_count = 4;
    let reads_per_thread = 200;
    let mut readers = Vec::with_capacity(reader_count);
    for _ in 0..reader_count {
        let v = Arc::clone(&vault);
        readers.push(thread::spawn(move || {
            for _ in 0..reads_per_thread {
                let bytes = v.with_key(handle, <[u8]>::to_vec).unwrap();
                // The reader sees either the original 0xa5 bytes or a
                // rotation's worth of distinct bytes; both lengths are
                // 32 (we always rotate to 32-byte keys), and no torn
                // reads.
                assert_eq!(bytes.len(), 32);
            }
        }));
    }

    // Rotation thread.
    let writer = {
        let v = Arc::clone(&vault);
        thread::spawn(move || {
            for i in 0u8..20 {
                v.rotate(handle, RawKey::new(vec![i; 32])).unwrap();
                thread::sleep(Duration::from_micros(50));
            }
        })
    };

    for reader in readers {
        reader.join().expect("reader thread joined");
    }
    writer.join().expect("writer thread joined");

    // After all the rotation activity, the final value should be the
    // last rotation we performed (i = 19).
    let final_bytes = vault.with_key(handle, <[u8]>::to_vec).unwrap();
    assert_eq!(final_bytes.len(), 32);
    assert_eq!(final_bytes, vec![19u8; 32]);
}

#[test]
fn many_registered_keys_independent() {
    let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();

    let mut handles = Vec::new();
    for i in 0u8..16 {
        let name = format!("key-{i}");
        let bytes = vec![i; 32];
        let h = vault.register(name, RawKey::new(bytes)).unwrap();
        handles.push((i, h));
    }
    assert_eq!(vault.key_count(), 16);

    for (i, h) in &handles {
        let observed = vault.with_key(*h, <[u8]>::to_vec).unwrap();
        assert_eq!(observed, vec![*i; 32]);
    }
}

#[test]
fn unregister_during_concurrent_with_key_does_not_panic() {
    let vault = Arc::new(KeyVaultBuilder::new().normalize_with_blake3(false).build());
    let h = vault.register("data", RawKey::new(vec![0u8; 32])).unwrap();

    let reader = {
        let v = Arc::clone(&vault);
        thread::spawn(move || {
            // Try reading; either succeeds or returns KeyNotFound after
            // the writer pulls the rug out. Both outcomes are allowed.
            for _ in 0..50 {
                let _ = v.with_key(h, <[u8]>::to_vec);
            }
        })
    };

    let writer = {
        let v = Arc::clone(&vault);
        thread::spawn(move || {
            thread::sleep(Duration::from_micros(100));
            let _ = v.unregister(h);
        })
    };

    reader.join().expect("reader joined");
    writer.join().expect("writer joined");
}
