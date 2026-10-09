//! Races between registry writers.
//!
//! `register` used to check for a duplicate name on one snapshot of the
//! registry and insert into a later one, so two threads registering the
//! same name at the same time could both succeed. These tests start many
//! threads on the same name at once and check that exactly one wins.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Barrier};
use std::thread;

use key_vault::{Error, KeyVaultBuilder, RawKey};

const THREADS: usize = 8;
const ROUNDS: usize = 200;

#[test]
fn concurrent_register_with_same_name_inserts_exactly_once() {
    let vault = Arc::new(KeyVaultBuilder::new().normalize_with_blake3(false).build());
    let barrier = Arc::new(Barrier::new(THREADS));

    let workers: Vec<_> = (0..THREADS)
        .map(|t| {
            let vault = Arc::clone(&vault);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut wins = Vec::with_capacity(ROUNDS);
                for round in 0..ROUNDS {
                    let _ = barrier.wait();
                    let fill = u8::try_from(t).unwrap();
                    match vault.register(format!("dup-{round}"), RawKey::new(vec![fill; 32])) {
                        Ok(h) => wins.push((round, h)),
                        Err(Error::InvalidConfig(_)) => {}
                        Err(other) => panic!("unexpected error: {other:?}"),
                    }
                }
                wins
            })
        })
        .collect();

    let mut wins_per_round = vec![0usize; ROUNDS];
    for w in workers {
        for (round, _handle) in w.join().unwrap() {
            wins_per_round[round] += 1;
        }
    }

    for (round, wins) in wins_per_round.iter().enumerate() {
        assert_eq!(*wins, 1, "name dup-{round} was registered {wins} times");
    }
    assert_eq!(vault.key_count(), ROUNDS);
    for round in 0..ROUNDS {
        assert!(vault.handle_for_name(&format!("dup-{round}")).is_some());
    }
}

#[test]
fn concurrent_register_and_unregister_keep_names_unique() {
    // Each round: one thread unregisters the current holder of a name
    // while others try to register the same name. At every point at most
    // one key may carry the name.
    let vault = Arc::new(KeyVaultBuilder::new().normalize_with_blake3(false).build());
    let _first = vault
        .register("shared", RawKey::new(vec![0u8; 16]))
        .unwrap();
    let barrier = Arc::new(Barrier::new(THREADS));

    let workers: Vec<_> = (0..THREADS)
        .map(|t| {
            let vault = Arc::clone(&vault);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                for _ in 0..ROUNDS {
                    let _ = barrier.wait();
                    if t == 0 {
                        if let Some(h) = vault.handle_for_name("shared") {
                            let _ = vault.unregister(h);
                        }
                    } else {
                        let fill = u8::try_from(t).unwrap();
                        let _ = vault.register("shared", RawKey::new(vec![fill; 16]));
                    }
                    let _ = barrier.wait();
                    if t == 0 {
                        assert!(vault.key_count() <= 1, "two keys share one name");
                    }
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    assert!(vault.key_count() <= 1);
}
