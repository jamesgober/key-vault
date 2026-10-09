//! The vault built without `std` (`--no-default-features`).
//!
//! The library is compiled `#![no_std]` here: spin locks instead of
//! `std::sync`, a `BTreeMap` registry without `arc-swap`, a per-call
//! scratch buffer instead of a thread-local, and a caller-supplied clock.
//! This test binary itself uses `std` only to run. CI runs it with
//! `cargo test --no-default-features --test no_std_vault`.

#![cfg(not(feature = "std"))]

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::sync::Arc;

use key_vault::{Clock, DynamicCodex, Error, KeyVaultBuilder, RawKey, SelfReferenceDecoy};

#[derive(Clone, Default)]
struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    fn advance(&self, secs: u64) {
        let _ = self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Duration {
        Duration::from_secs(self.0.load(Ordering::SeqCst))
    }
}

#[test]
fn core_vault_works_without_std() {
    let clock = ManualClock::default();
    let vault = KeyVaultBuilder::new()
        .normalize_with_blake3(false)
        .with_decoy(SelfReferenceDecoy)
        .with_codex(DynamicCodex::new().expect("codex"))
        .with_key_lockout(2, Duration::from_secs(60), Some(Duration::from_secs(30)))
        .with_master_key(RawKey::new(b"master credential".to_vec()))
        .with_master_unlock_backoff(Duration::from_secs(1), Duration::from_secs(8))
        .build_with_clock(clock.clone());

    let a = vault
        .register("a", RawKey::new((0u8..48).collect()))
        .expect("register");
    let b = vault
        .register("b", RawKey::new(vec![7u8; 32]))
        .expect("register");
    assert_eq!(
        vault.with_key(a, <[u8]>::to_vec).expect("with_key"),
        (0u8..48).collect::<Vec<u8>>()
    );
    vault.rotate(b, RawKey::new(vec![9u8; 16])).expect("rotate");
    assert_eq!(
        vault.with_key(b, <[u8]>::to_vec).expect("with_key"),
        vec![9u8; 16]
    );
    assert!(matches!(
        vault.register("a", RawKey::new(vec![1])),
        Err(Error::InvalidConfig(_))
    ));

    // Per-key lockout uses the supplied clock.
    vault.report_failure("a", None);
    vault.report_failure("a", None);
    assert!(vault.is_key_locked_out(a));
    assert!(matches!(vault.with_key(a, |_| ()), Err(Error::LockedOut)));
    assert!(vault.with_key(b, |_| ()).is_ok());
    clock.advance(30);
    assert!(!vault.is_key_locked_out(a));

    // So does the master backoff.
    assert!(vault.unlock_with_master(b"wrong").is_err());
    assert!(matches!(
        vault.unlock_with_master(b"master credential"),
        Err(Error::RateLimited { .. })
    ));
    clock.advance(1);
    vault
        .unlock_with_master(b"master credential")
        .expect("unlock");

    vault.unregister(a).expect("unregister");
    assert_eq!(vault.key_count(), 1);
}

#[test]
fn keyed_normalization_without_std() {
    let vault = KeyVaultBuilder::new()
        .with_keyed_normalization()
        .build_with_clock(ManualClock::default());
    let h = vault
        .register("k", RawKey::new(b"input".to_vec()))
        .expect("register");
    let out = vault.with_key(h, <[u8]>::to_vec).expect("with_key");
    assert_eq!(out.len(), 32);
    assert_ne!(out.as_slice(), blake3::hash(b"input").as_bytes());
}
