//! Integration tests for the Phase 0.3 fragmentation pipeline.
//!
//! These exercise the public surface from outside the crate, which is what
//! downstream consumers (e.g. `crypt-io`) will see. `RawKey` deliberately
//! does not expose its bytes to outside callers, so these tests verify
//! observable properties (length, error-freeness, chunk-count variability)
//! rather than byte equality — byte-level round-trip is covered by the
//! in-crate unit tests in `src/fragment/standard.rs` and `src/vault/mod.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use key_vault::{KeyVault, KeyVaultBuilder, RawKey};

#[test]
fn fragment_then_defragment_normalized_returns_thirty_two_bytes() {
    let vault: KeyVault = KeyVaultBuilder::new().build(); // normalization on
    let raw = RawKey::new(b"some user-supplied key material".to_vec());
    let frags = vault.fragment(&raw).unwrap();
    let recovered = vault.defragment(&frags).unwrap();
    // With BLAKE3 normalization on, the output is always 32 bytes.
    assert_eq!(recovered.len(), 32);
}

#[test]
fn fragment_then_defragment_without_normalization_preserves_length() {
    let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
    let original: Vec<u8> = (0u8..128).collect();
    let raw = RawKey::new(original.clone());
    let frags = vault.fragment(&raw).unwrap();
    let recovered = vault.defragment(&frags).unwrap();
    assert_eq!(recovered.len(), original.len());
}

#[test]
fn two_consecutive_fragmentations_do_not_all_share_chunk_counts() {
    let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
    let raw = RawKey::new((0u8..32).collect());

    let mut all_same = 0;
    for _ in 0..16 {
        let a = vault.fragment(&raw).unwrap();
        let b = vault.fragment(&raw).unwrap();
        if a.chunk_count() == b.chunk_count() {
            all_same += 1;
        }
    }
    assert!(
        all_same < 16,
        "all 16 pairs produced identical chunk counts \
         (broken randomness)"
    );
}

#[test]
fn large_key_round_trips_through_public_api() {
    let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
    let bytes: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    let raw = RawKey::new(bytes);
    let frags = vault.fragment(&raw).unwrap();
    let recovered = vault.defragment(&frags).unwrap();
    assert_eq!(recovered.len(), 4096);
}

#[test]
fn vault_is_send_and_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<KeyVault>();
    assert_sync::<KeyVault>();
}

#[test]
fn empty_key_is_rejected() {
    let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
    let err = vault.fragment(&RawKey::new(Vec::new())).unwrap_err();
    // The exact variant is part of the public API surface.
    let display = format!("{err}");
    assert!(display.contains("fragment"));
}
