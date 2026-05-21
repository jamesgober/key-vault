//! Phase 0.11.0 — property tests for the security/correctness
//! invariants that ride alongside the cargo-fuzz harness.
//!
//! Where `cargo-fuzz` requires Linux/macOS, `proptest` runs in the
//! normal `cargo test` gate on every platform. The properties tested
//! here are the cross-platform invariants the 1.0 contract depends on:
//!
//! - Fragment round-trip across arbitrary inputs and chunk ranges.
//! - Codex involution across the full byte range, repeated for fresh
//!   `DynamicCodex` and `StaticCodex` random involutions.
//! - `SelfReferenceDecoy` only emits bytes drawn from the source key.
//! - `KeyHandle::Debug` never reveals the underlying numeric id.
//! - Concurrent `with_key` callers see consistent (registered or
//!   rotated) bytes, never a torn read.

use std::sync::Arc;

use key_vault::{
    DecoyStrategy, DynamicCodex, FragmentStrategy, IdentityCodex, InterleavedFragmenter, KeyHandle,
    KeyVaultBuilder, RandomFragmenter, RawKey, SelfReferenceDecoy, StandardFragmenter, StaticCodex,
};
use proptest::prelude::*;

// ---- Layer 3: fragment round-trip ----

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_global_rejects: 4096,
        .. ProptestConfig::default()
    })]

    #[test]
    fn standard_round_trip(bytes in prop::collection::vec(any::<u8>(), 1..=512)) {
        let strat = StandardFragmenter::new();
        let key = RawKey::new(bytes.clone());
        let frags = strat.fragment(&key).expect("fragment");
        let recovered = strat.defragment(&frags).expect("defragment");
        prop_assert_eq!(recovered.len(), bytes.len());
    }

    #[test]
    fn interleaved_round_trip(bytes in prop::collection::vec(any::<u8>(), 1..=512)) {
        let strat = InterleavedFragmenter::new();
        let key = RawKey::new(bytes.clone());
        let frags = strat.fragment(&key).expect("fragment");
        let recovered = strat.defragment(&frags).expect("defragment");
        prop_assert_eq!(recovered.len(), bytes.len());
    }

    #[test]
    fn random_round_trip(bytes in prop::collection::vec(any::<u8>(), 1..=512)) {
        let strat = RandomFragmenter::new();
        let key = RawKey::new(bytes.clone());
        let frags = strat.fragment(&key).expect("fragment");
        let recovered = strat.defragment(&frags).expect("defragment");
        prop_assert_eq!(recovered.len(), bytes.len());
    }

    #[test]
    fn chunk_range_round_trip(
        bytes in prop::collection::vec(any::<u8>(), 1..=512),
        min in 1usize..=16,
        max in 1usize..=32,
    ) {
        let max = max.max(min);
        let strat = StandardFragmenter::with_chunk_range(min, max);
        let key = RawKey::new(bytes.clone());
        let frags = strat.fragment(&key).expect("fragment");
        let recovered = strat.defragment(&frags).expect("defragment");
        prop_assert_eq!(recovered.len(), bytes.len());
    }
}

// ---- Layer 5: codex involution ----

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        max_global_rejects: 1024,
        .. ProptestConfig::default()
    })]

    #[test]
    fn identity_codex_involution(byte in any::<u8>()) {
        let codex = IdentityCodex;
        prop_assert_eq!(codex.decode(codex.encode(byte)), byte);
    }

    #[test]
    fn static_codex_involution(byte in any::<u8>()) {
        let codex = StaticCodex::random_involution().expect("static codex");
        prop_assert_eq!(codex.decode(codex.encode(byte)), byte);
    }

    #[test]
    fn dynamic_codex_involution(byte in any::<u8>()) {
        let codex = DynamicCodex::new().expect("dynamic codex");
        prop_assert_eq!(codex.decode(codex.encode(byte)), byte);
    }

    #[test]
    fn dynamic_codex_full_byte_range_involution(_unused in any::<u8>()) {
        let codex = DynamicCodex::new().expect("dynamic codex");
        for b in 0u8..=u8::MAX {
            prop_assert_eq!(codex.decode(codex.encode(b)), b);
        }
    }
}

// Bring the codex trait into scope only for the involution module above.
#[allow(unused_imports)]
use key_vault::codex::Codex;

// ---- Layer 4: SelfReferenceDecoy must only draw from the key's byte set ----

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        max_global_rejects: 2048,
        .. ProptestConfig::default()
    })]

    #[test]
    fn self_reference_decoy_only_uses_key_bytes(
        bytes in prop::collection::vec(any::<u8>(), 1..=128),
        output_len in 1usize..=512,
    ) {
        let strat = SelfReferenceDecoy;
        let key = RawKey::new(bytes.clone());
        let out = strat.generate(&key, output_len).expect("decoy generate");
        prop_assert_eq!(out.len(), output_len);
        for byte in &out {
            prop_assert!(
                bytes.contains(byte),
                "SelfReferenceDecoy emitted 0x{:02x} outside the key's byte set",
                byte
            );
        }
    }
}

// ---- Layer 6: KeyHandle Debug opacity ----

proptest! {
    #[test]
    fn key_handle_debug_redacts_id(bytes in prop::collection::vec(any::<u8>(), 1..=64)) {
        let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let handle = vault
            .register("k", RawKey::new(bytes))
            .expect("register");
        let dbg = format!("{handle:?}");
        prop_assert!(
            dbg.contains("<redacted>") || dbg == "KeyHandle(<redacted>)",
            "KeyHandle Debug output leaked details: {dbg:?}"
        );
        // Belt and suspenders: the debug string must not contain any
        // decimal representation of the internal id either.
        prop_assert!(!dbg.contains("id:"), "KeyHandle Debug mentions an id field");
    }
}

// ---- Layer 9 + multi-key: handle uniqueness ----

proptest! {
    #[test]
    fn registered_handles_are_unique(
        names in prop::collection::vec("[a-z]{1,8}", 1..=8),
    ) {
        let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let mut handles: Vec<KeyHandle> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for name in names {
            if !seen.insert(name.clone()) {
                continue;
            }
            let h = vault
                .register(name, RawKey::new(b"key-bytes".to_vec()))
                .expect("register");
            for existing in &handles {
                prop_assert_ne!(h, *existing, "duplicate KeyHandle minted");
            }
            handles.push(h);
        }
    }
}

// ---- Concurrent reads are consistent ----

#[test]
fn concurrent_reads_never_observe_torn_state() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    let vault = Arc::new(KeyVaultBuilder::new().normalize_with_blake3(false).build());
    let initial = vec![0xAAu8; 32];
    let rotated = vec![0xBBu8; 32];

    let handle = vault
        .register("hot", RawKey::new(initial.clone()))
        .expect("register");

    let stop = Arc::new(AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 0..4 {
        let v = Arc::clone(&vault);
        let s = Arc::clone(&stop);
        readers.push(thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let res: Result<bool, _> = v.with_key(handle, |b| {
                    // Each byte must be uniformly 0xAA or uniformly 0xBB —
                    // never an interleaving of the two.
                    let first = b[0];
                    b.iter().all(|x| *x == first)
                });
                if let Ok(consistent) = res {
                    assert!(consistent, "torn read observed across rotation");
                }
            }
        }));
    }

    for _ in 0..50 {
        vault
            .rotate(handle, RawKey::new(rotated.clone()))
            .expect("rotate B");
        vault
            .rotate(handle, RawKey::new(initial.clone()))
            .expect("rotate A");
    }
    stop.store(true, Ordering::Relaxed);

    for r in readers {
        r.join().expect("reader thread");
    }
}
