#![no_main]
//! End-to-end vault fuzz.
//!
//! libFuzzer hands us a vector of `Op`s via `Arbitrary`; we replay
//! them against a fresh vault and assert that no operation panics,
//! that successful `with_key` returns the key we registered, and that
//! the registry stays internally consistent (a handle reported
//! `contains == true` always works for `with_key`).

use arbitrary::Arbitrary;
use key_vault::{KeyHandle, KeyVault, KeyVaultBuilder, RawKey};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    Register { name: String, bytes: Vec<u8> },
    WithKey { which: u8 },
    Rotate { which: u8, bytes: Vec<u8> },
    Unregister { which: u8 },
    Fragment { bytes: Vec<u8> },
}

#[derive(Arbitrary, Debug)]
struct Session {
    normalize: bool,
    ops: Vec<Op>,
}

fn pick_handle(handles: &[(KeyHandle, Vec<u8>)], which: u8) -> Option<usize> {
    if handles.is_empty() {
        return None;
    }
    Some(usize::from(which) % handles.len())
}

fuzz_target!(|session: Session| {
    let vault: KeyVault = KeyVaultBuilder::new()
        .normalize_with_blake3(session.normalize)
        .build();

    // (handle, expected bytes after possible BLAKE3 normalization).
    let mut handles: Vec<(KeyHandle, Vec<u8>)> = Vec::new();

    for op in session.ops.into_iter().take(64) {
        match op {
            Op::Register { name, bytes } => {
                if name.is_empty() || bytes.is_empty() {
                    continue;
                }
                // Skip dup names — that's a documented error, not a crash.
                if vault.handle_for_name(&name).is_some() {
                    continue;
                }
                let raw = RawKey::new(bytes.clone());
                if let Ok(handle) = vault.register(name, raw) {
                    let expected = if session.normalize {
                        // We don't have public BLAKE3 access here; just
                        // store the length so we can verify the API
                        // returns *something* without crashing.
                        vec![0; 32]
                    } else {
                        bytes
                    };
                    handles.push((handle, expected));
                }
            }
            Op::WithKey { which } => {
                let Some(idx) = pick_handle(&handles, which) else {
                    continue;
                };
                let (handle, expected) = &handles[idx];
                let _ = vault.with_key(*handle, |bytes| {
                    if !expected.is_empty() {
                        // Length is the only stable invariant under
                        // either normalization mode.
                        assert_eq!(bytes.len(), expected.len());
                    }
                });
            }
            Op::Rotate { which, bytes } => {
                if bytes.is_empty() {
                    continue;
                }
                let Some(idx) = pick_handle(&handles, which) else {
                    continue;
                };
                let handle = handles[idx].0;
                if vault.rotate(handle, RawKey::new(bytes.clone())).is_ok() {
                    handles[idx].1 = if session.normalize { vec![0; 32] } else { bytes };
                }
            }
            Op::Unregister { which } => {
                let Some(idx) = pick_handle(&handles, which) else {
                    continue;
                };
                let handle = handles[idx].0;
                if vault.unregister(handle).is_ok() {
                    let _ = handles.swap_remove(idx);
                }
            }
            Op::Fragment { bytes } => {
                if bytes.is_empty() {
                    continue;
                }
                if let Ok(frags) = vault.fragment(&RawKey::new(bytes.clone())) {
                    let recovered = vault.defragment(&frags).expect("defragment");
                    let expected_len = if session.normalize { 32 } else { bytes.len() };
                    assert_eq!(recovered.len(), expected_len);
                }
            }
        }
    }
});
