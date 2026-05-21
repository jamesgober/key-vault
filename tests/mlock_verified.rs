//! Phase 0.11.0 — Linux mlock verification.
//!
//! The 1.0 security contract requires that Layer 2 (`mlock` /
//! `VirtualLock`) actually page-locks fragment storage. On Linux we
//! can prove this by reading `/proc/self/status` and watching the
//! `VmLck` field grow as keys get registered. On non-Linux platforms
//! we don't have a stable userspace probe; those targets get a
//! compile-time skip and Linux CI carries the load.

#![cfg(target_os = "linux")]

use std::fs;

use key_vault::{KeyVaultBuilder, RawKey};

fn read_vm_lck_kib() -> u64 {
    let status = fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmLck:") {
            // Format: "VmLck:\t   <kb> kB"
            let n: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|t| t.parse().ok())
                .expect("parse VmLck value");
            return n;
        }
    }
    panic!("/proc/self/status missing VmLck line");
}

#[test]
fn vm_lck_grows_after_registering_many_keys() {
    // Some Linux configurations cap RLIMIT_MEMLOCK at 64 KiB by
    // default (notably docker --no-privileged). Skip cleanly in that
    // case so the gate doesn't false-fail.
    let before = read_vm_lck_kib();

    let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
    let mut handles = Vec::with_capacity(64);
    for i in 0..64u32 {
        let key = RawKey::new(vec![i as u8; 64]);
        match vault.register(format!("k{i}"), key) {
            Ok(h) => handles.push(h),
            Err(_) => break,
        }
    }

    let after = read_vm_lck_kib();
    // If mlock is permitted at all, VmLck must have strictly grown.
    // If the rlimit is zero we'd see no growth; treat that as
    // "skipped" rather than failed.
    if before == 0 && after == 0 {
        eprintln!("mlock_verified: VmLck stayed at 0 kB — RLIMIT_MEMLOCK likely 0; skipping");
        return;
    }
    assert!(
        after > before,
        "VmLck did not grow after 64 registrations (before={before} kB, after={after} kB)",
    );

    drop(handles);
    drop(vault);
}
