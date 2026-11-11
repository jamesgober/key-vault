//! Page-lock failures at the process's lock limit (Linux).
//!
//! The test lowers `RLIMIT_MEMLOCK` for this process (its own test binary,
//! so no other test shares the limit), fills the vault until a key cannot
//! be locked, and checks that the failure is reported, that strict
//! locking refuses the key, and that raising the limit again lets keys be
//! locked, including keys placed on pool pages that failed before.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use key_vault::{
    AccessContext, Error, FailureContext, KeyVaultBuilder, MemoryLockContext, RawKey,
    SecurityMonitor, ThresholdContext,
};

fn vmlck_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("VmLck:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|n| n.parse().ok())
        .unwrap()
}

/// Set the soft limit (capped at the hard one). Returns the old soft limit.
fn set_soft_limit(bytes: u64) -> u64 {
    let mut r = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `r` is a valid out-pointer.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &raw mut r) },
        0
    );
    let old = r.rlim_cur;
    r.rlim_cur = bytes.min(r.rlim_max);
    // SAFETY: `r` is a valid rlimit with `rlim_cur <= rlim_max`.
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const r) },
        0
    );
    old
}

#[derive(Default)]
struct LockMonitor {
    failures: AtomicUsize,
    refused: AtomicUsize,
}

impl SecurityMonitor for LockMonitor {
    fn on_decryption_failure(&self, _: &FailureContext) {}
    fn on_anomalous_access(&self, _: &AccessContext) {}
    fn on_threshold_breach(&self, _: &ThresholdContext) {}
    fn on_memory_lock_failure(&self, ctx: &MemoryLockContext) {
        let _ = self.failures.fetch_add(1, Ordering::SeqCst);
        if ctx.refused {
            let _ = self.refused.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn key() -> RawKey {
    // 600 bytes: many small chunks in the pool, and a layout block.
    RawKey::new(vec![9; 600])
}

#[test]
fn lock_failures_are_reported_refused_when_strict_and_retried() {
    let monitor = Arc::new(LockMonitor::default());
    let vault = KeyVaultBuilder::new()
        .normalize_with_blake3(false)
        .with_monitor(Arc::clone(&monitor) as Arc<dyn SecurityMonitor>)
        .build();
    let strict = KeyVaultBuilder::new()
        .normalize_with_blake3(false)
        .with_strict_locking(true)
        .with_monitor(Arc::clone(&monitor) as Arc<dyn SecurityMonitor>)
        .build();

    // Room for a few more pages than are locked now.
    let original = set_soft_limit((vmlck_kb() + 16) * 1024);
    let mut handles = Vec::new();
    let mut unlocked_at = None;
    for i in 0..20_000 {
        let h = vault.register(format!("k{i}"), key()).unwrap();
        handles.push(h);
        if vault.is_memory_locked(h) == Some(false) {
            unlocked_at = Some(i);
            break;
        }
    }
    let Some(unlocked_at) = unlocked_at else {
        // Root, or CAP_IPC_LOCK: the limit does not apply.
        println!("lock limit not enforced for this process; nothing to test");
        let _ = set_soft_limit(original);
        return;
    };
    // A few more keys at the limit.
    for i in 0..50 {
        handles.push(vault.register(format!("more{i}"), key()).unwrap());
    }
    let status = vault.memory_status();
    println!("at the limit after {unlocked_at} keys: {status:?}");
    assert!(status.unlocked() > 0);
    assert!(!status.all_locked());
    // Reported once for the run of failures, not once per key.
    assert_eq!(monitor.failures.load(Ordering::SeqCst), 1);

    // Strict locking refuses the key and stores nothing.
    let refused = strict.register("strict", key());
    assert!(
        matches!(refused, Err(Error::MemoryLock(_))),
        "strict register at the limit returned {refused:?}"
    );
    assert_eq!(strict.key_count(), 0);
    assert_eq!(monitor.refused.load(Ordering::SeqCst), 1);

    // Raise the limit: strict registration works again at once.
    let _ = set_soft_limit(64 << 20);
    let h = strict.register("strict", key()).unwrap();
    assert_eq!(strict.is_memory_locked(h), Some(true));
    assert_eq!(strict.with_key(h, <[u8]>::len).unwrap(), 600);

    // Free keys whose blocks sit on pages that failed to lock, register
    // new ones in their place: the pool retries those pages, so the new
    // keys (and the old ones sharing the pages) end up locked.
    let before = vault.memory_status();
    for &h in &handles[..handles.len() / 2] {
        vault.unregister(h).unwrap();
    }
    let mut fresh = Vec::new();
    for i in 0..(handles.len() / 2) {
        fresh.push(vault.register(format!("n{i}"), key()).unwrap());
    }
    let after = vault.memory_status();
    println!("before raising: {before:?}; after re-registering: {after:?}");
    assert!(
        after.all_locked(),
        "keys still unlocked after raising the limit: {after:?}"
    );
    for h in fresh {
        assert_eq!(vault.is_memory_locked(h), Some(true));
    }
    let _ = set_soft_limit(original);
}
