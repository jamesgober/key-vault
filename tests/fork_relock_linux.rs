//! Memory locks after `fork` (Linux).
//!
//! A child process does not inherit its parent's memory locks. The crate
//! registers a `pthread_atfork` handler and locks its pages again on the
//! child's next vault call, so a pre-fork server's workers keep their keys
//! out of swap. This test forks (from its own test binary, with no other
//! test running) and checks the child.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use key_vault::{KeyVaultBuilder, RawKey};

fn vmlck_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("VmLck:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|n| n.parse().ok())
        .unwrap()
}

#[test]
fn a_forked_child_locks_its_keys_again() {
    let vault = KeyVaultBuilder::new().build();
    let protected = KeyVaultBuilder::new().with_page_protection(true).build();
    let handles: Vec<_> = (0..500)
        .map(|i| {
            vault
                .register(format!("k{i}"), RawKey::new(vec![1; 32]))
                .unwrap()
        })
        .collect();
    let p = protected.register("p", RawKey::new(vec![2; 32])).unwrap();
    if !vault.memory_status().all_locked() || protected.is_memory_locked(p) != Some(true) {
        println!("this machine's lock limit is too low for the test");
        return;
    }
    let parent = vmlck_kb();

    // SAFETY: the child only reads files, uses the vault and exits with
    // `_exit`; this test binary runs no other test at the same time.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        let at_fork = vmlck_kb();
        let read = vault.with_key(handles[0], <[u8]>::len).unwrap_or(0);
        let after = vmlck_kb();
        let status = vault.memory_status();
        let protected_before = protected.is_memory_locked(p);
        let _ = protected.with_key(p, <[u8]>::len);
        let protected_after = protected.is_memory_locked(p);
        println!(
            "child: VmLck {at_fork} kB at fork, {after} kB after one read \
             (parent {parent} kB); {status:?}; protected key locked \
             {protected_before:?} before its first read, {protected_after:?} after"
        );
        let ok = read == 32
            && at_fork < parent
            && after * 2 >= parent
            && status.all_locked()
            && protected_before == Some(false)
            && protected_after == Some(true);
        // SAFETY: ends the child without running the parent's test
        // harness teardown.
        unsafe { libc::_exit(i32::from(!ok)) };
    }
    let mut status = 0;
    // SAFETY: `pid` is our child; `status` is a valid out-pointer.
    assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status), "child did not exit: {status}");
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "the child's keys were not locked again"
    );
    // The parent's own locks are untouched.
    assert!(vault.memory_status().all_locked());
}
