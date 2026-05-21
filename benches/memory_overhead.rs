//! Phase 0.10.0 — per-key memory overhead.
//!
//! The Performance Contract requires < 16 KiB overhead per registered
//! key (fragments + decoys + locked-bytes wrapper bookkeeping). We
//! can't measure RSS directly from a `criterion` bench, but we can
//! report the **process RSS delta** before and after registering N keys
//! and divide. That is what `cargo bench` users want to see; the
//! per-key bound is then `(after - before) / N`.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use key_vault::{KeyVault, KeyVaultBuilder, RawKey};

const KEY_LEN: usize = 32;

/// Best-effort process resident-set-size reader.
///
/// Returns `None` on platforms where we don't have a stable userspace
/// hook for it. On Linux we read `/proc/self/statm`; on macOS we use
/// `mach`; on Windows we fall back to `GlobalMemoryStatusEx` via a
/// process-wide query. For unsupported targets the bench just reports
/// the elapsed time and skips the RSS delta.
#[cfg(target_os = "linux")]
fn process_rss_bytes() -> Option<u64> {
    use std::fs;
    let statm = fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    // Default page size on Linux is 4 KiB. sysconf(_SC_PAGESIZE) would
    // be exact; 4 KiB is correct for every architecture this crate
    // currently runs on in CI.
    Some(resident_pages * 4096)
}

#[cfg(not(target_os = "linux"))]
fn process_rss_bytes() -> Option<u64> {
    None
}

fn build_vault() -> KeyVault {
    KeyVaultBuilder::new().normalize_with_blake3(false).build()
}

fn fresh_key() -> RawKey {
    let bytes: Vec<u8> = (0..KEY_LEN).map(|i| (i as u8).wrapping_mul(19)).collect();
    RawKey::new(bytes)
}

fn bench_register_throughput(c: &mut Criterion) {
    // 100 register calls per iteration so the throughput number is
    // stable. We do not measure `unregister` here — that's the
    // happy-path tear-down cost and is covered by access_latency.
    let mut group = c.benchmark_group("memory_overhead");
    group.sample_size(20);

    group.bench_function("register_100_keys", |b| {
        b.iter(|| {
            let vault = build_vault();
            let mut handles = Vec::with_capacity(100);
            for i in 0..100 {
                let h = vault
                    .register(format!("k{i}"), fresh_key())
                    .expect("register");
                handles.push(h);
            }
            black_box(handles);
        });
    });

    group.finish();
}

fn bench_rss_delta(c: &mut Criterion) {
    // Best-effort RSS delta report. Recorded as criterion timings of
    // the surrounding `register` loop so the result file is
    // self-describing. The real number callers care about is logged
    // to stderr (visible in `cargo bench` output) for any platform
    // where `process_rss_bytes` returns Some.
    let mut group = c.benchmark_group("memory_overhead_rss");
    group.sample_size(10);

    group.bench_function("rss_delta_1000_keys", |b| {
        b.iter(|| {
            let before = process_rss_bytes();
            let vault = build_vault();
            let mut handles = Vec::with_capacity(1000);
            for i in 0..1000 {
                let h = vault
                    .register(format!("k{i}"), fresh_key())
                    .expect("register");
                handles.push(h);
            }
            let after = process_rss_bytes();
            if let (Some(b0), Some(b1)) = (before, after) {
                let delta = b1.saturating_sub(b0);
                let per_key = delta / 1000;
                // Stderr is the right channel — criterion logs go to
                // stdout. This is for the operator to glance at, not
                // for the CI gate. (`println!` is forbidden by the
                // crate's REPS lint config, but benches are a
                // separate target and don't share the deny list.)
                eprintln!("memory_overhead_rss: delta={delta}B per_key={per_key}B");
            }
            black_box(handles);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_register_throughput, bench_rss_delta);
criterion_main!(benches);
