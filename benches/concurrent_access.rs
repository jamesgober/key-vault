//! Phase 0.10.0 — concurrent read scalability.
//!
//! The Performance Contract requires that concurrent reads on the same
//! handle are **lock-free, no degradation**. We measure aggregate
//! throughput at 1 / 4 / 16 / 64 threads to verify the `ArcSwap`-backed
//! registry doesn't introduce coordination overhead.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use key_vault::{KeyVault, KeyVaultBuilder, RawKey};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

const KEY_LEN: usize = 32;
const READS_PER_THREAD: u64 = 1_000;
const THREAD_COUNTS: &[usize] = &[1, 4, 16, 64];

fn build_vault() -> (Arc<KeyVault>, key_vault::KeyHandle) {
    let vault = Arc::new(KeyVaultBuilder::new().normalize_with_blake3(false).build());
    let key_bytes: Vec<u8> = (0..KEY_LEN).map(|i| (i as u8).wrapping_mul(7)).collect();
    let handle = vault
        .register("shared", RawKey::new(key_bytes))
        .expect("register");
    (vault, handle)
}

fn bench_concurrent_reads(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_reads");
    group.sample_size(20);

    for &threads in THREAD_COUNTS {
        group.throughput(Throughput::Elements((threads as u64) * READS_PER_THREAD));
        group.bench_with_input(
            BenchmarkId::from_parameter(threads),
            &threads,
            |b, &threads| {
                let (vault, handle) = build_vault();
                b.iter(|| {
                    let stop = Arc::new(AtomicBool::new(false));
                    let mut handles = Vec::with_capacity(threads);
                    for _ in 0..threads {
                        let vault = Arc::clone(&vault);
                        let stop = Arc::clone(&stop);
                        handles.push(thread::spawn(move || {
                            let mut acc: u64 = 0;
                            for _ in 0..READS_PER_THREAD {
                                if stop.load(Ordering::Relaxed) {
                                    break;
                                }
                                let sum: u64 = vault
                                    .with_key(handle, |bytes| {
                                        bytes.iter().copied().map(u64::from).sum()
                                    })
                                    .expect("with_key");
                                acc = acc.wrapping_add(sum);
                            }
                            acc
                        }));
                    }
                    let mut total: u64 = 0;
                    for h in handles {
                        total = total.wrapping_add(h.join().expect("thread"));
                    }
                    black_box(total);
                });
            },
        );
    }

    group.finish();
}

fn bench_reads_during_rotation(c: &mut Criterion) {
    // 4 reader threads contend with 1 rotator thread to verify that
    // ArcSwap::rcu doesn't stall readers.
    let mut group = c.benchmark_group("reads_during_rotation");
    group.sample_size(10);

    group.bench_function("4_readers_1_rotator", |b| {
        b.iter(|| {
            let (vault, handle) = build_vault();
            let stop = Arc::new(AtomicBool::new(false));

            let mut reader_handles = Vec::new();
            for _ in 0..4 {
                let vault = Arc::clone(&vault);
                let stop = Arc::clone(&stop);
                reader_handles.push(thread::spawn(move || {
                    let mut acc: u64 = 0;
                    let mut reads: u64 = 0;
                    while !stop.load(Ordering::Relaxed) {
                        let sum: u64 = vault
                            .with_key(handle, |bytes| bytes.iter().copied().map(u64::from).sum())
                            .expect("with_key");
                        acc = acc.wrapping_add(sum);
                        reads += 1;
                        if reads >= 500 {
                            break;
                        }
                    }
                    acc
                }));
            }

            // Rotate the key 10 times while readers hammer it.
            for i in 0..10u8 {
                let bytes: Vec<u8> = (0..KEY_LEN).map(|j| (j as u8) ^ i).collect();
                vault.rotate(handle, RawKey::new(bytes)).expect("rotate");
            }
            stop.store(true, Ordering::Relaxed);

            let mut total: u64 = 0;
            for h in reader_handles {
                total = total.wrapping_add(h.join().expect("thread"));
            }
            black_box(total);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_concurrent_reads, bench_reads_during_rotation);
criterion_main!(benches);
