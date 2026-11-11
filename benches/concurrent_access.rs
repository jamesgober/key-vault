//! Concurrent read scaling.
//!
//! Reader threads are started once per measurement and released together
//! by a barrier; each does a fixed number of `with_key` calls and the
//! measurement is the wall time from release to the last reader finishing.
//! Thread start-up is outside the measured window. (Before 1.2 this bench
//! spawned the threads inside every iteration and did 1,000 reads each, so
//! it mostly measured thread creation and could not show contention.)
//!
//! Two shapes, at 1 / 2 / 4 / 8 / 16 threads:
//!
//! - `same_key`: every thread reads one key (a signing or session key read
//!   by every request).
//! - `own_key`: each thread reads its own key.
//!
//! With no shared writes on the read path the two scale alike. Reported as
//! throughput (reads per second, all threads together).

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use key_vault::{KeyHandle, KeyVault, KeyVaultBuilder, RawKey};

const KEY_LEN: usize = 32;
const READS_PER_THREAD: u64 = 20_000;
const THREAD_COUNTS: &[usize] = &[1, 2, 4, 8, 16];

fn key(fill: u8) -> RawKey {
    RawKey::new(vec![fill; KEY_LEN])
}

/// Run `threads` readers, released together, each reading its handle
/// `reads` times; returns the time from release until all are done.
fn run_readers(vault: &KeyVault, handles: &[KeyHandle], reads: u64) -> Duration {
    let threads = handles.len();
    let start = Arc::new(Barrier::new(threads + 1));
    let joins: Vec<_> = handles
        .iter()
        .map(|&h| {
            let vault = vault.clone();
            let start = Arc::clone(&start);
            thread::spawn(move || {
                let _ = start.wait();
                let mut acc = 0u64;
                for _ in 0..reads {
                    acc =
                        acc.wrapping_add(vault.with_key(h, |k| u64::from(k[0])).expect("with_key"));
                }
                black_box(acc);
            })
        })
        .collect();
    let _ = start.wait();
    let t = Instant::now();
    for j in joins {
        j.join().expect("reader");
    }
    t.elapsed()
}

fn bench_concurrent_reads(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_reads");
    group.sample_size(10);
    let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
    let shared = vault.register("shared", key(1)).expect("register");
    let own: Vec<KeyHandle> = (0..THREAD_COUNTS[THREAD_COUNTS.len() - 1])
        .map(|i| vault.register(format!("own{i}"), key(2)).expect("register"))
        .collect();

    for &threads in THREAD_COUNTS {
        group.throughput(Throughput::Elements(threads as u64 * READS_PER_THREAD));
        let same = vec![shared; threads];
        group.bench_with_input(BenchmarkId::new("same_key", threads), &same, |b, hs| {
            b.iter_custom(|iters| {
                (0..iters)
                    .map(|_| run_readers(&vault, hs, READS_PER_THREAD))
                    .sum()
            });
        });
        let mine = own[..threads].to_vec();
        group.bench_with_input(BenchmarkId::new("own_key", threads), &mine, |b, hs| {
            b.iter_custom(|iters| {
                (0..iters)
                    .map(|_| run_readers(&vault, hs, READS_PER_THREAD))
                    .sum()
            });
        });
    }
    group.finish();
}

fn bench_reads_during_rotation(c: &mut Criterion) {
    // 4 readers on one key while another thread rotates it continuously.
    // Readers never wait for the writer; this shows what the rotations
    // cost them.
    let mut group = c.benchmark_group("reads_during_rotation");
    group.sample_size(10);
    group.throughput(Throughput::Elements(4 * READS_PER_THREAD));
    let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
    let handle = vault.register("rotating", key(1)).expect("register");
    group.bench_function("4_readers_1_rotator", |b| {
        b.iter_custom(|iters| {
            (0..iters)
                .map(|_| {
                    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let rotator = {
                        let (vault, stop) = (vault.clone(), Arc::clone(&stop));
                        thread::spawn(move || {
                            let mut i = 0u8;
                            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                                i = i.wrapping_add(1);
                                vault.rotate(handle, key(i)).expect("rotate");
                            }
                        })
                    };
                    let elapsed = run_readers(&vault, &[handle; 4], READS_PER_THREAD);
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    rotator.join().expect("rotator");
                    elapsed
                })
                .sum()
        });
    });
    group.finish();
}

criterion_group!(benches, bench_concurrent_reads, bench_reads_during_rotation);
criterion_main!(benches);
