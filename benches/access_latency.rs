//! Phase 0.10.0 — single-key access latency benchmarks.
//!
//! Covers the hot path that ships in production:
//! - Vault construction (empty).
//! - `KeyVault::register` (one-shot, includes fragmentation).
//! - `KeyVault::with_key` (defragment + codex decode + callback).
//! - `KeyVault::rotate` (atomic swap).
//!
//! The targets to beat live in the Performance Contract:
//!
//! | Operation | Target |
//! |-----------|--------|
//! | Vault creation, empty | <100µs |
//! | Key access (defrag, no codex) | <500ns |
//! | Key access (defrag with codex) | <1µs |

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use key_vault::{DynamicCodex, KeyVaultBuilder, RawKey};

/// Sizes (in bytes) that exercise the common key-length regime.
/// 16/32/64 cover AES-128/AES-256 keys + typical MACs; 256 stretches
/// the fragmenter into multi-chunk territory.
const KEY_SIZES: &[usize] = &[16, 32, 64, 256];

fn fresh_key(len: usize) -> RawKey {
    let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
    RawKey::new(bytes)
}

fn bench_vault_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_construction");

    group.bench_function("default", |b| {
        b.iter(|| {
            let vault = KeyVaultBuilder::new().build();
            black_box(vault);
        });
    });

    group.bench_function("normalize_off", |b| {
        b.iter(|| {
            let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
            black_box(vault);
        });
    });

    group.bench_function("with_dynamic_codex", |b| {
        b.iter(|| {
            let codex = match DynamicCodex::new() {
                Ok(c) => c,
                Err(_) => return,
            };
            let vault = KeyVaultBuilder::new().with_codex(codex).build();
            black_box(vault);
        });
    });

    group.finish();
}

fn bench_register(c: &mut Criterion) {
    let mut group = c.benchmark_group("register");

    for &len in KEY_SIZES {
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::new("no_codex", len), &len, |b, &len| {
            b.iter_batched(
                || {
                    let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
                    (vault, fresh_key(len))
                },
                |(vault, key)| {
                    let handle = vault.register("k", key).expect("register");
                    black_box(handle);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_with_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("with_key");

    // Target: <500ns no-codex, <1µs with codex.
    for &len in KEY_SIZES {
        group.throughput(Throughput::Bytes(len as u64));

        group.bench_with_input(BenchmarkId::new("no_codex", len), &len, |b, &len| {
            let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
            let handle = vault.register("k", fresh_key(len)).expect("register");
            b.iter(|| {
                let sum = vault
                    .with_key(handle, |bytes| {
                        bytes
                            .iter()
                            .copied()
                            .fold(0u32, |a, b| a.wrapping_add(u32::from(b)))
                    })
                    .expect("with_key");
                black_box(sum);
            });
        });

        group.bench_with_input(BenchmarkId::new("with_codex", len), &len, |b, &len| {
            let codex = DynamicCodex::new().expect("codex");
            let vault = KeyVaultBuilder::new()
                .normalize_with_blake3(false)
                .with_codex(codex)
                .build();
            let handle = vault.register("k", fresh_key(len)).expect("register");
            b.iter(|| {
                let sum = vault
                    .with_key(handle, |bytes| {
                        bytes
                            .iter()
                            .copied()
                            .fold(0u32, |a, b| a.wrapping_add(u32::from(b)))
                    })
                    .expect("with_key");
                black_box(sum);
            });
        });
    }

    group.finish();
}

fn bench_rotate(c: &mut Criterion) {
    let mut group = c.benchmark_group("rotate");

    for &len in KEY_SIZES {
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::new("no_codex", len), &len, |b, &len| {
            let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
            let handle = vault.register("k", fresh_key(len)).expect("register");
            b.iter_batched(
                || fresh_key(len),
                |new_key| {
                    vault.rotate(handle, new_key).expect("rotate");
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_one_shot_fragment_defragment(c: &mut Criterion) {
    let mut group = c.benchmark_group("one_shot");

    for &len in KEY_SIZES {
        group.throughput(Throughput::Bytes(len as u64));

        group.bench_with_input(BenchmarkId::new("fragment", len), &len, |b, &len| {
            let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
            let key = fresh_key(len);
            b.iter(|| {
                let frags = vault.fragment(&key).expect("fragment");
                black_box(frags);
            });
        });

        group.bench_with_input(BenchmarkId::new("defragment", len), &len, |b, &len| {
            let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
            let key = fresh_key(len);
            let frags = vault.fragment(&key).expect("fragment");
            b.iter(|| {
                let recovered = vault.defragment(&frags).expect("defragment");
                black_box(recovered);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_vault_construction,
    bench_register,
    bench_with_key,
    bench_rotate,
    bench_one_shot_fragment_defragment,
);
criterion_main!(benches);
