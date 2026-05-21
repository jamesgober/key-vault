//! Phase 0.10.0 — decoy strategy comparison.
//!
//! Measures the per-operation cost of each decoy strategy through the
//! full vault stack (Layer 2 + 3 + 4 + 7), so the numbers reflect what
//! production callers see, not microbench of `DecoyStrategy::generate`
//! in isolation.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use key_vault::{
    DecoyStrategy, KeyDerivedDecoy, KeyVaultBuilder, RandomDecoy, RawKey, SelfReferenceDecoy,
};

const KEY_SIZES: &[usize] = &[16, 32, 64, 256];

fn fresh_key(len: usize) -> RawKey {
    let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(17)).collect();
    RawKey::new(bytes)
}

fn bench_decoy<D: DecoyStrategy + 'static>(c: &mut Criterion, name: &str, build: impl Fn() -> D) {
    let mut group = c.benchmark_group(format!("decoy/{name}"));

    for &len in KEY_SIZES {
        group.throughput(Throughput::Bytes(len as u64));

        group.bench_with_input(BenchmarkId::new("register", len), &len, |b, &len| {
            b.iter_batched(
                || {
                    let vault = KeyVaultBuilder::new()
                        .normalize_with_blake3(false)
                        .with_decoy(build())
                        .build();
                    (vault, fresh_key(len))
                },
                |(vault, key)| {
                    let handle = vault.register("k", key).expect("register");
                    black_box(handle);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("with_key", len), &len, |b, &len| {
            let vault = KeyVaultBuilder::new()
                .normalize_with_blake3(false)
                .with_decoy(build())
                .build();
            let handle = vault.register("k", fresh_key(len)).expect("register");
            b.iter(|| {
                let sum = vault
                    .with_key(handle, |bytes| {
                        bytes.iter().copied().map(u32::from).sum::<u32>()
                    })
                    .expect("with_key");
                black_box(sum);
            });
        });
    }

    group.finish();
}

fn bench_random_decoy(c: &mut Criterion) {
    bench_decoy(c, "random", || RandomDecoy);
}

fn bench_self_ref_decoy(c: &mut Criterion) {
    bench_decoy(c, "self_reference", || SelfReferenceDecoy);
}

fn bench_key_derived_decoy(c: &mut Criterion) {
    bench_decoy(c, "key_derived", || KeyDerivedDecoy);
}

criterion_group!(
    benches,
    bench_random_decoy,
    bench_self_ref_decoy,
    bench_key_derived_decoy,
);
criterion_main!(benches);
