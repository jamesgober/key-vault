//! Phase 0.10.0 — codex overhead.
//!
//! Measures the per-operation cost of every codex implementation
//! through the vault hot path. The Performance Contract requires
//! `with_key` to stay under 1µs **with** codex applied, which is the
//! load-bearing comparison here.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use key_vault::{Codex, DynamicCodex, IdentityCodex, KeyVaultBuilder, RawKey, StaticCodex};

const KEY_SIZES: &[usize] = &[16, 32, 64, 256];

fn fresh_key(len: usize) -> RawKey {
    let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(11)).collect();
    RawKey::new(bytes)
}

fn bench_codex<C: Codex + 'static>(c: &mut Criterion, name: &str, build: impl Fn() -> C) {
    let mut group = c.benchmark_group(format!("codex/{name}"));

    for &len in KEY_SIZES {
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::new("with_key", len), &len, |b, &len| {
            let vault = KeyVaultBuilder::new()
                .normalize_with_blake3(false)
                .with_codex(build())
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

fn bench_no_codex_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("codex/none");
    for &len in KEY_SIZES {
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::new("with_key", len), &len, |b, &len| {
            let vault = KeyVaultBuilder::new().normalize_with_blake3(false).build();
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

fn bench_identity(c: &mut Criterion) {
    bench_codex(c, "identity", IdentityCodex::default);
}

fn bench_static_random_involution(c: &mut Criterion) {
    bench_codex(c, "static_random_involution", || {
        StaticCodex::random_involution().expect("static codex")
    });
}

fn bench_dynamic(c: &mut Criterion) {
    bench_codex(c, "dynamic", || DynamicCodex::new().expect("dynamic codex"));
}

criterion_group!(
    benches,
    bench_no_codex_baseline,
    bench_identity,
    bench_static_random_involution,
    bench_dynamic,
);
criterion_main!(benches);
