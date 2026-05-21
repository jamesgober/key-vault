//! Phase 0.10.0 — fragment strategy comparison.
//!
//! Direct head-to-head between `StandardFragmenter`,
//! `InterleavedFragmenter`, `RandomFragmenter`, and a representative
//! `LayeredFragmenter` composition. Strategies are driven through the
//! `FragmentStrategy` trait directly so the numbers measure the
//! strategy in isolation, not the vault's surrounding pipeline (which
//! `access_latency.rs` already covers for the vault default).

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use key_vault::{
    FragmentStrategy, InterleavedFragmenter, LayeredFragmenter, RandomFragmenter, RawKey,
    StandardFragmenter,
};
use std::sync::Arc;

fn layered() -> LayeredFragmenter {
    LayeredFragmenter::new(vec![
        Arc::new(StandardFragmenter::default()) as Arc<dyn FragmentStrategy>,
        Arc::new(InterleavedFragmenter::default()) as Arc<dyn FragmentStrategy>,
        Arc::new(RandomFragmenter::default()) as Arc<dyn FragmentStrategy>,
    ])
    .expect("layered fragmenter requires non-empty sub-strategies")
}

const KEY_SIZES: &[usize] = &[16, 32, 64, 256];

fn fresh_key(len: usize) -> RawKey {
    let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(13)).collect();
    RawKey::new(bytes)
}

fn bench_strategy<S: FragmentStrategy + 'static>(
    c: &mut Criterion,
    name: &str,
    build: impl Fn() -> S,
) {
    let mut group = c.benchmark_group(format!("fragment_strategy/{name}"));

    for &len in KEY_SIZES {
        group.throughput(Throughput::Bytes(len as u64));

        group.bench_with_input(BenchmarkId::new("fragment", len), &len, |b, &len| {
            let strat = build();
            let key = fresh_key(len);
            b.iter(|| {
                let frags = strat.fragment(&key).expect("fragment");
                black_box(frags);
            });
        });

        group.bench_with_input(BenchmarkId::new("defragment", len), &len, |b, &len| {
            let strat = build();
            let key = fresh_key(len);
            let frags = strat.fragment(&key).expect("fragment");
            b.iter(|| {
                let recovered = strat.defragment(&frags).expect("defragment");
                black_box(recovered);
            });
        });

        group.bench_with_input(BenchmarkId::new("round_trip", len), &len, |b, &len| {
            let strat = build();
            let key = fresh_key(len);
            b.iter(|| {
                let frags = strat.fragment(&key).expect("fragment");
                let recovered = strat.defragment(&frags).expect("defragment");
                black_box(recovered);
            });
        });
    }

    group.finish();
}

fn bench_standard(c: &mut Criterion) {
    bench_strategy(c, "standard", StandardFragmenter::default);
}

fn bench_interleaved(c: &mut Criterion) {
    bench_strategy(c, "interleaved", InterleavedFragmenter::default);
}

fn bench_random(c: &mut Criterion) {
    bench_strategy(c, "random", RandomFragmenter::default);
}

fn bench_layered(c: &mut Criterion) {
    bench_strategy(c, "layered", layered);
}

criterion_group!(
    benches,
    bench_standard,
    bench_interleaved,
    bench_random,
    bench_layered,
);
criterion_main!(benches);
