# key-vault fuzz harness

`cargo-fuzz` workspace for the 1.0 nuclear-proof contract. Every input
surface the vault exposes has a dedicated target. Targets:

| Target | What it fuzzes |
|--------|----------------|
| `fuzz_fragment_standard` | `StandardFragmenter::fragment` + `defragment` round-trip across arbitrary key bytes |
| `fuzz_fragment_interleaved` | `InterleavedFragmenter` round-trip |
| `fuzz_fragment_random` | `RandomFragmenter` round-trip |
| `fuzz_fragment_layered` | `LayeredFragmenter` (3-way composition) round-trip |
| `fuzz_decoy_strategies` | All three decoy strategies — output length matches request, no panic on arbitrary key + length combos |
| `fuzz_codex_involution` | Every codex satisfies `decode(encode(b)) == b` for every byte over arbitrary inputs |
| `fuzz_vault_end_to_end` | Driven sequence of `register` / `with_key` / `rotate` / `unregister` calls via `arbitrary` |

## Running

`cargo-fuzz` requires Linux or macOS (libFuzzer). On Windows use WSL or
a Linux runner. Run a single target:

```bash
cargo +nightly fuzz run fuzz_fragment_standard
```

Or for a fixed duration (the roadmap requires **1 CPU-hour per target**
for the 1.0 sign-off):

```bash
cargo +nightly fuzz run fuzz_fragment_standard -- -max_total_time=3600
```

Corpus inputs live under `fuzz/corpus/<target>/` and crash inputs
under `fuzz/artifacts/<target>/`. The latter is gitignored; commit the
corpus so future runs start from a warm set.

## Triage

Any panic, infinite loop, or OOM from libFuzzer is a contract
violation. The fix policy is documented in `.dev/ROADMAP.md` Phase
0.11.0:

- Panic → return `Result<_, Error>` instead.
- Infinite loop → add an iteration cap proportional to input length.
- OOM → cap the input size or refactor to bounded allocation.

Regression tests for any crash input land under `tests/` next to the
existing integration suites so they re-fire on every `cargo test`.
