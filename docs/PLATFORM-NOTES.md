<h1 align="center">
    <b>key-vault — Platform Notes</b>
    <br>
    <sub><sup>LINUX · MACOS · WINDOWS SPECIFICS</sup></sub>
</h1>

<p align="center">
    <i>What each supported target needs, what each handles differently, what each cannot do.</i>
</p>

---

## Supported targets

| Target triple | Tier | Status |
|---------------|------|--------|
| `x86_64-unknown-linux-gnu` | 1 | Full CI: stable + 1.85, fmt + clippy + test + doc + supply-chain |
| `x86_64-pc-windows-msvc` | 1 | Full CI: stable + 1.85, fmt + clippy + test + doc |
| `x86_64-apple-darwin` | 1 | Full CI: stable + 1.85, fmt + clippy + test + doc |
| `aarch64-apple-darwin` | 1 | Full CI: stable + 1.85, fmt + clippy + test + doc |
| `aarch64-unknown-linux-gnu` | 2 | Compiles on the matrix; no runtime CI runner available |
| `thumbv7em-none-eabihf` (`no_std`) | 2 | CI builds and lints the library without `std` on stable + 1.85; the vault's `no_std` code paths run on the Linux host |
| `x86_64-unknown-freebsd` | 3 | Checked locally before releases; no CI runner |

Tier-1 targets run the full test + bench suite on every push. Tier-2
compiles but does not run tests under CI; promote when runner capacity
allows.

---

## Layer 2 (page locking and dump exclusion) — per platform

Every OS limits how much memory a process may lock. A key registered
after that limit is reached is still stored, in memory the OS may write
to swap. Since 1.2 this is visible and can be refused:

- `KeyVault::memory_status()` counts registered keys whose memory is
  fully page-locked (and fully excluded from dumps);
  `KeyVault::is_memory_locked(handle)` and `Fragments::is_locked()`
  answer for one key. These read the current state, so a page locked by
  a later retry reads as locked.
- `SecurityMonitor::on_memory_lock_failure` fires when a key is stored
  unlocked (once per run of failures).
- `KeyVaultBuilder::with_strict_locking(true)` makes `register` and
  `rotate` fail with `Error::MemoryLock` instead of storing the key
  unlocked, and `with_key` fail the same way if its scratch buffer
  cannot be locked.
- The page pool records which of its pages are locked, hands out blocks
  on locked pages first, and retries pages whose lock failed, so raising
  the limit while the process runs helps keys registered afterwards
  (before 1.2 a pool page that failed to lock stayed unlocked for the
  life of the process).

A 32-byte key uses about 0.04 pages of pool memory (fragments and
layout), so a budget of N locked pages holds roughly 25 * N keys, fewer
with large keys, decoys, or page protection (one page or more per key).

### Linux

- `libc::mlock` on construction and `libc::munlock` on drop, applied to
  whole pages through a per-page reference count (1.0.2): a page is
  unlocked only when the last live buffer on it is dropped. Both
  syscalls are best-effort: once the process's locked memory reaches
  `RLIMIT_MEMLOCK` (8 MiB by default on many distributions, 64 KiB in
  many container runtimes), the call fails and the key is stored
  unlocked. `KeyVault::memory_status()` reports it, and strict locking
  refuses it (see above). The buffer still works as a plain
  zero-on-drop wrapper, so no key material leaks, just no swap
  protection. Check the limit with `ulimit -l` (in kB) or
  `grep "locked memory" /proc/<pid>/limits`.
- The `tests/mlock_verified.rs` integration test reads
  `/proc/self/status` `VmLck` before and after registering 64 keys to
  prove the syscall is being honoured. It self-skips when
  `VmLck` stays at zero (= unprivileged sandbox).
- Recommended ops setup: grant the running process
  `CAP_IPC_LOCK` capability, or raise `RLIMIT_MEMLOCK` via systemd's
  `LimitMEMLOCK=infinity`. For container workloads add
  `--ulimit memlock=-1` (Docker) or the equivalent
  `securityContext.capabilities.add: ["IPC_LOCK"]` (Kubernetes).
- Since 1.1, buffers up to 2048 bytes come from a pool of `mmap`'d
  pages that are locked and excluded once and kept for the life of the
  process; larger buffers use the heap and the reference count above.
- Dump exclusion (1.1): `madvise(MADV_DONTDUMP)` on every page that
  holds key material (pool pages when mapped, heap pages through the
  reference count, with `MADV_DODUMP` when the last buffer on a heap
  page is gone). Visible as
  `dd` in the mapping's `VmFlags` in `/proc/<pid>/smaps`; the unit
  tests check it. Core dumps written by the kernel (and by
  `systemd-coredump`, which reads them from the kernel) leave these
  pages out. `gcore` and debuggers read memory directly and do not.
- Android uses the same calls. FreeBSD and DragonFly use
  `MADV_NOCORE` / `MADV_CORE`.
- `fork`: a child process does not inherit memory locks (POSIX; Linux,
  macOS and the BSDs all behave this way), so before 1.2 a pre-fork
  server's workers held every key unlocked while the crate believed
  them locked. Since 1.2 the crate registers a `pthread_atfork` child
  handler that only sets a flag; the child's next vault call (`with_key`,
  `register`, `memory_status`, ...) locks every pool page and every
  page in the page table again, and each page-protected key is locked
  again the first time the child reads it. Until then the child's
  status reports those keys as unlocked. Dump exclusion
  (`MADV_DONTDUMP`) is inherited and needs nothing. As with any
  `fork` of a threaded process, fork from a quiet point: a child forked
  while another thread was inside a vault call can block on the crate's
  locks.

### macOS

- Same `libc::mlock` / `libc::munlock` path as Linux. macOS allows
  user-level mlock without privilege escalation up to the per-process
  limit (typically several hundred MiB, well above any realistic
  vault footprint).
- No `/proc/self/status` analogue, so the `mlock_verified` test is
  cfg-gated to Linux only. Functional behaviour is the same; what
  changes is the in-tree proof, not the syscall.
- No dump exclusion: macOS has no per-page way to keep memory out of a
  core dump. Core dumps are off by default on macOS (`ulimit -c 0`);
  keep them off on machines that hold keys.

### Windows

- `windows-sys` crate provides `VirtualLock(addr, len)` and
  `VirtualUnlock(addr, len)`. Both are best-effort and may return
  zero on failure; the wrapper handles the failure path identically
  to the Unix `mlock` failure.
- **Lock budget.** Windows lets a process lock only as many pages as
  fit in its minimum working-set size, less a few pages the system
  keeps. The default minimum is 200 KiB (maximum 1380 KiB), which
  leaves room for about 44 locked pages: in 1.1, roughly a thousand
  keys. Since 1.2, when `VirtualLock` fails with
  `ERROR_WORKING_SET_QUOTA` the crate raises the process's minimum and
  maximum working-set sizes with `SetProcessWorkingSetSize` (by at
  least 1 MiB at a time, 256 MiB in total) and tries again. Raising
  one's own working set needs only the "Increase a process working
  set" privilege (`SeIncreaseWorkingSetPrivilege`), which every user
  holds by default; if the call fails (a policy removed the privilege,
  or a job object caps the working set) the crate stops trying and
  locks fail as before, which `memory_status()` shows.
- To set the budget yourself instead, call
  `SetProcessWorkingSetSizeEx(GetCurrentProcess(), min, max, 0)` at
  start-up with `min` at least the memory you want locked plus about
  200 KiB, before building vaults. A job object with
  `JOB_OBJECT_LIMIT_WORKINGSET` (some service hosts and containers set
  one) bounds what either approach can reach.
- Dump exclusion (1.1): `WerRegisterExcludedMemoryBlock` on every page
  that holds key material, so Windows Error Reporting crash dumps leave
  them out. The function is looked up at run time (it exists from
  Windows 10 1709); on older systems the exclusion is skipped. WER
  keeps at most 512 excluded blocks per process. Since 1.2 the pool
  maps its memory 64 KiB (16 pages) at a time and excludes each such
  chunk as one block, so the pool uses one block per 16 pages; pool
  chunks are never released. Each excluded heap page and each
  page-protected key is one more block. Past 512 blocks, new memory is
  not excluded; a heap page or protected key frees its block when
  released, and a pool chunk whose exclusion failed is retried when
  its pages are handed out. `memory_status().excluded_from_dumps`
  shows how many keys are covered. Dumps taken with Task Manager,
  procdump, a debugger or `MiniDumpWriteDump` are not affected.
- BitLocker / TPM-backed full-disk encryption is the right
  complementary layer here. `VirtualLock` covers swap; BitLocker
  covers hibernation files, the page file and any dump that is
  written.

## Layer 10 (page protection) — per platform

Opt-in with `KeyVaultBuilder::with_page_protection(true)` (1.1).

| | Linux | macOS | Windows |
|-|-------|-------|---------|
| Mapping | `mmap` anonymous | `mmap` anonymous | `VirtualAlloc` |
| Between reads | `PROT_NONE` | `PROT_NONE` | `PAGE_NOACCESS` |
| While read | `PROT_READ` | `PROT_READ` | `PAGE_READONLY` |
| Locked while inaccessible | yes (`mlock`) | yes (`mlock`) | **no**: `PAGE_NOACCESS` drops a `VirtualLock` |
| Dump exclusion | `MADV_DONTDUMP` | none | WER (one block per key) |
| Page size per key | 4 KiB | 16 KiB (Apple Silicon), 4 KiB (Intel) | 4 KiB (64 KiB of address space) |

On Windows a protected key can be paged out while it is inaccessible;
keep the page file encrypted (BitLocker on the system drive, or
`fsutil behavior set EncryptPagingFile 1`) if you turn page protection
on there. The unit tests check the mapping state (`/proc/self/maps`,
`VirtualQuery`) and that reading a protected key in a child process
crashes it.

## `no_std` targets

Without `std` the crate builds for bare metal (`thumbv7em-none-eabihf`
in CI). There is no OS: no swap, no core dump, no page protection, so
`LockedBytes` is plain zero-on-drop memory there. The application
supplies the clock (`build_with_clock`) and, where `getrandom` has no
backend, the RNG (`register_rng!`). On hosted targets (Linux, macOS,
Windows) built without `std`, locking, dump exclusion and page
protection still work.

### What no platform protects

- **Cold-boot attacks** require power-down protocols + full-disk
  encryption + hardware key escrow. Out of scope.
- **DMA attacks via PCIe** require IOMMU + Thunderbolt
  authorisation. Out of scope.
- **Hibernation files** — Windows writes `hiberfil.sys`, macOS writes
  `/var/vm/sleepimage`, Linux writes the swap partition. mlock does
  not stop hibernation. Pair with full-disk encryption.

---

## Layer 1 fetchers — platform availability

| Fetcher | Linux | macOS | Windows | Notes |
|---------|:-----:|:-----:|:-------:|-------|
| `EnvFetch` | ✅ | ✅ | ✅ | Always available (feature `fetcher-env`) |
| `FileFetch` | ✅ | ✅ | ✅ | Feature `fetcher-file`. Reads a plaintext file. Unix checks (mode `0o600`, owner, directories on the path) are `#[cfg(unix)]`-gated; Windows skips them (use NTFS ACLs) |
| `KeychainFetch` | ✅ | ✅ | ✅ | Via the `keyring` crate (feature `fetcher-keychain`). Linux → Secret Service over D-Bus (GNOME Keyring / KWallet), pure Rust; macOS → Keychain Services; Windows → Credential Manager. Before 1.1 no store feature was enabled and `keyring` used its in-memory mock on every platform |
| `TpmFetch` | not implemented | not implemented | not implemented | `fetch` always returns `Error::Acquisition`. Nothing in the crate detects or talks to a TPM |

### Linux keychain specifics

`Secret Service` requires a running daemon (gnome-keyring-daemon or
kwalletd). Headless servers without a session manager will fail to
read the keychain. The recommendation for headless deployments is to
use `FileFetch` or `EnvFetch` against material delivered by your
secrets management tooling.

### macOS keychain specifics

Requires the calling process to have permission to access the
keychain item — first access typically pops a user prompt. Programs
that run as a daemon should either use the System keychain (requires
root) or pre-populate access groups in the keychain item ACL.

### Windows keychain specifics

`Credential Manager` is per-user. Service accounts that run as
`LocalSystem` see a different credential store than interactive
users — install secrets under the same account that the consuming
process runs as.

---

## TEE detection — per architecture

`tee::detect_tee_capabilities()` produces a `TeeCapabilities` struct.
Each field is one of `Detected`, `NotDetected`, or `Unknown`.

### x86_64

- **Intel SGX**: probed via CPUID leaf 7 (`EBX.bit2`).
- **Intel TDX**: probed via CPUID leaf `0x21` signature.
- **AMD SEV / SEV-SNP**: probed via CPUID `0x8000001F`.
- All three return `Unknown` on non-x86_64 hosts.

### ARM64

- **ARM TrustZone**: reports `Unknown`. Userspace cannot reliably
  probe TrustZone availability without OS-specific drivers; the
  conservative answer is "don't know".
- **Apple Secure Enclave**: `Detected` on Apple Silicon (`aarch64-apple-darwin`),
  `NotDetected` elsewhere.

### Linux-specific

- **AWS Nitro Enclaves**: reads `/sys/devices/virtual/dmi/id/sys_vendor`.
  `Detected` when the field reads `Amazon EC2` and `/dev/nitro_enclaves`
  is present; `NotDetected` otherwise. Falls back to `Unknown` on
  non-Linux.

---

## CI matrix

The Tier-1 targets run a six-cell matrix:

| OS | Toolchain |
|----|-----------|
| `ubuntu-latest` | `stable` |
| `ubuntu-latest` | `1.85.0` |
| `macos-latest` | `stable` |
| `macos-latest` | `1.85.0` |
| `windows-latest` | `stable` |
| `windows-latest` | `1.85.0` |

Each cell runs `cargo fmt --check`, `cargo clippy -D warnings`,
`cargo test --all-features`, and `cargo doc -D warnings`.

A `no_std` job (stable and 1.85.0) builds and lints the library for
`thumbv7em-none-eabihf` and runs `tests/no_std_vault.rs` against the
`no_std` build.

A separate `supply-chain` job runs `cargo audit` and `cargo deny check`
on Linux only — REPS-required and feeds the
[RustSec advisory database](https://rustsec.org) into the gate.

---

## Cross-compilation notes

The crate compiles cleanly on every Tier-1 target listed above. A few
gotchas if you cross-compile from one host to another:

- **From Linux/macOS to Windows**: requires the `windows-sys` MSVC
  target. Install `x86_64-pc-windows-msvc` via `rustup target add`
  and link with `lld` or MSVC's `link.exe`.
- **From Linux to macOS**: the `keyring` dependency uses the macOS
  Security framework — cross-compiling against the system framework
  requires the macOS SDK headers. Easiest path: build natively on
  macOS or use a Cirrus / GitHub Actions macOS runner.
- **From any host to musl Linux**: since 1.1 the Linux keychain
  backend is pure Rust (`zbus`), so `fetcher-keychain` no longer needs
  `libdbus`. A Secret Service daemon is still needed at run time.
- **To bare metal**: build with `default-features = false` and register
  an RNG with `register_rng!` if `getrandom` has no backend for the
  target.

---

<sub>key-vault Platform Notes — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
