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

Tier-1 targets run the full test + bench suite on every push. Tier-2
compiles but does not run tests under CI; promote when runner capacity
allows.

---

## Layer 2 (page locking) — per platform

### Linux

- `libc::mlock(addr, len)` on construction; `libc::munlock(addr, len)`
  on drop. Both syscalls are best-effort: when `RLIMIT_MEMLOCK = 0`
  (unprivileged containers, Docker default), the call fails and
  `LockedBytes::is_locked()` returns `false`. The buffer still works
  as a plain zero-on-drop wrapper — no key material leaks, just no
  swap protection.
- The `tests/mlock_verified.rs` integration test reads
  `/proc/self/status` `VmLck` before and after registering 64 keys to
  prove the syscall is being honoured. It self-skips when
  `VmLck` stays at zero (= unprivileged sandbox).
- Recommended ops setup: grant the running process
  `CAP_IPC_LOCK` capability, or raise `RLIMIT_MEMLOCK` via systemd's
  `LimitMEMLOCK=infinity`. For container workloads add
  `--ulimit memlock=-1` (Docker) or the equivalent
  `securityContext.capabilities.add: ["IPC_LOCK"]` (Kubernetes).

### macOS

- Same `libc::mlock` / `libc::munlock` path as Linux. macOS allows
  user-level mlock without privilege escalation up to the per-process
  limit (typically several hundred MiB, well above any realistic
  vault footprint).
- No `/proc/self/status` analogue, so the `mlock_verified` test is
  cfg-gated to Linux only. Functional behaviour is the same; what
  changes is the in-tree proof, not the syscall.

### Windows

- `windows-sys` crate provides `VirtualLock(addr, len)` and
  `VirtualUnlock(addr, len)`. Both are best-effort and may return
  zero on failure; the wrapper handles the failure path identically
  to the Unix `mlock` failure.
- `SetProcessWorkingSetSizeEx` controls the per-process working-set
  limit. The crate does not call it — downstream consumers with very
  large vaults may need to raise the limit from a privileged
  bootstrap step.
- BitLocker / TPM-backed full-disk encryption is the right
  complementary layer here. `VirtualLock` covers swap; BitLocker
  covers hibernation files and crash dumps.

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
| `FileFetch` | ✅ | ✅ | ✅ | Always available (feature `fetcher-file`). Unix permission check (`0o600`) is `#[cfg(unix)]`-gated; Windows skips the chmod check (use NTFS ACLs) |
| `KeychainFetch` | ✅ | ✅ | ✅ | Via the `keyring` crate (feature `fetcher-keychain`). Linux → Secret Service over D-Bus (GNOME Keyring / KWallet); macOS → Keychain Services; Windows → Credential Manager |
| `TpmFetch` | detection only | detection only | detection only | The detection path works everywhere; the *acquisition* path returns `Error::Acquisition("detection-only")` until full integration lands post-1.0 |

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
- **From any host to musl Linux**: `keyring` pulls in `dbus` which
  expects glibc; build with `--no-default-features` and disable
  `fetcher-keychain` for static musl targets.

---

<sub>key-vault Platform Notes — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
