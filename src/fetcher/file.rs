//! [`FileFetch`]: file-based [`KeyFetch`] backend.
//!
//! Reads key bytes from a file on disk. **The file is read as plaintext.**
//! `FileFetch` performs no decryption of any kind: the file contents are
//! returned verbatim as the key. For encryption at rest, rely on OS-level
//! disk encryption (LUKS / FileVault / BitLocker) or decrypt the file
//! yourself and pass the result to [`RawKey::new`].
//!
//! # Permission checks (Unix)
//!
//! The file is opened once and its mode and owner are read from the open
//! handle (`fstat`), so the checks and the read always refer to the same
//! file even if the path is swapped (for example by a symlink replacement)
//! in between. By default:
//!
//! - files readable or writable by group or others (any bit in `0o077`)
//!   are rejected;
//! - the file must be owned by the user the process runs as (effective
//!   uid) or by root (1.1);
//! - every directory on the path, after symlinks are resolved, must be
//!   owned by that user or root and must not be writable by group or
//!   others unless it has the sticky bit (like `/tmp`); the directory
//!   holding the path you gave (where a symlink would live) is checked the
//!   same way (1.1). Otherwise another user could replace the key file.
//!   The resolved path must still lead to the file that was opened.
//!
//! [`FileFetch::skip_directory_check`] turns off the directory check;
//! [`FileFetch::allow_loose_perms`] turns off all of them.
//!
//! On Windows there is no permission check: NTFS ACLs are trusted as is.
//!
//! # Threat profile
//!
//! Higher security than [`EnvFetch`](super::env::EnvFetch) on POSIX
//! systems because file permissions confine access to one user account.
//! Lower security than [`KeychainFetch`](super::keychain::KeychainFetch)
//! since the bytes live on disk in cleartext and persist across reboots.
//!
//! # Wiping
//!
//! The read buffer is allocated by this module and wiped on every error
//! path and whenever it has to grow. Copies inside the OS page cache or
//! the kernel are outside this crate's control.

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::String;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::{FetchContext, KeyFetch, RawKey};
use crate::Result;
use crate::error::Error;

/// `KeyFetch` implementation that reads a plaintext key file from disk.
///
/// By default, on Unix, files with any group or other permission bit set
/// (anything looser than `0o600`) are rejected; call
/// [`FileFetch::allow_loose_perms`] to disable that check (not recommended
/// outside of tests).
///
/// # Examples
///
/// ```no_run
/// use key_vault::{FetchContext, FileFetch, KeyFetch};
///
/// # fn main() -> Result<(), key_vault::Error> {
/// // Assume /etc/myapp/key.bin is mode 0600 and contains 32 bytes.
/// let fetcher = FileFetch::new("/etc/myapp/key.bin");
/// let raw = fetcher.fetch(&FetchContext::new("primary"))?;
/// assert_eq!(raw.len(), 32);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct FileFetch {
    path: PathBuf,
    strict_perms: bool,
    check_dirs: bool,
}

impl FileFetch {
    /// Construct a fetcher that reads the file at `path`. Strict Unix
    /// permission checking is enabled by default.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            strict_perms: true,
            check_dirs: true,
        }
    }

    /// Disable every Unix permission check: file mode, owner and
    /// directories.
    ///
    /// Useful for test fixtures and containers where the user controlling
    /// the file is the same as the process user but the file may have
    /// been created with `0o644`. **Do not** disable strict perms in
    /// production deployments where multiple users share the host.
    #[must_use]
    pub fn allow_loose_perms(mut self) -> Self {
        self.strict_perms = false;
        self
    }

    /// Keep the file mode and owner checks but skip the directory check.
    ///
    /// For layouts where a directory on the path is legitimately writable
    /// by a group (a shared deploy directory, for example) and you trust
    /// every member of it. Anyone who can write a directory on the path can
    /// replace the key file.
    #[must_use]
    pub fn skip_directory_check(mut self) -> Self {
        self.check_dirs = false;
        self
    }

    /// Path the fetcher reads from. Used in audit / diagnostic output.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl KeyFetch for FileFetch {
    fn fetch(&self, _ctx: &FetchContext) -> Result<RawKey> {
        // Open once. The permission check and the read both use this
        // handle, so they see the same file.
        let file = File::open(&self.path).map_err(|e| io_error(&self.path, &e))?;
        let checks = if self.strict_perms {
            Checks {
                file: true,
                dirs: self.check_dirs,
            }
        } else {
            Checks::NONE
        };
        read_checked(file, &self.path, checks)
    }

    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("file")
    }
}

/// Which permission checks to run.
#[derive(Debug, Clone, Copy)]
struct Checks {
    /// File mode and owner.
    file: bool,
    /// Directories on the path.
    dirs: bool,
}

impl Checks {
    #[cfg(all(test, unix))]
    const ALL: Self = Self {
        file: true,
        dirs: true,
    };
    const NONE: Self = Self {
        file: false,
        dirs: false,
    };
}

/// Run the permission checks on the open `file` and read it to the end.
fn read_checked(mut file: File, path: &Path, checks: Checks) -> Result<RawKey> {
    if checks.file {
        check_perms(&file, path, checks.dirs)?;
    }
    read_to_end_wiping(&mut file, path)
}

/// Read `file` to the end into a buffer that is wiped on every error and
/// on every growth step.
///
/// `std::fs::read` / `read_to_end` grow their `Vec` by reallocating,
/// which frees the old allocation with key bytes still in it. Here the
/// buffer is sized from the file length up front (plus one byte, so
/// end-of-file is seen without growing), and if the file turns out to be
/// longer the old buffer is copied into a larger one and zeroized.
fn read_to_end_wiping(file: &mut File, path: &Path) -> Result<RawKey> {
    let hint = file
        .metadata()
        .ok()
        .and_then(|m| usize::try_from(m.len()).ok())
        .unwrap_or(0);
    read_wiping(file, hint, path)
}

/// Read `reader` to the end, starting with a buffer of `hint + 1` bytes.
/// See [`read_to_end_wiping`].
fn read_wiping<R: Read>(reader: &mut R, hint: usize, path: &Path) -> Result<RawKey> {
    let mut buf = Zeroizing::new(alloc::vec![0u8; hint.saturating_add(1)]);
    let mut filled = 0usize;
    loop {
        if filled == buf.len() {
            let new_len = buf.len().saturating_mul(2).max(64);
            let mut bigger = Zeroizing::new(alloc::vec![0u8; new_len]);
            bigger[..filled].copy_from_slice(&buf[..filled]);
            // The old buffer is zeroized when it is dropped here.
            buf = bigger;
        }
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(io_error(path, &e)),
        }
    }
    // Shrinking the length keeps the allocation; `RawKey` zeroizes the
    // whole capacity on drop.
    buf.truncate(filled);
    Ok(RawKey::new(core::mem::take(&mut *buf)))
}

/// Build an `Error::Acquisition` for a file I/O failure.
fn io_error(path: &Path, e: &std::io::Error) -> Error {
    Error::Acquisition {
        source: Cow::Borrowed("file"),
        reason: io_failure_message(path, e),
    }
}

/// `Error::Acquisition` from the file fetcher with the given reason.
#[cfg(unix)]
fn rejected(reason: String) -> Error {
    Error::Acquisition {
        source: Cow::Borrowed("file"),
        reason,
    }
}

#[cfg(unix)]
fn check_perms(file: &File, path: &Path, check_dirs: bool) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = file.metadata().map_err(|e| io_error(path, &e))?;
    let mode = meta.permissions().mode();
    if (mode & 0o077) != 0 {
        return Err(rejected(format!(
            "{} is too permissive (mode {:o}); expected 0600 or stricter",
            path.display(),
            mode & 0o777
        )));
    }
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    check_owner(meta.uid(), euid, &path.display().to_string(), "file")?;
    if check_dirs {
        check_directories(path, &meta, euid)?;
    }
    Ok(())
}

/// The owner must be the effective user or root.
#[cfg(unix)]
fn check_owner(owner: u32, euid: u32, what: &str, kind: &str) -> Result<()> {
    if owner == euid || owner == 0 {
        Ok(())
    } else {
        Err(rejected(format!(
            "{kind} {what} is owned by uid {owner}; expected uid {euid} (the process user) or root"
        )))
    }
}

/// Check one directory on the key file's path.
#[cfg(unix)]
fn check_directory(dir: &Path, euid: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = std::fs::metadata(dir).map_err(|e| io_error(dir, &e))?;
    check_owner(meta.uid(), euid, &dir.display().to_string(), "directory")?;
    let mode = meta.permissions().mode();
    let writable_by_others = mode & 0o022 != 0;
    let sticky = mode & 0o1000 != 0;
    if writable_by_others && !sticky {
        return Err(rejected(format!(
            "directory {} is writable by group or others (mode {:o}), so the key file could be replaced",
            dir.display(),
            mode & 0o7777
        )));
    }
    Ok(())
}

/// Check every directory on the resolved path, plus the directory that
/// holds the path as given (where a symlink to the key would live), and
/// make sure the resolved path still leads to the opened file.
#[cfg(unix)]
fn check_directories(path: &Path, opened: &std::fs::Metadata, euid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let resolved = std::fs::canonicalize(path).map_err(|e| io_error(path, &e))?;
    let current = std::fs::metadata(&resolved).map_err(|e| io_error(path, &e))?;
    if (current.dev(), current.ino()) != (opened.dev(), opened.ino()) {
        return Err(rejected(format!(
            "{} changed while it was being checked",
            path.display()
        )));
    }
    for dir in resolved.ancestors().skip(1) {
        check_directory(dir, euid)?;
    }
    let given_parent = std::path::absolute(path)
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    if let Some(parent) = given_parent {
        if Some(parent.as_path()) != resolved.parent() {
            check_directory(&parent, euid)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // matches the Unix sibling's signature.
fn check_perms(_file: &File, _path: &Path, _check_dirs: bool) -> Result<()> {
    // Windows ACL inspection is non-trivial and platform-specific. For 1.0
    // we trust the OS-level access controls. Users who need additional
    // verification on Windows should layer it on top of FileFetch.
    Ok(())
}

/// Build a redaction-clean error message for a file I/O failure.
fn io_failure_message(path: &Path, e: &std::io::Error) -> String {
    // `std::io::Error` may include the OS error string. We restrict the
    // message to the path and the error *kind* (which is a short enum
    // discriminant) so secret-like substrings don't accidentally leak.
    format!("failed to read {}: {:?}", path.display(), e.kind())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a temporary file in the OS temp directory with the given
    /// contents. Returns the path; the file is cleaned up at end of test
    /// via the returned `_TempFile` guard.
    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(prefix: &str, contents: &[u8]) -> Self {
            let mut path = std::env::temp_dir();
            // Use process id + a counter for uniqueness. Pre-existing files
            // are overwritten — that's fine for unique prefixes.
            let suffix = format!("{}_{}", std::process::id(), prefix);
            path.push(format!("kv_test_{suffix}.bin"));
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(contents).unwrap();
            drop(f);
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn reads_file_contents() {
        let f = TempFile::new("read_ok", b"hello, world!");
        let fetcher = FileFetch::new(f.path()).allow_loose_perms();
        let raw = fetcher.fetch(&FetchContext::new("k")).unwrap();
        assert_eq!(raw.len(), 13);
    }

    #[test]
    fn missing_file_returns_acquisition_error() {
        let fetcher =
            FileFetch::new("/nonexistent/path/key-vault-test-missing.bin").allow_loose_perms();
        let err = fetcher.fetch(&FetchContext::new("k")).unwrap_err();
        match err {
            Error::Acquisition { source, reason } => {
                assert_eq!(source, "file");
                assert!(reason.contains("failed to read"));
            }
            other => panic!("expected Acquisition, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn strict_perms_rejects_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let f = TempFile::new("strict_perm", b"key");
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        let fetcher = FileFetch::new(f.path());
        let err = fetcher.fetch(&FetchContext::new("k")).unwrap_err();
        match err {
            Error::Acquisition { reason, .. } => {
                assert!(reason.contains("too permissive"));
            }
            other => panic!("expected Acquisition, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn strict_perms_accepts_0600() {
        use std::os::unix::fs::PermissionsExt;
        let f = TempFile::new("strict_0600", b"key");
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        let fetcher = FileFetch::new(f.path());
        let raw = fetcher.fetch(&FetchContext::new("k")).unwrap();
        assert_eq!(raw.len(), 3);
    }

    #[test]
    fn reads_files_of_many_sizes_exactly() {
        for len in [0usize, 1, 31, 32, 33, 4095, 4096, 4097, 70_000] {
            let contents: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let f = TempFile::new(&format!("sizes_{len}"), &contents);
            let raw = FileFetch::new(f.path())
                .allow_loose_perms()
                .fetch(&FetchContext::new("k"))
                .unwrap();
            assert_eq!(raw.as_bytes(), &contents[..], "mismatch at len {len}");
        }
    }

    #[test]
    fn read_grows_past_a_wrong_length_hint() {
        // A file can grow between `metadata()` and the read. Feed the
        // reader a length hint of 0 and check the growth path returns
        // every byte.
        let contents: Vec<u8> = (0..5000u32).map(|i| (i % 253) as u8).collect();
        let raw = read_wiping(&mut &contents[..], 0, Path::new("<memory>")).unwrap();
        assert_eq!(raw.as_bytes(), &contents[..]);
        let raw = read_wiping(&mut &contents[..], 10, Path::new("<memory>")).unwrap();
        assert_eq!(raw.as_bytes(), &contents[..]);
    }

    /// The permission check and the read must refer to the same file. Open
    /// a 0600 file, swap a world-readable file into its path, then check
    /// and read through the handle: the result is the original file's
    /// contents. The 1.0.1 code checked `metadata(path)` and then called
    /// `read(path)`, so a swap between the two read the other file.
    #[cfg(unix)]
    #[test]
    fn check_and_read_use_the_same_open_file() {
        use std::os::unix::fs::PermissionsExt;
        let good = TempFile::new("swap_good", b"checked-key");
        std::fs::set_permissions(good.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        let evil = TempFile::new("swap_evil", b"swapped-in");
        std::fs::set_permissions(evil.path(), std::fs::Permissions::from_mode(0o644)).unwrap();

        let handle = File::open(good.path()).unwrap();
        let second = File::open(good.path()).unwrap();
        // Replace the path's target after opening.
        std::fs::rename(evil.path(), good.path()).unwrap();

        let file_checks = Checks {
            file: true,
            dirs: false,
        };
        let raw = read_checked(handle, good.path(), file_checks).unwrap();
        assert_eq!(raw.as_bytes(), b"checked-key");

        // With the directory check (the default), the swap itself is
        // noticed: the path no longer leads to the file that was opened.
        let err = read_checked(second, good.path(), Checks::ALL).unwrap_err();
        assert!(format!("{err}").contains("changed while it was being checked"));

        // A fresh fetch sees the swapped-in, too-permissive file and
        // rejects it.
        let err = FileFetch::new(good.path())
            .fetch(&FetchContext::new("k"))
            .unwrap_err();
        assert!(matches!(err, Error::Acquisition { .. }));
    }

    /// A key file in a directory that others can write is rejected: they
    /// could replace it. `skip_directory_check` accepts it.
    #[cfg(unix)]
    #[test]
    fn directory_writable_by_others_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kv_test_dir_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("key.bin");
        std::fs::write(&file, b"secret").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = FileFetch::new(&file)
            .fetch(&FetchContext::new("k"))
            .unwrap_err();
        assert!(
            format!("{err}").contains("writable by group or others"),
            "{err}"
        );
        assert_eq!(
            FileFetch::new(&file)
                .skip_directory_check()
                .fetch(&FetchContext::new("k"))
                .unwrap()
                .len(),
            6
        );

        // Sticky world-writable (like /tmp) is fine: others cannot rename
        // or delete files they do not own.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(FileFetch::new(&file).fetch(&FetchContext::new("k")).is_ok());

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(FileFetch::new(&file).fetch(&FetchContext::new("k")).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The owner check accepts the process user and root only.
    #[cfg(unix)]
    #[test]
    fn owner_must_be_process_user_or_root() {
        assert!(check_owner(1000, 1000, "f", "file").is_ok());
        assert!(check_owner(0, 1000, "f", "file").is_ok());
        let err = check_owner(1001, 1000, "/k", "file").unwrap_err();
        assert!(format!("{err}").contains("owned by uid 1001"));
    }

    /// A symlink in a directory others can write is rejected even when the
    /// target directory is private: the link itself could be re-pointed.
    #[cfg(unix)]
    #[test]
    fn symlink_in_open_directory_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("kv_test_link_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let private = base.join("private");
        let open = base.join("open");
        std::fs::create_dir_all(&private).unwrap();
        std::fs::create_dir_all(&open).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = private.join("key.bin");
        std::fs::write(&target, b"secret").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = open.join("key.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(FileFetch::new(&link).fetch(&FetchContext::new("k")).is_ok());
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            FileFetch::new(&link)
                .fetch(&FetchContext::new("k"))
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn describe_returns_file() {
        assert_eq!(FileFetch::new("/dev/null").describe(), "file");
    }
}
