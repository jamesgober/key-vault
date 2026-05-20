//! [`FileFetch`] — file-based [`KeyFetch`] backend.
//!
//! Reads key bytes from a file on disk. On Unix the file's permission bits
//! are checked: by default we reject files that are readable by group or
//! world (any mode bit in `0o077` set). On Windows we trust the platform's
//! NTFS ACLs and do not perform a separate permission check.
//!
//! # On-disk format
//!
//! `FileFetch` does **not** perform AEAD decryption in this release. The
//! file contents are read verbatim and returned as the key. For
//! encryption-at-rest pair this fetcher with OS-level disk encryption
//! (LUKS / FileVault / BitLocker) or a sealed-key file format from
//! another crate. AEAD-encrypted file support is on the post-1.0 backlog.
//!
//! # Threat profile
//!
//! Higher security than [`EnvFetch`](super::env::EnvFetch) because file
//! permissions confine access to one user account on POSIX systems. Lower
//! security than [`KeychainFetch`](super::keychain::KeychainFetch) since
//! the bytes live on disk in cleartext and persist across reboots.

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::String;
use std::path::{Path, PathBuf};

use super::{FetchContext, KeyFetch, RawKey};
use crate::Result;
use crate::error::Error;

/// `KeyFetch` implementation that reads bytes from a file on disk.
///
/// By default Unix permission bits stricter than `0o600` are rejected; call
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
}

impl FileFetch {
    /// Construct a fetcher that reads the file at `path`. Strict Unix
    /// permission checking is enabled by default.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            strict_perms: true,
        }
    }

    /// Disable strict Unix permission checking.
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

    /// Path the fetcher reads from. Used in audit / diagnostic output.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl KeyFetch for FileFetch {
    fn fetch(&self, _ctx: &FetchContext) -> Result<RawKey> {
        if self.strict_perms {
            check_perms(&self.path)?;
        }
        std::fs::read(&self.path).map_or_else(
            |e| {
                Err(Error::Acquisition {
                    source: Cow::Borrowed("file"),
                    reason: io_failure_message(&self.path, &e),
                })
            },
            |bytes| Ok(RawKey::new(bytes)),
        )
    }

    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("file")
    }
}

#[cfg(unix)]
fn check_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| Error::Acquisition {
        source: Cow::Borrowed("file"),
        reason: io_failure_message(path, &e),
    })?;
    let mode = meta.permissions().mode();
    if (mode & 0o077) != 0 {
        return Err(Error::Acquisition {
            source: Cow::Borrowed("file"),
            reason: format!(
                "{} is too permissive (mode {:o}); expected 0600 or stricter",
                path.display(),
                mode & 0o777
            ),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // matches the Unix sibling's signature.
fn check_perms(_path: &Path) -> Result<()> {
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
    fn describe_returns_file() {
        assert_eq!(FileFetch::new("/dev/null").describe(), "file");
    }
}
