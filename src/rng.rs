//! Randomness source.
//!
//! Every random byte the crate uses (chunk sizes, shuffles, decoys, codex
//! tables, interleaving pools, keyed-hash keys) comes from [`fill`], which
//! calls `getrandom`.
//!
//! On targets `getrandom` supports (every OS the crate is tested on) this
//! is the operating system's CSPRNG. On targets it does not support (bare
//! metal, for example `thumbv7em-none-eabihf`) the application must
//! register its own source with [`register_rng!`](crate::register_rng). If
//! it does not, the final link fails with an undefined symbol
//! `__getrandom_custom`: there is no silent fallback.

use crate::Result;
use crate::error::Error;

/// Fill `buf` with random bytes.
pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::Internal("RNG failed"))
}

/// A single 64-bit random value.
pub(crate) fn random_u64() -> Result<u64> {
    let mut buf = [0u8; 8];
    fill(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

#[doc(hidden)]
pub mod __private {
    pub use getrandom;

    /// Error code reported when a registered RNG returns `false`.
    pub const FAILED: core::num::NonZeroU32 =
        match core::num::NonZeroU32::new(getrandom::Error::CUSTOM_START + 1) {
            Some(code) => code,
            None => core::num::NonZeroU32::MIN,
        };
}

/// Register the random number source for targets without an OS RNG.
///
/// key-vault gets randomness from `getrandom`. On targets `getrandom`
/// supports, that is the OS CSPRNG and this macro is not needed (if you
/// use it anyway, it has no effect there). On targets it does not support,
/// such as bare-metal `thumbv7em-none-eabihf`, you must call this macro
/// once in your binary crate, or linking fails with an undefined symbol
/// `__getrandom_custom`.
///
/// The function you pass has the signature `fn(&mut [u8]) -> bool`. It
/// fills the whole buffer with cryptographically secure random bytes (a
/// hardware TRNG, or a CSPRNG seeded from one) and returns `true`, or
/// returns `false` if it cannot. A `false` makes the vault operation that
/// needed randomness fail with [`Error::Internal`](crate::Error::Internal).
///
/// # Examples
///
/// ```
/// # mod board { pub mod trng { pub fn next_word() -> Option<u32> { Some(0) } } }
/// /// Fill `buf` from the board's hardware random number generator.
/// fn fill_from_trng(buf: &mut [u8]) -> bool {
///     for chunk in buf.chunks_mut(4) {
///         let Some(word) = board::trng::next_word() else {
///             return false; // TRNG fault: the vault operation fails
///         };
///         chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
///     }
///     true
/// }
///
/// key_vault::register_rng!(fill_from_trng);
/// # fn main() {}
/// ```
#[macro_export]
macro_rules! register_rng {
    ($path:path) => {
        const _: () = {
            fn __key_vault_rng(
                buf: &mut [u8],
            ) -> ::core::result::Result<(), $crate::__private::getrandom::Error> {
                let f: fn(&mut [u8]) -> bool = $path;
                if f(buf) {
                    ::core::result::Result::Ok(())
                } else {
                    ::core::result::Result::Err($crate::__private::getrandom::Error::from(
                        $crate::__private::FAILED,
                    ))
                }
            }
            $crate::__private::getrandom::register_custom_getrandom!(__key_vault_rng);
        };
    };
}
