//! The no-op codex.

use super::Codex;

/// Codex that leaves every byte unchanged.
///
/// `IdentityCodex` is the default Layer 5 implementation. It satisfies the
/// involution requirement trivially (`x → x → x`) and costs nothing at runtime.
/// Use a non-identity codex when you want the Layer 5 defense; use this one
/// when you are deliberately turning Layer 5 off.
///
/// # Examples
///
/// ```
/// use key_vault::codex::{Codex, IdentityCodex};
///
/// let c = IdentityCodex;
/// assert_eq!(c.encode(0xab), 0xab);
/// assert_eq!(c.decode(0xab), 0xab);
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct IdentityCodex;

impl Codex for IdentityCodex {
    #[inline]
    fn encode(&self, byte: u8) -> u8 {
        byte
    }

    #[inline]
    fn decode(&self, byte: u8) -> u8 {
        byte
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_every_byte_through() {
        let c = IdentityCodex;
        for b in 0u8..=255 {
            assert_eq!(c.encode(b), b);
            assert_eq!(c.decode(b), b);
        }
    }

    #[test]
    fn involution_holds_for_every_byte() {
        let c = IdentityCodex;
        for b in 0u8..=255 {
            assert_eq!(c.decode(c.encode(b)), b);
        }
    }
}
