//! Absolute address resolver (development/debug only — not ASLR-safe).

use crate::error::EngineResult;

use super::HexValue;

pub fn resolve(address: &HexValue) -> EngineResult<usize> {
    address.parse()
}
