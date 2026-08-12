//! Module-offset resolver: `module base + offset`.

use crate::error::{EngineError, EngineResult};
use crate::memory::{module_base, MemoryRegion};

use super::HexValue;

pub fn resolve(maps: &[MemoryRegion], module: &str, offset: &HexValue) -> EngineResult<usize> {
    let base = module_base(maps, module)
        .ok_or_else(|| EngineError::ModuleNotFound(module.to_string()))?;
    Ok(base + offset.parse()?)
}
