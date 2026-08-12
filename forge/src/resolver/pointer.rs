//! Pointer-chain resolver.
//!
//! Convention (provisional, CE-style): start at `module_base + offset`, then for
//! each entry in `offsets` dereference the current pointer and add the offset.
//! Every dereference is validated; a null or unreadable pointer aborts the chain
//! with [`EngineError::InvalidPointer`]. Pointer width is assumed 64-bit.
//!
//! Pointer chains are not the focus of this milestone; this provides a safe
//! foundation that can be refined later.

use crate::error::{EngineError, EngineResult};
use crate::memory::{module_base, MemoryAccess, MemoryRegion};

use super::HexValue;

pub fn resolve(
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    module: &str,
    offset: &HexValue,
    offsets: &[HexValue],
) -> EngineResult<usize> {
    let base = module_base(maps, module)
        .ok_or_else(|| EngineError::ModuleNotFound(module.to_string()))?;
    let mut ptr = base + offset.parse()?;

    for off in offsets {
        let val = mem
            .read_u64(ptr)
            .map_err(|e| EngineError::InvalidPointer(format!("deref at 0x{ptr:x} failed: {e}")))?;
        if val == 0 {
            return Err(EngineError::InvalidPointer(format!(
                "null pointer in chain at 0x{ptr:x}"
            )));
        }
        ptr = val as usize + off.parse()?;
    }
    Ok(ptr)
}
