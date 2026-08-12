//! Process-level module enumeration: read a pid's maps and resolve modules.
//!
//! Combines [`super::procfs`] I/O with the pure parser in
//! [`crate::memory::regions`].

use crate::error::{EngineError, EngineResult};
use crate::memory::{find_module, MemoryRegion, ModuleInfo};

use super::procfs;

/// All memory regions for `pid` (parsed from `/proc/<pid>/maps`).
pub fn read_modules(pid: i32) -> EngineResult<Vec<MemoryRegion>> {
    let raw = procfs::read_maps_raw(pid)?;
    Ok(crate::memory::regions::parse_maps(&raw))
}

/// Resolve a single module for `pid`.
pub fn find_process_module(pid: i32, module: &str) -> EngineResult<ModuleInfo> {
    let regions = read_modules(pid)?;
    find_module(&regions, module)
        .ok_or_else(|| EngineError::ModuleNotFound(module.to_string()))
}
