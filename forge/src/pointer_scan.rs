//! Pointer scanner: find pointer chains from static module addresses to a
//! dynamic (heap) target address.
//!
//! Optimized version: only scans anonymous (heap) memory + module regions,
//! caps the number of level-1 pointers, and reads in chunks to avoid blocking.

use crate::error::EngineResult;
use crate::memory::{MemoryAccess, MemoryRegion, ModuleInfo};
use serde::Serialize;

const MAX_CHUNK: usize = 4 * 1024 * 1024; // 4MB chunks

#[derive(Debug, Clone, Serialize)]
pub struct ChainLevel {
    pub address: usize,
    pub offset: usize,
    pub module: Option<String>,
    pub module_offset: Option<usize>,
    pub is_static: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PointerChain {
    pub levels: Vec<ChainLevel>,
    pub target: usize,
    pub target_offset: usize,
}

#[derive(Debug, Serialize)]
pub struct PointerScanResult {
    pub chains: Vec<PointerChain>,
    pub total_found: usize,
}

/// Scan for pointer chains to `target` address.
pub fn scan_pointers(
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    target: usize,
    max_depth: usize,
    max_offset: usize,
) -> EngineResult<PointerScanResult> {
    let mut chains = Vec::new();

    let found_modules = crate::memory::ops::loaded_modules(mem, maps);

    // Level 1: find all pointers to target ± max_offset in ALL readable+writable memory
    let level1_ptrs = find_pointers_to(mem, maps, target, max_offset, false)?;
    eprintln!(
        "[forge] ptrscan: found {} level-1 pointers to 0x{:x}",
        level1_ptrs.len(),
        target
    );

    let mut level1_count = 0;
    for ptr_addr in &level1_ptrs {
        level1_count += 1;
        if level1_count > 5000 {
            eprintln!("[forge] ptrscan: too many level-1 pointers, stopping");
            break;
        }

        let (module, module_offset, is_static) =
            classify_address_in_modules(*ptr_addr, &found_modules);

        let ptr_val = read_ptr(mem, *ptr_addr).unwrap_or(0);
        let target_off = if ptr_val <= target {
            target - ptr_val
        } else {
            0
        };

        let level = ChainLevel {
            address: *ptr_addr,
            offset: 0,
            module: module.clone(),
            module_offset,
            is_static,
        };

        if is_static {
            // Found a static base directly!
            chains.push(PointerChain {
                levels: vec![level],
                target,
                target_offset: target_off,
            });
            if chains.len() >= 20 {
                break;
            }
        } else if max_depth > 1 {
            // Level 2: find pointers to ptr_addr ± max_offset (scan ALL memory)
            let level2_ptrs = find_pointers_to(mem, maps, *ptr_addr, max_offset, false)?;
            for l2_addr in &level2_ptrs {
                let (mod2, off2, static2) = classify_address_in_modules(*l2_addr, &found_modules);
                let l2_val = read_ptr(mem, *l2_addr).unwrap_or(0);
                let l2_offset = if l2_val <= *ptr_addr {
                    *ptr_addr - l2_val
                } else {
                    0
                };

                let level2 = ChainLevel {
                    address: *l2_addr,
                    offset: l2_offset,
                    module: mod2.clone(),
                    module_offset: off2,
                    is_static: static2,
                };

                if static2 {
                    let level_copy = level.clone();
                    chains.push(PointerChain {
                        levels: vec![level2, level_copy],
                        target,
                        target_offset: target_off,
                    });
                    if chains.len() >= 20 {
                        break;
                    }
                } else if max_depth > 2 {
                    // Level 3: find pointers to l2_addr ± max_offset (scan ALL memory)
                    let level3_ptrs = find_pointers_to(mem, maps, *l2_addr, max_offset, false)?;
                    for l3_addr in &level3_ptrs {
                        let (mod3, off3, static3) =
                            classify_address_in_modules(*l3_addr, &found_modules);
                        let l3_val = read_ptr(mem, *l3_addr).unwrap_or(0);
                        let l3_offset = if l3_val <= *l2_addr {
                            *l2_addr - l3_val
                        } else {
                            0
                        };

                        let level3 = ChainLevel {
                            address: *l3_addr,
                            offset: l3_offset,
                            module: mod3.clone(),
                            module_offset: off3,
                            is_static: static3,
                        };

                        if static3 {
                            let level2_copy = level2.clone();
                            let level_copy = level.clone();
                            chains.push(PointerChain {
                                levels: vec![level3, level2_copy, level_copy],
                                target,
                                target_offset: target_off,
                            });
                            if chains.len() >= 20 {
                                break;
                            }
                        }
                    }
                }
            }
        }

        if chains.len() >= 20 {
            break;
        }
    }

    Ok(PointerScanResult {
        total_found: chains.len(),
        chains,
    })
}

/// Find all addresses in memory whose 8-byte value points to `target ± max_offset`.
/// If `anon_only` is true, only scan anonymous (no path) regions.
fn find_pointers_to(
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    target: usize,
    max_offset: usize,
    anon_only: bool,
) -> EngineResult<Vec<usize>> {
    let mut results = Vec::new();
    let lo = target.saturating_sub(max_offset);
    let hi = target + max_offset;

    for region in maps {
        if !region.readable || !region.writable {
            continue;
        }
        if anon_only && region.path.is_some() {
            continue;
        }
        let size = region.size();
        if size == 0 || size > 64 * 1024 * 1024 {
            continue;
        }

        let mut offset = 0usize;
        while offset < size {
            let chunk = MAX_CHUNK.min(size - offset);
            let addr = region.start + offset;
            let data = match mem.read_bytes(addr, chunk) {
                Ok(d) => d,
                Err(_) => {
                    offset += chunk;
                    continue;
                }
            };

            let mut i = 0;
            while i + 8 <= data.len() {
                let ptr = u64::from_ne_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                    data[i + 4],
                    data[i + 5],
                    data[i + 6],
                    data[i + 7],
                ]) as usize;
                if ptr >= lo && ptr <= hi {
                    results.push(addr + i);
                }
                i += 8;
            }
            offset += chunk;
        }
    }
    Ok(results)
}

fn read_ptr(mem: &MemoryAccess, addr: usize) -> EngineResult<usize> {
    let bytes = mem.read_bytes(addr, 8)?;
    Ok(u64::from_ne_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]) as usize)
}

fn classify_address_in_modules(
    addr: usize,
    modules: &[ModuleInfo],
) -> (Option<String>, Option<usize>, bool) {
    for m in modules {
        if addr >= m.base && addr < m.end {
            return (Some(m.name.clone()), Some(addr - m.base), true);
        }
    }
    (None, None, false)
}
