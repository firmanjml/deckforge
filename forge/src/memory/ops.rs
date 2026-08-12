//! Memory-backend abstraction used by the Auto Assembler engine.
//!
//! The AA engine is written against [`MemoryOps`] so that script execution
//! (aobscan/alloc/patch/rollback) is fully unit-testable without a live
//! process. [`LiveMemory`] adapts the engine's validated [`MemoryAccess`] +
//! cached maps; [`MockMemory`] (tests only) is a flat in-memory backend.

use crate::error::{EngineError, EngineResult};
use crate::memory::{module_base, MemoryAccess, MemoryRegion};
use crate::resolver::signature::{all_matches, PatternByte};

/// Cap on scan results returned by one AOB scan (safety valve; CE's aobscan
/// expects a unique match, and the AA layer enforces that on top).
pub const MAX_AOB_RESULTS: usize = 4096;
/// Largest single region an AOB scan will read.
const MAX_SCAN_REGION: usize = 512 * 1024 * 1024;
/// Scan chunk size.
const SCAN_CHUNK: usize = 4 * 1024 * 1024;

/// The generic memory operations the Auto Assembler engine needs. Deliberately
/// small: read/write, AOB scan, module lookup, alloc/dealloc, bitness.
pub trait MemoryOps {
    fn read_bytes(&self, addr: usize, len: usize) -> EngineResult<Vec<u8>>;
    fn write_bytes(&self, addr: usize, data: &[u8]) -> EngineResult<()>;
    /// All matches of an AOB pattern. `Some(module)` restricts the scan to
    /// that module's address span (`aobscanmodule`); `None` scans all
    /// readable memory (`aobscan`).
    fn aob_scan(&self, module: Option<&str>, pattern: &[PatternByte]) -> EngineResult<Vec<usize>>;
    /// All matches of an AOB pattern restricted to `[start, stop)`.
    fn aob_scan_range(
        &self,
        start: usize,
        stop: usize,
        pattern: &[PatternByte],
    ) -> EngineResult<Vec<usize>>;
    fn module_base(&self, name: &str) -> EngineResult<usize>;
    /// Allocate executable memory in the target, preferably near `near`
    /// (±2 GiB, so rel32 branches reach). Returns the base address.
    fn alloc(&self, size: usize, near: Option<usize>) -> EngineResult<usize>;
    fn dealloc(&self, addr: usize, size: usize) -> EngineResult<()>;
    /// Target process bitness: 64 or 32.
    fn bitness(&self) -> u32;
}

// ---------------------------------------------------------------------------
// LiveMemory
// ---------------------------------------------------------------------------

/// [`MemoryOps`] over a real attached process.
pub struct LiveMemory<'a> {
    pub mem: &'a MemoryAccess,
    pub maps: &'a [MemoryRegion],
    /// The trainer's main game module (e.g. "game.exe") — used for bitness.
    pub main_module: &'a str,
}

impl<'a> LiveMemory<'a> {
    pub fn new(mem: &'a MemoryAccess, maps: &'a [MemoryRegion], main_module: &'a str) -> Self {
        Self {
            mem,
            maps,
            main_module,
        }
    }

    /// The address span of a module: `[base, base + SizeOfImage)`. Under
    /// Proton most PE sections are mapped anonymous, so path-based region
    /// filtering alone would miss nearly all of the module; the PE span is
    /// what CE scans. Falls back to the path-matched region extent.
    fn module_span(&self, module: &str) -> EngineResult<(usize, usize)> {
        module_span(self.mem, self.maps, module)
    }
}

/// Read `SizeOfImage` from the PE optional header (offset 0x38 within the
/// optional header for both PE32 and PE32+). `None` when unreadable or not PE.
fn read_size_of_image(mem: &MemoryAccess, base: usize) -> Option<usize> {
    let mz = mem.read_bytes(base, 2).ok()?;
    if mz != [0x4D, 0x5A] {
        return None;
    }
    let e_lfanew = mem.read_u32(base + 0x3C).ok()? as usize;
    mem.read_u32(base + e_lfanew + 24 + 0x38)
        .ok()
        .map(|v| v as usize)
}

/// The address span of a module: `[base, base + SizeOfImage)`. Under Proton
/// most PE sections are mapped anonymous, so path-based region filtering
/// alone misses nearly all of the module; the PE span is what CE scans.
/// Falls back to the path-matched region extent.
pub(crate) fn module_span(
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    module: &str,
) -> EngineResult<(usize, usize)> {
    let base =
        module_base(maps, module).ok_or_else(|| EngineError::ModuleNotFound(module.to_string()))?;
    let end = read_size_of_image(mem, base)
        .map(|s| base.saturating_add(s))
        .unwrap_or_else(|| {
            maps.iter()
                .filter(|m| {
                    m.path.as_deref().is_some_and(|p| {
                        p.rsplit('/')
                            .next()
                            .unwrap_or(p)
                            .eq_ignore_ascii_case(module)
                    })
                })
                .map(|m| m.end)
                .max()
                .unwrap_or(base.saturating_add(64 * 1024 * 1024))
        });
    Ok((base, end))
}

impl<'a> MemoryOps for LiveMemory<'a> {
    fn read_bytes(&self, addr: usize, len: usize) -> EngineResult<Vec<u8>> {
        self.mem.read_bytes(addr, len)
    }

    fn write_bytes(&self, addr: usize, data: &[u8]) -> EngineResult<()> {
        self.mem.write_bytes(addr, data)
    }

    fn aob_scan(&self, module: Option<&str>, pattern: &[PatternByte]) -> EngineResult<Vec<usize>> {
        let (lo, hi) = match module {
            Some(m) => {
                let (lo, hi) = self.module_span(m)?;
                eprintln!(
                    "[aob_scan] module '{}' span: 0x{:X}..0x{:X} ({} bytes)",
                    m,
                    lo,
                    hi,
                    hi - lo
                );
                (lo, hi)
            }
            None => (0, usize::MAX),
        };
        let mut out = Vec::new();
        let mut regions_scanned = 0usize;
        let mut bytes_scanned = 0usize;
        for region in self.maps.iter() {
            if out.len() >= MAX_AOB_RESULTS {
                break;
            }
            if !region.readable {
                continue;
            }
            // Clip the region to the requested span.
            let start = region.start.max(lo);
            let end = region.end.min(hi);
            if start >= end || end - start > MAX_SCAN_REGION {
                continue;
            }
            let size = end - start;
            regions_scanned += 1;
            let mut offset = 0usize;
            let overlap = pattern.len().saturating_sub(1);
            while offset < size && out.len() < MAX_AOB_RESULTS {
                // Re-read the tail of the previous chunk so matches spanning
                // a chunk boundary are found exactly once.
                let back = overlap.min(offset);
                let addr = start + offset - back;
                let chunk = (SCAN_CHUNK + back).min(size - (offset - back));
                if let Ok(data) = self.mem.read_bytes(addr, chunk) {
                    bytes_scanned += data.len();
                    let new_start = start + offset;
                    for m in all_matches(&data, pattern) {
                        if addr + m + pattern.len() > new_start {
                            out.push(addr + m);
                            if out.len() >= MAX_AOB_RESULTS {
                                break;
                            }
                        }
                    }
                }
                offset += SCAN_CHUNK.min(size - offset);
            }
        }
        if module.is_some() && out.is_empty() {
            eprintln!(
                "[aob_scan] scanned {} regions ({} bytes) in module span, no match",
                regions_scanned, bytes_scanned
            );
            // Log a few region details for debugging.
            for r in self
                .maps
                .iter()
                .filter(|r| r.start >= lo && r.start < hi)
                .take(10)
            {
                eprintln!(
                    "[aob_scan]   region 0x{:X}..0x{:X} r={} w={} x={} path={:?}",
                    r.start, r.end, r.readable, r.writable, r.executable, r.path
                );
            }
        }
        Ok(out)
    }

    fn aob_scan_range(
        &self,
        start: usize,
        stop: usize,
        pattern: &[PatternByte],
    ) -> EngineResult<Vec<usize>> {
        if start >= stop {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for region in self.maps.iter() {
            if out.len() >= MAX_AOB_RESULTS {
                break;
            }
            if !region.readable {
                continue;
            }
            let clipped_start = region.start.max(start);
            let clipped_end = region.end.min(stop);
            if clipped_start >= clipped_end || clipped_end - clipped_start > MAX_SCAN_REGION {
                continue;
            }
            let size = clipped_end - clipped_start;
            let mut offset = 0usize;
            let overlap = pattern.len().saturating_sub(1);
            while offset < size && out.len() < MAX_AOB_RESULTS {
                let back = overlap.min(offset);
                let addr = clipped_start + offset - back;
                let chunk = (SCAN_CHUNK + back).min(size - (offset - back));
                if let Ok(data) = self.mem.read_bytes(addr, chunk) {
                    let new_start = clipped_start + offset;
                    for m in all_matches(&data, pattern) {
                        if addr + m + pattern.len() > new_start {
                            out.push(addr + m);
                            if out.len() >= MAX_AOB_RESULTS {
                                break;
                            }
                        }
                    }
                }
                offset += SCAN_CHUNK.min(size - offset);
            }
        }
        Ok(out)
    }

    fn module_base(&self, name: &str) -> EngineResult<usize> {
        module_base(self.maps, name).ok_or_else(|| EngineError::ModuleNotFound(name.to_string()))
    }

    fn alloc(&self, size: usize, near: Option<usize>) -> EngineResult<usize> {
        super::alloc::remote_alloc(self.mem.pid, size, near, self.maps)
    }

    fn dealloc(&self, addr: usize, size: usize) -> EngineResult<()> {
        super::alloc::remote_dealloc(self.mem.pid, addr, size, self.maps)
    }

    fn bitness(&self) -> u32 {
        pe_bitness(self.mem, self.maps, self.main_module)
    }
}

/// Bitness of the target's main module from its PE header
/// (0x8664 = x64 → 64, 0x14C = x86 → 32). Falls back to 64 when the module
/// is not a PE (native ELF on SteamOS is 64-bit in practice).
pub fn pe_bitness(mem: &MemoryAccess, maps: &[MemoryRegion], module: &str) -> u32 {
    let Some(base) = module_base(maps, module) else {
        return 64;
    };
    let Ok(mz) = mem.read_bytes(base, 2) else {
        return 64;
    };
    if mz != [0x4D, 0x5A] {
        return 64;
    }
    let Ok(e_lfanew) = mem.read_u32(base + 0x3C) else {
        return 64;
    };
    match mem.read_u16(base + e_lfanew as usize + 4) {
        Ok(0x14C) => 32,
        _ => 64,
    }
}

// ---------------------------------------------------------------------------
// MockMemory (tests)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// Flat in-memory backend for Auto Assembler tests. Modules are placed at
    /// configurable bases; `alloc` bumps from `ALLOC_BASE`. Reads of unwritten
    /// bytes return zeros.
    pub struct MockMemory {
        pub data: RefCell<Vec<u8>>,
        modules: HashMap<String, (usize, usize)>,
        next_alloc: RefCell<usize>,
        /// Every (addr, size) handed out by alloc, in order.
        pub allocs: RefCell<Vec<(usize, usize)>>,
        /// The `near` hint of each alloc call, in order.
        pub near_hints: RefCell<Vec<Option<usize>>>,
        /// Every (addr, size) passed to dealloc, in order.
        pub frees: RefCell<Vec<(usize, usize)>>,
        /// When true, write_bytes fails (rollback testing).
        pub fail_writes: RefCell<bool>,
        bitness: u32,
    }

    pub const CAP: usize = 0x400_0000; // 64 MiB flat space
    pub const ALLOC_BASE: usize = 0x20_0000;

    impl MockMemory {
        pub fn new(bitness: u32) -> Self {
            Self {
                data: RefCell::new(vec![0u8; CAP]),
                modules: HashMap::new(),
                next_alloc: RefCell::new(ALLOC_BASE),
                allocs: RefCell::new(Vec::new()),
                near_hints: RefCell::new(Vec::new()),
                frees: RefCell::new(Vec::new()),
                fail_writes: RefCell::new(false),
                bitness,
            }
        }

        /// Register a module occupying `[base, base+size)`.
        pub fn add_module(&mut self, name: &str, base: usize, size: usize) {
            assert!(base + size <= CAP, "module outside mock memory");
            self.modules.insert(name.to_string(), (base, size));
        }

        /// Test helper: plant bytes (bypasses fail_writes).
        pub fn plant(&self, addr: usize, bytes: &[u8]) {
            self.data.borrow_mut()[addr..addr + bytes.len()].copy_from_slice(bytes);
        }

        /// Test helper: read back bytes directly.
        pub fn peek(&self, addr: usize, len: usize) -> Vec<u8> {
            self.data.borrow()[addr..addr + len].to_vec()
        }
    }

    impl MemoryOps for MockMemory {
        fn read_bytes(&self, addr: usize, len: usize) -> EngineResult<Vec<u8>> {
            let data = self.data.borrow();
            if addr + len > data.len() {
                return Err(EngineError::MemoryReadFailed(format!(
                    "mock read outside memory: 0x{addr:X}+{len}"
                )));
            }
            Ok(data[addr..addr + len].to_vec())
        }

        fn write_bytes(&self, addr: usize, data_in: &[u8]) -> EngineResult<()> {
            if *self.fail_writes.borrow() {
                return Err(EngineError::MemoryWriteFailed(
                    "mock write failure (injected)".into(),
                ));
            }
            let mut data = self.data.borrow_mut();
            if addr + data_in.len() > data.len() {
                return Err(EngineError::MemoryWriteFailed(format!(
                    "mock write outside memory: 0x{addr:X}"
                )));
            }
            data[addr..addr + data_in.len()].copy_from_slice(data_in);
            Ok(())
        }

        fn aob_scan(
            &self,
            module: Option<&str>,
            pattern: &[PatternByte],
        ) -> EngineResult<Vec<usize>> {
            let data = self.data.borrow();
            let (lo, hi) = match module {
                Some(m) => {
                    let (base, size) = *self
                        .modules
                        .get(m)
                        .ok_or_else(|| EngineError::ModuleNotFound(m.to_string()))?;
                    (base, base + size)
                }
                None => (0, data.len()),
            };
            let mut out = Vec::new();
            for m in all_matches(&data[lo..hi], pattern) {
                out.push(lo + m);
                if out.len() >= MAX_AOB_RESULTS {
                    break;
                }
            }
            Ok(out)
        }

        fn aob_scan_range(
            &self,
            start: usize,
            stop: usize,
            pattern: &[PatternByte],
        ) -> EngineResult<Vec<usize>> {
            let data = self.data.borrow();
            let lo = start.min(data.len());
            let hi = stop.min(data.len());
            if lo >= hi {
                return Ok(Vec::new());
            }
            let mut out = Vec::new();
            for m in all_matches(&data[lo..hi], pattern) {
                out.push(lo + m);
                if out.len() >= MAX_AOB_RESULTS {
                    break;
                }
            }
            Ok(out)
        }

        fn module_base(&self, name: &str) -> EngineResult<usize> {
            self.modules
                .get(name)
                .map(|(b, _)| *b)
                .ok_or_else(|| EngineError::ModuleNotFound(name.to_string()))
        }

        fn alloc(&self, size: usize, near: Option<usize>) -> EngineResult<usize> {
            let size = (size + 0xFFF) & !0xFFF;
            let mut next = self.next_alloc.borrow_mut();
            if *next + size > CAP {
                return Err(EngineError::MemoryWriteFailed(
                    "mock allocator exhausted".into(),
                ));
            }
            let addr = *next;
            *next += size;
            self.allocs.borrow_mut().push((addr, size));
            self.near_hints.borrow_mut().push(near);
            Ok(addr)
        }

        fn dealloc(&self, addr: usize, size: usize) -> EngineResult<()> {
            self.frees.borrow_mut().push((addr, size));
            Ok(())
        }

        fn bitness(&self) -> u32 {
            self.bitness
        }
    }
}
