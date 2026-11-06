//! Memory-backend abstraction used by the Auto Assembler engine.
//!
//! The AA engine is written against [`MemoryOps`] so that script execution
//! (aobscan/alloc/patch/rollback) is fully unit-testable without a live
//! process. [`LiveMemory`] adapts the engine's validated [`MemoryAccess`] +
//! cached maps; [`MockMemory`] (tests only) is a flat in-memory backend.

use std::collections::HashSet;

use memchr::memmem::Finder;

use crate::error::{EngineError, EngineResult};
use crate::memory::regions::is_module_path;
use crate::memory::{find_module, module_base, MemoryAccess, MemoryRegion, ModuleInfo};
use crate::resolver::signature::{all_matches, PatternByte};

/// Cap on scan results returned by one AOB scan (safety valve; CE's aobscan
/// expects a unique match, and the AA layer enforces that on top).
pub const MAX_AOB_RESULTS: usize = 4096;
/// Largest single region an AOB scan will read. Regions are read in chunks, so
/// this does not guard our memory. A larger region cannot be fully backed on a
/// 16 GiB Deck, so it is mostly untouched reservation, and reading that costs
/// seconds of engine time and grows the target's page tables (measured in a dev
/// container, not on a Deck: 5 GiB/s and 2 MiB of page tables per GiB).
const MAX_SCAN_REGION: usize = 16 * 1024 * 1024 * 1024;
/// Scan chunk size.
pub(crate) const SCAN_CHUNK: usize = 4 * 1024 * 1024;

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
    let info =
        find_module(maps, module).ok_or_else(|| EngineError::ModuleNotFound(module.to_string()))?;
    let end = read_size_of_image(mem, info.base)
        .map(|s| info.base.saturating_add(s))
        .unwrap_or(info.end);
    Ok((info.base, end))
}

/// The `(addr, len)` reads that cover `[start, end)` one [`SCAN_CHUNK`] at a
/// time. Each read after the first starts `overlap` bytes early, so with an
/// `overlap` of the pattern length minus one, every match appears in exactly
/// one read: the one covering its last byte. Yields nothing for an empty range.
pub(crate) fn scan_chunks(
    start: usize,
    end: usize,
    overlap: usize,
) -> impl Iterator<Item = (usize, usize)> {
    let mut next = start;
    std::iter::from_fn(move || {
        if next >= end {
            return None;
        }
        let addr = next - overlap.min(next - start);
        next = end.min(next.saturating_add(SCAN_CHUNK));
        Some((addr, next - addr))
    })
}

/// Every file-backed module mapped into the process, with `end` taken from
/// [`module_span`] so PE sections that Proton maps anonymously count as part of
/// their module. Pseudo-paths such as `[heap]` are not modules.
pub(crate) fn loaded_modules(mem: &MemoryAccess, maps: &[MemoryRegion]) -> Vec<ModuleInfo> {
    let mut seen = HashSet::new();
    let mut modules = Vec::new();
    for path in maps
        .iter()
        .filter_map(|r| r.path.as_deref())
        .filter(|p| is_module_path(p))
    {
        let name = path.rsplit('/').next().unwrap_or(path);
        if !seen.insert(name.to_ascii_lowercase()) {
            continue;
        }
        if let (Some(mut info), Ok((base, end))) =
            (find_module(maps, name), module_span(mem, maps, name))
        {
            info.base = base;
            info.end = end;
            modules.push(info);
        }
    }
    modules
}

/// `region` clipped to `[lo, hi)`, or `None` when nothing is left to scan or the
/// result is over [`MAX_SCAN_REGION`], which is logged.
fn scan_bounds(region: &MemoryRegion, lo: usize, hi: usize) -> Option<(usize, usize)> {
    let (start, end) = (region.start.max(lo), region.end.min(hi));
    if start >= end {
        return None;
    }
    if end - start > MAX_SCAN_REGION {
        eprintln!(
            "[aob_scan] skipping region 0x{start:X}..0x{end:X}: {} bytes is over the {MAX_SCAN_REGION} byte limit",
            end - start
        );
        return None;
    }
    Some((start, end))
}

/// Append to `hits` every occurrence of `needle` in `[start, end)` at an address
/// that is a multiple of `align`, stopping once `hits` holds `max` addresses.
/// Overlapping occurrences all count; chunks that cannot be read are skipped.
pub(crate) fn find_bytes(
    mem: &MemoryAccess,
    start: usize,
    end: usize,
    needle: &[u8],
    align: usize,
    max: usize,
    hits: &mut Vec<usize>,
) {
    if needle.is_empty() {
        return;
    }
    let finder = Finder::new(needle);
    for (addr, len) in scan_chunks(start, end, needle.len() - 1) {
        let Ok(data) = mem.read_bytes(addr, len) else {
            continue;
        };
        for i in occurrences(&data, &finder) {
            if (addr + i) % align == 0 {
                hits.push(addr + i);
                if hits.len() >= max {
                    return;
                }
            }
        }
    }
}

/// Start offsets of every occurrence in `data`, overlapping ones included.
/// `memmem::find_iter` would skip those, and they can be the aligned hits.
fn occurrences<'a>(data: &'a [u8], finder: &'a Finder) -> impl Iterator<Item = usize> + 'a {
    let mut pos = 0;
    std::iter::from_fn(move || {
        let found = pos + finder.find(&data[pos..])?;
        pos = found + 1;
        Some(found)
    })
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
            let Some((start, end)) = scan_bounds(region, lo, hi) else {
                continue;
            };
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
            let Some((clipped_start, clipped_end)) = scan_bounds(region, start, stop) else {
                continue;
            };
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

#[cfg(test)]
mod scan_tests {
    use super::*;

    const START: usize = 0x1000_0000;

    /// The reads that fully contain a match at `[pos, pos + len)`.
    fn reads_containing(reads: &[(usize, usize)], pos: usize, len: usize) -> usize {
        reads
            .iter()
            .filter(|(addr, size)| *addr <= pos && pos + len <= addr + size)
            .count()
    }

    #[test]
    fn every_match_is_in_exactly_one_read() {
        let end = START + 3 * SCAN_CHUNK + 123;
        for len in [1, 2, 8, 4096, SCAN_CHUNK, SCAN_CHUNK + 1, 2 * SCAN_CHUNK + 7] {
            let reads: Vec<_> = scan_chunks(START, end, len - 1).collect();
            let mut positions = vec![START, end - len];
            for boundary in 1..=3 {
                let boundary = START + boundary * SCAN_CHUNK;
                positions.extend((0..=len.min(16)).map(|back| boundary - back));
                positions.push(boundary - len);
                positions.push(boundary);
            }
            for pos in positions {
                if pos >= START && pos + len <= end {
                    assert_eq!(reads_containing(&reads, pos, len), 1, "len {len} at 0x{pos:x}");
                }
            }
        }
    }

    #[test]
    fn reads_stay_in_range_and_cover_it() {
        let end = START + 2 * SCAN_CHUNK + 1;
        let reads: Vec<_> = scan_chunks(START, end, 7).collect();
        assert_eq!(
            reads,
            [
                (START, SCAN_CHUNK),
                (START + SCAN_CHUNK - 7, SCAN_CHUNK + 7),
                (START + 2 * SCAN_CHUNK - 7, 8),
            ]
        );
    }

    #[test]
    fn empty_ranges_read_nothing() {
        assert_eq!(scan_chunks(START, START, 7).count(), 0);
        assert_eq!(scan_chunks(START + 1, START, 7).count(), 0);
    }

    #[test]
    fn occurrences_agree_with_a_sliding_window() {
        let data = b"aaaabaaabaaaaa\x00\x00\x00\x00ab";
        let needles: [&[u8]; 7] = [b"a", b"aa", b"aaa", b"aab", b"ab", b"\x00\x00", b"missing"];
        for needle in needles {
            let expected: Vec<usize> = data
                .windows(needle.len())
                .enumerate()
                .filter(|(_, w)| *w == needle)
                .map(|(i, _)| i)
                .collect();
            let finder = Finder::new(needle);
            let found: Vec<usize> = occurrences(data, &finder).collect();
            assert_eq!(found, expected, "{needle:?}");
        }
    }

    #[test]
    fn occurrences_handle_a_needle_longer_than_the_data() {
        let finder = Finder::new(b"abc");
        assert_eq!(occurrences(b"ab", &finder).count(), 0);
        assert_eq!(occurrences(b"", &finder).count(), 0);
    }

    fn region(start: usize, end: usize) -> MemoryRegion {
        MemoryRegion {
            start,
            end,
            readable: true,
            writable: true,
            executable: false,
            private: true,
            path: None,
        }
    }

    #[test]
    fn scan_bounds_clips_to_the_requested_span() {
        let r = region(START, START + 0x1000);
        assert_eq!(scan_bounds(&r, 0, usize::MAX), Some((START, START + 0x1000)));
        assert_eq!(
            scan_bounds(&r, START + 0x10, START + 0x20),
            Some((START + 0x10, START + 0x20))
        );
        assert_eq!(scan_bounds(&r, START + 0x1000, usize::MAX), None);
    }

    #[test]
    fn scan_bounds_limits_the_clipped_size_not_the_region_size() {
        let at_limit = region(START, START + MAX_SCAN_REGION);
        assert!(scan_bounds(&at_limit, 0, usize::MAX).is_some());

        let over = region(START, START + MAX_SCAN_REGION + 1);
        assert_eq!(scan_bounds(&over, 0, usize::MAX), None);
        assert_eq!(
            scan_bounds(&over, START, START + 0x1000),
            Some((START, START + 0x1000))
        );
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

#[cfg(all(test, target_os = "linux"))]
mod live_tests {
    use super::*;
    use crate::resolver::signature::parse_pattern;

    const SIZE: usize = 1024 * 1024 * 1024;
    /// Past the 512 MiB where these regions used to be skipped.
    const PLANTED: usize = 700 * 1024 * 1024;
    const NEEDLE: [u8; 4] = [0xDE, 0xC0, 0xAD, 0x0B];

    /// A real 1 GiB mapping in this process that costs almost no memory: it is
    /// inaccessible apart from a window of chunks around `PLANTED`, so the other
    /// reads fail quickly and only the planted page is touched. A read that
    /// starts in the inaccessible part fails whole, so the window starts a chunk
    /// before the one holding `PLANTED`, whose overlap reaches back into it.
    struct SparseRegion {
        base: *mut libc::c_void,
    }

    impl SparseRegion {
        fn new() -> Self {
            // SAFETY: an anonymous mapping at an address the kernel picks, used
            // only through `base` and unmapped on drop. The window is inside it.
            let base = unsafe {
                let base = libc::mmap(
                    std::ptr::null_mut(),
                    SIZE,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                    -1,
                    0,
                );
                assert_ne!(base, libc::MAP_FAILED);
                let window = base.cast::<u8>().add((PLANTED / SCAN_CHUNK - 1) * SCAN_CHUNK);
                let prot = libc::PROT_READ | libc::PROT_WRITE;
                assert_eq!(libc::mprotect(window.cast(), 3 * SCAN_CHUNK, prot), 0);
                std::ptr::copy_nonoverlapping(
                    NEEDLE.as_ptr(),
                    base.cast::<u8>().add(PLANTED),
                    NEEDLE.len(),
                );
                base
            };
            Self { base }
        }

        fn start(&self) -> usize {
            self.base as usize
        }

        fn maps(&self) -> Vec<MemoryRegion> {
            vec![MemoryRegion {
                start: self.start(),
                end: self.start() + SIZE,
                readable: true,
                writable: true,
                executable: false,
                private: true,
                path: None,
            }]
        }
    }

    impl Drop for SparseRegion {
        fn drop(&mut self) {
            // SAFETY: `base` is the start of a live mapping of `SIZE` bytes.
            unsafe { libc::munmap(self.base, SIZE) };
        }
    }

    #[test]
    fn aob_scan_finds_a_match_in_a_region_over_512_mib() {
        let region = SparseRegion::new();
        let mem = MemoryAccess::new(std::process::id() as i32);
        let maps = region.maps();
        let live = LiveMemory::new(&mem, &maps, "game.exe");
        let pattern = parse_pattern("DE C0 AD 0B").unwrap();
        assert_eq!(
            live.aob_scan(None, &pattern).unwrap(),
            [region.start() + PLANTED]
        );
    }

    #[test]
    fn aob_scan_range_finds_a_match_in_a_range_over_512_mib() {
        let region = SparseRegion::new();
        let mem = MemoryAccess::new(std::process::id() as i32);
        let maps = region.maps();
        let live = LiveMemory::new(&mem, &maps, "game.exe");
        let pattern = parse_pattern("DE C0 AD 0B").unwrap();
        let (start, stop) = (region.start(), region.start() + SIZE);
        assert_eq!(
            live.aob_scan_range(start, stop, &pattern).unwrap(),
            [start + PLANTED]
        );
    }
}
