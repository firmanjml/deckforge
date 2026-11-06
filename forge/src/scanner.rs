//! Value scanner: scan a process's writable memory for a specific value,
//! then filter previous results to narrow down to a single address.
//!
//! This is the classic Cheat Engine "first scan → next scan" workflow. It reads
//! all writable regions and searches for the target value as a little-endian
//! integer of the requested width.

use crate::error::{EngineError, EngineResult};
use crate::memory::regions::is_scannable;
use crate::memory::{MemoryAccess, MemoryRegion};

/// Largest single region a scan reads. Regions are read in chunks, so this only
/// guards against scanning huge reservations the game never touches.
const MAX_SCAN_REGION: usize = 1024 * 1024 * 1024;
/// Cap on stored matches, which keeps a very common value from exhausting memory.
const MAX_RESULTS: usize = 10_000_000;

/// Holds the state of a value scan session: the set of addresses that matched
/// the last scan, ready to be filtered by the next value.
#[derive(Default)]
pub struct ScanState {
    pub results: Vec<usize>,
    pub width: usize,
}

impl ScanState {
    pub fn clear(&mut self) {
        self.results.clear();
        self.width = 0;
    }

    pub fn count(&self) -> usize {
        self.results.len()
    }
}

/// Scan all writable, readable regions for `value` as a `width`-byte integer
/// or float. Returns the matching addresses. Replaces any previous scan state.
pub fn first_scan(
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    value: f64,
    width: usize,
    is_float: bool,
) -> EngineResult<Vec<usize>> {
    let needle = if is_float {
        encode_float(value, width)?
    } else {
        encode_value(value as i64, width)?
    };
    let mut found = Vec::new();

    for region in maps.iter().filter(|r| is_scannable(r)) {
        let size = region.size();
        if size == 0 {
            continue;
        }
        if size > MAX_SCAN_REGION {
            eprintln!(
                "[forge] scan: skipping {size}-byte region at 0x{:x}",
                region.start
            );
            continue;
        }
        // Read in 1MB chunks to avoid blocking on huge regions and to make
        // partial reads non-fatal.
        const CHUNK: usize = 1024 * 1024;
        let mut offset = 0usize;
        while offset < size {
            let chunk_size = CHUNK.min(size - offset);
            let addr = region.start + offset;
            match mem.read_bytes(addr, chunk_size) {
                Ok(data) => {
                    scan_region(&data, addr, &needle, &mut found);
                    if found.len() > MAX_RESULTS {
                        return Err(EngineError::InvalidRequest(format!(
                            "more than {MAX_RESULTS} matches; scan for a less common value"
                        )));
                    }
                }
                Err(_) => {
                    // Skip unreadable chunks (unmapped pages, etc.)
                }
            }
            offset += chunk_size;
        }
    }
    Ok(found)
}

/// Filter previous results: keep only addresses whose current value equals
/// `value`.
pub fn next_scan(
    mem: &MemoryAccess,
    prev: &[usize],
    value: f64,
    width: usize,
    is_float: bool,
) -> EngineResult<Vec<usize>> {
    let needle = if is_float {
        encode_float(value, width)?
    } else {
        encode_value(value as i64, width)?
    };
    let mut found = Vec::new();
    for &addr in prev {
        match mem.read_bytes(addr, width) {
            Ok(data) => {
                if data == needle {
                    found.push(addr);
                }
            }
            Err(_) => {}
        }
    }
    Ok(found)
}

/// Check whether an address falls within a mapped module (static) or is in
/// heap/anonymous memory (dynamic). Returns (module_name, module_offset).
pub fn classify_address(maps: &[MemoryRegion], addr: usize) -> Option<(String, usize)> {
    for r in maps {
        if addr >= r.start && addr < r.end {
            if let Some(path) = &r.path {
                let base = maps
                    .iter()
                    .filter(|m| m.path.as_deref() == Some(path))
                    .map(|m| m.start)
                    .min()?;
                let name = path.rsplit('/').next().unwrap_or(path).to_string();
                return Some((name, addr - base));
            }
            return None; // anonymous region
        }
    }
    None
}

fn scan_region(data: &[u8], base: usize, needle: &[u8], found: &mut Vec<usize>) {
    let nlen = needle.len();
    if nlen == 0 || nlen > data.len() {
        return;
    }
    for (i, window) in data.windows(nlen).enumerate() {
        if window == needle {
            found.push(base + i);
        }
    }
}

fn encode_value(value: i64, width: usize) -> EngineResult<Vec<u8>> {
    Ok(match width {
        4 => (value as i32).to_ne_bytes().to_vec(),
        8 => value.to_ne_bytes().to_vec(),
        2 => (value as i16).to_ne_bytes().to_vec(),
        1 => (value as i8).to_ne_bytes().to_vec(),
        _ => {
            return Err(EngineError::InvalidRequest(format!(
                "unsupported width {width}"
            )))
        }
    })
}

/// Encode a float value (f64) as a little-endian byte pattern for scanning.
/// GameMaker stores all numbers as float64, so width=8 gives the double
/// representation. width=4 gives float32 (truncated).
fn encode_float(value: f64, width: usize) -> EngineResult<Vec<u8>> {
    Ok(match width {
        4 => (value as f32).to_ne_bytes().to_vec(),
        8 => value.to_ne_bytes().to_vec(),
        _ => {
            return Err(EngineError::InvalidRequest(format!(
                "unsupported float width {width}"
            )))
        }
    })
}

#[cfg(all(test, target_os = "linux"))]
mod live_tests {
    use super::*;
    use crate::memory::regions::parse_maps;
    use crate::process::procfs::read_maps_raw;

    /// Reads this test process's own memory, which needs no extra privileges.
    fn own_process() -> (MemoryAccess, Vec<MemoryRegion>) {
        let pid = std::process::id() as i32;
        let maps = parse_maps(&read_maps_raw(pid).expect("read maps"));
        (MemoryAccess::new(pid), maps)
    }

    #[test]
    fn first_scan_finds_value_in_region_over_64_mib() {
        const VALUE: i64 = 0x0012_3456_789A_BCDE;
        const OFFSET: usize = 70 * 1024 * 1024;
        let mut buf = vec![0u8; 80 * 1024 * 1024];
        buf[OFFSET..OFFSET + 8].copy_from_slice(&VALUE.to_ne_bytes());
        std::hint::black_box(&mut buf);
        let addr = buf.as_ptr() as usize + OFFSET;

        let (mem, maps) = own_process();
        let found = first_scan(&mem, &maps, VALUE as f64, 8, false).expect("scan");
        assert!(found.contains(&addr));
    }
}
