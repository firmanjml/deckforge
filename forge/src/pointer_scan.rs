//! Pointer scanner: find pointer chains from a module to a dynamic address.
//!
//! Scans once to index every value in writable memory that points at writable
//! memory, then walks that index backwards from the target. Each chain is a
//! ready-to-use `pointer` resolver, and is only returned after resolving it
//! against live memory reaches the target.
//!
//! The scan is 64-bit only, matching the `pointer` resolver.

use std::collections::HashSet;

use serde::Serialize;

use crate::error::EngineResult;
use crate::memory::regions::is_scannable;
use crate::memory::{MemoryAccess, MemoryRegion, ModuleInfo};
use crate::resolver::{pointer, HexValue};
use crate::scanner::classify_address;

const CHUNK: usize = 4 * 1024 * 1024;
const POINTER_SIZE: usize = 8;
const MAX_REGION: usize = 1024 * 1024 * 1024;
/// Caps memory use at about 320 MiB of index entries.
const MAX_INDEX_ENTRIES: usize = 20_000_000;
/// Caps how many addresses one search will explore.
const MAX_NODES: usize = 1_000_000;
const MAX_CHAINS: usize = 20;
const MAX_DEPTH: usize = 8;

/// A chain in the same shape as a `pointer` resolver in `trainer.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PointerChain {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub module: String,
    pub offset: String,
    pub offsets: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PointerScanResult {
    pub chains: Vec<PointerChain>,
    pub total_found: usize,
    /// True when a limit stopped the scan, so more chains may exist.
    pub truncated: bool,
}

/// An address on the way back from the target. `offset` is what gets added to
/// the pointer stored here to reach the next address towards the target.
struct Node {
    address: usize,
    next: Option<usize>,
    offset: usize,
}

/// Scan for pointer chains to `target`. `max_offset` limits the offset allowed
/// at each step. Offsets are never negative because the `pointer` resolver only
/// adds them.
pub fn scan_pointers(
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    target: usize,
    max_depth: usize,
    max_offset: usize,
) -> EngineResult<PointerScanResult> {
    let modules = crate::memory::ops::loaded_modules(mem, maps);
    let (index, mut truncated) = build_index(mem, maps);
    eprintln!("[forge] ptrscan: indexed {} pointers", index.len());

    let (found, search_truncated) = search(&index, &modules, target, max_depth, max_offset);
    truncated |= search_truncated;

    // Memory can change during a scan, so keep only chains that still work.
    let chains: Vec<PointerChain> = found
        .into_iter()
        .filter(|chain| reaches_target(chain, mem, maps, target))
        .collect();
    Ok(PointerScanResult {
        total_found: chains.len(),
        chains,
        truncated,
    })
}

/// Collect `(pointed-at value, address holding it)` pairs, sorted by value.
fn build_index(mem: &MemoryAccess, maps: &[MemoryRegion]) -> (Vec<(usize, usize)>, bool) {
    let regions: Vec<&MemoryRegion> = maps
        .iter()
        .filter(|r| is_scannable(r) && r.size() <= MAX_REGION)
        .collect();
    let mut ranges: Vec<(usize, usize)> = regions.iter().map(|r| (r.start, r.end)).collect();
    ranges.sort_unstable();

    let mut index = Vec::new();
    let mut truncated = false;
    'regions: for region in &regions {
        let mut offset = 0;
        while offset < region.size() {
            let len = CHUNK.min(region.size() - offset);
            let address = region.start + offset;
            offset += len;
            let Ok(data) = mem.read_bytes(address, len) else {
                continue;
            };
            for (i, bytes) in data.chunks_exact(POINTER_SIZE).enumerate() {
                let value = u64::from_ne_bytes(bytes.try_into().unwrap()) as usize;
                if in_ranges(&ranges, value) {
                    if index.len() >= MAX_INDEX_ENTRIES {
                        truncated = true;
                        break 'regions;
                    }
                    index.push((value, address + i * POINTER_SIZE));
                }
            }
        }
    }
    index.sort_unstable();
    (index, truncated)
}

fn in_ranges(sorted_ranges: &[(usize, usize)], value: usize) -> bool {
    let after = sorted_ranges.partition_point(|&(start, _)| start <= value);
    after > 0 && value < sorted_ranges[after - 1].1
}

/// Walk back from `target`, shortest chains first. A pointer stored inside a
/// module ends a chain; any other pointer is searched in the next round.
fn search(
    index: &[(usize, usize)],
    modules: &[ModuleInfo],
    target: usize,
    max_depth: usize,
    max_offset: usize,
) -> (Vec<PointerChain>, bool) {
    let mut nodes = vec![Node {
        address: target,
        next: None,
        offset: 0,
    }];
    let mut visited = HashSet::from([target]);
    let mut chains = Vec::new();
    let mut round = 0..1;

    for _ in 0..max_depth.min(MAX_DEPTH) {
        let round_end = nodes.len();
        for node_id in round {
            let address = nodes[node_id].address;
            let lowest = address.saturating_sub(max_offset);
            let first = index.partition_point(|&(value, _)| value < lowest);
            for &(value, holder) in index[first..].iter().take_while(|e| e.0 <= address) {
                let offset = address - value;
                if let Some((module, module_offset)) = classify_address(modules, holder) {
                    chains.push(build_chain(&nodes, node_id, module, module_offset, offset));
                    if chains.len() >= MAX_CHAINS {
                        return (chains, true);
                    }
                } else if visited.insert(holder) {
                    if nodes.len() >= MAX_NODES {
                        return (chains, true);
                    }
                    nodes.push(Node {
                        address: holder,
                        next: Some(node_id),
                        offset,
                    });
                }
            }
        }
        round = round_end..nodes.len();
    }
    (chains, false)
}

fn build_chain(
    nodes: &[Node],
    node_id: usize,
    module: &str,
    module_offset: usize,
    first_offset: usize,
) -> PointerChain {
    let mut offsets = vec![format!("0x{first_offset:X}")];
    let mut current = &nodes[node_id];
    while let Some(next) = current.next {
        offsets.push(format!("0x{:X}", current.offset));
        current = &nodes[next];
    }
    PointerChain {
        kind: "pointer",
        module: module.to_string(),
        offset: format!("0x{module_offset:X}"),
        offsets,
    }
}

fn reaches_target(
    chain: &PointerChain,
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    target: usize,
) -> bool {
    let offsets: Vec<HexValue> = chain.offsets.iter().cloned().map(HexValue::Str).collect();
    pointer::resolve(
        mem,
        maps,
        &chain.module,
        &HexValue::Str(chain.offset.clone()),
        &offsets,
    )
    .is_ok_and(|resolved| resolved == target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(base: usize, end: usize) -> ModuleInfo {
        ModuleInfo {
            name: "Game.exe".into(),
            base,
            end,
            regions: Vec::new(),
        }
    }

    #[test]
    fn range_lookup_includes_start_and_excludes_end() {
        let ranges = [(0x1000, 0x2000), (0x8000, 0x9000)];
        assert!(in_ranges(&ranges, 0x1000));
        assert!(!in_ranges(&ranges, 0x2000));
        assert!(in_ranges(&ranges, 0x8FFF));
        assert!(!in_ranges(&ranges, 0x500));
    }

    #[test]
    fn search_builds_offsets_from_module_towards_target() {
        // Game.exe+0x10 -> 0x5000; 0x5000 + 0x20 -> 0x7000; 0x7000 + 0x8 = target.
        let index = vec![(0x5000, 0x10_0010), (0x7000, 0x5020)];
        let modules = [module(0x10_0000, 0x20_0000)];
        let (chains, truncated) = search(&index, &modules, 0x7008, 3, 0x100);
        assert!(!truncated);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].offset, "0x10");
        assert_eq!(chains[0].offsets, ["0x20", "0x8"]);
    }

    #[test]
    fn search_never_produces_negative_offsets() {
        // This module pointer is above the target, so no offset can reach it.
        let index = vec![(0x7010, 0x10_0010)];
        let modules = [module(0x10_0000, 0x20_0000)];
        let (chains, _) = search(&index, &modules, 0x7008, 3, 0x100);
        assert!(chains.is_empty());
    }

    #[test]
    fn search_respects_depth_limit() {
        let index = vec![(0x5000, 0x10_0010), (0x7000, 0x5020)];
        let modules = [module(0x10_0000, 0x20_0000)];
        let (chains, _) = search(&index, &modules, 0x7008, 1, 0x100);
        assert!(chains.is_empty());
    }

    #[test]
    fn search_survives_pointer_cycles() {
        // 0x5000 and 0x6000 point at each other and nothing reaches a module.
        let index = vec![(0x5000, 0x6000), (0x6000, 0x5000)];
        let modules = [module(0x10_0000, 0x20_0000)];
        let (chains, _) = search(&index, &modules, 0x5000, 8, 0x100);
        assert!(chains.is_empty());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod live_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::memory::regions::parse_maps;
    use crate::process::procfs::read_maps_raw;

    // Non-zero initial values put these in the test binary's `.data` section.
    static BASE: AtomicUsize = AtomicUsize::new(1);
    static ABOVE_TARGET: AtomicUsize = AtomicUsize::new(1);

    /// Scans this test process's own memory for a real two-level chain.
    #[test]
    fn finds_chain_from_module_data_to_heap() {
        let value = Box::new([0u64; 16]);
        let mut middle = Box::new([0usize; 8]);
        middle[2] = value.as_ptr() as usize;
        let target = value.as_ptr() as usize + 0x18;
        BASE.store(middle.as_ptr() as usize, Ordering::SeqCst);
        ABOVE_TARGET.store(target + 0x20, Ordering::SeqCst);

        let pid = std::process::id() as i32;
        let maps = parse_maps(&read_maps_raw(pid).expect("read maps"));
        let mem = MemoryAccess::new(pid);
        let result = scan_pointers(&mem, &maps, target, 3, 0x40).expect("scan");

        let modules = crate::memory::ops::loaded_modules(&mem, &maps);
        let base = classify_address(&modules, BASE.as_ptr() as usize).expect("base");
        assert!(
            result.chains.iter().any(|c| {
                c.module == base.0
                    && c.offset == format!("0x{:X}", base.1)
                    && c.offsets == ["0x10", "0x18"]
            }),
            "expected chain missing from {:?}",
            result.chains
        );

        // A one-step chain from ABOVE_TARGET would need a negative offset.
        let above = classify_address(&modules, ABOVE_TARGET.as_ptr() as usize).expect("above");
        assert!(!result
            .chains
            .iter()
            .any(|c| c.offset == format!("0x{:X}", above.1) && c.offsets.len() == 1));
        std::hint::black_box((&value, &middle));
    }
}
