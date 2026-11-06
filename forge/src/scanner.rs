//! Value scanner: find an unknown address by narrowing candidates over several
//! passes, as in Cheat Engine's "first scan → next scan" workflow.
//!
//! A scan starts from an exact value or from a snapshot of all scannable memory
//! (an unknown starting value). Later passes keep candidates by exact value, or
//! by how they changed since the previous pass. Integers compare as signed.

use std::cmp::Ordering;

use serde::Deserialize;
use serde_json::Value;

use crate::error::{EngineError, EngineResult};
use crate::memory::regions::is_scannable;
use crate::memory::{MemoryAccess, MemoryRegion, ModuleInfo};

const CHUNK: usize = 1024 * 1024;
/// Largest single region a scan reads. Regions are read in chunks, so this only
/// guards against scanning huge reservations the game never touches.
const MAX_SCAN_REGION: usize = 1024 * 1024 * 1024;
/// Cap on stored matches, which keeps a very common value from exhausting memory.
const MAX_RESULTS: usize = 10_000_000;
/// Cap on the memory an unknown-value scan keeps as its baseline.
const MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// How a later pass decides which candidates to keep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    #[default]
    Exact,
    Increased,
    Decreased,
    Changed,
    Unchanged,
}

/// Width and encoding of the value being scanned for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ValueFormat {
    pub width: usize,
    pub float: bool,
}

impl ValueFormat {
    pub fn new(width: usize, float: bool) -> EngineResult<Self> {
        let valid = if float {
            matches!(width, 4 | 8)
        } else {
            matches!(width, 1 | 2 | 4 | 8)
        };
        if !valid {
            let kind = if float { "float" } else { "integer" };
            return Err(EngineError::InvalidRequest(format!(
                "unsupported {kind} width {width}"
            )));
        }
        Ok(Self { width, float })
    }

    fn decode_float(self, raw: &[u8]) -> f64 {
        match self.width {
            4 => f32::from_ne_bytes(raw[..4].try_into().unwrap()) as f64,
            _ => f64::from_ne_bytes(raw[..8].try_into().unwrap()),
        }
    }

    fn decode_int(self, raw: &[u8]) -> i64 {
        match self.width {
            1 => raw[0] as i8 as i64,
            2 => i16::from_ne_bytes(raw[..2].try_into().unwrap()) as i64,
            4 => i32::from_ne_bytes(raw[..4].try_into().unwrap()) as i64,
            _ => i64::from_ne_bytes(raw[..8].try_into().unwrap()),
        }
    }

    /// How `current` compares to `previous`. `None` when a float is NaN.
    fn compare(self, current: &[u8], previous: &[u8]) -> Option<Ordering> {
        if self.float {
            self.decode_float(current)
                .partial_cmp(&self.decode_float(previous))
        } else {
            Some(self.decode_int(current).cmp(&self.decode_int(previous)))
        }
    }
}

/// Matches an exact value, or a float within a tolerance.
struct ExactMatcher {
    format: ValueFormat,
    needle: Vec<u8>,
    near_float: Option<(f64, f64)>,
}

impl ExactMatcher {
    fn new(format: ValueFormat, value: &Value, tolerance: Option<f64>) -> EngineResult<Self> {
        if let Some(t) = tolerance {
            if !format.float {
                return Err(EngineError::InvalidRequest(
                    "tolerance only applies to float scans".into(),
                ));
            }
            if !t.is_finite() || t < 0.0 {
                return Err(EngineError::InvalidRequest(format!(
                    "invalid tolerance {t}"
                )));
            }
        }
        if format.float {
            let number = value
                .as_f64()
                .ok_or_else(|| EngineError::InvalidRequest("expected number".into()))?;
            let needle = if format.width == 4 {
                (number as f32).to_ne_bytes().to_vec()
            } else {
                number.to_ne_bytes().to_vec()
            };
            return Ok(Self {
                format,
                needle,
                near_float: tolerance.map(|t| (number, t)),
            });
        }
        let number = value
            .as_i64()
            .or_else(|| value.as_u64().map(|v| v as i64))
            .ok_or_else(|| EngineError::InvalidRequest("expected integer".into()))?;
        Ok(Self {
            format,
            needle: number.to_ne_bytes()[..format.width].to_vec(),
            near_float: None,
        })
    }

    fn matches(&self, raw: &[u8]) -> bool {
        match self.near_float {
            Some((target, tolerance)) => {
                (self.format.decode_float(raw) - target).abs() <= tolerance
            }
            None => raw == self.needle,
        }
    }

    /// Exact bytes can sit at any offset. Tolerance matching decodes every
    /// candidate, so it checks aligned values only.
    fn step(&self) -> usize {
        if self.near_float.is_some() {
            self.format.width
        } else {
            1
        }
    }
}

/// A copy of scannable memory, kept until the first filter of an unknown scan.
struct Snapshot {
    start: usize,
    data: Vec<u8>,
}

/// The state of a scan session: the candidates left after the last pass, with
/// the value each held then.
#[derive(Default)]
pub struct ScanState {
    pub results: Vec<usize>,
    previous: Vec<[u8; 8]>,
    format: ValueFormat,
    baseline: Vec<Snapshot>,
}

impl ScanState {
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Candidate count. An unknown scan counts every aligned value in memory.
    pub fn count(&self) -> usize {
        if self.baseline.is_empty() {
            self.results.len()
        } else {
            let bytes: usize = self.baseline.iter().map(|s| s.data.len()).sum();
            bytes / self.format.width
        }
    }

    fn is_active(&self) -> bool {
        !self.results.is_empty() || !self.baseline.is_empty()
    }

    /// Begin a new scan. With no `value`, snapshots memory for later comparison.
    pub fn start(
        &mut self,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
        format: ValueFormat,
        value: Option<&Value>,
        tolerance: Option<f64>,
    ) -> EngineResult<()> {
        self.clear();
        self.format = format;
        match value {
            None => self.baseline = take_snapshot(mem, maps)?,
            Some(value) => {
                let matcher = ExactMatcher::new(format, value, tolerance)?;
                (self.results, self.previous) = first_scan(mem, maps, &matcher)?;
            }
        }
        Ok(())
    }

    /// Narrow the candidates. `value` and `tolerance` apply to [`ScanMode::Exact`].
    /// On error the previous candidates are kept, so a different filter can be tried.
    pub fn filter(
        &mut self,
        mem: &MemoryAccess,
        mode: ScanMode,
        value: Option<&Value>,
        tolerance: Option<f64>,
    ) -> EngineResult<()> {
        if !self.is_active() {
            return Err(EngineError::InvalidRequest(
                "no previous scan to filter; run scan_value first".into(),
            ));
        }
        let format = self.format;
        let matcher = match (mode, value) {
            (ScanMode::Exact, Some(value)) => Some(ExactMatcher::new(format, value, tolerance)?),
            (ScanMode::Exact, None) => {
                return Err(EngineError::InvalidRequest(
                    "an exact filter needs a value".into(),
                ))
            }
            _ => None,
        };
        let keep = |current: &[u8], previous: &[u8]| match mode {
            ScanMode::Exact => matcher.as_ref().is_some_and(|m| m.matches(current)),
            ScanMode::Changed => current != previous,
            ScanMode::Unchanged => current == previous,
            ScanMode::Increased => format.compare(current, previous) == Some(Ordering::Greater),
            ScanMode::Decreased => format.compare(current, previous) == Some(Ordering::Less),
        };

        let mut results = Vec::new();
        let mut previous = Vec::new();
        let mut push = |address: usize, current: &[u8]| -> EngineResult<()> {
            if results.len() >= MAX_RESULTS {
                return Err(too_many_matches());
            }
            results.push(address);
            previous.push(to_slot(current));
            Ok(())
        };

        if self.baseline.is_empty() {
            for (&address, old) in self.results.iter().zip(&self.previous) {
                if let Ok(current) = mem.read_bytes(address, format.width) {
                    if current.len() == format.width && keep(&current, &old[..format.width]) {
                        push(address, &current)?;
                    }
                }
            }
        } else {
            for snapshot in &self.baseline {
                let Ok(data) = mem.read_bytes(snapshot.start, snapshot.data.len()) else {
                    continue;
                };
                let values = data
                    .chunks_exact(format.width)
                    .zip(snapshot.data.chunks_exact(format.width));
                for (i, (current, old)) in values.enumerate() {
                    if keep(current, old) {
                        push(snapshot.start + i * format.width, current)?;
                    }
                }
            }
        }

        self.results = results;
        self.previous = previous;
        self.baseline.clear();
        Ok(())
    }
}

fn too_many_matches() -> EngineError {
    EngineError::InvalidRequest(format!(
        "more than {MAX_RESULTS} matches; use a less common value or a stricter filter"
    ))
}

fn to_slot(raw: &[u8]) -> [u8; 8] {
    let mut slot = [0u8; 8];
    slot[..raw.len()].copy_from_slice(raw);
    slot
}

/// Call `visit` with each readable chunk of scannable memory.
fn for_each_chunk(
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    mut visit: impl FnMut(usize, Vec<u8>) -> EngineResult<()>,
) -> EngineResult<()> {
    for region in maps.iter().filter(|r| is_scannable(r)) {
        let size = region.size();
        if size > MAX_SCAN_REGION {
            eprintln!(
                "[forge] scan: skipping {size}-byte region at 0x{:x}",
                region.start
            );
            continue;
        }
        let mut offset = 0;
        while offset < size {
            let len = CHUNK.min(size - offset);
            let address = region.start + offset;
            offset += len;
            // Pages can be unmapped at any time, so a failed read is not fatal.
            if let Ok(data) = mem.read_bytes(address, len) {
                visit(address, data)?;
            }
        }
    }
    Ok(())
}

fn first_scan(
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    matcher: &ExactMatcher,
) -> EngineResult<(Vec<usize>, Vec<[u8; 8]>)> {
    let width = matcher.format.width;
    let step = matcher.step();
    let mut results = Vec::new();
    let mut previous = Vec::new();
    for_each_chunk(mem, maps, |address, data| {
        if data.len() < width {
            return Ok(());
        }
        for i in (0..=data.len() - width).step_by(step) {
            let raw = &data[i..i + width];
            if matcher.matches(raw) {
                if results.len() >= MAX_RESULTS {
                    return Err(too_many_matches());
                }
                results.push(address + i);
                previous.push(to_slot(raw));
            }
        }
        Ok(())
    })?;
    Ok((results, previous))
}

fn take_snapshot(mem: &MemoryAccess, maps: &[MemoryRegion]) -> EngineResult<Vec<Snapshot>> {
    let mut snapshots = Vec::new();
    let mut total = 0;
    for_each_chunk(mem, maps, |start, data| {
        total += data.len();
        if total > MAX_SNAPSHOT_BYTES {
            return Err(EngineError::InvalidRequest(format!(
                "more than {MAX_SNAPSHOT_BYTES} bytes of memory to snapshot; scan for a known value instead"
            )));
        }
        snapshots.push(Snapshot { start, data });
        Ok(())
    })?;
    Ok(snapshots)
}

/// Find the module containing `addr`, returning its name and the offset from
/// its base. `None` means the address is in dynamic memory such as the heap.
pub fn classify_address(modules: &[ModuleInfo], addr: usize) -> Option<(&str, usize)> {
    modules
        .iter()
        .find(|m| addr >= m.base && addr < m.end)
        .map(|m| (m.name.as_str(), addr - m.base))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classify_counts_anonymous_sections_inside_a_module_span() {
        // Only the PE header is file-backed, as under Proton; the span covers
        // the rest of the image.
        let modules = vec![ModuleInfo {
            name: "Game.exe".into(),
            base: 0x1_4000_0000,
            end: 0x1_4100_0000,
            regions: Vec::new(),
        }];
        assert_eq!(
            classify_address(&modules, 0x1_4080_0010),
            Some(("Game.exe", 0x80_0010))
        );
        assert_eq!(classify_address(&modules, 0x1_4100_0000), None);
    }

    #[test]
    fn format_rejects_invalid_widths() {
        assert!(ValueFormat::new(4, false).is_ok());
        assert!(ValueFormat::new(8, true).is_ok());
        assert!(ValueFormat::new(2, true).is_err());
        assert!(ValueFormat::new(3, false).is_err());
    }

    #[test]
    fn compare_treats_integers_as_signed() {
        let format = ValueFormat::new(4, false).unwrap();
        let minus_one = (-1i32).to_ne_bytes();
        let one = 1i32.to_ne_bytes();
        assert_eq!(format.compare(&minus_one, &one), Some(Ordering::Less));
    }

    #[test]
    fn compare_returns_none_for_nan() {
        let format = ValueFormat::new(4, true).unwrap();
        let nan = f32::NAN.to_ne_bytes();
        let one = 1f32.to_ne_bytes();
        assert_eq!(format.compare(&nan, &one), None);
    }

    #[test]
    fn exact_float_needs_identical_bytes() {
        let format = ValueFormat::new(4, true).unwrap();
        let matcher = ExactMatcher::new(format, &json!(73.0), None).unwrap();
        assert!(matcher.matches(&73f32.to_ne_bytes()));
        assert!(!matcher.matches(&73.25f32.to_ne_bytes()));
    }

    #[test]
    fn tolerance_finds_the_real_value_behind_a_rounded_display() {
        let format = ValueFormat::new(4, true).unwrap();
        let matcher = ExactMatcher::new(format, &json!(73.0), Some(0.5)).unwrap();
        assert!(matcher.matches(&73.25f32.to_ne_bytes()));
        assert!(!matcher.matches(&74f32.to_ne_bytes()));
        assert!(!matcher.matches(&f32::NAN.to_ne_bytes()));
    }

    #[test]
    fn tolerance_is_rejected_for_integers_and_invalid_values() {
        let int = ValueFormat::new(4, false).unwrap();
        assert!(ExactMatcher::new(int, &json!(1), Some(0.5)).is_err());
        let float = ValueFormat::new(4, true).unwrap();
        assert!(ExactMatcher::new(float, &json!(1), Some(-1.0)).is_err());
    }

    #[test]
    fn integer_needle_uses_requested_width() {
        let format = ValueFormat::new(2, false).unwrap();
        let matcher = ExactMatcher::new(format, &json!(-2), None).unwrap();
        assert!(matcher.matches(&(-2i16).to_ne_bytes()));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod live_tests {
    use super::*;
    use crate::memory::regions::parse_maps;
    use crate::process::procfs::read_maps_raw;
    use serde_json::json;

    /// Reads this test process's own memory, which needs no extra privileges.
    fn own_process() -> (MemoryAccess, Vec<MemoryRegion>) {
        let pid = std::process::id() as i32;
        let maps = parse_maps(&read_maps_raw(pid).expect("read maps"));
        (MemoryAccess::new(pid), maps)
    }

    #[test]
    fn exact_scan_finds_value_in_region_over_64_mib() {
        const VALUE: i64 = 0x7123_4567_89AB_CDEF;
        const OFFSET: usize = 70 * 1024 * 1024;
        let mut buf = vec![0u8; 80 * 1024 * 1024];
        buf[OFFSET..OFFSET + 8].copy_from_slice(&VALUE.to_ne_bytes());
        std::hint::black_box(&mut buf);
        let addr = buf.as_ptr() as usize + OFFSET;

        let (mem, maps) = own_process();
        let mut scan = ScanState::default();
        let format = ValueFormat::new(8, false).unwrap();
        scan.start(&mem, &maps, format, Some(&json!(VALUE)), None)
            .expect("scan");
        assert!(scan.results.contains(&addr));
    }

    #[test]
    fn exact_scan_then_comparison_filters_narrow_to_the_changed_value() {
        const FIRST: i32 = 0x3A7C_1E55;
        let mut value = Box::new([FIRST, FIRST]);
        std::hint::black_box(&mut value);
        let changing = value.as_ptr() as usize;
        let constant = changing + 4;

        let (mem, maps) = own_process();
        let mut scan = ScanState::default();
        let format = ValueFormat::new(4, false).unwrap();
        scan.start(&mem, &maps, format, Some(&json!(FIRST)), None)
            .expect("scan");
        assert!(scan.results.contains(&changing));
        assert!(scan.results.contains(&constant));

        value[0] = FIRST + 10;
        std::hint::black_box(&mut value);
        scan.filter(&mem, ScanMode::Unchanged, None, None)
            .expect("unchanged");
        assert!(!scan.results.contains(&changing));
        assert!(scan.results.contains(&constant));

        value[1] = FIRST - 10;
        std::hint::black_box(&mut value);
        scan.filter(&mem, ScanMode::Decreased, None, None)
            .expect("decreased");
        assert!(scan.results.contains(&constant));
    }

    #[test]
    fn unknown_scan_finds_a_decreased_float_near_a_rounded_value() {
        let mut value = Box::new(250.75f32);
        std::hint::black_box(&mut value);
        let addr = &*value as *const f32 as usize;

        let (mem, maps) = own_process();
        let mut scan = ScanState::default();
        let format = ValueFormat::new(4, true).unwrap();
        scan.start(&mem, &maps, format, None, None).expect("snapshot");
        assert!(scan.count() > 0);
        assert!(scan.results.is_empty());

        *value = 180.25;
        std::hint::black_box(&mut value);
        scan.filter(&mem, ScanMode::Decreased, None, None)
            .expect("decreased");
        assert!(scan.results.contains(&addr));

        scan.filter(&mem, ScanMode::Exact, Some(&json!(180)), Some(0.5))
            .expect("near");
        assert!(scan.results.contains(&addr));
    }

    #[test]
    fn filter_without_a_scan_is_an_error() {
        let (mem, _) = own_process();
        let mut scan = ScanState::default();
        assert!(scan.filter(&mem, ScanMode::Changed, None, None).is_err());
    }
}
