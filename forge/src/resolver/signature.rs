//! AOB / signature pattern parsing and scanning, plus the signature resolver.
//!
//! Patterns are parsed *once* into a [`Vec<PatternByte>`] and scanned with that
//! representation — never re-parsed per byte. The scanner reports no-match /
//! single / multiple so callers can refuse ambiguous matches.

use crate::error::{EngineError, EngineResult};
use crate::memory::ops::{module_span, scan_chunks};
use crate::memory::{MemoryAccess, MemoryRegion};

/// One byte of a parsed AOB pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternByte {
    Exact(u8),
    Wildcard,
}

/// Parse a pattern string like `"48 8B 05 ?? ?? ?? ?? 48 85 C0"` into bytes.
/// `??` (and bare `?`) are wildcards; every other token must be two hex digits.
pub fn parse_pattern(s: &str) -> EngineResult<Vec<PatternByte>> {
    let mut out = Vec::new();
    for tok in s.split_whitespace() {
        if tok.eq_ignore_ascii_case("??") || tok == "?" {
            out.push(PatternByte::Wildcard);
        } else if tok.len() == 2 {
            let b = u8::from_str_radix(tok, 16)
                .map_err(|_| EngineError::InvalidRequest(format!("invalid pattern byte '{tok}'")))?;
            out.push(PatternByte::Exact(b));
        } else {
            return Err(EngineError::InvalidRequest(format!(
                "invalid pattern token '{tok}'"
            )));
        }
    }
    if out.is_empty() {
        return Err(EngineError::InvalidRequest("empty pattern".into()));
    }
    Ok(out)
}

/// All match start offsets of `pattern` within `haystack`.
pub fn all_matches(haystack: &[u8], pattern: &[PatternByte]) -> Vec<usize> {
    let plen = pattern.len();
    if plen == 0 || plen > haystack.len() {
        return Vec::new();
    }
    let mut matches = Vec::new();
    for (i, window) in haystack.windows(plen).enumerate() {
        let mut ok = true;
        for (b, p) in window.iter().zip(pattern) {
            if let PatternByte::Exact(e) = p {
                if b != e {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            matches.push(i);
        }
    }
    matches
}

/// Classified result of a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanResult {
    NoMatch,
    Single(usize),
    Multiple(Vec<usize>),
}

/// Scan `haystack` for `pattern` and classify the outcome.
pub fn scan(haystack: &[u8], pattern: &[PatternByte]) -> ScanResult {
    match all_matches(haystack, pattern).len() {
        0 => ScanResult::NoMatch,
        1 => ScanResult::Single(all_matches(haystack, pattern)[0]),
        n => ScanResult::Multiple(all_matches(haystack, pattern)[..n].to_vec()),
    }
}

/// Require exactly one match, returning a structured error otherwise.
pub fn scan_unique(haystack: &[u8], pattern: &[PatternByte]) -> EngineResult<usize> {
    match scan(haystack, pattern) {
        ScanResult::NoMatch => Err(EngineError::SignatureNotFound),
        ScanResult::Single(off) => Ok(off),
        ScanResult::Multiple(_) => Err(EngineError::SignatureAmbiguous),
    }
}

/// Resolve a signature resolver to an absolute address.
///
/// Scans the module's whole address span, because Proton maps most PE sections
/// anonymously, and requires exactly one match across it. The optional `offset`
/// is added to the match.
pub fn resolve(
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    module: &str,
    pattern: &str,
    offset: Option<usize>,
) -> EngineResult<usize> {
    let (lo, hi) = module_span(mem, maps, module)?;
    let pat = parse_pattern(pattern)?;

    let mut found = None;
    for region in maps.iter().filter(|r| r.readable) {
        let (start, end) = (region.start.max(lo), region.end.min(hi));
        let mut logged = false;
        for (addr, len) in scan_chunks(start, end, pat.len() - 1) {
            match mem.read_bytes(addr, len) {
                Ok(data) => {
                    for off in all_matches(&data, &pat) {
                        // A second match settles the outcome.
                        if found.replace(addr + off).is_some() {
                            return Err(EngineError::SignatureAmbiguous);
                        }
                    }
                }
                Err(e) if !logged => {
                    // Skip what we cannot read (e.g. special mappings) but log.
                    eprintln!("[forge] signature scan: skip in region {start:x}-{end:x}: {e}");
                    logged = true;
                }
                Err(_) => {}
            }
        }
    }

    found
        .map(|addr| addr + offset.unwrap_or(0))
        .ok_or(EngineError::SignatureNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_and_wildcard() {
        let p = parse_pattern("48 8B 05 ?? ?? ?? ?? 48 85 C0").unwrap();
        assert_eq!(p.len(), 10);
        assert_eq!(p[0], PatternByte::Exact(0x48));
        assert_eq!(p[3], PatternByte::Wildcard);
        assert_eq!(p[6], PatternByte::Wildcard);
        assert_eq!(p[9], PatternByte::Exact(0xC0));
    }

    #[test]
    fn rejects_bad_tokens() {
        assert!(parse_pattern("48 8B ZZ").is_err());
        assert!(parse_pattern("48 8B 0").is_err()); // single hex digit
        assert!(parse_pattern("").is_err());
    }

    #[test]
    fn finds_single_match() {
        let p = parse_pattern("89 43 20").unwrap();
        let hay = [0x00, 0x89, 0x43, 0x20, 0xFF];
        assert_eq!(scan(&hay, &p), ScanResult::Single(1));
    }

    #[test]
    fn wildcard_matches_any_byte() {
        let p = parse_pattern("89 ?? 20").unwrap();
        let hay = [0x89, 0xAB, 0x20, 0x89, 0xCD, 0x20];
        assert_eq!(
            scan(&hay, &p),
            ScanResult::Multiple(vec![0, 3])
        );
    }

    #[test]
    fn no_match_returns_none() {
        let p = parse_pattern("DE AD BE EF").unwrap();
        let hay = [0x00, 0x01, 0x02, 0x03];
        assert_eq!(scan(&hay, &p), ScanResult::NoMatch);
    }

    #[test]
    fn scan_unique_errors_on_ambiguous() {
        let p = parse_pattern("AA").unwrap();
        let hay = [0xAA, 0xBB, 0xAA];
        assert!(matches!(scan_unique(&hay, &p), Err(EngineError::SignatureAmbiguous)));
    }

    #[test]
    fn scan_unique_errors_on_missing() {
        let p = parse_pattern("AA").unwrap();
        let hay = [0xBB, 0xCC];
        assert!(matches!(scan_unique(&hay, &p), Err(EngineError::SignatureNotFound)));
    }

    #[test]
    fn pattern_longer_than_haystack_is_no_match() {
        let p = parse_pattern("AA BB CC").unwrap();
        let hay = [0xAA, 0xBB];
        assert_eq!(scan(&hay, &p), ScanResult::NoMatch);
    }

    #[test]
    fn all_matches_returns_every_offset() {
        let p = parse_pattern("48 ?? 8B").unwrap();
        let hay = [0x48, 0x00, 0x8B, 0x48, 0x11, 0x8B, 0x48, 0x22, 0x99];
        assert_eq!(all_matches(&hay, &p), vec![0, 3]);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod live_tests {
    use super::*;
    use crate::memory::ops::SCAN_CHUNK;

    const PATTERN: &str = "DE C0 AD 0B 13 37 BE EF";
    const NEEDLE: [u8; 8] = [0xDE, 0xC0, 0xAD, 0x0B, 0x13, 0x37, 0xBE, 0xEF];
    const HEADER: usize = 0x1000;
    const IMAGE: usize = HEADER + SCAN_CHUNK + 0x1000;

    fn region(start: usize, end: usize, readable: bool, path: Option<&str>) -> MemoryRegion {
        MemoryRegion {
            start,
            end,
            readable,
            writable: false,
            executable: false,
            private: true,
            path: path.map(str::to_string),
        }
    }

    /// A PE image in this test process's memory, mapped the way Proton maps
    /// one: only the header page is file-backed and the sections are anonymous.
    /// Reading our own memory needs no extra privileges. The buffer runs past
    /// `SizeOfImage` so tests can plant bytes outside the module.
    struct FakeImage {
        buf: Vec<u8>,
    }

    impl FakeImage {
        fn new() -> Self {
            let mut buf = vec![0u8; IMAGE + 0x1000];
            buf[..2].copy_from_slice(b"MZ");
            buf[0x3C..0x40].copy_from_slice(&0x80u32.to_ne_bytes());
            buf[0x80 + 24 + 0x38..0x80 + 24 + 0x3C].copy_from_slice(&(IMAGE as u32).to_ne_bytes());
            Self { buf }
        }

        fn base(&self) -> usize {
            self.buf.as_ptr() as usize
        }

        /// Address where the anonymous section's chunks start.
        fn section(&self) -> usize {
            self.base() + HEADER
        }

        fn plant(&mut self, off: usize) -> usize {
            self.buf[off..off + NEEDLE.len()].copy_from_slice(&NEEDLE);
            self.base() + off
        }

        fn maps(&self) -> Vec<MemoryRegion> {
            let (base, section) = (self.base(), self.section());
            vec![
                region(base, section, true, Some("/games/Game.exe")),
                region(section, base + self.buf.len(), true, None),
            ]
        }

        fn resolve(&mut self, offset: Option<usize>) -> EngineResult<usize> {
            std::hint::black_box(&mut self.buf);
            let mem = MemoryAccess::new(std::process::id() as i32);
            resolve(&mem, &self.maps(), "game.exe", PATTERN, offset)
        }
    }

    #[test]
    fn finds_a_match_in_an_anonymous_section() {
        let mut image = FakeImage::new();
        let addr = image.plant(HEADER + 0x40);
        assert_eq!(image.resolve(None).unwrap(), addr);
        assert_eq!(image.resolve(Some(0x10)).unwrap(), addr + 0x10);
    }

    #[test]
    fn finds_a_match_in_the_file_backed_header() {
        let mut image = FakeImage::new();
        let addr = image.plant(0x200);
        assert_eq!(image.resolve(None).unwrap(), addr);
    }

    #[test]
    fn counts_a_match_around_a_chunk_boundary_exactly_once() {
        // Entirely before the boundary, across it at each split, and after it.
        for before in 0..=NEEDLE.len() {
            let mut image = FakeImage::new();
            let addr = image.plant(HEADER + SCAN_CHUNK - before);
            assert_eq!(image.resolve(None).unwrap(), addr, "{before} bytes before");
        }
    }

    #[test]
    fn duplicates_are_ambiguous() {
        // In one chunk, either side of a chunk boundary, and in separate regions.
        for (a, b) in [
            (HEADER + 0x40, HEADER + 0x80),
            (HEADER + SCAN_CHUNK - 0x20, HEADER + SCAN_CHUNK + 0x20),
            (0x200, HEADER + 0x40),
        ] {
            let mut image = FakeImage::new();
            image.plant(a);
            image.plant(b);
            assert!(matches!(image.resolve(None), Err(EngineError::SignatureAmbiguous)));
        }
    }

    #[test]
    fn overlapping_duplicates_across_a_chunk_boundary_are_ambiguous() {
        let mut image = FakeImage::new();
        let boundary = HEADER + SCAN_CHUNK;
        image.buf[boundary - 2..boundary + 2].fill(0xAB);
        std::hint::black_box(&mut image.buf);
        let mem = MemoryAccess::new(std::process::id() as i32);
        let maps = image.maps();
        // Two matches, at boundary - 2 and boundary - 1.
        assert!(matches!(
            resolve(&mem, &maps, "game.exe", "AB AB AB", None),
            Err(EngineError::SignatureAmbiguous)
        ));
    }

    #[test]
    fn no_match_is_not_found() {
        let mut image = FakeImage::new();
        assert!(matches!(image.resolve(None), Err(EngineError::SignatureNotFound)));
    }

    #[test]
    fn missing_module_is_reported_before_scanning() {
        let image = FakeImage::new();
        let mem = MemoryAccess::new(std::process::id() as i32);
        let result = resolve(&mem, &image.maps(), "other.exe", PATTERN, None);
        assert!(matches!(result, Err(EngineError::ModuleNotFound(_))));
    }

    #[test]
    fn ignores_matches_outside_the_module_span() {
        let mut image = FakeImage::new();
        let inside = image.plant(HEADER + 0x40);
        // The anonymous region continues past SizeOfImage.
        image.plant(IMAGE + 0x10);
        assert_eq!(image.resolve(None).unwrap(), inside);
    }

    #[test]
    fn skips_unreadable_regions() {
        let mut image = FakeImage::new();
        image.plant(HEADER + 0x40);
        std::hint::black_box(&mut image.buf);
        let (base, section) = (image.base(), image.section());
        let maps = [
            region(base, section, true, Some("/games/Game.exe")),
            region(section, base + IMAGE, false, None),
        ];
        let mem = MemoryAccess::new(std::process::id() as i32);
        let result = resolve(&mem, &maps, "game.exe", PATTERN, None);
        assert!(matches!(result, Err(EngineError::SignatureNotFound)));
    }

    #[test]
    fn non_pe_module_spans_its_own_regions_for_any_name_form() {
        // No MZ header, so the span falls back to the path-matched extent.
        let mut buf = vec![0u8; 0x4000];
        buf[0x3000..0x3000 + NEEDLE.len()].copy_from_slice(&NEEDLE);
        std::hint::black_box(&mut buf);
        let base = buf.as_ptr() as usize;
        let maps = [
            region(base, base + 0x1000, true, Some("/opt/game/libgame.so")),
            region(base + 0x1000, base + 0x4000, true, None),
        ];
        let mem = MemoryAccess::new(std::process::id() as i32);
        for module in ["libgame.so", "/opt/game/libgame.so"] {
            let result = resolve(&mem, &maps, module, PATTERN, None);
            assert!(matches!(result, Err(EngineError::SignatureNotFound)), "{module}");
        }
    }
}
