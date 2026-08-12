//! AOB / signature pattern parsing and scanning, plus the signature resolver.
//!
//! Patterns are parsed *once* into a [`Vec<PatternByte>`] and scanned with that
//! representation — never re-parsed per byte. The scanner reports no-match /
//! single / multiple so callers can refuse ambiguous matches.

use crate::error::{EngineError, EngineResult};
use crate::memory::{find_module, MemoryAccess, MemoryRegion};

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
/// Scans the readable regions of `module` and requires exactly one match
/// across the whole module. The optional `offset` is added to the match.
pub fn resolve(
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    module: &str,
    pattern: &str,
    offset: Option<usize>,
) -> EngineResult<usize> {
    let info = find_module(maps, module)
        .ok_or_else(|| EngineError::ModuleNotFound(module.to_string()))?;
    let pat = parse_pattern(pattern)?;

    let mut matches: Vec<usize> = Vec::new();
    for region in &info.regions {
        if !region.readable {
            continue;
        }
        match mem.read_bytes(region.start, region.size()) {
            Ok(data) => {
                for off in all_matches(&data, &pat) {
                    matches.push(region.start + off);
                }
            }
            Err(e) => {
                // Skip regions we cannot read (e.g. special mappings) but log.
                eprintln!(
                    "[forge] signature scan: skip region {:x}-{:x}: {}",
                    region.start, region.end, e
                );
            }
        }
    }

    match matches.len() {
        0 => Err(EngineError::SignatureNotFound),
        1 => Ok(matches[0] + offset.unwrap_or(0)),
        _ => Err(EngineError::SignatureAmbiguous),
    }
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
