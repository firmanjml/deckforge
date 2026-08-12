//! `/proc/<pid>/maps` parsing and module/region helpers.
//!
//! The *parsing* here is a pure function over a string so it can be unit-tested
//! on any platform. The actual reading of `/proc/<pid>/maps` lives in
//! [`crate::process::procfs`] (Linux runtime only).

use serde::Serialize;

/// A single mapped memory region from `/proc/<pid>/maps`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: usize,
    pub end: usize,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub private: bool,
    pub path: Option<String>,
}

impl MemoryRegion {
    pub fn size(&self) -> usize {
        self.end.saturating_sub(self.start)
    }
}

/// A resolved module: its name, address span, and constituent regions.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub base: usize,
    pub end: usize,
    pub regions: Vec<MemoryRegion>,
}

impl ModuleInfo {
    pub fn size(&self) -> usize {
        self.end.saturating_sub(self.base)
    }
}

/// Parse the full contents of a `/proc/<pid>/maps` file into regions.
///
/// Lines that fail to parse are skipped rather than aborting the whole parse —
/// a single malformed line should not poison the entire map view.
pub fn parse_maps(content: &str) -> Vec<MemoryRegion> {
    content
        .lines()
        .filter_map(parse_line)
        .collect()
}

fn parse_line(line: &str) -> Option<MemoryRegion> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    // Fields: addr-range perms offset dev inode [path...]
    // The path is the remainder after the 5th field so it may contain spaces
    // (e.g. "/usr/lib/x.so (deleted)").
    let (head, rest) = split_fields(line, 5);
    if head.len() < 5 {
        return None;
    }
    let range = head[0];
    let perms = head[1];
    // head[2] = offset, head[3] = dev, head[4] = inode (validated by count)

    let (start_s, end_s) = range.split_once('-')?;
    let start = usize::from_str_radix(start_s, 16).ok()?;
    let end = usize::from_str_radix(end_s, 16).ok()?;

    let pb = perms.as_bytes();
    if pb.len() < 4 {
        return None;
    }
    let readable = pb[0] == b'r';
    let writable = pb[1] == b'w';
    let executable = pb[2] == b'x';
    let private = pb[3] == b'p';

    let path = if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    };

    Some(MemoryRegion {
        start,
        end,
        readable,
        writable,
        executable,
        private,
        path,
    })
}

/// Extract the first `n` whitespace-delimited tokens from `s`, returning the
/// tokens plus the remaining (left-trimmed) string.
fn split_fields(s: &str, n: usize) -> (Vec<&str>, &str) {
    let mut tokens = Vec::with_capacity(n);
    let mut rest = s;
    while tokens.len() < n {
        let trimmed = rest.trim_start();
        if trimmed.is_empty() {
            return (tokens, "");
        }
        let end = trimmed
            .find(|c: char| c.is_whitespace())
            .unwrap_or(trimmed.len());
        let (tok, after) = trimmed.split_at(end);
        tokens.push(tok);
        rest = after;
    }
    (tokens, rest.trim_start())
}

/// Does a maps path refer to `module`? Matches the basename case-insensitively
/// (Windows PE names under Proton are case-insensitive) or the full path.
fn path_matches(path: &str, module: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path);
    basename.eq_ignore_ascii_case(module) || path.eq_ignore_ascii_case(module)
}

/// All regions belonging to a module.
pub fn module_regions<'a>(regions: &'a [MemoryRegion], module: &str) -> Vec<&'a MemoryRegion> {
    regions
        .iter()
        .filter(|r| r.path.as_deref().is_some_and(|p| path_matches(p, module)))
        .collect()
}

/// Lowest start address of a module (its base).
pub fn module_base(regions: &[MemoryRegion], module: &str) -> Option<usize> {
    module_regions(regions, module).iter().map(|r| r.start).min()
}

/// Resolve a module into base/end/regions, or `None` if it is not mapped.
pub fn find_module(regions: &[MemoryRegion], module: &str) -> Option<ModuleInfo> {
    let regs: Vec<MemoryRegion> = module_regions(regions, module)
        .into_iter()
        .cloned()
        .collect();
    if regs.is_empty() {
        return None;
    }
    let base = regs.iter().map(|r| r.start).min()?;
    let end = regs.iter().map(|r| r.end).max()?;
    Some(ModuleInfo {
        name: module.to_string(),
        base,
        end,
        regions: regs,
    })
}

pub fn readable_regions(regions: &[MemoryRegion]) -> Vec<&MemoryRegion> {
    regions.iter().filter(|r| r.readable).collect()
}

pub fn writable_regions(regions: &[MemoryRegion]) -> Vec<&MemoryRegion> {
    regions.iter().filter(|r| r.writable).collect()
}

pub fn executable_regions(regions: &[MemoryRegion]) -> Vec<&MemoryRegion> {
    regions.iter().filter(|r| r.executable).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MAPS: &str = "\
00400000-00452000 r-xp 00000000 fd:00 2034        /opt/game/ExampleGame.exe
00651000-00652000 r--p 00000000 fd:00 2034        /opt/game/ExampleGame.exe
00652000-00653000 rw-p 00000000 fd:00 2034        /opt/game/ExampleGame.exe
7f8b9c000000-7f8b9c021000 rw-p 00000000 00:00 0
7f8b9c021000-7f8b9c023000 r--p 00000000 fd:00 12345 /usr/lib/libc.so.6
7f8b9c023000-7f8b9c400000 -wxp 00000000 fd:00 12345 /usr/lib/libfoo.so (deleted)
";

    #[test]
    fn parses_all_lines() {
        let regions = parse_maps(SAMPLE_MAPS);
        assert_eq!(regions.len(), 6);
    }

    #[test]
    fn parses_perms_and_addresses() {
        let regions = parse_maps(SAMPLE_MAPS);
        let first = &regions[0];
        assert_eq!(first.start, 0x00400000);
        assert_eq!(first.end, 0x00452000);
        assert!(first.readable && !first.writable && first.executable && first.private);
        assert_eq!(first.path.as_deref(), Some("/opt/game/ExampleGame.exe"));
    }

    #[test]
    fn handles_anonymous_region_with_no_path() {
        let regions = parse_maps(SAMPLE_MAPS);
        let anon = &regions[3];
        assert!(anon.path.is_none());
        assert!(anon.readable && anon.writable && !anon.executable);
    }

    #[test]
    fn handles_path_with_deleted_suffix() {
        let regions = parse_maps(SAMPLE_MAPS);
        let deleted = &regions[5];
        assert_eq!(
            deleted.path.as_deref(),
            Some("/usr/lib/libfoo.so (deleted)")
        );
    }

    #[test]
    fn finds_module_case_insensitive() {
        let regions = parse_maps(SAMPLE_MAPS);
        let info = find_module(&regions, "examplegame.exe").expect("module should exist");
        assert_eq!(info.base, 0x00400000);
        assert_eq!(info.end, 0x00653000);
        assert_eq!(info.regions.len(), 3);
    }

    #[test]
    fn module_base_is_lowest_address() {
        let regions = parse_maps(SAMPLE_MAPS);
        assert_eq!(module_base(&regions, "ExampleGame.exe"), Some(0x00400000));
    }

    #[test]
    fn missing_module_returns_none() {
        let regions = parse_maps(SAMPLE_MAPS);
        assert!(find_module(&regions, "DoesNotExist.dll").is_none());
    }

    #[test]
    fn region_filters() {
        let regions = parse_maps(SAMPLE_MAPS);
        assert_eq!(readable_regions(&regions).len(), 5); // all but the '-' perms line
        assert_eq!(writable_regions(&regions).len(), 3);
        assert_eq!(executable_regions(&regions).len(), 2);
    }

    #[test]
    fn ignores_blank_and_malformed_lines() {
        let content = "\n  \nnot-a-map-line\n00400000-00452000 r-xp 00000000 fd:00 1 /x\n";
        let regions = parse_maps(content);
        assert_eq!(regions.len(), 1);
    }
}
