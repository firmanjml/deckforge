//! Auto Assembler source loading: `{$include ...}` expansion and
//! `[ENABLE]` / `[DISABLE]` section splitting.
//!
//! Includes are *source* dependencies: the included file's lines are spliced
//! into the including script at the include point, recursively. Paths resolve
//! relative to the including file and are jailed to the trainer package (no
//! absolute paths, no escaping via `..`). Include cycles and runaway nesting
//! are rejected.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::error::EngineError;
use crate::trainer::package;

use super::error::{ErrorCtx, Section};

/// Maximum include nesting depth (defense against runaway recursion).
const MAX_INCLUDE_DEPTH: usize = 16;

/// A source line with provenance for error reporting.
#[derive(Debug, Clone)]
pub struct SrcLine {
    pub text: String,
    /// Package-relative script file this line came from.
    pub file: String,
    /// 1-based line number in that file.
    pub line: u32,
}

/// A loaded script: both sections with includes expanded.
#[derive(Debug, Clone, Default)]
pub struct Source {
    pub enable: Vec<SrcLine>,
    pub disable: Vec<SrcLine>,
}

/// Load `file_rel` (package-relative), expand includes, split sections.
pub fn load(package_dir: &Path, file_rel: &str) -> Result<Source, EngineError> {
    let mut state = LoadState {
        package_dir,
        stack: Vec::new(),
        seen_stack: HashSet::new(),
    };
    let lines = state.load_file(file_rel, 0)?;
    Ok(split_sections(lines))
}

struct LoadState<'a> {
    package_dir: &'a Path,
    /// Include stack (for cycle detection), absolute paths.
    stack: Vec<PathBuf>,
    seen_stack: HashSet<PathBuf>,
}

impl<'a> LoadState<'a> {
    fn load_file(&mut self, rel: &str, depth: usize) -> Result<Vec<SrcLine>, EngineError> {
        if depth > MAX_INCLUDE_DEPTH {
            return Err(EngineError::InvalidTrainer(format!(
                "include depth exceeds {MAX_INCLUDE_DEPTH} (cyclic includes?)"
            )));
        }
        let abs = package::resolve_script_path(self.package_dir, rel)?;
        if self.seen_stack.contains(&abs) {
            return Err(EngineError::InvalidTrainer(format!(
                "cyclic {{$include}} of '{rel}'"
            )));
        }
        let content = std::fs::read_to_string(&abs).map_err(|e| {
            EngineError::InvalidTrainer(format!("cannot read script '{}': {e}", abs.display()))
        })?;

        self.stack.push(abs.clone());
        self.seen_stack.insert(abs.clone());
        let result = self.expand(&content, rel, &abs, depth);
        self.stack.pop();
        self.seen_stack.remove(&abs);
        result
    }

    fn expand(
        &mut self,
        content: &str,
        rel: &str,
        abs: &Path,
        depth: usize,
    ) -> Result<Vec<SrcLine>, EngineError> {
        let mut out = Vec::new();
        for (i, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if let Some(inc) = parse_include(line) {
                // Includes resolve relative to the including file, and must
                // stay inside the package.
                let inc_abs = package::resolve_include_path(self.package_dir, abs, inc)?;
                let inc_rel = inc_abs
                    .strip_prefix(self.package_dir)
                    .map(|p| p.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| inc.to_string());
                let included = self.load_file(&inc_rel, depth + 1)?;
                out.extend(included);
                continue;
            }
            out.push(SrcLine {
                text: raw.to_string(),
                file: rel.to_string(),
                line: (i + 1) as u32,
            });
        }
        Ok(out)
    }
}

/// Parse a `{$include path}` directive line (case-insensitive). Returns the
/// path when the whole line is an include directive.
fn parse_include(line: &str) -> Option<&str> {
    let lower = line.to_ascii_lowercase();
    if !lower.starts_with("{$include") {
        return None;
    }
    let rest = &line["{$include".len()..];
    let rest = rest.strip_suffix('}')?.trim();
    if rest.is_empty() {
        return None;
    }
    Some(rest)
}

/// Split expanded lines into [ENABLE] / [DISABLE] sections. Lines before the
/// first section header (other than comments/blanks/includes — already
/// expanded) are a hard error: CE requires section markers.
fn split_sections(lines: Vec<SrcLine>) -> Source {
    let mut src = Source::default();
    let mut current: Option<Section> = None;
    for line in lines {
        let t = line.text.trim();
        if t.eq_ignore_ascii_case("[enable]") {
            current = Some(Section::Enable);
            continue;
        }
        if t.eq_ignore_ascii_case("[disable]") {
            current = Some(Section::Disable);
            continue;
        }
        match current {
            Some(Section::Enable) => src.enable.push(line),
            Some(Section::Disable) => src.disable.push(line),
            None => {
                if !t.is_empty() && !is_comment(t) {
                    // Keep the line in ENABLE with a marker the parser will
                    // flag — losing provenance here would hide real errors.
                    // CE itself errors; the parser produces the diagnostic.
                    src.enable.push(SrcLine {
                        text: line.text.clone(),
                        file: line.file.clone(),
                        line: line.line,
                    });
                }
            }
        }
    }
    src
}

pub fn is_comment(t: &str) -> bool {
    t.starts_with("//") || t.starts_with(';')
}

/// Build an error context for a section of a script.
pub fn error_ctx(trainer: &str, owner: &str, script: &str, section: Section) -> ErrorCtx {
    ErrorCtx {
        trainer: trainer.to_string(),
        owner: owner.to_string(),
        script: script.to_string(),
        section,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_package() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "deckforge-aa-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(dir.join("scripts/common")).unwrap();
        dir
    }

    #[test]
    fn splits_enable_and_disable() {
        let dir = setup_package();
        fs::write(
            dir.join("scripts/x.asm"),
            "[ENABLE]\nlabel(a)\n[DISABLE]\ndealloc(a)\n",
        )
        .unwrap();
        let src = load(&dir, "scripts/x.asm").unwrap();
        assert_eq!(src.enable.len(), 1);
        assert_eq!(src.disable.len(), 1);
        assert_eq!(src.disable[0].line, 4);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn expands_includes() {
        let dir = setup_package();
        fs::write(dir.join("scripts/common/helpers.asm"), "[ENABLE]\nlabel(h)\n").unwrap();
        fs::write(
            dir.join("scripts/x.asm"),
            "{$include common/helpers.asm}\n[DISABLE]\n",
        )
        .unwrap();
        let src = load(&dir, "scripts/x.asm").unwrap();
        assert_eq!(src.enable.len(), 1);
        assert_eq!(src.enable[0].file, "scripts/common/helpers.asm");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn expands_nested_includes() {
        let dir = setup_package();
        fs::write(dir.join("scripts/common/a.asm"), "[ENABLE]\nlabel(a)\n").unwrap();
        fs::write(
            dir.join("scripts/common/b.asm"),
            "{$include a.asm}\n[DISABLE]\n",
        )
        .unwrap();
        fs::write(dir.join("scripts/x.asm"), "{$include common/b.asm}\n").unwrap();
        let src = load(&dir, "scripts/x.asm").unwrap();
        assert_eq!(src.enable.len(), 1);
        assert_eq!(src.enable[0].file, "scripts/common/a.asm");
        assert_eq!(src.disable.len(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_include_traversal() {
        let dir = setup_package();
        // One level up from scripts/ lands inside the package (legal);
        // two levels up escapes it (rejected).
        fs::write(dir.join("allowed.asm"), "[ENABLE]\n").unwrap();
        fs::write(
            dir.join("scripts/x.asm"),
            "{$include ../allowed.asm}\n",
        )
        .unwrap();
        assert!(load(&dir, "scripts/x.asm").is_ok());

        fs::write(
            dir.join("scripts/y.asm"),
            "{$include ../../outside.asm}\n",
        )
        .unwrap();
        assert!(load(&dir, "scripts/y.asm").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_include_cycles() {
        let dir = setup_package();
        fs::write(
            dir.join("scripts/common/a.asm"),
            "{$include b.asm}\n[ENABLE]\n",
        )
        .unwrap();
        fs::write(
            dir.join("scripts/common/b.asm"),
            "{$include a.asm}\n",
        )
        .unwrap();
        assert!(load(&dir, "scripts/common/a.asm").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_absolute_include() {
        let dir = setup_package();
        fs::write(dir.join("scripts/x.asm"), "{$include /etc/passwd}\n").unwrap();
        assert!(load(&dir, "scripts/x.asm").is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
