//! Trainer package script-path handling.
//!
//! Trainer packages are directories (`<appid>/trainer.json` plus a `scripts/`
//! tree). Scripts referenced from trainer.json (`scripts.setup`,
//! `scripts.bootstrap`, auto-assembler actions, Lua file resolvers) and from
//! `{$include}` directives are *source dependencies* resolved relative to the
//! including file inside the package. They must never escape the package:
//! absolute paths, `..` traversal, and paths outside the package directory are
//! rejected.

use std::path::{Component, Path, PathBuf};

use crate::error::{EngineError, EngineResult};

/// Validate that a trainer-declared script path is package-relative and safe.
/// Returns the path joined onto `package_dir` (lexically normalized).
pub fn resolve_script_path(package_dir: &Path, rel: &str) -> EngineResult<PathBuf> {
    resolve_within(package_dir, package_dir, rel)
}

/// Resolve an include path relative to the *including file's* directory, then
/// verify the result stays inside `package_dir`. Used by the Auto Assembler
/// `{$include ...}` directive.
pub fn resolve_include_path(
    package_dir: &Path,
    including_file: &Path,
    rel: &str,
) -> EngineResult<PathBuf> {
    let base = including_file
        .parent()
        .unwrap_or_else(|| Path::new("."));
    resolve_within(package_dir, base, rel).map_err(|e| {
        EngineError::InvalidTrainer(format!("invalid include '{rel}': {}", e.message()))
    })
}

/// Normalize `base.join(rel)` and verify the result stays inside `jail`.
fn resolve_within(jail: &Path, base: &Path, rel: &str) -> EngineResult<PathBuf> {
    // Trainer packages are built once and used cross-platform; forbid
    // backslashes and drive-letter colons so a path cannot mean different
    // things on Windows vs. SteamOS.
    if rel.contains('\\') || rel.contains(':') {
        return Err(EngineError::InvalidTrainer(format!(
            "script path '{rel}' must use forward slashes and no drive letters"
        )));
    }
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() {
        return Err(EngineError::InvalidTrainer(format!(
            "script path '{rel}' is absolute; paths must be relative to the trainer package"
        )));
    }
    if rel.trim().is_empty() {
        return Err(EngineError::InvalidTrainer("empty script path".into()));
    }
    let mut normalized = base.to_path_buf();
    for comp in rel_path.components() {
        match comp {
            Component::Normal(c) => normalized.push(c),
            Component::CurDir => {}
            Component::ParentDir => {
                // `..` is allowed while it stays inside the jail.
                if !normalized.pop() || !normalized.starts_with(jail) {
                    return Err(EngineError::InvalidTrainer(format!(
                        "script path '{rel}' escapes the trainer package"
                    )));
                }
            }
            other => {
                return Err(EngineError::InvalidTrainer(format!(
                    "script path '{rel}' has an invalid component ({other:?})"
                )));
            }
        }
    }
    if !normalized.starts_with(jail) {
        return Err(EngineError::InvalidTrainer(format!(
            "script path '{rel}' escapes the trainer package"
        )));
    }
    Ok(normalized)
}

/// Read a script file inside the package (path already validated relative).
pub fn read_script(package_dir: &Path, rel: &str) -> EngineResult<String> {
    let path = resolve_script_path(package_dir, rel)?;
    std::fs::read_to_string(&path).map_err(|e| {
        EngineError::InvalidTrainer(format!("cannot read script '{}': {e}", path.display()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_relative_paths() {
        let pkg = Path::new("/pkg/123456");
        assert_eq!(
            resolve_script_path(pkg, "scripts/infinite_health.asm").unwrap(),
            PathBuf::from("/pkg/123456/scripts/infinite_health.asm")
        );
        assert_eq!(
            resolve_script_path(pkg, "./scripts/x.lua").unwrap(),
            PathBuf::from("/pkg/123456/scripts/x.lua")
        );
    }

    #[test]
    fn rejects_traversal_and_absolute() {
        let pkg = Path::new("/pkg/123456");
        assert!(resolve_script_path(pkg, "../secret.lua").is_err());
        assert!(resolve_script_path(pkg, "scripts/../../secret.lua").is_err());
        assert!(resolve_script_path(pkg, "/etc/passwd").is_err());
        assert!(resolve_script_path(pkg, "").is_err());
    }

    #[test]
    fn rejects_windows_absolute_and_backslashes() {
        let pkg = Path::new("/pkg/123456");
        assert!(resolve_script_path(pkg, "C:/Windows/system.ini").is_err());
        assert!(resolve_script_path(pkg, "scripts\\foo.lua").is_err());
    }

    #[test]
    fn include_resolves_relative_to_including_file() {
        let pkg = Path::new("/pkg");
        let inc = resolve_include_path(pkg, Path::new("/pkg/scripts/infinite_health.asm"), "common/helpers.asm").unwrap();
        assert_eq!(inc, PathBuf::from("/pkg/scripts/common/helpers.asm"));
    }

    #[test]
    fn include_cannot_escape_package() {
        let pkg = Path::new("/pkg");
        // A deep include path that stays inside is fine.
        assert!(resolve_include_path(pkg, Path::new("/pkg/a/b/c.asm"), "../d.asm").is_ok());
        // Traversal past the package root is rejected even if individually
        // relative.
        let inc = resolve_include_path(pkg, Path::new("/pkg/c.asm"), "../../etc/x").is_err();
        assert!(inc);
        assert!(resolve_include_path(pkg, Path::new("/pkg/c.asm"), "..\\..\\x").is_err());
    }
}
