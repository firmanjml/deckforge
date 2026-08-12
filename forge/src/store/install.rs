//! Atomic, jailed trainer-package installation.
//!
//! A package is downloaded into a `<appid>.new/` staging directory, validated
//! with the real loader ([`crate::trainer::load_trainer_from_dir`]), and only
//! then swapped into place. A failed validation or a crash mid-download never
//! corrupts an existing working trainer.
//!
//! Every downloaded path is jailed to the package directory: absolute paths,
//! `..`, backslashes, and drive letters are rejected (zip-slip / cross-platform
//! path confusion defense).

use std::path::{Component, Path, PathBuf};

use crate::error::{EngineError, EngineResult};
use crate::trainer;

/// Download every file of a package into a fresh `<install_root>/<appid>.new/`
/// staging directory. `progress(done)` is called after each file writes.
/// On any error the staging directory is removed.
pub fn download_package(
    cfg: &crate::store::repo::RepoConfig,
    app_id: u64,
    files: &[String],
    progress: &dyn Fn(usize),
) -> EngineResult<PathBuf> {
    let root = trainer::install_root();
    let staging = root.join(format!("{app_id}.new"));

    if staging.exists() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    std::fs::create_dir_all(&staging).map_err(io_err)?;

    for (i, rel) in files.iter().enumerate() {
        let jailed = match jail_rel(rel) {
            Ok(p) => p,
            Err(e) => {
                cleanup(&staging);
                return Err(e);
            }
        };
        let url_path = format!("trainers/{app_id}/{rel}");
        let bytes = match crate::store::repo::fetch_raw_bytes(cfg, &url_path) {
            Ok(b) => b,
            Err(e) => {
                cleanup(&staging);
                return Err(e);
            }
        };
        let dest = staging.join(&jailed);
        if let Some(parent) = dest.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                cleanup(&staging);
                return Err(io_err(e));
            }
        }
        if let Err(e) = std::fs::write(&dest, &bytes) {
            cleanup(&staging);
            return Err(io_err(e));
        }
        progress(i + 1);
    }
    Ok(staging)
}

/// Validate a staged package and atomically swap it into
/// `<install_root>/<appid>/`. On validation failure the staging directory is
/// removed and an existing installed trainer is left untouched.
pub fn finalize_package(staging: &Path, app_id: u64) -> EngineResult<()> {
    if let Err(e) = trainer::load_trainer_from_dir(staging, app_id) {
        cleanup(staging);
        return Err(EngineError::RepoInvalidPackage(e.message()));
    }

    let root = trainer::install_root();
    let target = root.join(app_id.to_string());
    let old = root.join(format!("{app_id}.old"));

    // Remove any stale .old from a previous interrupted swap.
    let _ = std::fs::remove_dir_all(&old);

    if target.exists() {
        if let Err(e) = std::fs::rename(&target, &old) {
            return Err(io_err(e));
        }
    }
    if let Err(e) = std::fs::rename(staging, &target) {
        // Roll back: restore the previous trainer if we moved it aside.
        if old.exists() {
            let _ = std::fs::rename(&old, &target);
        }
        return Err(io_err(e));
    }
    let _ = std::fs::remove_dir_all(&old);
    Ok(())
}

/// Remove an installed trainer package. Idempotent: a missing package is Ok.
pub fn uninstall_package(app_id: u64) -> EngineResult<()> {
    let target = trainer::install_root().join(app_id.to_string());
    if !target.exists() {
        return Ok(());
    }
    std::fs::remove_dir_all(&target).map_err(|e| {
        EngineError::RepoIoError(format!("remove {}: {e}", target.display()))
    })
}

/// Jail a package-relative path: reject absolute, `..`, backslashes, drive
/// letters. Returns a normalized relative [`PathBuf`] that is safe to join
/// onto the staging directory.
fn jail_rel(rel: &str) -> EngineResult<PathBuf> {
    if rel.contains('\\') || rel.contains(':') {
        return Err(EngineError::RepoInvalidPackage(format!(
            "downloaded path '{rel}' must use forward slashes and no drive letters"
        )));
    }
    if rel.trim().is_empty() {
        return Err(EngineError::RepoInvalidPackage("empty downloaded path".into()));
    }
    let p = Path::new(rel);
    if p.is_absolute() {
        return Err(EngineError::RepoInvalidPackage(format!(
            "downloaded path '{rel}' is absolute"
        )));
    }
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(EngineError::RepoInvalidPackage(format!(
                    "downloaded path '{rel}' contains '..'"
                )));
            }
            other => {
                return Err(EngineError::RepoInvalidPackage(format!(
                    "downloaded path '{rel}' has an invalid component ({other:?})"
                )));
            }
        }
    }
    Ok(out)
}

fn io_err(e: std::io::Error) -> EngineError {
    EngineError::RepoIoError(e.to_string())
}

fn cleanup(p: &Path) {
    let _ = std::fs::remove_dir_all(p);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trainer::loader::trainer_dir;
    use std::fs;

    /// Tests in this module set DECKFORGE_TRAINER_DIR; serialize them.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn valid_json(app_id: u64) -> String {
        format!(
            r#"{{"formatVersion":1,"game":{{"steamAppId":{app_id},"name":"G","process":"g.exe"}},"trainer":{{"id":"t","name":"T","version":"1"}},"cheats":[]}}"#
        )
    }

    fn temp_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "deckforge-install-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn jail_rejects_unsafe_paths() {
        assert!(jail_rel("../x").is_err());
        assert!(jail_rel("a/../../b").is_err());
        assert!(jail_rel("/etc/passwd").is_err());
        assert!(jail_rel("C:/x").is_err());
        assert!(jail_rel("a\\b").is_err());
        assert!(jail_rel("").is_err());
        assert_eq!(
            jail_rel("scripts/common/helpers.asm").unwrap(),
            PathBuf::from("scripts/common/helpers.asm")
        );
        assert_eq!(jail_rel("./trainer.json").unwrap(), PathBuf::from("trainer.json"));
    }

    #[test]
    fn finalize_swaps_valid_package() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = temp_root();
        unsafe {
            std::env::set_var("DECKFORGE_TRAINER_DIR", &root);
        }
        let staging = root.join("555.new");
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("trainer.json"), valid_json(555)).unwrap();
        fs::create_dir_all(staging.join("scripts")).unwrap();
        fs::write(staging.join("scripts/x.asm"), "[ENABLE]\n").unwrap();

        finalize_package(&staging, 555).expect("valid package must finalize");

        assert!(root.join("555").join("trainer.json").is_file());
        assert!(root.join("555").join("scripts/x.asm").is_file());
        assert!(!staging.exists(), "staging must be consumed");
        assert_eq!(trainer_dir(), root);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn finalize_rejects_invalid_and_keeps_existing() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = temp_root();
        unsafe {
            std::env::set_var("DECKFORGE_TRAINER_DIR", &root);
        }
        // Pre-install a good 556.
        let target = root.join("556");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("trainer.json"), valid_json(556)).unwrap();

        // Staging with a mismatched AppID → validation fails.
        let staging = root.join("556.new");
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("trainer.json"), valid_json(999)).unwrap();

        let err = finalize_package(&staging, 556).unwrap_err();
        assert!(matches!(err, EngineError::RepoInvalidPackage(_)));
        assert!(!staging.exists(), "bad staging must be cleaned up");
        assert!(
            target.join("trainer.json").is_file(),
            "existing trainer must be untouched"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn uninstall_is_idempotent() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = temp_root();
        unsafe {
            std::env::set_var("DECKFORGE_TRAINER_DIR", &root);
        }
        let target = root.join("777");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("trainer.json"), valid_json(777)).unwrap();
        uninstall_package(777).unwrap();
        assert!(!target.exists());
        // Second call must not error.
        uninstall_package(777).unwrap();
        let _ = fs::remove_dir_all(&root);
    }
}
