//! Trainer file loading by Steam AppID.
//!
//! Production trainers live in an external persistent directory; during
//! development the `DECKFORGE_TRAINER_DIR` env var (defaulting to
//! `./fixtures/trainers`) selects the source. Production code must never assume
//! trainers are bundled with the plugin.

use std::env;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{EngineError, EngineResult};
use crate::resolver::Resolver;
use crate::trainer::definition::CheatAction;

use super::definition::TrainerDefinition;
use super::{package, validator};

/// Resolve the trainer root directory.
///
/// 1. `DECKFORGE_TRAINER_DIR` env var (development override / production config).
/// 2. `./fixtures/trainers` (development default).
///
/// Production deployments should set `DECKFORGE_TRAINER_DIR` to the persistent
/// DeckForge data directory.
pub fn trainer_dir() -> PathBuf {
    if let Ok(dir) = env::var("DECKFORGE_TRAINER_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from("./fixtures/trainers")
}

/// Path to `<trainer_dir>/<app_id>/trainer.json`.
pub fn trainer_path(app_id: u64) -> PathBuf {
    trainer_dir().join(app_id.to_string()).join("trainer.json")
}

/// Load and validate the trainer for `app_id` from its package directory
/// (`<trainer_dir>/<app_id>/`).
///
/// After validation, script *files* referenced by the trainer are resolved
/// against the package directory: Lua resolver/setup files are read and
/// inlined into the definition (so the runtime never touches the filesystem
/// for them), and every declared script path is checked to exist and stay
/// inside the package. Auto Assembler `.asm` sources are re-read at enable
/// time so trainer authors can iterate without reloading.
pub fn load_trainer(app_id: u64) -> EngineResult<TrainerDefinition> {
    let pkg_dir = trainer_dir().join(app_id.to_string());
    load_trainer_from_dir(&pkg_dir, app_id)
}

/// Load and validate a trainer package from an explicit directory.
///
/// Used by the trainer store to validate a freshly downloaded package before
/// it is swapped into place. `app_id` is the expected Steam AppID (used for
/// the `game.steamAppId` cross-check). After validation, script files are
/// resolved against `pkg_dir` (inlined / existence-checked).
pub fn load_trainer_from_dir(pkg_dir: &Path, app_id: u64) -> EngineResult<TrainerDefinition> {
    let path = pkg_dir.join("trainer.json");
    if !path.exists() {
        return Err(EngineError::TrainerNotFound);
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| EngineError::InvalidTrainer(format!("cannot read {}: {e}", path.display())))?;
    let mut def: TrainerDefinition = serde_json::from_str(&content)
        .map_err(|e| EngineError::InvalidTrainer(format!("JSON parse error: {e}")))?;
    def.package_dir = pkg_dir.to_path_buf();
    validator::validate(&def, app_id)?;
    load_script_files(&mut def)?;
    Ok(def)
}

/// Where the trainer store installs downloaded packages. Currently the same
/// directory Forge loads trainers from ([`trainer_dir`]): in dev that is
/// `./fixtures/trainers`, in production the persistent DeckForge data dir.
pub fn install_root() -> PathBuf {
    trainer_dir()
}

// ---------------------------------------------------------------------------
// Installed-trainer discovery (for the store's "installed" view)
// ---------------------------------------------------------------------------

/// Lightweight metadata read from an installed trainer's `trainer.json`,
/// without requiring the full definition (cheats, scripts, …) to be valid.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrainerMetaFile {
    game: TrainerMetaGame,
    trainer: TrainerMetaTrainer,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrainerMetaGame {
    #[allow(dead_code)]
    steam_app_id: u64,
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrainerMetaTrainer {
    name: String,
    version: String,
    #[serde(default)]
    author: Option<String>,
}

/// A locally installed trainer, for the store's "installed" view.
#[derive(Debug, Clone)]
pub struct InstalledTrainer {
    pub app_id: u64,
    pub game_name: String,
    pub trainer_name: String,
    pub version: String,
    pub author: Option<String>,
}

/// Scan the trainer directory for installed packages (`<app_id>/trainer.json`)
/// and return their metadata. Trainers whose `trainer.json` cannot be parsed
/// are skipped — they are invisible to the loader too.
pub fn installed_trainers() -> Vec<InstalledTrainer> {
    let root = trainer_dir();
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let app_id = match path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|s| s.parse::<u64>().ok())
        {
            Some(v) => v,
            None => continue,
        };
        let tj = path.join("trainer.json");
        if !tj.is_file() {
            continue;
        }
        let content = match std::fs::read_to_string(&tj) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let meta: TrainerMetaFile = match serde_json::from_str(&content) {
            Ok(m) => m,
            Err(_) => continue,
        };
        out.push(InstalledTrainer {
            app_id,
            game_name: meta.game.name,
            trainer_name: meta.trainer.name,
            version: meta.trainer.version,
            author: meta.trainer.author,
        });
    }
    out
}

/// Resolve every script file reference: inline Lua resolver/setup sources,
/// and verify auto-assembler/bootstrap files exist inside the package.
fn load_script_files(def: &mut TrainerDefinition) -> EngineResult<()> {
    let package_dir = def.package_dir.clone();

    // Lua setup files: read now, executed once per shared-VM boot.
    for rel in &def.scripts.setup {
        def.setup_scripts
            .push(package::read_script(&package_dir, rel)?);
    }

    // Bootstrap components: verify the file exists; contents are read lazily
    // at first initialization.
    for entry in &def.scripts.bootstrap {
        let path = package::resolve_script_path(&package_dir, entry.file())?;
        if !path.is_file() {
            return Err(EngineError::InvalidTrainer(format!(
                "bootstrap script '{}' does not exist",
                entry.file()
            )));
        }
    }

    for cheat in &mut def.cheats {
        match &mut cheat.action {
            CheatAction::AutoAssembler { file } => {
                let path = package::resolve_script_path(&package_dir, file)?;
                if !path.is_file() {
                    return Err(EngineError::InvalidTrainer(format!(
                        "auto-assembler script '{file}' (cheat '{}') does not exist",
                        cheat.id
                    )));
                }
            }
            CheatAction::Value { resolver, .. }
            | CheatAction::Freeze { resolver, .. }
            | CheatAction::Patch { resolver, .. } => inline_lua_resolver(&package_dir, resolver)?,
        }
    }
    Ok(())
}

/// Inline a `file`-based Lua resolver: read the source into `code` so the
/// script VM never touches the filesystem.
fn inline_lua_resolver(package_dir: &std::path::Path, resolver: &mut Resolver) -> EngineResult<()> {
    if let Resolver::Script {
        code,
        file,
        language,
    } = resolver
    {
        if let Some(lang) = language {
            if !lang.eq_ignore_ascii_case("lua") {
                return Err(EngineError::InvalidTrainer(format!(
                    "unsupported script language '{lang}' (only 'lua' is supported)"
                )));
            }
        }
        match (code.is_some(), file.clone()) {
            (true, Some(_)) => {
                return Err(EngineError::InvalidTrainer(
                    "script resolver must use either 'code' or 'file', not both".into(),
                ));
            }
            (false, None) => {
                return Err(EngineError::InvalidTrainer(
                    "script resolver needs either 'code' or 'file'".into(),
                ));
            }
            (false, Some(f)) => {
                *code = Some(package::read_script(package_dir, &f)?);
            }
            (true, None) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trainer::definition::CheatAction;
    use std::fs;

    /// Tests in this module set DECKFORGE_TRAINER_DIR; serialize them.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Build a self-contained trainer package in a temp dir (fixtures/ are
    /// git-ignored developer content, so tests must not depend on them).
    fn build_package(app_id: u64, trainer_json: &str, files: &[(&str, &str)]) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "deckforge-loader-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let pkg = root.join(app_id.to_string());
        fs::create_dir_all(&pkg).unwrap();
        fs::write(pkg.join("trainer.json"), trainer_json).unwrap();
        for (rel, content) in files {
            let path = pkg.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        root
    }

    const PACKAGE_JSON: &str = r#"{
      "formatVersion": 1,
      "game": { "steamAppId": 424242, "name": "G", "process": "game.exe" },
      "trainer": { "id": "t", "name": "T", "version": "1" },
      "scripts": {
        "setup": ["scripts/common/lib.lua"],
        "bootstrap": [ { "id": "player_instance", "file": "scripts/common/player_instance.asm" } ]
      },
      "cheats": [
        { "id": "ih", "name": "IH", "control": "toggle",
          "requires": ["player_instance"],
          "action": { "type": "auto_assembler", "file": "scripts/ih.asm" } },
        { "id": "money", "name": "Money", "control": "number",
          "action": { "type": "value", "valueType": "int32",
            "resolver": { "type": "script", "language": "lua", "file": "scripts/money.lua" } } },
        { "id": "inline", "name": "Inline", "control": "number",
          "action": { "type": "value", "valueType": "int32",
            "resolver": { "type": "script", "code": "return 0x1000" } } }
      ]
    }"#;

    #[test]
    fn loads_full_scripted_package() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = build_package(
            424242,
            PACKAGE_JSON,
            &[
                ("scripts/common/lib.lua", "function helper() return 1 end"),
                (
                    "scripts/common/player_instance.asm",
                    "[ENABLE]\nalloc(pi,64)\n",
                ),
                ("scripts/ih.asm", "[ENABLE]\nalloc(m,64)\n"),
                ("scripts/money.lua", "return 0x1234"),
            ],
        );
        unsafe {
            std::env::set_var("DECKFORGE_TRAINER_DIR", &root);
        }
        let def = load_trainer(424242).expect("package must load");

        // Bootstrap + requires.
        assert_eq!(def.scripts.bootstrap[0].id(), "player_instance");
        let ih = def.cheats.iter().find(|c| c.id == "ih").unwrap();
        assert!(matches!(ih.action, CheatAction::AutoAssembler { .. }));
        assert_eq!(ih.requires, vec!["player_instance"]);

        // Setup file read.
        assert_eq!(def.setup_scripts.len(), 1);
        assert!(def.setup_scripts[0].contains("helper"));

        // Lua file resolver inlined at load.
        let money = def.cheats.iter().find(|c| c.id == "money").unwrap();
        match &money.action {
            CheatAction::Value { resolver, .. } => match resolver {
                Resolver::Script { code, .. } => {
                    assert_eq!(code.as_deref(), Some("return 0x1234"));
                }
                other => panic!("expected script resolver, got {other:?}"),
            },
            other => panic!("expected value action, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_traversal_in_script_paths() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = build_package(
            424243,
            &PACKAGE_JSON
                .replace("scripts/money.lua", "../outside.lua")
                .replace("\"steamAppId\": 424242", "\"steamAppId\": 424243"),
            &[
                ("scripts/common/lib.lua", "function helper() return 1 end"),
                (
                    "scripts/common/player_instance.asm",
                    "[ENABLE]\nalloc(pi,64)\n",
                ),
                ("scripts/ih.asm", "[ENABLE]\nalloc(m,64)\n"),
            ],
        );
        unsafe {
            std::env::set_var("DECKFORGE_TRAINER_DIR", &root);
        }
        let err = load_trainer(424243).unwrap_err();
        assert!(matches!(err, EngineError::InvalidTrainer(_)));
        assert!(err.message().contains("escapes") || err.message().contains(".."));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_missing_script_file() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = build_package(
            424244,
            &PACKAGE_JSON.replace("\"steamAppId\": 424242", "\"steamAppId\": 424244"),
            &[
                ("scripts/common/lib.lua", "function helper() return 1 end"),
                (
                    "scripts/common/player_instance.asm",
                    "[ENABLE]\nalloc(pi,64)\n",
                ),
                // ih.asm deliberately missing
                ("scripts/money.lua", "return 0x1234"),
            ],
        );
        unsafe {
            std::env::set_var("DECKFORGE_TRAINER_DIR", &root);
        }
        let err = load_trainer(424244).unwrap_err();
        assert!(err.message().contains("does not exist"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn lists_installed_trainers() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!(
            "deckforge-installed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("111").join("scripts")).unwrap();
        fs::create_dir_all(root.join("222")).unwrap();
        fs::create_dir_all(root.join("notanappid")).unwrap();
        fs::create_dir_all(root.join("333")).unwrap(); // no trainer.json
        fs::write(
            root.join("111").join("trainer.json"),
            r#"{"formatVersion":1,"game":{"steamAppId":111,"name":"Game One","process":"g.exe"},"trainer":{"id":"t1","name":"Trainer One","version":"1.2.0","author":"me"},"cheats":[]}"#,
        )
        .unwrap();
        fs::write(
            root.join("222").join("trainer.json"),
            r#"{"formatVersion":1,"game":{"steamAppId":222,"name":"Game Two","process":"g2.exe"},"trainer":{"id":"t2","name":"Trainer Two","version":"0.9"},"cheats":[]}"#,
        )
        .unwrap();
        unsafe {
            std::env::set_var("DECKFORGE_TRAINER_DIR", &root);
        }
        let mut list = installed_trainers();
        list.sort_by_key(|t| t.app_id);
        assert_eq!(list.len(), 2, "non-numeric dir and dir without trainer.json skipped");
        assert_eq!(list[0].app_id, 111);
        assert_eq!(list[0].game_name, "Game One");
        assert_eq!(list[0].version, "1.2.0");
        assert_eq!(list[0].author.as_deref(), Some("me"));
        assert_eq!(list[1].app_id, 222);
        assert!(list[1].author.is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn load_trainer_from_dir_validates_and_checks_appid() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = build_package(
            424245,
            &PACKAGE_JSON.replace("\"steamAppId\": 424242", "\"steamAppId\": 424245"),
            &[
                ("scripts/common/lib.lua", "function helper() return 1 end"),
                ("scripts/common/player_instance.asm", "[ENABLE]\nalloc(pi,64)\n"),
                ("scripts/ih.asm", "[ENABLE]\nalloc(m,64)\n"),
                ("scripts/money.lua", "return 0x1234"),
            ],
        );
        let pkg = root.join("424245");
        let def = load_trainer_from_dir(&pkg, 424245).expect("must load from dir");
        assert_eq!(def.game.steam_app_id, 424245);
        // A mismatched expected AppID must fail validation.
        assert!(load_trainer_from_dir(&pkg, 999).is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
