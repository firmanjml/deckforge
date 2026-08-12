//! Auto Assembler + bootstrap-component lifecycle, decoupled from the
//! concrete process backend so the whole flow (lazy init, refcounting,
//! teardown) is testable with a mock memory backend.
//!
//! [`TrainerRuntime`](crate::trainer::runtime::TrainerRuntime) delegates here
//! with a [`LiveMemory`]; tests use a mock backend.

use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::autoasm::{Executor, Section};
use crate::error::{EngineError, EngineResult};
use crate::memory::MemoryOps;
use crate::trainer::definition::TrainerDefinition;
use crate::trainer::session::TrainerSession;

/// Runs Auto Assembler scripts and manages bootstrap components for one
/// trainer session.
pub struct AaRunner<'a> {
    pub ops: &'a dyn MemoryOps,
    pub session: Arc<Mutex<TrainerSession>>,
    pub package_dir: &'a Path,
    pub trainer_id: &'a str,
    pub def: &'a TrainerDefinition,
}

impl<'a> AaRunner<'a> {
    /// Run one section of a script owned by `owner` (cheat id or component
    /// id). The owner is recorded on every symbol/allocation the run creates.
    pub fn run(&self, owner: &str, file: &str, section: Section) -> EngineResult<()> {
        let mut exec = Executor {
            mem: self.ops,
            session: Arc::clone(&self.session),
            package_dir: self.package_dir,
            trainer: self.trainer_id.to_string(),
        };
        exec.run(owner, file, section)
    }

    /// Lazily initialize each required component and hold one reference per
    /// component for the caller. On failure, references already taken are
    /// released and components this call initialized are torn down again.
    pub fn ensure_dependencies(&self, requires: &[String]) -> EngineResult<Vec<String>> {
        let mut newly: Vec<String> = Vec::new();
        let mut held: Vec<String> = Vec::new();
        for comp in requires {
            let initialized = self.session.lock().unwrap().component_initialized(comp);
            if !initialized {
                if let Err(e) = self.init_component(comp) {
                    for h in &held {
                        self.session.lock().unwrap().component_remove_ref(h);
                    }
                    for n in &newly {
                        self.deinit_component(n);
                    }
                    return Err(e);
                }
                newly.push(comp.clone());
            }
            self.session.lock().unwrap().component_add_ref(comp);
            held.push(comp.clone());
        }
        Ok(newly)
    }

    /// Release one reference per required component; components that reach
    /// zero references are de-initialized.
    pub fn release_dependencies(&self, requires: &[String]) {
        for comp in requires {
            let count = self.session.lock().unwrap().component_remove_ref(comp);
            if count == 0 {
                self.deinit_component(comp);
            }
        }
    }

    /// Initialize components without holding references (stateless cheats).
    pub fn ensure_dependencies_now(&self, requires: &[String]) -> EngineResult<()> {
        for comp in requires {
            let initialized = self.session.lock().unwrap().component_initialized(comp);
            if !initialized {
                self.init_component(comp)?;
            }
        }
        Ok(())
    }

    /// Initialize a bootstrap component: run its `[ENABLE]` section with the
    /// component id as owner (so its symbols/allocations are owned by the
    /// component, not by any one cheat).
    pub fn init_component(&self, comp_id: &str) -> EngineResult<()> {
        let entry = self
            .def
            .scripts
            .bootstrap
            .iter()
            .find(|e| e.id() == comp_id)
            .ok_or_else(|| {
                EngineError::InvalidTrainer(format!("unknown component '{comp_id}'"))
            })?;
        let file = entry.file().to_string();
        self.run(comp_id, &file, Section::Enable)?;
        self.session
            .lock()
            .unwrap()
            .mark_component_initialized(comp_id);
        Ok(())
    }

    /// Best-effort component teardown (`[DISABLE]` + deinit marker).
    pub fn deinit_component(&self, comp_id: &str) {
        let file = self
            .def
            .scripts
            .bootstrap
            .iter()
            .find(|e| e.id() == comp_id)
            .map(|e| e.file().to_string());
        if let Some(file) = file {
            if let Err(e) = self.run(comp_id, &file, Section::Disable) {
                eprintln!("[forge] component '{comp_id}' disable failed: {e}");
            }
        }
        self.session
            .lock()
            .unwrap()
            .mark_component_deinitialized(comp_id);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::ops::mock::MockMemory;
    use crate::trainer::definition::BootstrapEntry;
    use std::fs;

    fn setup_package(files: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "deckforge-deps-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for (rel, content) in files {
            let path = dir.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        dir
    }

    /// A trainer definition with one bootstrap component `player_instance`.
    fn def_with_component() -> TrainerDefinition {
        let json = r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 1, "name": "G", "process": "game.exe" },
          "trainer": { "id": "t", "name": "T", "version": "1" },
          "scripts": {
            "bootstrap": [ { "id": "player_instance", "file": "scripts/common/player_instance.asm" } ]
          },
          "cheats": []
        }"#;
        let def: TrainerDefinition = serde_json::from_str(json).unwrap();
        // BootstrapEntry deserialization sanity check
        assert!(matches!(
            def.scripts.bootstrap[0],
            BootstrapEntry::Named { .. }
        ));
        def
    }

    const COMPONENT_SCRIPT: &str =
        "[ENABLE]\nalloc(playerInstance,64)\nregistersymbol(playerInstance)\n[DISABLE]\nunregistersymbol(playerInstance)\ndealloc(playerInstance)\n";

    fn runner<'a>(
        mem: &'a MockMemory,
        session: Arc<Mutex<TrainerSession>>,
        dir: &'a std::path::Path,
        def: &'a TrainerDefinition,
    ) -> AaRunner<'a> {
        AaRunner {
            ops: mem,
            session,
            package_dir: dir,
            trainer_id: "t",
            def,
        }
    }

    #[test]
    fn dependency_initializes_lazily() {
        let dir = setup_package(&[("scripts/common/player_instance.asm", COMPONENT_SCRIPT)]);
        let mut mem = MockMemory::new(64);
        mem.add_module("game.exe", 0x400000, 0x100000);
        let def = def_with_component();
        let session = Arc::new(Mutex::new(TrainerSession::new()));

        // Nothing initialized before first use.
        assert!(!session.lock().unwrap().component_initialized("player_instance"));

        let r = runner(&mem, Arc::clone(&session), &dir, &def);
        r.ensure_dependencies(&["player_instance".to_string()]).unwrap();

        let s = session.lock().unwrap();
        assert!(s.component_initialized("player_instance"));
        assert!(s.symbol("playerInstance").is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_cheats_share_one_dependency() {
        let dir = setup_package(&[("scripts/common/player_instance.asm", COMPONENT_SCRIPT)]);
        let mut mem = MockMemory::new(64);
        mem.add_module("game.exe", 0x400000, 0x100000);
        let def = def_with_component();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let r = runner(&mem, Arc::clone(&session), &dir, &def);

        let req = vec!["player_instance".to_string()];
        // Two cheats enable.
        r.ensure_dependencies(&req).unwrap();
        r.ensure_dependencies(&req).unwrap();
        // The component script ran once (one allocation only).
        assert_eq!(mem.allocs.borrow().len(), 1);
        assert!(session.lock().unwrap().symbol("playerInstance").is_some());

        // Disabling the first cheat keeps the component alive.
        r.release_dependencies(&req);
        assert!(session.lock().unwrap().component_initialized("player_instance"));
        assert!(session.lock().unwrap().symbol("playerInstance").is_some());
        assert!(mem.frees.borrow().is_empty());

        // Disabling the second tears it down.
        r.release_dependencies(&req);
        let s = session.lock().unwrap();
        assert!(!s.component_initialized("player_instance"));
        assert!(s.symbol("playerInstance").is_none());
        drop(s);
        assert_eq!(mem.frees.borrow().len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_dependency_init_unwinds() {
        // The component script fails (pattern not found).
        let dir = setup_package(&[(
            "scripts/common/player_instance.asm",
            "[ENABLE]\naobscanmodule(BOGUS,game.exe,DE AD BE EF DE AD)\n",
        )]);
        let mut mem = MockMemory::new(64);
        mem.add_module("game.exe", 0x400000, 0x100000);
        let def = def_with_component();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let r = runner(&mem, Arc::clone(&session), &dir, &def);

        let err = r
            .ensure_dependencies(&["player_instance".to_string()])
            .unwrap_err();
        assert!(matches!(err, EngineError::AutoAssemblerError(_)));
        let s = session.lock().unwrap();
        assert!(!s.component_initialized("player_instance"));
        assert_eq!(s.components.get("player_instance").map(|c| c.ref_count), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_component_errors() {
        let dir = setup_package(&[]);
        let mem = MockMemory::new(64);
        let def = def_with_component();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let r = runner(&mem, Arc::clone(&session), &dir, &def);
        let err = r.ensure_dependencies(&["nope".to_string()]).unwrap_err();
        assert!(matches!(err, EngineError::InvalidTrainer(_)));
        let _ = fs::remove_dir_all(&dir);
    }
}
