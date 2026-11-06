//! Trainer runtime: owns the loaded definition, per-cheat patch state, the
//! shared trainer session (symbols/allocations/bootstrap components), and
//! dispatches enable / disable / set_value through the memory + resolver +
//! script layers.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::autoasm::Section;
use crate::cheats::patch::PatchRuntime;
use crate::error::{EngineError, EngineResult};
use crate::memory::{LiveMemory, MemoryAccess, MemoryOps, MemoryRegion};
use crate::resolver;
use crate::trainer::components::AaRunner;
use crate::trainer::definition::{CheatAction, CheatDefinition, TrainerDefinition};
use crate::trainer::session::TrainerSession;

pub struct TrainerRuntime {
    pub def: TrainerDefinition,
    pub patches: HashMap<String, PatchRuntime>,
    pub last_errors: HashMap<String, String>,
    /// Shared sandboxed Lua engine for `"type": "script"` resolvers.
    pub scripts: crate::cheats::script::ScriptEngineHandle,
    /// Central freeze scheduler (infinite health/ammo style cheats).
    pub freezes: crate::cheats::freeze::FreezeManager,
    /// Trainer-session state: symbols, allocations, bootstrap components.
    /// Shared with the Lua engine (for `trainer.symbol()`).
    pub session: Arc<Mutex<TrainerSession>>,
    /// Currently enabled Auto Assembler cheats.
    pub aa_enabled: HashSet<String>,
}

impl TrainerRuntime {
    pub fn new(def: TrainerDefinition) -> Self {
        let mut patches = HashMap::new();
        for cheat in &def.cheats {
            if matches!(cheat.action, CheatAction::Patch { .. }) {
                patches.insert(cheat.id.clone(), PatchRuntime::default());
            }
        }
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let scripts = crate::cheats::script::new_handle(crate::cheats::script::ScriptEngine::new(
            &def.game.process,
            def.script_setup.clone(),
            def.setup_scripts.clone(),
            Arc::clone(&session),
        ));
        let freezes = crate::cheats::freeze::FreezeManager::new(&def.game.process);
        freezes.set_script_engine(Arc::clone(&scripts));
        Self {
            def,
            patches,
            last_errors: HashMap::new(),
            scripts,
            freezes,
            session,
            aa_enabled: HashSet::new(),
        }
    }

    fn index_of(&self, cheat_id: &str) -> EngineResult<usize> {
        self.def
            .cheats
            .iter()
            .position(|c| c.id == cheat_id)
            .ok_or_else(|| EngineError::InvalidRequest(format!("unknown cheat '{cheat_id}'")))
    }

    pub fn cheat(&self, cheat_id: &str) -> EngineResult<&CheatDefinition> {
        let i = self.index_of(cheat_id)?;
        Ok(&self.def.cheats[i])
    }

    /// Is a cheat currently enabled? (Patch, freeze, and Auto Assembler
    /// cheats track this.)
    pub fn is_enabled(&self, cheat_id: &str) -> bool {
        self.patches.get(cheat_id).is_some_and(|p| p.is_enabled())
            || self.freezes.contains(cheat_id)
            || self.aa_enabled.contains(cheat_id)
    }

    pub fn last_error(&self, cheat_id: &str) -> Option<&str> {
        self.last_errors.get(cheat_id).map(|s| s.as_str())
    }

    pub fn enable_cheat(
        &mut self,
        cheat_id: &str,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<()> {
        let result = self.enable_cheat_inner(cheat_id, mem, maps);
        self.record(cheat_id, &result);
        result
    }

    fn enable_cheat_inner(
        &mut self,
        cheat_id: &str,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<()> {
        let i = self.index_of(cheat_id)?;
        let action = self.def.cheats[i].action.clone();
        let is_aa = matches!(action, CheatAction::AutoAssembler { .. });

        // Runtime dependencies: initialize lazily, hold a reference for the
        // duration the cheat is enabled. `newly` tracks what *this* call
        // initialized so a failure can unwind cleanly.
        let newly = self.ensure_dependencies(cheat_id, mem, maps)?;

        let result = self.enable_action(cheat_id, action, mem, maps);
        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                self.release_dependencies(cheat_id, &newly, mem, maps);
                if is_aa {
                    self.aa_enabled.remove(cheat_id);
                }
                Err(e)
            }
        }
    }

    /// Execute the cheat's action assuming dependencies are held.
    fn enable_action(
        &mut self,
        cheat_id: &str,
        action: CheatAction,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<()> {
        match action {
            CheatAction::Patch {
                resolver,
                offset,
                expected,
                enabled,
            } => {
                let mut addr = resolver::resolve(&resolver, mem, maps, &self.scripts)?;
                addr += offset.as_ref().map(|h| h.parse()).transpose()?.unwrap_or(0);
                let exp = resolver::parse_hex_bytes(&expected)?;
                let en = resolver::parse_hex_bytes(&enabled)?;
                let runtime = self
                    .patches
                    .get_mut(cheat_id)
                    .expect("patch cheat must have a runtime entry");
                runtime.enable(mem, cheat_id, addr, &exp, &en)
            }
            CheatAction::Value { .. } => Err(EngineError::InvalidRequest(
                "value cheats are set with set_value, not enable".into(),
            )),
            CheatAction::Freeze {
                value_type,
                value,
                interval_ms,
                resolver,
                restore_on_disable,
            } => {
                if self.freezes.contains(cheat_id) {
                    return Err(EngineError::CheatAlreadyEnabled(cheat_id.to_string()));
                }
                let bytes = crate::cheats::value::value_to_bytes(
                    value_type,
                    &serde_json::Value::from(value),
                )?;
                self.freezes.set_pid(mem.pid);
                self.freezes.add(
                    cheat_id,
                    crate::cheats::freeze::FreezeEntry {
                        resolver,
                        bytes,
                        interval_ms: interval_ms.unwrap_or(100),
                        restore_on_disable,
                    },
                );
                Ok(())
            }
            CheatAction::AutoAssembler { file } => {
                if self.aa_enabled.contains(cheat_id) {
                    return Err(EngineError::CheatAlreadyEnabled(cheat_id.to_string()));
                }
                self.run_aa(cheat_id, &file, Section::Enable, mem, maps)?;
                self.aa_enabled.insert(cheat_id.to_string());
                Ok(())
            }
        }
    }

    pub fn disable_cheat(
        &mut self,
        cheat_id: &str,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<()> {
        let result = self.disable_cheat_inner(cheat_id, mem, maps);
        self.record(cheat_id, &result);
        result
    }

    fn disable_cheat_inner(
        &mut self,
        cheat_id: &str,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<()> {
        let i = self.index_of(cheat_id)?;
        let action = self.def.cheats[i].action.clone();
        let mut restored = Ok(());
        let result = match action {
            CheatAction::Patch { .. } => {
                let runtime = self
                    .patches
                    .get_mut(cheat_id)
                    .ok_or_else(|| EngineError::CheatNotEnabled(cheat_id.to_string()))?;
                runtime.disable(mem, cheat_id)
            }
            CheatAction::Freeze { ref resolver, .. } => {
                if self.freezes.remove(cheat_id) {
                    // Before the release below: the resolver may need a
                    // symbol that this cheat's dependency provides.
                    restored = self.restore_frozen(cheat_id, resolver, mem, maps);
                    Ok(())
                } else {
                    Err(EngineError::CheatNotEnabled(cheat_id.to_string()))
                }
            }
            CheatAction::AutoAssembler { ref file } => {
                if !self.aa_enabled.contains(cheat_id) {
                    return Err(EngineError::CheatNotEnabled(cheat_id.to_string()));
                }
                let r = self.run_aa(cheat_id, file, Section::Disable, mem, maps);
                if r.is_ok() {
                    self.aa_enabled.remove(cheat_id);
                }
                r
            }
            CheatAction::Value { .. } => Err(EngineError::InvalidRequest(
                "value cheats are stateless; only patch/freeze/auto_assembler cheats disable"
                    .into(),
            )),
        };
        match result {
            Ok(()) => {
                // Release this cheat's dependency references; components with
                // no remaining dependents are torn down.
                self.release_dependencies(cheat_id, &[], mem, maps);
                restored
            }
            Err(e) => Err(e),
        }
    }

    /// Write back the value saved when a `restoreOnDisable` freeze started. The
    /// saved address must still be where the resolver points: otherwise the
    /// game has moved the value and that memory may now hold something else.
    fn restore_frozen(
        &self,
        cheat_id: &str,
        resolver: &resolver::Resolver,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<()> {
        let Some(saved) = self.freezes.take_saved(cheat_id) else {
            return Ok(());
        };
        match resolver::resolve(resolver, mem, maps, &self.scripts) {
            Ok(addr) if addr == saved.addr => mem.write_bytes(addr, &saved.bytes),
            Ok(_) => {
                eprintln!("[forge] freeze '{cheat_id}': value moved; not restoring");
                Ok(())
            }
            Err(e) => {
                eprintln!("[forge] freeze '{cheat_id}': not restoring ({e})");
                Ok(())
            }
        }
    }

    /// Build an [`AaRunner`] over the live process for this trainer.
    fn runner<'a>(&'a self, live: &'a dyn MemoryOps) -> AaRunner<'a> {
        AaRunner {
            ops: live,
            session: Arc::clone(&self.session),
            package_dir: &self.def.package_dir,
            trainer_id: &self.def.trainer.id,
            def: &self.def,
        }
    }

    /// Live backend for the current attach.
    fn live<'a>(&'a self, mem: &'a MemoryAccess, maps: &'a [MemoryRegion]) -> LiveMemory<'a> {
        LiveMemory::new(mem, maps, &self.def.game.process)
    }

    /// Run one section of an Auto Assembler script owned by `owner`.
    fn run_aa(
        &mut self,
        owner: &str,
        file: &str,
        section: Section,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<()> {
        let live = self.live(mem, maps);
        self.runner(&live).run(owner, file, section)
    }

    /// Initialize every component in the cheat's `requires` list (lazily) and
    /// hold one reference per component. Returns the components that were
    /// newly initialized by this call.
    fn ensure_dependencies(
        &mut self,
        cheat_id: &str,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<Vec<String>> {
        let requires: Vec<String> = self.cheat(cheat_id)?.requires.clone();
        let live = self.live(mem, maps);
        self.runner(&live).ensure_dependencies(&requires)
    }

    /// Drop this cheat's dependency references. Components whose ref count
    /// reaches zero are de-initialized (their `[DISABLE]` runs, their symbols
    /// and allocations are released).
    fn release_dependencies(
        &mut self,
        cheat_id: &str,
        _newly: &[String],
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) {
        let Ok(cheat) = self.cheat(cheat_id) else {
            return;
        };
        let requires = cheat.requires.clone();
        let live = self.live(mem, maps);
        self.runner(&live).release_dependencies(&requires);
    }

    /// Ensure a cheat's dependencies are initialized *without* holding a
    /// reference — for stateless operations (set_value / read_cheat_value) on
    /// cheats that don't have an enabled lifetime.
    fn ensure_dependencies_now(
        &mut self,
        cheat_id: &str,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<()> {
        let requires = self.cheat(cheat_id)?.requires.clone();
        let live = self.live(mem, maps);
        self.runner(&live).ensure_dependencies_now(&requires)
    }

    pub fn set_value(
        &mut self,
        cheat_id: &str,
        value: &Value,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<Value> {
        let result = self.set_value_inner(cheat_id, value, mem, maps);
        self.record(cheat_id, &result);
        result
    }

    fn set_value_inner(
        &mut self,
        cheat_id: &str,
        value: &Value,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<Value> {
        let i = self.index_of(cheat_id)?;
        self.def.cheats[i].check_range(value)?;
        let action = self.def.cheats[i].action.clone();
        match action {
            CheatAction::Value {
                value_type,
                resolver,
                ..
            } => {
                // Script resolvers may depend on bootstrap-registered symbols;
                // initialize them on demand (no reference is held — value
                // cheats are stateless).
                self.ensure_dependencies_now(cheat_id, mem, maps)?;
                let addr = resolver::resolve(&resolver, mem, maps, &self.scripts)?;
                crate::cheats::value::write_value(mem, addr, value_type, value)?;
                Ok(value.clone())
            }
            CheatAction::Patch { .. } => Err(EngineError::InvalidRequest(
                "patch cheats use enable/disable, not set_value".into(),
            )),
            CheatAction::Freeze { .. } => Err(EngineError::NotImplemented),
            CheatAction::AutoAssembler { .. } => Err(EngineError::InvalidRequest(
                "auto_assembler cheats are toggles; they don't take values".into(),
            )),
        }
    }

    /// One-shot trigger for `action`-control cheats (a Decky button). Writes
    /// the action's declared value once — no `FreezeManager` entry, no
    /// enabled/disabled state. Supports `freeze` and `value` actions;
    /// `patch`/`auto_assembler` are toggle-only and are rejected.
    pub fn trigger_cheat(
        &mut self,
        cheat_id: &str,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<Value> {
        let result = self.trigger_cheat_inner(cheat_id, mem, maps);
        self.record(cheat_id, &result);
        result
    }

    fn trigger_cheat_inner(
        &mut self,
        cheat_id: &str,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<Value> {
        let i = self.index_of(cheat_id)?;
        let action = self.def.cheats[i].action.clone();
        match action {
            CheatAction::Freeze {
                value_type,
                value,
                resolver,
                ..
            } => {
                self.ensure_dependencies_now(cheat_id, mem, maps)?;
                let addr = resolver::resolve(&resolver, mem, maps, &self.scripts)?;
                let v = serde_json::Value::from(value);
                crate::cheats::value::write_value(mem, addr, value_type, &v)?;
                Ok(v)
            }
            CheatAction::Value {
                value_type,
                resolver,
                value,
            } => {
                let v = value.ok_or_else(|| {
                    EngineError::InvalidRequest(
                        "action control on a value cheat requires a declared \"value\" field"
                            .into(),
                    )
                })?;
                self.ensure_dependencies_now(cheat_id, mem, maps)?;
                let addr = resolver::resolve(&resolver, mem, maps, &self.scripts)?;
                crate::cheats::value::write_value(mem, addr, value_type, &v)?;
                Ok(v)
            }
            CheatAction::Patch { .. } => Err(EngineError::InvalidRequest(
                "action control does not support patch cheats; use control \"toggle\"".into(),
            )),
            CheatAction::AutoAssembler { .. } => Err(EngineError::InvalidRequest(
                "action control does not support auto_assembler cheats; use control \"toggle\""
                    .into(),
            )),
        }
    }

    fn record<T>(&mut self, cheat_id: &str, result: &EngineResult<T>) {
        match result {
            Ok(_) => {
                self.last_errors.remove(cheat_id);
            }
            Err(e) => {
                self.last_errors.insert(cheat_id.to_string(), e.message());
            }
        }
    }

    /// Discard all resolved addresses / patch state (e.g. on process exit).
    /// The definition is retained so cheats still render (all OFF).
    pub fn reset_runtime_state(&mut self) {
        for rt in self.patches.values_mut() {
            rt.reset();
        }
        self.scripts.lock().unwrap().reset();
        self.freezes.clear();
        self.last_errors.clear();
        self.aa_enabled.clear();
        self.session.lock().unwrap().clear();
    }

    /// Best-effort cleanup while the process is still alive (trainer reload /
    /// unload): run `[DISABLE]` for every active Auto Assembler cheat and
    /// every initialized bootstrap component, then clear session state.
    pub fn shutdown(&mut self, mem: &MemoryAccess, maps: &[MemoryRegion]) {
        // First, because a freeze resolver may need a symbol from a component.
        let freezes: Vec<(String, resolver::Resolver)> = self
            .def
            .cheats
            .iter()
            .filter_map(|c| match &c.action {
                CheatAction::Freeze { resolver, .. } => Some((c.id.clone(), resolver.clone())),
                _ => None,
            })
            .collect();
        for (id, resolver) in &freezes {
            if self.freezes.remove(id) {
                if let Err(e) = self.restore_frozen(id, resolver, mem, maps) {
                    eprintln!("[forge] shutdown: restore '{id}' failed: {e}");
                }
            }
        }
        // Clone the module name so `live` doesn't borrow `self`.
        let module = self.def.game.process.clone();
        let live = LiveMemory::new(mem, maps, &module);
        self.shutdown_impl(&live);
    }

    fn shutdown_impl(&mut self, ops: &dyn MemoryOps) {
        let aa: Vec<String> = self.aa_enabled.iter().cloned().collect();
        {
            let runner = self.runner(ops);
            for cheat_id in &aa {
                let file = match self.def.cheats.iter().find(|c| &c.id == cheat_id) {
                    Some(c) => match &c.action {
                        CheatAction::AutoAssembler { file } => Some(file.clone()),
                        _ => None,
                    },
                    None => None,
                };
                if let Some(file) = file {
                    if let Err(e) = runner.run(cheat_id, &file, Section::Disable) {
                        eprintln!("[forge] shutdown: disable '{cheat_id}' failed: {e}");
                    }
                }
            }
        }
        for cheat_id in &aa {
            self.aa_enabled.remove(cheat_id);
        }
        let components: Vec<String> = {
            let session = self.session.lock().unwrap();
            session
                .components
                .iter()
                .filter(|(_, c)| c.initialized)
                .map(|(id, _)| id.clone())
                .collect()
        };
        {
            let runner = self.runner(ops);
            for comp in &components {
                runner.deinit_component(comp);
            }
        }
        self.session.lock().unwrap().clear();
    }

    /// Read-only cheat resolution: resolve the cheat's address and read the
    /// current value back. Never writes. Used to validate resolvers against
    /// what the game shows.
    pub fn read_cheat_value(
        &mut self,
        cheat_id: &str,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<(usize, Value)> {
        let result = self.read_cheat_value_inner(cheat_id, mem, maps);
        self.record(cheat_id, &result);
        result
    }

    fn read_cheat_value_inner(
        &mut self,
        cheat_id: &str,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
    ) -> EngineResult<(usize, Value)> {
        let i = self.index_of(cheat_id)?;
        let action = self.def.cheats[i].action.clone();
        match action {
            CheatAction::Value {
                value_type,
                resolver,
                ..
            }
            | CheatAction::Freeze {
                value_type,
                resolver,
                ..
            } => {
                self.ensure_dependencies_now(cheat_id, mem, maps)?;
                let addr = resolver::resolve(&resolver, mem, maps, &self.scripts)?;
                let v = crate::cheats::value::read_value(mem, addr, value_type)?;
                Ok((addr, v))
            }
            CheatAction::Patch { .. } => Err(EngineError::InvalidRequest(
                "patch cheats have no readable value".into(),
            )),
            CheatAction::AutoAssembler { .. } => Err(EngineError::InvalidRequest(
                "auto_assembler cheats have no readable value".into(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::ops::mock::MockMemory;
    use std::fs;

    fn setup_package(files: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "deckforge-unload-{}-{}",
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

    const COMPONENT: &str =
        "[ENABLE]\nalloc(playerInstance,64)\nregistersymbol(playerInstance)\n[DISABLE]\nunregistersymbol(playerInstance)\ndealloc(playerInstance)\n";

    const CHEAT: &str = r#"
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 ?? ?? ?? ??)
alloc(newmem,1024,INJECT)
label(return)
newmem:
  movss [rbx+00000120],xmm0
  jmp return
INJECT:
  jmp newmem
  nop 3
return:
registersymbol(INJECT)
[DISABLE]
INJECT:
  db F3 0F 11 83 20 01 00 00
unregistersymbol(INJECT)
dealloc(newmem)
"#;

    // Second cheat hooks a different instruction (movss [rbx+120],xmm1).
    const CHEAT2: &str = r#"
[ENABLE]
aobscanmodule(INJECT2,game.exe,F3 0F 11 8B ?? ?? ?? ??)
alloc(newmem2,1024,INJECT2)
label(return2)
newmem2:
  movss [rbx+00000120],xmm1
  jmp return2
INJECT2:
  jmp newmem2
  nop 3
return2:
registersymbol(INJECT2)
[DISABLE]
INJECT2:
  db F3 0F 11 8B 20 01 00 00
unregistersymbol(INJECT2)
dealloc(newmem2)
"#;

    fn test_def(package_dir: &std::path::Path) -> TrainerDefinition {
        let json = r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 1, "name": "G", "process": "game.exe" },
          "trainer": { "id": "t", "name": "T", "version": "1" },
          "scripts": {
            "bootstrap": [ { "id": "player_instance", "file": "scripts/common/player_instance.asm" } ]
          },
          "cheats": [
            { "id": "infinite_health", "name": "IH", "control": "toggle",
              "requires": ["player_instance"],
              "action": { "type": "auto_assembler", "file": "scripts/infinite_health.asm" } },
            { "id": "infinite_stamina", "name": "IS", "control": "toggle",
              "requires": ["player_instance"],
              "action": { "type": "auto_assembler", "file": "scripts/infinite_stamina.asm" } }
          ]
        }"#;
        let mut def: TrainerDefinition = serde_json::from_str(json).unwrap();
        def.package_dir = package_dir.to_path_buf();
        def
    }

    fn mock_game() -> MockMemory {
        let mut mem = MockMemory::new(64);
        mem.add_module("game.exe", 0x400000, 0x100000);
        mem.plant(0x401000, &[0xF3, 0x0F, 0x11, 0x83, 0x20, 0x01, 0x00, 0x00]);
        mem.plant(0x402000, &[0xF3, 0x0F, 0x11, 0x8B, 0x20, 0x01, 0x00, 0x00]);
        mem
    }

    /// Full lifecycle: enable two cheats sharing one bootstrap component,
    /// disable one (component survives), then unload (restores the other
    /// cheat's patch, tears the component down, frees everything).
    #[test]
    fn trainer_unload_cleans_up() {
        let dir = setup_package(&[
            ("scripts/common/player_instance.asm", COMPONENT),
            ("scripts/infinite_health.asm", CHEAT),
            ("scripts/infinite_stamina.asm", CHEAT2),
        ]);
        let mem = mock_game();
        let mut rt = TrainerRuntime::new(test_def(&dir));

        // Enable both cheats through the runner (what enable_cheat does for
        // AA cheats, minus the concrete process backend).
        {
            let runner = rt.runner(&mem);
            runner
                .ensure_dependencies(&["player_instance".to_string()])
                .unwrap();
            runner
                .run(
                    "infinite_health",
                    "scripts/infinite_health.asm",
                    Section::Enable,
                )
                .unwrap();
        }
        rt.aa_enabled.insert("infinite_health".to_string());
        {
            let runner = rt.runner(&mem);
            runner
                .ensure_dependencies(&["player_instance".to_string()])
                .unwrap();
            runner
                .run(
                    "infinite_stamina",
                    "scripts/infinite_stamina.asm",
                    Section::Enable,
                )
                .unwrap();
        }
        rt.aa_enabled.insert("infinite_stamina".to_string());

        // Component initialized once, two allocs (component + one per cheat).
        assert_eq!(mem.allocs.borrow().len(), 3);
        assert!(rt
            .session
            .lock()
            .unwrap()
            .symbol("playerInstance")
            .is_some());
        assert!(rt.session.lock().unwrap().symbol("INJECT").is_some());
        // Patches applied at both hooks.
        assert_eq!(mem.peek(0x401000, 1), vec![0xE9]);
        assert_eq!(mem.peek(0x402000, 1), vec![0xE9]);

        // Disable one cheat: its patch restored, component still alive, the
        // other cheat's patch still in place.
        {
            let runner = rt.runner(&mem);
            runner
                .run(
                    "infinite_health",
                    "scripts/infinite_health.asm",
                    Section::Disable,
                )
                .unwrap();
            runner.release_dependencies(&["player_instance".to_string()]);
        }
        rt.aa_enabled.remove("infinite_health");
        assert_eq!(
            mem.peek(0x401000, 8),
            vec![0xF3, 0x0F, 0x11, 0x83, 0x20, 0x01, 0x00, 0x00]
        );
        assert_eq!(mem.peek(0x402000, 1), vec![0xE9]);
        assert!(rt
            .session
            .lock()
            .unwrap()
            .component_initialized("player_instance"));
        assert!(rt
            .session
            .lock()
            .unwrap()
            .symbol("playerInstance")
            .is_some());

        // Unload: the other cheat's [DISABLE] runs, the component is torn
        // down, everything is freed and cleared.
        rt.shutdown_impl(&mem);
        assert!(!rt.is_enabled("infinite_stamina"));
        assert_eq!(
            mem.peek(0x402000, 8),
            vec![0xF3, 0x0F, 0x11, 0x8B, 0x20, 0x01, 0x00, 0x00]
        );
        assert!(rt.session.lock().unwrap().symbols.is_empty());
        assert!(rt.session.lock().unwrap().allocations.is_empty());
        assert!(!rt
            .session
            .lock()
            .unwrap()
            .component_initialized("player_instance"));
        // All three allocations freed.
        assert_eq!(mem.frees.borrow().len(), 3);

        let _ = fs::remove_dir_all(&dir);
    }

    /// An `action`-control button on a `patch` cheat is rejected: patches are
    /// toggle-only (they have restore semantics). No memory access is needed
    /// for this branch, so pid 0 is fine.
    #[test]
    fn trigger_rejects_patch_action() {
        let json = r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 1, "name": "G", "process": "g.exe" },
          "trainer": { "id": "t", "name": "T", "version": "1" },
          "cheats": [{
            "id": "c", "name": "C", "control": "action",
            "action": { "type": "patch",
              "resolver": { "type": "absolute", "address": "0x1000" },
              "expected": "89 43", "enabled": "90 90" }
          }]
        }"#;
        let def: TrainerDefinition = serde_json::from_str(json).unwrap();
        let mut rt = TrainerRuntime::new(def);
        let mem = MemoryAccess::new(0);
        let maps: Vec<MemoryRegion> = vec![];
        let err = rt.trigger_cheat("c", &mem, &maps).unwrap_err();
        assert!(matches!(err, EngineError::InvalidRequest(_)));
        assert!(err.message().contains("patch"), "{}", err.message());
    }

    /// An `action`-control button on a `value` cheat without a declared
    /// `value` field is rejected (there is nothing to write). No memory access
    /// is needed for this branch.
    #[test]
    fn trigger_rejects_value_without_declared_value() {
        let json = r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 1, "name": "G", "process": "g.exe" },
          "trainer": { "id": "t", "name": "T", "version": "1" },
          "cheats": [{
            "id": "c", "name": "C", "control": "action",
            "action": { "type": "value", "valueType": "int32",
              "resolver": { "type": "absolute", "address": "0x1000" } }
          }]
        }"#;
        let def: TrainerDefinition = serde_json::from_str(json).unwrap();
        let mut rt = TrainerRuntime::new(def);
        let mem = MemoryAccess::new(0);
        let maps: Vec<MemoryRegion> = vec![];
        let err = rt.trigger_cheat("c", &mem, &maps).unwrap_err();
        assert!(matches!(err, EngineError::InvalidRequest(_)));
        assert!(err.message().contains("value"), "{}", err.message());
    }
}
