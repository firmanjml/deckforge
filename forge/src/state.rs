//! Engine state: the attached process, its cached maps, and the loaded trainer
//! runtime. This is Forge's source of truth — never stored in React or Python.

use crate::error::{EngineError, EngineResult};
use crate::memory::{MemoryAccess, MemoryRegion};
use crate::process::{self, procfs::is_alive, GameProcess};
use crate::protocol::{CheatData, GameData, GameInfoData, StatusData, TrainerData, TrainerSummaryData};
use crate::store::Store;
use crate::trainer::{self, TrainerRuntime};

pub const ENGINE_VERSION: &str = "0.1.0";

pub struct EngineState {
    pub process: Option<GameProcess>,
    pub maps: Option<Vec<MemoryRegion>>,
    pub trainer: Option<TrainerRuntime>,
    pub scan: crate::scanner::ScanState,
    /// Trainer store: browse/install/uninstall remote trainer packages.
    pub store: Store,
}

impl Default for EngineState {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineState {
    pub fn new() -> Self {
        Self {
            process: None,
            maps: None,
            trainer: None,
            scan: crate::scanner::ScanState::default(),
            store: Store::new(),
        }
    }

    pub fn is_attached(&self) -> bool {
        self.process.is_some()
    }

    /// Memory accessor for the attached process.
    pub fn memory(&self) -> EngineResult<MemoryAccess> {
        let pid = self
            .process
            .as_ref()
            .map(|p| p.pid)
            .ok_or(EngineError::GameNotRunning)?;
        Ok(MemoryAccess::new(pid))
    }

    /// Cached maps for the attached process.
    pub fn maps_slice(&self) -> EngineResult<&[MemoryRegion]> {
        self.maps.as_deref().ok_or(EngineError::GameNotRunning)
    }

    /// If the attached process has died, discard all runtime state.
    pub fn ensure_alive(&mut self) -> EngineResult<()> {
        if let Some(p) = &self.process {
            if !is_alive(p.pid) {
                self.detach();
                return Err(EngineError::GameNotRunning);
            }
        }
        Ok(())
    }

    /// Re-read `/proc/<pid>/maps`. The game keeps allocating as it runs
    /// (loading a save creates new heap regions), so maps cached at attach
    /// time go stale — call this before resolution-heavy operations.
    pub fn refresh_maps(&mut self) {
        if let Some(p) = &self.process {
            if let Ok(maps) = process::modules::read_modules(p.pid) {
                self.maps = Some(maps);
            }
        }
    }

    /// Discard process, maps, and per-cheat runtime state. The trainer
    /// definition is retained so the UI can still render (all cheats OFF).
    pub fn detach(&mut self) {
        self.process = None;
        self.maps = None;
        if let Some(t) = &mut self.trainer {
            t.reset_runtime_state();
        }
    }

    /// Discover and attach the game process for `app_id`, load its maps and
    /// trainer (if one exists).
    pub fn attach_game(&mut self, app_id: u64) -> EngineResult<GameData> {
        let gp = process::find_game_process(app_id)?;
        let pid = gp.pid;
        self.process = Some(gp);
        // Maps may fail to read for some processes; degrade gracefully.
        let maps = process::modules::read_modules(pid).unwrap_or_default();
        self.maps = Some(maps);
        self.load_trainer_for(app_id)?;
        Ok(self.game_data())
    }

    /// Load (or clear) the trainer for `app_id`. A missing trainer is not an
    /// error; an invalid one is. A replaced trainer is shut down cleanly
    /// first (best-effort disable of active script cheats).
    pub fn load_trainer_for(&mut self, app_id: u64) -> EngineResult<()> {
        match trainer::load_trainer(app_id) {
            Ok(def) => {
                if let Some(old) = self.trainer.as_mut() {
                    let mem = self.process.as_ref().map(|p| MemoryAccess::new(p.pid));
                    let maps = self.maps.clone().unwrap_or_default();
                    if let Some(mem) = mem {
                        old.shutdown(&mem, &maps);
                    }
                }
                self.trainer = Some(TrainerRuntime::new(def));
            }
            Err(EngineError::TrainerNotFound) => {
                if let Some(old) = self.trainer.as_mut() {
                    let mem = self.process.as_ref().map(|p| MemoryAccess::new(p.pid));
                    let maps = self.maps.clone().unwrap_or_default();
                    if let Some(mem) = mem {
                        old.shutdown(&mem, &maps);
                    }
                }
                self.trainer = None;
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    pub fn game_data(&self) -> GameData {
        let p = self
            .process
            .as_ref()
            .expect("game_data called without an attached process");
        GameData {
            app_id: p.app_id,
            pid: p.pid,
            name: self
                .trainer
                .as_ref()
                .map(|t| t.def.game.name.clone())
                .unwrap_or_else(|| p.executable.clone()),
            executable: p.executable.clone(),
        }
    }

    pub fn status(&self) -> StatusData {
        StatusData {
            engine_version: ENGINE_VERSION.to_string(),
            running: true,
            attached: self.is_attached(),
            game: self.process.as_ref().map(|_| self.game_data()),
            trainer: self.trainer.as_ref().map(|t| TrainerSummaryData {
                id: t.def.trainer.id.clone(),
                name: t.def.trainer.name.clone(),
                version: t.def.trainer.version.clone(),
            }),
        }
    }

    /// Full trainer payload for `get_trainer`, or `None` if no trainer loaded.
    pub fn trainer_data(&self) -> Option<TrainerData> {
        let t = self.trainer.as_ref()?;
        let game = GameInfoData {
            steam_app_id: t.def.game.steam_app_id,
            name: t.def.game.name.clone(),
            process: t.def.game.process.clone(),
        };
        let trainer = TrainerSummaryData {
            id: t.def.trainer.id.clone(),
            name: t.def.trainer.name.clone(),
            version: t.def.trainer.version.clone(),
        };
        let cheats: Vec<CheatData> = t
            .def
            .cheats
            .iter()
            .map(|c| CheatData {
                id: c.id.clone(),
                name: c.name.clone(),
                control: c.control.as_str().to_string(),
                enabled: t.is_enabled(&c.id),
                min: c.min,
                max: c.max,
                last_error: t.last_error(&c.id).map(|s| s.to_string()),
            })
            .collect();
        Some(TrainerData {
            game,
            trainer,
            cheats,
        })
    }
}
