//! DeckForge engine entry point.
//!
//! Reads newline-delimited JSON requests from stdin, dispatches them, and writes
//! one JSON response per line to stdout. Logs go to stderr only — stdout is
//! reserved exclusively for protocol messages.

// The engine defines a full error-code enum and trainer schema up front for
// forward compatibility; several variants/fields are reserved for features that
// land in later milestones (freeze, Lua, online repo). Allow dead code so the
// reserved surface compiles cleanly without per-field annotations.
#![allow(dead_code)]

mod autoasm;
mod cheats;
mod error;
mod memory;
mod pointer_scan;
mod process;
mod protocol;
mod resolver;
mod scanner;
mod state;
mod store;
mod trainer;

use std::io::{self, BufRead, Write};

use serde::Serialize;

use error::{EngineError, EngineResult};
use protocol::{
    CatalogData, CatalogItemData, CheatResultData, Command, GameData, InstalledListData,
    InstalledTrainerData, JobIdData, JobStatusData, PingData, PointerScanData, ReadBytesData,
    ReadValueData, ReloadTrainerData, Request, ResolveCheatData, Response, ScanClassifyData,
    ScanCountData, ScanResultsData, ScanStringData,
    ShutdownData, TriggerCheatData, UninstallData, ValueResultSetData, WriteValueData,
};
use state::EngineState;

fn main() {
    eprintln!("[deckforge-engine] starting v{}", state::ENGINE_VERSION);

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let mut state = EngineState::new();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[deckforge-engine] stdin error: {e}");
                break;
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse to a Value first so we can echo back the request id even when
        // the command payload is malformed.
        let raw: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                let resp = Response::error(
                    "__unknown__",
                    &EngineError::InvalidRequest(format!("malformed JSON: {e}")),
                );
                write_response(&mut out, &resp);
                continue;
            }
        };
        let id = extract_id(&raw);

        let req: Request = match serde_json::from_value(raw) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::error(
                    &id,
                    &EngineError::InvalidRequest(format!("invalid request: {e}")),
                );
                write_response(&mut out, &resp);
                continue;
            }
        };

        let shutting_down = matches!(req.command, Command::Shutdown);
        let resp = match dispatch(&mut state, &req.command) {
            Ok(data) => Response::success(&id, data),
            Err(e) => Response::error(&id, &e),
        };
        write_response(&mut out, &resp);

        if shutting_down {
            eprintln!("[deckforge-engine] shutdown requested, exiting");
            break;
        }
    }

    eprintln!("[deckforge-engine] exiting");
}

fn extract_id(raw: &serde_json::Value) -> String {
    raw.get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("__unknown__")
        .to_string()
}

fn write_response(out: &mut impl Write, resp: &Response) {
    if let Ok(s) = serde_json::to_string(resp) {
        let _ = writeln!(out, "{s}");
        let _ = out.flush();
    }
}

fn val<T: Serialize>(t: T) -> serde_json::Value {
    serde_json::to_value(t).unwrap_or(serde_json::Value::Null)
}

fn dispatch(state: &mut EngineState, cmd: &Command) -> EngineResult<serde_json::Value> {
    match cmd {
        Command::Ping => Ok(val(PingData {
            message: "pong".into(),
        })),

        Command::GetStatus => {
            // Auto-detach: if the attached game has exited, discard its state
            // so status immediately reports "not attached".
            let _ = state.ensure_alive();
            Ok(val(state.status()))
        }

        Command::DetectGame => match crate::process::discovery::detect_running_game()? {
            Some(gp) => Ok(val(GameData {
                app_id: gp.app_id,
                pid: gp.pid,
                name: gp.executable.clone(),
                executable: gp.executable,
            })),
            None => Ok(serde_json::Value::Null),
        },

        Command::GetActiveGame => Ok(match &state.process {
            Some(_) => val(state.game_data()),
            None => serde_json::Value::Null,
        }),

        Command::AttachGame { app_id } => {
            let data = state.attach_game(*app_id)?;
            Ok(val(data))
        }

        Command::GetTrainer { app_id } => {
            if let Some(app) = app_id {
                let current = state.process.as_ref().map(|p| p.app_id) == Some(*app);
                if !current && state.trainer.is_none() {
                    state.load_trainer_for(*app)?;
                }
            }
            Ok(match state.trainer_data() {
                Some(d) => val(d),
                None => serde_json::Value::Null,
            })
        }

        Command::EnableCheat { cheat_id } => {
            state.ensure_alive()?;
            state.refresh_maps();
            let mem = state.memory()?;
            let maps = state.maps_slice()?.to_vec();
            let t = state.trainer.as_mut().ok_or(EngineError::TrainerNotFound)?;
            t.enable_cheat(cheat_id, &mem, &maps)?;
            Ok(val(CheatResultData {
                cheat_id: cheat_id.clone(),
                enabled: true,
            }))
        }

        Command::DisableCheat { cheat_id } => {
            state.ensure_alive()?;
            state.refresh_maps();
            let mem = state.memory()?;
            let maps = state.maps_slice()?.to_vec();
            let t = state.trainer.as_mut().ok_or(EngineError::TrainerNotFound)?;
            t.disable_cheat(cheat_id, &mem, &maps)?;
            Ok(val(CheatResultData {
                cheat_id: cheat_id.clone(),
                enabled: false,
            }))
        }

        Command::SetValue { cheat_id, value } => {
            state.ensure_alive()?;
            state.refresh_maps();
            let mem = state.memory()?;
            let maps = state.maps_slice()?.to_vec();
            let t = state.trainer.as_mut().ok_or(EngineError::TrainerNotFound)?;
            let written = t.set_value(cheat_id, value, &mem, &maps)?;
            Ok(val(ValueResultSetData {
                cheat_id: cheat_id.clone(),
                value: written,
            }))
        }

        Command::TriggerCheat { cheat_id } => {
            state.ensure_alive()?;
            state.refresh_maps();
            let mem = state.memory()?;
            let maps = state.maps_slice()?.to_vec();
            let t = state.trainer.as_mut().ok_or(EngineError::TrainerNotFound)?;
            let value = t.trigger_cheat(cheat_id, &mem, &maps)?;
            Ok(val(TriggerCheatData {
                cheat_id: cheat_id.clone(),
                value,
            }))
        }

        Command::ReloadTrainer => {
            let app_id = state
                .process
                .as_ref()
                .map(|p| p.app_id)
                .ok_or(EngineError::GameNotRunning)?;
            state.load_trainer_for(app_id)?;
            Ok(val(ReloadTrainerData { reloaded: true }))
        }

        Command::ScanValue {
            value,
            width,
            float,
        } => {
            state.ensure_alive()?;
            let mem = state.memory()?;
            let maps = state.maps_slice()?.to_vec();
            let v = if *float {
                value
                    .as_f64()
                    .ok_or_else(|| EngineError::InvalidRequest("expected number".into()))?
            } else {
                value
                    .as_i64()
                    .ok_or_else(|| EngineError::InvalidRequest("expected integer".into()))?
                    as f64
            };
            let results = crate::scanner::first_scan(&mem, &maps, v, *width, *float)?;
            state.scan.width = *width;
            state.scan.results = results;
            Ok(val(ScanCountData {
                count: state.scan.count(),
            }))
        }

        Command::ScanFilter { value, float } => {
            state.ensure_alive()?;
            if state.scan.results.is_empty() {
                return Err(EngineError::InvalidRequest(
                    "no previous scan to filter; run scan_value first".into(),
                ));
            }
            let mem = state.memory()?;
            let v = if *float {
                value
                    .as_f64()
                    .ok_or_else(|| EngineError::InvalidRequest("expected number".into()))?
            } else {
                value
                    .as_i64()
                    .ok_or_else(|| EngineError::InvalidRequest("expected integer".into()))?
                    as f64
            };
            let results =
                crate::scanner::next_scan(&mem, &state.scan.results, v, state.scan.width, *float)?;
            state.scan.results = results;
            Ok(val(ScanCountData {
                count: state.scan.count(),
            }))
        }

        Command::ScanCount => Ok(val(ScanCountData {
            count: state.scan.count(),
        })),

        Command::ScanResults { limit } => {
            let limit = limit.unwrap_or(100);
            let addresses: Vec<usize> = state.scan.results.iter().take(limit).copied().collect();
            Ok(val(ScanResultsData {
                count: state.scan.count(),
                addresses,
            }))
        }

        Command::ScanClear => {
            state.scan.clear();
            Ok(val(ScanCountData { count: 0 }))
        }

        Command::ScanClassify { address } => {
            state.ensure_alive()?;
            state.refresh_maps();
            let mem = state.memory()?;
            let modules = crate::memory::ops::loaded_modules(&mem, state.maps_slice()?);
            let (module, module_offset, is_static) =
                match crate::scanner::classify_address(&modules, *address) {
                    Some((name, off)) => (Some(name.to_string()), Some(off), true),
                    None => (None, None, false),
                };
            Ok(val(ScanClassifyData {
                address: *address,
                module,
                module_offset,
                is_static,
            }))
        }

        Command::ReadValue { address, width } => {
            state.ensure_alive()?;
            let mem = state.memory()?;
            let bytes = mem.read_bytes(*address, *width)?;
            let (v, fval) = match *width {
                4 => (
                    i32::from_ne_bytes(bytes[..4].try_into().unwrap()) as i64,
                    None,
                ),
                8 => {
                    let i = i64::from_ne_bytes(bytes[..8].try_into().unwrap());
                    let f = f64::from_ne_bytes(bytes[..8].try_into().unwrap());
                    (i, Some(f))
                }
                2 => (
                    i16::from_ne_bytes(bytes[..2].try_into().unwrap()) as i64,
                    None,
                ),
                1 => (bytes[0] as i8 as i64, None),
                _ => {
                    return Err(EngineError::InvalidRequest(format!(
                        "unsupported width {width}"
                    )))
                }
            };
            Ok(val(ReadValueData {
                address: *address,
                value: v,
                float_value: fval,
                width: *width,
            }))
        }

        Command::WriteValue {
            address,
            value,
            width,
        } => {
            state.ensure_alive()?;
            let mem = state.memory()?;
            let bytes = match *width {
                4 => (*value as i32).to_ne_bytes().to_vec(),
                8 => value.to_ne_bytes().to_vec(),
                2 => (*value as i16).to_ne_bytes().to_vec(),
                1 => (*value as i8).to_ne_bytes().to_vec(),
                _ => {
                    return Err(EngineError::InvalidRequest(format!(
                        "unsupported width {width}"
                    )))
                }
            };
            mem.write_bytes(*address, &bytes)?;
            Ok(val(WriteValueData {
                address: *address,
                value: *value,
                width: *width,
            }))
        }

        Command::PointerScan {
            address,
            max_depth,
            max_offset,
        } => {
            state.ensure_alive()?;
            state.refresh_maps();
            let mem = state.memory()?;
            let maps = state.maps_slice()?.to_vec();
            let result =
                crate::pointer_scan::scan_pointers(&mem, &maps, *address, *max_depth, *max_offset)?;
            Ok(val(PointerScanData {
                chains: result.chains,
                total_found: result.total_found,
                truncated: result.truncated,
            }))
        }

        Command::ScanString {
            pattern,
            max_results,
        } => {
            state.ensure_alive()?;
            let mem = state.memory()?;
            let maps = state.maps_slice()?.to_vec();
            let needle = pattern.as_bytes();
            let max = if *max_results == 0 { 100 } else { *max_results };
            let mut found = Vec::new();

            // Scan ALL readable regions (including read-only data sections where
            // GameMaker stores its strings, and module code sections).
            for region in maps.iter().filter(|r| r.readable) {
                if found.len() >= max {
                    break;
                }
                let size = region.size();
                if size == 0 || size > 64 * 1024 * 1024 {
                    continue;
                }
                const CHUNK: usize = 4 * 1024 * 1024;
                let mut offset = 0usize;
                while offset < size && found.len() < max {
                    let chunk_size = CHUNK.min(size - offset);
                    let addr = region.start + offset;
                    match mem.read_bytes(addr, chunk_size) {
                        Ok(data) => {
                            let nlen = needle.len();
                            if nlen == 0 || nlen > data.len() {
                                offset += chunk_size;
                                continue;
                            }
                            for (i, window) in data.windows(nlen).enumerate() {
                                if window == needle {
                                    found.push(addr + i);
                                    if found.len() >= max {
                                        break;
                                    }
                                }
                            }
                        }
                        Err(_) => {}
                    }
                    offset += chunk_size;
                }
            }
            let count = found.len();
            Ok(val(ScanStringData {
                addresses: found,
                count,
            }))
        }

        Command::ReadBytes { address, size } => {
            state.ensure_alive()?;
            let mem = state.memory()?;
            let bytes = mem.read_bytes(*address, *size)?;
            Ok(val(ReadBytesData {
                address: *address,
                bytes,
            }))
        }

        Command::ResolveCheat { cheat_id } => {
            state.ensure_alive()?;
            state.refresh_maps();
            let mem = state.memory()?;
            let maps = state.maps_slice()?.to_vec();
            let t = state.trainer.as_mut().ok_or(EngineError::TrainerNotFound)?;
            let (addr, value) = t.read_cheat_value(cheat_id, &mem, &maps)?;
            Ok(val(ResolveCheatData {
                cheat_id: cheat_id.clone(),
                address: addr,
                value,
            }))
        }

        Command::RepoList => {
            let items = state.store.list_catalog()?;
            Ok(val(CatalogData {
                trainers: items
                    .into_iter()
                    .map(|i| CatalogItemData {
                        app_id: i.app_id,
                        game_name: i.game_name,
                        trainer_name: i.trainer_name,
                        version: i.version,
                        author: i.author,
                        file_count: i.file_count,
                        installed: i.installed,
                        installed_version: i.installed_version,
                        update_available: i.update_available,
                    })
                    .collect(),
            }))
        }

        Command::RepoInstall { app_id } => {
            let job_id = state.store.install(*app_id)?;
            Ok(val(JobIdData { job_id }))
        }

        Command::InstallStatus { job_id } => {
            let st = state.store.install_status(job_id)?;
            let mut reloaded = false;
            // Hot-reload the trainer exactly once when the job finishes, but
            // only if it matches the currently attached game (otherwise the
            // package is on disk and loads when that game attaches).
            if st.state == crate::store::JobState::Done && !st.reloaded {
                if state.process.as_ref().map(|p| p.app_id) == Some(st.app_id) {
                    let _ = state.load_trainer_for(st.app_id);
                    reloaded = true;
                }
                state.store.mark_reloaded(job_id);
            }
            Ok(val(JobStatusData {
                state: st.state.as_str().to_string(),
                progress: st.progress,
                error: st.error,
                app_id: st.app_id,
                reloaded: reloaded || st.reloaded,
            }))
        }

        Command::RepoUninstall { app_id } => {
            state.store.uninstall(*app_id)?;
            // If the uninstalled trainer is the loaded one, drop it.
            if state.process.as_ref().map(|p| p.app_id) == Some(*app_id) {
                let _ = state.load_trainer_for(*app_id);
            }
            Ok(val(UninstallData {
                app_id: *app_id,
                uninstalled: true,
            }))
        }

        Command::RepoListInstalled => {
            let list = state.store.list_installed()?;
            Ok(val(InstalledListData {
                trainers: list
                    .into_iter()
                    .map(|t| InstalledTrainerData {
                        app_id: t.app_id,
                        game_name: t.game_name,
                        trainer_name: t.trainer_name,
                        version: t.version,
                        author: t.author,
                    })
                    .collect(),
            }))
        }

        Command::Shutdown => Ok(val(ShutdownData {
            message: "shutting down".into(),
        })),
    }
}
