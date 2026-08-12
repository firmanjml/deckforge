//! Steam/Proton process discovery.
//!
//! Given a Steam AppID, find the real game process — not helper processes like
//! `steam`, `steamwebhelper`, `wineserver`, `pressure-vessel`, Proton launchers,
//! or crash handlers. The heuristic reads each candidate's `environ` for the
//! Steam AppID and excludes known helpers. Selection can be refined later.

use crate::error::{EngineError, EngineResult};

use super::procfs::{list_processes, read_environ, GameProcess, ProcInfo};

/// Processes that are never the game itself.
const HELPER_BLOCKLIST: &[&str] = &[
    "steam",
    "steamwebhelper",
    "wineserver",
    "pressure-vessel",
    "pressure-vessel-ad",
    "pressure-vessel-wrap",
    "steam-runtime",
    "crashpad_handler",
    "crashhandler",
    "isolate",
    "reaper",
];

/// Is `comm` a known helper process we should never attach to?
fn is_helper(comm: &str) -> bool {
    let comm = comm.to_ascii_lowercase();
    // Exact blocklist match, plus Proton launcher prefix.
    if HELPER_BLOCKLIST.iter().any(|h| comm == *h) {
        return true;
    }
    if comm.starts_with("proton")
        && (comm.contains("launcher") || comm.contains("init") || comm == "proton")
    {
        return true;
    }
    false
}

/// Does this process's environment reference `app_id` as the Steam game?
fn environ_matches_appid(pid: i32, app_id: u64) -> bool {
    let env = match read_environ(pid) {
        Ok(e) => e,
        Err(_) => return false,
    };
    let target = format!("SteamAppId={}", app_id);
    let target_game = format!("SteamGameId={}", app_id);
    env.iter().any(|e| e == &target || e == &target_game)
}

/// All processes whose environment references `app_id`, excluding helpers.
pub fn list_candidate_processes(app_id: u64) -> EngineResult<Vec<ProcInfo>> {
    let procs = list_processes()?;
    Ok(procs
        .into_iter()
        .filter(|p| !is_helper(&p.comm) && environ_matches_appid(p.pid, app_id))
        .collect())
}

/// Find the best game process for `app_id`.
///
/// Among candidates (env references the AppID, not a helper), prefer the one
/// with the most memory regions — the actual game binary has far more mapped
/// memory than launchers and helpers.
pub fn find_game_process(app_id: u64) -> EngineResult<GameProcess> {
    let candidates = list_candidate_processes(app_id)?;
    let best = candidates
        .into_iter()
        .max_by_key(|p| {
            // Count memory map entries as a proxy for process size — the real
            // game has hundreds/thousands of mapped regions; helpers have few.
            let maps = std::fs::read_to_string(format!("/proc/{}/maps", p.pid)).unwrap_or_default();
            maps.lines().filter(|l| !l.trim().is_empty()).count()
        })
        .ok_or(EngineError::ProcessNotFound)?;

    let executable = best
        .cmdline
        .first()
        .cloned()
        .unwrap_or_else(|| best.comm.clone());
    let executable_basename = executable
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&executable)
        .to_string();

    Ok(GameProcess {
        app_id,
        pid: best.pid,
        executable: executable_basename,
        command_line: best.cmdline.join(" "),
    })
}

/// Inspect a specific pid (for future developer-mode manual selection).
pub fn inspect_process(pid: i32) -> EngineResult<ProcInfo> {
    let procs = list_processes()?;
    procs
        .into_iter()
        .find(|p| p.pid == pid)
        .ok_or(EngineError::ProcessNotFound)
}

/// Detect the currently running Steam game without being told an AppID:
/// scan every non-helper process environment for `SteamGameId`/`SteamAppId`,
/// then pick the candidate with the most mapped regions (the real game binary
/// dwarfs launchers and wrappers). Returns `None` when no game is running.
pub fn detect_running_game() -> EngineResult<Option<GameProcess>> {
    let procs = list_processes()?;
    let mut best: Option<(ProcInfo, u64, usize)> = None;

    for p in procs {
        if is_helper(&p.comm) {
            continue;
        }
        let env = match read_environ(p.pid) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let app_id = env.iter().find_map(|e| {
            e.strip_prefix("SteamGameId=")
                .or_else(|| e.strip_prefix("SteamAppId="))
                .and_then(|v| v.parse::<u64>().ok())
        });
        let Some(app_id) = app_id else { continue };
        if app_id == 0 {
            continue;
        }
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", p.pid)).unwrap_or_default();
        let count = maps.lines().filter(|l| !l.trim().is_empty()).count();
        // Tiny wrappers have a handful of regions; the real game has hundreds.
        if count < 50 {
            continue;
        }
        if best.as_ref().is_none_or(|(_, _, c)| count > *c) {
            best = Some((p, app_id, count));
        }
    }

    Ok(best.map(|(p, app_id, _)| {
        let executable = p.cmdline.first().cloned().unwrap_or_else(|| p.comm.clone());
        let executable_basename = executable
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&executable)
            .to_string();
        GameProcess {
            app_id,
            pid: p.pid,
            executable: executable_basename,
            command_line: p.cmdline.join(" "),
        }
    }))
}
