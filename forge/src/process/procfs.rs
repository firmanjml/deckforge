//! `/proc` filesystem reading.
//!
//! All functions use `std::fs`, so they compile everywhere but only find real
//! data on Linux/SteamOS. They return structured errors on non-Linux hosts.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{EngineError, EngineResult};

/// Basic info about a process discovered under `/proc`.
#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: i32,
    pub comm: String,
    pub cmdline: Vec<String>,
}

/// The attached game process, resolved from a Steam AppID.
#[derive(Debug, Clone)]
pub struct GameProcess {
    pub app_id: u64,
    pub pid: i32,
    pub executable: String,
    pub command_line: String,
}

fn proc_path(pid: i32, file: &str) -> PathBuf {
    Path::new("/proc").join(pid.to_string()).join(file)
}

/// Is `pid` a live process? (`/proc/<pid>` exists.)
pub fn is_alive(pid: i32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

/// `/proc/<pid>/comm` (the executable basename, max 15 chars).
pub fn read_comm(pid: i32) -> EngineResult<String> {
    let s = fs::read_to_string(proc_path(pid, "comm"))
        .map_err(|_| EngineError::ProcessNotFound)?;
    Ok(s.trim().to_string())
}

/// `/proc/<pid>/cmdline` as a list of arguments (NUL-separated).
pub fn read_cmdline(pid: i32) -> EngineResult<Vec<String>> {
    let bytes = fs::read(proc_path(pid, "cmdline"))
        .map_err(|_| EngineError::ProcessNotFound)?;
    Ok(bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect())
}

/// `/proc/<pid>/environ` as a list of `KEY=VALUE` entries (NUL-separated).
pub fn read_environ(pid: i32) -> EngineResult<Vec<String>> {
    let bytes = fs::read(proc_path(pid, "environ"))
        .map_err(|_| EngineError::ProcessNotFound)?;
    Ok(bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect())
}

/// Full raw contents of `/proc/<pid>/maps`.
pub fn read_maps_raw(pid: i32) -> EngineResult<String> {
    fs::read_to_string(proc_path(pid, "maps"))
        .map_err(|_| EngineError::ProcessNotFound)
}

/// Full raw contents of `/proc/<pid>/status`.
pub fn read_status_raw(pid: i32) -> EngineResult<String> {
    fs::read_to_string(proc_path(pid, "status"))
        .map_err(|_| EngineError::ProcessNotFound)
}

/// Parse `/proc/<pid>/status` into a `field -> value` map.
pub fn parse_status(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        if let Some((k, v)) = line.split_once(':') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

/// Enumerate all live processes under `/proc` with their `comm` and `cmdline`.
pub fn list_processes() -> EngineResult<Vec<ProcInfo>> {
    let mut out = Vec::new();
    let entries = fs::read_dir("/proc").map_err(|_| EngineError::ProcessNotFound)?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let pid: i32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue, // not a pid directory
        };
        let comm = read_comm(pid).unwrap_or_default();
        let cmdline = read_cmdline(pid).unwrap_or_default();
        out.push(ProcInfo { pid, comm, cmdline });
    }
    Ok(out)
}
