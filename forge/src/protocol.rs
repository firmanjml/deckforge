//! Newline-delimited JSON IPC protocol.
//!
//! Wire shape (one JSON object per line):
//!
//! Request:  `{ "id": "req-1", "command": "ping" }`
//! Response: `{ "id": "req-1", "ok": true, "data": { ... } }`
//! Error:    `{ "id": "req-1", "ok": false, "error": { "code": "...", "message": "..." } }`
//!
//! Every request carries a unique `id`; every response echoes it. All Rust-side
//! payloads are strongly typed Serde structs — no ad-hoc JSON construction in
//! command handlers.

use serde::{Deserialize, Serialize};

use crate::error::EngineError;

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// Top-level request envelope: a request id plus the tagged command payload.
#[derive(Debug, Deserialize)]
pub struct Request {
    pub id: String,
    #[serde(flatten)]
    pub command: Command,
}

/// The full command set. `command` is the internal serde tag; variant names are
/// snake_cased to match the wire format (`enable_cheat`, `set_value`, ...).
/// Command-specific fields use camelCase on the wire (e.g. `cheatId`, `appId`).
#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    Ping,
    GetStatus,
    GetActiveGame,
    /// Auto-discovery: find the currently running Steam game (no AppID input).
    DetectGame,
    AttachGame {
        #[serde(rename = "appId")]
        app_id: u64,
    },
    GetTrainer {
        #[serde(rename = "appId", default)]
        app_id: Option<u64>,
    },
    EnableCheat {
        #[serde(rename = "cheatId")]
        cheat_id: String,
    },
    DisableCheat {
        #[serde(rename = "cheatId")]
        cheat_id: String,
    },
    SetValue {
        #[serde(rename = "cheatId")]
        cheat_id: String,
        value: serde_json::Value,
    },
    /// One-shot trigger for `action`-control cheats (a Decky button): writes
    /// the action's declared value once without entering enabled/disabled
    /// state. Currently supports `freeze` and `value` actions.
    TriggerCheat {
        #[serde(rename = "cheatId")]
        cheat_id: String,
    },
    ReloadTrainer,
    ScanValue {
        value: serde_json::Value,
        width: usize,
        #[serde(default)]
        float: bool,
    },
    ScanFilter {
        value: serde_json::Value,
        #[serde(default)]
        float: bool,
    },
    ScanCount,
    ScanResults {
        #[serde(default)]
        limit: Option<usize>,
    },
    ScanClear,
    ScanClassify {
        address: usize,
    },
    ReadValue {
        address: usize,
        width: usize,
    },
    WriteValue {
        address: usize,
        value: i64,
        width: usize,
    },
    ScanString {
        pattern: String,
        #[serde(default)]
        max_results: usize,
    },
    ReadBytes {
        address: usize,
        size: usize,
    },
    /// Read-only cheat validation: resolve the cheat's address and read its
    /// current value. Never writes memory.
    ResolveCheat {
        #[serde(rename = "cheatId")]
        cheat_id: String,
    },
    PointerScan {
        address: usize,
        #[serde(default = "default_depth")]
        max_depth: usize,
        #[serde(default = "default_offset")]
        max_offset: usize,
    },
    /// Trainer store: list the remote catalog, annotated with install status.
    RepoList,
    /// Trainer store: start a background install of a trainer package.
    RepoInstall {
        #[serde(rename = "appId")]
        app_id: u64,
    },
    /// Trainer store: poll an install job's status. When a job reaches `Done`
    /// the dispatch layer hot-reloads the trainer (once) for the attached game.
    InstallStatus {
        #[serde(rename = "jobId")]
        job_id: String,
    },
    /// Trainer store: remove an installed trainer package.
    RepoUninstall {
        #[serde(rename = "appId")]
        app_id: u64,
    },
    /// Trainer store: list locally installed trainers (no network).
    RepoListInstalled,
    Shutdown,
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct Response {
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorResponse>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
}

impl Response {
    pub fn success<T: Serialize>(id: &str, data: T) -> Self {
        Response {
            id: id.to_string(),
            ok: true,
            data: Some(serde_json::to_value(data).unwrap_or_else(|_| serde_json::Value::Null)),
            error: None,
        }
    }

    pub fn error(id: &str, err: &EngineError) -> Self {
        Response {
            id: id.to_string(),
            ok: false,
            data: None,
            error: Some(ErrorResponse {
                code: err.code().to_string(),
                message: err.message(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Response data payloads (strongly typed)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct PingData {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct StatusData {
    #[serde(rename = "engineVersion")]
    pub engine_version: String,
    pub running: bool,
    pub attached: bool,
    pub game: Option<GameData>,
    pub trainer: Option<TrainerSummaryData>,
}

#[derive(Debug, Serialize, Clone)]
pub struct GameData {
    #[serde(rename = "appId")]
    pub app_id: u64,
    pub pid: i32,
    pub name: String,
    pub executable: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct TrainerSummaryData {
    pub id: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct GameInfoData {
    #[serde(rename = "steamAppId")]
    pub steam_app_id: u64,
    pub name: String,
    pub process: String,
}

/// Full trainer payload returned by `get_trainer`. Cheats carry their current
/// runtime state so Cockpit renders dynamically from the engine's truth.
#[derive(Debug, Serialize)]
pub struct TrainerData {
    pub game: GameInfoData,
    pub trainer: TrainerSummaryData,
    pub cheats: Vec<CheatData>,
}

#[derive(Debug, Serialize, Clone)]
pub struct CheatData {
    pub id: String,
    pub name: String,
    pub control: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheatResultData {
    #[serde(rename = "cheatId")]
    pub cheat_id: String,
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct ValueResultSetData {
    #[serde(rename = "cheatId")]
    pub cheat_id: String,
    pub value: serde_json::Value,
}

/// Response payload for `trigger_cheat`: the value written by the one-shot
/// action (taken from the action's declared `value`).
#[derive(Debug, Serialize)]
pub struct TriggerCheatData {
    #[serde(rename = "cheatId")]
    pub cheat_id: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ShutdownData {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ReloadTrainerData {
    pub reloaded: bool,
}

#[derive(Debug, Serialize)]
pub struct ScanCountData {
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct ScanResultsData {
    pub addresses: Vec<usize>,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct ScanClassifyData {
    pub address: usize,
    pub module: Option<String>,
    pub module_offset: Option<usize>,
    pub is_static: bool,
}

#[derive(Debug, Serialize)]
pub struct ReadValueData {
    pub address: usize,
    pub value: i64,
    pub float_value: Option<f64>,
    pub width: usize,
}

#[derive(Debug, Serialize)]
pub struct WriteValueData {
    pub address: usize,
    pub value: i64,
    pub width: usize,
}

#[derive(Debug, Serialize)]
pub struct PointerScanData {
    pub chains: Vec<crate::pointer_scan::PointerChain>,
    pub total_found: usize,
}

fn default_depth() -> usize {
    3
}
fn default_offset() -> usize {
    0x1000
}

#[derive(Debug, Serialize)]
pub struct ResolveCheatData {
    pub cheat_id: String,
    pub address: usize,
    pub value: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ScanStringData {
    pub addresses: Vec<usize>,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct ReadBytesData {
    pub address: usize,
    pub bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Trainer store payloads
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct CatalogData {
    pub trainers: Vec<CatalogItemData>,
}

#[derive(Debug, Serialize)]
pub struct CatalogItemData {
    #[serde(rename = "appId")]
    pub app_id: u64,
    #[serde(rename = "gameName")]
    pub game_name: String,
    #[serde(rename = "trainerName")]
    pub trainer_name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(rename = "fileCount")]
    pub file_count: usize,
    pub installed: bool,
    #[serde(rename = "installedVersion", skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    #[serde(rename = "updateAvailable")]
    pub update_available: bool,
}

#[derive(Debug, Serialize)]
pub struct JobIdData {
    #[serde(rename = "jobId")]
    pub job_id: String,
}

#[derive(Debug, Serialize)]
pub struct JobStatusData {
    pub state: String,
    pub progress: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(rename = "appId")]
    pub app_id: u64,
    pub reloaded: bool,
}

#[derive(Debug, Serialize)]
pub struct UninstallData {
    #[serde(rename = "appId")]
    pub app_id: u64,
    pub uninstalled: bool,
}

#[derive(Debug, Serialize)]
pub struct InstalledListData {
    pub trainers: Vec<InstalledTrainerData>,
}

#[derive(Debug, Serialize)]
pub struct InstalledTrainerData {
    #[serde(rename = "appId")]
    pub app_id: u64,
    #[serde(rename = "gameName")]
    pub game_name: String,
    #[serde(rename = "trainerName")]
    pub trainer_name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_ping_request() {
        let req: Request = serde_json::from_str(r#"{"id":"req-1","command":"ping"}"#).unwrap();
        assert_eq!(req.id, "req-1");
        assert!(matches!(req.command, Command::Ping));
    }

    #[test]
    fn deserializes_enable_cheat_with_camel_case() {
        let req: Request =
            serde_json::from_str(r#"{"id":"r","command":"enable_cheat","cheatId":"ammo"}"#)
                .unwrap();
        assert!(matches!(req.command, Command::EnableCheat { .. }));
        match req.command {
            Command::EnableCheat { cheat_id } => assert_eq!(cheat_id, "ammo"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn deserializes_attach_game_app_id() {
        let req: Request =
            serde_json::from_str(r#"{"id":"r","command":"attach_game","appId":123456}"#).unwrap();
        match req.command {
            Command::AttachGame { app_id } => assert_eq!(app_id, 123456),
            _ => unreachable!(),
        }
    }

    #[test]
    fn deserializes_trigger_cheat() {
        let req: Request =
            serde_json::from_str(r#"{"id":"r","command":"trigger_cheat","cheatId":"enable_jump"}"#)
                .unwrap();
        match req.command {
            Command::TriggerCheat { cheat_id } => assert_eq!(cheat_id, "enable_jump"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn serializes_success_response() {
        let resp = Response::success(
            "req-9",
            PingData {
                message: "pong".into(),
            },
        );
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(v["id"], "req-9");
        assert_eq!(v["ok"], true);
        assert_eq!(v["data"]["message"], "pong");
        assert!(v.get("error").is_none());
    }

    #[test]
    fn serializes_error_response_with_code() {
        let err = EngineError::SignatureNotFound;
        let resp = Response::error("req-2", &err);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "SIGNATURE_NOT_FOUND");
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Signature"));
    }

    #[test]
    fn rejects_unknown_command() {
        assert!(serde_json::from_str::<Request>(r#"{"id":"r","command":"frobnicate"}"#).is_err());
    }

    #[test]
    fn status_data_uses_camel_case_keys() {
        let s = StatusData {
            engine_version: "0.1.0".into(),
            running: true,
            attached: false,
            game: None,
            trainer: None,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(v["engineVersion"], "0.1.0");
        assert_eq!(v["attached"], false);
    }
}
