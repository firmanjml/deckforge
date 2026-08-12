//! Structured engine errors.
//!
//! Every runtime failure maps to a stable string `code` that Cockpit and Relay
//! can branch on without parsing free-text messages. Normal runtime errors must
//! never panic the engine; they are converted into protocol error responses.

use std::fmt;

#[derive(Debug, Clone)]
pub enum EngineError {
    EngineNotRunning,
    InvalidRequest(String),
    NotImplemented,
    GameNotRunning,
    ProcessNotFound,
    ModuleNotFound(String),
    TrainerNotFound,
    InvalidTrainer(String),
    SignatureNotFound,
    SignatureAmbiguous,
    InvalidPointer(String),
    MemoryReadFailed(String),
    MemoryWriteFailed(String),
    ExpectedBytesMismatch,
    UnsupportedValueType(String),
    CheatAlreadyEnabled(String),
    CheatNotEnabled(String),
    /// Scripted (Lua) resolver failures: syntax/runtime errors in inline
    /// script code or `scriptSetup`, or a script not returning an address.
    ScriptError(String),
    /// Auto Assembler failures. The detail string carries full context
    /// (trainer, cheat, script file, section, line, command, underlying
    /// cause) — see [`crate::autoasm::AaError`].
    AutoAssemblerError(String),
    /// Online trainer repository: a network request failed (DNS, connect,
    /// read, non-2xx status other than rate-limit/not-found).
    RepoNetworkError(String),
    /// Online trainer repository: the requested AppID/package was not found
    /// in the repository catalog.
    RepoNotFound,
    /// Online trainer repository: a downloaded package failed validation
    /// (malformed trainer.json, AppID mismatch, bad script paths, …).
    RepoInvalidPackage(String),
    /// Online trainer repository: an unknown job id was polled.
    RepoJobNotFound,
    /// Online trainer repository: the GitHub API returned a 403 rate-limit
    /// response.
    RepoRateLimited,
    /// Online trainer repository: a local filesystem operation failed while
    /// installing/uninstalling a trainer package.
    RepoIoError(String),
}

impl EngineError {
    /// Stable wire code. Cockpit/Relay branch on this, never on `message`.
    pub fn code(&self) -> &'static str {
        match self {
            EngineError::EngineNotRunning => "ENGINE_NOT_RUNNING",
            EngineError::InvalidRequest(_) => "INVALID_REQUEST",
            EngineError::NotImplemented => "NOT_IMPLEMENTED",
            EngineError::GameNotRunning => "GAME_NOT_RUNNING",
            EngineError::ProcessNotFound => "PROCESS_NOT_FOUND",
            EngineError::ModuleNotFound(_) => "MODULE_NOT_FOUND",
            EngineError::TrainerNotFound => "TRAINER_NOT_FOUND",
            EngineError::InvalidTrainer(_) => "INVALID_TRAINER",
            EngineError::SignatureNotFound => "SIGNATURE_NOT_FOUND",
            EngineError::SignatureAmbiguous => "SIGNATURE_AMBIGUOUS",
            EngineError::InvalidPointer(_) => "INVALID_POINTER",
            EngineError::MemoryReadFailed(_) => "MEMORY_READ_FAILED",
            EngineError::MemoryWriteFailed(_) => "MEMORY_WRITE_FAILED",
            EngineError::ExpectedBytesMismatch => "EXPECTED_BYTES_MISMATCH",
            EngineError::UnsupportedValueType(_) => "UNSUPPORTED_VALUE_TYPE",
            EngineError::CheatAlreadyEnabled(_) => "CHEAT_ALREADY_ENABLED",
            EngineError::CheatNotEnabled(_) => "CHEAT_NOT_ENABLED",
            EngineError::ScriptError(_) => "SCRIPT_ERROR",
            EngineError::AutoAssemblerError(_) => "AUTO_ASSEMBLER_ERROR",
            EngineError::RepoNetworkError(_) => "REPO_NETWORK_ERROR",
            EngineError::RepoNotFound => "REPO_NOT_FOUND",
            EngineError::RepoInvalidPackage(_) => "REPO_INVALID_PACKAGE",
            EngineError::RepoJobNotFound => "REPO_JOB_NOT_FOUND",
            EngineError::RepoRateLimited => "REPO_RATE_LIMITED",
            EngineError::RepoIoError(_) => "REPO_IO_ERROR",
        }
    }

    /// Human-readable detail. For display only; not a control signal.
    pub fn message(&self) -> String {
        match self {
            EngineError::EngineNotRunning => "Forge engine is not running.".into(),
            EngineError::InvalidRequest(d) => format!("Invalid request: {d}"),
            EngineError::NotImplemented => "This operation is not implemented yet.".into(),
            EngineError::GameNotRunning => "No game process is currently attached.".into(),
            EngineError::ProcessNotFound => "No matching game process was found.".into(),
            EngineError::ModuleNotFound(m) => format!("Module '{m}' was not found in process maps."),
            EngineError::TrainerNotFound => "No trainer is installed for this game.".into(),
            EngineError::InvalidTrainer(d) => format!("Invalid trainer definition: {d}"),
            EngineError::SignatureNotFound => "Signature pattern did not match any address.".into(),
            EngineError::SignatureAmbiguous => "Signature pattern matched multiple addresses; refusing to pick arbitrarily.".into(),
            EngineError::InvalidPointer(d) => format!("Invalid pointer chain: {d}"),
            EngineError::MemoryReadFailed(d) => format!("Memory read failed: {d}"),
            EngineError::MemoryWriteFailed(d) => format!("Memory write failed: {d}"),
            EngineError::ExpectedBytesMismatch => "Expected bytes at target do not match; refusing to patch.".into(),
            EngineError::UnsupportedValueType(d) => format!("Unsupported value type: {d}"),
            EngineError::CheatAlreadyEnabled(id) => format!("Cheat '{id}' is already enabled."),
            EngineError::CheatNotEnabled(id) => format!("Cheat '{id}' is not enabled."),
            EngineError::ScriptError(d) => format!("Script error: {d}"),
            EngineError::AutoAssemblerError(d) => format!("AutoAssemblerError:\n{d}"),
            EngineError::RepoNetworkError(d) => format!("Repository network error: {d}"),
            EngineError::RepoNotFound => "No trainer was found in the repository for this game.".into(),
            EngineError::RepoInvalidPackage(d) => format!("Downloaded trainer package is invalid: {d}"),
            EngineError::RepoJobNotFound => "Unknown install job id.".into(),
            EngineError::RepoRateLimited => "GitHub API rate limit exceeded; set DECKFORGE_REPO_TOKEN or retry later.".into(),
            EngineError::RepoIoError(d) => format!("Repository filesystem error: {d}"),
        }
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for EngineError {}

pub type EngineResult<T> = Result<T, EngineError>;
