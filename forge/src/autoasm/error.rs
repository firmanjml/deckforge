//! Auto Assembler errors with full execution context.
//!
//! Every failure identifies the trainer, cheat/component, script file,
//! section (ENABLE/DISABLE), line number, the failing command, and the
//! underlying cause — so a ported CE table tells the author exactly which
//! line needs attention.

use std::fmt;

use crate::error::EngineError;

/// Which section of a script is executing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Enable,
    Disable,
}

impl Section {
    pub fn label(self) -> &'static str {
        match self {
            Section::Enable => "ENABLE",
            Section::Disable => "DISABLE",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AaError {
    pub trainer: String,
    /// Cheat id or bootstrap component id.
    pub owner: String,
    /// Script file (package-relative) the failing line came from.
    pub script: String,
    pub section: Section,
    pub line: u32,
    /// The failing command/source line (trimmed).
    pub command: String,
    /// Underlying cause.
    pub cause: String,
}

impl AaError {
    /// Format with the context the error was raised with.
    pub fn render(&self) -> String {
        format!(
            "trainer: {}\ncheat: {}\nscript: {}\nsection: {}\nline: {}\n\n{}\n\n{}",
            self.trainer,
            self.owner,
            self.script,
            self.section.label(),
            self.line,
            self.command,
            self.cause
        )
    }

    pub fn into_engine_error(self) -> EngineError {
        EngineError::AutoAssemblerError(self.render())
    }
}

impl fmt::Display for AaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AutoAssemblerError:\n{}", self.render())
    }
}

impl std::error::Error for AaError {}

pub type AaResult<T> = Result<T, AaError>;

/// Context carried by the executor to construct [`AaError`]s.
#[derive(Debug, Clone)]
pub struct ErrorCtx {
    pub trainer: String,
    pub owner: String,
    pub script: String,
    pub section: Section,
}

impl ErrorCtx {
    pub fn err(&self, line: u32, command: &str, cause: impl Into<String>) -> AaError {
        AaError {
            trainer: self.trainer.clone(),
            owner: self.owner.clone(),
            script: self.script.clone(),
            section: self.section,
            line,
            command: command.trim().to_string(),
            cause: cause.into(),
        }
    }
}
