//! Reversible byte-patch runtime.
//!
//! Enable: resolve target → read current bytes → verify against `expected` →
//! store originals → write `enabled` bytes → mark enabled.
//! Disable: restore stored originals → mark disabled.
//!
//! A patch is never marked enabled unless the write succeeds, and is never
//! applied when the expected bytes do not match.

use crate::error::{EngineError, EngineResult};
use crate::memory::MemoryAccess;

/// Per-patch runtime state (owned by Forge, never by React/Python).
#[derive(Debug, Default)]
pub struct PatchRuntime {
    pub enabled: bool,
    pub resolved_address: Option<usize>,
    pub original_bytes: Option<Vec<u8>>,
}

impl PatchRuntime {
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Apply a patch at `addr`. `expected` is verified before writing; the
    /// current bytes (which equal `expected`) are saved for restoration.
    pub fn enable(
        &mut self,
        mem: &MemoryAccess,
        cheat_id: &str,
        addr: usize,
        expected: &[u8],
        enabled_bytes: &[u8],
    ) -> EngineResult<()> {
        if self.enabled {
            return Err(EngineError::CheatAlreadyEnabled(cheat_id.to_string()));
        }
        let current = mem.read_bytes(addr, expected.len())?;
        if current != expected {
            return Err(EngineError::ExpectedBytesMismatch);
        }
        // Write first; only record state once the write is confirmed.
        mem.write_bytes(addr, enabled_bytes)?;
        self.original_bytes = Some(current);
        self.resolved_address = Some(addr);
        self.enabled = true;
        Ok(())
    }

    /// Restore the original bytes saved at enable time.
    pub fn disable(&mut self, mem: &MemoryAccess, cheat_id: &str) -> EngineResult<()> {
        if !self.enabled {
            return Err(EngineError::CheatNotEnabled(cheat_id.to_string()));
        }
        let addr = self
            .resolved_address
            .ok_or_else(|| EngineError::CheatNotEnabled(cheat_id.to_string()))?;
        let orig = self
            .original_bytes
            .take()
            .ok_or_else(|| EngineError::CheatNotEnabled(cheat_id.to_string()))?;
        mem.write_bytes(addr, &orig)?;
        self.enabled = false;
        self.resolved_address = None;
        Ok(())
    }

    /// Reset state without touching memory (used on process exit / detach).
    pub fn reset(&mut self) {
        self.enabled = false;
        self.resolved_address = None;
        self.original_bytes = None;
    }
}
