//! Low-level process-memory writing via `/proc/<pid>/mem` (Linux).
//!
//! Why not `process_vm_writev`? It does not use `FOLL_FORCE`: the kernel
//! only lets it write to VMAs with `VM_WRITE`, so *any* read-only page —
//! every code page of every game, private or shared — is rejected with
//! `EFAULT`. `/proc/<pid>/mem` writes go through `access_remote_vm` with
//! `FOLL_FORCE` (the same path gdb/scanmem use), which covers read-only
//! *private* pages (COW). Read-only **shared** pages (Wine/Proton PE image
//! sections) still fail (with `EIO` from `mem_write`, or `EFAULT`) — those
//! are handled one layer up by [`crate::memory::privatize`].
//!
//! The file is opened per call; trainer writes are rare (patches, cheat
//! toggles) and freeze ticks are infrequent enough that the open cost is
//! negligible.

use crate::error::{EngineError, EngineResult};

/// Attempt the write, reporting the raw errno (positive value) on failure
/// and the number of bytes written on success. Used by
/// [`crate::memory::privatize`] to distinguish `EFAULT`/`EIO` (read-only
/// shared mapping — recoverable via page privatization) from real errors.
#[cfg(target_os = "linux")]
pub(crate) fn try_write_bytes(pid: i32, addr: usize, data: &[u8]) -> Result<usize, i32> {
    use std::os::unix::fs::FileExt;

    if data.is_empty() {
        return Ok(0);
    }
    let path = format!("/proc/{pid}/mem");
    let mem = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|e| e.raw_os_error().unwrap_or(0))?;
    mem.write_at(data, addr as u64)
        .map_err(|e| e.raw_os_error().unwrap_or(0))
}

/// Write `data` to `addr` in the remote process `pid`.
#[cfg(target_os = "linux")]
pub fn write_bytes(pid: i32, addr: usize, data: &[u8]) -> EngineResult<()> {
    match try_write_bytes(pid, addr, data) {
        Ok(n) if n < data.len() => Err(EngineError::MemoryWriteFailed(format!(
            "partial write: {} of {} bytes",
            n,
            data.len()
        ))),
        Ok(_) => Ok(()),
        Err(errno) => Err(EngineError::MemoryWriteFailed(format!(
            "/proc/{pid}/mem write failed (errno {errno})"
        ))),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn write_bytes(_pid: i32, _addr: usize, _data: &[u8]) -> EngineResult<()> {
    Err(EngineError::MemoryWriteFailed(
        "process memory access is only supported on Linux".into(),
    ))
}
