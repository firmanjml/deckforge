//! Low-level process-memory reading via `process_vm_readv` (Linux).
//!
//! Unsafe syscall use is contained here. The rest of the engine talks to
//! [`crate::memory::MemoryAccess`] and never touches raw syscalls.

use crate::error::{EngineError, EngineResult};

/// Read `len` bytes from `addr` in the remote process `pid`.
#[cfg(target_os = "linux")]
pub fn read_bytes(pid: i32, addr: usize, len: usize) -> EngineResult<Vec<u8>> {
    use libc::{c_void, iovec, process_vm_readv};

    if len == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0u8; len];
    let local = iovec {
        iov_base: buf.as_mut_ptr() as *mut c_void,
        iov_len: len,
    };
    let remote = iovec {
        iov_base: addr as *mut c_void,
        iov_len: len,
    };

    // SAFETY: `process_vm_readv` reads from another process's virtual memory
    // into our owned buffer. The local iovec points at `buf` (valid for `len`),
    // the remote iovec points at `addr`. We check the return value below.
    let n = unsafe { process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(EngineError::MemoryReadFailed(format!(
            "process_vm_readv failed (errno {errno})"
        )));
    }
    let n = n as usize;
    if n < len {
        buf.truncate(n);
    }
    Ok(buf)
}

#[cfg(not(target_os = "linux"))]
pub fn read_bytes(_pid: i32, _addr: usize, _len: usize) -> EngineResult<Vec<u8>> {
    Err(EngineError::MemoryReadFailed(
        "process memory access is only supported on Linux".into(),
    ))
}
