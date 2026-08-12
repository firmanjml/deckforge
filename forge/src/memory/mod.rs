//! Typed process-memory access.
//!
//! All unsafe syscall work is contained in [`reader`] and [`writer`]. The rest
//! of the engine uses [`MemoryAccess`], which exposes typed primitives and
//! returns structured [`EngineError`]s on failure — it never panics on normal
//! read/write errors.

pub mod alloc;
pub mod disasm;
pub mod ops;
pub mod privatize;
pub mod reader;
pub mod regions;
pub mod writer;

#[cfg(all(test, target_os = "linux"))]
mod live_tests;

pub use ops::{LiveMemory, MemoryOps};
pub use regions::{find_module, module_base, MemoryRegion, ModuleInfo};

use crate::error::{EngineError, EngineResult};

/// Handle to a target process's memory, keyed by pid.
#[derive(Debug, Clone, Copy)]
pub struct MemoryAccess {
    pub pid: i32,
}

impl MemoryAccess {
    pub fn new(pid: i32) -> Self {
        Self { pid }
    }

    pub fn read_bytes(&self, addr: usize, len: usize) -> EngineResult<Vec<u8>> {
        reader::read_bytes(self.pid, addr, len)
    }

    /// Write bytes into the target. Falls back to privatizing read-only
    /// *shared* pages (Wine PE image sections) when the direct write is
    /// rejected with EFAULT — without that fallback, no code patch can ever
    /// land under Proton.
    pub fn write_bytes(&self, addr: usize, data: &[u8]) -> EngineResult<()> {
        privatize::write_bytes(self.pid, addr, data)
    }

    // --- integer reads ---------------------------------------------------

    pub fn read_i8(&self, addr: usize) -> EngineResult<i8> {
        Ok(self.read_array::<1>(addr)?[0] as i8)
    }
    pub fn read_u8(&self, addr: usize) -> EngineResult<u8> {
        Ok(self.read_array::<1>(addr)?[0])
    }
    pub fn read_i16(&self, addr: usize) -> EngineResult<i16> {
        Ok(i16::from_ne_bytes(self.read_array::<2>(addr)?))
    }
    pub fn read_u16(&self, addr: usize) -> EngineResult<u16> {
        Ok(u16::from_ne_bytes(self.read_array::<2>(addr)?))
    }
    pub fn read_i32(&self, addr: usize) -> EngineResult<i32> {
        Ok(i32::from_ne_bytes(self.read_array::<4>(addr)?))
    }
    pub fn read_u32(&self, addr: usize) -> EngineResult<u32> {
        Ok(u32::from_ne_bytes(self.read_array::<4>(addr)?))
    }
    pub fn read_i64(&self, addr: usize) -> EngineResult<i64> {
        Ok(i64::from_ne_bytes(self.read_array::<8>(addr)?))
    }
    pub fn read_u64(&self, addr: usize) -> EngineResult<u64> {
        Ok(u64::from_ne_bytes(self.read_array::<8>(addr)?))
    }

    // --- float reads -----------------------------------------------------

    pub fn read_f32(&self, addr: usize) -> EngineResult<f32> {
        Ok(f32::from_ne_bytes(self.read_array::<4>(addr)?))
    }
    pub fn read_f64(&self, addr: usize) -> EngineResult<f64> {
        Ok(f64::from_ne_bytes(self.read_array::<8>(addr)?))
    }

    // --- integer writes --------------------------------------------------

    pub fn write_i8(&self, addr: usize, v: i8) -> EngineResult<()> {
        self.write_bytes(addr, &[v as u8])
    }
    pub fn write_u8(&self, addr: usize, v: u8) -> EngineResult<()> {
        self.write_bytes(addr, &[v])
    }
    pub fn write_i16(&self, addr: usize, v: i16) -> EngineResult<()> {
        self.write_bytes(addr, &v.to_ne_bytes())
    }
    pub fn write_u16(&self, addr: usize, v: u16) -> EngineResult<()> {
        self.write_bytes(addr, &v.to_ne_bytes())
    }
    pub fn write_i32(&self, addr: usize, v: i32) -> EngineResult<()> {
        self.write_bytes(addr, &v.to_ne_bytes())
    }
    pub fn write_u32(&self, addr: usize, v: u32) -> EngineResult<()> {
        self.write_bytes(addr, &v.to_ne_bytes())
    }
    pub fn write_i64(&self, addr: usize, v: i64) -> EngineResult<()> {
        self.write_bytes(addr, &v.to_ne_bytes())
    }
    pub fn write_u64(&self, addr: usize, v: u64) -> EngineResult<()> {
        self.write_bytes(addr, &v.to_ne_bytes())
    }

    // --- float writes ----------------------------------------------------

    pub fn write_f32(&self, addr: usize, v: f32) -> EngineResult<()> {
        self.write_bytes(addr, &v.to_ne_bytes())
    }
    pub fn write_f64(&self, addr: usize, v: f64) -> EngineResult<()> {
        self.write_bytes(addr, &v.to_ne_bytes())
    }

    fn read_array<const N: usize>(&self, addr: usize) -> EngineResult<[u8; N]> {
        let buf = self.read_bytes(addr, N)?;
        if buf.len() != N {
            return Err(EngineError::MemoryReadFailed(format!(
                "short read: got {} bytes, need {N}",
                buf.len()
            )));
        }
        buf.try_into()
            .map_err(|_| EngineError::MemoryReadFailed("array conversion failed".into()))
    }
}
