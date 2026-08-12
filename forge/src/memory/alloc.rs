//! Remote memory allocation in the attached process (Linux).
//!
//! There is no `process_vm_alloc`; allocating memory in another process
//! requires executing a syscall *inside* it. We do that with ptrace syscall
//! injection:
//!
//! ```text
//! PTRACE_ATTACH (all threads) ── save victim regs + pick stub page
//!      ── write `syscall; int3` stub ── set mmap/munmap args
//!      ── PTRACE_CONT ── SIGTRAP at int3 ── read result from RAX
//!      ── restore bytes + regs ── PTRACE_DETACH (all threads)
//! ```
//!
//! Two details are critical under Proton/Wine:
//!
//! * The stub is *not* blindly written at the victim thread's current RIP.
//!   Wine maps PE image sections as read-only **shared** file mappings, and
//!   the kernel refuses FOLL_FORCE writes (`/proc/<pid>/mem`, ptrace
//!   `POKEDATA`) to shared read-only pages. A parked game thread usually
//!   sits in PE code, so the stub site is chosen from the maps instead: the
//!   RIP page only when it is private+executable (native ELF code),
//!   otherwise any private executable page (e.g. an ELF `.so` text page).
//!
//! * All threads are attached (stopped) during injection so no other thread
//!   can execute the borrowed stub page while it contains our stub.
//!
//! This needs the same ptrace privileges the engine already requires for
//! `process_vm_readv/writev`. Both x86_64 and 32-bit-compat (i386 ABI via
//! `int 0x80`) targets are supported; the ABI is detected from the process's
//! own ELF (`/proc/<pid>/exe`). On non-Linux platforms these are stubs
//! returning a structured error.

use crate::error::{EngineError, EngineResult};
use crate::memory::MemoryRegion;

/// Largest single allocation a script may request (CE's typical newmem is
/// 1 KiB–1 MiB; this is a generous ceiling).
pub const MAX_ALLOC_SIZE: usize = 16 * 1024 * 1024;

/// Allocate `size` bytes of RWX memory in process `pid`, preferably within
/// ±2 GiB of `near` so rel32 jumps/calls reach it.
#[cfg(target_os = "linux")]
pub fn remote_alloc(
    pid: i32,
    size: usize,
    near: Option<usize>,
    maps: &[MemoryRegion],
) -> EngineResult<usize> {
    imp::remote_alloc(pid, size, near, maps)
}

/// Free a region previously returned by [`remote_alloc`].
#[cfg(target_os = "linux")]
pub fn remote_dealloc(
    pid: i32,
    addr: usize,
    size: usize,
    maps: &[MemoryRegion],
) -> EngineResult<()> {
    imp::remote_dealloc(pid, addr, size, maps)
}

#[cfg(not(target_os = "linux"))]
pub fn remote_alloc(
    _pid: i32,
    _size: usize,
    _near: Option<usize>,
    _maps: &[MemoryRegion],
) -> EngineResult<usize> {
    Err(EngineError::InvalidRequest(
        "remote memory allocation is only supported on Linux".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn remote_dealloc(
    _pid: i32,
    _addr: usize,
    _size: usize,
    _maps: &[MemoryRegion],
) -> EngineResult<()> {
    Err(EngineError::InvalidRequest(
        "remote memory deallocation is only supported on Linux".into(),
    ))
}

#[cfg(target_os = "linux")]
pub(crate) mod imp {
    use super::*;
    use libc::{c_void, pid_t, user_regs_struct};
    use std::mem::MaybeUninit;

    const PROT_RWX: u64 = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
    const MAP_PRIV_ANON: u64 = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
    const MAP_FIXED_NOREPLACE: u64 = 0x100000;
    const PAGE: usize = 0x1000;
    /// CE allocates within rel32 reach of the injection point.
    const NEAR_WINDOW: u64 = 0x8000_0000; // ±2 GiB
    /// `syscall; int3` / `int 0x80; int3` are both 3 bytes.
    const STUB_LEN: usize = 3;
    /// Safety valve for the signal pass-through loop while waiting for int3.
    const MAX_CONT_RETRIES: usize = 32;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Abi {
        X86_64,
        I386,
    }

    /// Detect the *Linux process* ABI from `/proc/<pid>/exe`'s ELF header
    /// (e_machine: 0x3E = x86-64, 0x03 = i386). Defaults to x86_64.
    pub(crate) fn detect_abi(pid: i32) -> Abi {
        let path = format!("/proc/{pid}/exe");
        if let Ok(hdr) = std::fs::read(&path) {
            if hdr.len() >= 20 && hdr[0..4] == [0x7F, b'E', b'L', b'F'] {
                let machine = u16::from_le_bytes([hdr[18], hdr[19]]);
                if machine == 0x03 {
                    return Abi::I386;
                }
            }
        }
        Abi::X86_64
    }

    /// Error-encoded syscall results are -4095..=-1 (unsigned huge values).
    pub(crate) fn is_errno(ret: u64) -> bool {
        ret >= (-4095i64) as u64
    }

    /// All thread ids of `pid` (`/proc/<pid>/task/*`), leader first.
    fn list_threads(pid: i32) -> Vec<i32> {
        let mut tids = vec![pid];
        if let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/task")) {
            for entry in rd.flatten() {
                if let Ok(tid) = entry.file_name().to_string_lossy().parse::<i32>() {
                    if !tids.contains(&tid) {
                        tids.push(tid);
                    }
                }
            }
        }
        tids
    }

    /// waitpid for a ptrace stop on `tid` (`__WALL`: tracees are not our
    /// children). Returns the raw wait status.
    fn wait_stop(tid: i32) -> EngineResult<libc::c_int> {
        let mut status: libc::c_int = 0;
        let r = unsafe { libc::waitpid(tid as pid_t, &mut status, libc::__WALL) };
        if r < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(EngineError::InvalidRequest(format!(
                "ptrace waitpid failed (errno {errno})"
            )));
        }
        if !libc::WIFSTOPPED(status) {
            return Err(EngineError::InvalidRequest(
                "tracee did not stop (exited or signaled)".into(),
            ));
        }
        Ok(status)
    }

    fn getregs(tid: i32) -> EngineResult<user_regs_struct> {
        unsafe {
            let mut regs: user_regs_struct = MaybeUninit::zeroed().assume_init();
            if libc::ptrace(
                libc::PTRACE_GETREGS,
                tid as pid_t,
                0 as *mut c_void,
                &mut regs as *mut _ as *mut c_void,
            ) < 0
            {
                return Err(EngineError::InvalidRequest("PTRACE_GETREGS failed".into()));
            }
            Ok(regs)
        }
    }

    fn setregs(tid: i32, regs: &user_regs_struct) -> EngineResult<()> {
        unsafe {
            if libc::ptrace(
                libc::PTRACE_SETREGS,
                tid as pid_t,
                0 as *mut c_void,
                regs as *const _ as *mut c_void,
            ) < 0
            {
                return Err(EngineError::InvalidRequest("PTRACE_SETREGS failed".into()));
            }
            Ok(())
        }
    }

    /// Choose where to write the 3-byte syscall stub.
    ///
    /// The kernel only permits FOLL_FORCE writes (`/proc/<pid>/mem`) to
    /// read-only pages when the mapping is *private* (COW-capable); shared
    /// read-only mappings — Wine's PE image sections — refuse them.
    /// So: prefer the victim's current RIP when its page is
    /// private+executable (native ELF code); otherwise borrow the start of
    /// some private executable page (ELF `.so` text is always private).
    fn find_stub_site(rip: usize, maps: &[MemoryRegion]) -> Option<usize> {
        if let Some(r) = maps.iter().find(|r| r.start <= rip && rip < r.end) {
            if r.executable && r.private && rip + STUB_LEN <= r.end {
                return Some(rip);
            }
        }
        let mut candidates: Vec<&MemoryRegion> =
            maps.iter().filter(|r| r.executable && r.private).collect();
        // Prefer ELF library text (cold under Proton, always MAP_PRIVATE),
        // then other file-backed private exec pages, then anonymous ones.
        candidates.sort_by_key(|r| {
            let p = r.path.as_deref().unwrap_or("");
            if p.contains(".so") {
                0
            } else if !p.is_empty() {
                1
            } else {
                2
            }
        });
        candidates.first().map(|r| r.start)
    }

    /// Execute one syscall inside `pid`, returning its raw result.
    ///
    /// All threads are attached (stopped) for the duration so no other
    /// thread can execute the borrowed stub page. The victim thread's
    /// registers and the stub bytes are saved and restored on every path.
    pub(crate) fn remote_syscall(
        pid: i32,
        nr: u64,
        args: [u64; 6],
        abi: Abi,
        maps: &[MemoryRegion],
    ) -> EngineResult<u64> {
        unsafe {
            let mut attached: Vec<i32> = Vec::new();
            let mut leader_err: Option<i32> = None;
            for tid in list_threads(pid) {
                if libc::ptrace(
                    libc::PTRACE_ATTACH,
                    tid as pid_t,
                    0 as *mut c_void,
                    0 as *mut c_void,
                ) < 0
                {
                    let errno = *libc::__errno_location();
                    if tid == pid {
                        leader_err = Some(errno);
                    }
                    // Otherwise: thread raced an exit or is already traced —
                    // skip it.
                    continue;
                }
                attached.push(tid);
            }
            if let Some(errno) = leader_err {
                for tid in &attached {
                    libc::ptrace(
                        libc::PTRACE_DETACH,
                        *tid as pid_t,
                        0 as *mut c_void,
                        0 as *mut c_void,
                    );
                }
                return Err(EngineError::InvalidRequest(format!(
                    "ptrace attach failed (errno {errno})"
                )));
            }

            let result = (|| -> EngineResult<u64> {
                for tid in &attached {
                    wait_stop(*tid)?;
                }
                remote_syscall_inner(pid, nr, args, abi, maps)
            })();

            for tid in &attached {
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    *tid as pid_t,
                    0 as *mut c_void,
                    0 as *mut c_void,
                );
            }
            result
        }
    }

    /// SAFETY: all threads of `pid` must already be attached (stopped) by the
    /// caller; registers and stub bytes are restored before returning.
    unsafe fn remote_syscall_inner(
        pid: i32,
        nr: u64,
        args: [u64; 6],
        abi: Abi,
        maps: &[MemoryRegion],
    ) -> EngineResult<u64> {
        let saved = getregs(pid)?;
        let rip = saved.rip as usize;

        let stub: [u8; STUB_LEN] = match abi {
            Abi::X86_64 => [0x0F, 0x05, 0xCC], // syscall; int3
            Abi::I386 => [0xCD, 0x80, 0xCC],   // int 0x80; int3
        };

        // Pick the stub site from the maps; if they look stale (no viable
        // page at all), re-read them fresh and retry once.
        let stub_addr = match find_stub_site(rip, maps) {
            Some(a) => a,
            None => {
                let fresh = crate::process::procfs::read_maps_raw(pid)
                    .map(|raw| crate::memory::regions::parse_maps(&raw))
                    .unwrap_or_default();
                find_stub_site(rip, &fresh).ok_or_else(|| {
                    EngineError::InvalidRequest(
                        "no private executable page available for syscall stub".into(),
                    )
                })?
            }
        };

        let saved_bytes = crate::memory::reader::read_bytes(pid, stub_addr, STUB_LEN)?;
        if saved_bytes.len() != STUB_LEN {
            return Err(EngineError::InvalidRequest(
                "cannot read stub site in target".into(),
            ));
        }

        let result = (|| -> EngineResult<u64> {
            crate::memory::writer::write_bytes(pid, stub_addr, &stub)?;

            let mut regs = saved;
            match abi {
                Abi::X86_64 => {
                    regs.rax = nr;
                    regs.rdi = args[0];
                    regs.rsi = args[1];
                    regs.rdx = args[2];
                    regs.r10 = args[3];
                    regs.r8 = args[4];
                    regs.r9 = args[5];
                }
                Abi::I386 => {
                    regs.rax = nr;
                    regs.rbx = args[0];
                    regs.rcx = args[1];
                    regs.rdx = args[2];
                    regs.rsi = args[3];
                    regs.rdi = args[4];
                    regs.rbp = args[5];
                }
            }
            regs.rip = stub_addr as u64;
            setregs(pid, &regs)?;

            // Continue until the victim hits our int3. Other stops (pending
            // signals — Wine uses them heavily) are passed through.
            let mut pass_sig: libc::c_int = 0;
            let mut tries = 0;
            loop {
                if libc::ptrace(
                    libc::PTRACE_CONT,
                    pid as pid_t,
                    0 as *mut c_void,
                    pass_sig as *mut c_void,
                ) < 0
                {
                    return Err(EngineError::InvalidRequest("PTRACE_CONT failed".into()));
                }
                let status = wait_stop(pid)?;
                let sig = libc::WSTOPSIG(status);
                let out = getregs(pid)?;
                if sig == libc::SIGTRAP && out.rip as usize == stub_addr + STUB_LEN {
                    return Ok(out.rax);
                }
                pass_sig = sig;
                tries += 1;
                if tries > MAX_CONT_RETRIES {
                    return Err(EngineError::InvalidRequest(
                        "syscall stub was not reached (signal storm?)".into(),
                    ));
                }
            }
        })();

        // Always restore the original bytes and registers.
        let _ = crate::memory::writer::write_bytes(pid, stub_addr, &saved_bytes);
        let _ = setregs(pid, &saved);
        result
    }

    pub fn remote_alloc(
        pid: i32,
        size: usize,
        near: Option<usize>,
        maps: &[MemoryRegion],
    ) -> EngineResult<usize> {
        if size == 0 || size > MAX_ALLOC_SIZE {
            return Err(EngineError::InvalidRequest(format!(
                "invalid allocation size {size} (1..={MAX_ALLOC_SIZE})"
            )));
        }
        let size = (size + PAGE - 1) & !(PAGE - 1);
        let abi = detect_abi(pid);
        let (mmap_nr, _): (u64, u64) = match abi {
            Abi::X86_64 => (9, 11), // mmap, munmap
            Abi::I386 => (192, 91), // mmap2, munmap
        };

        // Candidate placement addresses, nearest first. Without a `near`
        // hint, let the kernel choose (addr=0, no FIXED flag).
        let candidates: Vec<Option<usize>> = match near {
            Some(n) => {
                let mut gaps = find_gaps(maps, n, size);
                gaps.push(None); // final fallback: kernel-chosen address
                gaps
            }
            None => vec![None],
        };

        let mut last_err = String::new();
        for cand in candidates {
            let (addr, flags) = match cand {
                Some(a) => (a as u64, MAP_PRIV_ANON | MAP_FIXED_NOREPLACE),
                None => (0, MAP_PRIV_ANON),
            };
            let ret = remote_syscall(
                pid,
                mmap_nr,
                [addr, size as u64, PROT_RWX, flags, (-1i64) as u64, 0],
                abi,
                maps,
            )?;
            if !is_errno(ret) && ret != 0 {
                return Ok(ret as usize);
            }
            last_err = format!("mmap failed (errno {})", errno_of(ret));
        }
        Err(EngineError::MemoryWriteFailed(format!(
            "remote allocation of {size} bytes failed: {last_err}"
        )))
    }

    fn errno_of(ret: u64) -> i64 {
        (ret as i64).wrapping_neg()
    }

    pub fn remote_dealloc(
        pid: i32,
        addr: usize,
        size: usize,
        maps: &[MemoryRegion],
    ) -> EngineResult<()> {
        let size = (size + PAGE - 1) & !(PAGE - 1);
        let abi = detect_abi(pid);
        let munmap_nr: u64 = match abi {
            Abi::X86_64 => 11,
            Abi::I386 => 91,
        };
        let ret = remote_syscall(
            pid,
            munmap_nr,
            [addr as u64, size as u64, 0, 0, 0, 0],
            abi,
            maps,
        )?;
        if is_errno(ret) {
            return Err(EngineError::MemoryWriteFailed(format!(
                "munmap(0x{addr:X}, {size}) failed (errno {})",
                errno_of(ret)
            )));
        }
        Ok(())
    }

    /// Free address gaps within ±2 GiB of `near`, page-aligned, ordered by
    /// distance from `near` (so the first successful FIXED_NOREPLACE mmap is
    /// as close as possible).
    fn find_gaps(maps: &[MemoryRegion], near: usize, size: usize) -> Vec<Option<usize>> {
        let lo = near.saturating_sub(NEAR_WINDOW as usize).max(0x10000);
        let hi = near.saturating_add(NEAR_WINDOW as usize);
        let mut regions: Vec<(usize, usize)> = maps
            .iter()
            .map(|m| (m.start.max(lo), m.end.min(hi)))
            .filter(|(s, e)| s < e)
            .collect();
        regions.sort_unstable();

        let mut gaps: Vec<usize> = Vec::new();
        let mut cursor = lo;
        for (s, e) in regions {
            if s > cursor && s - cursor >= size {
                gaps.push(cursor);
            }
            cursor = cursor.max(e);
        }
        if hi > cursor && hi - cursor >= size {
            gaps.push(cursor);
        }
        gaps.sort_by_key(|g| g.abs_diff(near));
        gaps.into_iter().map(Some).collect()
    }
}
