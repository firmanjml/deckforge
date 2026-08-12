//! Write fallback for read-only **shared** mappings (Wine/Proton PE image
//! pages).
//!
//! Linux permits FOLL_FORCE writes (`/proc/<pid>/mem`, ptrace `POKEDATA`)
//! to read-only pages only when the mapping is *private* (COW-capable).
//! Wine maps PE image sections as read-only **shared** file mappings, so
//! remote writes to a Proton game's code pages fail (`EIO`/`EFAULT`) — even
//! though the same patch works on Windows, where image sections are
//! copy-on-write per process. (In-process writes work under Wine because
//! Wine's write-watch SIGSEGV handler makes a private copy of the page;
//! remote writes bypass the fault handler entirely.)
//!
//! The fallback replicates Wine's COW from the outside, per affected page:
//!
//! ```text
//! read full page contents           (reads work fine on shared pages)
//! mmap  anonymous scratch page      (remote syscall injection)
//! write original contents into it
//! mremap scratch over the target    (MREMAP_FIXED: atomic replacement —
//!                                    the target never sees a zeroed page,
//!                                    and all threads are frozen inside
//!                                    remote_syscall while it happens)
//! mprotect back to the original perms
//! ```
//!
//! The page is then a private anonymous copy: the write succeeds, the shared
//! page cache (and the game files on disk) is never dirtied, and later
//! writes to the page take the fast path again (private + MAYWRITE →
//! FOLL_FORCE works).

#[cfg(target_os = "linux")]
use crate::error::EngineError;
use crate::error::EngineResult;

#[cfg(target_os = "linux")]
const PAGE: usize = 0x1000;

/// Write `data` to `addr` in process `pid`, privatizing shared read-only
/// pages when the direct write is rejected with `EFAULT`.
#[cfg(target_os = "linux")]
pub fn write_bytes(pid: i32, addr: usize, data: &[u8]) -> EngineResult<()> {
    use super::alloc::imp::{detect_abi, is_errno, remote_syscall, Abi};
    use super::regions::parse_maps;
    use super::writer::try_write_bytes;
    use crate::process::procfs::read_maps_raw;

    // Fast path: writable pages, or private read-only pages (FOLL_FORCE COW
    // via /proc/<pid>/mem — see writer.rs).
    match try_write_bytes(pid, addr, data) {
        Ok(n) if n == data.len() => return Ok(()),
        Ok(_) => {} // partial write: inspect the remaining pages
        // EFAULT or EIO: /proc/<pid>/mem's FOLL_FORCE failed — the signature
        // of a read-only *shared* mapping. Candidate for privatization.
        Err(libc::EFAULT) | Err(libc::EIO) => {}
        Err(errno) => {
            return Err(EngineError::MemoryWriteFailed(format!(
                "/proc/{pid}/mem write failed (errno {errno})"
            )));
        }
    }
    if data.is_empty() {
        return Ok(());
    }

    let maps = parse_maps(&read_maps_raw(pid)?);
    let abi = detect_abi(pid);
    let (mmap_nr, mremap_nr, mprotect_nr): (u64, u64, u64) = match abi {
        Abi::X86_64 => (9, 25, 10),   // mmap, mremap, mprotect
        Abi::I386 => (192, 163, 125), // mmap2, mremap, mprotect
    };
    const MAP_PRIV_ANON: u64 = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
    const PROT_RWX: u64 = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
    const MREMAP_MOVE_FIXED: u64 = 1 | 2; // MREMAP_MAYMOVE | MREMAP_FIXED

    let first_page = addr & !(PAGE - 1);
    let last_page = (addr + data.len() - 1) & !(PAGE - 1);

    let mut page = first_page;
    while page <= last_page {
        let region = maps
            .iter()
            .find(|r| r.start <= page && page < r.end)
            .ok_or_else(|| {
                EngineError::MemoryWriteFailed(format!(
                    "write to 0x{page:X} failed and the page is not mapped"
                ))
            })?;
        if !region.writable && !region.private {
            // Shared read-only page (e.g. a Wine PE image section) — make a
            // private copy the target can be patched through.
            let original = super::reader::read_bytes(pid, page, PAGE)?;
            if original.len() != PAGE {
                return Err(EngineError::MemoryWriteFailed(format!(
                    "cannot back up shared page 0x{page:X} before patching"
                )));
            }

            // 1. Scratch anonymous page (kernel-chosen address).
            let tmp = remote_syscall(
                pid,
                mmap_nr,
                [0, PAGE as u64, PROT_RWX, MAP_PRIV_ANON, (-1i64) as u64, 0],
                abi,
                &maps,
            )?;
            if is_errno(tmp) || tmp == 0 {
                return Err(EngineError::MemoryWriteFailed(format!(
                    "privatize: scratch mmap failed for page 0x{page:X}"
                )));
            }

            let result = (|| -> EngineResult<()> {
                // 2. Fill the scratch page with the original contents.
                super::writer::write_bytes(pid, tmp as usize, &original)?;
                // 3. Move the scratch mapping over the target page
                //    (replaces the shared mapping atomically).
                let moved = remote_syscall(
                    pid,
                    mremap_nr,
                    [
                        tmp,
                        PAGE as u64,
                        PAGE as u64,
                        MREMAP_MOVE_FIXED,
                        page as u64,
                        0,
                    ],
                    abi,
                    &maps,
                )?;
                if is_errno(moved) || moved as usize != page {
                    return Err(EngineError::MemoryWriteFailed(format!(
                        "privatize: mremap onto 0x{page:X} failed (ret 0x{moved:X})"
                    )));
                }
                // 4. Restore the page's original protection. The mapping is
                //    private now, so future FOLL_FORCE writes work.
                let mut prot = 0u64;
                if region.readable {
                    prot |= libc::PROT_READ as u64;
                }
                if region.writable {
                    prot |= libc::PROT_WRITE as u64;
                }
                if region.executable {
                    prot |= libc::PROT_EXEC as u64;
                }
                let mp = remote_syscall(
                    pid,
                    mprotect_nr,
                    [page as u64, PAGE as u64, prot, 0, 0, 0],
                    abi,
                    &maps,
                )?;
                if is_errno(mp) {
                    return Err(EngineError::MemoryWriteFailed(format!(
                        "privatize: mprotect(0x{page:X}) failed (ret 0x{mp:X})"
                    )));
                }
                Ok(())
            })();

            if result.is_err() {
                // Best effort: drop the scratch page so it doesn't leak.
                let _ = remote_syscall(
                    pid,
                    match abi {
                        Abi::X86_64 => 11,
                        Abi::I386 => 91,
                    },
                    [tmp, PAGE as u64, 0, 0, 0, 0],
                    abi,
                    &maps,
                );
                result?;
            }
        }
        page += PAGE;
    }

    // Retry: target pages are now private, so FOLL_FORCE covers r-x ones.
    match try_write_bytes(pid, addr, data) {
        Ok(n) if n == data.len() => Ok(()),
        Ok(n) => Err(EngineError::MemoryWriteFailed(format!(
            "partial write: {} of {} bytes",
            n,
            data.len()
        ))),
        Err(errno) => Err(EngineError::MemoryWriteFailed(format!(
            "/proc/{pid}/mem write failed (errno {errno}) even after privatizing shared pages"
        ))),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn write_bytes(pid: i32, addr: usize, data: &[u8]) -> EngineResult<()> {
    super::writer::write_bytes(pid, addr, data)
}
