//! Live end-to-end tests for remote syscall injection and the shared-page
//! write fallback. They spawn real child processes and use ptrace/process_vm
//! against them (the same privileges the engine needs on the Deck).
//!
//! Ignored by default; run explicitly with:
//!
//! ```text
//! cargo test memory::live_tests -- --ignored --nocapture
//! ```

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::alloc::{remote_alloc, remote_dealloc};
use super::regions::parse_maps;
use super::MemoryAccess;
use crate::process::procfs::read_maps_raw;

/// Spawn `sleep` as a live injection victim.
fn spawn_sleep() -> Child {
    Command::new("/bin/sleep")
        .arg("60")
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn sleep")
}

fn maps_of(pid: i32) -> Vec<super::MemoryRegion> {
    parse_maps(&read_maps_raw(pid).expect("read maps"))
}

/// Exercises the full ptrace syscall-injection path (attach all threads,
/// pick a private executable stub page, run mmap/munmap inside the target).
#[test]
#[ignore = "needs ptrace privileges; run explicitly"]
fn live_remote_alloc_roundtrip() {
    let mut child = spawn_sleep();
    let pid = child.id() as i32;
    let maps = maps_of(pid);

    let addr = remote_alloc(pid, 0x1234, None, &maps).expect("remote_alloc");
    assert!(addr >= 0x1000, "suspicious alloc address 0x{addr:X}");

    // The fresh RWX page is writable via the fast path.
    let mem = MemoryAccess::new(pid);
    mem.write_bytes(addr, &[0xAA, 0xBB, 0xCC, 0xDD])
        .expect("write");
    assert_eq!(
        mem.read_bytes(addr, 4).expect("read"),
        vec![0xAA, 0xBB, 0xCC, 0xDD]
    );

    remote_dealloc(pid, addr, 0x1234, &maps).expect("remote_dealloc");
    child.kill().ok();
    child.wait().ok();
}

/// The regression test for the Proton EFAULT bug: writing to a read-only
/// **shared** file mapping (exactly how Wine maps PE image sections) must
/// succeed via page privatization — and must NOT dirty the file on disk.
#[test]
#[ignore = "needs ptrace privileges; run explicitly"]
fn live_write_to_shared_readonly_page() {
    // Child mode: create a shared read-only file mapping and publish its
    // address, then sleep.
    if let Ok(path) = std::env::var("DF_CHILD_MAP_FILE") {
        let file_path = std::env::var("DF_CHILD_FILE").unwrap();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .open(&file_path)
            .unwrap();
        use std::os::unix::io::AsRawFd;
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                0x1000,
                libc::PROT_READ,
                libc::MAP_SHARED,
                f.as_raw_fd(),
                0,
            )
        };
        assert_ne!(addr, libc::MAP_FAILED);
        std::fs::write(&path, format!("{}", addr as usize)).unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    // Parent: set up the backing file (filled with 0x41) and spawn the
    // child helper (this same test binary).
    let dir = std::env::temp_dir();
    let file_path = dir.join(format!("df_shared_{}.bin", std::process::id()));
    let addr_file = dir.join(format!("df_shared_{}.addr", std::process::id()));
    std::fs::write(&file_path, vec![0x41u8; 0x1000]).unwrap();

    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .arg("memory::live_tests::live_write_to_shared_readonly_page")
        .arg("--exact")
        .arg("--nocapture")
        .arg("--ignored")
        .env("DF_CHILD_MAP_FILE", &addr_file)
        .env("DF_CHILD_FILE", &file_path)
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn child helper");
    let pid = child.id() as i32;

    // Wait for the child to publish the mapping address.
    let deadline = Instant::now() + Duration::from_secs(10);
    let addr: usize = loop {
        if let Ok(s) = std::fs::read_to_string(&addr_file) {
            if let Ok(a) = s.trim().parse() {
                break a;
            }
        }
        assert!(Instant::now() < deadline, "child never published address");
        std::thread::sleep(Duration::from_millis(50));
    };

    // Sanity: the mapping really is shared + read-only in the child's maps.
    let maps = maps_of(pid);
    let region = maps
        .iter()
        .find(|r| r.start <= addr && addr < r.end)
        .expect("mapping in child maps");
    assert!(!region.private, "mapping must be shared for this test");
    assert!(!region.writable, "mapping must be read-only for this test");

    // The write that used to die with EFAULT under Proton.
    let mem = MemoryAccess::new(pid);
    mem.write_bytes(addr + 0x10, &[0x42, 0x43, 0x44, 0x45])
        .expect("write via privatize fallback");

    // Bytes landed in the child's address space.
    let got = mem.read_bytes(addr + 0x10, 4).expect("read back");
    assert_eq!(got, vec![0x42, 0x43, 0x44, 0x45]);
    // Neighbouring bytes preserved by the privatize-and-restore flow.
    let around = mem.read_bytes(addr, 0x20).expect("read page");
    assert_eq!(&around[0..0x10], &[0x41u8; 0x10]);
    assert_eq!(&around[0x14..0x20], &[0x41u8; 0x0C]);

    // The backing file on disk was NOT dirtied.
    let on_disk = std::fs::read(&file_path).unwrap();
    assert!(
        on_disk.iter().all(|&b| b == 0x41),
        "shared file was modified on disk!"
    );

    // Child survived the whole procedure.
    assert!(child.try_wait().unwrap().is_none(), "child died");

    child.kill().ok();
    child.wait().ok();
    std::fs::remove_file(&file_path).ok();
    std::fs::remove_file(&addr_file).ok();
}
