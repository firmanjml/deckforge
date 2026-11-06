//! Freeze manager: a single background thread that periodically re-resolves
//! and re-writes frozen values ("Infinite Health", "Infinite Ammo", ...).
//!
//! Design (per AGENTS.md): one central manager, no per-freeze threads. The
//! thread re-resolves periodically, so room transitions, save loads, and
//! title→game state changes are all handled automatically — a frozen value
//! follows the game state instead of going stale. All freezes stop when the
//! game exits or the trainer resets.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::cheats::script::ScriptEngineHandle;
use crate::error::{EngineError, EngineResult};
use crate::memory::{MemoryAccess, MemoryRegion};
use crate::process::procfs::is_alive;
use crate::resolver::{self, Resolver};

/// One frozen value: resolver + pre-encoded bytes + write interval.
pub struct FreezeEntry {
    pub resolver: Resolver,
    pub bytes: Vec<u8>,
    pub interval_ms: u64,
    /// Save the value found at the address before freezing it.
    pub restore_on_disable: bool,
}

/// A value from before a freeze overwrote it.
pub struct SavedValue {
    pub addr: usize,
    pub bytes: Vec<u8>,
}

struct Shared {
    entries: HashMap<String, FreezeEntry>,
    saved: HashMap<String, SavedValue>,
    pid: Option<i32>,
    module: String,
    scripts: Option<ScriptEngineHandle>,
}

pub struct FreezeManager {
    shared: Arc<Mutex<Shared>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl FreezeManager {
    pub fn new(module: &str) -> Self {
        let shared = Arc::new(Mutex::new(Shared {
            entries: HashMap::new(),
            saved: HashMap::new(),
            pid: None,
            module: module.to_string(),
            scripts: None,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let th_shared = Arc::clone(&shared);
        let th_stop = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name("freeze-manager".into())
            .spawn(move || freeze_loop(th_shared, th_stop))
            .expect("failed to spawn freeze manager thread");
        Self {
            shared,
            stop,
            handle: Some(handle),
        }
    }

    /// The trainer's shared script engine, used when a frozen cheat has a
    /// `"type": "script"` resolver.
    pub fn set_script_engine(&self, scripts: ScriptEngineHandle) {
        self.shared.lock().unwrap().scripts = Some(scripts);
    }

    pub fn set_pid(&self, pid: i32) {
        self.shared.lock().unwrap().pid = Some(pid);
    }

    pub fn add(&self, id: &str, entry: FreezeEntry) {
        let mut shared = self.shared.lock().unwrap();
        shared.saved.remove(id);
        shared.entries.insert(id.to_string(), entry);
    }

    pub fn remove(&self, id: &str) -> bool {
        self.shared.lock().unwrap().entries.remove(id).is_some()
    }

    /// The value saved for a removed entry. No more can be saved after `remove`,
    /// and the loop checks for the entry under the same lock as its writes, so a
    /// restore cannot be overwritten by a write already in progress.
    pub fn take_saved(&self, id: &str) -> Option<SavedValue> {
        self.shared.lock().unwrap().saved.remove(id)
    }

    pub fn contains(&self, id: &str) -> bool {
        self.shared.lock().unwrap().entries.contains_key(id)
    }

    pub fn clear(&self) {
        let mut shared = self.shared.lock().unwrap();
        shared.entries.clear();
        shared.saved.clear();
    }

    fn stop_thread(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for FreezeManager {
    fn drop(&mut self) {
        self.stop_thread();
    }
}

/// Tick rate of the loop; per-entry intervals are honored on top of this.
const TICK: Duration = Duration::from_millis(25);
/// Maps are re-read this often (the game keeps allocating as it runs).
const MAPS_REFRESH: Duration = Duration::from_secs(1);
/// Frozen addresses are refreshed periodically so dynamic game state can move
/// without making expensive script resolvers run for every write tick. Signature
/// addresses are exempt; see [`needs_resolve`].
const ADDRESS_REFRESH: Duration = Duration::from_secs(1);
/// A failed cheat resets the script VM so script resolvers re-discover against
/// the current game state, for example once a player exists. Discovery can be
/// expensive and a failure can last a long time, so this is rate limited.
const REINIT_COOLDOWN: Duration = Duration::from_secs(30);

struct ResolvedFreeze {
    addr: usize,
    pid: i32,
    resolved_at: Instant,
}

/// Does a freeze that is due for a write have to resolve its address first?
///
/// Signature resolvers scan the whole module and code does not move while a
/// process lives, so their address is kept for as long as that process is the
/// target. A failed write drops `last`, which forces a new scan. Pointer and
/// script addresses follow game state, so every other resolver refreshes.
fn needs_resolve(
    resolver: &Resolver,
    last: Option<&ResolvedFreeze>,
    pid: i32,
    now: Instant,
) -> bool {
    let Some(last) = last else {
        return true;
    };
    if last.pid != pid {
        return true;
    }
    !matches!(resolver, Resolver::Signature { .. })
        && now.duration_since(last.resolved_at) >= ADDRESS_REFRESH
}

fn freeze_loop(shared: Arc<Mutex<Shared>>, stop: Arc<AtomicBool>) {
    let mut maps: Vec<MemoryRegion> = Vec::new();
    let mut last_maps = Instant::now() - MAPS_REFRESH;
    let mut last_write: HashMap<String, Instant> = HashMap::new();
    let mut resolved: HashMap<String, ResolvedFreeze> = HashMap::new();
    let mut failing: HashSet<String> = HashSet::new();
    let mut last_reinit: Option<Instant> = None;

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        let (pid, scripts, items) = {
            let s = shared.lock().unwrap();
            let items: Vec<(String, Resolver, Vec<u8>, u64, bool)> = s
                .entries
                .iter()
                .map(|(id, e)| {
                    (
                        id.clone(),
                        e.resolver.clone(),
                        e.bytes.clone(),
                        e.interval_ms,
                        e.restore_on_disable,
                    )
                })
                .collect();
            (s.pid, s.scripts.clone(), items)
        };

        let (Some(pid), Some(scripts)) = (pid, scripts) else {
            std::thread::sleep(TICK);
            continue;
        };
        if items.is_empty() || !is_alive(pid) {
            resolved.clear();
            std::thread::sleep(TICK);
            continue;
        }

        resolved.retain(|id, _| items.iter().any(|(item_id, ..)| item_id == id));
        failing.retain(|id| items.iter().any(|(item_id, ..)| item_id == id));

        if last_maps.elapsed() >= MAPS_REFRESH {
            if let Ok(m) = crate::process::modules::read_modules(pid) {
                maps = m;
            }
            last_maps = Instant::now();
        }

        let mem = MemoryAccess::new(pid);
        let now = Instant::now();
        for (id, res, bytes, interval_ms, restore) in items {
            let due = last_write
                .get(&id)
                .is_none_or(|t| now.duration_since(*t).as_millis() as u64 >= interval_ms.max(20));
            if !due {
                continue;
            }
            if needs_resolve(&res, resolved.get(&id), pid, now) {
                match resolver::resolve(&res, &mem, &maps, &scripts) {
                    Ok(addr) => {
                        resolved.insert(
                            id.clone(),
                            ResolvedFreeze {
                                addr,
                                pid,
                                resolved_at: now,
                            },
                        );
                    }
                    Err(e) => {
                        resolved.remove(&id);
                        if failing.insert(id.clone()) {
                            eprintln!(
                                "[forge] freeze '{id}': resolve failed ({e}); will keep retrying"
                            );
                        }
                        if reinit_due(last_reinit, now) {
                            last_reinit = Some(now);
                            scripts.lock().unwrap().reset();
                        }
                        last_write.insert(id, now + ADDRESS_REFRESH);
                        continue;
                    }
                }
            }

            let Some(addr) = resolved.get(&id).map(|entry| entry.addr) else {
                continue;
            };
            let written = {
                let mut s = shared.lock().unwrap();
                if !s.entries.contains_key(&id) {
                    continue; // disabled since this pass began
                }
                write_frozen(&mut s.saved, &mem, &id, addr, &bytes, restore)
            };
            match written {
                Ok(()) => {
                    failing.remove(&id);
                    last_write.insert(id, now);
                }
                Err(e) => {
                    resolved.remove(&id);
                    if failing.insert(id.clone()) {
                        eprintln!("[forge] freeze '{id}': write failed ({e}); will re-resolve");
                    }
                    if reinit_due(last_reinit, now) {
                        last_reinit = Some(now);
                        scripts.lock().unwrap().reset();
                    }
                    last_write.insert(id, now + ADDRESS_REFRESH);
                }
            }
        }

        std::thread::sleep(TICK);
    }
}

/// Write a frozen value, first saving what it replaces when the cheat restores
/// on disable. A new address is saved again, because the old value did not move
/// with the game's data.
fn write_frozen(
    saved: &mut HashMap<String, SavedValue>,
    mem: &MemoryAccess,
    id: &str,
    addr: usize,
    bytes: &[u8],
    restore: bool,
) -> EngineResult<()> {
    if restore && saved.get(id).is_none_or(|value| value.addr != addr) {
        let original = mem.read_bytes(addr, bytes.len())?;
        if original.len() != bytes.len() {
            return Err(EngineError::MemoryReadFailed(format!(
                "short read of frozen value at 0x{addr:x}"
            )));
        }
        saved.insert(
            id.to_string(),
            SavedValue {
                addr,
                bytes: original,
            },
        );
    }
    mem.write_bytes(addr, bytes)
}

fn reinit_due(last_reinit: Option<Instant>, now: Instant) -> bool {
    last_reinit.is_none_or(|last| now.duration_since(last) >= REINIT_COOLDOWN)
}

#[cfg(test)]
mod needs_resolve_tests {
    use super::*;

    const PID: i32 = 1234;

    fn resolver(json: serde_json::Value) -> Resolver {
        serde_json::from_value(json).unwrap()
    }

    fn signature() -> Resolver {
        resolver(serde_json::json!({
            "type": "signature", "module": "game.exe", "pattern": "90 90"
        }))
    }

    fn other_resolvers() -> [Resolver; 4] {
        [
            resolver(serde_json::json!({"type": "absolute", "address": "0x1000"})),
            resolver(serde_json::json!({
                "type": "module_offset", "module": "game.exe", "offset": "0x10"
            })),
            resolver(serde_json::json!({
                "type": "pointer", "module": "game.exe", "offset": "0x10", "offsets": ["0x8"]
            })),
            resolver(serde_json::json!({"type": "script", "code": "return 1"})),
        ]
    }

    fn resolved_at(resolved_at: Instant) -> ResolvedFreeze {
        ResolvedFreeze {
            addr: 0x1000,
            pid: PID,
            resolved_at,
        }
    }

    #[test]
    fn nothing_resolved_yet_always_resolves() {
        let now = Instant::now();
        assert!(needs_resolve(&signature(), None, PID, now));
        for r in other_resolvers() {
            assert!(needs_resolve(&r, None, PID, now), "{r:?}");
        }
    }

    #[test]
    fn signature_keeps_its_address_however_old() {
        let start = Instant::now();
        let last = resolved_at(start);
        for later in [Duration::ZERO, ADDRESS_REFRESH, Duration::from_secs(3600)] {
            assert!(!needs_resolve(&signature(), Some(&last), PID, start + later));
        }
    }

    #[test]
    fn other_resolvers_refresh_on_the_existing_schedule() {
        let start = Instant::now();
        let last = resolved_at(start);
        for r in other_resolvers() {
            let early = start + ADDRESS_REFRESH - Duration::from_millis(1);
            assert!(!needs_resolve(&r, Some(&last), PID, early), "{r:?}");
            assert!(needs_resolve(&r, Some(&last), PID, start + ADDRESS_REFRESH), "{r:?}");
        }
    }

    #[test]
    fn a_new_process_invalidates_every_address() {
        let now = Instant::now();
        let last = resolved_at(now);
        assert!(needs_resolve(&signature(), Some(&last), PID + 1, now));
        for r in other_resolvers() {
            assert!(needs_resolve(&r, Some(&last), PID + 1, now), "{r:?}");
        }
    }
}

#[cfg(test)]
mod reinit_tests {
    use super::*;

    #[test]
    fn first_failure_reinitializes_then_waits_for_the_cooldown() {
        let start = Instant::now();
        assert!(reinit_due(None, start));
        assert!(!reinit_due(Some(start), start + Duration::from_secs(29)));
        assert!(reinit_due(Some(start), start + REINIT_COOLDOWN));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod live_tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    use crate::cheats::script::{new_handle, ScriptEngine};
    use crate::trainer::session::TrainerSession;

    /// Run a real freeze against this test process until it takes effect, then
    /// remove it and return what was saved.
    fn freeze_and_remove(value: &mut i32, restore: bool) -> Option<SavedValue> {
        let addr = value as *mut i32 as usize;
        let manager = FreezeManager::new("test");
        manager.set_script_engine(new_handle(ScriptEngine::new(
            "test",
            None,
            Vec::new(),
            Arc::new(StdMutex::new(TrainerSession::new())),
        )));
        manager.set_pid(std::process::id() as i32);
        let resolver: Resolver =
            serde_json::from_value(serde_json::json!({"type": "absolute", "address": addr}))
                .unwrap();
        manager.add(
            "cheat",
            FreezeEntry {
                resolver,
                bytes: 999i32.to_ne_bytes().to_vec(),
                interval_ms: 20,
                restore_on_disable: restore,
            },
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while unsafe { std::ptr::read_volatile(value) } != 999 {
            assert!(Instant::now() < deadline, "freeze never wrote the value");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(manager.remove("cheat"));
        manager.take_saved("cheat")
    }

    #[test]
    fn saves_the_value_from_before_the_freeze() {
        let mut value = Box::new(5i32);
        let addr = &*value as *const i32 as usize;
        let saved = freeze_and_remove(&mut value, true).expect("saved value");
        assert_eq!(saved.addr, addr);
        assert_eq!(saved.bytes, 5i32.to_ne_bytes());
    }

    #[test]
    fn saves_nothing_unless_asked() {
        let mut value = Box::new(5i32);
        assert!(freeze_and_remove(&mut value, false).is_none());
    }

    /// Bytes for a signature to find, in this test binary's own `.data`, followed
    /// by the frozen value. Only tests that scan for this signature touch it.
    static mut SIGNED: [u8; 12] = [0x5A, 0xC3, 0x7E, 0x19, 0xD4, 0x62, 0xB8, 0x2F, 0, 0, 0, 0];

    fn signed_value() -> *mut i32 {
        std::ptr::addr_of_mut!(SIGNED).cast::<u8>().wrapping_add(8).cast()
    }

    /// Wait for the freeze to write `SIGNED`'s value after it is set to zero.
    fn assert_rewritten_within(limit: Duration) {
        unsafe { signed_value().write_unaligned(0) };
        let deadline = Instant::now() + limit;
        while unsafe { signed_value().read_unaligned() } != 999 {
            assert!(Instant::now() < deadline, "freeze stopped writing the value");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn signature_freeze_keeps_its_address_after_the_signature_disappears() {
        let exe = std::env::current_exe().unwrap();
        let module = exe.file_name().unwrap().to_str().unwrap().to_string();
        let manager = FreezeManager::new("test");
        manager.set_script_engine(new_handle(ScriptEngine::new(
            "test",
            None,
            Vec::new(),
            Arc::new(StdMutex::new(TrainerSession::new())),
        )));
        manager.set_pid(std::process::id() as i32);
        let resolver: Resolver = serde_json::from_value(serde_json::json!({
            "type": "signature",
            "module": module,
            "pattern": "5A C3 7E 19 D4 62 B8 2F",
            "offset": 8,
        }))
        .unwrap();
        manager.add(
            "cheat",
            FreezeEntry {
                resolver,
                bytes: 999i32.to_ne_bytes().to_vec(),
                interval_ms: 20,
                restore_on_disable: false,
            },
        );
        assert_rewritten_within(Duration::from_secs(5));

        // A rescan would now fail, and a failed resolve stops the writes.
        unsafe { std::ptr::addr_of_mut!(SIGNED).cast::<u8>().write_volatile(0) };
        std::thread::sleep(ADDRESS_REFRESH + Duration::from_millis(300));
        assert_rewritten_within(ADDRESS_REFRESH);
        assert!(manager.remove("cheat"));
    }
}
