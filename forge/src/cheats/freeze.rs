//! Freeze manager: a single background thread that periodically re-resolves
//! and re-writes frozen values ("Infinite Health", "Infinite Ammo", ...).
//!
//! Design (per AGENTS.md): one central manager, no per-freeze threads. The
//! thread re-resolves every tick, so room transitions, save loads, and
//! title→game state changes are all handled automatically — a frozen value
//! follows the game state instead of going stale. All freezes stop when the
//! game exits or the trainer resets.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::cheats::script::ScriptEngineHandle;
use crate::memory::{MemoryAccess, MemoryRegion};
use crate::process::procfs::is_alive;
use crate::resolver::{self, Resolver};

/// One frozen value: resolver + pre-encoded bytes + write interval.
pub struct FreezeEntry {
    pub resolver: Resolver,
    pub bytes: Vec<u8>,
    pub interval_ms: u64,
}

struct Shared {
    entries: HashMap<String, FreezeEntry>,
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
        self.shared
            .lock()
            .unwrap()
            .entries
            .insert(id.to_string(), entry);
    }

    pub fn remove(&self, id: &str) -> bool {
        self.shared.lock().unwrap().entries.remove(id).is_some()
    }

    pub fn contains(&self, id: &str) -> bool {
        self.shared.lock().unwrap().entries.contains_key(id)
    }

    pub fn clear(&self) {
        self.shared.lock().unwrap().entries.clear();
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
/// without making expensive script resolvers run for every write tick.
const ADDRESS_REFRESH: Duration = Duration::from_secs(1);
/// A failed cheat resets the script VM so script resolvers re-discover against
/// the current game state, for example once a player exists. Discovery can be
/// expensive and a failure can last a long time, so this is rate limited.
const REINIT_COOLDOWN: Duration = Duration::from_secs(30);

struct ResolvedFreeze {
    addr: usize,
    resolved_at: Instant,
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
            let items: Vec<(String, Resolver, Vec<u8>, u64)> = s
                .entries
                .iter()
                .map(|(id, e)| {
                    (
                        id.clone(),
                        e.resolver.clone(),
                        e.bytes.clone(),
                        e.interval_ms,
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

        resolved.retain(|id, _| items.iter().any(|(item_id, _, _, _)| item_id == id));
        failing.retain(|id| items.iter().any(|(item_id, _, _, _)| item_id == id));

        if last_maps.elapsed() >= MAPS_REFRESH {
            if let Ok(m) = crate::process::modules::read_modules(pid) {
                maps = m;
            }
            last_maps = Instant::now();
        }

        let mem = MemoryAccess::new(pid);
        let now = Instant::now();
        for (id, res, bytes, interval_ms) in items {
            let due = last_write
                .get(&id)
                .is_none_or(|t| now.duration_since(*t).as_millis() as u64 >= interval_ms.max(20));
            if !due {
                continue;
            }
            let needs_resolve = resolved
                .get(&id)
                .is_none_or(|entry| now.duration_since(entry.resolved_at) >= ADDRESS_REFRESH);

            if needs_resolve {
                match resolver::resolve(&res, &mem, &maps, &scripts) {
                    Ok(addr) => {
                        resolved.insert(
                            id.clone(),
                            ResolvedFreeze {
                                addr,
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
            match mem.write_bytes(addr, &bytes) {
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

fn reinit_due(last_reinit: Option<Instant>, now: Instant) -> bool {
    last_reinit.is_none_or(|last| now.duration_since(last) >= REINIT_COOLDOWN)
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
