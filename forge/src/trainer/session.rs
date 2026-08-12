//! Trainer-session state shared by every script in one loaded trainer:
//! registered symbols, Auto Assembler allocations, and bootstrap component
//! lifecycle (lazy init + reference counting).
//!
//! ```text
//! TrainerSession
//! ├── symbols        playerInstance = 0x…   (owners: {player_instance})
//! ├── allocations    newmem = 0x…, 1024     (owners: {infinite_health})
//! └── components     player_instance: initialized, ref_count = 2
//! ```
//!
//! Ownership rules: every symbol/allocation records *who* registered it (a
//! cheat id or a component id). `unregistersymbol`/`dealloc` executed by one
//! owner only removes that owner; the entry survives while other owners
//! remain, so a shared symbol is never yanked from under another active
//! cheat. Components are initialized lazily on first `requires` use and torn
//! down when the last dependent cheat disables.

use std::collections::{HashMap, HashSet};

/// A registered symbol: an address plus the set of scripts that registered it.
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    pub address: usize,
    pub owners: HashSet<String>,
}

/// A remote allocation made by `alloc(...)` in an Auto Assembler script.
#[derive(Debug, Clone)]
pub struct AllocEntry {
    pub address: usize,
    pub size: usize,
    pub owners: HashSet<String>,
}

/// Lifecycle of one bootstrap component (a shared `.asm` script).
#[derive(Debug, Clone, Default)]
pub struct ComponentState {
    pub initialized: bool,
    /// Number of currently enabled cheats requiring this component.
    pub ref_count: u32,
}

#[derive(Debug, Default)]
pub struct TrainerSession {
    pub symbols: HashMap<String, SymbolEntry>,
    pub allocations: HashMap<String, AllocEntry>,
    pub components: HashMap<String, ComponentState>,
}

impl TrainerSession {
    pub fn new() -> Self {
        Self::default()
    }

    // --- symbols ---------------------------------------------------------

    /// `registersymbol(name)`: bind `name` to `address`, crediting `owner`.
    /// Re-registering an existing symbol updates the address (CE semantics)
    /// and adds the owner.
    pub fn register_symbol(&mut self, name: &str, address: usize, owner: &str) {
        self.symbols
            .entry(name.to_string())
            .and_modify(|e| {
                e.address = address;
                e.owners.insert(owner.to_string());
            })
            .or_insert_with(|| SymbolEntry {
                address,
                owners: HashSet::from([owner.to_string()]),
            });
    }

    /// `unregistersymbol(name)` executed by `owner`. Removes only that owner;
    /// the symbol stays registered while other owners still reference it.
    /// Returns true if the symbol was (and stayed) removed.
    pub fn unregister_symbol(&mut self, name: &str, owner: &str) -> bool {
        match self.symbols.get_mut(name) {
            None => false,
            Some(e) => {
                e.owners.remove(owner);
                if e.owners.is_empty() {
                    self.symbols.remove(name);
                    true
                } else {
                    // Still owned by another active cheat/component: keep it.
                    false
                }
            }
        }
    }

    /// Look up a symbol's address.
    pub fn symbol(&self, name: &str) -> Option<usize> {
        self.symbols.get(name).map(|e| e.address)
    }

    /// Case-insensitive symbol lookup (CE symbols are case-insensitive).
    pub fn symbol_ci(&self, name: &str) -> Option<usize> {
        if let Some(a) = self.symbol(name) {
            return Some(a);
        }
        self.symbols
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, e)| e.address)
    }

    // --- allocations -------------------------------------------------------

    /// `alloc(name, ...)`: record an allocation, crediting `owner`.
    pub fn add_allocation(&mut self, name: &str, address: usize, size: usize, owner: &str) {
        self.allocations
            .entry(name.to_string())
            .and_modify(|e| {
                e.address = address;
                e.size = size;
                e.owners.insert(owner.to_string());
            })
            .or_insert_with(|| AllocEntry {
                address,
                size,
                owners: HashSet::from([owner.to_string()]),
            });
    }

    /// `dealloc(name)` executed by `owner`. Returns `Some((address, size))`
    /// when the entry lost its last owner and the memory should actually be
    /// freed; `None` when the name is unknown or still owned by others.
    pub fn remove_allocation(&mut self, name: &str, owner: &str) -> Option<(usize, usize)> {
        let e = self.allocations.get_mut(name)?;
        e.owners.remove(owner);
        if e.owners.is_empty() {
            let e = self.allocations.remove(name)?;
            Some((e.address, e.size))
        } else {
            None
        }
    }

    /// Look up an allocation's address (used when assembling `jmp newmem`
    /// and friends, where `name` refers to allocated memory).
    pub fn allocation(&self, name: &str) -> Option<usize> {
        self.allocations.get(name).map(|e| e.address)
    }

    // --- bootstrap components ----------------------------------------------

    pub fn component_initialized(&self, id: &str) -> bool {
        self.components.get(id).is_some_and(|c| c.initialized)
    }

    pub fn mark_component_initialized(&mut self, id: &str) {
        self.components.entry(id.to_string()).or_default().initialized = true;
    }

    pub fn mark_component_deinitialized(&mut self, id: &str) {
        self.components.entry(id.to_string()).or_default().initialized = false;
    }

    /// Add one dependent cheat; returns the new ref count.
    pub fn component_add_ref(&mut self, id: &str) -> u32 {
        let c = self.components.entry(id.to_string()).or_default();
        c.ref_count += 1;
        c.ref_count
    }

    /// Remove one dependent cheat; returns the new ref count.
    pub fn component_remove_ref(&mut self, id: &str) -> u32 {
        let c = self.components.entry(id.to_string()).or_default();
        c.ref_count = c.ref_count.saturating_sub(1);
        c.ref_count
    }

    /// Drop everything (process exit / trainer reload). Bookkeeping only —
    /// memory operations are the caller's concern.
    pub fn clear(&mut self) {
        self.symbols.clear();
        self.allocations.clear();
        self.components.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbols_track_owners() {
        let mut s = TrainerSession::new();
        s.register_symbol("playerInstance", 0x1000, "player_instance");
        assert_eq!(s.symbol("playerInstance"), Some(0x1000));
        // Shared: another script registers the same symbol.
        s.register_symbol("playerInstance", 0x1000, "infinite_health");
        // One owner unregisters: symbol survives.
        assert!(!s.unregister_symbol("playerInstance", "infinite_health"));
        assert_eq!(s.symbol("playerInstance"), Some(0x1000));
        // Last owner unregisters: symbol is gone.
        assert!(s.unregister_symbol("playerInstance", "player_instance"));
        assert_eq!(s.symbol("playerInstance"), None);
        assert!(!s.unregister_symbol("playerInstance", "nobody"));
    }

    #[test]
    fn symbol_lookup_is_case_insensitive_fallback() {
        let mut s = TrainerSession::new();
        s.register_symbol("PlayerInstance", 0x42, "a");
        assert_eq!(s.symbol_ci("playerinstance"), Some(0x42));
        assert_eq!(s.symbol_ci("PLAYERINSTANCE"), Some(0x42));
    }

    #[test]
    fn allocations_are_owner_tracked() {
        let mut s = TrainerSession::new();
        s.add_allocation("newmem", 0x7000, 1024, "cheat_a");
        s.add_allocation("newmem", 0x7000, 1024, "cheat_b");
        assert_eq!(s.allocation("newmem"), Some(0x7000));
        // First dealloc: still owned by cheat_b, nothing to free.
        assert_eq!(s.remove_allocation("newmem", "cheat_a"), None);
        assert_eq!(s.allocation("newmem"), Some(0x7000));
        // Last owner: free it.
        assert_eq!(s.remove_allocation("newmem", "cheat_b"), Some((0x7000, 1024)));
        assert_eq!(s.allocation("newmem"), None);
    }

    #[test]
    fn components_are_refcounted() {
        let mut s = TrainerSession::new();
        assert!(!s.component_initialized("player_instance"));
        s.mark_component_initialized("player_instance");
        assert!(s.component_initialized("player_instance"));
        assert_eq!(s.component_add_ref("player_instance"), 1);
        assert_eq!(s.component_add_ref("player_instance"), 2);
        assert_eq!(s.component_remove_ref("player_instance"), 1);
        assert_eq!(s.component_remove_ref("player_instance"), 0);
        // Saturates at zero.
        assert_eq!(s.component_remove_ref("player_instance"), 0);
        s.mark_component_deinitialized("player_instance");
        assert!(!s.component_initialized("player_instance"));
    }
}
