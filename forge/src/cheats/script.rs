//! Inline Lua script resolvers: a persistent, sandboxed Lua 5.4 VM (`mlua`)
//! per trainer.
//!
//! A resolver of `"type": "script"` carries inline Lua `code` that must return
//! the target address:
//!
//! ```json
//! { "type": "script", "code": "return gm_addr('BaseGame', 'player_health')" }
//! ```
//!
//! The VM is shared by every script resolver in a trainer and persists across
//! resolves, so expensive discovery (e.g. a Cheat Engine table port) can cache
//! itself in Lua globals — the classic pattern is a trainer-level
//! `scriptSetup` chunk that defines helpers, run once when the VM boots:
//!
//! ```lua
//! if not NameList then ... full discovery ... end
//! ```
//!
//! A fresh VM is created on trainer load / process exit (`reset`), so stale
//! discovery never survives a game restart.
//!
//! Sandbox policy: only `base` (minus `load`/`dofile`), `coroutine`, `table`,
//! `string`, `math`, and `utf8` are loaded. No `os`, `io`, `package`,
//! `require`, or `debug`. All game interaction goes through the `trainer.*`
//! API below, bound to the engine's validated memory layer. `print` is
//! redirected to stderr (stdout is the JSON protocol).

use std::sync::{Arc, Mutex};

use mlua::{Lua, LuaOptions, StdLib, Value, Variadic};

use crate::error::{EngineError, EngineResult};
use crate::memory::ops::{find_bytes, scan_chunks};
use crate::memory::{MemoryAccess, MemoryRegion};

/// Largest single memory region a scan will touch.
const MAX_SCAN_REGION: usize = 64 * 1024 * 1024;
/// Result cap for scan_string / scan_pointers_to.
const MAX_SCAN_RESULTS: usize = 4096;
/// Cap for disasm_targets window.
const MAX_DISASM_BYTES: usize = 0x4000;
/// Resolves at least this slow are logged, to make slow discovery visible.
const SLOW_RESOLVE: std::time::Duration = std::time::Duration::from_millis(250);

/// Shared handle to a trainer's script engine (main thread + freeze manager).
pub type ScriptEngineHandle = Arc<Mutex<ScriptEngine>>;

/// Wrap a script engine in its shared handle.
pub fn new_handle(engine: ScriptEngine) -> ScriptEngineHandle {
    Arc::new(Mutex::new(engine))
}

// ---------------------------------------------------------------------------
// ScriptEngine
// ---------------------------------------------------------------------------

/// Per-trainer Lua state. The VM boots lazily on first resolve so a trainer
/// whose cheats are never touched costs nothing.
pub struct ScriptEngine {
    vm: Option<Vm>,
    module: String,
    setup: Option<String>,
    /// Contents of `scripts.setup` files, executed after the inline setup.
    setup_scripts: Vec<String>,
    /// Trainer-session symbols for `trainer.symbol()`.
    session: Arc<Mutex<crate::trainer::session::TrainerSession>>,
}

struct Vm {
    lua: Lua,
    ctx: SharedCtx,
}

/// Mutable context the `trainer.*` closures read: which process, what maps.
struct Ctx {
    pid: i32,
    module: String,
    /// Shared so that a Lua API call does not copy the whole memory map.
    maps: Arc<Vec<MemoryRegion>>,
    /// Pointer size of the attached process, read once from its PE header.
    pointer_size: Option<usize>,
    session: Arc<Mutex<crate::trainer::session::TrainerSession>>,
}

type SharedCtx = Arc<Mutex<Ctx>>;

impl ScriptEngine {
    pub fn new(
        module: &str,
        setup: Option<String>,
        setup_scripts: Vec<String>,
        session: Arc<Mutex<crate::trainer::session::TrainerSession>>,
    ) -> Self {
        Self {
            vm: None,
            module: module.to_string(),
            setup,
            setup_scripts,
            session,
        }
    }

    /// Drop the VM (process exit / trainer reload). The next resolve boots a
    /// fresh VM and re-runs `scriptSetup`, so no stale state survives.
    pub fn reset(&mut self) {
        self.vm = None;
    }

    /// Run inline `code` and return the address it evaluates to.
    pub fn resolve(
        &mut self,
        mem: &MemoryAccess,
        maps: &[MemoryRegion],
        code: &str,
    ) -> EngineResult<usize> {
        self.ensure_vm()?;
        let vm = self.vm.as_mut().unwrap();
        {
            let mut ctx = vm.ctx.lock().unwrap();
            if ctx.pid != mem.pid {
                ctx.pointer_size = None;
            }
            ctx.pid = mem.pid;
            ctx.maps = Arc::new(maps.to_vec());
        }
        let started = std::time::Instant::now();
        let result = vm.lua.load(code).set_name("resolver").eval::<Value>();
        let elapsed = started.elapsed();
        if elapsed >= SLOW_RESOLVE {
            eprintln!("[forge] script resolve took {} ms", elapsed.as_millis());
        }
        let v = result.map_err(|e| EngineError::ScriptError(format!("{e}")))?;
        match v {
            Value::Integer(i) if i >= 0 => Ok(i as usize),
            other => Err(EngineError::ScriptError(format!(
                "script resolver must return an address (integer), got {}",
                other.type_name()
            ))),
        }
    }

    fn ensure_vm(&mut self) -> EngineResult<()> {
        if self.vm.is_some() {
            return Ok(());
        }
        let ctx: SharedCtx = Arc::new(Mutex::new(Ctx {
            pid: 0,
            module: self.module.clone(),
            maps: Arc::new(Vec::new()),
            pointer_size: None,
            session: Arc::clone(&self.session),
        }));
        let lua = create_sandboxed_lua()
            .map_err(|e| EngineError::ScriptError(format!("failed to create Lua VM: {e}")))?;
        register_trainer_api(&lua, Arc::clone(&ctx))
            .map_err(|e| EngineError::ScriptError(format!("failed to register trainer API: {e}")))?;
        if let Some(setup) = &self.setup {
            lua.load(setup.as_str())
                .set_name("scriptSetup")
                .exec()
                .map_err(|e| EngineError::ScriptError(format!("scriptSetup failed: {e}")))?;
        }
        for (i, chunk) in self.setup_scripts.iter().enumerate() {
            lua.load(chunk.as_str())
                .set_name(format!("scripts.setup[{i}]"))
                .exec()
                .map_err(|e| {
                    EngineError::ScriptError(format!("scripts.setup[{i}] failed: {e}"))
                })?;
        }
        self.vm = Some(Vm { lua, ctx });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sandboxed VM
// ---------------------------------------------------------------------------

/// Create a Lua VM with only safe standard libraries: no `os`, `io`,
/// `package`, or `debug`. `load`/`dofile` are removed as well so scripts
/// cannot load bytecode or external files. `print` goes to stderr.
fn create_sandboxed_lua() -> mlua::Result<Lua> {
    // NOTE: the base library is always loaded by mlua; do NOT use
    // StdLib::ALL_SAFE here — it still includes `os`/`io`/`package`.
    let lua = Lua::new_with(
        StdLib::COROUTINE | StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::UTF8,
        LuaOptions::default(),
    )?;
    let globals = lua.globals();
    for dangerous in ["load", "loadstring", "dofile", "require", "print"] {
        globals.set(dangerous, Value::Nil)?;
    }
    let print = lua.create_function(|_, args: Variadic<Value>| {
        let parts: Vec<String> = args.iter().map(fmt_lua_value).collect();
        eprintln!("[script] {}", parts.join("\t"));
        Ok(())
    })?;
    globals.set("print", print)?;
    Ok(lua)
}

fn fmt_lua_value(v: &Value) -> String {
    match v {
        Value::Nil => "nil".into(),
        Value::Boolean(b) => b.to_string(),
        Value::Integer(i) => i.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.to_string_lossy(),
        other => format!("{other:?}"),
    }
}

fn to_addr(addr: i64) -> mlua::Result<usize> {
    usize::try_from(addr).map_err(|_| mlua::Error::external(format!("invalid address {addr}")))
}

fn lua_err(e: EngineError) -> mlua::Error {
    mlua::Error::external(e)
}

/// Memory accessor for the attached process.
fn memory(ctx: &SharedCtx) -> MemoryAccess {
    MemoryAccess::new(ctx.lock().unwrap().pid)
}

/// `(mem, maps)` snapshot from the shared context.
fn snapshot(ctx: &SharedCtx) -> (MemoryAccess, Arc<Vec<MemoryRegion>>) {
    let g = ctx.lock().unwrap();
    (MemoryAccess::new(g.pid), Arc::clone(&g.maps))
}

// ---------------------------------------------------------------------------
// trainer.* API
// ---------------------------------------------------------------------------

macro_rules! reg_value_api {
    ($lua:expr, $tbl:expr, $ctx:expr, $rname:literal, $wname:literal, $ty:ty, $rmethod:ident, $wmethod:ident) => {{
        let c = Arc::clone(&$ctx);
        $tbl.set(
            $rname,
            $lua.create_function(move |_, addr: i64| {
                let addr = to_addr(addr)?;
                let mem = memory(&c);
                mem.$rmethod(addr).map_err(lua_err)
            })?,
        )?;
        let c = Arc::clone(&$ctx);
        $tbl.set(
            $wname,
            $lua.create_function(move |_, (addr, v): (i64, $ty)| {
                let addr = to_addr(addr)?;
                let mem = memory(&c);
                mem.$wmethod(addr, v).map_err(lua_err)
            })?,
        )?;
        mlua::Result::Ok(())
    }};
}

/// Register the sandboxed `trainer.*` API. Everything routes through the
/// engine's validated [`MemoryAccess`] / scanning layer.
fn register_trainer_api(lua: &Lua, ctx: SharedCtx) -> mlua::Result<()> {
    let t = lua.create_table()?;

    // --- typed value reads/writes -----------------------------------------
    reg_value_api!(lua, t, ctx, "read_i8", "write_i8", i8, read_i8, write_i8)?;
    reg_value_api!(lua, t, ctx, "read_i16", "write_i16", i16, read_i16, write_i16)?;
    reg_value_api!(lua, t, ctx, "read_i32", "write_i32", i32, read_i32, write_i32)?;
    reg_value_api!(lua, t, ctx, "read_i64", "write_i64", i64, read_i64, write_i64)?;
    reg_value_api!(lua, t, ctx, "read_u8", "write_u8", u8, read_u8, write_u8)?;
    reg_value_api!(lua, t, ctx, "read_u16", "write_u16", u16, read_u16, write_u16)?;
    reg_value_api!(lua, t, ctx, "read_u32", "write_u32", u32, read_u32, write_u32)?;
    reg_value_api!(lua, t, ctx, "read_u64", "write_u64", u64, read_u64, write_u64)?;
    reg_value_api!(lua, t, ctx, "read_f32", "write_f32", f32, read_f32, write_f32)?;
    reg_value_api!(lua, t, ctx, "read_f64", "write_f64", f64, read_f64, write_f64)?;

    // --- raw bytes ----------------------------------------------------------
    {
        let c = Arc::clone(&ctx);
        t.set(
            "read_bytes",
            lua.create_function(move |lua, (addr, len): (i64, usize)| {
                let addr = to_addr(addr)?;
                let mem = memory(&c);
                let bytes = mem.read_bytes(addr, len).map_err(lua_err)?;
                lua.create_sequence_from(bytes)
            })?,
        )?;
        // Raw bytes as a Lua *string* (fast native string.find scanning).
        let c = Arc::clone(&ctx);
        t.set(
            "read_block",
            lua.create_function(move |lua, (addr, len): (i64, usize)| {
                let addr = to_addr(addr)?;
                if len > 64 * 1024 * 1024 {
                    return Err(mlua::Error::external("read_block length capped at 64 MiB"));
                }
                let mem = memory(&c);
                let bytes = mem.read_bytes(addr, len).map_err(lua_err)?;
                Ok(Value::String(lua.create_string(&bytes)?))
            })?,
        )?;
        let c = Arc::clone(&ctx);
        t.set(
            "write_bytes",
            lua.create_function(move |_, (addr, bytes): (i64, mlua::Table)| {
                let addr = to_addr(addr)?;
                let data: Vec<u8> = bytes.sequence_values::<u8>().collect::<mlua::Result<_>>()?;
                let mem = memory(&c);
                mem.write_bytes(addr, &data).map_err(lua_err)
            })?,
        )?;
    }

    // --- pointer-size helpers ------------------------------------------------
    {
        let c = Arc::clone(&ctx);
        t.set(
            "pointer_size",
            lua.create_function(move |_, ()| pointer_size(&c).map(|p| p as i64))?,
        )?;
        let c = Arc::clone(&ctx);
        t.set(
            "is64",
            lua.create_function(move |_, ()| pointer_size(&c).map(|p| p == 8))?,
        )?;
        let c = Arc::clone(&ctx);
        t.set(
            "read_pointer",
            lua.create_function(move |_, addr: i64| {
                let addr = to_addr(addr)?;
                let mem = memory(&c);
                match pointer_size(&c)? {
                    8 => mem.read_u64(addr).map(|v| v as i64).map_err(lua_err),
                    _ => mem.read_u32(addr).map(|v| v as i64).map_err(lua_err),
                }
            })?,
        )?;
    }

    // --- strings --------------------------------------------------------------
    {
        let c = Arc::clone(&ctx);
        t.set(
            "read_string",
            lua.create_function(move |lua, (addr, max_len): (i64, Option<usize>)| {
                let addr = to_addr(addr)?;
                let max = max_len.unwrap_or(128).min(4096);
                let mem = memory(&c);
                let bytes = mem.read_bytes(addr, max).map_err(lua_err)?;
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                if end == 0 {
                    return Ok(Value::Nil);
                }
                Ok(Value::String(lua.create_string(&bytes[..end])?))
            })?,
        )?;
    }

    // --- modules / regions -----------------------------------------------------
    {
        let c = Arc::clone(&ctx);
        t.set(
            "find_module",
            lua.create_function(move |lua, name: String| {
                let (_, maps) = snapshot(&c);
                match crate::memory::find_module(&maps, &name) {
                    Some(info) => {
                        let out = lua.create_table()?;
                        out.set("base", info.base as i64)?;
                        out.set("size", info.size() as i64)?;
                        out.set("name", info.name.clone())?;
                        Ok(Value::Table(out))
                    }
                    None => Ok(Value::Nil),
                }
            })?,
        )?;

        let c = Arc::clone(&ctx);
        t.set(
            "region_of",
            lua.create_function(move |lua, addr: i64| {
                let addr = to_addr(addr)?;
                let (_, maps) = snapshot(&c);
                match maps.iter().find(|m| addr >= m.start && addr < m.end) {
                    Some(m) => {
                        let out = lua.create_table()?;
                        out.set("base", m.start as i64)?;
                        out.set("size", m.size() as i64)?;
                        out.set("readable", m.readable)?;
                        out.set("writable", m.writable)?;
                        out.set("executable", m.executable)?;
                        Ok(Value::Table(out))
                    }
                    None => Ok(Value::Nil),
                }
            })?,
        )?;

        // CE `enumMemoryRegions`: every mapped region, for scripts that need
        // to drive their own scans (e.g. engine-specific discovery).
        let c = Arc::clone(&ctx);
        t.set(
            "regions",
            lua.create_function(move |lua, ()| {
                let (_, maps) = snapshot(&c);
                let out = lua.create_table()?;
                for (i, m) in maps.iter().enumerate() {
                    let r = lua.create_table()?;
                    r.set("base", m.start as i64)?;
                    r.set("size", m.size() as i64)?;
                    r.set("readable", m.readable)?;
                    r.set("writable", m.writable)?;
                    r.set("executable", m.executable)?;
                    if let Some(p) = &m.path {
                        r.set("path", p.as_str())?;
                    }
                    out.set(i + 1, r)?;
                }
                Ok(Value::Table(out))
            })?,
        )?;
    }

    // --- resolvers --------------------------------------------------------------
    {
        let c = Arc::clone(&ctx);
        t.set(
            "scan_signature",
            lua.create_function(move |_, (module, pattern, offset): (String, String, Option<i64>)| {
                let (mem, maps) = snapshot(&c);
                let off = offset.map(to_addr).transpose()?;
                crate::resolver::signature::resolve(&mem, &maps, &module, &pattern, off)
                    .map(|a| a as i64)
                    .map_err(lua_err)
            })?,
        )?;

        let c = Arc::clone(&ctx);
        t.set(
            "scan_signature_all",
            lua.create_function(
                move |lua, (module, pattern): (String, String)| {
                    let (mem, maps) = snapshot(&c);
                    let pat = crate::resolver::signature::parse_pattern(&pattern)
                        .map_err(lua_err)?;
                    // Scan the module's whole PE span (Proton maps most
                    // sections anonymous, so path filtering is not enough).
                    let (lo, hi) =
                        crate::memory::ops::module_span(&mem, &maps, &module).map_err(lua_err)?;
                    let mut out = Vec::new();
                    'regions: for region in maps.iter() {
                        if !region.readable || region.size() > MAX_SCAN_REGION {
                            continue;
                        }
                        let (start, end) = (region.start.max(lo), region.end.min(hi));
                        for (addr, len) in scan_chunks(start, end, pat.len() - 1) {
                            let Ok(data) = mem.read_bytes(addr, len) else {
                                continue;
                            };
                            for m in crate::resolver::signature::all_matches(&data, &pat) {
                                out.push((addr + m) as i64);
                                if out.len() >= MAX_SCAN_RESULTS {
                                    break 'regions;
                                }
                            }
                        }
                    }
                    lua.create_sequence_from(out).map(Value::Table)
                },
            )?,
        )?;

        let c = Arc::clone(&ctx);
        t.set(
            "resolve_pointer",
            lua.create_function(
                move |_, (module, offset, offsets): (String, i64, Option<Vec<i64>>)| {
                    let (mem, maps) = snapshot(&c);
                    let to_hex = |v: i64| -> mlua::Result<crate::resolver::HexValue> {
                        let v = u64::try_from(v).map_err(|_| {
                            mlua::Error::external(format!("invalid offset {v}"))
                        })?;
                        Ok(crate::resolver::HexValue::Num(serde_json::Number::from(v)))
                    };
                    let base_off = to_hex(offset)?;
                    let offs: Vec<crate::resolver::HexValue> = offsets
                        .unwrap_or_default()
                        .into_iter()
                        .map(to_hex)
                        .collect::<mlua::Result<_>>()?;
                    crate::resolver::pointer::resolve(&mem, &maps, &module, &base_off, &offs)
                        .map(|a| a as i64)
                        .map_err(lua_err)
                },
            )?,
        )?;
    }

    // --- scans --------------------------------------------------------------------
    {
        // CE `stringscan`: find every occurrence of a byte string. When
        // `module` is given, only that module's regions are searched;
        // otherwise all readable regions.
        let c = Arc::clone(&ctx);
        t.set(
            "scan_string",
            lua.create_function(move |lua, (needle, module): (String, Option<String>)| {
                let (mem, maps) = snapshot(&c);
                let hits = scan_for_bytes(
                    &mem,
                    &maps,
                    needle.as_bytes(),
                    module.as_deref(),
                    false,
                )?;
                lua.create_sequence_from(hits.into_iter().map(|a| a as i64).collect::<Vec<_>>())
                    .map(Value::Table)
            })?,
        )?;

        // CE `pointerscan`/`fastscan`: find every pointer-sized slot storing
        // `addr`. Optional args: module (restrict to that module's regions),
        // writable (true = CE fastscan '+W': writable regions only, 4-byte
        // aligned; false/absent = all readable regions, unaligned).
        let c = Arc::clone(&ctx);
        t.set(
            "scan_pointers_to",
            lua.create_function(
                move |lua, (addr, module, writable): (i64, Option<String>, Option<bool>)| {
                    let addr = to_addr(addr)?;
                    let (mem, maps) = snapshot(&c);
                    let ps = pointer_size(&c)?;
                    let needle = if ps == 8 {
                        (addr as u64).to_ne_bytes().to_vec()
                    } else {
                        (addr as u32).to_ne_bytes().to_vec()
                    };
                    let (writable_only, align) = if writable == Some(true) {
                        (true, 4)
                    } else {
                        (false, 1)
                    };
                    let hits =
                        scan_impl(&mem, &maps, &needle, module.as_deref(), writable_only, align)?;
                    lua.create_sequence_from(hits.into_iter().map(|a| a as i64).collect::<Vec<_>>())
                        .map(Value::Table)
                },
            )?,
        )?;
    }

    // --- disassembly -------------------------------------------------------------
    {
        // CE `findAddress`: decode `size` bytes at `addr` and return every
        // address-like operand (RIP-relative targets, absolute [disp]
        // operands, pointer-sized immediates), in instruction order.
        let c = Arc::clone(&ctx);
        t.set(
            "disasm_targets",
            lua.create_function(move |lua, (addr, size): (i64, Option<usize>)| {
                let addr = to_addr(addr)?;
                let size = size.unwrap_or(0x200).min(MAX_DISASM_BYTES);
                let mem = memory(&c);
                let bitness = if pointer_size(&c)? == 8 { 64 } else { 32 };
                let bytes = mem.read_bytes(addr, size).map_err(lua_err)?;
                let d = crate::memory::disasm::IcedDisassembler::new(bitness);
                let mut out = Vec::new();
                for ins in crate::memory::disasm::Disassembler::decode(&d, &bytes, addr, size) {
                    for t in ins.address_operands() {
                        out.push(t as i64);
                    }
                }
                lua.create_sequence_from(out).map(Value::Table)
            })?,
        )?;
    }

    // --- RTTI ----------------------------------------------------------------------
    {
        // CE `getRTTIClassName`: MSVC RTTI class name of the object at
        // `addr` (its first field must be a vftable pointer), or nil.
        let c = Arc::clone(&ctx);
        t.set(
            "rtti_class_name",
            lua.create_function(move |lua, addr: i64| {
                let addr = to_addr(addr)?;
                let (mem, maps) = snapshot(&c);
                let is64 = pointer_size(&c)? == 8;
                match rtti_class_name(&mem, &maps, addr, is64) {
                    Some(name) => Ok(Value::String(lua.create_string(&name)?)),
                    None => Ok(Value::Nil),
                }
            })?,
        )?;
    }

    // --- misc -----------------------------------------------------------------------
    {
        let c = Arc::clone(&ctx);
        t.set(
            "pid",
            lua.create_function(move |_, ()| Ok(c.lock().unwrap().pid as i64))?,
        )?;

        // The trainer's game module (e.g. "Islets.exe") from trainer.json.
        let c = Arc::clone(&ctx);
        t.set(
            "module",
            lua.create_function(move |_, ()| Ok(c.lock().unwrap().module.clone()))?,
        )?;

        t.set(
            "sleep",
            lua.create_function(|_, ms: u64| {
                std::thread::sleep(std::time::Duration::from_millis(ms));
                Ok(())
            })?,
        )?;

        t.set(
            "log",
            lua.create_function(|_, args: Variadic<Value>| {
                let parts: Vec<String> = args.iter().map(fmt_lua_value).collect();
                eprintln!("[script] {}", parts.join(" "));
                Ok(())
            })?,
        )?;

        // Session symbol lookup: `trainer.symbol("playerInstance")` returns
        // the address registered by an Auto Assembler script, or nil.
        let c = Arc::clone(&ctx);
        t.set(
            "symbol",
            lua.create_function(move |_, name: String| {
                let g = c.lock().unwrap();
                let session = g.session.lock().unwrap();
                match session.symbol_ci(&name) {
                    Some(a) => Ok(Value::Integer(a as i64)),
                    None => Ok(Value::Nil),
                }
            })?,
        )?;
    }

    lua.globals().set("trainer", t)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Primitive implementations
// ---------------------------------------------------------------------------

/// Pointer size of the target, from the PE machine type of the game module
/// (0x8664 = x64 → 8, 0x14C = x86 → 4). Falls back to 8 when undetectable.
fn pointer_size(ctx: &SharedCtx) -> mlua::Result<usize> {
    let (mem, maps, module) = {
        let g = ctx.lock().unwrap();
        if let Some(size) = g.pointer_size {
            return Ok(size);
        }
        (MemoryAccess::new(g.pid), Arc::clone(&g.maps), g.module.clone())
    };
    let base = crate::memory::module_base(&maps, &module)
        .ok_or_else(|| lua_err(EngineError::ModuleNotFound(module.clone())))?;
    let mz = mem.read_bytes(base, 2).map_err(lua_err)?;
    let size = if mz == [0x4D, 0x5A] {
        let e_lfanew = mem.read_u32(base + 0x3C).map_err(lua_err)? as usize;
        match mem.read_u16(base + e_lfanew + 4).map_err(lua_err)? {
            0x14C => 4,
            _ => 8,
        }
    } else {
        8 // not a PE (native ELF?): assume 64-bit
    };
    ctx.lock().unwrap().pointer_size = Some(size);
    Ok(size)
}

/// Scan regions for `needle`, returning up to [`MAX_SCAN_RESULTS`] hit
/// addresses. `module` restricts to one module; `writable_only` mirrors CE's
/// '+W' scans. `align` restricts hit addresses to multiples (CE fsmAligned).
fn scan_for_bytes(
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    needle: &[u8],
    module: Option<&str>,
    writable_only: bool,
) -> mlua::Result<Vec<usize>> {
    scan_impl(mem, maps, needle, module, writable_only, 1)
}

fn scan_impl(
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    needle: &[u8],
    module: Option<&str>,
    writable_only: bool,
    align: usize,
) -> mlua::Result<Vec<usize>> {
    if needle.is_empty() {
        return Err(mlua::Error::external("empty scan pattern"));
    }
    // When a module is given, scan its whole PE span (under Proton most PE
    // sections are mapped anonymous, so path filtering alone would miss
    // them).
    let span = match module {
        Some(m) => Some(crate::memory::ops::module_span(mem, maps, m).map_err(lua_err)?),
        None => None,
    };
    let mut hits = Vec::new();
    for region in maps.iter() {
        if hits.len() >= MAX_SCAN_RESULTS {
            break;
        }
        if !region.readable || region.size() == 0 || region.size() > MAX_SCAN_REGION {
            continue;
        }
        if writable_only && !region.writable {
            continue;
        }
        let (rstart, rend) = match span {
            Some((lo, hi)) => {
                let s = region.start.max(lo);
                let e = region.end.min(hi);
                (s, e)
            }
            None => (region.start, region.end),
        };
        if rstart >= rend {
            continue;
        }
        find_bytes(mem, rstart, rend, needle, align, MAX_SCAN_RESULTS, &mut hits);
    }
    Ok(hits)
}

/// MSVC RTTI class name of the object at `obj` — port of the Rust
/// implementation formerly in the gamemaker resolver (CE `getRTTIClassName`).
fn rtti_class_name(
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    obj: usize,
    is64: bool,
) -> Option<String> {
    let ps = if is64 { 8 } else { 4 };
    let read_ptr = |a: usize| -> Option<usize> {
        if is64 {
            mem.read_u64(a).ok().map(|v| v as usize)
        } else {
            mem.read_u32(a).ok().map(|v| v as usize)
        }
    };
    let vftable = read_ptr(obj)?;
    let col = read_ptr(vftable.checked_sub(ps)?)?;

    let signature = mem.read_u32(col).ok()?;
    let td = if is64 {
        if signature != 1 {
            return None;
        }
        let td_rva = mem.read_u32(col + 0x0C).ok()? as usize;
        image_base_for(maps, col)?.checked_add(td_rva)?
    } else {
        if signature != 0 {
            return None;
        }
        read_ptr(col + 0x0C)?
    };

    let name_off = if is64 { 0x10 } else { 0x08 };
    let bytes = mem.read_bytes(td + name_off, 128).ok()?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

/// Image base of the module whose mapping contains `addr` (lowest start among
/// regions sharing the mapping path).
fn image_base_for(maps: &[MemoryRegion], addr: usize) -> Option<usize> {
    let region = maps
        .iter()
        .find(|m| addr >= m.start && addr < m.end && m.path.is_some())?;
    let path = region.path.as_deref()?;
    maps.iter()
        .filter(|m| m.path.as_deref() == Some(path))
        .map(|m| m.start)
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(setup: Option<&str>) -> ScriptEngine {
        ScriptEngine::new(
            "game.exe",
            setup.map(|s| s.to_string()),
            Vec::new(),
            Arc::new(Mutex::new(crate::trainer::session::TrainerSession::new())),
        )
    }

    // pid 0 / empty maps: every memory op fails, but pure-Lua logic works.
    fn mem() -> MemoryAccess {
        MemoryAccess::new(0)
    }

    #[test]
    fn resolver_must_return_integer_address() {
        let mut e = engine(None);
        assert_eq!(e.resolve(&mem(), &[], "return 0x1234").unwrap(), 0x1234);
        let err = e.resolve(&mem(), &[], "return 'nope'").unwrap_err();
        assert!(matches!(err, EngineError::ScriptError(_)));
        assert!(err.message().contains("must return an address"));
    }

    #[test]
    fn vm_persists_across_resolves() {
        let mut e = engine(None);
        e.resolve(&mem(), &[], "counter = (counter or 0) + 1 return counter").unwrap();
        let v = e
            .resolve(&mem(), &[], "counter = counter + 1 return counter")
            .unwrap();
        assert_eq!(v, 2);
        // reset drops the VM and its globals.
        e.reset();
        let v = e
            .resolve(&mem(), &[], "counter = (counter or 100) return counter")
            .unwrap();
        assert_eq!(v, 100);
    }

    #[test]
    fn setup_script_defines_helpers() {
        let mut e = engine(Some("function add_base(x) return x + 0x1000 end"));
        let v = e.resolve(&mem(), &[], "return add_base(0x20)").unwrap();
        assert_eq!(v, 0x1020);
    }

    #[test]
    fn setup_script_error_is_script_error() {
        let mut e = engine(Some("this is not lua"));
        let err = e.resolve(&mem(), &[], "return 1").unwrap_err();
        assert!(matches!(err, EngineError::ScriptError(_)));
        assert!(err.message().contains("scriptSetup failed"));
    }

    #[test]
    fn sandbox_blocks_dangerous_globals() {
        let mut e = engine(None);
        for expr in ["os", "io", "package", "debug", "require", "load", "dofile"] {
            let err = e
                .resolve(&mem(), &[], format!("return {expr}.x").as_str())
                .unwrap_err();
            assert!(
                matches!(err, EngineError::ScriptError(_)),
                "'{expr}' should be blocked"
            );
        }
        // Safe libraries stay available.
        e.resolve(&mem(), &[], "return math.floor(1.5) + 1").unwrap();
        e.resolve(&mem(), &[], "return #'abc'").unwrap();
    }

    #[test]
    fn lua_runtime_error_becomes_script_error() {
        let mut e = engine(None);
        let err = e.resolve(&mem(), &[], "error('boom')").unwrap_err();
        assert!(matches!(err, EngineError::ScriptError(_)));
        assert!(err.message().contains("boom"));
    }

    #[test]
    fn memory_api_failure_raises_lua_error() {
        // pid 0: reads fail on every platform (Linux: ESRCH, elsewhere: stub).
        let mut e = engine(None);
        let err = e
            .resolve(&mem(), &[], "return trainer.read_i32(0x1000)")
            .unwrap_err();
        assert!(matches!(err, EngineError::ScriptError(_)));
    }

    #[test]
    fn print_is_redirected_not_nil() {
        let mut e = engine(None);
        // Would error if print were nil; must not write to stdout either way.
        e.resolve(&mem(), &[], "print('hello', 42, nil) return 7")
            .unwrap();
    }

    fn engine_with_setup_files(files: Vec<String>) -> ScriptEngine {
        ScriptEngine::new(
            "game.exe",
            None,
            files,
            Arc::new(Mutex::new(crate::trainer::session::TrainerSession::new())),
        )
    }

    #[test]
    fn gamemaker_lua_loads_in_sandbox() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../fixtures/trainers/1669420/scripts/common/gamemaker.lua"
        );
        // `fixtures/` is git-ignored, so a clean checkout does not have this file.
        let Ok(src) = std::fs::read_to_string(path) else {
            eprintln!("skipping: {path} not present");
            return;
        };
        let mut e = engine_with_setup_files(vec![src]);
        // Pure helpers work without a process.
        let v = e
            .resolve(&mem(), &[], "return gm.valid_name('BaseGame') and 1 or 0")
            .unwrap();
        assert_eq!(v, 1);
        let v = e
            .resolve(&mem(), &[], "return gm.valid_name('not a name!') and 1 or 0")
            .unwrap();
        assert_eq!(v, 0);
        // Resolution against a dead/absent process fails with a script error
        // (module lookup fails), never a panic.
        let err = e
            .resolve(&mem(), &[], "return gm_addr('BaseGame', 'player_health')")
            .unwrap_err();
        assert!(matches!(err, EngineError::ScriptError(_)));
    }

    #[test]
    fn lua_sees_session_symbols() {
        let session = Arc::new(Mutex::new(crate::trainer::session::TrainerSession::new()));
        session
            .lock()
            .unwrap()
            .register_symbol("playerInstance", 0xDEAD0000, "test");
        let mut e = ScriptEngine::new("game.exe", None, Vec::new(), session);
        let v = e
            .resolve(&mem(), &[], "return trainer.symbol('playerInstance')")
            .unwrap();
        assert_eq!(v, 0xDEAD0000);
        // Unknown symbols return nil.
        let err = e
            .resolve(&mem(), &[], "local s = trainer.symbol('nope') if s == nil then return 5 end return 0")
            .unwrap();
        assert_eq!(err, 5);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod live_tests {
    use super::*;
    use crate::memory::ops::SCAN_CHUNK;

    const NEEDLE: [u8; 8] = [0xDE, 0xC0, 0xAD, 0x0B, 0x13, 0x37, 0xBE, 0xEF];

    /// Own-process memory (no privileges needed) described by maps that cover
    /// exactly one buffer, so chunk boundaries sit at known offsets.
    struct Target {
        buf: Vec<u8>,
    }

    impl Target {
        fn new() -> Self {
            Self {
                buf: vec![0u8; SCAN_CHUNK + 0x1000],
            }
        }

        fn base(&self) -> usize {
            self.buf.as_ptr() as usize
        }

        fn plant(&mut self, off: usize, bytes: &[u8]) -> usize {
            self.buf[off..off + bytes.len()].copy_from_slice(bytes);
            std::hint::black_box(&mut self.buf);
            self.base() + off
        }

        fn mem(&self) -> MemoryAccess {
            MemoryAccess::new(std::process::id() as i32)
        }

        fn maps(&self) -> Vec<MemoryRegion> {
            vec![MemoryRegion {
                start: self.base(),
                end: self.base() + self.buf.len(),
                readable: true,
                writable: true,
                executable: false,
                private: true,
                path: Some("/games/game.exe".to_string()),
            }]
        }

        fn lua(&self, code: &str) -> usize {
            let session = Arc::new(Mutex::new(crate::trainer::session::TrainerSession::new()));
            let mut e = ScriptEngine::new("game.exe", None, Vec::new(), session);
            e.resolve(&self.mem(), &self.maps(), code).unwrap()
        }
    }

    #[test]
    fn scan_impl_reports_a_match_around_a_chunk_boundary_once() {
        for before in 0..=NEEDLE.len() {
            let mut t = Target::new();
            let addr = t.plant(SCAN_CHUNK - before, &NEEDLE);
            let hits = scan_impl(&t.mem(), &t.maps(), &NEEDLE, None, false, 1).unwrap();
            assert_eq!(hits, [addr], "{before} bytes before the boundary");
        }
    }

    #[test]
    fn scan_impl_keeps_overlapping_matches_across_a_chunk_boundary() {
        let mut t = Target::new();
        let addr = t.plant(SCAN_CHUNK - 2, &[0xAB; 4]);
        let hits = scan_impl(&t.mem(), &t.maps(), &[0xAB; 3], None, false, 1).unwrap();
        assert_eq!(hits, [addr, addr + 1]);
    }

    #[test]
    fn scan_impl_applies_alignment_across_a_chunk_boundary() {
        let mut t = Target::new();
        // Pick the aligned and unaligned planting offsets near the boundary.
        let aligned = (t.base() + SCAN_CHUNK - 4) / 4 * 4 - t.base();
        let addr = t.plant(aligned, &NEEDLE);
        t.plant(aligned + 0x101, &NEEDLE);
        let hits = scan_impl(&t.mem(), &t.maps(), &NEEDLE, None, false, 4).unwrap();
        assert_eq!(hits, [addr]);
    }

    #[test]
    fn scan_string_finds_a_string_across_a_chunk_boundary() {
        let mut t = Target::new();
        t.plant(SCAN_CHUNK - 3, b"chunk-straddler");
        assert_eq!(t.lua("return #trainer.scan_string('chunk-straddler')"), 1);
    }

    #[test]
    fn scan_pointers_to_finds_a_pointer_across_a_chunk_boundary() {
        let mut t = Target::new();
        // Module "game.exe" has no MZ header here, so pointers are 8 bytes.
        let pointee: usize = 0x7ABC_DEF0_1234;
        t.plant(SCAN_CHUNK - 3, &pointee.to_ne_bytes());
        let code = format!("return #trainer.scan_pointers_to({pointee})");
        assert_eq!(t.lua(&code), 1);
    }

    #[test]
    fn scan_signature_all_finds_a_match_across_a_chunk_boundary_once() {
        let mut t = Target::new();
        t.plant(0x200, &NEEDLE);
        t.plant(SCAN_CHUNK - 3, &NEEDLE);
        let code = "return #trainer.scan_signature_all('game.exe', 'DE C0 AD 0B ?? ?? BE EF')";
        assert_eq!(t.lua(code), 2);
    }
}
