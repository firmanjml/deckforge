//! Auto Assembler execution engine.
//!
//! Runs one section (`[ENABLE]` / `[DISABLE]`) of a script against a
//! [`MemoryOps`] backend and a [`TrainerSession`]:
//!
//! ```text
//! parse → directives (scans/allocs bind symbols) → blocks grouped by origin
//!      → fixpoint assembly (labels get addresses) → ordered apply
//!        (writes journaled for rollback) → commit symbols/allocations
//! ```
//!
//! On `[ENABLE]` failure, every effect of the run is rolled back in reverse
//! order (bytes restored, allocations freed, symbols unregistered) so a cheat
//! is never left half-enabled. `[DISABLE]` runs best-effort and reports the
//! first error.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::error::EngineError;
use crate::memory::MemoryOps;
use crate::resolver::signature::parse_pattern;
use crate::trainer::session::TrainerSession;

use super::assemble;
use super::error::{AaError, ErrorCtx, Section};
use super::expr::{self, BareNumbers};
use super::parser::{self, DataWidth, Stmt, StmtLine};
use super::source;

/// CE aobscan/aobscanmodule require a unique match.
const MAX_ASSEMBLY_PASSES: usize = 8;

/// Everything needed to execute a script section.
pub struct Executor<'a> {
    pub mem: &'a dyn MemoryOps,
    pub session: Arc<Mutex<TrainerSession>>,
    pub package_dir: &'a Path,
    /// Trainer id (for error context).
    pub trainer: String,
}

/// One code block: content assembled at an origin address.
struct Block {
    origin: u64,
    items: Vec<Item>,
}

struct Item {
    kind: ItemKind,
    file: String,
    line: u32,
    text: String,
}

enum ItemKind {
    Asm,
    Data(DataWidth, Vec<String>),
    LabelDef(String),
}

/// An ordered non-code operation in the script stream.
enum Op {
    Write { block: usize },
    Assert { addr: String, bytes: String },
    RegisterSymbol { name: String },
    UnregisterSymbol { name: String },
    Dealloc { name: String },
}

struct OpLine {
    op: Op,
    file: String,
    line: u32,
    text: String,
}

/// Journal entries for rollback (enable) — reverse order.
enum JournalEntry {
    RestoreBytes {
        addr: usize,
        original: Vec<u8>,
    },
    Dealloc {
        name: String,
        addr: usize,
        size: usize,
    },
    UnregisterSymbol {
        name: String,
    },
}

/// (blocks, ordered ops, local symbols) produced by [`Executor::organize`].
type Organized = (Vec<Block>, Vec<OpLine>, HashMap<String, u64>);

impl<'a> Executor<'a> {
    /// Execute one section of `script_rel` (package-relative path).
    /// `owner` is the cheat id or component id that owns all symbols and
    /// allocations this run creates.
    pub fn run(
        &mut self,
        owner: &str,
        script_rel: &str,
        section: Section,
    ) -> Result<(), EngineError> {
        let ctx = source::error_ctx(&self.trainer, owner, script_rel, section);
        let src = source::load(self.package_dir, script_rel)
            .map_err(|e| ctx.err(0, script_rel, e.message()).into_engine_error())?;
        let lines = match section {
            Section::Enable => &src.enable,
            Section::Disable => &src.disable,
        };
        if lines.is_empty() {
            // No section = nothing to do (a script may legitimately only
            // define one direction, though CE trainers normally have both).
            return Ok(());
        }
        let stmts = parser::parse_section(lines, &ctx).map_err(AaError::into_engine_error)?;
        match section {
            Section::Enable => self
                .run_enable(&ctx, &stmts)
                .map_err(AaError::into_engine_error),
            Section::Disable => self
                .run_disable(&ctx, &stmts)
                .map_err(AaError::into_engine_error),
        }
    }

    // ------------------------------------------------------------------ //
    //  Shared: directives → symbols, statement stream → blocks + ops      //
    // ------------------------------------------------------------------ //

    /// Walk the statement stream, executing scan/alloc directives and
    /// grouping code into blocks. Allocations made here are journaled (for
    /// rollback) and recorded in `made_allocs` (for commit into the session
    /// on success). Returns (blocks, ops, local symbols).
    fn organize(
        &mut self,
        ctx: &ErrorCtx,
        stmts: &[StmtLine],
        journal: &mut Vec<JournalEntry>,
        made_allocs: &mut Vec<(String, usize, usize)>,
    ) -> Result<Organized, AaError> {
        let mut blocks: Vec<Block> = Vec::new();
        let mut ops: Vec<OpLine> = Vec::new();
        let mut symbols: HashMap<String, u64> = HashMap::new();
        // Index of the block currently collecting code.
        let mut current: Option<usize> = None;
        // Last allocation made by this run. No-hint allocs cluster near it
        // (see the Alloc arm below).
        let mut last_alloc: Option<u64> = None;

        for sl in stmts {
            let line_err = |cause: String| ctx.err(sl.line, &sl.text, cause);
            match &sl.stmt {
                Stmt::AobScan { name, pattern } => {
                    let addr = self.do_aobscan(None, pattern).map_err(line_err)?;
                    symbols.insert(name.clone(), addr);
                }
                Stmt::AobScanModule {
                    name,
                    module,
                    pattern,
                } => {
                    let addr = self.do_aobscan(Some(module), pattern).map_err(line_err)?;
                    symbols.insert(name.clone(), addr);
                }
                Stmt::AobScanRegion {
                    name,
                    start,
                    stop,
                    pattern,
                } => {
                    let addr = self
                        .do_aobscan_region(start, stop, pattern, &symbols)
                        .map_err(line_err)?;
                    symbols.insert(name.clone(), addr);
                }
                Stmt::Alloc { name, size, near } => {
                    let size_v = self
                        .eval(size, BareNumbers::Decimal, &symbols)
                        .map_err(line_err)?;
                    let near_v = match near {
                        Some(n) => {
                            Some(self.eval(n, BareNumbers::Hex, &symbols).map_err(line_err)?)
                        }
                        // CE parity: on Windows, sibling VirtualAllocs
                        // cluster near the process image, so a no-hint alloc
                        // usually stays within rel32 reach of the script's
                        // code block (`mov [symbol],reg` assembles
                        // RIP-relative). Under Proton a bare mmap lands GiB
                        // away from the injection point — cluster no-hint
                        // allocs near the previous alloc instead.
                        None => last_alloc,
                    };
                    if size_v == 0 || size_v > crate::memory::alloc::MAX_ALLOC_SIZE as u64 {
                        return Err(line_err(format!(
                            "alloc size {size_v} out of range (1..={})",
                            crate::memory::alloc::MAX_ALLOC_SIZE
                        )));
                    }
                    let addr = self
                        .mem
                        .alloc(size_v as usize, near_v.map(|v| v as usize))
                        .map_err(|e| line_err(e.message()))?;
                    symbols.insert(name.clone(), addr as u64);
                    last_alloc = Some(addr as u64);
                    made_allocs.push((name.clone(), addr, size_v as usize));
                    journal.push(JournalEntry::Dealloc {
                        name: name.clone(),
                        addr,
                        size: size_v as usize,
                    });
                }
                Stmt::LabelDecl(name) => {
                    // Declaration only; the definition appears as LabelDef.
                    let _ = name;
                }
                Stmt::LabelDef(name) => {
                    // If the name resolves to a symbol (scan/alloc/session),
                    // this starts a new block at that address; otherwise it's
                    // a plain label definition inside the current block.
                    let resolved = self.lookup_symbol(name, &symbols);
                    match resolved {
                        Some(addr) => {
                            blocks.push(Block {
                                origin: addr,
                                items: Vec::new(),
                            });
                            current = Some(blocks.len() - 1);
                            ops.push(OpLine {
                                op: Op::Write {
                                    block: blocks.len() - 1,
                                },
                                file: sl.file.clone(),
                                line: sl.line,
                                text: sl.text.clone(),
                            });
                        }
                        None => {
                            let idx = current.ok_or_else(|| {
                                line_err(format!(
                                    "label '{name}:' has no code origin (no aobscan/alloc block started)"
                                ))
                            })?;
                            blocks[idx].items.push(Item {
                                kind: ItemKind::LabelDef(name.clone()),
                                file: sl.file.clone(),
                                line: sl.line,
                                text: sl.text.clone(),
                            });
                        }
                    }
                }
                Stmt::Data { width, values } => {
                    let idx = current
                        .ok_or_else(|| line_err("db/dw/dd/dq outside a code block".to_string()))?;
                    blocks[idx].items.push(Item {
                        kind: ItemKind::Data(*width, values.clone()),
                        file: sl.file.clone(),
                        line: sl.line,
                        text: sl.text.clone(),
                    });
                }
                Stmt::ReadMem { addr, size } => {
                    // readmem is a data-emitting directive: it reads `size`
                    // bytes from `addr` and emits them as raw data bytes.
                    let idx = current
                        .ok_or_else(|| line_err("readmem outside a code block".to_string()))?;
                    let size_val = self
                        .eval(size, BareNumbers::Decimal, &symbols)
                        .map_err(line_err)? as usize;
                    let addr_val = self
                        .eval(addr, BareNumbers::Hex, &symbols)
                        .map_err(line_err)? as usize;
                    let bytes = self
                        .mem
                        .read_bytes(addr_val, size_val)
                        .map_err(|e| line_err(e.message()))?;
                    // Emit as byte data with hex string values.
                    let hex_vals: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
                    blocks[idx].items.push(Item {
                        kind: ItemKind::Data(DataWidth::Byte, hex_vals),
                        file: sl.file.clone(),
                        line: sl.line,
                        text: sl.text.clone(),
                    });
                }
                Stmt::Align { align, fill } => {
                    // align N, fill — pad the current block to the next
                    // multiple of N with the fill byte.
                    let idx = current
                        .ok_or_else(|| line_err("align outside a code block".to_string()))?;
                    let align_val = self
                        .eval(align, BareNumbers::Hex, &symbols)
                        .map_err(line_err)? as usize;
                    let fill_val = self
                        .eval(fill, BareNumbers::Hex, &symbols)
                        .map_err(line_err)? as u8;
                    if align_val == 0 || !align_val.is_power_of_two() {
                        return Err(line_err(format!(
                            "align value {align_val} must be a non-zero power of two"
                        )));
                    }
                    // Compute current offset within the block.
                    let empty_labels: HashMap<String, u64> = HashMap::new();
                    let mut current_offset = blocks[idx].origin;
                    for item in &blocks[idx].items {
                        match &item.kind {
                            ItemKind::LabelDef(_) => {}
                            ItemKind::Asm => {
                                let lookup = self.make_lookup_lenient(&symbols, &empty_labels);
                                let size = assemble::instr_size(
                                    self.mem.bitness(),
                                    current_offset,
                                    &item.text,
                                    &lookup,
                                )
                                .map_err(|c| ctx.err(item.line, &item.text, c))?;
                                current_offset += size as u64;
                            }
                            ItemKind::Data(width, values) => {
                                let lookup = self.make_lookup_lenient(&symbols, &empty_labels);
                                let size = data_size(*width, values, &lookup)
                                    .map_err(|c| ctx.err(item.line, &item.text, c))?;
                                current_offset += size;
                            }
                        }
                    }
                    let remainder = current_offset % align_val as u64;
                    if remainder > 0 {
                        let pad_count = align_val as u64 - remainder;
                        let pad_vals: Vec<String> =
                            (0..pad_count).map(|_| format!("{fill_val:02X}")).collect();
                        blocks[idx].items.push(Item {
                            kind: ItemKind::Data(DataWidth::Byte, pad_vals),
                            file: sl.file.clone(),
                            line: sl.line,
                            text: sl.text.clone(),
                        });
                    }
                }
                Stmt::Asm(text) => {
                    let idx = current.ok_or_else(|| {
                        line_err("assembly instruction outside a code block".to_string())
                    })?;
                    blocks[idx].items.push(Item {
                        kind: ItemKind::Asm,
                        file: sl.file.clone(),
                        line: sl.line,
                        text: text.clone(),
                    });
                }
                Stmt::Assert { addr, bytes } => ops.push(OpLine {
                    op: Op::Assert {
                        addr: addr.clone(),
                        bytes: bytes.clone(),
                    },
                    file: sl.file.clone(),
                    line: sl.line,
                    text: sl.text.clone(),
                }),
                Stmt::RegisterSymbol(name) => ops.push(OpLine {
                    op: Op::RegisterSymbol { name: name.clone() },
                    file: sl.file.clone(),
                    line: sl.line,
                    text: sl.text.clone(),
                }),
                Stmt::UnregisterSymbol(name) => ops.push(OpLine {
                    op: Op::UnregisterSymbol { name: name.clone() },
                    file: sl.file.clone(),
                    line: sl.line,
                    text: sl.text.clone(),
                }),
                Stmt::Dealloc { name } => ops.push(OpLine {
                    op: Op::Dealloc { name: name.clone() },
                    file: sl.file.clone(),
                    line: sl.line,
                    text: sl.text.clone(),
                }),
            }
        }
        Ok((blocks, ops, symbols))
    }

    // ------------------------------------------------------------------ //
    //  Assembly                                                            //
    // ------------------------------------------------------------------ //

    /// Assemble every block with a fixpoint loop over label addresses.
    ///
    /// Sizing passes resolve unknown symbols to 0 (forward-referenced labels
    /// get concrete addresses in later passes); the final pass uses strict
    /// resolution so genuinely unknown symbols produce errors. The loop stops
    /// when label addresses stabilize (near-form branches are fixed-size, so
    /// this almost always converges in two passes).
    fn assemble_blocks(
        &self,
        ctx: &ErrorCtx,
        blocks: &[Block],
        symbols: &mut HashMap<String, u64>,
    ) -> Result<Vec<Vec<u8>>, AaError> {
        let mut label_addrs: HashMap<String, u64> = HashMap::new();
        let mut prev: Option<HashMap<String, u64>> = None;

        for _pass in 0..MAX_ASSEMBLY_PASSES {
            label_addrs.clear();
            for block in blocks {
                let mut offset = block.origin;
                for item in &block.items {
                    match &item.kind {
                        ItemKind::LabelDef(name) => {
                            label_addrs.insert(name.clone(), offset);
                        }
                        ItemKind::Asm => {
                            let lookup = self.make_lookup_lenient(symbols, &label_addrs);
                            let size = assemble::instr_size(
                                self.mem.bitness(),
                                offset,
                                &item.text,
                                &lookup,
                            )
                            .map_err(|c| ctx.err(item.line, &item.text, c))?;
                            offset += size as u64;
                        }
                        ItemKind::Data(width, values) => {
                            let lookup = self.make_lookup_lenient(symbols, &label_addrs);
                            let size = data_size(*width, values, &lookup)
                                .map_err(|c| ctx.err(item.line, &item.text, c))?;
                            offset += size;
                        }
                    }
                }
            }
            if prev.as_ref() == Some(&label_addrs) {
                break;
            }
            prev = Some(label_addrs.clone());
        }

        // Publish label addresses as local symbols so registersymbol() and
        // later expressions can reference them.
        for (name, addr) in &label_addrs {
            symbols.insert(name.clone(), *addr);
        }

        // Final assembly with converged label addresses and strict lookup.
        let mut out = Vec::with_capacity(blocks.len());
        for block in blocks {
            let mut bytes = Vec::new();
            let mut offset = block.origin;
            for item in &block.items {
                match &item.kind {
                    ItemKind::LabelDef(_) => {}
                    ItemKind::Asm => {
                        let lookup = self.make_lookup(symbols, &label_addrs);
                        let b = assemble::assemble_instr(
                            self.mem.bitness(),
                            offset,
                            &item.text,
                            &lookup,
                        )
                        .map_err(|c| ctx.err(item.line, &item.text, c))?;
                        offset += b.len() as u64;
                        bytes.extend_from_slice(&b);
                    }
                    ItemKind::Data(width, values) => {
                        let lookup = self.make_lookup(symbols, &label_addrs);
                        let b = emit_data(*width, values, &lookup)
                            .map_err(|c| ctx.err(item.line, &item.text, c))?;
                        offset += b.len() as u64;
                        bytes.extend_from_slice(&b);
                    }
                }
            }
            out.push(bytes);
        }
        Ok(out)
    }

    // ------------------------------------------------------------------ //
    //  Enable (transactional) / Disable (best-effort)                     //
    // ------------------------------------------------------------------ //

    fn run_enable(&mut self, ctx: &ErrorCtx, stmts: &[StmtLine]) -> Result<(), AaError> {
        let mut journal: Vec<JournalEntry> = Vec::new();
        let mut made_allocs: Vec<(String, usize, usize)> = Vec::new();
        let owner = ctx.owner.clone();

        let result = (|executor: &mut Self| -> Result<(), AaError> {
            let (blocks, ops, mut symbols) =
                executor.organize(ctx, stmts, &mut journal, &mut made_allocs)?;
            let assembled = executor.assemble_blocks(ctx, &blocks, &mut symbols)?;
            executor.apply(ctx, &ops, &blocks, &assembled, &symbols, &mut journal)?;
            Ok(())
        })(self);

        match result {
            Ok(()) => {
                // Commit: publish this run's allocations into the session so
                // other scripts (and DISABLE's dealloc) can find them.
                let mut session = self.session.lock().unwrap();
                for (name, addr, size) in made_allocs {
                    session.add_allocation(&name, addr, size, &owner);
                }
                Ok(())
            }
            Err(e) => {
                self.rollback(&owner, &journal);
                Err(e)
            }
        }
    }

    fn run_disable(&mut self, ctx: &ErrorCtx, stmts: &[StmtLine]) -> Result<(), AaError> {
        let mut journal = Vec::new(); // disable is best-effort; no rollback
        let mut made_allocs = Vec::new();
        let owner = ctx.owner.clone();
        let (blocks, ops, mut symbols) =
            self.organize(ctx, stmts, &mut journal, &mut made_allocs)?;
        // Rare but legal: DISABLE allocates (e.g. for a temporary trampoline).
        {
            let mut session = self.session.lock().unwrap();
            for (name, addr, size) in &made_allocs {
                session.add_allocation(name, *addr, *size, &owner);
            }
        }
        let assembled = self.assemble_blocks(ctx, &blocks, &mut symbols)?;
        self.apply(ctx, &ops, &blocks, &assembled, &symbols, &mut journal)
    }

    /// Execute the ordered op stream: writes, asserts, symbol ops, deallocs.
    fn apply(
        &mut self,
        ctx: &ErrorCtx,
        ops: &[OpLine],
        blocks: &[Block],
        assembled: &[Vec<u8>],
        symbols: &HashMap<String, u64>,
        journal: &mut Vec<JournalEntry>,
    ) -> Result<(), AaError> {
        let owner = ctx.owner.clone();
        for ol in ops {
            let line_err = |cause: String| ctx.err(ol.line, &ol.text, cause);
            match &ol.op {
                Op::Write { block } => {
                    let addr = blocks[*block].origin as usize;
                    let bytes = &assembled[*block];
                    if bytes.is_empty() {
                        continue;
                    }
                    // Journal original bytes before overwriting.
                    let original = self
                        .mem
                        .read_bytes(addr, bytes.len())
                        .map_err(|e| line_err(e.message()))?;
                    self.mem
                        .write_bytes(addr, bytes)
                        .map_err(|e| line_err(e.message()))?;
                    journal.push(JournalEntry::RestoreBytes { addr, original });
                }
                Op::Assert { addr, bytes } => {
                    let a = self
                        .eval(addr, BareNumbers::Hex, symbols)
                        .map_err(&line_err)?;
                    let pat = parse_pattern(bytes)
                        .map_err(|e| line_err(format!("invalid assert bytes: {}", e.message())))?;
                    let actual = self
                        .mem
                        .read_bytes(a as usize, pat.len())
                        .map_err(|e| line_err(e.message()))?;
                    let matches = actual.iter().zip(&pat).all(|(b, p)| match p {
                        crate::resolver::signature::PatternByte::Exact(e) => b == e,
                        crate::resolver::signature::PatternByte::Wildcard => true,
                    });
                    if !matches {
                        return Err(line_err(format!(
                            "assert failed: expected [{bytes}] at 0x{a:X}, found [{}]",
                            actual
                                .iter()
                                .map(|b| format!("{b:02X}"))
                                .collect::<Vec<_>>()
                                .join(" ")
                        )));
                    }
                }
                Op::RegisterSymbol { name } => {
                    let addr = self.lookup_symbol(name, symbols).ok_or_else(|| {
                        line_err(format!(
                            "registersymbol: '{name}' is not defined (no aobscan/alloc/label bound it)"
                        ))
                    })?;
                    self.session
                        .lock()
                        .unwrap()
                        .register_symbol(name, addr as usize, &owner);
                    journal.push(JournalEntry::UnregisterSymbol { name: name.clone() });
                }
                Op::UnregisterSymbol { name } => {
                    self.session.lock().unwrap().unregister_symbol(name, &owner);
                }
                Op::Dealloc { name } => {
                    self.exec_dealloc(name, &owner).map_err(line_err)?;
                }
            }
        }
        Ok(())
    }

    /// dealloc(name): free a session allocation when this owner was the last
    /// one; free allocations made in *this* run directly.
    fn exec_dealloc(&mut self, name: &str, owner: &str) -> Result<(), String> {
        let freed = {
            let mut session = self.session.lock().unwrap();
            session.remove_allocation(name, owner)
        };
        match freed {
            Some((addr, size)) => self.mem.dealloc(addr, size).map_err(|e| e.message()),
            None => {
                // Unknown name or still owned by another active cheat.
                let session = self.session.lock().unwrap();
                if session.allocation(name).is_some() {
                    Ok(()) // shared allocation: kept alive for other owners
                } else {
                    Err(format!(
                        "dealloc: '{name}' is not an active allocation (already freed?)"
                    ))
                }
            }
        }
    }

    /// Undo every journaled effect, best-effort, in reverse order.
    fn rollback(&mut self, owner: &str, journal: &[JournalEntry]) {
        for entry in journal.iter().rev() {
            match entry {
                JournalEntry::RestoreBytes { addr, original } => {
                    let _ = self.mem.write_bytes(*addr, original);
                }
                JournalEntry::Dealloc { name, addr, size } => {
                    let _ = self.mem.dealloc(*addr, *size);
                    self.session.lock().unwrap().remove_allocation(name, owner);
                }
                JournalEntry::UnregisterSymbol { name } => {
                    // This run registered it under `owner`; removing that
                    // ownership rolls the registration back.
                    self.session.lock().unwrap().unregister_symbol(name, owner);
                }
            }
        }
    }

    // ------------------------------------------------------------------ //
    //  Lookups                                                             //
    // ------------------------------------------------------------------ //

    /// aobscan/aobscanmodule: unique match required (CE parity).
    fn do_aobscan(&self, module: Option<&str>, pattern: &str) -> Result<u64, String> {
        let pat = parse_pattern(pattern).map_err(|e| e.message())?;
        let matches = self.mem.aob_scan(module, &pat).map_err(|e| e.message())?;
        match matches.len() {
            0 => {
                let span_info = match module {
                    Some(_) => "\nhint: verify the game version matches the trainer's target \
                         version, and that the game is fully loaded (in-game, not main menu)"
                        .to_string(),
                    None => String::new(),
                };
                Err(match module {
                    Some(m) => format!("pattern was not found in module {m}{span_info}"),
                    None => "pattern was not found in readable memory".to_string(),
                })
            }
            1 => Ok(matches[0] as u64),
            n => Err(format!(
                "pattern matched {n} addresses; aobscan requires a unique match (add more context bytes)"
            )),
        }
    }

    /// Symbol resolution order: script-local symbols → session symbols →
    /// session allocations → module base.
    /// aobscanregion(name,start,stop,pattern): scan only the requested address
    /// range. CE treats the stop address as inclusive; MemoryOps uses a
    /// half-open range, so this converts with saturating_add(1).
    fn do_aobscan_region(
        &self,
        start: &str,
        stop: &str,
        pattern: &str,
        symbols: &HashMap<String, u64>,
    ) -> Result<u64, String> {
        let start = self.eval(start, BareNumbers::Hex, symbols)? as usize;
        let stop = self.eval(stop, BareNumbers::Hex, symbols)? as usize;
        if stop < start {
            return Err(format!(
                "aobscanregion stop address 0x{stop:X} is before start address 0x{start:X}"
            ));
        }
        let pat = parse_pattern(pattern).map_err(|e| e.message())?;
        let matches = self
            .mem
            .aob_scan_range(start, stop.saturating_add(1), &pat)
            .map_err(|e| e.message())?;
        match matches.len() {
            0 => Err(format!(
                "pattern was not found in range 0x{start:X}..0x{stop:X}"
            )),
            1 => Ok(matches[0] as u64),
            n => Err(format!(
                "pattern matched {n} addresses; aobscanregion requires a unique match (narrow the range or add more context bytes)"
            )),
        }
    }

    fn lookup_symbol(&self, name: &str, locals: &HashMap<String, u64>) -> Option<u64> {
        if let Some(v) = locals.get(name) {
            return Some(*v);
        }
        // Case-insensitive fallback for locals (CE symbols are CI).
        if let Some((_, v)) = locals.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
            return Some(*v);
        }
        let session = self.session.lock().unwrap();
        if let Some(a) = session.symbol_ci(name) {
            return Some(a as u64);
        }
        if let Some(a) = session.allocation(name) {
            return Some(a as u64);
        }
        drop(session);
        self.mem.module_base(name).ok().map(|a| a as u64)
    }

    fn eval(
        &self,
        text: &str,
        bare: BareNumbers,
        locals: &HashMap<String, u64>,
    ) -> Result<u64, String> {
        let empty: HashMap<String, u64> = HashMap::new();
        let lookup = self.make_lookup(locals, &empty);
        expr::eval(text, bare, &lookup)
    }

    fn make_lookup<'b>(
        &'b self,
        locals: &'b HashMap<String, u64>,
        labels: &'b HashMap<String, u64>,
    ) -> impl Fn(&str) -> Option<u64> + 'b {
        move |name: &str| {
            if let Some(v) = labels.get(name) {
                return Some(*v);
            }
            if let Some((_, v)) = labels.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
                return Some(*v);
            }
            self.lookup_symbol(name, locals)
        }
    }

    /// Sizing-pass lookup: unknown names resolve to 0 so forward-referenced
    /// labels size correctly before their addresses are known.
    fn make_lookup_lenient<'b>(
        &'b self,
        locals: &'b HashMap<String, u64>,
        labels: &'b HashMap<String, u64>,
    ) -> impl Fn(&str) -> Option<u64> + 'b {
        move |name: &str| {
            if let Some(v) = labels.get(name) {
                return Some(*v);
            }
            if let Some((_, v)) = labels.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
                return Some(*v);
            }
            Some(self.lookup_symbol(name, locals).unwrap_or(0))
        }
    }
}

/// Evaluate a data emission's total size without emitting.
fn data_size(
    width: DataWidth,
    values: &[String],
    lookup: &dyn Fn(&str) -> Option<u64>,
) -> Result<u64, String> {
    let mut total = 0u64;
    for v in values {
        let v = v.trim();
        if is_quoted(v) {
            total += (v.len() - 2) as u64; // string contents, db only
        } else {
            // Validate it evaluates (catches unknown symbols in pass 1).
            emit_data_value(width, v, lookup)?;
            total += width.size() as u64;
        }
    }
    Ok(total)
}

fn is_quoted(v: &str) -> bool {
    (v.starts_with('"') && v.ends_with('"') && v.len() >= 2)
        || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2)
}

/// Emit db/dw/dd/dq bytes.
fn emit_data(
    width: DataWidth,
    values: &[String],
    lookup: &dyn Fn(&str) -> Option<u64>,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for v in values {
        let v = v.trim();
        if is_quoted(v) {
            if width != DataWidth::Byte {
                return Err("string literals are only valid in db".into());
            }
            out.extend_from_slice(&v.as_bytes()[1..v.len() - 1]);
            continue;
        }
        out.extend_from_slice(&emit_data_value(width, v, lookup)?);
    }
    Ok(out)
}

fn emit_data_value(
    width: DataWidth,
    v: &str,
    lookup: &dyn Fn(&str) -> Option<u64>,
) -> Result<Vec<u8>, String> {
    // CE casts: (float)x, (double)x
    let lower = v.to_ascii_lowercase();
    if let Some(inner) = lower.strip_prefix("(float)") {
        let f = inner
            .trim()
            .parse::<f64>()
            .map_err(|_| format!("invalid (float) value '{v}'"))? as f32;
        return Ok(f.to_le_bytes().to_vec());
    }
    if let Some(inner) = lower.strip_prefix("(double)") {
        let f = inner
            .trim()
            .parse::<f64>()
            .map_err(|_| format!("invalid (double) value '{v}'"))?;
        return Ok(f.to_le_bytes().to_vec());
    }
    let value = expr::eval(v, BareNumbers::Hex, lookup)?;
    Ok(match width {
        DataWidth::Byte => vec![value as u8],
        DataWidth::Word => (value as u16).to_le_bytes().to_vec(),
        DataWidth::Dword => (value as u32).to_le_bytes().to_vec(),
        DataWidth::Qword => value.to_le_bytes().to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::ops::mock::{MockMemory, ALLOC_BASE};
    use std::fs;

    /// Write a script package to a temp dir; returns the package path.
    fn setup_package(files: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "deckforge-aa-rt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for (rel, content) in files {
            let path = dir.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        dir
    }

    fn make_executor<'a>(
        mem: &'a MockMemory,
        session: Arc<Mutex<TrainerSession>>,
        package_dir: &'a std::path::Path,
    ) -> Executor<'a> {
        Executor {
            mem,
            session,
            package_dir,
            trainer: "123456".into(),
        }
    }

    /// Mock game: `game.exe` at 0x400000 with the movss instruction from the
    /// task's example at 0x401000.
    fn mock_game() -> MockMemory {
        let mut mem = MockMemory::new(64);
        mem.add_module("game.exe", 0x400000, 0x100000);
        // movss [rbx+00000120],xmm0
        mem.plant(0x401000, &[0xF3, 0x0F, 0x11, 0x83, 0x20, 0x01, 0x00, 0x00]);
        mem
    }

    const EXAMPLE_SCRIPT: &str = r#"
[ENABLE]

aobscanmodule(INJECT,game.exe,F3 0F 11 83 ?? ?? ?? ??)
alloc(newmem,1024,INJECT)
label(return)

newmem:
    ; custom instructions
    movss [rbx+00000120],xmm0
    jmp return

INJECT:
    jmp newmem
    nop 3

return:

registersymbol(INJECT)


[DISABLE]

INJECT:
    db F3 0F 11 83 20 01 00 00

unregistersymbol(INJECT)
dealloc(newmem)
"#;

    #[test]
    fn enable_writes_jmp_and_registers_symbols() {
        let dir = setup_package(&[("scripts/infinite_health.asm", EXAMPLE_SCRIPT)]);
        let mem = mock_game();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);

        ex.run(
            "infinite_health",
            "scripts/infinite_health.asm",
            Section::Enable,
        )
        .unwrap();

        // INJECT: jmp newmem (E9 rel32) + 3 nops.
        let newmem = ALLOC_BASE;
        let inj = mem.peek(0x401000, 8);
        assert_eq!(inj[0], 0xE9);
        let rel = i32::from_le_bytes(inj[1..5].try_into().unwrap());
        assert_eq!(0x401000i64 + 5 + rel as i64, newmem as i64);
        assert_eq!(&inj[5..8], &[0x90, 0x90, 0x90]);

        // newmem: movss [rbx+120],xmm0 (8 bytes, disp32 form — 0x120 > i8)
        // then jmp return (→ 0x401008).
        let nm = mem.peek(newmem, 13);
        assert_eq!(&nm[..8], &[0xF3, 0x0F, 0x11, 0x83, 0x20, 0x01, 0x00, 0x00]);
        assert_eq!(nm[8], 0xE9);
        let rel2 = i32::from_le_bytes(nm[9..13].try_into().unwrap());
        assert_eq!(newmem as i64 + 13 + rel2 as i64, 0x401008);

        // Symbol registered and allocation recorded.
        let s = session.lock().unwrap();
        assert_eq!(s.symbol("INJECT"), Some(0x401000));
        assert_eq!(s.allocation("newmem"), Some(newmem));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disable_restores_and_cleans_up() {
        let dir = setup_package(&[("scripts/infinite_health.asm", EXAMPLE_SCRIPT)]);
        let mem = mock_game();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);

        ex.run(
            "infinite_health",
            "scripts/infinite_health.asm",
            Section::Enable,
        )
        .unwrap();
        ex.run(
            "infinite_health",
            "scripts/infinite_health.asm",
            Section::Disable,
        )
        .unwrap();

        // Original bytes restored.
        assert_eq!(
            mem.peek(0x401000, 8),
            vec![0xF3, 0x0F, 0x11, 0x83, 0x20, 0x01, 0x00, 0x00]
        );
        // Symbol gone, allocation freed.
        let s = session.lock().unwrap();
        assert_eq!(s.symbol("INJECT"), None);
        assert_eq!(s.allocation("newmem"), None);
        drop(s);
        assert_eq!(mem.frees.borrow().len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn aobscanmodule_missing_pattern_errors_with_context() {
        let dir = setup_package(&[(
            "scripts/x.asm",
            "[ENABLE]\naobscanmodule(INJECT,game.exe,DE AD BE EF)\n",
        )]);
        let mem = mock_game();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);

        let err = ex
            .run("cheat_x", "scripts/x.asm", Section::Enable)
            .unwrap_err();
        let EngineError::AutoAssemblerError(msg) = err else {
            panic!("expected AutoAssemblerError");
        };
        assert!(
            msg.contains("pattern was not found in module game.exe"),
            "{msg}"
        );
        assert!(msg.contains("cheat: cheat_x"), "{msg}");
        assert!(msg.contains("script: scripts/x.asm"), "{msg}");
        assert!(msg.contains("section: ENABLE"), "{msg}");
        assert!(msg.contains("line: 2"), "{msg}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn aobscan_ambiguous_pattern_errors() {
        let dir = setup_package(&[("scripts/x.asm", "[ENABLE]\naobscan(DUP,90 90)\n")]);
        let mut mem = mock_game();
        let _ = &mut mem;
        mem.plant(0x500000, &[0x90, 0x90]);
        mem.plant(0x500100, &[0x90, 0x90]);
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);
        let err = ex.run("c", "scripts/x.asm", Section::Enable).unwrap_err();
        assert!(err.message().contains("unique match"), "{}", err.message());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn aobscanregion_scans_only_requested_range() {
        let script = r#"
[ENABLE]
aobscanregion(INJECT,game.exe+1000,game.exe+1007,F3 0F 11 83 ?? ?? ?? ??)
registersymbol(INJECT)
"#;
        let dir = setup_package(&[("scripts/x.asm", script)]);
        let mem = mock_game();
        mem.plant(
            0x402000,
            &[0xF3, 0x0F, 0x11, 0x83, 0xAA, 0xBB, 0xCC, 0xDD],
        );
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);

        ex.run("c", "scripts/x.asm", Section::Enable).unwrap();

        assert_eq!(session.lock().unwrap().symbol("INJECT"), Some(0x401000));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsupported_directive_is_explicit_error() {
        let dir = setup_package(&[("scripts/x.asm", "[ENABLE]\ncreatethread(foo)\n")]);
        let mem = mock_game();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);
        let err = ex.run("c", "scripts/x.asm", Section::Enable).unwrap_err();
        assert!(
            err.message()
                .contains("Unsupported Auto Assembler directive: createthread"),
            "{}",
            err.message()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn enable_failure_rolls_back() {
        // The assert fails *after* the aobscan/alloc/registersymbol have run:
        // the alloc must be freed and the symbol removed.
        let script = r#"
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 ?? ?? ?? ??)
alloc(newmem,1024,INJECT)
newmem:
  nop
INJECT:
  db 90 90 90 90 90 90 90 90
registersymbol(INJECT)
assert(INJECT,DE AD BE EF DE AD BE EF)
"#;
        let dir = setup_package(&[("scripts/x.asm", script)]);
        let mem = mock_game();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);
        let err = ex.run("c", "scripts/x.asm", Section::Enable).unwrap_err();
        assert!(err.message().contains("assert failed"), "{}", err.message());
        // Bytes restored, alloc freed, symbol removed.
        assert_eq!(
            mem.peek(0x401000, 8),
            vec![0xF3, 0x0F, 0x11, 0x83, 0x20, 0x01, 0x00, 0x00]
        );
        assert_eq!(mem.frees.borrow().len(), 1);
        let s = session.lock().unwrap();
        assert_eq!(s.symbol("INJECT"), None);
        assert_eq!(s.allocation("newmem"), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn shared_symbols_across_cheats() {
        // Component-style script registers a symbol; another script reads it.
        let base_script = "[ENABLE]\nalloc(sharedmem,256)\nregistersymbol(sharedmem)\n[DISABLE]\nunregistersymbol(sharedmem)\ndealloc(sharedmem)\n";
        let user_script = "[ENABLE]\nassert(sharedmem,00)\n"; // reads the shared symbol
        let dir = setup_package(&[
            ("scripts/common/base.asm", base_script),
            ("scripts/user.asm", user_script),
        ]);
        let mem = mock_game();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);

        ex.run(
            "player_instance",
            "scripts/common/base.asm",
            Section::Enable,
        )
        .unwrap();
        // The second script sees the session symbol without re-scanning.
        ex.run("user_cheat", "scripts/user.asm", Section::Enable)
            .unwrap();
        assert!(session.lock().unwrap().symbol("sharedmem").is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn includes_are_expanded_at_source_level() {
        let helper = "alloc(frominclude,64)\n";
        let main = "[ENABLE]\n{$include common/helper.asm}\nregistersymbol(frominclude)\n";
        let dir = setup_package(&[
            ("scripts/common/helper.asm", helper),
            ("scripts/main.asm", main),
        ]);
        let mem = mock_game();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);
        ex.run("c", "scripts/main.asm", Section::Enable).unwrap();
        assert!(session.lock().unwrap().symbol("frominclude").is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn define_and_module_relative_expressions() {
        let script = r#"
[ENABLE]
define(HEALTH_OFF,00000120)
aobscanmodule(INJECT,game.exe,F3 0F 11 83 ?? ?? ?? ??)
alloc(newmem,1024)
newmem:
  mov rax,game.exe+1000
  mov [newmem+10],eax
  jmp INJECT
INJECT:
  nop 8
registersymbol(newmem)
"#;
        let dir = setup_package(&[("scripts/x.asm", script)]);
        let mem = mock_game();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);
        ex.run("c", "scripts/x.asm", Section::Enable).unwrap();
        // mov rax, game.exe+1000 → mov rax, 0x401000 (48 B8 imm64).
        let nm = mem.peek(ALLOC_BASE, 10);
        assert_eq!(&nm[..2], &[0x48, 0xB8]);
        assert_eq!(u64::from_le_bytes(nm[2..10].try_into().unwrap()), 0x401000);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dq_symbol_reference() {
        // Origin via alloc symbol, dq referencing another alloc symbol.
        let script = "[ENABLE]\nalloc(tbl,64)\nalloc(cave,64)\ntbl:\n  dq cave\n";
        let dir = setup_package(&[("scripts/x.asm", script)]);
        let mem = mock_game();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);
        ex.run("c", "scripts/x.asm", Section::Enable).unwrap();
        let s = session.lock().unwrap();
        let tbl = s.allocation("tbl").unwrap();
        let cave = s.allocation("cave").unwrap();
        drop(s);
        assert_eq!(
            u64::from_le_bytes(mem.peek(tbl, 8).try_into().unwrap()),
            cave as u64
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_symbol_errors_clearly() {
        let dir = setup_package(&[("scripts/x.asm", "[ENABLE]\nassert(nosuchsymbol,00)\n")]);
        let mem = mock_game();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);
        let err = ex.run("c", "scripts/x.asm", Section::Enable).unwrap_err();
        assert!(
            err.message().contains("unknown symbol 'nosuchsymbol'"),
            "{}",
            err.message()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlabeled_code_outside_block_errors() {
        let dir = setup_package(&[("scripts/x.asm", "[ENABLE]\nnop\n")]);
        let mem = mock_game();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);
        let err = ex.run("c", "scripts/x.asm", Section::Enable).unwrap_err();
        assert!(
            err.message().contains("outside a code block"),
            "{}",
            err.message()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn readmem_emits_bytes_from_target() {
        // readmem reads bytes from the process and emits them as data.
        let script = r#"
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 ?? ?? ?? ??)
alloc(newmem,256,INJECT)
newmem:
  readmem(INJECT,5)
INJECT:
  jmp newmem
  nop 3
registersymbol(INJECT)
[DISABLE]
INJECT:
  readmem(INJECT,5)
  nop 3
unregistersymbol(INJECT)
dealloc(newmem)
"#;
        let dir = setup_package(&[("scripts/x.asm", script)]);
        let mem = mock_game();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);
        ex.run("c", "scripts/x.asm", Section::Enable).unwrap();
        // newmem should contain the first 5 bytes of the original instruction:
        // F3 0F 11 83 20
        let nm = mem.peek(ALLOC_BASE, 5);
        assert_eq!(&nm, &[0xF3, 0x0F, 0x11, 0x83, 0x20]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn align_pads_code_block() {
        // align 10,cc should pad to the next multiple of 16 (0x10).
        let script = r#"
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 ?? ?? ?? ??)
alloc(newmem,256,INJECT)
newmem:
  nop
  align 10,cc
  nop
INJECT:
  jmp newmem
  nop 3
registersymbol(INJECT)
[DISABLE]
INJECT:
  db F3 0F 11 83 20 01 00 00
unregistersymbol(INJECT)
dealloc(newmem)
"#;
        let dir = setup_package(&[("scripts/x.asm", script)]);
        let mem = mock_game();
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);
        ex.run("c", "scripts/x.asm", Section::Enable).unwrap();
        // newmem[0] = 90 (nop), newmem[1..15] = CC (align padding), newmem[16] = 90
        let nm = mem.peek(ALLOC_BASE, 17);
        assert_eq!(nm[0], 0x90); // nop
        assert_eq!(nm[1], 0xCC); // align padding
        assert_eq!(nm[15], 0xCC); // last padding byte
        assert_eq!(nm[16], 0x90); // nop after align
        let _ = fs::remove_dir_all(&dir);
    }

    // ==================================================================
    // DOOM (2016) — OpenGL (DOOMx64.exe) trainer script verification.
    //
    // These mirror the fixture scripts in fixtures/trainers/379720/scripts.
    // The script bodies are inlined so the assembly/patch behaviour is
    // verified on every checkout, independent of the git-ignored fixtures.
    // ==================================================================

    /// Mock DOOMx64.exe at `base` (1 MiB span) with `aob` planted at `at`.
    fn doom_vk(at: usize, aob: &[u8]) -> MockMemory {
        let mut mem = MockMemory::new(64);
        mem.add_module("DOOMx64.exe", 0x400000, 0x10_0000);
        mem.plant(at, aob);
        mem
    }

    /// First offset of `needle` in `hay`, panicking with a message if absent.
    fn assert_contains(hay: &[u8], needle: &[u8]) -> usize {
        hay.windows(needle.len())
            .position(|w| w == needle)
            .unwrap_or_else(|| panic!("expected bytes {:02X?} in haystack", needle))
    }

    const DOOM_PLAYER_INSTANCE_ASM: &str = r#"
[ENABLE]
aobscanmodule(_player,DOOMx64.exe,F3 0F 10 81 20 3C 04 00)
alloc(newmem,256,_player)
alloc(_use,8)
label(return)
registersymbol(_player)
registersymbol(_use)

newmem:
  mov [_use],rcx
  movss xmm0,[rcx+0x43C20]
  jmp return

_player:
  jmp newmem
  nop 3

return:

[DISABLE]
_player:
  db F3 0F 10 81 20 3C 04 00

unregistersymbol(_player)
unregistersymbol(_use)
dealloc(_use)
dealloc(newmem)
"#;

    #[test]
    fn doom_player_instance_injects_and_captures_pointer() {
        let aob = [0xF3, 0x0F, 0x10, 0x81, 0x20, 0x3C, 0x04, 0x00];
        let inject = 0x401000usize;
        let mem = doom_vk(inject, &aob);
        let dir = setup_package(&[("scripts/player_instance.asm", DOOM_PLAYER_INSTANCE_ASM)]);
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);

        ex.run(
            "player_instance",
            "scripts/player_instance.asm",
            Section::Enable,
        )
        .unwrap();

        // Injection point: jmp newmem (E9 rel32) + 3 nops.
        let inj = mem.peek(inject, 8);
        assert_eq!(inj[0], 0xE9);
        assert_eq!(&inj[5..8], &[0x90, 0x90, 0x90]);

        // newmem begins with the pointer capture (mov [mem],rcx = 48 89 ...)
        // and contains the replicated original movss somewhere in the page.
        let nm = mem.peek(ALLOC_BASE, 0x1000);
        assert_eq!(&nm[..2], &[0x48, 0x89]);
        assert_ne!(assert_contains(&nm, &aob), usize::MAX);

        // Symbols + allocations registered.
        let s = session.lock().unwrap();
        assert_eq!(s.symbol("_player"), Some(inject));
        assert!(s.symbol("_use").is_some());
        assert!(s.allocation("_use").is_some());
        assert!(s.allocation("newmem").is_some());
        drop(s);

        // Placement: `newmem` honored its explicit near=_player hint, and
        // the no-hint `_use` clustered near the previous alloc (newmem) so
        // `mov [_use],rcx` stays within rel32 reach under Proton.
        let hints = mem.near_hints.borrow();
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0], Some(inject));
        assert_eq!(hints[1], Some(ALLOC_BASE));
        drop(hints);

        // Disable restores the original bytes and cleans up.
        ex.run(
            "player_instance",
            "scripts/player_instance.asm",
            Section::Disable,
        )
        .unwrap();
        assert_eq!(mem.peek(inject, 8), aob.to_vec());
        let s = session.lock().unwrap();
        assert_eq!(s.symbol("_player"), None);
        assert_eq!(s.symbol("_use"), None);
        assert_eq!(s.allocation("_use"), None);
        assert_eq!(s.allocation("newmem"), None);

        let _ = fs::remove_dir_all(&dir);
    }

    const DOOM_UNLIMITED_AMMO_ASM: &str = r#"
[ENABLE]
aobscanmodule(_ammo_fuel,DOOMx64.exe,8B 43 38 48 83 C4 20 5B C3 CC)
alloc(newmem,256,_ammo_fuel)
label(return)
registersymbol(_ammo_fuel)

newmem:
  mov dword ptr [rbx+38],#99
  mov eax,[rbx+38]
  add rsp,0x20
  jmp return

_ammo_fuel:
  jmp newmem
  nop 2

return:

[DISABLE]
_ammo_fuel:
  db 8B 43 38 48 83 C4 20

unregistersymbol(_ammo_fuel)
dealloc(newmem)
"#;

    #[test]
    fn doom_unlimited_ammo_injects_and_forces_99() {
        // AOB tail 5B C3 CC is context only; the 7 hooked bytes are mov+add.
        let aob = [0x8B, 0x43, 0x38, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3, 0xCC];
        let inject = 0x401000usize;
        let mem = doom_vk(inject, &aob);
        let dir = setup_package(&[("scripts/unlimited_ammo.asm", DOOM_UNLIMITED_AMMO_ASM)]);
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);

        ex.run(
            "unlimited_ammo",
            "scripts/unlimited_ammo.asm",
            Section::Enable,
        )
        .unwrap();

        // Injection: jmp newmem (5) + 2 nops = 7 bytes.
        let inj = mem.peek(inject, 7);
        assert_eq!(inj[0], 0xE9);
        assert_eq!(&inj[5..7], &[0x90, 0x90]);

        // newmem: mov dword ptr [rbx+38],0x63 ; mov eax,[rbx+38] ; add rsp,0x20 ; jmp
        let nm = mem.peek(ALLOC_BASE, 19);
        assert_eq!(
            &nm[..14],
            &[0xC7, 0x43, 0x38, 0x63, 0x00, 0x00, 0x00, 0x8B, 0x43, 0x38, 0x48, 0x83, 0xC4, 0x20]
        );
        assert_eq!(nm[14], 0xE9);

        let s = session.lock().unwrap();
        assert_eq!(s.symbol("_ammo_fuel"), Some(inject));
        assert!(s.allocation("newmem").is_some());
        drop(s);

        ex.run(
            "unlimited_ammo",
            "scripts/unlimited_ammo.asm",
            Section::Disable,
        )
        .unwrap();
        assert_eq!(
            mem.peek(inject, 7),
            vec![0x8B, 0x43, 0x38, 0x48, 0x83, 0xC4, 0x20]
        );
        let s = session.lock().unwrap();
        assert_eq!(s.symbol("_ammo_fuel"), None);
        assert_eq!(s.allocation("newmem"), None);

        let _ = fs::remove_dir_all(&dir);
    }

    const DOOM_UNLIMITED_GRENADE_ASM: &str = r#"
[ENABLE]
aobscanmodule(_grenade,DOOMx64.exe,8B 88 50 CB 00 00)
alloc(newmem,256,_grenade)
label(return)
registersymbol(_grenade)

newmem:
  mov dword ptr [rax+0xCB50],#9
  mov ecx,[rax+0xCB50]
  jmp return

_grenade:
  jmp newmem
  nop

return:

[DISABLE]
_grenade:
  db 8B 88 50 CB 00 00

unregistersymbol(_grenade)
dealloc(newmem)
"#;

    #[test]
    fn doom_unlimited_grenade_injects_and_forces_9() {
        let aob = [0x8B, 0x88, 0x50, 0xCB, 0x00, 0x00];
        let inject = 0x401000usize;
        let mem = doom_vk(inject, &aob);
        let dir = setup_package(&[("scripts/unlimited_grenade.asm", DOOM_UNLIMITED_GRENADE_ASM)]);
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);

        ex.run(
            "unlimited_grenade",
            "scripts/unlimited_grenade.asm",
            Section::Enable,
        )
        .unwrap();

        // Injection: jmp newmem (5) + 1 nop = 6 bytes.
        let inj = mem.peek(inject, 6);
        assert_eq!(inj[0], 0xE9);
        assert_eq!(inj[5], 0x90);

        // newmem: mov dword ptr [rax+0xCB50],9 ; mov ecx,[rax+0xCB50] ; jmp
        let nm = mem.peek(ALLOC_BASE, 21);
        assert_eq!(
            &nm[..16],
            &[
                0xC7, 0x80, 0x50, 0xCB, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x8B, 0x88, 0x50, 0xCB,
                0x00, 0x00
            ]
        );
        assert_eq!(nm[16], 0xE9);

        let s = session.lock().unwrap();
        assert_eq!(s.symbol("_grenade"), Some(inject));
        drop(s);

        ex.run(
            "unlimited_grenade",
            "scripts/unlimited_grenade.asm",
            Section::Disable,
        )
        .unwrap();
        assert_eq!(mem.peek(inject, 6), aob.to_vec());

        let _ = fs::remove_dir_all(&dir);
    }

    const DOOM_UNLIMITED_PRAETOR_ASM: &str = r#"
[ENABLE]
aobscanmodule(_praetor_suit_upgrade_points_collected,DOOMx64.exe,01 51 38 8B 71 38)
aobscanmodule(_praetor_suit_upgrade_points_used,DOOMx64.exe,89 7B 38 8B C7)
alloc(newmem_x,256,_praetor_suit_upgrade_points_collected)
alloc(newmem_y,256,_praetor_suit_upgrade_points_used)
label(code_x)
label(return_x)
label(return_y)
registersymbol(_praetor_suit_upgrade_points_collected)
registersymbol(_praetor_suit_upgrade_points_used)

newmem_x:
  mov dword ptr [rcx+38],#9999
code_x:
  add [rcx+38],edx
  mov esi,[rcx+38]
  jmp return_x

_praetor_suit_upgrade_points_collected:
  jmp newmem_x
  nop

return_x:

newmem_y:
  mov dword ptr [rbx+38],#9999
  mov eax,edi
  jmp return_y

_praetor_suit_upgrade_points_used:
  jmp newmem_y

return_y:

[DISABLE]
_praetor_suit_upgrade_points_collected:
  db 01 51 38 8B 71 38

_praetor_suit_upgrade_points_used:
  db 89 7B 38 8B C7

unregistersymbol(_praetor_suit_upgrade_points_collected)
unregistersymbol(_praetor_suit_upgrade_points_used)
dealloc(newmem_x)
dealloc(newmem_y)
"#;

    #[test]
    fn doom_unlimited_praetor_injects_both_hooks_and_forces_9999() {
        let aob_collected = [0x01, 0x51, 0x38, 0x8B, 0x71, 0x38];
        let aob_used = [0x89, 0x7B, 0x38, 0x8B, 0xC7];
        let inject_x = 0x401000usize;
        let inject_y = 0x402000usize;
        let mem = doom_vk(inject_x, &aob_collected);
        mem.plant(inject_y, &aob_used);
        let dir = setup_package(&[(
            "scripts/unlimited_praetor_points.asm",
            DOOM_UNLIMITED_PRAETOR_ASM,
        )]);
        let session = Arc::new(Mutex::new(TrainerSession::new()));
        let mut ex = make_executor(&mem, Arc::clone(&session), &dir);

        ex.run(
            "unlimited_praetor_points",
            "scripts/unlimited_praetor_points.asm",
            Section::Enable,
        )
        .unwrap();

        // Collected hook: jmp (5) + nop (1) = 6 bytes.
        let inj_x = mem.peek(inject_x, 6);
        assert_eq!(inj_x[0], 0xE9);
        assert_eq!(inj_x[5], 0x90);
        // Used hook: jmp (5) exactly fills the 5-byte site.
        let inj_y = mem.peek(inject_y, 5);
        assert_eq!(inj_y[0], 0xE9);

        // newmem_x: mov dword ptr [rcx+38],0x270F ; add [rcx+38],edx ; mov esi,[rcx+38] ; jmp
        let nmx = mem.peek(ALLOC_BASE, 18);
        assert_eq!(
            &nmx[..13],
            &[0xC7, 0x41, 0x38, 0x0F, 0x27, 0x00, 0x00, 0x01, 0x51, 0x38, 0x8B, 0x71, 0x38]
        );
        assert_eq!(nmx[13], 0xE9);

        // newmem_y (second alloc, one page up): mov dword ptr [rbx+38],0x270F ; mov eax,edi ; jmp
        // (iced encodes `mov eax,edi` in store-form 89 F8, equivalent to 8B C7.)
        let nmy = mem.peek(ALLOC_BASE + 0x1000, 14);
        assert_eq!(
            &nmy[..9],
            &[0xC7, 0x43, 0x38, 0x0F, 0x27, 0x00, 0x00, 0x89, 0xF8]
        );
        assert_eq!(nmy[9], 0xE9);

        let s = session.lock().unwrap();
        assert_eq!(
            s.symbol("_praetor_suit_upgrade_points_collected"),
            Some(inject_x)
        );
        assert_eq!(
            s.symbol("_praetor_suit_upgrade_points_used"),
            Some(inject_y)
        );
        assert!(s.allocation("newmem_x").is_some());
        assert!(s.allocation("newmem_y").is_some());
        drop(s);

        ex.run(
            "unlimited_praetor_points",
            "scripts/unlimited_praetor_points.asm",
            Section::Disable,
        )
        .unwrap();
        assert_eq!(mem.peek(inject_x, 6), aob_collected.to_vec());
        assert_eq!(mem.peek(inject_y, 5), aob_used.to_vec());
        let s = session.lock().unwrap();
        assert_eq!(s.symbol("_praetor_suit_upgrade_points_collected"), None);
        assert_eq!(s.symbol("_praetor_suit_upgrade_points_used"), None);
        assert_eq!(s.allocation("newmem_x"), None);
        assert_eq!(s.allocation("newmem_y"), None);

        let _ = fs::remove_dir_all(&dir);
    }
}
