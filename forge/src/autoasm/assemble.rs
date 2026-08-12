//! Intel-syntax x86/x64 text → machine code, backed by iced-x86's
//! `CodeAssembler` (pure Rust).
//!
//! This is deliberately a *subset* assembler covering the instructions that
//! appear in typical Cheat Engine trainer scripts: data movement (mov/lea/
//! xchg/movzx/movsx/movsxd/push/pop), integer ALU (add/sub/cmp/test/and/or/
//! xor/inc/dec/neg/not/shifts/imul), control flow (jmp/call/jcc/ret/nop/
//! int3), and scalar SSE float ops (movss/movsd, add/sub/mul/div, comiss,
//! cvt*). Anything else is an explicit "unsupported instruction" error so the
//! gap is visible and easy to extend.
//!
//! Labels/symbols are *not* resolved here: the caller passes a lookup
//! function, and all branch targets are assembled as absolute addresses
//! (near rel32 form — deterministic 5/6-byte encodings, CE parity).

use iced_x86::code_asm::*;
use iced_x86::{IcedError, Register};

use super::expr::{self, BareNumbers};

/// A parsed register operand (typed wrapper needed by CodeAssembler).
#[derive(Debug, Clone, Copy)]
pub enum RegOp {
    R8(AsmRegister8),
    R16(AsmRegister16),
    R32(AsmRegister32),
    R64(AsmRegister64),
    Xmm(AsmRegisterXmm),
    St(AsmRegisterSt),
}

impl RegOp {
    /// The plain iced register (for memory-operand construction).
    fn register(self) -> Register {
        match self {
            RegOp::R8(r) => r.into(),
            RegOp::R16(r) => r.into(),
            RegOp::R32(r) => r.into(),
            RegOp::R64(r) => r.into(),
            RegOp::Xmm(r) => r.into(),
            RegOp::St(r) => r.into(),
        }
    }
}

/// A parsed instruction operand.
#[derive(Debug, Clone, Copy)]
enum Opnd {
    Reg(RegOp),
    Mem(AsmMemoryOperand),
    /// Immediate or branch target. Kept as i128 so range checks happen at
    /// the point we know the required width.
    Imm(i128),
}

/// Parse a register name (case-insensitive) into a [`RegOp`].
fn parse_register(name: &str) -> Option<RegOp> {
    macro_rules! map {
        ($n:expr, $variant:ident, $($r:ident),+) => {
            match $n { $(stringify!($r) => Some(RegOp::$variant($r)),)+ _ => None }
        };
    }
    let n = name.to_ascii_lowercase();
    if let Some(r) = map!(
        n.as_str(),
        R64,
        rax,
        rcx,
        rdx,
        rbx,
        rsp,
        rbp,
        rsi,
        rdi,
        r8,
        r9,
        r10,
        r11,
        r12,
        r13,
        r14,
        r15
    ) {
        return Some(r);
    }
    if let Some(r) = map!(
        n.as_str(),
        R32,
        eax,
        ecx,
        edx,
        ebx,
        esp,
        ebp,
        esi,
        edi,
        r8d,
        r9d,
        r10d,
        r11d,
        r12d,
        r13d,
        r14d,
        r15d
    ) {
        return Some(r);
    }
    if let Some(r) = map!(
        n.as_str(),
        R16,
        ax,
        cx,
        dx,
        bx,
        sp,
        bp,
        si,
        di,
        r8w,
        r9w,
        r10w,
        r11w,
        r12w,
        r13w,
        r14w,
        r15w
    ) {
        return Some(r);
    }
    if let Some(r) = map!(
        n.as_str(),
        R8,
        al,
        cl,
        dl,
        bl,
        spl,
        bpl,
        sil,
        dil,
        ah,
        ch,
        dh,
        bh,
        r8b,
        r9b,
        r10b,
        r11b,
        r12b,
        r13b,
        r14b,
        r15b
    ) {
        return Some(r);
    }
    if let Some(r) = map!(
        n.as_str(),
        Xmm,
        xmm0,
        xmm1,
        xmm2,
        xmm3,
        xmm4,
        xmm5,
        xmm6,
        xmm7,
        xmm8,
        xmm9,
        xmm10,
        xmm11,
        xmm12,
        xmm13,
        xmm14,
        xmm15
    ) {
        return Some(r);
    }
    // x87 FPU registers: st0-st7 (also accept CE syntax st(0)-st(7)).
    if let Some(r) = map!(n.as_str(), St, st0, st1, st2, st3, st4, st5, st6, st7) {
        return Some(r);
    }
    // CE writes st(0) instead of st0; handle the parenthesized form.
    if let Some(rest) = n.strip_prefix("st(") {
        if let Some(num) = rest.strip_suffix(')') {
            return match num {
                "0" => Some(RegOp::St(st0)),
                "1" => Some(RegOp::St(st1)),
                "2" => Some(RegOp::St(st2)),
                "3" => Some(RegOp::St(st3)),
                "4" => Some(RegOp::St(st4)),
                "5" => Some(RegOp::St(st5)),
                "6" => Some(RegOp::St(st6)),
                "7" => Some(RegOp::St(st7)),
                _ => None,
            };
        }
    }
    None
}

/// Memory size hints (`qword ptr [...]` etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemSize {
    None,
    Byte,
    Word,
    Dword,
    Qword,
    Xword,
    Tbyte,
}

impl MemSize {
    fn apply(self, m: AsmMemoryOperand) -> AsmMemoryOperand {
        match self {
            MemSize::None => ptr(m),
            MemSize::Byte => byte_ptr(m),
            MemSize::Word => word_ptr(m),
            MemSize::Dword => dword_ptr(m),
            MemSize::Qword => qword_ptr(m),
            MemSize::Xword => xmmword_ptr(m),
            MemSize::Tbyte => tbyte_ptr(m),
        }
    }
}

/// Split operands on top-level commas (bracket/quote aware).
fn split_operands(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_squote = false;
    let mut in_dquote = false;
    let mut start = 0;
    let bytes = text.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        match c {
            b'\'' if !in_dquote => in_squote = !in_squote,
            b'"' if !in_squote => in_dquote = !in_dquote,
            b'[' | b'(' if !in_squote && !in_dquote => depth += 1,
            b']' | b')' if !in_squote && !in_dquote => depth -= 1,
            b',' if depth == 0 && !in_squote && !in_dquote => {
                out.push(text[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = text[start..].trim();
    if !last.is_empty() || !out.is_empty() {
        out.push(last);
    }
    out
}

/// Parse one operand text into an [`Opnd`].
fn parse_operand(
    text: &str,
    bitness: u32,
    lookup: &dyn Fn(&str) -> Option<u64>,
    rip_base: u64,
    used_rip: &mut bool,
) -> Result<Opnd, String> {
    let mut t = text.trim();

    // Size hints: "qword ptr [..]", "dword [..]", ...
    let mut size = MemSize::None;
    for (words, s) in [
        ("xmmword", MemSize::Xword),
        ("tbyte", MemSize::Tbyte),
        ("qword", MemSize::Qword),
        ("dword", MemSize::Dword),
        ("word", MemSize::Word),
        ("byte", MemSize::Byte),
    ] {
        if let Some(rest) = strip_prefix_ci(t, words) {
            if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                let rest = rest.trim_start();
                let rest = strip_prefix_ci(rest, "ptr")
                    .map(|r| r.trim_start())
                    .unwrap_or(rest);
                t = rest;
                size = s;
                break;
            }
        }
    }

    // Memory operand.
    if let Some(open) = t.find('[') {
        let close = t.rfind(']').ok_or("unbalanced '[' in memory operand")?;
        if close < open || !t[close + 1..].trim().is_empty() || !t[..open].trim().is_empty() {
            return Err(format!("malformed memory operand '{text}'"));
        }
        let inner = &t[open + 1..close];
        let mem = parse_memory(inner, bitness, lookup, rip_base, used_rip)?;
        return Ok(Opnd::Mem(size.apply(mem)));
    }

    // Register.
    if let Some(r) = parse_register(t) {
        return Ok(Opnd::Reg(r));
    }

    // Immediate / address expression.
    let v = expr::eval_i128(t, BareNumbers::Hex, lookup)?;
    Ok(Opnd::Imm(v))
}

fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    if text.len() >= prefix.len() && text[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&text[prefix.len()..])
    } else {
        None
    }
}

/// Parse `[base + index*scale + disp]` into an AsmMemoryOperand (no size).
///
/// iced's rip-relative memory operands take the *absolute target address* as
/// displacement; `rip_base` is the address RIP will hold when the instruction
/// executes (= address of the *next* instruction, supplied by the two-pass
/// assembly above).
fn parse_memory(
    inner: &str,
    bitness: u32,
    lookup: &dyn Fn(&str) -> Option<u64>,
    rip_base: u64,
    used_rip: &mut bool,
) -> Result<AsmMemoryOperand, String> {
    // Split into +/- terms; the first may be negative.
    let mut base: Option<RegOp> = None;
    let mut index: Option<(RegOp, u32)> = None;
    let mut rip_rel = false;
    let mut disp_parts: Vec<(bool, String)> = Vec::new(); // (subtract, text)

    let mut depth = 0i32;
    let mut start = 0;
    let mut pending_neg = false;
    let bytes = inner.as_bytes();
    let mut terms: Vec<(bool, &str)> = Vec::new();
    let mut i = 0;
    while i <= bytes.len() {
        let at_end = i == bytes.len();
        let c = if at_end { b'+' } else { bytes[i] };
        match c {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b'+' | b'-' if depth == 0 || at_end => {
                let t = inner[start..i].trim();
                if !t.is_empty() {
                    terms.push((pending_neg, t));
                }
                pending_neg = c == b'-';
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }

    for (neg, t) in terms {
        // register * scale?
        if let Some(star) = t.find('*') {
            let reg_name = t[..star].trim();
            let scale_text = t[star + 1..].trim();
            if let Some(r) = parse_register(reg_name) {
                let scale: u32 = scale_text
                    .parse()
                    .map_err(|_| format!("invalid scale '{scale_text}'"))?;
                if ![1, 2, 4, 8].contains(&scale) {
                    return Err(format!("invalid scale {scale} (must be 1, 2, 4 or 8)"));
                }
                if index.is_some() {
                    return Err("memory operand has two index registers".into());
                }
                if neg {
                    return Err("index register cannot be negated".into());
                }
                index = Some((r, scale));
                continue;
            }
            // Not reg*scale → part of the displacement expression.
            disp_parts.push((neg, t.to_string()));
            continue;
        }
        let lower = t.to_ascii_lowercase();
        if lower == "rip" || lower == "eip" {
            if neg || rip_rel || base.is_some() {
                return Err("invalid rip/eip-relative operand".into());
            }
            rip_rel = true;
            continue;
        }
        if let Some(r) = parse_register(t) {
            if neg {
                return Err("register term cannot be negated".into());
            }
            match r {
                RegOp::R64(_) | RegOp::R32(_) => {
                    if base.is_none() {
                        base = Some(r);
                    } else if index.is_none() {
                        index = Some((r, 1));
                    } else {
                        return Err("too many registers in memory operand".into());
                    }
                }
                _ => return Err("base/index must be a 32/64-bit register".into()),
            }
            continue;
        }
        disp_parts.push((neg, t.to_string()));
    }

    // Evaluate displacement as an expression (terms joined with signs).
    let mut disp: i128 = 0;
    for (neg, t) in &disp_parts {
        let v = expr::eval_i128(t, BareNumbers::Hex, lookup)?;
        disp += if *neg { -v } else { v };
    }
    let disp_i64 = i64::try_from(disp).map_err(|_| "displacement out of range".to_string())?;

    let expect64 = bitness == 64;

    if rip_rel {
        if index.is_some() {
            return Err("rip-relative addressing cannot have an index register".into());
        }
        *used_rip = true;
        // iced wants the absolute target: RIP at execution end + displacement.
        let target = (rip_base as i128 + disp) as i64;
        let m = AsmMemoryOperand::from(if expect64 {
            Register::RIP
        } else {
            Register::EIP
        });
        return Ok(m + target);
    }

    if let Some(b) = base {
        match (expect64, b) {
            (true, RegOp::R64(_)) | (false, RegOp::R32(_)) => {}
            _ => return Err("address register size does not match target bitness".into()),
        }
        if let Some((idx, scale)) = index {
            let imem = match (expect64, idx) {
                (true, RegOp::R64(r)) => r * scale as i32,
                (false, RegOp::R32(r)) => r * scale as i32,
                _ => return Err("index register size does not match target bitness".into()),
            };
            let combined = match b {
                RegOp::R64(bw) => bw + imem,
                RegOp::R32(bw) => bw + imem,
                _ => unreachable!(),
            };
            Ok(combined + disp_i64)
        } else {
            let m = AsmMemoryOperand::from(b.register());
            Ok(m + disp_i64)
        }
    } else if let Some((idx, scale)) = index {
        // [index*scale + disp]
        let imem = match (expect64, idx) {
            (true, RegOp::R64(r)) => r * scale as i32,
            (false, RegOp::R32(r)) => r * scale as i32,
            _ => return Err("index register size does not match target bitness".into()),
        };
        Ok(imem + disp_i64)
    } else {
        // [disp] absolute. x86-64 has no absolute disp32 form for addresses
        // that don't fit i32 — Cheat Engine assembles `[symbol]` as
        // RIP-relative in 64-bit, so do the same. (CE-table symbols are
        // alloc'd near the injection point, keeping them in rel32 reach.)
        if expect64 && i32::try_from(disp_i64).is_err() {
            *used_rip = true;
            // iced's rip-relative operands take the absolute target address.
            let m = AsmMemoryOperand::from(Register::RIP);
            return Ok(m + disp_i64);
        }
        Ok(AsmMemoryOperand::from(disp_i64))
    }
}

// ---------------------------------------------------------------------------
// Instruction assembly
// ---------------------------------------------------------------------------

type Lk<'a> = &'a dyn Fn(&str) -> Option<u64>;

/// Assemble one instruction line at `base_ip`. Returns the encoded bytes.
///
/// `[rip+x]` needs two passes: iced expects the *absolute target* in a
/// rip-relative operand, but the target depends on the instruction length.
/// Pass 1 measures the length; pass 2 (only when rip-relative) re-emits with
/// the corrected target. Length is stable between passes (rip+disp32 form).
pub fn assemble_instr(
    bitness: u32,
    base_ip: u64,
    text: &str,
    lookup: Lk,
) -> Result<Vec<u8>, String> {
    let mut a = CodeAssembler::new(bitness).map_err(|e| e.to_string())?;
    let used_rip = emit_instr(&mut a, text, lookup, base_ip)?;
    let bytes = a.assemble(base_ip).map_err(|e| e.to_string())?;
    if !used_rip {
        return Ok(bytes);
    }
    let mut a = CodeAssembler::new(bitness).map_err(|e| e.to_string())?;
    emit_instr(&mut a, text, lookup, base_ip + bytes.len() as u64)?;
    a.assemble(base_ip).map_err(|e| e.to_string())
}

/// Compute the size of an instruction at `base_ip` without emitting.
pub fn instr_size(bitness: u32, base_ip: u64, text: &str, lookup: Lk) -> Result<usize, String> {
    Ok(assemble_instr(bitness, base_ip, text, lookup)?.len())
}

/// Mnemonics the subset assembler supports. Checked before operand parsing so
/// unknown instructions produce a clear error instead of confusing
/// operand-level failures.
const SUPPORTED_MNEMONICS: &[&str] = &[
    "mov",
    "lea",
    "xchg",
    "movzx",
    "movsx",
    "movsxd",
    "push",
    "pop",
    "pushfq",
    "pushfd",
    "popfq",
    "popfd",
    "add",
    "or",
    "adc",
    "sbb",
    "and",
    "sub",
    "xor",
    "cmp",
    "test",
    "inc",
    "dec",
    "neg",
    "not",
    "mul",
    "div",
    "idiv",
    "imul",
    "shl",
    "sal",
    "shr",
    "sar",
    "rol",
    "ror",
    "jmp",
    "call",
    "ret",
    "nop",
    "int3",
    "cdqe",
    "cqo",
    "ja",
    "jnbe",
    "jae",
    "jnc",
    "jnb",
    "jb",
    "jc",
    "jnae",
    "jbe",
    "jna",
    "je",
    "jz",
    "jne",
    "jnz",
    "jg",
    "jnle",
    "jge",
    "jnl",
    "jl",
    "jnge",
    "jle",
    "jng",
    "jo",
    "jno",
    "js",
    "jns",
    "jp",
    "jpe",
    "jnp",
    "jpo",
    "movss",
    "movsd",
    "movaps",
    "movups",
    "movapd",
    "movupd",
    "movdqa",
    "movdqu",
    "addss",
    "subss",
    "mulss",
    "divss",
    "addsd",
    "subsd",
    "mulsd",
    "divsd",
    "minss",
    "maxss",
    "minsd",
    "maxsd",
    "sqrtss",
    "sqrtsd",
    "comiss",
    "ucomiss",
    "comisd",
    "ucomisd",
    "xorps",
    "xorpd",
    "pxor",
    "cvtss2sd",
    "cvtsd2ss",
    "cvtsi2ss",
    "cvtsi2sd",
    "cvttss2si",
    "cvtss2si",
    "cvttsd2si",
    "cvtsd2si",
    "movd",
    "movq",
    // --- x87 FPU -------------------------------------------------------
    "fld",
    "fst",
    "fstp",
    "fild",
    "fist",
    "fistp",
    "fldz",
    "fld1",
    "fldpi",
    "fldl2e",
    "fldl2t",
    "fldlg2",
    "fldln2",
    "fadd",
    "faddp",
    "fsub",
    "fsubp",
    "fsubr",
    "fsubrp",
    "fmul",
    "fmulp",
    "fdiv",
    "fdivp",
    "fdivr",
    "fdivrp",
    "fcom",
    "fcomp",
    "fcompp",
    "fucom",
    "fucomp",
    "fucompp",
    "fxch",
    "ffree",
    "fnop",
    "fdecstp",
    "fincstp",
    "fnstsw",
    "fnstcw",
    "fstpnce",
    // --- conditional move ----------------------------------------------
    "cmova",
    "cmovae",
    "cmovb",
    "cmovbe",
    "cmovc",
    "cmove",
    "cmovg",
    "cmovge",
    "cmovl",
    "cmovle",
    "cmovna",
    "cmovnae",
    "cmovnb",
    "cmovnbe",
    "cmovnc",
    "cmovne",
    "cmovng",
    "cmovnge",
    "cmovnl",
    "cmovnle",
    "cmovno",
    "cmovnp",
    "cmovns",
    "cmovnz",
    "cmovo",
    "cmovp",
    "cmovpe",
    "cmovpo",
    "cmovs",
    "cmovz",
    // --- set-byte-on-condition ----------------------------------------
    "seta",
    "setae",
    "setb",
    "setbe",
    "setc",
    "sete",
    "setg",
    "setge",
    "setl",
    "setle",
    "setna",
    "setnae",
    "setnb",
    "setnbe",
    "setnc",
    "setne",
    "setng",
    "setnge",
    "setnl",
    "setnle",
    "setno",
    "setnp",
    "setns",
    "setnz",
    "seto",
    "setp",
    "setpe",
    "setpo",
    "sets",
    "setz",
];

fn emit_instr(
    a: &mut CodeAssembler,
    text: &str,
    lookup: Lk,
    rip_base: u64,
) -> Result<bool, String> {
    let text = text.trim();
    let (mnemonic, rest) = match text.find(char::is_whitespace) {
        Some(i) => (text[..i].to_ascii_lowercase(), text[i..].trim()),
        None => (text.to_ascii_lowercase(), ""),
    };
    if !SUPPORTED_MNEMONICS.contains(&mnemonic.as_str()) {
        return Err(format!(
            "unsupported instruction '{mnemonic}' — the Auto Assembler subset \
             does not implement it yet"
        ));
    }
    let mut used_rip = false;
    let ops: Vec<Opnd> = if rest.is_empty() {
        Vec::new()
    } else {
        split_operands(rest)
            .iter()
            .map(|o| parse_operand(o, a.bitness(), lookup, rip_base, &mut used_rip))
            .collect::<Result<_, _>>()?
    };

    dispatch(a, &mnemonic, &ops, text)?;
    Ok(used_rip)
}

fn err_iced(r: Result<(), IcedError>) -> Result<(), String> {
    r.map_err(|e| e.to_string())
}

/// Map an operand count error.
fn arity(text: &str, got: usize, want: &str) -> Result<(), String> {
    Err(format!("'{text}': expected {want} operand(s), got {got}"))
}

// --- dispatch macros --------------------------------------------------------

/// reg,reg — all four GPR classes must match.
macro_rules! rr {
    ($a:ident.$m:ident, $d:expr, $s:expr) => {{
        match ($d, $s) {
            (RegOp::R8(d), RegOp::R8(s)) => err_iced($a.$m(d, s)),
            (RegOp::R16(d), RegOp::R16(s)) => err_iced($a.$m(d, s)),
            (RegOp::R32(d), RegOp::R32(s)) => err_iced($a.$m(d, s)),
            (RegOp::R64(d), RegOp::R64(s)) => err_iced($a.$m(d, s)),
            _ => Err("operand size mismatch".into()),
        }
    }};
}

/// reg,mem
macro_rules! rm {
    ($a:ident.$m:ident, $d:expr, $s:expr) => {{
        match $d {
            RegOp::R8(d) => err_iced($a.$m(d, $s)),
            RegOp::R16(d) => err_iced($a.$m(d, $s)),
            RegOp::R32(d) => err_iced($a.$m(d, $s)),
            RegOp::R64(d) => err_iced($a.$m(d, $s)),
            _ => Err("expected a register destination".into()),
        }
    }};
}

/// mem,reg
macro_rules! mr {
    ($a:ident.$m:ident, $d:expr, $s:expr) => {{
        match $s {
            RegOp::R8(s) => err_iced($a.$m($d, s)),
            RegOp::R16(s) => err_iced($a.$m($d, s)),
            RegOp::R32(s) => err_iced($a.$m($d, s)),
            RegOp::R64(s) => err_iced($a.$m($d, s)),
            _ => Err("expected a register source".into()),
        }
    }};
}

/// Wrap an immediate to the register's width as the i32/u32/i64/u64 the impl
/// expects. ALU ops take imm8/16/32 (sign-extended); mov r64 also has imm64.
macro_rules! ri {
    ($a:ident.$m:ident, $d:expr, $s:expr, $text:expr) => {{
        match $d {
            RegOp::R8(d) => {
                let v = $s as i64;
                if !(-128..=255).contains(&v) {
                    Err(format!(
                        "'{}': immediate {:#X} doesn't fit 8 bits",
                        $text, $s
                    ))
                } else {
                    err_iced($a.$m(d, v as i32))
                }
            }
            RegOp::R16(d) => {
                let v = $s as i64;
                if !(-32768..=65535).contains(&v) {
                    Err(format!(
                        "'{}': immediate {:#X} doesn't fit 16 bits",
                        $text, $s
                    ))
                } else {
                    err_iced($a.$m(d, v as i32))
                }
            }
            RegOp::R32(d) => err_iced($a.$m(d, $s as u32 as i32)),
            RegOp::R64(d) => {
                let v = $s;
                if v >= i32::MIN as i128 && v <= u32::MAX as i128 {
                    err_iced($a.$m(d, v as u32 as i32))
                } else {
                    Err(format!(
                        "'{}': 64-bit immediate not supported for this instruction",
                        $text
                    ))
                }
            }
            _ => Err("expected a register destination".into()),
        }
    }};
}

/// mem,imm — always imm32 (x86 has no imm64-to-memory form).
macro_rules! mi {
    ($a:ident.$m:ident, $d:expr, $s:expr, $text:expr) => {{
        let v = $s;
        if v < i32::MIN as i128 || v > u32::MAX as i128 {
            Err(format!("'{}': immediate must fit 32 bits", $text))
        } else if v >= i32::MIN as i128 && v <= i32::MAX as i128 {
            err_iced($a.$m($d, v as i32))
        } else {
            err_iced($a.$m($d, v as u32))
        }
    }};
}

/// Full binary-op set: (r,r) (r,m) (m,r) (r,imm) (m,imm).
macro_rules! binop {
    ($a:ident.$m:ident, $ops:expr, $text:expr) => {{
        match $ops {
            [Opnd::Reg(d), Opnd::Reg(s)] => rr!($a.$m, *d, *s),
            [Opnd::Reg(d), Opnd::Mem(s)] => rm!($a.$m, *d, *s),
            [Opnd::Mem(d), Opnd::Reg(s)] => mr!($a.$m, *d, *s),
            [Opnd::Reg(d), Opnd::Imm(s)] => ri!($a.$m, *d, *s, $text),
            [Opnd::Mem(d), Opnd::Imm(s)] => mi!($a.$m, *d, *s, $text),
            _ => arity($text, $ops.len(), "2 (register/memory/immediate)"),
        }
    }};
}

/// xmm binary op: (xmm,xmm) (xmm,mem).
macro_rules! xmmop {
    ($a:ident.$m:ident, $ops:expr, $text:expr) => {{
        match $ops {
            [Opnd::Reg(RegOp::Xmm(d)), Opnd::Reg(RegOp::Xmm(s))] => err_iced($a.$m(*d, *s)),
            [Opnd::Reg(RegOp::Xmm(d)), Opnd::Mem(s)] => err_iced($a.$m(*d, *s)),
            _ => arity($text, $ops.len(), "2 (xmm, xmm/memory)"),
        }
    }};
}

/// xmm move: (xmm,xmm) (xmm,mem) (mem,xmm).
macro_rules! xmmmov {
    ($a:ident.$m:ident, $ops:expr, $text:expr) => {{
        match $ops {
            [Opnd::Reg(RegOp::Xmm(d)), Opnd::Reg(RegOp::Xmm(s))] => err_iced($a.$m(*d, *s)),
            [Opnd::Reg(RegOp::Xmm(d)), Opnd::Mem(s)] => err_iced($a.$m(*d, *s)),
            [Opnd::Mem(d), Opnd::Reg(RegOp::Xmm(s))] => err_iced($a.$m(*d, *s)),
            _ => arity($text, $ops.len(), "2 (xmm/memory)"),
        }
    }};
}

/// Branch to absolute target: jmp/call/jcc.
macro_rules! branch {
    ($a:ident.$m:ident, $ops:expr, $text:expr) => {{
        match $ops {
            [Opnd::Imm(t)] => {
                let t = u64::try_from(*t)
                    .map_err(|_| format!("'{}': negative branch target", $text))?;
                err_iced($a.$m(t))
            }
            [Opnd::Reg(RegOp::R64(r))] => err_iced($a.$m(*r)),
            [Opnd::Reg(RegOp::R32(r))] => err_iced($a.$m(*r)),
            [Opnd::Mem(m)] => err_iced($a.$m(*m)),
            _ => arity($text, $ops.len(), "1 (address)"),
        }
    }};
}

/// Conditional jump: address target only (rel8/rel32 — no indirect forms).
macro_rules! jcc {
    ($a:ident.$m:ident, $ops:expr, $text:expr) => {{
        match $ops {
            [Opnd::Imm(t)] => {
                let t = u64::try_from(*t)
                    .map_err(|_| format!("'{}': negative branch target", $text))?;
                err_iced($a.$m(t))
            }
            _ => arity($text, $ops.len(), "1 (address)"),
        }
    }};
}

/// Single-operand ops: (r) or (m).
macro_rules! unary {
    ($a:ident.$m:ident, $ops:expr, $text:expr) => {{
        match $ops {
            [Opnd::Reg(r)] => match r {
                RegOp::R8(r) => err_iced($a.$m(*r)),
                RegOp::R16(r) => err_iced($a.$m(*r)),
                RegOp::R32(r) => err_iced($a.$m(*r)),
                RegOp::R64(r) => err_iced($a.$m(*r)),
                _ => Err("expected a GPR".into()),
            },
            [Opnd::Mem(m)] => err_iced($a.$m(*m)),
            _ => arity($text, $ops.len(), "1"),
        }
    }};
}

// ---------------------------------------------------------------------------
// x87 FPU / cmov / setcc dispatch macros
// ---------------------------------------------------------------------------

/// x87 1-operand: accepts memory or FPU register (st0-st7).
macro_rules! fpu_mem_or_st {
    ($a:ident.$m:ident, $ops:expr, $text:expr) => {{
        match $ops {
            [Opnd::Mem(m)] => err_iced($a.$m(*m)),
            [Opnd::Reg(RegOp::St(r))] => err_iced($a.$m(*r)),
            _ => arity($text, $ops.len(), "1 (memory or st register)"),
        }
    }};
}

/// x87 1-operand: memory only (fild, fist, fistp, fnstcw).
macro_rules! fpu_mem_only {
    ($a:ident.$m:ident, $ops:expr, $text:expr) => {{
        match $ops {
            [Opnd::Mem(m)] => err_iced($a.$m(*m)),
            _ => arity($text, $ops.len(), "1 (memory)"),
        }
    }};
}

/// x87 1-operand: FPU register only (fxch, ffree, fucom, fucomp).
macro_rules! fpu_st_only {
    ($a:ident.$m:ident, $ops:expr, $text:expr) => {{
        match $ops {
            [Opnd::Reg(RegOp::St(r))] => err_iced($a.$m(*r)),
            _ => arity($text, $ops.len(), "1 (st register)"),
        }
    }};
}

/// x87 0-operand (fldz, fld1, fcompp, fnop, etc.).
macro_rules! no_op {
    ($a:ident.$m:ident, $ops:expr, $text:expr) => {{
        match $ops {
            [] => err_iced($a.$m()),
            _ => arity($text, $ops.len(), "0"),
        }
    }};
}

/// cmovXX: (r16/32/64, r16/32/64) or (r16/32/64, mem). No 8-bit forms.
macro_rules! cmov_op {
    ($a:ident.$m:ident, $ops:expr, $text:expr) => {{
        match $ops {
            [Opnd::Reg(d), Opnd::Reg(s)] => match (d, s) {
                (RegOp::R16(d), RegOp::R16(s)) => err_iced($a.$m(*d, *s)),
                (RegOp::R32(d), RegOp::R32(s)) => err_iced($a.$m(*d, *s)),
                (RegOp::R64(d), RegOp::R64(s)) => err_iced($a.$m(*d, *s)),
                _ => Err("cmov: register size mismatch".into()),
            },
            [Opnd::Reg(d), Opnd::Mem(s)] => match d {
                RegOp::R16(d) => err_iced($a.$m(*d, *s)),
                RegOp::R32(d) => err_iced($a.$m(*d, *s)),
                RegOp::R64(d) => err_iced($a.$m(*d, *s)),
                _ => Err("cmov: destination must be 16/32/64-bit register".into()),
            },
            _ => arity($text, $ops.len(), "2 (reg, reg/mem)"),
        }
    }};
}

/// setXX: (r8) or (mem).
macro_rules! setcc_op {
    ($a:ident.$m:ident, $ops:expr, $text:expr) => {{
        match $ops {
            [Opnd::Reg(RegOp::R8(r))] => err_iced($a.$m(*r)),
            [Opnd::Mem(m)] => err_iced($a.$m(*m)),
            _ => arity($text, $ops.len(), "1 (r8 or memory)"),
        }
    }};
}

/// The main mnemonic dispatch.
fn dispatch(a: &mut CodeAssembler, mn: &str, ops: &[Opnd], text: &str) -> Result<(), String> {
    match mn {
        // --- data movement ---------------------------------------------------
        "mov" => mov_op(a, ops, text),
        "lea" => match ops {
            [Opnd::Reg(d), Opnd::Mem(s)] => match d {
                RegOp::R16(d) => err_iced(a.lea(*d, *s)),
                RegOp::R32(d) => err_iced(a.lea(*d, *s)),
                RegOp::R64(d) => err_iced(a.lea(*d, *s)),
                _ => Err("lea: destination must be a 16/32/64-bit register".into()),
            },
            _ => arity(text, ops.len(), "2 (register, memory)"),
        },
        "xchg" => {
            match ops {
                [Opnd::Reg(d), Opnd::Reg(s)] => rr!(a.xchg, *d, *s),
                // iced exposes xchg as (mem, reg); xchg r,m is the same encoding.
                [Opnd::Reg(d), Opnd::Mem(s)] => mr!(a.xchg, *s, *d),
                [Opnd::Mem(d), Opnd::Reg(s)] => mr!(a.xchg, *d, *s),
                _ => arity(text, ops.len(), "2"),
            }
        }
        "movzx" => extend_op(a, MovKind::Movzx, ops, text),
        "movsx" => extend_op(a, MovKind::Movsx, ops, text),
        "movsxd" => extend_op(a, MovKind::Movsxd, ops, text),

        // --- stack -------------------------------------------------------------
        "push" => match ops {
            [Opnd::Reg(RegOp::R64(r))] => err_iced(a.push(*r)),
            [Opnd::Reg(RegOp::R32(r))] => err_iced(a.push(*r)),
            [Opnd::Reg(RegOp::R16(r))] => err_iced(a.push(*r)),
            [Opnd::Mem(m)] => err_iced(a.push(*m)),
            [Opnd::Imm(v)] => {
                let v32 = i32::try_from(*v)
                    .or_else(|_| u32::try_from(*v).map(|u| u as i32))
                    .map_err(|_| format!("'{text}': push immediate must fit 32 bits"))?;
                err_iced(a.push(v32))
            }
            _ => arity(text, ops.len(), "1"),
        },
        "pop" => match ops {
            [Opnd::Reg(RegOp::R64(r))] => err_iced(a.pop(*r)),
            [Opnd::Reg(RegOp::R32(r))] => err_iced(a.pop(*r)),
            [Opnd::Reg(RegOp::R16(r))] => err_iced(a.pop(*r)),
            [Opnd::Mem(m)] => err_iced(a.pop(*m)),
            _ => arity(text, ops.len(), "1"),
        },
        "pushfq" | "pushfd" => err_iced(a.pushfq()),
        "popfq" | "popfd" => err_iced(a.popfq()),

        // --- integer ALU --------------------------------------------------------
        "add" => binop!(a.add, ops, text),
        "or" => binop!(a.or, ops, text),
        "adc" => binop!(a.adc, ops, text),
        "sbb" => binop!(a.sbb, ops, text),
        "and" => binop!(a.and, ops, text),
        "sub" => binop!(a.sub, ops, text),
        "xor" => binop!(a.xor, ops, text),
        "cmp" => binop!(a.cmp, ops, text),
        // test has no (r,m) form in iced (x86's TEST is r/m, r).
        "test" => match ops {
            [Opnd::Reg(d), Opnd::Reg(s)] => rr!(a.test, *d, *s),
            [Opnd::Reg(d), Opnd::Mem(s)] => mr!(a.test, *s, *d),
            [Opnd::Mem(d), Opnd::Reg(s)] => mr!(a.test, *d, *s),
            [Opnd::Reg(d), Opnd::Imm(s)] => ri!(a.test, *d, *s, text),
            [Opnd::Mem(d), Opnd::Imm(s)] => mi!(a.test, *d, *s, text),
            _ => arity(text, ops.len(), "2"),
        },

        "inc" => unary!(a.inc, ops, text),
        "dec" => unary!(a.dec, ops, text),
        "neg" => unary!(a.neg, ops, text),
        "not" => unary!(a.not, ops, text),
        "mul" => unary!(a.mul, ops, text),
        "div" => unary!(a.div, ops, text),
        "idiv" => unary!(a.idiv, ops, text),

        "imul" => {
            match ops {
                [Opnd::Reg(_)] | [Opnd::Mem(_)] => unary!(a.imul, ops, text),
                // 2-operand form: imul_2, r16/32/64 only.
                [Opnd::Reg(d), Opnd::Reg(s)] => match (d, s) {
                    (RegOp::R16(d), RegOp::R16(s)) => err_iced(a.imul_2(*d, *s)),
                    (RegOp::R32(d), RegOp::R32(s)) => err_iced(a.imul_2(*d, *s)),
                    (RegOp::R64(d), RegOp::R64(s)) => err_iced(a.imul_2(*d, *s)),
                    _ => Err("imul: 2-operand form needs matching 16/32/64-bit registers".into()),
                },
                [Opnd::Reg(d), Opnd::Mem(s)] => match d {
                    RegOp::R16(d) => err_iced(a.imul_2(*d, *s)),
                    RegOp::R32(d) => err_iced(a.imul_2(*d, *s)),
                    RegOp::R64(d) => err_iced(a.imul_2(*d, *s)),
                    _ => Err("imul: 2-operand form needs a 16/32/64-bit destination".into()),
                },
                _ => arity(text, ops.len(), "1 or 2"),
            }
        }

        "shl" | "sal" => shift_op(a, ShiftKind::Shl, ops, text),
        "shr" => shift_op(a, ShiftKind::Shr, ops, text),
        "sar" => shift_op(a, ShiftKind::Sar, ops, text),
        "rol" => shift_op(a, ShiftKind::Rol, ops, text),
        "ror" => shift_op(a, ShiftKind::Ror, ops, text),

        // --- control flow --------------------------------------------------------
        "jmp" => branch!(a.jmp, ops, text),
        "call" => branch!(a.call, ops, text),
        "ret" => match ops {
            [] => err_iced(a.ret()),
            [Opnd::Imm(v)] => err_iced(
                a.ret_1(
                    i32::try_from(*v)
                        .map_err(|_| format!("'{text}': ret immediate must fit 32 bits"))?,
                ),
            ),
            _ => arity(text, ops.len(), "0 or 1"),
        },
        "nop" => {
            match ops {
                [] => err_iced(a.nop()),
                // CE's `nop N` = N single-byte NOPs.
                [Opnd::Imm(n)] => {
                    if *n < 1 || *n > 256 {
                        return Err(format!("'{text}': nop count must be 1..=256"));
                    }
                    for _ in 0..*n {
                        err_iced(a.nop())?;
                    }
                    Ok(())
                }
                _ => arity(text, ops.len(), "0 or 1 (count)"),
            }
        }
        "int3" => err_iced(a.int3()),
        "cdqe" => err_iced(a.cdqe()),
        "cqo" => err_iced(a.cqo()),

        // jcc (aliases mapped to iced mnemonics)
        "ja" | "jnbe" => jcc!(a.ja, ops, text),
        "jae" | "jnc" | "jnb" => jcc!(a.jae, ops, text),
        "jb" | "jc" | "jnae" => jcc!(a.jb, ops, text),
        "jbe" | "jna" => jcc!(a.jbe, ops, text),
        "je" | "jz" => jcc!(a.je, ops, text),
        "jne" | "jnz" => jcc!(a.jne, ops, text),
        "jg" | "jnle" => jcc!(a.jg, ops, text),
        "jge" | "jnl" => jcc!(a.jge, ops, text),
        "jl" | "jnge" => jcc!(a.jl, ops, text),
        "jle" | "jng" => jcc!(a.jle, ops, text),
        "jo" => jcc!(a.jo, ops, text),
        "jno" => jcc!(a.jno, ops, text),
        "js" => jcc!(a.js, ops, text),
        "jns" => jcc!(a.jns, ops, text),
        "jp" | "jpe" => jcc!(a.jp, ops, text),
        "jnp" | "jpo" => jcc!(a.jnp, ops, text),

        // --- scalar SSE ---------------------------------------------------------
        "movss" => xmmmov!(a.movss, ops, text),
        // iced names the string-move instruction `movsd`; SSE2 movsd is movsd_2.
        "movsd" => xmmmov!(a.movsd_2, ops, text),
        "movaps" => xmmmov!(a.movaps, ops, text),
        "movups" => xmmmov!(a.movups, ops, text),
        "movapd" => xmmmov!(a.movapd, ops, text),
        "movupd" => xmmmov!(a.movupd, ops, text),
        "movdqa" => xmmmov!(a.movdqa, ops, text),
        "movdqu" => xmmmov!(a.movdqu, ops, text),

        "addss" => xmmop!(a.addss, ops, text),
        "subss" => xmmop!(a.subss, ops, text),
        "mulss" => xmmop!(a.mulss, ops, text),
        "divss" => xmmop!(a.divss, ops, text),
        "addsd" => xmmop!(a.addsd, ops, text),
        "subsd" => xmmop!(a.subsd, ops, text),
        "mulsd" => xmmop!(a.mulsd, ops, text),
        "divsd" => xmmop!(a.divsd, ops, text),
        "minss" => xmmop!(a.minss, ops, text),
        "maxss" => xmmop!(a.maxss, ops, text),
        "minsd" => xmmop!(a.minsd, ops, text),
        "maxsd" => xmmop!(a.maxsd, ops, text),
        "sqrtss" => xmmop!(a.sqrtss, ops, text),
        "sqrtsd" => xmmop!(a.sqrtsd, ops, text),
        "comiss" => xmmop!(a.comiss, ops, text),
        "ucomiss" => xmmop!(a.ucomiss, ops, text),
        "comisd" => xmmop!(a.comisd, ops, text),
        "ucomisd" => xmmop!(a.ucomisd, ops, text),
        "xorps" => xmmop!(a.xorps, ops, text),
        "xorpd" => xmmop!(a.xorpd, ops, text),
        "pxor" => xmmop!(a.pxor, ops, text),

        "cvtss2sd" => xmmop!(a.cvtss2sd, ops, text),
        "cvtsd2ss" => xmmop!(a.cvtsd2ss, ops, text),
        "cvtsi2ss" => cvt_int_to_float(a, CvtKind::Cvtsi2ss, ops, text),
        "cvtsi2sd" => cvt_int_to_float(a, CvtKind::Cvtsi2sd, ops, text),
        "cvttss2si" => cvt_float_to_int(a, CvtKind::Cvttss2si, ops, text),
        "cvtss2si" => cvt_float_to_int(a, CvtKind::Cvtss2si, ops, text),
        "cvttsd2si" => cvt_float_to_int(a, CvtKind::Cvttsd2si, ops, text),
        "cvtsd2si" => cvt_float_to_int(a, CvtKind::Cvtsd2si, ops, text),

        "movd" | "movq" => movd_movq(a, ops, text),

        // --- x87 FPU ----------------------------------------------------------
        // fld/fst/fstp: accept memory or FPU register (iced has both trait impls).
        "fld" => fpu_mem_or_st!(a.fld, ops, text),
        "fst" => fpu_mem_or_st!(a.fst, ops, text),
        "fstp" => fpu_mem_or_st!(a.fstp, ops, text),
        // fild/fist/fistp: memory only.
        "fild" => fpu_mem_only!(a.fild, ops, text),
        "fist" => fpu_mem_only!(a.fist, ops, text),
        "fistp" => fpu_mem_only!(a.fistp, ops, text),
        // Constants: no operands.
        "fldz" => no_op!(a.fldz, ops, text),
        "fld1" => no_op!(a.fld1, ops, text),
        "fldpi" => no_op!(a.fldpi, ops, text),
        "fldl2e" => no_op!(a.fldl2e, ops, text),
        "fldl2t" => no_op!(a.fldl2t, ops, text),
        "fldlg2" => no_op!(a.fldlg2, ops, text),
        "fldln2" => no_op!(a.fldln2, ops, text),
        // Arithmetic 1-operand: memory only (register form is 2-operand in iced).
        "fadd" => fpu_mem_only!(a.fadd, ops, text),
        "fsub" => fpu_mem_only!(a.fsub, ops, text),
        "fsubr" => fpu_mem_only!(a.fsubr, ops, text),
        "fmul" => fpu_mem_only!(a.fmul, ops, text),
        "fdiv" => fpu_mem_only!(a.fdiv, ops, text),
        "fdivr" => fpu_mem_only!(a.fdivr, ops, text),
        "fcom" => fpu_mem_only!(a.fcom, ops, text),
        "fcomp" => fpu_mem_only!(a.fcomp, ops, text),
        "fcompp" => no_op!(a.fcompp, ops, text),
        "fucompp" => no_op!(a.fucompp, ops, text),
        // 1-operand st register only.
        "ffree" => fpu_st_only!(a.ffree, ops, text),
        "fnop" => no_op!(a.fnop, ops, text),
        "fdecstp" => no_op!(a.fdecstp, ops, text),
        "fincstp" => no_op!(a.fincstp, ops, text),
        "fnstsw" => fpu_fnstsw(a, ops, text),
        "fnstcw" => fpu_mem_only!(a.fnstcw, ops, text),

        // --- conditional move ------------------------------------------------
        "cmova" => cmov_op!(a.cmova, ops, text),
        "cmovae" => cmov_op!(a.cmovae, ops, text),
        "cmovb" => cmov_op!(a.cmovb, ops, text),
        "cmovbe" => cmov_op!(a.cmovbe, ops, text),
        "cmovc" => cmov_op!(a.cmovb, ops, text),
        "cmove" => cmov_op!(a.cmove, ops, text),
        "cmovg" => cmov_op!(a.cmovg, ops, text),
        "cmovge" => cmov_op!(a.cmovge, ops, text),
        "cmovl" => cmov_op!(a.cmovl, ops, text),
        "cmovle" => cmov_op!(a.cmovle, ops, text),
        "cmovna" => cmov_op!(a.cmovbe, ops, text),
        "cmovnae" => cmov_op!(a.cmovb, ops, text),
        "cmovnb" => cmov_op!(a.cmovae, ops, text),
        "cmovnbe" => cmov_op!(a.cmova, ops, text),
        "cmovnc" => cmov_op!(a.cmovae, ops, text),
        "cmovne" => cmov_op!(a.cmovne, ops, text),
        "cmovng" => cmov_op!(a.cmovle, ops, text),
        "cmovnge" => cmov_op!(a.cmovl, ops, text),
        "cmovnl" => cmov_op!(a.cmovge, ops, text),
        "cmovnle" => cmov_op!(a.cmovg, ops, text),
        "cmovno" => cmov_op!(a.cmovno, ops, text),
        "cmovnp" => cmov_op!(a.cmovnp, ops, text),
        "cmovns" => cmov_op!(a.cmovns, ops, text),
        "cmovnz" => cmov_op!(a.cmovne, ops, text),
        "cmovo" => cmov_op!(a.cmovo, ops, text),
        "cmovp" => cmov_op!(a.cmovp, ops, text),
        "cmovpe" => cmov_op!(a.cmovp, ops, text),
        "cmovpo" => cmov_op!(a.cmovnp, ops, text),
        "cmovs" => cmov_op!(a.cmovs, ops, text),
        "cmovz" => cmov_op!(a.cmove, ops, text),

        // --- set-byte-on-condition -------------------------------------------
        "seta" => setcc_op!(a.seta, ops, text),
        "setae" => setcc_op!(a.setae, ops, text),
        "setb" => setcc_op!(a.setb, ops, text),
        "setbe" => setcc_op!(a.setbe, ops, text),
        "setc" => setcc_op!(a.setb, ops, text),
        "sete" => setcc_op!(a.sete, ops, text),
        "setg" => setcc_op!(a.setg, ops, text),
        "setge" => setcc_op!(a.setge, ops, text),
        "setl" => setcc_op!(a.setl, ops, text),
        "setle" => setcc_op!(a.setle, ops, text),
        "setna" => setcc_op!(a.setbe, ops, text),
        "setnae" => setcc_op!(a.setb, ops, text),
        "setnb" => setcc_op!(a.setae, ops, text),
        "setnbe" => setcc_op!(a.seta, ops, text),
        "setnc" => setcc_op!(a.setae, ops, text),
        "setne" => setcc_op!(a.setne, ops, text),
        "setng" => setcc_op!(a.setle, ops, text),
        "setnge" => setcc_op!(a.setl, ops, text),
        "setnl" => setcc_op!(a.setge, ops, text),
        "setnle" => setcc_op!(a.setg, ops, text),
        "setno" => setcc_op!(a.setno, ops, text),
        "setnp" => setcc_op!(a.setnp, ops, text),
        "setns" => setcc_op!(a.setns, ops, text),
        "setnz" => setcc_op!(a.setne, ops, text),
        "seto" => setcc_op!(a.seto, ops, text),
        "setp" => setcc_op!(a.setp, ops, text),
        "setpe" => setcc_op!(a.setp, ops, text),
        "setpo" => setcc_op!(a.setnp, ops, text),
        "sets" => setcc_op!(a.sets, ops, text),
        "setz" => setcc_op!(a.sete, ops, text),

        other => Err(format!(
            "unsupported instruction '{other}' — the Auto Assembler subset \
             does not implement it yet"
        )),
    }
}

/// mov has extra immediate forms: 64-bit immediate → movabs (via i64/u64
/// impls), smaller registers take width-wrapped i32.
fn mov_op(a: &mut CodeAssembler, ops: &[Opnd], text: &str) -> Result<(), String> {
    match ops {
        [Opnd::Reg(d), Opnd::Reg(s)] => rr!(a.mov, *d, *s),
        [Opnd::Reg(d), Opnd::Mem(s)] => rm!(a.mov, *d, *s),
        [Opnd::Mem(d), Opnd::Reg(s)] => mr!(a.mov, *d, *s),
        [Opnd::Reg(d), Opnd::Imm(s)] => {
            let v = *s;
            match d {
                RegOp::R64(d) => {
                    if v >= i32::MIN as i128 && v <= i32::MAX as i128 {
                        // sign-extended imm32 form (CE parity for small values)
                        err_iced(a.mov(*d, v as i64))
                    } else {
                        let v = u64::try_from(v)
                            .map_err(|_| format!("'{text}': immediate out of range"))?;
                        err_iced(a.mov(*d, v))
                    }
                }
                RegOp::R32(d) => err_iced(a.mov(*d, v as u32 as i32)),
                RegOp::R16(d) => {
                    let x = v as i64;
                    if !(-32768..=65535).contains(&x) {
                        Err(format!("'{text}': immediate {v:#X} doesn't fit 16 bits"))
                    } else {
                        err_iced(a.mov(*d, x as i32))
                    }
                }
                RegOp::R8(d) => {
                    let x = v as i64;
                    if !(-128..=255).contains(&x) {
                        Err(format!("'{text}': immediate {v:#X} doesn't fit 8 bits"))
                    } else {
                        err_iced(a.mov(*d, x as i32))
                    }
                }
                _ => Err("mov: invalid destination".into()),
            }
        }
        [Opnd::Mem(d), Opnd::Imm(s)] => mi!(a.mov, *d, *s, text),
        _ => arity(text, ops.len(), "2"),
    }
}

#[derive(Clone, Copy)]
enum MovKind {
    Movzx,
    Movsx,
    Movsxd,
}

/// movzx/movsx/movsxd: (r16/32/64, r8) (r32/64, r16) (r, mem).
fn extend_op(a: &mut CodeAssembler, kind: MovKind, ops: &[Opnd], text: &str) -> Result<(), String> {
    macro_rules! go {
        ($m:ident) => {{
            match ops {
                [Opnd::Reg(d), Opnd::Reg(s)] => match (d, s) {
                    (RegOp::R16(d), RegOp::R8(s)) => err_iced(a.$m(*d, *s)),
                    (RegOp::R32(d), RegOp::R8(s)) => err_iced(a.$m(*d, *s)),
                    (RegOp::R64(d), RegOp::R8(s)) => err_iced(a.$m(*d, *s)),
                    (RegOp::R16(d), RegOp::R16(s)) => err_iced(a.$m(*d, *s)),
                    (RegOp::R32(d), RegOp::R16(s)) => err_iced(a.$m(*d, *s)),
                    (RegOp::R64(d), RegOp::R16(s)) => err_iced(a.$m(*d, *s)),
                    _ => Err("movzx/movsx: size mismatch".into()),
                },
                [Opnd::Reg(d), Opnd::Mem(s)] => match d {
                    RegOp::R16(d) => err_iced(a.$m(*d, *s)),
                    RegOp::R32(d) => err_iced(a.$m(*d, *s)),
                    RegOp::R64(d) => err_iced(a.$m(*d, *s)),
                    _ => Err("expected a register destination".into()),
                },
                _ => arity(text, ops.len(), "2"),
            }
        }};
    }
    match kind {
        MovKind::Movzx => go!(movzx),
        MovKind::Movsx => go!(movsx),
        MovKind::Movsxd => match ops {
            [Opnd::Reg(RegOp::R64(d)), Opnd::Reg(RegOp::R32(s))] => err_iced(a.movsxd(*d, *s)),
            [Opnd::Reg(RegOp::R64(d)), Opnd::Mem(s)] => err_iced(a.movsxd(*d, *s)),
            _ => arity(text, ops.len(), "2 (r64, r32/memory)"),
        },
    }
}

#[derive(Clone, Copy)]
enum ShiftKind {
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
}

/// Shifts/rotates: (r/m, cl) or (r/m, imm8).
fn shift_op(
    a: &mut CodeAssembler,
    kind: ShiftKind,
    ops: &[Opnd],
    text: &str,
) -> Result<(), String> {
    macro_rules! go {
        ($m:ident) => {{
            match ops {
                [Opnd::Reg(d), Opnd::Reg(RegOp::R8(s))] if *s == cl => match d {
                    RegOp::R8(d) => err_iced(a.$m(*d, *s)),
                    RegOp::R16(d) => err_iced(a.$m(*d, *s)),
                    RegOp::R32(d) => err_iced(a.$m(*d, *s)),
                    RegOp::R64(d) => err_iced(a.$m(*d, *s)),
                    _ => Err("expected a GPR".into()),
                },
                [Opnd::Mem(m), Opnd::Reg(RegOp::R8(s))] if *s == cl => err_iced(a.$m(*m, *s)),
                [Opnd::Reg(d), Opnd::Imm(v)] => {
                    if *v < 0 || *v > 255 {
                        return Err(format!("'{text}': shift count must be 0..=255"));
                    }
                    let v = *v as i32;
                    match d {
                        RegOp::R8(d) => err_iced(a.$m(*d, v)),
                        RegOp::R16(d) => err_iced(a.$m(*d, v)),
                        RegOp::R32(d) => err_iced(a.$m(*d, v)),
                        RegOp::R64(d) => err_iced(a.$m(*d, v)),
                        _ => Err("expected a GPR".into()),
                    }
                }
                [Opnd::Mem(m), Opnd::Imm(v)] => {
                    if *v < 0 || *v > 255 {
                        return Err(format!("'{text}': shift count must be 0..=255"));
                    }
                    err_iced(a.$m(*m, *v as i32))
                }
                _ => arity(text, ops.len(), "2 (value, cl or imm8)"),
            }
        }};
    }
    match kind {
        ShiftKind::Shl => go!(shl),
        ShiftKind::Shr => go!(shr),
        ShiftKind::Sar => go!(sar),
        ShiftKind::Rol => go!(rol),
        ShiftKind::Ror => go!(ror),
    }
}

#[derive(Clone, Copy)]
enum CvtKind {
    Cvtsi2ss,
    Cvtsi2sd,
    Cvttss2si,
    Cvtss2si,
    Cvttsd2si,
    Cvtsd2si,
}

/// cvtsi2ss/cvtsi2sd: (xmm, r32/r64) (xmm, mem).
fn cvt_int_to_float(
    a: &mut CodeAssembler,
    kind: CvtKind,
    ops: &[Opnd],
    text: &str,
) -> Result<(), String> {
    macro_rules! go {
        ($m:ident) => {{
            match ops {
                [Opnd::Reg(RegOp::Xmm(d)), Opnd::Reg(RegOp::R32(s))] => err_iced(a.$m(*d, *s)),
                [Opnd::Reg(RegOp::Xmm(d)), Opnd::Reg(RegOp::R64(s))] => err_iced(a.$m(*d, *s)),
                [Opnd::Reg(RegOp::Xmm(d)), Opnd::Mem(s)] => err_iced(a.$m(*d, *s)),
                _ => arity(text, ops.len(), "2 (xmm, r32/r64/memory)"),
            }
        }};
    }
    match kind {
        CvtKind::Cvtsi2ss => go!(cvtsi2ss),
        CvtKind::Cvtsi2sd => go!(cvtsi2sd),
        _ => unreachable!(),
    }
}

/// cvt(t)(s)d2si family: (r32/r64, xmm) (r, mem).
fn cvt_float_to_int(
    a: &mut CodeAssembler,
    kind: CvtKind,
    ops: &[Opnd],
    text: &str,
) -> Result<(), String> {
    macro_rules! go {
        ($m:ident) => {{
            match ops {
                [Opnd::Reg(RegOp::R32(d)), Opnd::Reg(RegOp::Xmm(s))] => err_iced(a.$m(*d, *s)),
                [Opnd::Reg(RegOp::R64(d)), Opnd::Reg(RegOp::Xmm(s))] => err_iced(a.$m(*d, *s)),
                [Opnd::Reg(RegOp::R32(d)), Opnd::Mem(s)] => err_iced(a.$m(*d, *s)),
                [Opnd::Reg(RegOp::R64(d)), Opnd::Mem(s)] => err_iced(a.$m(*d, *s)),
                _ => arity(text, ops.len(), "2 (r32/r64, xmm/memory)"),
            }
        }};
    }
    match kind {
        CvtKind::Cvttss2si => go!(cvttss2si),
        CvtKind::Cvtss2si => go!(cvtss2si),
        CvtKind::Cvttsd2si => go!(cvttsd2si),
        CvtKind::Cvtsd2si => go!(cvtsd2si),
        _ => unreachable!(),
    }
}

/// movd/movq between xmm and GPR/memory.
fn movd_movq(a: &mut CodeAssembler, ops: &[Opnd], text: &str) -> Result<(), String> {
    match ops {
        [Opnd::Reg(RegOp::Xmm(d)), Opnd::Reg(RegOp::R32(s))] => err_iced(a.movd(*d, *s)),
        [Opnd::Reg(RegOp::R32(d)), Opnd::Reg(RegOp::Xmm(s))] => err_iced(a.movd(*d, *s)),
        [Opnd::Reg(RegOp::Xmm(d)), Opnd::Reg(RegOp::R64(s))] => err_iced(a.movq(*d, *s)),
        [Opnd::Reg(RegOp::R64(d)), Opnd::Reg(RegOp::Xmm(s))] => err_iced(a.movq(*d, *s)),
        [Opnd::Reg(RegOp::Xmm(d)), Opnd::Mem(s)] => err_iced(a.movd(*d, *s)),
        [Opnd::Mem(d), Opnd::Reg(RegOp::Xmm(s))] => err_iced(a.movd(*d, *s)),
        _ => arity(text, ops.len(), "2"),
    }
}

/// fnstsw: accepts ax (16-bit register) or memory.
fn fpu_fnstsw(a: &mut CodeAssembler, ops: &[Opnd], text: &str) -> Result<(), String> {
    match ops {
        [Opnd::Reg(RegOp::R16(r))] => err_iced(a.fnstsw(*r)),
        [Opnd::Mem(m)] => err_iced(a.fnstsw(*m)),
        _ => arity(text, ops.len(), "1 (ax or memory)"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn no_lookup(_: &str) -> Option<u64> {
        None
    }

    fn asm64(text: &str) -> Vec<u8> {
        assemble_instr(64, 0x1000, text, &no_lookup).unwrap()
    }

    fn asm64_at(text: &str, base: u64) -> Vec<u8> {
        assemble_instr(64, base, text, &no_lookup).unwrap()
    }

    #[test]
    fn mov_reg_reg() {
        assert_eq!(asm64("mov rax, rbx"), vec![0x48, 0x89, 0xD8]);
        assert_eq!(asm64("mov eax, ecx"), vec![0x89, 0xC8]);
        assert_eq!(asm64("mov al, cl"), vec![0x88, 0xC8]);
    }

    #[test]
    fn mov_mem_forms() {
        // mov [rbx+10],eax
        assert_eq!(asm64("mov [rbx+10],eax"), vec![0x89, 0x43, 0x10]);
        // mov rax,[rbx+10]
        assert_eq!(asm64("mov rax,[rbx+10]"), vec![0x48, 0x8B, 0x43, 0x10]);
        // movss [rbx+20],xmm0
        assert_eq!(
            asm64("movss [rbx+20],xmm0"),
            vec![0xF3, 0x0F, 0x11, 0x43, 0x20]
        );
        // dword size hint with immediate
        assert_eq!(
            asm64("mov dword ptr [rbx+10],5"),
            vec![0xC7, 0x43, 0x10, 0x05, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn mov_index_scale() {
        // mov rax,[rbx+rcx*4+10]
        assert_eq!(
            asm64("mov rax,[rbx+rcx*4+10]"),
            vec![0x48, 0x8B, 0x44, 0x8B, 0x10]
        );
    }

    #[test]
    fn mov_imm64_movabs() {
        // Big immediate → movabs.
        let b = asm64("mov rax,0x1122334455667788");
        assert_eq!(&b[..2], &[0x48, 0xB8]);
        assert_eq!(
            u64::from_le_bytes(b[2..10].try_into().unwrap()),
            0x1122334455667788
        );
        // iced always uses movabs for r64 immediates (CE would use the
        // shorter C7 form when the value fits i32; both are equivalent).
        let b = asm64("mov rax,5");
        assert_eq!(
            b,
            vec![0x48, 0xB8, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        // Negative immediate.
        let b = asm64("mov eax,-1");
        assert_eq!(b, vec![0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn jmp_absolute_near_form() {
        // jmp 0x2000 from 0x1000: E9 FB 0F 00 00 (rel = 0x2000-0x1005).
        let b = asm64_at("jmp 0x2000", 0x1000);
        assert_eq!(b, vec![0xE9, 0xFB, 0x0F, 0x00, 0x00]);
    }

    #[test]
    fn jcc_near_form() {
        // jne 0x2000 from 0x1000: 0F 85 FA 0F 00 00 (rel = 0x2000-0x1006).
        let b = asm64_at("jne 0x2000", 0x1000);
        assert_eq!(b, vec![0x0F, 0x85, 0xFA, 0x0F, 0x00, 0x00]);
    }

    #[test]
    fn nop_count() {
        assert_eq!(asm64("nop 3"), vec![0x90, 0x90, 0x90]);
        assert_eq!(asm64("nop"), vec![0x90]);
    }

    #[test]
    fn alu_ops() {
        assert_eq!(asm64("sub rsp,20"), vec![0x48, 0x83, 0xEC, 0x20]);
        assert_eq!(asm64("add rsp,20"), vec![0x48, 0x83, 0xC4, 0x20]);
        // (using ecx: cmp eax,imm has the special accumulator form)
        assert_eq!(asm64("cmp ecx,5"), vec![0x83, 0xF9, 0x05]);
        assert_eq!(asm64("test eax,eax"), vec![0x85, 0xC0]);
        assert_eq!(asm64("xor eax,eax"), vec![0x31, 0xC0]);
    }

    #[test]
    fn push_pop_ret() {
        assert_eq!(asm64("push rbx"), vec![0x53]);
        assert_eq!(asm64("pop rbx"), vec![0x5B]);
        assert_eq!(asm64("ret"), vec![0xC3]);
    }

    #[test]
    fn rip_relative() {
        // mov rax,[rip+10] at 0x1000: 48 8B 05 10 00 00 00
        // (target = next_ip 0x1007 + 0x10 = 0x1017; disp = 0x10)
        let b = asm64_at("mov rax,[rip+10]", 0x1000);
        assert_eq!(b, vec![0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00]);
        // Disassembly round-trip check: the decoded rip target is 0x1017.
        let d = crate::memory::disasm::IcedDisassembler::new(64);
        let ins = d.decode_one(&b, 0x1000).unwrap();
        assert_eq!(ins.rip_rel_target, Some(0x1017));
    }

    #[test]
    fn symbol_lookup_in_operands() {
        let lookup = |name: &str| match name {
            "playerInstance" => Some(0x12345678),
            _ => None,
        };
        // mov rax,[playerInstance] → iced picks the moffs form (48 A1 imm64),
        // which handles 64-bit absolute addresses directly.
        let b = assemble_instr(64, 0x1000, "mov rax,[playerInstance]", &lookup).unwrap();
        assert_eq!(&b[..2], &[0x48, 0xA1]);
        assert_eq!(u64::from_le_bytes(b[2..10].try_into().unwrap()), 0x12345678);
    }

    #[test]
    fn abs_mem_beyond_disp32_uses_rip_relative() {
        // CE parity: in 64-bit, `mov [symbol],reg` with a symbol that does
        // not fit disp32 assembles RIP-relative. Regression test for the
        // DOOM player_instance script: `mov [_use],rcx` where _use is an
        // alloc'd 64-bit address (used to fail with "Displacement must fit
        // an i32").
        let lookup = |name: &str| match name {
            "_use" => Some(0x7F12_3456_7000),
            _ => None,
        };
        // At 0x7F12_3456_6000: mov [rip+disp],rcx = 48 89 0D <disp32>;
        // disp = 0x1000 - 7 (insn len) = 0xFF9.
        let b = assemble_instr(64, 0x7F12_3456_6000, "mov [_use],rcx", &lookup).unwrap();
        assert_eq!(b, vec![0x48, 0x89, 0x0D, 0xF9, 0x0F, 0x00, 0x00]);
        // Load form too: mov rcx,[_use] = 48 8B 0D <disp32>.
        let b = assemble_instr(64, 0x7F12_3456_6000, "mov rcx,[_use]", &lookup).unwrap();
        assert_eq!(b, vec![0x48, 0x8B, 0x0D, 0xF9, 0x0F, 0x00, 0x00]);
        // Round-trip: the decoded rip target is the symbol address.
        let d = crate::memory::disasm::IcedDisassembler::new(64);
        let ins = d.decode_one(&b, 0x7F12_3456_6000).unwrap();
        assert_eq!(ins.rip_rel_target, Some(0x7F12_3456_7000));
    }

    #[test]
    fn abs_mem_fitting_disp32_stays_absolute() {
        // Addresses that fit i32 keep the absolute (SIB disp32) form:
        // mov [0x1000],rcx = 48 89 0C 25 00 10 00 00.
        let b = asm64("mov [0x1000],rcx");
        assert_eq!(b, vec![0x48, 0x89, 0x0C, 0x25, 0x00, 0x10, 0x00, 0x00]);
    }

    #[test]
    fn x86_32bit_mode() {
        // 32-bit: mov eax,[ebx+10]
        let b = assemble_instr(32, 0x1000, "mov eax,[ebx+10]", &no_lookup).unwrap();
        assert_eq!(b, vec![0x8B, 0x43, 0x10]);
        // jmp rel32 in 32-bit mode
        let b = assemble_instr(32, 0x1000, "jmp 0x2000", &no_lookup).unwrap();
        assert_eq!(b, vec![0xE9, 0xFB, 0x0F, 0x00, 0x00]);
    }

    #[test]
    fn unknown_instruction_is_explicit_error() {
        let err =
            assemble_instr(64, 0x1000, "vfmadd231ps zmm0, zmm1, zmm2", &no_lookup).unwrap_err();
        assert!(
            err.contains("unsupported instruction 'vfmadd231ps'"),
            "{err}"
        );
    }

    #[test]
    fn size_mismatch_errors() {
        assert!(assemble_instr(64, 0x1000, "mov rax, bl", &no_lookup).is_err());
    }

    #[test]
    fn sse_float_ops() {
        // movss xmm0,[rax]
        assert_eq!(asm64("movss xmm0,[rax]"), vec![0xF3, 0x0F, 0x10, 0x00]);
        // addss xmm0,xmm1
        assert_eq!(asm64("addss xmm0,xmm1"), vec![0xF3, 0x0F, 0x58, 0xC1]);
    }

    #[test]
    fn x87_fpu_ops() {
        // fld dword ptr [rax+10] — 10 is hex (0x10=16) in address context
        let b = asm64("fld dword ptr [rax+10]");
        assert_eq!(b, vec![0xD9, 0x40, 0x10]);
        // fstp dword ptr [rcx]
        let b = asm64("fstp dword ptr [rcx]");
        assert_eq!(b, vec![0xD9, 0x19]);
        // fstp st(0) — CE syntax for FPU register
        let b = asm64("fstp st(0)");
        assert_eq!(b, vec![0xDD, 0xD8]);
        // fstp st0 — standard syntax
        assert_eq!(asm64("fstp st0"), vec![0xDD, 0xD8]);
        // fild dword ptr [rsp+48] — 48 is hex 0x48=72
        let b = asm64("fild dword ptr [rsp+48]");
        assert_eq!(b, vec![0xDB, 0x44, 0x24, 0x48]);
        // fistp dword ptr [rsp+48]
        let b = asm64("fistp dword ptr [rsp+48]");
        assert_eq!(b, vec![0xDB, 0x5C, 0x24, 0x48]);
        // fldz
        assert_eq!(asm64("fldz"), vec![0xD9, 0xEE]);
        // fld1
        assert_eq!(asm64("fld1"), vec![0xD9, 0xE8]);
        // fmul dword ptr [rax] (1-operand memory)
        assert_eq!(asm64("fmul dword ptr [rax]"), vec![0xD8, 0x08]);
        // fcompp
        assert_eq!(asm64("fcompp"), vec![0xDE, 0xD9]);
    }

    #[test]
    fn cmov_and_setcc_ops() {
        // cmovne rax, rbx → 48 0F 45 C3 (reg=rax, r/m=rbx)
        let b = asm64("cmovne rax, rbx");
        assert_eq!(b, vec![0x48, 0x0F, 0x45, 0xC3]);
        // sete al
        assert_eq!(asm64("sete al"), vec![0x0F, 0x94, 0xC0]);
        // setne byte ptr [rax]
        let b = asm64("setne byte ptr [rax]");
        assert_eq!(b, vec![0x0F, 0x95, 0x00]);
    }

    #[test]
    fn anonymous_labels() {
        // @b and @f should resolve to synthetic names. Test that a simple
        // script with @@: compiles.
        let lookup = |name: &str| match name {
            "__anon_0" => Some(0x2000u64), // forward ref resolves here
            _ => None,
        };
        // jmp @f  →  jmp __anon_0
        let b = assemble_instr(64, 0x1000, "jmp __anon_0", &lookup).unwrap();
        assert_eq!(b, vec![0xE9, 0xFB, 0x0F, 0x00, 0x00]);
    }
}
