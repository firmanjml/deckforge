//! Instruction decoding for bytes read from the *target* process.
//!
//! This is a deliberately small abstraction over an x86/x64 decoder (iced-x86).
//! It exists so resolver code and Lua scripts (via `trainer.disasm_targets`)
//! can ask
//! architecture-level questions — "does this instruction reference address X
//! via RIP-relative addressing?", "what absolute address operands appear in
//! this byte range?" — without depending on decoder-specific types.
//!
//! Decoding machine instructions from the target process is platform-agnostic:
//! the bytes may come from a Windows PE running under Proton just as well as
//! from a native ELF.

/// A single decoded instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Absolute address of the instruction in the target process.
    pub address: usize,
    /// Length in bytes.
    pub len: usize,
    /// If the instruction has a RIP/EIP-relative memory operand, the absolute
    /// address it refers to (e.g. the target of `lea rax, [rip+0x1234]`).
    pub rip_rel_target: Option<usize>,
    /// If the instruction has an absolute memory operand with no base
    /// register (e.g. `mov eax, [0x00401000]` on x86), that address.
    pub abs_mem_target: Option<usize>,
    /// Immediate operands, in operand order. Only immediates that could
    /// plausibly be pointer-sized constants are included.
    pub immediates: Vec<u64>,
}

impl Instruction {
    /// All absolute-address-like operands of this instruction: the resolved
    /// RIP-relative target (if any) plus pointer-sized immediates.
    ///
    /// This is the native equivalent of the CE table's `findAddress()`, which
    /// scraped hex operands out of disassembly text.
    pub fn address_operands(&self) -> Vec<usize> {
        let mut out = Vec::new();
        if let Some(t) = self.rip_rel_target {
            out.push(t);
        }
        if let Some(t) = self.abs_mem_target {
            out.push(t);
        }
        for &imm in &self.immediates {
            out.push(imm as usize);
        }
        out
    }
}

/// A decoder for a fixed bitness.
pub trait Disassembler {
    /// Decode instructions from `bytes` (treated as living at `base` in the
    /// target), covering at most `max_bytes` of the buffer.
    fn decode(&self, bytes: &[u8], base: usize, max_bytes: usize) -> Vec<Instruction>;
}

/// iced-x86 backed disassembler.
pub struct IcedDisassembler {
    bitness: u32,
}

impl IcedDisassembler {
    /// `bitness` is 64 or 32, matching the *target* process.
    pub fn new(bitness: u32) -> Self {
        Self { bitness }
    }

    /// Convenience one-shot decode for a single instruction at `base`.
    pub fn decode_one(&self, bytes: &[u8], base: usize) -> Option<Instruction> {
        self.decode(bytes, base, bytes.len()).into_iter().next()
    }
}

impl Disassembler for IcedDisassembler {
    fn decode(&self, bytes: &[u8], base: usize, max_bytes: usize) -> Vec<Instruction> {
        use iced_x86::{Decoder, DecoderOptions, OpKind};

        let limit = bytes.len().min(max_bytes);
        let mut decoder = Decoder::with_ip(
            self.bitness,
            &bytes[..limit],
            base as u64,
            DecoderOptions::NONE,
        );
        let mut out = Vec::new();
        let mut instr = iced_x86::Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            if instr.is_invalid() {
                break;
            }
            let len = instr.len();
            let address = instr.ip() as usize;

            let mut rip_rel_target = None;
            let mut abs_mem_target = None;
            let mut immediates = Vec::new();
            for op in 0..instr.op_count() {
                match instr.op_kind(op) {
                    OpKind::Memory if instr.is_ip_rel_memory_operand() => {
                        rip_rel_target = Some(instr.ip_rel_memory_address() as usize);
                    }
                    OpKind::Memory
                        if instr.memory_base() == iced_x86::Register::None
                            && instr.memory_displ_size() > 0 =>
                    {
                        // Absolute [disp32] memory operand (common in 32-bit
                        // code: `mov eax, [0x00401000]`).
                        abs_mem_target = Some(instr.memory_displacement64() as usize);
                    }
                    OpKind::Immediate64 => immediates.push(instr.immediate64()),
                    OpKind::Immediate32 | OpKind::Immediate32to64 => {
                        immediates.push(instr.immediate32to64() as u64)
                    }
                    _ => {}
                }
            }
            out.push(Instruction {
                address,
                len,
                rip_rel_target,
                abs_mem_target,
                immediates,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_lea_rip_relative_target() {
        // lea rax, [rip+0x10]  ==  48 8D 05 10 00 00 00   at address 0x1000
        // target = next_ip (0x1007) + 0x10 = 0x1017
        let bytes = [0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00];
        let d = IcedDisassembler::new(64);
        let ins = d.decode_one(&bytes, 0x1000).expect("must decode");
        assert_eq!(ins.len, 7);
        assert_eq!(ins.rip_rel_target, Some(0x1017));
    }

    #[test]
    fn collects_mov_abs_memory_and_immediates() {
        // mov rax, [rip-0x77] == 48 8B 05 89 FF FF FF at 0x2000 -> 0x1F90
        // then mov rbx, 0x1122334455667788 == 48 BB 88 77 66 55 44 33 22 11
        let mut bytes = vec![0x48, 0x8B, 0x05, 0x89, 0xFF, 0xFF, 0xFF];
        bytes.extend_from_slice(&[0x48, 0xBB, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
        let d = IcedDisassembler::new(64);
        let ins = d.decode(&bytes, 0x2000, bytes.len());
        assert_eq!(ins.len(), 2);
        assert_eq!(ins[0].rip_rel_target, Some(0x1F90));
        assert_eq!(ins[1].immediates, vec![0x1122334455667788]);
        // address_operands carries both kinds
        assert_eq!(ins[0].address_operands(), vec![0x1F90]);
        assert_eq!(ins[1].address_operands(), vec![0x1122334455667788usize]);
    }

    #[test]
    fn stops_on_invalid_bytes() {
        let bytes = [0x90, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; // nop; then garbage
        let d = IcedDisassembler::new(64);
        let ins = d.decode(&bytes, 0x0, bytes.len());
        assert!(!ins.is_empty());
        assert_eq!(ins[0].len, 1);
    }
}
