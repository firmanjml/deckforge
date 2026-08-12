//! Cheat Engine–compatible Auto Assembler subsystem.
//!
//! ```text
//! .asm script
//!      ↓  source.rs    ({$include} expansion, [ENABLE]/[DISABLE] split)
//!      ↓  parser.rs    (directives / labels / data / asm lines, define() macros)
//!      ↓  runtime.rs   (scans + allocations bind symbols, blocks grouped)
//!      ↓  assemble.rs  (Intel-syntax subset → iced-x86 CodeAssembler)
//!      ↓  MemoryOps    (validated read/write/scan/alloc against the target)
//! ```
//!
//! Supported directive subset: `aobscan`, `aobscanmodule`, `alloc`, `dealloc`,
//! `label`, `define`, `registersymbol`, `unregistersymbol`, `assert`,
//! `db`/`dw`/`dd`/`dq`, `{$include}`, plus common x86/x64 instructions.
//! Unsupported directives/instructions are explicit errors, never ignored.

// AaError carries full execution context (trainer/cheat/script/section/line/
// command/cause) — that richness is the point (task: error reporting), so the
// Err variant is intentionally large.
#![allow(clippy::result_large_err)]

pub mod assemble;
pub mod error;
pub mod expr;
pub mod parser;
pub mod runtime;
pub mod source;

pub use error::Section;
pub use runtime::Executor;
