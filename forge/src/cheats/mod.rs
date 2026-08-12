//! Cheat execution layer: reversible patches, value writes, freezes, and the
//! sandboxed Lua engine used by `"type": "script"` resolvers.

pub mod freeze;
pub mod patch;
pub mod script;
pub mod value;
