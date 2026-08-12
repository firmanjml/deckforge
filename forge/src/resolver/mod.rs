//! Address resolvers: absolute, module_offset, pointer, signature, scan, script.
//!
//! A [`Resolver`] is deserialized from trainer JSON and resolved against the
//! attached process's memory + maps. Resolution never continues through invalid
//! memory and returns structured errors.

pub mod absolute;
pub mod module_offset;
pub mod pointer;
pub mod signature;

use serde::Deserialize;

use crate::cheats::script::ScriptEngineHandle;
use crate::error::{EngineError, EngineResult};
use crate::memory::{MemoryAccess, MemoryRegion};

/// A numeric value that may arrive as a hex string (`"0x20"`, `"32"`) or a JSON
/// number (`32`). Trainer JSON mixes these, so we accept both.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum HexValue {
    Str(String),
    Num(serde_json::Number),
}

impl HexValue {
    pub fn parse(&self) -> EngineResult<usize> {
        match self {
            HexValue::Str(s) => parse_addr(s),
            HexValue::Num(n) => n
                .as_u64()
                .map(|v| v as usize)
                .ok_or_else(|| EngineError::InvalidRequest(format!("invalid numeric offset {n}"))),
        }
    }
}

/// Parse a hex (`"0x..."`) or decimal address/offset string.
pub fn parse_addr(s: &str) -> EngineResult<usize> {
    let s = s.trim();
    let res = if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        usize::from_str_radix(rest, 16)
    } else {
        s.parse::<usize>()
    };
    res.map_err(|_| EngineError::InvalidRequest(format!("invalid address '{s}'")))
}

/// Parse a whitespace-separated hex byte string `"89 43 20"` → `[0x89, 0x43, 0x20]`.
pub fn parse_hex_bytes(s: &str) -> EngineResult<Vec<u8>> {
    s.split_whitespace()
        .map(|tok| {
            u8::from_str_radix(tok, 16)
                .map_err(|_| EngineError::InvalidRequest(format!("invalid byte '{tok}'")))
        })
        .collect()
}

/// The declarative resolver union, tagged by `type` on the wire.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Resolver {
    Absolute {
        address: HexValue,
    },
    ModuleOffset {
        module: String,
        offset: HexValue,
    },
    Pointer {
        module: String,
        offset: HexValue,
        #[serde(default)]
        offsets: Vec<HexValue>,
    },
    Signature {
        module: String,
        pattern: String,
        #[serde(default)]
        offset: Option<HexValue>,
    },
    Scan {
        #[serde(rename = "valueType")]
        value_type: String,
    },
    /// Lua resolver. Either inline `code` or a `file` inside the trainer
    /// package (relative path, jailed — no absolute paths, no `..`). The chunk
    /// runs in the trainer's shared sandboxed Lua VM (see
    /// [`crate::cheats::script`]) and must return the target address. The VM
    /// persists across resolves so scripts can cache discovery state in Lua
    /// globals; it resets on process exit.
    #[serde(rename = "script")]
    Script {
        #[serde(default)]
        code: Option<String>,
        #[serde(default)]
        file: Option<String>,
        /// Script language. Only `"lua"` is currently supported; the field
        /// exists so trainer files stay explicit about intent.
        #[serde(default)]
        language: Option<String>,
    },
}

/// Resolve a resolver to an absolute target address.
///
/// `scripts` is the trainer's shared Lua engine; it is only used by the
/// [`Resolver::Script`] variant and ignored by every other resolver.
pub fn resolve(
    resolver: &Resolver,
    mem: &MemoryAccess,
    maps: &[MemoryRegion],
    scripts: &ScriptEngineHandle,
) -> EngineResult<usize> {
    match resolver {
        Resolver::Absolute { address } => absolute::resolve(address),
        Resolver::ModuleOffset { module, offset } => {
            module_offset::resolve(maps, module, offset)
        }
        Resolver::Pointer {
            module,
            offset,
            offsets,
        } => pointer::resolve(mem, maps, module, offset, offsets),
        Resolver::Signature {
            module,
            pattern,
            offset,
        } => {
            let off = offset.as_ref().map(|h| h.parse()).transpose()?;
            signature::resolve(mem, maps, module, pattern, off)
        }
        Resolver::Scan { .. } => Err(EngineError::InvalidRequest(
            "scan resolver must be resolved via scan_resolve commands, not directly".into(),
        )),
        Resolver::Script { code, file, .. } => {
            // The loader inlines `file` contents into `code` at load time, so
            // by the time we resolve, `code` is always populated.
            let code = code.as_deref().ok_or_else(|| {
                EngineError::InvalidTrainer(format!(
                    "script resolver has no code (file '{}' was not loaded)",
                    file.as_deref().unwrap_or("<none>")
                ))
            })?;
            scripts
                .lock()
                .map_err(|_| EngineError::ScriptError("script engine lock poisoned".into()))?
                .resolve(mem, maps, code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_addr_hex_and_decimal() {
        assert_eq!(parse_addr("0x1AB0320").unwrap(), 0x1AB0320);
        assert_eq!(parse_addr("0X20").unwrap(), 0x20);
        assert_eq!(parse_addr("32").unwrap(), 32);
        assert!(parse_addr("nope").is_err());
    }

    #[test]
    fn parse_hex_bytes_basic() {
        assert_eq!(parse_hex_bytes("89 43 20").unwrap(), vec![0x89, 0x43, 0x20]);
        assert_eq!(parse_hex_bytes("90 90 90").unwrap(), vec![0x90, 0x90, 0x90]);
        assert!(parse_hex_bytes("89 ZZ").is_err());
    }

    #[test]
    fn hexvalue_from_string_and_number() {
        let from_str: HexValue = serde_json::from_str("\"0x20\"").unwrap();
        assert_eq!(from_str.parse().unwrap(), 0x20);
        let from_num: HexValue = serde_json::from_str("32").unwrap();
        assert_eq!(from_num.parse().unwrap(), 32);
    }

    #[test]
    fn module_offset_resolver_math() {
        // Module base + offset. Build a fake maps with one region at 0x400000.
        let maps = vec![MemoryRegion {
            start: 0x400000,
            end: 0x452000,
            readable: true,
            writable: false,
            executable: true,
            private: true,
            path: Some("Game.exe".into()),
        }];
        let mem = MemoryAccess::new(0);
        let scripts = crate::cheats::script::new_handle(crate::cheats::script::ScriptEngine::new("Game.exe", None, Vec::new(), std::sync::Arc::new(std::sync::Mutex::new(crate::trainer::session::TrainerSession::new()))));
        let r = Resolver::ModuleOffset {
            module: "Game.exe".into(),
            offset: HexValue::Str("0x18F020".into()),
        };
        // resolve needs memory only for pointer/signature; module_offset is pure.
        assert_eq!(
            resolve(&r, &mem, &maps, &scripts).unwrap(),
            0x400000 + 0x18F020
        );
    }

    #[test]
    fn module_offset_missing_module_errors() {
        let maps = vec![];
        let mem = MemoryAccess::new(0);
        let scripts = crate::cheats::script::new_handle(crate::cheats::script::ScriptEngine::new("Game.exe", None, Vec::new(), std::sync::Arc::new(std::sync::Mutex::new(crate::trainer::session::TrainerSession::new()))));
        let r = Resolver::ModuleOffset {
            module: "Nope.exe".into(),
            offset: HexValue::Num(serde_json::Number::from(0)),
        };
        assert!(matches!(
            resolve(&r, &mem, &maps, &scripts),
            Err(EngineError::ModuleNotFound(_))
        ));
    }
}
