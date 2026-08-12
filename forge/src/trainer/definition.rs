//! Trainer definition serde models.
//!
//! These types deserialize the declarative `trainer.json` schema. Most cheats
//! are declarative (patch/value/freeze); advanced behavior is provided by
//! script files inside the trainer package:
//!
//! * `"type": "auto_assembler"` actions run Cheat Engine–style `.asm` scripts.
//! * `"type": "script"` resolvers run sandboxed Lua, inline (`code`) or from a
//!   `.lua` file (`file`).
//! * `scripts.setup` lists Lua files run once when the shared VM boots;
//!   `scripts.bootstrap` lists Auto Assembler components with lazy, refcounted
//!   initialization that cheats pull in via `requires`.
//!
//! All script paths are relative to the trainer package directory and are
//! jailed to it by the loader/validator (no absolute paths, no `..`).

use std::path::PathBuf;

use serde::Deserialize;

use crate::resolver::{HexValue, Resolver};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrainerDefinition {
    pub format_version: u32,
    pub game: GameDefinition,
    pub trainer: TrainerMetadata,
    /// Optional Lua chunk run once when the trainer's shared script VM boots
    /// (before any `"type": "script"` resolver). Use it to define helper
    /// functions/globals that the inline resolver code calls. For anything
    /// non-trivial prefer `scripts.setup` files instead of inline code.
    #[serde(rename = "scriptSetup", default)]
    pub script_setup: Option<String>,
    /// Script files belonging to the trainer package.
    #[serde(default)]
    pub scripts: ScriptsSection,
    #[serde(default)]
    pub cheats: Vec<CheatDefinition>,
    /// Directory containing `trainer.json`; set by the loader, never parsed
    /// from JSON. All script paths are resolved (and jailed) against it.
    #[serde(skip)]
    pub package_dir: PathBuf,
    /// Contents of `scripts.setup` files, read by the loader and executed in
    /// order when the shared Lua VM boots (after the inline `scriptSetup`).
    #[serde(skip)]
    pub setup_scripts: Vec<String>,
}

/// Script file declarations of a trainer package.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptsSection {
    /// Lua files executed once per shared-VM boot, in order, before any
    /// resolver runs. Use for shared helpers (e.g. a GameMaker library).
    #[serde(default)]
    pub setup: Vec<String>,
    /// Auto Assembler components with lazy, refcounted initialization.
    /// A plain string entry takes its id from the file stem
    /// (`scripts/common/player_instance.asm` → `player_instance`).
    #[serde(default)]
    pub bootstrap: Vec<BootstrapEntry>,
}

/// A bootstrap component: either just a file path (id = file stem) or an
/// explicit `{ "id", "file" }` pair.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum BootstrapEntry {
    File(String),
    Named { id: String, file: String },
}

impl BootstrapEntry {
    pub fn file(&self) -> &str {
        match self {
            BootstrapEntry::File(f) => f,
            BootstrapEntry::Named { file, .. } => file,
        }
    }

    /// The component id: the explicit id, or the file stem.
    pub fn id(&self) -> String {
        match self {
            BootstrapEntry::Named { id, .. } => id.clone(),
            BootstrapEntry::File(f) => PathBuf::from(f)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| f.clone()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GameDefinition {
    pub steam_app_id: u64,
    pub name: String,
    pub process: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrainerMetadata {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub author: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheatDefinition {
    pub id: String,
    pub name: String,
    pub control: Control,
    #[serde(default)]
    pub min: Option<f64>,
    #[serde(default)]
    pub max: Option<f64>,
    /// Runtime dependencies: ids of bootstrap components that must be
    /// initialized before this cheat can enable. Lazily initialized on first
    /// enable, reference-counted across cheats, torn down when the last
    /// dependent cheat disables. Distinct from `{$include}` (a source-level
    /// dependency inside scripts).
    #[serde(default)]
    pub requires: Vec<String>,
    pub action: CheatAction,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Control {
    Toggle,
    Number,
    Slider,
    Action,
    Select,
}

impl Control {
    pub fn as_str(&self) -> &'static str {
        match self {
            Control::Toggle => "toggle",
            Control::Number => "number",
            Control::Slider => "slider",
            Control::Action => "action",
            Control::Select => "select",
        }
    }
}

/// The value-width type used by `value` and `freeze` actions.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum ValueType {
    #[serde(rename = "int8")]
    Int8,
    #[serde(rename = "int16")]
    Int16,
    #[serde(rename = "int32")]
    Int32,
    #[serde(rename = "int64")]
    Int64,
    #[serde(rename = "uint8")]
    UInt8,
    #[serde(rename = "uint16")]
    UInt16,
    #[serde(rename = "uint32")]
    UInt32,
    #[serde(rename = "uint64")]
    UInt64,
    #[serde(rename = "float32")]
    Float32,
    #[serde(rename = "float64")]
    Float64,
}

impl ValueType {
    pub fn size(&self) -> usize {
        match self {
            ValueType::Int8 | ValueType::UInt8 => 1,
            ValueType::Int16 | ValueType::UInt16 => 2,
            ValueType::Int32 | ValueType::UInt32 | ValueType::Float32 => 4,
            ValueType::Int64 | ValueType::UInt64 | ValueType::Float64 => 8,
        }
    }
}

/// The cheat action union, tagged by `type`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheatAction {
    Patch {
        resolver: Resolver,
        #[serde(default)]
        offset: Option<HexValue>,
        expected: String,
        enabled: String,
    },
    Value {
        #[serde(rename = "valueType")]
        value_type: ValueType,
        resolver: Resolver,
        /// Declared value for one-shot `action`-control writes (a Decky
        /// button). Optional: `number`/`slider` controls supply the value at
        /// runtime via `set_value`, so this is only read by `trigger_cheat`.
        #[serde(default)]
        value: Option<serde_json::Value>,
    },
    Freeze {
        #[serde(rename = "valueType")]
        value_type: ValueType,
        value: f64,
        #[serde(rename = "intervalMs", default)]
        interval_ms: Option<u64>,
        resolver: Resolver,
    },
    /// Cheat Engine–style Auto Assembler script file (toggle cheats only).
    /// The file normally contains `[ENABLE]` and `[DISABLE]` sections;
    /// enabling runs `[ENABLE]`, disabling runs `[DISABLE]`. The path is
    /// relative to the trainer package directory.
    AutoAssembler { file: String },
}
