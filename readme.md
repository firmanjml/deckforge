# DeckForge

DeckForge is a native trainer platform for Steam Deck and Decky Loader. It detects the running Steam/Proton game, loads an external trainer package for that Steam AppID, and presents controller-friendly cheat controls in Decky's quick-access menu.

DeckForge does not launch Windows trainer executables. Its Rust engine reads and writes the running game's memory directly through Linux/SteamOS APIs.

> DeckForge is intended for offline and single-player use. It does not bypass, evade, or hide from anti-cheat systems. Do not attach it to an anti-cheat-protected session.

https://github.com/user-attachments/assets/accb76a1-08ef-4d31-8524-7e989593932b

## How it works

```text
Steam game starts under Proton
            |
            v
Cockpit detects the active Steam AppID
            |
            v
Relay sends a newline-delimited JSON request
            |
            v
Forge finds the real game process and /proc maps
            |
            v
Forge loads <trainer-dir>/<appid>/trainer.json
            |
            v
Cockpit renders controls from the trainer definition
            |
            v
Forge resolves addresses and applies/restores changes
```

The project has three deliberately separate components:

| Component | Technology | Responsibility |
|---|---|---|
| `cockpit/` | React, TypeScript, `@decky/ui`, `@decky/api` | Detect the active game, render trainer controls, and show actionable state/errors. |
| `relay/` | Python | Keep one Forge process alive and forward Decky RPC calls over JSON stdin/stdout. |
| `forge/` | Rust | Discover processes, parse maps, resolve addresses, run trainer scripts, and own all runtime and memory state. |
| trainer package | JSON, optional `.asm` and `.lua` | Describe game-specific cheats without adding game-specific code to DeckForge. |

In short: **Cockpit presents. Relay forwards. Forge executes. Trainer files describe.**

Forge is a persistent executable named `deckforge-engine`. Every request has an ID and every response echoes it:

```json
{"id":"req-1","command":"enable_cheat","cheatId":"infinite_ammo"}
```

```json
{"id":"req-1","ok":true,"data":{"enabled":true}}
```

Rust reserves stdout for protocol responses and sends logs to stderr. Relay contains no memory or trainer logic, and Cockpit never sees raw addresses.

## Runtime lifecycle

When the Decky plugin opens, Cockpit polls Forge through Relay. If Forge is not attached, it searches for a likely Steam/Proton game process and attaches by AppID. Forge then:

1. Identifies the actual game process, excluding Steam, Wine, Proton, crash-handler, and helper processes.
2. Parses `/proc/<pid>/maps` and discovers the requested game module.
3. Loads and validates `<trainer-dir>/<appid>/trainer.json`.
4. Creates the trainer's shared symbol/allocation session.
5. Returns game, trainer, cheat, enabled, and error state to Cockpit.

When a game exits, Forge stops freezes and discards addresses, module data, patches, script VMs, symbols, and allocations. A later game launch is resolved from scratch, so stale addresses are never reused.

Memory reads use `process_vm_readv`. Writes use `/proc/<pid>/mem`; read-only shared Wine/Proton image pages have a page-privatization fallback so patches do not modify the backing game file. Auto Assembler allocations use remote `mmap`/`munmap` through ptrace syscall injection.

## Repository layout

```text
deckforge/
├── cockpit/                 Decky frontend
├── relay/                   thin Python adapter
├── forge/                   Rust engine
│   └── src/
│       ├── process/         Proton process discovery and procfs
│       ├── memory/          maps, reads, writes, allocation, disassembly
│       ├── resolver/        absolute, module offset, pointer, AOB, Lua
│       ├── cheats/          patch, value, freeze, script runtime
│       ├── autoasm/         CE-style Auto Assembler implementation
│       ├── trainer/         schema, loader, validation, package runtime
│       └── store/           remote trainer catalog/install support
├── fixtures/trainers/       development-only trainer packages
├── docs/                    deeper architecture/development/store notes
├── bin/                     staged deckforge-engine binary
├── main.py                  Decky entry shim to relay.main.Plugin
├── plugin.json
└── llm.txt                  CE-table porting reference for coding agents
```

Production trainer data is external to the plugin: under Decky, trainers live in `$DECKY_PLUGIN_RUNTIME_DIR/trainers`, so plugin updates do not remove them. The git-ignored `fixtures/trainers/` tree is optional local development content, and a fresh clone does not include it.

## Build and test

Prerequisites:

- Rust and Cargo
- Node.js and npm
- Python 3
- Linux or SteamOS for real process-memory work; pure logic and IPC can be tested on Windows

Build Forge and Cockpit:

```bash
cargo build --release --manifest-path forge/Cargo.toml
npm install
npm run build
```

On Windows, the same commands produce a Windows development engine and the Cockpit bundle. Windows builds cannot test Linux process attachment or memory access.

Run the Rust tests:

```bash
cargo test --manifest-path forge/Cargo.toml
```

To deploy manually, stage the Linux release binary as `bin/deckforge-engine`
and copy `dist/`, `main.py`, `relay/`, `plugin.json`, and `bin/` into the
Decky plugin directory. The engine binary must be executable.

Useful environment variables:

| Variable | Purpose |
|---|---|
| `DECKFORGE_ENGINE_PATH` | Override the Forge executable used by Relay. |
| `DECKFORGE_TRAINER_DIR` | Root containing one trainer package directory per Steam AppID. Under Decky it defaults to `$DECKY_PLUGIN_RUNTIME_DIR/trainers`; outside Decky it defaults to `fixtures/trainers`. |
| `DECKFORGE_REPO_OWNER`, `DECKFORGE_REPO_NAME`, `DECKFORGE_REPO_REF` | Override the remote trainer catalog. |
| `DECKFORGE_REPO_TOKEN` | Optional GitHub token for a higher API rate limit. |

Real validation of process discovery, code-page writes, remote allocation, and Decky rendering must be performed on a Steam Deck or compatible Linux/Proton environment.

## Create a trainer package

A package is a directory named with the game's Steam AppID:

```text
<trainer-dir>/
└── 123456/
    ├── trainer.json
    └── scripts/
        ├── common/
        │   └── player_pointer.asm
        ├── infinite_ammo.asm
        └── money.lua
```

For local development, place it under `fixtures/trainers/<appid>/` or point `DECKFORGE_TRAINER_DIR` at another root. `game.steamAppId` must match the directory name.

A minimal trainer:

```json
{
  "formatVersion": 1,
  "game": {
    "steamAppId": 123456,
    "name": "Example Game",
    "process": "ExampleGame.exe"
  },
  "trainer": {
    "id": "example-game-default",
    "name": "Example Game Trainer",
    "version": "1.0.0",
    "author": "Your Name"
  },
  "cheats": [
    {
      "id": "infinite_ammo",
      "name": "Infinite Ammo",
      "control": "toggle",
      "action": {
        "type": "patch",
        "resolver": {
          "type": "signature",
          "module": "ExampleGame.exe",
          "pattern": "89 43 20 48 8B ?? ??",
          "offset": 0
        },
        "expected": "89 43 20",
        "enabled": "90 90 90"
      }
    }
  ]
}
```

All IDs should be stable, lowercase `snake_case`. Script paths must use forward slashes, be relative to the package, and may not escape it with `..`.

### Controls and actions

Cockpit currently renders `toggle`, `number`, and `action`. The schema also accepts `slider` and `select`, but Cockpit does not render them yet.

| Control | Normal action | Behavior |
|---|---|---|
| `toggle` | `patch`, `freeze`, `auto_assembler` | Enable and disable stateful behavior. |
| `number` | `value` | Resolve and write the number supplied by the user. |
| `action` | `value` or `freeze` | Perform one write. A `value` action must declare its own `value`. |

Available value types are `int8`, `int16`, `int32`, `int64`, `uint8`, `uint16`, `uint32`, `uint64`, `float32`, and `float64`.

Choose the smallest mechanism that describes the cheat:

1. Use `patch` for a fixed byte replacement at a stable signature or module offset.
2. Use `value` for a user-supplied or one-shot typed value.
3. Use `freeze` when Forge must periodically re-resolve and rewrite a typed value.
4. Use `auto_assembler` for code caves, hooks, registered symbols, or multi-site changes.
5. Use a Lua `script` resolver when finding the address requires game-specific traversal or scanning logic.

### Patch action

```json
{
  "id": "no_reload",
  "name": "No Reload",
  "control": "toggle",
  "action": {
    "type": "patch",
    "resolver": {
      "type": "signature",
      "module": "ExampleGame.exe",
      "pattern": "29 83 A0 00 00 00 48 8B",
      "offset": 0
    },
    "offset": 0,
    "expected": "29 83 A0 00 00 00",
    "enabled": "90 90 90 90 90 90"
  }
}
```

Forge requires `expected` and `enabled` to have the same length. Enabling resolves the target, verifies the expected bytes, saves the original bytes, and writes the enabled bytes. Disabling restores the saved original bytes. Never widen a patch past complete instruction boundaries.

The resolver's `offset` moves from the signature match to a base target. The patch action's `offset` is then added to that resolved target. Prefer expressing the adjustment once unless the two stages are intentionally distinct.

### Value action

```json
{
  "id": "money",
  "name": "Money",
  "control": "number",
  "min": 0,
  "max": 999999999,
  "action": {
    "type": "value",
    "valueType": "int32",
    "resolver": {
      "type": "pointer",
      "module": "ExampleGame.exe",
      "offset": "0x123456",
      "offsets": ["0x20", "0x18", "0x8"]
    }
  }
}
```

An `action` button can use the same action with a declared value:

```json
{
  "id": "grant_money",
  "name": "Grant Money",
  "control": "action",
  "action": {
    "type": "value",
    "valueType": "int32",
    "value": 999999,
    "resolver": {
      "type": "module_offset",
      "module": "ExampleGame.exe",
      "offset": "0x123456"
    }
  }
}
```

### Freeze action

```json
{
  "id": "infinite_health",
  "name": "Infinite Health",
  "control": "toggle",
  "action": {
    "type": "freeze",
    "valueType": "float32",
    "value": 100.0,
    "intervalMs": 100,
    "resolver": {
      "type": "module_offset",
      "module": "ExampleGame.exe",
      "offset": "0xABCDEF"
    }
  }
}
```

All active freezes share one central manager. The resolver is run again during freeze ticks, which allows pointer- and Lua-resolved addresses to follow game state changes. Intervals are clamped to a practical minimum internally.

Turning a freeze off normally leaves the frozen value in memory. Add `"restoreOnDisable": true` to a `toggle` freeze when the old value should come back, such as a damage multiplier. Leave it off for changes the player wants to keep, such as currency. If the game has moved the value by then, Forge skips the restore instead of writing to memory that may now hold something else.

### Address resolvers

Module offset:

```json
{"type":"module_offset","module":"ExampleGame.exe","offset":"0x18F020"}
```

Pointer chain:

```json
{
  "type":"pointer",
  "module":"ExampleGame.exe",
  "offset":"0x1AB0320",
  "offsets":["0x30","0x18","0x20"]
}
```

The pointer resolver starts at `module base + offset`, reads a 64-bit pointer at each step, adds the corresponding listed offset, and validates every read. It is therefore currently suitable for x86-64 targets. For a 32-bit target, use a Lua resolver with `trainer.read_pointer()` until the declarative pointer resolver gains target-width detection.

Unique AOB signature:

```json
{
  "type":"signature",
  "module":"ExampleGame.exe",
  "pattern":"48 8B 05 ?? ?? ?? ?? 48 85 C0",
  "offset":0
}
```

`??` is a wildcard. A signature resolver must match exactly once; no match returns `SIGNATURE_NOT_FOUND`, and multiple matches return `SIGNATURE_AMBIGUOUS`.

Absolute addresses are available for development only:

```json
{"type":"absolute","address":"0x12345678"}
```

They are normally unsuitable for shipped trainers because of ASLR.

### Lua script resolver

Use Lua to return an address, not to implement a full cheat lifecycle:

```json
{
  "type":"script",
  "language":"lua",
  "file":"scripts/money.lua"
}
```

```lua
local holder = trainer.symbol("playerPtr")
if holder == nil then
  error("playerPtr is not available")
end

local player = trainer.read_pointer(holder)
return player + 0x2A8
```

The shared sandboxed Lua VM provides typed reads/writes, byte and string reads, module/region inspection, signatures, string/pointer scans, pointer resolution, disassembly targets, MSVC RTTI lookup, logging, and shared session symbols. It does not expose `os`, `io`, `package`, `require`, `debug`, filesystem access, networking, process execution, or native-library loading.

For shared Lua helpers, declare files in order under `scripts.setup`. The legacy inline `scriptSetup` string is also accepted, but files are easier to review.

```json
{
  "scripts": {
    "setup": ["scripts/common/gamemaker.lua"]
  }
}
```

There is no full `"type": "lua"` cheat action. Lua is currently used for address resolvers and setup libraries; stateful code injection belongs in `auto_assembler`.

## Port a Cheat Engine table

A `.CT` file is XML. Treat it as source material, not as a file DeckForge can load directly. Port each user-visible record into `trainer.json` and, when necessary, one or more package scripts.

### 1. Inventory the table

Record the Steam AppID, Proton process/module name, target architecture, value type, pointer paths, AOB patterns, Auto Assembler scripts, shared symbols, and dependencies between entries. Ignore CE UI grouping records unless they help organize the work.

Do not copy temporary addresses from a CE session. Prefer a unique AOB, a validated module offset for a fixed build, a pointer chain, or a Lua resolver.

### 2. Classify each CE entry

| CE table pattern | DeckForge representation |
|---|---|
| Address or pointer record edited by the user | `number` + `value` |
| Frozen address record | `toggle` + `freeze` |
| Simple `db` replacement with enable/disable bytes | `toggle` + `patch` |
| `aobscan` + `alloc` + hook + restore | `toggle` + `auto_assembler` `.asm` file |
| Shared injection that captures a player/object pointer | `scripts.bootstrap` component plus `requires` |
| CE Lua used only to discover an address | Lua `script` resolver and optional `scripts.setup` helper |
| CE Lua forms, timers, hotkeys, OS APIs, or arbitrary callbacks | Redesign; they are not DeckForge trainer features. |

### 3. Simplify before copying

If a CE script only replaces fixed bytes, use a declarative patch. It adds expected-byte verification and automatic restoration without maintaining a script.

For example, this CE entry:

```asm
[ENABLE]
aobscanmodule(ammo,ExampleGame.exe,29 83 A0 00 00 00 48 8B)
ammo:
  db 90 90 90 90 90 90

[DISABLE]
ammo:
  db 29 83 A0 00 00 00
```

should normally become the `patch` example above.

### 4. Port code injections to Auto Assembler files

```json
{
  "id":"infinite_ammo",
  "name":"Infinite Ammo",
  "control":"toggle",
  "action":{
    "type":"auto_assembler",
    "file":"scripts/infinite_ammo.asm"
  }
}
```

```asm
[ENABLE]
aobscanmodule(ammo,ExampleGame.exe,29 83 A0 00 00 00 48 8B)
assert(ammo,29 83 A0 00 00 00)
alloc(newmem,$1000,ammo)
label(return)
registersymbol(ammo)

newmem:
  // Preserve or replace every instruction overwritten at the hook site.
  jmp return

ammo:
  jmp newmem
  nop
return:

[DISABLE]
ammo:
  db 29 83 A0 00 00 00

unregistersymbol(ammo)
dealloc(newmem)
```

DeckForge supports `[ENABLE]`/`[DISABLE]`, `aobscan`, `aobscanmodule`, `aobscanregion`, `alloc`, `dealloc`, `label`, `define`, `registersymbol`, `unregistersymbol`, `assert`, `readmem`, `align`, `db`/`dw`/`dd`/`dq`, `{$include ...}`, anonymous labels, and a common x86/x64 Intel-syntax instruction subset.

Enable execution is transactional: writes are journaled, and a partial failure rolls back writes, allocations, and symbols. Unsupported directives and instructions fail with `AUTO_ASSEMBLER_ERROR`; they are never silently ignored.

Currently unsupported CE directives include `createthread`, `loadlibrary`, `globalalloc`, `fullaccess`, `aobscanunique`, `loadedsymbol`, `deallocf`, `allocnx`, `registerexe`, and `unregisterexe`. Rewrite or remove them. Use `{$include file.asm}`, not CE's `include(...)` directive.

### 5. Separate includes from runtime dependencies

`{$include common/helpers.asm}` splices source text at that location. The path is relative to the including file.

`requires` activates a declared bootstrap component at runtime. Components are lazy and reference-counted, so one shared player-pointer hook can serve several cheats:

```json
{
  "scripts": {
    "bootstrap": [
      {"id":"player_pointer","file":"scripts/common/player_pointer.asm"}
    ]
  },
  "cheats": [
    {
      "id":"health",
      "name":"Health",
      "control":"number",
      "requires":["player_pointer"],
      "action":{
        "type":"value",
        "valueType":"float32",
        "resolver":{
          "type":"script",
          "language":"lua",
          "code":"local p=trainer.symbol('playerPtr'); if not p then error('playerPtr unavailable') end; return trainer.read_pointer(p)+0x1C"
        }
      }
    }
  ]
}
```

The component stays enabled while any dependent stateful cheat holds it. Stateless reads and writes initialize dependencies on demand.

### 6. Verify the port

For every cheat:

1. Confirm the correct executable/module name under Proton, including case and extension.
2. Confirm every AOB is unique on the supported game build.
3. Confirm the overwrite length covers complete instructions and that a relative jump can reach its allocation.
4. Preserve registers, flags, stack balance, and all displaced original behavior unless the cheat intentionally changes it.
5. Make `[DISABLE]` restore exactly what `[ENABLE]` changed, then unregister symbols and deallocate memory.
6. Test enable, disable, repeated enable/disable, trainer reload, save/load transitions, level changes, and game exit/relaunch.
7. Test cheats together, especially entries sharing hooks or symbols.
8. Treat `EXPECTED_BYTES_MISMATCH`, signature ambiguity, and unsupported syntax as porting defects rather than bypassing the checks.

See [`llm.txt`](llm.txt) for a machine-oriented conversion contract, supported syntax notes, output template, and checklist suitable for giving a `.CT` table to an LLM.

## Errors and debugging

Forge returns stable error codes such as:

- `PROCESS_NOT_FOUND`, `MODULE_NOT_FOUND`, `TRAINER_NOT_FOUND`, `INVALID_TRAINER`
- `SIGNATURE_NOT_FOUND`, `SIGNATURE_AMBIGUOUS`, `INVALID_POINTER`
- `MEMORY_READ_FAILED`, `MEMORY_WRITE_FAILED`, `EXPECTED_BYTES_MISMATCH`
- `SCRIPT_ERROR`, `AUTO_ASSEMBLER_ERROR`

Auto Assembler errors include the trainer, cheat/component owner, script file, section, source line, command, and cause. Check Forge stderr for diagnostic detail; Cockpit intentionally shows only actionable messages.

If you keep local fixture packages under the git-ignored `fixtures/trainers/`, they can demonstrate declarative patches and values, freezes, code injections, `readmem`, bootstrap components, shared symbols, and Lua resolvers. Treat their offsets and signatures as game/build-specific examples, not reusable constants.

## Trainer store

Forge can list, install, update, and remove external trainer packages from a GitHub-backed catalog without rebuilding the plugin. Downloads are staged, path-jailed, validated with the normal trainer loader, and atomically swapped into the configured trainer directory. See [`docs/STORE.md`](docs/STORE.md) for repository layout, configuration, protocol, and trust details.

Additional implementation notes are in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).
