# DeckForge Architecture

DeckForge is a native Decky Loader trainer platform. Three components with
strictly separated responsibilities:

```
Decky UI
   │
   ▼
cockpit   — React / TypeScript   — presentation only
   │
   ▼
relay     — tiny Python adapter   — transport + engine lifecycle
   │
   ▼
forge     — Rust executable       — trainer + memory engine
   │
   ▼
external trainer data (trainer.json)
   │
   ▼
running game (Steam/Proton)
```

**In short: Cockpit presents. Relay forwards. Forge executes. Trainer files
describe.**

## cockpit (`cockpit/`)

Decky frontend built with `@decky/ui` + `@decky/api`, bundled by rollup
(`@decky/rollup`). Entry: `cockpit/src/index.tsx`.

- Polls engine status and renders it (Connected is only shown when the full
  Cockpit → Relay → Forge round-trip succeeds — never hardcoded).
- Attaches a running game by Steam AppID and renders cheats **dynamically** from
  the trainer definition returned by Forge. No game-specific cheats are
  hardcoded.
- All RPC goes through `cockpit/src/lib/backend.ts` — a single client that
  unwraps the structured envelope and throws a typed `ForgeError` carrying the
  stable `code`. Components branch on `error.code`, never on message strings.
- Never touches memory, pointers, signatures, or addresses.

## relay (`relay/`)

Tiny async Python bridge. `relay/main.py` exposes the Decky `callable` methods;
`relay/engine.py` owns the **persistent** Forge subprocess and JSON IPC.

- On plugin load: spawn `deckforge-engine` once. It stays alive for the plugin's
  lifetime — never one process per request.
- Forwards JSON requests over the child's stdin; routes responses by request id
  from stdout. Logs go to stderr; stdout is protocol-only.
- Returns the raw envelope `{ok, data, error:{code,message}}` so Cockpit can
  branch on codes. Transport failures surface as `ENGINE_NOT_RUNNING`.
- Auto-restarts the engine if it has exited.
- `main.py` (repo root) is a thin shim that re-exports `Plugin` from
  `relay/main.py`, because Decky Loader imports `main.py` from the plugin root.

## forge (`forge/`)

Rust binary (`deckforge-engine`). Owns all trainer runtime state and memory
access.

```
forge/src/
├── main.rs        event loop: stdin → dispatch → stdout (logs to stderr)
├── protocol.rs    typed JSON IPC: Request/Command, Response, payloads
├── error.rs       EngineError + stable wire codes
├── state.rs       EngineState: attached process, cached maps, trainer runtime
├── process/       /proc inspection, Steam/Proton discovery, module enumeration
├── memory/        /proc/maps parser + process_vm_readv/writev + typed r/w
│                  + MemoryOps trait (ops.rs) + remote mmap via ptrace (alloc.rs)
├── resolver/      absolute / module_offset / pointer / signature(AOB) / script(Lua)
├── autoasm/       Cheat Engine–compatible Auto Assembler:
│                  source ({$include}, sections) → parser (directives) →
│                  expressions → iced-x86 assembler → runtime (journal+rollback)
├── cheats/        patch (reversible) / value / freeze / script (sandboxed Lua VM)
└── trainer/       definition serde models / loader / validator / package
                   (path jailing) / components (bootstrap lifecycle) /
                   session (shared symbols + allocations) / runtime
```

- Newline-delimited JSON IPC. Every request has an `id`; every response echoes
  it. `stdout` = protocol only; `stderr` = logs.
- Memory access via `process_vm_readv`/`process_vm_writev` (Linux). Unsafe
  syscalls are contained in `memory/reader.rs` + `memory/writer.rs` +
  `memory/alloc.rs`.
- Patches verify `expected` bytes before writing, store originals, and only mark
  enabled after the write succeeds. Disable restores originals.
- Auto Assembler cheats (`"action": {"type": "auto_assembler", "file": ...}`)
  run CE-style `[ENABLE]`/`[DISABLE]` scripts with transactional rollback on
  enable failure; symbols and allocations live in the shared trainer session.
- Bootstrap components (`scripts.bootstrap` + cheat `requires`) initialize
  lazily and are reference-counted across cheats.
- Game-engine-specific resolution (e.g. GameMaker) lives in trainer package
  scripts (`scripts.setup` Lua libraries + `script` resolvers), never in the
  engine core.
- On process exit: discards resolved addresses, module cache, session state,
  and patch runtime state (never writes stale addresses). On trainer reload:
  best-effort disable of active script cheats first.

## Trainer data (`fixtures/` for dev)

Trainers are external runtime content, never bundled production code. Located by
`<trainer_dir>/<appid>/trainer.json`. Override with `DECKFORGE_TRAINER_DIR`
(under Decky, Relay defaults it to `$DECKY_PLUGIN_RUNTIME_DIR/trainers`, which
survives plugin updates; outside Decky the default is `fixtures/trainers`).

## Error codes

`ENGINE_NOT_RUNNING`, `INVALID_REQUEST`, `NOT_IMPLEMENTED`, `GAME_NOT_RUNNING`,
`PROCESS_NOT_FOUND`, `MODULE_NOT_FOUND`, `TRAINER_NOT_FOUND`, `INVALID_TRAINER`,
`SIGNATURE_NOT_FOUND`, `SIGNATURE_AMBIGUOUS`, `INVALID_POINTER`,
`MEMORY_READ_FAILED`, `MEMORY_WRITE_FAILED`, `EXPECTED_BYTES_MISMATCH`,
`UNSUPPORTED_VALUE_TYPE`, `CHEAT_ALREADY_ENABLED`, `CHEAT_NOT_ENABLED`,
`SCRIPT_ERROR`, `AUTO_ASSEMBLER_ERROR`.
