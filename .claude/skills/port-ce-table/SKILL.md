---
name: port-ce-table
description: Port a Cheat Engine .CT table into a DeckForge trainer package (trainer.json plus Auto Assembler and Lua scripts). Use when the user provides a .CT file or CE table contents and wants a DeckForge trainer, or asks to convert, port, or import a Cheat Engine table.
---

# Port a Cheat Engine table to DeckForge

A `.CT` file is XML source material. DeckForge never loads it, never runs Cheat
Engine, and never launches a Windows trainer. The output is a trainer package:

```
<trainer-root>/<steam-app-id>/
  trainer.json
  scripts/            # .asm and .lua files, only if needed
```

`llm.txt` at the repo root is the authoritative porting guide. `trainer.schema.json` is the
schema. Read both in full before converting anything, and follow them over this file if they differ.
This skill is the workflow and the guard rails. It does not repeat their templates.

## Hard rules

- Offline and single-player only. Refuse anti-cheat bypass, evasion, concealment, kernel
  tricks or online cheating, and say why.
- Game-specific logic lives only in the trainer package. Do not touch `cockpit/`, `relay/` or
  `forge/` to support one game.
- Never invent an address, AOB, expected bytes, process name or AppID. Use an obvious
  placeholder (`REPLACE_WITH_PROCESS.exe`, `0xREPLACE_ME`) and list it in the report.
- Never weaken or remove `expected` bytes, and never delete an unknown AA line to make the
  parser accept the file. Redesign it with supported primitives or report it as unsupported.
- Keep the original author, source and license attribution in `trainer.author` or comments.
- Never claim a trainer works. Only a test on Linux/SteamOS against the target build proves that.

## Workflow

### 1. Gather inputs

Get the complete `.CT` XML (not screenshots or a list of names). Then confirm or ask for:
Steam AppID, game name, the real Proton process or module name (with `.exe` and correct
case), x86 vs x86-64, the game build the table was made for, and the source and license.
If the table is a file in the workspace, read it fully. Do not skim.

### 2. Inventory the table

List every `CheatEntry`: description, value type, address and offsets, `AssemblerScript`,
`LuaScript`, parent/child symbol dependencies, and any pointer or AOB. Ignore CE UI
metadata (Color, LastState, ShowAsHex, group headers, hotkeys, `Active`). No cheat ships
enabled by default. Do not use CE `ID` as a public id. Derive stable lowercase
`snake_case` ids from the description.

### 3. Classify each entry

Use the decision tree in `llm.txt`. In short, pick the simplest form that works:

| CE pattern | DeckForge form |
|---|---|
| Fixed `db` byte replacement | `toggle` + `patch` (with `expected`) |
| User-edited value or pointer record | `number` + `value` |
| One-click write of a fixed value | `action` + `value` |
| Frozen record | `toggle` + `freeze` (consider `restoreOnDisable`) |
| aobscan + alloc + jmp hook | `toggle` + `auto_assembler` with a `.asm` file |
| Shared pointer-capture hook | `scripts.bootstrap` component + `requires` |
| CE Lua used only to find an address | Lua `script` resolver (+ `scripts.setup`) |
| CE forms, timers, hotkeys, OS/file/net APIs, onEnable loops | Redesign or report unsupported |

Prefer a declarative patch over a script whenever the script only swaps fixed bytes.
Prefer only `toggle`, `number` and `action` controls, since Cockpit does not render
`slider` or `select`.

### 4. Write the package

- `formatVersion: 1`, directory name equals `game.steamAppId`, valid JSON.
- Hex offsets are quoted (`"0x1A20"`); byte strings are uppercase, space-separated
  (`"48 8B ?? 20"`).
- Script paths are relative, use `/`, and contain no `..` or drive letters.
- Signatures must have exactly one match. Scope them to the module and wildcard only
  relocation bytes and real variable operands.
- The declarative pointer resolver is 64-bit only. For x86 targets use a Lua resolver with
  `trainer.read_pointer()`.
- Confirm the CE offset order for pointer chains instead of reversing it by intuition.
- Watch AA numeric context: address context is hex, size context is decimal. Use explicit
  `0x`, `$` or `#` prefixes.
- For AA hooks, count the whole instructions overwritten, replay them, keep the stack
  balanced, restore exact original bytes in `[DISABLE]`, and unregister and dealloc what
  the script owns.
- Unsupported AA directives (`createthread`, `loadlibrary`, `globalalloc`, `fullaccess`,
  `aobscanunique`, `loadedsymbol`, `deallocf`, `allocnx`, `registerexe`, CE `include()`)
  must be rewritten or reported.
- Do not preserve nested CE parent/child entries mechanically. Make dependencies explicit
  with `scripts.bootstrap` and `requires`.

### 5. Validate statically

Run these and report the real output:

```bash
# schema check (needs network for npx the first time)
npx ajv-cli@5 validate --spec=draft2020 --strict=false -s trainer.schema.json -d <package>/trainer.json

# real loader check, no game required (see docs/STORE.md)
cargo build --manifest-path forge/Cargo.toml
export DECKFORGE_TRAINER_DIR=<trainer-root>
printf '%s\n' \
  '{"id":"validate","command":"get_trainer","appId":<APPID>}' \
  '{"id":"stop","command":"shutdown"}' \
  | forge/target/debug/deckforge-engine
```

The `validate` response must be `"ok": true`. Fix errors by reading the reported code and
message (`llm.txt`, "Error-driven repair"). Do not paper over them. Both checks only prove the
package loads, not that the memory behavior is correct.

### 6. Final report

End with, in this order:

1. Files created.
2. CE entries converted, and the action and resolver type for each.
3. Shared components and the dependency graph.
4. Unsupported or omitted CE features, with exact reasons.
5. Placeholders and assumptions that need human confirmation.
6. Build-specific signatures, offsets and original bytes to verify.
7. Static checks run and their results.
8. On-device tests still required on SteamOS/Proton (attach, one AOB match, enable and
   disable restoring bytes, repeated cycles, cheats combined, save/load and respawn,
   game restart).

State plainly that the port is untested in-game unless the user confirms otherwise.
