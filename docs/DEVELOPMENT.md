# DeckForge Development Guide

## Prerequisites

- Rust toolchain (`cargo`, `rustc`) — Forge builds for the host; on the Steam
  Deck this is `x86_64-unknown-linux-gnu`.
- Node.js + npm — for the Cockpit frontend.
- Python 3 — for the Relay (the Decky runtime provides `decky`).

## Repository layout

```
deckforge/
├── cockpit/        React/TS Decky frontend
├── relay/          Python Decky backend (engine lifecycle + JSON IPC)
├── forge/          Rust trainer/memory engine
├── fixtures/       optional local trainers (git-ignored, not in a fresh clone)
├── docs/           architecture + this guide
├── plugin.json     Decky plugin manifest
├── package.json    frontend build (rollup / @decky/rollup)
├── rollup.config.js
├── tsconfig.json
└── main.py         Decky entry shim → relay.main.Plugin
```

## Build Forge

```bash
# debug (used by the local IPC test and dev runs)
cargo build --manifest-path forge/Cargo.toml

# release (what gets packaged to bin/deckforge-engine)
cargo build --release --manifest-path forge/Cargo.toml
```

The packaged binary target is `bin/deckforge-engine`. Relay resolves it from
`DECKFORGE_ENGINE_PATH`, then `bin/`, then `forge/target/{release,debug}/`.

## Build Cockpit

```bash
npm install
npm run build        # → dist/index.js (the Decky frontend bundle)
npm run watch        # rebuild on change during development
```

## Run Forge tests

```bash
cargo test --manifest-path forge/Cargo.toml
```

Tests that read process memory use their own test process, so they run without
extra privileges on Linux. Tests that need ptrace are ignored by default.

## Finding addresses with Forge commands

Value and pointer scans are developer tools, so Relay does not expose them and
Decky never shows them. Run `deckforge-engine` on the Deck or Linux machine with
the game running, then send one JSON request per line on stdin. Addresses are
decimal numbers.

```json
{"id":"1","command":"attach_game","appId":123456}
{"id":"2","command":"scan_value","value":100,"width":4}
{"id":"3","command":"scan_filter","value":93}
{"id":"4","command":"scan_results","limit":20}
{"id":"5","command":"scan_classify","address":101405967127568}
{"id":"6","command":"pointer_scan","address":101405967127568}
```

- **Start a scan:** `scan_value` takes `width` (1, 2, 4 or 8) and `float`. Leave
  out `value` when the starting value is unknown. For floats, `tolerance` also
  matches a rounded display, such as `"value":73,"tolerance":0.5` for 73.25, but
  only checks aligned values.
- **Narrow it down:** `scan_filter` takes `mode`, which is `exact` (the default,
  and needs `value`), `increased`, `decreased`, `changed` or `unchanged`.
  Integers compare as signed.
- **Make it permanent:** a scan result is only valid until the game restarts or
  moves the value. `scan_classify` reports whether it is already inside a module.
  Otherwise, each chain from `pointer_scan` can be pasted as a `pointer` resolver
  in `trainer.json`. Chains are checked against live memory but can still depend
  on heap layout, so relaunch the game and test before publishing.

## Running on a Steam Deck

1. Build Forge for the Deck (release): `cargo build --release`.
2. Build Cockpit: `npm run build`.
3. Copy `dist/`, `main.py`, `relay/`, `bin/deckforge-engine`, and `plugin.json`
   into a Decky plugin directory.
4. Under Decky, trainers are stored in `$DECKY_PLUGIN_RUNTIME_DIR/trainers`
   automatically. Set `DECKFORGE_TRAINER_DIR` to use a different directory, such
   as a local `fixtures/trainers`.

## What requires a Steam Deck

These cannot be verified off-device and are **not** claimed as verified here:

- Actual `/proc` process discovery for a running Proton game.
- `process_vm_readv` / `process_vm_writev` against a real game process.
- End-to-end enable/disable of a patch against live game memory.
- Decky Loader loading the plugin and rendering the frontend.

The pure-logic layers (protocol, maps parsing, AOB, trainer validation, memory
typed access signatures) are unit-tested on any host.
