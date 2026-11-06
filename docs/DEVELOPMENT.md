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
├── fixtures/       development-only trainer JSON
├── scripts/        build / test / deploy helpers
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

40 unit tests cover: JSON protocol (de)serialization, `/proc/maps` parsing,
AOB pattern parse + match (incl. ambiguity), trainer JSON parse + validation,
module-offset math, and value byte conversion.

## Local IPC smoke test (no Steam Deck required)

```bash
cargo build --manifest-path forge/Cargo.toml   # build the debug binary
python scripts/test_ipc.py
```

This spawns the persistent Forge binary via `relay/engine.py`, sends `ping`,
`get_status`, and `get_trainer(123456)` (resolved from `fixtures/`), and shows
structured errors for operations that need a live game. It proves the
Cockpit → Relay → Forge → response path.

## Running on a Steam Deck

1. Build Forge for the Deck (release): `cargo build --release`.
2. Build Cockpit: `npm run build`.
3. Copy `dist/`, `main.py`, `relay/`, `bin/deckforge-engine`, `plugin.json`,
   and (for dev) `fixtures/` into a Decky plugin directory, or use
   `scripts/deploy.sh` as a template.
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
