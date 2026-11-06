# Trainer Store

DeckForge can browse a public GitHub repository of trainer packages, download
a trainer for the current game, and install it — **without a plugin update**.
Forge owns all of this (it is the source of truth for trainer state); Relay
only forwards requests; Cockpit only renders.

```
Cockpit  StorePage.tsx
   │  repo_list / repo_install / install_status / repo_uninstall / repo_list_installed
   ▼
Relay    (5 thin forwarders)
   │  JSON IPC
   ▼
Forge    store module  ──►  GitHub (git trees API + raw.githubusercontent.com)
```

## Repository layout

The default repository is
[`github.com/firmanjml/deckforge-trainers`](https://github.com/firmanjml/deckforge-trainers)
on branch `main`. It mirrors the DeckForge trainer-package layout — **one
directory per Steam AppID**, each containing `trainer.json` plus an optional
`scripts/` tree. There is no manifest to maintain: the catalog is derived from
the trainers themselves.

```
deckforge-trainers/                 (branch: main)
└── trainers/
    ├── 1091500/
    │   ├── trainer.json            ← standard DeckForge trainer schema
    │   └── scripts/                (optional: .asm / .lua)
    │       └── infinite_health.asm
    └── 1245620/
        └── trainer.json
```

Each `trainer.json` uses the existing DeckForge format. The store reads
`game.steamAppId`, `game.name`, `trainer.name`, `trainer.version`, and
`trainer.author` for the catalog.

## Publishing your cheat

Community trainers are published through pull requests to
[`firmanjml/deckforge-trainers`](https://github.com/firmanjml/deckforge-trainers).
Do not add a game-specific trainer to the DeckForge engine repository. The
store repository is the source of external trainer packages.

### Submission workflow

1. Fork `deckforge-trainers` and create a branch for one game or one focused
   trainer update.
2. Add the package at `trainers/<steam-app-id>/trainer.json`, with optional
   `.asm` and `.lua` files below `trainers/<steam-app-id>/scripts/`.
3. Confirm that the directory name and `game.steamAppId` are identical, the
   Proton process name is correct, script paths stay inside the package, and
   every referenced file exists.
4. Preserve the original trainer/table author, source link, and applicable
   license. Do not submit game files, memory dumps, proprietary trainer
   executables, or a CE table you do not have permission to redistribute.
5. Test every cheat against the stated game build on SteamOS/Proton. Test both
   enable and disable behavior, combinations of cheats that share components,
   trainer reload, and game exit/relaunch.
6. Commit the package, push your branch, and open a pull request against the
   `main` branch of `deckforge-trainers`.

Use `trainer: add <game name> (<appid>)` for a new trainer PR title and
`trainer: update <game name> (<appid>)` for an existing package.

### Validate the package locally

First check the file against the schema, which finds misspelled fields and
control and action pairs that can never work (see "Validate with the JSON schema"
in the [readme](../readme.md)). Then build Forge, point it at the checkout's
`trainers/` directory, and request the trainer by AppID. This exercises the real loader, JSON schema validation,
script path jail, referenced-file checks, and Auto Assembler/Lua file loading
without requiring a running game:

```bash
cargo build --manifest-path /path/to/deckforge/forge/Cargo.toml
export DECKFORGE_TRAINER_DIR=/path/to/deckforge-trainers/trainers
printf '%s\n' \
  '{"id":"validate","command":"get_trainer","appId":123456}' \
  '{"id":"stop","command":"shutdown"}' \
  | /path/to/deckforge/forge/target/debug/deckforge-engine
```

Replace `123456` and both paths. The `validate` response must have `"ok":
true` and return the intended trainer. This proves that the package loads; it
does not prove that its signatures, offsets, hooks, or memory writes work in
the game.

Run the DeckForge test suite when the submission also changes engine-facing
fixtures or is being developed alongside an engine change:

```bash
cargo test --manifest-path /path/to/deckforge/forge/Cargo.toml
```

### Pull request template

Copy the following template into the pull-request description. Replace every
placeholder and report real results. Do not mark an item as passed when it was
not tested; write `Not tested` and explain why.

````markdown
## Trainer

- Game: `<game name>`
- Steam AppID: `<appid>`
- Process/module: `<game.exe>`
- Tested game build: `<version/build/date>`
- Trainer version: `<version>`
- Submission type: `New trainer | Trainer update`

## Summary

<!-- Explain what this trainer adds or changes. -->

- `<cheat or change>`
- `<cheat or change>`

## Source and license

- Original table/trainer author: `<name or N/A>`
- DeckForge port author: `<name>`
- Source URL: `<URL or N/A for original work>`
- Source license/permission: `<license or permission details>`
- Attribution retained in package: `Yes | No - explain`

I confirm that I have permission to submit and redistribute every file in this
package and that it contains no game files, memory dumps, or trainer
executables.

## Package validation results

- [ ] `trainers/<appid>/trainer.json` validates against `trainer.schema.json`.
- [ ] `trainers/<appid>/trainer.json` parses and loads through Forge.
- [ ] The package directory matches `game.steamAppId`.
- [ ] All `.asm`/`.lua` paths are relative and resolve inside the package.
- [ ] Every `requires` entry names an existing bootstrap component.
- [ ] Every AOB used by this trainer has exactly one match on the tested build.
- [ ] Patch expected/enabled byte lengths match and cover whole instructions.

Forge loader command:

```text
<exact command used>
```

Forge loader result:

```text
<paste the validate response, including ok/error status>
```

Automated test result:

```text
Command: <cargo test command, or Not run with reason>
Result: <passed/failed/not run; include test counts and relevant failures>
```

## On-device test results

- Device/OS: `<Steam Deck model and SteamOS version>`
- Proton version: `<version>`
- Test mode: `Offline/single-player; anti-cheat not active`

| Cheat | Enable/apply | Disable/restore | Reload/relaunch | Notes |
|---|---|---|---|---|
| `<cheat name>` | `Pass/Fail` | `Pass/Fail/N/A` | `Pass/Fail` | `<details>` |
| `<cheat name>` | `Pass/Fail` | `Pass/Fail/N/A` | `Pass/Fail` | `<details>` |

- [ ] Stateful cheats restore original behavior when disabled.
- [ ] Shared bootstrap components work with all dependent cheats.
- [ ] Repeated enable/disable cycles do not fail.
- [ ] Trainer reload succeeds with cheats active.
- [ ] Game exit stops all active writes; relaunch resolves fresh addresses.
- [ ] Cheats were tested together where interactions are possible.

## Known limitations

<!-- List build restrictions, required game state, untested paths, or N/A. -->

- `<limitation or N/A>`

## Reviewer notes

<!-- Highlight unusual hooks, Lua discovery, shared symbols, or risky areas. -->

- `<note or N/A>`
````

A pull request may be rejected when test results are missing, the package does
not load, a signature is ambiguous, disable behavior is not demonstrated, or
the submission's source and redistribution rights are unclear.

## How discovery & download work

- **Catalog (`repo_list`)**: one call to the GitHub **git trees API**
  (`GET /repos/{owner}/{repo}/git/trees/{ref}?recursive=1`, cached for 10 min),
  then each `trainer.json` is fetched via `raw.githubusercontent.com` (a CDN,
  not rate-limited like the API) for its metadata. Results are cross-referenced
  with the local trainer directory to flag `installed` / `updateAvailable`.
- **Install (`repo_install`)**: the cached tree enumerates every file under
  `trainers/<appid>/`; each is fetched via `raw.githubusercontent.com` and
  written to disk, preserving structure. This handles multi-file packages
  (scripts/) with no zip/tarball dependency.
- **Uninstall (`repo_uninstall`)**: removes `<trainer_dir>/<appid>/`.

Install runs on a **background worker thread** so a download never blocks
Forge's stdin loop or risks Relay's request timeout. `repo_install` returns a
job id immediately; Cockpit polls `install_status` until `done`/`failed`. The
worker does only network + disk + validation; the main thread hot-reloads the
trainer (once) when the job finishes and matches the attached game.

## Install target

Downloads are written into **`trainer::loader::trainer_dir()`** — the same
directory Forge loads trainers from:

- **Under Decky:** `$DECKY_PLUGIN_RUNTIME_DIR/trainers`. Relay sets
  `DECKFORGE_TRAINER_DIR` to this when it spawns Forge, so trainers survive
  plugin updates.
- **Outside Decky:** `fixtures/trainers`, unless `DECKFORGE_TRAINER_DIR` is set.

Routing through `trainer_dir()` guarantees the store writes to *exactly* the
path Forge reads from.

## Atomic, safe installation

1. Files download into `<trainer_dir>/<appid>.new/` (staging).
2. Every path is **jailed** to the package: absolute paths, `..`, backslashes,
   and drive letters are rejected (zip-slip / cross-platform defense).
3. The staged package is validated with the real loader
   (`load_trainer_from_dir`) before it is swapped in.
4. The previous install is moved aside to `<appid>.old/`, staging is renamed
   into place, and `.old` is removed. A failed validation or a crash
   mid-download never corrupts an existing working trainer.

## Configuration (environment variables, all optional)

| Variable | Default | Purpose |
|---|---|---|
| `DECKFORGE_REPO_OWNER` | `firmanjml` | GitHub repo owner |
| `DECKFORGE_REPO_NAME` | `deckforge-trainers` | GitHub repo name |
| `DECKFORGE_REPO_REF` | `main` | branch / ref |
| `DECKFORGE_REPO_TOKEN` | *(none)* | optional PAT → 5000/hr API limit instead of 60/hr |
| `DECKFORGE_TRAINER_DIR` | `$DECKY_PLUGIN_RUNTIME_DIR/trainers` under Decky, otherwise `fixtures/trainers` | install target |

Forge inherits these from its environment (Relay spawns it with
`env = dict(os.environ)`), so set them in the Decky/Relay environment.

## Protocol commands (Forge IPC)

| Command | Fields | Returns |
|---|---|---|
| `repo_list` | — | `{ trainers: [CatalogItem] }` |
| `repo_install` | `appId` | `{ jobId }` |
| `install_status` | `jobId` | `{ state, progress, error?, appId, reloaded }` |
| `repo_uninstall` | `appId` | `{ appId, uninstalled }` |
| `repo_list_installed` | — | `{ trainers: [InstalledTrainer] }` |

`state` ∈ `queued` · `downloading` · `validating` · `done` · `failed`.

## Error codes

| Code | Meaning |
|---|---|
| `REPO_NETWORK_ERROR` | A network request failed (DNS, connect, non-2xx). |
| `REPO_NOT_FOUND` | The AppID is not in the repository (or the package has no `trainer.json`). |
| `REPO_INVALID_PACKAGE` | A downloaded package failed validation. |
| `REPO_JOB_NOT_FOUND` | An unknown job id was polled. |
| `REPO_RATE_LIMITED` | GitHub API returned a 403 rate-limit response. |
| `REPO_IO_ERROR` | A local filesystem operation failed. |

## Security & trust

- The repository is public; trainers are validated by the existing `validator`
  before use. No code execution beyond what trainer packages already allow
  (declarative cheats + sandboxed Lua/Auto Assembler scripts).
- Downloaded paths are jailed; packages are validated before swap-in.
- `DECKFORGE_REPO_TOKEN`, if set, is sent only as a GitHub `Authorization`
  header and is never logged.

## Development & testing

Forge store unit tests (no network):

```
cargo test --manifest-path forge/Cargo.toml -- store:: trainer::loader::
```

- `store::repo::parse_packages` is tested against a recorded trees-API JSON
  fixture.
- `store::install` tests cover path jailing, the atomic swap, validation
  failure cleanup, and idempotent uninstall (temp directories).
- `trainer::loader` tests cover `load_trainer_from_dir` and
  `installed_trainers`.

### End-to-end test

1. Create `trainers/<appid>/trainer.json` in the `deckforge-trainers` repo.
2. Launch a game with that AppID, open DeckForge, select the store icon next to
   the title, and open the **Browse** tab.
3. Click **Install**; the progress bar advances; on `done` the trainer appears
   in the main view.
4. **Remove** uninstalls it.

## Scaling notes (future)

- `repo_list` fetches each `trainer.json` for metadata when the cache is cold.
  For a large catalog this could be moved to a background job or parallelized.
- Auto-update checks and signed packages (per-trainer `sha256`) are future work.
