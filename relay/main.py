"""Decky-facing RPC surface for the DeckForge relay.

This exposes high-level callable methods to Cockpit. Each method is a thin
forwarder to the persistent Forge engine over JSON IPC. No trainer logic lives
here — Relay is transport only.
"""

from __future__ import annotations

import os
import sys

# Make sibling modules importable both as a package (relay.main) and standalone.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import decky  # type: ignore

    _HAS_DECKY = True
except ImportError:  # allow local testing without the Decky runtime
    decky = None  # type: ignore
    _HAS_DECKY = False

from engine import Engine, EngineError  # noqa: E402


def _log(msg: str) -> None:
    if _HAS_DECKY and decky is not None:
        decky.logger.info(msg)
    else:
        print(msg, file=sys.stderr)


class Plugin:
    """Decky plugin backend. Instantiated by Decky Loader; `_main` runs on load."""

    async def _main(self) -> None:
        self.engine = Engine(logger=_log)
        try:
            await self.engine.start()
            _log("DeckForge relay started")
        except EngineError as e:
            _log(f"DeckForge relay failed to start engine: {e}")
            # Keep a broken engine handle so RPC calls return ENGINE_NOT_RUNNING
            # envelopes instead of crashing; Decky can reload to retry.

    async def _unload(self) -> None:
        engine = getattr(self, "engine", None)
        if engine is not None:
            await engine.stop()
        _log("DeckForge relay unloaded")

    async def _uninstall(self) -> None:
        pass

    async def _migration(self) -> None:
        pass

    # --- Decky-facing RPC methods (called from Cockpit via @decky/api) -----

    async def get_status(self) -> dict:
        return await self.engine.request("get_status")

    async def get_active_game(self) -> dict:
        return await self.engine.request("get_active_game")

    async def detect_game(self) -> dict:
        """Auto-discovery: the currently running Steam game, or null."""
        return await self.engine.request("detect_game")

    async def attach_game(self, app_id: int) -> dict:
        return await self.engine.request("attach_game", appId=app_id)

    async def get_trainer(self, app_id: int | None = None) -> dict:
        params = {} if app_id is None else {"appId": app_id}
        return await self.engine.request("get_trainer", **params)

    async def enable_cheat(self, cheat_id: str) -> dict:
        return await self.engine.request("enable_cheat", cheatId=cheat_id)

    async def disable_cheat(self, cheat_id: str) -> dict:
        return await self.engine.request("disable_cheat", cheatId=cheat_id)

    async def set_value(self, cheat_id: str, value) -> dict:
        return await self.engine.request("set_value", cheatId=cheat_id, value=value)

    async def trigger_cheat(self, cheat_id: str) -> dict:
        """One-shot trigger for an `action`-control cheat (a Decky button)."""
        return await self.engine.request("trigger_cheat", cheatId=cheat_id)

    async def reload_trainer(self) -> dict:
        return await self.engine.request("reload_trainer")

    # --- Trainer store (browse / install / uninstall) ----------------------

    async def repo_list(self) -> dict:
        """Browse the remote trainer catalog (annotated with install status)."""
        return await self.engine.request("repo_list")

    async def repo_install(self, app_id: int) -> dict:
        """Start a background install; returns a job id to poll with
        ``install_status``."""
        return await self.engine.request("repo_install", appId=app_id)

    async def install_status(self, job_id: str) -> dict:
        """Poll an install job's progress/state."""
        return await self.engine.request("install_status", jobId=job_id)

    async def repo_uninstall(self, app_id: int) -> dict:
        """Remove an installed trainer package (idempotent)."""
        return await self.engine.request("repo_uninstall", appId=app_id)

    async def repo_list_installed(self) -> dict:
        """List locally installed trainers (no network)."""
        return await self.engine.request("repo_list_installed")
