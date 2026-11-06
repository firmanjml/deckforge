"""Forge engine lifecycle + JSON IPC transport.

Relay is intentionally tiny: it spawns the persistent Rust ``deckforge-engine``
binary, keeps it alive while the Decky plugin is loaded, forwards JSON requests
over stdin, and routes JSON responses from stdout by request id. It contains no
trainer logic whatsoever.

All requests return the raw engine response envelope ``{"ok": bool, "data": ...,
"error": {"code", "message"}}`` so Cockpit can branch on structured error codes
without parsing free-text strings. Transport failures (engine not running,
timeout) are surfaced as synthetic envelopes with the ``ENGINE_NOT_RUNNING``
code.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class EngineError(Exception):
    """A structured error with a stable wire ``code``."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------

def _plugin_root() -> str:
    # engine.py lives in <root>/relay/engine.py
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resolve_binary_path() -> str:
    """Locate the deckforge-engine executable.

    Order: ``DECKFORGE_ENGINE_PATH`` env var, then ``bin/``, then cargo release
    and debug output (for local development). Falls back to ``bin/`` so a missing
    binary produces a clear error at start time.
    """
    env = os.environ.get("DECKFORGE_ENGINE_PATH")
    if env and os.path.isfile(env):
        return env

    root = _plugin_root()
    candidates = [
        os.path.join(root, "bin", "deckforge-engine"),
        os.path.join(root, "forge", "target", "release", "deckforge-engine"),
        os.path.join(root, "forge", "target", "debug", "deckforge-engine"),
    ]
    if os.name == "nt":  # allow Windows dev builds
        candidates += [
            os.path.join(root, "bin", "deckforge-engine.exe"),
            os.path.join(root, "forge", "target", "release", "deckforge-engine.exe"),
            os.path.join(root, "forge", "target", "debug", "deckforge-engine.exe"),
        ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return os.path.join(root, "bin", "deckforge-engine")


def resolve_trainer_dir(binary_path: str) -> str:
    """Locate the directory holding installed trainer packages.

    Order: ``DECKFORGE_TRAINER_DIR`` env var, then Decky's persistent runtime
    directory (which survives plugin updates), then ``fixtures/trainers`` next
    to the plugin for local development outside Decky.
    """
    override = os.environ.get("DECKFORGE_TRAINER_DIR")
    if override:
        return override
    runtime_dir = os.environ.get("DECKY_PLUGIN_RUNTIME_DIR")
    if runtime_dir:
        return os.path.join(runtime_dir, "trainers")
    plugin_dir = os.path.dirname(os.path.dirname(binary_path))
    return os.path.join(plugin_dir, "fixtures", "trainers")


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 15.0


def _envelope(ok: bool, data: Any = None, code: str = "", message: str = "") -> dict:
    env: dict = {"ok": ok}
    if ok:
        env["data"] = data
    else:
        env["error"] = {"code": code or "ENGINE_NOT_RUNNING", "message": message}
    return env


class Engine:
    """Manages the persistent Forge child process and JSON request/response."""

    def __init__(self, logger: Optional[Callable[[str], None]] = None):
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._counter = 0
        self._pending: dict[str, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None
        self._stderr_task: Optional[asyncio.Task] = None
        self._log = logger or _default_logger

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def start(self) -> None:
        if self.running:
            return
        path = resolve_binary_path()
        self._log(f"starting forge engine: {path}")
        try:
            trainer_dir = resolve_trainer_dir(path)
            env = dict(os.environ)
            env["DECKFORGE_TRAINER_DIR"] = trainer_dir
            self._log(f"trainer dir: {trainer_dir}")

            self._proc = await asyncio.create_subprocess_exec(
                path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except (FileNotFoundError, PermissionError, OSError) as e:
            self._proc = None
            raise EngineError(
                "ENGINE_NOT_RUNNING", f"cannot start forge binary ({path}): {e}"
            )
        self._reader_task = asyncio.create_task(self._read_stdout())
        self._stderr_task = asyncio.create_task(self._read_stderr())

    async def ensure_running(self) -> None:
        if not self.running:
            await self.start()

    async def stop(self) -> None:
        if not self._proc:
            return
        # Ask the engine to shut down cleanly, then escalate.
        try:
            await asyncio.wait_for(self._send("shutdown"), timeout=2.0)
        except Exception:
            pass
        try:
            self._proc.terminate()
            await asyncio.wait_for(self._proc.wait(), timeout=3.0)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass
        self._proc = None
        self._fail_pending("engine stopped")

    async def _read_stdout(self) -> None:
        assert self._proc and self._proc.stdout
        try:
            while True:
                line = await self._proc.stdout.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line.decode())
                except json.JSONDecodeError:
                    self._log(f"forge: unparseable stdout line: {line!r}")
                    continue
                rid = msg.get("id")
                fut = self._pending.pop(rid, None) if rid is not None else None
                if fut is not None and not fut.done():
                    fut.set_result(msg)
        except Exception as e:  # noqa: BLE001
            self._log(f"forge stdout reader ended: {e}")
        finally:
            # Process exited: fail any in-flight requests.
            self._fail_pending("forge engine process exited")

    async def _read_stderr(self) -> None:
        assert self._proc and self._proc.stderr
        try:
            while True:
                line = await self._proc.stderr.readline()
                if not line:
                    break
                self._log(f"forge: {line.decode().rstrip()}")
        except Exception:
            pass

    def _fail_pending(self, reason: str) -> None:
        for rid, fut in list(self._pending.items()):
            if not fut.done():
                fut.set_exception(EngineError("ENGINE_NOT_RUNNING", reason))
        self._pending.clear()

    async def _send(self, command: str, **params) -> str:
        """Write a request line; returns the assigned request id."""
        if not self.running or self._proc is None or self._proc.stdin is None:
            raise EngineError("ENGINE_NOT_RUNNING", "forge engine is not running")
        self._counter += 1
        rid = f"relay-{self._counter}"
        req = {"id": rid, "command": command, **params}
        self._proc.stdin.write((json.dumps(req) + "\n").encode())
        await self._proc.stdin.drain()
        return rid

    async def request(self, command: str, **params) -> dict:
        """Send a command and await its response envelope.

        Never raises on normal engine errors — returns a structured envelope so
        the caller can branch on ``error.code``. Raises only if cancelled.
        """
        try:
            await self.ensure_running()
        except EngineError as e:
            return _envelope(False, code=e.code, message=e.message)

        loop = asyncio.get_running_loop()
        try:
            rid = await self._send(command, **params)
        except EngineError as e:
            return _envelope(False, code=e.code, message=e.message)
        except Exception as e:  # noqa: BLE001
            return _envelope(False, message=f"failed to send request: {e}")

        fut = loop.create_future()
        self._pending[rid] = fut
        try:
            msg = await asyncio.wait_for(fut, timeout=DEFAULT_TIMEOUT)
            return msg
        except asyncio.TimeoutError:
            self._pending.pop(rid, None)
            return _envelope(False, message=f"request '{command}' timed out")
        except EngineError as e:
            return _envelope(False, code=e.code, message=e.message)
        except Exception as e:  # noqa: BLE001
            return _envelope(False, message=f"request '{command}' failed: {e}")


def _default_logger(msg: str) -> None:
    print(msg, file=sys.stderr)
