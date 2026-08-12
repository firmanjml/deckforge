"""Decky backend entry shim.

Decky Loader imports ``main.py`` from the plugin root and looks for a ``Plugin``
class. DeckForge keeps its backend logic in ``relay/`` per the AGENTS.md
architecture; this file only re-exports that ``Plugin`` so the source tree stays
organized while remaining compatible with Decky's loader contract.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from relay.main import Plugin  # noqa: E402,F401
