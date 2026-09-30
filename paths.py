"""
ARGUS - Path resolution.

A PyInstaller build changes where files live. Running as a script, data sits
next to the source. Frozen, PyInstaller unpacks bundled data into a separate
directory and points sys._MEIPASS at it — so a relative path like
"voices/en_GB-alan-medium.onnx" resolves against the wrong place and the app
starts, then silently fails to speak.

Worse, the bundle directory shouldn't be treated as writable, so anything
generated at runtime has to go somewhere else.

Every path in ARGUS goes through here so both cases behave identically.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import sys


def is_frozen() -> bool:
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def ensure_std_streams():
    """Give sys.stdout/stderr somewhere to go when there is no console.

    PyInstaller's --windowed bootloader sets both to None. Python's print()
    tolerates that, so the app appears to start -- but uvicorn does not.
    Its colour formatter calls sys.stdout.isatty() while configuring logging:

        uvicorn/logging.py: self.use_colors = sys.stdout.isatty()
        AttributeError: 'NoneType' object has no attribute 'isatty'

    which fails the whole dictConfig, kills the orchestrator thread before it
    binds a port, and leaves the launcher reporting only "the orchestrator did
    not respond within 40 seconds". Launched from a terminal the same build
    works, because the console supplies a real stdout -- exactly the reported
    "you must run it through PowerShell or it will not open at all".

    Lives here because every entry point needs it and each is reached
    independently: argus.py, the orchestrator, and each spawned worker, which
    re-imports from scratch under spawn and gets its own None streams.

    Safe to call more than once.
    """
    # Second failure mode, same symptom family: the streams exist but were
    # created from a pipe in the console codepage (cp1252 here). The banner
    # carries a U+00B7 middle dot, so printing it into a UTF-8-capturing
    # parent's pipe writes byte 0xB7 and the parent's decoder dies with
    # UnicodeDecodeError before it ever reads the actual refusal message.
    # Force UTF-8 with replacement on every real stream: anything ARGUS
    # prints must survive any reader's expectations.
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass  # stream already detached; a real write failure will surface on its own
    if sys.stdout is not None and sys.stderr is not None:
        return
    devnull = open(os.devnull, "w", encoding="utf-8", errors="replace")
    if sys.stdout is None:
        sys.stdout = devnull
    if sys.stderr is None:
        sys.stderr = devnull


def resource(*parts) -> str:
    """Read-only bundled data: the HUD, voice models, skills."""
    if is_frozen():
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, *parts)


def writable(*parts) -> str:
    """Anything generated at runtime. Never inside the bundle."""
    base = os.path.join(
        os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "ARGUS"
    )
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, *parts)


def app_dir() -> str:
    """Where the executable or main script actually lives."""
    if is_frozen():
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))
