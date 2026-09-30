"""
ARGUS - Privacy mode.

An always-listening microphone in a room where you take calls, handle
credentials, or have private conversations needs a hard off switch that isn't
buried in a settings menu.

When privacy mode is on, captured audio is discarded before transcription —
nothing is written to disk, nothing reaches a model. The only phrase still
acted on is the one that turns it back off.

STAGE 2 REGRESSION, FIXED HERE — the worst kind, a protection that silently
stopped protecting:

  enable()/disable() are dispatched by router.py, which runs in the
  ORCHESTRATOR process. is_muted() is called by listener._handle_segment,
  which after Stage 2 runs in the VOICE process. Those became two separate
  instances of this module with two separate _state dicts, so the mute set in
  one was invisible to the one that actually discards the audio.

  The failure was silent and actively misleading: ARGUS said "Privacy mode on.
  I've stopped listening", the HUD's mute indicator lit up (it reads
  /status, served by the orchestrator, which agreed), and the microphone kept
  transcribing everything.

The fix is a small block of shared memory that both processes read, rather
than an HTTP call from the voice process to ask. Reasons, in order:

  - is_muted() sits on the wake path, ahead of every transcription. A round
    trip there costs latency on the one check that must never be skipped.
  - It would have to fail somehow when the orchestrator is briefly
    unreachable, and BOTH answers are wrong: fail-open keeps a microphone live
    that the user believes is off, fail-closed makes ARGUS deaf whenever the
    orchestrator hiccups.
  - Shared memory has neither problem. Reading it is a lock and a load.

Both processes evaluate the expiry of a timed mute themselves, from the shared
deadline, so a timed mute lapses on schedule in the voice process even if
nothing in the orchestrator happens to call is_muted() in that window.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time
from datetime import datetime, timedelta

_state = {"muted": False, "until": None, "since": None}
_lock = threading.Lock()

# (multiprocessing.Value('b'), multiprocessing.Value('d')) once attached, or
# None when ARGUS runs as a single process — direct `python listener.py`, and

# kept working rather than left as dead code.
_mirror = None


def attach_mirror(muted_flag, until_ts):
    """Points this module at shared memory. Call once per process, at startup.

    Pushes whatever local state already exists, so attaching after a mute was
    set cannot silently drop it.
    """
    global _mirror
    _mirror = (muted_flag, until_ts)
    with _lock:
        muted, until = _state["muted"], _state["until"]
    if muted:
        _write(True, until.timestamp() if until else 0.0)


def _write(muted: bool, until_epoch: float):
    muted_flag, until_ts = _mirror
    # muted_flag's lock guards BOTH values: they are two separate Values with
    # two separate locks, and a reader must never see one updated without the
    # other (an indefinite mute momentarily wearing a stale deadline would
    # expire itself immediately).
    with muted_flag.get_lock():
        muted_flag.value = 1 if muted else 0
        until_ts.value = until_epoch


def _current():
    """(muted, until_epoch) from whichever store is authoritative, with an
    elapsed timed mute cleared as a side effect — in this process, without
    needing the other one to notice first."""
    if _mirror is not None:
        muted_flag, until_ts = _mirror
        with muted_flag.get_lock():
            if not muted_flag.value:
                return False, 0.0
            until = until_ts.value
            if until and time.time() > until:
                muted_flag.value = 0
                until_ts.value = 0.0
                print("[privacy] timed mute expired — listening again")
                return False, 0.0
            return True, until

    with _lock:
        if _state["muted"] and _state["until"] and datetime.now() > _state["until"]:
            _state["muted"] = False
            _state["until"] = None
            _state["since"] = None
            print("[privacy] timed mute expired — listening again")
        until = _state["until"]
        return _state["muted"], until.timestamp() if until else 0.0


def is_muted() -> bool:
    """Also handles timed mutes expiring on their own."""
    return _current()[0]


def enable(minutes: int | None = None) -> str:
    import security
    until = datetime.now() + timedelta(minutes=minutes) if minutes else None
    with _lock:
        _state["muted"] = True
        _state["since"] = datetime.now()
        _state["until"] = until
    if _mirror is not None:
        _write(True, until.timestamp() if until else 0.0)
    security.audit("privacy", f"enabled {minutes or 'indefinite'}")
    if minutes:
        return f"Privacy mode on for {minutes} minutes. I'll stop listening until then."
    return "Privacy mode on. I've stopped listening. Say 'Argus start listening' to resume."


def disable() -> str:
    import security
    was = _current()[0]
    with _lock:
        _state["muted"] = False
        _state["until"] = None
        _state["since"] = None
    if _mirror is not None:
        _write(False, 0.0)
    security.audit("privacy", "disabled")
    return "Listening again." if was else "I'm already listening."


def status() -> str:
    muted, until_epoch = _current()
    if not muted:
        return "I'm listening normally."
    if until_epoch:
        mins = max(0, int((until_epoch - time.time()) / 60))
        return f"Privacy mode is on for another {mins} minutes."
    return "Privacy mode is on. I'm not listening."
