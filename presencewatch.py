"""
ARGUS - Noticing that you came back.

faceauth already watches for you LEAVING: two consecutive misses at the camera
and it locks. What it cannot do is notice you RETURN, and the reason is one
line in its own tick:

    if not _presence["on"] or not auth.is_unlocked():
        return False

Once locked, presence stops. So ARGUS could shut the door behind you and then
never look up again. This module is the other half, and it lives outside
faceauth on purpose: faceauth is one of the CRITICAL files, ACL-locked because
it supplies an authentication factor, and a convenience feature is not a good
enough reason to unlock the security layer. Everything here uses its public,
read-only API.

IT GREETS. IT DOES NOT UNLOCK. This is not a limitation to be engineered
around later -- auth.py classes face as presence-only precisely because an
RGB camera cannot tell a person from a photograph of one. Recognising you is
enough to say hello and enough to put the PIN box in front of you. It is not,
and must never become, enough to open the machine.

THE CAMERA IS NOT HELD. Checks are spaced, each one opens and releases the
device through faceauth.grab_frames(), and the watch expires after
RETURN_WATCH_S so a machine left overnight is not waking its webcam until
morning. It also stops entirely while the Windows session itself is locked --
if the workstation is locked, nobody is sitting there to be greeted.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time

CHECK_INTERVAL_S = 20.0     # tighter than faceauth's 45s: returning should feel
                            # immediate, and this only runs while locked
RETURN_WATCH_S = 4 * 3600   # then stop looking; see the module docstring
GREET_COOLDOWN_S = 300.0    # never greet twice for one return

# How long at the machine before ARGUS mentions it. Two marks, not a running
# commentary: something that reminds you hourly is something you mute, and a
# muted assistant does not mention the six-hour one either.
LONG_SESSION_S = 3 * 3600
VERY_LONG_SESSION_S = 6 * 3600

_lock = threading.RLock()
_state = {
    "running": False,
    "locked_since": 0.0,
    "last_greet": 0.0,
    "greets": 0,
    "checks": 0,
    "last_error": "",
    "watching": False,
    # Continuous time unlocked, for the break reminder. Reset by locking --
    # which is the point: a lock IS a break, so coming back starts the clock
    # again rather than resuming a tally from this morning.
    "unlocked_since": 0.0,
    "session_marks": set(),
}


def _ready() -> bool:
    """Is there anything to watch for? Cheap, and never raises."""
    try:
        import faceauth
        return bool(faceauth.presence_enabled() and faceauth.is_enrolled())
    except Exception:
        return False


def _workstation_locked() -> bool:
    """True when Windows itself is locked -- nobody is there to greet.

    auth.py owns this check; borrowed rather than reimplemented so there is
    one definition of "the session is locked". Absent or failing, assume NOT
    locked: the cost of being wrong is one extra camera check, and the cost
    of the opposite assumption is never greeting anyone.
    """
    try:
        import auth
        fn = getattr(auth, "_workstation_is_locked", None)
        return bool(fn()) if callable(fn) else False
    except Exception:
        return False


def should_watch(now: float) -> bool:
    """Whether a check is worth making right now. Pure enough to test."""
    if not _ready():
        return False
    try:
        import auth
        if auth.is_unlocked():
            return False          # faceauth's own loop owns the unlocked case
    except Exception:
        return False
    with _lock:
        since = _state["locked_since"]
    if not since:
        return True               # just noticed the lock; start the clock
    return (now - since) <= RETURN_WATCH_S


def _maybe_mention_session(now: float) -> str:
    """Mention a long stretch at the machine, once per mark. Never raises.

    Independent of the face watch above: a break reminder should not require
    having enrolled a face, and tying it to that would hide it from everyone
    who never set the camera up.

    Each mark fires ONCE per continuous session. announce's own quiet hours
    and rate limits still apply, and it is deliberately not urgent -- a
    reminder to stretch is not worth waking anyone.
    """
    with _lock:
        since = _state["unlocked_since"]
        marks = set(_state["session_marks"])
    if not since:
        return ""
    elapsed = now - since

    kind = ""
    if elapsed >= VERY_LONG_SESSION_S and "very_long" not in marks:
        kind = "very_long_session"
        marks.add("very_long")
    elif elapsed >= LONG_SESSION_S and "long" not in marks:
        kind = "long_session"
        marks.add("long")
    if not kind:
        return ""

    # Recorded BEFORE announcing. If announce refuses -- quiet hours, privacy
    # mode, rate limit -- the mark is still spent, so it does not retry every
    # twenty seconds for the rest of the evening.
    with _lock:
        _state["session_marks"] = marks
    try:
        import announce
        announce.say(kind, now)
    except Exception:
        pass
    return kind


def _tick(now: float = None) -> bool:
    """One check. True if it greeted. Never raises."""
    now = now or time.time()

    try:
        import auth
        unlocked = auth.is_unlocked()
    except Exception:
        return False

    with _lock:
        if unlocked:
            # Back in. Reset so the NEXT lock starts a fresh watch, and arm
            # the greeting again for next time.
            _state["locked_since"] = 0.0
            _state["watching"] = False
            if not _state["unlocked_since"]:
                _state["unlocked_since"] = now
        else:
            # A lock IS a break. Clearing the clock here is why coming back
            # starts a fresh session rather than resuming this morning's tally.
            _state["unlocked_since"] = 0.0
            _state["session_marks"] = set()

    if unlocked:
        _maybe_mention_session(now)
        return False

    with _lock:
        if not _state["locked_since"]:
            _state["locked_since"] = now

    if not should_watch(now):
        with _lock:
            _state["watching"] = False
        return False
    if _workstation_locked():
        with _lock:
            _state["watching"] = False
        return False

    with _lock:
        _state["watching"] = True
        if now - _state["last_greet"] < GREET_COOLDOWN_S:
            return False

    try:
        import faceauth
        recognised, _msg = faceauth.recognise()
        with _lock:
            _state["checks"] += 1
    except Exception as e:
        with _lock:
            _state["last_error"] = f"{type(e).__name__}"
        return False

    if not recognised:
        return False

    # Seen. Say hello -- and nothing more. The PIN panel opens itself on the
    # next auth request; this does not and cannot unlock anything.
    try:
        import announce
        if not announce.say("welcome_back", now):
            return False
    except Exception as e:
        with _lock:
            _state["last_error"] = f"announce: {type(e).__name__}"
        return False

    with _lock:
        _state["last_greet"] = now
        _state["greets"] += 1
    return True


def _loop():
    while True:
        with _lock:
            if not _state["running"]:
                return
        try:
            _tick()
        except Exception as e:
            with _lock:
                _state["last_error"] = f"loop: {type(e).__name__}"
        time.sleep(CHECK_INTERVAL_S)


def start() -> bool:
    """Begin watching. Idempotent, and inert when face presence is not set up."""
    with _lock:
        if _state["running"]:
            return True
        _state["running"] = True
    threading.Thread(target=_loop, name="presence-return", daemon=True).start()
    return True


def stop():
    with _lock:
        _state["running"] = False


def status() -> dict:
    now = time.time()
    with _lock:
        since = _state["locked_since"]
        return {
            "running": _state["running"],
            "watching_for_return": _state["watching"],
            "locked_for_s": int(now - since) if since else 0,
            "watch_expires_in_s": max(0, int(RETURN_WATCH_S - (now - since)))
                                  if since else 0,
            "greets": _state["greets"],
            "checks": _state["checks"],
            "session_s": int(now - _state["unlocked_since"])
                         if _state["unlocked_since"] else 0,
            "last_error": _state["last_error"],
            # Stated because it is the security property, not a detail.
            "can_unlock": False,
        }
