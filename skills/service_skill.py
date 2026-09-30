"""
ARGUS - Windows service control.

View and manage Windows services. The read half (list, status) reports what is
running and what a named service's state is. The write half (start, stop,
restart) follows ARGUS's one staging pattern -- the same shape power_skill
uses for shutdown/restart/sleep:

  REQUEST stages the action and asks for the command PIN.
  CONFIRM checks the PIN and only then executes it.
  CANCEL drops a staged action without executing.

NEVER EXECUTED ON A SINGLE UTTERANCE. Starting or stopping a service is
staged first and confirmed with the same PIN that gates power actions -- the
security section's rule ("confirmation/authorization layer rather than
arbitrary voice execution") applied to one more surface. A stopped service
can take a machine offline the way a shutdown can (Spooler, Winmgmt,
wuauserv), so it gets the same friction as power, at L1 with the PIN inside
the skill rather than auth's L3 confirmation -- because a PIN contest is the
gate, not a spoken "confirm" (see power_skill.py's own history of why "yes"
was retired as confirmation).

WHY psutil AND NOT 'net stop' / 'sc stop'. execpolicy's allowlist has no
shell, and service control through a subprocess would widen it. psutil
ships WIN_SERVICE support -- win_service_iter() to enumerate, win_service_get()
for one service, and WindowsService.start()/stop()/restart()/status() to act
-- all in-process, no new allowlist entry. The one honest cost is elevation:
start/stop need the same rights a 'net stop' would, and an un-elevated ARGUS
reports the AccessDenied plainly rather than hiding it.

READ SENSITIVITY. Which services are running, and a named service's state,
reveal nothing a local process can't already query. LIST/STATUS/CANCEL ride
L1 alongside the other machine reads.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time

import psutil
import secrets_store
from config import COMMAND_PIN

CONFIRM_WINDOW = 25        # seconds a staged action stays valid
MAX_PIN_ATTEMPTS = 3       # per staged action; same bound as power_skill

# "restart" is start-after-stop: it cannot keep a running service running,
# but a configured service a stopped service starves is the same category of
# surprise as the stops themselves, so it stays in the confirmed set.
ACTIONS = ("start", "stop", "restart")

_pending = {"action": None, "name": None, "at": 0.0, "attempts": 0}
# RLock, not Lock: request() holds _lock and then calls has_pending(), which
# also acquires _lock -- a plain Lock deadlocks the calling thread on every
# single call (reproduced: request() never returns). Reentrant lets the same
# thread re-enter; a second, different thread still blocks exactly as before.
_lock = threading.RLock()


def has_pending() -> bool:
    with _lock:
        return bool(_pending["action"]) and \
            (time.time() - _pending["at"] <= CONFIRM_WINDOW)


def list_services(target: str = "") -> str:
    """Which services are running vs stopped. target optionally narrows to
    services whose name or display contains that word."""
    try:
        services = list(psutil.win_service_iter())
    except Exception as e:
        return f"I couldn't list services: {type(e).__name__}: {e}"
    words = (target or "").strip().lower()
    running, stopped = [], []
    for svc in services:
        try:
            name = svc.name()
            disp = svc.display_name()
            if words and words not in name.lower() and words not in disp.lower():
                continue
            try:
                state = svc.status()
            except psutil.AccessDenied:
                state = "unknown"
            (running if state == "running" else stopped).append(name)
        except Exception:
            continue
    running.sort()
    stopped.sort()
    if not running and not stopped:
        return "I couldn't find any matching services."
    lines = []
    if running:
        lines.append(f"{len(running)} running: {', '.join(running[:12])}"
                     + ("…" if len(running) > 12 else ""))
    if stopped:
        lines.append(f"{len(stopped)} stopped: {', '.join(stopped[:12])}"
                     + ("…" if len(stopped) > 12 else ""))
    return ". ".join(lines) + "."


def status(target: str = "") -> str:
    """One service's state. target names it the way a human would -- the
    service name or its display name, matched either way."""
    name = (target or "").strip()
    if not name:
        return "Which service do you want the state of?"
    svc = _find(name)
    if svc is None:
        return (f"I don't see a service whose name or display matches "
                f"{name}.")
    try:
        state = svc.status()
    except psutil.AccessDenied:
        return f"{svc.display_name()} exists, but I can't read its state."
    except Exception as e:
        return f"I couldn't read {name}'s state: {e}"
    disp = svc.display_name()
    return f"{disp} is {state}."


def _find(name: str):
    """Match a service by exact name, then display-name-insensitive, then
    prefix/substring so 'spooler' finds 'spooler', not just 'Print Spooler'."""
    try:
        exact = psutil.win_service_get(name)
        exact.name()   # raises NotFound for a bad name
        return exact
    except Exception:
        pass
    n = name.lower()
    try:
        for svc in psutil.win_service_iter():
            try:
                if svc.name().lower() == n or svc.display_name().lower() == n:
                    return svc
            except Exception:
                continue
    except Exception:
        pass
    try:
        for svc in psutil.win_service_iter():
            try:
                if n in svc.name().lower() or n in svc.display_name().lower():
                    return svc
            except Exception:
                continue
    except Exception:
        pass
    return None


def request(action: str, name: str = "") -> str:
    """Stages a service action. Does NOT execute it."""
    if action not in ACTIONS:
        return f"I can do start, stop or restart, not {action}."
    n = (name or "").strip()
    if not n:
        return f"Which service do you want me to {action}?"
    svc = _find(n)
    if svc is None:
        return f"I don't see a service matching {n}."
    with _lock:
        if has_pending():
            current = f"{_pending['action']} {_pending['name']}"
            return (f"I've already got {current} staged. "
                    f"Say cancel first.")
        _pending["action"] = action
        _pending["name"] = svc.display_name()
        _pending["at"] = time.time()
        _pending["attempts"] = 0
    if not COMMAND_PIN:
        return ("You want me to " + f"{action} {svc.display_name()}. "
                "But no command PIN is set in config.py, so I can't "
                "confirm this. Set COMMAND_PIN first.")
    return (f"You want me to {action} {svc.display_name()}? "
            "Type your PIN in the operator channel to confirm.")


def confirm(supplied: str = "") -> str:
    """Executes the staged action if the PIN matches. Constant-time compare
    -- same reasoning as power_skill.confirm()."""
    with _lock:
        action = _pending["action"]
        name = _pending["name"]
        attempts = _pending["attempts"]
    if not action:
        return "There's nothing waiting for confirmation."
    if time.time() - _pending["at"] > CONFIRM_WINDOW:
        with _lock:
            _pending["action"] = None
        return "That confirmation expired. Ask me again if you still want it."
    if not COMMAND_PIN:
        with _lock:
            _pending["action"] = None
        return "No command PIN is set, so I can't confirm this."

    # ARGUS-SEC-011: the SHARED gate, not a bare verify_pin. One wrong-PIN
    # budget covers every confirming skill, so grinding three guesses here,
    # three on a staged shutdown and three on a service restart stops
    # multiplying the budget. Handles both a migrated PBKDF2 hash and a
    # legacy plaintext PIN, with compare_digest in both branches.
    import security as _security
    if _security.pin_gate_remaining() > 0:
        return (f"Too many wrong PINs across ARGUS. Try again in "
                f"{int(_security.pin_gate_remaining()) + 1} seconds.")
    if not _security.pin_gate_verify(supplied, COMMAND_PIN):
        attempts += 1
        with _lock:
            _pending["attempts"] = attempts
        if attempts >= MAX_PIN_ATTEMPTS:
            with _lock:
                _pending["action"] = None
                _pending["attempts"] = 0
            return ("That's not the right PIN, and that was the last attempt. "
                    "I've cancelled it — ask me again if you meant it.")
        return (f"That's not the right PIN. "
                f"{MAX_PIN_ATTEMPTS - attempts} attempt"
                f"{'s' if MAX_PIN_ATTEMPTS - attempts != 1 else ''} left, "
                f"or say cancel.")

    with _lock:
        _pending["action"] = None
        _pending["attempts"] = 0
    try:
        svc = _find(name)
        if svc is None:
            return (f"I confirmed, but {name} isn't there any more -- "
                    f"nothing to {action}.")
        if action == "start":
            svc.start()
        elif action == "stop":
            svc.stop()
        else:
            svc.restart()
        return f"Confirmed. {name} is being {action}ed."
    except psutil.AccessDenied:
        return (f"Confirmed, but I don't have the rights to {action} {name} "
                f"— start ARGUS as administrator for service control.")
    except Exception as e:
        return f"I couldn't {action} {name}: {e}"


def cancel() -> str:
    """Drops the staged action, whatever it was."""
    with _lock:
        pending = bool(_pending["action"])
        _pending["action"] = None
        _pending["attempts"] = 0
    return "Cancelled." if pending else "Nothing to cancel."