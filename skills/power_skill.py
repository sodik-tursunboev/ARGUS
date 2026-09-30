"""
ARGUS - Power control.

Shutdown, restart, and sleep are the only commands in the system that can
destroy unsaved work, and they're triggered by a speech recognizer that
occasionally mishears. So they are NEVER executed on a single utterance.

ARGUS stages the action, says what it's about to do, and waits for the
command PIN (config.COMMAND_PIN) within a short window. Anything else —
silence, a different command, the wrong PIN, a timeout — cancels it.

BUGFIX: this used to accept a plain "yes" as confirmation. That's not
really authorization at all -- it means either a mishearing OR anyone else
in the room can power off the machine just by being in earshot when it's
staged. A PIN (meant to be typed into the operator channel, not spoken --
see config.COMMAND_PIN) is the actual "only you can command this" gate.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import subprocess
import time

import secrets_store
from config import COMMAND_PIN

CONFIRM_WINDOW = 25  # seconds the staged action stays valid

# A wrong PIN leaves the action STAGED so a genuine typo can be corrected
# without re-asking. That is deliberate and convenient, but with no counter it
# also meant unlimited guesses inside the window, and re-staging is a single
# utterance -- so there was no attempt limit on the one gate protecting
# shutdown at all. The global HTTP rate limit (30/60s) bounds it in practice;
# this bounds it on purpose.
#
# Three is enough for a fat-fingered PIN and far short of useful for guessing.
MAX_PIN_ATTEMPTS = 3

_pending = {"action": None, "at": 0.0, "attempts": 0}

# Failures that OUTLIVE the staged action. _pending is wiped by every
# request(), which is exactly why the per-action counter could be farmed --
# see request(). This one is cleared only by a correct PIN.
#
# ARGUS-SEC-004: PERSISTED across restarts. The threat model grants the
# attacker "ability to restart Argus", and this counter used to live only in
# memory -- so a wrong-PIN lockout was erased by relaunching, turning the
# limit into "3 guesses per restart, forever". Now the count and the
# locked-until time are written to the state directory and reloaded on start,
# so a restart loop no longer resets the lockout.
#
# HONEST LIMIT: an attacker running AS the user can delete this file, just as
# they can delete any user-writable state. This defeats an opportunistic or
# accidental reset, not a scripted attacker who owns the account -- against
# whom the real defence is PIN entropy multiplied by the 200k-round PBKDF2
# cost (~38 ms/guess), which no client-side lockout can add to.
import paths as _paths

_FAILURES_PATH = _paths.writable("pin_failures.json")
_failures = {"count": 0, "locked_until": 0.0}


def _load_failures():
    global _failures
    try:
        import json
        with open(_FAILURES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _failures = {"count": int(data.get("count", 0)),
                         "locked_until": float(data.get("locked_until", 0.0))}
    except (OSError, ValueError, TypeError):
        pass


def _save_failures():
    try:
        import json
        import os
        tmp = _FAILURES_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_failures, f)
        os.replace(tmp, _FAILURES_PATH)
    except OSError:
        pass


_load_failures()

# After this many wrong PINs in total, refuse to stage anything for a while.
# Set above MAX_PIN_ATTEMPTS so a single honest fumble (three tries on one
# staged action) does not lock the owner out; farming across re-requests
# does.
MAX_TOTAL_FAILURES = 6
LOCKOUT_BASE = 30.0          # seconds, doubled per extra failure
LOCKOUT_MAX = 900.0


def lockout_remaining() -> float:
    return max(0.0, _failures["locked_until"] - time.time())


def _record_failure():
    _failures["count"] += 1
    if _failures["count"] >= MAX_TOTAL_FAILURES:
        over = _failures["count"] - MAX_TOTAL_FAILURES
        wait = min(LOCKOUT_BASE * (2 ** over), LOCKOUT_MAX)
        _failures["locked_until"] = time.time() + wait
        try:
            import security

            security.security_event(
                security.PRIVILEGE_ESCALATION_ATTEMPT, skill="power",
                action="confirm", reason="pin_lockout",
                attempts=_failures["count"], status="failed")
        except Exception:
            pass
    _save_failures()          # survive a restart -- see ARGUS-SEC-004


def _clear_failures():
    _failures["count"] = 0
    _failures["locked_until"] = 0.0
    _save_failures()

ACTIONS = {
    "shutdown": (["shutdown", "/s", "/t", "5"], "shut down this machine"),
    "restart": (["shutdown", "/r", "/t", "5"], "restart this machine"),
    "sleep": (["rundll32.exe", "powrprof.dll,SetSuspendState", "0,1,0"], "put this machine to sleep"),
    "signout": (["shutdown", "/l"], "sign you out"),
}


def request(action: str) -> str:
    """Stages a power action. Does NOT execute it."""
    if action not in ACTIONS:
        return "I didn't follow that power command."

    # A LOCKOUT THAT SURVIVES RE-STAGING.
    #
    # MAX_PIN_ATTEMPTS was 3, but the counter lived in _pending and every
    # request() reset it -- so "shut down the pc", three guesses, "shut down
    # the pc", three more, indefinitely. Measured: 15 consecutive guesses with
    # no lockout, which makes an 8-digit PIN brute-forceable by voice.
    #
    # The failure count now lives OUTSIDE the staged action and is cleared
    # only by a correct PIN or by the lockout expiring, so re-staging buys
    # nothing.
    remaining = lockout_remaining()
    if remaining > 0:
        return (f"Too many wrong PINs. Try again in "
                f"{int(remaining) + 1} seconds.")

    _pending["action"] = action
    _pending["at"] = time.time()
    _pending["attempts"] = 0
    _, phrase = ACTIONS[action]
    if not COMMAND_PIN:
        return (f"You want me to {phrase}, but no command PIN is set in "
                "config.py, so I can't confirm this. Set COMMAND_PIN first.")
    return f"You want me to {phrase}. Type your PIN in the operator channel to confirm."


def confirm(supplied: str = "") -> str:
    """Executes the staged action if one is still valid AND supplied matches
    the configured PIN. Constant-time compare -- same reasoning as the
    session token check in main.py: don't leak the correct PIN via timing."""
    action = _pending["action"]
    if not action:
        return "There's nothing waiting for confirmation."

    if time.time() - _pending["at"] > CONFIRM_WINDOW:
        _pending["action"] = None
        return "That confirmation expired. Ask me again if you still want it."

    if not COMMAND_PIN:
        _pending["action"] = None
        return "No command PIN is set in config.py, so I can't confirm this."

    # ARGUS-SEC-011: the SHARED gate, not a bare verify_pin. One wrong-PIN
    # budget covers every confirming skill (power, files, service, env_var,
    # email, browser), so grinding three guesses here, three on a staged
    # deletion and three on a service restart stops multiplying the budget.
    # This skill's local counter below is the second line of defence.
    # pin_gate_verify handles both a migrated PBKDF2 hash and a legacy
    # plaintext PIN, and uses compare_digest in both branches so the timing
    # behaviour does not reveal which form is configured.
    import security as _security
    if _security.pin_gate_remaining() > 0:
        return (f"Too many wrong PINs across ARGUS. Try again in "
                f"{int(_security.pin_gate_remaining()) + 1} seconds.")
    if not _security.pin_gate_verify(supplied, COMMAND_PIN):
        _pending["attempts"] += 1
        _record_failure()          # survives re-staging; see request()
        left = MAX_PIN_ATTEMPTS - _pending["attempts"]
        if left <= 0:
            _pending["action"] = None
            _pending["attempts"] = 0
            try:
                import security
                security.audit("blocked", f"power/{action} PIN attempts exhausted", "cancelled")
            except Exception:
                pass
            return ("That's not the right PIN, and that was the last attempt. "
                    "I've cancelled it — ask me again if you meant it.")
        return (f"That's not the right PIN. {left} attempt{'s' if left > 1 else ''} "
                "left, or say cancel.")

    cmd, phrase = ACTIONS[action]
    _pending["action"] = None
    _clear_failures()          # a correct PIN is the only thing that clears it
    try:
        import security as _security
        _security.pin_gate_clear()   # and the shared one (ARGUS-SEC-011)
    except Exception:
        pass
    try:
        # execpolicy.spawn, not subprocess.Popen. The skill that can power the
        # machine off was the one skill starting a process outside the
        # execution policy -- no allowlist check, no metacharacter check, no
        # SHELL_COMMAND_REQUESTED event. spawn() applies all three and still
        # does not wait, which sleep needs (SetSuspendState does not return
        # until the machine wakes up).
        import execpolicy

        execpolicy.spawn(cmd)
        return f"Confirmed. About to {phrase}."
    except Exception as e:
        return f"I couldn't do that: {e}"


def cancel() -> str:
    if _pending["action"]:
        _pending["action"] = None
        import execpolicy

        try:
            execpolicy.run(["shutdown", "/a"], timeout=6)
        except execpolicy.ExecDenied:
            pass          # nothing scheduled to abort is not an error here
        return "Cancelled."
    return "Nothing to cancel."


def has_pending() -> bool:
    return bool(_pending["action"]) and (time.time() - _pending["at"] <= CONFIRM_WINDOW)
