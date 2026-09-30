"""
ARGUS - Locking itself when something critical happens.

The one autonomous action ARGUS is allowed to take against a threat, and the
reason it is allowed is that it only ever REDUCES what is possible. Locking
takes capability away -- from an attacker, and from you, equally -- and the
only way back is the PIN that was always the way in. There is no state it can
reach that you cannot undo by typing what you already know.

That asymmetry is the whole safety argument, and it is why this and not the
obvious alternatives. Killing a process, quarantining a file or dropping the
network are all irreversible in ways a false positive makes expensive: a
detector that is wrong once has then destroyed work, deleted something, or cut
you off mid-call. A detector that is wrong once here has locked a screen.

OFF BY DEFAULT. A machine that locks itself unexpectedly is alarming, and
alarming is how a security feature gets switched off permanently. It is armed
by asking for it out loud, and it says what it will do when you do.

CRITICAL ONLY. Not high, not medium. "High" is common enough that arming this
against it would mean locking the screen during ordinary work, which teaches
you to disarm it -- and that costs you the critical case too.

WHAT IT CANNOT DO: unlock, elevate, kill, delete, disconnect, or reach the
network. It calls auth.lock() and nothing else.

THE HONEST RISK, stated rather than buried: anything that can reliably trigger
a critical detection can make this lock your screen repeatedly. The rate limit
below bounds that to a nuisance, and the PIN always works -- but it is a real
trade, and it is why this is opt-in rather than on.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time

# Never lock twice inside this. A storm of findings is one event, and locking
# an already-locked screen every few seconds achieves nothing except making
# the log unreadable.
MIN_GAP_S = 120.0
MAX_PER_DAY = 8

_lock = threading.RLock()
_state = {
    "armed": False,
    "locks": [],            # epoch seconds
    "last_reason": "",
    "last_detector": "",
    "refusals": [],
}


def armed() -> bool:
    with _lock:
        return bool(_state["armed"])


def arm(on: bool) -> str:
    """Turn it on or off. Says plainly what it will do."""
    with _lock:
        _state["armed"] = bool(on)
    try:
        import security
        security.audit("lockdown_armed", f"on={bool(on)}", "ok")
    except Exception:
        pass
    if on:
        return ("Armed. If I detect something critical I'll lock the screen "
                "and tell you why. Your PIN unlocks it as normal.")
    return "Disarmed. I'll still warn you, but I won't lock the screen."


def _refuse(reason: str) -> bool:
    with _lock:
        _state["refusals"] = (_state["refusals"] + [reason])[-10:]
        _state["last_reason"] = reason
    return False


def consider(rec: dict, now: float = None) -> bool:
    """Lock the session if this finding warrants it. Returns whether it did.

    Never raises: it is called from the detection funnel, and a failure here
    must not cost the detection that triggered it.
    """
    now = now or time.time()
    try:
        if not armed():
            return _refuse("not armed")
        if (rec or {}).get("severity") != "critical":
            return _refuse("not critical")

        import auth
        if not auth.is_unlocked():
            # Already locked. Nothing to do, and saying so keeps the log
            # honest about why no lock appears against this finding.
            return _refuse("already locked")

        with _lock:
            recent = [t for t in _state["locks"] if t >= now - 86400]
            _state["locks"] = recent
        if recent and now - max(recent) < MIN_GAP_S:
            return _refuse("locked recently")
        if len(recent) >= MAX_PER_DAY:
            return _refuse("daily limit")

        auth.lock("threatmon: critical detection")
        with _lock:
            _state["locks"] = recent + [now]
            _state["last_detector"] = str(rec.get("detector", ""))[:40]
            _state["last_reason"] = ""

        try:
            import security
            # The DETECTOR, never the finding's text: the audit line for a
            # lock should say what tripped it, not restate the detection that
            # is already logged immediately above it.
            security.audit("lockdown", f"detector={rec.get('detector', '')}",
                           "ok")
        except Exception:
            pass

        # Say why, out loud. A screen that locks itself with no explanation is
        # indistinguishable from a fault, and that is how trust in it is lost.
        try:
            import announce
            announce.say("lockdown", now, urgent=True)
        except Exception:
            pass
        return True
    except Exception as e:
        return _refuse(f"{type(e).__name__}")


def status() -> dict:
    now = time.time()
    with _lock:
        today = [t for t in _state["locks"] if t >= now - 86400]
        return {
            "armed": _state["armed"],
            "locks_today": len(today),
            "daily_limit": MAX_PER_DAY,
            "last_detector": _state["last_detector"],
            "last_reason": _state["last_reason"],
            "recent_refusals": list(_state["refusals"])[-3:],
            # Stated because they are the security properties, not details.
            "can_unlock": False,
            "severities": ["critical"],
        }
