"""
ARGUS - The one channel by which ARGUS may speak without being spoken to.

proactive_skill's header states the constraint this module changes:

    "Never a message of its own. ARGUS has no channel to speak without being
     spoken to first -- there is no infrastructure for that, and building one
     would be a much bigger and riskier change."

That was true, and it is why nudges only ever ride along on a reply the user's
own command already produced. But an assistant that cannot say "welcome back"
when you sit down is missing the thing that makes it feel present at all, so
the channel is built here -- deliberately, narrowly, and with the risk named.

THE CHANNEL CARRIES A KIND, NEVER TEXT. This is the whole design. A queue that
carried strings would be a way to make ARGUS say arbitrary words out loud from
another process -- a speech-injection primitive sitting inside the assistant,
reachable by anything that could reach the queue. So what crosses the process
boundary is one identifier from a fixed set, and the WORDS are chosen on the
speaking side from a table it owns. Nothing a caller supplies is ever spoken.

It also means no detector finding can be announced. There is no parameter for
one -- the same construction alert() uses on the phone path, for the same
reason: what this machine has detected must not be read aloud to a room.

WHEN IT STAYS QUIET, in order:
  * privacy mode -- the microphone is off because you wanted quiet
  * quiet hours -- nothing unprompted at night
  * proactive remarks disabled -- ONE off switch, the existing one, rather
    than a second one nobody knows about
  * rate limits -- a minimum gap and an hourly cap
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time

# Every kind ARGUS may raise unprompted. Adding one is a deliberate edit here
# AND a matching line in the speaking side's table -- a kind with no text is
# silently dropped rather than spoken as its own name.
KINDS = frozenset({
    "welcome_back",
    # Spoken threat alerts. ONE KIND PER CATEGORY, never one per finding --
    # the kind IS the whole message, so the categories are chosen to be
    # actionable ("something set itself to start with your machine") without
    # naming the process, the path, or the file. A room is not private: a
    # colleague standing behind you should learn that ARGUS noticed
    # something, not what it found or where.
    "threat_persistence",   # something added itself to autostart
    "threat_credential",    # something reached for credentials in memory
    "threat_traffic",       # DNS / hosts / proxy changed under you
    "threat_tamper",        # something went after ARGUS's own protection
    "threat_tripwire",      # a canary file was touched
    "threat_exposure",      # something started accepting connections from the network
    "threat_defenses",      # a security protection switched off
    "threat_generic",       # detected, category not worth spelling out
    # ARGUS locked its own screen. Said out loud because a screen that locks
    # itself with no explanation is indistinguishable from a fault, and that
    # is exactly how trust in a protective feature is lost.
    "lockdown",
    # You have been at the machine a long time. TWO kinds rather than one
    # carrying a number, because the channel carries a kind and never text --
    # and "a few hours" at the six-hour mark is weak enough to be worth the
    # second entry. Two is the ceiling: a kind per hour would be text with
    # extra steps.
    "long_session",       # around three hours
    "very_long_session",  # around six
    # The task planner's own loop breaker tripped -- a step retried and
    # observed the IDENTICAL result twice running, or a plan's retry budget
    # ran out. Said out loud because a plan that silently stops is
    # indistinguishable from one that is still working; see router.py's
    # run_plan() for the two conditions that raise this.
    "plan_loop_broken",
    # The Agent Manager has a CRITICAL item in the agent inbox (a security
    # investigation that found something and proposes a response). Carries no
    # finding, no agent text -- only that the inbox needs the owner, same
    # construction as every threat kind above.
    "agent_attention",
})

# Which detector maps to which spoken category. A detector missing from here
# still speaks, as threat_generic -- a new detector must never be silent just
# because nobody remembered to file it.
DETECTOR_KINDS = {
    "persistence": "threat_persistence",
    "lsass": "threat_credential",
    "netconfig": "threat_traffic",
    "tamper": "threat_tamper",
    "canary": "threat_tripwire",
    "listening": "threat_exposure",
    "defenses": "threat_defenses",
}

# Severities worth interrupting you for. "medium" and below are visible on the
# HUD and in the audit log, and speaking them would make ARGUS the thing you
# switch off -- which costs you the critical ones too.
SPEAK_SEVERITIES = frozenset({"critical", "high"})

MIN_GAP_S = 120.0          # never two announcements inside two minutes
MAX_PER_HOUR = 6
QUIET_START_H = 23
QUIET_END_H = 8

_q = {"queue": None}
_lock = threading.RLock()
_state = {"sent": [], "last_reason": ""}


def attach(queue) -> None:
    """Register the shared queue. Called once per process."""
    with _lock:
        _q["queue"] = queue


def available() -> bool:
    with _lock:
        return _q["queue"] is not None


def _quiet_now(now: float) -> bool:
    h = time.localtime(now).tm_hour
    if QUIET_START_H <= QUIET_END_H:
        return QUIET_START_H <= h < QUIET_END_H
    return h >= QUIET_START_H or h < QUIET_END_H


def _blocked(now: float, urgent: bool = False) -> str:
    """Why this announcement must not happen, or "" if it may."""
    try:
        from skills import privacy_skill
        if privacy_skill.is_muted():
            return "privacy mode"
    except Exception:
        pass
    # Quiet hours silence pleasantries, not warnings. "Welcome back" at 3am is
    # noise; something reaching for credentials at 3am is the entire reason
    # the detector exists, and holding it until morning would be the wrong
    # kind of politeness. Privacy mode above still wins over both -- if the
    # microphone is off you have asked for silence explicitly.
    if _quiet_now(now) and not urgent:
        return "quiet hours"
    try:
        from skills import proactive_skill
        if not proactive_skill.is_enabled():
            return "proactive remarks are switched off"
    except Exception:
        pass
    with _lock:
        sent = [t for t in _state["sent"] if t >= now - 3600]
        _state["sent"] = sent
    if sent and now - max(sent) < MIN_GAP_S:
        return "too soon after the last one"
    if len(sent) >= MAX_PER_HOUR:
        return "hourly limit"
    return ""


def say(kind: str, now: float = None, urgent: bool = False) -> bool:
    """Ask ARGUS to speak KIND aloud. Returns whether it was queued.

    Takes no text on purpose. See the module docstring: a queue carrying
    strings would be a speech-injection primitive.

    `urgent` lifts quiet hours only, and nothing else -- privacy mode, the
    off switch and the rate limits all still apply. It exists so a genuine
    critical detection is not held until morning.
    """
    now = now or time.time()
    if kind not in KINDS:
        with _lock:
            _state["last_reason"] = f"unknown kind {kind!r}"
        return False
    reason = _blocked(now, urgent=urgent)
    if reason:
        with _lock:
            _state["last_reason"] = reason
        return False
    with _lock:
        q = _q["queue"]
    if q is None:
        with _lock:
            _state["last_reason"] = "no channel attached"
        return False
    try:
        q.put_nowait(kind)
    except Exception as e:
        with _lock:
            _state["last_reason"] = f"{type(e).__name__}"
        return False
    with _lock:
        _state["sent"] = (_state["sent"] + [now])[-50:]
        _state["last_reason"] = ""
    try:
        import security
        security.audit("announce", f"kind={kind}", "ok")
    except Exception:
        pass
    return True


def take() -> str:
    """The next pending kind, or "". Never blocks, never raises.

    Called from the voice process's own loop, so it must return instantly:
    blocking here would stall audio capture.
    """
    with _lock:
        q = _q["queue"]
    if q is None:
        return ""
    try:
        if q.empty():
            return ""
        kind = q.get_nowait()
    except Exception:
        return ""
    return kind if kind in KINDS else ""


def status() -> dict:
    now = time.time()
    with _lock:
        sent = [t for t in _state["sent"] if t >= now - 3600]
        return {
            "attached": _q["queue"] is not None,
            "kinds": sorted(KINDS),
            "sent_last_hour": len(sent),
            "hourly_limit": MAX_PER_HOUR,
            "in_quiet_hours": _quiet_now(now),
            "last_reason": _state["last_reason"],
            "carries_text": False,
        }
