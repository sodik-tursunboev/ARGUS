"""
ARGUS - Light proactivity.

Everything ARGUS has said until now, it has said because it was asked. Real
helpfulness sometimes means mentioning something worth knowing without
waiting to be asked first -- "by the way, you're almost out of disk space"
-- but that only reads as helpful if it stays rare and clearly optional.
Constant commentary is not proactive, it's noise, and is exactly the kind of
thing that turns an assistant into something exhausting to leave running.

Design constraints, in order of importance:

1. Never a message of its own. ARGUS has no channel to speak without being
   spoken to first -- there is no infrastructure for that, and building one
   would be a much bigger and riskier change than "light" proactivity calls
   for. A nudge only ever rides along as a trailing remark on a reply the
   user's own command already produced.
2. Rare. A global cooldown between any two nudges, plus a separate, longer
   cooldown per condition, so the same thing can't be mentioned twice in
   quick succession even if it stays true the whole time.
3. Only conditions that are genuinely actionable -- a reminder coming up, a
   battery about to die, a disk that's full, memory under real pressure.
   Nothing decorative, nothing the user couldn't do something about.
4. Silent during anything sensitive. Callers are expected to skip nudging on
   the stop-speaking sentinel, or while a PIN confirmation or a
   clarification is mid-flow -- that is not the moment to change the
   subject. Enforced at the call sites (main.py), not here, since only the
   caller knows what kind of reply it's holding.
5. An off switch, same shape as privacy mode: "stop mentioning things" turns
   it off, nothing here is forced on the user.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time

import psutil

_state = {"enabled": True, "last_nudge": 0.0, "last_by_kind": {}}
_lock = threading.Lock()

GLOBAL_COOLDOWN = 20 * 60      # minimum gap between any two nudges
KIND_COOLDOWN = 3 * 3600       # minimum gap before the SAME condition repeats

BATTERY_CRITICAL = 15          # percent, and unplugged
DISK_FULL = 90                 # percent
MEMORY_PRESSURE = 90           # percent
REMINDER_HORIZON = 4 * 60      # seconds ahead a reminder counts as "coming up"


def enable() -> str:
    with _lock:
        _state["enabled"] = True
    return "I'll mention things again when they come up."


def disable() -> str:
    with _lock:
        _state["enabled"] = False
    return "I'll stick to answering what you ask."


def is_enabled() -> bool:
    with _lock:
        return _state["enabled"]


def _reminder_nudge(now: float):
    try:
        from skills import timer_skill
        soon = timer_skill.soonest_due_within(REMINDER_HORIZON)
    except Exception:
        return None
    if not soon:
        return None
    mins = max(0, int((soon["due"] - now) / 60))
    when = "in under a minute" if mins == 0 else f"in about {mins} minute{'s' if mins != 1 else ''}"
    return f"heads up, {soon['label']} is coming up {when}."


def _battery_nudge(_now: float):
    battery = psutil.sensors_battery()
    if battery and not battery.power_plugged and battery.percent <= BATTERY_CRITICAL:
        return f"by the way, your battery's at {battery.percent:.0f} percent — might want to plug in."
    return None


def _disk_nudge(_now: float):
    disk = psutil.disk_usage("C:\\")
    if disk.percent >= DISK_FULL:
        return f"by the way, your disk is {disk.percent:.0f} percent full."
    return None


def _memory_nudge(_now: float):
    mem = psutil.virtual_memory()
    if mem.percent >= MEMORY_PRESSURE:
        return f"by the way, memory's at {mem.percent:.0f} percent — things might feel slow."
    return None


def _scheduled_nudge(_now: float):
    """A COUNT only, never a finding. scheduler_skill's own module docstring
    says why: what a background check discovered must not be read aloud to
    a room unprompted, same rule announce.py states for detector findings.
    This just says something is waiting to be ASKED about."""
    try:
        from skills import scheduler_skill
        n = scheduler_skill.unread_count()
    except Exception:
        return None
    if n <= 0:
        return None
    return (f"by the way, you have {n} result{'s' if n != 1 else ''} waiting "
            f"from your scheduled checks — ask me what they found.")


def _monitor_nudge(_now: float):
    """A COUNT only, never the finding itself -- same rule as _scheduled_nudge
    above, held for the monitor skill too (see skills/monitor_skill.py's own
    docstring: a watcher's finding must not be read aloud to a room
    unprompted; this just says something is waiting to be ASKED about)."""
    try:
        from skills import monitor_skill
        n = monitor_skill.unread_count()
    except Exception:
        return None
    if n <= 0:
        return None
    return (f"by the way, you have {n} monitor result{'s' if n != 1 else ''} "
            f"waiting — ask me what I found.")


def _watched_nudge(_now: float):
    'Same rule again, for watched tasks: a fired watched task.'
    try:
        from skills import watched_skill
        n = watched_skill.unread_count()
    except Exception:
        return None
    if n <= 0:
        return None
    return (f"by the way, {n} watched task{'s' if n != 1 else ''} fired — "
            f"ask me what I found.")


# Checked in this order and the first match wins -- reminders first, since a
# specific upcoming thing is the one signal here that's uniquely ARGUS's own
# state (Windows already shows battery/disk/memory in the taskbar; a
# reminder you set is not duplicated anywhere else).
def _goals_nudge(_now: float):
    'Same rule once more, for persistent goals: a scheduled fire.'
    try:
        from skills import goals_skill
        n = goals_skill.unread_count()
    except Exception:
        return None
    if n <= 0:
        return None
    return (f"by the way, {n} goal preparation{'s' if n != 1 else ''} "
            f"{'are' if n != 1 else 'is'} waiting — ask me what I prepared.")


# Checked in this order and the first match wins -- reminders first, since a
# specific upcoming thing is the one signal here that's uniquely ARGUS's own
# state (Windows already shows battery/disk/memory in the taskbar; a
# reminder you set is not duplicated anywhere else).
_CHECKS = [
    ("reminder", _reminder_nudge),
    ("battery", _battery_nudge),
    ("disk", _disk_nudge),
    ("memory", _memory_nudge),
    ("scheduled", _scheduled_nudge),
    ("monitor", _monitor_nudge),
    ("watched", _watched_nudge),
    ("goals", _goals_nudge),
]


def maybe_nudge() -> str | None:
    """The one function callers need. Returns a short trailing sentence for
    at most one condition, or None -- which is the overwhelmingly common
    return value, by design. Cheap psutil reads only: no blocking
    interval-based calls like system_stats() uses, since this runs on every
    single exchange and a 400ms stall on every command to maybe produce an
    aside nobody asked for would be a bad trade.
    """
    with _lock:
        if not _state["enabled"]:
            return None
        now = time.time()
        if now - _state["last_nudge"] < GLOBAL_COOLDOWN:
            return None

        for kind, check in _CHECKS:
            if now - _state["last_by_kind"].get(kind, 0.0) < KIND_COOLDOWN:
                continue
            try:
                text = check(now)
            except Exception as e:
                print(f"[proactive] {kind} check failed: {e}")
                continue
            if text:
                _state["last_nudge"] = now
                _state["last_by_kind"][kind] = now
                return text
        return None
