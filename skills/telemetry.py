"""
ARGUS - Own telemetry (per-command latency, usage, outcome).

The router model observes the machine but nothing observed the router. This
module records a compact per-command line for every dispatch -- which skill,
how long it took, whether it succeeded -- so "how is ARGUS doing" has a real
answer instead of a hand-wave.

TWO RECORDS, ONE READOUT. Every dispatch adds a durable line through
security.audit() (the same tamper-evident, cross-process, redacted log that
already records "blocked", "plan_run" and auth events -- that is the audit
trail, and telemetry rides it rather than opening a second sink). The
AGGREGATE is kept in memory because summing a whole log per question is
wasteful; system/stats reports the session aggregate, honestly labelled.

THIS TELLS NO LIES. stats() says "this session" because the aggregate is
in-memory and dies with the process -- pretending it survived restarts would
be inventing precision. The durable audit log is available for a different,
explicit question.

Cost: one short file append per command. That is the same shape as the
"blocked"/plan events security.audit() already performs on the hot path, so
it is a known, accepted cost -- and it can be switched off entirely via the
"telemetry" feature flag (system/set_flag telemetry off).
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time

_lock = threading.Lock()
_count = {}                 # (skill, action) -> number of dispatches
_ms_total = 0.0
_refused = 0
_failed = 0
_ok = 0
_enabled = True             # restored from flags.json at import, see _restore()

_AGG_CAP = 100              # distinct (skill,action) keys before pruning


def set_enabled(on: bool) -> None:
    global _enabled
    _enabled = bool(on)


def is_enabled() -> bool:
    return _enabled


def _restore() -> None:
    """Pick up the persisted "telemetry" feature flag if one exists, so a
    user who turned telemetry off keeps it off across restarts."""
    global _enabled
    try:
        import json
        import paths
        with open(paths.writable("flags.json"), "r", encoding="utf-8") as f:
            store = json.load(f)
        v = store.get("telemetry")
        if isinstance(v, bool):
            _enabled = v
    except Exception:
        pass


def record(skill: str, action: str, outcome: str = "ok",
           latency_ms: float = 0.0, via: str = "") -> None:
    """One dispatch, one line. Safe to call on any thread; never raises."""
    global _ms_total, _refused, _failed, _ok
    if not _enabled:
        return

    skill = (skill or "?").strip()
    action = (action or "?").strip()
    outcome = (outcome or "ok").strip()
    ms = float(latency_ms or 0.0)

    with _lock:
        _ms_total += ms
        if outcome == "refused":
            _refused += 1
        elif outcome == "failed":
            _failed += 1
        else:
            _ok += 1
        key = (skill, action)
        _count[key] = _count.get(key, 0) + 1
        if len(_count) > _AGG_CAP:
            # Oldest keys fall out; the durable audit log still has them.
            for k in list(_count)[:len(_count) - _AGG_CAP]:
                _count.pop(k, None)

    # The durable trail. Detail is kept short (the audit log redacts and
    # truncates anyway); via records which path served it (fast/model/chain).
    try:
        import security
        detail = f"{skill}/{action} {int(ms)}ms"
        if via:
            detail += f" [{via}]"
        security.audit("telemetry", detail, outcome)
    except Exception:
        pass


def stats() -> str:
    """A spoken summary of this session's dispatch history."""
    with _lock:
        ops = _ok + _refused + _failed
        if ops == 0:
            return "No commands routed through me this session yet."
        avg = _ms_total / ops
        top = max(_count, key=_count.get) if _count else ("-", "-")
        parts = [
            f"{ops} command{'s' if ops != 1 else ''} this session",
            f"average latency {int(avg)} milliseconds",
            f"top command: {top[0]}/{top[1]} ({_count[top]} times)",
        ]
        if _refused:
            parts.append(f"{_refused} refused")
        if _failed:
            parts.append(f"{_failed} failed")
    return ", ".join(parts) + "."


_restore()
