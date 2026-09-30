"""
ARGUS - Health & resource monitor.

A rolling picture of this machine's health, instead of another point-in-time
snapshot. pc/stats, storage/free and the diag skill all answer "right now";
this module keeps a short in-memory history so it can answer "how has the
machine BEEN" -- which numbers are climbing, which are of a sustained high,
and what that means.

Strictly read-only and strictly deterministic: psutil numbers composed into
a spoken sentence, no model call anywhere on the path. The only inputs are
live process statistics and this module's own rolling ring buffer.

A RING, NOT A DATABASE. History lives in memory (collections.deque, bounded),
is only as old as this process, and is never written to disk. That is enough
for "has the CPU been high for a while" and keeps this module as harmless as
the scheduler's read-only tier.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import collections
import time

import psutil

# ── rolling window ─────────────────────────────────────────────────────────
_RING_MAX = 360                      # 6 hours at one sample a minute, then drop off
_SAMPLE_MIN_GAP = 30.0               # don't sample more than once every 30s
_samples = collections.deque(maxlen=_RING_MAX)
_last_sample_at = 0.0

# Flags we admit during a check, used by report() to build a verdict.
# Attention thresholds (percent). Deliberately conservative: a machine that
# reads "fine" but isn't is more useful than one that cries wolf.
CPU_HIGH = 80.0
MEM_HIGH = 85.0
DISK_HIGH = 92.0
SUSTAINED_MINUTES = 5.0             # how long a high reading has to hold


def _sample() -> dict:
    """One point in the ring: CPU %, memory %, root-disk %."""
    cpu = psutil.cpu_percent(interval=0.4)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("C:\\").percent
    return {"cpu": cpu, "mem": mem, "disk": disk}


def _record() -> dict:
    """Sample, but never hammer the machine. Returns the fresh sample."""
    global _last_sample_at
    now = time.time()
    if now - _last_sample_at >= _SAMPLE_MIN_GAP or not _samples:
        s = _sample()
        s["at"] = now
        _samples.append(s)
        _last_sample_at = now
        return s
    return _samples[-1]


def _recent(samples: list, minutes: float) -> list:
    """samples within `minutes` of the newest sample."""
    if not samples:
        return []
    newest = samples[-1]["at"]
    return [s for s in samples if newest - s["at"] <= minutes * 60.0]


def _high_since(metric: str, threshold: float) -> bool:
    """True if the metric has been at/above threshold for SUSTAINED_MINUTES."""
    recent = _recent(list(_samples), SUSTAINED_MINUTES)
    if len(recent) < 3:              # not enough data to call it sustained
        return False
    over = [s for s in recent if s[metric] >= threshold]
    frac = len(over) / len(recent)
    return frac >= 0.7               # most of the recent window was over


def _fmt(pct: float) -> str:
    return f"{pct:.0f}%"


def check(period_hours: float = 1.0) -> str:
    """A spoken health readout: now vs. the rolling min/max over the window,
    plus the heaviest consumers and any recent anomaly notes."""
    from skills import pc_skill, anomaly_skill

    cur = _record()
    window = _recent(list(_samples), max(period_hours, 0.1))

    def mm(metric: str):
        vals = [s[metric] for s in window]
        if not vals:
            return cur[metric], cur[metric], cur[metric]
        return min(vals), max(vals), sum(vals) / len(vals)

    bits = [
        f"CPU is {_fmt(cur['cpu'])}",
        f"memory {_fmt(cur['mem'])}",
        f"disk {_fmt(cur['disk'])}",
    ]
    if window and len(window) > 1:
        for metric, label in (("cpu", "CPU"), ("mem", "memory"), ("disk", "disk")):
            lo, hi, _avg = mm(metric)
            if hi - lo >= 5:         # only mention spread when there is one
                bits.append(f"{label} ranged from {_fmt(lo)} to {_fmt(hi)} "
                            f"over the last {_human_window(period_hours)}")

    # Heaviest consumers worth a name (read-only: pc_skill.stoppable sorts by
    # CPU without stopping anything).
    top = []
    try:
        top = pc_skill.stoppable(limit=3)
    except Exception:
        top = []
    if top:
        names = ", ".join(str(r.get("name", "?")) for r in top[:3])
        bits.append(f"busiest: {names}")

    # Any process anomalies flagged recently? Told as a note, not asserted as
    # fact -- anomaly_skill decides what counts as one.
    try:
        notes = anomaly_skill.recent_summary(n=2)
    except Exception:
        notes = "Recent anomalies: check failed."
    if notes and "no anomalies" not in notes.lower():
        bits.append(notes)

    return ". ".join(bits) + "."


def report() -> str:
    """A verdict: healthy, or the one or two things worth attention.

    Deterministic thresholds, no model. 'Degraded' means a sustained high, not
    a transient spike -- a burst while compiling is normal; hours at 95% is not.
    """
    _record()
    problems = []
    if _high_since("cpu", CPU_HIGH):
        problems.append(f"CPU has been over {_fmt(CPU_HIGH)} for several minutes")
    if _high_since("mem", MEM_HIGH):
        problems.append(f"memory has been over {_fmt(MEM_HIGH)} for several minutes")
    cur = _samples[-1]
    if cur["disk"] >= DISK_HIGH:
        problems.append(f"the {_fmt(cur['disk'])} of your disk is in use")

    if not problems:
        return ("Everything looks healthy right now -- "
                f"CPU {_fmt(cur['cpu'])}, memory {_fmt(cur['mem'])}, "
                f"disk {_fmt(cur['disk'])} and nothing unusual recently.")
    return ("I'd keep an eye on: " + "; ".join(problems[:2])
            + ". Otherwise everything else looks normal.")


def _human_window(hours: float) -> str:
    if hours >= 24:
        return "day"
    if hours >= 1:
        return f"{int(hours)} hour{'s' if int(hours) != 1 else ''}"
    return f"{int(max(hours, 0.1) * 60)} minute{'s' if int(hours * 60) != 1 else ''}"


# Seed the ring at import so the first 'health check' has a baseline rather
# than a single point. Cheap and safe -- this is exactly what pc_skill does.
try:
    _record()
except Exception:
    pass