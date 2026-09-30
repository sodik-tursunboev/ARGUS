"""
ARGUS - Process anomaly detection.

Builds on main.py's existing sampler -- _sample_processes() already walks
every running process every 5 seconds for the HUD's process panel. This
does not repeat that walk; it consumes its output and keeps a running
statistical baseline of what's NORMAL for THIS machine, then flags what
falls outside it. Three signals, each corresponding to something a person
watching a process list would actually notice:

  1. A process never seen before, already consuming significant CPU.
  2. A known process's CPU or memory spiking well outside its own
     established historical range.
  3. A known process suddenly running with far more child processes than
     it typically has.

Baseline storage is a running (count, sum, sum-of-squares) per process
name, not a list of raw samples -- that gives an exact mean and standard
deviation in O(1) space per process, growing with the SET of distinct
process names seen, not with the number of samples taken. It persists to
disk and updates forever, so the baseline gets more accurate the longer
ARGUS runs, rather than starting cold every launch.

Crash discipline: every entry point here is expected to be called from
inside main.py's sampler loop, which already wraps each of its own
sections in try/except so one failing section can't take down the whole
thread (see the GPU/disk/battery sections in main.py's sampler()). This
module additionally protects itself, on the theory that a bug in NEW code
is more likely than a bug in the process walk it's built on: observe()
never raises, load()/save() never raise, and a first run with zero history
or a corrupted baseline file both degrade to "no anomalies, start
learning" rather than crashing anything.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import math
import os
import time

from config import VAULT_PATH

BASELINE_PATH = os.path.join(VAULT_PATH, "anomaly_baseline.json")

MIN_SAMPLES_FOR_BASELINE = 6      # ~30s of history before trusting a process's own mean/stddev
NEW_PROCESS_CPU_THRESHOLD = 25.0  # % CPU that makes a NEVER-SEEN process worth flagging
SPIKE_SIGMA = 3.0                 # standard deviations above the mean that counts as a spike
SPIKE_MIN_CPU = 20.0              # floor -- a statistically extreme but tiny CPU% isn't worth flagging
CHILD_BASELINE_MARGIN = 3         # extra children beyond the established typical count to flag
SAVE_EVERY_N_OBSERVE = 60         # persist roughly every 5 minutes at one observe() per 5s tick
ALERT_COOLDOWN = 300              # don't re-flag the SAME process for the SAME reason more than
                                   # once per 5 minutes -- a sustained spike would otherwise flag
                                   # on every single sampler tick

_baseline: dict = {}
_loaded = False
_observe_count = 0
_last_alert: dict = {}   # (name, kind) -> last time.time() it was flagged

# Kept here (not only in main.py's _snapshot) so a voice query for "any
# anomalies" doesn't need this module reaching back into main.py -- that
# would be a circular import, since main.py is what imports this module in
# the first place, not the other way around. main.py's sampler mirrors the
# same findings into _snapshot for the HUD's JSON; this is the module's
# own copy for router.py's dispatch to read directly.
_RECENT_CAP = 10
_recent: list = []


def _empty_stat():
    return {"count": 0, "cpu_sum": 0.0, "cpu_sq": 0.0, "cpu_max": 0.0,
             "mem_sum": 0.0, "mem_sq": 0.0, "mem_max": 0.0,
             "child_sum": 0, "child_max": 0,
             "first_seen": None, "last_seen": None}


def _load():
    """Populates _baseline from disk. Safe to call more than once -- only
    the first call actually reads the file. A missing or corrupt file (bad
    JSON, or JSON that isn't the shape expected) both degrade to an empty
    baseline rather than raising -- a fresh baseline is exactly what a
    first run looks like anyway, so a corrupted file fails no worse than
    the very first launch ever did.
    """
    global _baseline, _loaded
    if _loaded:
        return
    _loaded = True
    try:
        with open(BASELINE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            # Validate shape rather than trust it -- a hand-edited or
            # truncated file must degrade per-entry, not all-or-nothing.
            clean = {}
            for name, stat in data.items():
                if isinstance(stat, dict) and "count" in stat:
                    merged = _empty_stat()
                    merged.update({k: v for k, v in stat.items() if k in merged})
                    clean[name] = merged
            _baseline = clean
    except (OSError, ValueError, TypeError):
        _baseline = {}


def _save():
    try:
        os.makedirs(VAULT_PATH, exist_ok=True)
        tmp = BASELINE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_baseline, f)
        os.replace(tmp, BASELINE_PATH)
    except OSError as e:
        print(f"[anomaly] could not save baseline: {e}")


def _mean_std(stat: dict, sum_key: str, sq_key: str):
    n = stat["count"]
    if n < 1:
        return 0.0, 0.0
    mean = stat[sum_key] / n
    # variance = E[x^2] - E[x]^2. Floored at 0 -- floating point error can
    # push this fractionally negative for a near-constant series, and
    # sqrt() of a negative number is the div-by-zero-shaped crash this
    # module exists to not have.
    variance = max(0.0, stat[sq_key] / n - mean * mean)
    return mean, math.sqrt(variance)


def _is_spike(current: float, mean: float, std: float, floor: float, ratio: float = 2.0) -> bool:
    """A value counts as a spike if it clears the practical floor (SPIKE_MIN_CPU-
    style -- a statistically extreme but practically tiny value isn't worth
    flagging) AND either:
      - the process has genuine historical variance (std > 0): current is
        more than SPIKE_SIGMA standard deviations above the mean, or
      - the process has been perfectly stable so far (std == 0, common for
        a lightweight background process that's always been ~idle): current
        is more than `ratio`x the historical mean instead.
    BUGFIX: this used to require std > 0 unconditionally, with no fallback --
    a process with zero historical variance could never trigger a spike
    alert at all, no matter how extreme the deviation, because the sigma
    check is mathematically undefined (anything looks infinitely-many-sigma
    above a single repeated value) and was simply never reached. Caught by
    a test built around exactly that shape: a constant-CPU baseline followed
    by a real spike, which silently produced zero findings.
    """
    if current < floor:
        return False
    if std > 0:
        return current > mean + SPIKE_SIGMA * std
    return current > max(mean * ratio, floor)


def _alert_ready(name: str, kind: str, now: float) -> bool:
    key = f"{name}:{kind}"
    if now - _last_alert.get(key, 0.0) < ALERT_COOLDOWN:
        return False
    _last_alert[key] = now
    _prune_alerts(now)
    return True


def _prune_alerts(now: float):
    """Drops cooldown entries that can no longer suppress anything.

    _last_alert only ever grew: one entry per (process name, reason) pair ever
    seen, held for the life of the process. Bounded in practice by how many
    distinct process names a machine runs, but nothing here bounded it, and a
    machine that spawns uniquely-named processes (build workers, installers,
    per-PID temp executables) would grow it without limit. An entry older than
    the cooldown has no effect on _alert_ready's decision, so keeping it buys
    nothing.
    """
    if len(_last_alert) <= 256:
        return
    stale = [k for k, t in _last_alert.items() if now - t >= ALERT_COOLDOWN]
    for k in stale:
        del _last_alert[k]


def observe(processes: list) -> list:
    """Updates the baseline with this cycle's process list and returns a
    list of human-readable anomaly strings for anything unusual THIS
    cycle -- almost always empty, by design; most cycles are normal by
    definition of what a baseline is.

    `processes` is exactly _sample_processes()'s own return shape:
    [{"name", "pid", "mb", "cpu", "threads", "children"}, ...]. Never
    raises -- wrapped in its own try/except so a bug in NEW code can't
    reach the sampler loop calling it, on top of the sampler's own
    per-section isolation.
    """
    try:
        return _observe(processes)
    except Exception as e:
        print(f"[anomaly] observe failed, skipping this cycle: {type(e).__name__}: {e}")
        return []


def _observe(processes: list) -> list:
    global _observe_count
    _load()
    if not processes:
        return []

    now = time.time()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    findings = []

    for p in processes:
        name = p.get("name")
        if not name:
            continue
        cpu = float(p.get("cpu", 0) or 0)
        mb = float(p.get("mb", 0) or 0)
        children = int(p.get("children", 0) or 0)

        stat = _baseline.get(name)
        is_new = stat is None
        if is_new:
            stat = _empty_stat()
            stat["first_seen"] = stamp
            _baseline[name] = stat

        if is_new and cpu >= NEW_PROCESS_CPU_THRESHOLD and _alert_ready(name, "new", now):
            findings.append(
                f"{name} hasn't been seen on this machine before and is already "
                f"using {cpu:.0f} percent CPU."
            )

        elif not is_new and stat["count"] >= MIN_SAMPLES_FOR_BASELINE:
            cpu_mean, cpu_std = _mean_std(stat, "cpu_sum", "cpu_sq")
            if (_is_spike(cpu, cpu_mean, cpu_std, SPIKE_MIN_CPU)
                    and _alert_ready(name, "cpu_spike", now)):
                findings.append(
                    f"{name} is at {cpu:.0f} percent CPU, well above its usual "
                    f"{cpu_mean:.0f} percent."
                )

            mem_mean, mem_std = _mean_std(stat, "mem_sum", "mem_sq")
            # Floor is the process's own mean, not a fixed constant like
            # SPIKE_MIN_CPU -- memory footprints vary enormously by process
            # (a 5MB utility vs. a 2GB browser), so there's no one absolute
            # number that's a sensible floor for all of them the way ~20%
            # CPU is a reasonable floor regardless of which process it is.
            if (_is_spike(mb, mem_mean, mem_std, mem_mean * 1.2)
                    and _alert_ready(name, "mem_spike", now)):
                findings.append(
                    f"{name} is using {mb:.0f} megabytes of memory, well above its "
                    f"usual {mem_mean:.0f}."
                )

            child_mean = stat["child_sum"] / stat["count"]
            if (children > child_mean + CHILD_BASELINE_MARGIN
                    and children > stat["child_max"]
                    and _alert_ready(name, "children", now)):
                findings.append(
                    f"{name} now has {children} child processes, more than its "
                    f"usual {child_mean:.0f}."
                )

        # Update the running baseline AFTER checking -- this cycle's value
        # gets judged against history BEFORE becoming part of it.
        stat["count"] += 1
        stat["cpu_sum"] += cpu
        stat["cpu_sq"] += cpu * cpu
        stat["cpu_max"] = max(stat["cpu_max"], cpu)
        stat["mem_sum"] += mb
        stat["mem_sq"] += mb * mb
        stat["mem_max"] = max(stat["mem_max"], mb)
        stat["child_sum"] += children
        stat["child_max"] = max(stat["child_max"], children)
        stat["last_seen"] = stamp

    for f in findings:
        _recent.append({"at": stamp, "text": f})
    del _recent[:-_RECENT_CAP]

    _observe_count += 1
    if _observe_count % SAVE_EVERY_N_OBSERVE == 0:
        _save()

    return findings


def recent_summary(n: int = 5) -> str:
    """Spoken-friendly summary for a voice query ('any anomalies', 'is
    anything wrong'). Distinguishes an empty baseline (still learning,
    nothing to compare against yet) from a populated one with nothing
    currently flagged, since those mean different things to a user asking
    "is everything okay" a few minutes after ARGUS's very first launch.
    """
    _load()
    if not _recent:
        # _observe_count, not the number of distinct process names known --
        # a machine has dozens of distinct process names from the very first
        # cycle, so that count crosses MIN_SAMPLES_FOR_BASELINE almost
        # immediately and would never actually signal "still learning". The
        # cycle count is what MIN_SAMPLES_FOR_BASELINE is really about: has
        # this specific process been watched enough TIMES to trust its own
        # mean/stddev.
        if _observe_count < MIN_SAMPLES_FOR_BASELINE:
            return ("I haven't been watching long enough to know what's normal "
                    "for this machine yet, so I don't have a baseline to compare "
                    "against. Give it a few minutes.")
        return "Nothing unusual — everything's within normal range for this machine."
    items = _recent[-n:]
    return "Recent anomalies: " + " ".join(i["text"] for i in items)


def known_process_count() -> int:
    """How many distinct process names the baseline has any history for --
    surfaced so 'how's the baseline doing' has something concrete to say
    rather than a black box."""
    _load()
    return len(_baseline)
