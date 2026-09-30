"""
ARGUS - Background monitor skill (watch-until).

A separate, tightly-bounded "watch until" capability: "tell me when a file
shows up in Downloads", "let me know when battery is above 80", "watch the
logs folder until it has more than ten entries". One condition, watched in
the background, answered once when it becomes true.

THE BOUNDARY IS THE CONDITION, NOT AN EXPRESSION. This module accepts a
condition only from a fixed, reviewed ALLOWLIST -- file_exists,
battery_above/below, net_online, net_wifi_name, cpu_above/below,
folder_has, file_size_above. It is NOT a generic expression evaluator. A
generic "watch for X then run Y" fires an arbitrary response to an arbitrary
trigger, which is a new, unreviewed capability class; scheduler_skill's
docstring already declines that for scheduled work, and the same reasoning
holds here. Every condition here is local, deterministic, and read-only -- a
file check, a battery read, a CPU sample, a network probe, a folder count.
Nothing a monitor does can type, click, download, or spend.

WATCHES NEVER ACT. When a condition is met the monitor records a spoken
result and STOPS -- it answers the question that was asked and does not
invent follow-up work. Firing is one-shot by construction.

RESULTS ARE PULLED, NEVER PUSHED (scheduler_skill's rule, held here too).
A watcher's finding is exactly the shape of thing that must not be read
aloud to a room unprompted, so results land in results() for the owner to
ASK for, and at most a generic, content-free COUNT ("you have 2 monitor
results waiting") rides in through proactive_skill's existing nudge -- never
the finding itself. The one exception is the set() reply itself: "I'll let
you know" is said at scheduling time, in a conversation the owner started.

BOUNDED, NOT INDEFINITE. MAX_MONITORS caps the queue and every watch carries
a hard MAX_MONITOR_SECONDS (30 minutes) expiry after which it stops and has
to be re-asked -- an unattended watcher nobody remembers starting, still
running at 3 a.m. a week later, is its own kind of risk even if each probe
is harmless. One snapshot (one CPU sample, one battery read, one network
probe, one Wi-Fi query) is shared across all monitors on a tick so N watches
cost one probe, not N.

PATHS ARE CONFINED. folder/file conditions resolve through files_skill's own
_confinement (SEARCH_ROOTS -- Desktop, Documents, Downloads, Pictures,
Videos, C:\\ARGUS) so a watcher cannot be pointed at a path ARGUS would
refuse to act on in a spoken command. Reading a path is weaker than acting
on it, but keeping the same boundary is simpler to reason about and costs
nothing.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import re
import socket
import threading
import time
import uuid

import paths

_STORE_PATH = paths.writable("monitors.json")

MAX_MONITORS = 20
MAX_MONITOR_SECONDS = 30 * 60.0        # every watch expires after 30 minutes
POLL_INTERVAL = 30.0
MAX_RESULTS_PER_WATCH = 3

_lock = threading.Lock()


# ═══════════════════════════════════════════════════════════════════════════
# THE CONDITION CATALOGUE -- the allowlist. Adding a condition is a design
# decision (a new reviewed way for a background thread to make an assertion
# about this machine), not a one-liner.
# ═══════════════════════════════════════════════════════════════════════════

# cond -> {"desc": human label verb, "kind": how to parse the arg text}
_CONDITIONS = {
    "file_exists":     {"desc": "file",         "kind": "path"},
    "battery_above":   {"desc": "battery",      "kind": "pct"},
    "battery_below":   {"desc": "battery",      "kind": "pct"},
    "net_online":      {"desc": "the internet", "kind": "none"},
    "net_wifi_name":   {"desc": "wi-fi",        "kind": "text"},
    "cpu_above":       {"desc": "CPU",          "kind": "pct"},
    "cpu_below":       {"desc": "CPU",          "kind": "pct"},
    "folder_has":      {"desc": "folder",       "kind": "path_count"},
    "file_size_above": {"desc": "file",         "kind": "path_mb"},
}


def _confine(path: str) -> str:
    """Resolve PATH and confirm it is somewhere ARGUS works, via files_skill's
    own confinement. Raises FileOpError with a spoken refusal if not."""
    from skills import files_skill
    return files_skill._confined(path)


def _parse(text: str):
    """Parse a watch request into (cond, args, label). Returns a spoken
    refusal STRING when the request is not something this module may watch."""
    t = (text or "").strip()
    if not t:
        return "What should I watch for?"
    head, _, rest = t.partition(" ")
    cond = head.strip().lower()
    spec = _CONDITIONS.get(cond)
    if not spec:
        allowed = ", ".join(sorted(_CONDITIONS))
        return (f"I can only watch for exactly these things: {allowed}. "
                f"Like 'watch for battery_above 80'.")
    rest = rest.strip().strip('"').strip()

    try:
        if spec["kind"] == "none":
            args, label = {}, f"the {spec['desc']} to come back"
        elif spec["kind"] == "pct":
            pct = float(rest)
            if not 0 <= pct <= 100:
                return "The percentage needs to be between 0 and 100."
            args = {"pct": pct}
            above = "\u2265" if cond.endswith("above") else "\u2264"
            label = f"for {spec['desc']} to be {above} {pct}%"
        elif spec["kind"] == "text":
            if not rest:
                return "Which network should I watch for?"
            args = {"name": rest}
            label = f"for wi-fi to be on the {rest} network"
        elif spec["kind"] == "path":
            real = _confine(rest)
            args = {"path": real}
            label = f"for {os.path.basename(real)} ({real}) to exist"
        elif spec["kind"] == "path_count":
            path, _, count_s = rest.rpartition(",")
            real = _confine(path.strip())
            count = int(float(count_s.strip()))
            if count < 0:
                return "The count needs to be zero or more."
            args = {"path": real, "count": count}
            label = f"for {real} to hold at least {count} item"
            label += "s" if count != 1 else ""
        elif spec["kind"] == "path_mb":
            path, _, mb_s = rest.rpartition(",")
            real = _confine(path.strip())
            mb = float(mb_s.strip())
            if mb <= 0:
                return "The size needs to be more than zero."
            args = {"path": real, "mb": mb}
            label = f"for {os.path.basename(real)} to grow past {mb:g} MB"
        else:
            return "I can't parse that watch condition."
    except ValueError:
        return "That didn't parse as a number -- try e.g. 'battery_above 80'."
    except ImportError:
        return "I can't resolve paths right now, try again in a moment."
    except Exception as e:          # FileOpError refuses with a spoken reason
        return str(e)
    return cond, args, label


def _label_from(mon: dict) -> str:
    return mon.get("label") or f"{mon['cond']} {mon.get('args', {})}"


# ═══════════════════════════════════════════════════════════════════════════
# THE PROBES -- one snapshot per tick, shared by every monitor
# ═══════════════════════════════════════════════════════════════════════════

def _wifi_name() -> str:
    """Current SSID, "" when not on Wi-Fi or uncertain. Reuses
    network_skill.wifi_info() so there is exactly one reviewed execpolicy
    surface for Wi-Fi state instead of a second copy of the netsh call."""
    try:
        from skills import network_skill
        text = network_skill.wifi_info()
    except Exception:
        return ""
    if "not connected" in text.lower():
        return ""
    m = re.search(r"connected to (.+?)(?: at |\.)", text, re.I)
    return m.group(1).strip() if m else ""


def _snapshot() -> dict:
    """One set of machine readings for the tick. Every probe is independent
    and cheap; any failure just sets None so that condition can't falsely
    fire."""
    s = {}
    try:
        import psutil
        s["cpu"] = psutil.cpu_percent(interval=0.15)
        b = psutil.sensors_battery()
        s["battery"] = b.percent if b else None
    except Exception:
        s["cpu"], s["battery"] = None, None
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=3).close()
        s["online"] = True
    except OSError:
        s["online"] = False
    s["wifi"] = _wifi_name()
    return s


def _eval(mon: dict, s: dict) -> str | None:
    """Return a short detail string when the watch's condition is met, else
    None. Deterministic and read-only -- reads args and the snapshot only."""
    cond = mon["cond"]
    a = mon.get("args", {})

    if cond == "file_exists":
        return "it's there now" if os.path.exists(a.get("path", "")) else None

    if cond in ("battery_above", "battery_below"):
        pct = s.get("battery")
        if pct is None:
            return None
        if cond == "battery_above" and pct >= a["pct"]:
            return f"it's at {pct:.0f}%"
        if cond == "battery_below" and pct <= a["pct"]:
            return f"it's at {pct:.0f}%"
        return None

    if cond == "net_online":
        return "the internet is back" if s.get("online") else None

    if cond == "net_wifi_name":
        have = (s.get("wifi") or "").lower()
        want = (a.get("name") or "").lower()
        return f"it's on the {a['name']} network" if have and want and want in have else None

    if cond in ("cpu_above", "cpu_below"):
        cpu = s.get("cpu")
        if cpu is None:
            return None
        if cond == "cpu_above" and cpu >= a["pct"]:
            return f"it's at {cpu:.0f}%"
        if cond == "cpu_below" and cpu <= a["pct"]:
            return f"it's now {cpu:.0f}% -- things have settled"
        return None

    if cond == "folder_has":
        path = a.get("path", "")
        try:
            n = len(os.listdir(path))
        except OSError:
            n = 0
        if n >= a["count"]:
            plural = "" if n == 1 else "s"
            return f"there {'is' if n == 1 else 'are'} now {n} item{plural}"
        return None

    if cond == "file_size_above":
        path = a.get("path", "")
        if not os.path.exists(path):
            return None
        try:
            size_mb = os.path.getsize(path) / (1024 * 1024)
        except OSError:
            return None
        return f"it's now {size_mb:.1f} MB" if size_mb > a["mb"] else None

    return None


# ═══════════════════════════════════════════════════════════════════════════
# THE PUBLIC SURFACE
# ═══════════════════════════════════════════════════════════════════════════

def _load() -> list:
    try:
        with open(_STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save(watches: list) -> None:
    try:
        with open(_STORE_PATH, "w", encoding="utf-8") as f:
            json.dump(watches, f, indent=2)
    except Exception:
        pass


def _find(watches: list, query: str):
    q = (query or "").strip().lower()
    if not q:
        return None
    for w in watches:
        if q in w["id"].lower():
            return w
    for w in watches:
        if q in _label_from(w).lower():
            return w
    return None


def watch(condition: str) -> str:
    """Start watching one condition from the allowlist."""
    parsed = _parse(condition)
    if isinstance(parsed, str):
        return parsed
    cond, args, label = parsed

    with _lock:
        watches = _load()
        # Prune watches that are done (fired or expired) and old enough that
        # nobody is reviewing them any more -- same shape as scheduler_skill.
        watches = [w for w in watches if w.get("enabled", True)
                   or time.time() - w.get("created_at", 0) < 3600]
        if len(watches) >= MAX_MONITORS:
            return (f"You already have {MAX_MONITORS} monitors running -- "
                    f"cancel one first.")
        now = time.time()
        mon = {
            "id": uuid.uuid4().hex[:8],
            "cond": cond, "args": args, "label": label,
            "created_at": now,
            "expires_at": now + MAX_MONITOR_SECONDS,
            "results": [],
        }
        watches.append(mon)
        _save(watches)
    _ensure_running()
    minutes = int(MAX_MONITOR_SECONDS // 60)
    return (f"Watching ({mon['id']}): {label}. I'll let you know when it "
            f"happens -- up to {minutes} minutes.")


def list_watches(query: str = "") -> str:
    watches = [w for w in _load() if w.get("enabled", True)]
    if query:
        w = _find(watches, query)
        watches = [w] if w else []
    if not watches:
        return "No active monitors." if not query else f"No monitor matching {query}."
    return "; ".join(f'{w["id"]}: watching {_label_from(w)}' for w in watches)


def cancel(query: str) -> str:
    with _lock:
        watches = _load()
        w = _find(watches, query)
        if not w:
            return (f"I don't have a monitor matching {query}." if query
                    else "Cancel which monitor?")
        watches = [x for x in watches if x["id"] != w["id"]]
        _save(watches)
    return f'Stopped watching: {_label_from(w)} ({w["id"]}).'


def status() -> str:
    watches = _load()
    if not watches:
        return "No monitors."
    active = [w for w in watches if w.get("enabled", True)]
    pending = sum(len(w.get("results", [])) for w in watches)
    return (f"{len(watches)} monitor{'s' if len(watches) != 1 else ''} total, "
            f"{len(active)} active, {pending} result"
            f"{'s' if pending != 1 else ''} waiting.")


def results(query: str = "", limit: int = 5) -> str:
    watches = _load()
    if query:
        w = _find(watches, query)
        watches = [w] if w else []
    lines = []
    for w in watches:
        for r in w.get("results", [])[-limit:]:
            when = time.strftime("%H:%M", time.localtime(r["at"]))
            lines.append(f'[{when}] watching {w["label"]}: {r["text"]}')
    if not lines:
        return "No results yet." if query else "No monitors have fired yet."
    return " | ".join(lines[-limit:])


def unread_count() -> int:
    """For proactive_skill's nudge -- a COUNT only, never the finding itself.
    See module docstring."""
    return sum(len(w.get("results", [])) for w in _load())


def mark_read() -> None:
    with _lock:
        watches = _load()
        for w in watches:
            w["results"] = []
        _save(watches)


# ═══════════════════════════════════════════════════════════════════════════
# THE BACKGROUND LOOP
# ═══════════════════════════════════════════════════════════════════════════

_thread = None
_thread_lock = threading.Lock()


def _ensure_running():
    global _thread
    with _thread_lock:
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(target=_loop, name="argus-monitor", daemon=True)
            _thread.start()


def _loop():
    while True:
        time.sleep(POLL_INTERVAL)
        try:
            _run_due()
        except Exception as e:
            print(f"[monitor] tick failed: {type(e).__name__}: {e}")


def _run_due():
    now = time.time()
    with _lock:
        watches = _load()
    active = [w for w in watches if w.get("enabled", True) and w.get("cond")]
    if not active:
        return

    s = _snapshot()
    fired = []
    for w in active:
        if w.get("expires_at") and now >= w["expires_at"]:
            w["enabled"] = False          # expired without firing -- see docstring
            continue
        detail = _eval(w, s)
        if detail:
            results = list(w.get("results", []))
            results.append({"at": now, "text": (detail or "")[:120]})
            w["results"] = results[-MAX_RESULTS_PER_WATCH:]
            w["enabled"] = False          # one-shot: answered, now still
            fired.append(w)

    if fired:
        with _lock:
            # Re-read-modify-write so a concurrent watch() isn't clobbered.
            current = _load()
            by_id = {w["id"]: w for w in current}
            for w in fired:
                if w["id"] in by_id:
                    by_id[w["id"]].update(w)
            _save(list(by_id.values()))


def restart_pending():
    """Resume any enabled monitor from a previous run. Cheap JSON read; starts
    the poll thread only if there is actually something to watch."""
    watches = _load()
    if any(w.get("enabled", True) for w in watches):
        _ensure_running()


restart_pending()