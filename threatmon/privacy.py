"""
ARGUS - Privacy Watch: what used your microphone, camera and location, and when.

MITRE T1123 (Audio Capture), T1125 (Video Capture) -- which is what a RAT does
to a person, not to a server. This detector exists because it answers the
question someone actually asks about their OWN machine: "did something turn on
my camera?" No enterprise tool answers that for you; it is not a fleet question.

HOW WINDOWS KNOWS. Every time an app opens the mic or camera, Windows stamps
LastUsedTimeStart / LastUsedTimeStop into the per-app CapabilityAccessManager
ConsentStore. Reading it is free (measured 0.014s for all three capabilities)
and needs no elevation, no driver and no hooking. Packaged Store apps appear
under their package family name; desktop programs appear as their full path with
backslashes rewritten as '#', which is why _decode_app() exists.

WHAT WAS MEASURED, NOT ASSUMED. The obvious design would alert on "in use RIGHT
NOW" by looking for LastUsedTimeStop == 0 while Start is set. That is widely
documented and it is NOT true on this build: holding a real 2.5-second input
stream open produced a Stop time written 0.2s after Start, never a zero. A
headline feature built on it would have silently never fired. So this detector
does not claim live use. It reports SESSIONS -- a Start timestamp that moved
since the last look -- which was verified to update the instant the stream
opened, and it says as much in status() rather than implying a live tap.

SIGNAL, NOT NAGGING. On a personal machine the useful alert is "an app that has
NEVER used your microphone just used it", not "Discord used your microphone
again". So:
  * first use of a capability by an app with no history  -> ALERT
  * any use by a binary in a temp/download/roaming path  -> ALERT
  * a known app using it again                           -> timeline only
The timeline is always recorded and is what usage_since() and the spoken
"has anything used my camera today?" answer read from. Alerts stay rare enough
to mean something.

SELF-EXCLUSION. ARGUS holds the microphone essentially all the time -- it is a
voice assistant. Alerting on itself would make the feature useless within one
minute, so its own executable and interpreter are excluded by path, and that
exclusion is stated in status() rather than being an invisible blind spot.

PRIVACY OF THE PRIVACY WATCH. This never records what was captured -- it cannot;
it only ever sees that a device was opened and by whom. Nothing here leaves the
machine: findings go to the local chained audit log with the app BASENAME only,
and the full path stays in the local detections store like every other detector.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import sys
import threading
import time

import paths

try:
    import winreg
except Exception:
    winreg = None

CONSENT = (r"Software\Microsoft\Windows\CurrentVersion"
           r"\CapabilityAccessManager\ConsentStore")

# capability -> (ATT&CK id, human label). Location has no clean ATT&CK technique
# for this context; it is watched because it matters to a person, and it is
# reported under the audio/video umbrella rather than inventing a false tag.
CAPABILITIES = {
    "microphone": ("T1123", "microphone"),
    "webcam":     ("T1125", "camera"),
    "location":   ("T1125", "location"),
}
TECHNIQUE = "T1123"

# Free to read, so a short cadence costs nothing and keeps the timeline tight.
SCAN_INTERVAL_S = 30

BASELINE_PATH_OVERRIDE = None
CONSENT_ROOT_OVERRIDE = None          # tests point this at a scratch registry key
SELF_PATHS_OVERRIDE = None
_TIMELINE_MAX = 200

# Same fixed, documented table the persistence sentinel uses: a capability grab
# from one of these locations is worth an alert even from a known app.
SUSPICIOUS_DIRS = (
    r"\appdata\local\temp", r"\windows\temp", r"\downloads",
    r"\users\public", r"\$recycle.bin", r"\appdata\roaming\microsoft\windows",
)

_state = {
    "supported": winreg is not None,
    "running": False,
    "baseline_established": False,
    "apps": 0,
    "sessions_seen": 0,
    "alerts_total": 0,
    "scans": 0,
    "last_error": "",
    "live_detection": "sessions only -- 'in use right now' is not detectable "
                      "here (LastUsedTimeStop is written while the device is "
                      "still open on this build; measured, not assumed)",
    "self_excluded": "",
}
_timeline = []
_lock = threading.RLock()


# ── helpers ──────────────────────────────────────────────────────────────────
def _ft_to_epoch(ft):
    try:
        if not ft:
            return 0.0
        v = ft / 10_000_000 - 11644473600
        return v if v > 0 else 0.0
    except Exception:
        return 0.0


def _iso(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(epoch)) if epoch else ""


def _decode_app(key_name: str) -> tuple:
    """(display_name, full_path_or_'', is_desktop_app).

    Desktop programs are stored as their path with '\\' rewritten to '#'.
    Packaged Store apps are stored as a package family name and have no path.
    """
    if "#" in key_name:
        path = key_name.replace("#", "\\")
        return os.path.basename(path) or path, path, True
    return key_name, "", False


def _self_paths():
    """Exact paths that are ARGUS itself. Excluded so the voice assistant does
    not spend all day reporting that it is using the microphone.

    1.4.1, per the audit: this set used to include paths.app_dir() as a BARE
    PREFIX, so any binary running from the install tree inherited the
    exemption -- the same substring-exclusion shape the LSASS allowlist was
    fixed for. Since 1.4.1 every entry here is an EXACT path, and an app-dir
    match must additionally be a file the integrity manifest actually covers
    (see _manifested_in_app_dir). A process whose image was dropped beside
    ARGUS.py now alerts like any other app.
    """
    if SELF_PATHS_OVERRIDE is not None:
        return {p.lower() for p in SELF_PATHS_OVERRIDE}
    out = set()
    try:
        out.add(os.path.normcase(sys.executable))    # source runs: python.exe
        out.add(os.path.normcase(os.path.join(paths.app_dir(), "ARGUS.exe")))
    except Exception:
        pass
    return {p.lower() for p in out if p}


def _manifested_in_app_dir(path: str) -> bool:
    """True only when PATH sits in the install tree AND the integrity manifest
    covers it with a matching hash. Fail-closed: an unmanifested file -- the
    planted-DLL case this check exists for -- returns False, as does any error
    consulting the manifest.
    """
    try:
        import integrity
        root = os.path.normcase(os.path.abspath(paths.app_dir())) + os.sep
        full = os.path.normcase(os.path.abspath(path or ""))
        if not full.startswith(root):
            return False
        rel = os.path.relpath(full, root).replace(os.sep, "/")
        ok, _detail = integrity.verify_one(rel)
        return bool(ok)
    except Exception:
        return False


def is_self(path: str) -> bool:
    if not path:
        return False
    p = os.path.normcase(path).lower()
    for s in _self_paths():
        if p == s:
            return True
    return _manifested_in_app_dir(path)


def is_suspicious_path(path: str) -> bool:
    low = (path or "").lower()
    return any(d in low for d in SUSPICIOUS_DIRS)


def classify_use(app: str, path: str, is_desktop: bool, known: bool) -> tuple:
    """(alert?, severity, reasons) for one usage session. Pure."""
    reasons = []
    if is_suspicious_path(path):
        reasons.append(f"runs from {os.path.dirname(path)[-48:]}")
        return True, "high", reasons
    if known:
        # A known app using a capability it has used before is normal life.
        return False, "info", ["previously seen using this capability"]
    reasons.append("first time this app has used this capability")
    # Store apps are sandboxed and vetted; an unknown loose .exe is the case
    # that actually warrants a person's attention.
    return True, ("high" if is_desktop else "medium"), reasons


# ── collection ───────────────────────────────────────────────────────────────
def _consent_root():
    return CONSENT_ROOT_OVERRIDE or CONSENT


def _read_capability(hive, cap) -> dict:
    """{app_key: {"start":epoch,"stop":epoch}} for one capability under one hive."""
    out = {}
    base = _consent_root() + "\\" + cap
    for sub in ("", "\\NonPackaged"):
        try:
            with winreg.OpenKey(hive, base + sub) as k:
                for i in range(winreg.QueryInfoKey(k)[0]):
                    try:
                        name = winreg.EnumKey(k, i)
                    except OSError:
                        continue
                    if name == "NonPackaged":
                        continue
                    try:
                        with winreg.OpenKey(k, name) as ak:
                            vals = {}
                            for j in range(winreg.QueryInfoKey(ak)[1]):
                                try:
                                    vn, vv, _t = winreg.EnumValue(ak, j)
                                except OSError:
                                    continue
                                vals[vn] = vv
                    except OSError:
                        continue
                    start = _ft_to_epoch(vals.get("LastUsedTimeStart"))
                    if not start:
                        continue           # permission set but never actually used
                    out[name] = {"start": start,
                                 "stop": _ft_to_epoch(vals.get("LastUsedTimeStop"))}
        except FileNotFoundError:
            continue
    return out


def collect() -> dict:
    """{(capability, app_key): {"start","stop"}} across every capability/hive."""
    snap = {}
    hives = [winreg.HKEY_CURRENT_USER]
    if CONSENT_ROOT_OVERRIDE is None:
        # HKLM holds machine-wide consent on some builds (empty on this one);
        # reading it costs nothing and makes the detector correct elsewhere.
        hives.append(winreg.HKEY_LOCAL_MACHINE)
    for cap in CAPABILITIES:
        for hive in hives:
            try:
                for app, rec in _read_capability(hive, cap).items():
                    key = (cap, app)
                    prev = snap.get(key)
                    if prev is None or rec["start"] > prev["start"]:
                        snap[key] = rec
            except Exception as e:
                _state["last_error"] = f"{cap}: {type(e).__name__}"
    return snap


# ── diff ─────────────────────────────────────────────────────────────────────
def diff(old: dict, new: dict) -> list:
    """Usage sessions that are new since the baseline. Pure and total.

    A session is new when the app has no history at all, or when its Start
    timestamp moved forward. Note the keys here are (capability, app) tuples in
    memory but strings on disk, so callers normalise before comparing.
    """
    sessions = []
    for key, cur in new.items():
        cap, app = key
        prev = old.get(key)
        if prev is None:
            sessions.append({"capability": cap, "app_key": app,
                             "start": cur["start"], "stop": cur["stop"],
                             "known": False})
        elif cur["start"] > float(prev.get("start", 0) or 0):
            sessions.append({"capability": cap, "app_key": app,
                             "start": cur["start"], "stop": cur["stop"],
                             "known": True})
    sessions.sort(key=lambda s: s["start"])
    return sessions


def _duration(s) -> int:
    d = (s.get("stop") or 0) - (s.get("start") or 0)
    return int(d) if d > 0 else 0


# ── timeline ─────────────────────────────────────────────────────────────────
def _remember(entry):
    with _lock:
        _timeline.append(entry)
        if len(_timeline) > _TIMELINE_MAX:
            del _timeline[:len(_timeline) - _TIMELINE_MAX]


def timeline(n: int = 50) -> list:
    with _lock:
        return list(_timeline)[-n:][::-1]


def usage_since(hours: float = 24.0, capability: str = None) -> list:
    """Every recorded session in the last `hours`, newest first.

    This is what "has anything used my camera today?" reads. Local, no model.
    """
    cutoff = time.time() - hours * 3600
    with _lock:
        rows = [e for e in _timeline if e.get("at_epoch", 0) >= cutoff]
    if capability:
        rows = [e for e in rows if e.get("capability") == capability]
    return rows[::-1]


def usage_report(hours: float = 24.0) -> str:
    """A plain-language answer, built with string logic only -- no model, no
    network, so what your camera did never becomes someone else's telemetry."""
    rows = usage_since(hours)
    label = "today" if hours <= 24 else f"in the last {int(hours)} hours"
    if not rows:
        return (f"Nothing has used your microphone, camera or location {label} "
                f"— apart from ARGUS itself, which I don't count.")
    by_cap = {}
    for r in rows:
        by_cap.setdefault(r["capability"], []).append(r)
    parts = []
    for cap, items in sorted(by_cap.items()):
        human = CAPABILITIES.get(cap, ("", cap))[1]
        apps = []
        for i in items:
            if i["app"] not in apps:
                apps.append(i["app"])
        when = _iso(items[-1]["at_epoch"])[11:16]
        parts.append(f"{human}: {', '.join(apps[:4])}"
                     f"{' and others' if len(apps) > 4 else ''} "
                     f"(most recent {when})")
    flagged = [r for r in rows if r.get("alert")]
    out = f"{label.capitalize()}, " + "; ".join(parts) + "."
    if flagged:
        out += (f" {len(flagged)} of those I flagged: "
                + "; ".join(f"{r['app']} used your "
                            f"{CAPABILITIES.get(r['capability'], ('', r['capability']))[1]}"
                            f" for the first time" for r in flagged[:3]) + ".")
    return out


# ── baseline ─────────────────────────────────────────────────────────────────
def _baseline_path():
    return BASELINE_PATH_OVERRIDE or paths.writable("privacy_baseline.json")


def _flatten(snap: dict) -> dict:
    return {f"{cap}|{app}": rec for (cap, app), rec in snap.items()}


def _unflatten(flat: dict) -> dict:
    out = {}
    for k, v in (flat or {}).items():
        if "|" in k and isinstance(v, dict):
            cap, app = k.split("|", 1)
            out[(cap, app)] = v
    return out


def load_baseline():
    """The stored baseline, or None when there is no usable one.

    None and {} are DIFFERENT, and here the difference is reachable: on a fresh
    install nothing has used the camera or microphone yet, so the baseline is
    legitimately EMPTY. Treating empty as "not established" would re-baseline
    every pass and silently absorb the very first camera access -- the one event
    this detector exists to catch.
    """
    try:
        with open(_baseline_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None
        apps = data.get("apps")
        return _unflatten(apps) if isinstance(apps, dict) else None
    except (OSError, ValueError):
        return None


def save_baseline(snap: dict) -> bool:
    try:
        path = _baseline_path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"at": _iso(time.time()), "apps": _flatten(snap)}, fh,
                      separators=(",", ":"))
        os.replace(tmp, path)
        return True
    except OSError as e:
        _state["last_error"] = f"baseline save: {type(e).__name__}"
        return False


# ── emit / scan ──────────────────────────────────────────────────────────────
def _emit(record, session):
    cap = session["capability"]
    app, path, is_desktop = _decode_app(session["app_key"])
    alert, sev, reasons = classify_use(app, path, is_desktop, session["known"])
    tid, human = CAPABILITIES.get(cap, (TECHNIQUE, cap))
    dur = _duration(session)

    entry = {
        "capability": cap, "app": app, "path": path,
        "at": _iso(session["start"]), "at_epoch": session["start"],
        "duration_s": dur, "alert": alert, "severity": sev, "reasons": reasons,
    }
    _remember(entry)
    with _lock:
        _state["sessions_seen"] += 1
    if not alert:
        return None

    finding = {
        "technique": tid,
        "detector": "privacy",
        "severity": sev,
        "target": human,
        "name": app,
        "pid": 0,                      # the ConsentStore records apps, not pids
        "path": path,
        "action": f"{human}_used",
        "capability": cap,
        "where": human,
        "command": (f"{app} used your {human} at {_iso(session['start'])}"
                    + (f" for {dur}s" if dur else "")),
        "duration_s": dur,
        "reasons": reasons,
        "reason": f"privacy_{cap}_first_use",
        # Per (capability, app): a first use alerts once, not every rescan.
        "dedup": f"privacy|{cap}|{session['app_key']}",
        "ts": _iso(session["start"]) or time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    with _lock:
        _state["alerts_total"] += 1
    try:
        if record:
            record(finding)
    except Exception as e:
        _state["last_error"] = f"emit: {type(e).__name__}"
    return finding


def run_checks(record) -> list:
    """One pass: read the consent store, report NEW sessions, re-baseline."""
    snap = collect()
    # Drop ARGUS's own usage before anything else looks at it.
    excluded = 0
    filtered = {}
    for key, rec in snap.items():
        _app, path, _d = _decode_app(key[1])
        if is_self(path):
            excluded += 1
            continue
        filtered[key] = rec

    with _lock:
        _state["scans"] += 1
        _state["apps"] = len(filtered)
        _state["self_excluded"] = (f"{excluded} ARGUS-owned entr"
                                   f"{'y' if excluded == 1 else 'ies'}"
                                   if excluded else "none present")

    old = load_baseline()

    # Seed the timeline from the consent store whenever it is empty -- on first
    # run AND after every restart. The timeline lives in memory, but the consent
    # store IS the durable history, so rebuilding from it is free and correct.
    # Without this, a restarted ARGUS answers "has anything used my camera
    # today?" with "nothing" until something new happens, which is worse than
    # not answering: it is a confident wrong answer about the user's privacy.
    with _lock:
        needs_seed = not _timeline
    if needs_seed:
        for key, rec in filtered.items():
            app, path, _ = _decode_app(key[1])
            _remember({"capability": key[0], "app": app, "path": path,
                       "at": _iso(rec["start"]), "at_epoch": rec["start"],
                       "duration_s": _duration(rec), "alert": False,
                       "severity": "info",
                       "reasons": ["from the consent store's own history"]})
        with _lock:
            _timeline.sort(key=lambda e: e.get("at_epoch", 0))

    if old is None:                      # NOT `not old` -- see load_baseline()
        # First run: everything already in the consent store is history, not an
        # incident. The timeline is seeded (above); raise nothing.
        with _lock:
            _state["baseline_established"] = True
        save_baseline(filtered)
        return []

    with _lock:
        _state["baseline_established"] = True
    emitted = []
    for session in diff(old, filtered):
        try:
            f = _emit(record, session)
            if f:
                emitted.append(f)
        except Exception as e:
            _state["last_error"] = f"emit {session.get('app_key', '?')}: {type(e).__name__}"
    save_baseline(filtered)
    return emitted


# ── loop / lifecycle ─────────────────────────────────────────────────────────
def _watch_loop(record):
    with _lock:
        _state["running"] = True
    while True:
        try:
            run_checks(record)
        except Exception as e:
            _state["last_error"] = f"loop: {type(e).__name__}: {e}"[:120]
        time.sleep(SCAN_INTERVAL_S)


def start(record):
    if not _state["supported"]:
        _state["last_error"] = "winreg unavailable"
        return
    t = threading.Thread(target=_watch_loop, args=(record,), daemon=True,
                         name="argus-privacy-watch")
    t.start()


def status() -> dict:
    with _lock:
        degraded = ""
        if not _state["supported"]:
            degraded = "unsupported OS (winreg unavailable)"
        elif not _state["baseline_established"]:
            degraded = "baseline not yet established (first scan pending)"
        return {
            "detector": "privacy",
            "technique": TECHNIQUE,
            "techniques": ["T1123", "T1125"],
            "ok": _state["running"] and _state["supported"],
            "degraded": degraded,
            "apps": _state["apps"],
            "sessions_seen": _state["sessions_seen"],
            "findings_total": _state["alerts_total"],
            "scans": _state["scans"],
            "timeline": len(_timeline),
            "baseline_established": _state["baseline_established"],
            "live_detection": _state["live_detection"],
            "self_excluded": _state["self_excluded"],
            "last_error": _state["last_error"],
        }
