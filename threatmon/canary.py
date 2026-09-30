"""
ARGUS - Canary tokens / decoy tripwires (MITRE T1083, File and Directory
Discovery -- an attacker enumerating and reading credential-shaped files).

The idea is deception, not learning: files that look exactly like the things a
credential stealer hunts for -- passwords.txt, an .aws\\credentials, a wallet
seed phrase -- placed where those things really live, containing nothing real.
Nobody legitimate has any reason to open them, so ANY access is inherently
suspicious. There is no baseline, no threshold, no learning period; the first
touch is the alert.

DETECTION, HONESTLY. Two native, dependency-light mechanisms, and a plain
statement of what each can and cannot see:

  * STAT WATCH catches modification, replacement and deletion/move -- the file's
    size, mtime or content hash changing, or the file vanishing. Reliable.
  * OPEN WATCH catches a process that currently holds the decoy open, via
    psutil.open_files() (already a dependency; it resolves the handle safely,
    avoiding the named-pipe hang that hand-rolled NtQueryObject suffers). This
    is what attributes a READ to a process name and PID.

What NOTHING in user mode can see without kernel auditing is a pure directory
listing that merely stats the file, or a read that opens and closes faster than
a poll. status() says so rather than implying coverage that is not there. A real
stealer opens the file to read it, which the open watch is positioned to catch.

SAFETY. Planting NEVER overwrites a file that already exists -- if the user
genuinely has a passwords.txt, that name is skipped, not clobbered, and never
monitored (accessing your own real file is not an intrusion). Only files ARGUS
itself created are watched.

CRASH DISCIPLINE. A decoy moved or deleted out from under the watcher, a
permissions error, a psutil failure -- each is logged and skipped; the watch
thread never dies and never takes the orchestrator with it.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import hashlib
import json
import os
import threading
import time

import paths

try:
    import psutil
except Exception:
    psutil = None

TECHNIQUE = "T1083"

# Base directory for the decoys. None -> the real user profile (production).
# Tests point it at a temp dir so nothing lands on the real Desktop.
BASE_DIR_OVERRIDE = None
SCAN_INTERVAL_S = 5           # cheap stat watch cadence
# The open-handle sweep costs ~1s of CPU; run it every 3rd tick (~15s) so the
# watcher averages well under a tenth of one core rather than pinning it.
_OPEN_SCAN_EVERY = 3

# Realistic bait. Content is deliberately fake: the .aws keys are AWS's own
# publicly-documented EXAMPLE credentials, recognised everywhere as non-
# functional, so the file looks real to an attacker and is unmistakably a decoy
# in any forensic review.
CANARY_SPECS = [
    ("Desktop", "passwords.txt",
     "email: admin@home.local  pw: Summer2025!\n"
     "router admin: 192.168.1.1  pw: hunter2-changeme\n"
     "bank pin: see phone note\n"),
    ("Documents", "backup_codes.txt",
     "2FA backup codes (keep safe)\n"
     "  4831-9920  7712-0043  1190-8856  6624-3301\n"),
    (".aws", "credentials",
     "[default]\n"
     "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
     "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),
    ("Documents", "wallet_seed_phrase.txt",
     "metamask seed (do not share)\n"
     "ripple lunar velvet oyster canyon ember topple garden "
     "flint noble sugar drift\n"),
    ("Desktop", "vpn_admin_config.txt",
     "corp VPN\n  server: vpn.corp.local\n  user: admin\n  psk: pre-shared-2024\n"),
]

_state = {
    "supported": os.name == "nt" or True,
    "running": False,
    "planted": 0,
    "skipped": 0,
    "watched": [],
    "trips_total": 0,
    "last_error": "",
    "read_detection": "open-handle only (pure stat/listing not visible in user mode)",
}
_canaries = {}                 # path -> baseline dict
_lock = threading.RLock()


def _base_dir():
    return BASE_DIR_OVERRIDE or os.environ.get(
        "USERPROFILE", os.path.expanduser("~"))


def _registry_path():
    return paths.writable("canaries.json")


def _digest(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            h.update(fh.read(65536))
        return h.hexdigest()[:16]
    except OSError:
        return ""


def _baseline(path):
    try:
        st = os.stat(path)
        return {"size": st.st_size, "mtime": st.st_mtime, "sha": _digest(path)}
    except OSError:
        return None


def _load_registry() -> set:
    """normcase paths of decoys ARGUS created in a PREVIOUS session.

    Without this the whole detector silently dies after its first restart:
    plant() only adopted files it created THIS run, every decoy already existed
    by the second run, so all of them were skipped, `_canaries` was empty and
    nothing was watched. The files sat on disk looking like tripwires while
    status() reported "no decoys planted" -- a detector that had quietly
    stopped detecting. Re-adopting only what the registry says WE wrote keeps
    the safety property intact: a real file of the same name is still never
    watched, because it was never in the registry.
    """
    try:
        with open(_registry_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return {os.path.normcase(c["path"])
                for c in (data.get("canaries") or [])
                if isinstance(c, dict) and c.get("path")}
    except (OSError, ValueError, KeyError, TypeError):
        return set()


def _is_our_decoy(path: str, expected: str) -> bool:
    """True only if PATH still holds this decoy's exact text.

    Deliberately an EXACT comparison, not a heuristic. Anything looser risks
    adopting -- and therefore alerting on -- a file the user genuinely wrote,
    which is the one mistake this module must never make.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read() == expected
    except OSError:
        return False


def plant():
    """Create any decoys that do not already exist, and record a baseline for
    the ones WE own. Idempotent and non-destructive."""
    planted = skipped = readopted = 0
    ours_before = _load_registry()
    with _lock:
        for loc, name, content in CANARY_SPECS:
            d = os.path.join(_base_dir(), loc)
            path = os.path.join(d, name)
            key = os.path.normcase(path)
            try:
                if os.path.exists(path):
                    if key in ours_before or _is_our_decoy(path, content):
                        # Ours: either the registry says so, or the file still
                        # holds our exact decoy text.
                        #
                        # The content check is the RECOVERY path, and it was
                        # needed: the restart bug did not just stop watching,
                        # it re-saved an EMPTY registry every run, so the record
                        # of which files were ours had already been destroyed on
                        # this machine while five decoys sat on the Desktop
                        # unwatched. Byte-identical decoy text is unambiguous --
                        # a real passwords.txt does not contain AWS's published
                        # example keys, and a real .aws/credentials does not
                        # either -- so this recovers them without ever adopting
                        # a file the user actually wrote.
                        base = _baseline(path)
                        if base:
                            base["ours"] = True
                            _canaries[key] = {"path": path, **base}
                            readopted += 1
                        continue
                    # A REAL user file of the same name. Never clobbered, never
                    # monitored -- accessing your own file is not an intrusion.
                    skipped += 1
                    continue
                os.makedirs(d, exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(content)
                base = _baseline(path)
                if base:
                    base["ours"] = True
                    _canaries[os.path.normcase(path)] = {"path": path, **base}
                    planted += 1
            except OSError as e:
                _state["last_error"] = f"plant {name}: {type(e).__name__}"
        _state["planted"] = planted
        _state["readopted"] = readopted
        _state["skipped"] = skipped
        _state["watched"] = [c["path"] for c in _canaries.values()]
        _save_registry()
    return planted, skipped


def _save_registry():
    try:
        with open(_registry_path(), "w", encoding="utf-8") as fh:
            json.dump({"canaries": list(_canaries.values())}, fh, indent=1)
    except OSError:
        pass


# ── attribution ─────────────────────────────────────────────────────────────
def _who_has_open(paths_wanted: set):
    """{normcase path -> (pid, name)} for any canary a process currently holds
    open. Uses the fast single-enumeration scanner (winhandles); psutil's
    per-process open_files() sweep measured >2 minutes here and is unusable for
    a periodic watcher. Never raises."""
    try:
        from threatmon import winhandles
        return winhandles.open_holders(set(paths_wanted))
    except Exception as e:
        _state["last_error"] = f"attribution: {type(e).__name__}"
        return {}


# ── the trips ────────────────────────────────────────────────────────────────
def _emit(record, path, action, pid, name):
    finding = {
        "technique": TECHNIQUE,
        "detector": "canary",
        "severity": "high",
        "target": os.path.basename(path),
        "name": name or "(unattributed)",
        "pid": int(pid) if pid else 0,
        "path": path,
        "action": action,
        "reason": f"canary_{action}",
        # Per (file, action, accessor): re-alert if a DIFFERENT process trips it,
        # but do not spam while one keeps a handle open across ticks.
        "dedup": f"canary|{action}|{os.path.normcase(path)}|{pid or 0}",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    _state["trips_total"] += 1
    try:
        if record:
            record(finding)
    except Exception as e:
        _state["last_error"] = f"emit: {type(e).__name__}"
    return finding


def scan_stats(record):
    """Modification / replacement / deletion of any watched decoy."""
    with _lock:
        items = list(_canaries.items())
    for key, base in items:
        try:
            path = base["path"]
            if not os.path.exists(path):
                _emit(record, path, "deleted", None, None)
                # Re-plant so the tripwire persists, and reset the baseline.
                _replant(key, base)
                continue
            st = os.stat(path)
            if st.st_size != base["size"] or st.st_mtime != base["mtime"]:
                if _digest(path) != base["sha"]:
                    attr = _who_has_open({key})
                    pid, name = attr.get(key, (None, None))
                    _emit(record, path, "modified", pid, name)
                    with _lock:
                        nb = _baseline(path)
                        if nb:
                            _canaries[key].update(nb)
        except Exception as e:
            # Any failure on ONE decoy (a vanished dir, a permissions error, a
            # throwing attribution) must not stop the others being scanned or
            # kill the watch thread. Crash discipline over precision here.
            _state["last_error"] = f"stat {os.path.basename(base.get('path',''))}: {type(e).__name__}"


def scan_open(record):
    """Any process currently holding a decoy open -- the read/exfil signal."""
    with _lock:
        wanted = set(_canaries.keys())
    if not wanted:
        return
    for key, (pid, name) in _who_has_open(wanted).items():
        path = _canaries.get(key, {}).get("path", key)
        _emit(record, path, "opened", pid, name)


def _replant(key, base):
    try:
        loc_name = os.path.basename(base["path"])
        spec = next((s for s in CANARY_SPECS if s[1] == loc_name), None)
        if spec and not os.path.exists(base["path"]):
            os.makedirs(os.path.dirname(base["path"]), exist_ok=True)
            with open(base["path"], "w", encoding="utf-8") as fh:
                fh.write(spec[2])
        nb = _baseline(base["path"])
        if nb:
            with _lock:
                _canaries[key].update(nb)
    except OSError:
        pass


# ── loop / lifecycle ─────────────────────────────────────────────────────────
def run_checks(record, tick=0):
    """One pass. Each scan is guarded so one failing cannot stop the other or
    the loop."""
    try:
        scan_stats(record)
    except Exception as e:
        _state["last_error"] = f"scan_stats: {type(e).__name__}"
    if tick % _OPEN_SCAN_EVERY == 0:
        try:
            scan_open(record)
        except Exception as e:
            _state["last_error"] = f"scan_open: {type(e).__name__}"


def _watch_loop(record):
    _state["running"] = True
    tick = 0
    while True:
        try:
            run_checks(record, tick)
        except Exception as e:
            _state["last_error"] = f"loop: {type(e).__name__}: {e}"[:120]
        tick += 1
        time.sleep(SCAN_INTERVAL_S)


def start(record):
    try:
        plant()
    except Exception as e:
        _state["last_error"] = f"plant: {type(e).__name__}"
    t = threading.Thread(target=_watch_loop, args=(record,), daemon=True,
                         name="argus-canary-watch")
    t.start()


def status() -> dict:
    return {
        "detector": "canary",
        "technique": TECHNIQUE,
        "ok": _state["running"] and len(_canaries) > 0,
        "degraded": "" if _canaries else "no decoys planted",
        "planted": _state["planted"],
        "readopted": _state.get("readopted", 0),
        "skipped": _state["skipped"],
        "watched": len(_canaries),
        "trips_total": _state["trips_total"],
        "read_detection": _state["read_detection"],
        "last_error": _state["last_error"],
    }
