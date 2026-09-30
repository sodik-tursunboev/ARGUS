"""
ARGUS - Disk cleanup: temp files, caches and crash dumps that ACTUALLY get
deleted.

WHY THIS EXISTS. "clear my cache" used to fall through to the language model,
which answered one of two ways, both wrong. Either it explained how to open
Disk Cleanup -- advice, when an assistant sitting on the machine should just do
it -- or, worse, it replied "Your cache has been cleared." while nothing
whatsoever had happened. A confident false report of a completed action is the
single worst failure mode an assistant has, so this skill exists to make that
sentence true, and the routing exists so the model is never asked the question.

SAFETY COMES FROM SCOPE, NOT FROM CARE. This never accepts a path from the user.
There is no "clean <somewhere>" form and no wildcard: the only things it can
ever touch are the entries in LOCATIONS below, a fixed and documented table of
directories whose contents are regenerable by definition. A request phrased any
other way scans the same table or does nothing at all.

Five independent guards, because one is never enough for an irreversible
operation:

  1. CONTAINMENT. Every candidate is realpath()'d and must still resolve inside
     its own allowlisted root. This is what defeats a directory junction planted
     in %TEMP% pointing at Documents -- without it, "clean temp" becomes "delete
     my documents", and that is precisely how a cleaner turns into a weapon.
  2. FILES ONLY. Directories are never removed, only emptied. Nothing recurses
     into a reparse point.
  3. AGE. A file modified in the last MIN_AGE_S is skipped: temp files in active
     use are the ones an installer or a running app is holding open right now,
     and deleting those breaks live software rather than freeing anything.
  4. PROTECTED PATHS. integrity.is_protected() is consulted for every single
     file, the same last-gate files_skill._recycle() applies. ARGUS's own
     install directory and vault can never be a cleanup target.
  5. CONFIRMATION. A scan runs freely and deletes nothing; removal happens only
     after the user agrees to a specific, already-measured set of files.

WHAT IT DELIBERATELY WILL NOT DO. It does not empty the Recycle Bin. The bin IS
the undo for everything else on the machine, and a cleanup tool that empties it
has quietly destroyed the user's ability to recover from any other mistake --
including one of ARGUS's. Freeing that space is a decision for a person, in
Explorer, where the consequence is obvious. It also refuses to touch a browser's
cache while that browser is running, because deleting a live profile's cache
corrupts it; the browser is named in the reply so the user can close it and ask
again, rather than being told a vague "some things were skipped".

PERMANENT, NOT RECYCLED, AND THAT IS CORRECT HERE. files_skill sends user
documents to the Recycle Bin because a document is irreplaceable. Temp and cache
files are regenerable, and routing gigabytes of them through the bin would free
no space at all -- the exact thing the user asked for would not happen.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import time

try:
    import psutil
except Exception:
    psutil = None

# A file touched more recently than this is assumed to be in use.
MIN_AGE_S = 3600
# Bounds so a pathological tree cannot make a scan run forever.
MAX_FILES_PER_LOCATION = 60000
MAX_DEPTH = 12
# How long a scanned result stays valid for confirmation.
CONFIRM_WINDOW_S = 90

# Tests point this at a temp tree so a run never touches the real machine.
LOCATIONS_OVERRIDE = None


def _env(name, *parts):
    base = os.environ.get(name)
    return os.path.join(base, *parts) if base else None


def _locations() -> list:
    """(key, label, path, owner_process) -- the ENTIRE cleanup scope.

    owner_process is a browser whose cache must not be deleted while it runs.
    """
    if LOCATIONS_OVERRIDE is not None:
        return list(LOCATIONS_OVERRIDE)
    local = os.environ.get("LOCALAPPDATA") or ""
    win = os.environ.get("SystemRoot", r"C:\Windows")
    out = [
        ("user_temp", "Temporary files", os.environ.get("TEMP") or
         (os.path.join(local, "Temp") if local else None), None),
        ("windows_temp", "Windows temp", os.path.join(win, "Temp"), None),
        ("crash_dumps", "Crash dumps", _env("LOCALAPPDATA", "CrashDumps"), None),
        ("wer", "Error reports",
         _env("LOCALAPPDATA", "Microsoft", "Windows", "WER"), None),
        ("inetcache", "Internet cache",
         _env("LOCALAPPDATA", "Microsoft", "Windows", "INetCache"), None),
        ("edge_cache", "Edge cache",
         _env("LOCALAPPDATA", "Microsoft", "Edge", "User Data", "Default",
              "Cache", "Cache_Data"), "msedge.exe"),
        ("chrome_cache", "Chrome cache",
         _env("LOCALAPPDATA", "Google", "Chrome", "User Data", "Default",
              "Cache", "Cache_Data"), "chrome.exe"),
    ]
    return [(k, lbl, p, proc) for k, lbl, p, proc in out if p]


def _running(exe_name: str) -> bool:
    if not exe_name or psutil is None:
        return False
    try:
        target = exe_name.lower()
        for p in psutil.process_iter(["name"]):
            if (p.info.get("name") or "").lower() == target:
                return True
    except Exception:
        pass
    return False


def _contained(path: str, root: str) -> bool:
    """True only if PATH really lives inside ROOT once every link, junction and
    ..\\ has been resolved. The whole safety of this module rests here."""
    try:
        rp = os.path.realpath(path)
        rr = os.path.realpath(root)
        if not rr or not rp:
            return False
        return os.path.commonpath([rp, rr]) == rr
    except (OSError, ValueError):
        # commonpath raises ValueError across drives -- which is exactly the
        # case we must refuse, so a failure here is a "no", never a "probably".
        return False


def _is_protected(path: str) -> bool:
    try:
        import integrity
        return bool(integrity.is_protected(path))
    except Exception:
        # Fail CLOSED: if the protection check itself is unavailable, treat
        # everything as protected rather than deleting on a broken guard.
        return True


def human(n: int) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _scan_one(root: str, now: float) -> tuple:
    """(files, bytes, skipped_recent) for one allowlisted root."""
    files, total, recent = [], 0, 0
    if not root or not os.path.isdir(root):
        return files, total, recent
    root_depth = root.rstrip("\\/").count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        if dirpath.count(os.sep) - root_depth >= MAX_DEPTH:
            dirnames[:] = []
            continue
        # Never descend through a reparse point -- see guard 1.
        dirnames[:] = [d for d in dirnames
                       if not os.path.islink(os.path.join(dirpath, d))
                       and _contained(os.path.join(dirpath, d), root)]
        for name in filenames:
            if len(files) >= MAX_FILES_PER_LOCATION:
                return files, total, recent
            full = os.path.join(dirpath, name)
            try:
                if os.path.islink(full) or not _contained(full, root):
                    continue
                st = os.stat(full)
                if now - st.st_mtime < MIN_AGE_S:
                    recent += 1
                    continue
                if _is_protected(full):
                    continue
                files.append(full)
                total += st.st_size
            except OSError:
                continue
    return files, total, recent


_pending = {"at": 0.0, "plan": None}


def scan() -> dict:
    """Measure what could be freed. Deletes nothing, ever."""
    now = time.time()
    plan, skipped = [], []
    for key, label, path, owner in _locations():
        if not path or not os.path.isdir(path):
            continue
        if owner and _running(owner):
            skipped.append((label, f"{owner.replace('.exe', '')} is running"))
            continue
        files, size, recent = _scan_one(path, now)
        if files:
            plan.append({"key": key, "label": label, "root": path,
                         "files": files, "count": len(files), "bytes": size,
                         "recent_skipped": recent})
    return {"plan": plan, "skipped": skipped,
            "total_files": sum(p["count"] for p in plan),
            "total_bytes": sum(p["bytes"] for p in plan)}


def _summarise(res: dict) -> str:
    if not res["plan"]:
        base = "There's nothing worth clearing — your temp and cache folders are already clean."
        if res["skipped"]:
            base += (" I skipped " +
                     ", ".join(f"{lbl} ({why})" for lbl, why in res["skipped"]) + ".")
        return base
    parts = ", ".join(f"{p['label']} {human(p['bytes'])}" for p in res["plan"][:5])
    out = (f"I found {human(res['total_bytes'])} across "
           f"{res['total_files']} files — {parts}.")
    if res["skipped"]:
        out += (" I left " +
                ", ".join(f"{lbl} alone because {why}" for lbl, why in res["skipped"])
                + ".")
    return out


def stage() -> str:
    """What "clear my cache" runs: measure, report REAL numbers, then ask."""
    res = scan()
    if not res["plan"]:
        _pending.update(at=0.0, plan=None)
        return _summarise(res)
    _pending.update(at=time.time(), plan=res)
    return _summarise(res) + " Say 'yes' and I'll delete it."


def has_pending() -> bool:
    return bool(_pending["plan"]) and time.time() - _pending["at"] <= CONFIRM_WINDOW_S


def cancel() -> str:
    had = bool(_pending["plan"])
    _pending.update(at=0.0, plan=None)
    return "Left it alone." if had else "There was nothing waiting."


def run() -> str:
    """Delete the files measured by the staged scan. Re-verifies every guard.

    The plan is NOT trusted just because scan() built it: the file list is
    re-checked here, immediately before each unlink. Between the scan and the
    confirmation a path could have been replaced by a link pointing somewhere
    else -- a small window, but the whole point of the containment check is that
    it holds at the moment of deletion, not a minute earlier.
    """
    if not has_pending():
        _pending.update(at=0.0, plan=None)
        return ("I don't have a scan ready any more. Ask me to clear your "
                "cache again and I'll take a fresh look.")
    res = _pending["plan"]
    _pending.update(at=0.0, plan=None)

    removed = freed = locked = refused = 0
    per_location = []
    for p in res["plan"]:
        loc_removed = loc_freed = 0
        for full in p["files"]:
            try:
                if os.path.islink(full) or not _contained(full, p["root"]):
                    refused += 1
                    continue
                if _is_protected(full):
                    refused += 1
                    continue
                size = os.stat(full).st_size
                os.remove(full)
                loc_removed += 1
                loc_freed += size
            except PermissionError:
                locked += 1            # in use by a running program: expected
            except OSError:
                locked += 1
        removed += loc_removed
        freed += loc_freed
        if loc_removed:
            per_location.append(f"{p['label']} {human(loc_freed)}")

    _log(removed, freed, locked, refused)

    if not removed:
        return ("I couldn't remove anything — every file was still in use by a "
                "running program. Closing your browser and any installers "
                "usually frees them up.")
    out = f"Done. I deleted {removed} files and freed {human(freed)}"
    out += (" — " + ", ".join(per_location) + "." if per_location else ".")
    if locked:
        out += f" {locked} were in use and left alone."
    if refused:
        out += f" {refused} were refused by the safety checks."
    return out


def _log(removed, freed, locked, refused):
    try:
        import security
        security.audit("cleanup",
                       f"removed={removed} freed={freed}B "
                       f"locked={locked} refused={refused}", "ok")
    except Exception:
        pass


def status() -> dict:
    return {"locations": len(_locations()), "pending": has_pending(),
            "min_age_seconds": MIN_AGE_S}
