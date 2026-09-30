"""
ARGUS - Universal app control.

Replaces the hand-maintained allowlist with real discovery: scans the Windows
Start Menu for every installed application at startup, and enumerates running
processes for closing. You no longer edit config.py to add an app — if it's
installed, ARGUS can open it.

Safety: closing is guarded by PROTECTED_PROCESSES. Fuzzy matching plus
process-killing is a genuinely dangerous combination — "close system" must never
resolve to lsass.exe, and ARGUS must never kill its own Python process or Ollama.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import re
import json
import time
import difflib
import subprocess

import psutil

START_MENU_DIRS = [
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs",
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs"),
]

# Killing any of these either breaks Windows or kills ARGUS itself.
PROTECTED_PROCESSES = {
    "system", "system idle process", "registry", "memory compression",
    "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "smss.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "spoolsv.exe",
    "ctfmon.exe", "sihost.exe", "taskhostw.exe", "runtimebroker.exe",
    "searchhost.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "audiodg.exe", "conhost.exe", "wudfhost.exe", "dllhost.exe",
    # ARGUS's own stack — closing these is self-destruction
    "python.exe", "pythonw.exe", "ollama.exe", "ollama app.exe",
    "llama-server.exe", "electron.exe", "node.exe", "piper.exe",
}

# Common spoken names that don't match the shortcut text exactly.
ALIASES = {
    "vs code": "visual studio code",
    "vscode": "visual studio code",
    "code": "visual studio code",
    "browser": "google chrome",
    "chrome": "google chrome",
    "word": "microsoft word",
    "excel": "microsoft excel",
    "powerpoint": "microsoft powerpoint",
    "cmd": "command prompt",
    "files": "file explorer",
    "explorer": "file explorer",
    "settings": "settings",
    "calc": "calculator",
    # App Paths registers these under their executable stem, which is not
    # what anyone calls them out loud.
    "terminal": "wt",
    "windows terminal": "wt",
    "paint": "mspaint",
    "snipping tool": "snippingtool",
    "teams": "ms-teams",
    "task manager": "task manager",
    # NO alias for "edge". It is already indexed under its real name, and
    # forcing it to the App Paths stem "msedge" resolved exactly -- which
    # skipped the disambiguation between Edge and Edge Beta when both are
    # installed. An alias should reach an app that is otherwise unreachable,
    # not override a name that already works.
}

_app_index: dict[str, str] = {}


def _registry_apps() -> dict:
    """Executables Windows can launch by bare name, from App Paths.

    Read-only, and failures are swallowed per key: an unreadable registry
    entry must degrade the index, never break app launching entirely.
    """
    if os.name != "nt":
        return {}
    import winreg

    out = {}
    for root, path in (
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"),
    ):
        try:
            with winreg.OpenKey(root, path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        sub = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, sub) as skey:
                            exe, _ = winreg.QueryValueEx(skey, None)
                        exe = (exe or "").strip('"')
                        if not exe or not os.path.exists(exe):
                            continue
                        name = sub.lower().removesuffix(".exe").strip()
                        # Start Menu names win: they are what a person calls
                        # the app ("visual studio code"), while App Paths
                        # carries the executable stem ("code"). Both end up in
                        # the index, and neither overwrites the other.
                        if name and name not in out:
                            out[name] = exe
                    except OSError:
                        continue
        except OSError:
            continue
    return out


def build_index(verbose: bool = True) -> int:
    """Walks the Start Menu and indexes every shortcut. Called once at startup."""
    global _app_index
    index = {}
    for base in START_MENU_DIRS:
        if not os.path.isdir(base):
            continue
        for root, _dirs, files in os.walk(base):
            for fn in files:
                if not fn.lower().endswith((".lnk", ".url")):
                    continue
                name = os.path.splitext(fn)[0].lower().strip()
                # Prefer the shallower path when the same app appears twice
                if name not in index:
                    index[name] = os.path.join(root, fn)

    # Built-in Windows apps that have no Start Menu shortcut
    index.setdefault("file explorer", "explorer.exe")
    index.setdefault("command prompt", "cmd.exe")
    index.setdefault("task manager", "taskmgr.exe")
    index.setdefault("notepad", "notepad.exe")
    index.setdefault("calculator", "calc.exe")
    index.setdefault("settings", "ms-settings:")

    # THE REGISTRY, which is where Windows itself looks.
    #
    # Indexing only the Start Menu missed everything installed without a
    # shortcut: on this machine that is 32 real applications including Windows
    # Terminal, Paint, Snipping Tool, Teams, VS Code and winget. "open
    # terminal" answered "I couldn't find an app called terminal" on a machine
    # where Windows Terminal is installed and the Run box opens it by name.
    #
    # App Paths is exactly the list the Run box consults, so anything the user
    # can start by typing its name, ARGUS can now start by hearing it.
    index.update(_registry_apps())

    _app_index = index
    if verbose:
        print(f"[apps] indexed {len(index)} applications")
    return len(index)


_MAX_CLARIFY_OPTIONS = 4  # more than this, asking is unwieldy -- fall back to a guess

# Vendor words shared across unrelated products. Stripped before fuzzy
# matching so similarity is judged on the part that identifies the app --
# see _resolve, where "microsoft word" matched "microsoft edge" on this alone.
_VENDOR_PREFIX = re.compile(
    r"^(microsoft|google|windows|apple|adobe|oracle|mozilla|intel|nvidia)\s+",
    re.I)

# Script types that must never be launched as "an app". Deliberately does NOT
# include .exe, .lnk or .url -- those are what the Start Menu is made of.
_SCRIPT_EXTENSIONS = {
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".scr", ".reg", ".sh", ".py", ".pyw",
    ".jar", ".msi", ".msp", ".cpl", ".inf",
}


def _resolve(query: str) -> dict | None:
    """Finds the matching indexed app(s).

    Returns {"name":..., "path":...} for one clear match, {"candidates": [...]}
    when multiple real candidates tie with no exact winner (e.g. both
    "discord" and "discord ptb" are installed and the query is "discord" but
    typed/misheard as something that matches neither exactly), or None when
    nothing matches at all.

    BUGFIX: this used to always collapse multiple candidates to
    min(candidates, key=len) silently -- picking whichever installed app
    happened to have the shorter name, with zero indication a choice was
    even made. That's a coin flip dressed up as a decision. An exact name
    match still wins outright with no question asked; only genuine ties
    between real candidates get surfaced.
    """
    if not _app_index:
        build_index(verbose=False)

    q = query.lower().strip()
    # A user's own alias ("editor" -> "VS Code") wins over the shipped
    # default table below, since it's the more specific, explicitly-chosen
    # mapping. Deterministic dict lookup either way -- no model call.
    try:
        from skills.personalize_skill import resolve_alias
        q = (resolve_alias(q) or q).lower()
    except Exception:
        pass
    q = ALIASES.get(q, q)

    # 1. exact — always a clear, unambiguous winner regardless of what else
    # happens to start with or contain this string.
    if q in _app_index:
        return {"name": q, "path": _app_index[q]}

    # A BARE VENDOR NAME names a publisher, not a program. "open windows"
    # silently picked "windows powershell" and "open microsoft" picked
    # "microsoft edge" -- whichever happened to sort first among dozens of
    # matches. Ask instead of guessing: the user knows which they meant.
    if not _VENDOR_PREFIX.sub("", q + " ").strip():
        matches = sorted((n for n in _app_index if n.startswith(q)), key=len)
        return {"candidates": matches[:_MAX_CLARIFY_OPTIONS]} if matches else None

    # 2. an indexed name starts with the query ("telegram" -> "telegram desktop")
    starts = [n for n in _app_index if n.startswith(q)]
    if len(starts) == 1:
        return {"name": starts[0], "path": _app_index[starts[0]]}
    if 2 <= len(starts) <= _MAX_CLARIFY_OPTIONS:
        return {"candidates": sorted(starts, key=len)}
    if starts:  # too many to sensibly ask -- fall back to the old behaviour
        best = min(starts, key=len)
        return {"name": best, "path": _app_index[best]}

    # 3. query appears anywhere in an indexed name
    contains = [n for n in _app_index if q in n]
    if len(contains) == 1:
        return {"name": contains[0], "path": _app_index[contains[0]]}
    if 2 <= len(contains) <= _MAX_CLARIFY_OPTIONS:
        return {"candidates": sorted(contains, key=len)}
    if contains:
        best = min(contains, key=len)
        return {"name": best, "path": _app_index[best]}

    # 4. fuzzy — catches transcription slips like "telegraph" for "telegram".
    # Asks for up to 3 close matches now (was 1) specifically so a genuine
    # tie between two plausible mishearings is visible instead of hidden by
    # only ever looking at the single top-scored guess.
    # Compared with the VENDOR PREFIX STRIPPED, because that prefix is shared
    # by unrelated products and dominates the similarity score.
    #
    # "word" aliases to "microsoft word", which is not installed here. The
    # fuzzy step then scored it against "microsoft edge" -- 0.74, over the
    # cutoff, purely on the shared "microsoft " -- and ARGUS confidently
    # opened a WEB BROWSER when asked for a word processor. Opening the wrong
    # application is worse than admitting the right one is missing.
    #
    # Stripping the vendor leaves "word" against "edge", which correctly
    # scores near zero, while genuine mishearings ("telegraph" for "telegram")
    # are unaffected because their distinguishing part is what was misheard.
    bare_q = _VENDOR_PREFIX.sub("", q).strip() or q
    bare_map = {}
    for name in _app_index:
        bare_map.setdefault(_VENDOR_PREFIX.sub("", name).strip() or name, name)

    close = difflib.get_close_matches(bare_q, list(bare_map), n=3, cutoff=0.75)
    resolved = [bare_map[c] for c in close]
    if len(resolved) == 1:
        return {"name": resolved[0], "path": _app_index[resolved[0]]}
    if len(resolved) >= 2:
        return {"candidates": resolved}

    # 5. DROP TRAILING DESCRIPTIVE WORDS and try again.
    #
    # People name apps with more words than the shortcut has: "telegram
    # desktop", "chrome browser", "the steam app". Every step above anchors on
    # the whole phrase, so "telegram desktop" found nothing on a machine where
    # "telegram" is indexed and one word would have matched.
    #
    # Retried shortest-last so the most specific phrase still wins, and only
    # while at least one word remains -- this trims qualifiers, it does not
    # broaden a one-word query into matching anything.
    words = q.split()
    if len(words) > 1:
        for cut in range(len(words) - 1, 0, -1):
            shorter = " ".join(words[:cut])
            if len(shorter) < 3:
                break
            # NEVER retry on a vendor word alone. "microsoft word" trimmed to
            # "microsoft" prefix-matches "microsoft edge", which reintroduced
            # the exact wrong-app bug this function was fixed for one step
            # earlier: asked for a word processor, ARGUS opened a browser.
            # A vendor name identifies a publisher, not an application.
            if not _VENDOR_PREFIX.sub("", shorter + " ").strip():
                continue
            hit = _resolve(shorter)
            if hit:
                return hit

    return None


def open_app(query: str) -> str:
    if not query.strip():
        return "Which app would you like me to open?"

    hit = _resolve(query)
    if not hit:
        return f"I couldn't find an app called {query} on this machine."

    if "candidates" in hit:
        from skills import clarify_skill
        return clarify_skill.ask(hit["candidates"], "apps", "open")

    path = hit["path"]

    # THE INDEX IS ATTACKER-WRITABLE, so what comes out of it is checked.
    #
    # %APPDATA%\Microsoft\Windows\Start Menu\Programs is writable by the user
    # (verified), which means anything able to write as this user can drop a
    # .lnk there and make it openable by voice. That is not a new weakness --
    # the same attacker could place a shortcut you would click -- but it does
    # mean the index is untrusted input, and open_app was the one launch path
    # with no execution-policy check at all.
    #
    # A real Start Menu application is an .exe, a .lnk, a .url or a protocol
    # handler. A raw .bat, .ps1, .vbs, .cmd, .js or .hta pretending to be an
    # installed app is a script wearing an application's name, and voice is
    # not the place to run one.
    ext = os.path.splitext(path)[1].lower()
    if ext in _SCRIPT_EXTENSIONS:
        try:
            import security

            security.security_event(security.TOOL_DENIED, skill="apps",
                                    action="open", file=path,
                                    reason="script_masquerading_as_app",
                                    status="failed")
        except Exception:
            pass
        return (f"{hit['name']} points at a {ext} script rather than an "
                f"application, so I won't run it from a voice command.")

    # A path that vanished since indexing is a stale entry, not a launch.
    #
    # Three kinds of entry are legitimate and only ONE of them is a file on
    # disk, so each is recognised explicitly:
    #
    #   protocol handler   "ms-settings:"  -- a scheme with no path separator
    #   bare command       "calc.exe"      -- resolved by Windows through PATH
    #   absolute path      "C:\...\x.exe"  -- must actually exist
    #
    # The first attempt at this was `":" in path[:8]`, which is true of every
    # Windows drive letter -- so it waved through absolute paths that had been
    # deleted, and separately broke "calculator" (indexed as the bare command
    # calc.exe, which is not a path that exists relative to anything).
    is_protocol = bool(re.match(r"^[a-z][a-z0-9+.\-]*:(?![\\/])", path, re.I))
    is_bare_command = not os.path.isabs(path) and "\\" not in path and "/" not in path
    if not (is_protocol or is_bare_command or os.path.exists(path)):
        return (f"{hit['name']} is in my index but the file is gone. "
                f"Say \"rebuild the app index\" if it moved.")

    try:
        # os.startfile handles shortcuts, executables and protocol handlers
        # (ms-settings:) alike. shell=True was used here previously, which meant
        # any shell metacharacter in an indexed path became command injection.
        os.startfile(path)
        return f"Opening {hit['name']}."
    except Exception as e:
        return f"I found {hit['name']} but couldn't launch it: {e}"


def _running_processes() -> dict[str, list]:
    """Maps lowercase process name -> list of psutil.Process."""
    procs = {}
    for p in psutil.process_iter(["name"]):
        try:
            nm = (p.info["name"] or "").lower()
            if nm:
                procs.setdefault(nm, []).append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs


def close_app(query: str) -> str:
    if not query.strip():
        return "Which app should I close?"

    q = query.lower().strip()
    try:
        from skills.personalize_skill import resolve_alias
        q = (resolve_alias(q) or q).lower()
    except Exception:
        pass
    q = ALIASES.get(q, q)
    procs = _running_processes()

    # Exact stem match wins outright, no question asked, regardless of what
    # else happens to contain this string (e.g. "discord" against a machine
    # also running "discord ptb" -- the exact name is not ambiguous).
    for name in procs:
        if name not in PROTECTED_PROCESSES and name.replace(".exe", "") == q:
            return _terminate(name, procs, query)

    # Otherwise collect every plausible substring match.
    candidates = []
    for name in procs:
        if name in PROTECTED_PROCESSES:
            continue
        stem = name.replace(".exe", "")
        if q in stem or stem in q:
            candidates.append(name)

    if not candidates:
        close = difflib.get_close_matches(
            q,
            [n.replace(".exe", "") for n in procs if n not in PROTECTED_PROCESSES],
            n=3,
            cutoff=0.75,
        )
        candidates = [n for n in procs if n.replace(".exe", "") in close]

    if not candidates:
        return f"{query} doesn't appear to be running."

    # BUGFIX: this used to always collapse to min(candidates, key=len) --
    # picking whichever matching process happened to have the shorter name,
    # with no indication a choice was even made. A genuine tie between
    # distinct running processes gets asked about now instead of guessed --
    # closing the wrong one of two similarly-named apps isn't a harmless
    # mistake if either had unsaved work.
    if len(candidates) > 1:
        options = sorted({c.replace(".exe", "") for c in candidates}, key=len)
        if len(options) > 1:
            from skills import clarify_skill
            return clarify_skill.ask(options, "apps", "close")

    target = min(candidates, key=len)
    return _terminate(target, procs, query)


def _terminate(target: str, procs: dict, query: str) -> str:
    if target in PROTECTED_PROCESSES:
        return f"I won't close {target} — it's a protected system process."

    killed = 0
    for p in procs[target]:
        try:
            p.terminate()
            killed += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if killed:
        return f"Closed {target.replace('.exe', '')}."
    return f"I couldn't close {query} — it may need administrator rights."


# ── workspaces ───────────────────────────────────────────────────────────────
#
# "Set up my coding workspace" -- open the apps you always open and put them
# where you always put them, in one sentence.
#
# It lives here rather than in window_skill for a boring, deliberate reason:
# this module already declares filesystem and subprocess, and window_skill
# declares neither. Putting it there would mean granting two new capabilities
# to a module that manages window geometry, so that it could launch programs
# and write files -- a much wider grant than the feature needs. Opening apps
# is the part that needs privilege; arranging them is borrowed from
# window_skill, which keeps its narrow permissions.
#
# SAVED FROM WHAT IS ACTUALLY OPEN, never typed. A workspace you have to
# describe is a config file with a microphone attached; a workspace you save
# by arranging your screen once and saying "save this" is the feature.

WORKSPACE_MAX = 12          # named layouts kept
WORKSPACE_MAX_APPS = 8      # windows in one layout
_LAUNCH_SETTLE_S = 0.6      # between launches, so a slow app is not skipped
_WINDOW_WAIT_S = 12.0       # total budget waiting for launched windows to appear


def _workspace_path():
    from config import VAULT_PATH
    return os.path.join(VAULT_PATH, "workspaces.json")


def _load_workspaces() -> dict:
    try:
        with open(_workspace_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception:
        # A corrupt file must not make every workspace command fail; an empty
        # set is recoverable by saving again, an exception is not.
        return {}


def _save_workspaces(data: dict) -> bool:
    try:
        path = _workspace_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
        os.replace(tmp, path)       # atomic: a crash mid-write keeps the old set
        return True
    except Exception:
        return False


def save_workspace(name: str) -> str:
    """Remember the windows that are open now, and where they are."""
    name = " ".join((name or "").lower().split()).strip(" .")
    if not name:
        return "What should I call this workspace?"

    try:
        from skills import window_skill
        wins = window_skill._windows()
        ax, ay, aw, ah = window_skill._work_area()
    except Exception as e:
        return f"I couldn't read your windows ({type(e).__name__})."
    if not wins:
        return "I don't see any windows to save."

    entries = []
    for w in wins:
        try:
            if w.isMinimized or w.width < 120 or w.height < 90:
                continue        # minimised or a stray tooltip-sized window
            # Stored as FRACTIONS of the work area, not pixels: restoring on a
            # different monitor, or after the taskbar moves, should put things
            # in the same PLACE, not at the same coordinates.
            entries.append({
                "title": w.title[:120],
                "x": round((w.left - ax) / aw, 4),
                "y": round((w.top - ay) / ah, 4),
                "w": round(w.width / aw, 4),
                "h": round(w.height / ah, 4),
            })
        except Exception:
            continue
        if len(entries) >= WORKSPACE_MAX_APPS:
            break
    if not entries:
        return "I don't see any open windows worth saving."

    data = _load_workspaces()
    if name not in data and len(data) >= WORKSPACE_MAX:
        oldest = min(data, key=lambda k: data[k].get("saved", ""))
        data.pop(oldest, None)
    data[name] = {"saved": time.strftime("%Y-%m-%dT%H:%M:%S"),
                  "windows": entries}
    if not _save_workspaces(data):
        return "I couldn't write that down."
    try:
        import security
        security.audit("workspace_save", f"name={name[:40]} n={len(entries)}", "ok")
    except Exception:
        pass
    return (f"Saved \"{name}\" — {len(entries)} "
            f"{'window' if len(entries) == 1 else 'windows'} and where they sit.")


def _restore_one(entry: dict) -> bool:
    """Put one saved window back. Launches it if it is not already open."""
    from skills import window_skill

    title = entry.get("title", "")
    if not title:
        return False
    w = window_skill._find(title)
    if not w:
        # Not open. The saved TITLE usually contains the app name ("main.py -
        # Visual Studio Code"), so the last segment is the best launch query.
        guess = title.split(" - ")[-1].strip() or title
        try:
            open_app(guess)
        except Exception:
            return False
        deadline = time.time() + _WINDOW_WAIT_S
        while time.time() < deadline:
            time.sleep(_LAUNCH_SETTLE_S)
            w = window_skill._find(guess)
            if w:
                break
        if not w:
            return False

    try:
        ax, ay, aw, ah = window_skill._work_area()
        if getattr(w, "isMaximized", False) or getattr(w, "isMinimized", False):
            w.restore()
        w.moveTo(int(ax + aw * float(entry.get("x", 0))),
                 int(ay + ah * float(entry.get("y", 0))))
        w.resizeTo(max(200, int(aw * float(entry.get("w", 0.5)))),
                   max(150, int(ah * float(entry.get("h", 0.5)))))
        return True
    except Exception:
        return False


def restore_workspace(name: str) -> str:
    """Open and arrange a saved workspace."""
    name = " ".join((name or "").lower().split()).strip(" .")
    data = _load_workspaces()
    if not data:
        return ("I haven't saved any workspaces yet. Arrange your screen how "
                "you like it and say \"save this as my coding workspace\".")
    if name not in data:
        near = difflib.get_close_matches(name, list(data), n=1, cutoff=0.6)
        if not near:
            return (f"I don't have a workspace called {name}. I have: "
                    f"{', '.join(sorted(data))}.")
        name = near[0]

    entries = data[name].get("windows") or []
    done = sum(1 for e in entries if _restore_one(e))
    try:
        import security
        security.audit("workspace_restore", f"name={name[:40]} "
                       f"{done}/{len(entries)}", "ok")
    except Exception:
        pass
    if not done:
        return (f"I couldn't restore \"{name}\" — none of those windows would "
                f"open.")
    if done < len(entries):
        return (f"\"{name}\" is up — {done} of {len(entries)} windows. "
                f"I couldn't open the rest.")
    return f"\"{name}\" is up — {done} windows, back where you had them."


def list_workspaces() -> str:
    data = _load_workspaces()
    if not data:
        return ("No saved workspaces. Arrange your screen and say \"save this "
                "as my coding workspace\".")
    bits = [f"{n} ({len(v.get('windows') or [])})" for n, v in sorted(data.items())]
    return "Saved workspaces: " + ", ".join(bits) + "."


def forget_workspace(name: str) -> str:
    name = " ".join((name or "").lower().split()).strip(" .")
    data = _load_workspaces()
    if name not in data:
        return f"I don't have a workspace called {name}."
    data.pop(name, None)
    if not _save_workspaces(data):
        return "I couldn't update the list."
    return f"Forgotten \"{name}\"."


def list_running(limit: int = 12) -> str:
    """Top processes by memory — 'what's running' / 'what's using my memory'."""
    rows = []
    for p in psutil.process_iter(["name", "memory_info"]):
        try:
            nm = (p.info["name"] or "").lower()
            if nm in PROTECTED_PROCESSES or not nm:
                continue
            rows.append((nm.replace(".exe", ""), p.info["memory_info"].rss))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    merged: dict[str, int] = {}
    for nm, mem in rows:
        merged[nm] = merged.get(nm, 0) + mem

    top = sorted(merged.items(), key=lambda x: x[1], reverse=True)[:limit]
    if not top:
        return "I couldn't read the process list."
    parts = [f"{nm} at {mem / (1024**2):.0f} megabytes" for nm, mem in top[:5]]
    return "Top apps by memory: " + ", ".join(parts) + "."
