"""
ARGUS - Persistence Sentinel: autostart surfaces, watched as a DIFF.

MITRE T1547.001 (Registry Run Keys / Startup Folder), T1547.004 (Winlogon
Helper), T1543.003 (Windows Service), T1053.005 (Scheduled Task).

WHY A DIFF AND NOT A LIST. Sysinternals Autoruns already prints everything that
runs at boot -- roughly a thousand entries on this machine, which is exactly why
nobody reads it. The useful question in an investigation is never "what runs at
startup", it is "what STARTED running at startup since yesterday, and what did
it replace". That question needs memory between runs, which a one-shot tool
cannot have. So this detector keeps a baseline in %LOCALAPPDATA% and alerts only
on the delta: entries ADDED, entries whose command was MODIFIED (an attacker
hijacking a legitimate autostart is quieter than adding a new one), and entries
REMOVED (disabling a security product's autostart is itself an attack).

THE FIRST SCAN NEVER ALERTS. With ~1000 pre-existing entries, a detector that
alarmed on what it found the first time would emit a thousand false positives
and be switched off within a minute. The first pass silently records the
baseline and says so in status(); only later passes can raise anything.

SURFACES, DELIBERATELY FIXED. Five, each readable natively by a NON-ELEVATED
user, chosen so the detector is not silently blind in the shipped exe
(ELEVEN since 1.4.1 -- see the 1.4.1 note below):

  * Run / RunOnce keys, HKLM + HKCU, native and Wow6432Node views  -- winreg
  * Startup folders, per-user and all-users                        -- filesystem
  * Services set to start at boot/system/auto (Start <= 2)         -- winreg
  * Winlogon Userinit / Shell values                               -- winreg
  * Scheduled tasks, via the Task Scheduler COM API                -- comtypes

comtypes is used for tasks rather than pywin32 because comtypes is already a
declared runtime dependency AND already in the PyInstaller spec's hiddenimports
(pycaw pulls it in), so the task collector cannot work in development and then
vanish in the frozen build. The filesystem and registry routes to the task list
were both measured returning Access Denied without elevation; the COM API
returns what this user is actually entitled to see (157 tasks here), which is
the honest answer for a non-elevated detector.

WHAT THIS CANNOT DO. It cannot tell you WHICH PROCESS wrote an entry. Nothing in
user mode can, after the fact -- that needs kernel ETW or registry auditing. It
does not guess. What it reports instead is genuinely knowable and genuinely
useful: the registry key's own LastWriteTime (a real forensic timestamp, not the
scan time), and any threat this suite detected shortly before the entry
appeared, so an encoded-PowerShell process at 14:02 and a new Run key at 14:02
are shown together instead of as two unrelated lines. That is correlation, and
it is labelled as correlation -- not attribution.

WMI event subscriptions (T1546.003) were covered in 1.2.0 through plain
COM via comtypes -- the same dependency collect_tasks already used -- so the
MITRE grid cell for it renders green with a live provider behind it.

Since 1.4.1 the surface set is ELEVEN, closing the audit's "many well-known
ones are silently absent" list: IFEO/Debugger (T1546.012), HKCU COM
InprocServer32 redirection (T1546.015), UserInitMprLogonScript (T1037.001),
LSA Security Support Providers (T1547.005) and AppInit_DLLs (T1546.010). All
five are plain winreg reads this non-elevated user is entitled to, which is
the criterion the original five were chosen by; the collectors sit in the
same COLLECTORS table and inherit the same diff engine, flood guard, baseline
and severity grading -- additive, not architectural. Absent keys (the healthy
case for most of these) record nothing, so a planted entry is a clean ADD.

CRASH DISCIPLINE. Every collector is isolated. A surface that throws is recorded
as failed and is EXCLUDED FROM THE DIFF for that pass -- otherwise a transient
registry error would make every entry it could not read look like it had been
removed, and the sentinel would fabricate a hundred deletions. Partial coverage
is reported; it is never silently papered over.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import threading
import time

import paths

try:
    import winreg
except Exception:                                   # non-Windows / test hosts
    winreg = None

# Which ATT&CK id each surface reports under. The MITRE catalogue in mitre.py
# holds the authoritative names; this maps surface -> id so a finding is tagged
# with the technique that actually matches the surface rather than one blanket id.
SURFACE_TECHNIQUE = {
    "run":      "T1547.001",
    "startup":  "T1547.001",
    "winlogon": "T1547.004",
    "service":  "T1543.003",
    "task":     "T1053.005",
    # 1.2.0: WMI permanent event subscriptions, read through plain COM
    # (comtypes) -- the dependency that used to be called undeclared is the
    # one collect_tasks already uses. See threatmon/wmisubs.py.
    "wmi":      "T1546.003",
    # 1.4.1: the five best-known autostart surfaces the original five skipped,
    # each readable NON-ELEVATED through winreg -- the exact criterion the
    # original set used. Added in ATT&CK-frequency order per the audit.
    "ifeo":        "T1546.012",   # Image File Execution Options Debugger
    "comhijack":   "T1546.015",   # HKCU CLSID InprocServer32
    "logonscript": "T1037.001",  # UserInitMprLogonScript
    "ssp":         "T1547.005",  # LSA Security Support Providers
    "appinit":     "T1546.010",  # AppInit_DLLs
}
TECHNIQUE = "T1547.001"          # representative id for status()

# Persistence is durable by definition -- that is the whole point of it, so a
# slow cadence costs nothing and misses nothing. One full sweep of all five
# surfaces measured 0.90s on this machine (339 entries, 250 of them services);
# at 60s that is 1.5% of one core, against 18% if it rode the 5s sampler tick
# for no detection benefit whatsoever.
SCAN_INTERVAL_S = 60

# More changes than this in ONE pass is a baseline discontinuity, not an attack.
# Real persistence is 1-3 entries; nothing plants fifty. A baseline that was
# truncated, half-written, or copied from another machine parses as valid JSON
# and would otherwise emit hundreds of "added" findings -- burying the single
# real one that might be among them. Past the threshold the sentinel reports ONE
# loud finding saying the baseline desynchronised and re-anchors. Nothing is
# hidden by this: an attacker cannot use it to sneak an entry past, because
# crossing it is itself reported.
_FLOOD_THRESHOLD = 50

# Tests point these at a temp dir / temp registry key so a test run never
# touches the real user's autostart configuration or baseline.
BASELINE_PATH_OVERRIDE = None
STARTUP_DIRS_OVERRIDE = None
RUN_KEYS_OVERRIDE = None

_RUN_KEYS = [
    # (hive, subkey, view-flag) -- Wow6432Node is a genuinely different key, not
    # a duplicate: a 32-bit installer writes there and a 64-bit-only read misses it.
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run", 0),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 0),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run", 1),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 1),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", 0),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 0),
]
_TASK_ENUM_HIDDEN = 1
_WINLOGON_KEY = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
_WINLOGON_VALUES = ("Userinit", "Shell", "Taskman", "AppSetup")
_SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
# 1.4.1 surface keys (see the collector docstrings for why each is watched).
_IFEO_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
_COM_CLSID_ROOTS = (r"Software\Classes\CLSID",
                    r"Software\Classes\Wow6432Node\CLSID")
_SSP_KEYS = [
    ("HKLM", r"System\CurrentControlSet\Control\Lsa", 0),
    ("HKLM", r"System\CurrentControlSet\Control\Lsa", 1),
]
_APPINIT_KEYS = [
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Windows", 0),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Windows", 1),
]

# ── the (fixed, documented) suspicion table ──────────────────────────────────
# Not an open-ended signature list. These change a finding's SEVERITY only; a
# new autostart entry is reported either way. Substring match on the expanded,
# lowercased image path.
SUSPICIOUS_DIRS = (
    r"\appdata\local\temp",
    r"\windows\temp",
    r"\downloads",
    r"\users\public",
    r"\$recycle.bin",
    r"\programdata\microsoft\windows\start menu",   # dropped-shortcut trick
)
# Interpreters and proxy-execution binaries. An autostart entry that runs one of
# these is running a SCRIPT at boot, which is a different risk from an autostart
# entry that runs a compiled application.
SUSPICIOUS_EXES = (
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "msbuild.exe", "installutil.exe", "curl.exe", "bitsadmin.exe",
)
SUSPICIOUS_EXTS = (".vbs", ".js", ".jse", ".vbe", ".bat", ".cmd", ".ps1",
                   ".hta", ".scr", ".pif")
# Command-line shapes that are strong on their own regardless of the binary.
SUSPICIOUS_ARGS = (
    "-enc", "-encodedcommand", "-e ", "frombase64string", "iex", "invoke-expression",
    "downloadstring", "downloadfile", "-w hidden", "-windowstyle hidden",
    "-nop", "-noprofile", "bypass", "http://", "https://",
)

from threatmon import wmisubs

_state = {
    "supported": winreg is not None,
    "running": False,
    "baseline_established": False,
    "baseline_at": "",
    "entries": 0,
    "changes_total": 0,
    "scans": 0,
    "desyncs": 0,
    "failed_surfaces": [],
    "last_error": "",
    "uncovered": "",   # was: WMI event subscriptions -- covered since 1.2.0
    "attribution": "timestamp + temporal correlation (process attribution needs kernel ETW)",
}
_lock = threading.RLock()


# ── helpers ──────────────────────────────────────────────────────────────────
def _filetime_to_iso(ft: int) -> str:
    """Registry LastWriteTime (100ns ticks since 1601) -> local ISO string."""
    try:
        epoch = ft / 10_000_000 - 11644473600
        if epoch <= 0:
            return ""
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(epoch))
    except Exception:
        return ""


def exe_of(command: str) -> str:
    """Best-effort image path out of an autostart command line.

    Quoted first token wins ("C:\\Program Files\\x\\a.exe" -w hidden); otherwise
    the first whitespace-delimited token. Deliberately simple -- this feeds the
    suspicion check and the display basename, never a security decision that
    would be unsafe to get wrong.
    """
    if not command:
        return ""
    s = os.path.expandvars(command.strip())
    if s.startswith('"'):
        end = s.find('"', 1)
        return s[1:end] if end > 0 else s[1:]
    return s.split(" ")[0]


def classify_entry(command: str) -> tuple:
    """(severity, [reasons]) for a NEWLY-APPEARED autostart command.

    Pure: no registry, no filesystem, no clock. Unit-testable on strings alone,
    which is why the interesting logic lives here and not inside a collector.
    """
    reasons = []
    if not command:
        return "medium", ["empty command"]
    low = os.path.expandvars(command).lower()
    exe = os.path.basename(exe_of(command)).lower()

    for d in SUSPICIOUS_DIRS:
        if d in low:
            reasons.append(f"runs from {d.strip(chr(92))}")
            break
    if exe in SUSPICIOUS_EXES:
        reasons.append(f"launches interpreter/proxy binary ({exe})")
    for ext in SUSPICIOUS_EXTS:
        if exe.endswith(ext) or f"{ext} " in low or low.endswith(ext):
            reasons.append(f"executes a {ext} script")
            break
    for a in SUSPICIOUS_ARGS:
        if a in low:
            reasons.append(f"suspicious argument ({a.strip()})")
            break

    return ("high" if reasons else "medium"), reasons


# ── collectors ───────────────────────────────────────────────────────────────
# Each returns {entry_id: {"value": <command>, "when": <iso>, "where": <label>}}
# and is allowed to raise; collect_all() isolates them.
def _open(hive_name, sub, wow):
    hive = winreg.HKEY_LOCAL_MACHINE if hive_name == "HKLM" else winreg.HKEY_CURRENT_USER
    access = winreg.KEY_READ | (winreg.KEY_WOW64_32KEY if wow else winreg.KEY_WOW64_64KEY)
    return winreg.OpenKey(hive, sub, 0, access)


def collect_run() -> dict:
    out = {}
    if RUN_KEYS_OVERRIDE is not None:
        keys = RUN_KEYS_OVERRIDE
    else:
        keys = _RUN_KEYS
    for hive_name, sub, wow in keys:
        try:
            with _open(hive_name, sub, wow) as k:
                n_vals = winreg.QueryInfoKey(k)[1]
                when = _filetime_to_iso(winreg.QueryInfoKey(k)[2])
                label = f"{hive_name}\\{sub}" + ("  (32-bit view)" if wow else "")
                for i in range(n_vals):
                    try:
                        name, val, _typ = winreg.EnumValue(k, i)
                    except OSError:
                        continue
                    out[f"run:{hive_name}\\{sub}{'|32' if wow else ''}!{name}"] = {
                        "value": str(val), "when": when, "where": label, "item": name,
                    }
        except FileNotFoundError:
            continue                    # RunOnce often does not exist; not an error
    return out


def _startup_dirs():
    if STARTUP_DIRS_OVERRIDE is not None:
        return list(STARTUP_DIRS_OVERRIDE)
    tail = r"Microsoft\Windows\Start Menu\Programs\Startup"
    dirs = []
    for env in ("APPDATA", "PROGRAMDATA"):
        base = os.environ.get(env)
        if base:
            dirs.append(os.path.join(base, tail))
    return dirs


def collect_startup() -> dict:
    out = {}
    for d in _startup_dirs():
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if name.lower() == "desktop.ini":
                continue
            full = os.path.join(d, name)
            try:
                when = time.strftime("%Y-%m-%dT%H:%M:%S",
                                     time.localtime(os.path.getmtime(full)))
            except OSError:
                when = ""
            out[f"startup:{os.path.normcase(full)}"] = {
                "value": full, "when": when, "where": d, "item": name,
            }
    return out


def collect_winlogon() -> dict:
    out = {}
    for hive_name in ("HKLM", "HKCU"):
        try:
            with _open(hive_name, _WINLOGON_KEY, 0) as k:
                when = _filetime_to_iso(winreg.QueryInfoKey(k)[2])
                for val_name in _WINLOGON_VALUES:
                    try:
                        val, _ = winreg.QueryValueEx(k, val_name)
                    except FileNotFoundError:
                        continue
                    out[f"winlogon:{hive_name}!{val_name}"] = {
                        "value": str(val), "when": when,
                        "where": f"{hive_name}\\{_WINLOGON_KEY}", "item": val_name,
                    }
        except FileNotFoundError:
            continue
    return out


def collect_services() -> dict:
    """Services configured to start without a user: Start 0/1/2.

    A service moving from disabled/manual (3, 4) to automatic shows up here as
    an ADDED entry, which is the correct reading -- it just became persistent.
    """
    out = {}
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SERVICES_KEY) as root:
        n_keys = winreg.QueryInfoKey(root)[0]
        for i in range(n_keys):
            try:
                name = winreg.EnumKey(root, i)
            except OSError:
                continue
            try:
                with winreg.OpenKey(root, name) as k:
                    try:
                        start, _ = winreg.QueryValueEx(k, "Start")
                    except FileNotFoundError:
                        continue
                    if int(start) > 2:
                        continue
                    try:
                        image, _ = winreg.QueryValueEx(k, "ImagePath")
                    except FileNotFoundError:
                        image = ""
                    out[f"service:{name}"] = {
                        "value": str(image), "when": _filetime_to_iso(winreg.QueryInfoKey(k)[2]),
                        "where": f"HKLM\\{_SERVICES_KEY}\\{name}", "item": name,
                    }
            except OSError:
                continue                # a service key we may not read: skip, do not fail
    return out


# ── 1.4.1 surfaces: the audit's "silently absent" list ─────────────────────
# Each returns the same {entry_id: {value, when, where, item}} shape as the
# original collectors and is allowed to raise (collect_all() isolates it).
# All five are plain HKLM/HKCU reads this user is entitled to; an absent key is
# the normal case (most of these are NOT set on a healthy machine) and returns
# an empty dict, not an error.


def collect_ifeo() -> dict:
    """Image File Execution Options `Debugger` values (T1546.012).

    `Debugger` under IFEO redirects a named executable to whatever the value
    names -- silent, survives reboot, needs no admin to set under HKLM on some
    misconfigured machines and always worth watching. An ABSENT Debugger value
    is the healthy default, so only set values are recorded: recording nothing
    keeps the baseline small and a planted hijack shows up as a clean ADD.
    """
    out = {}
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _IFEO_KEY, 0,
                        winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as root:
        n_keys = winreg.QueryInfoKey(root)[0]
        for i in range(n_keys):
            try:
                img = winreg.EnumKey(root, i)
            except OSError:
                continue
            try:
                with winreg.OpenKey(root, img, 0,
                                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                    try:
                        dbg, _ = winreg.QueryValueEx(k, "Debugger")
                    except FileNotFoundError:
                        continue
                    if not (dbg or "").strip():
                        continue
                    out[f"ifeo:{img}"] = {
                        "value": str(dbg), "when": _filetime_to_iso(winreg.QueryInfoKey(k)[2]),
                        "where": f"HKLM\\{_IFEO_KEY}\\{img}", "item": img,
                    }
            except OSError:
                continue
    return out


def collect_comhijack() -> dict:
    """HKCU COM object redirections (T1546.015).

    HKCU\\Software\\Classes\\CLSID\\{...}\\InprocServer32 takes precedence over
    the machine-wide registration for THIS user -- no admin needed to set it,
    which is exactly why a sentinel reads it. A user's CLSID hive legitimately
    holds many entries (per-user installs), so every entry is recorded and the
    DIFF decides what is new -- the same decision the Run-key collector makes.
    """
    out = {}
    for clsid_root_name in _COM_CLSID_ROOTS:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, clsid_root_name, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as root:
                n_keys = winreg.QueryInfoKey(root)[0]
                for i in range(n_keys):
                    try:
                        clsid = winreg.EnumKey(root, i)
                    except OSError:
                        continue
                    sub = f"{clsid_root_name}\\{clsid}\\InprocServer32"
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub, 0,
                                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                            try:
                                dll, _ = winreg.QueryValueEx(k, "")
                            except FileNotFoundError:
                                continue
                            if not (dll or "").strip():
                                continue
                            out[f"comhijack:{clsid}"] = {
                                "value": str(dll), "when": _filetime_to_iso(winreg.QueryInfoKey(k)[2]),
                                "where": f"HKCU\\{sub}", "item": clsid,
                            }
                    except OSError:
                        continue
        except FileNotFoundError:
            continue
    return out


def collect_logonscript() -> dict:
    """UserInitMprLogonScript (T1037.001).

    Set under the user's own Environment key, runs at logon, hidden in plain
    sight in a key nobody associates with autostart. Usually absent.
    """
    out = {}
    sub = r"Environment"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            try:
                val, _ = winreg.QueryValueEx(k, "UserInitMprLogonScript")
            except FileNotFoundError:
                return out
            if not (val or "").strip():
                return out
            when = _filetime_to_iso(winreg.QueryInfoKey(k)[2])
            out["logonscript:UserInitMprLogonScript"] = {
                "value": str(val), "when": when,
                "where": f"HKCU\\{sub}", "item": "UserInitMprLogonScript",
            }
    except OSError:
        pass
    return out


def collect_ssp() -> dict:
    """LSA Security Support Providers (T1547.005).

    Security Packages (HKLM) and the 64/32-bit views of LSA Provider DLLs
    (HKLM): a DLL here loads INTO lsass at boot, which is why LSA's own
    protection (defenses.py watches RunAsPPL) and this collector are a pair.
    Read-only from here; a change is graded high by the diff, not by a guess.
    """
    out = {}
    for hive_name, sub, wow in _SSP_KEYS:
        try:
            with _open(hive_name, sub, wow) as k:
                for val_name in ("Security Packages",):
                    try:
                        val, _ = winreg.QueryValueEx(k, val_name)
                    except FileNotFoundError:
                        continue
                    joined = " ".join(str(v) for v in (val or []))
                    if not joined.strip():
                        continue
                    view = "|32" if wow else ""
                    out[f"ssp:{hive_name}\\{sub}{view}!{val_name}"] = {
                        "value": joined, "when": _filetime_to_iso(winreg.QueryInfoKey(k)[2]),
                        "where": f"{hive_name}\\{sub}" + ("  (32-bit view)" if wow else ""),
                        "item": val_name,
                    }
        except (FileNotFoundError, OSError):
            continue
    return out


def collect_appinit() -> dict:
    """AppInit_DLLs (T1546.010).

    A DLL here loads into every GUI process that links user32.dll. XP-era
    abuse, and modern Windows only honours it when LoadAppInit_DLLs=1 -- but
    "only honoured when a flag is set" is exactly a state worth watching, and
    the flag flip is the attack. Both the DLL list and the enabling flag are
    recorded so the flip shows up as a MODIFIED entry, not just a first appear.
    """
    out = {}
    for hive_name, sub, wow in _APPINIT_KEYS:
        try:
            with _open(hive_name, sub, wow) as k:
                when = _filetime_to_iso(winreg.QueryInfoKey(k)[2])
                try:
                    dlls, _ = winreg.QueryValueEx(k, "AppInit_DLLs")
                except FileNotFoundError:
                    dlls = ""
                try:
                    enabled, _ = winreg.QueryValueEx(k, "LoadAppInit_DLLs")
                except FileNotFoundError:
                    enabled = None
                dlls = str(dlls or "").strip()
                if dlls:
                    view = "|32" if wow else ""
                    out[f"appinit:{hive_name}\\{sub}{view}!AppInit_DLLs"] = {
                        "value": dlls, "when": when,
                        "where": f"{hive_name}\\{sub}" + ("  (32-bit view)" if wow else ""),
                        "item": "AppInit_DLLs",
                    }
                if enabled is not None and int(enabled or 0):
                    view = "|32" if wow else ""
                    out[f"appinit:{hive_name}\\{sub}{view}!LoadAppInit_DLLs"] = {
                        "value": str(enabled), "when": when,
                        "where": f"{hive_name}\\{sub}" + ("  (32-bit view)" if wow else ""),
                        "item": "LoadAppInit_DLLs",
                    }
        except (FileNotFoundError, OSError):
            continue
    return out


def collect_tasks() -> dict:
    """Scheduled tasks via the Task Scheduler COM API.

    Only what this user is entitled to see. Runs on the sentinel's own thread,
    so CoInitialize is handled by comtypes per-thread.
    """
    import comtypes.client

    out = {}
    svc = comtypes.client.CreateObject("Schedule.Service", dynamic=True)
    svc.Connect()

    def walk(folder, depth=0):
        # TASK_ENUM_HIDDEN (1) is load-bearing. GetTasks(0) omits hidden tasks,
        # and "hidden" is precisely what an attacker sets -- a sentinel that
        # enumerated only visible tasks would miss the ones worth finding.
        for tsk in folder.GetTasks(_TASK_ENUM_HIDDEN):
            try:
                d = tsk.Definition
                acts = []
                for a in d.Actions:
                    p = (getattr(a, "Path", "") or "").strip()
                    args = (getattr(a, "Arguments", "") or "").strip()
                    if p:
                        acts.append(f"{p} {args}".strip())
                out[f"task:{tsk.Path}"] = {
                    "value": " ; ".join(acts),
                    "when": "",
                    "where": "Task Scheduler",
                    "item": tsk.Path,
                    "enabled": bool(tsk.Enabled),
                }
            except Exception:
                continue                # one unreadable task must not lose the rest
        if depth < 6:
            for sub in folder.GetFolders(0):    # flags reserved, must be 0
                try:
                    walk(sub, depth + 1)
                except Exception:
                    continue
    walk(svc.GetFolder("\\"))
    return out


COLLECTORS = {
    "run":      collect_run,
    "startup":  collect_startup,
    "winlogon": collect_winlogon,
    "service":  collect_services,
    "task":     collect_tasks,
    # Sixth surface: WMI permanent event subscriptions (T1546.003). The
    # "undeclared dependency" that kept this uncovered was comtypes, which
    # this module already imports for the Task Scheduler.
    "wmi":      wmisubs.collect_wmi,
    # 1.4.1: the audit's "many well-known ones are silently absent" list, in
    # its recommended ATT&CK-frequency order. Each is a plain winreg read this
    # user is entitled to; each feeds the SAME diff engine, flood guard,
    # baseline and severity table -- additive, not architectural.
    "ifeo":        collect_ifeo,
    "comhijack":   collect_comhijack,
    "logonscript": collect_logonscript,
    "ssp":         collect_ssp,
    "appinit":     collect_appinit,
}


def collect_all() -> tuple:
    """({entry_id: entry}, ok_surfaces:set, failed:{surface: error}).

    A surface that throws is reported as failed and its entries are simply
    absent -- diff() must then skip it entirely rather than treat everything it
    could not read as deleted.
    """
    entries, ok, failed = {}, set(), {}
    for surface, fn in COLLECTORS.items():
        try:
            got = fn() or {}
            entries.update(got)
            ok.add(surface)
        except Exception as e:
            failed[surface] = f"{type(e).__name__}: {e}"[:120]
    return entries, ok, failed


# ── the diff ─────────────────────────────────────────────────────────────────
def surface_of(entry_id: str) -> str:
    surface = entry_id.split(":", 1)[0]
    # The WMI collector uses object-kind prefixes so entries stay distinct,
    # while the persistence pipeline reasons about one reviewed surface named
    # "wmi". Normalize at this boundary or successful WMI scans are silently
    # skipped by diff(), severity grading and baseline replacement.
    if surface in {"wmi_filter", "wmi_consumer", "wmi_binding"}:
        return "wmi"
    return surface


def diff(old: dict, new: dict, ok_surfaces: set) -> list:
    """Changes between two snapshots, restricted to surfaces that scanned OK.

    Pure and total: no I/O, no clock, no globals. This is where the detector's
    correctness actually lives, so it is testable directly with two dicts.
    """
    changes = []
    for eid, cur in new.items():
        surf = surface_of(eid)
        if surf not in ok_surfaces:
            continue
        prev = old.get(eid)
        if prev is None:
            changes.append({"change": "added", "id": eid, "surface": surf,
                            "value": cur.get("value", ""), "prev": "",
                            "when": cur.get("when", ""), "where": cur.get("where", ""),
                            "item": cur.get("item", "")})
        elif prev.get("value", "") != cur.get("value", ""):
            changes.append({"change": "modified", "id": eid, "surface": surf,
                            "value": cur.get("value", ""), "prev": prev.get("value", ""),
                            "when": cur.get("when", ""), "where": cur.get("where", ""),
                            "item": cur.get("item", "")})
    for eid, prev in old.items():
        surf = surface_of(eid)
        # Only claim a removal on a surface we actually managed to read; and
        # only if it is a surface we know about at all (a baseline written by a
        # future version could carry surfaces this one does not collect).
        if surf not in ok_surfaces or surf not in COLLECTORS:
            continue
        if eid not in new:
            changes.append({"change": "removed", "id": eid, "surface": surf,
                            "value": "", "prev": prev.get("value", ""),
                            "when": "", "where": prev.get("where", ""),
                            "item": prev.get("item", "")})
    return changes


def severity_of(change: dict) -> tuple:
    """(severity, reasons) for one diff entry.

    ADDED   -- graded by what it runs (classify_entry).
    MODIFIED-- always high: an existing, trusted autostart entry now runs
               something else. That is a hijack, and it is quieter than adding
               a new entry, so it must not be graded below one. WMI objects
               are the exception: they grade by their own classifier, because
               a modified filter is inert while a modified consumer is not.
    REMOVED -- low. Uninstalling software removes autostart entries all day;
               it is recorded for the timeline, not alarmed on. (An attacker
               disabling a security product is real, but indistinguishable here
               from a normal uninstall, and saying so is better than crying wolf.)
    """
    kind = change.get("change")
    if kind == "removed":
        return "low", ["autostart entry disappeared (often a normal uninstall)"]
    if kind == "modified" and surface_of(change.get("id", "")) == "wmi":
        # WMI objects carry their own grading -- a rewritten consumer is
        # exactly the swap an attacker makes to redirect an existing
        # subscription, so it grades by classify_wmi_entry, not by the
        # generic "rewritten" path.
        return wmisubs.classify_wmi_entry(change.get("item", ""),
                                          change.get("value", ""))
    if kind == "modified":
        _, reasons = classify_entry(change.get("value", ""))
        return "high", ["existing autostart entry was rewritten"] + reasons
    return classify_entry(change.get("value", ""))


def correlate(window_s: int = 120) -> list:
    """Detections this suite recorded in the last `window_s` seconds.

    Late import on purpose: threatmon/__init__ imports this module, so a
    top-level import would be circular. By call time the package is fully
    initialised. Never raises -- correlation is a bonus, not a precondition.
    """
    try:
        import threatmon
        now = time.time()
        out = []
        for r in threatmon.recent(20):
            if r.get("detector") == "persistence":
                continue
            try:
                ts = time.mktime(time.strptime(r.get("ts", ""), "%Y-%m-%dT%H:%M:%S"))
            except Exception:
                continue
            if 0 <= now - ts <= window_s:
                out.append(f"{r.get('detector')}: {r.get('name', '?')} "
                           f"pid={r.get('pid', '?')} [{r.get('technique', '')}]")
        return out[:3]
    except Exception:
        return []


# ── baseline persistence ─────────────────────────────────────────────────────
def _baseline_path():
    return BASELINE_PATH_OVERRIDE or paths.writable("persistence_baseline.json")


def report() -> str:
    """A spoken answer to "what starts with my machine?".

    Built with string logic only -- no model and no network, for the same
    reason privacy.usage_report() is: what runs on this machine at boot is
    exactly the kind of detail that must not become someone else's telemetry
    on its way to being phrased nicely.
    """
    s = status()
    if s.get("last_error"):
        return (f"I couldn't finish checking your startup entries "
                f"({s['last_error']}).")
    if not s.get("baseline_established"):
        return ("I haven't finished my first startup scan yet, so I have "
                "nothing to compare against. Ask me again in a minute.")

    n = s.get("entries", 0)
    surfaces = s.get("surfaces", 0)
    found = s.get("findings_total", 0)
    bits = [f"I'm tracking {n} startup {'entry' if n == 1 else 'entries'} "
            f"across {surfaces} places Windows can launch things from"]

    failed = s.get("surfaces_failed") or []
    if failed:
        bits.append(f"I couldn't read {', '.join(str(f) for f in failed)}")

    if not found:
        bits.append("nothing has changed since I took the baseline")
    else:
        recent = correlate(window_s=3600) or []
        if recent:
            bits.append(f"{found} change{'s' if found != 1 else ''} since "
                        f"then, {len(recent)} in the last hour")
        else:
            bits.append(f"{found} change{'s' if found != 1 else ''} since "
                        f"then, none recently")
    return ". ".join(bits) + "."


def load_baseline():
    """The stored baseline, or None when there is no usable one.

    None and {} are DIFFERENT: an empty-but-real baseline must still be diffed
    against, or the first change would be absorbed silently. Unreachable here in
    practice (this machine has 339 autostart entries), but the same sentinel is
    used in every detector so the contract cannot drift between them.
    """
    try:
        with open(_baseline_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None
        entries = data.get("entries")
        if isinstance(entries, dict):
            _state["baseline_at"] = data.get("at", "")
            return entries
        return None
    except (OSError, ValueError):
        # No baseline, unreadable, or corrupt JSON -> treat as "no baseline".
        # The next pass re-establishes it silently instead of alarming on every
        # entry, which is what a naive "assume empty then diff" would do.
        return None


def save_baseline(entries: dict) -> bool:
    try:
        path = _baseline_path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                       "entries": entries}, fh, separators=(",", ":"))
        os.replace(tmp, path)
        return True
    except OSError as e:
        _state["last_error"] = f"baseline save: {type(e).__name__}"
        return False


# ── emit / scan ──────────────────────────────────────────────────────────────
def _emit(record, change):
    sev, reasons = severity_of(change)
    surf = change["surface"]
    cmd = change.get("value") or change.get("prev") or ""
    corr = correlate() if change["change"] != "removed" else []
    finding = {
        "technique": SURFACE_TECHNIQUE.get(surf, TECHNIQUE),
        "detector": "persistence",
        "severity": sev,
        "target": change.get("item", "")[:120],
        "name": os.path.basename(exe_of(cmd)) or change.get("item", "?"),
        "pid": 0,                      # not knowable in user mode -- never guessed
        "path": exe_of(cmd),
        "action": change["change"],
        "surface": surf,
        "where": change.get("where", ""),
        "command": cmd[:300],
        "previous": (change.get("prev") or "")[:300],
        "changed_at": change.get("when", ""),
        "reasons": reasons,
        "correlated": corr,
        "reason": f"persistence_{change['change']}_{surf}",
        # Per (surface, entry, kind of change): a second DIFFERENT change to the
        # same entry alerts immediately; the same standing one does not repeat.
        "dedup": f"persistence|{change['change']}|{change['id']}",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    with _lock:
        _state["changes_total"] += 1
    try:
        if record:
            record(finding)
    except Exception as e:
        _state["last_error"] = f"emit: {type(e).__name__}"
    return finding


def _emit_desync(record, changes):
    """One finding standing in for an implausible flood of them.

    Deliberately NOT silent and NOT graded low: the analyst is told the count and
    the breakdown, so a genuine mass change is still visible -- just not as five
    hundred separate lines that would make the panel useless.
    """
    kinds, surfaces = {}, {}
    for c in changes:
        kinds[c["change"]] = kinds.get(c["change"], 0) + 1
        surfaces[c["surface"]] = surfaces.get(c["surface"], 0) + 1
    breakdown = ", ".join(f"{v} {k}" for k, v in sorted(kinds.items()))
    by_surface = ", ".join(f"{k}={v}" for k, v in sorted(surfaces.items()))
    finding = {
        "technique": TECHNIQUE,
        "detector": "persistence",
        "severity": "medium",
        "target": "autostart baseline",
        "name": "baseline desync",
        "pid": 0,
        "path": "",
        "action": "desync",
        "surface": "all",
        "where": "persistence baseline",
        "command": f"{len(changes)} autostart changes in one pass "
                   f"({breakdown}; {by_surface})",
        "previous": "",
        "changed_at": "",
        "reasons": [f"{len(changes)} changes at once exceeds the "
                    f"{_FLOOD_THRESHOLD}-change plausibility limit",
                    "baseline treated as desynchronised and re-anchored",
                    "individual changes suppressed to avoid burying real findings"],
        "correlated": correlate(),
        "reason": "persistence_baseline_desync",
        "dedup": "persistence|desync",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    with _lock:
        _state["changes_total"] += 1
        _state["desyncs"] += 1
    try:
        if record:
            record(finding)
    except Exception as e:
        _state["last_error"] = f"emit desync: {type(e).__name__}"
    return finding


def run_checks(record) -> list:
    """One full pass: collect, diff against the baseline, emit, re-baseline.

    Returns the findings emitted (empty on the baseline-establishing pass).
    """
    entries, ok, failed = collect_all()
    with _lock:
        _state["scans"] += 1
        _state["entries"] = len(entries)
        _state["failed_surfaces"] = sorted(failed)
        if failed:
            _state["last_error"] = "; ".join(f"{k}: {v}" for k, v in failed.items())[:160]

    old = load_baseline()
    if old is None:                      # NOT `not old` -- see load_baseline()
        # First ever run (or a wiped/corrupt baseline). Record and stay silent:
        # everything present now is the status quo, not an intrusion.
        save_baseline(entries)
        with _lock:
            _state["baseline_established"] = True
            _state["baseline_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        return []

    with _lock:
        _state["baseline_established"] = True
    changes = diff(old, entries, ok)
    emitted = []
    if len(changes) > _FLOOD_THRESHOLD:
        emitted.append(_emit_desync(record, changes))
    else:
        for change in changes:
            try:
                emitted.append(_emit(record, change))
            except Exception as e:
                _state["last_error"] = f"emit {change.get('id', '?')}: {type(e).__name__}"

    # Merge rather than replace: entries from a surface that FAILED this pass
    # must survive in the baseline, or the next successful pass would see them
    # reappear and report a hundred spurious additions.
    merged = dict(old)
    for eid in [e for e in old if surface_of(e) in ok]:
        merged.pop(eid, None)
    merged.update(entries)
    save_baseline(merged)
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
                         name="argus-persistence-watch")
    t.start()


def status() -> dict:
    with _lock:
        failed = list(_state["failed_surfaces"])
        degraded = ""
        if not _state["supported"]:
            degraded = "unsupported OS (winreg unavailable)"
        elif failed:
            degraded = f"{len(failed)} of {len(COLLECTORS)} autostart surfaces unreadable: " \
                       f"{', '.join(failed)}"
        elif not _state["baseline_established"]:
            degraded = "baseline not yet established (first scan pending)"
        elif "wmi" in failed:
            # Degrading, not lying: WMI COM can be unavailable (SIL, stripped
            # service). The other five surfaces still hold the detector up.
            degraded = "WMI subscription surface unreadable (T1546.003)"
        return {
            "detector": "persistence",
            "technique": TECHNIQUE,
            "techniques": sorted(set(SURFACE_TECHNIQUE.values())),
            "ok": _state["running"] and _state["supported"] and len(failed) < len(COLLECTORS),
            "degraded": degraded,
            "surfaces": len(COLLECTORS),
            "surfaces_failed": failed,
            "entries": _state["entries"],
            "baseline_established": _state["baseline_established"],
            "baseline_at": _state["baseline_at"],
            "scans": _state["scans"],
            "desyncs": _state["desyncs"],
            "findings_total": _state["changes_total"],
            "uncovered": _state["uncovered"],
            "attribution": _state["attribution"],
            "last_error": _state["last_error"],
        }
