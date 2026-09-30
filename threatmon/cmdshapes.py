"""
ARGUS - Command-shape detection for recovery-deletion and proxy execution.

The LOLBin watch list in threatmon/lolbin.py flags ABUSIVE INVOCATIONS of
signed Windows binaries. This module classifies a FAMILY of command shapes
that needed their own table because they cross binary boundaries:

  * Inhibit System Recovery (T1490)   -- vssadmin / wbadmin / wmic shadowcopy,
                                         bcdedit recoveryenabled
  * Proxy Execution (T1218.*)         -- regsvr32 scriptlet, msbuild inline
                                         task, installutil / odbcconf .dll
  * Tool Transfer (T1105)             -- curl / bitsadmin fetching to disk
  * Scheduled-task persistence (T1053.005) -- schtasks /create from a
                                         suspicious directory

WHY NOT JUST MORE ROWS IN lolbin.py'S classify(). classify() is keyed on the
process NAME and stays that way; these shapes are keyed on the COMMAND LINE
and apply across several binaries (vssadmin/wbadmin/diskshadow all reach the
same VSS writer; msbuild/installutil/odbcconf all load untrusted .NET code
the same way). One table here, consulted BY lolbin.classify() as a fallback,
keeps both lists in their own shape and keeps the tests able to pin each
entry on its own.

THE SAME DELIBERATE-NOT-A-SIGNATURE-ENGINE RULE AS LOLBIN. Every row below is
a command shape with essentially no legitimate use on a personal machine
('vssadmin delete shadows /all /quiet' has no benign caller), or the documented
proxy-execution shape for a binary that exists to be abused that way. Adding
a row is a considered change with a technique id attached, per entry.

CRASH DISCIPLINE. Attacker-controlled input, same as everywhere else: classify
is pure, tolerant of None/garbage, and returns None rather than raising.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re

# Shadow-copy deletion: vssadmin/wbadmin/wmic, matched on the command line so
# the shape is caught whichever binary reaches it. 'delete shadows' is the
# canonical ransomware precursor -- there is no consumer workflow that deletes
# every restore point on a laptop.
_SHADOW_DELETE = re.compile(
    r"\bdelete\s+shadows?\b|\bshadowcopy\s+delete\b", re.I)
# wbadmin's catalog equivalent.
_CATALOG_DELETE = re.compile(
    r"\bdelete\s+catalog\b", re.I)
# bcdedit turning recovery off: {default} is optional in real attacks.
_BCD_RECOVERY_OFF = re.compile(
    r"\bbcdedit\b.*\brecoveryenabled\s+(no|off)\b", re.I)
# regsvr32 with a scriptlet from an untrusted location, or a remote URL --
# regsvr32.exe scrobj.dll is T1218.010's documented shape.
_SCRLET = re.compile(r"\bscrobj\.dll\b", re.I)
# msbuild /installutil / odbcconf loading an untrusted project/dll. These are
# on-disk files; the location decides. The .csproj/.vbproj inline-task trick
# runs arbitrary C# from the project file itself.
_UNTRUSTED_DIR = ("\\temp\\", "\\appdata\\", "\\downloads\\",
                  "\\users\\public\\", "\\programdata\\", "\\$recycle.bin\\")
_TASK_FILE = re.compile(r"\.(csproj|vbproj|dll)\b", re.I)
# curl/bitsadmin transfer-to-disk: a URL plus a destination on this machine.
_URL = re.compile(r"https?://", re.I)
# schtasks creating a task that runs from an untrusted directory.
_CREATE = re.compile(r"\b(create|/create)\b", re.I)


def _has_untrusted_dir(cl: str) -> bool:
    low = cl.lower()
    return any(d in low for d in _UNTRUSTED_DIR)


def classify(name: str, cmdline: str):
    """(technique, reason) for a watched command shape, else None. Pure;
    tolerant of None/garbage input; never raises."""
    c = cmdline or ""
    cl = c.lower()
    if not c:
        return None
    n = (name or "").lower()

    # ── T1490: inhibit recovery ────────────────────────────────────────────
    # Keyed on the shape, not the binary: vssadmin, wbadmin, wmic and diskshadow
    # all reach shadow-copy deletion, and the technique is the same act.
    if n in ("vssadmin.exe", "wbadmin.exe", "wmic.exe", "diskshadow.exe"):
        if _SHADOW_DELETE.search(cl) or _CATALOG_DELETE.search(cl):
            return ("T1490", "shadow_or_catalog_delete")
    if n == "bcdedit.exe" and _BCD_RECOVERY_OFF.search(cl):
        return ("T1490", "recovery_disabled")

    # ── T1218.010 / T1218.004 / T1218.003: proxy execution ─────────────────
    if n == "regsvr32.exe" and _SCRLET.search(cl):
        return ("T1218.010", "regsvr32_scriptlet")
    if n == "msbuild.exe" and _TASK_FILE.search(cl) and _has_untrusted_dir(cl):
        return ("T1218", "msbuild_untrusted_project")
    if n in ("installutil.exe", "odbcconf.exe") and \
            _TASK_FILE.search(cl) and _has_untrusted_dir(cl):
        return ("T1218", "dotnet_proxy_untrusted_dll")

    # ── T1105: transfer to disk ─────────────────────────────────────────────
    if n == "curl.exe" and _URL.search(cl):
        return ("T1105", "curl_transfer")
    if n == "bitsadmin.exe" and _URL.search(cl):
        return ("T1105", "bitsadmin_transfer")

    # ── T1053.005: schtasks creating persistence from an untrusted dir ─────
    if n == "schtasks.exe" and _CREATE.search(cl) and _has_untrusted_dir(cl):
        return ("T1053.005", "schtasks_create_untrusted")

    return None
