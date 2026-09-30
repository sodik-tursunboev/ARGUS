"""
ARGUS - LOLBin abuse detection (MITRE T1059 / T1105 / T1140 / T1218 /
T1490 / T1053.005).

Living-off-the-land: attackers prefer signed, trusted Windows binaries because
they blend in. This watches a FIXED, DOCUMENTED set of signed binaries --
powershell, certutil, mshta, rundll32, plus (1.2.1) the recovery-deletion,
proxy-execution and transfer binaries in threatmon/cmdshapes.py -- for the
specific abusive argument shapes, and STOPS THERE. It is deliberately not an
open-ended, ever-growing signature engine; adding a binary or a pattern is a
considered change to this table, not a reflex.

  powershell.exe / pwsh.exe
    - an encoded command (-enc / -EncodedCommand / -e <base64>)   T1059.001
    - download-and-run or in-memory decode (DownloadString /
      DownloadFile / IEX / FromBase64String)                      T1059.001
    - stealth flag combo (hidden window + noprofile + bypass)     T1059.001
  certutil.exe
    - -urlcache / -verifyctl / -split with a URL (tool transfer)  T1105
    - -decode / -encode (turn a blob into a payload)              T1140
  mshta.exe
    - a remote URL, or inline javascript:/vbscript:               T1218
  rundll32.exe
    - javascript: proxy, ...,OpenURL                              T1218
    - a DLL loaded from Temp / AppData / Downloads                T1218
  vssadmin / wbadmin / wmic / diskshadow / bcdedit                (1.2.1)
    - shadow-copy or catalog deletion, recovery disabled          T1490
  regsvr32 / msbuild / installutil / odbcconf                     (1.2.1)
    - scriptlet / inline-task / untrusted-DLL proxy execution     T1218.010
  curl.exe / bitsadmin.exe                                        (1.2.1)
    - a URL fetch to disk                                         T1105
  schtasks.exe                                                    (1.2.1)
    - /create from an untrusted directory                         T1053.005

The 1.2.1 additions close the documented gap that the highest-signal,
lowest-false-positive command shapes on a personal machine were absent:
'vssadmin delete shadows /all /quiet' has essentially no legitimate use on a
laptop, and it was not watched. Each new entry lives in cmdshapes.py's table
with its own ATT&CK id, and classify() consults that table as a fallback --
same fixed, documented, reviewed-per-entry discipline, more entries.

SCOPE AND HONESTY. This is a POLL detector: it inspects the command lines of
RUNNING processes on the sampler's tick. It reliably catches a LOLBin that stays
resident (a beacon, a sleeping stager); a one-shot that starts and exits between
two polls can be missed -- catching every invocation needs process-creation
events (ETW / 4688 with command-line auditing), which is a separate, heavier
capability. status() says so rather than implying total coverage.

CRASH DISCIPLINE. Command lines are attacker-controlled and psutil can deny or
race them; every read and parse is guarded, malformed input classifies to
"nothing" rather than raising, and a failure fails closed for that process only.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import re
import time

try:
    import psutil
except Exception:
    psutil = None

from threatmon import cmdshapes

WATCHED = {
    "powershell.exe", "pwsh.exe", "certutil.exe", "mshta.exe", "rundll32.exe",
    # 1.2.1: recovery-deletion, proxy-execution and transfer binaries. Each
    # is classified by threatmon/cmdshapes.py (see classify() below).
    "vssadmin.exe", "wbadmin.exe", "wmic.exe", "diskshadow.exe", "bcdedit.exe",
    "regsvr32.exe", "msbuild.exe", "installutil.exe", "odbcconf.exe",
    "curl.exe", "bitsadmin.exe", "schtasks.exe",
}

_state = {
    "supported": True,
    "scans": 0,
    "findings_total": 0,
    "last_error": "",
    "coverage": "resident processes (one-shot invocations faster than the poll may be missed)",
}

# Pre-compiled, and kept small on purpose.
_ENC = re.compile(r"(?:^|\s)-e(?:c|n|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}", re.I)
_PS_DOWNLOAD = ("downloadstring", "downloadfile", "frombase64string",
                "invoke-expression", "iex(", "iex ", "net.webclient")
_URL = re.compile(r"https?://", re.I)
_SUSPECT_DIR = ("\\temp\\", "\\appdata\\", "\\downloads\\", "/temp/", "/appdata/")


def classify(name: str, cmdline: str):
    """(technique, reason) for a suspicious LOLBin invocation, else None. Pure;
    tolerant of None/garbage input."""
    n = (name or "").lower()
    c = cmdline or ""
    cl = c.lower()
    if not n:
        return None

    if n in ("powershell.exe", "pwsh.exe"):
        if "-encodedcommand" in cl or _ENC.search(c):
            return ("T1059.001", "encoded_command")
        if any(k in cl for k in _PS_DOWNLOAD):
            return ("T1059.001", "download_or_decode")
        if ("hidden" in cl) and ("bypass" in cl or "-nop" in cl or "-noprofile" in cl):
            return ("T1059.001", "stealth_flags")
        return None

    if n == "certutil.exe":
        if any(k in cl for k in ("-urlcache", "urlcache", "-verifyctl", "-split")) \
                and _URL.search(cl):
            return ("T1105", "certutil_url_transfer")
        if "-decode" in cl or "-encode" in cl:
            return ("T1140", "certutil_encode_decode")
        if _URL.search(cl):
            return ("T1105", "certutil_url")
        return None

    if n == "mshta.exe":
        if _URL.search(cl) or "javascript:" in cl or "vbscript:" in cl:
            return ("T1218", "mshta_remote_or_script")
        return None

    if n == "rundll32.exe":
        if "javascript:" in cl or "openurl" in cl:
            return ("T1218", "rundll32_proxy")
        if ".dll" in cl and any(seg in cl for seg in _SUSPECT_DIR):
            return ("T1218", "rundll32_untrusted_dll")
        return None

    # 1.2.1: recovery-deletion, proxy-execution, transfer and task-creation
    # shapes -- the family that crosses binary boundaries, so it lives in its
    # own table keyed on the command line. Pure, tolerant of garbage, and it
    # only ever fires on the watched binaries.
    return cmdshapes.classify(n, c)


def _redacted_snippet(cmdline: str) -> str:
    """A short, secret-scrubbed slice of the command line for LOCAL display.
    The full line never reaches the chained audit log (basename + technique
    only); this is for the operator's own review in the SECURITY panel."""
    try:
        import security
        return security.redact(cmdline or "")[:200]
    except Exception:
        return (cmdline or "")[:200]


def scan(processes=None) -> list:
    """Inspect running instances of the watched binaries. Returns findings.
    Fails closed to [] on a hard failure; per-process errors are skipped."""
    if psutil is None:
        _state["last_error"] = "psutil unavailable"
        return []
    findings = []
    try:
        for p in psutil.process_iter(["pid", "name"]):
            try:
                nm = (p.info.get("name") or "")
                if nm.lower() not in WATCHED:
                    continue
                try:
                    cl = p.cmdline()
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    continue
                cmdline = " ".join(cl) if cl else ""
                verdict = classify(nm, cmdline)
                if not verdict:
                    continue
                technique, reason = verdict
                try:
                    exe = p.exe()
                except Exception:
                    exe = ""
                findings.append({
                    "technique": technique,
                    "detector": "lolbin",
                    "severity": "high",
                    "target": nm,
                    "name": nm,
                    "pid": p.info.get("pid", 0),
                    "path": exe,
                    "reason": reason,
                    "detail": f"{nm}: {_redacted_snippet(cmdline)}",
                    # One standing invocation = one alert; a new pid or a new
                    # reason re-alerts.
                    "dedup": f"lolbin|{p.info.get('pid', 0)}|{reason}",
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                _state["last_error"] = f"proc: {type(e).__name__}"
                continue
        _state["scans"] += 1
        _state["findings_total"] += len(findings)
        return findings
    except Exception as e:
        _state["last_error"] = f"scan: {type(e).__name__}: {e}"[:120]
        return []


def status() -> dict:
    return {
        "detector": "lolbin",
        "technique": "T1059",
        "ok": _state["supported"],
        "degraded": "",
        "scans": _state["scans"],
        "findings_total": _state["findings_total"],
        "coverage": _state["coverage"],
        "watched": sorted(WATCHED),
        "last_error": _state["last_error"],
    }
