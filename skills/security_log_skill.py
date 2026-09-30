"""
ARGUS - Security / event log reader.

Reads the Windows event logs (Security, Application, System) and reports the
recent entries -- the "what happened on this machine" surface the Security
section asks for. READ-ONLY: this skill never clears, filters, subscribes to,
or exports a log; it pulls the last N records and describes them.

  READ -- "what's in the security log", "check the event log". target is
  "<log> [<count>]" -- log is security|application|system (the three logs a
  spoken request is most likely to mean), count caps the records pulled.
  BOUNDED BY DESIGN: MAX_EVENTS = 20 records at most, ever. A log can hold
  tens of thousands of 30-line records; a spoken summary of more than a
  handful is noise, and pulling the whole log is a report-to-an-attacker
  channel -- one command saying "read the security log" must not dump
  everything. The bound is in code, not the caller.

  STATUS -- which of the three logs exist and roughly how many records each
  holds. Metadata only, never entry content.

WHY pywin32 WINDOWS.EVTLOG AND NOT powershell/Get-WinEvent. execpolicy's
allowlist deliberately contains no PowerShell ("no generic run this shell
command skill"), and event-log reads need a subprocess like Get-WinEvent or
wevtutil only because they were written for one. win32evtlog is already
shipped (pywin32 -- a current dependency for WMI/printing, see
system_ext_skill.py) and reads the logs in-process: no new allowlist entry,
no shell, no text to parse from a shim. Same reasoning as the env skill using
winreg and the service skill using psutil.

SENSITIVITY. The SECURITY log records logon/logoff and authentication
failures -- genuinely private, and a favourite reconnaissance target. READ is
L2_REAUTH (fresh authentication, like files/find and vault): a stale unlock
from earlier in the session does not get you the logon history. STATUS is L1
(record counts reveal nothing). The privacy_skill's own on/off surface and
ARGUS's camera/mic usage report already model "this machine's security
state" at L1; the raw event log is one tier above that, so it gets one tier
above it.

HONEST LIMITS. The Security log requires elevation to READ (it is the one
log Windows gates); when the process is not elevated the read returns a
refusal and the skill says so plainly rather than guessing. Event rendering
needs the source's message DLLs; if the message text cannot be resolved the
skill reports the source + event id instead of a blank line or an exception.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import time

MAX_EVENTS = 20
_LOGS = ("security", "application", "system")

_FRIENDLY = {
    "security": "security log",
    "application": "application log",
    "system": "system log",
}

# EventType ints (win32evtlog.EVENTLOG_* constants) -> what a spoken report
# calls them. Kept as data so the reply never invents a level.
EVENT_TYPES = {
    0: "info", 4: "info", 8: "success audit", 16: "failure audit",
    1: "error", 2: "warning",
}


def _evtlog():
    import win32evtlog
    return win32evtlog


def _parse_target(target: str) -> tuple:
    """'<log> [<count>]' -- log defaults to system, count to MAX_EVENTS."""
    target = (target or "").strip()
    log, count = "system", MAX_EVENTS
    first, _, rest = target.partition(" ")
    first = first.lower()
    if first in _LOGS:
        log = first
        rest = rest.strip()
    elif first.isdigit():
        rest = target
    else:
        rest = target
    if rest.isdigit():
        count = min(max(int(rest), 1), MAX_EVENTS)
    return log, count


def _events(log: str, count: int):
    """Yield the last `count` records of log as dicts, oldest-first."""
    import win32evtlog
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | \
        win32evtlog.EVENTLOG_SEQUENTIAL_READ
    try:
        handle = win32evtlog.OpenEventLog(None, log)
    except win32evtlog.error as e:
        raise PermissionError(str(e)) from e
    try:
        records = win32evtlog.ReadEventLog(handle, flags, 0, count)
        for rec in reversed(records):
            yield {
                "time": rec.TimeGenerated.Format(),
                "source": getattr(rec, "SourceName", "") or "",
                "eid": getattr(rec, "EventID", 0) & 0x7FFF,
                "type": EVENT_TYPES.get(getattr(rec, "EventType", 0), "event"),
                "strings": list(getattr(rec, "StringInserts", []) or []),
                "category": getattr(rec, "EventCategory", 0) or "",
            }
    finally:
        win32evtlog.CloseEventLog(handle)


def read(target: str = "") -> str:
    """Recent entries from security/application/system, as a spoken string."""
    log, count = _parse_target(target)
    try:
        events = list(_events(log, count))
    except PermissionError:
        return (f"I can't read the {_FRIENDLY[log]} -- Windows gates it behind "
                "administrator rights, and I'm not elevated.")
    except Exception as e:
        return f"I couldn't read the {_FRIENDLY[log]}: {type(e).__name__}: {e}"
    if not events:
        return f"The {_FRIENDLY[log]} has no recent entries."
    lines = []
    for ev in events:
        text = _describe_event(ev)
        lines.append(f"{ev['time']} -- {ev['type']} -- {text}")
    head = (f"The last {len(events)} entries in the {_FRIENDLY[log]}:")
    return head + " " + ". ".join(lines[:MAX_EVENTS]) + "."


def _describe_event(ev: dict) -> str:
    """One record to a sentence. Prefers the log's own message text; falls
    back to source + event id when the message can't be resolved (missing
    DLL, a source with no localisable message -- see module docstring)."""
    first = ""
    for s in ev["strings"]:
        if s and s.strip():
            first = s.strip().replace("\n", " ").replace("  ", " ")
            break
    if first:
        return first[:160]
    ident = f"{ev['source']} event {ev['eid']}" if ev["source"] else \
        f"event {ev['eid']}"
    if ev["category"]:
        return f"{ident}, category {ev['category']}"
    return ident


def status(target: str = "") -> str:
    """Which logs exist and their record counts. Never entry content."""
    import win32evtlog
    bits = []
    for log in _LOGS:
        try:
            handle = win32evtlog.OpenEventLog(None, log)
        except Exception:
            continue
        try:
            n = win32evtlog.GetNumberOfEventLogRecords(handle)
            bits.append(f"{_FRIENDLY[log]} has {n} records")
        except Exception:
            bits.append(f"{_FRIENDLY[log]} is available")
        finally:
            win32evtlog.CloseEventLog(handle)
    if not bits:
        return "I couldn't open any event logs."
    return ". ".join(bits) + "."
