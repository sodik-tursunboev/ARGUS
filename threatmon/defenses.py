"""
ARGUS - Defensive Posture: which of this machine's own protections are on.

MITRE T1562.001 (Impair Defenses: Disable or Modify Tools), T1562.004 (Disable
or Modify System Firewall), T1548.002 (Abuse Elevation Control: Bypass UAC).

TWO QUESTIONS, AND THEY ARE NOT THE SAME QUESTION.

  "Am I protected?"            -- posture. A standing state. Asked out loud.
  "Did something turn it off?" -- an incident. A transition. Never asked,
                                  because you do not know to ask.

audit() answers the first. The watch loop answers the second, and the
difference between them is the reason this is a detector and not a status
readout: switching off Defender or dropping the firewall is one of the first
things an intruder does, and it is completely silent -- there is no window, no
toast, and by the time you next open the Security app the damage is done.

A CONTROL THAT WAS ALWAYS OFF IS NOT AN INCIDENT. That distinction is the
whole grading model. Script-block logging has never been on on this machine;
reporting it as an alert every 90 seconds would be false, exhausting, and
would bury the one that matters. So: the FIRST PASS NEVER ALERTS, exactly as
in persistence.py and listening.py, and only a control that CHANGES STATE
raises a finding. Everything that is merely weak shows up in audit() -- where
it is an answer to a question he asked -- and nowhere else.

WHY THE REGISTRY AND NOT THE OFFICIAL APIS. Every value read here was measured
readable by this non-elevated user (see the probe in the commit that added
this). The supported routes are worse in ways that matter for a shipped app:
Get-MpComputerStatus needs PowerShell, which execpolicy does not and must not
allow; WSC's COM interface (IWscProduct) is not exposed to non-elevated callers
for the settings that matter; and WMI needs a dependency that is absent from
the frozen build. A registry read is honest about what it is -- and where a
value can be absent for a legitimate reason, the check reports UNKNOWN rather
than guessing a default that flatters the machine.

WHAT THIS DOES NOT CLAIM.

  * It cannot see a third-party AV's real state. If Defender has stepped aside
    for another product, Defender's own keys read as disabled and that is NOT
    an unprotected machine. The Defender check says so in those words rather
    than reporting a false alarm, and the process probe is what distinguishes
    "switched off" from "switched off because something else took over".
  * Tamper Protection cannot be read reliably once it is ON -- that is the
    point of it. The value here is best-effort and labelled as such.
  * BitLocker, Credential Guard and Exploit Protection are NOT covered. Each
    needs elevation or an absent dependency, and a check that reports healthy
    in development while being blind in the exe is worse than an admitted gap.
    status() names them as uncovered.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import struct
import threading
import time

import paths

try:
    import winreg
except Exception:                                   # non-Windows / test hosts
    winreg = None

TECHNIQUE = "T1562.001"

CHECK_TECHNIQUE = {
    "defender_realtime": "T1562.001",
    "defender_antispyware": "T1562.001",
    "defender_tamper": "T1562.001",
    "defender_signatures": "T1562.001",
    "firewall_domain": "T1562.004",
    "firewall_private": "T1562.004",
    "firewall_public": "T1562.004",
    "uac_enabled": "T1548.002",
    "uac_prompt": "T1548.002",
    "uac_secure_desktop": "T1548.002",
    "smartscreen": "T1562.001",
    "secure_boot": "T1562.001",
    "lsa_protection": "T1562.001",
    "rdp_disabled": "T1562.004",
}

# Slower than the listener sentinel: these are configuration, and configuration
# does not change on its own. 90s is inside the window where noticing still
# helps and far outside anything that costs measurable CPU -- one pass is a
# handful of registry opens.
SCAN_INTERVAL_S = 90

BASELINE_PATH_OVERRIDE = None      # tests point this at a temp file

# Signatures older than this and Defender is running on stale definitions,
# which is a real gap rather than a pedantic one -- a week is several
# generations of commodity malware.
SIGNATURE_STALE_DAYS = 7

_HKLM = "HKLM"

# ── the check table ──────────────────────────────────────────────────────────
# (key, label, hive, subkey, value, interpreter). FIXED and documented: this is
# the scope of the audit, not a place to accrete settings. Each interpreter
# turns a raw registry value into (state, detail), where state is one of
# "on" / "off" / "weak" / "unknown".
#
# ABSENT IS NOT OFF, and getting that backwards is how a posture check lies.
# Most of these values do not exist on a default install because the default IS
# the secure setting -- DisableRealtimeMonitoring is absent when real-time
# protection is on. Each interpreter is told whether the value was found, and
# says what absence means for that specific key rather than applying one rule
# to all of them.

_ON, _OFF, _WEAK, _UNKNOWN = "on", "off", "weak", "unknown"


def _inverted(found, value, absent_state=_ON):
    """For DisableX values: 1 means the protection is OFF."""
    if not found:
        return absent_state, "not set, which is the default"
    return (_OFF, "explicitly disabled") if int(value or 0) else (_ON, "enabled")


def _plain(found, value, absent_state=_UNKNOWN):
    """For EnableX values: 1 means the protection is ON."""
    if not found:
        return absent_state, "not set"
    return (_ON, "enabled") if int(value or 0) else (_OFF, "explicitly disabled")


def _tamper(found, value):
    # 5 = on, 4 = off, 0 = off. Best effort by design: once Tamper Protection
    # is genuinely on, reading its own state is one of the things it protects.
    if not found:
        return _UNKNOWN, "cannot be read from here"
    v = int(value or 0)
    if v >= 5:
        return _ON, "on"
    if v == 4:
        return _OFF, "off"
    return _UNKNOWN, f"reports {v}, which I can't interpret confidently"


def _uac_prompt(found, value):
    """ConsentPromptBehaviorAdmin. 0 = elevate silently, which defeats UAC."""
    if not found:
        return _UNKNOWN, "not set"
    v = int(value or 0)
    if v == 0:
        return _OFF, "set to elevate without prompting"
    if v in (1, 2):
        return _ON, "prompts for credentials"
    if v == 5:
        return _ON, "prompts for non-Windows binaries"
    return _WEAK, f"set to {v}"


def _smartscreen(found, value):
    if not found:
        return _UNKNOWN, "not set"
    v = str(value or "").strip().lower()
    if v in ("requireadmin", "block"):
        return _ON, "blocking"
    if v == "warn":
        return _ON, "warning on unrecognised downloads"
    if v == "off":
        return _OFF, "off"
    return _WEAK, f"set to {value!r}"


def _lsa_ppl(found, value):
    """RunAsPPL. 1 or 2 means LSASS runs protected, which is the single
    control that most directly frustrates credential dumping -- the thing
    threatmon/lsass.py exists to detect."""
    if not found:
        return _OFF, "not enabled, so LSASS memory is readable by admin tools"
    v = int(value or 0)
    if v >= 1:
        return _ON, "LSASS runs as a protected process"
    return _OFF, "explicitly disabled"


def _rdp_denied(found, value):
    """fDenyTSConnections: 1 means Remote Desktop is REFUSED, which is the
    safe state. Reported as a protection being on rather than as RDP being
    off, so it reads the same direction as every other row."""
    if not found:
        return _UNKNOWN, "not set"
    return (_ON, "Remote Desktop is refused") if int(value or 0) \
        else (_OFF, "Remote Desktop accepts connections")


def _signature_age(found, value):
    """SignaturesLastUpdated is a FILETIME in a REG_BINARY: 8 bytes, little
    endian, 100ns ticks since 1601. Decoded rather than skipped because "your
    antivirus is on" and "your antivirus knows about this month's malware" are
    different claims and only the second one is worth much."""
    if not found or not isinstance(value, (bytes, bytearray)) or len(value) < 8:
        return _UNKNOWN, "cannot be read"
    try:
        ticks = struct.unpack("<Q", bytes(value[:8]))[0]
        epoch = ticks / 10_000_000 - 11644473600
        if epoch <= 0:
            return _UNKNOWN, "timestamp is not usable"
        days = (time.time() - epoch) / 86400.0
    except Exception:
        return _UNKNOWN, "timestamp is not usable"
    when = time.strftime("%d %b", time.localtime(epoch))
    if days > SIGNATURE_STALE_DAYS:
        return _OFF, f"definitions last updated {when}, {int(days)} days ago"
    return _ON, f"definitions updated {when}"


CHECKS = [
    ("defender_realtime", "Defender real-time protection", _HKLM,
     r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
     "DisableRealtimeMonitoring", _inverted),
    ("defender_antispyware", "Defender itself", _HKLM,
     r"SOFTWARE\Microsoft\Windows Defender", "DisableAntiSpyware", _inverted),
    ("defender_tamper", "Defender tamper protection", _HKLM,
     r"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", _tamper),
    ("defender_signatures", "Defender definitions", _HKLM,
     r"SOFTWARE\Microsoft\Windows Defender\Signature Updates",
     "SignaturesLastUpdated", _signature_age),
    ("firewall_domain", "Firewall on domain networks", _HKLM,
     r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
     r"\FirewallPolicy\DomainProfile", "EnableFirewall", _plain),
    ("firewall_private", "Firewall on private networks", _HKLM,
     r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
     r"\FirewallPolicy\StandardProfile", "EnableFirewall", _plain),
    ("firewall_public", "Firewall on public networks", _HKLM,
     r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
     r"\FirewallPolicy\PublicProfile", "EnableFirewall", _plain),
    ("uac_enabled", "User Account Control", _HKLM,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
     "EnableLUA", _plain),
    ("uac_prompt", "UAC elevation prompt", _HKLM,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
     "ConsentPromptBehaviorAdmin", _uac_prompt),
    ("uac_secure_desktop", "UAC secure desktop", _HKLM,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
     "PromptOnSecureDesktop", _plain),
    ("smartscreen", "SmartScreen", _HKLM,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
     "SmartScreenEnabled", _smartscreen),
    ("secure_boot", "Secure Boot", _HKLM,
     r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
     "UEFISecureBootEnabled", _plain),
    ("lsa_protection", "LSASS process protection", _HKLM,
     r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", _lsa_ppl),
    ("rdp_disabled", "Remote Desktop", _HKLM,
     r"SYSTEM\CurrentControlSet\Control\Terminal Server",
     "fDenyTSConnections", _rdp_denied),
]

# ── how to put it back ───────────────────────────────────────────────────────
# WHERE the setting lives, in the words of the UI he would actually click
# through. A posture report that says "tamper protection is off" and stops has
# handed him a problem; the next thing anybody says is "so how do I turn it on",
# and answering that is one table rather than a search.
#
# NO COMMANDS, AND NO OFFER TO DO IT. Every one of these is a hardening change
# to the machine's security configuration, and ARGUS deliberately has no path
# that writes any of them -- execpolicy allows neither PowerShell nor reg.exe,
# the module opens the registry read-only, and its own test asserts both. That
# is not a missing feature. A voice assistant that can switch UAC off on
# request is a voice assistant that can be talked into switching UAC off, and
# this whole package exists because that is the shape of the problem.
FIX_HINTS = {
    "defender_realtime":
        "Windows Security, then Virus & threat protection, then Manage settings",
    "defender_antispyware":
        "Windows Security, then Virus & threat protection — if it won't turn "
        "on, a policy or another AV is holding it off",
    "defender_tamper":
        "Windows Security, then Virus & threat protection, Manage settings, "
        "Tamper Protection",
    "defender_signatures":
        "Windows Security, then Virus & threat protection, Check for updates",
    "firewall_domain": "Windows Security, then Firewall & network protection",
    "firewall_private": "Windows Security, then Firewall & network protection",
    "firewall_public": "Windows Security, then Firewall & network protection",
    "uac_enabled":
        "search for 'Change User Account Control settings' — this one needs a "
        "restart",
    "uac_prompt": "the same 'Change User Account Control settings' panel",
    "uac_secure_desktop": "the same 'Change User Account Control settings' panel",
    "smartscreen":
        "Windows Security, then App & browser control, Reputation-based protection",
    "secure_boot":
        "your UEFI firmware settings — it can't be changed from inside Windows",
    "lsa_protection":
        "Windows Security, then Device security, Core isolation — or the "
        "RunAsPPL value under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa. "
        "This is the one that most directly frustrates credential dumping",
    "rdp_disabled":
        "Settings, System, Remote Desktop — turn it off if you don't use it",
}


# Controls whose loss is an emergency rather than a downgrade. A transition to
# OFF on any of these is graded critical; everything else is high (still worth
# interrupting for -- a protection turning itself off never has a benign
# explanation you would not already know about).
_CRITICAL_IF_LOST = frozenset({
    "defender_realtime", "defender_antispyware",
    "firewall_public", "firewall_private", "uac_enabled",
})

# Defender's own service processes. Used ONLY to tell "Defender was switched
# off" apart from "Defender stood down because another AV registered", which
# are the same registry state and completely different situations.
_DEFENDER_PROCESSES = ("msmpeng.exe", "mpdefendercoreservice.exe", "nissrv.exe")

_state = {
    "supported": winreg is not None,
    "running": False,
    "baseline_established": False,
    "baseline_at": "",
    "checks": 0,
    "weak": 0,
    "unknown": 0,
    "changes_total": 0,
    "scans": 0,
    "last_error": "",
    "uncovered": "BitLocker, Credential Guard and Exploit Protection (need elevation)",
    "attribution": "registry state only; which process changed a value needs kernel auditing",
}
_lock = threading.RLock()


# ── reading ──────────────────────────────────────────────────────────────────
def _read(subkey: str, value: str):
    """(found, value). A key or value that is absent returns (False, None);
    anything that FAILS raises, so audit() can tell "not configured" apart
    from "I could not look", which are different answers."""
    hive = winreg.HKEY_LOCAL_MACHINE
    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    try:
        with winreg.OpenKey(hive, subkey, 0, access) as k:
            try:
                v, _typ = winreg.QueryValueEx(k, value)
                return True, v
            except FileNotFoundError:
                return False, None
    except FileNotFoundError:
        return False, None


def _defender_running() -> bool:
    """Is Defender's engine actually running? Never raises."""
    try:
        import psutil
        names = set()
        for p in psutil.process_iter(["name"]):
            n = (p.info.get("name") or "").lower()
            if n:
                names.add(n)
        return any(d in names for d in _DEFENDER_PROCESSES)
    except Exception:
        return False


def audit() -> list:
    """Every control, as {key, label, state, detail, technique}.

    Total: a check that cannot be read is reported as unknown with the reason,
    never omitted. A posture report with rows silently missing is worse than no
    posture report, because the gap looks like a pass.
    """
    if winreg is None:
        return [{"key": k, "label": label, "state": _UNKNOWN,
                 "detail": "not a Windows machine",
                 "technique": CHECK_TECHNIQUE.get(k, TECHNIQUE)}
                for k, label, _h, _s, _v, _i in CHECKS]

    rows = []
    for key, label, _hive, subkey, value, interpret in CHECKS:
        try:
            found, raw = _read(subkey, value)
            state, detail = interpret(found, raw)
        except OSError as e:
            state, detail = _UNKNOWN, f"could not read ({type(e).__name__})"
        rows.append({"key": key, "label": label, "state": state,
                     "detail": detail,
                     "technique": CHECK_TECHNIQUE.get(key, TECHNIQUE)})

    # THE THIRD-PARTY AV CASE. Defender's keys read as disabled both when
    # somebody switched it off and when another product registered with the
    # Security Center and Defender stood down. Those are opposite situations
    # and the registry cannot tell them apart -- the running engine can.
    if not _defender_running():
        for row in rows:
            if row["key"].startswith("defender_") and row["state"] == _OFF:
                row["state"] = _UNKNOWN
                row["detail"] = ("Defender's engine isn't running — either it "
                                 "was switched off, or another security "
                                 "product has taken over from it")
    return rows


# ── grading a CHANGE ─────────────────────────────────────────────────────────
def severity_of(key: str, was: str, now: str) -> tuple:
    """(severity, reasons) for one control changing state.

    ONLY TRANSITIONS ARE GRADED. A control that has been off since the machine
    was built is posture, and posture belongs in audit() where he asked for it
    -- not in an alert every ninety seconds.
    """
    label = next((l for k, l, *_ in CHECKS if k == key), key)
    if now in (_OFF, _WEAK) and was == _ON:
        sev = "critical" if key in _CRITICAL_IF_LOST else "high"
        return sev, [f"{label} was on and is now {now}",
                     "a protection turning off is one of the first things an "
                     "intruder does, and Windows does not announce it"]
    if now == _ON and was in (_OFF, _WEAK):
        return "low", [f"{label} was turned back on"]
    if now == _UNKNOWN:
        return "medium", [f"{label} can no longer be read, and it could be "
                          f"before"]
    return "low", [f"{label} changed from {was} to {now}"]


def diff(old: dict, new: dict) -> list:
    """Controls whose state changed. Pure and total.

    A control that is NEW to the table (a check added by an upgrade) is not a
    change -- there is nothing to compare it against, and reporting it would
    make every ARGUS update look like a security event.
    """
    changes = []
    for key, now in new.items():
        was = old.get(key)
        if was is None or was == now:
            continue
        changes.append({"key": key, "was": was, "now": now})
    return changes


# ── baseline ─────────────────────────────────────────────────────────────────
def _baseline_path():
    return BASELINE_PATH_OVERRIDE or paths.writable("defenses_baseline.json")


def load_baseline():
    try:
        with open(_baseline_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None
        states = data.get("states")
        if isinstance(states, dict):
            _state["baseline_at"] = data.get("at", "")
            return states
        return None
    except (OSError, ValueError):
        return None


def save_baseline(states: dict) -> bool:
    try:
        path = _baseline_path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                       "states": states}, fh, separators=(",", ":"))
        os.replace(tmp, path)
        return True
    except OSError as e:
        _state["last_error"] = f"baseline save: {type(e).__name__}"
        return False


# ── emit / scan ──────────────────────────────────────────────────────────────
def _emit(record, change, rows_by_key):
    sev, reasons = severity_of(change["key"], change["was"], change["now"])
    key = change["key"]
    row = rows_by_key.get(key, {})
    finding = {
        "technique": CHECK_TECHNIQUE.get(key, TECHNIQUE),
        "detector": "defenses",
        "severity": sev,
        "target": key,
        "name": row.get("label", key),
        "pid": 0,               # not knowable in user mode -- never guessed
        "path": "",
        "action": f"{change['was']}->{change['now']}",
        "surface": "security settings",
        "where": "Windows security configuration",
        "reasons": reasons + ([row["detail"]] if row.get("detail") else []),
        "reason": f"defenses_{key}_{change['now']}",
        # Per control AND per destination state, so a control that is switched
        # off, back on, and off again alerts each time it goes off rather than
        # being swallowed as one standing condition.
        "dedup": f"defenses|{key}|{change['now']}",
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


def run_checks(record) -> list:
    try:
        rows = audit()
    except Exception as e:
        _state["last_error"] = f"audit: {type(e).__name__}: {e}"[:120]
        return []

    states = {r["key"]: r["state"] for r in rows}
    with _lock:
        _state["scans"] += 1
        _state["checks"] = len(rows)
        _state["weak"] = sum(1 for r in rows if r["state"] in (_OFF, _WEAK))
        _state["unknown"] = sum(1 for r in rows if r["state"] == _UNKNOWN)

    old = load_baseline()
    if old is None:
        save_baseline(states)
        with _lock:
            _state["baseline_established"] = True
            _state["baseline_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        return []

    with _lock:
        _state["baseline_established"] = True
    by_key = {r["key"]: r for r in rows}
    emitted = []
    for change in diff(old, states):
        try:
            emitted.append(_emit(record, change, by_key))
        except Exception as e:
            _state["last_error"] = f"emit {change.get('key', '?')}: {type(e).__name__}"
    save_baseline(states)
    return emitted


# ── the spoken answer ────────────────────────────────────────────────────────
def report() -> str:
    """A spoken answer to "am I protected?".

    String logic only -- no model, no network. Which of this machine's defences
    are on is exactly the telemetry that must not travel to a third party to be
    phrased nicely, and it is the rule every other readout in this package
    follows.

    LEADS WITH WHAT IS WRONG. A posture report that opens with eleven passing
    checks has made him wait for the answer; the two that failed are the answer.
    If nothing is wrong it says so in one sentence and stops.
    """
    try:
        rows = audit()
    except Exception as e:
        return f"I couldn't read your security settings just now ({type(e).__name__})."
    if not rows:
        return "I couldn't read any of your security settings."

    off = [r for r in rows if r["state"] == _OFF]
    weak = [r for r in rows if r["state"] == _WEAK]
    unknown = [r for r in rows if r["state"] == _UNKNOWN]
    on = [r for r in rows if r["state"] == _ON]

    bits = []
    if not off and not weak:
        bits.append(f"You're covered, Boss — all {len(on)} of the protections "
                    f"I can check are on")
    else:
        problems = off + weak
        named = "; ".join(f"{r['label']} is {r['detail']}" for r in problems[:3])
        more = len(problems) - min(3, len(problems))
        bits.append(f"{len(problems)} thing{'s' if len(problems) != 1 else ''} "
                    f"{'are' if len(problems) != 1 else 'is'} not where it "
                    f"should be")
        bits.append(named + (f"; and {more} more" if more > 0 else ""))
        # WHERE TO FIX IT, but only for the first one and only when there are
        # few enough that the advice is still advice. Three fix hints in a
        # spoken reply is a manual, and a manual read aloud is something you
        # stop listening to halfway through -- at which point the finding that
        # prompted it is lost too.
        hint = FIX_HINTS.get(problems[0]["key"], "")
        if hint and len(problems) <= 2:
            bits.append(f"you fix {problems[0]['label'].lower()} in {hint}")
        bits.append(f"the other {len(on)} checks are fine")

    if unknown:
        bits.append(f"{len(unknown)} I can't read from here without more "
                    f"privilege — {', '.join(r['label'] for r in unknown[:3])}")

    out = []
    for b in bits:
        b = b.strip()
        if b:
            out.append(b[0].upper() + b[1:])
    return ". ".join(out) + "."


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
                         name="argus-defenses-watch")
    t.start()


def status() -> dict:
    with _lock:
        degraded = ""
        if not _state["supported"]:
            degraded = "unsupported OS (winreg unavailable)"
        elif not _state["baseline_established"]:
            degraded = "baseline not yet established (first scan pending)"
        elif _state["unknown"]:
            degraded = (f"{_state['unknown']} of {_state['checks']} security "
                        f"settings cannot be read without elevation")
        return {
            "detector": "defenses",
            "technique": TECHNIQUE,
            "techniques": sorted(set(CHECK_TECHNIQUE.values())),
            "ok": _state["running"] and _state["supported"],
            "degraded": degraded,
            "checks": _state["checks"] or len(CHECKS),
            "weak": _state["weak"],
            "unreadable": _state["unknown"],
            "baseline_established": _state["baseline_established"],
            "baseline_at": _state["baseline_at"],
            "scans": _state["scans"],
            "findings_total": _state["changes_total"],
            "uncovered": _state["uncovered"],
            "attribution": _state["attribution"],
            "last_error": _state["last_error"],
        }
