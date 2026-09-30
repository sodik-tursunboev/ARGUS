"""
ARGUS - The unprivileged half of the LSASS split (the link).

Sits in the orchestrator, which runs sandbox.drop_privileges() at startup and
therefore can never hold SeDebugPrivilege. It asks the SEPARATE elevated helper
(threatmon/lsass_agent.py, installed by tools/install_lsass_helper.py) to scan
the kernel handle table, re-validates every finding locally, and -- when the
helper is not installed or not running -- falls back to the in-process scan on
which the original detection was built, reporting that fallback as DEGRADED
rather than as coverage. The orchestrator never gains the capability; the
helper never gains a language model.

The security decision is LOCAL by design: whatever the helper replies is
treated as evidence, not as truth. _validate_finding() re-runs the pure gates
(dangerous rights, not allowlisted, correct technique/target, sane pids) so a
compromised or buggy helper cannot feed the audit chain garbage -- and the
peer check in lsass_peer.connect_pipe()/peer_ok() ensures the helper is an
ARGUS process to begin with.

status() keeps the report key "lsass" (the MITRE grid and the security summary
both index on it) and adds 'mode' and 'coverage' so the summary can tell full
coverage from an honest fallback.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os

from threatmon import lsass, lsass_peer

TECHNIQUE = lsass.TECHNIQUE                       # "T1003.001"

_state = {
    "mode": "none",                # helper | inprocess | none
    "privilege": None,
    "last_scan_ok": None,
    "last_error": "",
    "scans": 0,
    "findings_total": 0,
    "lsass_pids": [],
}


def _helper_command(req: dict):
    """One request to the helper; None on any unreachability/trust failure.

    The caller distinguishes 'helper answered' from 'helper absent' -- both
    are safe, but they get different reports.
    """
    if os.name != "nt":
        _state["last_error"] = "not Windows"
        return None
    sid = lsass_peer.current_sid()
    if not sid:
        _state["last_error"] = "cannot determine owner SID"
        return None
    h = lsass_peer.connect_pipe(lsass_peer.pipe_name(sid))
    if not h:
        _state["last_error"] = ("elevated helper not running — install/start "
                                "with `python tools/install_lsass_helper.py`")
        return None
    try:
        spid = lsass_peer.named_pipe_server_pid(h)
        image, cmdline = lsass_peer.peer_identity(spid)
        ok, why = lsass_peer.peer_ok("server", image, cmdline)
        if not ok:
            _state["last_error"] = f"helper identity rejected: {why}"
            return None
        return lsass_peer.client_rpc(h, req)
    except Exception as e:
        _state["last_error"] = f"helper call: {type(e).__name__}: {e}"[:120]
        return None
    finally:
        try:
            ctypes_h_close(h)
        except Exception:
            pass


def ctypes_h_close(h):
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CloseHandle.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle(h)


def _validate_finding(f):
    """Re-check a helper-reported finding before it may enter the audit chain.

    Returns the finding (with helper provenance stamped on) or None. The
    helper is trusted within its one job, but 'trusted to scan' is not
    'believed about anything it says' -- the same pure gates that the
    in-process detector applies are applied here, one more time, to the wire
    data.
    """
    if not isinstance(f, dict):
        return None
    try:
        if f.get("technique") != TECHNIQUE:
            return None
        if f.get("detector") != "lsass":
            return None
        if str(f.get("target") or "").lower() not in ("lsass.exe", "lsass"):
            return None                       # this link only reports on lsass
        if not lsass.is_dangerous(f.get("access", 0)):
            return None
        if lsass.is_allowlisted(f.get("name", ""), f.get("path", "")):
            return None
        pid = int(f.get("pid", 0) or 0)
        tpid = int(f.get("target_pid", 0) or 0)
        if pid <= 0 or tpid <= 0:
            return None
        if not isinstance(f.get("rights", []), list) or not f["rights"]:
            return None
        out = dict(f)
        out["pid"] = pid
        out["target_pid"] = tpid
        out["via"] = "helper"
        out["elevated"] = True
        return out
    except (TypeError, ValueError):
        return None


def scan(processes=None) -> list:
    """Production entry point, same shape as lsass.scan: findings this tick.

    `processes` accepted-and-ignored so the coordinator calls every detector
    with the same signature. Never raises; the audit chain gets only validated
    records.
    """
    resp = _helper_command({"cmd": lsass_peer.CMD_SCAN})
    if resp is None or not resp.get("ok"):
        return _fallback_inprocess()

    _state["mode"] = "helper"
    _state["privilege"] = bool(resp.get("privilege"))
    _state["last_scan_ok"] = bool(resp.get("scan_ok", True))
    _state["scans"] += 1
    _state["lsass_pids"] = list(resp.get("lsass_pids") or [])
    if not resp.get("scan_ok"):
        _state["last_error"] = (resp.get("last_error") or "helper scan failed")

    findings = []
    for f in resp.get("findings") or []:
        v = _validate_finding(f)
        if v:
            findings.append(v)
    _state["findings_total"] += len(findings)
    return findings


def _fallback_inprocess() -> list:
    """The honest degraded path: today's scan, without the privilege.

    Called when the helper is absent, unreachable, or refused us. _state has
    already recorded why; lsass.scan() runs the same pure core but cannot see
    elevated dumpers, and status() says so.
    """
    _state["mode"] = "inprocess"
    try:
        found = lsass.scan() or []
    except Exception as e:
        _state["last_error"] = f"in-process scan: {type(e).__name__}"
        return []
    _state["lsass_pids"] = list(lsass.status().get("lsass_pids") or [])
    return found


def status() -> dict:
    """Health for the SECURITY panel and the honest security summary.

    Keeps the detector key "lsass" so the MITRE grid cell, the THREAT_DETECTED
    component, and security_summary()'s 'lsass' lookups all keep working, and
    adds mode/coverage so the summary can distinguish full coverage from an
    honest fallback instead of pretending.
    """
    supported = os.name == "nt"
    mode = _state["mode"]
    degraded = ""
    if not supported:
        degraded = "unsupported OS"
    elif mode == "helper":
        if _state["last_scan_ok"] is False:
            degraded = _state.get("last_error") or "helper scan failed"
    else:
        inner = lsass.status().get("degraded") or ""
        reason = _state.get("last_error") or "elevated helper not running"
        degraded = f"in-process (no elevated helper): {reason}"
        if inner:
            degraded += f"; {inner}"
    return {
        "detector": "lsass",
        "technique": TECHNIQUE,
        "ok": bool(supported) and not degraded,
        "degraded": degraded,
        "privilege": (True if mode == "helper" else lsass.status().get("privilege")),
        "scans": _state["scans"],
        "findings_total": _state["findings_total"],
        "lsass_pids": list(_state["lsass_pids"]),
        "last_error": _state["last_error"],
        "mode": mode,
        "coverage": ("full (elevated helper)" if mode == "helper"
                     else "limited (in-process, not elevated)"),
    }


def capability() -> tuple[bool, str]:
    """For the boot report: is full elevated coverage available RIGHT NOW?

    A live ping is the only question the boot report needs answered. Returns
    (ok, why) so the Step can be OK or UNAVAILABLE with the install path.
    """
    resp = _helper_command({"cmd": lsass_peer.CMD_PING})
    if resp is not None and resp.get("ok"):
        return True, ("elevated helper active — full LSASS coverage "
                      f"(privilege={bool(resp.get('privilege'))})")
    return False, (_state.get("last_error")
                   or "elevated helper unavailable")