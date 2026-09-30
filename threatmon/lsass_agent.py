"""
ARGUS - The privileged half of the LSASS split (the helper).

The reverse of lsass_link.py. That file knows nothing and sees everything; this
one holds the ONE privilege the orchestrator deliberately gives up, and does
nothing else with it.

WHAT THIS PROCESS IS
  * a named-pipe server on \\\\.\\pipe\\ARGUS-lsass-helper-<sid-hash> whose DACL
    grants only the owner SID (sddl_for_user), so neither SYSTEM (a higher
    account -- the exact thing lsass monitoring exists to notice) nor other
    users can connect;
  * the only caller is the orchestrator's lsass_link, which must first pass the
    peer check: an ARGUS launcher whose command line is running argus.py, or
    the frozen ARGUS.exe. Any other client is refused, and 'refused' includes
    getting a response: the connection is answered and closed, nothing more.
    The sole exception is the maintenance verb 'shutdown', honoured from a plain
    python interpreter so tools/install_lsass_helper.py --remove can retire a
    running helper -- see _client_allowed() for the RAISON; it is not a
    privilege boundary, it is a DoS-of-monitoring guard, and it stays
    interpreter-only.
  * when asked to scan, it runs the EXISTING pure detection core
    (threatmon/lsass.scan) under SeDebugPrivilege and returns the findings.
    It holds precisely one more capability than the orchestrator: seeing a
    credential dump taken by an elevated tool. It cannot speak, fetch a web
    page, run a skill, or call out over a network -- there is no code path
    for any of those things in this file.

WHAT IT IS PAID WITH, HONESTLY
A process that can duplicate handles out of an elevated owner is exactly what
an attacker with code execution in it would want. So: it is one small file (no
model, no HTTP, no skills), it does one verb (scan), and it is launched by a
scheduled task it did not install itself. Defending the pipe against 'the
attacker is running AS the user' beyond peer verification is out of scope for
user mode, and this file does not pretend otherwise. The defence in depth that
matters is that the privilege is isolated HERE so that the huge, network-
facing, prompt-fed process never has it at all.

EVERY CALL FAILS CLOSED. A scan error returns an honest error in the response,
not a half-formed finding set; a connection that fails the peer check is
answered (it is already connected) with ok=False, then dropped -- it is never
entered into any computation that produces findings.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import ctypes
import importlib.util
import os
import struct
import sys
import time
from ctypes import wintypes

import paths


def _load_leaf(rel: str):
    """Load a project LEAF module DIRECTLY from its file, bypassing the
    threatmon package __init__.

    Deliberately not "from threatmon import lsass, lsass_peer": importing the
    package executes threatmon/__init__.py, which eagerly imports the other
    twelve detectors. This process is ONE job and ONE privilege -- the whole
    reason it is trusted is that it is tiny -- so it must not drag the suite
    in: that would bloat this artefact to hundreds of MB and let a failure in
    an unrelated detector kill the helper at startup. Both modules here are
    leaf (stdlib plus a guarded psutil); loading them by file is safe.

    `root` resolves to the frozen bundle (_internal) or the source checkout;
    build_exe.py ships the two .py files as data under ./threatmon so the
    frozen helper finds them.
    """
    root = getattr(sys, "_MEIPASS", None) \
        or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location(
        f"argus_leaf_{rel[:-3]}", os.path.join(root, "threatmon", rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


try:
    lsass = _load_leaf("lsass.py")
    lsass_peer = _load_leaf("lsass_peer.py")
except Exception as _e:
    # Only reached when the source files cannot be found -- e.g. a build that
    # omitted the add-data. Fell back to the package import: it drags the full
    # suite in, but a rich helper that runs is better than one that cannot
    # start at all. status()'s degraded report makes which path happened visible.
    from threatmon import lsass, lsass_peer  # noqa: F811
    _load_leaf = None  # noqa: F811  (unused after fallback; keeps reader honest)

# Named-pipe creation constants (winbase.h / winnt.h).
PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
PIPE_INSTANCES = 1                 # serialises scans; all we need and all we want
PIPE_BUFFER = 65536
ERROR_PIPE_CONNECTED = 535         # client connected between create and connect


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD),
                ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]


def _security_attributes(sid):
    """SECURITY_ATTRIBUTES carrying the owner-SID-only DACL for the pipe.

    CreateNamedPipeW copies the DACL at create time, so the descriptor heap
    object this points at never needs to outlive the call.
    """
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.LocalFree.restype = wintypes.HANDLE
    adv.LocalFree.argtypes = [ctypes.c_void_p]
    desc = ctypes.c_void_p()
    ok = adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        lsass_peer.sddl_for_user(sid), 1, ctypes.byref(desc), None)
    if not ok or not desc:
        return None
    try:
        sa = _SECURITY_ATTRIBUTES()
        sa.nLength = ctypes.sizeof(_SECURITY_ATTRIBUTES)
        sa.lpSecurityDescriptor = desc
        sa.bInheritHandle = False
        return sa
    finally:
        # CreateNamedPipeW has already copied the DACL by the time we get here.
        adv.LocalFree(desc)


def _create_pipe(name, sid):
    """Create (bind) the helper pipe. Returns the handle, not yet connected."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateNamedPipeW.restype = wintypes.HANDLE
    k32.CreateNamedPipeW.argtypes = [
        ctypes.c_wchar_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(_SECURITY_ATTRIBUTES)]
    sa = _security_attributes(sid)
    h = k32.CreateNamedPipeW(
        name, PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_INSTANCES, PIPE_BUFFER, PIPE_BUFFER, 0,
        ctypes.byref(sa) if sa else None)
    return h


def _wait_bytes(h, k32, need: int, deadline) -> None:
    """Block until NEED bytes of a peer's request are waiting, or DEADLINE.

    PeekNamedPipe reports how many bytes are buffered WITHOUT consuming them,
    and -- unlike ReadFile -- it returns immediately even on a blocked,
    wait-mode pipe. That is exactly the property the stall defence needs: without
    it, a peer that connects and sends nothing would hold the helper's single
    instance in ReadFile forever. The blocking reads below then only run once
    the data is known to be present, so they complete instantly.
    """
    k32.PeekNamedPipe.restype = wintypes.BOOL
    k32.PeekNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                  ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
                                  ctypes.c_void_p]
    while True:
        avail = wintypes.DWORD(0)
        if not k32.PeekNamedPipe(h, None, 0, None, ctypes.byref(avail), None):
            raise OSError("pipe peek failed")
        if avail.value >= need:
            return
        if time.time() >= deadline:
            raise OSError("peer connected but sent nothing")
        time.sleep(_STALL_POLL_MS)


# How long a CONNECTED peer may sit without delivering a complete request
# before the helper drops it and keeps serving. A legitimate client's request
# arrives in milliseconds; anything slower is a stall, and the whole reason a
# deadline exists is that without one a silent peer would hold the helper's
# ONLY pipe instance in a blocking ReadFile forever, silently killing LSASS
# coverage until the process is restarted.
READ_TIMEOUT_S = 6.0
_STALL_POLL_MS = 0.05

# Connections dropped because a peer stalled, sent garbage, or failed the peer
# check. Surfaced in _state() so the orchestrator can name a pattern of them
# instead of mistaking "being attacked" for "being quiet".
_dropped = [0]


def _state():
    """The helper's own status, reported back so the link can be honest."""
    st = lsass.status()
    return {
        "mode": "helper",
        "privilege": st.get("privilege"),
        "scan_ok": st.get("ok"),
        "last_error": st.get("degraded") or st.get("last_error") or "",
        "lsass_pids": st.get("lsass_pids") or [],
        "scans": st.get("scans"),
        "findings_total": st.get("findings_total"),
        "dropped": _dropped[0],
    }


def _client_allowed(cmd: str, image: str, cmdline) -> bool:
    """Whether this peer may ask the helper to do THIS command.

    ping/scan keep the strict ARGUS-process bar (peer_ok). The single
    exception is 'shutdown': tools/install_lsass_helper.py --remove runs as
    "python tools/install_lsass_helper.py" and must be able to retire a helper
    that is currently serving. Any process allowed to run an interpreter could
    already stop ARGUS or delete the helper's task, so honouring 'please exit'
    from one defends nothing that is still defended -- and refusing it would
    leave a ghost server answering scans after its task was removed. It
    remains interpreter-ONLY: an arbitrary .exe cannot even do that.
    """
    base = os.path.basename((image or "").replace("\\", "/")).lower()
    if cmd == lsass_peer.CMD_SHUTDOWN:
        return base in lsass_peer.ALLOWED_INTERPRETERS
    ok, _why = lsass_peer.peer_ok("client", image, cmdline)
    return ok


def _dispatch(req: dict, exit_flag: list) -> dict:
    """Handle one request. exit_flag is [bool]; 'shutdown' flips it."""
    cmd = req.get("cmd")
    if cmd == lsass_peer.CMD_PING:
        return dict(_state(), ok=True)
    if cmd == lsass_peer.CMD_SCAN:
        try:
            findings = lsass.scan()
        except Exception as e:
            # Fail closed: no partial findings, an honest error instead.
            return dict(_state(), ok=True, error=f"{type(e).__name__}: {e}",
                        findings=[])
        out = []
        for f in findings or []:
            flagged = dict(f)
            flagged["via"] = "helper"
            flagged["elevated"] = True
            out.append(flagged)
        return dict(_state(), ok=True, findings=out[:lsass_peer.MAX_FINDINGS])
    if cmd == lsass_peer.CMD_SHUTDOWN:
        exit_flag[0] = True
        return {"ok": True, "mode": "helper", "shutting_down": True}
    # Unknown verb: refuse politely. Never echo attacker-shaped input back into
    # any reply beyond the fixed string.
    return dict(_state(), ok=False, error="unknown command")


def _serve(sid, log):
    """Connection loop: bind, wait, verify the peer, answer, disconnect.

    Strictly sequential. One instance means one client at a time, and a scan
    takes a hundred-odd milliseconds, so serialisation costs nothing here.

    EVERY CONNECTION IS DEADLINE-BOUNDED. The pipe is deliberately writable by
    anything running as this user (the boundary is peer verification, not
    secrecy), and the helper has exactly one instance; so a peer that connects
    and sends nothing must not be able to hold that instance in ReadFile
    forever -- that would silently kill LSASS coverage until the process was
    restarted. _wait_bytes peeks for data until a deadline, then drops the
    peer and keeps serving. The price is that the ONE legitimate scan in
    flight during the stall window sees ERROR_PIPE_BUSY and the orchestrator
    burns one degraded tick -- cheap against a permanent wedge.
    """
    def drop(reason):
        _dropped[0] += 1
        log(reason)

    name = lsass_peer.pipe_name(sid)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.ConnectNamedPipe.restype = wintypes.BOOL
    k32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k32.DisconnectNamedPipe.restype = wintypes.BOOL
    k32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    exit_flag = [False]
    log(f"lsass-helper up on {name}")

    while not exit_flag[0]:
        h = _create_pipe(name, sid)
        if not lsass_peer.is_valid_handle(h):
            log("CreateNamedPipe failed — retrying in 2s")
            time.sleep(2)
            continue
        served = False
        try:
            k32.ConnectNamedPipe(h, None)       # blocking, PIPE_WAIT
            err = ctypes.get_last_error()
            if err not in (0, ERROR_PIPE_CONNECTED):
                continue
            # Bounded read FIRST: the only command a peer we then refuse may
            # have sent is 'shutdown', and the strict gate below still decides
            # whether the command is honoured. Nothing fragile depends on the
            # order -- reads are deadline-bounded in either order.
            deadline = time.time() + READ_TIMEOUT_S
            _wait_bytes(h, k32, 4, deadline)
            hdr = lsass_peer.read_exact(h, 4)
            (n,) = struct.unpack_from("<I", hdr)
            if n > lsass_peer.MAX_FRAME:
                raise OSError("oversized request")
            _wait_bytes(h, k32, n, deadline)
            body = lsass_peer.read_exact(h, n)
            req, _ = lsass_peer.frame_decode(hdr + body)
            if not isinstance(req, dict) or not isinstance(req.get("cmd"), str):
                raise OSError("request is not a valid command object")
            # ── peer verification, before any command is honoured ─────────────
            cpid = lsass_peer.named_pipe_client_pid(h)
            image, cmdline = lsass_peer.peer_identity(cpid)
            if not _client_allowed(req["cmd"], image, cmdline):
                drop(f"refused peer pid={cpid} cmd={req['cmd']}")
                lsass_peer.write_all(
                    h, lsass_peer.frame_encode(
                        {"ok": False, "error": "untrusted peer"}))
                continue
            resp = _dispatch(req, exit_flag)
            served = True
            lsass_peer.write_all(h, lsass_peer.frame_encode(resp))
        except Exception as e:
            drop(f"connection error: {type(e).__name__}: {e}")
        finally:
            try:
                k32.DisconnectNamedPipe(h)
            except Exception:
                pass
            try:
                k32.CloseHandle(h)
            except Exception:
                pass
    log("lsass-helper shutting down")


def main() -> int:
    """Entry point for the scheduled task / PyInstaller launcher."""
    paths.ensure_std_streams()
    if os.name != "nt":
        return 1
    sid = lsass_peer.current_sid()
    if not sid:
        return 1
    # Enable SeDebugPrivilege NOW, not lazily on first scan: the very first
    # scan a user triggers must already see elevated dumpers. If this fails the
    # helper still serves -- status reports privilege=False honestly and the
    # link degrades rather than lying.
    lsass._enable_debug_privilege()
    _serve(sid, print)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())