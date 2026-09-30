"""
ARGUS - LSASS elevated-helper wire protocol (shared by both processes).

THE PROBLEM THIS EXISTS TO SOLVE
The orchestrator strips SeDebugPrivilege on purpose (sandbox.drop_privileges):
a process containing a language model, an HTTP control plane and a web-fetching
skill must not be able to read another process's memory. But an ELEVATED tool
that dumps lsass memory -- the one currently invisible to threatmon/lsass.py,
which cannot duplicate handles out of an elevated owner once the privilege is
gone -- is exactly the highest-signal event on a Windows endpoint. So the in-
process detector and the capability it needs are deliberately split:

  1. threatmon/lsass_agent.py  a TINY separate process, run elevated and holding
     SeDebugPrivilege, that does ONLY the handle-table scan (the pure core of
     threatmon/lsass.py) and reports findings on a named pipe. No model, no
     HTTP, no skills.
  2. threatmon/lsass_link.py   lives in the orchestrator, which stays
     privilege-stripped and never gains the capability. It asks the helper to
     scan and re-validates every finding locally.

This module is what the two share: the pipe name, the framing, and -- the part
that makes the split a boundary rather than a convenience -- the rule each side
uses to prove the OTHER is really ARGUS before trusting it.

SECURITY MODEL, STATED PLAINLY
A per-user pipe is not a secret channel: anything running as this user can
compute the name (it is derived from the owner SID) and either connect as a
client or -- worse -- try to BE the helper. The boundary is therefore PEER
VERIFICATION, done by BOTH sides on every connection:

  * the helper only serves a peer whose image is an ARGUS launcher AND whose
    command line is actually running argus.py (source) or is the bundled
    ARGUS.exe (frozen);
  * the client only accepts responses from a peer whose image is an ARGUS
    launcher running lsass_agent.py, or is the bundled lsass-helper.exe.

This raises the bar from "any process running as your user" to "an ARGUS
process". It does NOT defeat code injected into an ARGUS process itself -- no
user-mode check at this layer can -- and it is honesty about that, not an
attempt to hide it, that the comments here keep repeating.

EVERYTHING ON THE WIRE IS LENGTH-CAPPED. A hostile or corrupt peer must not
be able to make either side allocate without bound; MAX_FRAME is the hard
ceiling and findings are capped far below it.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import ctypes
import hashlib
import json
import os
import struct
from ctypes import wintypes

# ── the pipe ────────────────────────────────────────────────────────────────
# The name hashes the OWNER SID, so the pipe is per-login (a second person
# logged into the same machine uses a different name) and stable across helper
# restarts -- the scheduled task can find it again tomorrow. The hash is not a
# secret (the SID is public to the account); secrecy was never the boundary
# here, peer verification is.
PIPE_PREFIX = r"\\.\pipe\ARGUS-lsass-helper-"

# 1 MiB. Catastrophic-limit, not a target: real finding sets are a handful of
# entries, and MAX_FINDINGS below keeps a scan reply four orders of magnitude
# under this.
MAX_FRAME = 1 << 20
MAX_FINDINGS = 500

# A blocked helper is busy scanning for a hundred-odd milliseconds at most, so
# a connecting client waits this long rather than failing on the first
# ERROR_PIPE_BUSY. 60 tries * 100 ms = 6 s.
CONNECT_RETRIES = 60
CONNECT_RETRY_MS = 0.1

# Commands a client may send. Kept to three verbs; the point of the helper is
# to do ONE thing, and "do one thing" is the strongest argument for trusting it.
CMD_PING = "ping"
CMD_SCAN = "scan"
# Server-only maintenance verb, used by tools/install_lsass_helper.py from a
# console, never by the orchestrator.
CMD_SHUTDOWN = "shutdown"


# ── pure: pipe name + DACL ─────────────────────────────────────────────────
def pipe_token(sid: str) -> str:
    """A short stable token for a SID. 16 hex chars."""
    return hashlib.sha256((sid or "").encode("utf-8")).hexdigest()[:16]


def pipe_name(sid: str) -> str:
    """The named-pipe path a given owner's helper lives on."""
    return PIPE_PREFIX + pipe_token(sid)


def sddl_for_user(sid: str) -> str:
    """SDDL DACL granting the OWNER SID alone read+write on the pipe.

    Explicitly NOT Administrators and NOT Everyone: the Medium-integrity
    orchestrator must connect (it holds the user SID but a filtered, deny-
    only Administrators group), SYSTEM and other accounts must not.
    """
    return f"D:P(A;;GA;;;{sid})"


# ── pure: framing ───────────────────────────────────────────────────────────
def frame_encode(obj: dict) -> bytes:
    """Length-prefixed JSON: 4-byte little-endian length, then the payload."""
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_FRAME:
        raise ValueError("frame exceeds the size cap")
    return struct.pack("<I", len(payload)) + payload


def frame_decode(raw: bytes):
    """(object, rest) from a buffer holding >= one frame. Raises when a corrupt
    or oversized header/body could otherwise wedge the caller."""
    if len(raw) < 4:
        raise ValueError("truncated frame header")
    (n,) = struct.unpack_from("<I", raw)
    if n > MAX_FRAME:
        raise ValueError("frame length exceeds the size cap")
    need = 4 + n
    if len(raw) < need:
        raise ValueError("truncated frame body")
    obj = json.loads(raw[4:need].decode("utf-8"))
    return obj, raw[need:]


# ── pure: who is allowed to be the other end ───────────────────────────────
# A frozen ARGUS is one self-contained launcher and needs no command-line
# check. An interpreter must additionally show, in its own command line, that
# it is running the ARGUS script the role requires -- "python.exe evil.py"
# must not count as ARGUS even though it is the right interpreter, which is
# exactly the guess a basename-by-itself check would wave through.
CLIENT_FROZEN = ("argus.exe",)
SERVER_FROZEN = ("lsass-helper.exe",)
CLIENT_SCRIPTS = frozenset({"argus.py"})
SERVER_SCRIPTS = frozenset({"lsass_agent.py"})
ALLOWED_INTERPRETERS = frozenset(
    {"python.exe", "pythonw.exe", "python3.exe", "py.exe"}
)


def cmdline_launches(cmdline, script_names) -> bool:
    """True when CMDLINE contains a token that runs one of SCRIPT_NAMES.

    Looks for a script argument AFTER the interpreter, tolerating quotes and
    full paths. A bare "argus.py" in argv[0] (the py launcher leaves it there)
    does not count -- something must be RUNNING the script.
    """
    toks = [str(t).strip().strip('"') for t in (cmdline or [])]
    for t in toks[1:]:
        if t and os.path.basename(t.replace("\\", "/")).lower() in script_names:
            return True
    return False


def peer_ok(role: str, image: str, cmdline) -> tuple[bool, str]:
    """Whether a peer of ROLE ('client' or 'server') may be trusted.

    The one vote every connection is decided by, on both sides. Pure -- no OS
    calls -- so it is unit-testable anywhere and, being the security decision,
    that testability is not a nicety.
    """
    base = os.path.basename((image or "").replace("\\", "/")).lower()
    if role == "client":
        if base in CLIENT_FROZEN:
            return True, ""
        if base not in ALLOWED_INTERPRETERS:
            return False, f"{base or '(no image)'} is not an ARGUS launcher"
        if not cmdline_launches(cmdline, CLIENT_SCRIPTS):
            return False, "interpreter is not running ARGUS (argus.py)"
        return True, ""
    if role == "server":
        if base in SERVER_FROZEN:
            return True, ""
        if base not in ALLOWED_INTERPRETERS:
            return False, f"{base or '(no image)'} is not the LSASS helper"
        if not cmdline_launches(cmdline, SERVER_SCRIPTS):
            return False, "interpreter is not running the LSASS helper (lsass_agent.py)"
        return True, ""
    return False, f"unknown peer role {role!r}"


# ── OS layer: identity of the current owner and of a peer process ──────────
def current_sid() -> str:
    """The STRING SID of the current process's user, via pure ctypes.

    Deliberately no pywin32: the helper must be a tiny, self-contained artifact
    and pywin32 is only a build-time dependency elsewhere. Any failure returns
    "" and callers fail closed (no pipe, no service).
    """
    if os.name != "nt":
        return ""
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        TOKEN_QUERY = 0x0008
        TokenUser = 1

        class _SID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

        class _TOKEN_USER(ctypes.Structure):
            _fields_ = [("User", _SID_AND_ATTRIBUTES)]

        htok = wintypes.HANDLE()
        if not adv.OpenProcessToken(k32.GetCurrentProcess(), TOKEN_QUERY,
                                    ctypes.byref(htok)):
            return ""
        try:
            size = wintypes.DWORD(0)
            adv.GetTokenInformation(htok, TokenUser, None, 0, ctypes.byref(size))
            buf = ctypes.create_string_buffer(max(1, int(size.value)))
            if not adv.GetTokenInformation(htok, TokenUser, buf, len(buf),
                                           ctypes.byref(size)):
                return ""
            tu = ctypes.cast(buf, ctypes.POINTER(_TOKEN_USER)).contents
            if not tu.User.Sid:
                return ""
            out = ctypes.create_unicode_buffer(256)
            adv.ConvertSidToStringSidW(ctypes.c_void_p(tu.User.Sid),
                                       ctypes.byref(out))
            return out.value
        finally:
            k32.CloseHandle(htok)
    except Exception:
        return ""


def query_process_image(pid) -> str:
    """The full executable path of a process, or '' on any failure."""
    if os.name != "nt" or not pid:
        return ""
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not h:
            return ""
        try:
            buf = ctypes.create_unicode_buffer(32768)
            n = wintypes.DWORD(len(buf))
            if not k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
                return ""
            return buf.value
        finally:
            k32.CloseHandle(h)
    except Exception:
        return ""


def peer_cmdline(pid) -> list:
    """Command line of a peer process, best-effort via psutil (guarded)."""
    try:
        import psutil
        return list(psutil.Process(int(pid)).cmdline() or [])
    except Exception:
        return []


def peer_identity(pid) -> tuple[str, list]:
    """(image, cmdline) for a peer, tolerantly. Used by both sides to vote."""
    return query_process_image(pid), peer_cmdline(pid)


def named_pipe_client_pid(h) -> int:
    """PID of the client on the other end of server handle H, or 0."""
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        pid = wintypes.DWORD(0)
        if not k32.GetNamedPipeClientProcessId(h, ctypes.byref(pid)):
            return 0
        return int(pid.value)
    except Exception:
        return 0


def named_pipe_server_pid(h) -> int:
    """PID of the server on the other end of client handle H, or 0."""
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        pid = wintypes.DWORD(0)
        if not k32.GetNamedPipeServerProcessId(h, ctypes.byref(pid)):
            return 0
        return int(pid.value)
    except Exception:
        return 0


def is_valid_handle(h) -> bool:
    """True when HANDLE is not NULL and not INVALID_HANDLE_VALUE (-1)."""
    if not h:
        return False
    try:
        return int(getattr(h, "value", h) or 0) not in (0, -1)
    except (TypeError, ValueError):
        return False


# ── OS layer: blocking byte I/O both ends share ───────────────────────────
def write_all(h, data: bytes) -> bool:
    """Write every byte, handling short writes. True only if all went out."""
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                  wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                  ctypes.c_void_p]
        off = 0
        while off < len(data):
            chunk = bytes(data[off:off + 65536])
            written = wintypes.DWORD(0)
            nb = k32.WriteFile(h, ctypes.c_char_p(chunk), len(chunk),
                               ctypes.byref(written), None)
            if not nb:
                return False
            if not written.value:
                return False
            off += int(written.value)
        return True
    except Exception:
        return False


def read_exact(h, n: int) -> bytes:
    """Read exactly N bytes or raise. N must already be bounded by the caller."""
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                 ctypes.c_void_p]
        out = bytearray()
        while len(out) < n:
            want = min(n - len(out), 65536)
            buf = ctypes.create_string_buffer(want)
            got = wintypes.DWORD(0)
            if not k32.ReadFile(h, buf, want, ctypes.byref(got), None):
                raise OSError("read failed")
            if not got.value:
                raise OSError("pipe closed")
            out += buf.raw[:got.value]
        return bytes(out)
    except Exception as e:
        raise OSError(f"pipe read: {e}")


# ── OS layer: the client half of a connection ──────────────────────────────
# _GENERIC_READ | _GENERIC_WRITE against the helper pipe. SECURITY_IDENTIFICATION
# (impersonate at identification level, no token query) + SQOS makes this a
# least-requesting open rather than a delegation-capable one.
_GENERIC_READ_WRITE = 0xC0000000
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80
_SECURITY_SQOS_PRESENT = 0x100000
_SECURITY_IDENTIFICATION = 0x00010000
_ERROR_PIPE_BUSY = 231
_ERROR_FILE_NOT_FOUND = 2


def connect_pipe(name: str):
    """Open a client handle to the helper pipe, waiting through ERROR_PIPE_BUSY
    (the single-instance helper is mid-scan). Returns the handle or None.

    None means one of: the helper is not running, the name is unreachable, or
    the wait gave up -- all of which the caller reports as degraded rather than
    raising, because "the helper is busy" and "the helper is gone" have one
    answer: use the in-process fallback and say so.
    """
    if os.name != "nt":
        return None
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [ctypes.c_wchar_p, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                wintypes.HANDLE]

    def _open():
        return k32.CreateFileW(
            name, _GENERIC_READ_WRITE, 0, None, _OPEN_EXISTING,
            _FILE_ATTRIBUTE_NORMAL | _SECURITY_SQOS_PRESENT | _SECURITY_IDENTIFICATION,
            None)

    h = _open()
    if not is_valid_handle(h) and ctypes.get_last_error() == _ERROR_PIPE_BUSY:
        try:
            k32.WaitNamedPipeW.restype = wintypes.BOOL
            k32.WaitNamedPipeW.argtypes = [ctypes.c_wchar_p, wintypes.DWORD]
            for _ in range(CONNECT_RETRIES):
                if k32.WaitNamedPipeW(name, int(CONNECT_RETRY_MS * 1000)):
                    break
                if ctypes.get_last_error() == _ERROR_FILE_NOT_FOUND:
                    break               # helper went away mid-wait
        except Exception:
            pass
        h = _open()
    return h if is_valid_handle(h) else None


def client_rpc(h, req: dict, max_frame: int = MAX_FRAME) -> dict:
    """Send one request frame on handle H and return the response dict.

    Raises on any protocol failure (write fail, closed pipe, oversized reply,
    malformed frame) so the caller decides fallback -- the security decision
    stays with the caller, not with a helper-authorised transport.
    """
    data = frame_encode(req)
    if not write_all(h, data):
        raise OSError("pipe write failed")
    hdr = read_exact(h, 4)
    (n,) = struct.unpack_from("<I", hdr)
    if n < 0 or n > max_frame:
        raise OSError("oversized reply from peer")
    body = read_exact(h, n)
    resp, _rest = frame_decode(hdr + body)
    return resp