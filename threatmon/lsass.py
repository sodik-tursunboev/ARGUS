"""
ARGUS - LSASS credential-dumping detection (MITRE T1003.001).

WHAT IT CATCHES. A process that opens a handle to lsass.exe with access rights
beyond simple querying -- PROCESS_VM_READ is the one a minidump needs, and it,
VM_WRITE, VM_OPERATION, CREATE_THREAD and DUP_HANDLE are the rights an attacker
reaches for to read credential material out of LSASS memory. Reading lsass at
all requires SeDebugPrivilege, so a *legitimate* opener is nearly always a
system service or security product; anything else doing it is the single
highest-signal event on a Windows endpoint.

HOW, IN USER MODE, WITHOUT A DRIVER. There is no user-mode hook for "someone
called OpenProcess". What there IS: the kernel's own handle table, readable via
NtQuerySystemInformation(SystemExtendedHandleInformation). We enumerate every
open handle, keep only the process-typed ones whose granted access is dangerous,
duplicate each into ourselves far enough to ask GetProcessId() what it points
at, and flag the ones pointing at lsass whose owner is not on a tight
allowlist. This is a POLLING snapshot, not interception: a handle held only for
a few milliseconds between two scans can be missed. A real minidump holds the
handle for as long as it takes to write tens of megabytes, which a tight poll
catches -- which is exactly why the shipped test is Task Manager's "Create dump
file", the same thing real EDRs flag.

LIMITS, STATED PLAINLY. To DuplicateHandle out of an elevated owner we must open
it with PROCESS_DUP_HANDLE, which needs SeDebugPrivilege -- i.e. ARGUS itself
must run elevated to see a dump taken by an elevated tool. We enable the
privilege best-effort and report in status() whether we actually hold it, so the
security summary can say "LSASS monitoring degraded: not elevated" rather than
implying coverage it does not have. A blind spot named is worth more than a
green tick that lies.

CRASH DISCIPLINE. Every OS call is wrapped. Any failure -- privilege denied, a
malformed handle table, an API that returns an unexpected status -- makes the
scan fail CLOSED: it records the error, returns no findings for that cycle, and
leaves the sampler thread (which also owns GPU/disk/network telemetry) running.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import ctypes
import os
import time
from ctypes import wintypes

try:
    import psutil
except Exception:                      # psutil is a hard dep of ARGUS, but the
    psutil = None                      # detector must import even if it is not.

TECHNIQUE = "T1003.001"

# ── process access rights (winnt.h) ────────────────────────────────────────
PROCESS_TERMINATE = 0x0001
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_ALL_ACCESS = 0x1FFFFF

# The bits that mean "this opener can read or tamper with the target's memory
# or clone its handles" -- everything a credential dump is built from. Querying
# rights (QUERY_INFORMATION / QUERY_LIMITED_INFORMATION / SYNCHRONIZE) are
# deliberately absent: those are the "basic query permissions" the spec says to
# ignore, and half the system holds them on everything.
DANGEROUS_BITS = {
    PROCESS_VM_READ: "PROCESS_VM_READ",
    PROCESS_VM_WRITE: "PROCESS_VM_WRITE",
    PROCESS_VM_OPERATION: "PROCESS_VM_OPERATION",
    PROCESS_CREATE_THREAD: "PROCESS_CREATE_THREAD",
    PROCESS_DUP_HANDLE: "PROCESS_DUP_HANDLE",
    PROCESS_TERMINATE: "PROCESS_TERMINATE",
}

# Names that legitimately open other processes' memory as part of normal
# Windows operation or endpoint security. Kept deliberately SHORT and paired,
# where it matters, with the directory the real binary lives in so a malware
# named msmpeng.exe in the user's Downloads folder is not waved through on its
# name alone. taskmgr.exe is intentionally ABSENT: creating an lsass dump from
# Task Manager is precisely the benign-but-flaggable act the shipped test uses,
# and real EDRs alert on it too.
#
# name (lowercased, with .exe) -> required ABSOLUTE directory, expanded and
# normcase'd at check time. 1.2.0: the directory test is an ANCHORED PREFIX
# test on the expanded, normalized path -- the old substring test matched a
# binary named msmpeng.exe inside any folder merely CONTAINING "windows
# defender" (C:\Users\me\Windows Defender\msmpeng.exe was waved through).
# Anchoring keeps the same intent without the bypass.
DEFAULT_ALLOWLIST = {
    "wininit.exe": (r"%SystemRoot%\System32"),
    "services.exe": (r"%SystemRoot%\System32"),
    "lsass.exe": (r"%SystemRoot%\System32"),
    "csrss.exe": (r"%SystemRoot%\System32"),
    # Defender lives under ProgramData (the AV) and System32 (the EDR sensor
    # service host). Both are anchored, so a user-created "C:\x Windows
    # Defender" folder still fails the check.
    "msmpeng.exe": (r"%ProgramData%\Microsoft\Windows Defender;"
                    r"%SystemRoot%\System32"),
    "mssense.exe": (r"%ProgramData%\Microsoft\Windows Defender;"
                    r"%SystemRoot%\System32"),
    "senseir.exe": (r"%ProgramData%\Microsoft\Windows Defender;"
                    r"%SystemRoot%\System32"),
    "wdatpcanary.exe": (r"%ProgramData%\Microsoft\Windows Defender;"
                        r"%SystemRoot%\System32"),
}

# ── runtime status, for the SECURITY panel and the honest summary ──────────
_state = {
    "supported": os.name == "nt",
    "privilege": None,        # True/False once probed; None = not yet
    "last_scan_ok": None,
    "last_error": "",
    "scans": 0,
    "findings_total": 0,
    "lsass_pids": [],
}

_proc_type_index = None       # discovered once per process, then cached


# ══════════════════════════════════════════════════════════════════════════
#  PURE LOGIC  -- no OS calls, so it is unit-testable anywhere.
# ══════════════════════════════════════════════════════════════════════════
def classify_access(mask: int) -> list:
    """The dangerous rights present in an access mask, most-severe order.

    PROCESS_ALL_ACCESS is reported as itself rather than expanded into its
    dozen constituent bits, because "someone opened lsass for ALL_ACCESS" is a
    clearer line in a log than the enumerated flags.
    """
    mask = int(mask) & 0xFFFFFFFF
    if (mask & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS:
        return ["PROCESS_ALL_ACCESS"]
    out = []
    for bit, nm in sorted(DANGEROUS_BITS.items()):
        if mask & bit:
            out.append(nm)
    return out


def is_dangerous(mask: int) -> bool:
    """True if the mask grants memory-read/-write or handle-duplication rights."""
    return bool(classify_access(mask))


def is_allowlisted(name: str, path: str, allowlist: dict = None) -> bool:
    """Whether an opener is a known-legitimate one.

    Matched on the lowercased executable NAME, and -- when the allowlist entry
    names a required directory -- only if the REAL path sits UNDER one of the
    anchored directories. An empty name never matches (unknown openers are
    never trusted by default).

    1.2.0: anchored, not substring. The old check was
    ``req.lower() in path.lower()``, so a hostile binary placed in a folder
    the attacker names after the requirement -- C:\\Users\\me\\Windows
    Defender\\msmpeng.exe -- satisfied a substring of the required directory
    without being under it. Now the requirement is a set of ABSOLUTE
    directories, expanded and normcase'd, and the candidate path must have
    one of them as a path PREFIX (checked per component, so
    C:\\Windows\\System32 does not match C:\\Windows\\System32evil).

    STAYS PURE on purpose: the real-path resolution happens in the scanner
    (which can afford it), the tests need no filesystem, and a unit test can
    still pin the bypass shut with plain strings.
    """
    if allowlist is None:
        allowlist = DEFAULT_ALLOWLIST
    if not name:
        return False
    req = allowlist.get(name.lower())
    if req is None:
        return False
    if not req:
        return True

    import os as _os

    def _anchored_dirs(spec: str) -> list:
        out = []
        for part in str(spec).split(";"):
            part = part.strip()
            if not part:
                continue
            p = _os.path.normcase(_os.path.normpath(_os.path.expandvars(part)))
            out.append(p.rstrip(_os.sep) + _os.sep)
        return out

    candidate = _os.path.normcase(_os.path.normpath(path or ""))
    if not candidate:
        return False
    for d in _anchored_dirs(req):
        if candidate.startswith(d):
            return True
    return False


def build_finding(owner_pid, name, path, target_name, target_pid, mask) -> dict:
    """Assemble one detection record. Pure; the scanner supplies the OS facts."""
    return {
        "technique": TECHNIQUE,
        "detector": "lsass",
        "severity": "critical",
        "target": target_name,
        "target_pid": int(target_pid),
        "pid": int(owner_pid),
        "name": name or "(unknown)",
        "path": path or "(unknown)",
        "access": int(mask) & 0xFFFFFFFF,
        "rights": classify_access(mask),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


# ══════════════════════════════════════════════════════════════════════════
#  OS LAYER  -- ctypes/Win32. Everything below fails closed.
# ══════════════════════════════════════════════════════════════════════════
_SYSTEM_EXTENDED_HANDLE_INFORMATION = 64
_STATUS_SUCCESS = 0
_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004


class _HANDLE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Object", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_size_t),
        ("HandleValue", ctypes.c_size_t),
        ("GrantedAccess", ctypes.c_uint32),
        ("CreatorBackTraceIndex", ctypes.c_uint16),
        ("ObjectTypeIndex", ctypes.c_uint16),
        ("HandleAttributes", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


def _enable_debug_privilege() -> bool:
    """Best-effort SeDebugPrivilege. Returns whether we now hold it.

    Without it we can still enumerate the handle table, but DuplicateHandle out
    of any process we don't own will be denied -- which is most of the
    interesting ones. Reported in status() either way; never raised.
    """
    if os.name != "nt":
        return False
    try:
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)

        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        SE_PRIVILEGE_ENABLED = 0x00000002

        class LUID(ctypes.Structure):
            _fields_ = [("Low", wintypes.DWORD), ("High", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("Count", wintypes.DWORD),
                        ("Privilege", LUID_AND_ATTRIBUTES)]

        token = wintypes.HANDLE()
        if not adv.OpenProcessToken(k32.GetCurrentProcess(),
                                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                    ctypes.byref(token)):
            return False
        try:
            luid = LUID()
            if not adv.LookupPrivilegeValueW(None, "SeDebugPrivilege",
                                             ctypes.byref(luid)):
                return False
            tp = TOKEN_PRIVILEGES()
            tp.Count = 1
            tp.Privilege.Luid = luid
            tp.Privilege.Attributes = SE_PRIVILEGE_ENABLED
            adv.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0,
                                      None, None)
            # AdjustTokenPrivileges reports success even when it silently
            # granted nothing; GetLastError == ERROR_NOT_ALL_ASSIGNED (1300)
            # is how "you are not allowed this privilege" actually surfaces.
            return ctypes.get_last_error() == 0
        finally:
            k32.CloseHandle(token)
    except Exception as e:
        _state["last_error"] = f"privilege probe: {type(e).__name__}"
        return False


def _enum_handles():
    """Every open handle on the system as a ctypes array of _HANDLE_ENTRY.

    Grows the buffer until the kernel stops complaining about its size. Raises
    on any hard failure so the caller's fail-closed wrapper records it.
    """
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    size = 1 << 20                              # 1 MiB; doubles as needed
    ret = ctypes.c_ulong(0)
    for _ in range(12):                         # cap growth -> ~4 GiB worst case
        buf = (ctypes.c_byte * size)()
        status = ntdll.NtQuerySystemInformation(
            _SYSTEM_EXTENDED_HANDLE_INFORMATION, buf, size, ctypes.byref(ret))
        status &= 0xFFFFFFFF
        if status == _STATUS_SUCCESS:
            break
        if status == _STATUS_INFO_LENGTH_MISMATCH:
            # ret is unreliable for this class; just double.
            size *= 2
            continue
        raise OSError(f"NtQuerySystemInformation status=0x{status:08x}")
    else:
        raise OSError("handle table kept growing past the cap")

    ptr = ctypes.c_size_t.from_buffer(buf)
    count = int(ptr.value)
    # Header is NumberOfHandles + Reserved, both pointer-sized.
    offset = ctypes.sizeof(ctypes.c_size_t) * 2
    # Guard against a count that would run off the end of the buffer.
    max_fit = (size - offset) // ctypes.sizeof(_HANDLE_ENTRY)
    count = min(count, max_fit)
    array_t = _HANDLE_ENTRY * count
    return array_t.from_buffer(buf, offset), buf     # keep buf alive with array


def _discover_process_type_index(k32) -> int:
    """The ObjectTypeIndex the kernel uses for Process handles, on this boot.

    Found empirically: open a handle to ourselves, locate that exact
    (pid, handle) row in the table, and read its type index. The value is
    stable per boot but not across Windows versions, so it is never hardcoded.
    """
    global _proc_type_index
    if _proc_type_index is not None:
        return _proc_type_index
    mypid = os.getpid()
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, mypid)
    if not h:
        raise OSError("OpenProcess(self) failed")
    try:
        entries, _buf = _enum_handles()
        want = int(h)
        for e in entries:
            if e.UniqueProcessId == mypid and e.HandleValue == want:
                _proc_type_index = e.ObjectTypeIndex
                return _proc_type_index
        raise OSError("own process handle not found in table")
    finally:
        k32.CloseHandle(h)


def scan_targets(target_pids, allowlist=None, label="lsass", limit=6000) -> list:
    """The real detection core, parameterised by which PIDs are the targets.

    Production points it at lsass; the test points it at a victim PID it made
    itself, so the entire ctypes path -- enumerate, filter, duplicate, resolve,
    classify, allowlist -- is exercised for real without needing lsass or
    elevation. Returns a list of findings; on ANY failure returns [] and records
    the error (fail closed).
    """
    if os.name != "nt":
        _state["last_scan_ok"] = False
        _state["last_error"] = "not Windows"
        return []
    targets = {int(p) for p in target_pids}
    if not targets:
        _state["last_scan_ok"] = False
        _state["last_error"] = "no target pids"
        return []

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Explicit prototypes on every call. Without them ctypes treats arguments
    # and returns as 32-bit int, which silently truncates 64-bit HANDLE values
    # on x64 -- the duplicated handle points at garbage and the whole detection
    # fails quietly. This is exactly the class of bug that "looks like it works"
    # until a handle value happens to exceed 2^31.
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.GetProcessId.restype = wintypes.DWORD
    k32.GetProcessId.argtypes = [wintypes.HANDLE]
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.DuplicateHandle.restype = wintypes.BOOL
    k32.DuplicateHandle.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL,
        wintypes.DWORD]

    findings = []
    src_cache = {}      # owner_pid -> source handle opened for DUP, or None
    mypid = os.getpid()
    try:
        proc_type = _discover_process_type_index(k32)
        entries, _buf = _enum_handles()
        dups = 0
        for e in entries:
            if dups >= limit:
                break
            if e.ObjectTypeIndex != proc_type:
                continue
            if not is_dangerous(e.GrantedAccess):
                continue
            owner = int(e.UniqueProcessId)
            if owner in (mypid, 0) or owner in targets:
                continue                       # self / idle / target-opens-self

            if owner not in src_cache:
                src_cache[owner] = k32.OpenProcess(PROCESS_DUP_HANDLE, False, owner)
            src = src_cache[owner]
            if not src:
                continue                       # can't open owner (likely not elevated)

            dup = wintypes.HANDLE()
            # Re-request QUERY_LIMITED_INFORMATION on the duplicate rather than
            # DUPLICATE_SAME_ACCESS: the source handle may hold ONLY VM_READ (a
            # dumper needs nothing more), and a duplicate with no query right
            # makes GetProcessId return 0 -- which silently loses every
            # detection. Asking for a query right on the dup is legal once we
            # hold PROCESS_DUP_HANDLE on the owner, and is the whole point.
            ok = k32.DuplicateHandle(src, wintypes.HANDLE(e.HandleValue),
                                     k32.GetCurrentProcess(), ctypes.byref(dup),
                                     PROCESS_QUERY_LIMITED_INFORMATION, False, 0)
            dups += 1
            if not ok or not dup.value:
                continue
            try:
                tpid = int(k32.GetProcessId(dup))
            finally:
                k32.CloseHandle(dup)
            if tpid not in targets:
                continue

            name, path = _owner_identity(owner)
            if is_allowlisted(name, path, allowlist):
                continue
            tname = _pid_name(tpid) or (label + ".exe")
            findings.append(build_finding(owner, name, path, tname, tpid,
                                          e.GrantedAccess))

        _state["last_scan_ok"] = True
        _state["last_error"] = ""
        _state["scans"] += 1
        _state["findings_total"] += len(findings)
        return findings
    except Exception as e:
        _state["last_scan_ok"] = False
        _state["last_error"] = f"{type(e).__name__}: {e}"[:120]
        return []
    finally:
        for h in src_cache.values():
            if h:
                try:
                    k32.CloseHandle(h)
                except Exception:
                    pass


def _owner_identity(pid):
    if psutil is None:
        return "(unknown)", ""
    try:
        p = psutil.Process(pid)
        name = p.name() or ""
        try:
            path = p.exe() or ""
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            path = ""
        return name, path
    except Exception:
        return "(unknown)", ""


def _pid_name(pid):
    if psutil is None:
        return ""
    try:
        return psutil.Process(pid).name()
    except Exception:
        return ""


def lsass_pids() -> list:
    """PID(s) of lsass.exe. Normally exactly one."""
    pids = []
    if psutil is None:
        return pids
    try:
        for p in psutil.process_iter(["pid", "name"]):
            if (p.info.get("name") or "").lower() == "lsass.exe":
                pids.append(p.info["pid"])
    except Exception as e:
        _state["last_error"] = f"lsass lookup: {type(e).__name__}"
    return pids


def scan(processes=None) -> list:
    """Production entry point: detect dangerous handles to lsass.exe.

    `processes` is accepted (and ignored) so the coordinator can call every
    detector with the same signature as anomaly_skill.observe(processes).
    """
    if _state["privilege"] is None:
        _state["privilege"] = _enable_debug_privilege()
    pids = lsass_pids()
    _state["lsass_pids"] = pids
    if not pids:
        _state["last_scan_ok"] = False
        _state["last_error"] = "lsass.exe not found"
        return []
    return scan_targets(pids, DEFAULT_ALLOWLIST, label="lsass")


def status() -> dict:
    """Health for the SECURITY panel and the honest security summary."""
    ok = bool(_state["supported"]) and _state.get("last_scan_ok") is not False
    degraded = ""
    if not _state["supported"]:
        degraded = "unsupported OS"
    elif _state["privilege"] is False:
        degraded = "not elevated (SeDebugPrivilege unavailable)"
    elif _state.get("last_scan_ok") is False:
        degraded = _state.get("last_error") or "last scan failed"
    return {
        "detector": "lsass",
        "technique": TECHNIQUE,
        "ok": ok and not degraded,
        "degraded": degraded,
        "privilege": _state["privilege"],
        "scans": _state["scans"],
        "findings_total": _state["findings_total"],
        "lsass_pids": list(_state["lsass_pids"]),
        "last_error": _state["last_error"],
    }
