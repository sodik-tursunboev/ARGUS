"""
ARGUS - OS-level privilege reduction and process sandboxing.

Three separate mechanisms, all kernel-enforced, none needing a new dependency.

1. PRIVILEGE REDUCTION (drop_privileges)

   A process inherits the token of whatever launched it. Launched from an
   elevated shell -- which happens, via a scheduled task with "highest
   privileges", or just running it from an admin terminal once -- ARGUS holds
   SeDebugPrivilege at High integrity. Measured on this machine:

       SeDebugPrivilege                ENABLED    <- read any process's memory
       SeImpersonatePrivilege          ENABLED
       SeCreateGlobalPrivilege         ENABLED
       SeTakeOwnershipPrivilege        held
       SeLoadDriverPrivilege           held
       SeBackupPrivilege               held       <- read any file, ignoring ACLs
       SeRestorePrivilege              held       <- write any file, ignoring ACLs
       integrity                       S-1-16-12288 (High)

   A "disabled" privilege is not absent: any code in the process can enable it
   with one call. So these are REMOVED (SE_PRIVILEGE_REMOVED), which is
   irreversible for the life of the process, rather than merely turned off.

   An always-listening assistant with a language model in the loop has no
   business being able to read another process's memory.

2. IMAGE-LOAD HARDENING (harden_image_loading)

   SetProcessMitigationPolicy(ProcessImageLoadPolicy) refuses DLLs from
   network paths and from files written by low-integrity processes (a browser
   download, for instance), and prefers System32 when a name exists in both
   places. That is the practical part of "prevent arbitrary DLL loading" --
   the full version, MicrosoftSignedOnly, would refuse Python's own
   extension modules and kill the process instantly.

3. JOB OBJECTS (JobLimits / execpolicy.run)

   A Python timeout kills the child it spawned. It does not kill that child's
   children, so a subprocess that forks leaves orphans behind. A job object
   with KILL_ON_JOB_CLOSE is a kernel guarantee about the whole tree, plus
   hard caps on memory and process count that a timeout cannot express.

WHAT THIS IS NOT. None of it sandboxes ARGUS from the user's own files -- it
runs as that user by design, and needs to. It reduces what a compromised
ARGUS could reach BEYOND that: other processes' memory, ACL-bypassing file
access, driver loading, and DLLs from untrusted locations.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys

IS_WINDOWS = os.name == "nt"

# SeChangeNotifyPrivilege is "bypass traverse checking" -- ordinary path
# resolution depends on it, and removing it breaks file access across the
# board. It is held by every process on the system for that reason.
ALWAYS_KEEP = {"SeChangeNotifyPrivilege"}

# The orchestrator additionally needs to be able to initiate a shutdown,
# because power_skill exists. The workers need nothing at all.
ORCHESTRATOR_KEEP = ALWAYS_KEEP | {"SeShutdownPrivilege"}
WORKER_KEEP = set(ALWAYS_KEEP)


def is_elevated() -> bool:
    """True if this process holds an elevated (Administrator) token."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def harden_acls_if_needed() -> tuple:
    """Run the ACL hardening ONCE, only when elevated and not already done.

    (ran, note). Called from boot so a build that requests elevation
    (ARGUS.spec uac_admin) does not need tools/harden_acls.ps1 run by hand
    after every rebuild.

    THREE GUARDS, because this rewrites ACLs on the security layer and a bad
    run could lock the owner out of their own files:

      1. Only when ALREADY elevated. It never prompts, never self-elevates,
         and never re-launches itself -- a program that escalates its own
         privileges is the behaviour this codebase exists to detect.
      2. Only when integrity.acls_hardened() says they are NOT hardened, so
         the common path is a no-op. icacls /reset + /inheritance:r on every
         boot would rewrite ACLs thousands of times for no reason and turn a
         one-off risk into a recurring one.
      3. Never fatal. A failure is reported and boot continues -- being unable
         to harden is a weaker posture, not a reason to refuse to start.

    Deliberately NOT reachable from any skill, the router or an endpoint, for
    the same reason sealing is not: anything that can change the ACLs on the
    security layer can also remove them.
    """
    import integrity
    try:
        hardened, note = integrity.acls_hardened()
        if hardened:
            return False, "already hardened"
        if not is_elevated():
            return False, ("not elevated — run tools/harden_acls.ps1 as "
                           "Administrator, or launch the elevated build")

        import paths
        script = paths.resource("tools", "harden_acls.ps1")
        if not os.path.isfile(script):
            return False, "harden_acls.ps1 not bundled with this build"

        args = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", script]
        if paths.is_frozen():
            args += ["-App", os.path.dirname(sys.executable)]
        proc = subprocess.run(args, capture_output=True, text=True, timeout=180)
        ok_after, note_after = integrity.acls_hardened()
        try:
            import security
            security.audit("acl_harden",
                           f"rc={proc.returncode} hardened={ok_after}", "ok")
        except Exception:
            pass
        if proc.returncode != 0:
            return False, (f"icacls returned {proc.returncode}: "
                           f"{(proc.stderr or proc.stdout or '').strip()[:90]}")
        return True, note_after
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def current_privileges() -> dict:
    """{name: 'enabled'|'disabled'} for every privilege on this token."""
    if not IS_WINDOWS:
        return {}
    try:
        import win32api
        import win32security
        tok = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
        out = {}
        for luid, attr in win32security.GetTokenInformation(
                tok, win32security.TokenPrivileges):
            name = win32security.LookupPrivilegeName(None, luid)
            out[name] = ("enabled"
                         if attr & win32security.SE_PRIVILEGE_ENABLED
                         else "disabled")
        return out
    except Exception as e:
        # 1.4.1: the failure is RECORDED, not swallowed -- an empty dict here
        # used to be indistinguishable from a fully hardened token, which is
        # exactly the fail-open the audit flagged. report() reads this and
        # surfaces "unknown" instead of a flattering zero.
        _drop_state["detail"] = f"privilege query failed: {type(e).__name__}: {e}"[:120]
        return {}


def integrity_level() -> str:
    if not IS_WINDOWS:
        return ""
    try:
        import win32api
        import win32security
        tok = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
        sid = win32security.GetTokenInformation(
            tok, win32security.TokenIntegrityLevel)[0]
        rid = win32security.ConvertSidToStringSid(sid).rsplit("-", 1)[-1]
        return {"4096": "Low", "8192": "Medium", "12288": "High",
                "16384": "System"}.get(rid, rid)
    except Exception:
        return ""


# 1.4.1: what actually happened when drop_privileges() ran. "not_attempted"
# (before any call), "ok" (ran clean, whether or not anything was removed),
# "failed" (could not read the token / pywin32 missing / adjust failed --
# NOTHING was dropped and the process may still hold everything), or
# "not_applicable" (non-Windows). The audit's point: a silent no-op must not
# read as a hardened process.
_drop_state = {"state": "not_attempted", "detail": ""}


def drop_status() -> dict:
    """The record of the last drop_privileges() attempt. Never raises."""
    return dict(_drop_state)


def drop_privileges(keep=None) -> list:
    """Permanently removes every privilege except KEEP. Returns what went.

    SE_PRIVILEGE_REMOVED, not SE_PRIVILEGE_ENABLED=0: a disabled privilege can
    be re-enabled by any code running in the process, so disabling it defends
    against nothing that matters. Removal cannot be undone without a new
    token, which means restarting the process.

    1.4.1: every failure now records WHY in _drop_state (surfaced by report()
    and drop_status()) instead of returning [] indistinguishably from "there
    was nothing to drop". The return type and empty-on-nothing behaviour are
    unchanged -- callers keep their interface, the reporting stops lying.
    """
    if not IS_WINDOWS:
        _drop_state["state"] = "not_applicable"
        _drop_state["detail"] = "non-Windows host"
        return []
    keep = set(keep or ALWAYS_KEEP)
    try:
        import win32api
        import win32security
    except ImportError:
        _drop_state["state"] = "failed"
        _drop_state["detail"] = "pywin32 unavailable -- NOTHING was dropped"
        print(f"[sandbox] {_drop_state['detail']}")
        return []

    try:
        tok = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY)
        held = win32security.GetTokenInformation(tok, win32security.TokenPrivileges)
    except Exception as e:
        _drop_state["state"] = "failed"
        _drop_state["detail"] = f"could not read the token: {e}"[:120]
        print(f"[sandbox] {_drop_state['detail']}")
        return []

    removed, to_remove = [], []
    for luid, _attr in held:
        try:
            name = win32security.LookupPrivilegeName(None, luid)
        except Exception:
            continue
        if name in keep:
            continue
        to_remove.append((luid, win32security.SE_PRIVILEGE_REMOVED))
        removed.append(name)

    if not to_remove:
        _drop_state["state"] = "ok"
        _drop_state["detail"] = "nothing to remove beyond KEEP"
        return []
    try:
        win32security.AdjustTokenPrivileges(tok, False, to_remove)
    except Exception as e:
        _drop_state["state"] = "failed"
        _drop_state["detail"] = f"could not drop privileges: {e}"[:120]
        print(f"[sandbox] {_drop_state['detail']}")
        return []
    _drop_state["state"] = "ok"
    _drop_state["detail"] = f"{len(removed)} privilege(s) removed"
    return sorted(removed)


# ── image-load policy ──────────────────────────────────────────────────
_ProcessImageLoadPolicy = 10
_NO_REMOTE_IMAGES = 0x1
_NO_LOW_LABEL_IMAGES = 0x2
_PREFER_SYSTEM32 = 0x4


def harden_image_loading() -> bool:
    """Refuse DLLs from network paths and low-integrity files.

    Deliberately NOT MicrosoftSignedOnly: Python's own extension modules
    (numpy, ctranslate2, onnxruntime) are not Microsoft-signed, so that
    setting terminates the process on the next import.
    """
    if not IS_WINDOWS:
        return False
    try:
        flags = wt.DWORD(_NO_REMOTE_IMAGES | _NO_LOW_LABEL_IMAGES | _PREFER_SYSTEM32)
        ok = ctypes.windll.kernel32.SetProcessMitigationPolicy(
            _ProcessImageLoadPolicy, ctypes.byref(flags), ctypes.sizeof(flags))
        return bool(ok)
    except Exception as e:
        print(f"[sandbox] image-load hardening unavailable: {e}")
        return False


# ── job objects ────────────────────────────────────────────────────────
class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in
                ("ReadOperationCount", "WriteOperationCount",
                 "OtherOperationCount", "ReadTransferCount",
                 "WriteTransferCount", "OtherTransferCount")]


class _BASIC_LIMIT(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wt.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wt.DWORD),
        ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
        ("PriorityClass", wt.DWORD),
        ("SchedulingClass", wt.DWORD),
    ]


class _EXTENDED_LIMIT(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BASIC_LIMIT),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _UI_RESTRICTIONS(ctypes.Structure):
    _fields_ = [("UIRestrictionsClass", wt.DWORD)]


_JobObjectExtendedLimitInformation = 9
_JobObjectBasicUIRestrictions = 4

_LIMIT_PROCESS_TIME = 0x00000002
_LIMIT_ACTIVE_PROCESS = 0x00000008
_LIMIT_PROCESS_MEMORY = 0x00000100
_LIMIT_JOB_MEMORY = 0x00000200
_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

# Clipboard and display settings are the ones that matter for a helper process
# reading network state. EXITWINDOWS is deliberately NOT restricted here as a
# blanket rule -- see run_sandboxed's ui_restricted argument.
_UILIMIT_READCLIPBOARD = 0x00000002
_UILIMIT_WRITECLIPBOARD = 0x00000004
_UILIMIT_SYSTEMPARAMETERS = 0x00000008
_UILIMIT_DISPLAYSETTINGS = 0x00000010
_UILIMIT_EXITWINDOWS = 0x00000080


class JobLimits:
    """A kernel-enforced cage for a child process and everything it spawns."""

    def __init__(self, memory_mb=512, max_processes=4, cpu_seconds=30,
                 ui_restricted=True):
        self.handle = None
        if not IS_WINDOWS:
            return
        k32 = ctypes.windll.kernel32
        k32.CreateJobObjectW.restype = wt.HANDLE
        self.handle = k32.CreateJobObjectW(None, None)
        if not self.handle:
            return

        info = _EXTENDED_LIMIT()
        info.BasicLimitInformation.LimitFlags = (
            _LIMIT_KILL_ON_JOB_CLOSE | _LIMIT_ACTIVE_PROCESS
            | _LIMIT_PROCESS_MEMORY | _LIMIT_JOB_MEMORY
            | _LIMIT_PROCESS_TIME | _LIMIT_DIE_ON_UNHANDLED_EXCEPTION)
        info.BasicLimitInformation.ActiveProcessLimit = max_processes
        # 100ns units.
        info.BasicLimitInformation.PerProcessUserTimeLimit = int(cpu_seconds * 10_000_000)
        info.ProcessMemoryLimit = memory_mb * 1024 * 1024
        info.JobMemoryLimit = memory_mb * 1024 * 1024
        k32.SetInformationJobObject(
            self.handle, _JobObjectExtendedLimitInformation,
            ctypes.byref(info), ctypes.sizeof(info))

        if ui_restricted:
            ui = _UI_RESTRICTIONS()
            ui.UIRestrictionsClass = (
                _UILIMIT_READCLIPBOARD | _UILIMIT_WRITECLIPBOARD
                | _UILIMIT_SYSTEMPARAMETERS | _UILIMIT_DISPLAYSETTINGS
                | _UILIMIT_EXITWINDOWS)
            k32.SetInformationJobObject(
                self.handle, _JobObjectBasicUIRestrictions,
                ctypes.byref(ui), ctypes.sizeof(ui))

    def assign(self, pid: int) -> bool:
        if not self.handle:
            return False
        k32 = ctypes.windll.kernel32
        PROCESS_SET_QUOTA, PROCESS_TERMINATE = 0x0100, 0x0001
        k32.OpenProcess.restype = wt.HANDLE
        h = k32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid)
        if not h:
            return False
        try:
            return bool(k32.AssignProcessToJobObject(self.handle, h))
        finally:
            k32.CloseHandle(h)

    def close(self):
        """Closing the handle kills every process still in the job."""
        if self.handle:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def run_sandboxed(argv, timeout=20.0, memory_mb=512, max_processes=4,
                  ui_restricted=True, **kwargs):
    """subprocess.run inside a job object.

    The job is what makes the timeout honest: subprocess kills the child it
    started, while closing the job handle kills the child AND anything the
    child spawned. Without it a helper that forks leaves orphans that outlive
    the command that was supposed to have been cancelled.
    """
    kwargs.pop("shell", None)
    # Popen has no capture_output -- that is a subprocess.run convenience, and
    # passing it through raises TypeError. Translate it to the pipes Popen
    # actually understands, since callers reasonably expect run()'s vocabulary.
    if kwargs.pop("capture_output", True):
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)
    if IS_WINDOWS:
        kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)

    job = JobLimits(memory_mb=memory_mb, max_processes=max_processes,
                    cpu_seconds=max(1, int(timeout)), ui_restricted=ui_restricted)
    proc = None
    try:
        proc = subprocess.Popen(argv, shell=False, **kwargs)
        job.assign(proc.pid)
        out, err = proc.communicate(timeout=timeout)
        return subprocess.CompletedProcess(argv, proc.returncode, out, err)
    except subprocess.TimeoutExpired:
        raise
    finally:
        if proc and proc.poll() is None:
            proc.kill()
        job.close()          # kills anything the child left behind


def report() -> dict:
    privs = current_privileges()
    return {
        "integrity": integrity_level(),
        "privileges_held": len(privs),
        # 1.4.1: False means the token could not be read -- "unknown", which is
        # a different situation from a genuinely zero-privilege token and used
        # to be reported identically.
        "privileges_known": bool(privs) or not IS_WINDOWS,
        "drop": _drop_state["state"],
        "drop_detail": _drop_state["detail"],
        "dangerous_held": sorted(
            p for p in privs
            if p in {"SeDebugPrivilege", "SeBackupPrivilege",
                     "SeRestorePrivilege", "SeTakeOwnershipPrivilege",
                     "SeLoadDriverPrivilege", "SeImpersonatePrivilege"}),
    }
