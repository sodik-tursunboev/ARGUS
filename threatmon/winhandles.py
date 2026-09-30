"""
ARGUS - Fast "who has this file open" via the kernel handle table.

psutil.open_files() answers this too, but by walking EVERY process and
re-resolving all of its handles -- on a real desktop that measured well over two
minutes per sweep, unusable for a watcher that must run every few seconds. This
does one NtQuerySystemInformation to get the whole system's handle table, keeps
only the File-typed handles, duplicates each far enough to ask its name, and
matches against the paths we care about. One enumeration, targeted resolution --
sub-second where the per-process walk took minutes.

THE PIPE-HANG, HANDLED. NtQueryObject(ObjectNameInformation) blocks forever on a
handle to a synchronous named pipe -- the classic footgun of this technique. We
call GetFileType() first (which never blocks) and resolve the NAME only for
FILE_TYPE_DISK handles, so a pipe is skipped, not waited on. No worker-thread
timeout gymnastics needed.

Everything fails closed: any API error yields an empty result for that sweep
rather than an exception into the caller.
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
except Exception:
    psutil = None

from threatmon.lsass import _enum_handles      # one enumeration, shared

_OBJECT_NAME_INFORMATION = 1
_FILE_TYPE_DISK = 0x0001
_PROCESS_DUP_HANDLE = 0x0040
_DUPLICATE_SAME_ACCESS = 0x00000002
_STATUS_SUCCESS = 0

_file_type_index = None
_drive_map_cache = None


class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", wintypes.USHORT),
                ("MaximumLength", wintypes.USHORT),
                ("Buffer", wintypes.LPWSTR)]


def _drive_map():
    """{'\\device\\harddiskvolume3': 'C:'} so an NT path becomes a DOS path."""
    global _drive_map_cache
    if _drive_map_cache is not None:
        return _drive_map_cache
    m = {}
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        buf = ctypes.create_unicode_buffer(1024)
        for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = c + ":"
            if k32.QueryDosDeviceW(drive, buf, 1024):
                # A drive can map to several targets (comma-joined); take each.
                for target in buf.value.split("\x00"):
                    if target:
                        m[target.lower()] = drive
    except Exception:
        pass
    _drive_map_cache = m
    return m


def _nt_to_dos(nt_path: str) -> str:
    low = nt_path.lower()
    for dev, drive in _drive_map().items():
        if low.startswith(dev + "\\") or low == dev:
            return drive + nt_path[len(dev):]
    return nt_path


def _discover_file_type_index(k32) -> int:
    """The ObjectTypeIndex the kernel uses for File handles, on this boot."""
    global _file_type_index
    if _file_type_index is not None:
        return _file_type_index
    # Open a handle to a file we certainly can: this very module.
    fd = os.open(__file__, os.O_RDONLY)
    try:
        import msvcrt
        h = msvcrt.get_osfhandle(fd)
        entries, _buf = _enum_handles()
        mypid = os.getpid()
        for e in entries:
            if e.UniqueProcessId == mypid and e.HandleValue == int(h):
                _file_type_index = e.ObjectTypeIndex
                return _file_type_index
        raise OSError("own file handle not found in table")
    finally:
        os.close(fd)


def _query_name(k32, ntdll, handle) -> str:
    """The NT object name of a handle, or "" -- only ever called on DISK files,
    so it cannot hit the named-pipe hang."""
    size = 2048
    for _ in range(2):
        buf = (ctypes.c_byte * size)()
        ret = ctypes.c_ulong(0)
        status = ntdll.NtQueryObject(handle, _OBJECT_NAME_INFORMATION, buf,
                                     size, ctypes.byref(ret)) & 0xFFFFFFFF
        if status == _STATUS_SUCCESS:
            us = _UNICODE_STRING.from_buffer_copy(buf, 0)
            if us.Length and us.Buffer:
                return us.Buffer[: us.Length // 2]
            return ""
        if status in (0xC0000004, 0xC0000023):     # length mismatch / too small
            size = max(size * 2, int(ret.value) or size * 2)
            continue
        return ""
    return ""


def open_holders(target_paths_normcase: set, budget_s: float = 3.0) -> dict:
    """{normcase path -> (pid, name)} for any target a process currently holds
    open. Bounded by a wall-clock budget so a pathological table cannot stall
    the watch thread. Fails closed to {}.
    """
    if os.name != "nt" or not target_paths_normcase:
        return {}
    out = {}
    deadline = time.time() + budget_s
    src_cache = {}
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.GetFileType.restype = wintypes.DWORD
        k32.GetFileType.argtypes = [wintypes.HANDLE]
        k32.DuplicateHandle.restype = wintypes.BOOL
        k32.DuplicateHandle.argtypes = [
            wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
            ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL,
            wintypes.DWORD]

        ftype = _discover_file_type_index(k32)
        entries, _buf = _enum_handles()
        names = _pid_names()
        mypid = os.getpid()

        for e in entries:
            if time.time() > deadline:
                break
            if e.ObjectTypeIndex != ftype:
                continue
            owner = int(e.UniqueProcessId)
            if owner in (0, 4):
                continue                       # system/idle; can't dup anyway
            if owner not in src_cache:
                src_cache[owner] = (k32.OpenProcess(_PROCESS_DUP_HANDLE, False, owner)
                                    if owner != mypid else k32.GetCurrentProcess())
            src = src_cache[owner]
            if not src:
                continue
            dup = wintypes.HANDLE()
            if not k32.DuplicateHandle(src, wintypes.HANDLE(e.HandleValue),
                                       k32.GetCurrentProcess(), ctypes.byref(dup),
                                       0, False, _DUPLICATE_SAME_ACCESS):
                continue
            try:
                if k32.GetFileType(dup) != _FILE_TYPE_DISK:
                    continue                   # skip pipes/char devices (hang-safe)
                name = _query_name(k32, ntdll, dup)
                if not name:
                    continue
                dos = os.path.normcase(_nt_to_dos(name))
                if dos in target_paths_normcase:
                    out[dos] = (owner, names.get(owner, "?"))
            finally:
                k32.CloseHandle(dup)
        return out
    except Exception:
        return {}
    finally:
        myproc = None
        for owner, h in src_cache.items():
            if h and owner != os.getpid():
                try:
                    ctypes.WinDLL("kernel32").CloseHandle(h)
                except Exception:
                    pass


def _pid_names() -> dict:
    out = {}
    if psutil is None:
        return out
    try:
        for p in psutil.process_iter(["pid", "name"]):
            out[p.info["pid"]] = p.info.get("name") or "?"
    except Exception:
        pass
    return out
