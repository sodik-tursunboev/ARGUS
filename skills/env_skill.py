r"""
ARGUS - User environment variable manager.

Read and set the CURRENT USER's environment variables.

  LIST -- "what are my environment variables". Reports the user's own
  variables (os.environ minus the ones that came from the system or the
  machine). A spoken reply is bounded: MAX_LIST = 20 names, and REGISTRY-only
  system variables like SystemRoot are never claimed as the user's.

  GET -- "what is PATH". The value of one named variable, from the process
  environment -- which is exactly what a newly launched program would see.

  SET -- "set MYTOKEN to abc123". STAGED + PIN, the same shape as
  power_skill and service_skill: request stays the action, confirm checks the
  command PIN and only then persists, cancel drops it. Persist goes to the
  USER-level registry key (HKEY_CURRENT_USER\Environment) -- the same place
  setx writes -- then broadcasts WM_SETTINGCHANGE so Windows and new programs
  see it immediately. The running process's own os.environ is updated too, so
  ARGUS sees it in this session.

WHY HKCU\Environment AND NOT setx. execpolicy's allowlist deliberately has no
shell, so 'setx NAME VALUE' would widen it. The registry write is the same
destination setx uses, done in-process over winreg (stdlib) with no new
allowlist entry -- the exact equivalent of the service skill using psutil
and the security-log skill using win32evtlog instead of PowerShell.

SENSITIVITY. SET changes what every new program in the user's session starts
with -- a staged action that alters the user's own environment, but one the
user can fully reverse by changing the value back. It is PIN-gated the same
way power and service actions are, but it is not L4: an environment value is
not destructive or irreversible (a wrong value is corrected by setting it
again, unlike a deletion). LIST/GET/CANCEL are plain local reads at L1.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import ctypes
import os
import threading
import time
import winreg

import secrets_store
from config import COMMAND_PIN

CONFIRM_WINDOW = 25        # seconds a staged action stays valid
MAX_PIN_ATTEMPTS = 3       # per staged action; same bound as power_skill
MAX_LIST = 20

# Everything else in the process environment came from the system or the
# machine (SystemRoot, ProgramFiles, ...). These are never reported as "the
# user's variables".
_SYSTEM_ONLY = frozenset(
    "ALLUSERSPROFILE APPDATA CommonProgramFiles CommonProgramFiles(x86) "
    "CommonProgramW6432 COMPUTERNAME ComSpec HOMEDRIVE HOMEPATH LOCALAPPDATA "
    "LOGONSERVER NUMBER_OF_PROCESSORS OS PATHEXT PROCESSOR_ARCHITECTURE "
    "PROCESSOR_IDENTIFIER PROCESSOR_LEVEL PROCESSOR_REVISION ProgramData "
    "ProgramFiles ProgramFiles(x86) ProgramW6432 PUBLIC SystemDrive "
    "SystemRoot TEMP TMP USERDOMAIN USERDOMAIN_ROAMINGPROFILE USERNAME "
    "USERPROFILE windir".split())

_pending = {"name": None, "value": None, "at": 0.0, "attempts": 0}
# RLock, not Lock: request() holds _lock across its staged-state checks and
# also acquires _lock via has_pending() -- a plain Lock deadlocks the calling
# thread on every single call (reproduced: request() never returns). Reentrant
# lets the same thread re-enter; different threads still serialize.
_lock = threading.RLock()


def has_pending() -> bool:
    with _lock:
        return bool(_pending["name"]) and \
            (time.time() - _pending["at"] <= CONFIRM_WINDOW)


def list_env(target: str = "") -> str:
    """The user's own environment variables, as a spoken list."""
    want = (target or "").strip().lower()
    ours = []
    for name, value in sorted(os.environ.items()):
        if name in _SYSTEM_ONLY:
            continue
        if not want or want in name.lower() or want in (value or "").lower():
            ours.append(name)
    if not ours:
        return (f"I don't see any user environment variable matching "
                f"{target or 'that'}.")
    shown = ours[:MAX_LIST]
    head = (f"{len(ours)} user environment variable"
            f"{'s' if len(ours) != 1 else ''}: "
            f"{', '.join(shown)}")
    if len(ours) > MAX_LIST:
        head += f", and {len(ours) - MAX_LIST} more"
    return head + "."


def get_env(target: str = "") -> str:
    """One variable's value -- what a program launched right now would see."""
    name = (target or "").strip()
    if not name:
        return "Which environment variable do you want the value of?"
    value = os.environ.get(name)
    if value is None:
        return f"There's no environment variable called {name}."
    if not value:
        return f"{name} is set to an empty value."
    return f"{name} is set to {value}."


def request(name: str = "", value: str = "") -> str:
    """Stages setting name=value. Does NOT persist it."""
    n = (name or "").strip()
    if not n:
        return "Which environment variable do you want to set?"
    n = n.upper()
    if not _NAME_OK.match(n):
        return (f"{name} isn't a name I can set -- environment variable "
                f"names are letters, digits and underscores.")
    if n in _DANGEROUS_NAMES:
        return (f"I won't set {n} -- it controls where Windows or other "
                f"programs load code from, and changing it would affect "
                f"every program you run afterward, including ARGUS's own.")

    with _lock:
        if has_pending():
            current = f"{_pending['name']} = {_pending['value']}"
            return (f"I've already got {current} staged. Say cancel first.")
        _pending["name"] = n
        _pending["value"] = value or ""
        _pending["at"] = time.time()
        _pending["attempts"] = 0
    if not COMMAND_PIN:
        return ("You want me to set "
                f"{n} = {'(empty)' if not value else value}. But no command "
                "PIN is set in config.py, so I can't confirm this. Set "
                "COMMAND_PIN first.")
    return (f"You want me to set "
            f"{n} = {'(empty)' if not value else value}? "
            "Type your PIN in the operator channel to confirm.")


import re as _re
_NAME_OK = _re.compile(r"^[A-Z][A-Z0-9_]{1,254}$")

# _NAME_OK only checks SHAPE. request() authenticates WHO via the PIN, same
# as every confirming skill -- but nothing else here constrains WHAT, unlike
# files_skill (confined roots), apps_skill (extension checks), power/service
# skills (fixed targets). These specific names all control where a LATER
# program -- including ARGUS's own python.exe subprocesses -- loads code or
# resolves paths from, so setting one is not "correct a value later" the way
# an ordinary variable is; it is a standing code-execution redirection until
# manually undone. Denied outright rather than PIN-gated at a higher level,
# because there is no legitimate voice command this codebase supports that
# needs to set any of them.
_DANGEROUS_NAMES = frozenset(
    "PATH PATHEXT PYTHONPATH PYTHONSTARTUP PYTHONHOME COMSPEC PSMODULEPATH "
    "NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES "
    "HOMEDRIVE HOMEPATH USERPROFILE APPDATA LOCALAPPDATA WINDIR SYSTEMROOT "
    "SYSTEMDRIVE COMPUTERNAME LOGONSERVER USERDOMAIN".split())


def confirm(supplied: str = "") -> str:
    """Executes the staged write if the PIN matches. Constant-time compare."""
    with _lock:
        name = _pending["name"]
        value = _pending["value"]
        attempts = _pending["attempts"]
    if not name:
        return "There's nothing waiting for confirmation."
    if time.time() - _pending["at"] > CONFIRM_WINDOW:
        with _lock:
            _pending["name"] = None
        return "That confirmation expired. Ask me again if you still want it."
    if not COMMAND_PIN:
        with _lock:
            _pending["name"] = None
        return "No command PIN is set, so I can't confirm this."

    # ARGUS-SEC-011: the SHARED gate, not a bare verify_pin. One wrong-PIN
    # budget covers every confirming skill, so grinding three guesses here,
    # three on a staged shutdown and three on a service restart stops
    # multiplying the budget. Handles both a migrated PBKDF2 hash and a
    # legacy plaintext PIN, with compare_digest in both branches.
    import security as _security
    if _security.pin_gate_remaining() > 0:
        return (f"Too many wrong PINs across ARGUS. Try again in "
                f"{int(_security.pin_gate_remaining()) + 1} seconds.")
    if not _security.pin_gate_verify(supplied, COMMAND_PIN):
        attempts += 1
        with _lock:
            _pending["attempts"] = attempts
        if attempts >= MAX_PIN_ATTEMPTS:
            with _lock:
                _pending["name"] = None
                _pending["attempts"] = 0
            return ("That's not the right PIN, and that was the last attempt. "
                    "I've cancelled it — ask me again if you meant it.")
        return (f"That's not the right PIN. "
                f"{MAX_PIN_ATTEMPTS - attempts} attempt"
                f"{'s' if MAX_PIN_ATTEMPTS - attempts != 1 else ''} left, "
                f"or say cancel.")

    with _lock:
        _pending["name"] = None
        _pending["attempts"] = 0
    try:
        _persist(name, value)
        return f"Confirmed. Set {name} = {'(empty)' if not value else value}."
    except Exception as e:
        return f"I couldn't set {name}: {type(e).__name__}: {e}"


def _persist(name: str, value: str) -> None:
    """Write to HKCU\\Environment (the user variables key -- what setx uses),
    broadcast WM_SETTINGCHANGE so Windows and new processes see it, and
    update this process's own copy. Refuses nothing that is a valid write."""
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0,
                         winreg.KEY_SET_VALUE)
    try:
        if value:
            winreg.SetValueEx(key, name, 0, winreg.REG_EXPAND_SZ, value)
        else:
            # An empty value sets the variable to empty, matching setx's
            # delete-with-empty semantics for a variable the user names.
            winreg.SetValueEx(key, name, 0, winreg.REG_EXPAND_SZ, "")
    finally:
        winreg.CloseKey(key)
    os.environ[name] = value
    _broadcast()


def _broadcast() -> None:
    """Tell Windows a user environment variable changed. WM_SETTINGCHANGE is
    how Explorer learns about it; without this a new console doesn't see the
    value until the next logon."""
    try:
        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x001A
        SMTO_ABORTIFHUNG = 0x0002
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment",
            SMTO_ABORTIFHUNG, 5000, None)
    except Exception:
        pass


def cancel() -> str:
    """Drops the staged write, whatever it was."""
    with _lock:
        pending = bool(_pending["name"])
        _pending["name"] = None
        _pending["attempts"] = 0
    return "Cancelled." if pending else "Nothing to cancel."