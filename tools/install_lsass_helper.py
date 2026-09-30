'ARGUS - Install / uninstall the LSASS elevated helper.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import ctypes
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TASK = "ARGUS-LSASS-Helper"


def is_elevated() -> bool:
    """True when this process holds an elevated (admin-role) token."""
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def helper_target() -> str:
    """The command the scheduled task should run, as ONE /TR string.

    Prefers the frozen, self-contained helper built by build_exe.py (no
    console, no interpreter needed there); falls back to pythonw + the agent
    script for source trees. pythonw so the helper gets no console window at
    logon; it has no stdout to show anyway.
    """
    frozen = os.path.join(ROOT, "dist", "lsass-helper", "lsass-helper.exe")
    if os.path.isfile(frozen):
        return f'"{frozen}"'

    script = os.path.join(ROOT, "threatmon", "lsass_agent.py")
    if not os.path.isfile(script):
        raise SystemExit(f"ERROR: {script} not found.\n"
                         "  Run this from inside the argus-os folder.")
    pythonw = os.path.join(os.path.dirname(sys.executable or ""), "pythonw.exe")
    if not os.path.isfile(pythonw) or not sys.executable:
        pythonw = sys.executable or "pythonw"
    return f'"{pythonw}" "{script}"'


def _schtasks(*args) -> subprocess.CompletedProcess:
    return subprocess.run(["schtasks", *args], capture_output=True, text=True)


def _target_frozen() -> bool:
    return bool(helper_target().startswith('"') and "lsass-helper.exe" in helper_target())


def install() -> int:
    if not is_elevated():
        print("REQUIRED: run this from an ELEVATED prompt (administrator).\n"
              "Open PowerShell as administrator, or run: ! python "
              "tools/install_lsass_helper.py\n"
              "A non-elevated registration would create a task that then fails "
              "to run with highest privileges -- refusing instead.")
        return 2

    target = helper_target()
    print(f"Registering task {TASK} ...")
    print(f"  command: {target}")
    r = _schtasks("/Create", "/TN", TASK, "/TR", target,
                  "/SC", "ONLOGON", "/RL", "HIGHEST", "/F")
    if r.returncode != 0:
        print(f"  schtasks failed:\n{r.stderr.strip() or r.stdout.strip()}")
        return 1
    print("  [ok] task registered (ONLOGON, HIGHEST).")
    print("Install complete. It takes effect at the next logon; from a running")
    print("session, sign out and back in -- or start it now by hand:")
    print(f"  schtasks /Run /TN {TASK}")
    return 0


def remove() -> int:
    # Best-effort stop of a helper that is currently serving, BEFORE the task
    # is deleted: the orchetor would otherwise keep talking to a ghost.
    try:
        _request_shutdown()
    except Exception:
        pass
    r = _schtasks("/Delete", "/TN", TASK, "/F")
    if r.returncode != 0:
        print(f"  schtasks failed:\n{r.stderr.strip() or r.stdout.strip()}")
        return 1
    print("  [ok] task removed.")
    return 0


def _request_shutdown():
    """Ask a running helper to exit, over its pipe. Best-effort."""
    sys.path.insert(0, ROOT)
    from threatmon import lsass_peer

    sid = lsass_peer.current_sid()
    if not sid:
        return
    h = lsass_peer.connect_pipe(lsass_peer.pipe_name(sid))
    if not h:
        return
    try:
        spid = lsass_peer.named_pipe_server_pid(h)
        image, cmdline = lsass_peer.peer_identity(spid)
        ok, _ = lsass_peer.peer_ok("server", image, cmdline)
        if not ok:
            return
        lsass_peer.client_rpc(h, {"cmd": lsass_peer.CMD_SHUTDOWN})
    finally:
        try:
            import ctypes as _c
            _c.windll.kernel32.CloseHandle(h)
        except Exception:
            pass


def status() -> int:
    target = helper_target()
    print(f"Task:        {TASK}")
    print(f"Command:     {target}")
    print(f"Registered:  {'binary (frozen)' if _target_frozen()
                          else 'pythonw + script'}")
    r = _schtasks("/Query", "/TN", TASK, "/FO", "LIST", "/V")
    if r.returncode != 0:
        print("  not registered. Install with: python tools/install_lsass_helper.py")
        print("  (requires an elevated shell)")
        return 1
    for line in r.stdout.splitlines():
        if any(k in line for k in ("Task Name", "Status", "Logon Mode", "Schedule Type",
                                   "Result", "Run As User", "Task To Run", "Scheduled Task State")):
            print("  " + line.strip())
    return 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a.strip().startswith("--")]
    if "--remove" in args:
        raise SystemExit(remove())
    if "--status" in args:
        raise SystemExit(status())
    raise SystemExit(install())