"""
ARGUS - Startup registration.

Adds ARGUS to the Windows Startup folder so it launches when you log in.
Uses a shortcut in shell:startup rather than a registry Run key — it's visible,
user-editable, and removable from the same folder without touching the registry.

Run:  python install_startup.py           (register)
      python install_startup.py --remove  (unregister)
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import sys

STARTUP_DIR = os.path.join(
    os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup"
)
SHORTCUT = os.path.join(STARTUP_DIR, "ARGUS.lnk")


def find_target() -> str:
    """Prefers a built exe; falls back to running argus.py with pythonw."""
    root = os.path.dirname(os.path.abspath(__file__))

    exe = os.path.join(root, "dist", "ARGUS", "ARGUS.exe")
    if os.path.exists(exe):
        return exe

    exe = os.path.join(root, "ARGUS.exe")
    if os.path.exists(exe):
        return exe

    script = os.path.join(root, "argus.py")
    if os.path.exists(script):
        pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        if os.path.exists(pythonw):
            return f'"{pythonw}" "{script}"'
        return f'"{sys.executable}" "{script}"'

    print("Couldn't find ARGUS.exe or argus.py.")
    sys.exit(1)


def install():
    try:
        import win32com.client
    except ImportError:
        print("Needs pywin32. Run: pip install pywin32")
        sys.exit(1)

    target = find_target()
    root = os.path.dirname(os.path.abspath(__file__))

    shell = win32com.client.Dispatch("WScript.Shell")
    link = shell.CreateShortCut(SHORTCUT)

    if target.startswith('"'):
        parts = target.split('" "')
        link.TargetPath = parts[0].strip('"')
        link.Arguments = '"' + parts[1] if len(parts) > 1 else ""
    else:
        link.TargetPath = target
        link.WorkingDirectory = os.path.dirname(target)

    link.WorkingDirectory = link.WorkingDirectory or root
    link.Description = "ARGUS"
    link.save()

    print(f"Registered. ARGUS will start when you log in.\n  {SHORTCUT}")
    print("\nNote: Ollama must also be running at login. Its installer normally")
    print("sets that up — check Task Manager > Startup if ARGUS can't reach it.")


def remove():
    if os.path.exists(SHORTCUT):
        os.remove(SHORTCUT)
        print("Removed from startup.")
    else:
        print("Wasn't registered.")


if __name__ == "__main__":
    if "--remove" in sys.argv:
        remove()
    else:
        install()
