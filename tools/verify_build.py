"""
ARGUS - Check the BUILT app, not the source.

    python tools/verify_build.py

Running the suites from source proves very little about the packaged app.
PyInstaller changes what exists on disk (no .py files), what sys.stdout is
(None under --windowed), which modules got collected, and where the payload
lives (_internal, not beside the exe). Every one of those has broken a build
that passed every test:

  * /skills reads intent.py's SOURCE to build its command list -- empty in the
    exe until intent.py was bundled as data.
  * the integrity manifest scanned the exe's own folder, which in a
    PyInstaller 6 onedir build contains one file, so anti-tampering covered
    the launcher stub and nothing else.
  * plugins looked up "skills/x.py" while the frozen manifest keys them as
    "_internal/skills/x.py", so a completely intact build reported every
    skill as modified and refused to boot.

None of those were visible from source. This launches the real executable and
asks it.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(ROOT, "dist", "ARGUS", "ARGUS.exe")
API = "http://127.0.0.1:8420"
TOKEN_FILE = os.path.join(os.environ.get("LOCALAPPDATA", ""), "ARGUS",
                          "session.token")

fails = []


def check(label, cond, detail=""):
    if not cond:
        fails.append(label)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {label}{'  ' + detail if detail else ''}")


def get(path, token, timeout=25):
    req = urllib.request.Request(API + path, headers={"x-argus-token": token})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def post(path, token, payload, timeout=25):
    req = urllib.request.Request(
        API + path, method="POST", data=json.dumps(payload).encode("utf-8"),
        headers={"x-argus-token": token, "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def main() -> int:
    if not os.path.exists(EXE):
        print(f"No build at {EXE}. Run: python build_exe.py")
        return 1

    print(f"Launching {EXE}")
    before = os.path.getmtime(TOKEN_FILE) if os.path.exists(TOKEN_FILE) else 0
    t0 = time.time()
    try:
        proc = subprocess.Popen([EXE], cwd=os.path.dirname(EXE))
    except OSError as e:
        # WinError 740. The build requests elevation (build_exe.py --uac-admin),
        # and CreateProcess does not raise a UAC prompt -- only the shell does.
        # Fall back to ShellExecute "runas", which prompts once and starts the
        # app elevated. Without this the verifier cannot check an elevated build
        # at all, and would report a perfectly good exe as broken.
        if getattr(e, "winerror", None) != 740:
            raise
        print("  build requires elevation — asking Windows for a UAC prompt")
        import ctypes
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", EXE, None, os.path.dirname(EXE), 1)
        if int(rc) <= 32:
            print(f"  elevation was declined or failed (ShellExecute returned "
                  f"{rc}). Approve the UAC prompt, or run this verifier from "
                  f"an elevated PowerShell.")
            return 1
        proc = None            # started detached; nothing to wait on directly

    token, deadline = None, time.time() + 180
    while time.time() < deadline:
        time.sleep(1)
        if os.path.exists(TOKEN_FILE) and os.path.getmtime(TOKEN_FILE) > before:
            candidate = open(TOKEN_FILE, encoding="utf-8").read().strip()
            if candidate:
                try:
                    get("/health", candidate, timeout=4)
                    token = candidate
                    break
                except (urllib.error.URLError, OSError, ValueError):
                    pass
    if not token:
        print("  the exe did not answer within 180s")
        print(f"  see {os.path.join(os.path.dirname(TOKEN_FILE), 'startup-failure.log')}")
        if proc is not None:
            proc.terminate()
        else:
            subprocess.run(["taskkill", "/F", "/IM", "ARGUS.exe", "/T"],
                           capture_output=True)
        return 1

    startup = time.time() - t0
    print(f"  API answered after {startup:.1f}s\n")

    try:
        print("=== identity and licence ===")
        a = get("/about", token)
        check("reports itself as a frozen build", a["build"] == "frozen", a["build"])
        check("author is stated", bool(a.get("author")), a.get("author", ""))
        check("copyright is stated", "Copyright" in a.get("copyright", ""),
              a.get("copyright", ""))
        check("creation date is stated", bool(a.get("created")), a.get("created", ""))
        check("licence is GPL-3.0-or-later", a["licence"] == "GPL-3.0-or-later")

        print("\n=== anti-tampering is actually active ===")
        r = get("/security-report", token)
        i = r["integrity"]
        check("the manifest is sealed", i["sealed"],
              "" if i["sealed"] else
              "NOT SEALED — the build did not establish a baseline")
        check("the signature is valid", i["signature_valid"])
        check("it covers more than the launcher stub", i["files"] > 5,
              f"{i['files']} files")
        check("nothing is reported modified", i["ok"], i["summary"])
        check("the audit chain is intact or honestly unanchored",
              r["audit"]["chain_intact"], r["audit"]["chain_note"])

        print("\n=== the panels work in the exe ===")
        sk = get("/skills", token)
        check("intent.py was readable inside the bundle",
              not sk.get("unreadable"), str(sk.get("unreadable")))
        check("the command list is populated", sk["count"] > 0,
              f"{sk['count']} commands in {len(sk['groups'])} groups")
        s = get("/settings", token)
        check("settings are returned", len(s["fields"]) > 0)
        check("settings.json lives outside the bundle", "dist" not in s["path"],
              s["path"])
        check("locked fields are marked non-editable",
              all(not f["editable"] for f in s["fields"] if f["class"] == "locked"))

        print("\n=== the frozen server refuses privileged writes ===")
        w = post("/settings", token, {"changes": {"AUTH_ENABLED": False,
                                                  "CLOUD_ENABLED": True}})
        check("security settings are refused", w["applied"] == []
              and len(w["rejected"]) == 2, str(w["rejected"])[:80])
        w = post("/settings", token, {"changes": {"DEFAULT_CITY": "Nukus"}})
        check("an ordinary setting still applies",
              w["applied"] == ["DEFAULT_CITY"], str(w))
        post("/settings/reset", token, {"name": ""})

        print("\n=== new skills survived the build ===")
        pairs = {(g["skill"], a_["action"])
                 for g in sk["groups"] for a_ in g["actions"]}
        check("storage/free is present", ("storage", "free") in pairs)
        check("storage/largest is present", ("storage", "largest") in pairs)
        check("pc/battery is present", ("pc", "battery") in pairs)

        print("\n=== startup ===")
        check("the splash image was bundled",
              os.path.exists(os.path.join(ROOT, "dist", "ARGUS", "_internal",
                                          "hud", "img", "splash.png"))
              or os.path.exists(os.path.join(ROOT, "hud", "img", "splash.png")))
        print(f"  [note] API ready in {startup:.1f}s "
              f"(a cold first launch is slower; the splash covers it)")

    finally:
        # proc is None when the app was started elevated via ShellExecute --
        # there is no handle to wait on, and an unelevated terminate() would be
        # refused anyway. taskkill (which runs elevated if this process is)
        # remains the reliable stop in both cases.
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=25)
            except subprocess.TimeoutExpired:
                proc.kill()
        subprocess.run(["taskkill", "/F", "/IM", "ARGUS.exe", "/T"],
                       capture_output=True)

    print("\n" + "=" * 66)
    if fails:
        print(f"{len(fails)} FAILED: {fails}")
        return 1
    print("BUILD VERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
