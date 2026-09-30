'ARGUS - Build the Windows app.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
NAME = "ARGUS"
HELPER_NAME = "lsass-helper"
HUD_V2_DIST = os.path.join(ROOT, "hud-v2", "dist")
HUD_V2_FILES = (
    "index.html",
    os.path.join("assets", "argus-waking.mp4"),
    os.path.join("assets", "core-idle.jpg"),
    os.path.join("assets", "core-alert.jpg"),
    os.path.join("assets", "splash.png"),
)


def fail(msg):
    print(f"\n  ERROR: {msg}\n")
    sys.exit(1)


def require_hud_v2_tree(root: str, label: str) -> None:
    """Fail closed unless the Vite entry and every local entry asset exist."""
    missing = [rel for rel in HUD_V2_FILES
               if not os.path.isfile(os.path.join(root, rel))]
    if missing:
        fail(f"{label} is incomplete: {', '.join(missing)}")
    index = os.path.join(root, "index.html")
    try:
        with open(index, encoding="utf-8") as f:
            html = f.read()
    except OSError as e:
        fail(f"{label} index cannot be read: {e}")
    refs = re.findall(r"(?:src|href)=[\"']([^\"']+)[\"']", html,
                      flags=re.IGNORECASE)
    local = []
    for ref in refs:
        if ref.startswith(("http:", "https:", "//", "data:", "#")):
            continue
        rel = ref.split("?", 1)[0].lstrip("./").replace("/", os.sep)
        full = os.path.abspath(os.path.join(root, rel))
        if os.path.commonpath((os.path.abspath(root), full)) != os.path.abspath(root):
            fail(f"{label} index references an escaping asset: {ref}")
        local.append((ref, full))
    js = [ref for ref, full in local
          if re.fullmatch(r"assets[\\/]index-[^\\/]+\.js", ref.lstrip("./"))
          and os.path.isfile(full)]
    css = [ref for ref, full in local
           if re.fullmatch(r"assets[\\/]index-[^\\/]+\.css", ref.lstrip("./"))
           and os.path.isfile(full)]
    if not js:
        fail(f"{label} has no packaged Vite index-*.js bundle")
    if not css:
        fail(f"{label} has no packaged Vite index-*.css bundle")
    absent = [ref for ref, full in local if not os.path.isfile(full)]
    if absent:
        fail(f"{label} index references missing assets: {', '.join(absent)}")


def add_data(source: str, destination: str) -> str:
    """Return PyInstaller's single-argument data-bundle syntax."""
    return f"--add-data={source}{os.pathsep}{destination}"


def add_tree(source: str, destination: str) -> list[str]:
    """Package every regular release file explicitly, preserving subpaths.

    PyInstaller's directory form produced a partial V2 tree in a prior build;
    explicit file entries keep hashed JS chunks, CSS, media, fonts, and future
    nested Vite outputs under the intended runtime root.
    """
    entries: list[str] = []
    for directory, dirs, files in os.walk(source):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            relative_dir = os.path.relpath(directory, source)
            target = destination if relative_dir == "." else os.path.join(destination, relative_dir)
            entries.append(add_data(full, target))
    return entries


def preflight():
    """Catch the common failures before spending ten minutes on a build."""
    print("Preflight checks...\n")

    try:
        import PyInstaller  # noqa: F401
        print("  [ok] PyInstaller")
    except ImportError:
        fail("PyInstaller not installed. Run: pip install pyinstaller")

    if not os.path.exists(os.path.join(ROOT, "argus.py")):
        fail("argus.py not found. Run this from inside the argus folder.")
    print("  [ok] argus.py")

    require_hud_v2_tree(HUD_V2_DIST, "hud-v2/dist")
    print("  [ok] hud-v2/dist release assets")

    voices = os.path.join(ROOT, "voices")
    if not os.path.isdir(voices):
        fail("voices\\ folder not found. Download a Piper voice first.")
    onnx = [f for f in os.listdir(voices) if f.endswith(".onnx")]
    if not onnx:
        fail("No .onnx voice in voices\\. Download one from huggingface.co/rhasspy/piper-voices")
    print(f"  [ok] voice model ({onnx[0]})")

    # Verify the configured voice actually exists — a mismatch here builds fine
    # and then fails silently at runtime, which is far more annoying to debug.
    try:
        sys.path.insert(0, ROOT)
        import config
        cfg_voice = os.path.join(ROOT, config.PIPER_MODEL_PATH.replace("/", os.sep))
        if not os.path.exists(cfg_voice):
            fail(
                f"config.py points at {config.PIPER_MODEL_PATH} but that file doesn't exist.\n"
                f"  Found instead: {', '.join(onnx)}\n"
                f"  Fix PIPER_MODEL_PATH in config.py before building."
            )
        print(f"  [ok] config.py voice path matches")
        print(f"  [ok] model: {config.OLLAMA_MODEL}")
    except Exception as e:
        fail(f"config.py couldn't be loaded: {e}")

    for f in ("security.py", "paths.py", "brain.py", "listener.py",
              "ipc.py", "stt_worker.py", "tts_worker.py"):
        if not os.path.exists(os.path.join(ROOT, f)):
            fail(f"{f} missing — the build would be incomplete.")
    print("  [ok] core modules present")

    missing = []
    for mod in ("webview", "faster_whisper", "psutil", "sounddevice"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        fail(f"Missing packages: {', '.join(missing)}\n  Run: pip install -r requirements.txt")
    print("  [ok] all runtime packages present")

    # The helper must exist as a source file or the second build fails halfway
    # through a long two-artefact build.
    if not os.path.exists(os.path.join(ROOT, "threatmon", "lsass_agent.py")):
        fail("threatmon\\lsass_agent.py not found — the LSASS elevated helper "
             "cannot be built.")
    print("  [ok] threatmon/lsass_agent.py (LSASS elevated helper)")

    print()


def build():
    preflight()

    # Build V2 immediately before packaging it. This avoids shipping an old
    # dist directory even when the PyInstaller command itself succeeds.
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    if not npm:
        fail("npm was not found; HUD V2 cannot be rebuilt for packaging.")
    v2_build = subprocess.run([npm, "run", "build"],
                              cwd=os.path.join(ROOT, "hud-v2"),
                              shell=(os.name == "nt"))
    if v2_build.returncode != 0:
        fail("HUD V2 production build failed; refusing to package stale assets.")
    require_hud_v2_tree(HUD_V2_DIST, "hud-v2/dist after build")

    # Clear old build artifacts — stale ones cause confusing failures.
    for d in ("build", "dist"):
        p = os.path.join(ROOT, d)
        if os.path.isdir(p):
            print(f"Removing old {d}\\ ...")
            shutil.rmtree(p, ignore_errors=True)

    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onedir",
        "--name", NAME,
        "--windowed",
        "--collect-all", "faster_whisper",
        "--collect-all", "openwakeword",
        "--collect-all", "onnxruntime",
        "--collect-all", "ctranslate2",
        "--collect-all", "piper",
        "--collect-all", "webview",
        "--collect-all", "tokenizers",
        # uvicorn resolves its event loop and protocol implementations by
        # STRING at runtime -- uvicorn.loops.auto imports "uvicorn.loops.asyncio"
        # by name, and the protocol .auto modules do the same. PyInstaller's
        # static analysis cannot follow that, so listing only the .auto shims
        # bundled the chooser without the thing it chooses.
        #
        # The result in the packaged app: Server.run() returned immediately
        # WITHOUT raising, the orchestrator thread ended silently, and the
        # launcher reported "the orchestrator did not respond within 40
        # seconds" before quitting. Double-clicked, that looked like nothing
        # happening at all; from a terminal the same build appeared to work
        # because the failure text was visible and the timing looked like a
        # slow start.
        "--collect-all", "uvicorn",
        "--hidden-import", "uvicorn.logging",
        "--hidden-import", "uvicorn.loops.auto",
        "--hidden-import", "uvicorn.loops.asyncio",
        "--hidden-import", "uvicorn.protocols.http.auto",
        "--hidden-import", "uvicorn.protocols.http.h11_impl",
        "--hidden-import", "uvicorn.protocols.http.httptools_impl",
        "--hidden-import", "uvicorn.protocols.websockets.auto",
        "--hidden-import", "uvicorn.protocols.websockets.websockets_impl",
        "--hidden-import", "uvicorn.protocols.websockets.wsproto_impl",
        "--hidden-import", "uvicorn.lifespan.on",
        "--hidden-import", "uvicorn.lifespan.off",
        "--hidden-import", "h11",
        "--hidden-import", "anyio",
        "--hidden-import", "sniffio",
        "--hidden-import", "comtypes",
        # tzdata is DATA, not code: PyInstaller's import scan cannot see it,
        # because zoneinfo reaches it through importlib.resources at runtime
        # rather than by importing it. Without collect-all the packaged build
        # has an empty TZPATH and every timezone name fails -- the exact
        # failure the source tree had before tzdata was installed, except only
        # in the shipped artefact, which is the worst place to find it.
        "--collect-all", "tzdata",
        "--hidden-import", "pycaw",
        "--hidden-import", "pygetwindow",
        "--hidden-import", "plyer.platforms.win.notification",
        "--hidden-import", "security",
        "--hidden-import", "paths",
        "--hidden-import", "brain",
        "--hidden-import", "intent",
        "--hidden-import", "router",
        "--hidden-import", "listener",
        "--hidden-import", "tts",
        "--hidden-import", "ollama_client",
        # Stage 2 worker processes. These are only ever reached as
        # multiprocessing spawn targets, never by a literal import statement
        # PyInstaller's analyser can follow, so without naming them here the
        # build succeeds and the voice stack then fails to start at runtime.
        "--hidden-import", "ipc",
        "--hidden-import", "stt_worker",
        "--hidden-import", "tts_worker",
        # Reached only from inside endpoint functions, never at module level.
        "--hidden-import", "settings",
        # faceauth is imported INSIDE functions on purpose (auth._verify_face
        # and router's face branch) so that auth.py -- which every gated command
        # goes through -- never pays for loading OpenCV. Named here because a
        # function-level import is exactly the kind the analyser is least
        # reliable at following, and the failure mode is silent: face works from
        # source and the panel says "not available" in the exe.
        "--hidden-import", "faceauth",
        "--hidden-import", "threatmon",
        "--hidden-import", "threatmon.persistence",
        "--hidden-import", "threatmon.privacy",
        "--hidden-import", "threatmon.netconfig",
        "--hidden-import", "skills.cleanup_skill",
        # intent.py ships as DATA as well as code. The /skills endpoint builds
        # the command list by reading intent.py's source and pulling out the
        # skill/action pairs it declares, so the panel can never claim a
        # command that does not exist. Frozen, there are no .py files on disk
        # -- without this the read fails and the Skills panel is empty in the
        # exe while being complete when run from source.
        add_data(os.path.join(ROOT, "intent.py"), "."),
        *add_tree(HUD_V2_DIST, "hud-v2/dist"),
        add_data(os.path.join(ROOT, "voices"), "voices"),
        add_data(os.path.join(ROOT, "skills"), "skills"),
        # REQUEST ELEVATION AT LAUNCH (UAC prompt every start).
        #
        # What it buys: the build can harden its own install ACLs at first boot
        # (sandbox.harden_acls_if_needed) instead of needing harden_acls.ps1 run
        # by hand after every rebuild.
        #
        # What it does NOT buy, and this is easy to assume wrongly: the
        # stripped MAIN process cannot see an elevated credential dump. main.py
        # calls sandbox.drop_privileges() at startup, which REMOVES
        # SeDebugPrivilege permanently and deliberately, so the elevated token
        # is handed back before any skill or model runs. That is not undone by
        # keeping the privilege IN this process: the second artefact below
        # (dist\lsass-helper\lsass-helper.exe) is a separate ONE-job helper that
        # holds SeDebugPrivilege and does ONLY the handle-table scan. The model
        # process stays stripped forever; the helper never gains a model.
        "--uac-admin",
        # faceauth.py reads the Haar cascade XML out of cv2/data/ at runtime.
        # A --hidden-import alone bundles the module WITHOUT that data
        # directory, so face detection would work from source and fail only
        # inside the exe -- collect-all is what brings the cascades.
        "--collect-all", "cv2",
        # Bundled so the elevated build can harden its own ACLs at first boot.
        add_data(os.path.join(ROOT, "tools", "harden_acls.ps1"), "tools"),
    ]

    # SPLASH SCREEN.
    #
    # Reported directly: "the exe itself opens too slow when you press it at
    # first, after 10-15 seconds." That time is real -- a 0.6 GB onedir bundle
    # has to be paged in and virus-scanned on a cold start -- and none of it is
    # avoidable by making the Python faster, because argus.py's own imports are
    # already down to os/sys/threading/time/paths/config.
    #
    # What IS fixable is that nothing appears while it happens. The bootloader
    # paints this image before the interpreter starts, so the app acknowledges
    # the click almost immediately instead of looking like it ignored it.
    # argus.py closes it the moment the HUD window is up.
    splash = os.path.join(ROOT, "hud-v2", "dist", "assets", "splash.png")
    if os.path.exists(splash):
        args += ["--splash", splash]
        print("Splash screen: hud-v2/dist/assets/splash.png")
    else:
        print("WARNING: no splash image; first launch will show nothing "
              "for several seconds.")

    icon = os.path.join(ROOT, "argus.ico")
    if os.path.exists(icon):
        args += ["--icon", icon]
        print("Using argus.ico\n")

    args.append(os.path.join(ROOT, "argus.py"))

    print("Building. This takes 5-15 minutes and produces a large folder.\n")
    result = subprocess.run(args, cwd=ROOT)

    if result.returncode != 0:
        print("\n" + "=" * 60)
        print("BUILD FAILED. Most common causes:")
        print("  1. Antivirus blocking PyInstaller — add an exclusion for this folder")
        print("  2. A package installed outside this venv — check venv is active")
        print("  3. Out of disk space — the build needs several GB free")
        print("=" * 60)
        sys.exit(result.returncode)

    out = os.path.join(ROOT, "dist", NAME)
    exe = os.path.join(out, f"{NAME}.exe")

    if not os.path.exists(exe):
        fail("Build reported success but ARGUS.exe wasn't produced.")

    packaged_v2 = os.path.join(out, "_internal", "hud-v2", "dist")
    require_hud_v2_tree(packaged_v2, "packaged HUD V2")
    print(f"  [ok] packaged HUD V2 ({packaged_v2})")

    size = sum(
        os.path.getsize(os.path.join(dp, f))
        for dp, _dn, fn in os.walk(out) for f in fn
    ) / (1024 ** 3)

    # Establish the tamper baseline for what was just built. Without this the
    # packaged app reports "not sealed -- no baseline to compare against" and
    # its anti-tampering does nothing at all, which is the state every build
    # before this one shipped in. Sealing here rather than on first launch
    # means the baseline is the build output, not whatever the folder happens
    # to contain by the time someone first runs it.
    if "--no-seal" in sys.argv:
        print("\nPackage validation passed; frozen baseline intentionally not sealed.")
    else:
      try:
        # preflight() imported config into its own local scope, so the name is
        # not available here -- the seal step failed with NameError and the
        # build reported success while shipping an unsealed baseline.
        import config as _config
        import integrity
        m = integrity.seal_frozen(out, reason=f"build {_config.APP_VERSION}")
        signed = "signed" if m["signed"] else "UNSIGNED (no DPAPI)"
        print(f"\nIntegrity baseline sealed: {len(m['entries'])} files, {signed}")
      except Exception as e:
        print(f"\nWARNING: could not seal the integrity baseline: {e}")
        print("  The app will run but will report itself as unverified.")

    # ── second artefact: the LSASS elevated helper ─────────────────────────
    # A ONE-job process that holds SeDebugPrivilege so the stripped
    # orchestrator can still see an elevated credential dump (T1003.001). Built
    # WITHOUT --uac-admin (the task's /RL HIGHEST does the elevation, lazily and
    # in the same-user context the pipe's DACL requires) and WITHOUT any of the
    # model/HUD/voice collects: the smaller and more single-purpose this binary
    # is, the safer it is to hold the one privilege the main app gives up.
    # A helper build failure is NOT fatal to the build: the app still works,
    # and falls back to the in-process (non-elevated) LSASS scan.
    print("Building the LSASS elevated helper (lsass-helper.exe)...")
    helper_args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onedir",
        "--name", HELPER_NAME,
        "--windowed",
        # psutil is imported under a guard (best-effort command-line read of the
        # peer); name it so the bundle never depends on the analyser looking
        # inside a try/except. It may be absent at runtime -- peer_cmdline()
        # tolerates that -- but the frozen helper should try to have it.
        "--hidden-import", "psutil",
        # The helper loads lsass.py and lsass_peer.py BY FILE (see
        # lsass_agent._load_leaf) so that importing it never executes
        # threatmon/__init__.py -- which would eagerly drag in the other twelve
        # detectors and unmake the "small, single-purpose" property the whole
        # split rests on. Ship those two leaf modules as data so the frozen
        # helper finds them next to itself in _internal/threatmon/.
        add_data(os.path.join(ROOT, "threatmon", "lsass.py"), "threatmon"),
        add_data(os.path.join(ROOT, "threatmon", "lsass_peer.py"), "threatmon"),
        os.path.join(ROOT, "threatmon", "lsass_agent.py"),
    ]
    hres = subprocess.run(helper_args, cwd=ROOT)
    helper_out = os.path.join(ROOT, "dist", HELPER_NAME)
    if hres.returncode != 0 or not os.path.exists(
            os.path.join(helper_out, f"{HELPER_NAME}.exe")):
        print("\nWARNING: the elevated helper did not build.")
        print("  ARGUS still works — LSASS coverage falls back to the ")
        print("  in-process (non-elevated) scan, reported honestly as degraded.")
        print("  Fix and install later with: python tools/install_lsass_helper.py")
    else:
        # seal_frozen() stores one baseline per user, which the main ARGUS
        # process reads at launch. The optional helper is a separate binary
        # and does not consume that baseline; sealing it here would overwrite
        # the just-sealed ARGUS manifest with a helper-only file set.
        print("  [ok] helper built (main ARGUS integrity baseline retained)")
        print("  [ok] install it once, from an ELEVATED shell:")
        print(f"        python tools/install_lsass_helper.py  ({HELPER_NAME}.exe)")

    print("\n" + "=" * 60)
    print("BUILD COMPLETE")
    print(f"  App:  {exe}")
    print(f"  Size: {size:.1f} GB")
    print("=" * 60)
    print("\nNext:")
    print("  1. Test it — double-click ARGUS.exe")
    print("  2. Move the whole ARGUS folder wherever you want it")
    print("  3. Run: python install_startup.py    (launch at login)")
    print("  4. Install the LSASS elevated helper (covers ELEVATED")
    print("     credential dumps), from an ELEVATED shell:")
    print("       python tools/install_lsass_helper.py")
    print("  5. HARDEN the install against DLL planting (ARGUS-SEC-005),")
    print("     from an ELEVATED PowerShell:")
    print(f"       .\\tools\\harden_acls.ps1 -App \"{out}\"")
    print("     Until you do, anything running as your user can drop a DLL")
    print("     beside the exe and have it load at the next launch.")
    print("\nOllama must be installed and running separately.")
    print("\nNOTE: this executable is unsigned. Windows SmartScreen will warn on")
    print("first run (More info -> Run anyway), and some antivirus flags")
    print("PyInstaller output as suspicious. That's expected for a self-built")
    print("app; signing requires a paid code-signing certificate.")


if __name__ == "__main__":
    build()
