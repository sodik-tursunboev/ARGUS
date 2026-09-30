"""
ARGUS - Single entry point.

Starts the orchestrator API, the voice listener, and the HUD in one process.
Greets you on launch, reports system health, and waits.

Run:  python argus.py

Copyright (C) 2026 Sodik Tursunboev

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.

See THIRD-PARTY-NOTICES.md for the licences of bundled dependencies, and for
why GPL-3.0 is the licence this project can actually ship under.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import sys
import threading
import time

import paths

# BEFORE config, uvicorn, or anything that touches logging. A --windowed build
# starts with sys.stdout set to None, and uvicorn's formatter calls
# sys.stdout.isatty() while configuring logging -- which is why the packaged
# app only ever started from a terminal. See paths.ensure_std_streams.
paths.ensure_std_streams()

# Only chdir when running as a script. A frozen app must not assume the bundle
# directory is the working directory.
if not paths.is_frozen():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

from config import ASSISTANT_NAME, USER_NAME

BANNER = r"""
    _    ____   ____ _   _ ____
   / \  |  _ \ / ___| | | / ___|
  / _ \ | |_) | |  _| | | \___ \
 / ___ \|  _ <| |_| | |_| |___) |
/_/   \_\_| \_\\____|\___/|____/
              local-first  |  cloud opt-in
"""


def _silence_windows_socket_noise():
    """Windows' proactor event loop raises ConnectionResetError when a client
    goes away mid-request — which the HUD does constantly as it polls. The
    exception is harmless but floods the console with tracebacks."""
    import asyncio

    # BUGFIX: this used to test for Windows by doing
    #   getattr(asyncio, "WindowsProactorEventLoopPolicy", None)
    # and then never using the value for anything but a None check. On Python
    # 3.14 merely TOUCHING that attribute emits a DeprecationWarning naming a
    # future Python version, which is printed to stderr the moment ARGUS
    # starts. In the packaged build that lands on a black console before the
    # window appears and reads exactly like a fatal version error -- it was
    # reported as "ERROR: Python 3.14 something" and assumed to be the reason
    # the app would not open. It was never an error, and never fatal.
    # sys.platform answers the actual question without touching deprecated API.
    if sys.platform != "win32":
        return

    def handler(loop, context):
        exc = context.get("exception")
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError)):
            return
        loop.default_exception_handler(context)

    original = asyncio.new_event_loop

    def patched():
        loop = original()
        loop.set_exception_handler(handler)
        return loop

    asyncio.new_event_loop = patched


ORCHESTRATOR_PORT = 8420
_instance_mutex = None


def acquire_instance_lock(name: str = "Local\\ARGUS_Main_8420") -> bool:
    """Serialize Windows launches before either copy can publish a token.

    A port probe alone has a boot-time gap: two copies can both see the port
    free, import the API (and publish different credentials), then only one
    succeeds in binding. The OS releases this handle if ARGUS exits/crashes.
    """
    if sys.platform != "win32":
        return True
    import ctypes

    global _instance_mutex
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = (ctypes.c_void_p, ctypes.c_bool,
                                      ctypes.c_wchar_p)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = ctypes.c_bool
    handle = kernel32.CreateMutexW(None, False, name)
    if not handle:
        raise OSError(ctypes.get_last_error(), "ARGUS instance lock unavailable")
    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        kernel32.CloseHandle(handle)
        return False
    _instance_mutex = handle
    return True

# Set by start_orchestrator when it dies, so the startup check can report the
# REAL reason instead of guessing. Previously the thread died silently and the
# only thing the user ever saw was a canned "Is Ollama running?".
_orchestrator_error = {"exc": None, "tb": ""}


def port_in_use(port: int = ORCHESTRATOR_PORT) -> bool:
    """True when something is already listening. Checked BEFORE starting, so a
    second copy of ARGUS fails in a second with an accurate message rather than
    after a 40-second timeout with a misleading one."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def start_orchestrator():
    # EVERYTHING is inside the try, imports included.
    #
    # These two imports used to sit above it. This runs on a background thread,
    # so an ImportError here killed the thread with a traceback written to a
    # stderr that a --windowed build does not have -- leaving
    # _orchestrator_error empty and the launcher able to say only "the
    # orchestrator did not respond within 40 seconds". The cause was one frame
    # away the whole time and nothing could see it.
    try:
        import uvicorn
        from main import app

        _silence_windows_socket_noise()
        # Single Config — the previous version built one, discarded it, then
        # built another, which was just wasted work.
        config = uvicorn.Config(app, host="127.0.0.1", port=ORCHESTRATOR_PORT,
                                log_level="warning")
        uvicorn.Server(config).run()
        # Returning WITHOUT raising is its own failure mode and was invisible.
        # In the packaged build run() came straight back, the thread ended
        # quietly, _orchestrator_error stayed empty, and main() could only
        # report "the orchestrator did not respond within 40 seconds" -- true,
        # but it named a symptom and not a cause.
        _orchestrator_error["exc"] = RuntimeError(
            "uvicorn returned immediately without serving (usually a missing "
            "loop/protocol implementation in a frozen build)")
    except Exception as e:
        # This runs on a daemon thread: without capturing it, the failure is
        # invisible and the main thread can only report that nothing came up.
        #
        # The TRACEBACK is kept, not just the exception. A frozen build fails
        # with things like ModuleNotFoundError several frames deep inside a
        # dependency, and the exception text alone ("No module named 'x'")
        # does not say which import chain asked for it.
        import traceback

        _orchestrator_error["exc"] = e
        _orchestrator_error["tb"] = traceback.format_exc()
        print(f"[{ASSISTANT_NAME.lower()}] orchestrator stopped: {e}")


def wait_for_orchestrator(timeout: float = 40.0) -> bool:
    import requests
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get("http://127.0.0.1:8420/health", timeout=1)
            return True
        except requests.exceptions.RequestException:
            time.sleep(0.4)
    return False


_voice_proc = {"p": None}
_voice_shutdown = threading.Event()


def stop_voice():
    """Tears the voice process down and stops the supervisor respawning it.

    Registered with atexit, and called explicitly by _fatal(). This is not
    optional bookkeeping: the voice process is deliberately NOT daemonic (see
    start_voice), so multiprocessing's own exit handler would otherwise JOIN
    it at interpreter shutdown -- and it never returns, so closing the HUD
    would hang the app instead of quitting it.

    atexit runs handlers LIFO and multiprocessing registers its own at import
    time, so registering this later means it runs FIRST. That ordering is the
    whole reason this works.
    """
    _voice_shutdown.set()
    p = _voice_proc.get("p")
    if p is None or not p.is_alive():
        return
    print(f"[{ASSISTANT_NAME.lower()}] stopping voice process...")
    p.terminate()
    p.join(timeout=10)
    if p.is_alive():
        p.kill()


def start_voice(ready_event, privacy_mirror=None, hud_awake=None,
                announce_q=None):
    """Launches the voice stack as its own PROCESS and keeps it running.

    STAGE 2. This used to run listener.main() on a daemon thread, and recover
    from a crash with importlib.reload(listener). Two things were wrong with
    that, beyond the obvious:

      1. The listener shared this interpreter with uvicorn, the router, the
         skills and the psutil sampler. sounddevice's capture and playback
         callbacks are Python callbacks that must take the GIL every buffer
         period, so they were competing with all of it. That is what starved
         the audio path; see ipc.py.

      2. reload() rebinds a module's globals but cannot reclaim what a
         still-running thread references. A crash-restart therefore left the
         PREVIOUS incarnation's Whisper models resident next to the new ones,
         on a card with 4GB total, and re-ran the CUDA DLL search so PATH grew
         every time.

    Both go away here. The child owns the microphone, the speaker, and (as
    grandchildren) the Whisper and Piper processes; killing it releases all of
    that back to the OS. The supervision that used to live in start_voice's
    loop now lives inside listener.run_voice_process, so an ordinary crash is
    handled without a process respawn; this loop is the outer backstop for the
    child dying outright.

    The session token is passed explicitly rather than left to security.py's
    import-time generation, which in a separate process would mint a different
    one and 401 on every request.

    NOT daemon=True, deliberately, and this is not a style choice:
    multiprocessing forbids a daemonic process from having children
    ("daemonic processes are not allowed to have children"), and this process's
    entire job is to own the STT and TTS workers. Marking it daemonic made it
    unable to start them at all. Lifetime is instead handled at both ends --
    stop_voice() above kills it when the parent goes down cleanly, and
    listener's own parent watchdog makes it exit if the parent dies in a way
    that never reaches an atexit handler.
    """
    import multiprocessing

    import security

    ctx = multiprocessing.get_context("spawn")
    backoff = 2
    while not _voice_shutdown.is_set():
        p = ctx.Process(
            target=_voice_entry,
            args=(security.SESSION_TOKEN, ready_event, privacy_mirror,
                  hud_awake, announce_q),
            name="argus-voice",
        )
        p.start()
        _voice_proc["p"] = p
        print(f"[{ASSISTANT_NAME.lower()}] voice process started (pid {p.pid})")
        p.join()
        if _voice_shutdown.is_set():
            return
        print(f"[{ASSISTANT_NAME.lower()}] voice process exited "
              f"(code {p.exitcode}) — restarting in {backoff}s")
        ready_event.clear()
        time.sleep(backoff)
        backoff = min(backoff * 2, 30)


def _voice_entry(token, ready_event, privacy_mirror=None, hud_awake=None,
                 announce_q=None):
    """Module-level so it is picklable as a spawn target on Windows."""
    import listener

    if announce_q is not None:
        try:
            import announce
            announce.attach(announce_q)      # this side only ever READS it
        except Exception:
            pass
    listener.run_voice_process(token, ready_event=ready_event,
                               privacy_mirror=privacy_mirror,
                               hud_awake=hud_awake)


def start_hud():
    """HUD renders on the main thread — pywebview requires this."""
    try:
        import webview
    except ImportError:
        print(f"[{ASSISTANT_NAME.lower()}] pywebview missing — running headless.")
        print("  pip install pywebview")
        while True:
            time.sleep(3600)

    # The verified V2 route is the sole supported interface. A bad/missing
    # build presents its controlled server error; it never falls back to V1.
    hud = "http://127.0.0.1:8420/"
    try:
        import integrity
        v2_index = paths.resource("hud-v2", "dist", "index.html")
        ok, _detail = integrity.verify_one(integrity.manifest_key(v2_index))
        if not ok:
            print(f"[{ASSISTANT_NAME.lower()}] HUD V2 integrity verification failed.")
    except Exception:
        print(f"[{ASSISTANT_NAME.lower()}] HUD V2 verification unavailable.")

    # Dismiss the bootloader's splash now that a real window is about to
    # appear. pyi_splash exists only inside a frozen build that was given
    # --splash, so every other case is a no-op rather than an error -- and a
    # failure to close it must never stop the app from starting, since the
    # splash is cosmetic and the assistant is not.
    try:
        import pyi_splash            # type: ignore[import-not-found]
        pyi_splash.close()
    except Exception:
        pass

    window = webview.create_window(
        ASSISTANT_NAME,
        hud,
        width=1200,
        height=780,
        min_size=(1366, 768),
        background_color="#01050a",
        # A 1200x780 window on a full HD+ monitor left the wake video (and
        # everything else) filling only a fraction of the screen, which read
        # as "the video is small/half-window" even once its own CSS was
        # fixed to fill 100% of the window it's given. Launching maximized
        # gives it the whole screen for the reveal, while keeping normal
        # window chrome so you can still un-maximize, move, or close it.
        maximized=True,
    )

    def inject_token(w):
        """Hands the session token to the HUD in memory rather than writing it
        to a file. Nothing to leave behind, and the bundle stays read-only."""
        import security
        import time
        time.sleep(0.5)
        try:
            # Compatibility reinforcement for the canonical V2 bridge. The
            # server injects this before page load; never persist or build it.
            w.evaluate_js(f'window.__ARGUS_TOKEN__ = "{security.SESSION_TOKEN}";')
        except Exception as e:
            print(f"[argus] token injection failed: {e}")

    # THE HUD MUST NOT BE ABLE TO KILL THE ASSISTANT.
    #
    # webview.start() blocks until the window closes, and when it returned
    # main() simply fell through to shutdown. In the packaged build it
    # returned IMMEDIATELY -- so a double-clicked ARGUS.exe booted correctly,
    # started the orchestrator, indexed 93 apps, brought the voice stack up,
    # printed "opening interface...", and then quit. From a terminal you could
    # read the log and think it half-worked; double-clicked, nothing appeared
    # and the app was simply gone.
    #
    # ARGUS is a VOICE assistant. The window is a nice-to-have; the microphone
    # is the product. A HUD that fails to open is a degraded mode, not a fatal
    # error, so this keeps running headless and says why -- into the audit log
    # as well as stdout, because a windowed build has no console to print to.
    started_at = time.time()
    failure = ""
    try:
        webview.start(inject_token, window, debug=False)
    except Exception as e:
        failure = f"{e.__class__.__name__}: {e}"

    elapsed = time.time() - started_at
    if failure or elapsed < 2.0:
        why = failure or (f"the window closed after {elapsed:.1f}s without "
                          f"being interacted with")
        print(f"[{ASSISTANT_NAME.lower()}] the HUD did not stay open ({why}).")
        print(f"[{ASSISTANT_NAME.lower()}] continuing WITHOUT the window — "
              f"voice still works. Say the wake word.")
        try:
            import security as _sec
            _sec.audit("hud", "failed to open", why[:80])
        except Exception:
            pass
        while True:
            time.sleep(3600)


def _fatal(title: str, message: str):
    """Prints AND shows a native Windows dialog, then exits.

    BUGFIX: a startup refusal used to ONLY print(). That's fine when running
    `python argus.py` from a terminal -- reported as working correctly -- but
    the packaged build is a --windowed exe, which has NO console attached at
    all. print() there has nowhere to go. The refusal was firing exactly as
    designed (port already in use -> refuse cleanly instead of fighting the
    other copy for the socket), but from double-clicking the exe it looked
    identical to nothing happening, which is exactly what got reported.
    A message box is visible either way a launch happened, so both paths now
    behave the same instead of diverging on how ARGUS was started.
    """
    print(f"[{ASSISTANT_NAME.lower()}] {message}")

    # Take the splash down FIRST. It is an always-on-top window drawn by the
    # bootloader, so a failure dialog raised behind it is a dialog nobody can
    # read -- the launch would look like it hung on the splash rather than
    # like it refused for a stated reason.
    try:
        import pyi_splash            # type: ignore[import-not-found]
        pyi_splash.close()
    except Exception:
        pass

    # WRITE IT DOWN. A --windowed build has no console, so print() goes
    # nowhere, and the dialog is gone the moment it is dismissed -- which
    # leaves a user who double-clicked ARGUS.exe with a window that flashed
    # and vanished and nothing to send anyone. This file is the only durable
    # record of WHY a launch refused, and it is the first thing to read when
    # "it doesn't open".
    try:
        import datetime

        log = paths.writable("startup-failure.log")
        with open(log, "a", encoding="utf-8") as f:
            f.write(f"\n{'=' * 62}\n"
                    f"{datetime.datetime.now().isoformat(timespec='seconds')}  "
                    f"{'frozen' if paths.is_frozen() else 'source'} build\n"
                    f"{title}\n{message}\n")
        print(f"[{ASSISTANT_NAME.lower()}] written to {log}")
    except Exception:
        pass

    # Before the dialog, not after: MessageBoxW blocks until the user clicks,
    # and a voice process left running behind a modal error box would still
    # hold the microphone and its two model processes the whole time.
    try:
        stop_voice()
    except Exception:
        pass

    # ARGUS_NO_DIALOG exists because MessageBoxW blocks until a human clicks
    # it, and not every launch has a human. An automated run -- the test
    # suite, CI, a scheduled start on a locked machine -- would otherwise sit
    # on this line until something killed it, showing a timeout where the real
    # answer ("the port is already in use") had already been printed a

    # someone was sitting at the machine to dismiss the box, and hung
    # overnight when nobody was.
    #
    # The dialog still shows by default, because the bug it was added for --
    # a --windowed exe with no console, where print() goes nowhere -- is real
    # and this must not quietly undo it.
    if os.environ.get("ARGUS_NO_DIALOG"):
        sys.exit(1)

    try:
        import ctypes
        MB_OK, MB_ICONERROR, MB_SYSTEMMODAL = 0x0, 0x10, 0x1000
        ctypes.windll.user32.MessageBoxW(
            None, message, f"{ASSISTANT_NAME} — {title}",
            MB_OK | MB_ICONERROR | MB_SYSTEMMODAL,
        )
    except Exception as e:
        # The console print() above already happened -- a dialog that fails
        # to display must not hide that this was ever attempted.
        print(f"[{ASSISTANT_NAME.lower()}] (could not show a dialog: {e})")
    sys.exit(1)


def main():
    print(BANNER)

    # Privileges go FIRST, before the boot chain and before anything is
    # imported that might do work. main.py already drops them, but it only
    # does so when the orchestrator thread imports it -- which left the whole
    # boot chain (52 file reads, hashing, DPAPI, WinVerifyTrust) running with
    # SeDebugPrivilege, SeTakeOwnershipPrivilege, SeLoadDriverPrivilege and
    # five other privileges it has no use for.
    #
    # Same process, so this changes nothing about what the voice and HUD
    # children inherit; it only shortens the window in which this process is
    # more powerful than it needs to be. The removal is irreversible
    # (SE_PRIVILEGE_REMOVED, not "disabled"), and calling it twice is a no-op.
    try:
        import sandbox

        _before = len(sandbox.current_privileges())
        sandbox.drop_privileges(sandbox.ORCHESTRATOR_KEEP)
        _after = len(sandbox.current_privileges())
        print(f"[sandbox] privileges {_before} -> {_after}")
    except Exception as e:
        # Never fatal. A hardening step that stops the assistant from starting
        # gets removed by whoever is trying to use their machine.
        print(f"[sandbox] privilege drop skipped: {e}")

    # Checked before announcing a start we may not be able to make -- printing
    # "starting orchestrator..." and then immediately reporting the port is
    # taken reads as a crash mid-startup rather than a clean refusal.
    #
    # It also comes before the boot chain, and the ordering is deliberate:
    # port_in_use() is a socket connect with no side effects, while the boot
    # chain ends by announcing "ARGUS operational". Running boot first meant a
    # second launch printed a full successful boot report and THEN refused to
    # start, which reads as a crash immediately after everything worked.
    if port_in_use():
        _fatal(
            "Already running",
            f"Port {ORCHESTRATOR_PORT} is already in use, so ARGUS is almost "
            f"certainly already running.\n\nClose the other copy first -- check "
            f"the taskbar, or look for ARGUS.exe / python.exe in Task Manager. "
            f"Ollama is not the problem here.",
        )

    # The secure boot chain runs before the orchestrator, the app index and
    # the HUD. Verifying integrity after starting the thing whose integrity is
    # in question proves nothing: by then a modified auth.py has been imported
    # and is already making authorization decisions. See boot.py.
    import boot
    import config as _config
    import security as _security

    _security.init_audit(_config.VAULT_PATH)
    report = boot.run_boot()
    if not report.ok:
        _fatal(
            "Security check failed",
            f"ARGUS did not start because a security check failed:\n\n"
            f"{report.abort_reason}\n\n"
            f"If you changed these files deliberately, re-seal the baseline:\n"
            f"    python tools/argus_integrity.py diff\n"
            f"    python tools/argus_integrity.py seal --force\n\n"
            f"If you did not, restore them:\n"
            f"    python tools/argus_integrity.py rollback",
        )

    print(f"[{ASSISTANT_NAME.lower()}] starting orchestrator...")

    name = ASSISTANT_NAME.lower()
    threading.Thread(target=start_orchestrator, daemon=True).start()

    if not wait_for_orchestrator():
        # Report what actually went wrong when we know it. The old message
        # named Ollama unconditionally, which is a guess and usually the wrong
        # one -- the orchestrator binds its port and serves /health without
        # Ollama being up at all.
        err = _orchestrator_error["exc"]
        if err:
            msg = f"The orchestrator failed to start:\n\n{err}"
            tb = _orchestrator_error.get("tb") or ""
            if tb:
                # Into the log file, not the dialog -- a message box full of
                # stack frames helps nobody, but the log is what gets read
                # when a packaged build refuses to start.
                msg += f"\n\n--- traceback ---\n{tb}"
        else:
            msg = ("The orchestrator did not respond within 40 seconds.\n\n"
                   "If this persists, open a terminal in the ARGUS folder and "
                   "run: python doctor.py")
        _fatal("Startup failed", msg)
    print(f"[{ASSISTANT_NAME.lower()}] orchestrator ready")

    try:
        from skills import apps_skill
        apps_skill.build_index()
    except Exception as e:
        print(f"[{ASSISTANT_NAME.lower()}] app indexing failed: {e}")

    # Resume reminders saved before the last shutdown. Started here rather than
    # lazily on first use so a reminder set yesterday still fires today even if
    # no new one is set this session.
    try:
        from skills import timer_skill
        timer_skill.start()
    except Exception as e:
        print(f"[{ASSISTANT_NAME.lower()}] reminder restore failed: {e}")

    # An mp.Event rather than listener.READY: that Event now lives in another
    # process's memory and this one can no longer see it change.
    import atexit
    import multiprocessing

    # Registered AFTER multiprocessing is imported so that atexit's LIFO order
    # runs it BEFORE multiprocessing's own handler, which would otherwise join
    # the (non-daemonic) voice process forever. See stop_voice().
    atexit.register(stop_voice)

    ctx = multiprocessing.get_context("spawn")
    voice_ready = ctx.Event()

    # "The interface has finished waking, you may speak now."
    #
    # voice_ready means the SPEECH WORKERS are up, which is not the same thing
    # and was being used as though it were: ARGUS greeted the moment Whisper
    # and Piper loaded, talking over the wake video's own narration or, if the
    # user had not clicked to start it yet, arriving from a program that had
    # visibly not opened. This event is set by the HUD itself, through
    # /hud-awake, once the reveal is done. The orchestrator runs in THIS
    # process, so it can hold the handle; the voice process waits on it.
    # The unprompted-speech channel. Created here because this process holds
    # the orchestrator (which decides there is something to say) and spawns
    # the voice process (which owns the speaker). It carries a KIND, never
    # text -- see announce.py on why a queue of strings would be a
    # speech-injection primitive rather than a feature.
    announce_q = ctx.Queue()
    try:
        import announce
        announce.attach(announce_q)
    except Exception as e:
        print(f"[{ASSISTANT_NAME.lower()}] announce channel unavailable: {e}")

    hud_awake = ctx.Event()
    try:
        import main as _orchestrator_app
        _orchestrator_app.set_hud_awake_event(hud_awake)
    except Exception as e:
        # A greeting that never comes is worse than one that comes early, so a
        # failure to wire this up sets the event and preserves the old
        # behaviour rather than leaving ARGUS mute.
        print(f"[{ASSISTANT_NAME.lower()}] hud-awake wiring failed: {e}")
        hud_awake.set()

    # Privacy mode is set in THIS process (router.py dispatches it) and enforced
    # in the voice process (listener discards the audio). Since Stage 2 those
    # are different interpreters, so the flag has to live in shared memory or
    # the mute never reaches the microphone. See skills/privacy_skill.py.
    from skills import privacy_skill

    privacy_muted = ctx.Value("b", 0)
    privacy_until = ctx.Value("d", 0.0)
    privacy_skill.attach_mirror(privacy_muted, privacy_until)

    threading.Thread(
        target=start_voice,
        args=(voice_ready, (privacy_muted, privacy_until), hud_awake,
              announce_q),
        daemon=True,
    ).start()

    # Waited on rather than slept through -- model load time varies hugely by
    # machine and by whether the model is cached, so a fixed delay is always
    # wrong somewhere. The greeting itself is spoken by the voice process (see
    # listener._greet); this is only so the console says something truthful
    # before the HUD takes over the foreground.
    if voice_ready.wait(timeout=300):
        print(f"[{ASSISTANT_NAME.lower()}] voice stack ready")
    else:
        print(f"[{ASSISTANT_NAME.lower()}] voice stack slow to load — "
              f"continuing, it will come up on its own")

    print(f"[{ASSISTANT_NAME.lower()}] opening interface...")
    start_hud()


if __name__ == "__main__":
    # REQUIRED, and it must come first. Under "spawn" (the only start method
    # Windows has) every child re-executes this file to import the target; in a
    # PyInstaller build that means re-running the bundled executable. Without
    # freeze_support() the child would fall straight through into main() and
    # try to start a second orchestrator, hit port_in_use(), and show the
    # "already running" dialog -- from a process the user never launched.
    import multiprocessing

    multiprocessing.freeze_support()

    try:
        if not acquire_instance_lock():
            _fatal(
                "Already running",
                "ARGUS is already starting or running. Close the other copy "
                "before opening another; a second launch would invalidate "
                "the first copy's session token.",
            )
        main()
    except SystemExit:
        raise  # _fatal()'s own sys.exit(1) -- already handled, already shown
    except Exception as e:
        # Catch-all for anything NOT already wrapped inside main() (most of
        # it is; see the try/excepts around app indexing, reminder restore,
        # and the greeting). Two specific failures were made visible above,
        # but an unanticipated THIRD one -- a genuine crash rather than a
        # handled refusal -- would previously print a traceback that, same
        # as before, has no console to land in inside the packaged build and
        # simply vanishes. This is the backstop for everything neither of us
        # thought of yet, not a replacement for handling a known failure
        # properly at its source.
        import traceback
        traceback.print_exc()
        _fatal("Unexpected error", f"ARGUS hit an unexpected error on startup:\n\n{e}")
