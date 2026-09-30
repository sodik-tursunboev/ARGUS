"""
ARGUS - Worker process plumbing.

STAGE 2, and the reason it exists:

Whisper and Piper used to run as thread pools inside the same process as the
microphone InputStream and the speaker OutputStream. Both libraries release the
GIL during inference, so the GIL was never the whole story -- the problem was
two things at once. First, CPU oversubscription: each library sized its thread
pool to the whole machine (Stage 1 capped both). Second, and not fixable by
capping anything, sounddevice's capture and playback callbacks are PYTHON
callbacks. They must acquire the GIL every buffer period, and they were
competing for it with regex cascades, JSON parsing of Ollama's token stream,
and a psutil walk over 300 processes -- all in the same interpreter.

Stage 1 bought headroom. This removes the contention: the models move out of
the audio process entirely, so the voice process does nothing per audio frame
except an RMS and one state-machine step.

The protocol is deliberately small -- a request queue, a response queue, and a
correlation id:

  request   (req_id, payload)
  response  (req_id, ok, result_or_error_string)

Callers block in call(); one reader thread fans responses back out to them. The
correlation id is not ceremony: several threads in the voice process can have
calls outstanding at once (the capture loop's barge-in check and a segment
handler's command transcription), and without ids a call that timed out would
leave its late reply in the queue for the NEXT caller to mistake for its own --
every subsequent answer shifted by one, which would look exactly like the
garbled-transcription bug _MODEL_LOCK was originally added to fix.

Heavy imports (faster_whisper, piper, onnxruntime) live INSIDE each worker's
run() rather than at its module level, so that a parent importing the module
just to reference run() as a Process target does not drag the models into the
audio process -- which would defeat the entire point of this file.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import itertools
import multiprocessing as mp
import queue
import threading
import time


class WorkerError(RuntimeError):
    """A worker call failed, timed out, or the worker died mid-request."""


# Sent by a worker on the response queue, with this id, once its model is
# loaded and it is ready to serve. Not a normal reply, so it never collides
# with a correlation id (which start at 1).
READY_ID = 0


class WorkerClient:
    """Owns one child process and talks to it over a pair of queues.

    Restart policy: a worker that dies is restarted automatically by a monitor
    thread, and every call outstanding at that moment fails fast with
    WorkerError rather than hanging until its timeout. That is deliberately
    different from the old behaviour, where a crashed model took the whole
    listener thread with it and argus.py recovered by importlib.reload()ing the
    module -- which left the previous incarnation's models alive and resident
    on a 4GB card for as long as any in-flight thread still referenced them.
    """

    def __init__(self, name: str, target, args: tuple = (),
                 start_timeout: float = 240.0, max_restarts: int = 5):
        self.name = name
        self._target = target
        self._args = args
        self._start_timeout = start_timeout
        self._max_restarts = max_restarts

        # "spawn" explicitly rather than relying on the platform default: this
        # is the only start method Windows has, and naming it keeps behaviour
        # identical if any of this is ever run elsewhere.
        self._ctx = mp.get_context("spawn")

        self._ids = itertools.count(1)
        self._pending: dict = {}          # req_id -> [Event, ok, payload]
        self._lock = threading.Lock()

        self._req_q = None
        self._resp_q = None
        self._proc = None
        self._ready = threading.Event()
        self._reader = None
        self._monitor = None
        self._shutdown = threading.Event()
        self._restarts = 0
        self._info = None                 # whatever the worker reported at READY

    # ── lifecycle ─────────────────────────────────────────────────────

    def start(self) -> bool:
        """Spawns the worker and blocks until it reports ready.

        Returns True on success. A worker that never reports ready is a hard
        failure the caller has to decide about -- for STT that is fatal, for
        TTS it is degraded-but-usable, so this reports rather than exits.
        """
        self._spawn()
        if not self._ready.wait(self._start_timeout):
            print(f"[ipc] {self.name}: not ready after {self._start_timeout:.0f}s")
            return False
        if self._monitor is None:
            self._monitor = threading.Thread(
                target=self._monitor_loop, name=f"{self.name}-monitor", daemon=True)
            self._monitor.start()
        return True

    def _spawn(self):
        self._ready.clear()
        self._req_q = self._ctx.Queue()
        self._resp_q = self._ctx.Queue()
        self._proc = self._ctx.Process(
            target=self._target,
            args=(self._req_q, self._resp_q) + tuple(self._args),
            name=self.name,
            daemon=True,
        )
        self._proc.start()
        self._reader = threading.Thread(
            target=self._read_loop, args=(self._resp_q,),
            name=f"{self.name}-reader", daemon=True)
        self._reader.start()
        print(f"[ipc] {self.name}: process {self._proc.pid} starting")

    def stop(self):
        self._shutdown.set()
        try:
            if self._req_q is not None:
                self._req_q.put((None, None))     # poison pill
        except Exception:
            pass
        proc = self._proc
        if proc is not None and proc.is_alive():
            proc.join(timeout=3.0)
            if proc.is_alive():
                proc.terminate()

    @property
    def info(self):
        """Whatever the worker reported alongside READY (mode, device, ...)."""
        return self._info

    def is_ready(self) -> bool:
        return self._ready.is_set()

    # ── request / response ────────────────────────────────────────────

    def call(self, payload, timeout: float = 60.0):
        """Sends one request and blocks for its reply.

        Raises WorkerError on a worker-side exception, a timeout, or a worker
        that is not currently up. Callers are expected to treat that as "this
        one utterance failed" and carry on -- never as fatal.
        """
        if not self._ready.is_set():
            raise WorkerError(f"{self.name} is not ready")

        req_id = next(self._ids)
        slot = [threading.Event(), False, None]
        with self._lock:
            self._pending[req_id] = slot
        try:
            self._req_q.put((req_id, payload))
            if not slot[0].wait(timeout):
                raise WorkerError(f"{self.name} timed out after {timeout:.0f}s")
            if not slot[1]:
                raise WorkerError(f"{self.name}: {slot[2]}")
            return slot[2]
        finally:
            with self._lock:
                self._pending.pop(req_id, None)

    def _read_loop(self, resp_q):
        """One reader per worker incarnation. Bound to the queue it was started
        with, so a restart's reader cannot consume from a stale queue."""
        while not self._shutdown.is_set():
            try:
                msg = resp_q.get(timeout=0.5)
            except queue.Empty:
                continue
            except (OSError, EOFError, ValueError):
                return                      # queue closed -- this incarnation is done
            if msg is None:
                return
            req_id, ok, payload = msg
            if req_id == READY_ID:
                self._info = payload
                self._ready.set()
                print(f"[ipc] {self.name}: ready ({payload})")
                continue
            with self._lock:
                slot = self._pending.get(req_id)
            if slot is None:
                continue                    # timed out already; drop the late reply
            slot[1], slot[2] = ok, payload
            slot[0].set()

    def _fail_all_pending(self, reason: str):
        with self._lock:
            slots = list(self._pending.values())
            self._pending.clear()
        for slot in slots:
            slot[1], slot[2] = False, reason
            slot[0].set()

    def _monitor_loop(self):
        """Restarts a worker that dies, and fails its in-flight calls at once.

        Without the fail-fast half, a crash would leave every caller blocked
        until its own timeout -- for a 60s command timeout that is a minute of
        ARGUS looking alive and being deaf, which is precisely the failure mode
        argus.py's restart loop was written to prevent and did not.
        """
        while not self._shutdown.is_set():
            time.sleep(1.0)
            proc = self._proc
            if proc is None or proc.is_alive() or self._shutdown.is_set():
                continue

            code = proc.exitcode
            print(f"[ipc] {self.name}: died (exit {code}) — restarting")
            self._ready.clear()
            self._fail_all_pending(f"{self.name} died (exit {code})")

            self._restarts += 1
            if self._restarts > self._max_restarts:
                print(f"[ipc] {self.name}: {self._restarts} restarts — giving up")
                return

            # Back off a little so a worker that cannot load at all (a missing
            # model, a broken CUDA install) does not spin the CPU respawning.
            time.sleep(min(2 ** self._restarts, 30))
            try:
                self._spawn()
                if not self._ready.wait(self._start_timeout):
                    print(f"[ipc] {self.name}: restart did not become ready")
            except Exception as e:
                print(f"[ipc] {self.name}: restart failed: {e}")


# ── worker-side helpers ───────────────────────────────────────────────

def line_buffer_output():
    """Makes a child process's prints appear as they happen.

    A spawned child inherits the parent's stdout handle, but when that is a
    pipe rather than a console Python block-buffers it -- so 8KB of worker
    diagnostics sit unwritten and are lost outright if the process is later
    terminated. That turned "run ARGUS piped to a log file" into a way to see
    nothing at all from the three most interesting processes.

    Guarded: under a --windowed PyInstaller build sys.stdout is None.
    """
    import sys

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, ValueError, OSError):
            pass


def _die_with_parent():
    """Exits this worker when the process that started it goes away.

    daemon=True is not enough on Windows. It makes multiprocessing terminate
    this process during the parent's ORDERLY interpreter shutdown -- but the
    voice process is itself stopped with terminate() (TerminateProcess), which
    runs no cleanup at all. Without this, stopping ARGUS would leave a Whisper
    process and a Piper process orphaned, holding their models resident on a
    card with 4GB total.

    parent_process().join() waits on an OS handle, so unlike polling
    os.getppid() it cannot be fooled by PID reuse.
    """
    import os

    parent = mp.parent_process()
    if parent is None:
        return

    def watch():
        parent.join()
        os._exit(0)

    threading.Thread(target=watch, name="parent-watchdog", daemon=True).start()


def serve(req_q, resp_q, handler, ready_info=None):
    # A spawned worker re-imports from scratch and, in a windowed
    # frozen build, starts with sys.stdout/stderr set to None.
    import paths

    paths.ensure_std_streams()

    """The loop every worker's run() ends with.

    Reports ready, then answers requests one at a time until it is told to
    stop. Single-threaded on purpose: it gives each worker exactly the
    serialization _MODEL_LOCK used to provide inside the listener, without a
    lock that anything else can contend for. CTranslate2 model instances are
    not documented as safe for concurrent transcribe() calls, and this is now
    the only thing that touches them.
    """
    line_buffer_output()
    _die_with_parent()

    # A worker holds a multi-gigabyte model file and nothing else. It needs no
    # OS privileges at all, so it keeps none -- and it refuses DLLs from
    # network paths or low-integrity files, which is the realistic load path
    # for something malicious arriving alongside a downloaded model.
    try:
        import sandbox
        dropped = sandbox.drop_privileges(sandbox.WORKER_KEEP)
        hardened = sandbox.harden_image_loading()
        if dropped:
            print(f"[sandbox] worker dropped {len(dropped)} privilege(s); "
                  f"image-load hardening {'on' if hardened else 'unavailable'}")
    except Exception as e:
        print(f"[sandbox] worker hardening skipped: {e}")

    resp_q.put((READY_ID, True, ready_info))
    while True:
        try:
            msg = req_q.get()
        except (OSError, EOFError, ValueError):
            return
        if msg is None:
            return
        req_id, payload = msg
        if req_id is None:
            return                          # poison pill from stop()
        try:
            resp_q.put((req_id, True, handler(payload)))
        except Exception as e:
            import traceback
            traceback.print_exc()
            resp_q.put((req_id, False, f"{type(e).__name__}: {e}"))
