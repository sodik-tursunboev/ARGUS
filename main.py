"""
ARGUS - Orchestrator API.

BUGFIXES IN THIS VERSION:

1. /status was polled every 700ms and ran os.listdir() over three vault folders
   on every single call — constant filesystem I/O for a number that changes
   maybe once an hour. Now cached and refreshed on a slow timer.

2. /telemetry was polled every 3s and walked EVERY running process reading
   memory_info, then fetched weather synchronously when its cache expired,
   blocking the endpoint for seconds. All sampling now happens on one background
   thread; the endpoints just read the last sample and return instantly.

3. cpu_percent(interval=None) returns 0.0 on its first ever call. The sampler
   primes it at startup so the HUD doesn't show a false zero.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import asyncio
import json
import os
import threading
import time

import psutil
import requests
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import auth
import paths

# No console in a --windowed build means sys.stdout is None, and
# uvicorn reads it while configuring logging. See
# paths.ensure_std_streams.
paths.ensure_std_streams()
import security
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, StreamingResponse
import route_trace
from router import handle, handle_stream
from skills import (
    vault_skill, passive_memory, history_store,
    proactive_skill, power_skill, clarify_skill, cloud_gate, social_skill,
)
from config import OLLAMA_HOST, OLLAMA_MODEL, VAULT_PATH, CLOUD_ENABLED

# The module itself as well as the four names above. The panel endpoints read
# a dozen settings between them and need to see LIVE values -- settings.py
# writes user overrides back onto the config module, so a `from config import
# X` binding taken at import time would keep reporting the shipped default
# after the user had changed it.
import config

security.init_audit(VAULT_PATH)

# Shed OS privileges before anything else runs. ARGUS inherits the token of
# whatever launched it, so from an elevated shell or a scheduled task with
# "highest privileges" it starts holding SeDebugPrivilege (read any process's
# memory), SeBackupPrivilege and SeRestorePrivilege (read/write any file,
# ignoring ACLs) and SeLoadDriverPrivilege. An always-listening assistant with
# a language model in the loop needs none of them.
#
# Only SeShutdownPrivilege is kept, because power_skill exists. Removal is
# permanent for the life of the process -- see sandbox.drop_privileges for why
# merely disabling them would defend against nothing.
try:
    import sandbox
    _before = sandbox.report()
    _dropped = sandbox.drop_privileges(sandbox.ORCHESTRATOR_KEEP)
    if _dropped:
        print(f"[sandbox] dropped {len(_dropped)} privilege(s) "
              f"(integrity {_before['integrity']}): {', '.join(_dropped[:4])}"
              f"{'...' if len(_dropped) > 4 else ''}")
    if sandbox.harden_image_loading():
        print("[sandbox] image-load policy: no remote or low-integrity DLLs")
except Exception as e:
    print(f"[sandbox] hardening skipped: {e}")

auth.start()


# agents sharing the ONE configured model through a serial runtime. Pure
# addition: if the layer fails to start, ARGUS continues without it --
# agents/service.start() catches its own errors and logs.
try:
    from agents import service as _agents_service
    _agents_service.start()
except Exception as _agents_err:
    print(f"[agents] layer unavailable: {type(_agents_err).__name__}")

# Keep checking after boot. The startup verification answers whether the
# install was intact when it launched; this answers whether it still is, which
# for a process that stays up for days is a different question.
try:
    import integrity as _integrity
    _integrity.start_watch()
    # ARGUS-SEC-005: a writable frozen install is a DLL-plant foothold. Log it
    # once at boot so it is on the audited record, not only in the live panel.
    if paths.is_frozen():
        _w, _note = _integrity.install_dir_writable()
        if _w:
            print(f"[security] {_note} — run tools/harden_acls.ps1 -App")
            security.security_event(security.SECURITY_POLICY_CHANGED,
                                    component="install", reason="dir_writable",
                                    status="failed")
except Exception as e:
    print(f"[integrity] continuous verification not started: {e}")

app = FastAPI(title="ARGUS")


@app.on_event("startup")
def _publish_runtime_token():
    """Only the serving process may replace the active session-token file.

    Importing main for a read-only context lookup in a spawned worker must
    not invalidate the token held by the already-running HUD and voice client.
    """
    security.publish_token()

_img_dir = paths.resource("hud", "img")
if os.path.isdir(_img_dir):
    app.mount("/assets", StaticFiles(directory=_img_dir), name="assets")


# ═══════════════════════════════════════════════════════════════════════
# SECURITY — this was a serious hole.
#
# This API can open and close applications, TYPE ARBITRARY KEYSTROKES into
# whatever window has focus, read the clipboard, take screenshots, and shut the
# machine down. It previously ran with allow_origins=["*"].
#
# That meant ANY website you visited while ARGUS was running could do:
#
#     fetch('http://127.0.0.1:8420/command', {
#       method: 'POST',
#       headers: {'Content-Type': 'application/json'},
#       body: JSON.stringify({text: 'type rm -rf ...'})
#     })
#
# ...and the browser would allow it. That is remote code execution on this
# machine from any web page.
#
# Fix: browsers always attach an Origin header on cross-origin requests. The
# HUD loads from file://, which sends "null" or no Origin at all. So we reject
# anything carrying a real http(s) Origin. The server also binds to 127.0.0.1
# only, so nothing off-machine can reach it either way.
# ═══════════════════════════════════════════════════════════════════════

ALLOWED_ORIGINS = {
    "null", "file://",
    # Explicit local development and preview origins. Never use a wildcard.
    "http://127.0.0.1:5173", "http://localhost:5173",
    "http://127.0.0.1:4173", "http://localhost:4173",
    "http://127.0.0.1:8420", "http://localhost:8420",
}


# Endpoints that don't act on the machine and don't leak anything sensitive.
# /assets/ is exempted too: it serves static images the HUD's core visual uses,
# and <img> tags cannot attach a custom auth header, so this has to be public
# the same way "/" is — it's read-only, non-sensitive, and delivers nothing
# an unauthenticated request couldn't already get from the page itself.
PUBLIC_PATHS = {"/", "/v2/", "/health", "/docs", "/openapi.json"}
PUBLIC_PREFIXES = ("/assets/", "/v2/assets/")

# 256 KB. The largest legitimate body is a settings object or a typed command;
# this is two orders of magnitude above either.
MAX_BODY_BYTES = 256 * 1024

SECURITY_HEADERS = {
    # No off-machine anything. media-src covers the HUD's boot video, and
    # frame-ancestors 'none' stops the page being embedded anywhere.
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "media-src 'self' blob:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    # This API can open applications and synthesise keystrokes. Nothing it
    # serves has any business asking for hardware.
    "Permissions-Policy": ("geolocation=(), camera=(), microphone=(), "
                           "payment=(), usb=(), interest-cohort=()"),
    "Cache-Control": "no-store",
}


def _harden(response):
    """Apply the response headers. Used on EVERY exit from guard().

    Applying them only on the success path meant the 401, 403, 413 and 429
    replies -- the ones an attacker sees most of -- went out without nosniff
    or a CSP. They are small JSON bodies, but "the error responses are the
    unprotected ones" is precisely the sort of gap that is never noticed.
    """
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response


def _note_rejected(path: str, reason: str) -> None:
    """A command refused by the guard never reaches command(), so nothing there
    can give it a terminal state. Recorded here, or a rate-limited or
    unauthenticated command is exactly the request that leaves no trace at all
    (the voice client reports it only as "I couldn't reach my brain")."""
    if path in ("/command", "/command-stream"):
        route_trace.reject("command", reason)


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path

    # 1. Origin check — stops web pages entirely.
    origin = request.headers.get("origin")
    if origin and origin not in ALLOWED_ORIGINS:
        print(f"[security] blocked origin: {origin}")
        security.audit("blocked", f"origin {origin}", "403")
        _note_rejected(path, "origin not allowed")
        return _harden(JSONResponse(
            {"detail": "Requests from web pages are not permitted."},
            status_code=403,
        ))

    # 2. Token check on anything that acts on the machine.
    #
    # The Origin check alone only stops browsers. Any other program running as
    # your user could POST to this port and make ARGUS synthesise keystrokes or
    # power the machine off. The token is generated fresh each launch and
    # written to a user-scoped file.
    if path not in PUBLIC_PATHS and not path.startswith(PUBLIC_PREFIXES):
        supplied = request.headers.get("x-argus-token", "")
        # token_valid() rather than a direct comparison: it also accepts the
        # PREVIOUS token during its grace window, so enabling rotation does
        # not fail requests that were already in flight. Still constant-time,
        # and still a single comparison from this code's point of view.
        if not security.token_valid(supplied):
            security.audit("blocked", f"bad token on {path}", "401")
            _note_rejected(path, "invalid session token")
            return _harden(JSONResponse({"detail": "Invalid session token."},
                                        status_code=401))

    # 3. Rate limit — a runaway loop shouldn't be able to spam commands.
    if path in ("/command", "/command-stream") and not security.rate_ok():
        security.audit("blocked", "rate limit", "429")
        _note_rejected(path, "rate limited")
        return _harden(JSONResponse({"detail": "Too many commands."},
                                    status_code=429))

    # 4. Body size. Every endpoint here takes a short command or a small
    # settings object; nothing legitimately posts megabytes. Without a bound,
    # a single request could make the process allocate until it died, and an
    # assistant that can be switched off by one POST is a denial of service
    # with no authentication required beyond the local token.
    if request.method in ("POST", "PUT", "PATCH"):
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            security.audit("blocked", f"oversized body on {path}", "413")
            _note_rejected(path, "oversized body")
            return _harden(JSONResponse(
                {"detail": f"Request body exceeds {MAX_BODY_BYTES} bytes."},
                status_code=413))

    response = await call_next(request)

    # 5. Response hardening.
    #
    # The HUD is a web page that renders language-model output, research
    # summaries and file names -- all of which can contain text ARGUS did not
    # write. connect-src 'self' is the load-bearing one: even if something
    # were injected into that page, it could not send anything off this
    # machine, which turns a scripting bug from exfiltration into a defacement.
    #
    # 'unsafe-inline' is present because the HUD is one file with inline
    # script and style, and claiming otherwise would just mean a CSP that
    # breaks the interface and gets removed. It is stated here rather than
    # quietly relied on.
    return _harden(response)


def secrets_compare(a: str, b: str) -> bool:
    """Constant-time comparison — avoids leaking the token via timing."""
    import hmac
    return hmac.compare_digest(a or "", b or "")


app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(ALLOWED_ORIGINS),
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "x-argus-token"],
)


# REST remains the initial snapshot path. This bounded channel sends only
# subsequent sampler changes, so a stalled WebView cannot retain history or
# slow the sampler thread.
class _HudEventHub:
    _MAX_PENDING = 16

    def __init__(self):
        self._clients: dict[int, tuple[asyncio.AbstractEventLoop, asyncio.Queue[str]]] = {}
        self._lock = threading.Lock()
        self._next_id = 0

    async def subscribe(self) -> tuple[int, asyncio.Queue[str]]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=self._MAX_PENDING)
        key = id(queue)
        with self._lock:
            self._clients[key] = (asyncio.get_running_loop(), queue)
        return key, queue

    def unsubscribe(self, key: int) -> None:
        with self._lock:
            self._clients.pop(key, None)

    @staticmethod
    def _put_latest(queue: asyncio.Queue[str], message: str) -> None:
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            pass

    def publish(self, event_type: str, payload: dict) -> None:
        # Payloads are built from explicit sampler fields below. Command text,
        # credentials, audit bodies, and raw authentication data are excluded.
        with self._lock:
            self._next_id += 1
            event_id = str(self._next_id)
            clients = list(self._clients.values())
        message = json.dumps({
            "type": event_type, "version": 1,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "eventId": event_id, "payload": payload,
        }, separators=(",", ":"))
        for loop, queue in clients:
            try:
                loop.call_soon_threadsafe(self._put_latest, queue, message)
            except RuntimeError:
                pass


_hud_events = _HudEventHub()


@app.websocket("/ws")
async def hud_websocket(websocket: WebSocket):
    """Authenticated, loopback-only live updates after REST bootstrap."""
    origin = websocket.headers.get("origin")
    peer = websocket.client.host if websocket.client else ""
    # A browser WebSocket cannot attach a custom request header. The runtime
    # session token therefore travels in a WebSocket subprotocol header, never
    # in the URL where normal access logs would record it.
    protocols = [item.strip() for item in
                 websocket.headers.get("sec-websocket-protocol", "").split(",")]
    token = protocols[1] if len(protocols) == 2 and protocols[0] == "argus-token" else ""
    if (peer not in {"127.0.0.1", "::1"}
            or (origin and origin not in ALLOWED_ORIGINS)
            or not security.token_valid(token)):
        # Never audit a URL or token; reject the handshake before acceptance.
        security.audit("blocked", "bad websocket connection", "401")
        await websocket.close(code=1008)
        return

    await websocket.accept(subprotocol="argus-token")
    key, queue = await _hud_events.subscribe()
    try:
        while True:
            await websocket.send_text(await queue.get())
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        _hud_events.unsubscribe(key)

START_TIME = time.time()
MAX_HISTORY = 12

last_exchange = {"text": "", "reply": "", "latency_ms": None}
voice_state = {"state": "standby"}

# Restored from disk so a restart resumes the conversation instead of wiping
# it. history_store returns [] for a missing, malformed or stale transcript,
# so this is safe on a first run and can't resurrect a days-old context.
conversation_history = history_store.load(MAX_HISTORY)
if conversation_history:
    print(f"[history] resumed {len(conversation_history) // 2} exchange(s)")

# /command and /command-stream are both plain `def` endpoints, so FastAPI runs
# them on the threadpool -- two can genuinely overlap (the HUD's text input
# while a voice command is still streaming). Appending to a list is atomic
# under the GIL, but "append user, append assistant, then trim" is three
# operations, and interleaving them can split a pair or trim someone else's
# turn mid-write. Cheap to hold: this guards bookkeeping, never a model call.
_history_lock = threading.Lock()

# Everything below is written by the sampler thread and only read by endpoints.
_snapshot = {
    "cpu": 0.0,
    "cpu_cores": [],
    "mem_pct": 0.0,
    "mem_used_gb": 0.0,
    "mem_total_gb": 0.0,
    "disk_pct": 0.0,
    "disk_free_gb": 0,
    "battery": None,
    "charging": False,
    "net_sent_gb": 0.0,
    "net_recv_gb": 0.0,
    "weather": "",
    "top_processes": [],
    "note_count": 0,
    # GPU. None until proven available — the HUD renders N/A rather than a
    # fabricated 0%, which matters: a silent 0% reads as "idle GPU", not
    # "we couldn't check."
    "gpu_available": False,
    "gpu_pct": None,
    "vram_used_mb": None,
    "vram_total_mb": None,
    "gpu_temp_c": None,
    "swap_pct": 0.0,
    "swap_used_gb": 0.0,
    "swap_total_gb": 0.0,
    "anomalies": [],
    # Active-defence detections (threatmon): LSASS access, tamper, canary trips,
    # LOLBin abuse, clipboard hijack. A capped rolling list, newest appended,
    # each already deduped and logged to the audit chain inside threatmon.
    "detections": [],
}

_gpu_checked = {"done": False, "available": False}

_last_hud_telemetry: dict[str, object] = {}


def _publish_hud_telemetry() -> None:
    """Publish only changed, safe sampler fields to subscribed HUDs."""
    system = {key: _snapshot[key] for key in (
        "cpu", "mem_pct", "mem_used_gb", "mem_total_gb", "disk_pct",
        "disk_free_gb", "gpu_pct", "gpu_available",
    )}
    network = {key: _snapshot[key] for key in ("net_sent_gb", "net_recv_gb")}
    for event_type, payload in (("telemetry.system", system),
                                ("telemetry.network", network)):
        if _last_hud_telemetry.get(event_type) != payload:
            _last_hud_telemetry[event_type] = dict(payload)
            _hud_events.publish(event_type, payload)


_last_hud_security: dict[str, object] = {}


def _publish_hud_security() -> None:
    """Publish only changed auth/posture/alert facts, from the identical
    sources /status, /threat-report, and /telemetry's own latest_alert()
    already read -- never a second, separately-derived opinion of any of
    them. Same "only on change" discipline as _publish_hud_telemetry()."""
    auth_state = {"status": "valid" if auth.is_unlocked()
                  else ("required" if _pin_pending() else "unknown")}
    try:
        import threatmon
        level = str(threatmon.overall_level() or "").lower()
    except Exception:
        level = ""
    posture = ("critical" if "critical" in level
               else "warning" if any(w in level for w in ("elevated", "warn", "medium"))
               else "normal")
    sec_state = {"posture": posture}
    try:
        alert = threatmon.latest_alert()
    except Exception:
        alert = None
    events = [("auth.state", auth_state), ("security.state", sec_state)]
    if alert and alert.get("severity"):
        events.append(("security.alert", {"level": alert.get("severity", ""),
                                          "severity": alert.get("severity", ""),
                                          "detector": alert.get("detector", "")}))
    for event_type, payload in events:
        if _last_hud_security.get(event_type) != payload:
            _last_hud_security[event_type] = dict(payload)
            _hud_events.publish(event_type, payload)


def _sample_gpu():
    """One nvidia-smi call, parsed. Cheap (~10-20ms) but still not run every
    tick — see the sampler's cadence below. Fails silently and permanently
    on non-NVIDIA machines after the first attempt, so we're not spawning a
    process every few seconds for nothing."""
    import subprocess

    if _gpu_checked["done"] and not _gpu_checked["available"]:
        return  # confirmed absent on an earlier tick, don't keep retrying

    try:
        out = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=3,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        if out.returncode != 0 or not out.stdout.strip():
            raise RuntimeError("nvidia-smi returned no data")

        # Multi-GPU machines get one line per card; take the first.
        util, used, total, temp = (
            v.strip() for v in out.stdout.strip().splitlines()[0].split(",")
        )
        _snapshot["gpu_available"] = True
        _snapshot["gpu_pct"] = float(util)
        _snapshot["vram_used_mb"] = float(used)
        _snapshot["vram_total_mb"] = float(total)
        _snapshot["gpu_temp_c"] = float(temp)
        _gpu_checked["available"] = True

    except (FileNotFoundError, subprocess.SubprocessError, RuntimeError, ValueError):
        # No NVIDIA card, no driver, or nvidia-smi not on PATH. Not an error —
        # most machines don't have this, and the HUD already handles it as N/A.
        _snapshot["gpu_available"] = False
    finally:
        _gpu_checked["done"] = True


# psutil only reports accurate per-process CPU% when cpu_percent() is called
# repeatedly on the SAME Process object across cycles -- it measures elapsed
# CPU time since the previous call on that object. process_iter() hands back
# fresh objects every call, so without this cache every reading would be a
# meaningless 0.0. Pruned each cycle so it doesn't grow forever as processes
# come and go.
_proc_cache: dict[int, "psutil.Process"] = {}


def _sample_processes():
    """Bounded walk — stops after a fixed number of processes so a machine with
    hundreds of them can't stall the sampler.

    Reports the single largest instance of each process name, not merged
    totals — PID and per-process CPU% only make sense for one real process,
    not a summed group.

    Optimized: Batches process metadata query, then samples CPU on the top
    candidate processes to avoid hundreds of expensive Win32 process queries per tick.
    """
    seen_pids = set()
    best: dict[str, dict] = {}
    child_count: dict[int, int] = {}
    try:
        attrs = ["pid", "name", "memory_info", "num_threads", "ppid"]
        procs_raw = []
        for i, p in enumerate(psutil.process_iter(attrs)):
            if i > 300:
                break
            try:
                info = p.info
                pid = info["pid"]
                seen_pids.add(pid)
                ppid = info.get("ppid")
                if ppid:
                    child_count[ppid] = child_count.get(ppid, 0) + 1
                nm = (info["name"] or "").replace(".exe", "")
                if not nm:
                    continue
                mem_info = info.get("memory_info")
                mb = (mem_info.rss / (1024 ** 2)) if mem_info else 0.0
                procs_raw.append((pid, nm, mb, info.get("num_threads") or 0))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Sort candidate processes by memory to only sample CPU on the heaviest/active ones
        procs_raw.sort(key=lambda x: x[2], reverse=True)
        # Limit CPU sampling to top 50 processes
        cpu_candidates = {pid for pid, nm, mb, th in procs_raw[:50]}

        for pid, nm, mb, th in procs_raw:
            cpu = 0.0
            if pid in cpu_candidates:
                cached = _proc_cache.get(pid)
                if cached is None:
                    try:
                        cached = psutil.Process(pid)
                        cached.cpu_percent(interval=None)  # prime — first read is always 0
                        _proc_cache[pid] = cached
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                else:
                    try:
                        cpu = cached.cpu_percent(interval=None)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

            if nm not in best or mb > best[nm]["mb"]:
                best[nm] = {
                    "name": nm, "pid": pid, "mb": round(mb),
                    "cpu": round(cpu, 1), "threads": th,
                }
    except Exception:
        return []

    for pid in list(_proc_cache):
        if pid not in seen_pids:
            del _proc_cache[pid]

    for entry in best.values():
        entry["children"] = child_count.get(entry["pid"], 0)

    return sorted(best.values(), key=lambda x: x["mb"], reverse=True)


def _count_notes():
    try:
        vault_skill.ensure_vault()
        return sum(
            len([f for f in os.listdir(d) if f.endswith(".md")])
            for d in (vault_skill.RAW_DIR, vault_skill.WIKI_DIR, vault_skill.OUTPUTS_DIR)
        )
    except Exception:
        return 0


def sampler():
    """One background thread does all the expensive work, at sane intervals.
    Endpoints become pure dictionary reads."""
    psutil.cpu_percent(interval=None)          # prime — first call always returns 0
    psutil.cpu_percent(interval=None, percpu=True)

    # Start the background (thread-based) detectors once: canary file-watch and
    # the tamper watchdog run their own loops rather than on this tick. Guarded
    # so a detector that fails to start can never stop the sampler from starting.
    try:
        import threatmon
        threatmon.start()
    except Exception as e:
        print(f"[sampler] threatmon start: {e}")

    # Noticing you come back. Inert unless face presence is enabled and a face
    # is enrolled, and it only ever greets -- it cannot unlock (see
    # presencewatch.py). Guarded like the detectors above.
    try:
        import presencewatch
        presencewatch.start()
    except Exception as e:
        print(f"[sampler] presence-return start: {e}")

    # NOT started: the Telegram receiver. Both remote-notification paths
    # (Twilio voice, Telegram) are deliberately dormant -- the modules remain
    # because they are complete and tested, but nothing starts them and
    # neither is configured, so neither opens a socket or costs anything.
    # Turning one back on is a deliberate edit here, not a config flag.

    tick = 0
    while True:
        try:
            # Every second: cheap counters
            _snapshot["cpu"] = psutil.cpu_percent(interval=None)
            _snapshot["cpu_cores"] = psutil.cpu_percent(interval=None, percpu=True)

            mem = psutil.virtual_memory()
            _snapshot["mem_pct"] = mem.percent
            _snapshot["mem_used_gb"] = round(mem.used / (1024 ** 3), 1)
            _snapshot["mem_total_gb"] = round(mem.total / (1024 ** 3), 1)

            swap = psutil.swap_memory()
            _snapshot["swap_pct"] = swap.percent
            _snapshot["swap_used_gb"] = round(swap.used / (1024 ** 3), 1)
            _snapshot["swap_total_gb"] = round(swap.total / (1024 ** 3), 1)

            net = psutil.net_io_counters()
            _snapshot["net_sent_gb"] = round(net.bytes_sent / (1024 ** 3), 2)
            _snapshot["net_recv_gb"] = round(net.bytes_recv / (1024 ** 3), 2)

            # Every 5s: GPU, disk, battery, processes
            if tick % 5 == 0:
                try:
                    _sample_gpu()
                except Exception as e:
                    print(f"[sampler] gpu: {e}")


            # Every 5s: disk, battery, processes
            if tick % 5 == 0:
                try:
                    d = psutil.disk_usage("C:\\")
                    _snapshot["disk_pct"] = d.percent
                    _snapshot["disk_free_gb"] = round(d.free / (1024 ** 3))
                except OSError:
                    pass
                bat = psutil.sensors_battery()
                _snapshot["battery"] = round(bat.percent) if bat else None
                _snapshot["charging"] = bat.power_plugged if bat else False
                processes = _sample_processes()
                _snapshot["top_processes"] = processes[:6]

                # Anomaly detection: own try/except, same as every other
                # section here -- a bad calculation, a corrupted baseline
                # file, or (before anomaly_skill's own division guard) a
                # divide-by-zero on a process's first-ever sample must not
                # be able to take down this thread, which also owns GPU,
                # disk, battery and network sampling for the whole HUD.
                # anomaly_skill.observe() already can't raise on its own
                # (it catches internally too), so this is deliberate
                # belt-and-suspenders, not redundant -- the belt should
                # still hold if the suspenders ever don't.
                try:
                    from skills import anomaly_skill
                    # findings is already cooldown-gated inside observe()
                    # (won't repeat the same process+reason inside 5
                    # minutes), so this is safe to log every occurrence
                    # rather than needing its own dedup on top. Appended
                    # to a capped rolling list, not overwritten -- a bare
                    # "if findings:" here would leave a stale flagged
                    # anomaly sitting in the HUD's state forever after it
                    # actually cleared, since an empty cycle would simply
                    # skip updating rather than reflecting "resolved now".
                    findings = anomaly_skill.observe(processes)
                    for f in findings:
                        security.audit("anomaly", "", f)
                        _snapshot["anomalies"].append(
                            {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "text": f})
                    del _snapshot["anomalies"][:-10]
                except Exception as e:
                    print(f"[sampler] anomaly: {e}")

                # Active-defence detectors (threatmon). SAME fault-isolation
                # contract as the anomaly block above: its own try/except, fails
                # closed, and can never take down this thread -- which also owns
                # GPU, disk, battery and network sampling. Findings are already
                # deduped, MITRE-tagged and written to the audit chain inside
                # threatmon.record(); here we only mirror them into the HUD's
                # capped rolling list for the SECURITY panel to read.
                try:
                    import threatmon
                    for rec in threatmon.poll(processes):
                        _snapshot["detections"].append({
                            "at": rec.get("ts"),
                            "detector": rec.get("detector"),
                            "technique": rec.get("technique"),
                            "severity": rec.get("severity", "warn"),
                            "name": rec.get("name"),
                            "pid": rec.get("pid"),
                            "path": rec.get("path"),
                            "target": rec.get("target"),
                            "rights": rec.get("rights", []),
                        })
                    del _snapshot["detections"][:-20]
                except Exception as e:
                    print(f"[sampler] threatmon: {e}")

            # Every 30s: vault note count
            if tick % 30 == 0:
                _snapshot["note_count"] = _count_notes()

            # Every 10 min: weather (network call, kept well off the request path)
            if tick % 600 == 0:
                try:
                    from skills import weather_skill
                    _snapshot["weather"] = weather_skill.get_weather("")
                except Exception:
                    pass

            _publish_hud_telemetry()
            _publish_hud_security()

        except Exception as e:
            print(f"[sampler] {e}")

        tick += 1
        time.sleep(1)


threading.Thread(target=sampler, daemon=True).start()

# Fill the conversational response pools before the first exchange, so even the
# opening "thanks" is a fresh line rather than the canned fallback. Non-fatal
# and fully asynchronous -- see skills/social_skill.py.
try:
    social_skill.prewarm()
except Exception as e:
    print(f"[social] prewarm skipped: {e}")


class VoiceStateRequest(BaseModel):
    state: str


class CommandRequest(BaseModel):
    text: str


class CommandResponse(BaseModel):
    reply: str
    # Which capability produced this. Sent so the HUD can SHOW it: a
    # misrouted command usually returns something plausible, and the only
    # clue is the answer feeling slightly off. "PRIVACY WATCH" lighting up
    # when you asked about your camera is confirmation; "CHAT" lighting up is
    # the bug, visible immediately.
    skill: str = ""
    action: str = ""
    auth_required: bool = False
    confirmation_required: bool = False
    auth_level: int | None = None
    auth_requirement: str = ""
    # How the request ENDED, and which path it took (see route_trace.py). Additive:
    # a client that does not know these fields ignores them. status is exactly one
    # of COMPLETED / FAILED / DENIED / TIMEOUT / CANCELLED, so "did that finish, or
    # was I ignored" has an answer that is not inferred from silence.
    request_id: str = ""
    status: str = ""
    route: str = ""


@app.get("/", response_class=HTMLResponse)
def hud():
    """Serves the HUD itself.

    ROOT CAUSE FIX: the HUD used to load from file:// and had to be handed the
    session token by the Python side after page load. That handoff raced against
    page load and behaved differently across pywebview versions — when it lost,
    every request returned 401 and the HUD reported "orchestrator unreachable"
    while system stats stayed blank.

    Serving it from here makes it same-origin and lets the token be substituted
    into the HTML server-side, before the browser ever sees it. There is nothing
    left to race."""
    return hud_v2()


def _verify_v2_file(path: str) -> tuple[bool, str]:
    """Do not hand the local session bridge to an unsigned V2 artefact."""
    import integrity
    return integrity.verify_one(integrity.manifest_key(path))


@app.get("/v2/", response_class=HTMLResponse)
def hud_v2():
    """Serve the signed V2 production entry point from the API origin.

    Relative Vite asset URLs resolve under /v2/, avoiding a development server,
    CORS dependency, or a token baked into the bundle.
    """
    index_path = paths.resource("hud-v2", "dist", "index.html")
    try:
        with open(index_path, encoding="utf-8") as f:
            html = f.read()
    except OSError as e:
        print(f"[hud] HUD V2 build missing: {e}")
        return HTMLResponse("<pre>ARGUS HUD V2 build is unavailable.</pre>", status_code=503)

    ok, detail = _verify_v2_file(index_path)
    if not ok:
        security.security_event(security.SECURITY_POLICY_CHANGED,
                                component="hud_v2", reason="integrity_mismatch",
                                status="failed")
        return HTMLResponse(
            "<pre>ARGUS HUD V2 was not served because its signed build "
            f"could not be verified. {detail}</pre>", status_code=409)

    # Runtime-only, same-origin session bridge. json.dumps prevents a token
    # character from becoming executable markup; it never enters Vite output.
    bridge = f"<script>window.__ARGUS_TOKEN__={json.dumps(security.SESSION_TOKEN)};</script>"
    if "<head>" not in html:
        return HTMLResponse("<pre>ARGUS HUD V2 entry point is malformed.</pre>", status_code=500)
    print("[hud] HUD V2 entry verified and served")
    return HTMLResponse(html.replace("<head>", f"<head>{bridge}", 1))


@app.get("/v2/assets/{asset_path:path}")
def hud_v2_asset(asset_path: str):
    """Serve only signed V2 assets; reject traversal and missing build files."""
    asset_root = os.path.abspath(paths.resource("hud-v2", "dist", "assets"))
    candidate = os.path.abspath(os.path.join(asset_root, asset_path))
    try:
        contained = os.path.commonpath((asset_root, candidate)) == asset_root
    except ValueError:
        contained = False
    if not contained or not os.path.isfile(candidate):
        return PlainTextResponse("HUD V2 asset not found.", status_code=404)
    ok, detail = _verify_v2_file(candidate)
    if not ok:
        print(f"[hud] blocked unsigned V2 asset: {asset_path} ({detail})")
        return PlainTextResponse("HUD V2 asset verification failed.", status_code=409)
    return FileResponse(candidate)


@app.get("/health")
def health():
    return {"status": "alive"}


@app.get("/zt")
def zt_posture():
    """The zero-trust posture, for the HUD's security panel.

    Read-only session state behind the same token middleware as every other
    reading. Deliberately a separate endpoint rather than a field bolted onto
    /telemetry: the score is derived from security events, not host metrics,
    and its update cadence is event-driven rather than sampler-driven.
    """
    import zt
    return zt.posture()


@app.get("/ollama-check")
def ollama_check():
    """Real reachability check for the boot sequence's HUD overlay -- not a
    scripted always-succeeds line. Hits Ollama's lightweight /api/tags
    (lists installed models) rather than /api/chat, so this reports whether
    the Ollama server itself is up without waiting on a model load."""
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=3)
        r.raise_for_status()
        models = r.json().get("models", [])
        return {"ok": True, "model_count": len(models)}
    except Exception as e:
        return {"ok": False, "detail": str(e)[:120]}


@app.post("/voice-state")
def set_voice_state(req: VoiceStateRequest):
    voice_state["state"] = req.state
    return {"ok": True}


# ── the HUD tells us when it has finished waking ─────────────────────────────
#
# ARGUS greeted as soon as the SPEECH WORKERS were ready, which has nothing to
# do with whether the window is up. In practice that meant it talked over the
# wake video's own narration, or before the user had even clicked to start it
# -- audio arriving from a program that, as far as the screen was concerned,
# had not opened yet.
#
# The orchestrator runs in argus.py's process, so it can hold the shared
# multiprocessing Event that the separate voice process waits on. This is the
# only thing that sets it.
_hud_awake = {"event": None}


def set_hud_awake_event(ev) -> None:
    """Called once by argus.py before the server starts."""
    _hud_awake["event"] = ev


@app.post("/hud-awake")
def post_hud_awake():
    """The wake sequence has finished and the interface is visible.

    Idempotent: the HUD may send this more than once (a reload, a skipped
    wake), and setting an already-set Event is harmless.
    """
    ev = _hud_awake.get("event")
    if ev is not None:
        ev.set()
    return {"ok": True}


class UnlockRequest(BaseModel):
    secret: str = ""


@app.post("/unlock")
def post_unlock(req: UnlockRequest):
    """Authenticate from the HUD's own PIN field.

    WHY THIS EXISTS AS ITS OWN ENDPOINT. Until now the only way to unlock was
    to SAY or TYPE the PIN as an ordinary command ("unlock argus 12345678"),
    which routed through router -> auth. That works, but it drags raw
    authentication material through the command path: the transcript box, the
    conversation history, the follow-up resolver and anything else that sees a
    user utterance. A dedicated endpoint keeps the secret on one short path --
    request body -> auth.verify() -> discarded -- and lets the HUD render it
    masked, which a command box cannot do.

    The value is handed to EVERY configured factor rather than parsed into one,
    exactly as router.py does, so the reply cannot reveal which factor was
    being checked or which one failed. auth.verify() owns the lockout, the
    backoff and the deliberately identical failure message; nothing here
    second-guesses it, and nothing here logs the secret.
    """
    supplied = {name: req.secret for name in auth.AUTH_REQUIRED_FACTORS}
    ok, message = auth.verify(supplied)
    # Never echo, never log, never keep. The local name is rebound so a later
    # traceback frame cannot carry it either.
    supplied = req.secret = None
    return {
        "ok": bool(ok),
        # auth.verify() returns ("", True) when auth is disabled in config;
        # an empty string reaching the UI would look like a silent failure.
        "message": message or ("Unlocked." if ok else "That didn't work."),
        "status": auth.status(),
    }


@app.post("/lock")
def post_lock():
    """Lock immediately from the HUD, without waiting for the idle timer."""
    auth.lock("locked from the HUD")
    return {"ok": True, "status": auth.status()}


# ── timezone ─────────────────────────────────────────────────────────────────
#
# NOT in settings.py's FIELDS table, and that is a constraint rather than a
# choice: settings.py is integrity-CRITICAL and ACL-hardened, so a preference
# the owner is expected to change cannot live there without turning every
# change into a re-seal. It lives in the writable state directory instead (see
# pc_skill), and these two endpoints are how the SETTINGS panel reaches it.


class TimezoneRequest(BaseModel):
    timezone: str = ""


@app.get("/timezone")
def get_timezone():
    try:
        from skills import pc_skill
        return pc_skill.timezone_status()
    except Exception as e:
        return {"error": f"{type(e).__name__}", "following_machine": True}


@app.post("/timezone")
def post_timezone(req: TimezoneRequest):
    """Set or clear the timezone ARGUS answers with.

    Gated as ("pc", "timezone"), which has no entry in auth.LEVELS and so
    lands on the fail-closed default -- a fresh authentication. That is the
    right gate: it changes what every later answer about time means.
    """
    allowed, reason = auth.authorize("pc", "timezone", req.timezone or "")
    if not allowed:
        return {"ok": False, "message": reason, "needs_auth": True}
    try:
        from skills import pc_skill
        message = pc_skill.set_timezone(req.timezone or "")
        st = pc_skill.timezone_status()
    except Exception as e:
        return {"ok": False, "message": f"That didn't work ({type(e).__name__})."}
    auth.touch()
    # ok reflects whether it was ACCEPTED, not merely whether the call
    # returned: set_timezone refuses an unrecognised name and says so, and
    # reporting that as success would leave the panel showing a zone that is
    # not in effect.
    accepted = bool(st["following_machine"]) or bool(st["configured"])
    return {"ok": accepted and "don't recognise" not in message,
            "message": message, "status": st}


# ── guided repair ────────────────────────────────────────────────────────────
#
# THE BUTTON DOES NOT REPAIR ANYTHING. /repair/offer stages and returns the
# question; /repair/apply carries out what was staged. Two calls, with a human
# between them, for the same reason the spoken path works that way -- and the
# HUD is not a way around the gate: both go through auth.authorize() under the
# real (skill, action) pair, so a click is authorised exactly as a spoken
# "fix it" is. There is no path here that takes a target from the request.


@app.post("/repair/offer")
def post_repair_offer():
    """Stage a repair for the newest fixable finding and return the question."""
    allowed, reason = auth.authorize("remedy", "offer")
    if not allowed:
        return {"ok": False, "staged": False, "message": reason}
    try:
        from threatmon import remedy as _remedy
        message = _remedy.offer()
        p = _remedy.pending()
    except Exception as e:
        return {"ok": False, "staged": False,
                "message": f"I couldn't work that out ({type(e).__name__})."}
    auth.touch()
    return {"ok": True, "staged": bool(p), "message": message,
            "fix": p.get("fix", ""), "detail": p.get("detail", "")}


@app.post("/repair/apply")
def post_repair_apply():
    """Carry out the staged repair. Nothing else can reach this."""
    allowed, reason = auth.authorize("remedy", "apply")
    if not allowed:
        # The L2 refusal is the common case here and is not an error: it means
        # the PIN is stale, and the HUD's own unlock panel is the answer. Said
        # in the words auth chose rather than reworded.
        return {"ok": False, "message": reason, "needs_auth": True}
    try:
        from threatmon import remedy as _remedy
        message = _remedy.apply_pending()
    except Exception as e:
        return {"ok": False,
                "message": f"That went wrong ({type(e).__name__})."}
    auth.touch()
    return {"ok": True, "message": message}


@app.post("/repair/cancel")
def post_repair_cancel():
    try:
        from threatmon import remedy as _remedy
        return {"ok": True, "message": _remedy.cancel()}
    except Exception as e:
        return {"ok": False, "message": f"{type(e).__name__}"}


@app.get("/auth-status")
def get_auth_status():
    """Lock state for the UNLOCK panel. Says nothing about which factors exist
    or which one last failed -- auth.status() is already written to that rule."""
    return auth.status()


class FaceToggleRequest(BaseModel):
    on: bool = False


@app.get("/face/status")
def face_status():
    """Enrolment and presence-watch state for the FACE panel."""
    try:
        import faceauth
        return faceauth.status()
    except Exception as e:
        return {"available": False, "error": f"{type(e).__name__}: {e}"}


@app.post("/face/enroll")
def face_enroll():
    """Learn the owner's face. Stores histograms only -- never an image.

    These four routes used to call straight into faceauth with no
    auth.authorize() at all -- unlike the identical (skill, action) pairs on
    the voice/text path, which always go through router._dispatch_inner()'s
    unconditional gate. The only thing standing between "locked" and
    re-enrolling whoever is in front of the camera as the recognised owner
    was the generic per-launch session token, which SECURITY.md's own threat
    model already treats as readable by any process running as this user.
    Gated the same as router.py gates it: ("face","enroll") is L2_REAUTH.
    """
    allowed, reason = auth.authorize("face", "enroll")
    if not allowed:
        return {"ok": False, "message": reason, "needs_auth": True}
    try:
        import faceauth
        msg = faceauth.enroll()
        security.audit("face_enroll", f"enrolled={faceauth.is_enrolled()}", "ok")
        auth.touch()
        return {"ok": faceauth.is_enrolled(), "message": msg,
                "status": faceauth.status()}
    except Exception as e:
        return {"ok": False, "message": f"Enrolment failed ({type(e).__name__})."}


@app.post("/face/forget")
def face_forget():
    """("face","forget") is L1_UNLOCKED -- see face_enroll's note above on why
    this route needs the same gate the voice path already has: unauthenticated,
    this was a one-shot way to erase a configured auth factor out from under
    the owner."""
    allowed, reason = auth.authorize("face", "forget")
    if not allowed:
        return {"ok": False, "message": reason, "needs_auth": True}
    try:
        import faceauth
        msg = faceauth.forget()
        security.audit("face_forget", "deleted", "ok")
        auth.touch()
        return {"ok": True, "message": msg, "status": faceauth.status()}
    except Exception as e:
        return {"ok": False, "message": f"Couldn't delete ({type(e).__name__})."}


@app.post("/face/check")
def face_check():
    """'Do you recognise me?' -- the greeting path. No security DECISION (face
    alone never unlocks anything, see PRESENCE_ONLY_FACTORS), but it still
    activates the camera, so it gets the same L1_UNLOCKED gate the voice path
    already applies -- see face_enroll's note above."""
    allowed, reason = auth.authorize("face", "check")
    if not allowed:
        return {"ok": False, "message": reason, "needs_auth": True}
    try:
        import faceauth
        ok, msg = faceauth.recognise()
        auth.touch()
        return {"ok": ok, "message": msg, "status": faceauth.status()}
    except Exception as e:
        return {"ok": False, "message": f"Camera check failed ({type(e).__name__})."}


@app.post("/face/presence")
def face_presence(req: FaceToggleRequest):
    """Turn the walk-away auto-lock on or off. Maps to the same ("face",
    "watch"/"unwatch") pair the voice path uses -- see face_enroll's note
    above; unauthenticated, this could silently disable the auto-lock without
    ever unlocking the session."""
    action = "watch" if req.on else "unwatch"
    allowed, reason = auth.authorize("face", action)
    if not allowed:
        return {"ok": False, "message": reason, "needs_auth": True}
    try:
        import faceauth
        msg = faceauth.set_presence(req.on)
        auth.touch()
        return {"ok": faceauth.presence_enabled(), "message": msg,
                "status": faceauth.status()}
    except Exception as e:
        return {"ok": False, "message": f"Couldn't change that ({type(e).__name__})."}


@app.post("/clear-memory")
def clear_memory():
    """Discard the persisted conversation history.

    This is a DESTRUCTIVE action -- the transcript is permanently gone -- and
    it used to sit behind only the ambient bearer token, with no
    authorization and no record. Zero trust says a state-changing admission
    carries its OWN authorization and audit, not whatever the token happens
    to allow. So it is gated at ("history","clear") == L2_REAUTH (a fresh
    authentication, the same class as profile/forget), exactly as a spoken
    equivalent would be, and the action is recorded on the audit chain.
    """
    allowed, reason = auth.authorize("history", "clear")
    if not allowed:
        security.audit("blocked", "history/clear denied", reason[:60])
        return {"ok": False, "message": reason, "needs_auth": True}

    with _history_lock:
        conversation_history.clear()
    # Also drop the persisted copy. Without this, clearing memory would appear
    # to work and then the whole conversation would come back on next launch --
    # a "forget this" that doesn't forget is worse than no button at all.
    history_store.clear()

    # On the record, on the same chain that protects everything else. A clear
    # that happened but could never be shown to have happened is a clear that
    # the user cannot later verify -- and an attacker clearing history to cover
    # tracks is exactly the event the audit chain exists to reveal.
    try:
        security.audit("history_cleared", "conversation history discarded", "ok")
        security.security_event(security.CONFIG_CHANGED, component="history_store",
                                reason="user_clear", status="ok")
    except Exception:
        pass
    auth.touch()
    return {"ok": True}


@app.get("/audit-log")
def audit_log():
    """Raw audit log for the HUD's export button. Same file the 'activity
    log' voice command reads a tail of (security.read_audit); this returns
    the whole thing as plain text so it can be downloaded as a file, not
    spoken. Already behind the standard token-auth middleware -- no wider
    exposure than any other endpoint here."""
    if not security._AUDIT_PATH or not os.path.exists(security._AUDIT_PATH):
        return PlainTextResponse("No activity recorded yet.")
    try:
        with open(security._AUDIT_PATH, "r", encoding="utf-8") as f:
            return PlainTextResponse(f.read())
    except OSError as e:
        return PlainTextResponse(f"Couldn't read the audit log: {e}", status_code=500)


# ─────────────────────────────────────────────────────────────────────
# APP PANELS
#
# The HUD is an ambient dashboard; these back the panels that make it an
# application you can inspect and configure rather than only watch. All of
# them sit behind the same token middleware as every other endpoint.
# ─────────────────────────────────────────────────────────────────────

@app.get("/about")
def about():
    """Identity, version, licence and provenance."""
    import platform

    import integrity
    import paths as _paths

    res = integrity.verify()
    return {
        "name": config.ASSISTANT_NAME,
        "version": config.APP_VERSION,
        # The AUTHOR is not the same field as the user of the machine. They
        # happen to be the same person here, but USER_FULL_NAME is a setting
        # that feeds the speech prompt and can be changed, and authorship is
        # not something a settings edit should be able to reassign.
        "author": config.COPYRIGHT_HOLDER,
        "copyright": f"Copyright (C) {config.COPYRIGHT_YEAR} "
                     f"{config.COPYRIGHT_HOLDER}",
        "created": config.CREATED,
        "licence": "GPL-3.0-or-later",
        "licence_reason": (
            "Speech synthesis uses piper-tts, which is GPL-3.0 because Piper "
            "links espeak-ng. The packaged executable contains it, so ARGUS "
            "adopts the same licence rather than shipping a binary whose "
            "terms differ from its source."),
        "build": "frozen" if _paths.is_frozen() else "source",
        "python": platform.python_version(),
        "os": f"{platform.system()} {platform.release()}",
        "install_root": integrity.ROOT,
        "vault": config.VAULT_PATH,
        "files_verified": len(integrity.protected_files()),
        "integrity": res.summary(),
        "integrity_ok": res.ok,
    }


@app.get("/settings")
def get_settings():
    import settings as _settings

    return {"fields": _settings.all_settings(),
            "needs_restart": _settings.needs_restart(),
            "path": _settings.SETTINGS_PATH}


class SettingsRequest(BaseModel):
    changes: dict = {}


@app.post("/settings")
def post_settings(req: SettingsRequest):
    """Apply setting changes.

    Security-class fields are refused here rather than in the UI. A panel that
    merely hides a control is not a control: the refusal has to live on the
    server, because the client is a web view and anything it can render it can
    also be made to POST.
    """
    import settings as _settings

    applied, rejected = _settings.update(req.changes)
    if applied:
        security.security_event(security.CONFIG_CHANGED, component="settings",
                                count=len(applied), reason="user_edit",
                                status="ok")
    for name, why in rejected:
        if "security setting" in why:
            security.security_event(security.SECURITY_POLICY_CHANGED,
                                    component="settings", reason="refused",
                                    status="failed")
    return {"applied": applied,
            "rejected": [{"name": n, "reason": r} for n, r in rejected],
            "needs_restart": _settings.needs_restart()}


class ResetRequest(BaseModel):
    name: str = ""


@app.post("/settings/reset")
def post_settings_reset(req: ResetRequest):
    """Drop one override, or every override with an empty name.

    Restores the shipped value in the running process too, not just in the
    file -- see settings.reset(). A reset that leaves the old value running is
    not a reset.
    """
    import settings as _settings

    removed = _settings.reset(req.name)
    if removed:
        security.security_event(security.CONFIG_CHANGED, component="settings",
                                count=removed, reason="user_reset", status="ok")
    return {"removed": removed, "needs_restart": _settings.needs_restart()}


@app.get("/skills")
def list_skills():
    """What ARGUS can actually be asked to do.

    Built from intent.py's declared fast paths rather than written by hand, so
    it cannot describe a command that does not exist -- or omit one that does.
    Discoverability is a real fix here: the commonest complaint about a voice
    assistant is not knowing what it understands.
    """
    import re

    import intent
    import paths as _paths

    src_path = _paths.resource("intent.py")
    try:
        with open(src_path, encoding="utf-8") as f:
            src = f.read()
        unreadable = ""
    except OSError as e:
        # Frozen builds have no .py files on disk unless intent.py was bundled
        # as data (build_exe.py does this deliberately). Say so rather than
        # returning an empty list, which would read as "ARGUS can do nothing".
        src, unreadable = "", f"{type(e).__name__}: {src_path}"
    pairs = sorted(set(re.findall(
        r'"skill":\s*"(\w+)",\s*"action":\s*"(\w+)"', src)))

    EXAMPLES = {
        ("apps", "open"): "open telegram",
        ("apps", "close"): "close telegram",
        ("apps", "list"): "what apps are running",
        ("calc", "calculate"): "what is 15% of 240",
        ("calc", "convert"): "convert 10 km to miles",
        ("control", "volume_set"): "set volume to 40",
        ("control", "mute"): "mute",
        ("control", "clipboard_read"): "read my clipboard",
        ("files", "find"): "find my cv",
        ("files", "delete"): "delete the file called notes",
        ("knowledge", "define"): "define serendipity",
        ("knowledge", "lookup"): "look up Uzbekistan",
        ("knowledge", "translate"): "translate hello to French",
        ("net", "ip"): "what is my ip",
        ("net", "online"): "am I online",
        ("pc", "time"): "what time is it",
        ("pc", "stats"): "what is my cpu usage",
        ("pc", "battery"): "how much battery do I have",
        ("storage", "free"): "how much disk space is left",
        ("storage", "largest"): "what is taking up space in my downloads",
        ("pc", "snapshot"): "take a screenshot",
        ("power", "request"): "shut down the computer",
        ("privacy", "on"): "privacy mode",
        ("privacy", "off"): "start listening",
        ("profile", "remember"): "remember that I like tea",
        ("research", "quick"): "search for python tutorials",
        ("timer", "set"): "set a timer for 5 minutes",
        ("vault", "write"): "make a note that I need milk",
        ("weather", "get"): "what is the weather",
        ("window", "minimize_all"): "minimise all windows",
        ("youtube", "play"): "play lofi on youtube",
    }
    groups: dict = {}
    for skill, action in pairs:
        groups.setdefault(skill, []).append(
            {"action": action, "example": EXAMPLES.get((skill, action), "")})
    return {"count": len(pairs),
            "groups": [{"skill": k, "actions": v} for k, v in sorted(groups.items())],
            "unreadable": unreadable,
            "note": "You can also just ask ARGUS anything — questions that "
                    "match none of these go to the language model."}



#
# Read-only status + job submission/cancellation, all behind the same token
# middleware as every other acting endpoint (nothing here is in PUBLIC_PATHS,
# so an unauthenticated call never sees even the agent list). Responses carry
# job text only through security.redact -- an objective is free-form user
# input, the same way a command is.


class AgentJobRequest(BaseModel):
    objective: str = ""
    priority: int | None = None


class AgentRouteRequest(BaseModel):
    """Auto-routed submission (V2 §16): the backend picks the agent with a
    deterministic keyword table over REGISTERED, ENABLED agents only -- the
    model is never asked to invent a destination, and the response names the
    agent it chose so the caller is never left guessing."""
    objective: str = ""
    priority: int | None = None


class AutonomyRequest(BaseModel):
    """Owner kill-switch payload for the agents' bounded autonomy scheduler."""
    enabled: bool


@app.get("/api/agents")
def agents_list():
    from agents.coordinator import coordinator as _agents_coordinator
    out = _agents_coordinator().status(redact=security.redact)
    try:
        from agents import autonomy
        out["autonomy"] = {k: v for k, v in autonomy.status().items()
                           if k != "schedule"}
    except Exception:
        out["autonomy"] = {"enabled": False}
    return out


@app.get("/api/agents/jobs")
def agents_jobs():
    from agents.coordinator import coordinator as _agents_coordinator
    coord = _agents_coordinator()
    return {"jobs": coord.jobs(limit=25, redact=security.redact),
            "queue_depth": coord.queue_depth()}


@app.get("/api/agents/jobs/{job_id}")
def agents_job_detail(job_id: str):
    from agents.coordinator import coordinator as _agents_coordinator
    job = _agents_coordinator().job(job_id, redact=security.redact)
    if job is None:
        return JSONResponse({"detail": "No such job."}, status_code=404)
    return job


@app.post("/api/agents/{agent_id}/jobs")
def agents_submit(agent_id: str, req: AgentJobRequest):
    from agents.coordinator import coordinator as _agents_coordinator
    job, why = _agents_coordinator().submit(
        agent_id, req.objective, req.priority)
    if job is None:
        status_code = 404 if why == "unknown_agent" else 429
        return JSONResponse({"detail": why}, status_code=status_code)
    security.audit("agent_job_submit", f"{agent_id} {job.job_id}", "ok")
    return {"job_id": job.job_id, "agent_id": agent_id, "state": job.state}


@app.post("/api/agents/route")
def agents_routed_submit(req: AgentRouteRequest):
    """Submit an objective to whichever registered specialist the deterministic
    router selects (fallback: assistant). Same validation, queue, capability
    boundary and events as a direct submission -- routing only picks the
    destination, it grants nothing."""
    from agents.coordinator import coordinator as _agents_coordinator
    from agents.routing import route
    reg = registry_all_ids()
    agent_id = route(req.objective, enabled_ids=reg)
    job, why = _agents_coordinator().submit(
        agent_id, req.objective, req.priority)
    if job is None:
        return JSONResponse({"detail": why, "agent_id": agent_id},
                            status_code=429)
    security.audit("agent_job_submit", f"route->{agent_id} {job.job_id}", "ok")
    return {"job_id": job.job_id, "agent_id": agent_id, "state": job.state,
            "routed": True}


def registry_all_ids() -> set[str]:
    """Enabled agent ids for the router's candidate set."""
    from agents.registry import registry as _registry
    return {rt.spec.id for rt in _registry().all() if rt.spec.enabled}


@app.delete("/api/agents/jobs/{job_id}")
def agents_cancel(job_id: str):
    from agents.coordinator import coordinator as _agents_coordinator
    ok, why = _agents_coordinator().cancel(job_id)
    if not ok:
        return JSONResponse({"detail": why}, status_code=404)
    security.audit("agent_job_cancel", job_id, "ok")
    return {"ok": True, "detail": why}


@app.post("/api/agents/autonomy")
def agents_autonomy_toggle(req: AutonomyRequest):
    """Owner kill-switch for the bounded autonomy scheduler. Off means the
    loop stops dispatching within one interval; the request-driven layer is
    unaffected. Audited like every owner action."""
    from agents import autonomy
    st = autonomy.set_enabled(bool(req.enabled))
    return st


@app.get("/api/agents/autonomy")
def agents_autonomy_status():
    from agents import autonomy
    return autonomy.status()


# ── Dynamic (temporary) agents API ───────────────────────────────────────────
#
# agents/ephemeral.py owns all of it. Same token middleware as every endpoint
# above; same rule: an agent may be created ONLY by running a request through
# Architect -> Governor -> Policy. There is no endpoint that builds an agent
# from a client-supplied spec, and nothing here can grant a capability -- a
# request that names one the parent lacks is denied and audited. GET is the
# read-only view a frontend needs for "CORE AGENTS: 10 / TEMP AGENTS: N" and
# the parent -> child tree; task text and summaries pass through redact().


class DynamicSpawnRequest(BaseModel):
    task: str = ""
    role: str = ""            # a hint for choosing a specialist template
    parent: str = ""          # optional core agent to spawn under (owner only)
    capabilities: list[str] = []
    data_classes: list[str] = []


class DynamicEnabledRequest(BaseModel):
    enabled: bool


@app.get("/api/agents/dynamic")
def agents_dynamic():
    from agents import ephemeral
    return ephemeral.manager().snapshot(redact=security.redact)


@app.post("/api/agents/dynamic/spawn")
def agents_dynamic_spawn(req: DynamicSpawnRequest):
    from agents import ephemeral
    out = ephemeral.manager().request_spawn(
        "owner", req.task, role_hint=req.role, parent=req.parent,
        capabilities=req.capabilities, data_classes=req.data_classes,
        source="api")
    return JSONResponse(out.as_dict(), status_code=200 if out.approved else 403)


@app.delete("/api/agents/dynamic/{agent_id}")
def agents_dynamic_destroy(agent_id: str):
    from agents import ephemeral
    if not ephemeral.manager().destroy(agent_id, "owner_cancel"):
        return JSONResponse({"detail": "No such temporary agent."},
                            status_code=404)
    security.audit("agent_dynamic_destroy", agent_id[:16], "ok")
    return {"ok": True}


@app.post("/api/agents/dynamic/enabled")
def agents_dynamic_enabled(req: DynamicEnabledRequest):
    """Owner kill switch for temporary agents. OFF refuses every new spawn and
    destroys the live ones."""
    from agents import ephemeral
    return ephemeral.manager().set_enabled(bool(req.enabled), by="owner")



#
# agents/orchestrator.py owns all of it. Same token middleware; same rule as
# everything above: the orchestrator is not a policy, auth or execution
# authority, and it is never in front of a trivial request -- POST declines a
# goal a single agent can handle (naming that agent) without a model call.
# Nothing here decides local-vs-cloud (upstream routing owns that). GET views
# are the data a frontend needs for AGENT TEAM / tasks / tree; task text and
# summaries pass through redact().


class TeamSubmitRequest(BaseModel):
    goal: str = ""
    material: str = ""            # optional owner-supplied text (code, logs)
    request_id: str = ""          # optional; the same id names the same team
    priority: int = 2
    max_runtime_seconds: int | None = None
    max_model_calls: int | None = None


class TeamCancelRequest(BaseModel):
    reason: str = "owner_cancel"


@app.get("/api/agents/teams")
def agents_teams():
    from agents.orchestrator import orchestrator
    o = orchestrator()
    return {"teams": o.teams(redact=security.redact), **o.status()}


@app.post("/api/agents/teams/assess")
def agents_teams_assess(req: TeamSubmitRequest):
    """Would this goal warrant a team? Pure, no side effects, no model call."""
    from agents.orchestrator import orchestrator
    return orchestrator().assess(req.goal, req.material)


@app.post("/api/agents/teams")
def agents_teams_submit(req: TeamSubmitRequest):
    from agents.orchestrator import orchestrator
    sub = orchestrator().submit_complex_task(
        req.goal, req.material, request_id=req.request_id[:40],
        priority=max(1, min(4, int(req.priority))),
        max_runtime_seconds=req.max_runtime_seconds,
        max_model_calls=req.max_model_calls)
    if not sub.accepted:
        code = 429 if sub.reason == "max_active_teams" else 422
        return JSONResponse(sub.as_dict(), status_code=code)
    security.audit("agent_team_submit", sub.team_id, "ok")
    return sub.as_dict()


@app.get("/api/agents/teams/{team_id}")
def agents_team_detail(team_id: str):
    from agents.orchestrator import orchestrator
    out = orchestrator().team(team_id, redact=security.redact)
    if out is None:
        return JSONResponse({"detail": "No such team."}, status_code=404)
    return out


@app.get("/api/agents/teams/{team_id}/tasks")
def agents_team_tasks(team_id: str):
    from agents.orchestrator import orchestrator
    out = orchestrator().tasks(team_id, redact=security.redact)
    if out is None:
        return JSONResponse({"detail": "No such team."}, status_code=404)
    return {"team_id": team_id, "tasks": out}


@app.get("/api/agents/teams/{team_id}/tree")
def agents_team_tree(team_id: str):
    from agents.orchestrator import orchestrator
    out = orchestrator().tree(team_id, redact=security.redact)
    if out is None:
        return JSONResponse({"detail": "No such team."}, status_code=404)
    return {"team_id": team_id, "tree": out}


@app.post("/api/agents/teams/{team_id}/cancel")
def agents_team_cancel(team_id: str, req: TeamCancelRequest | None = None):
    from agents.orchestrator import orchestrator
    reason = (req.reason if req is not None else "owner_cancel")[:40]
    if not orchestrator().cancel_team(team_id, reason):
        return JSONResponse({"detail": "No such active team."}, status_code=404)
    return {"ok": True, "team_id": team_id}


# ── Agent Manager + CEO inbox ────────────────────────────────────────────────
#
# agents/agent_manager.py + agents/inbox.py own all of it. Same token
# middleware as every endpoint above. The Manager coordinates and talks; it is
# not an authority: a goal posted here goes through the same planner,
# orchestrator, Architect -> Governor pipeline as a team request, a CEO reply
# is routed data (never an auth factor), and a chat message to an agent
# becomes an ordinary analysis job -- nothing here executes anything. Text
# passes through inbox.clean() on the way in and security.redact() on the way
# out.


class ManagerGoalRequest(BaseModel):
    goal: str = ""
    material: str = ""


class InboxReplyRequest(BaseModel):
    text: str = ""
    choice: str = ""


class AgentChatRequest(BaseModel):
    text: str = ""


class AcademyTrainRequest(BaseModel):
    agent_ids: list[str] = []
    topic: str = ""


def _redact_msgs(items: list) -> list:
    for m in items:
        m["title"] = security.redact(m["title"])
        m["body"] = security.redact(m["body"])
        for r in m["replies"]:
            r["text"] = security.redact(r["text"])
    return items


@app.get("/api/agents/manager")
def agents_manager_state():
    from agents.agent_manager import agent_manager
    return agent_manager().state(redact=security.redact)


@app.post("/api/agents/manager/goals")
def agents_manager_goal(req: ManagerGoalRequest):
    from agents.agent_manager import agent_manager
    out = agent_manager().submit_goal(req.goal[:1200], req.material[:6000])
    security.audit("agent_manager_goal", f"{out.get('outcome')} "
                   f"{out.get('team_id') or out.get('hire_id') or out.get('job_id') or ''}",
                   "ok" if out.get("outcome") not in ("failed", "declined") else "declined")
    return JSONResponse(out, status_code=422 if out.get("outcome") == "declined" else 200)


@app.get("/api/agents/inbox")
def agents_inbox(thread: str = "", limit: int = 60):
    from agents.inbox import inbox
    box = inbox()
    return {"messages": _redact_msgs(box.messages(thread=thread[:40], limit=limit)),
            "summary": box.summary()}


@app.post("/api/agents/inbox/{message_id}/reply")
def agents_inbox_reply(message_id: str, req: InboxReplyRequest):
    from agents.agent_manager import agent_manager
    # 6000: an answer to "I need the code" IS the code (the inbox keeps a
    # 400-char display copy; the orchestrator scrubs the material itself).
    out = agent_manager().reply(message_id[:20], text=req.text[:6000], choice=req.choice[:24])
    if not out.get("ok") and out.get("reason") in ("no_such_message", "not_replyable",
                                                   "invalid_choice", "choice_required",
                                                   "empty_reply", "already_answered"):
        return JSONResponse(out, status_code=404 if out["reason"] == "no_such_message" else 422)
    security.audit("agent_inbox_reply", f"{message_id[:20]} -> {out.get('routed_to', '')}",
                   "ok" if out.get("ok") else "failed")
    return out


@app.post("/api/agents/inbox/{message_id}/read")
def agents_inbox_read(message_id: str):
    from agents.inbox import inbox
    if not inbox().mark_read(message_id[:20]):
        return JSONResponse({"detail": "No such message."}, status_code=404)
    return {"ok": True}


@app.post("/api/agents/{agent_id}/chat")
def agents_chat(agent_id: str, req: AgentChatRequest):
    from agents.agent_manager import agent_manager
    out = agent_manager().chat(agent_id, req.text)
    if out.get("reason") == "unknown_agent":
        return JSONResponse(out, status_code=404)
    security.audit("agent_chat", f"{agent_id[:40]} {out.get('job_id', '')}".strip(),
                   "ok" if out.get("ok") else "declined")
    return out


@app.get("/api/agents/academy")
def agents_academy_state():
    from agents.academy import academy
    return academy().state()


@app.post("/api/agents/academy/train")
def agents_academy_train(req: AcademyTrainRequest):
    from agents.academy import academy
    out = academy().train(req.agent_ids, req.topic[:80])
    security.audit("academy_train", f"{len(out['sessions'])} sessions", "ok" if out["ok"] else "declined")
    return JSONResponse(out, status_code=200 if out["ok"] else 422)


@app.post("/api/agents/academy/{agent_id}/cancel")
def agents_academy_cancel(agent_id: str):
    from agents.academy import academy
    ok = academy().cancel(agent_id.lower()[:40])
    security.audit("academy_cancel", agent_id[:40], "ok" if ok else "declined")
    return JSONResponse({"ok": ok}, status_code=200 if ok else 404)


@app.get("/security-report")
def security_report():
    """The security posture, as it actually is right now.

    Reports what is OFF as plainly as what is on. A security panel that only
    lists green ticks is marketing; the value is in showing the gaps.
    """
    import auth
    import execpolicy
    import integrity
    import netpolicy
    import plugins
    import sandbox
    import secrets_store
    import voiceauth

    res = integrity.verify()
    hardened, acl_note = integrity.acls_hardened()
    install_writable, install_note = integrity.install_dir_writable()
    chain_ok, chain_note = security.verify_chain()
    try:
        privs = len(sandbox.current_privileges())
    except Exception:
        privs = None

    return {
        "integrity": {
            "sealed": res.sealed, "ok": res.ok, "signed": res.signed,
            "signature_valid": res.signature_ok,
            "files": len(integrity.protected_files()),
            "summary": res.summary(),
        },
        "authentication": {
            "enabled": bool(config.AUTH_ENABLED),
            "factors": list(getattr(config, "AUTH_REQUIRED_FACTORS", ())),
            "unlocked": auth.is_unlocked(),
            "pin_hashed": secrets_store.pin_is_hashed(config.COMMAND_PIN),
            "note": ("Authentication is switched off in config.py — every "
                     "level below L5 is permitted."
                     if not config.AUTH_ENABLED else ""),
        },
        "voice": {
            "replay_detection": bool(getattr(config, "VOICE_REPLAY_DETECTION", False)),
            "speaker_verification": voiceauth.speaker_available(),
            "note": "Liveness only — no speaker biometrics installed.",
        },
        "sandbox": {
            "privileges_held": privs,
            "acls_hardened": hardened,
            "acl_note": acl_note,
            # ARGUS-SEC-005: surfaced so a writable install dir is visible
            # rather than a silent DLL-plant foothold.
            "install_dir_writable": install_writable,
            "install_dir_note": install_note,
            "allowed_executables": sorted(execpolicy.ALLOWED_EXECUTABLES),
        },
        "network": {
            "egress_policy": netpolicy.describe()
            if hasattr(netpolicy, "describe") else "allowlist enforced",
            "cloud_enabled": bool(config.CLOUD_ENABLED),
        },
        "skills": {
            "allowlisted": len(plugins.SKILL_PERMISSIONS),
            "violations": len(plugins.verify_permissions()),
        },
        "audit": {
            # Whether the record of what ARGUS did can still be trusted. A
            # security panel that reports every control as healthy while its
            # own evidence trail has been edited is reporting on nothing.
            "chain_intact": chain_ok,
            "chain_note": chain_note,
        },
    }


@app.get("/threat-report")
def threat_report():
    """Active-defence state for the SECURITY panel: per-detector health, the
    MITRE coverage grid, recent detections, and the overall level. Local only,
    behind the same Origin + token middleware as every other endpoint."""
    try:
        import threatmon
        st = threatmon.summary_state()
        st["level"] = threatmon.overall_level()
        return st
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "detectors": [],
                "grid": [], "recent": [], "level": "UNKNOWN"}


@app.get("/security-summary")
def security_summary():
    """The plain-language 'how secure am I' verdict. Synthesised deterministically
    and entirely locally (threatmon.security_summary makes no model or network
    call), so this machine's security telemetry never touches the cloud path."""
    try:
        import threatmon
        return threatmon.security_summary()
    except Exception as e:
        return {"level": "UNKNOWN",
                "verdict": f"Security summary unavailable: {type(e).__name__}.",
                "degraded": ["the summary generator itself failed"],
                "generated_locally": True}


@app.get("/status")
def status():
    return {
        # Carried here rather than templated into the HUD so the footer shows
        # the version the RUNNING backend reports. /about would be the obvious
        # home for it, but /about re-hashes every protected file, which is far
        # too much work for a label the HUD wants once at startup.
        "version": config.APP_VERSION,
        "uptime_seconds": int(time.time() - START_TIME),
        "note_count": _snapshot["note_count"],
        "last_command": last_exchange["text"],
        "last_reply": last_exchange["reply"],
        "last_latency_ms": last_exchange["latency_ms"],
        "voice_state": voice_state["state"],
        "model": OLLAMA_MODEL,
        "muted": _privacy_state(),
        "history_msgs": len(conversation_history),
        "history_max": MAX_HISTORY,
        # Lets the HUD mask what you're about to type in its own on-screen
        # log instead of echoing a PIN attempt in cleartext on screen before
        # the request even sends -- see _sanitize_for_log for the matching
        # server-side leak this closes. Only a boolean: never which action
        # is staged or the PIN itself.
        "pin_pending": _pin_pending(),
        # Which engine answered the LAST completed exchange, and whether
        # cloud routing is configured at all -- the HUD's ENGINE indicator
        # (the HUD V2 status panel) reads this each poll. "local" is always
        # correct even before any exchange has happened, since
        # cloud_gate's own default is "local" until a real cloud call
        # actually succeeds.
        "engine": cloud_gate.get_engine(),
        "cloud_enabled": CLOUD_ENABLED,
        # What is ACTUALLY running, read from config and from the last real call
        # (route_trace.runtime_info) -- additive, the keys above are unchanged.
        "runtime": _runtime_brief(),
    }


def _runtime_brief() -> dict:
    """The few runtime facts the status panel wants. Cached reads only: /status is
    polled every second and must never wait on the model server."""
    try:
        info = route_trace.runtime_info(probe=False)
        return {k: info[k] for k in (
            "current_route", "current_provider", "current_model", "current_engine",
            "local_model", "local_model_available", "cloud_enabled")}
    except Exception:
        return {}


@app.get("/route-trace")
def get_route_trace(n: int = 20, events: bool = False):
    """Per-request debug view: for each recent request, its id, the route it took,
    which provider and model actually answered, how many model calls it cost (and
    how many of those left the machine), retries, latency and how it ended -- plus
    the current runtime and the cloud-call limits.

    Behind the same session-token check as every non-public endpoint. It carries no
    request text (only lengths) and no key material, by construction: see
    route_trace.py."""
    n = max(1, min(int(n), 100))
    return {
        "runtime": route_trace.runtime_info(probe=True),
        "recent": route_trace.recent(n, events=bool(events)),
    }


def _pin_pending() -> bool:
    try:
        from skills import power_skill
        return power_skill.has_pending()
    except Exception:
        return False


def _privacy_state() -> bool:
    try:
        from skills import privacy_skill
        return privacy_skill.is_muted()
    except Exception:
        return False


@app.get("/telemetry")
def telemetry():
    """A snapshot the caller owns outright.

    dict(_snapshot) is a SHALLOW copy, so the returned dict shared its nested
    lists with the live sampler -- confirmed directly: appending to
    _snapshot["anomalies"] afterwards changed the length inside an
    already-returned response. "anomalies" is the one the sampler mutates in
    place (append then del [:-10]) rather than rebinding, and FastAPI
    serializes AFTER this function returns, so the window is wider than it
    looks.

    I could not force a serialization failure in six seconds of hammering, so
    this is a latent aliasing bug rather than an observed crash -- but handing
    a caller a structure that keeps changing underneath it is wrong on its own
    terms, and a per-request list copy is far cheaper than the class of bug it
    removes.
    """
    snap = dict(_snapshot)
    for key, value in snap.items():
        if isinstance(value, list):
            snap[key] = list(value)
    # The live-intel brief rides along on the telemetry the HUD already polls
    # every couple of seconds, rather than on a websocket of its own. That
    # keeps it behind the same Origin + token middleware as every other
    # reading, adds no new endpoint to defend, and needs no reconnect logic --
    # the panel simply appears on the next poll after a search and retires
    # itself when intel_skill's TTL expires.
    try:
        from skills import intel_skill
        snap["intel"] = intel_skill.latest()
    except Exception:
        snap["intel"] = {"items": []}
    # Gesture state rides along the same way, for the MODULES panel's live
    # line. Cheap: status() reads a dict under a lock and touches no camera.
    try:
        import gesturewatch
        snap["gesture"] = gesturewatch.status()
    except Exception:
        snap["gesture"] = {"armed": False, "available": False}
    # The newest high/critical finding, so the spoken alert's "it's on your
    # screen" is true without the HUD having to poll a second endpoint. Local
    # only, and it reads a buffer under a lock -- no scan happens here.
    try:
        import threatmon
        snap["threat"] = threatmon.latest_alert()
    except Exception:
        snap["threat"] = {}
    # WHETHER THERE IS A REPAIR FOR IT, so the alert can carry a FIX THIS
    # affordance instead of leaving the owner to work out what to do about a
    # finding. Only the LABEL travels -- what the repair would do, in words.
    # Nothing here stages or runs anything: the HUD's button posts to /repair,
    # which asks first, and the repair itself is gated at L2 like every other
    # action that changes the machine.
    try:
        from threatmon import remedy as _remedy
        keys = _remedy.available_for(snap.get("threat") or {})
        if keys:
            spec = _remedy.FIXES[keys[0]]
            snap["repair"] = {
                "available": True,
                "fix": keys[0],
                "label": spec["label"],
                "detail": spec["describe"](snap["threat"]),
                "undoable": bool(spec["undoable"]),
            }
        else:
            snap["repair"] = {"available": False}
    except Exception:
        snap["repair"] = {"available": False}
    try:
        from threatmon import lockdown as _lockdown
        snap["lockdown"] = _lockdown.status()
    except Exception:
        snap["lockdown"] = {"armed": False}
    try:
        from threatmon import usbwatch as _usb
        st = _usb.status()
        snap["usb"] = {"attached_now": st.get("attached_now", 0),
                       "devices_known": st.get("devices_known", 0)}
    except Exception:
        snap["usb"] = {"attached_now": 0}
    return snap


def _sanitize_for_log(text: str) -> str:
    """VULNERABILITY FOUND & FIXED: while a power confirmation is pending
    (skills/power_skill.py), intent.py routes WHATEVER the next utterance is
    straight to power_skill.confirm() as a PIN attempt -- correct or not.
    That raw text was reaching security.audit("command", req.text),
    conversation_history (unredacted -- actively fed back into the LLM as
    context on every later turn), and last_exchange["text"] (redact()'s
    patterns require a mix of letters/digits/symbols, so a bare numeric PIN
    matches none of them and sailed straight through). Combined, that meant
    the one secret this system has was sitting in plaintext in the audit
    log -- which now has a one-click export button -- AND in the HUD's
    last-command display AND in the model's own context window.

    SECOND GAP, now closed: the has_pending() guard only fired MID-FLOW. A user
    who typed their PIN as a bare command with NOTHING staged (a real one landed
    in the shared audit.log this way) hit none of it -- so the exact PIN is
    caught here regardless of state, via security.is_command_pin(), which is
    also what redact() now uses. Redacting at the SOURCE matters because
    conversation_history stores this returned text directly (line ~1174),
    without a later redact() pass -- so a value not scrubbed here reaches the
    model verbatim on every subsequent turn.

    Checked BEFORE dispatch (has_pending() reads as False once confirm()
    resolves it), so this must be computed once per request and threaded
    through -- not recomputed later.
    """
    from skills import power_skill
    if power_skill.has_pending() or security.is_command_pin(text):
        return "[PIN entry — redacted]"
    return text


def _mid_sensitive_flow() -> bool:
    """True when a PIN confirmation or a clarification is pending RIGHT NOW,
    before the current command is dispatched.

    Must be called BEFORE handle() runs, not after. power_skill.confirm() and
    clarify_skill.resolve() both resolve their own pending flag as a side
    effect of handling the current command, so has_pending() checked after
    dispatch is checking state this exact exchange just changed, not whether
    the exchange was itself part of that flow. Caught by the e2e test: it
    looked right (has_pending() is real state, not a stub) right up until a
    PIN attempt was actually submitted.

    CORRECTED: this used to claim a wrong PIN "clears it despite not
    confirming anything". It never did -- power_skill.confirm() left the
    action staged on a bad PIN so a typo could be retried, which is also why
    there was no attempt limit on it at all. It now clears after
    power_skill.MAX_PIN_ATTEMPTS, so the claim is true on the LAST wrong
    attempt and false on the earlier ones. Either way this function's timing
    requirement is unchanged: check before dispatch, not after.
    """
    return power_skill.has_pending() or clarify_skill.has_pending()


def _proactive_nudge(reply: str, was_mid_flow: bool) -> str:
    """A short trailing sentence to ride along on REPLY, or "" almost always
    -- see proactive_skill.py. Centralized so /command and /command-stream
    apply the exact same guards rather than two copies that could quietly
    drift apart.

    Takes the reply itself so it can refuse to ride along on the
    stop-speaking sentinel -- appending anything to "__SILENT__" would stop
    it comparing equal in _finish_exchange's own check just below, turning a
    "say nothing" into "say something", which is the one guarantee that
    sentinel exists to make. Takes was_mid_flow (see _mid_sensitive_flow)
    rather than checking has_pending() itself, since by the time this runs
    the current command may have just been the confirmation or the
    clarification answer -- correctly resolved or not -- and this is not the
    moment for ARGUS to change the subject onto its own agenda either way.
    """
    if not reply or str(reply).strip() == "__SILENT__":
        return ""
    if was_mid_flow:
        return ""
    try:
        return proactive_skill.maybe_nudge() or ""
    except Exception as e:
        print(f"[proactive] skipped: {e}")
        return ""


def _finish_exchange(req_text: str, reply: str, t0: float):
    """Shared bookkeeping for both /command and /command-stream: audit,
    redact, append to conversation history, and record latency for the
    HUD's dashboard. latency_ms is total time here (not time-to-first-chunk)
    -- it's a system-health figure shown on screen, not something heard, so
    "how long did the whole exchange take" is the more useful number.

    req_text here is already the SANITIZED text (see _sanitize_for_log,
    applied by the caller before dispatch) -- never the raw PIN attempt."""
    voice_state["state"] = "standby"
    last_exchange["latency_ms"] = round((time.perf_counter() - t0) * 1000)

    if not reply or not str(reply).strip():
        reply = "Done."

    # The silent sentinel is intentional (a "stop" command) — don't log it as an
    # exchange or it clutters the HUD with __SILENT__.
    if str(reply).strip() != "__SILENT__":
        security.audit("reply", "", reply)
        # Redact before anything persists it — history and the HUD are both
        # places a copied password should never end up.
        safe_reply = security.redact(reply)
        # And before it goes back to the caller -- /command returns this
        # function's return value verbatim as the JSON reply. Redacting only
        # the archived copy (below) while handing the ORIGINAL back to the
        # HTTP caller meant a secret never reached conversation_history but
        # still shipped in the response that put it there in the first place.
        reply = safe_reply
        # Tagged with WHICH ENGINE actually answered this exchange, not
        # merely which one it was ELIGIBLE for -- cloud_gate.get_engine()
        # only ever reads "cloud" after a real Groq call already succeeded
        # (see router.handle()'s reset-to-local-by-default and brain.py's
        # set_engine_cloud()), so an exchange that was cloud-eligible but
        # fell back to local after a Groq failure is tagged "local" here,
        # not "cloud". That's deliberately the conservative direction: it
        # costs a future cloud call slightly less context, never the
        # reverse (content that needed to stay local never gets tagged
        # cloud-safe just because it theoretically could have gone either
        # way). filter_history_for_cloud() is the only thing that reads
        # this tag -- see skills/cloud_gate.py.
        tier = cloud_gate.get_engine()
        # Whether THIS exchange's content must never reach the cloud. Recorded
        # per-entry so filter_history_for_cloud() can forward ordinary context
        # forward while still withholding anything sensitive -- see that
        # function. Computed from the content, not the engine: a turn answered
        # locally for speed is not thereby secret, and a knowledge turn should
        # remain available as context for the next question.
        #
        # AND from what RAN. The request text alone is not enough: "what apps
        # are running" and "read my cv" read as ordinary words to a check on the
        # text, but their replies are built from this machine. exchange_was_local()
        # is set by the router when the routing policy called the request local,
        # and by the dispatcher whenever a machine skill executed -- either one
        # withholds this pair from every later hosted-model call.
        sensitive = cloud_gate.is_sensitive(req_text) or cloud_gate.exchange_was_local()
        with _history_lock:
            conversation_history.append({"role": "user", "content": req_text,
                                         "tier": tier, "sensitive": sensitive})
            conversation_history.append(
                {"role": "assistant", "content": safe_reply,
                 "tier": tier, "sensitive": sensitive})
            del conversation_history[:-MAX_HISTORY]
            # Mirrored to disk on every exchange rather than at shutdown: ARGUS
            # is closed by killing the window or the process as often as not,
            # and a save that only runs on a clean exit is the save that never
            # happens. Inside the lock so the file can't capture a half-written
            # pair either.
            history_store.save(conversation_history, MAX_HISTORY)
        last_exchange["text"] = security.redact(req_text)
        last_exchange["reply"] = safe_reply

        # Passive memory: notice durable facts mentioned in passing rather
        # than only what ARGUS is explicitly told to remember. Runs on the
        # SANITIZED text (never a raw PIN attempt) and is audited, so anything
        # learned automatically is visible in the log rather than appearing
        # silently in the profile. Deliberately non-fatal -- a memory that
        # cannot be written must never take down the reply that was already
        # produced and, on the voice path, already spoken.
        try:
            learned = passive_memory.observe(req_text)
            if learned:
                security.audit("learned", "", learned)
                print(f"[memory] learned: {learned}")
        except Exception as e:
            print(f"[memory] skipped: {e}")
    else:
        last_exchange["text"] = req_text
        last_exchange["reply"] = "— stopped —"
    return reply


@app.post("/command", response_model=CommandResponse)
def command(req: CommandRequest):
    """Used by the HUD's own text input and command deck -- always a single
    complete reply, no TTS involved on this path. Voice commands go through
    /command-stream instead (see listener.py's execute())."""
    voice_state["state"] = "thinking"
    logged_text = _sanitize_for_log(req.text)
    security.audit("command", logged_text)
    t0 = time.perf_counter()
    was_mid_flow = _mid_sensitive_flow()  # captured BEFORE dispatch -- see _mid_sensitive_flow
    # EVERY request ends in exactly one terminal state. request() opens the trace,
    # binds it for the router, the providers and the skills, and guarantees it is
    # closed even if something below raises -- an escaping exception is FAILED,
    # not a request that quietly never finished. See route_trace.py.
    with route_trace.request("command", len(req.text)) as tr:
        try:
            reply = handle(req.text, history=conversation_history)
        except Exception as e:
            print(f"[command] {e}")
            import traceback
            traceback.print_exc()
            tr.fail(type(e).__name__)
            reply = "Something went wrong handling that."
        nudge = _proactive_nudge(reply, was_mid_flow)
        if nudge:
            reply = f"{reply} {nudge}"
        reply = _finish_exchange(logged_text, reply, t0)
        d = {}
        try:
            import router
            d = router.last_dispatch()
        except Exception:
            pass
        refused = False
        level = None
        try:
            refused = bool(router.last_refused())
            level = auth.level_for(d.get("skill", ""), d.get("action", ""))
        except Exception:
            pass
        requires_auth = refused and "authenticate" in str(reply).lower()
        requires_confirmation = refused and "needs confirming" in str(reply).lower()
        # Settle the state now so the response can report it. DENIED / FAILED
        # markers set by the router or brain are honoured; otherwise COMPLETED.
        tr.finish()
        tr.delivered()
        return CommandResponse(reply=reply, skill=d.get("skill", ""),
                               action=d.get("action", ""),
                               auth_required=requires_auth,
                               confirmation_required=requires_confirmation,
                               auth_level=level if refused else None,
                               auth_requirement=("fresh authentication" if requires_auth else ""),
                               request_id=tr.request_id, status=tr.state,
                               route=tr.route)


@app.post("/command-stream")
def command_stream(req: CommandRequest):
    """Streaming counterpart to /command, used by the voice pipeline so TTS
    can start on the first sentence instead of waiting for the whole reply
    to generate. Response body is newline-delimited: each line is one
    complete, speakable chunk (a whole sentence for the "chat" path, or the
    single complete reply for anything else -- see router.handle_stream)."""
    voice_state["state"] = "thinking"
    logged_text = _sanitize_for_log(req.text)
    security.audit("command", logged_text)
    t0 = time.perf_counter()
    was_mid_flow = _mid_sensitive_flow()  # captured BEFORE dispatch -- see _mid_sensitive_flow
    # Opened here, where the request ARRIVES, and closed in gen()'s finally, where it
    # ends. In between it is re-entered on every chunk (scoped_iter): the framework
    # may pull each chunk on a different worker thread, so a trace bound once would
    # be gone by the second sentence -- and this is the path voice uses.
    tr = route_trace.begin("stream", len(req.text))

    def gen():
        parts = []
        try:
            for chunk in route_trace.scoped_iter(
                    tr, handle_stream(req.text, history=conversation_history)):
                chunk = str(chunk)
                parts.append(chunk)
                # Redact BEFORE yielding, not after. _finish_exchange's own
                # redaction runs in the `finally` below, once every chunk has
                # already gone out over the HTTP response and, on the voice
                # path, already been spoken by TTS -- by then it protects only
                # the archived copy. Each chunk is a full sentence (or the
                # whole reply), far longer than any pattern in
                # security.SECRET_PATTERNS, so redacting per-chunk carries the
                # same accuracy as redacting the joined text would.
                yield security.redact(chunk).replace("\n", " ") + "\n"

            # A proactive aside, if one applies, is yielded as its OWN chunk
            # rather than appended to the text above. On this path each
            # chunk is spoken as it arrives -- by the time _finish_exchange
            # runs below, everything already yielded has already been played
            # through TTS, so bolting a nudge onto the joined text down there
            # would add it to the HUD transcript but never actually say it.
            # A second short line here is what makes it a spoken aside
            # instead of only a written one.
            nudge = _proactive_nudge(" ".join(parts), was_mid_flow)
            if nudge:
                parts.append(nudge)
                yield security.redact(nudge) + "\n"
            # Every chunk has been handed to the transport: the reply is complete.
            tr.delivered()
            tr.finish()
        except GeneratorExit:
            # The client stopped reading (a barge-in, a closed connection) before
            # the reply finished. That used to leave no record at all; it is now a
            # CANCELLED request. Re-raised: closing a generator must still close it.
            tr.finish(route_trace.State.CANCELLED, "client closed the stream")
            raise
        except Exception as e:
            print(f"[command-stream] {e}")
            import traceback
            traceback.print_exc()
            tr.fail(type(e).__name__)
            tr.finish()
            if not parts:
                yield "Something went wrong handling that.\n"
                parts.append("Something went wrong handling that.")
        finally:
            tr.finish()     # idempotent: the safety net for any exit not handled above
            _finish_exchange(logged_text, " ".join(parts), t0)

    return StreamingResponse(gen(), media_type="text/plain",
                             headers={"X-Argus-Request-Id": tr.request_id})
